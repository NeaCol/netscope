import socket
import struct
import threading
import unittest

from netscope.protocols.dns import encode_dns_query, parse_dns_message, query_dns


class TestDnsHardening(unittest.TestCase):
    def test_label_over_63_bytes_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            encode_dns_query("a" * 70 + ".example")
        self.assertIn("63", str(ctx.exception))

    def test_empty_domain_is_rejected(self):
        with self.assertRaises(ValueError):
            encode_dns_query("   ")

    def test_empty_label_is_rejected(self):
        with self.assertRaises(ValueError):
            encode_dns_query("example..com")

    def test_unicode_domain_is_idna_encoded(self):
        query = encode_dns_query("bücher.example")
        self.assertIn(b"xn--bcher-kva", query)

    def test_message_rcode_names(self):
        wire = bytearray(encode_dns_query("example.com"))
        wire[2] = 0x81
        wire[3] = 0x83
        message = parse_dns_message(bytes(wire))
        self.assertEqual(message.rcode, 3)
        self.assertEqual(message.rcode_name, "NXDOMAIN")
        self.assertTrue(message.is_response)

    def test_query_reports_nxdomain_instead_of_noerror(self):
        with _FakeResolver(rcode=3, answer=False) as resolver:
            result = query_dns("nope.invalid", "A", server="127.0.0.1", timeout=0.5, port=resolver.port)
        self.assertEqual(result.status, "NXDOMAIN")
        self.assertEqual(result.answers, [])
        self.assertIsNotNone(result.error_message)

    def test_query_accepts_a_matching_response(self):
        with _FakeResolver() as resolver:
            result = query_dns("example.com", "A", server="127.0.0.1", timeout=0.5, port=resolver.port)
        self.assertEqual(result.status, "NOERROR")
        self.assertEqual([a.data for a in result.answers], ["6.6.6.6"])

    def test_query_ignores_a_response_with_a_foreign_transaction_id(self):
        with _FakeResolver(echo_tx=False) as resolver:
            result = query_dns("example.com", "A", server="127.0.0.1", timeout=0.3, port=resolver.port)
        self.assertEqual(result.status, "TIMEOUT")
        self.assertEqual(result.answers, [])

    def test_query_ignores_a_querys_echo(self):
        with _FakeResolver(qr=False) as resolver:
            result = query_dns("example.com", "A", server="127.0.0.1", timeout=0.3, port=resolver.port)
        self.assertEqual(result.status, "TIMEOUT")
        self.assertEqual(result.answers, [])

    def test_unsupported_record_type_is_rejected(self):
        with self.assertRaises(ValueError):
            query_dns("example.com", "FOO")


class _FakeResolver:
    """A one-shot stub resolver on loopback that answers on an ephemeral port."""

    def __init__(self, rcode: int = 0, answer: bool = True, echo_tx: bool = True, qr: bool = True):
        self.rcode = rcode
        self.answer = answer
        self.echo_tx = echo_tx
        self.qr = qr
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.05)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                query, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            resp = bytearray(query)
            if not self.echo_tx:
                resp[0:2] = b"\xde\xad"
            resp[2] = (0x80 if self.qr else 0x00) | 0x01
            resp[3] = 0x80 | self.rcode
            resp[6:8] = struct.pack("!H", 1 if self.answer else 0)
            if self.answer:
                resp += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([6, 6, 6, 6])
            try:
                self.sock.sendto(bytes(resp), addr)
            except OSError:
                return

    def __enter__(self) -> "_FakeResolver":
        return self

    def __exit__(self, *exc_info) -> None:
        self._stop.set()
        self.sock.close()
