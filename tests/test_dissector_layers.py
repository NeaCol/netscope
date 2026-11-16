import struct
import unittest

from netscope.protocols.dissector import dissect_packet, parse_tcp_options


def _ipv4_tcp_frame(dst_port: int = 80, payload: bytes = b"", flags: int = 0x02, frag: int = 0,
                    ip_total_length: int = None, options: bytes = b"") -> bytes:
    tcp_hdr_len = 20 + len(options)
    tcp = struct.pack("!HHIIBBHHH", 49152, dst_port, 1000, 0, (tcp_hdr_len // 4) << 4, flags, 64240, 0, 0) + options + payload
    total = ip_total_length if ip_total_length is not None else 20 + len(tcp)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, frag, 64, 6, 0,
        bytes([192, 168, 1, 50]), bytes([93, 142, 18, 52]),
    )
    return b"\x00\x1f\x6d\x9a\x33\x54" + b"\x00\x0c\x29\x4b\x82\x11" + b"\x08\x00" + ip + tcp


class TestVlanAndFragments(unittest.TestCase):
    def test_8021q_tag_is_stripped_and_dissected(self):
        base = _ipv4_tcp_frame()
        tagged = base[:12] + b"\x81\x00" + struct.pack("!H", 0xA064) + b"\x08\x00" + base[14:]
        pkt = dissect_packet(tagged)
        names = [layer.name for layer in pkt.layers]
        self.assertIn("802.1Q VLAN Tag", names)
        self.assertTrue(any("IPv4" in n for n in names))
        self.assertTrue(any("TCP" in n for n in names))
        tag = next(layer for layer in pkt.layers if "VLAN" in layer.name)
        self.assertEqual(tag.fields["VLAN ID"], 100)
        self.assertEqual(tag.fields["PCP (Priority)"], 5)
        self.assertIn("SYN", pkt.summary)

    def test_qinq_double_tag_is_dissected(self):
        base = _ipv4_tcp_frame()
        tagged = (
            base[:12]
            + b"\x88\xa8" + struct.pack("!H", 200)
            + b"\x81\x00" + struct.pack("!H", 100)
            + b"\x08\x00"
            + base[14:]
        )
        pkt = dissect_packet(tagged)
        tags = [layer for layer in pkt.layers if "Tag" in layer.name]
        self.assertEqual(len(tags), 2)
        self.assertEqual(tags[0].fields["VLAN ID"], 200)
        self.assertTrue(any("TCP" in layer.name for layer in pkt.layers))

    def test_non_first_fragment_is_not_dissected_as_tcp(self):
        frame = _ipv4_tcp_frame(frag=0x2000 | 185)
        pkt = dissect_packet(frame)
        self.assertIn("fragment", pkt.summary)
        self.assertFalse(any(layer.name.startswith("TCP") for layer in pkt.layers))
        self.assertTrue(any("Fragment offset" in note for note in pkt.educational_notes))

    def test_first_fragment_with_mf_is_dissected_with_a_note(self):
        pkt = dissect_packet(_ipv4_tcp_frame(frag=0x2000))
        self.assertTrue(any(layer.name.startswith("TCP") for layer in pkt.layers))
        self.assertTrue(any("More Fragments" in note for note in pkt.educational_notes))

    def test_ethernet_padding_does_not_leak_into_the_payload(self):
        body = b"GET /status HTTP/1.1\r\nHost: netscope.dev\r\n\r\n"
        ip_total = 20 + 20 + len(body)
        frame = _ipv4_tcp_frame(dst_port=80, payload=body, flags=0x18, ip_total_length=ip_total) + b"\x00" * 8
        pkt = dissect_packet(frame)
        http = next(layer for layer in pkt.layers if "HTTP" in layer.name)
        self.assertEqual(http.fields["Start Line"], "GET /status HTTP/1.1")


class TestTcpOptions(unittest.TestCase):
    def test_syn_options_are_decoded(self):
        options = (
            struct.pack("!BBH", 2, 4, 1460)
            + struct.pack("!BB", 4, 2)
            + struct.pack("!BBII", 8, 10, 777, 0)
            + b"\x01"
            + struct.pack("!BBB", 3, 3, 7)
        )
        pkt = dissect_packet(_ipv4_tcp_frame(dst_port=443, options=options))
        tcp = next(layer for layer in pkt.layers if layer.name.startswith("TCP"))
        self.assertIn("MSS=1460", tcp.fields["Options"])
        self.assertIn("WS=7", tcp.fields["Options"])
        self.assertIn("SACK_PERM", tcp.fields["Options"])
        self.assertTrue(any("MSS 1460" in note for note in pkt.educational_notes))

    def test_malformed_option_length_does_not_hang(self):
        parsed = parse_tcp_options(b"\x02\x00\x00\x00")
        self.assertIn("Malformed", parsed)

    def test_truncated_option_block_is_reported(self):
        parsed = parse_tcp_options(b"\x02\x04\x05")
        self.assertIn("Truncated", parsed)

    def test_plain_header_has_no_options_field(self):
        pkt = dissect_packet(_ipv4_tcp_frame())
        tcp = next(layer for layer in pkt.layers if layer.name.startswith("TCP"))
        self.assertNotIn("Options", tcp.fields)
