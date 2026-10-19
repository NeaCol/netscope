import io
import unittest
from netscope.protocols.dissector import dissect_packet, format_hex_dump, format_mac
from netscope.protocols.dns import encode_dns_query, parse_dns_response, query_dns
from netscope.protocols.pcap import generate_educational_pcap, parse_pcap_packets, read_pcap, write_pcap


class TestProtocols(unittest.TestCase):
    def test_format_mac(self):
        self.assertEqual(format_mac(b"\x00\x0c\x29\x4b\x82\x11"), "00:0C:29:4B:82:11")

    def test_format_hex_dump(self):
        dump = format_hex_dump(b"Hello World 1234567890")
        self.assertIn("48 65 6c 6c 6f", dump)
        self.assertIn("|Hello World 1234|", dump)

    def test_dissect_short_frame(self):
        pkt = dissect_packet(b"\x00\x01\x02")
        self.assertIn("Malformed", pkt.summary)
        self.assertEqual(len(pkt.layers), 0)

    def test_dissect_arp_frame(self):
        arp_raw = (
            b"\xff\xff\xff\xff\xff\xff"
            b"\x00\x0c\x29\x4b\x82\x11"
            b"\x08\x06"
            b"\x00\x01\x08\x00\x06\x04\x00\x01"
            b"\x00\x0c\x29\x4b\x82\x11"
            b"\xc0\xa8\x01\x32"
            b"\x00\x00\x00\x00\x00\x00"
            b"\xc0\xa8\x01\x01"
        )
        pkt = dissect_packet(arp_raw)
        self.assertIn("ARP Request", pkt.summary)
        layer_names = [l.name for l in pkt.layers]
        self.assertTrue(any("Ethernet" in name for name in layer_names))
        self.assertTrue(any("ARP" in name for name in layer_names))

    def test_dissect_ipv4_icmp(self):
        icmp_raw = (
            b"\x00\x1f\x6d\x9a\x33\x54"
            b"\x00\x0c\x29\x4b\x82\x11"
            b"\x08\x00"
            b"\x45\x00\x00\x1c\x12\x34\x40\x00\x40\x01\x00\x00\xc0\xa8\x01\x02\xc0\xa8\x01\x01"
            b"\x08\x00\x00\x00\x11\x22\x00\x01"
        )
        pkt = dissect_packet(icmp_raw)
        self.assertIn("ICMP Echo Request", pkt.summary)
        self.assertTrue(any("IPv4" in l.name for l in pkt.layers))
        self.assertTrue(any("ICMP" in l.name for l in pkt.layers))

    def test_dissect_ipv4_tcp_syn(self):
        tcp_raw = (
            b"\x00\x1f\x6d\x9a\x33\x54"
            b"\x00\x0c\x29\x4b\x82\x11"
            b"\x08\x00"
            b"\x45\x00\x00\x28\x10\x01\x40\x00\x40\x06\x00\x00\xc0\xa8\x01\x02\x5d\x8e\x12\x34"
            b"\xc0\x00\x00\x50\x00\x00\x03\xe8\x00\x00\x00\x00\x50\x02\xfa\xf0\x00\x00\x00\x00"
        )
        pkt = dissect_packet(tcp_raw)
        self.assertIn("SYN", pkt.summary)
        self.assertTrue(any("TCP" in l.name for l in pkt.layers))
        self.assertTrue(any("SYN" in note for note in pkt.educational_notes))

    def test_synthetic_pcap_roundtrip(self):
        pcap_bytes = generate_educational_pcap()
        self.assertGreater(len(pcap_bytes), 100)

        packets = parse_pcap_packets(pcap_bytes)
        self.assertEqual(len(packets), 7)

        stream = io.BytesIO()
        frame_list = [(p.timestamp, b"\x00" * p.length) for p in packets]
        write_pcap(frame_list, stream)
        self.assertGreater(len(stream.getvalue()), 100)

    def test_dns_query_encoding(self):
        query = encode_dns_query("example.com", 1)
        self.assertGreater(len(query), 12)
        self.assertIn(b"example", query)
        self.assertIn(b"com", query)

    def test_dns_response_parser(self):
        dns_wire = (
            b"\x1a\x2b"
            b"\x81\x80"
            b"\x00\x01\x00\x01\x00\x00\x00\x00"
            b"\x07example\x03com\x00"
            b"\x00\x01\x00\x01"
            b"\xc0\x0c"
            b"\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04"
            b"\x5d\xb8\xd8\x22"
        )
        answers = parse_dns_response(dns_wire, "A")
        self.assertEqual(len(answers), 1)
        self.assertEqual(answers[0].name, "example.com")
        self.assertEqual(answers[0].record_type, "A")
        self.assertEqual(answers[0].data, "93.184.216.34")
        self.assertEqual(answers[0].ttl, 300)
