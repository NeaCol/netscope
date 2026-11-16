import io
import struct
import unittest

from netscope.protocols.pcap import PcapFormatError, generate_educational_pcap, read_pcap


def _build_pcap(payload: bytes, magic: int = 0xA1B2C3D4, byte_order: str = "<", linktype: int = 1, frac: int = 123456) -> bytes:
    buf = io.BytesIO()
    buf.write(struct.pack(byte_order + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype))
    buf.write(struct.pack(byte_order + "IIII", 1_700_000_000, frac, len(payload), len(payload)))
    buf.write(payload)
    return buf.getvalue()


class TestCaptureFormats(unittest.TestCase):
    def test_nanosecond_capture_is_read(self):
        payload = b"\x00" * 12 + b"\x08\x00" + b"\x45" + b"\x00" * 19
        packets = list(read_pcap(_build_pcap(payload, magic=0xA1B23C4D, frac=123456789)))
        self.assertEqual(len(packets), 1)
        ts, data = packets[0]
        self.assertAlmostEqual(ts, 1_700_000_000.123456789, places=6)
        self.assertEqual(data, payload)

    def test_big_endian_capture_is_read(self):
        payload = b"\x00" * 12 + b"\x08\x00" + b"\x45" + b"\x00" * 19
        packets = list(read_pcap(_build_pcap(payload, byte_order=">", frac=500000)))
        self.assertEqual(len(packets), 1)
        self.assertAlmostEqual(packets[0][0], 1_700_000_000.5, places=6)

    def test_pcapng_is_rejected_with_a_hint(self):
        header = struct.pack("<IHHiIII", 0x0A0D0D0A, 2, 4, 0, 0, 65535, 1)
        with self.assertRaises(PcapFormatError) as ctx:
            list(read_pcap(header + b"\x00" * 32))
        self.assertIn("pcapng", str(ctx.exception))

    def test_truncated_header_is_rejected(self):
        with self.assertRaises(PcapFormatError):
            list(read_pcap(b"\xd4\xc3\xb2\xa1"))

    def test_non_ethernet_linktype_is_rejected(self):
        payload = b"\x00" * 12 + b"\x08\x00" + b"\x45" + b"\x00" * 19
        with self.assertRaises(PcapFormatError) as ctx:
            list(read_pcap(_build_pcap(payload, linktype=113)))
        self.assertIn("LINUX_SLL", str(ctx.exception))

    def test_sample_capture_lengths_are_consistent(self):
        # The shipped sample is the documentation fixture: a wrong total length
        # truncates real dissectors and silently hides the packet's payload.
        for index, (_, raw) in enumerate(read_pcap(generate_educational_pcap()), start=1):
            if struct.unpack("!H", raw[12:14])[0] != 0x0800:
                continue
            ip_total = struct.unpack("!H", raw[16:18])[0]
            ihl = (raw[14] & 0x0F) * 4
            self.assertEqual(ip_total, len(raw) - 14, f"packet {index}: IP total length disagrees with the frame")
            if raw[23] == 17:
                udp_len = struct.unpack("!H", raw[14 + ihl + 4 : 14 + ihl + 6])[0]
                self.assertEqual(udp_len, ip_total - ihl, f"packet {index}: UDP length disagrees with the IP payload")
