import io
import struct
import time
from typing import BinaryIO, Generator, List, Optional, Tuple, Union
from netscope.protocols.dissector import DissectedPacket, dissect_packet

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1


def read_pcap(stream_or_path: Union[str, bytes, BinaryIO]) -> Generator[Tuple[float, bytes], None, None]:
    if isinstance(stream_or_path, str):
        with open(stream_or_path, "rb") as f:
            data = f.read()
            stream = io.BytesIO(data)
    elif isinstance(stream_or_path, bytes):
        stream = io.BytesIO(stream_or_path)
    else:
        stream = stream_or_path

    global_header = stream.read(24)
    if len(global_header) < 24:
        return

    magic, ver_major, ver_minor, thiszone, sigfigs, snaplen, network = struct.unpack("!IHHiIII", global_header)

    is_big_endian = magic == 0xA1B2C3D4
    if magic == 0xD4C3B2A1:
        is_big_endian = False
    elif magic != 0xA1B2C3D4:
        fmt = "<IHHiIII"
        magic, ver_major, ver_minor, thiszone, sigfigs, snaplen, network = struct.unpack(fmt, global_header)
        if magic == 0xA1B2C3D4:
            is_big_endian = False
        else:
            return

    hdr_fmt = ">IIII" if is_big_endian else "<IIII"

    while True:
        pkt_hdr = stream.read(16)
        if len(pkt_hdr) < 16:
            break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(hdr_fmt, pkt_hdr)
        data = stream.read(incl_len)
        if len(data) < incl_len:
            break
        timestamp = ts_sec + (ts_usec / 1_000_000.0)
        yield timestamp, data


def write_pcap(packets: List[Tuple[float, bytes]], stream_or_path: Union[str, BinaryIO]) -> None:
    if isinstance(stream_or_path, str):
        stream = open(stream_or_path, "wb")
        close_needed = True
    else:
        stream = stream_or_path
        close_needed = False

    try:
        global_hdr = struct.pack("!IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)
        stream.write(global_hdr)

        for ts, data in packets:
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            incl_len = len(data)
            orig_len = incl_len
            pkt_hdr = struct.pack("!IIII", ts_sec, ts_usec, incl_len, orig_len)
            stream.write(pkt_hdr)
            stream.write(data)
    finally:
        if close_needed:
            stream.close()


def generate_educational_pcap() -> bytes:
    packets: List[Tuple[float, bytes]] = []
    base_time = time.time() - 10.0

    client_mac = b"\x00\x0c\x29\x4b\x82\x11"
    gw_mac = b"\x00\x1f\x6d\x9a\x33\x54"
    server_mac = b"\x52\x54\x00\x12\x34\x56"

    # Packet 1: ARP Request
    arp_req = (
        b"\xff\xff\xff\xff\xff\xff"
        + client_mac
        + b"\x08\x06"
        + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        + client_mac
        + b"\xc0\xa8\x01\x32"  # 192.168.1.50
        + b"\x00\x00\x00\x00\x00\x00"
        + b"\xc0\xa8\x01\x01"  # 192.168.1.1
    )
    packets.append((base_time, arp_req))

    # Packet 2: ARP Reply
    arp_rep = (
        client_mac
        + gw_mac
        + b"\x08\x06"
        + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
        + gw_mac
        + b"\xc0\xa8\x01\x01"
        + client_mac
        + b"\xc0\xa8\x01\x32"
    )
    packets.append((base_time + 0.0012, arp_rep))

    # Packet 3: DNS Query
    dns_query = (
        gw_mac
        + client_mac
        + b"\x08\x00"
        + struct.pack("!BBHHHBBH4s4s", 0x45, 0, 57, 0x1001, 0x4000, 64, 17, 0, b"\xc0\xa8\x01\x32", b"\x01\x01\x01\x01")
        + struct.pack("!HHHH", 53421, 53, 37, 0)
        + struct.pack("!HHHHHH", 0x7A12, 0x0100, 1, 0, 0, 0)
        + b"\x08netscope\x03dev\x00"
        + struct.pack("!HH", 1, 1)
    )
    packets.append((base_time + 0.050, dns_query))

    # Packet 4: DNS Response
    dns_resp = (
        client_mac
        + gw_mac
        + b"\x08\x00"
        + struct.pack("!BBHHHBBH4s4s", 0x45, 0, 73, 0x9002, 0x4000, 56, 17, 0, b"\x01\x01\x01\x01", b"\xc0\xa8\x01\x32")
        + struct.pack("!HHHH", 53, 53421, 53, 0)
        + struct.pack("!HHHHHH", 0x7A12, 0x8180, 1, 1, 0, 0)
        + b"\x08netscope\x03dev\x00"
        + struct.pack("!HH", 1, 1)
        + b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 300, 4)
        + b"\x5d\x8e\x12\x34"  # 93.142.18.52
    )
    packets.append((base_time + 0.068, dns_resp))

    # Packet 5: TCP SYN
    tcp_syn = (
        gw_mac
        + client_mac
        + b"\x08\x00"
        + struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0x2001, 0x4000, 64, 6, 0, b"\xc0\xa8\x01\x32", b"\x5d\x8e\x12\x34")
        + struct.pack("!HHIIBBHHH", 49152, 80, 1000, 0, 0x50, 0x02, 64240, 0, 0)
    )
    packets.append((base_time + 0.080, tcp_syn))

    # Packet 6: TCP SYN-ACK
    tcp_synack = (
        client_mac
        + gw_mac
        + b"\x08\x00"
        + struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0x7001, 0x4000, 58, 6, 0, b"\x5d\x8e\x12\x34", b"\xc0\xa8\x01\x32")
        + struct.pack("!HHIIBBHHH", 80, 49152, 5000, 1001, 0x50, 0x12, 65535, 0, 0)
    )
    packets.append((base_time + 0.095, tcp_synack))

    # Packet 7: TCP ACK + HTTP Request
    http_payload = b"GET /status HTTP/1.1\r\nHost: netscope.dev\r\nUser-Agent: NetScope/1.0\r\n\r\n"
    tcp_http = (
        gw_mac
        + client_mac
        + b"\x08\x00"
        + struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(http_payload), 0x2002, 0x4000, 64, 6, 0, b"\xc0\xa8\x01\x32", b"\x5d\x8e\x12\x34")
        + struct.pack("!HHIIBBHHH", 49152, 80, 1001, 5001, 0x50, 0x18, 64240, 0, 0)
        + http_payload
    )
    packets.append((base_time + 0.098, tcp_http))

    buf = io.BytesIO()
    write_pcap(packets, buf)
    return buf.getvalue()


def parse_pcap_packets(pcap_data: Union[str, bytes]) -> List[DissectedPacket]:
    dissected: List[DissectedPacket] = []
    for ts, raw in read_pcap(pcap_data):
        pkt = dissect_packet(raw, timestamp=ts)
        dissected.append(pkt)
    return dissected
