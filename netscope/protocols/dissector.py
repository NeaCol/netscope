import ipaddress
import socket
import struct
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PacketLayer:
    name: str
    fields: Dict[str, Any] = field(default_factory=dict)
    description: str = ""


@dataclass
class DissectedPacket:
    timestamp: float
    length: int
    summary: str
    layers: List[PacketLayer] = field(default_factory=list)
    hex_dump: str = ""
    payload_preview: Optional[str] = None
    educational_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "length": self.length,
            "summary": self.summary,
            "layers": [asdict(l) for l in self.layers],
            "hex_dump": self.hex_dump,
            "payload_preview": self.payload_preview,
            "educational_notes": self.educational_notes,
        }


def format_hex_dump(data: bytes, max_bytes: int = 256) -> str:
    lines = []
    chunk = data[:max_bytes]
    for offset in range(0, len(chunk), 16):
        line_slice = chunk[offset : offset + 16]
        hex_parts = [f"{b:02x}" for b in line_slice]
        hex_str = " ".join(hex_parts[:8]) + "  " + " ".join(hex_parts[8:])
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in line_slice)
        lines.append(f"{offset:04x}   {hex_str:<49}  |{ascii_str}|")
    if len(data) > max_bytes:
        lines.append(f"... ({len(data) - max_bytes} bytes omitted)")
    return "\n".join(lines)


def format_mac(b: bytes) -> str:
    return ":".join(f"{x:02X}" for x in b)


def parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    original_offset = offset
    jumped = False
    bytes_consumed = 0
    visited_offsets = set()

    while offset < len(data):
        if offset in visited_offsets or len(visited_offsets) > 20:
            break
        visited_offsets.add(offset)
        length = data[offset]
        if length == 0:
            if not jumped:
                bytes_consumed += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
            if not jumped:
                bytes_consumed += 2
                jumped = True
            offset = pointer
            continue
        offset += 1
        if not jumped:
            bytes_consumed += 1
        if offset + length > len(data):
            labels.append(data[offset:].decode("utf-8", errors="replace"))
            if not jumped:
                bytes_consumed += len(data) - offset
            break
        labels.append(data[offset : offset + length].decode("utf-8", errors="replace"))
        offset += length
        if not jumped:
            bytes_consumed += length

    total_consumed = bytes_consumed if jumped else (offset - original_offset + 1)
    if total_consumed <= 0:
        total_consumed = min(1, len(data) - original_offset)
    return ".".join(labels), total_consumed


def dissect_packet(raw_data: bytes, timestamp: float = 0.0) -> DissectedPacket:
    total_len = len(raw_data)
    layers: List[PacketLayer] = []
    notes: List[str] = []
    summary = f"Raw Packet ({total_len} bytes)"

    if total_len < 14:
        return DissectedPacket(
            timestamp=timestamp,
            length=total_len,
            summary="Malformed / Incomplete Frame",
            hex_dump=format_hex_dump(raw_data),
            educational_notes=["Frame is shorter than minimum 14-byte Ethernet header."],
        )

    dst_mac = format_mac(raw_data[0:6])
    src_mac = format_mac(raw_data[6:12])
    ethertype = struct.unpack("!H", raw_data[12:14])[0]

    eth_layer = PacketLayer(
        name="Ethernet II",
        fields={
            "Destination MAC": dst_mac,
            "Source MAC": src_mac,
            "EtherType": f"0x{ethertype:04x}",
        },
        description="Data Link Layer (L2) framing with 48-bit physical MAC addresses.",
    )
    layers.append(eth_layer)

    payload = raw_data[14:]

    if ethertype == 0x0806:
        if len(payload) >= 28:
            hw_type, proto_type, hw_len, proto_len, opcode = struct.unpack("!HHBBH", payload[:8])
            sender_mac = format_mac(payload[8:14])
            sender_ip = socket.inet_ntoa(payload[14:18])
            target_mac = format_mac(payload[18:24])
            target_ip = socket.inet_ntoa(payload[24:28])

            op_name = "Request" if opcode == 1 else ("Reply" if opcode == 2 else f"Opcode {opcode}")
            summary = f"ARP {op_name}: Who has {target_ip}? Tell {sender_ip}" if opcode == 1 else f"ARP Reply: {sender_ip} is at {sender_mac}"

            layers.append(
                PacketLayer(
                    name="ARP (Address Resolution Protocol)",
                    fields={
                        "Hardware Type": hw_type,
                        "Protocol Type": f"0x{proto_type:04x}",
                        "Opcode": f"{opcode} ({op_name})",
                        "Sender MAC": sender_mac,
                        "Sender IP": sender_ip,
                        "Target MAC": target_mac,
                        "Target IP": target_ip,
                    },
                    description="Maps IP network addresses to physical link layer MAC addresses.",
                )
            )
            notes.append("ARP operates without encryption or authentication; gratuitous ARPs update subnet neighbor tables.")

    elif ethertype == 0x0800:
        if len(payload) >= 20:
            version_ihl = payload[0]
            version = version_ihl >> 4
            ihl = (version_ihl & 0x0F) * 4
            if ihl < 20 or ihl > len(payload):
                return DissectedPacket(
                    timestamp=timestamp,
                    length=total_len,
                    summary=f"Malformed IPv4 Packet (invalid IHL: {ihl})",
                    layers=layers,
                    hex_dump=format_hex_dump(raw_data),
                    educational_notes=["IPv4 header length (IHL) is corrupted or out of packet bounds."],
                )
            tos = payload[1]
            ip_total_length = struct.unpack("!H", payload[2:4])[0]
            ident = struct.unpack("!H", payload[4:6])[0]
            flags_frag = struct.unpack("!H", payload[6:8])[0]
            df = bool(flags_frag & 0x4000)
            mf = bool(flags_frag & 0x2000)
            frag_offset = flags_frag & 0x1FFF
            ttl = payload[8]
            proto_num = payload[9]
            chksum = struct.unpack("!H", payload[10:12])[0]
            src_ip = socket.inet_ntoa(payload[12:16])
            dst_ip = socket.inet_ntoa(payload[16:20])

            proto_names = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 89: "OSPF"}
            proto_str = proto_names.get(proto_num, f"Protocol {proto_num}")

            summary = f"IPv4 {src_ip} -> {dst_ip} ({proto_str})"

            layers.append(
                PacketLayer(
                    name="IPv4 (Internet Protocol v4)",
                    fields={
                        "Version": version,
                        "Header Length": f"{ihl} bytes",
                        "TOS / DSCP": tos,
                        "Total Length": ip_total_length,
                        "Identification": f"0x{ident:04x} ({ident})",
                        "Flags": f"DF={'1' if df else '0'}, MF={'1' if mf else '0'}",
                        "Fragment Offset": frag_offset,
                        "Time to Live (TTL)": ttl,
                        "Protocol": f"{proto_num} ({proto_str})",
                        "Checksum": f"0x{chksum:04x}",
                        "Source IP": src_ip,
                        "Destination IP": dst_ip,
                    },
                    description="Network Layer (L3) packet delivering host-to-host datagrams.",
                )
            )

            if ttl <= 64:
                notes.append(f"TTL={ttl}: typical for Linux, Android, or macOS systems (initial default 64).")
            elif ttl <= 128:
                notes.append(f"TTL={ttl}: typical for Microsoft Windows systems (initial default 128).")
            else:
                notes.append(f"TTL={ttl}: typical for network appliances/routers (initial default 255).")

            l4_data = payload[ihl:]
            if proto_num == 1 and len(l4_data) >= 8:
                summary = _dissect_icmp(l4_data, src_ip, dst_ip, layers, notes)
            elif proto_num == 6 and len(l4_data) >= 20:
                summary = _dissect_tcp(l4_data, src_ip, dst_ip, layers, notes)
            elif proto_num == 17 and len(l4_data) >= 8:
                summary = _dissect_udp(l4_data, src_ip, dst_ip, layers, notes)

    elif ethertype == 0x86DD and len(payload) >= 40:
        v_tc_fl = struct.unpack("!I", payload[:4])[0]
        version = v_tc_fl >> 28
        payload_len, next_hdr, hop_limit = struct.unpack("!HBB", payload[4:8])
        src_ip6 = socket.inet_ntop(socket.AF_INET6, payload[8:24])
        dst_ip6 = socket.inet_ntop(socket.AF_INET6, payload[24:40])

        summary = f"IPv6 {src_ip6} -> {dst_ip6} Next={next_hdr}"

        layers.append(
            PacketLayer(
                name="IPv6 (Internet Protocol v6)",
                fields={
                    "Version": version,
                    "Payload Length": payload_len,
                    "Next Header": next_hdr,
                    "Hop Limit": hop_limit,
                    "Source IPv6": src_ip6,
                    "Destination IPv6": dst_ip6,
                },
                description="Modern 128-bit hierarchical addressing architecture.",
            )
        )

        l4_data = payload[40:]
        if next_hdr == 6 and len(l4_data) >= 20:
            summary = _dissect_tcp(l4_data, src_ip6, dst_ip6, layers, notes)
        elif next_hdr == 17 and len(l4_data) >= 8:
            summary = _dissect_udp(l4_data, src_ip6, dst_ip6, layers, notes)
        elif next_hdr == 58 and len(l4_data) >= 4:
            summary = _dissect_icmpv6(l4_data, src_ip6, dst_ip6, layers, notes)

    preview = None
    if len(raw_data) > 14:
        sample = raw_data[14:78]
        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in sample)
        preview = printable

    return DissectedPacket(
        timestamp=timestamp,
        length=total_len,
        summary=summary,
        layers=layers,
        hex_dump=format_hex_dump(raw_data),
        payload_preview=preview,
        educational_notes=notes,
    )


def _dissect_icmp(l4_data: bytes, src_ip: str, dst_ip: str, layers: List[PacketLayer], notes: List[str]) -> str:
    icmp_type, icmp_code, icmp_chk = struct.unpack("!BBH", l4_data[:4])
    icmp_names = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        8: "Echo Request",
        11: "Time Exceeded (TTL expired)",
    }
    type_name = icmp_names.get(icmp_type, f"Type {icmp_type}")
    summary = f"ICMP {type_name} ({src_ip} -> {dst_ip})"

    icmp_fields = {
        "Type": f"{icmp_type} ({type_name})",
        "Code": icmp_code,
        "Checksum": f"0x{icmp_chk:04x}",
    }
    if icmp_type in (0, 8) and len(l4_data) >= 8:
        ident, seq = struct.unpack("!HH", l4_data[4:8])
        icmp_fields["Identifier"] = ident
        icmp_fields["Sequence Number"] = seq

    layers.append(
        PacketLayer(
            name="ICMP (Internet Control Message Protocol)",
            fields=icmp_fields,
            description="Network diagnostic and error reporting protocol.",
        )
    )
    return summary


def _dissect_icmpv6(l4_data: bytes, src_ip: str, dst_ip: str, layers: List[PacketLayer], notes: List[str]) -> str:
    icmp_type, icmp_code, icmp_chk = struct.unpack("!BBH", l4_data[:4])
    icmpv6_names = {
        1: "Destination Unreachable",
        2: "Packet Too Big",
        3: "Time Exceeded",
        128: "Echo Request",
        129: "Echo Reply",
        133: "Router Solicitation",
        134: "Router Advertisement",
        135: "Neighbor Solicitation",
        136: "Neighbor Advertisement",
    }
    type_name = icmpv6_names.get(icmp_type, f"Type {icmp_type}")
    summary = f"ICMPv6 {type_name} ({src_ip} -> {dst_ip})"

    icmp_fields = {
        "Type": f"{icmp_type} ({type_name})",
        "Code": icmp_code,
        "Checksum": f"0x{icmp_chk:04x}",
    }
    if icmp_type in (128, 129) and len(l4_data) >= 8:
        ident, seq = struct.unpack("!HH", l4_data[4:8])
        icmp_fields["Identifier"] = ident
        icmp_fields["Sequence Number"] = seq

    layers.append(
        PacketLayer(
            name="ICMPv6 (Internet Control Message Protocol v6)",
            fields=icmp_fields,
            description="Control message protocol for IPv6, replacing IPv4 ARP and IGMP.",
        )
    )
    return summary


def _dissect_tcp(l4_data: bytes, src_ip: str, dst_ip: str, layers: List[PacketLayer], notes: List[str]) -> str:
    src_port, dst_port, seq, ack, offset_reserved, flags, win, tcp_chk, urg = struct.unpack("!HHIIBBHHH", l4_data[:20])
    tcp_hdr_len = (offset_reserved >> 4) * 4
    if tcp_hdr_len < 20 or tcp_hdr_len > len(l4_data):
        tcp_hdr_len = 20

    flag_bits = {
        "URG": bool(flags & 0x20),
        "ACK": bool(flags & 0x10),
        "PSH": bool(flags & 0x08),
        "RST": bool(flags & 0x04),
        "SYN": bool(flags & 0x02),
        "FIN": bool(flags & 0x01),
    }
    active_flags = [k for k, v in flag_bits.items() if v]
    flags_repr = ",".join(active_flags) if active_flags else "None"

    summary = f"TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{flags_repr}] Seq={seq} Ack={ack}"

    layers.append(
        PacketLayer(
            name="TCP (Transmission Control Protocol)",
            fields={
                "Source Port": src_port,
                "Destination Port": dst_port,
                "Sequence Number": seq,
                "Acknowledgment Number": ack,
                "Header Length": f"{tcp_hdr_len} bytes",
                "Flags": flags_repr,
                "Window Size": win,
                "Checksum": f"0x{tcp_chk:04x}",
                "Urgent Pointer": urg,
            },
            description="Connection-oriented, reliable transport layer with byte-stream ordering.",
        )
    )

    if flag_bits.get("SYN") and not flag_bits.get("ACK"):
        notes.append("TCP SYN: client is initiating 3-way handshake.")
    elif flag_bits.get("SYN") and flag_bits.get("ACK"):
        notes.append("TCP SYN-ACK: server acknowledged client and accepted connection.")
    elif flag_bits.get("RST"):
        notes.append("TCP RST: connection aborted or port is closed on remote host.")

    app_data = l4_data[tcp_hdr_len:]
    if app_data:
        app_summary = _dissect_app_layer(app_data, src_port, dst_port, layers, notes)
        if app_summary:
            summary = app_summary

    return summary


def _dissect_udp(l4_data: bytes, src_ip: str, dst_ip: str, layers: List[PacketLayer], notes: List[str]) -> str:
    src_port, dst_port, udp_len, udp_chk = struct.unpack("!HHHH", l4_data[:8])
    summary = f"UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port} Len={udp_len}"

    layers.append(
        PacketLayer(
            name="UDP (User Datagram Protocol)",
            fields={
                "Source Port": src_port,
                "Destination Port": dst_port,
                "Length": udp_len,
                "Checksum": f"0x{udp_chk:04x}",
            },
            description="Lightweight, connectionless transport layer without retransmission overhead.",
        )
    )

    app_data = l4_data[8:udp_len] if 8 <= udp_len <= len(l4_data) else l4_data[8:]
    if app_data:
        app_summary = _dissect_app_layer(app_data, src_port, dst_port, layers, notes)
        if app_summary:
            summary = app_summary

    return summary


def _dissect_app_layer(data: bytes, src_port: int, dst_port: int, layers: List[PacketLayer], notes: List[str]) -> Optional[str]:
    if 53 in (src_port, dst_port) and len(data) >= 12:
        tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
        is_response = bool(flags & 0x8000)
        opcode = (flags >> 11) & 0x0F
        rcode = flags & 0x0F

        dns_fields = {
            "Transaction ID": f"0x{tx_id:04x}",
            "Type": "Response" if is_response else "Query",
            "Opcode": opcode,
            "Questions Count": qdcount,
            "Answer RRs": ancount,
            "Response Code": rcode,
        }

        q_name, offset = parse_dns_name(data, 12)
        qtype_str = "A"
        if q_name:
            dns_fields["Query Domain"] = q_name
            if 12 + offset + 4 <= len(data):
                qtype, qclass = struct.unpack("!HH", data[12 + offset : 12 + offset + 4])
                type_map = {1: "A (IPv4)", 28: "AAAA (IPv6)", 15: "MX", 16: "TXT", 2: "NS", 5: "CNAME"}
                qtype_str = type_map.get(qtype, f"Type {qtype}")
                dns_fields["Query Type"] = qtype_str

        answers_list: List[str] = []
        if is_response and ancount > 0:
            ans_offset = 12 + offset + 4
            for _ in range(min(ancount, 6)):
                if ans_offset >= len(data):
                    break
                _, a_consumed = parse_dns_name(data, ans_offset)
                ans_offset += a_consumed
                if ans_offset + 10 > len(data):
                    break
                a_type, a_cls, a_ttl, a_rdlen = struct.unpack("!HHIH", data[ans_offset : ans_offset + 10])
                ans_offset += 10
                a_rdata = data[ans_offset : ans_offset + a_rdlen]
                ans_offset += a_rdlen
                if a_type == 1 and a_rdlen == 4 and len(a_rdata) == 4:
                    answers_list.append(socket.inet_ntoa(a_rdata))
                elif a_type == 28 and a_rdlen == 16 and len(a_rdata) == 16:
                    answers_list.append(socket.inet_ntop(socket.AF_INET6, a_rdata))
                elif a_type in (2, 5, 12):
                    cname, _ = parse_dns_name(data, ans_offset - a_rdlen)
                    if cname:
                        answers_list.append(cname)

        if answers_list:
            dns_fields["Answers"] = ", ".join(answers_list)

        layers.append(
            PacketLayer(
                name="DNS (Domain Name System)",
                fields=dns_fields,
                description="Translates human-readable domain names into IP addresses (RFC 1035).",
            )
        )
        notes.append("DNS uses UDP for rapid resolution with low latency; falls back to TCP when responses exceed 512 bytes.")

        if is_response:
            ans_text = f" -> {', '.join(answers_list)}" if answers_list else ""
            return f"DNS Response: {q_name or 'domain'}{ans_text}"
        return f"DNS Query: {q_name or 'domain'} ({qtype_str})"

    if 80 in (src_port, dst_port) or 8080 in (src_port, dst_port):
        text = data.decode("utf-8", errors="ignore")
        first_line = text.split("\r\n")[0]
        if any(first_line.startswith(m) for m in ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "HTTP/")):
            headers = {}
            for line in text.split("\r\n")[1:8]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers[k] = v
            layers.append(
                PacketLayer(
                    name="HTTP (Hypertext Transfer Protocol)",
                    fields={"Start Line": first_line, **headers},
                    description="Cleartext application protocol powering the World Wide Web.",
                )
            )
            return f"HTTP {first_line[:45]}"

    if 443 in (src_port, dst_port) or 8443 in (src_port, dst_port):
        if len(data) >= 5 and data[0] == 0x16:
            rec_ver = struct.unpack("!H", data[1:3])[0]
            rec_len = struct.unpack("!H", data[3:5])[0]
            tls_fields = {
                "Record Type": "Handshake (0x16)",
                "TLS Version": f"0x{rec_ver:04x}",
                "Length": f"{rec_len} bytes",
            }
            summary_part = "Handshake"
            if len(data) >= 6 and data[5] == 0x01:
                tls_fields["Handshake Type"] = "Client Hello (0x01)"
                summary_part = "Client Hello"
                notes.append("TLS Client Hello initiates encrypted negotiation, presenting supported ciphersuites and SNI.")
            layers.append(
                PacketLayer(
                    name="TLS (Transport Layer Security)",
                    fields=tls_fields,
                    description="Cryptographic protocol providing end-to-end security and privacy.",
                )
            )
            return f"TLS {summary_part}"

    return None
