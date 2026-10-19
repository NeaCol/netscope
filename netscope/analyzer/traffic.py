from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Tuple
from netscope.protocols.dissector import DissectedPacket


@dataclass
class ConversationStats:
    endpoint_a: str
    endpoint_b: str
    packets: int
    bytes_count: int


@dataclass
class TrafficAnalysisReport:
    total_packets: int
    total_bytes: int
    duration_seconds: float
    protocols_breakdown: Dict[str, int]
    top_conversations: List[ConversationStats] = field(default_factory=list)
    packet_size_buckets: Dict[str, int] = field(default_factory=dict)
    tcp_flags_breakdown: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "duration_seconds": round(self.duration_seconds, 3),
            "protocols_breakdown": self.protocols_breakdown,
            "top_conversations": [asdict(c) for c in self.top_conversations],
            "packet_size_buckets": self.packet_size_buckets,
            "tcp_flags_breakdown": self.tcp_flags_breakdown,
        }


def analyze_traffic(packets: List[DissectedPacket]) -> TrafficAnalysisReport:
    if not packets:
        return TrafficAnalysisReport(
            total_packets=0,
            total_bytes=0,
            duration_seconds=0.0,
            protocols_breakdown={},
            top_conversations=[],
            packet_size_buckets={},
            tcp_flags_breakdown={},
        )

    total_bytes = sum(p.length for p in packets)
    timestamps = [p.timestamp for p in packets if p.timestamp > 0]
    duration = (max(timestamps) - min(timestamps)) if len(timestamps) > 1 else 0.0

    proto_counts: Counter[str] = Counter()
    conversations: Dict[Tuple[str, str], Dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0})
    size_buckets = {"< 64 B": 0, "64 - 511 B": 0, "512 - 1023 B": 0, ">= 1024 B": 0}
    tcp_flags: Counter[str] = Counter()

    for p in packets:
        if p.length < 64:
            size_buckets["< 64 B"] += 1
        elif p.length < 512:
            size_buckets["64 - 511 B"] += 1
        elif p.length < 1024:
            size_buckets["512 - 1023 B"] += 1
        else:
            size_buckets[">= 1024 B"] += 1

        src_ip = None
        dst_ip = None

        for layer in p.layers:
            name_base = layer.name.split()[0]
            proto_counts[name_base] += 1

            if "IPv4" in layer.name:
                src_ip = layer.fields.get("Source IP")
                dst_ip = layer.fields.get("Destination IP")
            elif "IPv6" in layer.name:
                src_ip = layer.fields.get("Source IPv6")
                dst_ip = layer.fields.get("Destination IPv6")
            elif "ARP" in layer.name:
                src_ip = layer.fields.get("Sender IP")
                dst_ip = layer.fields.get("Target IP")
            elif "TCP" in layer.name:
                flags_str = str(layer.fields.get("Flags", ""))
                for flag in ("SYN", "ACK", "FIN", "RST", "PSH", "URG"):
                    if flag in flags_str:
                        tcp_flags[flag] += 1

        if src_ip and dst_ip:
            pair = tuple(sorted([src_ip, dst_ip]))
            conversations[pair]["packets"] += 1
            conversations[pair]["bytes"] += p.length

    top_convos = []
    for (a, b), data in sorted(conversations.items(), key=lambda x: x[1]["bytes"], reverse=True)[:5]:
        top_convos.append(
            ConversationStats(
                endpoint_a=a,
                endpoint_b=b,
                packets=data["packets"],
                bytes_count=data["bytes"],
            )
        )

    return TrafficAnalysisReport(
        total_packets=len(packets),
        total_bytes=total_bytes,
        duration_seconds=duration,
        protocols_breakdown=dict(proto_counts),
        top_conversations=top_convos,
        packet_size_buckets=size_buckets,
        tcp_flags_breakdown=dict(tcp_flags),
    )
