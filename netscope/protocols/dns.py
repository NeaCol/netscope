import concurrent.futures
import socket
import struct
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
from netscope.protocols.dissector import parse_dns_name

DNS_RECORD_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}

WELL_KNOWN_RESOLVERS = {
    "Cloudflare": "1.1.1.1",
    "Google": "8.8.8.8",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
}


@dataclass
class DnsAnswerRecord:
    name: str
    record_type: str
    ttl: int
    data: str


@dataclass
class DnsQueryResult:
    domain: str
    record_type: str
    server: str
    response_time_ms: float
    answers: List[DnsAnswerRecord] = field(default_factory=list)
    status: str = "NOERROR"
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "record_type": self.record_type,
            "server": self.server,
            "response_time_ms": round(self.response_time_ms, 2),
            "answers": [asdict(a) for a in self.answers],
            "status": self.status,
            "error_message": self.error_message,
        }


@dataclass
class DnsBenchmarkEntry:
    provider: str
    server: str
    latency_ms: float
    status: str
    answers_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "server": self.server,
            "latency_ms": round(self.latency_ms, 2),
            "status": self.status,
            "answers_count": self.answers_count,
        }


def encode_dns_query(domain: str, qtype_int: int = 1) -> bytes:
    tx_id = 0x1A2B
    flags = 0x0100
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)

    qname = b""
    for part in domain.strip(".").split("."):
        encoded = part.encode("utf-8")
        qname += bytes([len(encoded)]) + encoded
    qname += b"\x00"

    qtype_class = struct.pack("!HH", qtype_int, 1)
    return header + qname + qtype_class


def parse_dns_response(data: bytes, expected_type_str: str) -> List[DnsAnswerRecord]:
    if len(data) < 12:
        return []

    flags, qdcount, ancount = struct.unpack("!HHH", data[2:8])
    rcode = flags & 0x0F
    if rcode != 0:
        return []

    offset = 12
    for _ in range(qdcount):
        _, bytes_consumed = parse_dns_name(data, offset)
        offset += bytes_consumed + 4

    type_map_rev = {v: k for k, v in DNS_RECORD_TYPES.items()}
    answers: List[DnsAnswerRecord] = []

    for _ in range(ancount):
        if offset >= len(data):
            break
        name, consumed = parse_dns_name(data, offset)
        offset += consumed
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata_raw = data[offset : offset + rdlength]
        offset += rdlength

        rtype_str = type_map_rev.get(rtype, f"TYPE_{rtype}")
        val_str = ""

        if rtype == 1 and rdlength == 4:
            val_str = socket.inet_ntoa(rdata_raw)
        elif rtype == 28 and rdlength == 16:
            val_str = socket.inet_ntop(socket.AF_INET6, rdata_raw)
        elif rtype in (2, 5, 12):
            val_str, _ = parse_dns_name(data, offset - rdlength)
        elif rtype == 15 and rdlength > 2:
            pref = struct.unpack("!H", rdata_raw[:2])[0]
            mx_name, _ = parse_dns_name(data, offset - rdlength + 2)
            val_str = f"{pref} {mx_name}"
        elif rtype == 16:
            txt_parts = []
            txt_offset = 0
            while txt_offset < len(rdata_raw):
                t_len = rdata_raw[txt_offset]
                txt_offset += 1
                txt_parts.append(rdata_raw[txt_offset : txt_offset + t_len].decode("utf-8", errors="replace"))
                txt_offset += t_len
            val_str = '"' + " ".join(txt_parts) + '"'
        else:
            val_str = rdata_raw.hex()

        answers.append(DnsAnswerRecord(name=name, record_type=rtype_str, ttl=ttl, data=val_str))

    return answers


def query_dns(domain: str, record_type: str = "A", server: str = "1.1.1.1", timeout: float = 2.0) -> DnsQueryResult:
    rtype_int = DNS_RECORD_TYPES.get(record_type.upper(), 1)
    query_bytes = encode_dns_query(domain, rtype_int)

    start = time.perf_counter()
    answers: List[DnsAnswerRecord] = []
    error_msg = None
    status = "NOERROR"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(query_bytes, (server, 53))
            resp_bytes, _ = s.recvfrom(2048)
            rtt = (time.perf_counter() - start) * 1000.0
            answers = parse_dns_response(resp_bytes, record_type)
    except socket.timeout:
        rtt = (time.perf_counter() - start) * 1000.0
        status = "TIMEOUT"
        error_msg = f"DNS query timed out after {timeout}s"
    except Exception as e:
        rtt = (time.perf_counter() - start) * 1000.0
        status = "ERROR"
        error_msg = str(e)

    if not answers and status == "NOERROR" and record_type.upper() in ("A", "AAAA"):
        try:
            family = socket.AF_INET if record_type.upper() == "A" else socket.AF_INET6
            res = socket.getaddrinfo(domain, None, family=family)
            for item in res:
                addr = item[4][0]
                answers.append(DnsAnswerRecord(name=domain, record_type=record_type.upper(), ttl=300, data=addr))
        except Exception:
            pass

    return DnsQueryResult(
        domain=domain,
        record_type=record_type.upper(),
        server=server,
        response_time_ms=rtt,
        answers=answers,
        status=status,
        error_message=error_msg,
    )


def benchmark_resolvers(domain: str = "cloudflare.com", timeout: float = 1.5) -> List[DnsBenchmarkEntry]:
    targets = dict(WELL_KNOWN_RESOLVERS)
    results: List[DnsBenchmarkEntry] = []

    def _test(provider: str, ip: str) -> DnsBenchmarkEntry:
        res = query_dns(domain, "A", server=ip, timeout=timeout)
        return DnsBenchmarkEntry(
            provider=provider,
            server=ip,
            latency_ms=res.response_time_ms,
            status=res.status,
            answers_count=len(res.answers),
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(targets)) as executor:
        futures = [executor.submit(_test, name, ip) for name, ip in targets.items()]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: (x.status != "NOERROR", x.latency_ms))
    return results
