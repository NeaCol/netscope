import concurrent.futures
import secrets
import socket
import struct
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple
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

# RFC 1035 4.1.1: labels are limited to 63 octets and the whole encoded name
# (including length bytes and the root terminator) to 255.
MAX_LABEL_LENGTH = 63
MAX_NAME_LENGTH = 255

DNS_RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
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


def _encode_label(label: str) -> bytes:
    """Encode one DNS label, validating the wire limits instead of overflowing."""
    try:
        raw = label.encode("ascii")
    except UnicodeEncodeError:
        try:
            raw = label.encode("idna")
        except UnicodeError as exc:
            raise ValueError(f"label {label!r} cannot be encoded as IDNA: {exc}") from None
    if not raw:
        raise ValueError("domain contains an empty label")
    if len(raw) > MAX_LABEL_LENGTH:
        raise ValueError(
            f"label {label!r} is {len(raw)} bytes; RFC 1035 limits a label to {MAX_LABEL_LENGTH} bytes"
        )
    return raw


def encode_dns_query(domain: str, qtype_int: int = 1, tx_id: int = 0x1A2B) -> bytes:
    """Build a single-question DNS query packet.

    Raises ``ValueError`` for names that cannot be represented on the wire:
    a 64+ byte label used to be encoded with its own length as the label
    length byte, producing a malformed packet that servers answer with
    FORMERR (or drop).
    """
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("domain must be a non-empty string")
    if not 0 <= tx_id <= 0xFFFF:
        raise ValueError(f"transaction id {tx_id} is outside the 16-bit range")

    labels = domain.strip().strip(".").split(".")
    qname = b""
    for part in labels:
        encoded = _encode_label(part)
        qname += bytes([len(encoded)]) + encoded
    qname += b"\x00"
    if len(qname) > MAX_NAME_LENGTH:
        raise ValueError(
            f"domain {domain!r} encodes to {len(qname)} bytes; RFC 1035 limits a name to {MAX_NAME_LENGTH} bytes"
        )

    header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    qtype_class = struct.pack("!HH", qtype_int, 1)
    return header + qname + qtype_class


@dataclass
class DnsMessage:
    """Header fields that decide whether a datagram answers the question we asked."""

    tx_id: int
    is_response: bool
    opcode: int
    rcode: int
    question_count: int
    answer_count: int
    answers: List[DnsAnswerRecord] = field(default_factory=list)

    @property
    def rcode_name(self) -> str:
        return DNS_RCODE_NAMES.get(self.rcode, f"RCODE{self.rcode}")


def parse_dns_message(data: bytes) -> Optional[DnsMessage]:
    """Parse a DNS message header plus its answer section (``None`` if truncated)."""
    if len(data) < 12:
        return None
    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    message = DnsMessage(
        tx_id=tx_id,
        is_response=bool(flags & 0x8000),
        opcode=(flags >> 11) & 0x0F,
        rcode=flags & 0x0F,
        question_count=qdcount,
        answer_count=ancount,
    )
    message.answers = _parse_answers(data, qdcount, ancount)
    return message


def _parse_answers(data: bytes, qdcount: int, ancount: int) -> List[DnsAnswerRecord]:
    offset = 12
    for _ in range(qdcount):
        _, bytes_consumed = parse_dns_name(data, offset)
        offset += bytes_consumed + 4
    if offset > len(data):
        return []

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


def parse_dns_response(data: bytes, expected_type_str: str = "A") -> List[DnsAnswerRecord]:
    """Return the answer records of a response.

    ``expected_type_str`` records which type was asked for; CNAME chains are
    kept in the answer list because they are part of the resolution path.
    Callers that need the response code (NXDOMAIN, SERVFAIL...) must use
    :func:`parse_dns_message`.
    """
    message = parse_dns_message(data)
    if message is None:
        return []
    return message.answers


def _receive_matching_response(sock: socket.socket, tx_id: int, deadline: float) -> Tuple[bytes, float]:
    """Wait for a datagram that actually answers *our* query.

    UDP sockets hand over whatever arrives: a late reply to an earlier query,
    a spoofed packet, or the resolver echoing our own query back.  Accepting
    the first datagram is how a query can report answers for a name it never
    asked about, so mismatched datagrams are dropped until the deadline.
    """
    start = time.perf_counter()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("no matching DNS response before the deadline")
        sock.settimeout(remaining)
        datagram, _ = sock.recvfrom(4096)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        if len(datagram) < 12:
            continue
        resp_tx_id, flags = struct.unpack("!HH", datagram[:4])
        if resp_tx_id != tx_id or not flags & 0x8000:
            continue
        return datagram, elapsed_ms


def query_dns(
    domain: str,
    record_type: str = "A",
    server: str = "1.1.1.1",
    timeout: float = 2.0,
    port: int = 53,
) -> DnsQueryResult:
    if timeout <= 0:
        raise ValueError(f"timeout must be > 0, got {timeout}")
    if not 1 <= port <= 65535:
        raise ValueError(f"port {port} is outside the valid range 1-65535")
    record_type = record_type.upper()
    if record_type not in DNS_RECORD_TYPES:
        valid = ", ".join(sorted(DNS_RECORD_TYPES))
        raise ValueError(f"unsupported DNS record type {record_type!r}; choose one of: {valid}")

    rtype_int = DNS_RECORD_TYPES[record_type]
    tx_id = secrets.randbits(16)
    query_bytes = encode_dns_query(domain, rtype_int, tx_id=tx_id)

    start = time.perf_counter()
    answers: List[DnsAnswerRecord] = []
    error_msg = None
    status = "NOERROR"
    rtt = 0.0

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(query_bytes, (server, port))
            resp_bytes, rtt = _receive_matching_response(s, tx_id, time.monotonic() + timeout)
            message = parse_dns_message(resp_bytes) if resp_bytes else None
            if message is None:
                status = "ERROR"
                error_msg = "truncated DNS response (shorter than a 12-byte header)"
            else:
                answers = message.answers
                status = message.rcode_name
                if message.rcode != 0:
                    error_msg = f"resolver {server} answered {message.rcode_name}"
    except socket.timeout:
        rtt = (time.perf_counter() - start) * 1000.0
        status = "TIMEOUT"
        error_msg = f"DNS query timed out after {timeout}s (no matching response from {server})"
    except Exception as e:
        rtt = (time.perf_counter() - start) * 1000.0
        status = "ERROR"
        error_msg = str(e)

    return DnsQueryResult(
        domain=domain,
        record_type=record_type,
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
