import concurrent.futures
import socket
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

WELL_KNOWN_PORTS: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "Microsoft-DS/SMB",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP-Dev",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9090: "Prometheus",
    27017: "MongoDB",
}


@dataclass
class PortScanResult:
    port: int
    service: str
    is_open: bool
    banner: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def parse_port_spec(spec: Optional[str]) -> Optional[List[int]]:
    """Parse ``"80,443,8000-8002"`` into a validated port list.

    Returns ``None`` for an empty/absent spec so callers keep their "default
    port list" behaviour.  Anything that cannot be turned into 1..65535 ports
    raises ``ValueError`` - silently dropping the bad tokens, as the CLI and
    the dashboard used to do, turns ``-p abc`` into a scan of nothing that
    reports "No open ports detected" with exit code 0.
    """
    if spec is None:
        return None
    text = spec.strip()
    if not text:
        return None

    ports: List[int] = []
    for token in text.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            bounds = token.split("-")
            if len(bounds) != 2:
                raise ValueError(f"invalid port range {token!r}")
            try:
                start, end = int(bounds[0]), int(bounds[1])
            except ValueError:
                raise ValueError(f"invalid port range {token!r}") from None
            if start > end:
                raise ValueError(f"invalid port range {token!r}: start is greater than end")
            candidates = range(start, end + 1)
        else:
            try:
                candidates = [int(token)]
            except ValueError:
                raise ValueError(f"invalid port {token!r}") from None
        for port in candidates:
            if not 1 <= port <= 65535:
                raise ValueError(f"port {port} is outside the valid range 1-65535")
            if port not in ports:
                ports.append(port)

    if not ports:
        raise ValueError(f"no valid ports in {spec!r}")
    return ports


def check_port(host: str, port: int, timeout: float = 0.5) -> PortScanResult:
    if not 1 <= port <= 65535:
        raise ValueError(f"port {port} is outside the valid range 1-65535")
    service = WELL_KNOWN_PORTS.get(port, "Unknown")
    banner = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                try:
                    s.settimeout(0.3)
                    s.sendall(b"\r\n")
                    raw = s.recv(128)
                    if raw:
                        banner = raw.decode("utf-8", errors="ignore").strip()
                except Exception:
                    pass
                return PortScanResult(port=port, service=service, is_open=True, banner=banner)
    except Exception:
        pass
    return PortScanResult(port=port, service=service, is_open=False)


def scan_ports(host: str, ports: Optional[List[int]] = None, timeout: float = 0.4, max_threads: int = 20) -> List[PortScanResult]:
    if max_threads < 1:
        raise ValueError(f"max_threads must be >= 1, got {max_threads}")
    if timeout <= 0:
        raise ValueError(f"timeout must be > 0, got {timeout}")
    target_ports = ports if ports is not None else list(WELL_KNOWN_PORTS.keys())
    for port in target_ports:
        if not 1 <= port <= 65535:
            raise ValueError(f"port {port} is outside the valid range 1-65535")
    results: List[PortScanResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(check_port, host, p, timeout): p for p in target_ports}
        for future in concurrent.futures.as_completed(futures):
            try:
                res = future.result()
            except Exception:
                continue
            if res.is_open:
                results.append(res)

    results.sort(key=lambda x: x.port)
    return results
