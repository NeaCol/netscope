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


def check_port(host: str, port: int, timeout: float = 0.5) -> PortScanResult:
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
    target_ports = ports if ports is not None else list(WELL_KNOWN_PORTS.keys())
    results: List[PortScanResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(check_port, host, p, timeout): p for p in target_ports}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res.is_open:
                results.append(res)

    results.sort(key=lambda x: x.port)
    return results
