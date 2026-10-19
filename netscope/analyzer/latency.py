import math
import platform
import re
import socket
import statistics
import subprocess
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class LatencyStats:
    target: str
    sent: int
    received: int
    packet_loss_pct: float
    min_ms: float
    avg_ms: float
    max_ms: float
    stddev_ms: float
    jitter_ms: float
    samples: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "sent": self.sent,
            "received": self.received,
            "packet_loss_pct": round(self.packet_loss_pct, 2),
            "min_ms": round(self.min_ms, 2),
            "avg_ms": round(self.avg_ms, 2),
            "max_ms": round(self.max_ms, 2),
            "stddev_ms": round(self.stddev_ms, 2),
            "jitter_ms": round(self.jitter_ms, 2),
            "samples": [round(s, 2) for s in self.samples],
        }


@dataclass
class TracerouteHop:
    hop: int
    ip: Optional[str]
    hostname: Optional[str]
    rtt_ms: Optional[float]
    status: str = "active"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def calculate_jitter(samples: List[float]) -> float:
    if len(samples) < 2:
        return 0.0
    differences = [abs(samples[i] - samples[i - 1]) for i in range(1, len(samples))]
    return sum(differences) / len(differences)


def tcp_ping_single(host: str, port: int = 80, timeout: float = 1.0) -> Optional[float]:
    start = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((host, port))
            if res in (0, 10061, 111):
                return (time.perf_counter() - start) * 1000.0
    except Exception:
        pass
    return None


def icmp_ping_single(host: str, timeout: int = 1000) -> Optional[float]:
    try:
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout / 1000))), host]

        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=(timeout / 1000) + 1.0)
        if re.search(r"(?:time|tiempo)\s*<\s*1\s*m?s?", out, re.IGNORECASE):
            return 0.5
        match = re.search(r"(?:time|tiempo)\s*[=:]\s*(\d+(?:\.\d+)?)\s*m?s?", out, re.IGNORECASE)
        if match:
            return float(match.group(1))
        avg_match = re.search(r"(?:Media|Average|Promedio)\s*=\s*(\d+(?:\.\d+)?)\s*m?s?", out, re.IGNORECASE)
        if avg_match:
            return float(avg_match.group(1))
    except Exception:
        pass
    return None


def measure_latency(host: str, count: int = 5, interval: float = 0.1, mode: str = "auto") -> LatencyStats:
    samples: List[float] = []

    for i in range(count):
        rtt = None
        if mode in ("auto", "icmp"):
            rtt = icmp_ping_single(host)
        if rtt is None and mode in ("auto", "tcp"):
            for p in (80, 443, 53, 22):
                rtt = tcp_ping_single(host, p)
                if rtt is not None:
                    break

        if rtt is not None:
            samples.append(rtt)

        if i < count - 1 and interval > 0:
            time.sleep(interval)

    received = len(samples)
    loss = ((count - received) / count) * 100.0 if count > 0 else 0.0

    if samples:
        min_v = min(samples)
        max_v = max(samples)
        avg_v = sum(samples) / len(samples)
        stddev_v = statistics.stdev(samples) if len(samples) > 1 else 0.0
        jitter_v = calculate_jitter(samples)
    else:
        min_v = max_v = avg_v = stddev_v = jitter_v = 0.0

    return LatencyStats(
        target=host,
        sent=count,
        received=received,
        packet_loss_pct=loss,
        min_ms=min_v,
        avg_ms=avg_v,
        max_ms=max_v,
        stddev_ms=stddev_v,
        jitter_ms=jitter_v,
        samples=samples,
    )


def run_traceroute(target: str, max_hops: int = 20, timeout_per_hop: float = 1.5) -> List[TracerouteHop]:
    hops: List[TracerouteHop] = []
    is_windows = platform.system() == "Windows"

    try:
        if is_windows:
            cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(int(timeout_per_hop * 1000)), target]
        else:
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(int(timeout_per_hop)), target]

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            out, _ = proc.communicate(timeout=max_hops * timeout_per_hop + 5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()

        for line in out.splitlines():
            line = line.strip()
            match = re.match(r"^(\d+)\s+(.+)$", line)
            if not match:
                continue

            hop_num = int(match.group(1))
            rest = match.group(2)

            ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", rest)
            ip_val = ip_match.group(1) if ip_match else None

            time_matches = re.findall(r"(\d+(?:\.\d+)?)\s*ms", rest)
            rtt_val = float(time_matches[0]) if time_matches else None

            status = "active" if ip_val else "timeout"

            hops.append(
                TracerouteHop(
                    hop=hop_num,
                    ip=ip_val,
                    hostname=None,
                    rtt_ms=rtt_val,
                    status=status,
                )
            )
            if ip_val and ip_val == target:
                break
    except Exception:
        pass

    return hops
