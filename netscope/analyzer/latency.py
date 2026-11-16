import math
import platform
import re
import shutil
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
            # -W takes whole seconds: round up, otherwise a 1500 ms budget
            # silently became 1 s and probes "timed out" that would have passed.
            cmd = ["ping", "-c", "1", "-W", str(max(1, math.ceil(timeout / 1000))), host]

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


LATENCY_MODES = ("auto", "icmp", "tcp")


def measure_latency(host: str, count: int = 5, interval: float = 0.1, mode: str = "auto") -> LatencyStats:
    if count < 1:
        # count=0 used to report "0 transmitted, 0.0% loss" with no data at all;
        # a negative count reported 100% loss. Both looked like healthy runs.
        raise ValueError(f"count must be at least 1, got {count}")
    if interval < 0:
        raise ValueError(f"interval must be >= 0, got {interval}")
    if mode not in LATENCY_MODES:
        raise ValueError(f"unsupported probe mode {mode!r}; choose one of: {', '.join(LATENCY_MODES)}")

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


@dataclass
class TracerouteReport:
    hops: List[TracerouteHop] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"hops": [h.to_dict() for h in self.hops], "error": self.error}


def run_traceroute_report(target: str, max_hops: int = 20, timeout_per_hop: float = 1.5) -> TracerouteReport:
    """Trace a route and explain *why* it is empty when it is.

    Returning an empty list for "the traceroute binary is not installed" made
    the CLI report "no responsive hops or host unreachable" - a network
    diagnosis for a missing package.
    """
    if max_hops < 1:
        raise ValueError(f"max_hops must be at least 1, got {max_hops}")
    if timeout_per_hop <= 0:
        raise ValueError(f"timeout_per_hop must be > 0, got {timeout_per_hop}")

    hops: List[TracerouteHop] = []
    is_windows = platform.system() == "Windows"
    binary = "tracert" if is_windows else "traceroute"
    if shutil.which(binary) is None:
        return TracerouteReport(hops=[], error=f"{binary} is not installed; install it to use hop-by-hop tracing")

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
    except Exception as exc:  # noqa: BLE001 - reported back to the caller
        return TracerouteReport(hops=hops, error=f"traceroute failed: {exc}")

    return TracerouteReport(hops=hops)


def run_traceroute(target: str, max_hops: int = 20, timeout_per_hop: float = 1.5) -> List[TracerouteHop]:
    return run_traceroute_report(target, max_hops=max_hops, timeout_per_hop=timeout_per_hop).hops
