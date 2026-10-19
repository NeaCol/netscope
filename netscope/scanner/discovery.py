import concurrent.futures
import ipaddress
import platform
import re
import socket
import subprocess
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
from netscope.scanner.interfaces import get_default_gateway_and_ip, get_primary_interface

OUI_PREFIXES: Dict[str, str] = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:05:69": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU/KVM",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "28:CD:C1": "Raspberry Pi Foundation",
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "F4:F5:D8": "Google",
    "00:17:88": "Philips Lighting",
    "EC:FA:BC": "Espressif Inc.",
    "24:0A:C4": "Espressif Inc.",
    "30:AE:A4": "Espressif Inc.",
    "00:1E:C2": "Apple",
    "F0:18:98": "Apple",
    "AC:DE:48": "Apple",
    "F4:D4:88": "Apple",
    "BC:D0:74": "Apple",
    "00:14:22": "Dell",
    "F8:DB:88": "Dell",
    "00:25:90": "Supermicro",
    "00:1B:21": "Intel",
    "A4:4C:C8": "Intel",
    "00:04:96": "Extreme Networks",
    "00:1F:6D": "Cisco",
    "00:26:0B": "Cisco",
    "00:1E:58": "D-Link",
    "14:D6:4D": "D-Link",
    "00:18:4D": "Netgear",
    "2C:30:33": "Netgear",
    "50:C7:BF": "TP-Link",
    "E8:48:B8": "TP-Link",
    "98:DA:C4": "TP-Link",
    "00:1A:2B": "ASUSTek",
    "04:D9:F5": "ASUSTek",
    "74:D0:2B": "ASUSTek",
    "F0:9F:C2": "Ubiquiti Networks",
    "78:8A:20": "Ubiquiti Networks",
    "24:A4:3C": "Ubiquiti Networks",
    "00:15:5D": "Microsoft Hyper-V",
    "DC:F5:05": "Amazon Technologies",
    "44:65:0D": "Amazon Technologies",
}


@dataclass
class DiscoveredHost:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: str = "Unknown"
    is_gateway: bool = False
    is_local: bool = False
    response_time_ms: float = 0.0
    status: str = "online"
    open_ports: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def lookup_vendor(mac: Optional[str]) -> str:
    if not mac:
        return "Unknown"
    cleaned = mac.upper().replace("-", ":")
    prefix = ":".join(cleaned.split(":")[:3])
    return OUI_PREFIXES.get(prefix, "Standard Network Device")


def read_system_arp_table() -> Dict[str, str]:
    table: Dict[str, str] = {}
    try:
        cmd = ["arp", "-a"]
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=4)
        for line in out.splitlines():
            line = line.strip()
            match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F[:-]{17})", line)
            if match:
                ip_found = match.group(1)
                mac_found = match.group(2).replace("-", ":").upper()
                if not mac_found.startswith("FF:FF:FF") and not ip_found.startswith("224.") and not ip_found.endswith(".255"):
                    table[ip_found] = mac_found
    except Exception:
        pass
    return table


def probe_single_host(ip: str, timeout: float = 0.25) -> tuple[str, bool, float]:
    start = time.perf_counter()
    target_ports = [80, 443, 22, 445, 135, 53, 8080]
    for port in target_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                res = s.connect_ex((ip, port))
                if res == 0:
                    elapsed = (time.perf_counter() - start) * 1000.0
                    return ip, True, elapsed
        except Exception:
            continue
    elapsed = (time.perf_counter() - start) * 1000.0
    return ip, False, elapsed


def resolve_hostname(ip: str) -> Optional[str]:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None


def scan_subnet(cidr: Optional[str] = None, max_threads: int = 40, timeout: float = 0.3) -> List[DiscoveredHost]:
    gateway_ip, local_ip = get_default_gateway_and_ip()
    primary = get_primary_interface()

    if not cidr and primary and primary.cidr:
        cidr = primary.cidr
    elif not cidr and local_ip:
        octets = local_ip.split(".")
        cidr = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    elif not cidr:
        cidr = "192.168.1.0/24"

    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        network = ipaddress.IPv4Network("192.168.1.0/24")

    arp_table = read_system_arp_table()
    hosts_to_probe: List[str] = []

    for host in network.hosts():
        ip_str = str(host)
        hosts_to_probe.append(ip_str)
        if len(hosts_to_probe) >= 254:
            break

    active_ips: Dict[str, float] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(probe_single_host, ip, timeout): ip for ip in hosts_to_probe}
        for future in concurrent.futures.as_completed(futures):
            ip, is_alive, rtt = future.result()
            if is_alive:
                active_ips[ip] = rtt

    for ip in arp_table.keys():
        try:
            if ipaddress.IPv4Address(ip) in network and ip not in active_ips:
                active_ips[ip] = 1.0
        except ValueError:
            pass

    if local_ip and local_ip not in active_ips:
        active_ips[local_ip] = 0.1
    if gateway_ip and gateway_ip not in active_ips:
        active_ips[gateway_ip] = 1.2

    results: List[DiscoveredHost] = []

    for ip, rtt in sorted(active_ips.items(), key=lambda x: ipaddress.IPv4Address(x[0])):
        mac = arp_table.get(ip)
        if not mac and ip == local_ip and primary:
            mac = primary.mac

        vendor = lookup_vendor(mac)
        is_gw = bool(gateway_ip and ip == gateway_ip)
        is_loc = bool(local_ip and ip == local_ip)
        hostname = resolve_hostname(ip)

        results.append(
            DiscoveredHost(
                ip=ip,
                mac=mac,
                hostname=hostname,
                vendor=vendor,
                is_gateway=is_gw,
                is_local=is_loc,
                response_time_ms=round(rtt, 2),
                status="online",
            )
        )

    return results
