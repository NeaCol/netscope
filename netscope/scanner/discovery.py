import concurrent.futures
import ipaddress
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
    "2C:EC:F7": "Apple",
    "44:D8:78": "Apple",
    "3C:22:FB": "Apple",
    "A4:83:E7": "Apple",
    "68:FE:F7": "Apple",
    "18:65:90": "Apple",
    "AC:BC:32": "Apple",
    "D8:57:EF": "Samsung",
    "50:01:D9": "Samsung",
    "00:12:FB": "Samsung",
    "34:23:87": "Samsung",
    "88:36:5F": "Samsung",
    "64:1C:AE": "Samsung",
    "28:56:3A": "Xiaomi / Tuya",
    "78:11:DC": "Xiaomi",
    "64:90:C1": "Xiaomi",
    "50:EC:50": "Xiaomi",
    "60:45:E8": "Espressif Inc.",
    "24:62:AB": "Espressif Inc.",
    "84:F3:EB": "Espressif Inc.",
    "EC:62:60": "Espressif Inc.",
    "48:55:19": "Espressif Inc.",
    "00:E0:4C": "Realtek",
    "54:EE:75": "Realtek",
    "00:26:18": "Realtek",
    "00:1B:78": "HP",
    "3C:D9:2B": "HP",
    "9C:8E:99": "HP",
    "00:1E:10": "Huawei",
    "00:25:9E": "Huawei",
    "00:46:4B": "Huawei",
    "70:72:0D": "Huawei",
    "00:04:1F": "Sony",
    "00:13:A9": "Sony",
    "F8:46:1C": "Sony",
    "00:1C:62": "LG Electronics",
    "00:1F:6B": "LG Electronics",
    "00:14:22": "Dell",
    "F8:DB:88": "Dell",
    "00:25:90": "Supermicro",
    "00:1B:21": "Intel",
    "A4:4C:C8": "Intel",
    "00:1E:67": "Intel",
    "00:15:00": "Intel",
    "34:13:E8": "Intel",
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


ARP_FIELD_SEPARATOR = re.compile(r"\s+")


def normalize_mac(raw: Optional[str]) -> Optional[str]:
    """Normalize any platform's MAC spelling to ``AA:BB:CC:DD:EE:FF``.

    ``arp -a`` on macOS/BSD prints single-digit octets (``0:1f:6d:9a:33:54``),
    Windows prints dash-separated octets and Cisco gear prints
    ``001f.6d9a.3354``.  All of them describe the same 48-bit address, so they
    must reach the OUI table in one canonical form - otherwise vendor lookups
    and de-duplication silently miss every host.
    """
    if not raw:
        return None
    candidate = raw.strip().lower().replace("-", ":")

    if "." in candidate and ":" not in candidate:
        groups = candidate.split(".")
        if len(groups) != 3 or any(len(g) != 4 for g in groups):
            return None
        candidate = ":".join(
            [groups[0][0:2], groups[0][2:4], groups[1][0:2], groups[1][2:4], groups[2][0:2], groups[2][2:4]]
        )

    octets = candidate.split(":")
    if len(octets) != 6:
        return None
    normalized = []
    for octet in octets:
        if not octet or len(octet) > 2 or not all(c in "0123456789abcdef" for c in octet):
            return None
        normalized.append(octet.zfill(2).upper())
    return ":".join(normalized)


def lookup_vendor(mac: Optional[str]) -> str:
    normalized = normalize_mac(mac)
    if not normalized:
        return "Unknown"
    prefix = ":".join(normalized.split(":")[:3])
    return OUI_PREFIXES.get(prefix, "Standard Network Device")


def _is_usable_ipv4(ip: str) -> bool:
    """Filter out addresses that can never be a LAN peer worth reporting."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    if addr.is_multicast or addr.is_loopback or addr.is_link_local or addr.is_unspecified or addr.is_reserved:
        return False
    if addr == ipaddress.IPv4Address("255.255.255.255") or ip.endswith(".255"):
        return False
    return True


def _is_usable_mac(mac: str) -> bool:
    return not (mac.startswith("FF:FF:FF") or mac.startswith("01:00:5E") or mac.startswith("33:33"))


def _parse_arp_command_output(text: str) -> Dict[str, str]:
    """Parse ``arp -a`` output in its net-tools, BSD/macOS and Windows shapes."""
    table: Dict[str, str] = {}
    mac_pattern = re.compile(r"\b[0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5}\b|\b[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\b")
    ip_pattern = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")

    for line in text.splitlines():
        ip_match = ip_pattern.search(line)
        mac_match = mac_pattern.search(line)
        if not ip_match or not mac_match:
            continue
        ip = ip_match.group(1)
        mac = normalize_mac(mac_match.group(0))
        if not mac or not _is_usable_ipv4(ip) or not _is_usable_mac(mac):
            continue
        table[ip] = mac
    return table


def _parse_proc_net_arp(text: str) -> Dict[str, str]:
    """Parse ``/proc/net/arp`` (available on every Linux box, net-tools or not)."""
    table: Dict[str, str] = {}
    for line in text.splitlines()[1:]:
        fields = ARP_FIELD_SEPARATOR.split(line.strip())
        if len(fields) < 4:
            continue
        ip, flags, mac = fields[0], fields[2], normalize_mac(fields[3])
        # flags 0x2 == ATF_COM (complete entry); 0x0 means resolution failed.
        if mac and flags not in ("0x0", "0x00") and _is_usable_ipv4(ip) and _is_usable_mac(mac):
            table[ip] = mac
    return table


def _parse_ip_neigh_output(text: str) -> Dict[str, str]:
    """Parse ``ip neigh show`` output (iproute2, the default on modern Linux)."""
    table: Dict[str, str] = {}
    for line in text.splitlines():
        fields = ARP_FIELD_SEPARATOR.split(line.strip())
        if len(fields) < 4 or "lladdr" not in fields:
            continue
        ip = fields[0]
        mac = normalize_mac(fields[fields.index("lladdr") + 1])
        state = fields[-1].upper()
        if state in ("FAILED", "INCOMPLETE"):
            continue
        if mac and _is_usable_ipv4(ip) and _is_usable_mac(mac):
            table[ip] = mac
    return table


def read_system_arp_table() -> Dict[str, str]:
    """Read the neighbor table, falling back across the three platform sources.

    ``arp`` comes from net-tools, which modern Linux distributions no longer
    install by default, so a missing binary used to make neighbor discovery
    report an empty LAN.  ``/proc/net/arp`` and ``ip neigh show`` cover that
    case without adding a dependency.
    """
    parsers = (
        (["arp", "-a"], _parse_arp_command_output),
        (["ip", "neigh", "show"], _parse_ip_neigh_output),
    )
    for cmd, parser in parsers:
        try:
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=4)
        except (OSError, subprocess.SubprocessError):
            continue
        table = parser(out)
        if table:
            return table

    try:
        with open("/proc/net/arp", "r", encoding="utf-8") as handle:
            table = _parse_proc_net_arp(handle.read())
            if table:
                return table
    except OSError:
        pass
    return {}


def probe_single_host(ip: str, timeout: float = 0.15) -> tuple[str, bool, float]:
    start = time.perf_counter()
    target_ports = [80, 445, 135, 443]
    for port in target_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                res = s.connect_ex((ip, port))
                if res in (0, 10061, 111):
                    elapsed = (time.perf_counter() - start) * 1000.0
                    return ip, True, elapsed
        except Exception:
            continue
    elapsed = (time.perf_counter() - start) * 1000.0
    return ip, False, elapsed


def resolve_hostnames(ips: List[str], timeout: float = 0.6, max_workers: int = 20) -> Dict[str, Optional[str]]:
    """Reverse-resolve ``ips`` with a *real* deadline.

    The previous per-IP ``with ThreadPoolExecutor(...)`` helper looked bounded
    but was not: ``future.result(timeout=...)`` raises on time, and then the
    ``with`` block calls ``shutdown(wait=True)`` which blocks until the
    lookup finishes anyway.  A dead reverse zone therefore stalled a scan for
    as long as the resolver wanted.  One shared pool plus ``wait(timeout)``
    returns at the deadline and leaves the orphaned lookups to die on their
    own (``shutdown(wait=False, cancel_futures=True)``).
    """
    results: Dict[str, Optional[str]] = {ip: None for ip in ips}
    if not ips:
        return results

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(ips))))
    futures = {pool.submit(socket.gethostbyaddr, ip): ip for ip in ips}
    try:
        done, pending = concurrent.futures.wait(futures, timeout=max(0.0, timeout))
        for future in pending:
            future.cancel()
        for future in done:
            ip = futures[future]
            try:
                results[ip] = future.result()[0]
            except Exception:
                results[ip] = None
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return results


def resolve_hostname(ip: str, timeout: float = 0.6) -> Optional[str]:
    return resolve_hostnames([ip], timeout=timeout).get(ip)


def scan_subnet(cidr: Optional[str] = None, max_threads: int = 40, timeout: float = 0.15) -> List[DiscoveredHost]:
    if max_threads < 1:
        raise ValueError(f"max_threads must be >= 1, got {max_threads}")
    if timeout <= 0:
        raise ValueError(f"timeout must be > 0, got {timeout}")

    explicit_cidr = cidr is not None
    gateway_ip, local_ip = get_default_gateway_and_ip()
    primary = get_primary_interface()

    if not cidr and primary and primary.cidr:
        cidr = primary.cidr
    elif not cidr and local_ip:
        octets = local_ip.split(".")
        cidr = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    elif not cidr:
        cidr = "192.168.1.0/24"

    if explicit_cidr:
        # A caller-supplied subnet must never be silently replaced by
        # 192.168.1.0/24: the scan would return another network's hosts while
        # reporting them as the requested one.
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid subnet {cidr!r}: {exc}") from None
    else:
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            network = ipaddress.IPv4Network("192.168.1.0/24")

    arp_table = read_system_arp_table()
    hosts_to_probe: List[str] = []

    if network.num_addresses > 256 and local_ip:
        try:
            local_addr = ipaddress.IPv4Address(local_ip)
            if local_addr in network:
                octs = local_ip.split(".")
                slice_net = ipaddress.IPv4Network(f"{octs[0]}.{octs[1]}.{octs[2]}.0/24", strict=False)
                for h in slice_net.hosts():
                    hosts_to_probe.append(str(h))
        except ValueError:
            pass

    if not hosts_to_probe:
        for host in network.hosts():
            hosts_to_probe.append(str(host))
            if len(hosts_to_probe) >= 254:
                break

    active_ips: Dict[str, float] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(probe_single_host, ip, timeout): ip for ip in hosts_to_probe}
        for future in concurrent.futures.as_completed(futures):
            try:
                ip, is_alive, rtt = future.result()
            except Exception:
                continue
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

    hostnames: Dict[str, Optional[str]] = resolve_hostnames(list(active_ips.keys()), timeout=0.6)

    results: List[DiscoveredHost] = []

    for ip, rtt in sorted(active_ips.items(), key=lambda x: ipaddress.IPv4Address(x[0])):
        mac = arp_table.get(ip)
        if not mac and ip == local_ip and primary:
            mac = primary.mac

        vendor = lookup_vendor(mac)
        is_gw = bool(gateway_ip and ip == gateway_ip)
        is_loc = bool(local_ip and ip == local_ip)
        hostname = hostnames.get(ip)

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
