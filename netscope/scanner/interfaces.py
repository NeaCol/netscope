import ipaddress
import platform
import socket
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
import psutil


@dataclass
class InterfaceAddress:
    family: str
    address: str
    netmask: Optional[str] = None
    broadcast: Optional[str] = None
    ptp: Optional[str] = None


@dataclass
class NetworkInterface:
    name: str
    is_up: bool
    speed: int
    mtu: int
    addresses: List[InterfaceAddress] = field(default_factory=list)
    mac: Optional[str] = None
    ipv4: Optional[str] = None
    ipv4_netmask: Optional[str] = None
    ipv6: Optional[str] = None
    cidr: Optional[str] = None
    is_loopback: bool = False
    is_default: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def get_default_gateway_and_ip() -> tuple[Optional[str], Optional[str]]:
    local_ip = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
    except Exception:
        local_ip = None

    gateway = None
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(
                ["route", "print", "0.0.0.0"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gateway = parts[2]
                    break
        else:
            out = subprocess.check_output(
                ["ip", "route", "show", "default"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
            parts = out.strip().split()
            if "via" in parts:
                gateway = parts[parts.index("via") + 1]
    except Exception:
        gateway = None

    return gateway, local_ip


def list_interfaces() -> List[NetworkInterface]:
    gateway, active_ip = get_default_gateway_and_ip()
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    results: List[NetworkInterface] = []

    for name, addr_list in addrs.items():
        stat = stats.get(name)
        is_up = stat.isup if stat else False
        speed = stat.speed if stat else 0
        mtu = stat.mtu if stat else 0

        nic = NetworkInterface(name=name, is_up=is_up, speed=speed, mtu=mtu)

        for addr in addr_list:
            family_name = str(addr.family.name if hasattr(addr.family, "name") else addr.family)
            nic.addresses.append(
                InterfaceAddress(
                    family=family_name,
                    address=addr.address,
                    netmask=addr.netmask,
                    broadcast=addr.broadcast,
                    ptp=addr.ptp,
                )
            )

            if getattr(addr.family, "name", None) == "AF_LINK" or addr.family == psutil.AF_LINK:
                nic.mac = addr.address
            elif getattr(addr.family, "name", None) == "AF_INET" or addr.family == socket.AF_INET:
                nic.ipv4 = addr.address
                nic.ipv4_netmask = addr.netmask
                if addr.address.startswith("127."):
                    nic.is_loopback = True
                if addr.netmask:
                    try:
                        net = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                        nic.cidr = str(net)
                    except ValueError:
                        pass
            elif getattr(addr.family, "name", None) == "AF_INET6" or addr.family == socket.AF_INET6:
                if not nic.ipv6:
                    nic.ipv6 = addr.address.split("%")[0]

        if nic.ipv4 and active_ip and nic.ipv4 == active_ip:
            nic.is_default = True

        results.append(nic)

    return results


def get_primary_interface() -> Optional[NetworkInterface]:
    interfaces = list_interfaces()
    for nic in interfaces:
        if nic.is_default:
            return nic
    for nic in interfaces:
        if nic.is_up and not nic.is_loopback and nic.ipv4:
            return nic
    return interfaces[0] if interfaces else None
