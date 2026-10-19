from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
from netscope.scanner.discovery import DiscoveredHost, scan_subnet
from netscope.scanner.interfaces import get_default_gateway_and_ip, get_primary_interface


@dataclass
class TopologyNode:
    id: str
    label: str
    node_type: str
    ip: str
    mac: Optional[str] = None
    vendor: str = "Unknown"
    latency_ms: float = 0.0
    status: str = "online"
    tier: int = 1


@dataclass
class TopologyLink:
    source: str
    target: str
    link_type: str
    latency_ms: float = 0.0


@dataclass
class NetworkTopologyGraph:
    nodes: List[TopologyNode] = field(default_factory=list)
    links: List[TopologyLink] = field(default_factory=list)
    gateway_ip: Optional[str] = None
    local_ip: Optional[str] = None
    subnet_cidr: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gateway_ip": self.gateway_ip,
            "local_ip": self.local_ip,
            "subnet_cidr": self.subnet_cidr,
            "nodes": [asdict(n) for n in self.nodes],
            "links": [asdict(l) for l in self.links],
        }


def build_network_topology(discovered: Optional[List[DiscoveredHost]] = None, scan: bool = False) -> NetworkTopologyGraph:
    gw_ip, local_ip = get_default_gateway_and_ip()
    primary = get_primary_interface()
    cidr = primary.cidr if primary else "192.168.1.0/24"

    if discovered is None:
        if scan:
            discovered = scan_subnet(cidr=cidr)
        else:
            import ipaddress
            from netscope.scanner.discovery import lookup_vendor, read_system_arp_table
            arp_table = read_system_arp_table()
            discovered = []
            target_network = None
            if cidr:
                try:
                    target_network = ipaddress.IPv4Network(cidr, strict=False)
                except ValueError:
                    pass

            for ip, mac in arp_table.items():
                if ip in (gw_ip, local_ip):
                    continue
                try:
                    ip_obj = ipaddress.IPv4Address(ip)
                    if ip_obj.is_multicast or ip_obj.is_loopback or ip_obj.is_link_local:
                        continue
                    if target_network and ip_obj not in target_network:
                        continue
                except ValueError:
                    continue
                discovered.append(
                    DiscoveredHost(
                        ip=ip,
                        mac=mac,
                        vendor=lookup_vendor(mac),
                        response_time_ms=1.0,
                        status="online",
                    )
                )

    nodes: List[TopologyNode] = []
    links: List[TopologyLink] = []

    wan_node_id = "node_wan_internet"
    nodes.append(
        TopologyNode(
            id=wan_node_id,
            label="Internet / WAN",
            node_type="wan",
            ip="0.0.0.0",
            vendor="Global Routing System",
            latency_ms=12.0,
            status="online",
            tier=0,
        )
    )

    gw_node_id = f"node_gw_{gw_ip.replace('.', '_')}" if gw_ip else "node_gw_default"
    nodes.append(
        TopologyNode(
            id=gw_node_id,
            label=f"Gateway ({gw_ip or 'Router'})",
            node_type="gateway",
            ip=gw_ip or "192.168.1.1",
            vendor="Network Router",
            latency_ms=1.5,
            status="online",
            tier=1,
        )
    )

    links.append(
        TopologyLink(
            source=wan_node_id,
            target=gw_node_id,
            link_type="wan_uplink",
            latency_ms=12.0,
        )
    )

    seen_ips = {gw_ip} if gw_ip else set()

    if local_ip and local_ip not in seen_ips:
        loc_id = f"node_loc_{local_ip.replace('.', '_')}"
        nodes.append(
            TopologyNode(
                id=loc_id,
                label=f"This Machine ({local_ip})",
                node_type="local_host",
                ip=local_ip,
                mac=primary.mac if primary else None,
                vendor=primary.name if primary else "Host",
                latency_ms=0.1,
                status="online",
                tier=2,
            )
        )
        links.append(
            TopologyLink(
                source=gw_node_id,
                target=loc_id,
                link_type="lan_link",
                latency_ms=0.5,
            )
        )
        seen_ips.add(local_ip)

    for host in discovered:
        if host.ip in seen_ips:
            continue
        seen_ips.add(host.ip)

        h_id = f"node_host_{host.ip.replace('.', '_')}"
        label = host.hostname if host.hostname else f"Host {host.ip}"
        nodes.append(
            TopologyNode(
                id=h_id,
                label=label,
                node_type="lan_host",
                ip=host.ip,
                mac=host.mac,
                vendor=host.vendor,
                latency_ms=host.response_time_ms,
                status=host.status,
                tier=2,
            )
        )
        links.append(
            TopologyLink(
                source=gw_node_id,
                target=h_id,
                link_type="lan_link",
                latency_ms=host.response_time_ms,
            )
        )

    return NetworkTopologyGraph(
        nodes=nodes,
        links=links,
        gateway_ip=gw_ip,
        local_ip=local_ip,
        subnet_cidr=cidr,
    )
