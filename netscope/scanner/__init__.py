from netscope.scanner.discovery import DiscoveredHost, scan_subnet
from netscope.scanner.interfaces import NetworkInterface, get_default_gateway_and_ip, get_primary_interface, list_interfaces
from netscope.scanner.ports import PortScanResult, check_port, scan_ports

__all__ = [
    "NetworkInterface",
    "list_interfaces",
    "get_primary_interface",
    "get_default_gateway_and_ip",
    "DiscoveredHost",
    "scan_subnet",
    "PortScanResult",
    "check_port",
    "scan_ports",
]
