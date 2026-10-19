import unittest
from netscope.scanner.discovery import lookup_vendor, probe_single_host
from netscope.scanner.interfaces import get_default_gateway_and_ip, get_primary_interface, list_interfaces
from netscope.scanner.ports import check_port, scan_ports


class TestScanner(unittest.TestCase):
    def test_list_interfaces(self):
        interfaces = list_interfaces()
        self.assertIsInstance(interfaces, list)
        self.assertGreater(len(interfaces), 0)

        for nic in interfaces:
            self.assertIsNotNone(nic.name)
            self.assertIsInstance(nic.is_up, bool)
            self.assertIsInstance(nic.speed, int)
            self.assertIsInstance(nic.mtu, int)

    def test_get_primary_interface(self):
        primary = get_primary_interface()
        self.assertIsNotNone(primary)
        self.assertIsInstance(primary.name, str)

    def test_get_default_gateway_and_ip(self):
        gw, ip = get_default_gateway_and_ip()
        if ip is not None:
            self.assertRegex(ip, r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

    def test_lookup_vendor(self):
        self.assertEqual(lookup_vendor("B8:27:EB:01:02:03"), "Raspberry Pi Foundation")
        self.assertEqual(lookup_vendor("00:0C:29:AA:BB:CC"), "VMware")
        self.assertEqual(lookup_vendor("00:1E:C2:11:22:33"), "Apple")
        self.assertEqual(lookup_vendor("FF:EE:DD:00:11:22"), "Standard Network Device")
        self.assertEqual(lookup_vendor(None), "Unknown")

    def test_probe_single_host(self):
        ip, is_alive, rtt = probe_single_host("127.0.0.1", timeout=0.1)
        self.assertEqual(ip, "127.0.0.1")
        self.assertIsInstance(is_alive, bool)
        self.assertGreaterEqual(rtt, 0.0)

    def test_check_port_closed(self):
        res = check_port("127.0.0.1", 65530, timeout=0.1)
        self.assertEqual(res.port, 65530)
        self.assertFalse(res.is_open)

    def test_scan_ports_empty(self):
        res = scan_ports("127.0.0.1", ports=[65531, 65532], timeout=0.1)
        self.assertIsInstance(res, list)
