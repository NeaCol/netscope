import socket
import time
import unittest
from unittest import mock

from netscope.scanner.discovery import (
    _parse_arp_command_output,
    _parse_ip_neigh_output,
    _parse_proc_net_arp,
    lookup_vendor,
    normalize_mac,
    probe_single_host,
    read_system_arp_table,
    resolve_hostname,
    resolve_hostnames,
    scan_subnet,
)
from netscope.scanner.interfaces import get_default_gateway_and_ip, get_primary_interface, list_interfaces
from netscope.scanner.ports import check_port, parse_port_spec, scan_ports


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

    def test_lookup_vendor_expanded(self):
        self.assertEqual(lookup_vendor("2C:EC:F7:11:22:33"), "Apple")
        self.assertEqual(lookup_vendor("28:56:3A:AA:BB:CC"), "Xiaomi / Tuya")
        self.assertEqual(lookup_vendor("60:45:E8:12:34:56"), "Espressif Inc.")
        self.assertEqual(lookup_vendor("D8:57:EF:00:11:22"), "Samsung")

    def test_read_arp_table_filters_multicast(self):
        from netscope.scanner.discovery import read_system_arp_table
        table = read_system_arp_table()
        self.assertNotIn("239.255.255.250", table)
        for ip, mac in table.items():
            self.assertFalse(mac.startswith("01:00:5E"))
            self.assertFalse(mac.startswith("FF:FF:FF"))


class TestNeighborDiscovery(unittest.TestCase):
    def test_normalize_mac_variants(self):
        expected = "00:1F:6D:9A:33:54"
        for raw in ("00:1f:6d:9a:33:54", "0:1f:6d:9a:33:54", "00-1F-6D-9A-33-54", "001f.6d9a.3354"):
            self.assertEqual(normalize_mac(raw), expected, raw)
        for bad in (None, "", "not-a-mac", "00:1f:6d:9a:33", "00:1f:6d:9a:33:54:66"):
            self.assertIsNone(normalize_mac(bad), bad)

    def test_vendor_lookup_accepts_bsd_style_macs(self):
        # macOS prints single-digit octets: without normalization every Apple
        # and VMware host on the LAN was reported as "Standard Network Device".
        self.assertEqual(lookup_vendor("0:c:29:4b:82:11"), "VMware")
        self.assertEqual(lookup_vendor("b8:27:eb:1:2:3"), "Raspberry Pi Foundation")
        self.assertEqual(lookup_vendor("00-0C-29-4B-82-11"), "VMware")

    def test_arp_output_net_tools(self):
        text = (
            "? (192.168.1.1) at 00:1f:6d:9a:33:54 [ether] on eth0\n"
            "? (192.168.1.77) at <incomplete> on eth0\n"
        )
        self.assertEqual(_parse_arp_command_output(text), {"192.168.1.1": "00:1F:6D:9A:33:54"})

    def test_arp_output_bsd(self):
        text = (
            "? (192.168.1.1) at 0:1f:6d:9a:33:54 on en0 ifscope [ethernet]\n"
            "? (192.168.1.50) at bc:d0:74:1:2:33 on en0 ifscope [ethernet]\n"
        )
        self.assertEqual(
            _parse_arp_command_output(text),
            {"192.168.1.1": "00:1F:6D:9A:33:54", "192.168.1.50": "BC:D0:74:01:02:33"},
        )

    def test_arp_output_windows(self):
        text = (
            "Interface: 192.168.1.50 --- 0x5\n"
            "  Internet Address      Physical Address      Type\n"
            "  192.168.1.1           00-1f-6d-9a-33-54     dynamic\n"
        )
        self.assertEqual(_parse_arp_command_output(text), {"192.168.1.1": "00:1F:6D:9A:33:54"})

    def test_proc_net_arp_skips_incomplete_entries(self):
        text = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         00:1f:6d:9a:33:54     *        eth0\n"
            "192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0\n"
        )
        self.assertEqual(_parse_proc_net_arp(text), {"192.168.1.1": "00:1F:6D:9A:33:54"})

    def test_ip_neigh_parsing(self):
        text = (
            "192.168.1.1 dev eth0 lladdr 00:1f:6d:9a:33:54 REACHABLE\n"
            "192.168.1.8 dev eth0  FAILED\n"
            "192.168.1.9 dev eth0 lladdr bc:d0:74:01:02:33 STALE\n"
        )
        self.assertEqual(
            _parse_ip_neigh_output(text),
            {"192.168.1.1": "00:1F:6D:9A:33:54", "192.168.1.9": "BC:D0:74:01:02:33"},
        )

    def test_table_falls_back_when_arp_binary_is_missing(self):
        neigh = "192.168.1.1 dev eth0 lladdr 00:1f:6d:9a:33:54 REACHABLE\n"

        def fake_check_output(cmd, *args, **kwargs):
            if cmd[0] == "arp":
                raise FileNotFoundError("arp not installed")
            return neigh

        with mock.patch("subprocess.check_output", fake_check_output):
            self.assertEqual(read_system_arp_table(), {"192.168.1.1": "00:1F:6D:9A:33:54"})

    def test_reverse_dns_timeout_is_enforced(self):
        def slow_lookup(_ip):
            time.sleep(2.0)
            return ("slow.example", [], ["10.0.0.9"])

        with mock.patch("socket.gethostbyaddr", slow_lookup):
            started = time.perf_counter()
            result = resolve_hostname("10.0.0.9", timeout=0.2)
            elapsed = time.perf_counter() - started
        self.assertIsNone(result)
        self.assertLess(elapsed, 1.0, "the reverse lookup timeout was not honoured")

    def test_resolve_hostnames_returns_names(self):
        names = {"10.0.0.1": "router.lan", "10.0.0.2": "nas.lan"}

        def fake_lookup(ip):
            if ip in names:
                return (names[ip], [], [ip])
            raise socket.herror("unknown host")

        with mock.patch("socket.gethostbyaddr", fake_lookup):
            result = resolve_hostnames(["10.0.0.1", "10.0.0.2", "10.0.0.3"], timeout=0.5)
        self.assertEqual(result, {"10.0.0.1": "router.lan", "10.0.0.2": "nas.lan", "10.0.0.3": None})

    def test_scan_subnet_rejects_zero_threads(self):
        with self.assertRaises(ValueError):
            scan_subnet(cidr="192.168.1.0/30", max_threads=0)

    def test_scan_subnet_rejects_invalid_explicit_cidr(self):
        # Silently scanning 192.168.1.0/24 instead reported another network's
        # hosts as if they were the requested subnet.
        with self.assertRaises(ValueError):
            scan_subnet(cidr="not-a-subnet")


class TestPortSpec(unittest.TestCase):
    def test_parses_lists_and_ranges(self):
        self.assertEqual(parse_port_spec("80,443"), [80, 443])
        self.assertEqual(parse_port_spec("22, 80-82"), [22, 80, 81, 82])
        self.assertEqual(parse_port_spec("80,80,80"), [80])

    def test_empty_spec_means_default(self):
        self.assertIsNone(parse_port_spec(None))
        self.assertIsNone(parse_port_spec("   "))

    def test_rejects_bad_tokens(self):
        for bad in ("abc", "80,abc", "70000", "0", "80-", "90-80", "-1"):
            with self.assertRaises(ValueError, msg=bad):
                parse_port_spec(bad)

    def test_check_port_rejects_out_of_range(self):
        with self.assertRaises(ValueError):
            check_port("127.0.0.1", 70000, timeout=0.05)

    def test_scan_ports_rejects_zero_threads(self):
        with self.assertRaises(ValueError):
            scan_ports("127.0.0.1", ports=[80], max_threads=0)
