import unittest
from netscope.analyzer.latency import calculate_jitter, measure_latency
from netscope.analyzer.topology import build_network_topology
from netscope.analyzer.traffic import analyze_traffic
from netscope.protocols.pcap import generate_educational_pcap, parse_pcap_packets
from netscope.scanner.discovery import DiscoveredHost


class TestAnalyzer(unittest.TestCase):
    def test_calculate_jitter_empty(self):
        self.assertEqual(calculate_jitter([]), 0.0)
        self.assertEqual(calculate_jitter([10.0]), 0.0)

    def test_calculate_jitter_constant(self):
        self.assertEqual(calculate_jitter([15.0, 15.0, 15.0]), 0.0)

    def test_calculate_jitter_varying(self):
        jitter = calculate_jitter([10.0, 20.0, 15.0])
        self.assertAlmostEqual(jitter, 7.5)

    def test_measure_latency_local(self):
        stats = measure_latency("127.0.0.1", count=2, interval=0.01)
        self.assertEqual(stats.target, "127.0.0.1")
        self.assertEqual(stats.sent, 2)
        self.assertGreaterEqual(stats.received, 0)
        self.assertIsInstance(stats.packet_loss_pct, float)

    def test_analyze_traffic_empty(self):
        report = analyze_traffic([])
        self.assertEqual(report.total_packets, 0)
        self.assertEqual(report.total_bytes, 0)

    def test_analyze_traffic_sample_pcap(self):
        raw = generate_educational_pcap()
        packets = parse_pcap_packets(raw)
        report = analyze_traffic(packets)

        self.assertEqual(report.total_packets, 7)
        self.assertGreater(report.total_bytes, 0)
        self.assertIn("Ethernet", report.protocols_breakdown)
        self.assertIn("ARP", report.protocols_breakdown)
        self.assertIn("IPv4", report.protocols_breakdown)
        self.assertIn("TCP", report.protocols_breakdown)
        self.assertIn("SYN", report.tcp_flags_breakdown)

    def test_build_network_topology(self):
        mock_hosts = [
            DiscoveredHost(ip="192.168.1.1", vendor="Router Co", is_gateway=True),
            DiscoveredHost(ip="192.168.1.15", vendor="Apple", hostname="macbook.local"),
            DiscoveredHost(ip="192.168.1.80", vendor="Espressif Inc.", hostname="iot-sensor"),
        ]
        graph = build_network_topology(discovered=mock_hosts)

        self.assertIsInstance(graph.nodes, list)
        self.assertIsInstance(graph.links, list)
        self.assertGreaterEqual(len(graph.nodes), 4)

        node_types = {n.node_type for n in graph.nodes}
        self.assertIn("wan", node_types)
        self.assertIn("gateway", node_types)
        self.assertIn("lan_host", node_types)

        link_types = {l.link_type for l in graph.links}
        self.assertIn("wan_uplink", link_types)
        self.assertIn("lan_link", link_types)

    def test_traceroute_nonexistent_host(self):
        from netscope.analyzer.latency import run_traceroute
        hops = run_traceroute("non-existent-target-test-123.invalid", max_hops=2, timeout_per_hop=0.2)
        # Should NOT return fake hops (192.168.1.1 or 14.5ms)
        fake_hops = [h for h in hops if h.ip == "192.168.1.1" and h.rtt_ms == 1.2]
        self.assertEqual(len(fake_hops), 0)
