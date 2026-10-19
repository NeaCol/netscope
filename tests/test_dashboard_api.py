import unittest
from fastapi.testclient import TestClient
from netscope.dashboard.server import app


class TestDashboardAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_root_index_html(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("NetScope", res.text)

    def test_api_status(self):
        res = self.client.get("/api/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("version", data)
        self.assertIn("platform", data)

    def test_api_interfaces(self):
        res = self.client.get("/api/interfaces")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)

    def test_api_dns_single(self):
        res = self.client.get("/api/dns?domain=example.com&type=A")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["domain"], "example.com")
        self.assertIn("response_time_ms", data)

    def test_api_ping(self):
        res = self.client.get("/api/ping?target=127.0.0.1&count=2")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["target"], "127.0.0.1")
        self.assertIn("jitter_ms", data)

    def test_api_topology(self):
        res = self.client.get("/api/topology")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("nodes", data)
        self.assertIn("links", data)

    def test_api_sample_pcap(self):
        res = self.client.get("/api/sample-pcap")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("report", data)
        self.assertIn("packets", data)
        self.assertEqual(len(data["packets"]), 7)

    def test_api_analyze_packet_valid_hex(self):
        sample_hex = "ffffffffffff000c294b821108060001080006040001000c294b8211c0a80132000000000000c0a80101"
        res = self.client.post("/api/analyze-packet", json={"hex_data": sample_hex})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("ARP", data["summary"])
        self.assertGreater(len(data["layers"]), 0)

    def test_api_analyze_packet_invalid_hex(self):
        res = self.client.post("/api/analyze-packet", json={"hex_data": "not-valid-hex-zzz"})
        self.assertEqual(res.status_code, 400)

    def test_api_ports_limit(self):
        many_ports = ",".join(str(i) for i in range(1, 105))
        res = self.client.get(f"/api/ports?host=127.0.0.1&ports={many_ports}")
        self.assertEqual(res.status_code, 400)
        self.assertIn("Maximum 100 ports", res.json()["detail"])

    def test_api_analyze_packet_oversized(self):
        oversized_hex = "00" * 70000
        res = self.client.post("/api/analyze-packet", json={"hex_data": oversized_hex})
        self.assertEqual(res.status_code, 400)

    def test_api_trace(self):
        res = self.client.get("/api/trace?target=127.0.0.1&max_hops=2")
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.json(), list)
