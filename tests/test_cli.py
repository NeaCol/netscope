import io
import json
import unittest
from contextlib import redirect_stdout
from netscope.cli.main import build_parser, main


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.parser = build_parser()

    def test_parser_version(self):
        with self.assertRaises(SystemExit) as cm:
            self.parser.parse_args(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_cli_interfaces_json(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["interfaces", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(f.getvalue())
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)

    def test_cli_ping_json(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["ping", "127.0.0.1", "-c", "1", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(f.getvalue())
        self.assertEqual(data["target"], "127.0.0.1")
        self.assertIn("packet_loss_pct", data)

    def test_cli_pcap_sample(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["pcap", "--sample", "--json", "--limit", "3"])
        self.assertEqual(code, 0)
        data = json.loads(f.getvalue())
        self.assertIn("report", data)
        self.assertIn("packets", data)
        self.assertEqual(len(data["packets"]), 3)

    def test_cli_topology_json(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["topology", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(f.getvalue())
        self.assertIn("nodes", data)
        self.assertIn("links", data)

    def test_cli_no_args_shows_help(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main([])
        self.assertEqual(code, 1)
