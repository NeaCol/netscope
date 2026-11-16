import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

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

    def test_cli_ports_json(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["ports", "127.0.0.1", "-p", "65530", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(f.getvalue())
        self.assertIsInstance(data, list)

    def test_cli_trace_unreachable(self):
        f = io.StringIO()
        with redirect_stdout(f):
            code = main(["trace", "non-existent-target-test-123.invalid", "--max-hops", "1"])
        self.assertEqual(code, 0)


class TestCliValidation(unittest.TestCase):
    def test_missing_capture_file_exits_2(self):
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = main(["pcap", "/tmp/definitely-not-here.pcap"])
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err.getvalue())

    def test_non_pcap_file_exits_2(self):
        path = "/tmp/netscope-not-a-capture.bin"
        with open(path, "wb") as handle:
            handle.write(b"just some text, not a capture at all")
        try:
            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = main(["pcap", path])
            self.assertEqual(code, 2)
            self.assertIn("not a pcap", err.getvalue())
        finally:
            import os
            os.unlink(path)

    def test_limit_zero_is_rejected_by_the_parser(self):
        with self.assertRaises(SystemExit) as ctx:
            build_parser().parse_args(["pcap", "--sample", "--limit", "0"])
        self.assertEqual(ctx.exception.code, 2)

    def test_count_zero_is_rejected_by_the_parser(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["ping", "127.0.0.1", "-c", "0"])

    def test_invalid_port_token_exits_2(self):
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = main(["ports", "127.0.0.1", "-p", "abc"])
        self.assertEqual(code, 2)
        self.assertIn("invalid port", err.getvalue())

    def test_out_of_range_port_exits_2(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(["ports", "127.0.0.1", "-p", "70000"]), 2)

    def test_unknown_dns_type_exits_2(self):
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = main(["dns", "example.com", "--type", "FOO"])
        self.assertEqual(code, 2)
        self.assertIn("unsupported DNS record type", err.getvalue())

    def test_invalid_subnet_exits_2(self):
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = main(["scan", "--subnet", "nonsense"])
        self.assertEqual(code, 2)
        self.assertIn("invalid subnet", err.getvalue())

    def test_trace_without_traceroute_explains_itself(self):
        err = io.StringIO()
        with mock.patch("netscope.analyzer.latency.shutil.which", return_value=None):
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = main(["trace", "127.0.0.1", "--max-hops", "1"])
        self.assertEqual(code, 0)
        self.assertIn("not installed", err.getvalue())
