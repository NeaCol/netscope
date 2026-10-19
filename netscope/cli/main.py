import argparse
import json
import sys
from typing import List, Optional
from netscope import __version__
from netscope.analyzer.latency import measure_latency, run_traceroute
from netscope.analyzer.topology import build_network_topology
from netscope.analyzer.traffic import analyze_traffic
from netscope.protocols.dns import benchmark_resolvers, query_dns
from netscope.protocols.pcap import generate_educational_pcap, parse_pcap_packets
from netscope.scanner.discovery import scan_subnet
from netscope.scanner.interfaces import list_interfaces


def print_table(headers: List[str], rows: List[List[str]]) -> None:
    if not rows:
        print("No entries found.")
        return
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(val)))

    fmt = "  ".join(f"{{:<{w}}}" for w in col_widths)
    separator = "  ".join("-" * w for w in col_widths)

    print(fmt.format(*headers))
    print(separator)
    for row in rows:
        print(fmt.format(*[str(r) for r in row]))


def cmd_interfaces(args: argparse.Namespace) -> int:
    interfaces = list_interfaces()
    if args.json:
        print(json.dumps([nic.to_dict() for nic in interfaces], indent=2))
        return 0

    headers = ["Interface", "Status", "IPv4", "CIDR", "MAC", "Speed"]
    rows = []
    for nic in interfaces:
        status = "UP" if nic.is_up else "DOWN"
        speed = f"{nic.speed} Mbps" if nic.speed > 0 else "-"
        rows.append([
            nic.name + (" *" if nic.is_default else ""),
            status,
            nic.ipv4 or "-",
            nic.cidr or "-",
            nic.mac or "-",
            speed,
        ])
    print(f"\nNetScope Interfaces (Primary: *)\n")
    print_table(headers, rows)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    if not args.json:
        print(f"Scanning subnet {args.subnet or 'default'}...")
    hosts = scan_subnet(cidr=args.subnet, max_threads=args.threads)
    if args.json:
        print(json.dumps([h.to_dict() for h in hosts], indent=2))
        return 0

    headers = ["IP Address", "Role", "Vendor", "Hostname", "MAC", "RTT (ms)"]
    rows = []
    for h in hosts:
        role = "Gateway" if h.is_gateway else ("This Host" if h.is_local else "Host")
        rows.append([
            h.ip,
            role,
            h.vendor[:24],
            (h.hostname or "-")[:20],
            h.mac or "-",
            f"{h.response_time_ms:.1f}",
        ])
    print(f"\nDiscovered {len(hosts)} active devices on network:\n")
    print_table(headers, rows)
    return 0


def cmd_dns(args: argparse.Namespace) -> int:
    if args.benchmark:
        if not args.json:
            print(f"Running DNS resolver benchmark against {args.domain}...\n")
        bench = benchmark_resolvers(domain=args.domain)
        if args.json:
            print(json.dumps([b.to_dict() for b in bench], indent=2))
            return 0
        headers = ["Provider", "Server IP", "Latency (ms)", "Status", "Answers"]
        rows = [[b.provider, b.server, f"{b.latency_ms:.1f}", b.status, str(b.answers_count)] for b in bench]
        print_table(headers, rows)
        return 0

    res = query_dns(domain=args.domain, record_type=args.type, server=args.server)
    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
        return 0

    print(f"\nDNS Query: {res.domain} (Type {res.record_type})")
    print(f"Server: {res.server} | Status: {res.status} | Latency: {res.response_time_ms:.1f} ms\n")
    if res.answers:
        headers = ["Name", "Type", "TTL", "Data"]
        rows = [[a.name, a.record_type, str(a.ttl), a.data] for a in res.answers]
        print_table(headers, rows)
    else:
        print("No answer records returned.")
        if res.error_message:
            print(f"Error: {res.error_message}")
    return 0


def cmd_ping(args: argparse.Namespace) -> int:
    if not args.json:
        print(f"PING {args.target} ({args.count} probes)...")
    stats = measure_latency(host=args.target, count=args.count, interval=args.interval)
    if args.json:
        print(json.dumps(stats.to_dict(), indent=2))
        return 0

    print(f"\n--- {stats.target} NetScope Latency Statistics ---")
    print(f"{stats.sent} packets transmitted, {stats.received} received, {stats.packet_loss_pct:.1f}% packet loss")
    if stats.received > 0:
        print(f"rtt min/avg/max/stddev = {stats.min_ms:.2f} / {stats.avg_ms:.2f} / {stats.max_ms:.2f} / {stats.stddev_ms:.2f} ms")
        print(f"interarrival jitter = {stats.jitter_ms:.2f} ms")
        print(f"probes: {', '.join(f'{s:.1f}ms' for s in stats.samples)}")
    return 0


def cmd_trace(args: argparse.Namespace) -> int:
    if not args.json:
        print(f"Tracing route to {args.target} (max {args.max_hops} hops)...")
    hops = run_traceroute(target=args.target, max_hops=args.max_hops)
    if args.json:
        print(json.dumps([h.to_dict() for h in hops], indent=2))
        return 0

    headers = ["Hop", "IP Address", "RTT (ms)", "Status"]
    rows = [[str(h.hop), h.ip or "*", f"{h.rtt_ms:.1f}" if h.rtt_ms else "*", h.status] for h in hops]
    print()
    print_table(headers, rows)
    return 0


def cmd_pcap(args: argparse.Namespace) -> int:
    if args.sample:
        data = generate_educational_pcap()
        out_path = args.output or "sample_capture.pcap"
        with open(out_path, "wb") as f:
            f.write(data)
        if not args.json:
            print(f"Generated educational sample PCAP at: {out_path} ({len(data)} bytes)")
        target_path = out_path
    elif args.file:
        target_path = args.file
    else:
        print("Please provide a .pcap file path or use --sample")
        return 1

    with open(target_path, "rb") as f:
        raw_pcap = f.read()

    packets = parse_pcap_packets(raw_pcap)
    report = analyze_traffic(packets)

    if args.json:
        print(json.dumps({
            "report": report.to_dict(),
            "packets": [p.to_dict() for p in packets[:args.limit]],
        }, indent=2))
        return 0

    print(f"\nNetScope PCAP Dissection: {target_path}")
    print(f"Total Packets: {report.total_packets} | Total Bytes: {report.total_bytes} | Duration: {report.duration_seconds:.2f}s\n")
    print("Protocol Distribution:")
    for proto, cnt in report.protocols_breakdown.items():
        print(f"  {proto:<12}: {cnt} packets")

    if report.top_conversations:
        print("\nTop Conversations:")
        for conv in report.top_conversations:
            print(f"  {conv.endpoint_a} <-> {conv.endpoint_b}: {conv.packets} pkts, {conv.bytes_count} bytes")

    print(f"\nDissected Packets (Showing first {min(len(packets), args.limit)}):")
    headers = ["#", "Summary", "Length"]
    rows = [[str(i + 1), p.summary[:65], f"{p.length} B"] for i, p in enumerate(packets[:args.limit])]
    print_table(headers, rows)
    return 0


def cmd_topology(args: argparse.Namespace) -> int:
    if not args.json:
        print("Building local network topology...")
    topo = build_network_topology()
    if args.json:
        print(json.dumps(topo.to_dict(), indent=2))
        return 0

    print(f"\nNetwork Topology: Subnet {topo.subnet_cidr or 'Unknown'}")
    print(f"Gateway: {topo.gateway_ip or 'None'} | Local Machine: {topo.local_ip or 'None'}\n")
    headers = ["Node ID", "Type", "IP Address", "Label", "Vendor", "Latency"]
    rows = [[n.id, n.node_type, n.ip, n.label[:22], n.vendor[:18], f"{n.latency_ms:.1f} ms"] for n in topo.nodes]
    print_table(headers, rows)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from netscope.dashboard.server import start_server

    print(f"Starting NetScope Dashboard on http://{args.host}:{args.port}")
    if args.open:
        import threading
        import webbrowser

        def _open():
            import time
            time.sleep(1.0)
            webbrowser.open(f"http://{args.host}:{args.port}")

        threading.Thread(target=_open, daemon=True).start()

    start_server(host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscope",
        description="NetScope: Educational Network Diagnostic, Protocol Dissection, and Topology Tool",
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    p_iface = subparsers.add_parser("interfaces", help="List system network interfaces")
    p_iface.add_argument("--json", action="store_true", help="Output JSON format")
    p_iface.set_defaults(func=cmd_interfaces)

    p_scan = subparsers.add_parser("scan", help="Discover active devices on local network subnet")
    p_scan.add_argument("--subnet", type=str, help="Subnet CIDR (e.g. 192.168.1.0/24)")
    p_scan.add_argument("--threads", type=int, default=40, help="Concurrent probe threads")
    p_scan.add_argument("--json", action="store_true", help="Output JSON format")
    p_scan.set_defaults(func=cmd_scan)

    p_dns = subparsers.add_parser("dns", help="Analyze DNS records and benchmark resolvers")
    p_dns.add_argument("domain", type=str, help="Domain name to resolve")
    p_dns.add_argument("--type", type=str, default="A", help="Record type (A, AAAA, MX, TXT, NS, CNAME)")
    p_dns.add_argument("--server", type=str, default="1.1.1.1", help="Target DNS server IP")
    p_dns.add_argument("--benchmark", action="store_true", help="Benchmark top public resolvers")
    p_dns.add_argument("--json", action="store_true", help="Output JSON format")
    p_dns.set_defaults(func=cmd_dns)

    p_ping = subparsers.add_parser("ping", help="Measure latency, packet loss, and jitter")
    p_ping.add_argument("target", type=str, help="Target IP or hostname")
    p_ping.add_argument("-c", "--count", type=int, default=5, help="Number of probes")
    p_ping.add_argument("-i", "--interval", type=float, default=0.1, help="Interval between probes")
    p_ping.add_argument("--json", action="store_true", help="Output JSON format")
    p_ping.set_defaults(func=cmd_ping)

    p_trace = subparsers.add_parser("trace", help="Hop-by-hop route latency tracing")
    p_trace.add_argument("target", type=str, help="Target destination")
    p_trace.add_argument("--max-hops", type=int, default=20, help="Max hops")
    p_trace.add_argument("--json", action="store_true", help="Output JSON format")
    p_trace.set_defaults(func=cmd_trace)

    p_pcap = subparsers.add_parser("pcap", help="Dissect PCAP files and analyze traffic")
    p_pcap.add_argument("file", nargs="?", type=str, help="Path to .pcap capture")
    p_pcap.add_argument("--sample", action="store_true", help="Generate educational synthetic pcap")
    p_pcap.add_argument("--output", type=str, help="Output path when generating sample")
    p_pcap.add_argument("--limit", type=int, default=15, help="Max packets to print")
    p_pcap.add_argument("--json", action="store_true", help="Output JSON format")
    p_pcap.set_defaults(func=cmd_pcap)

    p_topo = subparsers.add_parser("topology", help="Build network topology graph")
    p_topo.add_argument("--json", action="store_true", help="Output JSON format")
    p_topo.set_defaults(func=cmd_topology)

    p_serve = subparsers.add_parser("serve", help="Start self-hosted web dashboard")
    p_serve.add_argument("--host", type=str, default="127.0.0.1", help="Bind host")
    p_serve.add_argument("--port", type=int, default=8080, help="Bind port")
    p_serve.add_argument("--open", action="store_true", help="Open browser on launch")
    p_serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
