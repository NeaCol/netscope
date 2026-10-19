# NetScope

[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests Passing](https://img.shields.io/badge/tests-52%20passed-brightgreen.svg)]()
[![Code Style: Clean](https://img.shields.io/badge/code%20style-clean%20%26%20typed-black.svg)]()
[![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg)]()

> **Educational Network Diagnostic Workbench & Topology Visualizer**

NetScope is an open-source, dual-mode (CLI & Self-Hosted Web Dashboard) network engineering utility designed for students, educators, and systems engineers. It provides legitimate diagnostic capabilities across local subnet discovery, multi-layer binary packet dissection, recursive DNS resolution benchmarking, and interactive topological graph mapping.

---

## Architecture

The project is structured into modular, decoupled domain packages:

```
netscope/
├── scanner/           # Host discovery, ARP tables, NIC enumeration, port inspection
│   ├── interfaces.py  # System NIC address & routing introspection (psutil/socket)
│   ├── discovery.py   # Subnet host discovery sweep & hardware OUI resolution
│   └── ports.py       # TCP connection probing & service detection
├── protocols/         # Protocol parsing & network capture processing
│   ├── dissector.py   # Multi-layer packet dissector (L2 through L7, IPv4 & IPv6)
│   ├── pcap.py        # Libpcap 2.4 reader/writer & synthetic educational generator
│   └── dns.py         # RFC 1035 query builder & multi-resolver benchmark engine
├── analyzer/          # Telemetry, traffic statistics & topological graph generation
│   ├── latency.py     # High-resolution RTT statistics & RFC 3550 jitter calculation
│   ├── traffic.py     # Conversation aggregation & protocol distribution
│   └── topology.py    # Hierarchical graph generator (WAN -> Gateway -> Hosts)
├── cli/               # Command-line interface with table and JSON formatting
│   └── main.py        # Subcommands: interfaces, scan, ports, dns, ping, trace, pcap, topology, serve
└── dashboard/         # Self-hosted anti-slop web dashboard
    ├── server.py      # FastAPI / Uvicorn REST backend and static file server
    └── static/        # Zero-telemetry frontend (Jost typography, SVG topology, inspector)
```

---

## Features

### 1. Interactive Network Topology Visualizer
- Generates live SVG node-link graph mapping upstream WAN routes, local gateway, primary host, and discovered subnet endpoints.
- Interactive Node Inspector displaying physical MAC, vendor heuristics, round-trip time, and on-demand port auditing.

### 2. Multi-Layer Binary Packet Dissector
- Dissects raw frame bytes or PCAP capture files down to bitwise fields:
  - **Layer 2 (Data Link):** Ethernet II framing with 48-bit physical MAC addresses and EtherType decoding.
  - **Layer 3 (Network):** IPv4 (IHL, DSCP, TTL origin heuristics, protocol ID), IPv6, ARP (Request/Reply), ICMP (Echo Request/Reply, Time Exceeded).
  - **Layer 4 (Transport):** TCP (SYN/ACK/FIN flags, sequence and acknowledgment numbers, window sizing), UDP datagrams.
  - **Layer 7 (Application):** DNS query and response records, HTTP/1.1 request/response headers, TLS Client Hello SNI detection.
- Includes a synchronized split-view with formatted hexadecimal offset dumps and RFC educational callouts.

### 3. DNS Resolver Benchmark & Record Analyzer
- Live concurrent latency comparison across public and local resolvers: Cloudflare (`1.1.1.1`), Google (`8.8.8.8`), Quad9 (`9.9.9.9`), and OpenDNS (`208.67.222.222`).
- Comprehensive query support for `A`, `AAAA`, `MX`, `TXT`, `NS`, `CNAME`, and reverse `PTR` lookups with exact TTL timings.

### 4. High-Resolution Latency & RFC 3550 Jitter Telemetry
- Computes packet transmission variance (interarrival jitter), minimum, maximum, mean, and standard deviation RTT.
- Hop-by-hop route tracing identifying intermediate routing nodes and latency hops.

### 5. Local Subnet Discovery & Interface Introspection
- Scans user-specified CIDR blocks (e.g. `192.168.1.0/24`) combining ARP tables and multi-threaded socket probing.
- Automatic IEEE OUI manufacturer resolution (Apple, Intel, Raspberry Pi, Cisco, Dell, Espressif, Ubiquiti, etc.).
- Deep inspection of host interfaces: status, IPv4/IPv6, MAC, MTU, operational link speed, and default routing table entries.

---

## Installation

### Prerequisites
- Python 3.9+ (Python 3.14 compatible)
- Standard network interface with read permissions

### Setup
```bash
git clone https://github.com/your-username/netscope.git
cd netscope

# Install dependencies or install in editable mode
pip install -e .
```

---

## CLI Usage

NetScope provides a modular command-line suite supporting both human-readable ASCII tables and structured `--json` outputs for scripting:

### List Network Interfaces
```bash
netscope interfaces
```

### Scan Local Subnet
```bash
netscope scan --subnet 192.168.1.0/24 --threads 40
```

### Audit Open Ports on Host
```bash
netscope ports 192.168.1.1 -p 80,443,22,53
```

### Benchmark DNS Resolvers
```bash
netscope dns cloudflare.com --benchmark
```

### Query Specific DNS Records
```bash
netscope dns github.com --type AAAA
netscope dns google.com --type MX
```

### Measure Latency & RFC 3550 Jitter
```bash
netscope ping 1.1.1.1 --count 5
```

### Trace Route Hops
```bash
netscope trace 8.8.8.8 --max-hops 15
```

### Dissect PCAP Captures
```bash
# Generate and dissect educational sample capture
netscope pcap --sample

# Dissect an existing capture file
netscope pcap capture.pcap --limit 10
```

### Output Network Topology Graph
```bash
netscope topology --json
```

### Launch Self-Hosted Web Dashboard
```bash
netscope serve --host 127.0.0.1 --port 8080 --open
```

Visit `http://127.0.0.1:8080` in any modern browser.

---

## Running the Test Suite

The repository includes a comprehensive 52-test unit and integration test suite:

```bash
pytest tests -v
```

Output:
```
============================= test session starts =============================
collected 52 items

tests/test_analyzer.py ........                                          [ 15%]
tests/test_cli.py ........                                               [ 30%]
tests/test_dashboard_api.py ............                                  [ 53%]
tests/test_protocols.py ................                                 [ 84%]
tests/test_scanner.py ........                                           [100%]

======================= 52 passed, 1 warning in 2.38s =========================
```

---

## Educational Ethics Disclaimer

NetScope is designed exclusively for educational demonstration, diagnostic network administration, and authorized infrastructure auditing. Do not execute subnet discovery sweeps or connection probes against networks where you lack explicit administrative authorization.

---

## License

This project is released under the [MIT License](LICENSE). Contributions, issues, and forks are welcome.
