# NetScope

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%20%7C%203.14-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python Version" />
  <img src="https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Kali_Linux-Verified-557C94?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali Linux Audited" />
  <img src="https://img.shields.io/badge/Tests-114%20passed-brightgreen?style=for-the-badge" alt="Tests" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License MIT" />
</p>

<p align="center">
  <a href="https://skillicons.dev">
    <img src="https://skillicons.dev/icons?i=python,fastapi,linux,bash,docker,git" alt="Tech Stack" />
  </a>
</p>

> **Educational Network Diagnostic Workbench & Topology Visualizer**

NetScope is an open-source, dual-mode (CLI and self-hosted web dashboard) network engineering utility for students, educators, and systems engineers. It provides diagnostic capabilities across local subnet discovery, multi-layer binary packet dissection, recursive DNS resolution benchmarking, and interactive topological graph mapping.

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
└── dashboard/         # Self-hosted web dashboard
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
  - **Layer 2 (Data Link):** Ethernet II framing with 48-bit physical MAC addresses and EtherType decoding, plus IEEE 802.1Q VLAN and 802.1ad (QinQ) tag stacks (PCP, DEI, VLAN ID) before the inner EtherType.
  - **Layer 3 (Network):** IPv4 (IHL, DSCP, TTL origin heuristics, protocol ID), IPv6, ARP (Request/Reply), ICMP (Echo Request/Reply, Time Exceeded).
  - **Layer 4 (Transport):** TCP (SYN/ACK/FIN flags, sequence and acknowledgment numbers, window sizing, full option block: MSS, window scale, SACK, timestamps), UDP datagrams. Non-first IP fragments are labelled as fragments instead of being misread as complete transport segments, and app-layer parsing stops at the IP total length so Ethernet padding never leaks into payloads.
  - **Layer 7 (Application):** DNS query and response records, HTTP/1.1 request/response headers, TLS Client Hello SNI detection.
- Includes a synchronized split-view with formatted hexadecimal offset dumps and RFC educational callouts.

### 3. DNS Resolver Benchmark & Record Analyzer
- Live concurrent latency comparison across public and local resolvers: Cloudflare (`1.1.1.1`), Google (`8.8.8.8`), Quad9 (`9.9.9.9`), and OpenDNS (`208.67.222.222`).
- Comprehensive query support for `A`, `AAAA`, `MX`, `TXT`, `NS`, `CNAME`, and reverse `PTR` lookups with exact TTL timings.
- Every query uses a random transaction ID and only accepts a response with a matching ID and the QR bit set, so late or spoofed datagrams are discarded instead of being reported as answers.
- Response codes are surfaced as the query status (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`, ...) rather than being folded into an empty answer list.

### 4. High-Resolution Latency & RFC 3550 Jitter Telemetry
- Computes packet transmission variance (interarrival jitter), minimum, maximum, mean, and standard deviation RTT.
- Hop-by-hop route tracing identifying intermediate routing nodes and latency hops.

### 5. Local Subnet Discovery & Interface Introspection
- Scans user-specified CIDR blocks (e.g. `192.168.1.0/24`) combining the system neighbor table with multi-threaded socket probing. The neighbor table is read from `arp -a`, then `ip neigh show`, then `/proc/net/arp`, so a Linux host without net-tools still discovers its LAN.
- Automatic IEEE OUI manufacturer resolution (Apple, Intel, Raspberry Pi, Cisco, Dell, Espressif, Ubiquiti, etc.) from any MAC spelling (`0:1f:6d:9a:33:54`, `00-1F-6D-9A-33-54`, `001f.6d9a.3354`).
- Reverse DNS lookups run against one bounded worker pool with a real deadline, so a slow reverse zone cannot stall a sweep.
- Deep inspection of host interfaces: status, IPv4/IPv6, MAC, MTU, operational link speed, and default routing table entries.

---

## Installation

### Prerequisites
- Python 3.9+ (Python 3.14 compatible)
- Standard network interface with read permissions

### Setup
```bash
git clone https://github.com/NeaCol/netscope.git
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

### Input Validation

Numeric bounds, port ranges, CIDR blocks and DNS record types are validated before any work starts, and problem input exits with status `2` plus a message on stderr instead of a traceback or an empty result that looks like a clean scan:

```bash
netscope ports 192.168.1.10 -p 80,443,8000-8010   # ranges and lists
netscope ports 192.168.1.10 -p 99999              # error: port 99999 is outside the valid range 1-65535
netscope dns example.com --type BOGUS             # error: unsupported DNS record type 'BOGUS'
netscope pcap notes.txt                           # error: notes.txt: not a pcap capture (magic 0x6f742061)
```

Capture support covers classic libpcap files with microsecond **or** nanosecond timestamps and Ethernet frames. A pcapng or non-Ethernet capture is rejected with a message naming the conversion to run (`editcap -F pcap`, `editcap -T ether`) rather than silently reporting zero packets.

### Launch Self-Hosted Web Dashboard
```bash
netscope serve --host 127.0.0.1 --port 8080 --open
```

Visit `http://127.0.0.1:8080` in any modern browser.

---

## Running the Test Suite

The test suite covers unit and integration tests (114 tests):

```bash
pytest tests -v
```

Output:
```
$ pytest tests -q
collected 114 items

tests/test_analyzer.py ............                                      [ 10%]
tests/test_cli.py .................                                      [ 25%]
tests/test_dashboard_api.py ................                             [ 40%]
tests/test_protocols.py ..........................................       [ 76%]
tests/test_scanner.py ..........................                         [100%]

======================== 114 passed, 1 warning in 1.84s ========================
```

---

## Educational Ethics Disclaimer

NetScope is designed exclusively for educational demonstration, diagnostic network administration, and authorized infrastructure auditing. Do not execute subnet discovery sweeps or connection probes against networks where you lack explicit administrative authorization.

---

## License

This project is licensed under the [MIT License](LICENSE).
