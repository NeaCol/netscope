# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Network Security & Packet Dissection Guidelines

NetScope is engineered as an educational network analysis tool and topology workbench:
- **Raw Socket Privileges:** NetScope avoids unnecessary elevated root/administrator privileges whenever standard unprivileged POSIX/WinSock calls suffice (e.g. standard UDP/TCP connection probes and ARP cache lookups).
- **Packet Dissection Boundary Defense:** The packet dissector enforces strict bounds checking against frame lengths, malformed IPv4/IPv6 headers, fragmented payloads, and recursive DNS compression loops (`test_dns_compression_loop_protection`).
- **Input Sanitization:** Hex dumps and pcap file streams undergo byte length validation prior to parsing, preventing arbitrary memory overflow or denial-of-service vulnerabilities.
- **Defensive Auditing:** NetScope's API endpoints and packet parsing routines are tested and verified using standard Kali Linux network diagnostic toolsets and synthetic packet fuzzers.

## Reporting a Vulnerability

If you encounter a potential security vector or parsing vulnerability:
1. Do not submit public issues on GitHub.
2. Email full vulnerability reproduction steps directly to `milansanchz@gmail.com`.
3. Provide sample hex streams or pcap fixtures demonstrating the edge case.
4. Vulnerability acknowledgments and resolutions are processed within 48 hours.
