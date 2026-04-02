PyNetScan — Network Scanner & Vulnerability Assessment Tool

A Python-based network reconnaissance tool built from scratch, capable of host discovery, port scanning, banner grabbing, and automated CVE vulnerability lookup.

Overview

PyNetScan is a multi-stage network scanner that replicates the core functionality of professional tools like *nmap* and *Nessus*. It was built as a cybersecurity learning project to understand how network reconnaissance and vulnerability assessment works at a fundamental level.

Features

•	Host Discovery Ping sweep to find all alive devices on a network
•	Port Scanning Multi-threaded scanning of common ports
•	Banner Grabbing Identifies software and version info from open ports
•	CVE Lookup Automatically queries the NIST National Vulnerability Database for known vulnerabilities
•	Multi threaded Fast concurrent scanning using Thread Pool Executor
•	Cross Platform Works on both Windows and Linux

Project Structure

network-scanner/
├── network_scanner_v1.py   # Stage 1: Ping Sweeper
├── network_scanner_v2.py   # Stage 2: Port Scanner
├── network_scanner_v3.py   # Stage 3: Banner Grabber
├── network_scanner_v4.py   # Stage 4: CVE Lookup (full tool)
└── README.md

Each version builds on the previous one, showing the iterative development process

Requirements

•	Python 3.x
•	No external libraries required — uses only Python standard library modules:
i.	`socket` — port connections
ii.	`subprocess` — ping commands
iii.	`ipaddress` — CIDR network parsing
iv.	`concurrent.futures` — threading
v.	`urllib` — NVD API requests
vi.	`json` — parsing API responses


 
Usage

Run the full tool (Stage 4):
python network_scanner_v4.py
You will be prompted to choose:
========================================
  NETWORK SCANNER v4.0 - CVE Lookup
========================================

Scan options:
  1. Scan entire network
  2. Scan single IP

Choice (1 or 2):

Option 1 — Scan entire network:
Enter network (e.g. 192.168.1.0/24): 192.168.1.0/24

Option 2 — Scan single IP:
Enter IP (e.g. 192.168.1.158): 192.168.1.158

Example Output
============================================================
  TARGET: 192.168.1.158
  STARTED: 2026-01-30 16:34:29
============================================================

[*] Scanning ports...

[*] Open ports found:

  PORT     SERVICE      SOFTWARE        VERSION      BANNER
  ---------------------------------------------------------------
  22       SSH          OpenSSH         9.6p1        SSH-2.0-OpenSSH_9.6p1 Ubuntu...
  80       HTTP         Unknown         Unknown      HTTP/1.0 405 Method Not Allowed...
  139      NetBIOS      Unknown         Unknown      No banner
  445      SMB          Unknown         Unknown      No banner

[*] Looking up CVEs (this may take a moment) ...

  ───────────────────────────────────────────────────────
  CVE Lookup: OpenSSH 9.6p1 (Port 22/SSH)
  ───────────────────────────────────────────────────────
  ✅ No CVEs found for OpenSSH 9.6p1

============================================================
  SCAN COMPLETE: 2026-04-02 16:34:33
============================================================
How It Works

Stage 1 — Ping Sweep
Sends ICMP ping requests to every IP in the target range using `subprocess`. Uses threading to ping multiple hosts simultaneously. Detects OS to use correct ping flags (`-n` on Windows, `-c` on Linux).

Stage 2 Port Scanner
Attempts a TCP connection to each port using `socket.connect_ex()`. A return code of `0` means the port is open. Scans 17 common ports including SSH, HTTP, SMB, RDP, FTP, and more.

Stage 3 Banner Grabbing
Connects to each open port and reads the service banner. For HTTP ports, sends a `HEAD` request to prompt a response. Extracts software name and version from the raw banner text.

Stage 4 CVE Lookup
Queries the **NIST National Vulnerability Database (NVD) API v2.0** with the identified software and version. Parses the JSON response to extract CVE ID, CVSS severity score, and description. Respects NVD rate limits with a 1-second delay between requests.

Security Concepts Demonstrated

| Concept | Where It Appears |
|---|---|
| ICMP / Ping | Stage 1 — Host Discovery |
| TCP Handshake | Stage 2 — Port Scanning |
| Service Fingerprinting | Stage 3 — Banner Grabbing |
| CVE / CVSS Scoring | Stage 4 — Vulnerability Assessment |
| Cross-platform Development | OS detection for ping flags |
| Concurrent Programming | ThreadPoolExecutor throughout |
| REST API Integration | NVD API querying |

Author

Built by Arqam as part of a hands-on cybersecurity learning journey.

o	Concepts covered: Network reconnaissance, port scanning, service fingerprinting, vulnerability assessment
o	Tools referenced: nmap, Nessus, OpenVAS
o	Database used: [NIST National Vulnerability Database](https://nvd.nist.gov)

