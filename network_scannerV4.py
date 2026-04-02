#!/usr/bin/env python3
# ============================================
# Network Scanner - Stage 4: CVE Lookup
# ============================================

import socket
import ipaddress
import subprocess
import platform
import urllib.request  # built-in HTTP requests (no pip install needed)
import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# ----------------------------------
# COMMON PORTS
# ----------------------------------
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

HTTP_PORTS = {80, 443, 8080, 8443}

# ----------------------------------
# STEP 1: Extract software + version
# from a raw banner string
# e.g. "SSH-2.0-OpenSSH_9.6p1 Ubuntu"
#   →  ("OpenSSH", "9.6p1")
# ----------------------------------
def parse_banner(banner, service):
    if not banner:
        return None, None

    software = None
    version  = None

    # SSH banners follow a standard format:
    # SSH-2.0-OpenSSH_9.6p1
    if service == "SSH" and "OpenSSH" in banner:
        software = "OpenSSH"
        # Split on underscore to get version
        parts = banner.split("OpenSSH_")
        if len(parts) > 1:
            # Take first word of version (before space)
            version = parts[1].split()[0]

    # HTTP banners: look for Server: header
    # e.g. "Server: nginx/1.18.0"
    elif service in ("HTTP", "HTTPS"):
        if "Server:" in banner:
            server_part = banner.split("Server:")[1].strip().split()[0]
            if "/" in server_part:
                software, version = server_part.split("/", 1)
            else:
                software = server_part

        # Also check for common servers mentioned anywhere
        for known in ["nginx", "Apache", "lighttpd", "IIS", "CasaOS"]:
            if known.lower() in banner.lower():
                software = known
                break

    # FTP banners often say "220 FileZilla Server 1.2.0"
    elif service == "FTP":
        words = banner.split()
        for i, word in enumerate(words):
            if any(ftp in word for ftp in ["FileZilla", "ProFTPD", "vsftpd", "Pure-FTPd"]):
                software = word
                if i + 1 < len(words):
                    version = words[i + 1]
                break

    # Generic fallback — try to find version-like pattern (x.x.x)
    if not version and software:
        import re
        match = re.search(r'(\d+\.\d+[\.\d]*)', banner)
        if match:
            version = match.group(1)

    return software, version

# ----------------------------------
# STEP 2: Query NVD API for CVEs
# Takes software name + version
# Returns list of CVE results
# ----------------------------------
def lookup_cves(software, version, max_results=5):
    if not software:
        return []

    try:
        # Build search keyword
        # e.g. "OpenSSH 9.6p1" or just "OpenSSH" if no version
        keyword = f"{software} {version}" if version else software
        keyword_encoded = keyword.replace(" ", "%20")

        # NVD API endpoint
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?keywordSearch={keyword_encoded}"
            f"&resultsPerPage={max_results}"
        )

        # Make the request with a User-Agent header
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "NetworkScanner/1.0"}
        )

        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())

        cves = []
        for item in data.get("vulnerabilities", []):
            cve     = item.get("cve", {})
            cve_id  = cve.get("id", "Unknown")

            # Get severity score (CVSS)
            metrics  = cve.get("metrics", {})
            severity = "Unknown"
            score    = "N/A"

            # Try CVSSv3 first, then v2
            if "cvssMetricV31" in metrics:
                cvss     = metrics["cvssMetricV31"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "Unknown")
                score    = cvss.get("baseScore", "N/A")
            elif "cvssMetricV2" in metrics:
                cvss     = metrics["cvssMetricV2"][0]["cvssData"]
                score    = cvss.get("baseScore", "N/A")
                severity = "MEDIUM" if float(score) >= 4 else "LOW"

            # Get description
            descriptions = cve.get("descriptions", [])
            description  = next(
                (d["value"] for d in descriptions if d["language"] == "en"),
                "No description available"
            )
            # Truncate long descriptions
            if len(description) > 120:
                description = description[:120] + "..."

            cves.append({
                "id":          cve_id,
                "score":       score,
                "severity":    severity,
                "description": description
            })

        return cves

    except Exception as e:
        return []

# ----------------------------------
# STEP 3: Color code severity
# Makes output easier to read
# ----------------------------------
def severity_label(severity):
    labels = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH":     "🟠 HIGH",
        "MEDIUM":   "🟡 MEDIUM",
        "LOW":      "🟢 LOW",
    }
    return labels.get(severity.upper(), "⚪ UNKNOWN")

# ----------------------------------
# STEP 4: Banner grabbing (Stage 3)
# ----------------------------------
def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((str(ip), port))

        if port in HTTP_PORTS:
            request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
            sock.send(request.encode())
        else:
            sock.send(b"\r\n")

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()

        lines      = [line.strip() for line in banner.splitlines() if line.strip()]
        clean_banner = " | ".join(lines[:3])
        return clean_banner if clean_banner else None

    except Exception:
        return None

# ----------------------------------
# STEP 5: Scan port + grab banner
#         + lookup CVEs all in one
# ----------------------------------
def scan_port_full(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((str(ip), port))
        sock.close()

        if result == 0:
            service  = COMMON_PORTS.get(port, "Unknown")
            banner   = grab_banner(ip, port)
            software, version = parse_banner(banner, service)

            return {
                "port":     port,
                "service":  service,
                "banner":   banner,
                "software": software,
                "version":  version,
            }
        return None

    except Exception:
        return None

# ----------------------------------
# STEP 6: Full scan with CVE lookup
# ----------------------------------
def full_scan_with_cves(ip):
    print(f"\n{'='*60}")
    print(f"  TARGET: {ip}")
    print(f"  STARTED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    # Port scan
    print(f"\n[*] Scanning ports...")
    open_ports = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(scan_port_full, ip, port): port
            for port in COMMON_PORTS.keys()
        }
        for future in futures:
            result = future.result()
            if result is not None:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])

    if not open_ports:
        print("[-] No open ports found.")
        return

    # Display port results
    print(f"\n[*] Open ports found:\n")
    print(f"  {'PORT':<8} {'SERVICE':<12} {'SOFTWARE':<15} {'VERSION':<12} BANNER")
    print(f"  {'-'*75}")

    for entry in open_ports:
        port     = entry["port"]
        service  = entry["service"]
        software = entry["software"] or "Unknown"
        version  = entry["version"]  or "Unknown"
        banner   = entry["banner"]   or "No banner"

        if len(banner) > 35:
            banner = banner[:35] + "..."

        print(f"  {port:<8} {service:<12} {software:<15} {version:<12} {banner}")

    # CVE Lookup
    print(f"\n[*] Looking up CVEs (this may take a moment)...\n")

    for entry in open_ports:
        software = entry["software"]
        version  = entry["version"]
        port     = entry["port"]
        service  = entry["service"]

        if not software or software == "Unknown":
            continue

        print(f"\n  {'─'*55}")
        print(f"  🔍 CVE Lookup: {software} {version or ''} (Port {port}/{service})")
        print(f"  {'─'*55}")

        cves = lookup_cves(software, version)

        if not cves:
            print(f"  ✅ No CVEs found for {software} {version or ''}")
        else:
            print(f"  ⚠️  Found {len(cves)} CVE(s):\n")
            for cve in cves:
                print(f"  [{severity_label(cve['severity'])}] {cve['id']} (Score: {cve['score']})")
                print(f"  └─ {cve['description']}\n")

        # NVD rate limits to 5 requests/second without API key
        # Small delay to be respectful
        time.sleep(1)

    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

# ----------------------------------
# Entry point
# ----------------------------------
if __name__ == "__main__":
    print("\n========================================")
    print("  NETWORK SCANNER v4.0 - CVE Lookup")
    print("========================================")
    print("\nScan options:")
    print("  1. Scan entire network")
    print("  2. Scan single IP")

    choice = input("\nChoice (1 or 2): ").strip()

    if choice == "1":
        target     = input("Enter network (e.g. 192.168.0.0/24): ").strip()
        alive      = []
        network    = ipaddress.ip_network(target, strict=False)

        def ping_host(ip):
            system = platform.system().lower()
            cmd    = ["ping", "-n", "1", "-w", "500", str(ip)] if system == "windows" else ["ping", "-c", "1", "-W", "1", str(ip)]
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return str(ip) if result.returncode == 0 else None

        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(ping_host, network.hosts())
        alive = [r for r in results if r is not None]

        for host in alive:
            full_scan_with_cves(host)

    elif choice == "2":
        target = input("Enter IP (e.g. 192.168.0.158): ").strip()
        full_scan_with_cves(target)

    else:
        print("[-] Invalid choice")
        