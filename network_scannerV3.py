#!/usr/bin/env python3
# ============================================
# Network Scanner - Stage 3: Banner Grabber
# ============================================

import socket
import ipaddress
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# ----------------------------------
# COMMON PORTS (expanded from Stage 2)
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

# ----------------------------------
# HTTP probes for web servers
# Some ports don't send a banner
# automatically — we need to ASK
# by sending an HTTP request
# ----------------------------------
HTTP_PORTS = {80, 443, 8080, 8443}

# ----------------------------------
# STEP 1: Grab banner from a port
# We connect and listen for what
# the service says about itself
# ----------------------------------
def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((str(ip), port))

        # For HTTP ports, we need to send a request first
        # before the server responds with info
        if port in HTTP_PORTS:
            # Send a basic HTTP HEAD request
            request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
            sock.send(request.encode())
        else:
            # For other services (SSH, FTP etc)
            # just send a newline to prompt a response
            sock.send(b"\r\n")

        # Receive up to 1024 bytes of response
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()

        # Clean up the banner — remove extra whitespace
        # and only take the first 3 lines (most useful info)
        lines = [line.strip() for line in banner.splitlines() if line.strip()]
        clean_banner = " | ".join(lines[:3])

        return clean_banner if clean_banner else None

    except socket.timeout:
        return None
    except ConnectionRefusedError:
        return None
    except Exception:
        return None

# ----------------------------------
# STEP 2: Scan ports + grab banners
# Combines Stage 2 port scanning
# with our new banner grabbing
# ----------------------------------
def scan_port_with_banner(ip, port):
    try:
        # First check if port is open (from Stage 2)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((str(ip), port))
        sock.close()

        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")

            # Port is open — now try to grab its banner
            banner = grab_banner(ip, port)

            return {
                "port": port,
                "service": service,
                "banner": banner
            }
        return None

    except socket.error:
        return None

# ----------------------------------
# STEP 3: Full host scan with banners
# ----------------------------------
def scan_host_with_banners(ip):
    print(f"\n[*] Scanning {ip}...")
    open_ports = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(scan_port_with_banner, ip, port): port
            for port in COMMON_PORTS.keys()
        }
        for future in futures:
            result = future.result()
            if result is not None:
                open_ports.append(result)

    # Sort by port number
    open_ports.sort(key=lambda x: x["port"])

    if open_ports:
        print(f"\n  {'PORT':<8} {'SERVICE':<12} {'BANNER'}")
        print(f"  {'-'*60}")
        for entry in open_ports:
            port    = entry["port"]
            service = entry["service"]
            banner  = entry["banner"] or "No banner received"

            # Truncate long banners for clean display
            if len(banner) > 60:
                banner = banner[:60] + "..."

            print(f"  {port:<8} {service:<12} {banner}")
    else:
        print(f"  [-] No open ports found on {ip}")

    return ip, open_ports

# ----------------------------------
# Ping helpers (from Stage 1)
# ----------------------------------
def get_ping_command(ip):
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", "1", "-w", "500", str(ip)]
    else:
        return ["ping", "-c", "1", "-W", "1", str(ip)]

def ping_host(ip):
    command = get_ping_command(ip)
    result = subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    if result.returncode == 0:
        return str(ip)
    return None

def ping_sweep(network_cidr):
    print(f"[*] Starting ping sweep on {network_cidr}")
    network = ipaddress.ip_network(network_cidr, strict=False)
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(ping_host, network.hosts())
    alive_hosts = [r for r in results if r is not None]
    print(f"[*] Found {len(alive_hosts)} alive host(s)")
    return alive_hosts

# ----------------------------------
# STEP 4: Entry point
# Option to scan whole network
# or just one specific IP
# ----------------------------------
if __name__ == "__main__":
    print("\n========================================")
    print("  NETWORK SCANNER v3.0 - Banner Grabber")
    print("========================================")
    print("\nScan options:")
    print("  1. Scan entire network (ping sweep + port scan + banners)")
    print("  2. Scan single IP     (port scan + banners only)")

    choice = input("\nChoice (1 or 2): ").strip()

    if choice == "1":
        target = input("Enter network (e.g. 192.168.0.0/24): ").strip()
        start  = datetime.now()
        alive  = ping_sweep(target)
        for host in alive:
            scan_host_with_banners(host)
        duration = datetime.now() - start
        print(f"\n[*] Completed in {duration.total_seconds():.2f} seconds")

    elif choice == "2":
        target = input("Enter IP to scan (e.g. 192.168.0.158): ").strip()
        start  = datetime.now()
        scan_host_with_banners(target)
        duration = datetime.now() - start
        print(f"\n[*] Completed in {duration.total_seconds():.2f} seconds")

    else:
        print("[-] Invalid choice")
        