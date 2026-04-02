#!/usr/bin/env python3
# ============================================
# Network Scanner - Stage 2: Port Scanner
# ============================================

import socket                                      # lets us connect to ports
import ipaddress                                   # IP range handling
import subprocess                                  # for ping (from Stage 1)
import platform                                    # OS detection (from Stage 1)
from concurrent.futures import ThreadPoolExecutor  # threading for speed
from datetime import datetime                      # to track scan time

# ----------------------------------
# COMMON PORTS TO SCAN
# A dictionary of port : service name
# so our output is human-readable
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
# STEP 1: Check if a single port is open
# We try to connect to ip:port
# If connection succeeds → port is OPEN
# If it times out/refuses → port is CLOSED
# ----------------------------------
def scan_port(ip, port):
    try:
        # socket.AF_INET = IPv4
        # socket.SOCK_STREAM = TCP connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Only wait 1 second for a response
        sock.settimeout(1)
        
        # connect_ex returns 0 if connection succeeded
        # (unlike connect() which throws an exception)
        result = sock.connect_ex((str(ip), port))
        sock.close()
        
        if result == 0:
            # Look up service name, default to "Unknown"
            service = COMMON_PORTS.get(port, "Unknown")
            return port, service
        return None
    
    except socket.error:
        return None

# ----------------------------------
# STEP 2: Scan all common ports on one IP
# Runs scan_port() for every port in
# our COMMON_PORTS list using threads
# ----------------------------------
def scan_host(ip):
    print(f"\n[*] Scanning ports on {ip}...")
    
    open_ports = []
    
    # Use threads to scan all ports simultaneously
    with ThreadPoolExecutor(max_workers=50) as executor:
        # Submit a scan_port job for every port
        futures = {
            executor.submit(scan_port, ip, port): port 
            for port in COMMON_PORTS.keys()
        }
        
        # Collect results as they complete
        for future in futures:
            result = future.result()
            if result is not None:
                open_ports.append(result)
    
    # Sort results by port number
    open_ports.sort(key=lambda x: x[0])
    
    if open_ports:
        print(f"  [+] Open ports on {ip}:")
        for port, service in open_ports:
            print(f"      Port {port:<6} → {service}")
    else:
        print(f"  [-] No common ports open on {ip}")
    
    return ip, open_ports

# ----------------------------------
# STEP 3: Ping sweep (from Stage 1)
# Keeping this here so the script
# is fully self contained
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
    print(f"\n[*] Starting ping sweep on {network_cidr}")
    network = ipaddress.ip_network(network_cidr, strict=False)
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(ping_host, network.hosts())
    
    alive_hosts = [r for r in results if r is not None]
    print(f"[*] Found {len(alive_hosts)} alive host(s)")
    return alive_hosts

# ----------------------------------
# STEP 4: Full scan — combines both stages
# 1. Find alive hosts
# 2. Scan ports on each alive host
# ----------------------------------
def full_scan(network_cidr):
    start_time = datetime.now()
    print(f"\n{'='*50}")
    print(f"  NETWORK SCANNER v2.0")
    print(f"  Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}")
    
    # Stage 1: find alive hosts
    alive_hosts = ping_sweep(network_cidr)
    
    if not alive_hosts:
        print("\n[-] No alive hosts found. Exiting.")
        return
    
    # Stage 2: port scan each alive host
    print(f"\n[*] Starting port scan on {len(alive_hosts)} host(s)...")
    
    all_results = {}
    for host in alive_hosts:
        ip, open_ports = scan_host(host)
        all_results[ip] = open_ports
    
    # Final summary
    end_time = datetime.now()
    duration = end_time - start_time
    
    print(f"\n{'='*50}")
    print(f"  SCAN SUMMARY")
    print(f"{'='*50}")
    for ip, ports in all_results.items():
        if ports:
            port_list = ", ".join([str(p[0]) for p in ports])
            print(f"  {ip:<20} Open ports: {port_list}")
        else:
            print(f"  {ip:<20} No open ports found")
    
    print(f"\n[*] Scan completed in {duration.total_seconds():.2f} seconds")

# ----------------------------------
# Entry point
# ----------------------------------
if __name__ == "__main__":
    target = input("\nEnter network to scan (e.g. 192.168.1.0/24): ").strip()
    full_scan(target)