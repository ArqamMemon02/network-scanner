#!/usr/bin/env python3
# ============================================
# Network Scanner - Stage 1: Ping Sweeper
# ============================================

import subprocess   # lets us run system commands (like ping)
import platform     # detects if we're on Windows or Linux
import ipaddress    # helps us work with IP ranges
from concurrent.futures import ThreadPoolExecutor  # threading for speed

# ----------------------------------
# STEP 1: Detect the OS
# We need this because the ping command
# is slightly different on Windows vs Linux
# ----------------------------------
def get_ping_command(ip):
    system = platform.system().lower()  # returns 'windows' or 'linux'
    
    if system == "windows":
        # -n 1 = send 1 packet, -w 500 = wait 500ms max
        return ["ping", "-n", "1", "-w", "500", str(ip)]
    else:
        # -c 1 = send 1 packet, -W 1 = wait 1 second max
        return ["ping", "-c", "1", "-W", "1", str(ip)]

# ----------------------------------
# STEP 2: Ping a single IP
# Returns True if host is alive
# Returns False if no response
# ----------------------------------
def ping_host(ip):
    command = get_ping_command(ip)
    
    # subprocess.run() runs the ping command
    # stdout/stderr=subprocess.DEVNULL silences the output
    # (we don't want ping's raw output cluttering our screen)
    result = subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    
    # returncode 0 means success (host replied)
    # anything else means no response
    if result.returncode == 0:
        print(f"  [+] Host ALIVE: {ip}")
        return str(ip)
    return None

# ----------------------------------
# STEP 3: Sweep an entire network range
# Uses threads to scan multiple IPs
# at the same time (much faster!)
# ----------------------------------
def ping_sweep(network_cidr):
    print(f"\n[*] Starting ping sweep on: {network_cidr}")
    print(f"[*] Scanning...\n")
    
    # ipaddress.ip_network() parses the CIDR notation
    # e.g. "192.168.1.0/24" → all IPs from .1 to .254
    # strict=False is forgiving with input format
    network = ipaddress.ip_network(network_cidr, strict=False)
    
    alive_hosts = []
    
    # ThreadPoolExecutor runs ping_host() on many IPs simultaneously
    # max_workers=50 means 50 threads at once — fast but not too aggressive
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(ping_host, network.hosts())
    
    # Filter out the None results (dead hosts)
    alive_hosts = [r for r in results if r is not None]
    
    # Summary
    print(f"\n[*] Scan complete!")
    print(f"[*] Found {len(alive_hosts)} alive host(s):\n")
    for host in alive_hosts:
        print(f"    → {host}")
    
    return alive_hosts

# ----------------------------------
# STEP 4: Entry point
# This runs when you execute the script
# ----------------------------------
if __name__ == "__main__":
    # Get input from user
    target = input("\nEnter network to scan (e.g. 192.168.1.0/24): ").strip()
    
    # Run the sweep and store results
    # (we'll pass these into Stage 2 later!)
    alive = ping_sweep(target)