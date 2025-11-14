#!/usr/bin/env python3
"""
parse_nmap_to_csv.py

Takes an Nmap normal output file (.nmap) and generates:
1. ip_ports.csv           => IP, "port port port"
2. ip_ports_expanded.csv  => IP:port per line

Usage:
    python3 parse_nmap_to_csv.py input.nmap
"""

import re
import csv
import sys
from pathlib import Path

if len(sys.argv) < 2:
    print("Usage: python3 parse_nmap_to_csv.py input.nmap")
    sys.exit(1)

input_file = Path(sys.argv[1])
if not input_file.exists():
    print(f"File not found: {input_file}")
    sys.exit(1)

# Regex to find a port line like:
# 80/tcp open http
PORT_REGEX = re.compile(r"(\d+)/tcp\s+open")

ip_ports = {}  # { "192.168.1.10": [80,443,25] }

current_ip = None

with input_file.open("r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.strip()

        # Detect host line like: "Nmap scan report for 192.168.1.10"
        if line.startswith("Nmap scan report for"):
            parts = line.split()
            current_ip = parts[-1]  # last part is the IP/hostname
            ip_ports.setdefault(current_ip, [])
            continue

        # Parse ports
        match = PORT_REGEX.search(line)
        if match and current_ip:
            port = int(match.group(1))
            if port not in ip_ports[current_ip]:
                ip_ports[current_ip].append(port)

# -----------------------------
# CSV 1: ip_ports.csv
# -----------------------------
with open("ip_ports.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["IP", "Ports"])
    for ip, ports in ip_ports.items():
        ports_str = " ".join(str(p) for p in sorted(ports))
        writer.writerow([ip, ports_str])

# -----------------------------
# CSV 2: ip_ports_expanded.csv
# -----------------------------
with open("ip_ports_expanded.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["IP_Port"])
    for ip, ports in ip_ports.items():
        for p in sorted(ports):
            writer.writerow([f"{ip}:{p}"])

print("✅ Done!")
print("Generated:")
print("  • ip_ports.csv")
print("  • ip_ports_expanded.csv")
