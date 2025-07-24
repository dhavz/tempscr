#!/bin/bash
echo "[+] Network Interfaces"
ip a

echo "[+] Listening Ports"
ss -tuln

echo "[+] Routing Table"
ip route

echo "[+] DNS Configuration"
cat /etc/resolv.conf
