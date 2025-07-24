#!/bin/bash
echo "[+] Installed Packages (Debian/Ubuntu)"
dpkg -l 2>/dev/null | head -n 10

echo "[+] Installed Packages (RHEL/CentOS)"
rpm -qa 2>/dev/null | head -n 10

echo "[+] Developer Tools"
which gcc g++ make 2>/dev/null
