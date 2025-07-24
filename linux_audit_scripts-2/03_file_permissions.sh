#!/bin/bash
echo "[+] World-writable Files"
find / -type f -perm -0002 -ls 2>/dev/null

echo "[+] SUID Binaries"
find / -perm -4000 -type f 2>/dev/null

echo "[+] SGID Binaries"
find / -perm -2000 -type f 2>/dev/null
