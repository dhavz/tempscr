#!/bin/bash
echo "[+] User and Authentication Info"
cat /etc/passwd
cat /etc/shadow 2>/dev/null
getent passwd
echo "[*] Checking for users with UID 0:"
awk -F: '$3 == 0 { print $1 }' /etc/passwd
