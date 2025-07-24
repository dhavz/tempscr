#!/bin/bash
echo "[+] Auth Logs"
cat /var/log/auth.log 2>/dev/null | tail -n 20
cat /var/log/secure 2>/dev/null | tail -n 20

echo "[+] Syslog"
cat /var/log/syslog 2>/dev/null | tail -n 20
