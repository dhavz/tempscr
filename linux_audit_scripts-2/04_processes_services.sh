#!/bin/bash
echo "[+] Running Processes"
ps aux

echo "[+] Services"
systemctl list-units --type=service --all
