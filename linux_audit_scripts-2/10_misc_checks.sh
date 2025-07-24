#!/bin/bash
echo "[+] SSH Config"
cat /etc/ssh/sshd_config 2>/dev/null

echo "[+] Bash Aliases"
cat ~/.bashrc ~/.bash_aliases 2>/dev/null

echo "[+] Kernel Modules"
lsmod
