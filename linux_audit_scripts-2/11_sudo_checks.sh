#!/bin/bash
echo "[+] Sudo Permissions"
sudo -l 2>/dev/null

echo "[+] Sudo NOPASSWD Entries"
grep -r 'NOPASSWD' /etc/sudoers* 2>/dev/null
