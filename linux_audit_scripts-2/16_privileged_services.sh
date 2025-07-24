#!/bin/bash
echo "[+] Writable systemd service files"
find /etc/systemd/system /lib/systemd/system -type f -writable 2>/dev/null
