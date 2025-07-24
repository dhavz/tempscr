#!/bin/bash
echo "[+] Linux Capabilities on Binaries"
getcap -r / 2>/dev/null
