#!/bin/bash

# Simplified SUID Privilege Escalation Finder Script

echo "[*] SUID Check - Looking for potentially exploitable binaries..."

if ! command -v strings &>/dev/null; then
    echo "[!] 'strings' command not found!"
fi

if ! command -v strace &>/dev/null; then
    echo "[!] 'strace' command not found!"
fi

ROOT_FOLDER="/"
find "$ROOT_FOLDER" -perm -4000 -type f ! -path "/dev/*" 2>/dev/null | while read sname; do
    echo "[+] Found SUID binary: $sname"

    # Check if current user owns it
    if [ -O "$sname" ]; then
        echo "    [!] You own this SUID file (could be abused): $sname"
    fi

    # Check if writable
    if [ -w "$sname" ]; then
        echo "    [!] Writable SUID file (VERY dangerous): $sname"
    fi

    # Try basic string check for commands/binaries
    if command -v strings &>/dev/null; then
        strings "$sname" 2>/dev/null | grep -E "/bin/|/usr/|sh|bash" | sort -u | while read line; do
            if [ -f "$line" ] && [ -w "$line" ]; then
                echo "    [!] Uses writable file: $line (from $sname)"
            fi
        done
    fi
done

echo "[*] Done. Review writable and owned SUID files carefully."
