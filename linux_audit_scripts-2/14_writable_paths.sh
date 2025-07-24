#!/bin/bash
echo "[+] Writable Directories in PATH"
IFS=':' read -ra dirs <<< "$PATH"
for dir in "${dirs[@]}"; do
  [ -w "$dir" ] && echo "Writable: $dir"
done

echo "[+] Writable System Directories"
/bin/find / -type d -perm -0002 -path "/usr*" 2>/dev/null
