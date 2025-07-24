#!/bin/bash

output="/tmp/found_secrets.txt"
patterns='(password|passwd|secret|token|apikey|api_key|authorization)'

echo "[+] Searching for Potential Secrets in Readable Files..."
echo "[+] Output will be saved to $output"

# Run the search and save output
find / -type f -readable -exec grep -IHinE "$patterns" {} \; 2>/dev/null | tee "$output"

echo
echo "[✓] Done. Full results saved to: $output"
