#!/bin/bash
echo "[+] Searching for Potential Secrets in Readable Files"
patterns='(password|passwd|secret|token|apikey|api_key|authorization)'
find / -type f -readable -exec grep -IHinE "$patterns" {} \; 2>/dev/null
