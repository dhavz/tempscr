#!/bin/bash
# Simple Audit Launcher

echo "System Audit Tool - Starting..."

# Add some randomness to execution timing
sleep $((RANDOM % 5 + 1))

# Run the audit script with stealth options
if [ -f "./system_audit.sh" ]; then
    echo "Running system compliance audit..."
    bash ./system_audit.sh -s -q "$@" 2>/dev/null
    echo "Audit completed. Check output for results."
elif [ -f "./minimal_audit.sh" ]; then
    echo "Running minimal audit..."
    bash ./minimal_audit.sh "$@"
else
    echo "No audit scripts found."
    exit 1
fi 