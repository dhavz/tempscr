#!/bin/bash
# System Information Collection Tool
# Performs selective enumeration without aggressive file system scanning

# Configuration
OUTPUT_DIR="/tmp"
LOG_FILE="$OUTPUT_DIR/.sysinfo_$(date +%s).log"
STEALTH_DELAY=8
MAX_RESULTS=20

# Stealth delay function
stealth_sleep() {
    sleep $((RANDOM % $STEALTH_DELAY + 3))
}

# Quiet execution with limited output
quiet_exec() {
    local title="$1"
    local cmd="$2"
    echo "[$(date '+%H:%M:%S')] Checking $title..." >&2
    echo "=== $title ===" >> "$LOG_FILE"
    eval "$cmd" 2>/dev/null | head -n $MAX_RESULTS >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    stealth_sleep
}

# Start enumeration
echo "System Information Collection Tool"
echo "================================="
echo "Output will be saved to: $LOG_FILE"
echo ""

# Basic system information (safe)
quiet_exec "System Info" "uname -a; uptime; date"
quiet_exec "Current User" "id; whoami; groups"

# User enumeration (limited)
quiet_exec "User Accounts" "getent passwd | grep -E '/(bash|sh)$' | head -15"
quiet_exec "Current Groups" "getent group | head -15"

# Network information (basic only)
quiet_exec "Network Config" "ip addr show 2>/dev/null || ifconfig 2>/dev/null"
quiet_exec "Network Routes" "ip route show 2>/dev/null || route -n 2>/dev/null"

# Process information (limited)
quiet_exec "Running Processes" "ps aux | head -25"
quiet_exec "Process Tree" "pstree -p 2>/dev/null | head -20"

# Service information (selective)
quiet_exec "Active Services" "systemctl list-units --type=service --state=active --no-pager 2>/dev/null | head -20"
quiet_exec "Listening Ports" "ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null | head -20"

# File system (very limited, no aggressive scanning)
quiet_exec "Mount Points" "mount | grep -v tmpfs | head -15"
quiet_exec "Disk Usage" "df -h | head -10"

# Environment and configuration (safe)
quiet_exec "Environment" "env | grep -E '^(PATH|HOME|USER|SHELL)=' | head -10"
quiet_exec "Sudo Access" "timeout 5 sudo -l 2>/dev/null | head -10"

# SSH configuration (read-only)
quiet_exec "SSH Config" "grep -E '^(Port|PermitRootLogin|PasswordAuthentication)' /etc/ssh/sshd_config 2>/dev/null"

# Scheduled tasks (limited)
quiet_exec "User Crontab" "crontab -l 2>/dev/null | head -10"
quiet_exec "System Cron" "ls -la /etc/cron.d/ 2>/dev/null | head -10"

# Recent logs (minimal)
quiet_exec "Recent Auth" "tail -5 /var/log/auth.log 2>/dev/null || tail -5 /var/log/secure 2>/dev/null"

# Home directory (current user only)
quiet_exec "Home Directory" "ls -la $HOME 2>/dev/null | head -15"

# Writable locations (very limited scope)
quiet_exec "Writable Dirs" "find /tmp /var/tmp -maxdepth 1 -writable -type d 2>/dev/null"

# SUID files (very selective)
quiet_exec "SUID in /usr/bin" "find /usr/bin -maxdepth 1 -perm -4000 -type f 2>/dev/null | head -10"

echo ""
echo "Collection completed successfully."
echo "Results saved to: $LOG_FILE"
echo ""
echo "To view results:"
echo "  cat $LOG_FILE"
echo "  grep -A5 -B1 'pattern' $LOG_FILE"
echo ""
echo "To clean up:"
echo "  rm $LOG_FILE" 