#!/usr/bin/env bash
set -euo pipefail

# Defaults
HOST=""
PORT=22
USER=""
UPDIR=""
IDENTITY=""
OUT="sftp_audit_report.html"

usage(){ echo "Usage: $0 -h HOST [-p PORT] -u USER -d /Upload [-i ID_RSA] [-o report.html]"; exit 1; }

while getopts "h:p:u:d:i:o:" opt; do
  case $opt in
    h) HOST="$OPTARG";;
    p) PORT="$OPTARG";;
    u) USER="$OPTARG";;
    d) UPDIR="$OPTARG";;
    i) IDENTITY="$OPTARG";;
    o) OUT="$OPTARG";;
    *) usage;;
  esacdone

[[ -z "$HOST" || -z "$USER" || -z "$UPDIR" ]] && usage

# Workdir
WD="$(mktemp -d)"
trap 'rm -rf "$WD"' EXIT

SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=no -p "$PORT")
[[ -n "$IDENTITY" ]] && SSH_OPTS+=(-i "$IDENTITY")

# Collect banners
echo "[*] Grabbing SSH banner..."
( ssh -vvv "${SSH_OPTS[@]}" "$USER@$HOST" exit ) >"$WD/ssh_vvv.txt" 2>&1 || true

echo "[*] Grabbing host keys..."
( ssh-keyscan -p "$PORT" "$HOST" ) >"$WD/ssh_keyscan.txt" 2>&1 || true

# Optional nmap algo enumeration (if available)
NMAP_OUT="$WD/nmap.txt"
if command -v nmap >/dev/null 2>&1; then
  echo "[*] Running nmap ssh2-enum-algos..."
  ( nmap -p "$PORT" --script ssh2-enum-algos "$HOST" ) >"$NMAP_OUT" 2>&1 || true
else
  echo "nmap not found; skipping algo enumeration" >"$NMAP_OUT"
fi

# SFTP batch to exercise upload-only behavior
echo "[*] Running SFTP probes..."
PROBE_LOCAL="$WD/probe-$$.txt"
echo "probe $(date -u +"%FT%TZ")" > "$PROBE_LOCAL"
BASENAME="$(basename "$PROBE_LOCAL")"

SFTP_CMDS_LIST="$WD/sftp_list.txt"
cat > "$SFTP_CMDS_LIST" <<EOF
cd $UPDIR
ls -l
EOF

SFTP_CMDS_UPLOAD="$WD/sftp_upload.txt"
cat > "$SFTP_CMDS_UPLOAD" <<EOF
cd $UPDIR
put $PROBE_LOCAL
EOF

SFTP_CMDS_GET="$WD/sftp_get.txt"
cat > "$SFTP_CMDS_GET" <<EOF
cd $UPDIR
get $BASENAME $WD/get_attempt.bin
EOF

SFTP_CMDS_RENAME="$WD/sftp_rename.txt"
cat > "$SFTP_CMDS_RENAME" <<EOF
cd $UPDIR
rename $BASENAME ${BASENAME}.renamed
EOF

SFTP_CMDS_REMOVE="$WD/sftp_remove.txt"
cat > "$SFTP_CMDS_REMOVE" <<EOF
cd $UPDIR
rm ${BASENAME}.renamed
rm $BASENAME
EOF

# Runner
run_sftp () {
  local script="$1" out="$2"
  if [[ -n "$IDENTITY" ]]; then
    sftp -b "$script" -i "$IDENTITY" -P "$PORT" "$USER@$HOST" >"$out" 2>&1 || true
  else
    sftp -b "$script" -P "$PORT" "$USER@$HOST" >"$out" 2>&1 || true
  fi
}

run_sftp "$SFTP_CMDS_LIST"   "$WD/out_ls.txt"
run_sftp "$SFTP_CMDS_UPLOAD" "$WD/out_put.txt"
run_sftp "$SFTP_CMDS_GET"    "$WD/out_get.txt"
run_sftp "$SFTP_CMDS_RENAME" "$WD/out_rename.txt"
run_sftp "$SFTP_CMDS_REMOVE" "$WD/out_rm.txt"

# Heuristics
ok()   { echo "OK"; }
risk() { echo "RISK"; }

STAT_LIST="OK"
grep -E 'Cannot|Permission denied|Failure|not allowed|No such file' "$WD/out_ls.txt" >/dev/null 2>&1 || STAT_LIST="RISK"

STAT_PUT="OK"
grep -E 'Failure|Permission denied' "$WD/out_put.txt" >/dev/null 2>&1 && STAT_PUT="RISK"

STAT_GET="OK"
grep -E 'Fetching' "$WD/out_get.txt" >/dev/null 2>&1 && STAT_GET="RISK" # should NOT fetch
grep -Ei 'Permission denied|Failure|not found|No such file' "$WD/out_get.txt" >/dev/null 2>&1 || true
# If we actually created get_attempt.bin, that’s a risk
[[ -s "$WD/get_attempt.bin" ]] && STAT_GET="RISK"

STAT_RENAME="OK"
grep -E 'renamed|->' "$WD/out_rename.txt" >/dev/null 2>&1 && STAT_RENAME="RISK"

STAT_RM="OK"
grep -E 'Removing|removed' "$WD/out_rm.txt" >/dev/null 2>&1 && STAT_RM="RISK"

# OpenSSH version & CVE-2024-6387 window heuristic (8.5p1.. <9.8p1)
OPENSSH_VER="$(grep -i 'remote software version' "$WD/ssh_vvv.txt" | sed -E 's/.*version[[:space:]]+//I' | awk '{print $1}' | head -1)"
CVE_NOTE=""
if [[ "$OPENSSH_VER" =~ OpenSSH_([0-9]+\.[0-9]+) ]]; then
  ver="${BASH_REMATCH[1]}"
  # compare major.minor using awk
  cmp() { awk -v a="$1" -v b="$2" 'BEGIN{split(a,x,".");split(b,y,".");if (x[1]==y[1]) print (x[2]<y[2]? -1 : (x[2]>y[2]? 1 : 0)); else print (x[1]<y[1]? -1 : 1)}'; }
  if [[ $(cmp "$ver" "8.5") -ge 0 && $(cmp "$ver" "9.8") -lt 0 ]]; then
    CVE_NOTE="RISK"
  else
    CVE_NOTE="OK"
  fi
else
  CVE_NOTE="Unknown"
fi

# Terrapin indicators (very rough): chacha20-poly1305 or CBC+EtM offered
TERRAPIN="Unknown"
if grep -qi 'chacha20-poly1305' "$NMAP_OUT"; then TERRAPIN="RISK"; fi
if grep -qiE 'cbc' "$NMAP_OUT" && grep -qiE 'etm' "$NMAP_OUT"; then TERRAPIN="RISK"; fi
if [[ "$TERRAPIN" == "Unknown" && -s "$NMAP_OUT" ]]; then TERRAPIN="OK"; fi

# HTML report
html_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }
BANNER="$(cat "$WD/ssh_vvv.txt"   | html_escape)"
KEYSCAN="$(cat "$WD/ssh_keyscan.txt" | html_escape)"
NMAPTXT="$(cat "$NMAP_OUT" | html_escape)"

cat > "$OUT" <<EOF
<!doctype html><html><head><meta charset="utf-8">
<title>SFTP Audit Report</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:2rem}
h1{margin:0 0 .25rem 0} .muted{color:#666}
table{border-collapse:collapse;width:100%;margin-top:1rem}
th,td{border:1px solid #e5e5e5;padding:.5rem .6rem;font-size:14px;vertical-align:top}
th{background:#fafafa;text-align:left}
.ok{background:#eff9f1} .bad{background:#ffecec}
pre{white-space:pre-wrap;background:#fafafa;border:1px solid #eee;padding:.5rem;border-radius:6px}
</style></head><body>
<h1>SFTP Audit Report</h1>
<div class="muted">Host: ${HOST}:${PORT} · User: ${USER} · Run: $(date -u +"%FT%TZ")</div>

<table>
<tr><th>Category</th><th>Check</th><th>Status</th><th>Details</th><th>Evidence</th><th>Remediation</th></tr>

<tr class="${STAT_LIST/OK/ok}${STAT_LIST/RISK/bad}">
<td>Permissions</td><td>Directory listing disabled</td><td>${STAT_LIST}</td>
<td>Upload-only dropboxes should not permit listing.</td>
<td><pre>$(cat "$WD/out_ls.txt" | html_escape)</pre></td>
<td>Use d-wx------ + chroot/ForceCommand.</td></tr>

<tr class="${STAT_PUT/OK/ok}${STAT_PUT/RISK/bad}">
<td>Upload</td><td>Upload allowed</td><td>${STAT_PUT}</td>
<td>Uploads should succeed.</td>
<td><pre>$(cat "$WD/out_put.txt" | html_escape)</pre></td>
<td>Fix perms/config if intended upload fails.</td></tr>

<tr class="${STAT_GET/OK/ok}${STAT_GET/RISK/bad}">
<td>Permissions</td><td>Read-back prevented</td><td>${STAT_GET}</td>
<td>Clients must not download from dropbox.</td>
<td><pre>$(cat "$WD/out_get.txt" | html_escape)</pre></td>
<td>Remove read perms; ensure internal-sftp + chroot.</td></tr>

<tr class="${STAT_RENAME/OK/ok}${STAT_RENAME/RISK/bad}">
<td>Permissions</td><td>Rename prevented</td><td>${STAT_RENAME}</td>
<td>Renaming can enable tampering or confusion.</td>
<td><pre>$(cat "$WD/out_rename.txt" | html_escape)</pre></td>
<td>Deny rename or move/lock files on arrival.</td></tr>

<tr class="${STAT_RM/OK/ok}${STAT_RM/RISK/bad}">
<td>Permissions</td><td>Delete prevented</td><td>${STAT_RM}</td>
<td>Uploaders shouldn't delete after submission.</td>
<td><pre>$(cat "$WD/out_rm.txt" | html_escape)</pre></td>
<td>Harden perms; server-side move/lock.</td></tr>

<tr class="${CVE_NOTE/OK/ok}${CVE_NOTE/RISK/bad}">
<td>Vulnerabilities</td><td>OpenSSH regreSSHion window (CVE-2024-6387)</td><td>${CVE_NOTE}</td>
<td>Flagged if banner suggests OpenSSH 8.5–9.7.</td>
<td><pre>${OPENSSH_VER}</pre></td>
<td>Upgrade to 9.8p1+ / vendor-patched build.</td></tr>

<tr class="${TERRAPIN/OK/ok}${TERRAPIN/RISK/bad}">
<td>Vulnerabilities</td><td>Terrapin indicators</td><td>${TERRAPIN}</td>
<td>chacha20-poly1305 or CBC+EtM offered.</td>
<td><pre>$(grep -Ei "kex|cipher|mac|chacha|etm|cbc" "$NMAP_OUT" | html_escape)</pre></td>
<td>Prefer GCM; disable vulnerable modes.</td></tr>

</table>

<h3>SSH Banner (ssh -vvv)</h3><pre>${BANNER}</pre>
<h3>ssh-keyscan</h3><pre>${KEYSCAN}</pre>
<h3>Nmap ssh2-enum-algos</h3><pre>${NMAPTXT}</pre>

</body></html>
EOF

echo "[+] Report: $OUT"
