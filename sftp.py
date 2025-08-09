#!/usr/bin/env python3
import argparse, os, sys, subprocess, shlex, tempfile, time, random, string, html
from datetime import datetime
from pathlib import Path

# Third-party: paramiko
try:
    import paramiko
except ImportError:
    print("Please: pip install paramiko", file=sys.stderr)
    sys.exit(2)

################################################################################
# Helpers
################################################################################

def run(cmd, timeout=20):
    try:
        out = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode(errors="ignore")
    except Exception as e:
        return f"__ERROR__ {e}"

def rand_name(prefix, ext="txt", n=6):
    s = "".join(random.choice(string.ascii_lowercase) for _ in range(n))
    return f"{prefix}-{s}.{ext}"

def record(result_list, category, name, ok, details, evidence=None, remediation=None):
    result_list.append({
        "category": category,
        "name": name,
        "ok": bool(ok),
        "details": details,
        "evidence": evidence or "",
        "remediation": remediation or ""
    })

################################################################################
# SSH/SFTP checks
################################################################################

def ssh_banner(host, port):
    # Try ssh -vvv (fast banner) and ssh-keyscan for hostkey/fingerprint
    vvv = run(f"ssh -vvv -oBatchMode=yes -oStrictHostKeyChecking=no -p {port} {host} exit", timeout=10)
    keyscan = run(f"ssh-keyscan -p {port} {host}", timeout=10)
    return vvv, keyscan

def nmap_algos(host, port):
    # Requires nmap + NSE ssh2-enum-algos
    return run(f"nmap -p {port} --script ssh2-enum-algos {host}", timeout=45)

def parse_openssh_version(vvv_output):
    # Find "Remote protocol version 2.0, remote software version OpenSSH_9.6p1"
    ver = None
    for line in vvv_output.splitlines():
        if "remote software version" in line.lower():
            # Try to extract token after this phrase
            parts = line.split("version", 1)[-1].strip().split()
            if parts:
                ver = parts[0]
                break
    return ver  # e.g., OpenSSH_9.6p1

def version_in_range(ver_token, low_inc, high_ex):
    # crude parser for OpenSSH_X.YpZ
    # returns True if low_inc <= ver < high_ex
    try:
        if not ver_token or "OpenSSH_" not in ver_token:
            return False
        v = ver_token.split("OpenSSH_")[-1]
        # remove possible distro suffix
        core = "".join(ch for ch in v if (ch.isdigit() or ch=='.'))
        def to_tuple(x):
            parts = x.split(".")
            return tuple(int(p) for p in parts)
        vt = to_tuple(core)
        return to_tuple(low_inc) <= vt < to_tuple(high_ex)
    except:
        return False

def sftp_probe(host, port, user, auth, remote_dir, results):
    t0 = time.time()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect over SSH
    if auth.get("pkeyfile"):
        pkey = paramiko.RSAKey.from_private_key_file(auth["pkeyfile"], password=auth.get("pkeypass"))
        client.connect(host, port=port, username=user, pkey=pkey, timeout=15, look_for_keys=False, allow_agent=False)
    else:
        client.connect(host, port=port, username=user, password=auth["password"], timeout=15, look_for_keys=False, allow_agent=False)

    transport = client.get_transport()
    so = transport.get_security_options()
    # Note: security_options here are client prefs, not server offers. Keep for evidence only.
    kex = so.kex
    ciphers = so.ciphers
    macs = so.macs

    # Start SFTP
    sftp = client.open_sftp()
    sftp_version = getattr(sftp, 'sftp_version', None)

    # Basic evidence
    record(results, "SFTP", "SFTP Protocol Version", True, f"Server reports SFTP v{sftp_version}", evidence=f"paramiko sftp_version={sftp_version}")
    record(results, "SSH", "Client Prefs (Paramiko)", True, "Client-side preferences captured (not server truth).", evidence=f"kex={kex}\nciphers={ciphers}\nmacs={macs}")

    # Ensure remote_dir exists (do not create if missing)
    # Attempt listing (should fail in upload-only d-wx------)
    listing_ok = True
    listing_err = ""
    try:
        _ = sftp.listdir(remote_dir)
    except Exception as e:
        listing_ok = False
        listing_err = str(e)

    if listing_ok:
        record(results, "Permissions", "Directory listing disabled?", False,
               f"`ls` worked in {remote_dir} (unexpected for upload-only).",
               evidence="listdir() returned entries",
               remediation="Disable listing (execute-only) on upload dropbox; use d-wx------ and chroot, verify Match/ChrootDirectory.")
    else:
        record(results, "Permissions", "Directory listing disabled?", True,
               f"`ls` failed as expected in upload-only dropbox.",
               evidence=listing_err)

    # Upload probe
    local_tmp = Path(tempfile.gettempdir())
    up1 = local_tmp / rand_name("audit")
    up1.write_text("probe-1\n")
    remote1 = remote_dir.rstrip("/") + "/" + up1.name

    put_ok, put_err = True, ""
    try:
        sftp.put(str(up1), remote1)
    except Exception as e:
        put_ok, put_err = False, str(e)

    record(results, "Upload", "Can upload file", put_ok,
           "Upload should succeed in upload-only directory.",
           evidence=put_err if not put_ok else f"uploaded {up1.name}",
           remediation=None if put_ok else "Fix directory/write perms or SFTP config for intended drop folder.")

    # Try to read back (should fail)
    get_ok, get_err = True, ""
    local_copy = local_tmp / rand_name("download-attempt")
    try:
        sftp.get(remote1, str(local_copy))
    except Exception as e:
        get_ok, get_err = False, str(e)

    record(results, "Permissions", "Prevent read-back", not get_ok,
           "Upload-only dropbox must not allow downloads/read-back.",
           evidence=get_err if not get_ok else "able to get()",
           remediation="Ensure directory perms and ForceCommand/internal-sftp + Chroot prevent reads; verify POSIX perms (no 'r').")

    # Try stat on guessed names (should fail)
    guess = remote_dir.rstrip("/") + "/" + rand_name("guess")
    stat_ok, stat_err = True, ""
    try:
        sftp.stat(guess)
    except Exception as e:
        stat_ok, stat_err = False, str(e)

    record(results, "Permissions", "Prevent filename probing (stat)", not stat_ok,
           "Upload-only dropbox should not reveal existence via stat().",
           evidence=stat_err if not stat_ok else "stat() returned info",
           remediation="Tighten perms and ensure chroot + upload mask prevent metadata disclosure.")

    # Try overwrite
    up2 = local_tmp / rand_name("audit-overwrite")
    up2.write_text("probe-2-overwrite\n")
    remote_same = remote1  # same name as first upload
    overwrite_ok = True
    overwrite_err = ""
    try:
        sftp.put(str(up2), remote_same)
    except Exception as e:
        overwrite_ok = False
        overwrite_err = str(e)

    record(results, "Permissions", "Prevent overwrite of existing files", not overwrite_ok,
           "Overwrite should usually be denied in dropboxes (or server should move/lock immediately).",
           evidence=overwrite_err if not overwrite_ok else "second put() succeeded",
           remediation="Configure server to move/lock files on arrival or deny overwrites.")

    # Try rename (should be denied often)
    new_remote = remote1 + ".renamed"
    rename_ok = True
    rename_err = ""
    try:
        sftp.rename(remote1, new_remote)
    except Exception as e:
        rename_ok = False
        rename_err = str(e)
    record(results, "Permissions", "Prevent rename operations", not rename_ok,
           "Renames in dropbox are often restricted.",
           evidence=rename_err if not rename_ok else "rename succeeded",
           remediation="Harden sftp subsystem or use permissions/umask to prevent renames.")

    # Try delete (should be denied)
    rm_ok = True
    rm_err = ""
    try:
        sftp.remove(new_remote if rename_ok else remote1)
    except Exception as e:
        rm_ok = False
        rm_err = str(e)
    record(results, "Permissions", "Prevent delete of uploaded files", not rm_ok,
           "Delete should be denied to prevent tampering after upload.",
           evidence=rm_err if not rm_ok else "remove() succeeded",
           remediation="Enforce permissions so uploaders cannot delete.")

    sftp.close()
    client.close()
    t1 = time.time()
    record(results, "Session", "End-to-end time (s)", True, f"{t1 - t0:.2f}", evidence="")

################################################################################
# HTML report
################################################################################

HTML_TMPL = """<!doctype html>
<html><head>
<meta charset="utf-8">
<title>SFTP Audit Report</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif; margin:2rem;}
h1{margin-bottom:.25rem} .muted{color:#666}
table{border-collapse:collapse;width:100%;margin-top:1rem}
th,td{border:1px solid #e5e5e5;padding:.5rem .6rem;font-size:14px;vertical-align:top}
th{background:#fafafa;text-align:left}
.bad{background:#ffecec} .ok{background:#eff9f1}
.category{font-weight:600}
pre{white-space:pre-wrap;background:#fafafa;border:1px solid #eee;padding:.5rem;border-radius:6px}
.note{font-size:13px;color:#444;margin-top:1rem}
.kv{margin:.75rem 0}
.kv div{margin-bottom:.25rem}
</style></head><body>
<h1>SFTP Audit Report</h1>
<div class="muted">Host: {host}:{port} · User: {user} · Run: {ts}</div>

<div class="kv">
  <div><strong>SSH banner (ssh -vvv):</strong></div>
  <pre>{banner}</pre>
  <div><strong>ssh-keyscan:</strong></div>
  <pre>{keyscan}</pre>
  <div><strong>Nmap ssh2-enum-algos:</strong></div>
  <pre>{nmap}</pre>
</div>

<table>
  <tr><th>Category</th><th>Check</th><th>Status</th><th>Details</th><th>Evidence</th><th>Remediation</th></tr>
  {rows}
</table>

<div class="note">
<strong>Notes & References</strong><br>
• SFTP v3 ops & background (SFTP rides on SSH; protocol security depends on SSH).<br>
• SSH algo enumeration via Nmap helps spot weak KEX/ciphers/MACs; prefer modern sets.<br>
• Watch for OpenSSH regreSSHion (CVE-2024-6387) if banner shows affected versions.<br>
• Terrapin risks depend on negotiated modes (e.g., chacha20-poly1305, CBC-EtM); prefer GCM.<br>
</div>
</body></html>
"""

def render_html(host, port, user, banner, keyscan, nmap_out, results):
    def esc(x): return html.escape(x or "")
    rows = []
    for r in results:
        cls = "ok" if r["ok"] else "bad"
        rows.append(
            f"<tr class='{cls}'>"
            f"<td class='category'>{esc(r['category'])}</td>"
            f"<td>{esc(r['name'])}</td>"
            f"<td>{'OK' if r['ok'] else 'RISK'}</td>"
            f"<td>{esc(r['details'])}</td>"
            f"<td><pre>{esc(r['evidence'])}</pre></td>"
            f"<td>{esc(r['remediation'])}</td>"
            f"</tr>"
        )
    return HTML_TMPL.format(
        host=esc(host), port=esc(str(port)), user=esc(user),
        ts=datetime.utcnow().isoformat()+"Z",
        banner=esc(banner),
        keyscan=esc(keyscan),
        nmap=esc(nmap_out),
        rows="\n".join(rows)
    )

################################################################################
# Main
################################################################################

def main():
    ap = argparse.ArgumentParser(description="Comprehensive SFTP audit (upload-only safe).")
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--user", required=True)
    auth = ap.add_mutually_exclusive_group(required=True)
    auth.add_argument("--password")
    auth.add_argument("--pkeyfile")
    ap.add_argument("--pkeypass")
    ap.add_argument("--upload-dir", required=True, help="Remote upload-only directory (e.g., /Upload)")
    ap.add_argument("--out", default="sftp_audit_report.html")
    args = ap.parse_args()

    results = []

    # Banners and algos
    banner, keyscan = ssh_banner(args.host, args.port)
    nmap_out = nmap_algos(args.host, args.port)

    # Flag OpenSSH CVE-2024-6387 window if possible
    openssh_ver = parse_openssh_version(banner)
    if openssh_ver and version_in_range(openssh_ver, "8.5", "9.8"):
        record(results, "Vuln", "OpenSSH regreSSHion window (CVE-2024-6387)", False,
               f"Banner shows {openssh_ver} (potentially affected range).",
               evidence="Qualys CVE-2024-6387 regreSSHion",
               remediation="Upgrade OpenSSH to 9.8p1+ or vendor-patched build; verify glibc impact; see vendor advisories.")

    # Terrapin heuristics: if nmap shows chacha20-poly1305 or *-cbc* with EtM
    terrapin_risk = False
    terr_notes = []
    if "chacha20-poly1305" in nmap_out.lower():
        terrapin_risk = True
        terr_notes.append("chacha20-poly1305 offered")
    if "cbc" in nmap_out.lower() and ("etm" in nmap_out.lower() or "etm@openssh.com" in nmap_out.lower()):
        terrapin_risk = True
        terr_notes.append("CBC-EtM offered")
    if terrapin_risk:
        record(results, "Vuln", "Terrapin risk indicators", False,
               "Server advertises modes linked to Terrapin attacks.",
               evidence="; ".join(terr_notes),
               remediation="Prefer GCM modes; update SSH, disable vulnerable modes, and apply vendor mitigations.")

    # SFTP probes (safe)
    sftp_probe(args.host, args.port, args.user,
               {"password": args.password, "pkeyfile": args.pkeyfile, "pkeypass": args.pkeypass},
               args.upload_dir, results)

    html_report = render_html(args.host, args.port, args.user, banner, keyscan, nmap_out, results)
    Path(args.out).write_text(html_report, encoding="utf-8")
    print(f"[+] Report written to {args.out}")

if __name__ == "__main__":
    main()
