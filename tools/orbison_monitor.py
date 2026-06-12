#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""
Production monitor for os-kea-unbound.

Runs hourly checks against the production box, archives snapshots locally,
and generates a weekly summary comparing audit script output against raw
DNS drill verification.

Usage:
    python3 tools/orbison_monitor.py --once
    python3 tools/orbison_monitor.py              # runs checks + archives
    python3 tools/orbison_monitor.py --weekly-summary
    python3 tools/orbison_monitor.py --install-launchd
    python3 tools/orbison_monitor.py --uninstall-launchd

See tools/.env.example for required environment variables.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import subprocess
import sys
import time

# Allow `import tools.lib.*` from repo root
sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))

from tools.lib.dns_verify import DNSVerifier
from tools.lib.kea import KeaClient, KeaError
from tools.lib.report import Archive, CheckResult, Snapshot, WeeklySummary
from tools.lib.ssh import SSHSession
from tools.lib.unbound import UnboundClient

SCRIPT_PATH = pathlib.Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[1]
LAUNCHD_LABEL = "com.tkr.kea-unbound-monitor"
LAUNCHD_PLIST = (
    pathlib.Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
)


# ---------------------------------------------------------------------------
# Environment loading
# ---------------------------------------------------------------------------

def _load_env(config_file: str) -> None:
    path = pathlib.Path(config_file)
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


def _require(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        print(f"[ERROR] Required env var {name} is not set.", file=sys.stderr)
        sys.exit(1)
    return val


def _get_prod_domain() -> str:
    return os.environ.get("PROD_DOMAIN", "").strip()


def _get_archive_dir() -> pathlib.Path:
    d = os.environ.get("MONITOR_ARCHIVE_DIR", "~/.kea-unbound-monitor")
    return pathlib.Path(d).expanduser()


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_service_health(ssh: SSHSession) -> CheckResult:
    details_parts: list[str] = []
    ok = True
    raw: dict = {}

    # Daemon status
    try:
        status = ssh.sudo(
            "/usr/local/sbin/pluginctl -s kea-unbound-ddns status", timeout=10
        )
        running = "is running" in status
        raw["daemon_status"] = status[:200]
        raw["daemon_running"] = running
        if not running:
            ok = False
            details_parts.append("daemon not running")
    except Exception as exc:
        ok = False
        details_parts.append(f"status check error: {exc}")

    # PID file consistency
    try:
        pid = ssh.sudo("cat /var/run/kea-unbound-ddns.pid", check=False).strip()
        sup = ssh.sudo("cat /var/run/kea-unbound-ddns.supervisor.pid", check=False).strip()
        raw["child_pid"] = pid
        raw["supervisor_pid"] = sup
        if pid and sup and pid == sup:
            ok = False
            details_parts.append("child and supervisor PIDs are identical")
    except Exception:
        pass

    # Port 53535
    try:
        bound_check = ssh.run("netstat -ul 2>/dev/null || ss -ul 2>/dev/null", check=False)
        port_bound = "53535" in bound_check
        raw["port_53535_bound"] = port_bound
        if not port_bound:
            ok = False
            details_parts.append("port 53535 not bound")
    except Exception:
        pass

    details = "; ".join(details_parts) if details_parts else "all ok"
    return CheckResult("service_health", ok, details, raw)


def check_kea_health(kea: KeaClient) -> CheckResult:
    raw: dict = {}
    ok = True
    details = ""

    try:
        ver = kea.version_get()
        raw["version"] = ver[:80]
    except Exception as exc:
        return CheckResult("kea_health", False, f"version-get failed: {exc}", raw)

    try:
        leases = kea.lease4_get_all()
        raw["lease_count"] = len(leases)
        details = f"{len(leases)} active leases"
    except KeaError as exc:
        ok = False
        details = f"lease4-get-all failed: {exc}"

    return CheckResult("kea_health", ok, details, raw)


def check_unbound_health(unbound: UnboundClient) -> CheckResult:
    raw: dict = {}
    ok = True
    details = ""

    try:
        status = unbound.status()
        running = "is running" in status or "uptime" in status
        raw["status"] = status[:200]
        if not running:
            ok = False
            details = "unbound not running"
    except Exception as exc:
        return CheckResult("unbound_health", False, f"status error: {exc}", raw)

    try:
        count = unbound.local_data_count()
        raw["local_data_count"] = count
        details = details or f"{count} local_data entries"
    except Exception as exc:
        raw["local_data_error"] = str(exc)

    return CheckResult("unbound_health", ok, details, raw)


def check_audit_snapshot(ssh: SSHSession) -> CheckResult:
    try:
        raw_output = ssh.sudo(
            "/usr/local/opnsense/scripts/keaunbound/local-data-audit.py --report-json",
            timeout=30,
        )
        audit = json.loads(raw_output)
    except Exception as exc:
        return CheckResult("audit_snapshot", False, f"audit failed: {exc}", None)

    complete = audit.get("complete", True)
    records = audit.get("records", [])
    orphaned = audit.get("orphaned_ptrs", [])

    by_status: dict[str, int] = {}
    for r in records:
        s = r.get("status", "unknown")
        by_status[s] = by_status.get(s, 0) + 1

    raw = {
        "complete": complete,
        "kea_error": audit.get("kea_error"),
        "record_count": len(records),
        "orphan_count": len(orphaned),
        "stale_count": by_status.get("stale", 0),
        "ok_count": by_status.get("ok", 0),
        "missing_ptr_count": by_status.get("missing-PTR", 0),
        "by_status": by_status,
    }

    ok = complete and by_status.get("stale", 0) == 0
    parts = []
    if not complete:
        parts.append(f"kea_error={audit.get('kea_error')!r}")
    if by_status.get("stale", 0):
        parts.append(f"stale={by_status['stale']}")
    if orphaned:
        parts.append(f"orphan={len(orphaned)}")
    details = "; ".join(parts) if parts else f"{len(records)} records, all ok"

    return CheckResult("audit_snapshot", ok, details, raw)


def check_dns_forward_verify(
    kea: KeaClient, dns: DNSVerifier, domain: str
) -> CheckResult:
    try:
        leases = kea.lease4_get_all()
    except Exception as exc:
        return CheckResult("dns_forward_verify", False, f"lease query failed: {exc}", [])

    results = []
    failed: list[str] = []

    for lease in leases:
        hostname = (lease.get("hostname") or "").strip()
        ip = lease.get("ip-address", "")
        if not hostname or not ip:
            continue
        # Strip domain suffix if Kea already qualified it
        bare = hostname.replace(f".{domain}", "").strip(".")
        r = dns.verify_pair(bare, ip, domain)
        r["hostname"] = bare
        r["ip"] = ip
        results.append(r)
        if not r["forward_ok"]:
            failed.append(f"{bare} → {ip} (got {r['forward_answer']!r})")

    ok = len(failed) == 0
    details = (
        f"{len(results)} pairs checked, {len(failed)} forward failures"
        if failed else f"{len(results)} pairs all ok"
    )
    return CheckResult("dns_forward_verify", ok, details, results)


def check_dns_reverse_verify(
    kea: KeaClient, dns: DNSVerifier, domain: str
) -> CheckResult:
    try:
        leases = kea.lease4_get_all()
    except Exception as exc:
        return CheckResult("dns_reverse_verify", False, f"lease query failed: {exc}", [])

    results = []
    failed: list[str] = []

    for lease in leases:
        hostname = (lease.get("hostname") or "").strip()
        ip = lease.get("ip-address", "")
        if not hostname or not ip:
            continue
        bare = hostname.replace(f".{domain}", "").strip(".")
        r = dns.verify_pair(bare, ip, domain)
        results.append({"hostname": bare, "ip": ip, "ptr_ok": r["ptr_ok"],
                        "ptr_answer": r["ptr_answer"]})
        if not r["ptr_ok"]:
            failed.append(f"{ip} PTR → {r['ptr_answer']!r}")

    ok = len(failed) == 0
    details = (
        f"{len(results)} pairs checked, {len(failed)} PTR failures"
        if failed else f"{len(results)} PTR pairs all ok"
    )
    return CheckResult("dns_reverse_verify", ok, details, results)


def check_consistency_delta(
    kea: KeaClient, unbound: UnboundClient, domain: str
) -> CheckResult:
    """Flag leases with no DNS and DNS with no lease."""
    raw: dict = {"leases_no_dns": [], "dns_no_lease": []}
    ok = True

    try:
        leases = kea.lease4_get_all()
        lease_map = {
            (lease.get("hostname", "").replace(f".{domain}", "").strip("."),
             lease.get("ip-address", "")): lease
            for lease in leases
            if lease.get("hostname") and lease.get("ip-address")
        }
    except Exception as exc:
        return CheckResult("consistency_delta", False, f"kea error: {exc}", raw)

    try:
        dns_data = unbound.list_local_data()
    except Exception as exc:
        return CheckResult("consistency_delta", False, f"unbound error: {exc}", raw)

    # Leases with no DNS
    for (hostname, ip), _ in lease_map.items():
        fqdn = f"{hostname}.{domain}"
        if fqdn not in dns_data and hostname not in dns_data:
            raw["leases_no_dns"].append({"hostname": hostname, "ip": ip})
            ok = False

    # DNS entries (forward only) with no active lease
    for name in dns_data:
        bare = name.replace(f".{domain}", "").strip(".")
        if bare.endswith(".in-addr.arpa") or bare.endswith(".ip6.arpa"):
            continue
        # Check whether any lease matches
        matched = any(h == bare for h, _ in lease_map)
        if not matched:
            raw["dns_no_lease"].append(name)
            # Not necessarily an error (reservations also valid); just note it

    parts = []
    if raw["leases_no_dns"]:
        parts.append(f"{len(raw['leases_no_dns'])} leases without DNS")
    if raw["dns_no_lease"]:
        parts.append(f"{len(raw['dns_no_lease'])} DNS names without lease (may be reservations)")

    details = "; ".join(parts) if parts else "consistent"
    return CheckResult("consistency_delta", ok, details, raw)


def check_log_harvest(
    ssh: SSHSession, archive: Archive, host: str
) -> CheckResult:
    today = datetime.date.today().strftime("%Y%m%d")
    log_path = f"/var/log/keaunbound/keaunbound_{today}.log"
    try:
        log_bytes = ssh.sftp_read(log_path)
        saved = archive.append_log_lines(host, today, log_bytes)
        size = len(log_bytes)
        errors = sum(1 for line in log_bytes.decode(errors="replace").splitlines()
                     if "[ERROR]" in line or "ERROR" in line)
        return CheckResult(
            "log_harvest", True,
            f"{size} bytes saved to {saved.name}, {errors} error lines",
            {"log_path": log_path, "size": size, "error_lines": errors},
        )
    except Exception as exc:
        return CheckResult("log_harvest", False, f"log harvest failed: {exc}", None)


# ---------------------------------------------------------------------------
# Full check set
# ---------------------------------------------------------------------------

def run_checks(
    ssh: SSHSession,
    kea: KeaClient,
    unbound: UnboundClient,
    dns: DNSVerifier,
    archive: Archive,
    prod_host: str,
    domain: str,
) -> Snapshot:
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    checks: list[CheckResult] = []

    check_funcs = [
        ("service_health", lambda: check_service_health(ssh)),
        ("kea_health",     lambda: check_kea_health(kea)),
        ("unbound_health", lambda: check_unbound_health(unbound)),
        ("audit_snapshot", lambda: check_audit_snapshot(ssh)),
        ("dns_forward",    lambda: check_dns_forward_verify(kea, dns, domain)),
        ("dns_reverse",    lambda: check_dns_reverse_verify(kea, dns, domain)),
        ("consistency",    lambda: check_consistency_delta(kea, unbound, domain)),
        ("log_harvest",    lambda: check_log_harvest(ssh, archive, prod_host)),
    ]

    for label, fn in check_funcs:
        print(f"  [{label}]", end=" ", flush=True)
        try:
            result = fn()
            icon = "✓" if result.ok else "✗"
            print(f"{icon} {result.details}")
            checks.append(result)
        except Exception as exc:
            print(f"! ERROR: {exc}")
            checks.append(CheckResult(label, False, f"exception: {exc}", None))

    return Snapshot(timestamp=ts, host=prod_host, checks=checks)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_snapshot(snap: Snapshot) -> str:
    lines = [
        f"\n{'=' * 60}",
        f"MONITOR SNAPSHOT  {snap.timestamp[:19].replace('T', ' ')}",
        f"Host: {snap.host}  |  {'ALL OK' if snap.all_ok else 'FAILURES DETECTED'}",
        "=" * 60,
    ]
    for c in snap.checks:
        icon = "✓" if c.ok else "✗"
        lines.append(f"  {icon} {c.name:<25} {c.details}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Launchd install / uninstall
# ---------------------------------------------------------------------------

def install_launchd(config_file: str) -> None:
    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{SCRIPT_PATH}</string>
        <string>--config</string>
        <string>{pathlib.Path(config_file).resolve()}</string>
    </array>
    <key>StartInterval</key>
    <integer>3600</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{_get_archive_dir()}/launchd.log</string>
    <key>StandardErrorPath</key>
    <string>{_get_archive_dir()}/launchd.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin</string>
    </dict>
</dict>
</plist>
"""
    _get_archive_dir().mkdir(parents=True, exist_ok=True)
    LAUNCHD_PLIST.parent.mkdir(parents=True, exist_ok=True)
    LAUNCHD_PLIST.write_text(plist_content)
    print(f"Written: {LAUNCHD_PLIST}")

    result = subprocess.run(
        ["launchctl", "load", "-w", str(LAUNCHD_PLIST)],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print("launchd job installed and loaded.")
        print(f"Check: launchctl list | grep {LAUNCHD_LABEL}")
    else:
        print(f"launchctl load failed: {result.stderr.strip()}", file=sys.stderr)


def uninstall_launchd() -> None:
    if LAUNCHD_PLIST.exists():
        subprocess.run(["launchctl", "unload", "-w", str(LAUNCHD_PLIST)],
                       capture_output=True)
        LAUNCHD_PLIST.unlink(missing_ok=True)
        print(f"Removed {LAUNCHD_PLIST} and unloaded job.")
    else:
        print("No launchd plist found.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Production monitor for os-kea-unbound",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--once", action="store_true",
                        help="Run all checks once, print to stdout, no archive")
    parser.add_argument("--config", default="tools/.env",
                        help="Path to .env file (default: tools/.env)")
    parser.add_argument("--archive-dir",
                        help="Override MONITOR_ARCHIVE_DIR")
    parser.add_argument("--weekly-summary", action="store_true",
                        help="Print weekly diff report from archive and exit")
    parser.add_argument("--install-launchd", action="store_true",
                        help="Install hourly launchd job and exit")
    parser.add_argument("--uninstall-launchd", action="store_true",
                        help="Uninstall launchd job and exit")
    args = parser.parse_args()

    _load_env(args.config)

    if args.uninstall_launchd:
        uninstall_launchd()
        return

    if args.install_launchd:
        install_launchd(args.config)
        return

    archive_dir = pathlib.Path(args.archive_dir).expanduser() if args.archive_dir \
        else _get_archive_dir()
    archive = Archive(archive_dir)

    if args.weekly_summary:
        since = datetime.date.today() - datetime.timedelta(days=7)
        snaps = archive.load_all(since=since)
        if not snaps:
            print(f"No snapshots in {archive_dir} from the past 7 days.")
            return
        summary = WeeklySummary(snaps)
        print(summary.render())
        # Also write JSON
        out = archive_dir / f"weekly_{datetime.date.today().isoformat()}.json"
        out.write_text(json.dumps({
            "generated": datetime.datetime.now().isoformat(),
            "snapshot_count": len(snaps),
            "uptime_pct": summary.uptime_pct(),
            "flapping_hosts": summary.flapping_hosts(),
            "stale_orphan_events": summary.stale_orphan_events(),
            "top_errors": summary.error_summary()[:20],
            "record_count_timeline": summary.record_count_timeline(),
        }, indent=2))
        print(f"\nJSON report: {out}")
        return

    # Connect
    prod_host = _require("PROD_HOST")
    prod_user = _require("PROD_SSH_USER")
    prod_pass = _require("PROD_SSH_PASS")
    domain = _get_prod_domain()

    if not domain:
        print("[ERROR] PROD_DOMAIN not set.", file=sys.stderr)
        sys.exit(1)

    print(f"Connecting to {prod_host}...")
    try:
        ssh = SSHSession(prod_host, prod_user, prod_pass)
    except Exception as exc:
        print(f"[FATAL] SSH failed: {exc}", file=sys.stderr)
        sys.exit(1)

    kea = KeaClient(ssh)
    unbound = UnboundClient(ssh)
    dns = DNSVerifier(ssh)

    try:
        print(f"Running checks at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}...")
        snap = run_checks(ssh, kea, unbound, dns, archive, prod_host, domain)
        print(render_snapshot(snap))

        if not args.once:
            saved = archive.save(snap)
            print(f"\nSnapshot saved: {saved}")
    finally:
        ssh.close()

    sys.exit(0 if snap.all_ok else 1)


if __name__ == "__main__":
    main()
