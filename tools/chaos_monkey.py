#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""
Chaos monkey for os-kea-unbound.

Runs adversarial scenarios against dev-opnsense + dev-dhcpclient to test
resilience, recovery, and correctness of the DHCP → DNS pipeline.

Usage:
    python3 tools/chaos_monkey.py --list
    python3 tools/chaos_monkey.py --setup-only
    python3 tools/chaos_monkey.py --scenario lease_crud
    python3 tools/chaos_monkey.py --all --delay 10

See tools/.env.example for required environment variables.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import sys
import time
import traceback

# Allow `import tools.lib.*` from repo root
sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))

from tools.lib.dns_verify import DNSVerifier
from tools.lib.kea import KeaClient, KeaError
from tools.lib.report import render_chaos_results
from tools.lib.ssh import SSHSession
from tools.lib.unbound import UnboundClient
from tools.scenarios import ScenarioResult, all_scenarios, get_scenario
from tools.scenarios.base import ChaosConfig, ChaosContext

# Import all scenario modules so their @register decorators fire
import tools.scenarios.lease_lifecycle      # noqa: F401
import tools.scenarios.service_resilience   # noqa: F401
import tools.scenarios.dhcp_client          # noqa: F401
import tools.scenarios.hostile_inputs       # noqa: F401
import tools.scenarios.collisions           # noqa: F401
import tools.scenarios.config_toggles       # noqa: F401
import tools.scenarios.ddns_path            # noqa: F401
import tools.scenarios.ipv6                 # noqa: F401
import tools.scenarios.ptr_formats          # noqa: F401
import tools.scenarios.ddns_ncr_verify      # noqa: F401

REPO_ROOT = pathlib.Path(__file__).parents[1]


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
        print(f"[ERROR] Required env var {name} is not set. Check your .env file.", file=sys.stderr)
        sys.exit(1)
    return val


def _load_config() -> ChaosConfig:
    return ChaosConfig(
        opnsense_host=_require("DEV_OPNSENSE_HOST"),
        opnsense_user=_require("DEV_OPNSENSE_SSH_USER"),
        opnsense_pass=_require("DEV_OPNSENSE_SSH_PASS"),
        dhcpclient_host=_require("DEV_DHCPCLIENT_HOST"),
        dhcpclient_user=_require("DEV_DHCPCLIENT_SSH_USER"),
        dhcpclient_pass=_require("DEV_DHCPCLIENT_SSH_PASS"),
        dhcpclient_lan_if=os.environ.get("DEV_DHCPCLIENT_LAN_IF", "ens19"),
        dev_domain=os.environ.get("DEV_DOMAIN", "lan"),
        test_ip_prefix=os.environ.get("TEST_IP_PREFIX", "192.168.99."),
        test_subnet_id=(
            int(os.environ["TEST_SUBNET_ID"])
            if os.environ.get("TEST_SUBNET_ID", "").strip()
            else None
        ),
    )


# ---------------------------------------------------------------------------
# Baseline verification
# ---------------------------------------------------------------------------

def verify_baseline(ctx: ChaosContext) -> list[str]:
    """Return a list of baseline failures (empty = ready)."""
    failures: list[str] = []

    print("  Checking SSH connectivity...", end=" ", flush=True)
    try:
        ctx.ssh.run("hostname")
        print("ok")
    except Exception as exc:
        print(f"FAIL ({exc})")
        failures.append(f"Cannot SSH to dev-opnsense: {exc}")
        return failures  # no point continuing

    try:
        ctx.client.run("hostname")
    except Exception as exc:
        failures.append(f"Cannot SSH to dev-dhcpclient: {exc}")

    print("  Checking plugin service...", end=" ", flush=True)
    try:
        status = ctx.daemon_status()
        if "is running" in status:
            print("running")
        else:
            print(f"NOT running ({status[:60]})")
            failures.append("kea-unbound-ddns service is not running")
    except Exception as exc:
        print(f"FAIL ({exc})")
        failures.append(f"Cannot check daemon status: {exc}")

    print("  Checking Kea...", end=" ", flush=True)
    try:
        ver = ctx.kea.version_get()
        print(f"ok ({ver[:40]})")
    except Exception as exc:
        print(f"FAIL ({exc})")
        failures.append(f"Kea unreachable: {exc}")

    print("  Checking Unbound...", end=" ", flush=True)
    if ctx.unbound.is_running():
        print("ok")
    else:
        print("NOT running")
        failures.append("Unbound is not running")

    print("  Checking port 53535...", end=" ", flush=True)
    try:
        # On FreeBSD, sockstat needs root to see other users' sockets.
        # On Linux, ss/netstat work without root. Try both.
        out = ctx.ssh.sudo(
            "sockstat -4 2>/dev/null | grep 53535 || "
            "netstat -an 2>/dev/null | grep 53535 || "
            "ss -uln 2>/dev/null | grep 53535 || true",
            check=False
        )
        if "53535" in out:
            print("bound")
        else:
            print("NOT bound")
            failures.append("Port 53535 is not bound")
    except Exception as exc:
        failures.append(f"Cannot check port 53535: {exc}")

    print("  Running audit check...", end=" ", flush=True)
    try:
        audit = ctx.run_audit()
        if not audit.get("complete", True):
            print(f"incomplete (kea_error={audit.get('kea_error')!r})")
            failures.append("Audit returned complete=false")
        else:
            stale = sum(1 for r in audit.get("records", []) if r.get("status") == "stale")
            orphan = len(audit.get("orphaned_ptrs", []))
            print(f"ok (stale={stale}, orphan={orphan})")
    except Exception as exc:
        print(f"FAIL ({exc})")
        failures.append(f"Audit script failed: {exc}")

    return failures


# ---------------------------------------------------------------------------
# Scenario runner
# ---------------------------------------------------------------------------

def run_scenario(scenario_cls, ctx: ChaosContext) -> ScenarioResult:
    scenario = scenario_cls()
    name = scenario.name
    desc = scenario.description
    start = time.time()
    ctx.events = []
    # Reset per-scenario so allocated IPs always stay within .220-.254
    ctx._ip_counter = 220
    ctx._v6_counter = 0x100

    print(f"\n  ▶ {name}: {desc}")

    try:
        scenario.setup(ctx)
    except Exception as exc:
        return ScenarioResult(
            name=name, description=desc, status="skip",
            failures=[], events=ctx.events,
            duration_s=time.time() - start,
            error=str(exc),
        )

    failures: list[str] = []
    error: str | None = None

    try:
        scenario.run(ctx)
        failures = scenario.verify(ctx)
    except Exception as exc:
        error = traceback.format_exc()
        ctx.events.append({"t": time.time(), "type": "exception",
                           "detail": str(exc)[:200]})
    finally:
        try:
            scenario.cleanup(ctx)
        except Exception as cleanup_exc:
            ctx.events.append({
                "t": time.time(), "type": "cleanup_error",
                "detail": str(cleanup_exc)[:200]
            })

    if error:
        status = "error"
    elif failures:
        status = "fail"
    else:
        status = "pass"

    duration = time.time() - start
    icon = {"pass": "✓", "fail": "✗", "error": "!", "skip": "–"}[status]
    print(f"    {icon} {status.upper()}  ({duration:.1f}s)")
    for f in failures:
        print(f"      ✗ {f}")
    if error:
        print(f"      ! {error[:200]}")

    return ScenarioResult(
        name=name, description=desc, status=status,
        failures=failures, events=ctx.events,
        duration_s=duration, error=error,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Chaos monkey for os-kea-unbound",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--scenario", action="append", dest="scenarios",
                        help="Run only this scenario (may be repeated)")
    parser.add_argument("--all", action="store_true",
                        help="Run all registered scenarios in order")
    parser.add_argument("--list", action="store_true",
                        help="Print all available scenarios and exit")
    parser.add_argument("--deploy", action="store_true",
                        help="Run make upgrade on dev-opnsense before starting")
    parser.add_argument("--setup-only", action="store_true",
                        help="Verify baseline only, then exit")
    parser.add_argument("--config", default="tools/.env",
                        help="Path to .env file (default: tools/.env)")
    parser.add_argument("--output", default="tools/results",
                        help="Directory for JSON result file (default: tools/results/)")
    parser.add_argument("--delay", type=int, default=10,
                        help="Seconds between scenarios (default: 10)")
    parser.add_argument("--stop-on-fail", action="store_true",
                        help="Halt after first failure")
    args = parser.parse_args()

    _load_env(args.config)

    if args.list:
        print("Available scenarios:")
        for cls in all_scenarios():
            tags = ", ".join(cls.tags) if cls.tags else "—"
            print(f"  {cls.name:<35} [{tags}]")
            print(f"    {cls.description}")
        return

    cfg = _load_config()

    print("=" * 60)
    print("CHAOS MONKEY — os-kea-unbound")
    print(f"Target: {cfg.opnsense_host}")
    print(f"Client: {cfg.dhcpclient_host}")
    print("=" * 60)

    # Establish connections
    print("\nConnecting...")
    try:
        ssh = SSHSession(cfg.opnsense_host, cfg.opnsense_user, cfg.opnsense_pass)
        client = SSHSession(cfg.dhcpclient_host, cfg.dhcpclient_user, cfg.dhcpclient_pass)
    except Exception as exc:
        print(f"[FATAL] SSH connection failed: {exc}", file=sys.stderr)
        sys.exit(1)

    kea = KeaClient(ssh)
    unbound = UnboundClient(ssh)
    dns = DNSVerifier(ssh)
    ctx = ChaosContext(ssh, client, kea, unbound, dns, cfg)

    # Optional deploy
    if args.deploy:
        print("\nDeploying plugin...")
        try:
            plugin_dir = os.environ.get("PLUGIN_DIR", "/usr/plugins/net/kea-unbound")
            ssh.sudo(f"cd {plugin_dir} && make upgrade", timeout=180)
            ssh.sudo("/usr/local/sbin/pluginctl -s webgui restart", timeout=60)
            ssh.sudo("service configd restart", timeout=30)
            time.sleep(5)
            print("  Deploy complete.")
        except Exception as exc:
            print(f"  [WARN] Deploy failed: {exc}")

    # Baseline verification
    print("\nVerifying baseline...")
    baseline_failures = verify_baseline(ctx)
    if baseline_failures:
        print("\n[FATAL] Baseline verification failed:")
        for f in baseline_failures:
            print(f"  ✗ {f}")
        sys.exit(1)
    print("  Baseline OK.")

    if args.setup_only:
        print("\nSetup-only mode. Done.")
        return

    # Determine which scenarios to run
    if args.scenarios:
        to_run = [get_scenario(n) for n in args.scenarios]
    elif args.all:
        to_run = all_scenarios()
    else:
        parser.print_help()
        print("\n[INFO] Use --all or --scenario NAME to run scenarios.", file=sys.stderr)
        return

    # Run scenarios
    results: list[ScenarioResult] = []
    print(f"\nRunning {len(to_run)} scenario(s)...")
    for i, cls in enumerate(to_run):
        if i > 0:
            time.sleep(args.delay)
        result = run_scenario(cls, ctx)
        results.append(result)
        if args.stop_on_fail and result.status in ("fail", "error"):
            print("\n[STOP] Halting due to failure (--stop-on-fail).")
            break

    # Close connections
    ssh.close()
    client.close()

    # Write JSON report
    output_dir = pathlib.Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = output_dir / f"chaos_{ts}.json"
    report = {
        "run_at": datetime.datetime.now().isoformat(),
        "target": cfg.opnsense_host,
        "total": len(results),
        "passed": sum(1 for r in results if r.status == "pass"),
        "failed": sum(1 for r in results if r.status == "fail"),
        "errored": sum(1 for r in results if r.status == "error"),
        "skipped": sum(1 for r in results if r.status == "skip"),
        "results": [r.as_dict() for r in results],
    }
    report_path.write_text(json.dumps(report, indent=2))

    # Print summary
    print(render_chaos_results([r.as_dict() for r in results]))
    print(f"Full report: {report_path}")

    # Exit code
    failed = sum(1 for r in results if r.status in ("fail", "error"))
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
