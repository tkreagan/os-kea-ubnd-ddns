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
import tools.scenarios.ncr_name_formats     # noqa: F401

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
            # Strip inline comments (# ...) unless the value starts with a quote
            v = v.strip()
            if not v.startswith(("'", '"')) and "#" in v:
                v = v.split("#", 1)[0].strip()
            os.environ.setdefault(k.strip(), v)


def _require(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        print(f"[ERROR] Required env var {name} is not set. Check your .env file.", file=sys.stderr)
        sys.exit(1)
    return val


def _load_config() -> ChaosConfig:
    def _opt_key(env_name: str) -> str | None:
        v = os.environ.get(env_name, "").strip()
        return v if v else None

    return ChaosConfig(
        opnsense_host=_require("DEV_OPNSENSE_HOST"),
        opnsense_user=_require("DEV_OPNSENSE_SSH_USER"),
        opnsense_pass=os.environ.get("DEV_OPNSENSE_SSH_PASS", ""),
        dhcpclient_host=_require("DEV_DHCPCLIENT_HOST"),
        dhcpclient_user=_require("DEV_DHCPCLIENT_SSH_USER"),
        dhcpclient_pass=os.environ.get("DEV_DHCPCLIENT_SSH_PASS", ""),
        dhcpclient_lan_if=os.environ.get("DEV_DHCPCLIENT_LAN_IF", "ens19"),
        dev_domain=os.environ.get("DEV_DOMAIN", "lan"),
        test_ip_prefix=os.environ.get("TEST_IP_PREFIX", "192.168.99."),
        test_v6_prefix=os.environ.get("TEST_V6_PREFIX", "fd00:cafe::"),
        test_subnet_id=(
            int(os.environ["TEST_SUBNET_ID"])
            if os.environ.get("TEST_SUBNET_ID", "").strip()
            else None
        ),
        opnsense_key=_opt_key("DEV_OPNSENSE_SSH_KEY"),
        dhcpclient_key=_opt_key("DEV_DHCPCLIENT_SSH_KEY"),
    )


# ---------------------------------------------------------------------------
# Plugin deploy (handles both fresh installs and upgrades)
# ---------------------------------------------------------------------------

def _deploy_plugin(ssh, repo_root: pathlib.Path) -> None:
    """Install or upgrade the plugin on dev-opnsense.

    Uses one of two strategies:
    - make upgrade (when /usr/plugins/Mk/plugins.mk is present — the normal
      dev build tree is populated)
    - Direct file install (copies src/ → /usr/local/ directly; no pkg
      registration — works on a clean box with no build infrastructure)

    After installing, restarts configd and webgui so new actions/templates
    and PHP controllers take effect.
    """
    import subprocess
    import tempfile

    plugin_dir = os.environ.get("PLUGIN_DIR", "/usr/plugins/net/kea-unbound")

    # Pick strategy: if the Mk infrastructure is present, use make upgrade.
    # Otherwise fall back to direct file install (dev-box-safe, no pkg needed).
    mk_present = ssh.sudo(
        "test -f /usr/plugins/Mk/plugins.mk && echo yes || echo no",
        check=False, timeout=10,
    ).strip() == "yes"

    # Build src-only tarball (used by both strategies)
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as f:
        src_tarball = pathlib.Path(f.name)
    try:
        subprocess.run(
            [
                "tar",
                "--exclude=__pycache__",
                "--exclude=.DS_Store",
                "--exclude=._*",
                "--exclude=*.pyc",
                "-czf", str(src_tarball),
                "-C", str(repo_root / "src"),
                ".",
            ],
            env={**os.environ, "COPYFILE_DISABLE": "1"},
            check=True,
        )
        ssh.sftp_put(src_tarball, "/tmp/keaunbound-src.tar.gz")
    finally:
        src_tarball.unlink(missing_ok=True)

    if mk_present:
        print(f"  Using make upgrade (build tree at {plugin_dir})")
        was_installed = ssh.sudo(
            f"test -f {plugin_dir}/Makefile && echo yes || echo no",
            check=False, timeout=10,
        ).strip() == "yes"

        if not was_installed:
            # Upload Makefile + pkg-descr so make upgrade can run
            ssh.sudo(f"mkdir -p {plugin_dir}/src", check=True, timeout=10)
            with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as f:
                meta_tarball = pathlib.Path(f.name)
            try:
                subprocess.run(
                    ["tar", "--exclude=__pycache__", "--exclude=.DS_Store",
                     "--exclude=._*", "--exclude=*.pyc", "--exclude=.git",
                     "-czf", str(meta_tarball),
                     "-C", str(repo_root), "Makefile", "pkg-descr"],
                    env={**os.environ, "COPYFILE_DISABLE": "1"},
                    check=True,
                )
                ssh.sftp_put(meta_tarball, "/tmp/keaunbound-meta.tar.gz")
            finally:
                meta_tarball.unlink(missing_ok=True)
            ssh.sudo(
                f"tar --no-xattrs --no-acls --no-fflags "
                f"-xzf /tmp/keaunbound-meta.tar.gz -C {plugin_dir}",
                timeout=30,
            )

        # Place src/ into build tree and run make upgrade
        ssh.sudo(
            f"tar --no-xattrs --no-acls --no-fflags "
            f"-xzf /tmp/keaunbound-src.tar.gz -C {plugin_dir}/src",
            timeout=30,
        )
        print("  Running make upgrade...")
        ssh.sudo(f"cd {plugin_dir} && make upgrade", timeout=180)

    else:
        # Direct install: copy src/ tree directly into /usr/local/
        print("  Direct file install (no Mk build infra found)")
        was_installed = ssh.sudo(
            "test -f /usr/local/sbin/kea-unbound-ddns.py && echo yes || echo no",
            check=False, timeout=10,
        ).strip() == "yes"
        ssh.sudo(
            "tar --no-xattrs --no-acls --no-fflags "
            "-xzf /tmp/keaunbound-src.tar.gz -C /usr/local/",
            timeout=30,
        )
        ssh.sudo("chmod 755 /usr/local/sbin/kea-unbound-ddns.py", timeout=10)
        ssh.sudo(
            "find /usr/local/opnsense/scripts/keaunbound -name '*.py' "
            "-exec chmod 755 {} \\;",
            timeout=10,
        )
        if not was_installed:
            # First install: make scripts executable
            ssh.sudo(
                "find /usr/local/opnsense/scripts/keaunbound -type f "
                "-exec chmod 755 {} \\;",
                check=False, timeout=10,
            )

    # Restart services so new configs take effect
    print("  Restarting services...")
    ssh.sudo("service configd restart", timeout=30)
    time.sleep(3)
    ssh.sudo("/usr/local/sbin/pluginctl -s webgui restart", timeout=60,
             check=False)
    time.sleep(5)

    # Start or restart the daemon
    print("  Starting kea-unbound-ddns...")
    ssh.sudo("/usr/local/sbin/configctl keaunbound restart", timeout=30,
             check=False)
    time.sleep(3)


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

    if not isinstance(ctx.client, _UnavailableSession):
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


def _ensure_kea_services(ctx: ChaosContext) -> None:
    """Restart Kea services if any stopped during a scenario.

    Uses OPNsense's service management (configctl kea restart) so the
    manual_config=1 flag is respected and Kea configs are not regenerated.
    Best-effort — swallows all errors so it never breaks scenario accounting.
    """
    try:
        # Check if d2 pidfile is present (d2 must run for SM to reach NORMAL)
        out = ctx.ssh.sudo(
            "test -f /var/run/kea/kea-dhcp-ddns.kea-dhcp-ddns.pid && echo yes || echo no",
            check=False, timeout=10,
        )
        if "yes" not in out:
            ctx.ssh.sudo("/usr/local/sbin/configctl kea restart", check=False, timeout=30)
            time.sleep(5)
    except Exception:
        pass


def _ensure_daemon_running(ctx: ChaosContext) -> None:
    """Restart kea-unbound-ddns if it stopped during a scenario.

    Best-effort: swallows all errors so it never breaks scenario accounting.
    """
    try:
        if ctx.daemon_is_running():
            return
        ctx.ssh.sudo(
            "/usr/local/sbin/configctl keaunbound start || true",
            check=False, timeout=15,
        )
        time.sleep(3)
    except Exception:
        pass


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
        # If Kea services (including d2) died during the scenario, restart via
        # OPNsense's service management so manual_config=1 is respected.
        _ensure_kea_services(ctx)
        # If the daemon died during the scenario (supervisor killed, etc.),
        # restart it so subsequent scenarios don't all fail.
        _ensure_daemon_running(ctx)

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
# Stub session for unreachable hosts
# ---------------------------------------------------------------------------

class _UnavailableSession:
    """Stub that raises RuntimeError for every method.

    Used when dev-dhcpclient is unreachable (e.g. running from outside the LAN).
    Scenarios that access ctx.client will raise and be recorded as "error",
    which is the correct outcome — they need the client to run.
    """
    def __init__(self, host: str):
        self._host = host

    def _fail(self, *_a, **_kw):
        raise RuntimeError(
            f"dhcpclient ({self._host}) is not reachable from this runner"
        )

    def run(self, *a, **kw): return self._fail()
    def sudo(self, *a, **kw): return self._fail()
    def script(self, *a, **kw): return self._fail()
    def sftp_put(self, *a, **kw): return self._fail()
    def sftp_get(self, *a, **kw): return self._fail()
    def close(self): pass
    def __call__(self, *a, **kw): return self._fail()
    def __enter__(self): return self
    def __exit__(self, *_): pass


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
        ssh = SSHSession(cfg.opnsense_host, cfg.opnsense_user, cfg.opnsense_pass,
                         key_file=cfg.opnsense_key)
    except Exception as exc:
        print(f"[FATAL] SSH to {cfg.opnsense_host} failed: {exc}", file=sys.stderr)
        sys.exit(1)

    # dhcpclient is on the LAN and may not be reachable directly from the
    # runner (e.g. when running from a Mac outside the LAN).  Make it optional:
    # scenarios that call ctx.client will raise at runtime and be marked error.
    try:
        client = SSHSession(cfg.dhcpclient_host, cfg.dhcpclient_user, cfg.dhcpclient_pass,
                            key_file=cfg.dhcpclient_key)
        print(f"  Connected to dhcpclient ({cfg.dhcpclient_host})")
    except Exception as exc:
        print(f"  [WARN] Cannot reach dhcpclient ({cfg.dhcpclient_host}): {exc}")
        print("  dhcp_client scenarios will be skipped.")
        client = _UnavailableSession(cfg.dhcpclient_host)

    kea = KeaClient(ssh)
    unbound = UnboundClient(ssh)
    dns = DNSVerifier(ssh)
    ctx = ChaosContext(ssh, client, kea, unbound, dns, cfg)

    # Optional deploy
    if args.deploy:
        print("\nDeploying plugin...")
        try:
            _deploy_plugin(ssh, REPO_ROOT)
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
