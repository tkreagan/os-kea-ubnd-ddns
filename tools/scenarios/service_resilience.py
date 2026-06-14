# SPDX-License-Identifier: BSD-2-Clause
"""
Service resilience scenarios: daemon kill/restart, kea restart, unbound restart.
"""
from __future__ import annotations

import time

from tools.scenarios import register
from tools.scenarios.base import Scenario, ChaosContext
from tools.lib.kea import KeaError

CONFIGCTL = "/usr/local/sbin/configctl keaunbound"
PIDFILE = "/var/run/kea-unbound-ddns.pid"
SUPERVISOR_PIDFILE = "/var/run/kea-unbound-ddns.supervisor.pid"


def _get_pid(ctx: ChaosContext, pidfile: str) -> str:
    return ctx.ssh.sudo(f"cat {pidfile}", check=False).strip()


def _daemon_port_bound(ctx: ChaosContext) -> bool:
    out = ctx.ssh.sudo(
        "sockstat -4 2>/dev/null | grep 53535 || "
        "netstat -an 2>/dev/null | grep 53535 || true",
        check=False
    )
    return "53535" in out


@register
class DaemonKill(Scenario):
    name = "daemon_kill"
    description = "Kill child process; verify supervisor respawns it within 8s"
    tags = ["service", "resilience"]

    def run(self, ctx: ChaosContext) -> None:
        self._pre_pid = _get_pid(ctx, PIDFILE)
        ctx.event("pre_kill_pid", pid=self._pre_pid)
        # Kill only the child (by pidfile), NOT the supervisor.
        # pkill -f would match the supervisor's cmdline too (it contains the
        # script name as an argument), killing both and preventing respawn.
        ctx.ssh.sudo(f"pkill -F {PIDFILE} 2>/dev/null || true", check=False)
        ctx.event("daemon_killed")
        ctx.wait(8, "wait for supervisor respawn")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        if not ctx.daemon_is_running():
            failures.append("Daemon not running after 8s respawn window")
        if not _daemon_port_bound(ctx):
            failures.append("Port 53535 not bound after respawn")
        new_pid = _get_pid(ctx, PIDFILE)
        if new_pid and new_pid == self._pre_pid:
            failures.append(f"PID unchanged after kill ({new_pid})")
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        # Ensure daemon is running cleanly before next scenario
        if not ctx.daemon_is_running():
            ctx.ssh.sudo(f"{CONFIGCTL} start", timeout=15, check=False)
            time.sleep(3)


@register
class SupervisorKill(Scenario):
    name = "supervisor_kill"
    description = "Kill daemon supervisor; verify clean stop; restart via configctl"
    tags = ["service", "resilience"]

    def run(self, ctx: ChaosContext) -> None:
        sup_pid = _get_pid(ctx, SUPERVISOR_PIDFILE)
        ctx.event("supervisor_pid", pid=sup_pid)
        if not sup_pid:
            ctx.event("warn", msg="No supervisor pidfile found — skipping kill")
            self._skipped = True
            return
        self._skipped = False
        ctx.ssh.sudo(
            f"pkill -F {SUPERVISOR_PIDFILE} || true", check=False
        )
        ctx.event("supervisor_killed")
        # Wait for both supervisor and child pidfiles to disappear — the child
        # receives SIGTERM from the supervisor and takes a moment to exit.
        # daemon(8) refuses to start a new supervisor if the child pidfile still
        # references a running process, so we must not call start until both are
        # gone.  Poll for up to 10s before giving up and removing them manually.
        for _ in range(10):
            time.sleep(1)
            sup_gone = ctx.ssh.sudo(
                f"test -f {SUPERVISOR_PIDFILE} && echo exists || echo gone",
                check=False
            ).strip()
            child_gone = ctx.ssh.sudo(
                f"test -f {PIDFILE} && echo exists || echo gone",
                check=False
            ).strip()
            if sup_gone == "gone" and child_gone == "gone":
                break
        else:
            # Timed out — force-remove stale pidfiles so start can proceed
            ctx.ssh.sudo(
                f"rm -f {SUPERVISOR_PIDFILE} {PIDFILE}", check=False
            )
        ctx.event("pidfiles_cleared")

    def verify(self, ctx: ChaosContext) -> list[str]:
        if getattr(self, "_skipped", False):
            return []
        failures = []
        # After killing supervisor, no orphaned daemon processes should remain
        zombies = ctx.ssh.run(
            "pgrep -f kea-unbound-ddns.py || true", check=False
        )
        if zombies.strip():
            failures.append(
                f"Zombie kea-unbound-ddns processes remain: {zombies[:80]}"
            )
        # Restart and verify clean start
        ctx.ssh.sudo(f"{CONFIGCTL} start", timeout=15, check=False)
        time.sleep(5)
        if not ctx.daemon_is_running():
            failures.append("Daemon failed to restart after supervisor kill")
        if not _daemon_port_bound(ctx):
            failures.append("Port 53535 not bound after restart")
        return failures


@register
class KeaRestart(Scenario):
    name = "kea_restart"
    description = "Stop kea-dhcp4, run sync (expect non-fatal error), restart, sync again; verify records"
    tags = ["service", "resilience", "slow"]

    def run(self, ctx: ChaosContext) -> None:
        self._pairs = []
        for i in range(3):
            hostname, ip = ctx.alloc_host(f"-kear{i}")
            ctx.kea.lease4_add(ip, f"aa:bb:cc:ee:{i:02x}:00", hostname,
                               valid_lft=3600, subnet_id=ctx.subnet_id())
            self._pairs.append((hostname, ip))
        ctx.run_sync("dynamic")
        ctx.wait(2, "initial sync settle")

        # Stop Kea
        ctx.ssh.sudo("/usr/local/sbin/configctl kea stop || pkill -f kea-dhcp4 || true",
                     check=False, timeout=20)
        ctx.event("kea_stopped")
        ctx.wait(2, "let kea stop")

        # Sync with Kea down — should fail gracefully, not crash
        try:
            ctx.run_sync("dynamic")
            ctx.event("sync_with_kea_down", outcome="exited_ok")
        except Exception as exc:
            ctx.event("sync_with_kea_down", outcome="error", detail=str(exc)[:100])

        # Restart Kea
        ctx.ssh.sudo("/usr/local/sbin/configctl kea start || true",
                     check=False, timeout=20)
        ctx.event("kea_started")
        ctx.wait(5, "let kea start")
        ctx.run_sync("dynamic")
        ctx.wait(2, "post-restart sync settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        for hostname, ip in self._pairs:
            if not ctx.unbound.has_record(f"{hostname}.{ctx.domain}", ip):
                failures.append(f"A record missing after Kea restart: {hostname}")
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        # Ensure Kea is running
        ctx.ssh.sudo(
            "/usr/local/sbin/configctl kea start || true",
            check=False, timeout=20
        )
        time.sleep(3)
        for _, ip in getattr(self, "_pairs", []):
            try:
                ctx.kea.lease4_del(ip)
            except Exception:
                pass
        ctx.run_clean()


@register
class UnboundRestart(Scenario):
    name = "unbound_restart"
    description = "Restart unbound (clears local_data); run sync again; verify re-registration"
    tags = ["service", "resilience"]

    def run(self, ctx: ChaosContext) -> None:
        self._pairs = []
        for i in range(3):
            hostname, ip = ctx.alloc_host(f"-ubr{i}")
            ctx.kea.lease4_add(ip, f"aa:bb:cc:ff:{i:02x}:00", hostname,
                               valid_lft=3600, subnet_id=ctx.subnet_id())
            self._pairs.append((hostname, ip))
        ctx.run_sync("dynamic")
        ctx.wait(2, "initial sync")

        # Restart Unbound (wipes local_data)
        ctx.ssh.sudo(
            "/usr/local/sbin/configctl unbound restart || /usr/local/sbin/pluginctl -s unbound restart || true",
            check=False, timeout=20
        )
        ctx.event("unbound_restarted")
        ctx.wait(4, "let unbound start + stable")

        # Sync should re-register everything
        ctx.run_sync("dynamic")
        ctx.wait(2, "post-restart sync settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        for hostname, ip in self._pairs:
            if not ctx.unbound.has_record(f"{hostname}.{ctx.domain}", ip):
                failures.append(f"A record missing after Unbound restart: {hostname}")
            if not ctx.unbound.has_ptr(ip, f"{hostname}.{ctx.domain}"):
                failures.append(f"PTR missing after Unbound restart: {ip}")
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        for _, ip in getattr(self, "_pairs", []):
            try:
                ctx.kea.lease4_del(ip)
            except Exception:
                pass
        ctx.run_clean()


@register
class SimultaneousFlip(Scenario):
    name = "simultaneous_flip"
    description = "Stop kea + unbound simultaneously; restart both; sync; verify full recovery"
    tags = ["service", "resilience", "slow"]

    def run(self, ctx: ChaosContext) -> None:
        self._pairs = []
        for i in range(3):
            hostname, ip = ctx.alloc_host(f"-simflip{i}")
            ctx.kea.lease4_add(ip, f"aa:bc:cd:{i:02x}:00:00", hostname,
                               valid_lft=3600, subnet_id=ctx.subnet_id())
            self._pairs.append((hostname, ip))
        ctx.run_sync("dynamic")
        ctx.wait(2, "initial sync")

        # Stop both simultaneously.
        # Use pkill -x (exact process-name match) for unbound so we don't
        # accidentally kill kea-unbound-ddns.py whose cmdline also contains
        # "unbound". For kea-dhcp4 the exact name is safe.
        ctx.ssh.sudo(
            "service kea-dhcp4 stop; service unbound stop; "
            "pkill -x kea-dhcp4 || true; pkill -x unbound || true; "
            "pkill -f kea-dhcp-ddns || true",
            check=False, timeout=20
        )
        ctx.event("both_services_stopped")
        ctx.wait(4, "let services stop")

        # Restart in correct order: Unbound first, then Kea + d2
        ctx.ssh.sudo(
            "/usr/local/sbin/configctl unbound start || /usr/local/sbin/pluginctl -s unbound start || true",
            check=False, timeout=20
        )
        ctx.wait(4, "let unbound start")
        ctx.ssh.sudo(
            "/usr/local/sbin/configctl kea start || true",
            check=False, timeout=20
        )
        ctx.wait(5, "let kea start")
        ctx.event("both_services_restarted")
        ctx.wait(5, "let all Kea daemons (including d2) stabilise")

        # Wait for Kea to be responsive, then sync (retry a few times).
        for attempt in range(3):
            try:
                ctx.kea.version_get()
                break
            except Exception:
                ctx.wait(3, f"waiting for Kea to be ready (attempt {attempt+1})")

        ctx.run_sync("dynamic")
        ctx.wait(3, "post-restart sync")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        if not ctx.unbound.is_running():
            failures.append("Unbound not running after restart")
        for hostname, ip in self._pairs:
            if not ctx.unbound.has_record(f"{hostname}.{ctx.domain}", ip):
                failures.append(f"A missing after simultaneous flip: {hostname}")
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        # Ensure all three services are up
        ctx.ssh.sudo(
            "/usr/local/sbin/configctl unbound start || true; "
            "/usr/local/sbin/configctl kea start || true",
            check=False, timeout=20
        )
        time.sleep(3)
        if not ctx.daemon_is_running():
            ctx.ssh.sudo(
                "/usr/local/sbin/configctl keaunbound start || true",
                check=False, timeout=15
            )
            time.sleep(3)
        for _, ip in getattr(self, "_pairs", []):
            try:
                ctx.kea.lease4_del(ip)
            except Exception:
                pass
        ctx.run_clean()
