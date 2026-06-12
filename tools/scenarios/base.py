# SPDX-License-Identifier: BSD-2-Clause
"""
Base class for chaos monkey scenarios, plus the ChaosContext bag.
"""
from __future__ import annotations

import dataclasses
import time
from typing import Any

from tools.lib.dns_verify import DNSVerifier
from tools.lib.kea import KeaClient
from tools.lib.ssh import SSHSession
from tools.lib.unbound import UnboundClient


@dataclasses.dataclass
class ChaosConfig:
    """Runtime configuration drawn from .env / CLI."""
    opnsense_host: str
    opnsense_user: str
    opnsense_pass: str
    dhcpclient_host: str
    dhcpclient_user: str
    dhcpclient_pass: str
    dhcpclient_lan_if: str
    dev_domain: str
    test_ip_prefix: str      # e.g. "192.168.99."
    test_subnet_id: int | None
    output_dir: str = "tools/results"
    delay_secs: int = 10


class ChaosContext:
    """
    Live connections + helpers passed to every scenario.

    Log events with ctx.event("type", key=value, ...) — they accumulate
    in ctx.events and are written to the JSON result file.
    """

    def __init__(self,
                 ssh: SSHSession,
                 client: SSHSession,
                 kea: KeaClient,
                 unbound: UnboundClient,
                 dns: DNSVerifier,
                 cfg: ChaosConfig):
        self.ssh = ssh
        self.client = client
        self.kea = kea
        self.unbound = unbound
        self.dns = dns
        self.cfg = cfg
        self.events: list[dict] = []
        self._subnet_id: int | None = cfg.test_subnet_id
        self._ip_counter: int = 200  # start allocating from .200

    @property
    def domain(self) -> str:
        return self.cfg.dev_domain

    @property
    def ip_prefix(self) -> str:
        return self.cfg.test_ip_prefix

    def subnet_id(self) -> int:
        """Return the Kea subnet-id, auto-discovering if not configured."""
        if self._subnet_id is None:
            discovered = self.kea.discover_subnet_id()
            if discovered is None:
                raise RuntimeError("Could not discover Kea subnet-id")
            self._subnet_id = discovered
        return self._subnet_id

    def alloc_ip(self) -> str:
        """Allocate a unique test IP from the configured prefix."""
        ip = f"{self.ip_prefix}{self._ip_counter}"
        self._ip_counter += 1
        return ip

    def alloc_host(self, suffix: str = "") -> tuple[str, str]:
        """Return (hostname, ip) for a new test entry."""
        idx = self._ip_counter
        ip = self.alloc_ip()
        hostname = f"chaos-{idx:03d}{suffix}"
        return hostname, ip

    def event(self, etype: str, **kwargs: Any) -> None:
        self.events.append({"t": time.time(), "type": etype, **kwargs})

    def wait(self, secs: float, reason: str = "") -> None:
        self.event("wait", secs=secs, reason=reason)
        time.sleep(secs)

    def run_sync(self, kind: str = "dynamic") -> str:
        """Run sync_static or sync_dynamic via configctl."""
        action = "sync_dynamic" if kind == "dynamic" else "sync_static"
        return self.ssh.sudo(
            f"/usr/local/sbin/configctl keaunbound {action}", timeout=30
        )

    def run_clean(self) -> str:
        return self.ssh.sudo(
            "/usr/local/sbin/configctl keaunbound clean", timeout=30
        )

    def run_audit(self) -> dict:
        raw = self.ssh.sudo(
            "/usr/local/opnsense/scripts/keaunbound/local-data-audit.py --report-json",
            timeout=30,
        )
        import json
        return json.loads(raw)

    def daemon_status(self) -> str:
        return self.ssh.sudo(
            "/usr/local/sbin/pluginctl -s kea-unbound-ddns status", timeout=10
        )

    def daemon_is_running(self) -> bool:
        try:
            return "is running" in self.daemon_status()
        except Exception:
            return False

    def reset_state(self) -> None:
        """Wipe all injected leases + stale records, restore clean baseline."""
        try:
            self.kea.lease4_wipe()
        except Exception:
            pass
        try:
            self.run_clean()
        except Exception:
            pass
        time.sleep(2)


class Scenario:
    """
    Base class for chaos scenarios.

    Subclasses must set `name` and `description`, and may override any of
    setup / run / verify / cleanup.
    """

    name: str = ""
    description: str = ""
    tags: list[str] = []

    def setup(self, ctx: ChaosContext) -> None:
        """Preconditions — raise to skip scenario (not a failure)."""

    def run(self, ctx: ChaosContext) -> None:
        """Inject chaos."""

    def verify(self, ctx: ChaosContext) -> list[str]:
        """Return a list of failure strings (empty = pass)."""
        return []

    def cleanup(self, ctx: ChaosContext) -> None:
        """Restore state. Always called, even on failure."""
        ctx.reset_state()
