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
    test_ip_prefix: str      # e.g. "192.168.1."
    test_v6_prefix: str      # e.g. "fd00:cafe::" — must match the DHCPv6 subnet
    test_subnet_id: int | None
    opnsense_key: str | None = None   # path to SSH private key (key auth)
    dhcpclient_key: str | None = None
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
        self._subnet6_id: int | None = None
        self._ip_counter: int = 220   # start at .220 — above the DHCP pool (.100-.200)
        self._v6_counter: int = 0x100  # start allocating from prefix::100

    @property
    def domain(self) -> str:
        return self.cfg.dev_domain

    @property
    def ip_prefix(self) -> str:
        return self.cfg.test_ip_prefix

    @property
    def v6_prefix(self) -> str:
        return self.cfg.test_v6_prefix

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
        """Return (hostname, ipv4) for a new DHCPv4 test entry."""
        idx = self._ip_counter
        ip = self.alloc_ip()
        hostname = f"chaos-{idx:03d}{suffix}"
        return hostname, ip

    def subnet6_id(self) -> int:
        """Return the DHCPv6 subnet-id, auto-discovering if not set."""
        if self._subnet6_id is None:
            discovered = self.kea.discover_subnet_id(service="dhcp6")
            if discovered is None:
                raise RuntimeError("Could not discover Kea dhcp6 subnet-id")
            self._subnet6_id = discovered
        return self._subnet6_id

    def require_dhcp6(self) -> None:
        """Assert kea-dhcp6 is available; raises RuntimeError (→ SKIP) if not.

        Call this from scenario.setup() so that missing DHCPv6 is a graceful
        skip rather than an error in run().
        """
        from tools.lib.kea import KeaError
        try:
            subnet = self.kea.discover_subnet_id(service="dhcp6")
        except KeaError as exc:
            raise RuntimeError(f"DHCPv6 not available: {exc}") from exc
        if subnet is None:
            raise RuntimeError("DHCPv6 not configured — no kea-dhcp6 subnet found")

    def alloc_v6_addr(self, prefix: str | None = None) -> str:
        """Allocate a unique test IPv6 address from the configured v6 prefix."""
        pfx = prefix if prefix is not None else self.cfg.test_v6_prefix
        addr = f"{pfx}{self._v6_counter:x}"
        self._v6_counter += 1
        return addr

    def alloc_v6_host(self, suffix: str = "", prefix: str | None = None) -> tuple[str, str]:
        """Return (hostname, ipv6) for a new DHCPv6 test entry."""
        idx = self._v6_counter
        ip = self.alloc_v6_addr(prefix)
        hostname = f"chaos6-{idx:03x}{suffix}"
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
            f"/usr/local/sbin/configctl keaubnd {action}", timeout=30
        )

    def run_clean(self) -> str:
        return self.ssh.sudo(
            "/usr/local/sbin/configctl keaubnd clean", timeout=30
        )

    def run_audit(self) -> dict:
        raw = self.ssh.sudo(
            "timeout 25 /usr/local/opnsense/scripts/keaubnd/local-data-audit.py --report-json",
            timeout=30,
        )
        import json
        return json.loads(raw)

    def daemon_status(self) -> str:
        return self.ssh.sudo(
            "/usr/local/sbin/pluginctl -s kea-ubnd-ddns status", timeout=10
        )

    def daemon_is_running(self) -> bool:
        try:
            return "is running" in self.daemon_status()
        except Exception:
            return False

    def send_ncr(self, payload: bytes) -> None:
        """Send a DNS UPDATE packet to the daemon via the remote host's loopback.

        The daemon binds to 127.0.0.1:53535 only; sending from the Mac runner's
        external interface would be silently dropped.  This method base64-encodes
        the wire payload and runs a tiny python3 script on dev-opnsense that
        decodes and sends it locally — no sudo required.
        """
        import base64
        b64 = base64.b64encode(payload).decode()
        script = (
            f"import socket, base64\n"
            f"pkt = base64.b64decode('{b64}')\n"
            "with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:\n"
            "    s.settimeout(1.0)\n"
            "    try:\n"
            "        s.sendto(pkt, ('127.0.0.1', 53535))\n"
            "    except Exception:\n"
            "        pass\n"
        )
        self.ssh.script("python3", script)

    def reset_state(self, v6: bool = False) -> None:
        """Wipe all injected leases + stale records, restore clean baseline."""
        try:
            self.kea.lease4_wipe()
        except Exception:
            pass
        if v6:
            try:
                self.kea.lease6_wipe()
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
