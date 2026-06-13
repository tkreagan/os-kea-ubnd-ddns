# SPDX-License-Identifier: BSD-2-Clause
"""
Real DHCP client scenarios using dev-dhcpclient.
"""
from __future__ import annotations

import time

from tools.scenarios import register
from tools.scenarios.base import Scenario, ChaosContext


def _current_lease_ip(ctx: ChaosContext) -> str | None:
    """Return the current IP held by the DHCP client box, or None."""
    iface = ctx.cfg.dhcpclient_lan_if
    code = f"""
import subprocess
r = subprocess.run(['ip', '-4', 'addr', 'show', 'dev', '{iface}'], capture_output=True, text=True)
for line in r.stdout.splitlines():
    if 'scope global' in line:
        print(line.split()[1].split('/')[0])
        break
"""
    result = ctx.client.script("python3", code)
    return result.strip() or None


def _current_lease_hostname(ctx: ChaosContext) -> str | None:
    """Return the hostname the client is currently sending in DHCP requests."""
    out = ctx.client.run("hostname -s", check=False)
    return out.strip() or None


def _release_and_renew(ctx: ChaosContext, extra_opts: str = "") -> None:
    iface = ctx.cfg.dhcpclient_lan_if
    # networkctl renew is the correct way to trigger a fresh DHCP cycle when
    # systemd-networkd manages the interface; dhclient conflicts with it.
    ctx.client.sudo(
        f"networkctl renew {iface} 2>/dev/null || "
        f"dhclient -r {iface} 2>/dev/null; dhclient {extra_opts} {iface} 2>/dev/null || true",
        timeout=30
    )


@register
class RealDhcpRenew(Scenario):
    name = "real_dhcp_renew"
    description = "Force dev-dhcpclient to release+renew; sync; verify DNS matches current lease"
    tags = ["dhcp_client", "basic"]

    def run(self, ctx: ChaosContext) -> None:
        _release_and_renew(ctx)
        ctx.wait(3, "let DHCP propagate")
        ctx.run_sync("dynamic")
        ctx.wait(2, "let sync settle")
        self._ip = _current_lease_ip(ctx)
        self._hostname = _current_lease_hostname(ctx)
        ctx.event("renew_complete", ip=self._ip, hostname=self._hostname)

    def verify(self, ctx: ChaosContext) -> list[str]:
        if not self._ip:
            return ["Could not determine client IP after renew"]
        if not self._hostname:
            return ["Could not determine client hostname"]
        failures = []
        fqdn = f"{self._hostname}.{ctx.domain}"
        if not ctx.unbound.has_record(fqdn, self._ip):
            failures.append(f"A record {fqdn} → {self._ip} not in Unbound")
        result = ctx.dns.verify_pair(self._hostname, self._ip, ctx.domain)
        if not result["forward_ok"]:
            failures.append(
                f"drill forward: {fqdn} → {result['forward_answer']!r}, expected {self._ip}"
            )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        # Leave the client with a lease; clean injected chaos from earlier scenarios
        pass


@register
class HostnameChange(Scenario):
    name = "hostname_change"
    description = "Renew with new hostname; verify old record cleaned, new one registered"
    tags = ["dhcp_client", "cleanup"]
    OLD_NAME = "chaos-old-name"
    NEW_NAME = "chaos-new-name"

    def setup(self, ctx: ChaosContext) -> None:
        # Set known initial hostname
        ctx.client.sudo(f"hostname {self.OLD_NAME}", check=False)

    def run(self, ctx: ChaosContext) -> None:
        iface = ctx.cfg.dhcpclient_lan_if
        # First renew with old name
        ctx.client.sudo(
            f"dhclient -r {iface}; dhclient -h {self.OLD_NAME} {iface}",
            timeout=30
        )
        ctx.wait(3, "establish old lease")
        ctx.run_sync("dynamic")
        ctx.wait(2, "initial sync")
        self._old_ip = _current_lease_ip(ctx)
        ctx.event("old_lease", ip=self._old_ip, hostname=self.OLD_NAME)

        # Renew with new hostname
        ctx.client.sudo(
            f"dhclient -r {iface}; dhclient -h {self.NEW_NAME} {iface}",
            timeout=30
        )
        ctx.wait(3, "let new hostname propagate")
        ctx.run_sync("dynamic")
        ctx.run_clean()
        ctx.wait(2, "let sync+clean settle")
        self._new_ip = _current_lease_ip(ctx)
        ctx.event("new_lease", ip=self._new_ip, hostname=self.NEW_NAME)

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        new_fqdn = f"{self.NEW_NAME}.{ctx.domain}"
        if self._new_ip and not ctx.unbound.has_record(new_fqdn, self._new_ip):
            failures.append(f"New A record {new_fqdn} → {self._new_ip} not found")

        old_fqdn = f"{self.OLD_NAME}.{ctx.domain}"
        data = ctx.unbound.list_local_data()
        if old_fqdn in data or self.OLD_NAME in data:
            failures.append(f"Old record {old_fqdn} still present in Unbound")
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        ctx.client.sudo(f"hostname {ctx.cfg.dhcpclient_host.split('.')[0]}", check=False)
        ctx.run_clean()


@register
class NoHostname(Scenario):
    name = "no_hostname"
    description = "DHCP renew without hostname option; verify no blank/numeric record created"
    tags = ["dhcp_client", "hostile"]

    def run(self, ctx: ChaosContext) -> None:
        iface = ctx.cfg.dhcpclient_lan_if
        # '-I ""' sends no client identifier; suppress hostname via dhclient.conf
        ctx.client.sudo(
            f"dhclient -r {iface}; "
            f"dhclient -cf /dev/null {iface}",   # blank config = no hostname option
            timeout=30
        )
        ctx.wait(3, "let no-hostname lease propagate")
        ctx.run_sync("dynamic")
        ctx.wait(2, "sync settle")
        self._ip = _current_lease_ip(ctx)
        ctx.event("no_hostname_lease", ip=self._ip)

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        data = ctx.unbound.list_local_data()
        # Verify no record with an empty name or all-numeric name was created.
        # Skip Unbound's built-in reverse zones (arpa delegations) — those are
        # normal and have numeric first labels (e.g. 10.in-addr.arpa).
        for name in data:
            if name.endswith(".in-addr.arpa") or name.endswith(".ip6.arpa"):
                continue
            if not name.strip():
                failures.append(f"Empty DNS name found in Unbound: {name!r}")
            bare = name.split(".")[0]
            if bare.isdigit():
                failures.append(f"Numeric hostname registered: {name}")
        # Audit should still be complete (no crash)
        audit = ctx.run_audit()
        if not audit.get("complete", True):
            failures.append(f"Audit returned complete=false: {audit.get('kea_error')}")
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        # Restore normal DHCP
        iface = ctx.cfg.dhcpclient_lan_if
        hostname = ctx.cfg.dhcpclient_host.split(".")[0]
        ctx.client.sudo(
            f"dhclient -r {iface}; dhclient -h {hostname} {iface}",
            timeout=30, check=False
        )
        ctx.run_clean()


@register
class MultiClient(Scenario):
    name = "multi_client"
    description = "Spawn 3 dhclient processes with distinct hostnames; verify 3 DNS records"
    tags = ["dhcp_client", "stress"]
    NAMES = ["chaos-mc-alpha", "chaos-mc-beta", "chaos-mc-gamma"]

    def setup(self, ctx: ChaosContext) -> None:
        # Need macvlan or multiple MACs — use ip link add macvlan for extra interfaces
        # Check that ip link is available
        ctx.client.sudo("ip link help 2>&1 | head -1 || true", check=False, timeout=5)

    def run(self, ctx: ChaosContext) -> None:
        iface = ctx.cfg.dhcpclient_lan_if
        self._vifs: list[str] = []

        for i, name in enumerate(self.NAMES):
            vif = f"chaos{i}"
            mac = f"aa:bb:cd:{i:02x}:ef:01"
            # Create macvlan interface with distinct MAC
            ctx.client.sudo(
                f"ip link add {vif} link {iface} type macvlan mode bridge; "
                f"ip link set {vif} address {mac}; "
                f"ip link set {vif} up",
                check=False, timeout=10
            )
            self._vifs.append(vif)
            ctx.client.sudo(
                f"dhclient -h {name} {vif} &",
                timeout=15, check=False
            )
            ctx.event("dhclient_started", name=name, vif=vif, mac=mac)

        ctx.wait(5, "let all DHCP requests complete")
        ctx.run_sync("dynamic")
        ctx.wait(2, "sync settle")

        # Record which IPs were acquired
        self._acquired: list[tuple[str, str]] = []
        for vif, name in zip(self._vifs, self.NAMES):
            code = f"""
import subprocess
out = subprocess.check_output(['ip', '-4', 'addr', 'show', 'dev', '{vif}'], text=True, stderr=subprocess.DEVNULL)
for line in out.splitlines():
    if 'scope global' in line:
        print(line.split()[1].split('/')[0])
        break
"""
            try:
                ip = ctx.client.script("python3", code).strip()
            except Exception:
                ip = ""
            if ip:
                self._acquired.append((name, ip))
                ctx.event("lease_acquired", vif=vif, name=name, ip=ip)

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        if len(self._acquired) < len(self.NAMES):
            failures.append(
                f"Only {len(self._acquired)}/{len(self.NAMES)} clients acquired leases"
            )
        for name, ip in self._acquired:
            fqdn = f"{name}.{ctx.domain}"
            if not ctx.unbound.has_record(fqdn, ip):
                failures.append(f"A record missing for multi-client {name} → {ip}")
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        for vif in getattr(self, "_vifs", []):
            ctx.client.sudo(
                f"dhclient -r {vif}; ip link del {vif} || true",
                check=False, timeout=10
            )
        ctx.run_clean()
