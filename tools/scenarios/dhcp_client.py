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


def _ensure_iface_up(ctx: ChaosContext) -> None:
    """Bring the LAN interface up if it is currently DOWN."""
    iface = ctx.cfg.dhcpclient_lan_if
    out = ctx.client.run(f"ip link show {iface} 2>/dev/null || true", check=False)
    if "state UP" not in out and "state UNKNOWN" not in out:
        ctx.client.sudo(f"ip link set {iface} up", check=False, timeout=10)
        time.sleep(2)


def _dhclient_with_hostname(ctx: ChaosContext, iface: str, hostname: str, timeout: int = 30) -> None:
    """Release any existing lease on iface and get a new one advertising hostname."""
    # This version of dhclient has no -h flag; hostname must be sent via a temp config.
    # Write config to /tmp (world-writable) via script() over stdin — avoids the
    # shell quoting issues that arise with mixed single/double quotes in sudo().
    cfgfile = f"/tmp/dhclient-{iface}-chaos.conf"
    ctx.client.script("python3", (
        f"open('{cfgfile}', 'w').write('send host-name = \"{hostname}\";\\n')\n"
    ))
    ctx.client.sudo(
        f"dhclient -r {iface} 2>/dev/null; "
        f"dhclient -v -cf {cfgfile} {iface} 2>&1 || true",
        timeout=timeout
    )
    ctx.client.sudo(f"rm -f {cfgfile}", check=False)


def _release_and_renew(ctx: ChaosContext, extra_opts: str = "") -> None:
    iface = ctx.cfg.dhcpclient_lan_if
    _ensure_iface_up(ctx)
    # Use -v with 2>&1 so dhclient's verbose output (including "bound to...") flows
    # through the SSH stdout channel. The drain loop waits until dhclient's daemon
    # closes the inherited fd, which only happens after configuring the IP.
    ctx.client.sudo(
        f"dhclient -r {iface} 2>/dev/null; dhclient -v {extra_opts} {iface} 2>&1 || "
        f"networkctl renew {iface} 2>/dev/null || true",
        timeout=30
    )


@register
class RealDhcpRenew(Scenario):
    name = "real_dhcp_renew"
    description = "Force dev-dhcpclient to release+renew; sync; verify DNS matches current lease"
    tags = ["dhcp_client", "basic"]

    def setup(self, ctx: ChaosContext) -> None:
        ctx.client.run("true")  # raises UnavailableSession → SKIP if client unreachable
        _ensure_iface_up(ctx)

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
    description = "Update Kea lease hostname; verify old DNS record cleaned, new one registered"
    tags = ["dhcp_client", "cleanup"]
    OLD_NAME = "chaos-old-name"
    NEW_NAME = "chaos-new-name"
    MAC = "aa:bb:cc:88:01:02"

    def run(self, ctx: ChaosContext) -> None:
        # Kea doesn't propagate option-12 hostname to the lease without DDNS; inject
        # via the API so we test the sync/cleanup logic without relying on DHCP FQDN.
        _, self._ip = ctx.alloc_host("-hcfmt")
        ctx.kea.lease4_add(self._ip, self.MAC, self.OLD_NAME,
                           valid_lft=3600, subnet_id=ctx.subnet_id())
        ctx.run_sync("dynamic")
        ctx.wait(2, "initial sync")
        ctx.event("old_lease", ip=self._ip, hostname=self.OLD_NAME)

        # Replace with new hostname
        ctx.kea.lease4_del(self._ip)
        ctx.kea.lease4_add(self._ip, self.MAC, self.NEW_NAME,
                           valid_lft=3600, subnet_id=ctx.subnet_id())
        ctx.run_sync("dynamic")
        ctx.run_clean()
        ctx.wait(2, "sync+clean settle")
        ctx.event("new_lease", ip=self._ip, hostname=self.NEW_NAME)

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        new_fqdn = f"{self.NEW_NAME}.{ctx.domain}"
        if not ctx.unbound.has_record(new_fqdn, self._ip):
            failures.append(f"New A record {new_fqdn} → {self._ip} not found")

        old_fqdn = f"{self.OLD_NAME}.{ctx.domain}"
        data = ctx.unbound.list_local_data()
        if old_fqdn in data or self.OLD_NAME in data:
            failures.append(f"Old record {old_fqdn} still present in Unbound")
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            ctx.kea.lease4_del(self._ip)
        except Exception:
            pass
        ctx.run_clean()


@register
class NoHostname(Scenario):
    name = "no_hostname"
    description = "DHCP renew without hostname option; verify no blank/numeric record created"
    tags = ["dhcp_client", "hostile"]

    def setup(self, ctx: ChaosContext) -> None:
        ctx.client.run("true")  # raises UnavailableSession → SKIP if client unreachable
        _ensure_iface_up(ctx)

    def run(self, ctx: ChaosContext) -> None:
        iface = ctx.cfg.dhcpclient_lan_if
        # '-I ""' sends no client identifier; suppress hostname via dhclient.conf
        ctx.client.sudo(
            f"dhclient -r {iface} 2>/dev/null; "
            f"dhclient -v -cf /dev/null {iface} 2>&1",   # blank config = no hostname option
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
        _dhclient_with_hostname(ctx, iface, hostname)
        ctx.run_clean()


@register
class MultiClient(Scenario):
    name = "multi_client"
    description = "Inject 3 leases with distinct hostnames via Kea API; verify 3 DNS records"
    tags = ["dhcp_client", "stress"]
    NAMES = ["chaos-mc-alpha", "chaos-mc-beta", "chaos-mc-gamma"]
    MACS = ["aa:bb:cd:00:ef:01", "aa:bb:cd:01:ef:01", "aa:bb:cd:02:ef:01"]

    def run(self, ctx: ChaosContext) -> None:
        self._pairs: list[tuple[str, str]] = []
        for i, name in enumerate(self.NAMES):
            _, ip = ctx.alloc_host(f"-mc{i}")
            mac = self.MACS[i]
            ctx.kea.lease4_add(ip, mac, name, valid_lft=3600, subnet_id=ctx.subnet_id())
            self._pairs.append((name, ip))
            ctx.event("lease_added", name=name, ip=ip, mac=mac)

        ctx.run_sync("dynamic")
        ctx.wait(2, "sync settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        for name, ip in self._pairs:
            fqdn = f"{name}.{ctx.domain}"
            if not ctx.unbound.has_record(fqdn, ip):
                failures.append(f"A record missing for {name} → {ip}")
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        for _, ip in getattr(self, "_pairs", []):
            try:
                ctx.kea.lease4_del(ip)
            except Exception:
                pass
        ctx.run_clean()
