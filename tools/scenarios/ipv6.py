# SPDX-License-Identifier: BSD-2-Clause
"""
IPv6 / dual-stack chaos scenarios.

Prerequisite: DHCPv6 must be running on dev-opnsense with the test environment
set up (tools/setup_dhcp6_testenv.sh). Scenarios that inject DHCPv6 leases
directly via Kea's lease6-add API require kea-dhcp6 with lease_cmds hook loaded
and the control socket at /var/run/kea/kea6-ctrl-socket.

All scenarios call ctx.reset_state(v6=True) in cleanup to wipe both v4 and v6
leases and run bulk clean.
"""
from __future__ import annotations

import time

from tools.lib.kea import KeaError
from tools.scenarios import register
from tools.scenarios.base import ChaosContext, Scenario

# DUID used for all test leases — arbitrary bytes, unique enough for isolation.
_TEST_DUID = "00:03:00:01:aa:bb:cc:dd:ee:01"


@register
class DualStackHost(Scenario):
    name = "dual_stack_host"
    description = (
        "Inject one DHCPv4 and one DHCPv6 lease for the same hostname; sync; "
        "verify both A and AAAA records are present in Unbound with correct PTRs"
    )
    tags = ["ipv6", "dual-stack", "basic"]

    def setup(self, ctx: ChaosContext) -> None:
        ctx.require_dhcp6()

    def run(self, ctx: ChaosContext) -> None:
        hostname, ipv4 = ctx.alloc_host("-ds")
        _, ipv6 = ctx.alloc_v6_host("-ds", prefix=ctx.v6_prefix)
        # Use the same hostname for both families.
        ipv6_hostname = hostname

        mac = f"aa:bb:cc:dd:01:{ctx._ip_counter % 256:02x}"
        ctx.kea.lease4_add(ipv4, mac, hostname, valid_lft=3600,
                           subnet_id=ctx.subnet_id())
        ctx.kea.lease6_add(ipv6, _TEST_DUID, ipv6_hostname, valid_lft=3600,
                           subnet_id=ctx.subnet6_id())
        self._hostname = hostname
        self._ipv4 = ipv4
        self._ipv6 = ipv6
        ctx.event("leases_injected", hostname=hostname, ipv4=ipv4, ipv6=ipv6)

        ctx.run_sync("dynamic")
        ctx.wait(2, "let sync settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        fqdn = f"{self._hostname}.{ctx.domain}"

        if not ctx.unbound.has_record(fqdn, self._ipv4, "A"):
            failures.append(f"A record missing: {fqdn} → {self._ipv4}")
        if not ctx.unbound.has_record(fqdn, self._ipv6, "AAAA"):
            failures.append(f"AAAA record missing: {fqdn} → {self._ipv6}")
        if not ctx.unbound.has_ptr(self._ipv4, fqdn):
            failures.append(f"PTR missing for IPv4: {self._ipv4} → {fqdn}")
        if not ctx.unbound.has_ptr(self._ipv6, fqdn):
            failures.append(f"PTR missing for IPv6: {self._ipv6} → {fqdn}")

        result = ctx.dns.verify_pair(self._hostname, self._ipv4, ctx.domain, "A")
        if not result["forward_ok"]:
            failures.append(
                f"drill A failed for {self._hostname}: {result['forward_answer']!r}"
            )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        for attr in ("_ipv4", "_ipv6"):
            try:
                ip = getattr(self, attr, None)
                if ip and ":" not in ip:
                    ctx.kea.lease4_del(ip)
                elif ip:
                    ctx.kea.lease6_del(ip)
            except Exception:
                pass
        ctx.reset_state(v6=True)


@register
class StaleAaaaCleanup(Scenario):
    name = "stale_aaaa_cleanup"
    description = (
        "Dual-stack host has its AAAA replaced; verify clean removes only the "
        "stale AAAA and its PTR while preserving the A record and its PTR"
    )
    tags = ["ipv6", "dual-stack", "stale", "cleanup"]

    def setup(self, ctx: ChaosContext) -> None:
        ctx.require_dhcp6()

    def run(self, ctx: ChaosContext) -> None:
        hostname, ipv4 = ctx.alloc_host("-stale6")
        _, ipv6_new = ctx.alloc_v6_host("-stale6", prefix=ctx.v6_prefix)
        _, ipv6_old = ctx.alloc_v6_host("-stale6-old", prefix=ctx.v6_prefix)

        mac = f"aa:bb:cc:dd:02:{ctx._ip_counter % 256:02x}"
        # Inject v4 lease.
        ctx.kea.lease4_add(ipv4, mac, hostname, valid_lft=3600,
                           subnet_id=ctx.subnet_id())
        # Inject new v6 lease.
        ctx.kea.lease6_add(ipv6_new, _TEST_DUID, hostname, valid_lft=3600,
                           subnet_id=ctx.subnet6_id())
        ctx.event("leases_injected", hostname=hostname, ipv4=ipv4,
                  ipv6_new=ipv6_new, ipv6_old=ipv6_old)

        ctx.run_sync("dynamic")
        ctx.wait(2, "initial sync")

        # Manually add a stale AAAA directly to Unbound (simulating an old lease
        # that Kea no longer holds) without touching Kea's lease DB.
        fqdn = f"{hostname}.{ctx.domain}"
        ctx.ssh.sudo(
            f"/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
            f"local_data '{fqdn} 120 IN AAAA {ipv6_old}'"
        )
        ctx.event("stale_injected", ipv6_old=ipv6_old)

        self._hostname = hostname
        self._ipv4 = ipv4
        self._ipv6_new = ipv6_new
        self._ipv6_old = ipv6_old

    def verify(self, ctx: ChaosContext) -> list[str]:
        # Run bulk clean, then check that old AAAA is gone and A+new AAAA survive.
        ctx.run_clean()
        ctx.wait(2, "post-clean settle")

        failures = []
        fqdn = f"{self._hostname}.{ctx.domain}"
        import ipaddress as _ia

        if not ctx.unbound.has_record(fqdn, self._ipv4, "A"):
            failures.append(f"A record was removed (should survive): {fqdn} → {self._ipv4}")
        if not ctx.unbound.has_record(fqdn, self._ipv6_new, "AAAA"):
            failures.append(f"New AAAA removed (should survive): {fqdn} → {self._ipv6_new}")
        if ctx.unbound.has_record(fqdn, self._ipv6_old, "AAAA"):
            failures.append(f"Stale AAAA still present: {fqdn} → {self._ipv6_old}")

        # PTR for the old AAAA must be gone.
        old_ptr = _ia.ip_address(self._ipv6_old).reverse_pointer
        if ctx.unbound.has_ptr(self._ipv6_old, fqdn):
            failures.append(f"Stale AAAA PTR still present: {old_ptr} → {fqdn}")

        # PTR for the valid A must survive.
        if not ctx.unbound.has_ptr(self._ipv4, fqdn):
            failures.append(f"Valid A PTR removed: {self._ipv4} → {fqdn}")

        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        for attr in ("_ipv4",):
            try:
                ctx.kea.lease4_del(getattr(self, attr, ""))
            except Exception:
                pass
        try:
            ctx.kea.lease6_del(self._ipv6_new)
        except Exception:
            pass
        ctx.reset_state(v6=True)


@register
class Ipv6OnlyHost(Scenario):
    name = "ipv6_only_host"
    description = (
        "Inject a DHCPv6-only lease (no v4); sync; verify AAAA and PTR present; "
        "remove the lease; clean; verify both gone"
    )
    tags = ["ipv6", "basic"]

    def setup(self, ctx: ChaosContext) -> None:
        ctx.require_dhcp6()

    def run(self, ctx: ChaosContext) -> None:
        hostname, ipv6 = ctx.alloc_v6_host("-v6only", prefix=ctx.v6_prefix)
        ctx.kea.lease6_add(ipv6, _TEST_DUID, hostname, valid_lft=3600,
                           subnet_id=ctx.subnet6_id())
        self._hostname = hostname
        self._ipv6 = ipv6
        ctx.event("lease_injected", hostname=hostname, ipv6=ipv6)
        ctx.run_sync("dynamic")
        ctx.wait(2, "initial sync")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        fqdn = f"{self._hostname}.{ctx.domain}"

        if not ctx.unbound.has_record(fqdn, self._ipv6, "AAAA"):
            failures.append(f"AAAA missing: {fqdn} → {self._ipv6}")
        if not ctx.unbound.has_ptr(self._ipv6, fqdn):
            failures.append(f"PTR missing for {self._ipv6} → {fqdn}")
        # Must have NO A record — check raw data for any A-type lines.
        raw = ctx.unbound.list_local_data()
        a_lines = [l for l in raw.get(fqdn, [])
                   if len(l.split()) >= 4 and l.split()[3] == "A"]
        if a_lines:
            failures.append(f"Unexpected A record for {fqdn}: {a_lines}")

        # Delete the lease; clean; verify gone.
        try:
            ctx.kea.lease6_del(self._ipv6)
        except Exception as exc:
            failures.append(f"lease6_del failed: {exc}")
            return failures

        ctx.run_clean()
        ctx.wait(2, "post-clean")

        if ctx.unbound.has_record(fqdn, self._ipv6, "AAAA"):
            failures.append(f"AAAA still present after clean: {fqdn}")
        if ctx.unbound.has_ptr(self._ipv6, fqdn):
            failures.append(f"PTR still present after clean: {self._ipv6}")

        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            ctx.kea.lease6_del(getattr(self, "_ipv6", ""))
        except Exception:
            pass
        ctx.reset_state(v6=True)


@register
class DualStackFamilyIsolation(Scenario):
    name = "dual_stack_family_isolation"
    description = (
        "Verify collision policy is family-scoped: a v4 reservation winning a "
        "hostname does not block a v6 lease for the same name"
    )
    tags = ["ipv6", "dual-stack", "collision"]

    def setup(self, ctx: ChaosContext) -> None:
        ctx.require_dhcp6()
        from tools.lib.kea import KeaError
        try:
            ctx.kea.query("subnet4-reservation-get",
                          arguments={"subnet-id": 99999, "ip-address": "0.0.0.0"})
        except KeaError as exc:
            if "not supported" in str(exc):
                raise RuntimeError(
                    "host_cmds hook not loaded — enable it in kea-dhcp4.conf to run this scenario"
                )

    def run(self, ctx: ChaosContext) -> None:
        hostname, ipv4 = ctx.alloc_host("-fiso")
        _, ipv6 = ctx.alloc_v6_host("-fiso", prefix=ctx.v6_prefix)
        hostname_v6 = hostname  # same name, different family

        mac = f"aa:bb:cc:dd:03:{ctx._ip_counter % 256:02x}"

        # Add static v4 reservation.
        subnet4 = ctx.subnet_id()
        ctx.kea.reservation_add(subnet4, ipv4, mac, hostname)
        # Add v6 lease for same hostname.
        ctx.kea.lease6_add(ipv6, _TEST_DUID, hostname_v6, valid_lft=3600,
                           subnet_id=ctx.subnet6_id())
        self._hostname = hostname
        self._ipv4 = ipv4
        self._ipv6 = ipv6
        ctx.event("leases_injected", hostname=hostname, ipv4=ipv4, ipv6=ipv6)

        ctx.run_sync("static")
        ctx.run_sync("dynamic")
        ctx.wait(2, "sync settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        fqdn = f"{self._hostname}.{ctx.domain}"

        if not ctx.unbound.has_record(fqdn, self._ipv4, "A"):
            failures.append(f"v4 reservation A missing: {fqdn} → {self._ipv4}")
        if not ctx.unbound.has_record(fqdn, self._ipv6, "AAAA"):
            failures.append(
                f"v6 lease AAAA blocked by v4 reservation (family isolation failed): "
                f"{fqdn} → {self._ipv6}"
            )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            ctx.kea.reservation_del(ctx.subnet_id(), self._ipv4)
        except Exception:
            pass
        try:
            ctx.kea.lease6_del(self._ipv6)
        except Exception:
            pass
        ctx.reset_state(v6=True)


@register
class Ipv6MultipleAddresses(Scenario):
    name = "ipv6_multiple_addresses"
    description = (
        "DHCPv6 reservation with two addresses; sync; verify two AAAA records "
        "and two PTRs all present"
    )
    tags = ["ipv6", "reservation", "basic"]

    def setup(self, ctx: ChaosContext) -> None:
        ctx.require_dhcp6()
        from tools.lib.kea import KeaError
        try:
            ctx.kea.query("subnet6-reservation-get", service="dhcp6",
                          arguments={"subnet-id": 99999, "ip-address": "::"})
        except KeaError as exc:
            if "not supported" in str(exc):
                raise RuntimeError(
                    "host_cmds hook not loaded — enable it in kea-dhcp6.conf to run this scenario"
                )

    def run(self, ctx: ChaosContext) -> None:
        hostname, ipv6a = ctx.alloc_v6_host("-multi", prefix=ctx.v6_prefix)
        _, ipv6b = ctx.alloc_v6_host("-multi2", prefix=ctx.v6_prefix)

        subnet6 = ctx.subnet6_id()
        # Add a reservation with two addresses via the host_cmds API.
        ctx.kea.query("subnet6-reservation-add", service="dhcp6", arguments={
            "reservation": {
                "subnet-id": subnet6,
                "duid": _TEST_DUID,
                "hostname": hostname,
                "ip-addresses": [ipv6a, ipv6b],
            }
        })
        self._hostname = hostname
        self._ipv6a = ipv6a
        self._ipv6b = ipv6b
        ctx.event("reservation_injected", hostname=hostname,
                  ipv6a=ipv6a, ipv6b=ipv6b)

        ctx.run_sync("static")
        ctx.wait(2, "static sync settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        fqdn = f"{self._hostname}.{ctx.domain}"

        for ip in (self._ipv6a, self._ipv6b):
            if not ctx.unbound.has_record(fqdn, ip, "AAAA"):
                failures.append(f"AAAA missing for address {ip}: {fqdn}")
            if not ctx.unbound.has_ptr(ip, fqdn):
                failures.append(f"PTR missing: {ip} → {fqdn}")
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            ctx.kea.query("subnet6-reservation-del", service="dhcp6", arguments={
                "subnet-id": ctx.subnet6_id(),
                "identifier-type": "duid",
                "identifier": _TEST_DUID,
            })
        except Exception:
            pass
        ctx.reset_state(v6=True)
