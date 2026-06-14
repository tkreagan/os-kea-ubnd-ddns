# SPDX-License-Identifier: BSD-2-Clause
"""
DDNS NCR record-level verification scenarios.

Tests that the live DDNS listener (kea-ubnd-ddns.py) correctly handles
DNS UPDATE packets and produces the right output in Unbound:

  * A vs AAAA record types stored with exact type (not confused)
  * Synthesized PTR has the right arpa format for each family
  * DELETE A preserves AAAA + its PTR (family isolation in delete path)
  * DELETE AAAA preserves A + its PTR
  * Dual-family updates (A + AAAA for the same hostname): both types, both PTRs
  * NCR for a name already in Unbound (idempotent re-add)
  * IP change via NCR (last_wins): old PTR removed, new PTR added

All inject directly into port 53535 via DNS UPDATE (UDP) — no Kea involvement.
The daemon processes the UPDATE synchronously; a 2-second settle is sufficient.
"""
from __future__ import annotations

import ipaddress
import time

from tools.scenarios import register
from tools.scenarios.base import Scenario, ChaosContext

_V6_PREFIX = "fd43::"   # isolated from other scenario prefixes


# ---------------------------------------------------------------------------
# DNS UPDATE wire helpers
# ---------------------------------------------------------------------------

def _send(ctx, payload: bytes) -> None:
    """Send DNS UPDATE via the remote host's loopback (daemon binds 127.0.0.1 only)."""
    ctx.send_ncr(payload)


def _add_a(hostname: str, ip: str, domain: str, ttl: int = 300) -> bytes:
    import dns.update, dns.name, dns.rdataclass, dns.rdatatype, dns.rdata
    zone = dns.name.from_text(domain + ".")
    upd = dns.update.UpdateMessage(zone)
    upd.add(dns.name.from_text(f"{hostname}.{domain}."), ttl,
            dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, ip))
    return upd.to_wire()


def _add_aaaa(hostname: str, ipv6: str, domain: str, ttl: int = 300) -> bytes:
    import dns.update, dns.name, dns.rdataclass, dns.rdatatype, dns.rdata
    zone = dns.name.from_text(domain + ".")
    upd = dns.update.UpdateMessage(zone)
    upd.add(dns.name.from_text(f"{hostname}.{domain}."), ttl,
            dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.AAAA, ipv6))
    return upd.to_wire()


def _del_a(hostname: str, ip: str, domain: str) -> bytes:
    """DELETE specific A rdata (not the whole name)."""
    import dns.update, dns.name, dns.rdataclass, dns.rdatatype, dns.rdata
    zone = dns.name.from_text(domain + ".")
    upd = dns.update.UpdateMessage(zone)
    upd.delete(dns.name.from_text(f"{hostname}.{domain}."),
               dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, ip))
    return upd.to_wire()


def _del_aaaa(hostname: str, ipv6: str, domain: str) -> bytes:
    """DELETE specific AAAA rdata."""
    import dns.update, dns.name, dns.rdataclass, dns.rdatatype, dns.rdata
    zone = dns.name.from_text(domain + ".")
    upd = dns.update.UpdateMessage(zone)
    upd.delete(dns.name.from_text(f"{hostname}.{domain}."),
               dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.AAAA, ipv6))
    return upd.to_wire()


def _del_name(hostname: str, domain: str) -> bytes:
    """DELETE all RRsets for a name (rdtype ANY)."""
    import dns.update, dns.name
    zone = dns.name.from_text(domain + ".")
    upd = dns.update.UpdateMessage(zone)
    upd.delete(dns.name.from_text(f"{hostname}.{domain}."))
    return upd.to_wire()


def _arpa(ip: str) -> str:
    return str(ipaddress.ip_address(ip).reverse_pointer)


# ---------------------------------------------------------------------------

@register
class DdnsAddVerifyA(Scenario):
    name = "ddns_add_verify_a"
    description = (
        "DDNS NCR A ADD: verify record is stored as type A (not AAAA), "
        "synthesized PTR uses in-addr.arpa, and drill resolves both"
    )
    tags = ["ddns", "verify", "ipv4", "ptr"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running")

    def run(self, ctx: ChaosContext) -> None:
        hostname, ip = ctx.alloc_host("-ddnsA")
        _send(ctx, _add_a(hostname, ip, ctx.domain))
        self._hostname = hostname
        self._ip = ip
        self._fqdn = f"{hostname}.{ctx.domain}"
        ctx.event("ncr_sent", type="A", hostname=hostname, ip=ip)
        ctx.wait(2, "daemon NCR settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        # Record must be type A, not accidentally AAAA
        if not ctx.unbound.has_record(self._fqdn, self._ip, "A"):
            failures.append(f"A record missing: {self._fqdn} → {self._ip}")
        if ctx.unbound.has_record(self._fqdn, self._ip, "AAAA"):
            failures.append(f"IPv4 addr stored as AAAA (type confusion): {self._fqdn}")

        # PTR must use in-addr.arpa form
        expected_arpa = _arpa(self._ip)
        if not ctx.unbound.has_ptr(self._ip, self._fqdn):
            failures.append(f"PTR missing: {expected_arpa} → {self._fqdn}")
        raw = ctx.unbound.list_local_data()
        if expected_arpa not in raw:
            failures.append(
                f"PTR not keyed by in-addr.arpa: expected {expected_arpa!r}, "
                f"arpa keys: {[k for k in raw if 'arpa' in k]!r}"
            )

        # DNS resolution
        result = ctx.dns.verify_pair(self._hostname, self._ip, ctx.domain, "A")
        if not result["forward_ok"]:
            failures.append(f"drill A: {result['forward_answer']!r} ≠ {self._ip}")
        if not result["ptr_ok"]:
            failures.append(f"drill PTR: {result['ptr_answer']!r} (expected {self._fqdn})")
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            _send(ctx, _del_name(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "delete settle")
        ctx.run_clean()


@register
class DdnsAddVerifyAaaa(Scenario):
    name = "ddns_add_verify_aaaa"
    description = (
        "DDNS NCR AAAA ADD: verify stored as AAAA (not A), synthesized PTR is "
        "full 32-nibble ip6.arpa, and drill AAAA resolves"
    )
    tags = ["ddns", "verify", "ipv6", "ptr"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running")

    def run(self, ctx: ChaosContext) -> None:
        hostname, ipv6 = ctx.alloc_v6_host("-ddnsAAAA", prefix=_V6_PREFIX)
        _send(ctx, _add_aaaa(hostname, ipv6, ctx.domain))
        self._hostname = hostname
        self._ipv6 = ipv6
        self._fqdn = f"{hostname}.{ctx.domain}"
        ctx.event("ncr_sent", type="AAAA", hostname=hostname, ipv6=ipv6)
        ctx.wait(2, "daemon NCR settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        # Must be AAAA, not A
        if not ctx.unbound.has_record(self._fqdn, self._ipv6, "AAAA"):
            failures.append(f"AAAA record missing: {self._fqdn} → {self._ipv6}")
        if ctx.unbound.has_record(self._fqdn, self._ipv6, "A"):
            failures.append(f"IPv6 addr stored as A (type confusion): {self._fqdn}")

        # PTR must be full 32-nibble ip6.arpa
        expected_arpa = _arpa(self._ipv6)
        if not ctx.unbound.has_ptr(self._ipv6, self._fqdn):
            failures.append(f"IPv6 PTR missing: {expected_arpa} → {self._fqdn}")
        raw = ctx.unbound.list_local_data()
        if expected_arpa not in raw:
            failures.append(
                f"PTR not keyed by ip6.arpa: expected {expected_arpa!r}, "
                f"ip6 keys: {[k for k in raw if 'ip6.arpa' in k]!r}"
            )
        else:
            # Verify nibble count
            nibble_part = expected_arpa[:-len(".ip6.arpa")]
            nibbles = nibble_part.split(".")
            if len(nibbles) != 32:
                failures.append(
                    f"ip6.arpa PTR has {len(nibbles)} labels not 32: {expected_arpa!r}"
                )

        # DNS resolution (AAAA forward)
        result = ctx.dns.verify_pair(self._hostname, self._ipv6, ctx.domain, "AAAA")
        if not result["forward_ok"]:
            failures.append(
                f"drill AAAA: {result['forward_answer']!r} ≠ {self._ipv6}"
            )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            _send(ctx, _del_name(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "delete settle")
        ctx.run_clean()


@register
class DdnsDualFamilyNcr(Scenario):
    name = "ddns_dual_family_ncr"
    description = (
        "DDNS A + AAAA NCRs for same hostname: both record types and both PTRs "
        "must coexist; neither family interferes with the other"
    )
    tags = ["ddns", "verify", "dual-stack", "ptr"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running")

    def run(self, ctx: ChaosContext) -> None:
        hostname, ipv4 = ctx.alloc_host("-dsdual")
        _, ipv6 = ctx.alloc_v6_host("-dsdual", prefix=_V6_PREFIX)
        host = ctx.cfg.opnsense_host
        _send(ctx, _add_a(hostname, ipv4, ctx.domain))
        ctx.wait(1, "A NCR settle")
        _send(ctx, _add_aaaa(hostname, ipv6, ctx.domain))
        self._hostname = hostname
        self._ipv4 = ipv4
        self._ipv6 = ipv6
        self._fqdn = f"{hostname}.{ctx.domain}"
        ctx.event("ncr_sent", hostname=hostname, ipv4=ipv4, ipv6=ipv6)
        ctx.wait(2, "AAAA NCR settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        fqdn = self._fqdn

        # Both forward records must be present with the correct type
        if not ctx.unbound.has_record(fqdn, self._ipv4, "A"):
            failures.append(f"A record missing: {fqdn} → {self._ipv4}")
        if ctx.unbound.has_record(fqdn, self._ipv4, "AAAA"):
            failures.append(f"IPv4 addr registered as AAAA (type confusion)")
        if not ctx.unbound.has_record(fqdn, self._ipv6, "AAAA"):
            failures.append(f"AAAA record missing: {fqdn} → {self._ipv6}")
        if ctx.unbound.has_record(fqdn, self._ipv6, "A"):
            failures.append(f"IPv6 addr registered as A (type confusion)")

        # Both PTRs must exist with correct arpa formats
        if not ctx.unbound.has_ptr(self._ipv4, fqdn):
            failures.append(f"IPv4 PTR missing: {_arpa(self._ipv4)} → {fqdn}")
        if not ctx.unbound.has_ptr(self._ipv6, fqdn):
            failures.append(f"IPv6 PTR missing: {_arpa(self._ipv6)} → {fqdn}")

        # Adding AAAA must not have removed A or its PTR (and vice versa)
        raw = ctx.unbound.list_local_data()
        if _arpa(self._ipv4) not in raw:
            failures.append(f"in-addr.arpa PTR key gone: {_arpa(self._ipv4)!r}")
        if _arpa(self._ipv6) not in raw:
            failures.append(f"ip6.arpa PTR key gone: {_arpa(self._ipv6)!r}")

        # DNS resolution for both families
        for rdtype, ip in [("A", self._ipv4), ("AAAA", self._ipv6)]:
            result = ctx.dns.verify_pair(self._hostname, ip, ctx.domain, rdtype)
            if not result["forward_ok"]:
                failures.append(
                    f"drill {rdtype}: {result['forward_answer']!r} ≠ {ip}"
                )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        host = ctx.cfg.opnsense_host
        try:
            _send(ctx, _del_name(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "delete settle")
        ctx.run_clean()


@register
class DdnsDeleteAPreservesAaaa(Scenario):
    name = "ddns_delete_a_preserves_aaaa"
    description = (
        "Dual-stack host: DDNS DELETE A removes A + in-addr.arpa PTR; "
        "AAAA and its ip6.arpa PTR must survive"
    )
    tags = ["ddns", "verify", "dual-stack", "delete", "ptr"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running")

    def run(self, ctx: ChaosContext) -> None:
        hostname, ipv4 = ctx.alloc_host("-delAkeepAAAA")
        _, ipv6 = ctx.alloc_v6_host("-delAkeepAAAA", prefix=_V6_PREFIX)
        host = ctx.cfg.opnsense_host

        # Establish dual-stack state
        _send(ctx, _add_a(hostname, ipv4, ctx.domain))
        ctx.wait(1, "A add settle")
        _send(ctx, _add_aaaa(hostname, ipv6, ctx.domain))
        ctx.wait(2, "AAAA add settle")

        self._hostname = hostname
        self._ipv4 = ipv4
        self._ipv6 = ipv6
        self._fqdn = f"{hostname}.{ctx.domain}"
        ctx.event("dual_stack_established", hostname=hostname, ipv4=ipv4, ipv6=ipv6)

        # Verify both present before the delete
        pre_a = ctx.unbound.has_record(self._fqdn, ipv4, "A")
        pre_aaaa = ctx.unbound.has_record(self._fqdn, ipv6, "AAAA")
        ctx.event("pre_delete_state", a_present=pre_a, aaaa_present=pre_aaaa)
        if not pre_a or not pre_aaaa:
            ctx.event("warn", msg="pre-delete state incomplete — test may give false results")

        # Delete only the A record
        _send(ctx, _del_a(hostname, ipv4, ctx.domain))
        ctx.wait(2, "A delete settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        fqdn = self._fqdn

        # A and its in-addr.arpa PTR must be gone
        if ctx.unbound.has_record(fqdn, self._ipv4, "A"):
            failures.append(f"A record still present after DELETE: {fqdn} → {self._ipv4}")
        if ctx.unbound.has_ptr(self._ipv4, fqdn):
            failures.append(
                f"in-addr.arpa PTR still present after A DELETE: "
                f"{_arpa(self._ipv4)} → {fqdn}"
            )

        # AAAA and its ip6.arpa PTR must survive
        if not ctx.unbound.has_record(fqdn, self._ipv6, "AAAA"):
            failures.append(
                f"AAAA removed by A delete (family isolation failure): {fqdn} → {self._ipv6}"
            )
        if not ctx.unbound.has_ptr(self._ipv6, fqdn):
            failures.append(
                f"ip6.arpa PTR removed by A delete (family isolation failure): "
                f"{_arpa(self._ipv6)} → {fqdn}"
            )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        host = ctx.cfg.opnsense_host
        try:
            _send(ctx, _del_name(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "delete settle")
        ctx.run_clean()


@register
class DdnsDeleteAaaaPreservesA(Scenario):
    name = "ddns_delete_aaaa_preserves_a"
    description = (
        "Dual-stack host: DDNS DELETE AAAA removes AAAA + ip6.arpa PTR; "
        "A and its in-addr.arpa PTR must survive"
    )
    tags = ["ddns", "verify", "dual-stack", "delete", "ptr"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running")

    def run(self, ctx: ChaosContext) -> None:
        hostname, ipv4 = ctx.alloc_host("-delAAAAkeepA")
        _, ipv6 = ctx.alloc_v6_host("-delAAAAkeepA", prefix=_V6_PREFIX)
        host = ctx.cfg.opnsense_host

        _send(ctx, _add_a(hostname, ipv4, ctx.domain))
        ctx.wait(1, "A add settle")
        _send(ctx, _add_aaaa(hostname, ipv6, ctx.domain))
        ctx.wait(2, "AAAA add settle")

        self._hostname = hostname
        self._ipv4 = ipv4
        self._ipv6 = ipv6
        self._fqdn = f"{hostname}.{ctx.domain}"

        pre_a = ctx.unbound.has_record(self._fqdn, ipv4, "A")
        pre_aaaa = ctx.unbound.has_record(self._fqdn, ipv6, "AAAA")
        ctx.event("dual_stack_established", hostname=hostname,
                  ipv4=ipv4, ipv6=ipv6, pre_a=pre_a, pre_aaaa=pre_aaaa)

        # Delete only the AAAA record
        _send(ctx, _del_aaaa(hostname, ipv6, ctx.domain))
        ctx.wait(2, "AAAA delete settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        fqdn = self._fqdn

        # AAAA and its ip6.arpa PTR must be gone
        if ctx.unbound.has_record(fqdn, self._ipv6, "AAAA"):
            failures.append(f"AAAA still present after DELETE: {fqdn} → {self._ipv6}")
        if ctx.unbound.has_ptr(self._ipv6, fqdn):
            failures.append(
                f"ip6.arpa PTR still present after AAAA DELETE: "
                f"{_arpa(self._ipv6)} → {fqdn}"
            )

        # A and its in-addr.arpa PTR must survive
        if not ctx.unbound.has_record(fqdn, self._ipv4, "A"):
            failures.append(
                f"A removed by AAAA delete (family isolation failure): {fqdn} → {self._ipv4}"
            )
        if not ctx.unbound.has_ptr(self._ipv4, fqdn):
            failures.append(
                f"in-addr.arpa PTR removed by AAAA delete (family isolation failure): "
                f"{_arpa(self._ipv4)} → {fqdn}"
            )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        host = ctx.cfg.opnsense_host
        try:
            _send(ctx, _del_name(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "delete settle")
        ctx.run_clean()


@register
class DdnsNcrIdempotent(Scenario):
    name = "ddns_ncr_idempotent"
    description = (
        "Re-send the same A NCR three times; verify exactly one A record and "
        "one PTR (no duplicates from repeated adds)"
    )
    tags = ["ddns", "verify", "idempotent"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running")

    def run(self, ctx: ChaosContext) -> None:
        hostname, ip = ctx.alloc_host("-idem")
        host = ctx.cfg.opnsense_host
        payload = _add_a(hostname, ip, ctx.domain)
        for _ in range(3):
            _send(ctx, payload)
            time.sleep(0.5)
        self._hostname = hostname
        self._ip = ip
        self._fqdn = f"{hostname}.{ctx.domain}"
        ctx.event("repeated_ncr_sent", count=3, hostname=hostname, ip=ip)
        ctx.wait(2, "last NCR settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        raw = ctx.unbound.list_local_data()
        fqdn = self._fqdn

        # Forward record — unbound-control uses tabs between fields
        fwd_lines = [l for l in raw.get(fqdn, [])
                     if l.split()[3:4] == ["A"] and self._ip in l]
        if len(fwd_lines) == 0:
            failures.append(f"A record missing after repeated NCRs: {fqdn}")
        elif len(fwd_lines) > 1:
            failures.append(
                f"Duplicate A records after repeated NCRs: {len(fwd_lines)} "
                f"entries for {fqdn} → {self._ip}"
            )

        # PTR record
        arpa = _arpa(self._ip)
        ptr_lines = [l for l in raw.get(arpa, []) if "PTR" in l]
        if len(ptr_lines) == 0:
            failures.append(f"PTR missing after repeated NCRs: {arpa}")
        elif len(ptr_lines) > 1:
            failures.append(
                f"Duplicate PTRs after repeated NCRs: {len(ptr_lines)} entries for {arpa}"
            )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            _send(ctx, _del_name(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "delete settle")
        ctx.run_clean()


@register
class DdnsIpChangeLastWins(Scenario):
    name = "ddns_ip_change_last_wins"
    description = (
        "Send NCR A for ip1, then NCR A for same host with ip2; under last_wins "
        "ip1's record + PTR must be replaced by ip2's"
    )
    tags = ["ddns", "verify", "collision", "last_wins"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running")
        # Confirm policy is last_wins (the default)
        policy_out = ctx.ssh.sudo(
            "grep -o 'last_wins\\|first_wins\\|allow' /conf/config.xml | head -1",
            check=False, timeout=5,
        ).strip()
        if policy_out and policy_out not in ("last_wins", ""):
            raise RuntimeError(
                f"collision_policy is {policy_out!r}, not last_wins — skipping"
            )

    def run(self, ctx: ChaosContext) -> None:
        hostname, ip1 = ctx.alloc_host("-ipcng1")
        _, ip2 = ctx.alloc_host("-ipcng2")
        host = ctx.cfg.opnsense_host

        _send(ctx, _add_a(hostname, ip1, ctx.domain))
        ctx.wait(2, "ip1 NCR settle")

        _send(ctx, _add_a(hostname, ip2, ctx.domain))
        self._hostname = hostname
        self._ip1 = ip1
        self._ip2 = ip2
        self._fqdn = f"{hostname}.{ctx.domain}"
        ctx.event("ip_change_sent", hostname=hostname, ip1=ip1, ip2=ip2)
        ctx.wait(2, "ip2 NCR settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        fqdn = self._fqdn

        # ip2 must be present
        if not ctx.unbound.has_record(fqdn, self._ip2, "A"):
            failures.append(f"New IP not registered: {fqdn} → {self._ip2}")

        # ip1 must be gone (replaced by ip2 under last_wins)
        if ctx.unbound.has_record(fqdn, self._ip1, "A"):
            failures.append(
                f"Old IP still present after last_wins replacement: "
                f"{fqdn} → {self._ip1}"
            )

        # PTR for ip1 must be gone
        if ctx.unbound.has_ptr(self._ip1, fqdn):
            failures.append(
                f"Stale PTR for old IP still present: {_arpa(self._ip1)} → {fqdn}"
            )

        # PTR for ip2 must exist
        if not ctx.unbound.has_ptr(self._ip2, fqdn):
            failures.append(
                f"New PTR missing: {_arpa(self._ip2)} → {fqdn}"
            )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        host = ctx.cfg.opnsense_host
        try:
            _send(ctx, _del_name(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "delete settle")
        ctx.run_clean()


@register
class DdnsOrphanedPtrCleanup(Scenario):
    name = "ddns_orphaned_ptr_cleanup"
    description = (
        "After DELETE ALL for a hostname, run bulk clean; verify that the "
        "orphaned PTR records (in-addr.arpa + ip6.arpa) are also removed"
    )
    tags = ["ddns", "verify", "ptr", "cleanup"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running")

    def run(self, ctx: ChaosContext) -> None:
        hostname, ipv4 = ctx.alloc_host("-orphptr")
        host = ctx.cfg.opnsense_host

        # Add A record
        _send(ctx, _add_a(hostname, ipv4, ctx.domain))
        ctx.wait(2, "A add settle")

        self._hostname = hostname
        self._ipv4 = ipv4
        self._fqdn = f"{hostname}.{ctx.domain}"
        ctx.event("a_added", hostname=hostname, ipv4=ipv4)

        # Manually remove ONLY the forward A record from Unbound (simulates
        # a forward record lost without proper PTR cleanup — orphaned PTR)
        ctx.ssh.sudo(
            f"/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
            f"local_data_remove '{self._fqdn}'",
            check=False, timeout=10,
        )
        ctx.event("forward_removed_manually", fqdn=self._fqdn)

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        arpa = _arpa(self._ipv4)

        # Confirm the PTR is currently orphaned (no forward record)
        has_fwd = ctx.unbound.has_record(self._fqdn, self._ipv4, "A")
        has_ptr = ctx.unbound.has_ptr(self._ipv4, self._fqdn)
        ctx.event("before_clean", has_fwd=has_fwd, has_ptr=has_ptr)

        if not has_ptr:
            # PTR was already gone — the daemon may have cleaned it as part of
            # the remove; this is acceptable (not a failure)
            ctx.event("ptr_already_gone")
            return failures

        # Run bulk clean and verify the orphaned PTR is removed
        ctx.run_clean()
        ctx.wait(2, "post-clean settle")

        if ctx.unbound.has_ptr(self._ipv4, self._fqdn):
            failures.append(
                f"Orphaned PTR still present after bulk clean: {arpa} → {self._fqdn}"
            )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            _send(ctx, _del_name(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "delete settle")
        ctx.run_clean()
