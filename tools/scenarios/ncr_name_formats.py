# SPDX-License-Identifier: BSD-2-Clause
"""
NCR format, PTR translation, and name-extraction correctness scenarios.

Historical bugs in this area:
  * IPv6 PTR written in compressed form instead of full 32-nibble ip6.arpa
  * PTR rdata missing trailing dot (relative name) causing mis-resolution
  * PTR target containing bare hostname instead of FQDN (domain suffix lost)
  * A vs AAAA type confusion on NCR with FQDN owner name
  * DELETE A removing the other family's ip6.arpa PTR (family isolation)
  * Duplicate PTRs when synthesis + explicit PTR NCR both fire for same IP

All scenarios inject NCRs directly to 127.0.0.1:53535 via the daemon's UDP
socket.  No Kea involvement — daemon must be running.
"""
from __future__ import annotations

import ipaddress
import time

from tools.scenarios import register
from tools.scenarios.base import Scenario, ChaosContext

# ULA prefix isolated from other scenario prefixes
_V6_PREFIX = "fd45::"


# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------

def _wire_a(hostname: str, ip: str, domain: str, ttl: int = 300) -> bytes:
    import dns.update, dns.name, dns.rdataclass, dns.rdatatype, dns.rdata
    zone = dns.name.from_text(domain + ".")
    upd = dns.update.UpdateMessage(zone)
    upd.add(dns.name.from_text(f"{hostname}.{domain}."), ttl,
            dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, ip))
    return upd.to_wire()


def _wire_aaaa(hostname: str, ipv6: str, domain: str, ttl: int = 300) -> bytes:
    import dns.update, dns.name, dns.rdataclass, dns.rdatatype, dns.rdata
    zone = dns.name.from_text(domain + ".")
    upd = dns.update.UpdateMessage(zone)
    upd.add(dns.name.from_text(f"{hostname}.{domain}."), ttl,
            dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.AAAA, ipv6))
    return upd.to_wire()


def _wire_del_a(hostname: str, ip: str, domain: str) -> bytes:
    """DELETE specific A rdata (type-specific, not whole name)."""
    import dns.update, dns.name, dns.rdataclass, dns.rdatatype, dns.rdata
    zone = dns.name.from_text(domain + ".")
    upd = dns.update.UpdateMessage(zone)
    upd.delete(dns.name.from_text(f"{hostname}.{domain}."),
               dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, ip))
    return upd.to_wire()


def _wire_del_aaaa(hostname: str, ipv6: str, domain: str) -> bytes:
    """DELETE specific AAAA rdata."""
    import dns.update, dns.name, dns.rdataclass, dns.rdatatype, dns.rdata
    zone = dns.name.from_text(domain + ".")
    upd = dns.update.UpdateMessage(zone)
    upd.delete(dns.name.from_text(f"{hostname}.{domain}."),
               dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.AAAA, ipv6))
    return upd.to_wire()


def _wire_del_all(hostname: str, domain: str) -> bytes:
    """DELETE all RRsets for a name."""
    import dns.update, dns.name
    zone = dns.name.from_text(domain + ".")
    upd = dns.update.UpdateMessage(zone)
    upd.delete(dns.name.from_text(f"{hostname}.{domain}."))
    return upd.to_wire()


def _wire_explicit_ptr(arpa: str, target_fqdn: str, domain: str, ttl: int = 300) -> bytes:
    """Build an explicit PTR UPDATE (owner=arpa, rdata=target FQDN with trailing dot)."""
    import dns.update, dns.name, dns.rdataclass, dns.rdatatype, dns.rdata
    zone = dns.name.from_text(domain + ".")
    upd = dns.update.UpdateMessage(zone)
    target = target_fqdn.rstrip(".") + "."
    upd.add(dns.name.from_text(arpa + "."), ttl,
            dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.PTR, target))
    return upd.to_wire()


def _arpa(ip: str) -> str:
    return str(ipaddress.ip_address(ip).reverse_pointer)


def _send(ctx: ChaosContext, payload: bytes) -> None:
    ctx.send_ncr(payload)


def _ptr_lines_for(ctx: ChaosContext, arpa: str) -> list[str]:
    """Return all raw local_data lines for the given arpa owner name."""
    raw = ctx.unbound.list_local_data()
    return [l for l in raw.get(arpa, []) if "PTR" in l]


def _fwd_lines_for(ctx: ChaosContext, fqdn: str, rdtype: str) -> list[str]:
    """Return all raw local_data lines for fqdn with the given rdtype."""
    raw = ctx.unbound.list_local_data()
    return [l for l in raw.get(fqdn, [])
            if len(l.split()) >= 4 and l.split()[3] == rdtype.upper()]


# ---------------------------------------------------------------------------

@register
class PtrRdataHasTrailingDot(Scenario):
    """After an A NCR the synthesized PTR rdata in Unbound must be
    'hostname.domain.' (absolute FQDN with trailing dot), not a relative name.
    A relative PTR target would cause resolvers to append the search domain,
    producing a broken double-suffix like 'hostname.domain.lan.'."""
    name = "ptr_rdata_has_trailing_dot"
    description = (
        "A NCR → verify raw PTR rdata in Unbound is 'hostname.domain.' "
        "(trailing dot = absolute FQDN, not relative)"
    )
    tags = ["ptr", "format", "rdata", "ddns"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running")

    def run(self, ctx: ChaosContext) -> None:
        hostname, ip = ctx.alloc_host("-ptrdot")
        _send(ctx, _wire_a(hostname, ip, ctx.domain))
        self._hostname = hostname
        self._ip = ip
        self._fqdn = f"{hostname}.{ctx.domain}"
        ctx.event("ncr_sent", hostname=hostname, ip=ip)
        ctx.wait(2, "daemon NCR settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        arpa = _arpa(self._ip)

        # A record check
        if not ctx.unbound.has_record(self._fqdn, self._ip, "A"):
            failures.append(f"A record missing: {self._fqdn} → {self._ip}")

        # Raw PTR rdata check — must end with "."
        ptr_lines = _ptr_lines_for(ctx, arpa)
        if not ptr_lines:
            failures.append(f"PTR record missing in Unbound: {arpa}")
        else:
            for line in ptr_lines:
                parts = line.split()
                if len(parts) < 5:
                    failures.append(f"PTR line has too few fields: {line!r}")
                    continue
                rdata = parts[4]
                # The rdata should be 'hostname.domain.' (with trailing dot)
                if not rdata.endswith("."):
                    failures.append(
                        f"PTR rdata missing trailing dot (relative name!): "
                        f"{rdata!r} — should be {self._fqdn!r}."
                    )
                # And must contain the full domain, not just the bare hostname
                if "." not in rdata.rstrip("."):
                    failures.append(
                        f"PTR rdata is bare hostname without domain: {rdata!r} "
                        f"(expected {self._fqdn}.)"
                    )
                # And must resolve via drill
                result = ctx.dns.verify_pair(self._hostname, self._ip, ctx.domain, "A")
                if not result["ptr_ok"]:
                    failures.append(
                        f"drill PTR → {result['ptr_answer']!r}, "
                        f"expected {self._fqdn!r}"
                    )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            _send(ctx, _wire_del_all(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "delete settle")
        ctx.run_clean()


@register
class PtrTargetIncludesDomain(Scenario):
    """PTR target must be the full FQDN 'hostname.domain', not the bare hostname.
    If the domain suffix is stripped, reverse DNS returns just 'hostname' which
    doesn't match forward-confirmed FQDNs and breaks many tools."""
    name = "ptr_target_includes_domain"
    description = (
        "A NCR → PTR target must be 'hostname.domain' (full FQDN), "
        "not bare 'hostname'"
    )
    tags = ["ptr", "format", "fqdn", "ddns"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running")

    def run(self, ctx: ChaosContext) -> None:
        hostname, ip = ctx.alloc_host("-ptrdomain")
        _send(ctx, _wire_a(hostname, ip, ctx.domain))
        self._hostname = hostname
        self._ip = ip
        self._fqdn = f"{hostname}.{ctx.domain}"
        ctx.event("ncr_sent", hostname=hostname, ip=ip)
        ctx.wait(2, "daemon NCR settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        arpa = _arpa(self._ip)

        ptr_lines = _ptr_lines_for(ctx, arpa)
        if not ptr_lines:
            failures.append(f"PTR missing: {arpa}")
            return failures

        for line in ptr_lines:
            parts = line.split()
            if len(parts) < 5:
                continue
            rdata = parts[4].rstrip(".")
            # Must not be bare hostname — must include at least one dot
            if "." not in rdata:
                failures.append(
                    f"PTR target is bare hostname (missing domain): {rdata!r}; "
                    f"expected {self._fqdn!r}"
                )
            elif rdata != self._fqdn:
                failures.append(
                    f"PTR target mismatch: {rdata!r} ≠ {self._fqdn!r}"
                )

        # Cross-check: drill PTR must return the full FQDN
        ptr_answer = ctx.dns.reverse(self._ip)
        if ptr_answer is None:
            failures.append(f"drill PTR returned nothing for {self._ip}")
        elif "." not in ptr_answer:
            failures.append(
                f"drill PTR returned bare hostname {ptr_answer!r} — "
                f"domain suffix is missing"
            )
        elif ptr_answer != self._fqdn:
            failures.append(
                f"drill PTR → {ptr_answer!r}, expected {self._fqdn!r}"
            )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            _send(ctx, _wire_del_all(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "delete settle")
        ctx.run_clean()


@register
class IPv6CompressedNcrPtr(Scenario):
    """AAAA NCR with a compressed IPv6 address (e.g. fd45::100).
    The daemon must expand it via ipaddress.ip_address() to produce the full
    32-nibble ip6.arpa PTR owner, not a compressed or partial form."""
    name = "ipv6_compressed_ncr_ptr"
    description = (
        "AAAA NCR with compressed IPv6 → synthesized PTR must be the full "
        "32-nibble ip6.arpa form, not compressed"
    )
    tags = ["ptr", "format", "ipv6", "ddns"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running")

    def run(self, ctx: ChaosContext) -> None:
        # alloc_v6_host gives e.g. "fd45::100" — inherently compressed
        hostname, ipv6 = ctx.alloc_v6_host("-v6cmpptr", prefix=_V6_PREFIX)
        _send(ctx, _wire_aaaa(hostname, ipv6, ctx.domain))
        self._hostname = hostname
        self._ipv6 = ipv6
        self._fqdn = f"{hostname}.{ctx.domain}"
        ctx.event("ncr_sent", hostname=hostname, ipv6=ipv6)
        ctx.wait(2, "daemon NCR settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        fqdn = self._fqdn
        expected_arpa = _arpa(self._ipv6)  # full 32-nibble from ipaddress

        # Forward: must be AAAA not A
        if not ctx.unbound.has_record(fqdn, self._ipv6, "AAAA"):
            failures.append(f"AAAA record missing: {fqdn} → {self._ipv6}")
        if ctx.unbound.has_record(fqdn, self._ipv6, "A"):
            failures.append(f"IPv6 address mis-stored as A: {fqdn}")

        # PTR: must exist under the full 32-nibble ip6.arpa owner
        ptr_lines = _ptr_lines_for(ctx, expected_arpa)
        if not ptr_lines:
            raw = ctx.unbound.list_local_data()
            ip6_keys = [k for k in raw if "ip6.arpa" in k]
            failures.append(
                f"No PTR at {expected_arpa!r}; "
                f"ip6.arpa keys present: {ip6_keys!r}"
            )
        else:
            # Verify it's the 32-nibble form
            nibbles = expected_arpa[:-len(".ip6.arpa")].split(".")
            if len(nibbles) != 32:
                failures.append(
                    f"ip6.arpa PTR key has {len(nibbles)} labels (expected 32): "
                    f"{expected_arpa!r}"
                )
            if not all(len(n) == 1 and n in "0123456789abcdef" for n in nibbles):
                failures.append(
                    f"ip6.arpa PTR key contains non-single-hex nibble: {expected_arpa!r}"
                )

        # PTR rdata must be the full FQDN with trailing dot
        for line in ptr_lines:
            parts = line.split()
            if len(parts) >= 5:
                rdata = parts[4]
                if not rdata.endswith("."):
                    failures.append(
                        f"IPv6 PTR rdata missing trailing dot: {rdata!r}"
                    )
                if "." not in rdata.rstrip("."):
                    failures.append(
                        f"IPv6 PTR rdata is bare hostname (no domain): {rdata!r}"
                    )

        # Forward DNS
        result = ctx.dns.verify_pair(self._hostname, self._ipv6, ctx.domain, "AAAA")
        if not result["forward_ok"]:
            failures.append(
                f"drill AAAA: {result['forward_answer']!r} ≠ {self._ipv6}"
            )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            _send(ctx, _wire_del_all(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "delete settle")
        ctx.run_clean()


@register
class IPv6ExpandedNcrPtr(Scenario):
    """AAAA NCR with a fully-expanded IPv6 address string.
    The PTR arpa form must be identical to the compressed-address case —
    ipaddress normalizes both to the same canonical form."""
    name = "ipv6_expanded_ncr_ptr"
    description = (
        "AAAA NCR with fully-expanded IPv6 → same 32-nibble ip6.arpa PTR "
        "as the compressed-address path (normalization check)"
    )
    tags = ["ptr", "format", "ipv6", "ddns"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running")

    def run(self, ctx: ChaosContext) -> None:
        hostname, ipv6_compressed = ctx.alloc_v6_host("-v6expptr", prefix=_V6_PREFIX)
        # Expand to full 8-group form
        ipv6_expanded = ipaddress.IPv6Address(ipv6_compressed).exploded
        # Send the UPDATE with the expanded string — dnspython parses it to the same rdata
        _send(ctx, _wire_aaaa(hostname, ipv6_expanded, ctx.domain))
        self._hostname = hostname
        self._ipv6_compressed = ipv6_compressed
        self._ipv6_expanded = ipv6_expanded
        self._fqdn = f"{hostname}.{ctx.domain}"
        ctx.event("ncr_sent", hostname=hostname, ipv6_expanded=ipv6_expanded,
                  ipv6_compressed=ipv6_compressed)
        ctx.wait(2, "daemon NCR settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        fqdn = self._fqdn
        # Both forms normalize to the same arpa key
        expected_arpa = _arpa(self._ipv6_compressed)

        # Unbound stores the canonical (compressed) form — try both
        found = (ctx.unbound.has_record(fqdn, self._ipv6_compressed, "AAAA") or
                 ctx.unbound.has_record(fqdn, self._ipv6_expanded, "AAAA"))
        if not found:
            failures.append(
                f"AAAA record missing (neither compressed {self._ipv6_compressed!r} "
                f"nor expanded {self._ipv6_expanded!r}): {fqdn}"
            )

        ptr_lines = _ptr_lines_for(ctx, expected_arpa)
        if not ptr_lines:
            failures.append(f"PTR missing at {expected_arpa!r}")
        else:
            nibbles = expected_arpa[:-len(".ip6.arpa")].split(".")
            if len(nibbles) != 32:
                failures.append(
                    f"ip6.arpa PTR has {len(nibbles)} labels (expected 32): "
                    f"{expected_arpa!r}"
                )

        result = ctx.dns.verify_pair(self._hostname, self._ipv6_compressed, ctx.domain, "AAAA")
        if not result["forward_ok"]:
            failures.append(
                f"drill AAAA: {result['forward_answer']!r} ≠ {self._ipv6_compressed}"
            )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            _send(ctx, _wire_del_all(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "delete settle")
        ctx.run_clean()


@register
class NcrAandAAAACoexistWithPtrs(Scenario):
    """Separate A and AAAA NCRs (as kea-dhcp-ddns sends them) for the same
    hostname must produce two independent forward records + two independent PTRs.
    Neither NCR should remove or overwrite the other family's record."""
    name = "ncr_a_and_aaaa_coexist_with_ptrs"
    description = (
        "Separate A NCR then AAAA NCR for same hostname: A + in-addr.arpa PTR "
        "and AAAA + ip6.arpa PTR must all coexist independently"
    )
    tags = ["ptr", "format", "dual-stack", "ddns", "coexist"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running")

    def run(self, ctx: ChaosContext) -> None:
        hostname, ipv4 = ctx.alloc_host("-coexist")
        _, ipv6 = ctx.alloc_v6_host("-coexist", prefix=_V6_PREFIX)
        _send(ctx, _wire_a(hostname, ipv4, ctx.domain))
        ctx.wait(1, "A NCR settle")
        _send(ctx, _wire_aaaa(hostname, ipv6, ctx.domain))
        self._hostname = hostname
        self._ipv4 = ipv4
        self._ipv6 = ipv6
        self._fqdn = f"{hostname}.{ctx.domain}"
        ctx.event("ncr_sent", hostname=hostname, ipv4=ipv4, ipv6=ipv6)
        ctx.wait(2, "AAAA NCR settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        fqdn = self._fqdn

        # Forward records — exact type check
        if not ctx.unbound.has_record(fqdn, self._ipv4, "A"):
            failures.append(f"A record missing: {fqdn} → {self._ipv4}")
        if ctx.unbound.has_record(fqdn, self._ipv4, "AAAA"):
            failures.append(f"IPv4 addr stored as AAAA (type confusion): {fqdn}")
        if not ctx.unbound.has_record(fqdn, self._ipv6, "AAAA"):
            failures.append(f"AAAA record missing: {fqdn} → {self._ipv6}")
        if ctx.unbound.has_record(fqdn, self._ipv6, "A"):
            failures.append(f"IPv6 addr stored as A (type confusion): {fqdn}")

        # PTRs — both must exist with correct arpa owner keys
        arpa4 = _arpa(self._ipv4)
        arpa6 = _arpa(self._ipv6)

        ptr4_lines = _ptr_lines_for(ctx, arpa4)
        if not ptr4_lines:
            failures.append(f"in-addr.arpa PTR missing: {arpa4}")
        else:
            rdata = ptr4_lines[0].split()[-1].rstrip(".")
            if rdata != fqdn:
                failures.append(
                    f"in-addr.arpa PTR target wrong: {rdata!r} ≠ {fqdn!r}"
                )

        ptr6_lines = _ptr_lines_for(ctx, arpa6)
        if not ptr6_lines:
            failures.append(f"ip6.arpa PTR missing: {arpa6}")
        else:
            # Verify 32-nibble format
            nibbles = arpa6[:-len(".ip6.arpa")].split(".")
            if len(nibbles) != 32:
                failures.append(
                    f"ip6.arpa PTR key has {len(nibbles)} labels: {arpa6!r}"
                )
            rdata = ptr6_lines[0].split()[-1].rstrip(".")
            if rdata != fqdn:
                failures.append(
                    f"ip6.arpa PTR target wrong: {rdata!r} ≠ {fqdn!r}"
                )

        # AAAA NCR must not have removed the A or its PTR
        if not ctx.unbound.has_record(fqdn, self._ipv4, "A"):
            failures.append(
                f"A record gone after AAAA NCR (AAAA must not affect A): {fqdn}"
            )
        if not _ptr_lines_for(ctx, arpa4):
            failures.append(
                f"in-addr.arpa PTR gone after AAAA NCR (family isolation failure)"
            )

        # DNS resolution for both families
        for rdtype, ip in [("A", self._ipv4), ("AAAA", self._ipv6)]:
            result = ctx.dns.verify_pair(self._hostname, ip, ctx.domain, rdtype)
            if not result["forward_ok"]:
                failures.append(
                    f"drill {rdtype}: {result['forward_answer']!r} ≠ {ip}"
                )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            _send(ctx, _wire_del_all(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "delete settle")
        ctx.run_clean()


@register
class NcrDeleteALeavesIPv6PtrIntact(Scenario):
    """After a dual-stack NCR sequence, DELETE A must remove only:
      - the A record
      - the in-addr.arpa PTR
    It must NOT touch:
      - the AAAA record
      - the ip6.arpa PTR (32-nibble form must survive intact)"""
    name = "ncr_delete_a_leaves_ipv6_ptr_intact"
    description = (
        "DELETE A NCR: A + in-addr.arpa PTR removed; "
        "AAAA + full 32-nibble ip6.arpa PTR survive"
    )
    tags = ["ptr", "format", "dual-stack", "delete", "ddns"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running")

    def run(self, ctx: ChaosContext) -> None:
        hostname, ipv4 = ctx.alloc_host("-delAv6ptr")
        _, ipv6 = ctx.alloc_v6_host("-delAv6ptr", prefix=_V6_PREFIX)
        _send(ctx, _wire_a(hostname, ipv4, ctx.domain))
        ctx.wait(1, "A settle")
        _send(ctx, _wire_aaaa(hostname, ipv6, ctx.domain))
        ctx.wait(2, "AAAA settle")

        self._hostname = hostname
        self._ipv4 = ipv4
        self._ipv6 = ipv6
        self._fqdn = f"{hostname}.{ctx.domain}"
        self._arpa4 = _arpa(ipv4)
        self._arpa6 = _arpa(ipv6)

        # Record pre-delete state
        pre_a = ctx.unbound.has_record(self._fqdn, ipv4, "A")
        pre_aaaa = ctx.unbound.has_record(self._fqdn, ipv6, "AAAA")
        pre_ptr4 = bool(_ptr_lines_for(ctx, self._arpa4))
        pre_ptr6 = bool(_ptr_lines_for(ctx, self._arpa6))
        ctx.event("pre_delete", a=pre_a, aaaa=pre_aaaa,
                  ptr4=pre_ptr4, ptr6=pre_ptr6,
                  arpa6=self._arpa6)

        # Now delete only the A
        _send(ctx, _wire_del_a(hostname, ipv4, ctx.domain))
        ctx.wait(2, "DELETE A settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        fqdn = self._fqdn

        # A and its PTR must be gone
        if ctx.unbound.has_record(fqdn, self._ipv4, "A"):
            failures.append(f"A still present after DELETE A: {fqdn} → {self._ipv4}")
        if _ptr_lines_for(ctx, self._arpa4):
            failures.append(
                f"in-addr.arpa PTR still present after DELETE A: {self._arpa4}"
            )

        # AAAA must survive
        if not ctx.unbound.has_record(fqdn, self._ipv6, "AAAA"):
            failures.append(
                f"AAAA removed by DELETE A (family isolation failure): {fqdn}"
            )

        # ip6.arpa PTR must survive with full 32-nibble format
        ptr6_lines = _ptr_lines_for(ctx, self._arpa6)
        if not ptr6_lines:
            failures.append(
                f"ip6.arpa PTR removed by DELETE A (family isolation failure): "
                f"{self._arpa6}"
            )
        else:
            # Verify 32-nibble form intact
            nibbles = self._arpa6[:-len(".ip6.arpa")].split(".")
            if len(nibbles) != 32:
                failures.append(
                    f"ip6.arpa PTR key is not 32-nibble: {self._arpa6!r}"
                )
            # PTR rdata target must still be the full FQDN
            rdata = ptr6_lines[0].split()[-1].rstrip(".")
            if rdata != fqdn:
                failures.append(
                    f"ip6.arpa PTR target corrupted: {rdata!r} ≠ {fqdn!r}"
                )

        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            _send(ctx, _wire_del_all(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "delete settle")
        ctx.run_clean()


@register
class NcrDeleteAAAALeavesIPv4PtrIntact(Scenario):
    """Mirror of NcrDeleteALeavesIPv6PtrIntact: DELETE AAAA must remove only
    the AAAA and ip6.arpa PTR, leaving A and in-addr.arpa PTR untouched."""
    name = "ncr_delete_aaaa_leaves_ipv4_ptr_intact"
    description = (
        "DELETE AAAA NCR: AAAA + ip6.arpa PTR removed; "
        "A + in-addr.arpa PTR survive"
    )
    tags = ["ptr", "format", "dual-stack", "delete", "ddns"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running")

    def run(self, ctx: ChaosContext) -> None:
        hostname, ipv4 = ctx.alloc_host("-delAAAAv4ptr")
        _, ipv6 = ctx.alloc_v6_host("-delAAAAv4ptr", prefix=_V6_PREFIX)
        _send(ctx, _wire_a(hostname, ipv4, ctx.domain))
        ctx.wait(1, "A settle")
        _send(ctx, _wire_aaaa(hostname, ipv6, ctx.domain))
        ctx.wait(2, "AAAA settle")

        self._hostname = hostname
        self._ipv4 = ipv4
        self._ipv6 = ipv6
        self._fqdn = f"{hostname}.{ctx.domain}"
        self._arpa4 = _arpa(ipv4)
        self._arpa6 = _arpa(ipv6)

        pre_a = ctx.unbound.has_record(self._fqdn, ipv4, "A")
        pre_aaaa = ctx.unbound.has_record(self._fqdn, ipv6, "AAAA")
        ctx.event("pre_delete", a=pre_a, aaaa=pre_aaaa)

        _send(ctx, _wire_del_aaaa(hostname, ipv6, ctx.domain))
        ctx.wait(2, "DELETE AAAA settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        fqdn = self._fqdn

        # AAAA and ip6.arpa PTR must be gone
        if ctx.unbound.has_record(fqdn, self._ipv6, "AAAA"):
            failures.append(f"AAAA still present after DELETE: {fqdn}")
        if _ptr_lines_for(ctx, self._arpa6):
            failures.append(
                f"ip6.arpa PTR still present after DELETE AAAA: {self._arpa6}"
            )

        # A must survive
        if not ctx.unbound.has_record(fqdn, self._ipv4, "A"):
            failures.append(
                f"A removed by DELETE AAAA (family isolation failure): {fqdn}"
            )

        # in-addr.arpa PTR must survive
        ptr4_lines = _ptr_lines_for(ctx, self._arpa4)
        if not ptr4_lines:
            failures.append(
                f"in-addr.arpa PTR removed by DELETE AAAA (family isolation): "
                f"{self._arpa4}"
            )
        else:
            rdata = ptr4_lines[0].split()[-1].rstrip(".")
            if rdata != fqdn:
                failures.append(
                    f"in-addr.arpa PTR target corrupted: {rdata!r} ≠ {fqdn!r}"
                )

        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            _send(ctx, _wire_del_all(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "delete settle")
        ctx.run_clean()


@register
class NcrExplicitPtrNcrNoDuplicate(Scenario):
    """kea-dhcp-ddns sends two separate NCRs per lease:
      1. A/AAAA NCR → daemon synthesizes a PTR
      2. Explicit PTR NCR → daemon applies the PTR

    After both arrive, there must be exactly ONE PTR for the arpa owner —
    Unbound must not duplicate the record when re-adding the same PTR."""
    name = "ncr_explicit_ptr_ncr_no_duplicate"
    description = (
        "A NCR (daemon synthesizes PTR) + explicit PTR NCR: "
        "exactly one PTR in Unbound (no duplicate)"
    )
    tags = ["ptr", "ddns", "duplicate", "explicit"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running")

    def run(self, ctx: ChaosContext) -> None:
        hostname, ip = ctx.alloc_host("-explptrnc")
        fqdn = f"{hostname}.{ctx.domain}"
        arpa = _arpa(ip)

        # Step 1: A NCR — daemon will synthesize PTR
        _send(ctx, _wire_a(hostname, ip, ctx.domain))
        ctx.wait(2, "A NCR: synthesized PTR settle")

        # Step 2: Explicit PTR NCR for the same arpa — as kea-dhcp-ddns would send
        _send(ctx, _wire_explicit_ptr(arpa, fqdn, ctx.domain))
        self._hostname = hostname
        self._ip = ip
        self._fqdn = fqdn
        self._arpa = arpa
        ctx.event("explicit_ptr_sent", arpa=arpa, target=fqdn)
        ctx.wait(2, "explicit PTR NCR settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []

        # A record must still be present
        if not ctx.unbound.has_record(self._fqdn, self._ip, "A"):
            failures.append(f"A record gone: {self._fqdn}")

        # PTR must exist exactly once
        ptr_lines = _ptr_lines_for(ctx, self._arpa)
        if not ptr_lines:
            failures.append(f"PTR missing: {self._arpa}")
        elif len(ptr_lines) > 1:
            failures.append(
                f"Duplicate PTRs for {self._arpa}: {len(ptr_lines)} records "
                f"(synthesis + explicit NCR must not double-add): {ptr_lines!r}"
            )
        else:
            rdata = ptr_lines[0].split()[-1].rstrip(".")
            if rdata != self._fqdn:
                failures.append(
                    f"PTR target wrong: {rdata!r} ≠ {self._fqdn!r}"
                )

        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            _send(ctx, _wire_del_all(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "delete settle")
        ctx.run_clean()


@register
class NcrIPChangeUpdatesPtr(Scenario):
    """A NCR with ip1 then A NCR with ip2 for same hostname (IP change, as when
    a DHCP lease renews with a new address). Under last_wins:
      - ip1 A record and in-addr.arpa PTR must be replaced
      - ip2 A record and in-addr.arpa PTR must be present
      - No stale PTR for ip1 must remain"""
    name = "ncr_ip_change_updates_ptr"
    description = (
        "IP change via NCR: old A + in-addr.arpa PTR replaced; "
        "new A + PTR present; stale PTR gone"
    )
    tags = ["ptr", "format", "collision", "last_wins", "ddns"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running")
        policy = ctx.ssh.sudo(
            "grep -o 'last_wins\\|first_wins\\|allow' /conf/config.xml | head -1",
            check=False, timeout=5,
        ).strip()
        if policy and policy not in ("last_wins", ""):
            raise RuntimeError(f"collision_policy={policy!r}; test requires last_wins")

    def run(self, ctx: ChaosContext) -> None:
        hostname, ip1 = ctx.alloc_host("-ipcng1")
        _, ip2 = ctx.alloc_host("-ipcng2")

        _send(ctx, _wire_a(hostname, ip1, ctx.domain))
        ctx.wait(2, "ip1 NCR settle")

        pre_a = ctx.unbound.has_record(f"{hostname}.{ctx.domain}", ip1, "A")
        pre_ptr = bool(_ptr_lines_for(ctx, _arpa(ip1)))
        ctx.event("ip1_state", a=pre_a, ptr=pre_ptr)

        _send(ctx, _wire_a(hostname, ip2, ctx.domain))
        self._hostname = hostname
        self._ip1 = ip1
        self._ip2 = ip2
        self._fqdn = f"{hostname}.{ctx.domain}"
        ctx.event("ip2_ncr_sent", ip1=ip1, ip2=ip2)
        ctx.wait(2, "ip2 NCR settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        fqdn = self._fqdn

        # ip2 must be present
        if not ctx.unbound.has_record(fqdn, self._ip2, "A"):
            failures.append(f"New A missing: {fqdn} → {self._ip2}")

        # ip1 must be gone (last_wins replaced it)
        if ctx.unbound.has_record(fqdn, self._ip1, "A"):
            failures.append(f"Stale A still present: {fqdn} → {self._ip1}")

        # Stale PTR for ip1 must be gone
        stale_ptr_lines = _ptr_lines_for(ctx, _arpa(self._ip1))
        if stale_ptr_lines:
            failures.append(
                f"Stale in-addr.arpa PTR for old IP still present: "
                f"{_arpa(self._ip1)} (last_wins must remove it)"
            )

        # New PTR for ip2 must exist
        new_ptr_lines = _ptr_lines_for(ctx, _arpa(self._ip2))
        if not new_ptr_lines:
            failures.append(f"New PTR missing: {_arpa(self._ip2)} → {fqdn}")
        else:
            rdata = new_ptr_lines[0].split()[-1].rstrip(".")
            if rdata != fqdn:
                failures.append(
                    f"New PTR target wrong: {rdata!r} ≠ {fqdn!r}"
                )

        # Drill forward
        result = ctx.dns.verify_pair(self._hostname, self._ip2, ctx.domain, "A")
        if not result["forward_ok"]:
            failures.append(f"drill A: {result['forward_answer']!r} ≠ {self._ip2}")

        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            _send(ctx, _wire_del_all(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "delete settle")
        ctx.run_clean()


@register
class NcrRawLocalDataConsistency(Scenario):
    """Cross-verify that has_record/has_ptr agree with drill for both A and AAAA.
    This catches discrepancies between the test helper's list_local_data parsing
    and what Unbound actually serves via the DNS protocol."""
    name = "ncr_raw_local_data_consistency"
    description = (
        "A + AAAA NCRs: verify has_record/has_ptr and drill all agree on "
        "the same forward + PTR state (helper vs DNS consistency)"
    )
    tags = ["ptr", "format", "dual-stack", "consistency", "ddns"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running")

    def run(self, ctx: ChaosContext) -> None:
        hostname, ipv4 = ctx.alloc_host("-rawconsist")
        _, ipv6 = ctx.alloc_v6_host("-rawconsist", prefix=_V6_PREFIX)
        _send(ctx, _wire_a(hostname, ipv4, ctx.domain))
        ctx.wait(1, "A settle")
        _send(ctx, _wire_aaaa(hostname, ipv6, ctx.domain))
        self._hostname = hostname
        self._ipv4 = ipv4
        self._ipv6 = ipv6
        self._fqdn = f"{hostname}.{ctx.domain}"
        ctx.event("ncr_sent", hostname=hostname, ipv4=ipv4, ipv6=ipv6)
        ctx.wait(2, "AAAA settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        fqdn = self._fqdn

        # --- list_local_data (helper) ---
        helper_a = ctx.unbound.has_record(fqdn, self._ipv4, "A")
        helper_aaaa = ctx.unbound.has_record(fqdn, self._ipv6, "AAAA")
        helper_ptr4 = ctx.unbound.has_ptr(self._ipv4, fqdn)
        helper_ptr6 = ctx.unbound.has_ptr(self._ipv6, fqdn)

        # --- drill (live DNS) ---
        drill_a = ctx.dns.verify_pair(self._hostname, self._ipv4, ctx.domain, "A")
        drill_aaaa = ctx.dns.verify_pair(self._hostname, self._ipv6, ctx.domain, "AAAA")

        ctx.event("helper_state",
                  a=helper_a, aaaa=helper_aaaa, ptr4=helper_ptr4, ptr6=helper_ptr6)
        ctx.event("drill_state",
                  a_ok=drill_a["forward_ok"], a_ans=drill_a["forward_answer"],
                  a_ptr_ok=drill_a["ptr_ok"], a_ptr_ans=drill_a["ptr_answer"],
                  aaaa_ok=drill_aaaa["forward_ok"], aaaa_ans=drill_aaaa["forward_answer"])

        # A: helper must agree with drill
        if not helper_a:
            failures.append(f"list_local_data: A record missing: {fqdn} → {self._ipv4}")
        if not drill_a["forward_ok"]:
            failures.append(
                f"drill A: {drill_a['forward_answer']!r} ≠ {self._ipv4}"
            )
        if helper_a and not drill_a["forward_ok"]:
            failures.append(
                "INCONSISTENCY: list_local_data says A exists but drill A disagrees"
            )

        # AAAA: helper must agree with drill
        if not helper_aaaa:
            failures.append(f"list_local_data: AAAA record missing: {fqdn} → {self._ipv6}")
        if not drill_aaaa["forward_ok"]:
            failures.append(
                f"drill AAAA: {drill_aaaa['forward_answer']!r} ≠ {self._ipv6}"
            )
        if helper_aaaa and not drill_aaaa["forward_ok"]:
            failures.append(
                "INCONSISTENCY: list_local_data says AAAA exists but drill AAAA disagrees"
            )

        # PTR4: helper must agree with drill PTR
        if not helper_ptr4:
            failures.append(
                f"list_local_data: in-addr.arpa PTR missing: {_arpa(self._ipv4)}"
            )
        if not drill_a["ptr_ok"]:
            failures.append(
                f"drill PTR (A): {drill_a['ptr_answer']!r} ≠ {fqdn}"
            )
        if helper_ptr4 and not drill_a["ptr_ok"]:
            failures.append(
                "INCONSISTENCY: list_local_data says PTR4 exists but drill PTR disagrees"
            )

        # PTR6: helper check
        if not helper_ptr6:
            failures.append(
                f"list_local_data: ip6.arpa PTR missing: {_arpa(self._ipv6)}"
            )

        # Raw format verification for ip6.arpa PTR
        arpa6 = _arpa(self._ipv6)
        ptr6_lines = _ptr_lines_for(ctx, arpa6)
        if ptr6_lines:
            nibbles = arpa6[:-len(".ip6.arpa")].split(".")
            if len(nibbles) != 32:
                failures.append(
                    f"ip6.arpa PTR key has {len(nibbles)} nibble labels: {arpa6!r}"
                )
            rdata = ptr6_lines[0].split()[-1]
            if not rdata.endswith("."):
                failures.append(
                    f"ip6.arpa PTR rdata missing trailing dot: {rdata!r}"
                )

        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            _send(ctx, _wire_del_all(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "delete settle")
        ctx.run_clean()
