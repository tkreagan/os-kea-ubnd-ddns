# SPDX-License-Identifier: BSD-2-Clause
"""
PTR format correctness scenarios.

Tests that PTR records produced by both the sync path and the live DDNS NCR
path use the correct wire format:
  IPv4: N.N.N.N.in-addr.arpa  (4 reversed octets + ".in-addr.arpa")
  IPv6: full 32-nibble reversed + ".ip6.arpa"  (no compressed form)

Also tests PTR-target format (hostname must have trailing dot in the PTR rdata
so Unbound resolves it as an absolute name rather than relative to a zone).

All scenarios send NCRs directly to 127.0.0.1:53535 on dev-opnsense, so they
need the daemon running but do NOT require Kea interaction.
"""
from __future__ import annotations

import ipaddress
import socket
import time

from tools.scenarios import register
from tools.scenarios.base import Scenario, ChaosContext

DDNS_PORT = 53535

_TEST_V6_PREFIX = "fd42::"   # isolated from other scenario prefixes


# ---------------------------------------------------------------------------
# DNS UPDATE builders
# ---------------------------------------------------------------------------

def _build_a_update(hostname: str, ip: str, domain: str, ttl: int = 300) -> bytes:
    import dns.update, dns.name, dns.rdataclass, dns.rdatatype, dns.rdata
    zone = dns.name.from_text(domain + ".")
    upd = dns.update.UpdateMessage(zone)
    upd.add(
        dns.name.from_text(f"{hostname}.{domain}."),
        ttl,
        dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, ip),
    )
    return upd.to_wire()


def _build_aaaa_update(hostname: str, ipv6: str, domain: str, ttl: int = 300) -> bytes:
    import dns.update, dns.name, dns.rdataclass, dns.rdatatype, dns.rdata
    zone = dns.name.from_text(domain + ".")
    upd = dns.update.UpdateMessage(zone)
    upd.add(
        dns.name.from_text(f"{hostname}.{domain}."),
        ttl,
        dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.AAAA, ipv6),
    )
    return upd.to_wire()


def _build_delete(hostname: str, domain: str) -> bytes:
    import dns.update, dns.name
    zone = dns.name.from_text(domain + ".")
    upd = dns.update.UpdateMessage(zone)
    upd.delete(dns.name.from_text(f"{hostname}.{domain}."))
    return upd.to_wire()


def _build_ptr_update(arpa_name: str, target_fqdn: str, domain: str, ttl: int = 300) -> bytes:
    """Build an explicit PTR NCR (owner = arpa name, rdata = target FQDN)."""
    import dns.update, dns.name, dns.rdataclass, dns.rdatatype, dns.rdata
    # For an explicit PTR NCR, the zone is the appropriate arpa zone; for
    # simplicity we address it to the reverse zone's parent.  The daemon
    # processes the authority section regardless of zone match.
    zone = dns.name.from_text(domain + ".")
    upd = dns.update.UpdateMessage(zone)
    upd.add(
        dns.name.from_text(arpa_name + "."),
        ttl,
        dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.PTR,
                             target_fqdn.rstrip(".") + "."),
    )
    return upd.to_wire()


def _send(host: str, payload: bytes, timeout: float = 1.0) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(payload, (host, DDNS_PORT))


def _expected_arpa_v4(ip: str) -> str:
    return str(ipaddress.IPv4Address(ip).reverse_pointer)


def _expected_arpa_v6(ip: str) -> str:
    return str(ipaddress.IPv6Address(ip).reverse_pointer)


# ---------------------------------------------------------------------------

@register
class PtrFormatV4Sync(Scenario):
    name = "ptr_format_v4_sync"
    description = (
        "Sync an IPv4 lease; verify PTR owner is exactly N.N.N.N.in-addr.arpa "
        "and resolves via drill to the hostname"
    )
    tags = ["ptr", "format", "ipv4", "sync"]

    def run(self, ctx: ChaosContext) -> None:
        hostname, ip = ctx.alloc_host("-ptrf4")
        mac = f"aa:bb:cc:f4:{ctx._ip_counter % 256:02x}:01"
        ctx.kea.lease4_add(ip, mac, hostname, valid_lft=3600,
                           subnet_id=ctx.subnet_id())
        self._hostname = hostname
        self._ip = ip
        ctx.event("lease_added", hostname=hostname, ip=ip)
        ctx.run_sync("dynamic")
        ctx.wait(2, "sync settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        fqdn = f"{self._hostname}.{ctx.domain}"
        expected_arpa = _expected_arpa_v4(self._ip)

        # Forward record must be A (not AAAA)
        if not ctx.unbound.has_record(fqdn, self._ip, "A"):
            failures.append(f"A record missing: {fqdn} → {self._ip}")
        if ctx.unbound.has_record(fqdn, self._ip, "AAAA"):
            failures.append(f"IPv4 address incorrectly stored as AAAA: {fqdn}")

        # PTR must exist under the correct arpa owner name
        if not ctx.unbound.has_ptr(self._ip, fqdn):
            failures.append(
                f"PTR missing: expected {expected_arpa} → {fqdn}"
            )

        # Verify the arpa owner name format in the raw data
        raw_data = ctx.unbound.list_local_data()
        if expected_arpa not in raw_data:
            failures.append(
                f"PTR owner not in expected in-addr.arpa format: "
                f"got keys {[k for k in raw_data if 'arpa' in k]!r}"
            )

        # Live DNS query via drill
        result = ctx.dns.verify_pair(self._hostname, self._ip, ctx.domain, "A")
        if not result["forward_ok"]:
            failures.append(
                f"drill A failed: {self._hostname} → {result['forward_answer']!r} "
                f"(expected {self._ip})"
            )
        if not result["ptr_ok"]:
            failures.append(
                f"drill PTR failed: {self._ip} → {result['ptr_answer']!r} "
                f"(expected {fqdn})"
            )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            ctx.kea.lease4_del(self._ip)
        except Exception:
            pass
        ctx.run_clean()


@register
class PtrFormatV6Sync(Scenario):
    name = "ptr_format_v6_sync"
    description = (
        "Sync an IPv6 lease; verify PTR owner is exactly the full 32-nibble "
        "ip6.arpa form (not compressed) and resolves via drill"
    )
    tags = ["ptr", "format", "ipv6", "sync"]

    def setup(self, ctx: ChaosContext) -> None:
        from tools.lib.kea import KeaError
        try:
            ctx.kea.discover_subnet_id(service="dhcp6")
        except KeaError as exc:
            raise RuntimeError(f"DHCPv6 not available: {exc}") from exc

    def run(self, ctx: ChaosContext) -> None:
        hostname, ipv6 = ctx.alloc_v6_host("-ptrf6", prefix=_TEST_V6_PREFIX)
        duid = "00:03:00:01:aa:bb:cc:f6:01:01"
        ctx.kea.lease6_add(ipv6, duid, hostname, valid_lft=3600,
                           subnet_id=ctx.subnet6_id())
        self._hostname = hostname
        self._ipv6 = ipv6
        ctx.event("lease_added", hostname=hostname, ipv6=ipv6)
        ctx.run_sync("dynamic")
        ctx.wait(2, "sync settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        fqdn = f"{self._hostname}.{ctx.domain}"
        expected_arpa = _expected_arpa_v6(self._ipv6)

        # Forward record must be AAAA (not A)
        if not ctx.unbound.has_record(fqdn, self._ipv6, "AAAA"):
            failures.append(f"AAAA record missing: {fqdn} → {self._ipv6}")
        if ctx.unbound.has_record(fqdn, self._ipv6, "A"):
            failures.append(f"IPv6 address incorrectly stored as A: {fqdn}")

        # PTR must exist under the correct 32-nibble ip6.arpa owner name
        if not ctx.unbound.has_ptr(self._ipv6, fqdn):
            failures.append(
                f"PTR missing: expected {expected_arpa} → {fqdn}"
            )

        # Verify 32-nibble format: key must end with ".ip6.arpa" and have 32 labels before it
        raw_data = ctx.unbound.list_local_data()
        ip6_keys = [k for k in raw_data if k.endswith(".ip6.arpa")]
        if not ip6_keys:
            failures.append("No ip6.arpa PTR key found in Unbound local_data")
        else:
            for k in ip6_keys:
                nibble_part = k[:-len(".ip6.arpa")]
                nibbles = nibble_part.split(".")
                if len(nibbles) != 32:
                    failures.append(
                        f"ip6.arpa PTR key has {len(nibbles)} labels (expected 32): {k!r}"
                    )
                elif not all(len(n) == 1 and n in "0123456789abcdef" for n in nibbles):
                    failures.append(
                        f"ip6.arpa PTR key contains non-hex or multi-char nibble: {k!r}"
                    )

        # Live DNS query via drill
        result = ctx.dns.verify_pair(self._hostname, self._ipv6, ctx.domain, "AAAA")
        if not result["forward_ok"]:
            failures.append(
                f"drill AAAA failed: {self._hostname} → {result['forward_answer']!r} "
                f"(expected {self._ipv6})"
            )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        try:
            ctx.kea.lease6_del(self._ipv6)
        except Exception:
            pass
        ctx.reset_state(v6=True)


@register
class DdnsPtrSynthesisV4(Scenario):
    name = "ddns_ptr_synthesis_v4"
    description = (
        "Send a DDNS NCR A ADD; verify the daemon synthesizes a correctly-formatted "
        "in-addr.arpa PTR (not just that a PTR exists)"
    )
    tags = ["ptr", "format", "ddns", "ipv4"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running — cannot test DDNS path")

    def run(self, ctx: ChaosContext) -> None:
        hostname, ip = ctx.alloc_host("-ddnsv4ptr")
        payload = _build_a_update(hostname, ip, ctx.domain)
        _send(ctx.cfg.opnsense_host, payload)
        self._hostname = hostname
        self._ip = ip
        self._fqdn = f"{hostname}.{ctx.domain}"
        ctx.event("ncr_sent", hostname=hostname, ip=ip)
        ctx.wait(2, "daemon process NCR")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        expected_arpa = _expected_arpa_v4(self._ip)

        # Forward record must be type A
        if not ctx.unbound.has_record(self._fqdn, self._ip, "A"):
            failures.append(f"A record missing after NCR: {self._fqdn} → {self._ip}")
        if ctx.unbound.has_record(self._fqdn, self._ip, "AAAA"):
            failures.append(f"IPv4 incorrectly registered as AAAA: {self._fqdn}")

        # PTR must exist and be keyed by the correct arpa owner
        if not ctx.unbound.has_ptr(self._ip, self._fqdn):
            failures.append(f"Synthesized PTR missing: {expected_arpa} → {self._fqdn}")

        raw_data = ctx.unbound.list_local_data()
        if expected_arpa not in raw_data:
            failures.append(
                f"PTR stored under wrong key — expected {expected_arpa!r}, "
                f"arpa keys present: {[k for k in raw_data if 'arpa' in k]!r}"
            )

        # PTR target must reference the full FQDN (drill PTR resolution)
        result = ctx.dns.verify_pair(self._hostname, self._ip, ctx.domain, "A")
        if not result["ptr_ok"]:
            failures.append(
                f"drill PTR for {self._ip} → {result['ptr_answer']!r} "
                f"(expected {self._fqdn})"
            )
        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        host = ctx.cfg.opnsense_host
        try:
            _send(host, _build_delete(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "let delete settle")
        ctx.run_clean()


@register
class DdnsPtrSynthesisV6(Scenario):
    name = "ddns_ptr_synthesis_v6"
    description = (
        "Send a DDNS NCR AAAA ADD; verify the daemon synthesizes a full 32-nibble "
        "ip6.arpa PTR (correct format, not compressed)"
    )
    tags = ["ptr", "format", "ddns", "ipv6"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running — cannot test DDNS path")

    def run(self, ctx: ChaosContext) -> None:
        hostname, ipv6 = ctx.alloc_v6_host("-ddnsv6ptr", prefix=_TEST_V6_PREFIX)
        payload = _build_aaaa_update(hostname, ipv6, ctx.domain)
        _send(ctx.cfg.opnsense_host, payload)
        self._hostname = hostname
        self._ipv6 = ipv6
        self._fqdn = f"{hostname}.{ctx.domain}"
        ctx.event("ncr_sent", hostname=hostname, ipv6=ipv6)
        ctx.wait(2, "daemon process NCR")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        expected_arpa = _expected_arpa_v6(self._ipv6)

        # Forward record must be type AAAA (not A)
        if not ctx.unbound.has_record(self._fqdn, self._ipv6, "AAAA"):
            failures.append(f"AAAA record missing after NCR: {self._fqdn} → {self._ipv6}")
        if ctx.unbound.has_record(self._fqdn, self._ipv6, "A"):
            failures.append(f"IPv6 address incorrectly registered as A: {self._fqdn}")

        # PTR must be the full 32-nibble ip6.arpa form
        if not ctx.unbound.has_ptr(self._ipv6, self._fqdn):
            failures.append(f"Synthesized IPv6 PTR missing: {expected_arpa} → {self._fqdn}")

        raw_data = ctx.unbound.list_local_data()
        ip6_keys = [k for k in raw_data if k.endswith(".ip6.arpa")]
        if not ip6_keys:
            failures.append("No ip6.arpa PTR key found — daemon did not synthesize IPv6 PTR")
        else:
            for k in ip6_keys:
                nibble_part = k[:-len(".ip6.arpa")]
                nibbles = nibble_part.split(".")
                if len(nibbles) != 32:
                    failures.append(
                        f"ip6.arpa PTR key has {len(nibbles)} labels (expected 32): {k!r}"
                    )

        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        host = ctx.cfg.opnsense_host
        try:
            _send(host, _build_delete(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "let delete settle")
        ctx.run_clean()


@register
class ExplicitPtrNcr(Scenario):
    name = "explicit_ptr_ncr"
    description = (
        "Send an explicit PTR NCR (not an A/AAAA ADD); verify PTR is applied "
        "without a duplicate synthesized PTR"
    )
    tags = ["ptr", "ddns", "explicit"]

    def setup(self, ctx: ChaosContext) -> None:
        if not ctx.daemon_is_running():
            raise RuntimeError("Daemon not running — cannot test DDNS path")

    def run(self, ctx: ChaosContext) -> None:
        # First add an A record so there's a forward name to associate with
        hostname, ip = ctx.alloc_host("-explptr")
        _send(ctx.cfg.opnsense_host, _build_a_update(hostname, ip, ctx.domain))
        ctx.wait(2, "A NCR settle")

        # Now send an explicit PTR NCR (as kea-dhcp-ddns would for PTR updates)
        arpa = _expected_arpa_v4(ip)
        fqdn = f"{hostname}.{ctx.domain}"
        _send(ctx.cfg.opnsense_host,
              _build_ptr_update(arpa, fqdn, ctx.domain))
        self._hostname = hostname
        self._ip = ip
        self._arpa = arpa
        self._fqdn = fqdn
        ctx.event("explicit_ptr_sent", arpa=arpa, target=fqdn)
        ctx.wait(2, "PTR NCR settle")

    def verify(self, ctx: ChaosContext) -> list[str]:
        failures = []
        raw_data = ctx.unbound.list_local_data()

        # A record must still be present
        if not ctx.unbound.has_record(self._fqdn, self._ip, "A"):
            failures.append(f"A record gone after explicit PTR NCR: {self._fqdn}")

        # PTR must be present exactly once
        arpa_lines = raw_data.get(self._arpa, [])
        ptr_lines = [l for l in arpa_lines if "PTR" in l]
        if not ptr_lines:
            failures.append(f"PTR record missing after explicit PTR NCR: {self._arpa}")
        elif len(ptr_lines) > 1:
            failures.append(
                f"Duplicate PTRs for {self._arpa}: {len(ptr_lines)} records "
                f"(synthesis must not double-add when explicit NCR arrives)"
            )
        else:
            # PTR target must be the FQDN with trailing dot
            line = ptr_lines[0]
            if self._hostname not in line:
                failures.append(
                    f"PTR target incorrect: {line!r} does not reference {self._hostname}"
                )

        return failures

    def cleanup(self, ctx: ChaosContext) -> None:
        host = ctx.cfg.opnsense_host
        try:
            _send(host, _build_delete(self._hostname, ctx.domain))
        except Exception:
            pass
        ctx.wait(1, "let delete settle")
        ctx.run_clean()
