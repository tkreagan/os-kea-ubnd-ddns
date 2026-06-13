# SPDX-License-Identifier: BSD-2-Clause
"""
Unit tests for kea-sync.py's _collect_writes() -- the pure conflict-resolution
and dedup core. Runs on macOS with no dev box, no Kea, no unbound-control: we
feed synthetic record lists and assert on the computed (to_add, to_remove,
won_keys) without touching the network or Unbound.

Loads the lib with a stubbed kea_transport (the relative import the real module
does on the box), then loads kea-sync.py by path.

Run:  python3 -m pytest tools/test_kea_sync_collect.py -v
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import types

_ROOT = pathlib.Path(__file__).parents[1]
_LIB = _ROOT / "src/opnsense/scripts/keaunbound/lib/keaunbound_sync.py"
_SYNC = _ROOT / "src/opnsense/scripts/keaunbound/kea-sync.py"

# Stub the transport layer the lib imports relatively (from .kea_transport ...).
_pkg = types.ModuleType("lib")
_pkg.__path__ = []  # mark as package
_kt = types.ModuleType("lib.kea_transport")
_kt.KeaUnavailableError = type("KeaUnavailableError", (Exception,), {})
_kt.KeaServiceUnavailableError = type("KeaServiceUnavailableError", (Exception,), {})
_kt.kea_query = lambda *a, **k: {}
sys.modules["lib"] = _pkg
sys.modules["lib.kea_transport"] = _kt

_lib_spec = importlib.util.spec_from_file_location("lib.keaunbound_sync", _LIB)
_lib = importlib.util.module_from_spec(_lib_spec)
sys.modules["lib.keaunbound_sync"] = _lib
_lib_spec.loader.exec_module(_lib)

# kea-sync.py inserts the scripts dir on sys.path and does `from lib.keaunbound_sync
# import ...`. Our stub above already satisfies that, so load it by path.
_sync_spec = importlib.util.spec_from_file_location("kea_sync", _SYNC)
kea_sync = importlib.util.module_from_spec(_sync_spec)
sys.modules["kea_sync"] = kea_sync
_sync_spec.loader.exec_module(kea_sync)

_collect_writes = kea_sync._collect_writes


# ── helpers ──────────────────────────────────────────────────────────────────
def rec(host, ip, rtype="A", ttl=None):
    return (host, ip, rtype, ttl)


def collect(records, rtype="A", policy="last_wins", synth=False,
            unbound_fwd=None, prior=None, host_entries=None):
    return _collect_writes(
        records, rtype, host_entries or {}, policy, synth,
        unbound_fwd or {}, prior or set(), _NullLogger(),
    )


class _NullLogger:
    def debug(self, *a, **k): pass
    def info(self, *a, **k): pass
    def warning(self, *a, **k): pass
    def error(self, *a, **k): pass


def adds_for(to_add):
    """Parse to_add lines into {name: set(ips)} for A/AAAA records only."""
    out = {}
    for line in to_add:
        parts = line.split()
        # "name [ttl] IN TYPE rdata"  -> TYPE is parts[-2], rdata parts[-1]
        if parts[-2] in ("A", "AAAA"):
            out.setdefault(parts[0], set()).add(parts[-1])
    return out


# ── the dedup bug: two leases, same FQDN, last_wins ──────────────────────────
def test_last_wins_dedups_to_single_record():
    # Sorted ascending by cltt already (caller does that): .50 then .51.
    records = [rec("host.x", "192.168.1.50"), rec("host.x", "192.168.1.51")]
    to_add, to_remove, won, n_add, n_skip = collect(records, policy="last_wins")
    a = adds_for(to_add)
    assert a == {"host.x": {"192.168.1.51"}}   # only the highest-cltt winner
    assert n_add == 1
    assert won == {"host.x"}


def test_first_wins_dedups_to_single_record():
    records = [rec("host.x", "192.168.1.50"), rec("host.x", "192.168.1.51")]
    to_add, to_remove, won, n_add, n_skip = collect(records, policy="first_wins")
    a = adds_for(to_add)
    assert a == {"host.x": {"192.168.1.50"}}   # earliest-seen (lowest cltt) wins
    assert n_add == 1


def test_allow_keeps_all_records_no_dedup():
    records = [rec("host.x", "192.168.1.50"), rec("host.x", "192.168.1.51")]
    to_add, to_remove, won, n_add, n_skip = collect(records, policy="allow")
    a = adds_for(to_add)
    assert a == {"host.x": {"192.168.1.50", "192.168.1.51"}}
    assert to_remove == []
    assert won == set()                        # allow never blocks leases


# ── snapshot replacement ──────────────────────────────────────────────────────
def test_replaces_differing_snapshot_record():
    # Unbound already has a stale .99; the winner is .50.
    records = [rec("host.x", "192.168.1.50")]
    to_add, to_remove, won, _, _ = collect(
        records, policy="last_wins", unbound_fwd={"host.x": {"192.168.1.99"}})
    assert "host.x" in to_remove                # remove the stale before add
    assert adds_for(to_add) == {"host.x": {"192.168.1.50"}}


def test_idempotent_when_snapshot_already_correct():
    records = [rec("host.x", "192.168.1.50")]
    to_add, to_remove, won, _, _ = collect(
        records, policy="last_wins", unbound_fwd={"host.x": {"192.168.1.50"}})
    assert to_remove == []                      # nothing to replace
    assert adds_for(to_add) == {"host.x": {"192.168.1.50"}}  # re-add is idempotent


# ── reservations beat leases, family-scoped ──────────────────────────────────
def test_prior_claim_blocks_same_family_lease():
    records = [rec("host.x", "192.168.1.50")]
    _, _, _, n_add, n_skip = collect(
        records, rtype="A", policy="last_wins", prior={"host.x"})
    assert n_add == 0 and n_skip == 1           # reservation beats the lease


def test_prior_claim_is_family_scoped():
    # A v4 reservation claim must NOT block a v6 lease for the same host. The
    # dynamic pass calls _collect_writes per family with that family's claim set;
    # the AAAA pass receives an empty prior set even though A is claimed.
    records = [rec("host.x", "fd00::50", rtype="AAAA")]
    _, _, _, n_add, n_skip = collect(
        records, rtype="AAAA", policy="last_wins", prior=set())
    assert n_add == 1                           # v6 lease published despite v4 res


# ── guards ────────────────────────────────────────────────────────────────────
def test_host_entries_guard_skips_forward():
    records = [rec("static.x", "192.168.1.10")]
    _, _, _, n_add, n_skip = collect(
        records, policy="last_wins", host_entries={"static.x": ["..."]})
    assert n_add == 0 and n_skip == 1


def test_insane_name_skipped():
    records = [rec("localhost", "192.168.1.10")]
    _, _, _, n_add, n_skip = collect(records, policy="last_wins")
    assert n_add == 0 and n_skip == 1


# ── PTR synthesis uses IP-keyed host_entries guard ───────────────────────────
def test_ptr_emitted_and_ip_guarded():
    records = [rec("host.x", "192.168.1.50")]
    # PTR for .50 should be emitted...
    to_add, _, _, _, _ = collect(records, policy="last_wins", synth=True)
    assert any("IN PTR host.x." in line for line in to_add)
    # ...but suppressed when the IP is in host_entries (OPNsense owns the PTR).
    to_add2, _, _, _, _ = collect(
        records, policy="last_wins", synth=True,
        host_entries={"192.168.1.50": ["..."]})
    assert not any("IN PTR" in line for line in to_add2)


# ── private helper aliases ────────────────────────────────────────────────────
# These expose keaunbound_sync internals for direct unit testing without going
# through the full sync pipeline.
import ipaddress as _ia

_normalize_raw_lease = _lib._normalize_raw_lease
_build_suffix_map = _lib._build_suffix_map
find_stale_records = _lib.find_stale_records
_arpa_to_ip = _lib._arpa_to_ip


# ── _arpa_to_ip round-trip ────────────────────────────────────────────────────

def test_arpa_to_ip_ipv4_basic():
    assert _arpa_to_ip("1.1.168.192.in-addr.arpa") == "192.168.1.1"


def test_arpa_to_ip_ipv4_trailing_dot():
    assert _arpa_to_ip("1.1.168.192.in-addr.arpa.") == "192.168.1.1"


def test_arpa_to_ip_ipv6_loopback():
    ptr = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
    assert _arpa_to_ip(ptr) == "::1"


def test_arpa_to_ip_ipv6_ula_roundtrip():
    ip = "fd00::1ab"
    ptr = _ia.ip_address(ip).reverse_pointer
    assert _arpa_to_ip(ptr) == ip


def test_arpa_to_ip_ipv6_full_address():
    # Verify a non-trivial address with many non-zero nibbles.
    ip = "2001:db8::1"
    ptr = _ia.ip_address(ip).reverse_pointer
    assert _arpa_to_ip(ptr) == ip


def test_arpa_to_ip_invalid_returns_empty():
    assert _arpa_to_ip("not.a.ptr.name") == ""
    assert _arpa_to_ip("1.2.3.in-addr.arpa") == ""   # only 3 octets
    assert _arpa_to_ip("") == ""


# ── _normalize_raw_lease: DHCPv6 lease-type filtering ────────────────────────

_NOW = 1_700_000_000  # fixed epoch well before any expiry used in tests


def _v6_lease(**overrides):
    """Minimal valid DHCPv6 IA_NA lease, suitable for _normalize_raw_lease."""
    base = {
        "state": 0,
        "type": 0,              # IA_NA — the only type that belongs in DNS
        "subnet-id": 1,
        "ip-address": "fd00::1",
        "hostname": "host.example.com",
        "valid-lft": 3600,
        "expire": _NOW + 3600,
    }
    base.update(overrides)
    return base


def test_normalize_ia_na_passes():
    result = _normalize_raw_lease(
        _v6_lease(), is_v4=False,
        suffix_by_subnet={1: "example.com"}, default_suffix="example.com",
        now=_NOW)
    assert result is not None
    assert result["ipv6"] == "fd00::1"
    assert result["hostname"] == "host.example.com"


def test_normalize_ia_ta_blocked():
    # IA_TA (type=1) — temporary address, not stable enough for DNS
    result = _normalize_raw_lease(
        _v6_lease(type=1), is_v4=False,
        suffix_by_subnet={}, default_suffix="example.com",
        now=_NOW)
    assert result is None


def test_normalize_ia_pd_blocked():
    # IA_PD (type=2) — delegated prefix, ip-address is a network, not a host
    result = _normalize_raw_lease(
        _v6_lease(type=2, **{"ip-address": "fd01::"}), is_v4=False,
        suffix_by_subnet={}, default_suffix="example.com",
        now=_NOW)
    assert result is None


# ── _normalize_raw_lease: ddns-send-updates subnet filtering ─────────────────

def test_normalize_ddns_disabled_subnet_blocked():
    # Subnet 1 is in the disabled set — lease must be skipped
    result = _normalize_raw_lease(
        _v6_lease(), is_v4=False,
        suffix_by_subnet={1: "example.com"}, default_suffix="example.com",
        now=_NOW, ddns_disabled_subnets={1})
    assert result is None


def test_normalize_ddns_enabled_subnet_not_blocked():
    # Subnet 2 is NOT in the disabled set — lease must pass through
    result = _normalize_raw_lease(
        _v6_lease(**{"subnet-id": 2}), is_v4=False,
        suffix_by_subnet={1: "example.com", 2: "example.com"},
        default_suffix="example.com",
        now=_NOW, ddns_disabled_subnets={1})
    assert result is not None


# ── _build_suffix_map: ddns-send-updates inheritance ─────────────────────────

def test_build_suffix_map_global_disabled():
    dhcp_config = {
        "ddns-send-updates": False,
        "subnet6": [{"id": 1, "subnet": "fd00::/64"}],
    }
    _, _, disabled = _build_suffix_map("dhcp6", dhcp_config)
    assert 1 in disabled


def test_build_suffix_map_global_enabled_subnet_not_disabled():
    dhcp_config = {
        "ddns-send-updates": True,
        "subnet6": [{"id": 1, "subnet": "fd00::/64"}],
    }
    _, _, disabled = _build_suffix_map("dhcp6", dhcp_config)
    assert 1 not in disabled


def test_build_suffix_map_subnet_overrides_global_false():
    # Global says false, subnet explicitly says true — subnet wins.
    dhcp_config = {
        "ddns-send-updates": False,
        "subnet6": [{"id": 1, "subnet": "fd00::/64", "ddns-send-updates": True}],
    }
    _, _, disabled = _build_suffix_map("dhcp6", dhcp_config)
    assert 1 not in disabled


def test_build_suffix_map_subnet_overrides_global_true_to_false():
    # Global says true, subnet explicitly says false — subnet wins.
    dhcp_config = {
        "ddns-send-updates": True,
        "subnet6": [{"id": 1, "subnet": "fd00::/64", "ddns-send-updates": False}],
    }
    _, _, disabled = _build_suffix_map("dhcp6", dhcp_config)
    assert 1 in disabled


def test_build_suffix_map_shared_network_inherits_false():
    # Shared-network says false; child subnet has no override — inherits disabled.
    dhcp_config = {
        "ddns-send-updates": True,          # global is true
        "shared-networks": [
            {
                "name": "net1",
                "ddns-send-updates": False,  # net overrides to false
                "subnet6": [{"id": 2, "subnet": "fd00::/64"}],  # no override
            }
        ],
        "subnet6": [],
    }
    _, _, disabled = _build_suffix_map("dhcp6", dhcp_config)
    assert 2 in disabled


def test_build_suffix_map_shared_network_subnet_overrides_back():
    # Shared-network says false; child subnet overrides back to true.
    dhcp_config = {
        "ddns-send-updates": True,
        "shared-networks": [
            {
                "name": "net1",
                "ddns-send-updates": False,
                "subnet6": [{"id": 3, "subnet": "fd00:1::/64",
                             "ddns-send-updates": True}],
            }
        ],
        "subnet6": [],
    }
    _, _, disabled = _build_suffix_map("dhcp6", dhcp_config)
    assert 3 not in disabled


# ── find_stale_records: dual-stack / per-IP staleness ────────────────────────

def _fwd_line(name, ip, rtype, ttl=120):
    return f"{name} {ttl} IN {rtype} {ip}"


def _ptr_line(ptr_name, target, ttl=120):
    return f"{ptr_name} {ttl} IN PTR {target}."


def _v6_ptr(ip):
    return _ia.ip_address(ip).reverse_pointer


def test_find_stale_records_stale_aaaa_valid_a():
    """
    Dual-stack host: A is in Kea, AAAA is not.
    Only the (name, ipv6) pair should be stale.
    The valid A's PTR is preserved; the stale AAAA's PTR is orphaned.
    """
    host = "host.example.com"
    ipv4 = "192.168.1.50"
    ipv6_stale = "fd00::50"
    ipv4_ptr = _ia.ip_address(ipv4).reverse_pointer
    ipv6_ptr = _v6_ptr(ipv6_stale)

    unbound_data = {
        host: [_fwd_line(host, ipv4, "A"), _fwd_line(host, ipv6_stale, "AAAA")],
        ipv4_ptr: [_ptr_line(ipv4_ptr, host)],
        ipv6_ptr: [_ptr_line(ipv6_ptr, host)],
    }
    kea_pairs = {(host, ipv4)}  # only the A is backed by Kea

    stale_pairs, orphaned_ptrs = find_stale_records(unbound_data, kea_pairs, {})

    assert (host, ipv6_stale) in stale_pairs, "stale AAAA must be flagged"
    assert (host, ipv4) not in stale_pairs, "valid A must not be flagged"
    assert len(stale_pairs) == 1

    assert ipv6_ptr in orphaned_ptrs, "PTR for stale AAAA must be orphaned"
    assert ipv4_ptr not in orphaned_ptrs, "PTR for valid A must be preserved"


def test_find_stale_records_stale_a_valid_aaaa():
    """Mirror case: A is stale, AAAA is valid."""
    host = "host.example.com"
    ipv4_stale = "192.168.1.51"
    ipv6 = "fd00::51"
    ipv4_ptr = _ia.ip_address(ipv4_stale).reverse_pointer
    ipv6_ptr = _v6_ptr(ipv6)

    unbound_data = {
        host: [_fwd_line(host, ipv4_stale, "A"), _fwd_line(host, ipv6, "AAAA")],
        ipv4_ptr: [_ptr_line(ipv4_ptr, host)],
        ipv6_ptr: [_ptr_line(ipv6_ptr, host)],
    }
    kea_pairs = {(host, ipv6)}

    stale_pairs, orphaned_ptrs = find_stale_records(unbound_data, kea_pairs, {})

    assert (host, ipv4_stale) in stale_pairs
    assert (host, ipv6) not in stale_pairs
    assert ipv4_ptr in orphaned_ptrs
    assert ipv6_ptr not in orphaned_ptrs


def test_find_stale_records_fully_stale_dual_stack():
    """Both A and AAAA are stale — both pairs and both PTRs flagged."""
    host = "host.example.com"
    ipv4 = "192.168.1.52"
    ipv6 = "fd00::52"
    ipv4_ptr = _ia.ip_address(ipv4).reverse_pointer
    ipv6_ptr = _v6_ptr(ipv6)

    unbound_data = {
        host: [_fwd_line(host, ipv4, "A"), _fwd_line(host, ipv6, "AAAA")],
        ipv4_ptr: [_ptr_line(ipv4_ptr, host)],
        ipv6_ptr: [_ptr_line(ipv6_ptr, host)],
    }
    kea_pairs = set()

    stale_pairs, orphaned_ptrs = find_stale_records(unbound_data, kea_pairs, {})

    assert stale_pairs == {(host, ipv4), (host, ipv6)}
    assert orphaned_ptrs == {ipv4_ptr, ipv6_ptr}


def test_find_stale_records_host_entries_guard_dual_stack():
    """OPNsense-managed names are never considered stale regardless of family."""
    host = "static.example.com"
    ipv4 = "192.168.1.10"
    ipv6 = "fd00::10"

    unbound_data = {host: [_fwd_line(host, ipv4, "A"), _fwd_line(host, ipv6, "AAAA")]}
    kea_pairs = set()                           # nothing in Kea
    host_entries = {host: ["..."]}              # OPNsense owns this name

    stale_pairs, _ = find_stale_records(unbound_data, kea_pairs, host_entries)
    assert len(stale_pairs) == 0


def test_find_stale_records_single_ip_name():
    """Single-family host: only A, stale. Verify stale_pairs and orphaned PTR."""
    host = "old.example.com"
    ip = "192.168.1.99"
    ptr = _ia.ip_address(ip).reverse_pointer

    unbound_data = {
        host: [_fwd_line(host, ip, "A")],
        ptr: [_ptr_line(ptr, host)],
    }
    kea_pairs = set()

    stale_pairs, orphaned_ptrs = find_stale_records(unbound_data, kea_pairs, {})
    assert stale_pairs == {(host, ip)}
    assert ptr in orphaned_ptrs
