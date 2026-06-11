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
