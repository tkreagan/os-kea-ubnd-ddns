# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit tests for kea-sync.py — focused on _collect_writes PTR behaviour.

_collect_writes is a module-level function in the kea-sync script; loaded via
the load_script() helper so the hyphenated filename is not an obstacle.
"""

from __future__ import annotations

import logging
import unittest.mock as mock

import pytest

from .conftest import load_script
from lib.kea_transport import KeaServiceUnavailableError, KeaUnavailableError

pytestmark = pytest.mark.unit

kea_sync = load_script("kea-sync.py")

_log = logging.getLogger("test-kea-sync")
_log.addHandler(logging.NullHandler())


def _collect(records, rtype="A", policy="last_wins", synthesize_ptr=True,
             unbound_fwd=None, prior_claim_keys=None, host_entries=None,
             magic_fqdns=None, write_magic_ptrs=False):
    """Thin wrapper around _collect_writes with sane defaults for unit tests."""
    return kea_sync._collect_writes(
        records=records,
        rtype=rtype,
        host_entries=host_entries or {},
        policy=policy,
        synthesize_ptr=synthesize_ptr,
        unbound_fwd=unbound_fwd or {},
        prior_claim_keys=prior_claim_keys or set(),
        logger=_log,
        magic_fqdns=magic_fqdns,
        write_magic_ptrs=write_magic_ptrs,
    )


# ── normalize_hostname ────────────────────────────────────────────────────────
# is_sane_name was removed from the daemon; validation now lives here.

@pytest.mark.parametrize("name,expect_none", [
    ("myhost.lan",              False),
    ("foo.bar.baz",             False),
    ("host-with-dash.lan",      False),
    ("a.b",                     False),
    ("x1.lan",                  False),
    # first-label all-digit is a DHCP artifact — rejected
    ("123host.lan",             False),   # mixed ok
    ("1abc.lan",                False),   # mixed ok
    # reserved / nonsense
    ("",                        True),
    (".",                       True),
    ("localhost",               True),
    ("localdomain",             True),
    # all-numeric (IP addresses passed as names)
    ("192.168.1.1",             True),
    ("10.0.0.1",                True),
    ("1.2.3.4",                 True),
    # invalid first label
    ("-bad.lan",                True),
    ("_foo.lan",                True),
    # invalid chars in non-first labels
    ("valid.evil!label.lan",    True),
    ("valid._svc.lan",          True),
    ("valid.bad-.lan",          True),
    ("valid.-bad.lan",          True),
])
def test_normalize_hostname(name, expect_none):
    result = kea_sync.normalize_hostname(name)
    if expect_none:
        assert result is None, f"expected None for {name!r}, got {result!r}"
    else:
        assert result is not None, f"expected valid result for {name!r}, got None"
        assert result == result.lower(), "result must be lowercased"


# ── PTR pre-remove in to_remove ───────────────────────────────────────────────

def test_collect_writes_ptr_in_to_remove_last_wins():
    """_collect_writes always puts the arpa name in to_remove before to_add
    so _execute_writes clears any stale PTR target before writing the new one."""
    records = [("host.lan", "192.168.1.10", "A", 300)]
    to_add, to_remove, *_ = _collect(records, policy="last_wins")

    ptr = "10.1.168.192.in-addr.arpa"
    assert ptr in to_remove, "arpa name must be in to_remove to evict stale targets"
    assert any(ptr in r for r in to_add), "PTR record must still be in to_add"


def test_collect_writes_ptr_in_to_remove_first_wins():
    records = [("host.lan", "192.168.1.10", "A", 300)]
    to_add, to_remove, *_ = _collect(records, policy="first_wins")
    ptr = "10.1.168.192.in-addr.arpa"
    assert ptr in to_remove
    assert any(ptr in r for r in to_add)


def test_collect_writes_ptr_in_to_remove_allow():
    records = [("host.lan", "192.168.1.10", "A", 300)]
    to_add, to_remove, *_ = _collect(records, policy="allow")
    ptr = "10.1.168.192.in-addr.arpa"
    assert ptr in to_remove
    assert any(ptr in r for r in to_add)


def test_collect_writes_ptr_not_in_to_remove_when_synthesize_off():
    """synthesize_ptr=False: no PTR entries in either to_remove or to_add."""
    records = [("host.lan", "192.168.1.10", "A", 300)]
    to_add, to_remove, *_ = _collect(records, synthesize_ptr=False)
    ptr = "10.1.168.192.in-addr.arpa"
    assert ptr not in to_remove
    assert not any(ptr in r for r in to_add)


def test_collect_writes_ptr_points_to_correct_hostname():
    """PTR record in to_add must point to the winner hostname, not a stale one."""
    records = [("newhost.lan", "192.168.1.20", "A", 300)]
    to_add, to_remove, *_ = _collect(records)
    ptr = "20.1.168.192.in-addr.arpa"
    assert any(ptr in r and "newhost.lan." in r for r in to_add), \
        "PTR record must target the correct hostname"


def test_collect_writes_ip_reassignment_old_ptr_removed():
    """IP reassigned to a new hostname: to_remove contains the arpa name so the
    stale PTR target from the old hostname is cleared before the new one is added.

    This is the core IP-reassignment gap: host1 had .10, host2 now gets .10.
    host2 has no existing Unbound record (unbound_fwd is empty for host2),
    so no forward collision is detected. Without the unconditional pre-remove,
    Unbound would accumulate host1's PTR target alongside host2's.
    """
    # host2.lan is getting 192.168.1.10; host1.lan previously held it but has
    # already been cleaned from Unbound's forward records (stale forward removed).
    # The PTR for .10 still points to host1.lan in Unbound — this is what we fix.
    records = [("host2.lan", "192.168.1.10", "A", 300)]
    to_add, to_remove, *_ = _collect(records, policy="last_wins", unbound_fwd={})
    ptr = "10.1.168.192.in-addr.arpa"
    assert ptr in to_remove, \
        "arpa name must be in to_remove even when host2 has no prior Unbound entry"


# ── sync_static / sync_full: disabled vs errored Kea service ─────────────────

def _minimal_sync_static_kwargs():
    return dict(
        host_entries={},
        policy="last_wins",
        synthesize_ptr=True,
        unbound_snapshot={},
        dry_run=False,
        logger=_log,
    )


def test_sync_static_skips_disabled_service():
    """KeaServiceUnavailableError (socket absent / rc=2) → service skipped, sync succeeds."""
    with mock.patch.object(kea_sync, "query_kea_reservations",
                           side_effect=KeaServiceUnavailableError("dhcp4 disabled")):
        # Should not raise; returns normally (0 records written)
        claims, _, _, errs, _ = kea_sync.sync_static(**_minimal_sync_static_kwargs())
    assert errs == 0


def test_sync_static_fails_on_reachable_daemon_error():
    """KeaUnavailableError (rc=1 from reachable daemon) propagates — sync must not succeed silently."""
    with mock.patch.object(kea_sync, "query_kea_reservations",
                           side_effect=KeaUnavailableError("config-get failed rc=1")):
        with pytest.raises(KeaUnavailableError):
            kea_sync.sync_static(**_minimal_sync_static_kwargs())


# ── _prune_departed_magic ─────────────────────────────────────────────────────
#
# State keys are full lowercased FQDNs after Finding 2 fix (e.g. "laptop.lan",
# not bare "laptop"). new_state is {fqdn_key: [entries]}; old_state is
# {"magic_names": {fqdn_key: [entries]}}.

def _mock_uc_capture(removed):
    def _uc(cmd):
        if cmd[0] == "local_data_remove":
            removed.append(cmd[1])
        return True
    return _uc


def test_prune_departed_magic_full_sync_removes_departed():
    """Full sync (restrict_keys=None) removes departed magic FQDNs."""
    removed = []
    old = {"magic_names": {
        "laptop.lan": [{"ip": "10.0.0.1", "magic_fqdn": "laptop-mAABBCC.lan."}],
        "phone.lan":  [{"ip": "10.0.0.2", "magic_fqdn": "phone-mDDEEFF.lan."}],
    }}
    # phone still present; laptop departed
    new = {"phone.lan": [{"ip": "10.0.0.2", "magic_fqdn": "phone-mDDEEFF.lan."}]}

    orig_uc = kea_sync.unbound_control
    kea_sync.unbound_control = _mock_uc_capture(removed)
    try:
        kea_sync._prune_departed_magic(old, new, None, False, _log)
    finally:
        kea_sync.unbound_control = orig_uc

    assert "laptop-mAABBCC.lan." in removed
    assert "phone-mDDEEFF.lan." not in removed


def test_prune_departed_magic_targeted_drain_skips_other_hosts():
    """Targeted drain must NOT touch other hosts' magic names."""
    removed = []
    old = {"magic_names": {
        "laptop.lan": [{"ip": "10.0.0.1", "magic_fqdn": "laptop-mAABBCC.lan."}],
        "phone.lan":  [{"ip": "10.0.0.2", "magic_fqdn": "phone-mDDEEFF.lan."}],
    }}
    new = {"laptop.lan": [{"ip": "10.0.0.1", "magic_fqdn": "laptop-mAABBCC.lan."}]}
    restrict = frozenset({"laptop.lan"})

    orig_uc = kea_sync.unbound_control
    kea_sync.unbound_control = _mock_uc_capture(removed)
    try:
        kea_sync._prune_departed_magic(old, new, restrict, False, _log)
    finally:
        kea_sync.unbound_control = orig_uc

    assert "phone-mDDEEFF.lan." not in removed
    assert "laptop-mAABBCC.lan." not in removed  # still present


def test_prune_departed_magic_targeted_drain_removes_departed_host():
    """Targeted drain removes magic names whose magic_fqdn left new_state."""
    removed = []
    old = {"magic_names": {
        "laptop.lan": [{"ip": "10.0.0.1", "magic_fqdn": "laptop-mAABBCC.lan."}],
        "phone.lan":  [{"ip": "10.0.0.2", "magic_fqdn": "phone-mDDEEFF.lan."}],
    }}
    new: dict = {}  # laptop resolved; phone not in drain scope
    restrict = frozenset({"laptop.lan"})

    orig_uc = kea_sync.unbound_control
    kea_sync.unbound_control = _mock_uc_capture(removed)
    try:
        kea_sync._prune_departed_magic(old, new, restrict, False, _log)
    finally:
        kea_sync.unbound_control = orig_uc

    assert "laptop-mAABBCC.lan." in removed
    assert "phone-mDDEEFF.lan." not in removed


def test_prune_departed_magic_ip_change_keeps_magic_fqdn():
    """Finding 3 regression: a magic FQDN whose IP changed must NOT be pruned.

    Before the fix, prune was keyed on IP departure: old_ip not in new_ips.
    A device that renews into a new IP while in a collision group would have
    its magic FQDN removed even though _execute_writes just re-added it at
    the new address. After the fix, prune keys on magic_fqdn survival.
    """
    removed = []
    old = {"magic_names": {
        "laptop.lan": [{"ip": "10.0.0.1", "magic_fqdn": "laptop-mAABBCC.lan."}],
    }}
    # Same magic FQDN, but new IP (10.0.0.3 instead of 10.0.0.1)
    new = {"laptop.lan": [{"ip": "10.0.0.3", "magic_fqdn": "laptop-mAABBCC.lan."}]}

    orig_uc = kea_sync.unbound_control
    kea_sync.unbound_control = _mock_uc_capture(removed)
    try:
        kea_sync._prune_departed_magic(old, new, None, False, _log)
    finally:
        kea_sync.unbound_control = orig_uc

    assert "laptop-mAABBCC.lan." not in removed, \
        "magic FQDN must survive when device renews into a new IP (Finding 3)"


# ── _magic_prepass — cross-domain isolation (Finding 2) ──────────────────────

def test_magic_prepass_cross_domain_no_collision():
    """Finding 2 regression: same bare label in different DDNS domains must NOT collide.

    'printer.floor1.lan' and 'printer.floor2.lan' share bare label 'printer'
    but are distinct FQDNs. The prepass must NOT group them; neither gets a
    magic name (each FQDN maps to exactly one IP).
    """
    records = [
        ("printer.floor1.lan", "192.168.1.10", "A", 300),
        ("printer.floor2.lan", "192.168.2.10", "A", 300),
    ]
    raw = [{"hw-address": "aa:bb:cc:dd:ee:01"},
           {"hw-address": "aa:bb:cc:dd:ee:02"}]
    result = kea_sync._magic_prepass(records, raw, {}, False, _log)
    assert result == {}, \
        f"distinct FQDNs must not collide; got magic_fqdns={result}"


def test_magic_prepass_same_fqdn_two_ips_collides():
    """Same FQDN with two IPs IS a real collision and gets magic FQDNs."""
    records = [
        ("laptop.home.lan", "10.0.0.1", "A", 300),
        ("laptop.home.lan", "10.0.0.2", "A", 300),
    ]
    raw = [{"hw-address": "aa:bb:cc:01:02:03"},
           {"hw-address": "aa:bb:cc:04:05:06"}]
    result = kea_sync._magic_prepass(records, raw, {}, False, _log)
    assert len(result) == 2, "two IPs under one FQDN must produce two magic entries"
    # Both magic FQDNs must end with the correct domain
    for magic_fqdn in result.values():
        assert magic_fqdn.endswith(".home.lan"), \
            f"magic FQDN domain must match source FQDN domain; got {magic_fqdn}"


# ── _collect_writes: write_magic_ptrs ────────────────────────────────────────

def test_collect_writes_write_magic_ptrs_adds_ptr_for_magic_name():
    """write_magic_ptrs=True: a PTR record is synthesized for the magic FQDN IP."""
    records = [("laptop.lan", "192.168.1.10", "A", 300)]
    magic_fqdns = {"192.168.1.10": "laptop-mAABBCC.lan"}
    to_add, to_remove, *_ = _collect(
        records,
        policy="last_wins",
        synthesize_ptr=True,
        magic_fqdns=magic_fqdns,
        write_magic_ptrs=True,
    )
    ptr = "10.1.168.192.in-addr.arpa"
    assert any(ptr in r and "laptop-mAABBCC.lan" in r for r in to_add), \
        "PTR for the magic FQDN must appear in to_add when write_magic_ptrs=True"


def test_collect_writes_no_magic_ptr_without_flag():
    """write_magic_ptrs=False (default): no PTR for the magic FQDN IP."""
    records = [("laptop.lan", "192.168.1.10", "A", 300)]
    magic_fqdns = {"192.168.1.10": "laptop-mAABBCC.lan"}
    to_add, to_remove, *_ = _collect(
        records,
        policy="last_wins",
        synthesize_ptr=True,
        magic_fqdns=magic_fqdns,
        write_magic_ptrs=False,
    )
    assert not any("laptop-mAABBCC.lan" in r and "in-addr.arpa" in r
                   for r in to_add), \
        "No magic PTR must appear when write_magic_ptrs=False"
