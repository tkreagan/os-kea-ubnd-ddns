# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit tests for kea-sync.py — the merged Kea → Unbound reconciler.

These replace the old test_lease_sync.py / test_reservation_sync.py, which
targeted the lease-sync.py and reservation-sync.py scripts that were merged
into kea-sync.py. Coverage is retargeted at the current functions:

  * _collect_writes() — the pure collision/dedup/winner-resolution core, the
    most logic-dense (and most regression-prone) part of the reconciler.
  * sync_static()     — the static reservation pass.
  * sync_dynamic()    — the active-lease pass (TTL, claims, targeted drain).

Patches are applied at the kea_sync module level because the script imports
names directly into its own namespace (from lib.keaubnd_sync import ...).
"""

from __future__ import annotations

import logging
import time
import unittest.mock as mock

import pytest

from lib.keaubnd_sync import KeaServiceUnavailableError, KeaUnavailableError
from .conftest import load_script

pytestmark = pytest.mark.unit

ks = load_script("kea-sync.py")

LOG = logging.getLogger("test_kea_sync")
LOG.addHandler(logging.NullHandler())


# ── helpers ──────────────────────────────────────────────────────────────────

def _adds(to_add):
    """A-record / AAAA add lines (exclude synthesized PTRs)."""
    return [r for r in to_add if " IN A " in r or " IN AAAA " in r]


def _ptrs(to_add):
    return [r for r in to_add if " IN PTR " in r]


def _batched(mock_batch):
    """Flatten every record passed to unbound_local_datas_batch across calls."""
    out = []
    for call in mock_batch.call_args_list:
        out.extend(call.args[0])
    return out


def _res(hostname, ip):
    return {"hostname": hostname, "ip": ip, "ipv6": None}


def _res6(hostname, ipv6):
    return {"hostname": hostname, "ip": None, "ipv6": ipv6}


def _lease(hostname, ip, expires=None, vlft=3600):
    return {"hostname": hostname, "ip": ip, "ipv6": None,
            "expires": expires or (int(time.time()) + vlft),
            "valid_lifetime": vlft}


def _lease6(hostname, ipv6, expires=None, vlft=3600):
    return {"hostname": hostname, "ip": None, "ipv6": ipv6,
            "expires": expires or (int(time.time()) + vlft),
            "valid_lifetime": vlft}


# ── _collect_writes: collision / winner resolution ───────────────────────────

def test_collect_allow_is_additive():
    recs = [("h.lan", "192.168.1.1", "A", 100),
            ("h.lan", "192.168.1.2", "A", 100)]
    to_add, to_remove, won, na, ns = ks._collect_writes(
        recs, "A", {}, "allow", True, {}, set(), LOG)
    assert len(_adds(to_add)) == 2          # both IPs kept, no dedup
    assert to_remove == []
    assert won == set()                     # allow never claims (leases not blocked)


def test_collect_first_wins_keeps_earliest():
    recs = [("h.lan", "192.168.1.1", "A", 100),
            ("h.lan", "192.168.1.2", "A", 100)]
    to_add, _, won, _, ns = ks._collect_writes(
        recs, "A", {}, "first_wins", True, {}, set(), LOG)
    adds = _adds(to_add)
    assert len(adds) == 1 and "192.168.1.1" in adds[0]
    assert "h.lan" in won and ns == 1


def test_collect_last_wins_keeps_latest():
    recs = [("h.lan", "192.168.1.1", "A", 100),
            ("h.lan", "192.168.1.2", "A", 100)]
    to_add, _, _, _, _ = ks._collect_writes(
        recs, "A", {}, "last_wins", True, {}, set(), LOG)
    adds = _adds(to_add)
    assert len(adds) == 1 and "192.168.1.2" in adds[0]


def test_collect_reservation_beats_lease():
    # prior_claim_keys carries the reservation FQDNs (lower-cased); a lease for
    # the same name in the same family must be skipped.
    recs = [("h.lan", "192.168.1.50", "A", 100)]
    to_add, _, _, _, ns = ks._collect_writes(
        recs, "A", {}, "last_wins", True, {}, {"h.lan"}, LOG)
    assert _adds(to_add) == [] and ns == 1


def test_collect_skips_host_entries():
    recs = [("static.lan", "192.168.1.9", "A", 100)]
    to_add, _, _, _, ns = ks._collect_writes(
        recs, "A", {"static.lan": ["local-data: ..."]}, "last_wins",
        True, {}, set(), LOG)
    assert _adds(to_add) == [] and ns == 1


@pytest.mark.parametrize("bad", ["localhost", "123456.lan", "bad!host.lan"])
def test_collect_skips_insane_names(bad):
    recs = [(bad, "192.168.1.9", "A", 100)]
    to_add, _, _, _, _ = ks._collect_writes(
        recs, "A", {}, "last_wins", True, {}, set(), LOG)
    assert _adds(to_add) == []


def test_collect_no_ptr_when_synthesize_off():
    recs = [("h.lan", "192.168.1.1", "A", 100)]
    to_add, _, _, _, _ = ks._collect_writes(
        recs, "A", {}, "last_wins", False, {}, set(), LOG)
    assert _adds(to_add) and _ptrs(to_add) == []


def test_collect_ptr_when_synthesize_on():
    recs = [("h.lan", "192.168.1.1", "A", 100)]
    to_add, _, _, _, _ = ks._collect_writes(
        recs, "A", {}, "last_wins", True, {}, set(), LOG)
    assert _ptrs(to_add) and "1.1.168.192.in-addr.arpa" in _ptrs(to_add)[0]


def test_collect_idempotent_no_remove_when_unchanged():
    # Unbound already holds exactly the winner → add only, no remove.
    recs = [("h.lan", "192.168.1.1", "A", 100)]
    to_add, to_remove, _, _, _ = ks._collect_writes(
        recs, "A", {}, "last_wins", True, {"h.lan": {"192.168.1.1"}}, set(), LOG)
    assert to_remove == [] and _adds(to_add)


def test_collect_replaces_when_unbound_differs():
    # Unbound holds a different IP → remove-then-add (and drop the stale PTR).
    recs = [("h.lan", "192.168.1.1", "A", 100)]
    to_add, to_remove, _, _, _ = ks._collect_writes(
        recs, "A", {}, "last_wins", True, {"h.lan": {"192.168.1.9"}}, set(), LOG)
    assert "h.lan" in to_remove
    assert any("9.1.168.192.in-addr.arpa" in r for r in to_remove)  # stale PTR


def test_collect_multi_ip_emits_all():
    # allow_multi_ip: a single host with several reserved addresses keeps them all.
    recs = [("h.lan", "2001:db8::1", "AAAA", None),
            ("h.lan", "2001:db8::2", "AAAA", None)]
    to_add, _, won, _, _ = ks._collect_writes(
        recs, "AAAA", {}, "last_wins", True, {}, set(), LOG, allow_multi_ip=True)
    assert len(_adds(to_add)) == 2 and "h.lan" in won


# ── sync_static ──────────────────────────────────────────────────────────────

@mock.patch.object(ks, "unbound_local_datas_batch", return_value=True)
@mock.patch.object(ks, "unbound_control", return_value=True)
@mock.patch.object(ks, "query_kea_reservations")
def test_sync_static_writes_a_and_ptr(mock_qkr, mock_uc, mock_batch):
    mock_qkr.side_effect = [[_res("myhost.lan", "192.168.1.100")],
                            KeaServiceUnavailableError("dhcp6 off")]
    claims, added, skipped, errors = ks.sync_static(
        {}, "last_wins", True, {}, False, LOG)
    recs = _batched(mock_batch)
    assert any("myhost.lan" in r and " IN A " in r for r in recs)
    assert any(" IN PTR " in r for r in recs)
    assert errors == 0 and added >= 1
    assert "myhost.lan" in claims["A"]


@mock.patch.object(ks, "unbound_local_datas_batch", return_value=True)
@mock.patch.object(ks, "unbound_control", return_value=True)
@mock.patch.object(ks, "query_kea_reservations")
def test_sync_static_aaaa(mock_qkr, mock_uc, mock_batch):
    mock_qkr.side_effect = [KeaServiceUnavailableError("dhcp4 off"),
                            [_res6("v6host.lan", "2001:db8::1")]]
    claims, added, _, errors = ks.sync_static({}, "last_wins", True, {}, False, LOG)
    assert any("v6host.lan" in r and " IN AAAA " in r for r in _batched(mock_batch))
    assert errors == 0


@mock.patch.object(ks, "unbound_local_datas_batch", return_value=True)
@mock.patch.object(ks, "unbound_control", return_value=True)
@mock.patch.object(ks, "query_kea_reservations")
def test_sync_static_dry_run_writes_nothing(mock_qkr, mock_uc, mock_batch):
    mock_qkr.side_effect = [[_res("myhost.lan", "192.168.1.100")],
                            KeaServiceUnavailableError("off")]
    ks.sync_static({}, "last_wins", True, {}, True, LOG)
    mock_batch.assert_not_called()
    mock_uc.assert_not_called()


@mock.patch.object(ks, "unbound_local_datas_batch", return_value=False)
@mock.patch.object(ks, "unbound_control", return_value=True)
@mock.patch.object(ks, "query_kea_reservations")
def test_sync_static_batch_failure_counts_error(mock_qkr, mock_uc, mock_batch):
    mock_qkr.side_effect = [[_res("myhost.lan", "192.168.1.100")],
                            KeaServiceUnavailableError("off")]
    _, _, _, errors = ks.sync_static({}, "last_wins", True, {}, False, LOG)
    assert errors >= 1


@mock.patch.object(ks, "unbound_local_datas_batch", return_value=True)
@mock.patch.object(ks, "unbound_control", return_value=True)
@mock.patch.object(ks, "query_kea_reservations")
def test_sync_static_kea_unavailable_propagates(mock_qkr, mock_uc, mock_batch):
    # A hard Kea failure must NOT be swallowed — the caller fails fast.
    mock_qkr.side_effect = KeaUnavailableError("socket gone")
    with pytest.raises(KeaUnavailableError):
        ks.sync_static({}, "last_wins", True, {}, False, LOG)


# ── sync_dynamic ─────────────────────────────────────────────────────────────

@mock.patch.object(ks, "unbound_local_datas_batch", return_value=True)
@mock.patch.object(ks, "unbound_control", return_value=True)
@mock.patch.object(ks, "query_kea_leases")
def test_sync_dynamic_writes_a_with_ttl(mock_qkl, mock_uc, mock_batch):
    future = int(time.time()) + 500
    mock_qkl.side_effect = [[_lease("client.lan", "192.168.1.200", future)],
                            KeaServiceUnavailableError("dhcp6 off")]
    added, _, errors = ks.sync_dynamic(
        {}, "last_wins", True, {}, ks._empty_claims(), None, False, LOG)
    a_lines = [r for r in _batched(mock_batch)
               if "client.lan" in r and " IN A 192.168.1.200" in r]
    assert a_lines and errors == 0 and added >= 1
    # TTL is the remaining lease time (≈500s), not a fixed value.
    ttl = int(a_lines[0].split()[1])
    assert 0 < ttl <= 500


@mock.patch.object(ks, "unbound_local_datas_batch", return_value=True)
@mock.patch.object(ks, "unbound_control", return_value=True)
@mock.patch.object(ks, "query_kea_leases")
def test_sync_dynamic_reservation_claim_blocks_lease(mock_qkl, mock_uc, mock_batch):
    mock_qkl.side_effect = [[_lease("client.lan", "192.168.1.200")],
                            KeaServiceUnavailableError("off")]
    claims = {"A": {"client.lan"}, "AAAA": set()}
    added, skipped, _ = ks.sync_dynamic(
        {}, "last_wins", True, {}, claims, None, False, LOG)
    assert added == 0 and skipped >= 1
    mock_batch.assert_not_called()


@mock.patch.object(ks, "unbound_local_datas_batch", return_value=True)
@mock.patch.object(ks, "unbound_control", return_value=True)
@mock.patch.object(ks, "query_kea_leases_by_hostname")
@mock.patch.object(ks, "query_kea_leases")
def test_sync_dynamic_names_filter_uses_by_hostname(mock_qkl, mock_byhost,
                                                    mock_uc, mock_batch):
    mock_byhost.side_effect = [[_lease("client.lan", "192.168.1.200")], [], []]
    ks.sync_dynamic({}, "last_wins", True, {}, ks._empty_claims(),
                    frozenset({"client.lan"}), False, LOG)
    assert mock_byhost.called
    mock_qkl.assert_not_called()      # targeted drain must not pull the full table


@mock.patch.object(ks, "unbound_local_datas_batch", return_value=True)
@mock.patch.object(ks, "unbound_control", return_value=True)
@mock.patch.object(ks, "query_kea_leases")
def test_sync_dynamic_skips_blank_hostname(mock_qkl, mock_uc, mock_batch):
    mock_qkl.side_effect = [[_lease("", "192.168.1.200")],
                            KeaServiceUnavailableError("off")]
    added, _, _ = ks.sync_dynamic(
        {}, "last_wins", True, {}, ks._empty_claims(), None, False, LOG)
    assert added == 0
    mock_batch.assert_not_called()
