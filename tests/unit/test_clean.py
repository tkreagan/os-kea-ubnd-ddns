# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit tests for local-data-clean.py.

Patches at the clean module level because the script imports names
directly into its own namespace.
"""

from __future__ import annotations

import unittest.mock as mock

import pytest

from lib.keaubnd_sync import KeaServiceUnavailableError, KeaUnavailableError
from .conftest import load_script

pytestmark = pytest.mark.unit

clean = load_script("local-data-clean.py")


# ── clean_stale_records (bulk) ────────────────────────────────────────────────

@mock.patch.object(clean, "unbound_control", return_value=True)
@mock.patch.object(clean, "collect_kea_pairs")
@mock.patch.object(clean, "unbound_list_local_data")
@mock.patch.object(clean, "read_host_entries", return_value={})
def test_bulk_removes_stale_hostname(mock_rhe, mock_ld, mock_ckp, mock_uc):
    mock_ld.return_value = {
        "ghost.lan": ["ghost.lan. 300 IN A 192.168.1.99"]
    }
    mock_ckp.return_value = set()
    rc = clean.clean_stale_records()
    assert rc == 0
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("local_data_remove" in c and "ghost.lan" in c for c in calls)


@mock.patch.object(clean, "unbound_control", return_value=True)
@mock.patch.object(clean, "collect_kea_pairs")
@mock.patch.object(clean, "unbound_list_local_data")
@mock.patch.object(clean, "read_host_entries", return_value={})
def test_bulk_preserves_kea_backed(mock_rhe, mock_ld, mock_ckp, mock_uc):
    mock_ld.return_value = {
        "live.lan": ["live.lan. 300 IN A 192.168.1.10"]
    }
    mock_ckp.return_value = {("live.lan", "192.168.1.10")}
    clean.clean_stale_records()
    calls = [str(c) for c in mock_uc.call_args_list]
    assert not any("live.lan" in c for c in calls)


@mock.patch.object(clean, "collect_kea_pairs",
                   side_effect=KeaUnavailableError("socket gone"))
@mock.patch.object(clean, "unbound_list_local_data", return_value={})
@mock.patch.object(clean, "read_host_entries", return_value={})
def test_bulk_aborts_when_kea_unavailable(mock_rhe, mock_ld, mock_ckp):
    rc = clean.clean_stale_records()
    assert rc == 1


@mock.patch.object(clean, "unbound_control", return_value=True)
@mock.patch.object(clean, "collect_kea_pairs")
@mock.patch.object(clean, "unbound_list_local_data")
@mock.patch.object(clean, "read_host_entries", return_value={})
def test_bulk_dry_run_no_calls(mock_rhe, mock_ld, mock_ckp, mock_uc):
    mock_ld.return_value = {"ghost.lan": ["ghost.lan. 300 IN A 192.168.1.99"]}
    mock_ckp.return_value = set()
    clean.clean_stale_records(dry_run=True)
    mock_uc.assert_not_called()


@mock.patch.object(clean, "unbound_control", return_value=True)
@mock.patch.object(clean, "collect_kea_pairs", return_value=set())
@mock.patch.object(clean, "unbound_list_local_data", return_value={})
@mock.patch.object(clean, "read_host_entries", return_value={})
def test_bulk_no_stale_records_returns_zero(mock_rhe, mock_ld, mock_ckp, mock_uc):
    rc = clean.clean_stale_records()
    assert rc == 0
    mock_uc.assert_not_called()


# ── clean_host (targeted) ─────────────────────────────────────────────────────

@mock.patch.object(clean, "unbound_local_datas_batch", return_value=True)
@mock.patch.object(clean, "unbound_control", return_value=True)
@mock.patch.object(clean, "unbound_list_local_data")
@mock.patch.object(clean, "read_host_entries", return_value={})
@mock.patch.object(clean, "_kea_ips_for_hostname")
def test_clean_host_removes_stale_ip(mock_kea, mock_rhe, mock_ld, mock_uc, mock_batch):
    mock_ld.return_value = {
        "myhost.lan": [
            "myhost.lan. 300 IN A 192.168.1.5",
            "myhost.lan. 300 IN A 192.168.1.6",
        ]
    }
    mock_kea.return_value = {"192.168.1.6"}
    rc = clean.clean_host("myhost.lan", keep_ip="192.168.1.6")
    assert rc == 0
    # The stale IP is dropped via a name-level remove on unbound_control...
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("local_data_remove" in c and "myhost.lan" in c for c in calls)
    # ...and the surviving IP is re-added via the batch helper (not per-record).
    batched = [r for call in mock_batch.call_args_list for r in call.args[0]]
    assert any("192.168.1.6" in r for r in batched)


@mock.patch.object(clean, "unbound_control", return_value=True)
@mock.patch.object(clean, "unbound_list_local_data")
@mock.patch.object(clean, "read_host_entries", return_value={})
@mock.patch.object(clean, "_kea_ips_for_hostname")
def test_clean_host_aborts_when_kea_unreachable(mock_kea, mock_rhe, mock_ld, mock_uc):
    mock_ld.return_value = {}
    mock_kea.return_value = None
    rc = clean.clean_host("myhost.lan")
    assert rc == 0
    mock_uc.assert_not_called()


@mock.patch.object(clean, "unbound_control", return_value=True)
@mock.patch.object(clean, "unbound_list_local_data")
@mock.patch.object(clean, "read_host_entries")
@mock.patch.object(clean, "_kea_ips_for_hostname")
def test_clean_host_skips_host_entries_name(mock_kea, mock_rhe, mock_ld, mock_uc):
    mock_rhe.return_value = {"static-host.lan": ["local-data: ..."]}
    mock_ld.return_value = {}
    rc = clean.clean_host("static-host.lan")
    assert rc == 0
    mock_kea.assert_not_called()
    mock_uc.assert_not_called()


@mock.patch.object(clean, "unbound_control", return_value=True)
@mock.patch.object(clean, "unbound_list_local_data")
@mock.patch.object(clean, "read_host_entries", return_value={})
@mock.patch.object(clean, "_kea_ips_for_hostname")
def test_clean_host_no_stale_ips_is_noop(mock_kea, mock_rhe, mock_ld, mock_uc):
    mock_ld.return_value = {
        "myhost.lan": ["myhost.lan. 300 IN A 192.168.1.10"]
    }
    mock_kea.return_value = {"192.168.1.10"}
    rc = clean.clean_host("myhost.lan")
    assert rc == 0
    mock_uc.assert_not_called()


@mock.patch.object(clean, "unbound_control", return_value=True)
@mock.patch.object(clean, "unbound_list_local_data")
@mock.patch.object(clean, "read_host_entries", return_value={})
@mock.patch.object(clean, "_kea_ips_for_hostname")
def test_clean_host_refuses_to_remove_last_record(mock_kea, mock_rhe, mock_ld, mock_uc):
    mock_ld.return_value = {
        "myhost.lan": ["myhost.lan. 300 IN A 192.168.1.5"]
    }
    mock_kea.return_value = set()
    rc = clean.clean_host("myhost.lan", keep_ip=None)
    assert rc == 0
    calls = [str(c) for c in mock_uc.call_args_list]
    assert not any("local_data_remove" in c for c in calls)


# ── synthesis-aware pass-through ──────────────────────────────────────────────

@mock.patch.object(clean, "unbound_control", return_value=True)
@mock.patch.object(clean, "find_stale_records", return_value=(set(), set()))
@mock.patch.object(clean, "collect_kea_pairs", return_value=set())
@mock.patch.object(clean, "unbound_list_local_data", return_value={})
@mock.patch.object(clean, "read_host_entries", return_value={})
@mock.patch.object(clean, "read_d2_reverse_zones", return_value={"1.168.192.in-addr.arpa"})
@mock.patch.object(clean, "get_synthesize_ptr", return_value=False)
def test_bulk_passes_synthesize_flag_to_find_stale(
        mock_gsp, mock_rdz, mock_rhe, mock_ld, mock_ckp, mock_fsr, mock_uc):
    """clean_stale_records reads synthesize_ptr + d2_reverse_zones and forwards them."""
    clean.clean_stale_records()
    mock_fsr.assert_called_once()
    _, kwargs = mock_fsr.call_args
    assert kwargs.get("synthesize_ptr") is False
    assert kwargs.get("d2_reverse_zones") == {"1.168.192.in-addr.arpa"}
