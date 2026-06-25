# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit tests for local-data-clean.py.

Patches at the clean module level because the script imports names
directly into its own namespace.
"""

from __future__ import annotations

import sys
import unittest.mock as mock

import pytest

from lib.keaubnd_sync import KeaServiceUnavailableError, KeaUnavailableError
from .conftest import load_script

pytestmark = pytest.mark.unit

clean = load_script("local-data-clean.py")


def _run_main(*argv):
    """Call clean.main() with a controlled argv."""
    with mock.patch("sys.argv", ["local-data-clean.py"] + list(argv)):
        return clean.main()


# ── bulk clean (via main()) ───────────────────────────────────────────────────
# The bulk path calls discover_stale() then clean_stale_records(); patch both
# at the clean module level (imported names in that namespace).

@mock.patch.object(clean, "unbound_mutation_lock")
@mock.patch.object(clean, "clean_stale_records", return_value=0)
@mock.patch.object(clean, "discover_stale")
def test_bulk_removes_stale_hostname(mock_ds, mock_csr, mock_lock):
    mock_ds.return_value = ({}, {("ghost.lan", "192.168.1.99")}, set())
    rc = _run_main()
    assert rc == 0
    mock_csr.assert_called_once()
    # stale_pairs and orphaned_ptrs forwarded to clean_stale_records
    args = mock_csr.call_args
    assert ("ghost.lan", "192.168.1.99") in args[0][1]


@mock.patch.object(clean, "unbound_mutation_lock")
@mock.patch.object(clean, "clean_stale_records", return_value=0)
@mock.patch.object(clean, "discover_stale")
def test_bulk_preserves_kea_backed(mock_ds, mock_csr, mock_lock):
    mock_ds.return_value = ({}, set(), set())
    rc = _run_main()
    assert rc == 0
    mock_csr.assert_not_called()


@mock.patch.object(clean, "unbound_mutation_lock")
@mock.patch.object(clean, "discover_stale")
def test_bulk_aborts_when_kea_unavailable(mock_ds, mock_lock):
    mock_ds.side_effect = KeaUnavailableError("socket gone")
    rc = _run_main()
    assert rc == 1


@mock.patch.object(clean, "clean_stale_records")
@mock.patch.object(clean, "discover_stale")
def test_bulk_dry_run_no_removals(mock_ds, mock_csr):
    mock_ds.return_value = ({}, {("ghost.lan", "192.168.1.99")}, set())
    rc = _run_main("--dry-run")
    assert rc == 0
    mock_csr.assert_not_called()


@mock.patch.object(clean, "unbound_mutation_lock")
@mock.patch.object(clean, "clean_stale_records", return_value=0)
@mock.patch.object(clean, "discover_stale")
def test_bulk_no_stale_records_returns_zero(mock_ds, mock_csr, mock_lock):
    mock_ds.return_value = ({}, set(), set())
    rc = _run_main()
    assert rc == 0
    mock_csr.assert_not_called()


@mock.patch.object(clean, "unbound_mutation_lock")
@mock.patch.object(clean, "clean_stale_records", return_value=0)
@mock.patch.object(clean, "discover_stale")
def test_bulk_passes_no_synthesize_ptr_to_discover(mock_ds, mock_csr, mock_lock):
    mock_ds.return_value = ({}, set(), set())
    _run_main("--no-synthesize-ptr")
    mock_ds.assert_called_once()
    assert mock_ds.call_args[0][0] is False  # synthesize_ptr=False


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
    uc_calls = [str(c) for c in mock_uc.call_args_list]
    assert any("local_data_remove" in c and "myhost.lan" in c for c in uc_calls)
    # re-add of surviving IP goes through unbound_local_datas_batch
    assert mock_batch.called
    batch_args = str(mock_batch.call_args_list)
    assert "192.168.1.6" in batch_args


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
