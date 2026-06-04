# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit tests for lease-sync.py (sync_leases function).

Patches at the lsync module level because the script imports names
directly into its own namespace (from lib.keaunbound_sync import ...).
"""

from __future__ import annotations

import time
import unittest.mock as mock

import pytest

from lib.keaunbound_sync import KeaServiceUnavailableError, KeaUnavailableError
from .conftest import load_script

pytestmark = pytest.mark.unit

lsync = load_script("lease-sync.py")


def _lease(hostname, ip, expires=None):
    return {
        "hostname": hostname,
        "ip": ip,
        "ipv6": None,
        "expires": expires or (int(time.time()) + 3600),
    }


def _lease6(hostname, ipv6, expires=None):
    return {
        "hostname": hostname,
        "ip": None,
        "ipv6": ipv6,
        "expires": expires or (int(time.time()) + 3600),
    }


@mock.patch.object(lsync, "unbound_control", return_value=True)
@mock.patch.object(lsync, "read_host_entries", return_value={})
@mock.patch.object(lsync, "query_kea_leases")
def test_sync_leases_adds_a_with_ttl(mock_qkl, mock_rhe, mock_uc):
    future = int(time.time()) + 500
    mock_qkl.side_effect = [
        [_lease("client.lan", "192.168.1.200", future)],
        KeaServiceUnavailableError("off"),
    ]
    rc = lsync.sync_leases()
    assert rc == 0
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("client.lan" in c and "192.168.1.200" in c for c in calls)


@mock.patch.object(lsync, "unbound_control", return_value=True)
@mock.patch.object(lsync, "read_host_entries", return_value={})
@mock.patch.object(lsync, "query_kea_leases")
def test_sync_leases_adds_aaaa(mock_qkl, mock_rhe, mock_uc):
    mock_qkl.side_effect = [
        KeaServiceUnavailableError("off"),
        [_lease6("v6client.lan", "2001:db8::200")],
    ]
    rc = lsync.sync_leases()
    assert rc == 0
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("AAAA" in c for c in calls)


@mock.patch.object(lsync, "unbound_control", return_value=True)
@mock.patch.object(lsync, "read_host_entries", return_value={})
@mock.patch.object(lsync, "query_kea_leases")
def test_sync_leases_skips_blank_hostname(mock_qkl, mock_rhe, mock_uc):
    mock_qkl.side_effect = [
        [_lease("", "192.168.1.200")],
        KeaServiceUnavailableError("off"),
    ]
    lsync.sync_leases()
    mock_uc.assert_not_called()


@mock.patch.object(lsync, "unbound_control", return_value=True)
@mock.patch.object(lsync, "read_host_entries")
@mock.patch.object(lsync, "query_kea_leases")
def test_sync_leases_skips_host_entries(mock_qkl, mock_rhe, mock_uc):
    mock_rhe.return_value = {"static-host.lan": ["local-data: ..."]}
    mock_qkl.side_effect = [
        [_lease("static-host.lan", "192.168.1.50")],
        KeaServiceUnavailableError("off"),
    ]
    lsync.sync_leases()
    mock_uc.assert_not_called()


@mock.patch.object(lsync, "unbound_control", return_value=True)
@mock.patch.object(lsync, "read_host_entries", return_value={})
@mock.patch.object(lsync, "query_kea_leases")
def test_sync_leases_dry_run_no_calls(mock_qkl, mock_rhe, mock_uc):
    mock_qkl.side_effect = [
        [_lease("client.lan", "192.168.1.200")],
        KeaServiceUnavailableError("off"),
    ]
    lsync.sync_leases(dry_run=True)
    mock_uc.assert_not_called()


@mock.patch.object(lsync, "unbound_control", return_value=True)
@mock.patch.object(lsync, "read_host_entries", return_value={})
@mock.patch.object(lsync, "query_kea_leases")
def test_sync_leases_kea_unavailable_counts_error(mock_qkl, mock_rhe, mock_uc):
    mock_qkl.side_effect = [
        KeaUnavailableError("socket gone"),
        KeaServiceUnavailableError("off"),
    ]
    rc = lsync.sync_leases()
    assert rc == 1
