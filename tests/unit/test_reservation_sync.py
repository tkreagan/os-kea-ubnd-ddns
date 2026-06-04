# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit tests for reservation-sync.py (sync_reservations function).

Patches at the rsync module level because the script imports names
directly into its own namespace (from lib.keaunbound_sync import ...).
"""

from __future__ import annotations

import unittest.mock as mock

import pytest

from lib.keaunbound_sync import KeaServiceUnavailableError, KeaUnavailableError
from .conftest import load_script

pytestmark = pytest.mark.unit

rsync = load_script("reservation-sync.py")


def _res(hostname, ip):
    return {"hostname": hostname, "ip": ip, "ipv6": None}


def _res6(hostname, ipv6):
    return {"hostname": hostname, "ip": None, "ipv6": ipv6}


@mock.patch.object(rsync, "unbound_control", return_value=True)
@mock.patch.object(rsync, "read_host_entries", return_value={})
@mock.patch.object(rsync, "query_kea_reservations")
def test_sync_reservations_adds_a_and_ptr(mock_qkr, mock_rhe, mock_uc):
    mock_qkr.side_effect = [
        [_res("myhost.lan", "192.168.1.100")],
        KeaServiceUnavailableError("dhcp6 off"),
    ]
    rc = rsync.sync_reservations()
    assert rc == 0
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("A" in c and "myhost.lan" in c for c in calls)
    assert any("PTR" in c for c in calls)


@mock.patch.object(rsync, "unbound_control", return_value=True)
@mock.patch.object(rsync, "read_host_entries", return_value={})
@mock.patch.object(rsync, "query_kea_reservations")
def test_sync_reservations_adds_aaaa(mock_qkr, mock_rhe, mock_uc):
    mock_qkr.side_effect = [
        KeaServiceUnavailableError("dhcp4 off"),
        [_res6("v6host.lan", "2001:db8::1")],
    ]
    rc = rsync.sync_reservations()
    assert rc == 0
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("AAAA" in c and "v6host.lan" in c for c in calls)


@mock.patch.object(rsync, "unbound_control", return_value=True)
@mock.patch.object(rsync, "read_host_entries", return_value={})
@mock.patch.object(rsync, "query_kea_reservations")
def test_sync_reservations_skips_blank_hostname(mock_qkr, mock_rhe, mock_uc):
    mock_qkr.side_effect = [
        [_res("", "192.168.1.100")],
        KeaServiceUnavailableError("off"),
    ]
    rsync.sync_reservations()
    mock_uc.assert_not_called()


@mock.patch.object(rsync, "unbound_control", return_value=True)
@mock.patch.object(rsync, "read_host_entries", return_value={})
@mock.patch.object(rsync, "query_kea_reservations")
def test_sync_reservations_skips_nonsense_name(mock_qkr, mock_rhe, mock_uc):
    mock_qkr.side_effect = [
        [_res("localhost", "127.0.0.1")],
        KeaServiceUnavailableError("off"),
    ]
    rsync.sync_reservations()
    mock_uc.assert_not_called()


@mock.patch.object(rsync, "unbound_control", return_value=True)
@mock.patch.object(rsync, "read_host_entries")
@mock.patch.object(rsync, "query_kea_reservations")
def test_sync_reservations_skips_host_entries(mock_qkr, mock_rhe, mock_uc):
    mock_rhe.return_value = {"static-host.lan": ["local-data: ..."]}
    mock_qkr.side_effect = [
        [_res("static-host.lan", "192.168.1.50")],
        KeaServiceUnavailableError("off"),
    ]
    rsync.sync_reservations()
    mock_uc.assert_not_called()


@mock.patch.object(rsync, "unbound_control", return_value=True)
@mock.patch.object(rsync, "read_host_entries", return_value={})
@mock.patch.object(rsync, "query_kea_reservations")
def test_sync_reservations_service_unavailable_skips(mock_qkr, mock_rhe, mock_uc):
    mock_qkr.side_effect = [
        KeaServiceUnavailableError("dhcp4 off"),
        KeaServiceUnavailableError("dhcp6 off"),
    ]
    rc = rsync.sync_reservations()
    assert rc == 0
    mock_uc.assert_not_called()


@mock.patch.object(rsync, "unbound_control", return_value=True)
@mock.patch.object(rsync, "read_host_entries", return_value={})
@mock.patch.object(rsync, "query_kea_reservations")
def test_sync_reservations_kea_unavailable_counts_error(mock_qkr, mock_rhe, mock_uc):
    mock_qkr.side_effect = [
        KeaUnavailableError("socket not found"),
        KeaServiceUnavailableError("off"),
    ]
    rc = rsync.sync_reservations()
    assert rc == 1


@mock.patch.object(rsync, "unbound_control", return_value=True)
@mock.patch.object(rsync, "read_host_entries", return_value={})
@mock.patch.object(rsync, "query_kea_reservations")
def test_sync_reservations_dry_run_no_calls(mock_qkr, mock_rhe, mock_uc):
    mock_qkr.side_effect = [
        [_res("myhost.lan", "192.168.1.100")],
        KeaServiceUnavailableError("off"),
    ]
    rsync.sync_reservations(dry_run=True)
    mock_uc.assert_not_called()


@mock.patch.object(rsync, "unbound_control", return_value=False)
@mock.patch.object(rsync, "read_host_entries", return_value={})
@mock.patch.object(rsync, "query_kea_reservations")
def test_sync_reservations_unbound_failure_returns_one(mock_qkr, mock_rhe, mock_uc):
    mock_qkr.side_effect = [
        [_res("myhost.lan", "192.168.1.100")],
        KeaServiceUnavailableError("off"),
    ]
    rc = rsync.sync_reservations()
    assert rc == 1
