# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit tests for local-data-audit.py.

Patches at the audit module level because the script imports names
directly into its own namespace.
"""

from __future__ import annotations

import json
import unittest.mock as mock
from io import StringIO

import pytest

from lib.keaunbound_sync import KeaServiceUnavailableError, KeaUnavailableError
from .conftest import load_script

pytestmark = pytest.mark.unit

audit = load_script("local-data-audit.py")


def _capture_audit(**overrides):
    """Run audit_local_data with mock overrides, return parsed JSON."""
    defaults = {
        "read_host_entries": {},
        "unbound_list_local_data": {},
        "query_kea_reservations": [],
        "query_kea_leases": [],
    }
    defaults.update(overrides)

    def _side(val):
        return val if callable(val) else mock.MagicMock(return_value=val)

    captured = StringIO()
    with mock.patch.object(audit, "read_host_entries",
                           return_value=defaults["read_host_entries"]), \
         mock.patch.object(audit, "unbound_list_local_data",
                           return_value=defaults["unbound_list_local_data"]), \
         mock.patch.object(audit, "query_kea_reservations",
                           side_effect=defaults["query_kea_reservations"]
                           if isinstance(defaults["query_kea_reservations"], list)
                           else defaults["query_kea_reservations"]), \
         mock.patch.object(audit, "query_kea_leases",
                           side_effect=defaults["query_kea_leases"]
                           if isinstance(defaults["query_kea_leases"], list)
                           else defaults["query_kea_leases"]), \
         mock.patch("sys.stdout", captured):
        audit.audit_local_data(report_json=True)
    return json.loads(captured.getvalue())


# ── complete flag ─────────────────────────────────────────────────────────────

def test_audit_complete_true_when_all_ok():
    result = _capture_audit(
        query_kea_reservations=[[], KeaServiceUnavailableError("off")],
        query_kea_leases=[[], KeaServiceUnavailableError("off")],
    )
    assert result["complete"] is True
    assert result["kea_error"] is None


def test_audit_complete_false_kea_unavailable():
    def raise_unavailable(*a, **kw):
        raise KeaUnavailableError("socket gone")

    result = _capture_audit(
        query_kea_reservations=raise_unavailable,
        query_kea_leases=raise_unavailable,
    )
    assert result["complete"] is False
    assert result["kea_error"] is not None


# ── record status ─────────────────────────────────────────────────────────────

def test_audit_record_ok_reservation_in_unbound():
    hostname = "myhost.lan"
    ip = "192.168.1.100"
    ptr = "100.1.168.192.in-addr.arpa"
    result = _capture_audit(
        unbound_list_local_data={
            hostname: [f"{hostname}. 300 IN A {ip}"],
            ptr: [f"{ptr}. 300 IN PTR {hostname}."],
        },
        query_kea_reservations=[
            [{"hostname": hostname, "ip": ip, "ipv6": None}],
            KeaServiceUnavailableError("off"),
        ],
        query_kea_leases=[[], KeaServiceUnavailableError("off")],
    )
    records = [r for r in result["records"] if r["hostname"] == hostname]
    assert len(records) == 1
    r = records[0]
    assert r["status"] == "ok"
    assert r["reserved"] is True
    assert r["live"] is True
    assert r["ptr_registered"] is True


def test_audit_record_missing_ptr():
    hostname = "myhost.lan"
    ip = "192.168.1.100"
    result = _capture_audit(
        unbound_list_local_data={hostname: [f"{hostname}. 300 IN A {ip}"]},
        query_kea_reservations=[
            [{"hostname": hostname, "ip": ip, "ipv6": None}],
            KeaServiceUnavailableError("off"),
        ],
        query_kea_leases=[[], KeaServiceUnavailableError("off")],
    )
    r = next(r for r in result["records"] if r["hostname"] == hostname)
    assert r["status"] == "missing-PTR"
    assert r["ptr_registered"] is False


def test_audit_record_stale_unbound_only():
    hostname = "ghost.lan"
    ip = "192.168.1.99"
    result = _capture_audit(
        unbound_list_local_data={hostname: [f"{hostname}. 300 IN A {ip}"]},
        query_kea_reservations=[[], KeaServiceUnavailableError("off")],
        query_kea_leases=[[], KeaServiceUnavailableError("off")],
    )
    assert result["complete"] is True
    r = next(r for r in result["records"] if r["hostname"] == hostname)
    assert r["status"] == "stale"


def test_audit_record_static_from_host_entries():
    hostname = "static-host.lan"
    ip = "192.168.1.50"
    result = _capture_audit(
        read_host_entries={hostname: [f'local-data: "{hostname}. 3600 IN A {ip}"']},
        query_kea_reservations=[[], KeaServiceUnavailableError("off")],
        query_kea_leases=[[], KeaServiceUnavailableError("off")],
    )
    r = next((r for r in result["records"] if r["hostname"] == hostname), None)
    assert r is not None
    assert r["status"] == "static"
    assert r["override"] is True


def test_audit_unknown_status_when_incomplete():
    hostname = "ghost.lan"
    ip = "192.168.1.99"

    def raise_unavail(*a, **kw):
        raise KeaUnavailableError("gone")

    result = _capture_audit(
        unbound_list_local_data={hostname: [f"{hostname}. 300 IN A {ip}"]},
        query_kea_reservations=raise_unavail,
        query_kea_leases=raise_unavail,
    )
    assert result["complete"] is False
    r = next(r for r in result["records"] if r["hostname"] == hostname)
    assert r["status"] == "unknown"


# ── orphaned_ptrs ─────────────────────────────────────────────────────────────

def test_audit_orphaned_ptr_detected():
    ptr = "99.1.168.192.in-addr.arpa"
    result = _capture_audit(
        unbound_list_local_data={ptr: [f"{ptr}. 300 IN PTR ghost.lan."]},
        query_kea_reservations=[[], KeaServiceUnavailableError("off")],
        query_kea_leases=[[], KeaServiceUnavailableError("off")],
    )
    assert len(result["orphaned_ptrs"]) == 1
    o = result["orphaned_ptrs"][0]
    assert o["ptr_name"] == ptr
    assert o["status"] == "orphaned-PTR"


# ── PTR state ─────────────────────────────────────────────────────────────────

def test_audit_ptr_state_correct():
    hostname = "myhost.lan"
    ip = "192.168.1.5"
    ptr = "5.1.168.192.in-addr.arpa"
    result = _capture_audit(
        unbound_list_local_data={
            hostname: [f"{hostname}. 300 IN A {ip}"],
            ptr: [f"{ptr}. 300 IN PTR {hostname}."],
        },
        query_kea_reservations=[
            [{"hostname": hostname, "ip": ip, "ipv6": None}],
            KeaServiceUnavailableError("off"),
        ],
        query_kea_leases=[[], KeaServiceUnavailableError("off")],
    )
    r = next(r for r in result["records"] if r["hostname"] == hostname)
    assert r["ptr_state"] == "correct"


def test_audit_ptr_state_wrong():
    hostname = "myhost.lan"
    ip = "192.168.1.5"
    ptr = "5.1.168.192.in-addr.arpa"
    result = _capture_audit(
        unbound_list_local_data={
            hostname: [f"{hostname}. 300 IN A {ip}"],
            ptr: [f"{ptr}. 300 IN PTR otherhost.lan."],
        },
        query_kea_reservations=[
            [{"hostname": hostname, "ip": ip, "ipv6": None}],
            KeaServiceUnavailableError("off"),
        ],
        query_kea_leases=[[], KeaServiceUnavailableError("off")],
    )
    r = next(r for r in result["records"] if r["hostname"] == hostname)
    assert r["ptr_state"] == "wrong"


def test_audit_json_output_has_required_keys():
    result = _capture_audit(
        query_kea_reservations=[[], KeaServiceUnavailableError("off")],
        query_kea_leases=[[], KeaServiceUnavailableError("off")],
    )
    for key in ("complete", "kea_error", "records", "orphaned_ptrs", "ptr_records"):
        assert key in result, f"Missing key: {key}"
