# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit tests for lib/keaunbound_sync.py.

Covers: is_sane_name, qualify_hostname, reverse_ptr, is_ptr_name,
read_host_entries, is_in_host_entries, find_stale_records,
unbound_list_local_data, query_kea_reservations, query_kea_leases.
"""

from __future__ import annotations

import time
import unittest.mock as mock

import pytest

from lib import keaunbound_sync
from lib.keaunbound_sync import (
    KeaServiceUnavailableError,
    KeaUnavailableError,
    find_stale_records,
    is_in_host_entries,
    is_ptr_name,
    is_sane_name,
    qualify_hostname,
    query_kea_leases,
    query_kea_reservations,
    read_host_entries,
    reverse_ptr,
    unbound_list_local_data,
)

pytestmark = pytest.mark.unit


# ── is_sane_name ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,expect", [
    ("myhost.lan",     True),
    ("foo-bar.lan",    True),
    ("a.b.c.d",        True),
    ("",               False),
    (".",              False),
    ("localhost",      False),
    ("localdomain",    False),
    ("192.168.1.1",    False),
    ("10.0.0.1",       False),
    ("-bad.lan",       False),
    ("_svc.lan",       False),
])
def test_is_sane_name(name, expect):
    assert is_sane_name(name) is expect


# ── qualify_hostname ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("hostname,suffix,expected", [
    ("myhost",        "lan",  "myhost.lan"),
    ("myhost.lan",    "lan",  "myhost.lan"),    # already qualified — leave as-is
    ("myhost.lan.",   "lan",  "myhost.lan"),    # strip trailing dot
    ("myhost",        "",     "myhost"),        # no suffix → bare name
    ("",              "lan",  ""),              # empty hostname
    ("myhost",        "home.lan", "myhost.home.lan"),
])
def test_qualify_hostname(hostname, suffix, expected):
    assert qualify_hostname(hostname, suffix) == expected


# ── reverse_ptr ───────────────────────────────────────────────────────────────

def test_reverse_ptr_ipv4():
    assert reverse_ptr("192.168.1.1") == "1.1.168.192.in-addr.arpa"


def test_reverse_ptr_ipv6():
    result = reverse_ptr("::1")
    assert result.endswith(".ip6.arpa")


def test_reverse_ptr_invalid():
    assert reverse_ptr("not-an-ip") is None
    assert reverse_ptr("") is None


# ── is_ptr_name ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,expect", [
    ("1.168.192.in-addr.arpa",  True),
    ("1.0.0.0.ip6.arpa",        True),
    ("myhost.lan",               False),
    ("",                         False),
])
def test_is_ptr_name(name, expect):
    assert is_ptr_name(name) is expect


# ── read_host_entries ─────────────────────────────────────────────────────────

def test_read_host_entries_parses_fixture(host_entries_path, monkeypatch):
    monkeypatch.setattr(keaunbound_sync, "HOST_ENTRIES", str(host_entries_path))
    entries = read_host_entries()
    assert "router.lan" in entries
    assert "static-host.lan" in entries


def test_read_host_entries_ptr_by_ip(host_entries_path, monkeypatch):
    monkeypatch.setattr(keaunbound_sync, "HOST_ENTRIES", str(host_entries_path))
    entries = read_host_entries()
    assert "192.168.1.1" in entries


def test_read_host_entries_missing_file_returns_empty(monkeypatch):
    monkeypatch.setattr(keaunbound_sync, "HOST_ENTRIES", "/nonexistent/file.conf")
    assert read_host_entries() == {}


def test_read_host_entries_empty_file(tmp_path, monkeypatch):
    f = tmp_path / "he.conf"
    f.write_text("")
    monkeypatch.setattr(keaunbound_sync, "HOST_ENTRIES", str(f))
    assert read_host_entries() == {}


def test_read_host_entries_skips_comments(tmp_path, monkeypatch):
    f = tmp_path / "he.conf"
    f.write_text("# this is a comment\n")
    monkeypatch.setattr(keaunbound_sync, "HOST_ENTRIES", str(f))
    assert read_host_entries() == {}


# ── is_in_host_entries ────────────────────────────────────────────────────────

def test_is_in_host_entries_present():
    entries = {"router.lan": ["local-data: ..."], "192.168.1.1": ["local-data-ptr: ..."]}
    assert is_in_host_entries("router.lan", entries) is True


def test_is_in_host_entries_absent():
    entries = {"router.lan": ["local-data: ..."]}
    assert is_in_host_entries("other.lan", entries) is False


# ── find_stale_records ────────────────────────────────────────────────────────

def _unbound_data(*records):
    """Build a minimal unbound_data dict from 'name. TTL IN TYPE rdata' strings."""
    data = {}
    for line in records:
        parts = line.split()
        name = parts[0].rstrip(".")
        data.setdefault(name, []).append(line)
    return data


def test_find_stale_records_identifies_stale_forward():
    unbound = _unbound_data("ghost.lan. 300 IN A 192.168.1.99")
    kea_pairs = set()  # nothing in Kea
    host_entries = {}
    stale, orphans = find_stale_records(unbound, kea_pairs, host_entries)
    assert "ghost.lan" in stale


def test_find_stale_records_keeps_kea_backed():
    unbound = _unbound_data("live.lan. 300 IN A 192.168.1.10")
    kea_pairs = {("live.lan", "192.168.1.10")}
    host_entries = {}
    stale, orphans = find_stale_records(unbound, kea_pairs, host_entries)
    assert "live.lan" not in stale


def test_find_stale_records_respects_host_entries():
    unbound = _unbound_data("static-host.lan. 300 IN A 192.168.1.50")
    kea_pairs = set()
    host_entries = {"static-host.lan": ["local-data: ..."]}
    stale, orphans = find_stale_records(unbound, kea_pairs, host_entries)
    assert "static-host.lan" not in stale


def test_find_stale_records_per_pair_not_per_ip():
    """IP in Kea for a DIFFERENT host should not save this host's record."""
    unbound = _unbound_data("host-a.lan. 300 IN A 10.0.0.1")
    # host-b has IP 10.0.0.1 — but host-a doesn't
    kea_pairs = {("host-b.lan", "10.0.0.1")}
    host_entries = {}
    stale, orphans = find_stale_records(unbound, kea_pairs, host_entries)
    assert "host-a.lan" in stale


def test_find_stale_records_orphaned_ptr():
    unbound = _unbound_data(
        "99.1.168.192.in-addr.arpa. 300 IN PTR ghost.lan.",
    )
    kea_pairs = set()
    host_entries = {}
    stale, orphans = find_stale_records(unbound, kea_pairs, host_entries)
    assert "99.1.168.192.in-addr.arpa" in orphans


def test_find_stale_records_ptr_backed_by_live_forward():
    unbound = _unbound_data(
        "live.lan. 300 IN A 192.168.1.10",
        "10.1.168.192.in-addr.arpa. 300 IN PTR live.lan.",
    )
    kea_pairs = {("live.lan", "192.168.1.10")}
    host_entries = {}
    stale, orphans = find_stale_records(unbound, kea_pairs, host_entries)
    assert "live.lan" not in stale
    assert "10.1.168.192.in-addr.arpa" not in orphans


def test_find_stale_records_ptr_becomes_orphan_when_forward_stale():
    unbound = _unbound_data(
        "ghost.lan. 300 IN A 192.168.1.99",
        "99.1.168.192.in-addr.arpa. 300 IN PTR ghost.lan.",
    )
    kea_pairs = set()
    host_entries = {}
    stale, orphans = find_stale_records(unbound, kea_pairs, host_entries)
    assert "ghost.lan" in stale
    assert "99.1.168.192.in-addr.arpa" in orphans


def test_find_stale_records_empty_unbound():
    stale, orphans = find_stale_records({}, set(), {})
    assert stale == set()
    assert orphans == set()


# ── unbound_list_local_data ───────────────────────────────────────────────────

@mock.patch("subprocess.run")
def test_unbound_list_local_data_parses(mock_run):
    mock_run.return_value = mock.Mock(
        returncode=0,
        stdout=(
            "myhost.lan. 300 IN A 192.168.1.5\n"
            "5.1.168.192.in-addr.arpa. 300 IN PTR myhost.lan.\n"
        ),
    )
    data = unbound_list_local_data()
    assert "myhost.lan" in data
    assert "5.1.168.192.in-addr.arpa" in data


@mock.patch("subprocess.run")
def test_unbound_list_local_data_returns_empty_on_error(mock_run):
    mock_run.return_value = mock.Mock(returncode=1, stdout="", stderr="error")
    assert unbound_list_local_data() == {}


# ── query_kea_reservations ────────────────────────────────────────────────────

def _mock_kea_config_response(reservations, suffix="lan"):
    return {
        "result": 0,
        "arguments": {
            "Dhcp4": {
                "ddns-qualifying-suffix": suffix,
                "subnet4": [{"id": 1, "subnet": "192.168.1.0/24",
                              "reservations": reservations}],
            }
        }
    }


@mock.patch("lib.keaunbound_sync.query_kea_api")
@mock.patch("lib.keaunbound_sync.get_system_domain", return_value="lan")
def test_query_kea_reservations_basic(mock_dom, mock_api):
    mock_api.return_value = _mock_kea_config_response([
        {"hw-address": "aa:bb:cc:00:00:01",
         "ip-address": "192.168.1.100",
         "hostname": "myhost"},
    ])
    reservations = query_kea_reservations("dhcp4")
    assert len(reservations) == 1
    assert reservations[0]["hostname"] == "myhost.lan"
    assert reservations[0]["ip"] == "192.168.1.100"


@mock.patch("lib.keaunbound_sync.query_kea_api")
@mock.patch("lib.keaunbound_sync.get_system_domain", return_value="lan")
def test_query_kea_reservations_skips_blank_hostname(mock_dom, mock_api):
    mock_api.return_value = _mock_kea_config_response([
        {"hw-address": "aa:bb:cc:00:00:01", "ip-address": "192.168.1.100", "hostname": ""},
    ])
    reservations = query_kea_reservations("dhcp4")
    assert reservations == []


# ── query_kea_leases ──────────────────────────────────────────────────────────

def _mock_lease_config():
    return {
        "result": 0,
        "arguments": {
            "Dhcp4": {
                "ddns-qualifying-suffix": "lan",
                "subnet4": [{"id": 1, "subnet": "192.168.1.0/24"}],
            }
        }
    }


def _mock_lease_response(leases):
    return {"result": 0, "arguments": {"leases": leases}}


@mock.patch("lib.keaunbound_sync.query_kea_api")
@mock.patch("lib.keaunbound_sync.get_system_domain", return_value="lan")
def test_query_kea_leases_active(mock_dom, mock_api):
    future = int(time.time()) + 3600
    mock_api.side_effect = [
        _mock_lease_config(),
        _mock_lease_response([{
            "hostname": "client",
            "ip-address": "192.168.1.200",
            "state": 0,
            "expire": future,
            "subnet-id": 1,
        }]),
    ]
    leases = query_kea_leases("dhcp4")
    assert len(leases) == 1
    assert leases[0]["hostname"] == "client.lan"
    assert leases[0]["ip"] == "192.168.1.200"
    assert leases[0]["expires"] == future


@mock.patch("lib.keaunbound_sync.query_kea_api")
@mock.patch("lib.keaunbound_sync.get_system_domain", return_value="lan")
def test_query_kea_leases_skips_declined(mock_dom, mock_api):
    future = int(time.time()) + 3600
    mock_api.side_effect = [
        _mock_lease_config(),
        _mock_lease_response([{
            "hostname": "declined",
            "ip-address": "192.168.1.201",
            "state": 1,  # declined
            "expire": future,
            "subnet-id": 1,
        }]),
    ]
    leases = query_kea_leases("dhcp4")
    assert leases == []


@mock.patch("lib.keaunbound_sync.query_kea_api")
@mock.patch("lib.keaunbound_sync.get_system_domain", return_value="lan")
def test_query_kea_leases_skips_expired(mock_dom, mock_api):
    past = int(time.time()) - 100
    mock_api.side_effect = [
        _mock_lease_config(),
        _mock_lease_response([{
            "hostname": "expired",
            "ip-address": "192.168.1.202",
            "state": 0,
            "expire": past,
            "subnet-id": 1,
        }]),
    ]
    leases = query_kea_leases("dhcp4")
    assert leases == []


@mock.patch("lib.keaunbound_sync.query_kea_api")
@mock.patch("lib.keaunbound_sync.get_system_domain", return_value="lan")
def test_query_kea_leases_infinite_expiry(mock_dom, mock_api):
    mock_api.side_effect = [
        _mock_lease_config(),
        _mock_lease_response([{
            "hostname": "permanent",
            "ip-address": "192.168.1.203",
            "state": 0,
            "expire": 0,  # infinite
            "subnet-id": 1,
        }]),
    ]
    leases = query_kea_leases("dhcp4")
    assert len(leases) == 1
    assert leases[0]["expires"] > int(time.time())
