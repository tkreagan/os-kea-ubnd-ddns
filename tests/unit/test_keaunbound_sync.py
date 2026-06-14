# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit tests for lib/keaubnd_sync.py.

Covers: is_sane_name, qualify_hostname, reverse_ptr, is_ptr_name,
read_host_entries, is_in_host_entries, find_stale_records,
unbound_list_local_data, query_kea_reservations, query_kea_leases.
"""

from __future__ import annotations

import time
import unittest.mock as mock

import pytest

from lib import keaubnd_sync
from lib.keaubnd_sync import (
    KeaServiceUnavailableError,
    KeaUnavailableError,
    _arpa_to_ip,
    find_stale_records,
    get_synthesize_ptr,
    ip_covered_by_d2_reverse,
    is_in_host_entries,
    is_ptr_name,
    is_sane_name,
    qualify_hostname,
    query_kea_leases,
    query_kea_reservations,
    read_d2_reverse_zones,
    read_host_entries,
    reverse_ptr,
    unbound_list_local_data,
)

pytestmark = pytest.mark.unit


# ── is_sane_name ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,expect", [
    ("myhost.lan",              True),
    ("foo-bar.lan",             True),
    ("a.b.c.d",                 True),
    ("x1.example.com",          True),
    ("a" * 63 + ".lan",         True),   # 63-char label is ok
    # all-label validation: invalid chars in non-first labels
    ("valid.evil!label.lan",    False),
    ("valid._svc.lan",          False),
    ("valid.bad-.lan",          False),
    ("valid.-bad.lan",          False),
    ("a" * 64 + ".lan",         False),  # 64-char label exceeds RFC 1035 max
    # reserved / nonsense
    ("",                        False),
    (".",                       False),
    ("localhost",               False),
    ("localdomain",             False),
    # all-numeric
    ("192.168.1.1",             False),
    ("10.0.0.1",                False),
    # invalid first label
    ("-bad.lan",                False),
    ("_svc.lan",                False),
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
    monkeypatch.setattr(keaubnd_sync, "HOST_ENTRIES", str(host_entries_path))
    entries = read_host_entries()
    assert "router.lan" in entries
    assert "static-host.lan" in entries


def test_read_host_entries_ptr_by_ip(host_entries_path, monkeypatch):
    monkeypatch.setattr(keaubnd_sync, "HOST_ENTRIES", str(host_entries_path))
    entries = read_host_entries()
    assert "192.168.1.1" in entries


def test_read_host_entries_missing_file_returns_empty(monkeypatch):
    monkeypatch.setattr(keaubnd_sync, "HOST_ENTRIES", "/nonexistent/file.conf")
    assert read_host_entries() == {}


def test_read_host_entries_empty_file(tmp_path, monkeypatch):
    f = tmp_path / "he.conf"
    f.write_text("")
    monkeypatch.setattr(keaubnd_sync, "HOST_ENTRIES", str(f))
    assert read_host_entries() == {}


def test_read_host_entries_skips_comments(tmp_path, monkeypatch):
    f = tmp_path / "he.conf"
    f.write_text("# this is a comment\n")
    monkeypatch.setattr(keaubnd_sync, "HOST_ENTRIES", str(f))
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


@mock.patch("lib.keaubnd_sync.query_kea_api")
@mock.patch("lib.keaubnd_sync.get_system_domain", return_value="lan")
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


@mock.patch("lib.keaubnd_sync.query_kea_api")
@mock.patch("lib.keaubnd_sync.get_system_domain", return_value="lan")
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


@mock.patch("lib.keaubnd_sync.query_kea_api")
@mock.patch("lib.keaubnd_sync.get_system_domain", return_value="lan")
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


@mock.patch("lib.keaubnd_sync.query_kea_api")
@mock.patch("lib.keaubnd_sync.get_system_domain", return_value="lan")
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


@mock.patch("lib.keaubnd_sync.query_kea_api")
@mock.patch("lib.keaubnd_sync.get_system_domain", return_value="lan")
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


@mock.patch("lib.keaubnd_sync.query_kea_api")
@mock.patch("lib.keaubnd_sync.get_system_domain", return_value="lan")
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


# ── get_synthesize_ptr ────────────────────────────────────────────────────────

def test_get_synthesize_ptr_default_when_missing(tmp_path, monkeypatch):
    xml = "<opnsense><OPNsense><KeaUbnd><general></general></KeaUbnd></OPNsense></opnsense>"
    f = tmp_path / "config.xml"
    f.write_text(xml)
    monkeypatch.setattr(keaubnd_sync, "CONFIG_XML", str(f))
    assert get_synthesize_ptr() is True


def test_get_synthesize_ptr_returns_true_when_one(tmp_path, monkeypatch):
    xml = "<opnsense><OPNsense><KeaUbnd><general><synthesize_ptr>1</synthesize_ptr></general></KeaUbnd></OPNsense></opnsense>"
    f = tmp_path / "config.xml"
    f.write_text(xml)
    monkeypatch.setattr(keaubnd_sync, "CONFIG_XML", str(f))
    assert get_synthesize_ptr() is True


def test_get_synthesize_ptr_returns_false_when_zero(tmp_path, monkeypatch):
    xml = "<opnsense><OPNsense><KeaUbnd><general><synthesize_ptr>0</synthesize_ptr></general></KeaUbnd></OPNsense></opnsense>"
    f = tmp_path / "config.xml"
    f.write_text(xml)
    monkeypatch.setattr(keaubnd_sync, "CONFIG_XML", str(f))
    assert get_synthesize_ptr() is False


def test_get_synthesize_ptr_default_on_bad_xml(tmp_path, monkeypatch):
    f = tmp_path / "config.xml"
    f.write_text("not xml")
    monkeypatch.setattr(keaubnd_sync, "CONFIG_XML", str(f))
    assert get_synthesize_ptr() is True


# ── _arpa_to_ip ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,expected", [
    ("1.1.168.192.in-addr.arpa",   "192.168.1.1"),
    ("100.1.168.192.in-addr.arpa", "192.168.1.100"),
    ("1.0.0.0.ip6.arpa",           ""),   # only 4 nibbles — not a full PTR owner
    ("myhost.lan",                 ""),
    ("",                           ""),
    ("1.1.168.192.in-addr.arpa.",  "192.168.1.1"),  # trailing dot stripped
])
def test_arpa_to_ip_ipv4(name, expected):
    assert _arpa_to_ip(name) == expected


def test_arpa_to_ip_ipv6():
    # ::1 arpa form has 32 nibbles
    arpa = "1." + "0." * 31 + "ip6.arpa"
    result = _arpa_to_ip(arpa)
    assert result == "::1"


# ── read_d2_reverse_zones ─────────────────────────────────────────────────────

def test_read_d2_reverse_zones_parses(tmp_path, monkeypatch):
    conf = {
        "DhcpDdns": {
            "reverse-ddns": {
                "ddns-domains": [
                    {"name": "1.168.192.in-addr.arpa.", "dns-servers": []},
                    {"name": "2.168.192.in-addr.arpa.", "dns-servers": []},
                ]
            }
        }
    }
    import json
    f = tmp_path / "kea-dhcp-ddns.conf"
    f.write_text(json.dumps(conf))
    monkeypatch.setattr(keaubnd_sync, "D2_CONF", str(f))
    zones = read_d2_reverse_zones()
    assert "1.168.192.in-addr.arpa" in zones
    assert "2.168.192.in-addr.arpa" in zones


def test_read_d2_reverse_zones_absent_file(monkeypatch):
    monkeypatch.setattr(keaubnd_sync, "D2_CONF", "/nonexistent/kea-dhcp-ddns.conf")
    assert read_d2_reverse_zones() == set()


def test_read_d2_reverse_zones_no_reverse_domains(tmp_path, monkeypatch):
    conf = {"DhcpDdns": {"forward-ddns": {"ddns-domains": []}}}
    import json
    f = tmp_path / "kea-dhcp-ddns.conf"
    f.write_text(json.dumps(conf))
    monkeypatch.setattr(keaubnd_sync, "D2_CONF", str(f))
    assert read_d2_reverse_zones() == set()


# ── ip_covered_by_d2_reverse ──────────────────────────────────────────────────

def test_ip_covered_by_d2_reverse_v4_covered():
    zones = {"1.168.192.in-addr.arpa"}
    assert ip_covered_by_d2_reverse("192.168.1.100", zones) is True


def test_ip_covered_by_d2_reverse_v4_not_covered():
    zones = {"2.168.192.in-addr.arpa"}
    assert ip_covered_by_d2_reverse("192.168.1.100", zones) is False


def test_ip_covered_by_d2_reverse_empty_zones():
    assert ip_covered_by_d2_reverse("192.168.1.1", set()) is False


def test_ip_covered_by_d2_reverse_v6_covered():
    # 2001:db8::1 arpa: 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
    # A /32 zone would be "8.b.d.0.1.0.0.2.ip6.arpa"
    # We test with the exact /128 zone so the arpa == zone check fires.
    arpa = reverse_ptr("2001:db8::1")
    zones = {arpa}
    assert ip_covered_by_d2_reverse("2001:db8::1", zones) is True


def test_ip_covered_by_d2_reverse_invalid_ip():
    zones = {"1.168.192.in-addr.arpa"}
    assert ip_covered_by_d2_reverse("not-an-ip", zones) is False


# ── find_stale_records — synthesis-aware cleanup matrix ──────────────────────

def test_find_stale_records_synthesis_on_keeps_active_lease_ptr():
    """synthesize_ptr=True (default): PTR backed by live forward → kept."""
    unbound = _unbound_data(
        "live.lan. 300 IN A 192.168.1.10",
        "10.1.168.192.in-addr.arpa. 300 IN PTR live.lan.",
    )
    kea_pairs = {("live.lan", "192.168.1.10")}
    stale, orphans = find_stale_records(unbound, kea_pairs, {}, synthesize_ptr=True)
    assert "live.lan" not in stale
    assert "10.1.168.192.in-addr.arpa" not in orphans


def test_find_stale_records_synthesis_off_no_d2_removes_ptr():
    """synthesize_ptr=False + no D2 zone: PTR is unconditionally orphaned even with live forward."""
    unbound = _unbound_data(
        "live.lan. 300 IN A 192.168.1.10",
        "10.1.168.192.in-addr.arpa. 300 IN PTR live.lan.",
    )
    kea_pairs = {("live.lan", "192.168.1.10")}
    stale, orphans = find_stale_records(
        unbound, kea_pairs, {}, synthesize_ptr=False, d2_reverse_zones=set()
    )
    assert "live.lan" not in stale          # forward kept — Kea still backs it
    assert "10.1.168.192.in-addr.arpa" in orphans  # PTR unconditionally removed


def test_find_stale_records_synthesis_off_d2_covers_ip_keeps_ptr():
    """synthesize_ptr=False + D2 zone covers the IP: PTR is D2-managed, leave it."""
    unbound = _unbound_data(
        "live.lan. 300 IN A 192.168.1.10",
        "10.1.168.192.in-addr.arpa. 300 IN PTR live.lan.",
    )
    kea_pairs = {("live.lan", "192.168.1.10")}
    stale, orphans = find_stale_records(
        unbound, kea_pairs, {},
        synthesize_ptr=False,
        d2_reverse_zones={"1.168.192.in-addr.arpa"},
    )
    assert "10.1.168.192.in-addr.arpa" not in orphans


def test_find_stale_records_host_override_ptr_preserved_synthesis_on():
    """Host-override PTR (IP-keyed in host_entries) is never flagged regardless of synthesis."""
    unbound = _unbound_data(
        "router.lan. 300 IN A 192.168.1.1",
        "1.1.168.192.in-addr.arpa. 300 IN PTR router.lan.",
    )
    kea_pairs = set()  # not in Kea — OPNsense manages this
    # host_entries is IP-keyed for PTRs (the realistic format)
    host_entries = {
        "router.lan": ["local-data: \"router.lan. IN A 192.168.1.1\""],
        "192.168.1.1": ["local-data-ptr: \"192.168.1.1 router.lan.\""],
    }
    stale, orphans = find_stale_records(
        unbound, kea_pairs, host_entries, synthesize_ptr=True
    )
    assert "router.lan" not in stale
    assert "1.1.168.192.in-addr.arpa" not in orphans


def test_find_stale_records_host_override_ptr_preserved_synthesis_off():
    """Host-override PTR preserved even when synthesis is OFF and no D2 zone."""
    unbound = _unbound_data(
        "router.lan. 300 IN A 192.168.1.1",
        "1.1.168.192.in-addr.arpa. 300 IN PTR router.lan.",
    )
    kea_pairs = set()
    host_entries = {
        "router.lan": ["local-data: \"router.lan. IN A 192.168.1.1\""],
        "192.168.1.1": ["local-data-ptr: \"192.168.1.1 router.lan.\""],
    }
    stale, orphans = find_stale_records(
        unbound, kea_pairs, host_entries,
        synthesize_ptr=False, d2_reverse_zones=set()
    )
    assert "router.lan" not in stale
    assert "1.1.168.192.in-addr.arpa" not in orphans


def test_find_stale_records_synthesis_off_v6_removes_ptr():
    """Same rule applies for ip6.arpa PTRs."""
    v6_arpa = reverse_ptr("2001:db8::1")
    assert v6_arpa is not None
    unbound = _unbound_data(
        f"v6host.lan. 300 IN AAAA 2001:db8::1",
        f"{v6_arpa}. 300 IN PTR v6host.lan.",
    )
    kea_pairs = {("v6host.lan", "2001:db8::1")}
    stale, orphans = find_stale_records(
        unbound, kea_pairs, {}, synthesize_ptr=False, d2_reverse_zones=set()
    )
    assert "v6host.lan" not in stale
    assert v6_arpa in orphans
