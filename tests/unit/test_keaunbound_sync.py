# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit tests for lib/keaubnd_sync.py.

Covers: is_sane_name, qualify_hostname, reverse_ptr, is_ptr_name,
read_host_entries, is_in_host_entries, find_stale_records,
unbound_list_local_data, query_kea_reservations, query_kea_leases.
"""

from __future__ import annotations

import fcntl
import signal
import threading
import time
import unittest.mock as mock

import pytest

from lib import keaubnd_sync
from lib.keaubnd_sync import (
    KeaServiceUnavailableError,
    KeaUnavailableError,
    _arpa_to_ip,
    compute_magic_suffix,
    discover_stale,
    duid_extract_mac,
    find_stale_records,
    ip_covered_by_d2_reverse,
    is_in_host_entries,
    is_laa,
    is_ptr_name,
    normalize_hostname,
    protected_magic_from_state,
    qualify_hostname,
    query_kea_leases,
    query_kea_reservations,
    read_d2_reverse_zones,
    read_host_entries,
    reverse_ptr,
    unbound_list_local_data,
)

pytestmark = pytest.mark.unit


# ── normalize_hostname ────────────────────────────────────────────────────────
# is_sane_name was removed; validate via normalize_hostname (returns None on reject).

@pytest.mark.parametrize("name,expect_valid", [
    ("myhost.lan",              True),
    ("foo-bar.lan",             True),
    ("a.b.c.d",                 True),
    ("x1.example.com",          True),
    ("a" * 63 + ".lan",         True),
    # all-label validation: invalid chars in non-first labels
    ("valid.evil!label.lan",    False),
    ("valid._svc.lan",          False),
    ("valid.bad-.lan",          False),
    ("valid.-bad.lan",          False),
    ("a" * 64 + ".lan",         False),
    # reserved / nonsense
    ("",                        False),
    (".",                       False),
    ("localhost",               False),
    ("localdomain",             False),
    # all-numeric (IP-like names)
    ("192.168.1.1",             False),
    ("10.0.0.1",                False),
    # invalid first label
    ("-bad.lan",                False),
    ("_svc.lan",                False),
])
def test_normalize_hostname_validity(name, expect_valid):
    result = normalize_hostname(name)
    if expect_valid:
        assert result is not None, f"expected valid result for {name!r}, got None"
    else:
        assert result is None, f"expected None for {name!r}, got {result!r}"


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
    monkeypatch.setattr(keaubnd_sync._rt, "get_host_entries", lambda: str(host_entries_path))
    entries = read_host_entries()
    assert "router.lan" in entries
    assert "static-host.lan" in entries


def test_read_host_entries_ptr_by_ip(host_entries_path, monkeypatch):
    monkeypatch.setattr(keaubnd_sync._rt, "get_host_entries", lambda: str(host_entries_path))
    entries = read_host_entries()
    assert "192.168.1.1" in entries


def test_read_host_entries_missing_file_returns_empty(monkeypatch):
    monkeypatch.setattr(keaubnd_sync._rt, "get_host_entries", lambda: "/nonexistent/file.conf")
    assert read_host_entries() == {}


def test_read_host_entries_empty_file(tmp_path, monkeypatch):
    f = tmp_path / "he.conf"
    f.write_text("")
    monkeypatch.setattr(keaubnd_sync._rt, "get_host_entries", lambda: str(f))
    assert read_host_entries() == {}


def test_read_host_entries_skips_comments(tmp_path, monkeypatch):
    f = tmp_path / "he.conf"
    f.write_text("# this is a comment\n")
    monkeypatch.setattr(keaubnd_sync._rt, "get_host_entries", lambda: str(f))
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
    assert any(n == "ghost.lan" for n, _ in stale)


def test_find_stale_records_keeps_kea_backed():
    unbound = _unbound_data("live.lan. 300 IN A 192.168.1.10")
    kea_pairs = {("live.lan", "192.168.1.10")}
    host_entries = {}
    stale, orphans = find_stale_records(unbound, kea_pairs, host_entries)
    assert not any(n == "live.lan" for n, _ in stale)


def test_find_stale_records_respects_host_entries():
    unbound = _unbound_data("static-host.lan. 300 IN A 192.168.1.50")
    kea_pairs = set()
    host_entries = {"static-host.lan": ["local-data: ..."]}
    stale, orphans = find_stale_records(unbound, kea_pairs, host_entries)
    assert not any(n == "static-host.lan" for n, _ in stale)


def test_find_stale_records_per_pair_not_per_ip():
    """IP in Kea for a DIFFERENT host should not save this host's record."""
    unbound = _unbound_data("host-a.lan. 300 IN A 10.0.0.1")
    # host-b has IP 10.0.0.1 — but host-a doesn't
    kea_pairs = {("host-b.lan", "10.0.0.1")}
    host_entries = {}
    stale, orphans = find_stale_records(unbound, kea_pairs, host_entries)
    assert any(n == "host-a.lan" for n, _ in stale)


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
    assert not any(n == "live.lan" for n, _ in stale)
    assert "10.1.168.192.in-addr.arpa" not in orphans


def test_find_stale_records_ptr_becomes_orphan_when_forward_stale():
    unbound = _unbound_data(
        "ghost.lan. 300 IN A 192.168.1.99",
        "99.1.168.192.in-addr.arpa. 300 IN PTR ghost.lan.",
    )
    kea_pairs = set()
    host_entries = {}
    stale, orphans = find_stale_records(unbound, kea_pairs, host_entries)
    assert any(n == "ghost.lan" for n, _ in stale)
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
    monkeypatch.setattr(keaubnd_sync._rt, "get_kea_conf", lambda svc: str(f) if svc == "d2" else None)
    zones = read_d2_reverse_zones()
    assert "1.168.192.in-addr.arpa" in zones
    assert "2.168.192.in-addr.arpa" in zones


def test_read_d2_reverse_zones_absent_file(monkeypatch):
    monkeypatch.setattr(keaubnd_sync._rt, "get_kea_conf", lambda svc: "/nonexistent/kea-dhcp-ddns.conf" if svc == "d2" else None)
    assert read_d2_reverse_zones() == set()


def test_read_d2_reverse_zones_no_reverse_domains(tmp_path, monkeypatch):
    conf = {"DhcpDdns": {"forward-ddns": {"ddns-domains": []}}}
    import json
    f = tmp_path / "kea-dhcp-ddns.conf"
    f.write_text(json.dumps(conf))
    monkeypatch.setattr(keaubnd_sync._rt, "get_kea_conf", lambda svc: str(f) if svc == "d2" else None)
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
    assert not any(n == "live.lan" for n, _ in stale)
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
    assert not any(n == "live.lan" for n, _ in stale)          # forward kept — Kea still backs it
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
    assert not any(n == "router.lan" for n, _ in stale)
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
    assert not any(n == "router.lan" for n, _ in stale)
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
    assert not any(n == "v6host.lan" for n, _ in stale)
    assert v6_arpa in orphans


# ── protected_magic_from_state ────────────────────────────────────────────────

def _magic_state(fqdn_key: str, ip: str, fqdn: str, source: str) -> dict:
    """Build a magic state dict. fqdn_key must be the full FQDN (e.g. 'laptop.lan'),
    not a bare label — magic state keys changed to full FQDNs in Finding 2 fix."""
    return {"magic_names": {fqdn_key: [{"magic_fqdn": fqdn, "ip": ip, "source": source}]}}


def test_protected_magic_static_always_protected():
    state = _magic_state("laptop.lan", "192.168.1.5", "laptop-mAABBCC.lan", "static")
    protected = protected_magic_from_state(state, kea_pairs=set())
    assert "laptop-maabbcc.lan" in protected


def test_protected_magic_override_always_protected():
    state = _magic_state("laptop.lan", "192.168.1.5", "laptop-mAABBCC.lan", "override")
    protected = protected_magic_from_state(state, kea_pairs=set())
    assert "laptop-maabbcc.lan" in protected


def test_protected_magic_lease_protected_when_active():
    state = _magic_state("laptop.lan", "192.168.1.5", "laptop-mAABBCC.lan", "lease")
    kea_pairs = {("laptop.lan", "192.168.1.5")}
    protected = protected_magic_from_state(state, kea_pairs=kea_pairs)
    assert "laptop-maabbcc.lan" in protected


def test_protected_magic_lease_not_protected_when_expired():
    state = _magic_state("laptop.lan", "192.168.1.5", "laptop-mAABBCC.lan", "lease")
    protected = protected_magic_from_state(state, kea_pairs=set())
    assert "laptop-maabbcc.lan" not in protected


def test_protected_magic_empty_state():
    assert protected_magic_from_state({}, kea_pairs=set()) == set()


# ── discover_stale ────────────────────────────────────────────────────────────

@mock.patch.object(keaubnd_sync, "find_stale_records", return_value=(set(), set()))
@mock.patch.object(keaubnd_sync, "protected_magic_from_state", return_value=set())
@mock.patch.object(keaubnd_sync, "read_magic_state", return_value={})
@mock.patch.object(keaubnd_sync, "read_d2_reverse_zones", return_value={"1.168.192.in-addr.arpa"})
@mock.patch.object(keaubnd_sync, "collect_kea_pairs", return_value=set())
@mock.patch.object(keaubnd_sync, "unbound_list_local_data", return_value={})
@mock.patch.object(keaubnd_sync, "read_host_entries", return_value={})
def test_discover_stale_passes_d2_zones_to_find_stale(
        mock_rhe, mock_ld, mock_ckp, mock_rdz, mock_rms, mock_pms, mock_fsr):
    discover_stale(synthesize_ptr=True)
    _, kwargs = mock_fsr.call_args
    assert kwargs.get("d2_reverse_zones") == {"1.168.192.in-addr.arpa"}


@mock.patch.object(keaubnd_sync, "find_stale_records", return_value=(set(), set()))
@mock.patch.object(keaubnd_sync, "protected_magic_from_state", return_value=set())
@mock.patch.object(keaubnd_sync, "read_magic_state", return_value={})
@mock.patch.object(keaubnd_sync, "read_d2_reverse_zones", return_value=set())
@mock.patch.object(keaubnd_sync, "collect_kea_pairs", return_value=set())
@mock.patch.object(keaubnd_sync, "unbound_list_local_data", return_value={})
@mock.patch.object(keaubnd_sync, "read_host_entries", return_value={})
def test_discover_stale_passes_synthesize_ptr(
        mock_rhe, mock_ld, mock_ckp, mock_rdz, mock_rms, mock_pms, mock_fsr):
    discover_stale(synthesize_ptr=False)
    _, kwargs = mock_fsr.call_args
    assert kwargs.get("synthesize_ptr") is False


@mock.patch.object(keaubnd_sync, "read_d2_reverse_zones", return_value=set())
@mock.patch.object(keaubnd_sync, "collect_kea_pairs",
                   side_effect=KeaUnavailableError("down"))
@mock.patch.object(keaubnd_sync, "unbound_list_local_data", return_value={})
@mock.patch.object(keaubnd_sync, "read_host_entries", return_value={})
def test_discover_stale_propagates_kea_unavailable(mock_rhe, mock_ld, mock_ckp, mock_rdz):
    with pytest.raises(KeaUnavailableError):
        discover_stale()


@mock.patch.object(keaubnd_sync, "find_stale_records")
@mock.patch.object(keaubnd_sync, "protected_magic_from_state", return_value={"laptop-m112233.lan"})
@mock.patch.object(keaubnd_sync, "read_magic_state", return_value={})
@mock.patch.object(keaubnd_sync, "read_d2_reverse_zones", return_value=set())
@mock.patch.object(keaubnd_sync, "collect_kea_pairs", return_value=set())
@mock.patch.object(keaubnd_sync, "unbound_list_local_data", return_value={})
@mock.patch.object(keaubnd_sync, "read_host_entries", return_value={})
def test_discover_stale_passes_protected_magic(
        mock_rhe, mock_ld, mock_ckp, mock_rdz, mock_rms, mock_pms, mock_fsr):
    mock_fsr.return_value = (set(), set())
    discover_stale()
    _, kwargs = mock_fsr.call_args
    assert kwargs.get("protected_magic_fqdns") == {"laptop-m112233.lan"}


# ── unbound_mutation_lock — bounded-wait (Phase C) ───────────────────────────

def test_lock_yields_when_uncontested(tmp_path, monkeypatch):
    """Lock acquired immediately when uncontested; body runs without exception."""
    monkeypatch.setattr(keaubnd_sync, "MUTATION_LOCK_DIR", str(tmp_path))
    monkeypatch.setattr(keaubnd_sync, "MUTATION_LOCK_PATH", str(tmp_path / "test.lock"))
    reached = []
    with keaubnd_sync.unbound_mutation_lock(blocking=True, timeout_secs=2):
        reached.append(True)
    assert reached == [True]


def test_lock_timeout_raises_timeout_error(tmp_path, monkeypatch):
    """When the lock is held by another fd, a short timeout raises TimeoutError."""
    monkeypatch.setattr(keaubnd_sync, "MUTATION_LOCK_DIR", str(tmp_path))
    lock_path = str(tmp_path / "test.lock")
    monkeypatch.setattr(keaubnd_sync, "MUTATION_LOCK_PATH", lock_path)

    # Hold the lock on a separate fd so our attempt blocks.
    holder = open(lock_path, "w")
    fcntl.flock(holder, fcntl.LOCK_EX)
    try:
        with pytest.raises(TimeoutError):
            with keaubnd_sync.unbound_mutation_lock(blocking=True, timeout_secs=0.1):
                pass
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN)
        holder.close()


def test_lock_timeout_restores_signal_handler(tmp_path, monkeypatch):
    """After a timeout, SIGALRM handler is restored to its pre-call value."""
    monkeypatch.setattr(keaubnd_sync, "MUTATION_LOCK_DIR", str(tmp_path))
    lock_path = str(tmp_path / "test.lock")
    monkeypatch.setattr(keaubnd_sync, "MUTATION_LOCK_PATH", lock_path)

    sentinel = object()
    original = signal.signal(signal.SIGALRM, lambda s, f: sentinel)

    holder = open(lock_path, "w")
    fcntl.flock(holder, fcntl.LOCK_EX)
    try:
        try:
            with keaubnd_sync.unbound_mutation_lock(blocking=True, timeout_secs=0.1):
                pass
        except TimeoutError:
            pass
        restored = signal.getsignal(signal.SIGALRM)
        assert restored is original or callable(restored), \
            "SIGALRM handler must be restored after timeout"
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN)
        holder.close()
        signal.signal(signal.SIGALRM, signal.SIG_DFL)


def test_lock_float_timeout_accepted(tmp_path, monkeypatch):
    """float timeout_secs is accepted (no TypeError from signal.alarm's int-only API)."""
    monkeypatch.setattr(keaubnd_sync, "MUTATION_LOCK_DIR", str(tmp_path))
    monkeypatch.setattr(keaubnd_sync, "MUTATION_LOCK_PATH", str(tmp_path / "test.lock"))
    # 0.5s float must not raise TypeError — that was the alarm() limitation
    with keaubnd_sync.unbound_mutation_lock(blocking=True, timeout_secs=0.5):
        pass  # acquired immediately; just verifying no TypeError


def test_lock_spurious_sigalrm_after_acquired(tmp_path, monkeypatch):
    """SIGALRM delivered in the tiny window after flock returns but before
    setitimer(0) cancels the timer must be suppressed (acquired=True), not
    raise TimeoutError. Finding H.

    Simulated by injecting a SIGALRM delivery inside the setitimer(0) call —
    at that moment the _alarm_handler closure is still installed and acquired=True."""
    import os as _os
    monkeypatch.setattr(keaubnd_sync, "MUTATION_LOCK_DIR", str(tmp_path))
    monkeypatch.setattr(keaubnd_sync, "MUTATION_LOCK_PATH", str(tmp_path / "test.lock"))

    real_setitimer = signal.setitimer

    def inject_alarm_on_cancel(which, seconds, interval=0.0):
        # Simulate a queued SIGALRM firing just as we try to cancel it.
        if which == signal.ITIMER_REAL and seconds == 0:
            _os.kill(_os.getpid(), signal.SIGALRM)
        return real_setitimer(which, seconds, interval)

    reached = []
    with mock.patch("signal.setitimer", side_effect=inject_alarm_on_cancel):
        # Must NOT raise TimeoutError despite the injected SIGALRM —
        # because acquired=True when the alarm fires during cancel.
        with keaubnd_sync.unbound_mutation_lock(blocking=True, timeout_secs=2):
            reached.append(True)
    assert reached == [True], "lock body must be reached without TimeoutError"


# ── is_laa ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("mac,expect", [
    ("02:00:00:00:00:01", True),    # U/L bit set
    ("06:00:00:00:00:01", True),    # multicast+LAA bits both set
    ("00:11:22:33:44:55", False),   # globally unique
    ("aa:bb:cc:dd:ee:ff", True),    # LAA bit set (0xaa & 0x02)
    ("de:ad:be:ef:00:01", True),    # 0xde = 0b11011110, U/L bit set
    ("0c:00:00:00:00:01", False),   # 0x0c = 0b00001100, U/L bit clear
    ("001122334455",      False),   # bare hex, globally unique
    ("021122334455",      True),    # bare hex, LAA bit set
    ("",                  False),   # empty
    ("zz:bad",            False),   # invalid hex
])
def test_is_laa(mac, expect):
    assert is_laa(mac) == expect


# ── duid_extract_mac ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("duid,expected_mac", [
    # DUID-LL (type 3), hw-type 1 (Ethernet)
    ("00:03:00:01:de:ad:be:ef:00:01", "de:ad:be:ef:00:01"),
    # DUID-LLT (type 1), hw-type 1 (Ethernet) — 4-byte time 0x12345678
    ("00:01:00:01:12:34:56:78:aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"),
    # DUID-LL (type 3), hw-type 6 (IEEE 802)
    ("00:03:00:06:02:00:5e:10:20:30", "02:00:5e:10:20:30"),
    # DUID-LLT (type 1), hw-type 6 (IEEE 802)
    ("00:01:00:06:00:00:00:00:02:00:5e:10:20:30", "02:00:5e:10:20:30"),
    # DUID-EN (type 2) — no embedded MAC
    ("00:02:00:00:09:bf:00:01:02:03", None),
    # DUID-UUID (type 4) — no embedded MAC
    ("00:04:00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f", None),
    # hw-type 7 (ArcNet) — not an Ethernet family type
    ("00:03:00:07:aa:bb:cc:dd:ee:ff", None),
    # too short to contain a MAC
    ("00:03:00:01:aa:bb",             None),
    # completely malformed
    ("not-hex",                       None),
    # bare hex string (no colons) — DUID-LL, hw-type 1
    ("000300010a0b0c0d0e0f",          "0a:0b:0c:0d:0e:0f"),
])
def test_duid_extract_mac(duid, expected_mac):
    assert duid_extract_mac(duid) == expected_mac


# ── compute_magic_suffix — DUID LAA detection ─────────────────────────────────

def test_compute_magic_suffix_duid_llt_laa_tagged():
    # DUID-LLT with LAA MAC (0x02 bit set in first byte)
    duid = "00:01:00:01:12:34:56:78:02:00:5e:10:20:30"
    result = compute_magic_suffix("duid", duid, laa_tag=True)
    assert result.startswith("laa-d"), f"Expected laa-d prefix, got {result!r}"


def test_compute_magic_suffix_duid_ll_laa_tagged():
    # DUID-LL with LAA MAC
    duid = "00:03:00:01:de:ad:be:ef:00:01"  # 0xde has U/L bit set
    result = compute_magic_suffix("duid", duid, laa_tag=True)
    assert result.startswith("laa-d"), f"Expected laa-d prefix, got {result!r}"


def test_compute_magic_suffix_duid_llt_globally_unique_no_laa():
    # DUID-LLT with globally unique MAC — no laa- prefix even with laa_tag
    duid = "00:01:00:01:12:34:56:78:00:11:22:33:44:55"
    result = compute_magic_suffix("duid", duid, laa_tag=True)
    assert not result.startswith("laa-"), f"Expected no laa- prefix, got {result!r}"
    assert result.startswith("d"), f"Expected d prefix, got {result!r}"


def test_compute_magic_suffix_duid_en_not_tagged():
    # DUID-EN has no embedded MAC — no laa- prefix even with laa_tag
    duid = "00:02:00:00:09:bf:00:01:02:03"
    result = compute_magic_suffix("duid", duid, laa_tag=True)
    assert not result.startswith("laa-"), f"Expected no laa- prefix, got {result!r}"


def test_compute_magic_suffix_duid_laa_tag_disabled():
    # laa_tag=False suppresses laa- prefix even for LAA DUIDs
    duid = "00:03:00:01:de:ad:be:ef:00:01"
    result = compute_magic_suffix("duid", duid, laa_tag=False)
    assert not result.startswith("laa-"), f"Expected no laa- prefix, got {result!r}"


# ── _evict_record ─────────────────────────────────────────────────────────────

def _make_qub(data: dict):
    """Build a qub callable from {name: {rtype: [(ip, ttl)]}} mapping.

    Example: {"host.lan": {"A": [("10.0.0.1", "300"), ("10.0.0.2", "300")], "AAAA": []}}
    """
    def qub(name, rtype):
        return list(data.get(name, {}).get(rtype, []))
    return qub


class TestEvictRecord:
    """_evict_record: targeted removal preserving sibling records."""

    def _uc_capture(self):
        calls = []
        def uc(args):
            calls.append(list(args))
            return True
        return uc, calls

    def test_evict_removes_target_and_restores_sibling(self):
        """Evicting one IP from a name with a sibling must restore the sibling."""
        uc, calls = self._uc_capture()
        qub = _make_qub({"host.lan": {
            "A": [("192.168.1.10", "300"), ("192.168.1.11", "300")],
            "AAAA": [],
        }})
        import logging
        result = keaubnd_sync._evict_record(
            uc, qub, "host.lan", "A", {"192.168.1.10"}, logging.getLogger("t"))
        assert result is True
        remove_calls = [c for c in calls if c[0] == "local_data_remove"]
        add_calls = [c for c in calls if c[0] == "local_data"]
        assert any("host.lan" in c[1] for c in remove_calls), "local_data_remove must be called"
        assert any("192.168.1.11" in c[1] for c in add_calls), \
            "sibling 192.168.1.11 must be restored"
        assert not any("192.168.1.10" in c[1] for c in add_calls), \
            "evicted IP must not be re-added"

    def test_evict_clears_all_when_no_siblings(self):
        """Evicting the only IP in a name leaves no records at that name."""
        uc, calls = self._uc_capture()
        qub = _make_qub({"host.lan": {"A": [("192.168.1.10", "300")], "AAAA": []}})
        import logging
        keaubnd_sync._evict_record(
            uc, qub, "host.lan", "A", {"192.168.1.10"}, logging.getLogger("t"))
        remove_calls = [c for c in calls if c[0] == "local_data_remove"]
        add_calls = [c for c in calls if c[0] == "local_data"]
        assert remove_calls, "local_data_remove must be called"
        assert not any("192.168.1.10" in c[1] for c in add_calls), \
            "evicted IP must not be re-added"


# ── purge_released_ip: PTR target guard ───────────────────────────────────────

class TestPurgeReleasedIpPtrGuard:
    """purge_released_ip must NOT remove a PTR that already points at a new host.

    Finding: if a released IP was immediately reassigned and the logwatcher
    fires for the old release, the PTR in Unbound may already target the new
    hostname. The guard checks ptr_targets before removing.
    """

    def _run_purge(self, ip, unbound_data, kea_ips=None, removed=None):
        """Run purge_released_ip with mocked Kea query and unbound_control."""
        if removed is None:
            removed = []

        def fake_uc(cmd):
            removed.append(list(cmd))
            return True

        def fake_kea_ips(name, logger=None):
            return kea_ips or set()

        with mock.patch.object(keaubnd_sync, "unbound_control", side_effect=fake_uc), \
             mock.patch.object(keaubnd_sync, "kea_ips_for_hostname",
                               side_effect=fake_kea_ips):
            import logging
            keaubnd_sync.purge_released_ip(
                ip, unbound_data, host_entries={}, logger=logging.getLogger("t"))
        return removed

    def test_ptr_removed_when_still_targets_purged_host(self):
        """PTR is removed if it still points at the released host."""
        ptr = "10.1.168.192.in-addr.arpa"
        unbound_data = {
            "old-host.lan": ["old-host.lan 300 IN A 192.168.1.10"],
            ptr: [f"{ptr} 300 IN PTR old-host.lan."],
        }
        removed = self._run_purge("192.168.1.10", unbound_data)
        assert any("local_data_remove" in " ".join(c) and ptr in " ".join(c)
                   for c in removed), \
            "PTR must be removed when it still targets the purged host"

    def test_ptr_left_when_already_reassigned(self):
        """Finding: PTR is NOT removed if it now points at a different host.

        Scenario: 192.168.1.10 was released by old-host.lan, then immediately
        reassigned to new-host.lan. Unbound PTR now targets new-host.lan.
        purge_released_ip fires for old-host.lan's release — it must NOT touch
        the PTR because it already belongs to the new host.
        """
        ptr = "10.1.168.192.in-addr.arpa"
        unbound_data = {
            "old-host.lan": ["old-host.lan 300 IN A 192.168.1.10"],
            ptr: [f"{ptr} 300 IN PTR new-host.lan."],  # already reassigned
        }
        removed = self._run_purge("192.168.1.10", unbound_data)
        assert not any(ptr in " ".join(c) for c in removed), \
            "PTR must NOT be removed when it already targets a different host (Finding)"
