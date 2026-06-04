# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit tests for kea-unbound-ddns.py.

Covers: is_sane_name, reverse_ptr, is_static_entry, process_update,
parse_tsig_key, query_unbound.  All unbound-control calls are mocked.
"""

from __future__ import annotations

import logging
import unittest.mock as mock

import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from .conftest import load_script

pytestmark = pytest.mark.unit

daemon = load_script("kea-unbound-ddns.py")

_log = logging.getLogger("test-daemon")
_log.addHandler(logging.NullHandler())


# ── is_sane_name ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,expect", [
    ("myhost.lan",          True),
    ("foo.bar.baz",         True),
    ("host-with-dash.lan",  True),
    ("a.b",                 True),
    ("x1.lan",              True),
    ("",                    False),
    (".",                   False),
    ("localhost",           False),
    ("localdomain",         False),
    ("192.168.1.1",         False),
    ("10.0.0.1",            False),
    ("1.2.3.4",             False),
    ("-bad.lan",            False),
    ("_foo.lan",            False),
    ("123host.lan",         True),
    ("1abc.lan",            True),
])
def test_is_sane_name(name, expect):
    assert daemon.is_sane_name(name, _log) is expect


# ── reverse_ptr ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("ip,expected_suffix", [
    ("192.168.1.1",  ".in-addr.arpa"),
    ("10.0.0.1",     ".in-addr.arpa"),
    ("127.0.0.1",    ".in-addr.arpa"),
    ("::1",          ".ip6.arpa"),
    ("2001:db8::1",  ".ip6.arpa"),
    ("fe80::1",      ".ip6.arpa"),
])
def test_reverse_ptr_valid(ip, expected_suffix):
    result = daemon.reverse_ptr(ip)
    assert result is not None
    assert result.endswith(expected_suffix)


def test_reverse_ptr_ipv4_correctness():
    assert daemon.reverse_ptr("192.168.1.100") == "100.1.168.192.in-addr.arpa"


def test_reverse_ptr_ipv6_loopback():
    result = daemon.reverse_ptr("::1")
    assert result == "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"


@pytest.mark.parametrize("bad", ["not-an-ip", "256.0.0.1", "foo", ""])
def test_reverse_ptr_invalid(bad):
    assert daemon.reverse_ptr(bad) is None


# ── is_static_entry ───────────────────────────────────────────────────────────

def test_is_static_entry_found_forward(tmp_path):
    f = tmp_path / "host_entries.conf"
    f.write_text('local-data: "router.lan. 3600 IN A 192.168.1.1"\n')
    assert daemon.is_static_entry("router.lan", "A", _log, [str(f)]) is True


def test_is_static_entry_found_ptr(tmp_path):
    f = tmp_path / "host_entries.conf"
    f.write_text('local-data-ptr: "192.168.1.1 router.lan."\n')
    assert daemon.is_static_entry("192.168.1.1", "PTR", _log, [str(f)]) is True


def test_is_static_entry_not_found(tmp_path):
    f = tmp_path / "host_entries.conf"
    f.write_text('local-data: "router.lan. 3600 IN A 192.168.1.1"\n')
    assert daemon.is_static_entry("other.lan", "A", _log, [str(f)]) is False


def test_is_static_entry_missing_file():
    assert daemon.is_static_entry("any.lan", "A", _log, ["/nonexistent/file"]) is False


def test_is_static_entry_empty_static_files():
    assert daemon.is_static_entry("any.lan", "A", _log, []) is False


def test_is_static_entry_aaaa(tmp_path):
    f = tmp_path / "host_entries.conf"
    f.write_text('local-data: "ipv6host.lan. 3600 IN AAAA 2001:db8::1"\n')
    assert daemon.is_static_entry("ipv6host.lan", "AAAA", _log, [str(f)]) is True
    assert daemon.is_static_entry("ipv6host.lan", "A", _log, [str(f)]) is False


# ── parse_tsig_key ────────────────────────────────────────────────────────────

def test_parse_tsig_key_none():
    assert daemon.parse_tsig_key(None) is None


def test_parse_tsig_key_valid():
    keyring = daemon.parse_tsig_key("testkey:dGVzdHNlY3JldA==", "HMAC-SHA256")
    assert keyring is not None
    assert isinstance(keyring, dict)


def test_parse_tsig_key_all_algorithms():
    algos = ["HMAC-MD5", "HMAC-SHA1", "HMAC-SHA224",
             "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"]
    for algo in algos:
        kr = daemon.parse_tsig_key("k:dGVzdA==", algo)
        assert kr is not None, f"Failed for {algo}"


def test_parse_tsig_key_no_colon():
    with pytest.raises(SystemExit):
        daemon.parse_tsig_key("invalidsecret")


def test_parse_tsig_key_unknown_algorithm():
    with pytest.raises(SystemExit):
        daemon.parse_tsig_key("k:dGVzdA==", "HMAC-BOGUS")


# ── process_update helpers ────────────────────────────────────────────────────

def _make_update_msg(name_str: str, rdtype_str: str, rdata_str: str,
                     ttl: int = 300) -> dns.message.Message:
    zone = dns.name.from_text("lan.")
    msg = dns.message.make_query(zone, dns.rdatatype.SOA)
    msg.flags |= dns.flags.QR
    msg.set_opcode(dns.opcode.UPDATE)
    name = dns.name.from_text(name_str if name_str.endswith(".") else name_str + ".")
    rdtype = dns.rdatatype.from_text(rdtype_str)
    rdclass = dns.rdataclass.IN
    rrset = dns.rrset.RRset(name, rdclass, rdtype)
    rrset.ttl = ttl
    rr = dns.rdata.from_text(rdclass, rdtype, rdata_str)
    rrset.add(rr)
    msg.authority.append(rrset)
    return msg


def _make_delete_msg(name_str: str, rdtype_str: str) -> dns.message.Message:
    zone = dns.name.from_text("lan.")
    msg = dns.message.make_query(zone, dns.rdatatype.SOA)
    msg.flags |= dns.flags.QR
    msg.set_opcode(dns.opcode.UPDATE)
    name = dns.name.from_text(name_str if name_str.endswith(".") else name_str + ".")
    rdtype = dns.rdatatype.from_text(rdtype_str)
    rrset = dns.rrset.RRset(name, dns.rdataclass.ANY, rdtype)
    rrset.ttl = 0
    msg.authority.append(rrset)
    return msg


# ── process_update — ADD path ─────────────────────────────────────────────────

@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_add_a_calls_local_data(mock_uc, tmp_path):
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("testhost.lan", "A", "192.168.1.200")
    rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log, [str(he)])
    assert rc == dns.rcode.NOERROR
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("local_data" in c and "testhost.lan" in c and "192.168.1.200" in c for c in calls)
    assert any("PTR" in c or "in-addr.arpa" in c for c in calls)


@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_add_aaaa_registers_ip6_ptr(mock_uc, tmp_path):
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("testhost.lan", "AAAA", "2001:db8::200")
    rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log, [str(he)])
    assert rc == dns.rcode.NOERROR
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("2001:db8::200" in c for c in calls)
    assert any("ip6.arpa" in c for c in calls)


@mock.patch("subprocess.run")
def test_process_update_add_dry_run_no_subprocess_calls(mock_run, tmp_path):
    """dry_run=True: unbound_control is invoked but subprocess.run must not be."""
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("testhost.lan", "A", "192.168.1.200")
    daemon.process_update(msg, "/var/unbound/unbound.conf", True, _log, [str(he)])
    mock_run.assert_not_called()


@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_skips_static_entry(mock_uc, tmp_path):
    he = tmp_path / "host_entries.conf"
    he.write_text('local-data: "router.lan. 3600 IN A 192.168.1.1"\n')
    msg = _make_update_msg("router.lan", "A", "192.168.1.1")
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log, [str(he)])
    mock_uc.assert_not_called()


@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_skips_nonsense_name(mock_uc, tmp_path):
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("localhost", "A", "127.0.0.1")
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log, [str(he)])
    mock_uc.assert_not_called()


@mock.patch.object(daemon, "unbound_control", return_value=False)
def test_process_update_add_failure_returns_servfail(mock_uc, tmp_path):
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("testhost.lan", "A", "192.168.1.200")
    rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log, [str(he)])
    assert rc == dns.rcode.SERVFAIL


# ── process_update — DELETE path ──────────────────────────────────────────────

@mock.patch.object(daemon, "query_unbound", return_value=[])
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_delete_a_no_aaaa(mock_uc, mock_qu, tmp_path):
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_delete_msg("testhost.lan", "A")
    rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log, [str(he)])
    assert rc == dns.rcode.NOERROR
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("local_data_remove" in c and "testhost.lan" in c for c in calls)


@mock.patch.object(daemon, "query_unbound", return_value=[("2001:db8::1", 300)])
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_delete_a_preserves_aaaa(mock_uc, mock_qu, tmp_path):
    """Deleting A must preserve existing AAAA by re-adding it."""
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_delete_msg("testhost.lan", "A")
    rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log, [str(he)])
    assert rc == dns.rcode.NOERROR
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("local_data" in c and "2001:db8::1" in c for c in calls)


# ── query_unbound ─────────────────────────────────────────────────────────────

@mock.patch("subprocess.run")
def test_query_unbound_parses_output(mock_run):
    mock_run.return_value = mock.Mock(
        returncode=0,
        stdout="testhost.lan. 300 IN A 192.168.1.5\n",
        stderr="",
    )
    result = daemon.query_unbound("testhost.lan", "A", _log)
    assert result == [("192.168.1.5", 300)]


@mock.patch("subprocess.run")
def test_query_unbound_filters_type(mock_run):
    mock_run.return_value = mock.Mock(
        returncode=0,
        stdout=(
            "testhost.lan. 300 IN A 192.168.1.5\n"
            "testhost.lan. 300 IN AAAA 2001:db8::1\n"
        ),
        stderr="",
    )
    result = daemon.query_unbound("testhost.lan", "A", _log)
    assert result == [("192.168.1.5", 300)]


@mock.patch("subprocess.run")
def test_query_unbound_returns_empty_on_failure(mock_run):
    mock_run.return_value = mock.Mock(returncode=1, stdout="", stderr="error")
    assert daemon.query_unbound("testhost.lan", "A", _log) == []
