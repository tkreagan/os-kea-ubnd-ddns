# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit tests for kea-ubnd-ddns.py.

Covers: is_sane_name, reverse_ptr, HostEntriesCache.is_static, process_update,
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

daemon = load_script("kea-ubnd-ddns.py")

_log = logging.getLogger("test-daemon")
_log.addHandler(logging.NullHandler())


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_cache(path, log=_log):
    """Build a HostEntriesCache from a file path (str or pathlib.Path)."""
    return daemon.HostEntriesCache(str(path), log)


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
    """DNS UPDATE: delete all RRs of a type (rdclass=ANY, no rdata)."""
    zone = dns.name.from_text("lan.")
    msg = dns.message.make_query(zone, dns.rdatatype.SOA)
    msg.flags |= dns.flags.QR
    msg.set_opcode(dns.opcode.UPDATE)
    name = dns.name.from_text(name_str if name_str.endswith(".") else name_str + ".")
    rdtype = dns.rdatatype.from_text(rdtype_str)
    # Mirror parsed UPDATE: dnspython normalizes rdclass to IN and sets .deleting.
    rrset = dns.rrset.RRset(name, dns.rdataclass.IN, rdtype)
    rrset.ttl = 0
    rrset.deleting = dns.rdataclass.ANY
    msg.authority.append(rrset)
    return msg


def _make_delete_specific_msg(name_str: str, rdtype_str: str,
                               rdata_str: str) -> dns.message.Message:
    """DNS UPDATE: delete one specific RR (rdclass=NONE with rdata).

    Models kea-dhcp-ddns deleting a single address when a host has multiple
    records of the same family — e.g. one of two AAAA leases expires."""
    zone = dns.name.from_text("lan.")
    msg = dns.message.make_query(zone, dns.rdatatype.SOA)
    msg.flags |= dns.flags.QR
    msg.set_opcode(dns.opcode.UPDATE)
    name = dns.name.from_text(name_str if name_str.endswith(".") else name_str + ".")
    rdtype = dns.rdatatype.from_text(rdtype_str)
    # dnspython normalizes parsed UPDATE rdclass to IN and exposes the delete-class
    # via rrset.deleting.  Mirror that here so the daemon sees the same structure.
    rrset = dns.rrset.RRset(name, dns.rdataclass.IN, rdtype)
    rrset.ttl = 0
    rrset.deleting = dns.rdataclass.NONE
    rr = dns.rdata.from_text(dns.rdataclass.IN, rdtype, rdata_str)
    rrset.add(rr)
    msg.authority.append(rrset)
    return msg


# ── is_sane_name ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,expect", [
    ("myhost.lan",          True),
    ("foo.bar.baz",         True),
    ("host-with-dash.lan",  True),
    ("a.b",                 True),
    ("x1.lan",              True),
    ("123host.lan",         True),
    ("1abc.lan",            True),
    # all-label validation: invalid chars in non-first labels
    ("valid.evil!label.lan",    False),
    ("valid._svc.lan",          False),
    ("valid.bad-.lan",          False),
    ("valid.-bad.lan",          False),
    # length limits
    ("a" * 63 + ".lan",         True),   # 63-char label is ok
    ("a" * 64 + ".lan",         False),  # 64-char label exceeds RFC 1035 max
    # reserved / nonsense
    ("",                    False),
    (".",                   False),
    ("localhost",           False),
    ("localdomain",         False),
    # all-numeric (IP addresses passed as names)
    ("192.168.1.1",         False),
    ("10.0.0.1",            False),
    ("1.2.3.4",             False),
    # invalid first label (existing behaviour preserved)
    ("-bad.lan",            False),
    ("_foo.lan",            False),
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


# ── HostEntriesCache.is_static ────────────────────────────────────────────────

def test_is_static_found_forward(tmp_path):
    f = tmp_path / "host_entries.conf"
    f.write_text('local-data: "router.lan. 3600 IN A 192.168.1.1"\n')
    assert _make_cache(f).is_static("router.lan") is True


def test_is_static_not_found(tmp_path):
    f = tmp_path / "host_entries.conf"
    f.write_text('local-data: "router.lan. 3600 IN A 192.168.1.1"\n')
    assert _make_cache(f).is_static("other.lan") is False


def test_is_static_missing_file():
    assert _make_cache("/nonexistent/host_entries.conf").is_static("any.lan") is False


def test_is_static_empty_file(tmp_path):
    f = tmp_path / "host_entries.conf"
    f.write_text("")
    assert _make_cache(f).is_static("any.lan") is False


def test_is_static_aaaa(tmp_path):
    f = tmp_path / "host_entries.conf"
    f.write_text('local-data: "ipv6host.lan. 3600 IN AAAA 2001:db8::1"\n')
    assert _make_cache(f).is_static("ipv6host.lan") is True


# ── HostEntriesCache.is_static — PTR (arpa-name / IP-keyed) ──────────────────
# OPNsense writes: local-data-ptr: "192.168.1.1 router.lan."
# The daemon calls is_static() with the arpa form "1.1.168.192.in-addr.arpa".
# is_static() decodes the arpa name via _arpa_to_ip() and looks up the IP.

def test_is_static_ptr_by_ip(tmp_path):
    f = tmp_path / "host_entries.conf"
    f.write_text('local-data-ptr: "192.168.1.1 router.lan."\n')
    assert _make_cache(f).is_static("192.168.1.1") is True


def test_is_static_ptr_arpa_name_matches_ip_keyed(tmp_path):
    """F2 regression: arpa-name PTR lookup must match OPNsense's IP-keyed entry."""
    f = tmp_path / "host_entries.conf"
    f.write_text('local-data-ptr: "192.168.1.1 router.lan."\n')
    assert _make_cache(f).is_static("1.1.168.192.in-addr.arpa") is True, (
        "F2: arpa-name must decode to IP and match the IP-keyed host_entries entry"
    )


def test_is_static_ptr_arpa_v6_matches_ip_keyed(tmp_path):
    """F2 regression (IPv6): ip6.arpa arpa name must match IP-keyed local-data-ptr."""
    f = tmp_path / "host_entries.conf"
    f.write_text('local-data-ptr: "2001:db8::1 ipv6-static.lan."\n')
    ptr_name = daemon.reverse_ptr("2001:db8::1")
    assert ptr_name is not None
    assert _make_cache(f).is_static(ptr_name) is True, (
        "F2 (v6): ip6.arpa arpa-name must match IP-keyed local-data-ptr"
    )


def test_is_static_ptr_unrelated_ip_not_blocked(tmp_path):
    """A static PTR for 192.168.1.1 must not block lookup for 192.168.1.2."""
    f = tmp_path / "host_entries.conf"
    f.write_text('local-data-ptr: "192.168.1.1 router.lan."\n')
    assert _make_cache(f).is_static("2.1.168.192.in-addr.arpa") is False


def test_is_static_forward_not_blocked_by_ptr(tmp_path):
    """F1 regression: a static PTR must not block an unrelated forward name."""
    f = tmp_path / "host_entries.conf"
    f.write_text('local-data-ptr: "192.168.1.1 router.lan."\n')
    assert _make_cache(f).is_static("other.lan") is False


# ── _arpa_to_ip ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("ptr,expected_ip", [
    ("100.1.168.192.in-addr.arpa",   "192.168.1.100"),
    ("1.1.168.192.in-addr.arpa",     "192.168.1.1"),
    ("1.0.0.10.in-addr.arpa",        "10.0.0.1"),
    ("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
     "::1"),
])
def test_arpa_to_ip_valid(ptr, expected_ip):
    import ipaddress
    result = daemon._arpa_to_ip(ptr)
    assert result != ""
    assert ipaddress.ip_address(result) == ipaddress.ip_address(expected_ip)


@pytest.mark.parametrize("bad", [
    "not-a-ptr",
    "1.168.192.in-addr.arpa",    # only 3 labels
    "foo.in-addr.arpa",
    "",
    "192.168.1.1",               # plain IP, not arpa
])
def test_arpa_to_ip_invalid(bad):
    assert daemon._arpa_to_ip(bad) == ""


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


# ── process_update — ADD path ─────────────────────────────────────────────────

@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_add_a_calls_local_data(mock_uc, tmp_path):
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("testhost.lan", "A", "192.168.1.200")
    rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                               _make_cache(he))
    assert rc == dns.rcode.NOERROR
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("local_data" in c and "testhost.lan" in c and "192.168.1.200" in c
               for c in calls)
    assert any("PTR" in c or "in-addr.arpa" in c for c in calls)


@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_add_aaaa_registers_ip6_ptr(mock_uc, tmp_path):
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("testhost.lan", "AAAA", "2001:db8::200")
    rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                               _make_cache(he))
    assert rc == dns.rcode.NOERROR
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("2001:db8::200" in c for c in calls)
    assert any("ip6.arpa" in c for c in calls)


# ── process_update — synthesize_ptr flag ──────────────────────────────────────

@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_no_synthesize_ptr_skips_ptr(mock_uc, tmp_path):
    """synthesize_ptr=False: forward A registered but no PTR synthesized."""
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("testhost.lan", "A", "192.168.1.50")
    rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                               _make_cache(he), synthesize_ptr=False)
    assert rc == dns.rcode.NOERROR
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("local_data" in c and "testhost.lan" in c and "192.168.1.50" in c
               for c in calls), "forward A must still be registered"
    assert not any("in-addr.arpa" in c or ("local_data" in c and "PTR" in c)
                   for c in calls), "no PTR must be added when synthesize_ptr=False"


@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_synthesize_ptr_on_adds_ptr(mock_uc, tmp_path):
    """synthesize_ptr=True (default): PTR synthesized alongside forward A."""
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("testhost.lan", "A", "192.168.1.51")
    rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                               _make_cache(he), synthesize_ptr=True)
    assert rc == dns.rcode.NOERROR
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("in-addr.arpa" in c for c in calls), "PTR must be added"


@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_no_synthesize_ptr_v6(mock_uc, tmp_path):
    """synthesize_ptr=False: no ip6.arpa PTR for AAAA adds."""
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("testhost.lan", "AAAA", "2001:db8::51")
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                          _make_cache(he), synthesize_ptr=False)
    calls = [str(c) for c in mock_uc.call_args_list]
    assert not any("ip6.arpa" in c for c in calls), "no ip6.arpa PTR when synthesize_ptr=False"


@mock.patch.object(daemon, "query_unbound", return_value=[])
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_no_synthesize_ptr_delete_no_ptr_removal(mock_uc, mock_qu, tmp_path):
    """synthesize_ptr=False on delete: forward removed but no PTR removal attempted."""
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_delete_msg("testhost.lan", "A")
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                          _make_cache(he), synthesize_ptr=False)
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("local_data_remove" in c and "testhost.lan" in c for c in calls)
    assert not any("in-addr.arpa" in c for c in calls), \
        "no PTR removal when synthesize_ptr=False"


# ── process_update — F2 end-to-end: static PTR preserved on A-add ─────────────

@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_static_ptr_preserved_on_a_add(mock_uc, tmp_path):
    """F2 e2e: static IP-keyed local-data-ptr must block PTR synthesis so the
    OPNsense-managed PTR is not clobbered by a DDNS A-add for a different hostname
    on the same IP."""
    he = tmp_path / "host_entries.conf"
    he.write_text('local-data-ptr: "192.168.1.1 router.lan."\n')
    msg = _make_update_msg("other.lan", "A", "192.168.1.1")
    rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                               _make_cache(he))
    assert rc == dns.rcode.NOERROR
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("local_data" in c and "other.lan" in c and "192.168.1.1" in c
               for c in calls), "F1: forward A must be registered despite static PTR"
    ptr_name = daemon.reverse_ptr("192.168.1.1")
    assert not any("local_data" in c and ptr_name in c
                   for c in calls), "F2: static IP-keyed PTR must not be clobbered"


@mock.patch.object(daemon, "query_unbound", return_value=[])
@mock.patch("subprocess.run")
def test_process_update_add_dry_run_no_subprocess_calls(mock_run, mock_qu, tmp_path):
    """dry_run=True: no mutation subprocess calls; query_unbound reads are separate."""
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("testhost.lan", "A", "192.168.1.200")
    daemon.process_update(msg, "/var/unbound/unbound.conf", True, _log,
                          _make_cache(he))
    mock_run.assert_not_called()


@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_skips_static_entry(mock_uc, tmp_path):
    he = tmp_path / "host_entries.conf"
    he.write_text('local-data: "router.lan. 3600 IN A 192.168.1.1"\n')
    msg = _make_update_msg("router.lan", "A", "192.168.1.1")
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                          _make_cache(he))
    mock_uc.assert_not_called()


@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_skips_nonsense_name(mock_uc, tmp_path):
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("localhost", "A", "127.0.0.1")
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                          _make_cache(he))
    mock_uc.assert_not_called()


@mock.patch.object(daemon, "unbound_control", return_value=False)
def test_process_update_add_failure_returns_servfail(mock_uc, tmp_path):
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("testhost.lan", "A", "192.168.1.200")
    rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                               _make_cache(he))
    assert rc == dns.rcode.SERVFAIL


# ── process_update — DELETE path ──────────────────────────────────────────────

@mock.patch.object(daemon, "query_unbound", return_value=[])
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_delete_a_no_aaaa(mock_uc, mock_qu, tmp_path):
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_delete_msg("testhost.lan", "A")
    rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                               _make_cache(he))
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
    rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                               _make_cache(he))
    assert rc == dns.rcode.NOERROR
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("local_data" in c and "2001:db8::1" in c for c in calls)


# ── process_update — H2: same-family sibling preservation ─────────────────────
# local_data_remove name wipes ALL rrsets for that name. When a DELETE names
# only one of several AAAA records, the remaining AAAA siblings must be
# read before the remove and restored after.

@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_delete_specific_aaaa_preserves_sibling(mock_uc, tmp_path):
    """H2 fix: DELETE for one AAAA must not destroy a sibling AAAA."""
    he = tmp_path / "host_entries.conf"
    he.write_text("")

    # Host currently has two AAAA records; query_unbound returns family-appropriate data.
    def _qu(name, rdtype, logger, unbound_conf):
        if rdtype == "AAAA":
            return [("2001:db8::1", 300), ("2001:db8::2", 300)]
        return []  # no A records

    with mock.patch.object(daemon, "query_unbound", side_effect=_qu):
        msg = _make_delete_specific_msg("testhost.lan", "AAAA", "2001:db8::1")
        rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                                   _make_cache(he))

    assert rc == dns.rcode.NOERROR
    calls = [str(c) for c in mock_uc.call_args_list]

    # The name must be removed (local_data_remove wipes all types).
    assert any("local_data_remove" in c and "testhost.lan" in c for c in calls), \
        "local_data_remove must be called for the name"

    # The surviving sibling (2001:db8::2) must be re-added.
    assert any("local_data" in c and "2001:db8::2" in c for c in calls), \
        "H2: surviving same-family AAAA sibling must be restored after delete"

    # The deleted IP (2001:db8::1) must NOT be re-added.
    restore_calls = [c for c in calls if "local_data" in c and "local_data_remove" not in c]
    assert not any("2001:db8::1" in c for c in restore_calls), \
        "the deleted AAAA must not be re-added"


@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_delete_specific_aaaa_removes_only_target_ptr(mock_uc, tmp_path):
    """H2 fix: PTR removal must target only the deleted IP, not surviving siblings."""
    he = tmp_path / "host_entries.conf"
    he.write_text("")

    def _qu(name, rdtype, logger, unbound_conf):
        if rdtype == "AAAA":
            return [("2001:db8::1", 300), ("2001:db8::2", 300)]
        return []

    with mock.patch.object(daemon, "query_unbound", side_effect=_qu):
        msg = _make_delete_specific_msg("testhost.lan", "AAAA", "2001:db8::1")
        daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                              _make_cache(he))

    calls = [str(c) for c in mock_uc.call_args_list]
    ptr_deleted = daemon.reverse_ptr("2001:db8::1")
    ptr_sibling = daemon.reverse_ptr("2001:db8::2")

    # PTR for the deleted IP must be removed.
    assert any("local_data_remove" in c and ptr_deleted in c for c in calls), \
        "PTR for deleted IP must be removed"

    # PTR for the sibling must be restored (re-added), not removed.
    assert not any("local_data_remove" in c and ptr_sibling in c for c in calls), \
        "PTR for surviving sibling must not be removed"
    assert any("local_data" in c and ptr_sibling in c for c in calls), \
        "PTR for surviving sibling must be re-added"


@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_delete_specific_a_preserves_sibling(mock_uc, tmp_path):
    """H2 fix applies to A records too: second A survives a specific-IP delete."""
    he = tmp_path / "host_entries.conf"
    he.write_text("")

    def _qu(name, rdtype, logger, unbound_conf):
        if rdtype == "A":
            return [("192.168.1.10", 300), ("192.168.1.11", 300)]
        return []  # no AAAA

    with mock.patch.object(daemon, "query_unbound", side_effect=_qu):
        msg = _make_delete_specific_msg("testhost.lan", "A", "192.168.1.10")
        rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                                   _make_cache(he))

    assert rc == dns.rcode.NOERROR
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("local_data" in c and "192.168.1.11" in c for c in calls), \
        "H2: surviving A sibling must be restored"
    restore_calls = [c for c in calls if "local_data" in c and "local_data_remove" not in c]
    assert not any("192.168.1.10" in c for c in restore_calls), \
        "deleted A must not be re-added"


# ── query_unbound ─────────────────────────────────────────────────────────────

@mock.patch("subprocess.run")
def test_query_unbound_parses_output(mock_run):
    mock_run.return_value = mock.Mock(
        returncode=0,
        stdout="testhost.lan. 300 IN A 192.168.1.5\n",
        stderr="",
    )
    result = daemon.query_unbound("testhost.lan", "A", _log,
                                  "/var/unbound/unbound.conf")
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
    result = daemon.query_unbound("testhost.lan", "A", _log,
                                  "/var/unbound/unbound.conf")
    assert result == [("192.168.1.5", 300)]


@mock.patch("subprocess.run")
def test_query_unbound_returns_empty_on_failure(mock_run):
    mock_run.return_value = mock.Mock(returncode=1, stdout="", stderr="error")
    assert daemon.query_unbound("testhost.lan", "A", _log,
                                "/var/unbound/unbound.conf") == []
