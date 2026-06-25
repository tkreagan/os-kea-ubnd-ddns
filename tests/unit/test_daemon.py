# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit tests for kea-ubnd-ddns.py.

Covers: is_sane_name, reverse_ptr, HostEntriesCache.is_static, process_update,
parse_tsig_key, _filter_local_data.  All unbound-control calls are mocked.
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


def _snapshot(*records) -> "unittest.mock.Mock":
    """Return a subprocess.run mock whose stdout is a list_local_data response.

    Each record is a (name, ttl, rtype, rdata) tuple. The returned mock can be
    used as subprocess.run's return_value for tests that exercise the snapshot path.
    """
    import unittest.mock as _mock
    stdout = "".join(f"{name}. {ttl} IN {rtype} {rdata}\n"
                     for name, ttl, rtype, rdata in records)
    return _mock.Mock(returncode=0, stdout=stdout, stderr="")


# ── normalize_hostname ────────────────────────────────────────────────────────
# is_sane_name was removed; hostname validation now lives in
# lib/keaubnd_sync.normalize_hostname. Tests moved to test_kea_sync.py.


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


@mock.patch("subprocess.run")
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_no_synthesize_ptr_delete_no_ptr_removal(mock_uc, mock_run, tmp_path):
    """synthesize_ptr=False on delete: forward removed but no PTR removal attempted."""
    mock_run.return_value = _snapshot()  # no existing records
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


@mock.patch("subprocess.run")
def test_process_update_add_dry_run_no_subprocess_calls(mock_run, tmp_path):
    """allow + dry_run + ADD: zero subprocess calls.

    allow policy skips the snapshot fetch for ADD NCRs (no collision check
    needed), and dry_run skips all mutation calls — so subprocess.run is
    never touched."""
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("testhost.lan", "A", "192.168.1.200")
    daemon.process_update(msg, "/var/unbound/unbound.conf", True, _log,
                          _make_cache(he), collision_policy="allow")
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

@mock.patch("subprocess.run")
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_delete_a_no_aaaa(mock_uc, mock_run, tmp_path):
    mock_run.return_value = _snapshot()  # no existing records
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_delete_msg("testhost.lan", "A")
    rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                               _make_cache(he))
    assert rc == dns.rcode.NOERROR
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("local_data_remove" in c and "testhost.lan" in c for c in calls)


@mock.patch("subprocess.run")
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_delete_a_preserves_aaaa(mock_uc, mock_run, tmp_path):
    """Deleting A must preserve existing AAAA by re-adding it."""
    mock_run.return_value = _snapshot(("testhost.lan", 300, "AAAA", "2001:db8::1"))
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

@mock.patch("subprocess.run")
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_delete_specific_aaaa_preserves_sibling(mock_uc, mock_run, tmp_path):
    """H2 fix: DELETE for one AAAA must not destroy a sibling AAAA."""
    mock_run.return_value = _snapshot(
        ("testhost.lan", 300, "AAAA", "2001:db8::1"),
        ("testhost.lan", 300, "AAAA", "2001:db8::2"),
    )
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_delete_specific_msg("testhost.lan", "AAAA", "2001:db8::1")
    rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                               _make_cache(he))

    assert rc == dns.rcode.NOERROR
    calls = [str(c) for c in mock_uc.call_args_list]

    assert any("local_data_remove" in c and "testhost.lan" in c for c in calls), \
        "local_data_remove must be called for the name"
    assert any("local_data" in c and "2001:db8::2" in c for c in calls), \
        "H2: surviving same-family AAAA sibling must be restored after delete"
    restore_calls = [c for c in calls if "local_data" in c and "local_data_remove" not in c]
    assert not any("2001:db8::1" in c for c in restore_calls), \
        "the deleted AAAA must not be re-added"


@mock.patch("subprocess.run")
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_delete_specific_aaaa_removes_only_target_ptr(mock_uc, mock_run, tmp_path):
    """H2 fix: PTR removal must target only the deleted IP, not surviving siblings."""
    mock_run.return_value = _snapshot(
        ("testhost.lan", 300, "AAAA", "2001:db8::1"),
        ("testhost.lan", 300, "AAAA", "2001:db8::2"),
    )
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_delete_specific_msg("testhost.lan", "AAAA", "2001:db8::1")
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                          _make_cache(he))

    calls = [str(c) for c in mock_uc.call_args_list]
    ptr_deleted = daemon.reverse_ptr("2001:db8::1")
    ptr_sibling = daemon.reverse_ptr("2001:db8::2")

    assert any("local_data_remove" in c and ptr_deleted in c for c in calls), \
        "PTR for deleted IP must be removed"
    assert not any("local_data_remove" in c and ptr_sibling in c for c in calls), \
        "PTR for surviving sibling must not be removed"
    # Note: the current implementation does not proactively re-add the surviving
    # sibling's PTR — it only guards against over-deletion.


@mock.patch("subprocess.run")
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_process_update_delete_specific_a_preserves_sibling(mock_uc, mock_run, tmp_path):
    """H2 fix applies to A records too: second A survives a specific-IP delete."""
    mock_run.return_value = _snapshot(
        ("testhost.lan", 300, "A", "192.168.1.10"),
        ("testhost.lan", 300, "A", "192.168.1.11"),
    )
    he = tmp_path / "host_entries.conf"
    he.write_text("")
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


# ── _filter_local_data ────────────────────────────────────────────────────────

def test_filter_local_data_parses_a_record():
    stdout = "testhost.lan. 300 IN A 192.168.1.5\n"
    assert daemon._filter_local_data(stdout, "testhost.lan", "A") == [("192.168.1.5", 300)]


def test_filter_local_data_filters_by_type():
    stdout = (
        "testhost.lan. 300 IN A 192.168.1.5\n"
        "testhost.lan. 300 IN AAAA 2001:db8::1\n"
    )
    assert daemon._filter_local_data(stdout, "testhost.lan", "A") == [("192.168.1.5", 300)]
    assert daemon._filter_local_data(stdout, "testhost.lan", "AAAA") == [("2001:db8::1", 300)]


def test_filter_local_data_filters_by_name():
    stdout = (
        "host1.lan. 300 IN A 192.168.1.1\n"
        "host2.lan. 300 IN A 192.168.1.2\n"
    )
    assert daemon._filter_local_data(stdout, "host1.lan", "A") == [("192.168.1.1", 300)]
    assert daemon._filter_local_data(stdout, "host2.lan", "A") == [("192.168.1.2", 300)]


def test_filter_local_data_empty_stdout():
    assert daemon._filter_local_data("", "testhost.lan", "A") == []


# ── process_update — none collision policy ────────────────────────────────────

@mock.patch("subprocess.run")
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_none_no_collision_adds_normally(mock_uc, mock_run, tmp_path):
    """none + no existing record → falls through to a normal add."""
    mock_run.return_value = _snapshot()  # empty Unbound
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("laptop.lan", "A", "192.168.1.50")
    rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                               _make_cache(he), collision_policy="none")
    assert rc == dns.rcode.NOERROR
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("local_data" in c and "laptop.lan" in c and "192.168.1.50" in c
               for c in calls), "non-colliding ADD must be applied normally"


@mock.patch("subprocess.run")
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_none_collision_evicts_existing_skips_new(mock_uc, mock_run, tmp_path):
    """none + existing A for same host → evict old record, skip new, NOERROR."""
    mock_run.return_value = _snapshot(("laptop.lan", 300, "A", "192.168.1.10"))
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("laptop.lan", "A", "192.168.1.20")
    rc = daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                               _make_cache(he), collision_policy="none")
    assert rc == dns.rcode.NOERROR
    calls = [str(c) for c in mock_uc.call_args_list]
    # existing record must be evicted
    assert any("local_data_remove" in c and "laptop.lan" in c for c in calls), \
        "none: existing record must be evicted"
    # new record must NOT be added
    add_calls = [c for c in calls if "local_data" in c and "local_data_remove" not in c]
    assert not any("192.168.1.20" in c for c in add_calls), \
        "none: collider IP must not be added"


@mock.patch("subprocess.run")
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_none_collision_marks_dirty_out(mock_uc, mock_run, tmp_path):
    """none collision must populate the dirty_out set with the colliding name."""
    mock_run.return_value = _snapshot(("laptop.lan", 300, "A", "192.168.1.10"))
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("laptop.lan", "A", "192.168.1.20")
    dirty: set = set()
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                          _make_cache(he), collision_policy="none", dirty_out=dirty)
    assert "laptop.lan" in dirty, "none: colliding hostname must be added to dirty_out"


@mock.patch("subprocess.run")
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_none_no_collision_does_not_populate_dirty_out(mock_uc, mock_run, tmp_path):
    """none + no existing record → dirty_out stays empty."""
    mock_run.return_value = _snapshot()
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("laptop.lan", "A", "192.168.1.50")
    dirty: set = set()
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                          _make_cache(he), collision_policy="none", dirty_out=dirty)
    assert not dirty, "none: no collision means dirty_out must remain empty"


@mock.patch("subprocess.run")
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_none_collision_evicts_ptr(mock_uc, mock_run, tmp_path):
    """none eviction must also remove the PTR for the evicted IP."""
    mock_run.return_value = _snapshot(("laptop.lan", 300, "A", "192.168.1.10"))
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("laptop.lan", "A", "192.168.1.20")
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                          _make_cache(he), collision_policy="none")
    calls = [str(c) for c in mock_uc.call_args_list]
    ptr_old = daemon.reverse_ptr("192.168.1.10")
    ptr_new = daemon.reverse_ptr("192.168.1.20")
    assert any("local_data_remove" in c and ptr_old in c for c in calls), \
        "none: PTR for evicted IP must be removed"
    remove_calls = [c for c in calls if "local_data_remove" in c]
    assert not any(ptr_new in c for c in remove_calls), \
        "none: PTR for new (non-added) IP must not be removed"


@mock.patch("subprocess.run")
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_none_collision_preserves_other_family(mock_uc, mock_run, tmp_path):
    """none eviction must not destroy an AAAA record for the same host."""
    mock_run.return_value = _snapshot(
        ("laptop.lan", 300, "A", "192.168.1.10"),
        ("laptop.lan", 300, "AAAA", "2001:db8::1"),
    )
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("laptop.lan", "A", "192.168.1.20")
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                          _make_cache(he), collision_policy="none")
    calls = [str(c) for c in mock_uc.call_args_list]
    add_calls = [c for c in calls if "local_data" in c and "local_data_remove" not in c]
    assert any("2001:db8::1" in c for c in add_calls), \
        "none: AAAA sibling must be restored after A eviction"


def test_filter_local_data_no_match():
    stdout = "other.lan. 300 IN A 192.168.1.5\n"
    assert daemon._filter_local_data(stdout, "testhost.lan", "A") == []


# ── process_update — magic_names live-path spec ───────────────────────────────

@mock.patch("subprocess.run")
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_magic_no_collision_adds_normally_with_ptr(mock_uc, mock_run, tmp_path):
    """magic_names + no collision: bare-name add proceeds normally, including PTR."""
    mock_run.return_value = _snapshot()  # empty Unbound
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("laptop.lan", "A", "192.168.1.50")
    dirty: set = set()
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                          _make_cache(he), magic_names=True, dirty_out=dirty)
    calls = [str(c) for c in mock_uc.call_args_list]
    assert any("local_data" in c and "laptop.lan" in c and "192.168.1.50" in c
               for c in calls), "magic no-collision: A record must be added"
    ptr = daemon.reverse_ptr("192.168.1.50")
    assert any("local_data" in c and ptr in c for c in calls), \
        "magic no-collision: PTR must be synthesized (no collision to suppress it)"
    assert not dirty, "magic no-collision: dirty_out must be empty"


@mock.patch("subprocess.run")
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_magic_collision_marks_dirty_for_drain(mock_uc, mock_run, tmp_path):
    """magic_names + collision: name marked dirty so drain computes magic FQDNs."""
    mock_run.return_value = _snapshot(("laptop.lan", 300, "A", "192.168.1.10"))
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("laptop.lan", "A", "192.168.1.20")
    dirty: set = set()
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                          _make_cache(he), collision_policy="last_wins",
                          magic_names=True, dirty_out=dirty)
    assert "laptop.lan" in dirty, \
        "magic + last_wins collision: name must be in dirty_out for drain"


@mock.patch("subprocess.run")
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_magic_collision_skips_inline_ptr(mock_uc, mock_run, tmp_path):
    """magic_names + collision: inline PTR must not be synthesized (drain owns it)."""
    mock_run.return_value = _snapshot(("laptop.lan", 300, "A", "192.168.1.10"))
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("laptop.lan", "A", "192.168.1.20")
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                          _make_cache(he), collision_policy="last_wins",
                          magic_names=True, dirty_out=set())
    calls = [str(c) for c in mock_uc.call_args_list]
    ptr_new = daemon.reverse_ptr("192.168.1.20")
    add_calls = [c for c in calls if "local_data" in c and "local_data_remove" not in c]
    assert not any(ptr_new in c for c in add_calls), \
        "magic + collision: PTR for new IP must not be written inline"


@mock.patch("subprocess.run")
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_magic_allow_collision_defers_to_drain(mock_uc, mock_run, tmp_path):
    """magic_names + allow + collision: both IPs added but name marked dirty for drain."""
    mock_run.return_value = _snapshot(("laptop.lan", 300, "A", "192.168.1.10"))
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("laptop.lan", "A", "192.168.1.20")
    dirty: set = set()
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                          _make_cache(he), collision_policy="allow",
                          magic_names=True, dirty_out=dirty)
    calls = [str(c) for c in mock_uc.call_args_list]
    # allow still adds the new record
    assert any("local_data" in c and "192.168.1.20" in c
               and "local_data_remove" not in c for c in calls), \
        "magic + allow + collision: new A must still be added"
    # but drain must be triggered
    assert "laptop.lan" in dirty, \
        "magic + allow + collision: name must be in dirty_out for drain"


@mock.patch("subprocess.run")
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_magic_allow_fetches_snapshot_for_collision_detection(mock_uc, mock_run, tmp_path):
    """magic_names + allow: snapshot must be fetched even for a plain ADD (no deletes).

    Without magic_names, allow skips the snapshot for ADDs. With magic_names on,
    the snapshot is needed to detect collisions for the drain-defer trigger."""
    mock_run.return_value = _snapshot()  # empty
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("laptop.lan", "A", "192.168.1.50")
    # magic_names=True, policy=allow, no deletes — snapshot must be fetched
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                          _make_cache(he), collision_policy="allow", magic_names=True)
    assert mock_run.called, \
        "magic + allow + ADD: list_local_data snapshot must be fetched"


@mock.patch("subprocess.run")
@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_magic_first_wins_collision_marks_dirty(mock_uc, mock_run, tmp_path):
    """magic_names + first_wins + collision: name marked dirty even though NCR is blocked."""
    mock_run.return_value = _snapshot(("laptop.lan", 300, "A", "192.168.1.10"))
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("laptop.lan", "A", "192.168.1.20")
    dirty: set = set()
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                          _make_cache(he), collision_policy="first_wins",
                          magic_names=True, dirty_out=dirty)
    assert "laptop.lan" in dirty, \
        "magic + first_wins collision: name must be in dirty_out so drain can compute magic FQDNs"


# ── process_update — PTR pre-remove before add ───────────────────────────────

@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_ptr_synthesis_removes_before_add(mock_uc, tmp_path):
    """PTR synthesis must issue local_data_remove <arpa> before local_data <PTR record>.

    Without this, Unbound accumulates stale PTR targets when an IP is reassigned
    to a new hostname and no DELETE NCR for the old hostname was received first.
    """
    he = tmp_path / "host_entries.conf"
    he.write_text("")
    msg = _make_update_msg("newhost.lan", "A", "192.168.1.77")
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                          _make_cache(he), synthesize_ptr=True)
    calls = [c.args[0] for c in mock_uc.call_args_list]
    ptr = daemon.reverse_ptr("192.168.1.77")
    remove_idx = next((i for i, c in enumerate(calls)
                       if c[0] == "local_data_remove" and c[1] == ptr), None)
    add_idx = next((i for i, c in enumerate(calls)
                    if c[0] == "local_data" and ptr in c[1]), None)
    assert remove_idx is not None, "local_data_remove must be called for the arpa name"
    assert add_idx is not None, "local_data must be called to add the PTR record"
    assert remove_idx < add_idx, "local_data_remove must precede local_data for the arpa name"


@mock.patch.object(daemon, "unbound_control", return_value=True)
def test_ptr_synthesis_no_remove_when_static(mock_uc, tmp_path):
    """Static PTR guard: local_data_remove must NOT be called for a static arpa name."""
    he = tmp_path / "host_entries.conf"
    he.write_text('local-data-ptr: "192.168.1.77 reserved.lan."\n')
    msg = _make_update_msg("other.lan", "A", "192.168.1.77")
    daemon.process_update(msg, "/var/unbound/unbound.conf", False, _log,
                          _make_cache(he), synthesize_ptr=True)
    calls = [c.args[0] for c in mock_uc.call_args_list]
    ptr = daemon.reverse_ptr("192.168.1.77")
    assert not any(c[0] == "local_data_remove" and c[1] == ptr for c in calls), \
        "local_data_remove must not be called for a static PTR arpa name"


# ── extract_deleted_ips ───────────────────────────────────────────────────────

def test_extract_deleted_ips_specific_rdata_delete():
    """A specific-rdata A delete yields the deleted IP."""
    msg = _make_delete_specific_msg("host.lan.", "A", "192.168.1.50")
    ips = daemon.extract_deleted_ips(msg)
    assert "192.168.1.50" in ips


def test_extract_deleted_ips_no_deletes_returns_empty():
    """An ADD update yields no deleted IPs."""
    msg = _make_update_msg("host.lan", "A", "192.168.1.50")
    ips = daemon.extract_deleted_ips(msg)
    assert ips == set()


# ── SM dirty_deletes / note_dirty_delete ─────────────────────────────────────

import lib.consistency_sm as _csm_mod


class TestDirtyDeletes:
    def test_note_dirty_ncr_with_ips_accumulates(self):
        """IPs from DELETE NCRs are stored as _DirtyEntry('ip', ...) in the unified pool."""
        sm = _csm_mod.ConsistencySM()
        sm.note_dirty_ncr(set(), {"10.0.0.1", "10.0.0.2"})
        ip_values = {e.value for e in sm.dirty if e.kind == "ip"}
        assert "10.0.0.1" in ip_values
        assert "10.0.0.2" in ip_values

    def test_spawn_drain_or_normal_carries_purge_ips(self):
        sm = _csm_mod.ConsistencySM()
        sm.state = _csm_mod.State.NORMAL
        sm.dirty = {_csm_mod._DirtyEntry("name", "host.lan"),
                    _csm_mod._DirtyEntry("ip", "10.0.0.1")}
        ds = sm._spawn_drain_or_normal()
        assert len(ds) == 1
        spawn = ds[0]
        assert isinstance(spawn, _csm_mod.Spawn)
        assert spawn.purge_ips == frozenset({"10.0.0.1"})
        assert "host.lan" in (spawn.names or set())

    def test_spawn_drain_clears_ip_entries(self):
        """IP _DirtyEntry items are consumed (moved to _draining_ips) when drain spawns."""
        sm = _csm_mod.ConsistencySM()
        sm.state = _csm_mod.State.NORMAL
        sm.dirty = {_csm_mod._DirtyEntry("name", "host.lan"),
                    _csm_mod._DirtyEntry("ip", "10.0.0.1")}
        sm._spawn_drain_or_normal()
        # After spawn, no ip entries should remain in dirty
        remaining_ips = {e.value for e in sm.dirty if e.kind == "ip"}
        assert not remaining_ips, f"ip entries must be consumed at spawn; got {remaining_ips}"

    def test_after_drain_failure_restores_ips(self):
        """On drain failure, consumed IPs must be put back into dirty."""
        sm = _csm_mod.ConsistencySM()
        sm.state = _csm_mod.State.NORMAL
        sm.dirty = {_csm_mod._DirtyEntry("name", "host.lan"),
                    _csm_mod._DirtyEntry("ip", "10.0.0.1")}
        sm._spawn_drain_or_normal()
        sm._after_drain(now=0.0, exit_code=1)
        remaining_ips = {e.value for e in sm.dirty if e.kind == "ip"}
        assert "10.0.0.1" in remaining_ips, \
            "failed drain must restore IPs back to dirty"

    def test_on_pending_aborted_restores_ips(self):
        """KillPending abort must restore in-flight IPs back to dirty."""
        sm = _csm_mod.ConsistencySM()
        sm.state = _csm_mod.State.NORMAL
        sm.dirty = {_csm_mod._DirtyEntry("name", "host.lan"),
                    _csm_mod._DirtyEntry("ip", "10.0.0.5")}
        sm._spawn_drain_or_normal()
        sm._on_pending_aborted()
        remaining_ips = {e.value for e in sm.dirty if e.kind == "ip"}
        assert "10.0.0.5" in remaining_ips, \
            "aborted pending must restore IPs back to dirty"

    def test_purge_ips_none_when_no_ip_entries(self):
        """Spawn.purge_ips is None when dirty has no ip-kind entries."""
        sm = _csm_mod.ConsistencySM()
        sm.state = _csm_mod.State.NORMAL
        sm.dirty = {_csm_mod._DirtyEntry("name", "host.lan")}
        ds = sm._spawn_drain_or_normal()
        spawn = ds[0]
        assert spawn.purge_ips is None


# ── Phase 5 tests (E, F, G-logic, G-config, H, I, J) ─────────────────────────

class TestFindingE:
    """E: fast_reload_pending set when entering NORMAL → immediate ScheduleWake."""

    def test_go_normal_with_pending_schedules_wake(self):
        sm = _csm_mod.ConsistencySM()
        sm.state = _csm_mod.State.BLOCKED
        sm.fast_reload_pending = True
        ds = sm._go_normal()
        assert any(isinstance(d, _csm_mod.ScheduleWake) and d.delay == 0.0 for d in ds)

    def test_go_normal_without_pending_no_wake(self):
        sm = _csm_mod.ConsistencySM()
        sm.state = _csm_mod.State.BLOCKED
        sm.fast_reload_pending = False
        ds = sm._go_normal()
        assert not any(isinstance(d, _csm_mod.ScheduleWake) for d in ds)

    def test_after_drain_success_with_pending_schedules_wake(self):
        """drain-exit with fast_reload_pending set → goes NORMAL → ScheduleWake."""
        sm = _csm_mod.ConsistencySM()
        sm.state = _csm_mod.State.NORMAL
        sm._pending = _csm_mod._Pending.DRAIN
        sm._draining = {"host.lan"}
        sm.fast_reload_pending = True
        ds = sm.on_sync_exit(1.0, 0)
        # No more dirty → _go_normal → ScheduleWake
        assert any(isinstance(d, _csm_mod.ScheduleWake) for d in ds)


class TestFindingGLogic:
    """G-logic: _spawn_drain_or_normal escalates to full RECONCILE when overflowed."""

    def test_overflow_escalates_to_reconcile(self):
        sm = _csm_mod.ConsistencySM()
        sm.state = _csm_mod.State.NORMAL
        sm.overflowed = True
        sm.dirty = {_csm_mod._DirtyEntry("name", "a.lan"),
                    _csm_mod._DirtyEntry("name", "b.lan")}
        ds = sm._spawn_drain_or_normal()
        assert len(ds) == 1
        spawn = ds[0]
        assert isinstance(spawn, _csm_mod.Spawn)
        assert spawn.names is None   # full reconcile
        assert sm._pending is _csm_mod._Pending.RECONCILE

    def test_overflow_dirty_not_cleared_at_spawn(self):
        """dirty is NOT cleared when escalating via overflow — _after_reconcile owns that."""
        sm = _csm_mod.ConsistencySM()
        sm.overflowed = True
        entry = _csm_mod._DirtyEntry("name", "x.lan")
        sm.dirty = {entry}
        sm._spawn_drain_or_normal()
        assert entry in sm.dirty

    def test_drain_loop_overflow_escalates(self):
        """Dirty names accumulate past cap during drain → next loop escalates."""
        cfg = _csm_mod.SMConfig(dirty_cap=2)
        sm = _csm_mod.ConsistencySM(cfg)
        sm.state = _csm_mod.State.NORMAL
        # Put three names in dirty — this exceeds the cap
        sm.note_dirty_ncr({"a.lan", "b.lan", "c.lan"})
        assert sm.overflowed
        ds = sm._spawn_drain_or_normal()
        assert isinstance(ds[0], _csm_mod.Spawn)
        assert ds[0].names is None


class TestFindingGConfig:
    """G-config: SMConfig.dirty_cap default is 50."""

    def test_default_dirty_cap(self):
        cfg = _csm_mod.SMConfig()
        assert cfg.dirty_cap == 50


def _make_daemon_args(**overrides):
    """Minimal args namespace for Daemon.__init__ (no TSIG, all defaults)."""
    defaults = dict(
        tsig_key=None,
        tsig_algorithm="HMAC-SHA256",
        dirty_cap=None,
        max_full_sync_attempts=None,
        readiness_watchdog_minutes=None,
        fast_reload_threshold=None,
        collision_policy="last_wins",
        magic_names=False,
        laa_tag=False,
        no_synthesize_ptr=False,
        clean_on_restart=False,
        dry_run=False,
        verbose=False,
        unbound_conf="/fake/unbound.conf",
        host_entries="/dev/null",
    )
    defaults.update(overrides)
    return mock.MagicMock(**defaults)


class TestFindingF:
    """F: subprocess spawned with start_new_session=True; _kill_child uses killpg."""

    def _make_daemon(self):
        import lib.keaubnd_runtime as _rt_mod
        with mock.patch.object(_rt_mod, "get_fast_reload_threshold", return_value=0), \
             mock.patch.object(_rt_mod, "get_host_entries", return_value="/dev/null"), \
             mock.patch.object(_rt_mod, "get_unbound_conf", return_value="/fake/unbound.conf"):
            return daemon.Daemon(_make_daemon_args(), _log)

    def test_spawn_uses_start_new_session(self):
        """_spawn passes start_new_session=True to Popen."""
        d = self._make_daemon()
        d.kq = mock.MagicMock()
        d.child = None
        directive = _csm_mod.Spawn("full", None)

        with mock.patch("subprocess.Popen") as mock_popen, \
             mock.patch.object(d, "_register_child"):
            mock_proc = mock.MagicMock()
            mock_proc.pid = 99999
            mock_popen.return_value = mock_proc
            d._spawn(directive)

        _, pkwargs = mock_popen.call_args
        assert pkwargs.get("start_new_session") is True

    def test_kill_child_uses_killpg(self):
        """_kill_child sends SIGTERM to the process group, not just the direct child."""
        d = self._make_daemon()
        mock_child = mock.MagicMock()
        mock_child.pid = 99998
        d.child = mock_child

        with mock.patch("os.getpgid", return_value=99998) as mock_getpgid, \
             mock.patch("os.killpg") as mock_killpg:
            d._kill_child()

        mock_getpgid.assert_called_with(99998)
        mock_killpg.assert_called()
        import signal as _sig
        sig = mock_killpg.call_args[0][1]
        assert sig == _sig.SIGTERM


class TestFinding5:
    """Finding 5: non-connection SERVFAIL (unbound-control partial failure) must
    schedule a drain via note_dirty_ncr so the names are retried.

    Before the fix, only the collision-policy `dirty_out` path called
    note_dirty_ncr after a SERVFAIL; a bare SERVFAIL from unbound-control
    (e.g. local_data failed but no connection error) left the record
    un-dirty and was never retried.
    """

    def _make_daemon(self, tmp_path):
        import lib.keaubnd_runtime as _rt_mod
        import lib.consistency_sm as _csm
        with mock.patch.object(_rt_mod, "get_fast_reload_threshold", return_value=0), \
             mock.patch.object(_rt_mod, "get_host_entries", return_value=str(tmp_path / "he.conf")), \
             mock.patch.object(_rt_mod, "get_unbound_conf", return_value="/fake/unbound.conf"):
            (tmp_path / "he.conf").write_text("")
            args = _make_daemon_args()
            d = daemon.Daemon(args, _log)
            d.kq = mock.MagicMock()
            # Daemon.__init__ arms kqueue watchers; on macOS the pid/file watches fail
            # and transition the SM to BLOCKED. Force NORMAL so _apply_or_defer
            # exercises the live path (BLOCKED short-circuits before process_update).
            d.sm.state = _csm.State.NORMAL
            return d

    def _patched_apply(self, d, msg, process_update_side_effect):
        """Drive _apply_or_defer with mocked lock, process_update, and _arm_timer."""
        dirty_called_with = []

        def _note_dirty(names, deleted_ips=None):
            dirty_called_with.append(set(names) if names else set())

        d.sm.note_dirty_ncr = _note_dirty

        lock_cm = mock.MagicMock()
        lock_cm.__enter__ = mock.Mock(return_value=None)
        lock_cm.__exit__ = mock.Mock(return_value=False)

        with mock.patch.object(daemon, "unbound_mutation_lock", return_value=lock_cm), \
             mock.patch.object(daemon, "process_update",
                               side_effect=process_update_side_effect), \
             mock.patch.object(d, "_arm_timer"):
            rc = d._apply_or_defer(msg)

        return rc, dirty_called_with

    def test_servfail_with_empty_dirty_out_marks_name_dirty(self, tmp_path):
        """When process_update returns SERVFAIL and dirty_out stays empty,
        _apply_or_defer must call note_dirty_ncr(names) to schedule a drain (Finding 5)."""
        d = self._make_daemon(tmp_path)
        msg = _make_update_msg("host.lan", "A", "192.168.1.50")

        rc, dirty_called_with = self._patched_apply(
            d, msg, lambda *a, **kw: dns.rcode.SERVFAIL
        )

        assert rc == dns.rcode.SERVFAIL
        assert dirty_called_with, \
            "note_dirty_ncr must be called when SERVFAIL with empty dirty_out (Finding 5)"
        all_names = set.union(*dirty_called_with)
        assert "host.lan" in all_names, \
            f"host.lan must appear in dirty names; got {dirty_called_with}"

    def test_servfail_with_dirty_out_marks_dirty_out_not_names(self, tmp_path):
        """When dirty_out is populated (collision path) note_dirty_ncr gets dirty_out."""
        d = self._make_daemon(tmp_path)
        msg = _make_update_msg("laptop.lan", "A", "192.168.1.51")

        def _fake_pu(*args, dirty_out=None, **kwargs):
            if dirty_out is not None:
                dirty_out.add("laptop-mAABBCC.lan")
            return dns.rcode.SERVFAIL

        rc, dirty_called_with = self._patched_apply(d, msg, _fake_pu)

        assert rc == dns.rcode.SERVFAIL
        assert dirty_called_with, "note_dirty_ncr must be called"
        all_names = set.union(*dirty_called_with)
        assert "laptop-mAABBCC.lan" in all_names, \
            "dirty_out names must appear in note_dirty_ncr call"


class TestFindingJ:
    """J: daemon main() fails fast when keaubnd.json is missing."""

    def test_main_exits_on_missing_runtime_config(self, monkeypatch):
        import lib.keaubnd_runtime as _rt_mod
        monkeypatch.setattr(_rt_mod, "_cache", None)
        monkeypatch.setattr(_rt_mod, "_config_path", "/nonexistent/keaubnd.json")

        with pytest.raises(SystemExit) as exc_info:
            # parse_args needs a clean argv; patch sys.argv
            with mock.patch("sys.argv", ["kea-ubnd-ddns.py"]):
                with mock.patch("lib.keaubnd_runtime.load",
                                side_effect=RuntimeError("keaubnd.json not found")):
                    daemon.main()
        assert exc_info.value.code == 1
