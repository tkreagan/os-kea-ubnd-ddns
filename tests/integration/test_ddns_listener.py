# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration tests — DDNS listener (kea-ubnd-ddns.py).

Sends RFC 2136 DNS UPDATE packets to 127.0.0.1:53535 via the SSH tunnel
and verifies that the daemon registers / removes records in Unbound.
Fuzzing cases verify the daemon survives malformed input without crashing.
"""

from __future__ import annotations

import base64
import time

import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.tsig
import dns.tsigkeyring
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

LISTENER_PORT = 53535
LISTENER_HOST = "127.0.0.1"


def _send_udp_via_ssh(ssh, data: bytes) -> bytes:
    """
    Send a UDP packet to 127.0.0.1:53535 on the OPNsense box via the existing
    paramiko session (the listener is bound to loopback, not reachable from the
    Mac directly).  Returns the daemon's response bytes, or b"" on timeout.
    """
    encoded = base64.b64encode(data).decode()
    code = (
        f"import socket, base64\n"
        f"s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        f"s.settimeout(3)\n"
        f"s.sendto(base64.b64decode('{encoded}'), ('127.0.0.1', {LISTENER_PORT}))\n"
        f"try:\n"
        f"    r, _ = s.recvfrom(65535)\n"
        f"    print(base64.b64encode(r).decode())\n"
        f"except socket.timeout:\n"
        f"    print('')\n"
    )
    raw = ssh.script("python3", code).strip()
    return base64.b64decode(raw) if raw else b""


def _zone_from_hostname(name_str: str) -> dns.name.Name:
    """Derive the DNS zone (parent of the first label) from a hostname."""
    parts = name_str.rstrip(".").split(".")
    if len(parts) > 2:
        return dns.name.from_text(".".join(parts[1:]) + ".")
    return dns.name.from_text("lan.")


def _make_update(name_str: str, rdtype_str: str, rdata_str: str,
                 ttl: int = 300) -> bytes:
    zone = _zone_from_hostname(name_str)
    msg = dns.message.make_query(zone, dns.rdatatype.SOA)
    msg.set_opcode(dns.opcode.UPDATE)

    name = dns.name.from_text(name_str if name_str.endswith(".") else name_str + ".")
    rdtype = dns.rdatatype.from_text(rdtype_str)
    rrset = dns.rrset.RRset(name, dns.rdataclass.IN, rdtype)
    rrset.ttl = ttl
    rr = dns.rdata.from_text(dns.rdataclass.IN, rdtype, rdata_str)
    rrset.add(rr)
    msg.authority.append(rrset)
    return msg.to_wire()


def _make_delete(name_str: str, rdtype_str: str) -> bytes:
    zone = _zone_from_hostname(name_str)
    msg = dns.message.make_query(zone, dns.rdatatype.SOA)
    msg.set_opcode(dns.opcode.UPDATE)
    name = dns.name.from_text(name_str if name_str.endswith(".") else name_str + ".")
    rdtype = dns.rdatatype.from_text(rdtype_str)
    rrset = dns.rrset.RRset(name, dns.rdataclass.ANY, rdtype)
    rrset.ttl = 0
    msg.authority.append(rrset)
    return msg.to_wire()


def _daemon_alive(ssh) -> bool:
    """Return True if the daemon supervisor process is running."""
    result = ssh(
        "[ -f /var/run/kea-ubnd-ddns.supervisor.pid ] && "
        "kill -0 $(cat /var/run/kea-ubnd-ddns.supervisor.pid) 2>/dev/null "
        "&& echo alive || echo dead",
        check=False,
    ).strip()
    return result == "alive"


@pytest.fixture(autouse=True)
def daemon_running(ssh, deploy):
    ssh("/usr/local/sbin/configctl keaubnd stop", check=False)
    time.sleep(0.5)
    ssh("/usr/local/sbin/configctl keaubnd start")
    time.sleep(2)
    yield
    ssh("/usr/local/sbin/configctl keaubnd stop", check=False)


def test_ddns_add_a_registers_in_unbound(ssh, unbound, test_host, test_log):
    hostname = test_host["hostname"]
    ip = test_host["ip"]
    test_log("injected", {"type": "ddns_update", "op": "ADD A", "hostname": hostname, "ip": ip})

    wire = _make_update(hostname, "A", ip)
    resp_bytes = _send_udp_via_ssh(ssh, wire)

    time.sleep(1)
    has_a = unbound.has_record(hostname, ip, "A")
    has_ptr = unbound.has_ptr(ip, hostname)

    test_log("observed", {"unbound_A": has_a, "unbound_PTR": has_ptr})
    assert has_a, f"A record for {hostname} → {ip} not found in Unbound"
    assert has_ptr, f"PTR for {ip} → {hostname} not found in Unbound"

    # Parse response rcode
    if resp_bytes:
        resp = dns.message.from_wire(resp_bytes)
        assert resp.rcode() == dns.rcode.NOERROR

    # Cleanup
    unbound.remove_record(hostname)
    import ipaddress
    ptr = str(ipaddress.ip_address(ip).reverse_pointer)
    ssh(f"/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
        f"local_data_remove {ptr}", check=False)
    test_log("cleaned", True)


def test_ddns_add_aaaa_registers_ptr(ssh, unbound, test_host_v6, test_log):
    hostname = test_host_v6["hostname"]
    ipv6 = test_host_v6["ip"]
    test_log("injected", {"type": "ddns_update", "op": "ADD AAAA", "hostname": hostname, "ipv6": ipv6})

    wire = _make_update(hostname, "AAAA", ipv6)
    _send_udp_via_ssh(ssh, wire)
    time.sleep(1)

    has_aaaa = unbound.has_record(hostname, ipv6, "AAAA")
    has_ptr = unbound.has_ptr(ipv6, hostname)
    test_log("observed", {"unbound_AAAA": has_aaaa, "unbound_PTR": has_ptr})
    assert has_aaaa
    assert has_ptr

    unbound.remove_record(hostname)
    import ipaddress
    ptr = str(ipaddress.ip_address(ipv6).reverse_pointer)
    ssh(f"/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
        f"local_data_remove {ptr}", check=False)
    test_log("cleaned", True)


def test_ddns_delete_a_removes_record(ssh, unbound, test_host, test_log):
    hostname = test_host["hostname"]
    ip = test_host["ip"]
    # Pre-register
    ssh(f"/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
        f"local_data '{hostname} 300 IN A {ip}'")
    time.sleep(0.5)
    assert unbound.has_record(hostname, ip, "A")

    wire = _make_delete(hostname, "A")
    _send_udp_via_ssh(ssh, wire)
    time.sleep(1)

    test_log("observed", {"still_present": unbound.has_record(hostname, ip, "A")})
    assert not unbound.has_record(hostname, ip, "A"), "Record still present after DELETE"
    test_log("cleaned", True)


def test_ddns_delete_a_preserves_aaaa(ssh, unbound, test_host, test_log):
    hostname = test_host["hostname"]
    ip = test_host["ip"]
    ipv6 = "2001:db8:99::2"

    # Pre-register both
    ssh(f"/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
        f"local_data '{hostname} 300 IN A {ip}'")
    ssh(f"/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
        f"local_data '{hostname} 300 IN AAAA {ipv6}'")
    time.sleep(0.5)

    wire = _make_delete(hostname, "A")
    _send_udp_via_ssh(ssh, wire)
    time.sleep(1)

    test_log("observed", {
        "A_still_present": unbound.has_record(hostname, ip, "A"),
        "AAAA_still_present": unbound.has_record(hostname, ipv6, "AAAA"),
    })
    assert not unbound.has_record(hostname, ip, "A")
    assert unbound.has_record(hostname, ipv6, "AAAA"), "AAAA was incorrectly removed"

    unbound.remove_record(hostname)
    test_log("cleaned", True)


def test_ddns_skips_static_entry(ssh, unbound, test_log):
    """Static entries in host_entries.conf must not be overwritten by DNS UPDATE."""
    HOST_ENTRIES = "/var/unbound/host_entries.conf"
    hostname = "ddns-guard-test.lan"
    guard_ip = "10.88.88.88"
    rogue_ip = "10.99.99.99"

    original = ssh(f"cat {HOST_ENTRIES}", check=False)
    entry = f'\nlocal-data: "{hostname}. 300 IN A {guard_ip}"\n'
    ssh.sudo_script("python3", f"open({HOST_ENTRIES!r}, 'a').write({entry!r})")
    ssh("/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf reload",
        check=False)

    # Restart the daemon so it picks up the new host_entries.conf
    ssh("/usr/local/sbin/configctl keaubnd stop", check=False)
    time.sleep(0.5)
    ssh("/usr/local/sbin/configctl keaubnd start")
    time.sleep(2)

    try:
        wire = _make_update(hostname, "A", rogue_ip)
        _send_udp_via_ssh(ssh, wire)
        time.sleep(1)

        rogue = unbound.has_record(hostname, rogue_ip, "A")
        test_log("observed", {"rogue_added": rogue, "guard_still_present":
                               unbound.has_record(hostname, guard_ip, "A")})
        assert not rogue, "Static entry was overwritten — static guard failed"
    finally:
        ssh.sudo_script("python3", f"open({HOST_ENTRIES!r}, 'w').write({original!r})")
        ssh("/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf reload",
            check=False)
        test_log("cleaned", True)


def test_ddns_rejects_nonsense_name(ssh, unbound, test_log):
    wire = _make_update("localhost", "A", "127.0.0.2")
    _send_udp_via_ssh(ssh, wire)
    time.sleep(1)
    # No record should be added
    assert not unbound.has_record("localhost", "127.0.0.2", "A")
    test_log("observed", {"nonsense_added": False})


# ── Fuzzing ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("bad_data", [
    b"",                                   # empty
    b"\x00" * 12,                          # zeroed header
    b"\xff" * 100,                         # random garbage
    b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # ASCII junk
    b"\x00\x01" + b"\x00" * 200,           # truncated
])
def test_ddns_fuzzing_daemon_survives(ssh, bad_data, test_log):
    """Daemon must survive malformed packets without crashing."""
    _send_udp_via_ssh(ssh, bad_data)
    time.sleep(0.5)
    alive = _daemon_alive(ssh)
    test_log("observed", {"daemon_alive_after_fuzz": alive})
    assert alive, "Daemon crashed after receiving malformed packet"


def test_ddns_rapid_fire_survives(ssh, test_log):
    """20 rapid UPDATE packets must not crash or zombie the daemon."""
    assert _daemon_alive(ssh), "Daemon not running before rapid fire"
    for i in range(20):
        wire = _make_update(f"fuzz{i:04d}.lan", "A", f"10.99.{i // 256}.{i % 256}")
        _send_udp_via_ssh(ssh, wire)
    time.sleep(2)
    alive = _daemon_alive(ssh)
    test_log("observed", {"daemon_alive_after_rapid_fire": alive})
    assert alive, "Daemon not running after rapid fire"
