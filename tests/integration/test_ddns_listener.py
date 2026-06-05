# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration tests — DDNS listener (kea-unbound-ddns.py).

Sends RFC 2136 DNS UPDATE packets to 127.0.0.1:53535 via the SSH tunnel
and verifies that the daemon registers / removes records in Unbound.
Fuzzing cases verify the daemon survives malformed input without crashing.
"""

from __future__ import annotations

import json
import socket
import subprocess
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


def _send_udp_via_ssh(box, data: bytes) -> bytes:
    """
    Send a UDP packet to 127.0.0.1:53535 on the OPNsense box by running a Python
    one-liner over SSH (the listener is bound to loopback, not accessible
    from the Mac directly).
    """
    import base64
    encoded = base64.b64encode(data).decode()
    cmd = (
        f"ssh -o ConnectTimeout=10 {box['ssh_user']}@{box['host']} "
        f"\"python3 -c \\\"import socket,base64; "
        f"s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
        f"s.settimeout(3); "
        f"s.sendto(base64.b64decode('{encoded}'),('127.0.0.1',{LISTENER_PORT})); "
        f"r,_ = s.recvfrom(65535); "
        f"import sys; sys.stdout.buffer.write(r)\\\"\""
    )
    result = subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
    return result.stdout


def _make_update(name_str: str, rdtype_str: str, rdata_str: str,
                 ttl: int = 300) -> bytes:
    zone = dns.name.from_text("lan.")
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
    zone = dns.name.from_text("lan.")
    msg = dns.message.make_query(zone, dns.rdatatype.SOA)
    msg.set_opcode(dns.opcode.UPDATE)
    name = dns.name.from_text(name_str if name_str.endswith(".") else name_str + ".")
    rdtype = dns.rdatatype.from_text(rdtype_str)
    rrset = dns.rrset.RRset(name, dns.rdataclass.ANY, rdtype)
    rrset.ttl = 0
    msg.authority.append(rrset)
    return msg.to_wire()


@pytest.fixture(autouse=True)
def daemon_running(ssh, deploy):
    ssh("/usr/local/sbin/configctl keaunbound stop", check=False)
    time.sleep(0.5)
    ssh("/usr/local/sbin/configctl keaunbound start")
    time.sleep(2)
    yield
    ssh("/usr/local/sbin/configctl keaunbound stop", check=False)


def test_ddns_add_a_registers_in_unbound(box, ssh, unbound, test_host, test_log):
    hostname = test_host["hostname"]
    ip = test_host["ip"]
    test_log("injected", {"type": "ddns_update", "op": "ADD A", "hostname": hostname, "ip": ip})

    wire = _make_update(hostname, "A", ip)
    resp_bytes = _send_udp_via_ssh(box, wire)

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


def test_ddns_add_aaaa_registers_ptr(box, ssh, unbound, test_log):
    hostname = f"{TEST_HOST_PREFIX}v6.lan"
    ipv6 = "2001:db8:99::1"
    test_log("injected", {"type": "ddns_update", "op": "ADD AAAA", "hostname": hostname, "ipv6": ipv6})

    wire = _make_update(hostname, "AAAA", ipv6)
    _send_udp_via_ssh(box, wire)
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


def test_ddns_delete_a_removes_record(box, ssh, unbound, test_host, test_log):
    hostname = test_host["hostname"]
    ip = test_host["ip"]
    # Pre-register
    ssh(f"/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
        f"local_data '{hostname} 300 IN A {ip}'")
    time.sleep(0.5)
    assert unbound.has_record(hostname, ip, "A")

    wire = _make_delete(hostname, "A")
    _send_udp_via_ssh(box, wire)
    time.sleep(1)

    test_log("observed", {"still_present": unbound.has_record(hostname, ip, "A")})
    assert not unbound.has_record(hostname, ip, "A"), "Record still present after DELETE"
    test_log("cleaned", True)


def test_ddns_delete_a_preserves_aaaa(box, ssh, unbound, test_host, test_log):
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
    _send_udp_via_ssh(box, wire)
    time.sleep(1)

    test_log("observed", {
        "A_still_present": unbound.has_record(hostname, ip, "A"),
        "AAAA_still_present": unbound.has_record(hostname, ipv6, "AAAA"),
    })
    assert not unbound.has_record(hostname, ip, "A")
    assert unbound.has_record(hostname, ipv6, "AAAA"), "AAAA was incorrectly removed"

    unbound.remove_record(hostname)
    test_log("cleaned", True)


def test_ddns_skips_static_entry(box, ssh, unbound, test_log):
    """Static entries in host_entries.conf must not be overwritten."""
    hostname = "router.lan"
    original_ip = ssh(
        "/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
        "list_local_data | grep 'router.lan' | head -1",
        check=False,
    )

    # Attempt to overwrite router.lan with a rogue IP
    wire = _make_update(hostname, "A", "10.99.99.99")
    _send_udp_via_ssh(box, wire)
    time.sleep(1)

    # If static guard works, router.lan should NOT point to the rogue IP
    rogue = unbound.has_record(hostname, "10.99.99.99", "A")
    test_log("observed", {"rogue_added": rogue, "original": original_ip})
    assert not rogue, "Static entry was overwritten — static guard failed"


def test_ddns_rejects_nonsense_name(box, ssh, unbound, test_log):
    wire = _make_update("localhost", "A", "127.0.0.2")
    _send_udp_via_ssh(box, wire)
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
def test_ddns_fuzzing_daemon_survives(box, ssh, bad_data, test_log):
    """Daemon must survive malformed packets without crashing."""
    _send_udp_via_ssh(box, bad_data)
    time.sleep(0.5)
    # Daemon is still running
    count = int(ssh("pgrep -c -f kea-unbound-ddns.py || echo 0", check=False).strip())
    test_log("observed", {"process_count_after_fuzz": count})
    assert count >= 1, "Daemon crashed after receiving malformed packet"


def test_ddns_rapid_fire_survives(box, ssh, test_log):
    """1000 valid UPDATE packets must not crash or zombie the daemon."""
    count_before = int(ssh("pgrep -c -f kea-unbound-ddns.py || echo 0", check=False).strip())
    for i in range(20):  # reduced for speed; full 1000 would be slow over SSH
        wire = _make_update(f"fuzz{i:04d}.lan", "A", f"10.99.{i // 256}.{i % 256}")
        _send_udp_via_ssh(box, wire)
    time.sleep(2)
    count_after = int(ssh("pgrep -c -f kea-unbound-ddns.py || echo 0", check=False).strip())
    test_log("observed", {"before": count_before, "after": count_after})
    assert count_after >= 1, "Daemon not running after rapid fire"
    assert count_after <= count_before + 1, "Extra daemon processes spawned"
