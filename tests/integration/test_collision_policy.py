# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration tests — plugin-level collision_policy setting.

Exercises all three policies (allow / first_wins / last_wins) by sending
RFC 2136 UPDATE packets directly to the listener's UDP port, simulating NCRs
from kea-dhcp-ddns without requiring a full DHCP flow.

Tests:
  CP-1 allow        — two different IPs for the same FQDN both land in Unbound
  CP-2 first-prereq — first_wins + prereqs present → YXRRSET returned, original kept
  CP-3 first-noprq  — first_wins + no prereqs    → NOERROR returned, A silently blocked
  CP-4 first-ptr    — first_wins blocks explicit PTR packet too (no PTR leak)
  CP-5 last         — last_wins → existing record replaced by new registrant

All Unbound checks use list_local_data, NOT drill -x (see D2 methodology note).
"""

from __future__ import annotations

import time

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

# DNS rcode integers we care about
_NOERROR = 0
_YXRRSET = 9

# ── Helpers ───────────────────────────────────────────────────────────────────

_CONFIG_XML    = "/conf/config.xml"
_DAEMON_SUP    = "/var/run/kea-unbound-ddns.supervisor.pid"
_START_SCRIPT  = "/usr/local/opnsense/scripts/keaunbound/start.py"
_LISTENER_PORT = 53535


def _set_collision_policy(ssh, policy: str) -> None:
    """Write collision_policy into config.xml via the OPNsense box."""
    ssh.script("python3", f"""\
import xml.etree.ElementTree as ET
tree = ET.parse("/conf/config.xml")
root = tree.getroot()
node = root.find("OPNsense/KeaUnbound/general/collision_policy")
if node is None:
    general = root.find("OPNsense/KeaUnbound/general")
    if general is None:
        raise SystemExit("OPNsense/KeaUnbound/general missing from config.xml")
    node = ET.SubElement(general, "collision_policy")
node.text = {policy!r}
tree.write("/conf/config.xml", xml_declaration=True, encoding="UTF-8")
print("ok")
""")


def _restart_daemon(ssh) -> None:
    """Kill the supervisor and start a fresh daemon instance."""
    ssh(f"pkill -F {_DAEMON_SUP} 2>/dev/null || true")
    time.sleep(3)
    ssh(f"python3 {_START_SCRIPT}")
    time.sleep(2)


def _send_a_update(ssh, fqdn: str, ip: str, with_prereqs: bool = False) -> int:
    """
    Send an RFC 2136 A-record ADD to the listener and return the rcode integer.

    with_prereqs=True mimics check-with-dhcid mode: a YXRRSET prerequisite
    (present() in dnspython) is placed in the answer section, signalling to the
    listener that DHCID checking was performed by D2.
    """
    abs_fqdn = fqdn.rstrip(".") + "."
    result = ssh.script("python3", f"""\
import socket, dns.update, dns.name, dns.rdatatype, dns.message
name = dns.name.from_text({abs_fqdn!r})
upd  = dns.update.UpdateMessage(dns.name.root)
upd.add(name, 300, dns.rdatatype.A, {ip!r})
if {with_prereqs!r}:
    upd.present(name, dns.rdatatype.A)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(upd.to_wire(), ("127.0.0.1", {_LISTENER_PORT}))
resp, _ = s.recvfrom(65536)
print(dns.message.from_wire(resp).rcode())
""")
    try:
        return int(result.strip())
    except ValueError:
        raise RuntimeError(f"Unexpected response from listener: {result!r}")


def _send_ptr_update(ssh, ip: str, hostname: str) -> int:
    """Send an RFC 2136 explicit PTR ADD and return the rcode integer."""
    abs_hostname = hostname.rstrip(".") + "."
    result = ssh.script("python3", f"""\
import socket, ipaddress, dns.update, dns.name, dns.rdatatype, dns.message
ptr = str(ipaddress.ip_address({ip!r}).reverse_pointer) + "."
target = {abs_hostname!r}
name = dns.name.from_text(ptr)
upd  = dns.update.UpdateMessage(dns.name.root)
upd.add(name, 300, dns.rdatatype.PTR, target)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(upd.to_wire(), ("127.0.0.1", {_LISTENER_PORT}))
resp, _ = s.recvfrom(65536)
print(dns.message.from_wire(resp).rcode())
""")
    try:
        return int(result.strip())
    except ValueError:
        raise RuntimeError(f"Unexpected response from listener: {result!r}")


def _other_ip(ip: str, offset: int = 50) -> str:
    """Return a different IP in the same /24 for use as 'client A' record."""
    prefix = ".".join(ip.split(".")[:3]) + "."
    last = int(ip.split(".")[-1])
    new_last = (last - offset) if last > offset else (last + offset)
    return prefix + str(new_last)


# ── Test class ────────────────────────────────────────────────────────────────

class TestCollisionPolicy:
    """
    CP test group: plugin-level collision_policy.

    Each test:
      1. Sets the desired collision_policy in config.xml
      2. Restarts the daemon to pick up the new policy
      3. Pre-populates Unbound with a "client A" record (the existing registrant)
      4. Sends an RFC 2136 UPDATE for the same FQDN to a different IP (client B)
      5. Asserts the expected Unbound state and rcode
      6. Cleans up Unbound records and restores policy=allow + daemon restart
    """

    @pytest.fixture(autouse=True)
    def _restore_policy(self, ssh):
        """Always restore policy=allow and restart daemon after each test."""
        yield
        _set_collision_policy(ssh, "allow")
        _restart_daemon(ssh)

    # ── CP-1: allow ───────────────────────────────────────────────────────────

    def test_cp1_allow_accumulates_both_records(
            self, ssh, unbound, test_host, test_log):
        """
        CP-1 (allow): two clients claiming the same FQDN both get A records.
        This is the default behaviour — no collision protection.
        """
        hostname = test_host["hostname"]
        ip_b     = test_host["ip"]
        ip_a     = _other_ip(ip_b)

        _set_collision_policy(ssh, "allow")
        _restart_daemon(ssh)

        # Client A already registered
        unbound.add_record(f'"{hostname}. 300 IN A {ip_a}"')

        try:
            # Client B registers the same name
            rcode = _send_a_update(ssh, hostname, ip_b)

            test_log("injected", {"hostname": hostname, "ip_a": ip_a, "ip_b": ip_b})
            test_log("observed", {
                "rcode": rcode,
                "has_ip_a": unbound.has_record(hostname, ip_a, "A"),
                "has_ip_b": unbound.has_record(hostname, ip_b, "A"),
            })

            assert rcode == _NOERROR, f"allow policy must return NOERROR; got rcode {rcode}"
            assert unbound.has_record(hostname, ip_a, "A"), \
                f"allow: original record {ip_a} must still be present"
            assert unbound.has_record(hostname, ip_b, "A"), \
                f"allow: new record {ip_b} must also be added"

        finally:
            unbound.remove_record(hostname)
            test_log("cleaned", {"hostname": hostname})

    # ── CP-2: first_wins with prerequisites ──────────────────────────────────

    def test_cp2_first_wins_with_prereqs_returns_yxrrset(
            self, ssh, unbound, test_host, test_log):
        """
        CP-2 (first_wins, prereqs present): collider's UPDATE is rejected with
        YXRRSET and the original record is preserved.

        Prereqs in the packet signal that D2 is in check-with-dhcid mode.
        The listener returns YXRRSET so D2 logs DHCP_DDNS_UPDATE_FAILED.
        """
        hostname = test_host["hostname"]
        ip_b     = test_host["ip"]
        ip_a     = _other_ip(ip_b)

        _set_collision_policy(ssh, "first_wins")
        _restart_daemon(ssh)

        unbound.add_record(f'"{hostname}. 300 IN A {ip_a}"')

        try:
            rcode = _send_a_update(ssh, hostname, ip_b, with_prereqs=True)

            test_log("injected", {"hostname": hostname, "ip_a": ip_a, "ip_b": ip_b})
            test_log("observed", {
                "rcode": rcode,
                "has_ip_a": unbound.has_record(hostname, ip_a, "A"),
                "has_ip_b": unbound.has_record(hostname, ip_b, "A"),
            })

            assert rcode == _YXRRSET, \
                f"first_wins + prereqs must return YXRRSET (9); got rcode {rcode}"
            assert unbound.has_record(hostname, ip_a, "A"), \
                f"first_wins: original record {ip_a} must be preserved"
            assert not unbound.has_record(hostname, ip_b, "A"), \
                f"first_wins: collider {ip_b} must NOT be added"

        finally:
            unbound.remove_record(hostname)
            test_log("cleaned", {"hostname": hostname})

    # ── CP-3: first_wins without prerequisites ───────────────────────────────

    def test_cp3_first_wins_no_prereqs_blocks_silently(
            self, ssh, unbound, test_host, test_log):
        """
        CP-3 (first_wins, no prereqs): collider is silently blocked.
        NOERROR is returned (D2 won't retry) but the A record is NOT added.

        No-prereqs means D2 is in no-check-without-dhcid mode; D2 won't
        interpret YXRRSET meaningfully, so we skip it and return NOERROR.
        The plugin enforces first_wins regardless — the add is silently skipped.
        """
        hostname = test_host["hostname"]
        ip_b     = test_host["ip"]
        ip_a     = _other_ip(ip_b)

        _set_collision_policy(ssh, "first_wins")
        _restart_daemon(ssh)

        unbound.add_record(f'"{hostname}. 300 IN A {ip_a}"')

        try:
            rcode = _send_a_update(ssh, hostname, ip_b, with_prereqs=False)

            test_log("injected", {"hostname": hostname, "ip_a": ip_a, "ip_b": ip_b})
            test_log("observed", {
                "rcode": rcode,
                "has_ip_a": unbound.has_record(hostname, ip_a, "A"),
                "has_ip_b": unbound.has_record(hostname, ip_b, "A"),
            })

            assert rcode == _NOERROR, \
                f"first_wins + no prereqs must return NOERROR; got rcode {rcode}"
            assert unbound.has_record(hostname, ip_a, "A"), \
                f"first_wins: original record {ip_a} must be preserved"
            assert not unbound.has_record(hostname, ip_b, "A"), \
                f"first_wins: collider {ip_b} must NOT be added even with NOERROR"

        finally:
            unbound.remove_record(hostname)
            test_log("cleaned", {"hostname": hostname})

    # ── CP-4: first_wins blocks explicit PTR packet too ───────────────────────

    def test_cp4_first_wins_blocks_ptr_packet(
            self, ssh, unbound, test_host, test_log):
        """
        CP-4 (first_wins, PTR consistency): when the A is blocked, the
        subsequent explicit PTR UPDATE from D2 must also be blocked.

        D2 sends A and PTR as separate UDP packets. The second packet is a
        PTR ADD for ip_b -> hostname. Since hostname is already registered to
        ip_a, the listener must not add a PTR for ip_b (that would be a dangling
        PTR pointing to a name not registered at ip_b).
        """
        hostname = test_host["hostname"]
        ip_b     = test_host["ip"]
        ip_a     = _other_ip(ip_b)

        _set_collision_policy(ssh, "first_wins")
        _restart_daemon(ssh)

        unbound.add_record(f'"{hostname}. 300 IN A {ip_a}"')

        try:
            # Packet 1: A ADD — blocked
            rcode_a = _send_a_update(ssh, hostname, ip_b, with_prereqs=False)
            # Packet 2: PTR ADD — must also be blocked
            rcode_ptr = _send_ptr_update(ssh, ip_b, hostname)

            test_log("injected", {"hostname": hostname, "ip_a": ip_a, "ip_b": ip_b})
            test_log("observed", {
                "rcode_a": rcode_a,
                "rcode_ptr": rcode_ptr,
                "has_ip_a": unbound.has_record(hostname, ip_a, "A"),
                "has_ip_b": unbound.has_record(hostname, ip_b, "A"),
                "has_ptr_b": unbound.has_ptr(ip_b, hostname),
            })

            assert rcode_a == _NOERROR, \
                f"A packet: expected NOERROR; got {rcode_a}"
            assert rcode_ptr == _NOERROR, \
                f"PTR packet: expected NOERROR; got {rcode_ptr}"
            assert unbound.has_record(hostname, ip_a, "A"), \
                f"original A record {ip_a} must be preserved"
            assert not unbound.has_record(hostname, ip_b, "A"), \
                f"collider A {ip_b} must not be added"
            assert not unbound.has_ptr(ip_b, hostname), \
                f"collider PTR for {ip_b} must not be added (no dangling PTR)"

        finally:
            unbound.remove_record(hostname)
            import ipaddress
            ptr_b = str(ipaddress.ip_address(ip_b).reverse_pointer)
            unbound.remove_record(ptr_b)
            test_log("cleaned", {"hostname": hostname})

    # ── CP-5: last_wins ───────────────────────────────────────────────────────

    def test_cp5_last_wins_replaces_existing(
            self, ssh, unbound, test_host, test_log):
        """
        CP-5 (last_wins): new registrant's IP replaces the existing one.
        The old A record is removed; only the new IP survives.
        """
        hostname = test_host["hostname"]
        ip_b     = test_host["ip"]
        ip_a     = _other_ip(ip_b)

        _set_collision_policy(ssh, "last_wins")
        _restart_daemon(ssh)

        unbound.add_record(f'"{hostname}. 300 IN A {ip_a}"')

        try:
            rcode = _send_a_update(ssh, hostname, ip_b)

            test_log("injected", {"hostname": hostname, "ip_a": ip_a, "ip_b": ip_b})
            test_log("observed", {
                "rcode": rcode,
                "has_ip_a": unbound.has_record(hostname, ip_a, "A"),
                "has_ip_b": unbound.has_record(hostname, ip_b, "A"),
            })

            assert rcode == _NOERROR, \
                f"last_wins must return NOERROR; got rcode {rcode}"
            assert not unbound.has_record(hostname, ip_a, "A"), \
                f"last_wins: old record {ip_a} must be removed"
            assert unbound.has_record(hostname, ip_b, "A"), \
                f"last_wins: new record {ip_b} must be present"

        finally:
            unbound.remove_record(hostname)
            test_log("cleaned", {"hostname": hostname})
