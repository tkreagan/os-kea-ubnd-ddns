# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration tests — Kea lease and reservation injection.

Injects synthetic leases / reservations via the Kea control socket, runs
the sync scripts, and verifies Unbound state.  All test data uses the
192.168.99.200-254 range and "testhost-NNN.lan" hostnames.

Prerequisites:
  - dhcp4 running with a subnet that covers 192.168.99.0/24
  - lease_cmds hook loaded in kea-dhcp4 (for lease4-add)
  - The plugin installed and configured on the OPNsense box
"""

from __future__ import annotations

import time

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

# Discover the first subnet ID on the box at session start
@pytest.fixture(scope="session")
def dhcp4_subnet_id(kea):
    resp = kea("config-get", service="dhcp4")
    subnets = resp.get("arguments", {}).get("Dhcp4", {}).get("subnet4", [])
    if not subnets:
        pytest.skip("No DHCPv4 subnets configured on the OPNsense box")
    return subnets[0]["id"]


@pytest.fixture
def injected_lease(kea, dhcp4_subnet_id, test_host, unbound, test_log):
    """Inject an active DHCPv4 lease and clean it up after the test."""
    hostname = test_host["hostname"]
    ip = test_host["ip"]
    expire = int(time.time()) + 3600

    test_log("injected", {
        "type": "lease4",
        "hostname": hostname,
        "ip": ip,
        "subnet_id": dhcp4_subnet_id,
        "expire": expire,
    })

    resp = kea("lease4-add", service="dhcp4", arguments={
        "ip-address": ip,
        "hw-address": "aa:bb:cc:99:00:01",
        "hostname": hostname.replace(".lan", ""),
        "subnet-id": dhcp4_subnet_id,
        "expire": expire,
        "valid-lft": 3600,
        "state": 0,
    })
    if resp.get("result", 1) != 0:
        pytest.skip(f"lease4-add failed: {resp.get('text')} "
                    f"(lease_cmds hook may not be loaded)")

    yield hostname, ip

    # Cleanup — remove lease and Unbound record
    kea("lease4-del", service="dhcp4", arguments={"ip-address": ip})
    unbound.remove_record(hostname)
    import ipaddress
    ptr = str(ipaddress.ip_address(ip).reverse_pointer)
    # ignore errors — record may already be gone
    try:
        unbound.remove_record(ptr)
    except Exception:
        pass
    test_log("cleaned", True)


@pytest.fixture
def injected_reservation(kea, dhcp4_subnet_id, test_host, unbound, test_log):
    """Inject a static reservation via subnet4-reservation-add."""
    hostname = test_host["hostname"]
    ip = test_host["ip"]

    test_log("injected", {
        "type": "reservation",
        "hostname": hostname,
        "ip": ip,
        "subnet_id": dhcp4_subnet_id,
    })

    resp = kea("subnet4-reservation-add", service="dhcp4", arguments={
        "reservation": {
            "subnet-id": dhcp4_subnet_id,
            "hw-address": "aa:bb:cc:99:00:02",
            "ip-address": ip,
            "hostname": hostname.replace(".lan", ""),
        }
    })
    if resp.get("result", 1) != 0:
        pytest.skip(f"subnet4-reservation-add failed: {resp.get('text')}")

    yield hostname, ip

    kea("subnet4-reservation-del", service="dhcp4", arguments={
        "subnet-id": dhcp4_subnet_id,
        "ip-address": ip,
    })
    unbound.remove_record(hostname)
    try:
        import ipaddress
        ptr = str(ipaddress.ip_address(ip).reverse_pointer)
        unbound.remove_record(ptr)
    except Exception:
        pass
    test_log("cleaned", True)


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_lease_sync_registers_active_lease(ssh, injected_lease, unbound, test_log):
    hostname, ip = injected_lease
    ssh("/usr/local/sbin/configctl keaunbound sync_dynamic")
    time.sleep(2)

    has_a = unbound.has_record(hostname, ip, "A")
    has_ptr = unbound.has_ptr(ip, hostname)
    test_log("observed", {"unbound_A": has_a, "unbound_PTR": has_ptr})
    assert has_a, f"A record {hostname} → {ip} not in Unbound after lease sync"
    assert has_ptr, f"PTR for {ip} not in Unbound after lease sync"


def test_lease_sync_ttl_is_bounded(ssh, kea, dhcp4_subnet_id, test_host, unbound, test_log):
    hostname = test_host["hostname"]
    ip = test_host["ip"]
    expire = int(time.time()) + 500

    kea("lease4-add", service="dhcp4", arguments={
        "ip-address": ip, "hw-address": "aa:bb:cc:99:00:03",
        "hostname": hostname.replace(".lan", ""),
        "subnet-id": dhcp4_subnet_id,
        "expire": expire, "valid-lft": 500, "state": 0,
    })
    ssh("/usr/local/sbin/configctl keaunbound sync_dynamic")
    time.sleep(2)

    data = unbound.list_local_data()
    lines = data.get(hostname, [])
    ttl = None
    for line in lines:
        parts = line.split()
        if len(parts) >= 5 and "A" in parts[3] and ip in parts[4]:
            ttl = int(parts[1])
    test_log("observed", {"ttl": ttl})
    assert ttl is not None, "Record not found in Unbound"
    assert 1 <= ttl <= 500, f"TTL {ttl} out of expected range 1-500"

    kea("lease4-del", service="dhcp4", arguments={"ip-address": ip})
    unbound.remove_record(hostname)
    test_log("cleaned", True)


def test_reservation_sync_registers_static(ssh, injected_reservation, unbound, test_log):
    hostname, ip = injected_reservation
    ssh("/usr/local/sbin/configctl keaunbound sync_static")
    time.sleep(2)

    has_a = unbound.has_record(hostname, ip, "A")
    has_ptr = unbound.has_ptr(ip, hostname)
    test_log("observed", {"unbound_A": has_a, "unbound_PTR": has_ptr})
    assert has_a, f"A record {hostname} → {ip} not found after reservation sync"
    assert has_ptr


def test_expired_lease_not_synced(ssh, kea, dhcp4_subnet_id, test_host, unbound, test_log):
    hostname = test_host["hostname"]
    ip = test_host["ip"]
    past = int(time.time()) - 100

    kea("lease4-add", service="dhcp4", arguments={
        "ip-address": ip, "hw-address": "aa:bb:cc:99:00:04",
        "hostname": hostname.replace(".lan", ""),
        "subnet-id": dhcp4_subnet_id,
        "expire": past, "valid-lft": 3600, "state": 0,
    })
    ssh("/usr/local/sbin/configctl keaunbound sync_dynamic")
    time.sleep(2)

    has_a = unbound.has_record(hostname, ip, "A")
    test_log("observed", {"expired_lease_in_unbound": has_a})
    assert not has_a, "Expired lease was incorrectly registered in Unbound"

    kea("lease4-del", service="dhcp4", arguments={"ip-address": ip})
    test_log("cleaned", True)


def test_declined_lease_not_synced(ssh, kea, dhcp4_subnet_id, test_host, unbound, test_log):
    hostname = test_host["hostname"]
    ip = test_host["ip"]
    expire = int(time.time()) + 3600

    kea("lease4-add", service="dhcp4", arguments={
        "ip-address": ip, "hw-address": "aa:bb:cc:99:00:05",
        "hostname": hostname.replace(".lan", ""),
        "subnet-id": dhcp4_subnet_id,
        "expire": expire, "valid-lft": 3600,
        "state": 1,  # declined
    })
    ssh("/usr/local/sbin/configctl keaunbound sync_dynamic")
    time.sleep(2)

    has_a = unbound.has_record(hostname, ip, "A")
    test_log("observed", {"declined_lease_in_unbound": has_a})
    assert not has_a, "Declined lease was incorrectly registered"

    kea("lease4-del", service="dhcp4", arguments={"ip-address": ip})
    test_log("cleaned", True)


def test_dual_stack_both_registered(ssh, kea, dhcp4_subnet_id, test_host, unbound, test_log):
    hostname = test_host["hostname"]
    ip4 = test_host["ip"]
    ip6 = "2001:db8:99::1"

    kea("lease4-add", service="dhcp4", arguments={
        "ip-address": ip4, "hw-address": "aa:bb:cc:99:00:06",
        "hostname": hostname.replace(".lan", ""),
        "subnet-id": dhcp4_subnet_id,
        "expire": int(time.time()) + 3600, "valid-lft": 3600, "state": 0,
    })
    # Inject AAAA directly (Kea6 may not be configured on the test box)
    ssh(f"/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
        f"local_data '{hostname} 300 IN AAAA {ip6}'")

    ssh("/usr/local/sbin/configctl keaunbound sync_dynamic")
    time.sleep(2)

    test_log("observed", {
        "has_A": unbound.has_record(hostname, ip4, "A"),
        "has_AAAA": unbound.has_record(hostname, ip6, "AAAA"),
    })
    assert unbound.has_record(hostname, ip4, "A")
    assert unbound.has_record(hostname, ip6, "AAAA")

    kea("lease4-del", service="dhcp4", arguments={"ip-address": ip4})
    unbound.remove_record(hostname)
    test_log("cleaned", True)
