# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration tests — reservation-sync.py and lease-sync.py.

Verifies that the configd actions sync_static and sync_dynamic actually
produce the expected Unbound records, and that the host_entries.conf guard
prevents static overrides from being touched.
"""

from __future__ import annotations

import time

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]


def test_sync_static_runs_without_error(ssh, deploy, test_log):
    out = ssh("/usr/local/sbin/configctl keaunbound sync_static")
    test_log("observed", {"output": out[:500]})
    # Must not contain "Error" from the Python script (configd output)
    assert "Traceback" not in out
    assert "Exception" not in out


def test_sync_dynamic_runs_without_error(ssh, deploy, test_log):
    out = ssh("/usr/local/sbin/configctl keaunbound sync_dynamic")
    test_log("observed", {"output": out[:500]})
    assert "Traceback" not in out
    assert "Exception" not in out


def test_sync_static_registers_reservation(ssh, kea, dhcp4_subnet_id,
                                           test_host, unbound, test_log):
    hostname = test_host["hostname"]
    ip = test_host["ip"]

    kea("subnet4-reservation-add", service="dhcp4", arguments={
        "reservation": {
            "subnet-id": dhcp4_subnet_id,
            "hw-address": "aa:bb:cc:88:00:01",
            "ip-address": ip,
            "hostname": hostname.replace(".lan", ""),
        }
    })
    test_log("injected", {"type": "reservation", "hostname": hostname, "ip": ip})

    ssh("/usr/local/sbin/configctl keaunbound sync_static")
    time.sleep(2)

    has_a = unbound.has_record(hostname, ip, "A")
    has_ptr = unbound.has_ptr(ip, hostname)
    test_log("observed", {"has_A": has_a, "has_PTR": has_ptr})
    assert has_a
    assert has_ptr

    kea("subnet4-reservation-del", service="dhcp4",
        arguments={"subnet-id": dhcp4_subnet_id, "ip-address": ip})
    unbound.remove_record(hostname)
    try:
        import ipaddress
        unbound.remove_record(str(ipaddress.ip_address(ip).reverse_pointer))
    except Exception:
        pass
    test_log("cleaned", True)


def test_sync_does_not_touch_host_entries(ssh, unbound, test_log):
    """Records in host_entries.conf must survive a sync without change."""
    before = unbound.list_local_data().get("router.lan", [])
    ssh("/usr/local/sbin/configctl keaunbound sync_static")
    time.sleep(2)
    after = unbound.list_local_data().get("router.lan", [])
    test_log("observed", {"before": before, "after": after})
    # Both empty is fine (router.lan may not be on this test box)
    # The point is they must be equal
    assert before == after, "host_entries.conf record changed after sync"


def test_sync_dynamic_ttl_bounded(ssh, kea, dhcp4_subnet_id, test_host, unbound, test_log):
    hostname = test_host["hostname"]
    ip = test_host["ip"]
    target_ttl = 600
    expire = int(time.time()) + target_ttl

    kea("lease4-add", service="dhcp4", arguments={
        "ip-address": ip, "hw-address": "aa:bb:cc:88:00:02",
        "hostname": hostname.replace(".lan", ""),
        "subnet-id": dhcp4_subnet_id,
        "expire": expire, "valid-lft": target_ttl, "state": 0,
    })
    test_log("injected", {"hostname": hostname, "ip": ip, "target_ttl": target_ttl})

    ssh("/usr/local/sbin/configctl keaunbound sync_dynamic")
    time.sleep(2)

    data = unbound.list_local_data()
    ttl = None
    for line in data.get(hostname, []):
        parts = line.split()
        if len(parts) >= 5 and "A" in parts[3]:
            ttl = int(parts[1])
    test_log("observed", {"ttl": ttl})
    assert ttl is not None
    assert 1 <= ttl <= target_ttl

    kea("lease4-del", service="dhcp4", arguments={"ip-address": ip})
    unbound.remove_record(hostname)
    test_log("cleaned", True)
