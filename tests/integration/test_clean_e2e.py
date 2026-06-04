# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration tests — local-data-clean.py end-to-end.

Injects synthetic stale records into Unbound (not backed by Kea) and
verifies that the clean script removes them while leaving valid records alone.
"""

from __future__ import annotations

import time

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]


@pytest.fixture
def stale_record(ssh, test_host, unbound, test_log):
    """Inject a stale Unbound record with no Kea backing."""
    hostname = test_host["hostname"]
    ip = test_host["ip"]
    ssh(f"/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
        f"local_data '{hostname} 300 IN A {ip}'")
    test_log("injected", {"type": "stale_unbound_record", "hostname": hostname, "ip": ip})
    yield hostname, ip
    # Cleanup in case the test failed (record may already be gone)
    ssh(f"/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
        f"local_data_remove {hostname}", check=False)
    test_log("cleaned", True)


def test_clean_removes_stale_record(ssh, stale_record, unbound, test_log):
    hostname, ip = stale_record
    assert unbound.has_record(hostname, ip, "A"), "Pre-condition: stale record not found"

    ssh("/usr/local/sbin/configctl keaunbound clean")
    time.sleep(2)

    still_present = unbound.has_record(hostname, ip, "A")
    test_log("observed", {"still_present": still_present})
    assert not still_present, f"Stale record {hostname} → {ip} not removed by clean"


def test_clean_removes_orphaned_ptr(ssh, test_host, unbound, test_log):
    hostname = test_host["hostname"]
    ip = test_host["ip"]
    import ipaddress
    ptr = str(ipaddress.ip_address(ip).reverse_pointer)

    # Inject orphaned PTR without a forward record
    ssh(f"/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
        f"local_data '{ptr} 300 IN PTR {hostname}.'")
    test_log("injected", {"type": "orphaned_ptr", "ptr": ptr, "target": hostname})

    ssh("/usr/local/sbin/configctl keaunbound clean")
    time.sleep(2)

    data = unbound.list_local_data()
    ptr_present = ptr in data
    test_log("observed", {"ptr_still_present": ptr_present})
    assert not ptr_present, f"Orphaned PTR {ptr} not removed"
    test_log("cleaned", True)


def test_clean_preserves_kea_backed_record(ssh, kea, dhcp4_subnet_id,
                                           test_host, unbound, test_log):
    hostname = test_host["hostname"]
    ip = test_host["ip"]

    kea("lease4-add", service="dhcp4", arguments={
        "ip-address": ip, "hw-address": "aa:bb:cc:77:00:01",
        "hostname": hostname.replace(".lan", ""),
        "subnet-id": dhcp4_subnet_id,
        "expire": int(time.time()) + 3600, "valid-lft": 3600, "state": 0,
    })
    ssh(f"/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
        f"local_data '{hostname} 300 IN A {ip}'")
    test_log("injected", {"type": "kea_backed_record", "hostname": hostname, "ip": ip})

    ssh("/usr/local/sbin/configctl keaunbound clean")
    time.sleep(2)

    still_present = unbound.has_record(hostname, ip, "A")
    test_log("observed", {"still_present": still_present})
    assert still_present, f"Valid Kea-backed record {hostname} was incorrectly removed"

    kea("lease4-del", service="dhcp4", arguments={"ip-address": ip})
    unbound.remove_record(hostname)
    test_log("cleaned", True)


def test_clean_does_not_touch_host_entries(ssh, unbound, test_log):
    """Records from host_entries.conf must survive a clean run."""
    before = unbound.list_local_data().get("router.lan", [])
    ssh("/usr/local/sbin/configctl keaunbound clean")
    time.sleep(2)
    after = unbound.list_local_data().get("router.lan", [])
    test_log("observed", {"before": before, "after": after})
    assert before == after, "host_entries.conf record was changed by clean"


def test_clean_dry_run_does_not_remove(ssh, stale_record, unbound, test_log):
    hostname, ip = stale_record
    ssh("/usr/local/opnsense/scripts/keaunbound/local-data-clean.py --dry-run")
    time.sleep(1)
    still_present = unbound.has_record(hostname, ip, "A")
    test_log("observed", {"still_present_after_dry_run": still_present})
    assert still_present, "Dry-run removed a record — it should not have"
