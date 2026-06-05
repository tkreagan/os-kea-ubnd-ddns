# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration tests — local-data-audit.py end-to-end.

Verifies the JSON output structure and status values against known
injected state on the OPNsense box.
"""

from __future__ import annotations

import json
import time

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]


def _run_audit(ssh) -> dict:
    raw = ssh("/usr/local/opnsense/scripts/keaunbound/local-data-audit.py --report-json")
    return json.loads(raw)


def test_audit_returns_valid_json(ssh, deploy, test_log):
    result = _run_audit(ssh)
    test_log("observed", {"complete": result.get("complete")})
    for key in ("complete", "kea_error", "records", "orphaned_ptrs", "ptr_records"):
        assert key in result, f"Missing key: {key}"


def test_audit_complete_when_kea_running(ssh, test_log):
    result = _run_audit(ssh)
    test_log("observed", {"complete": result["complete"], "kea_error": result["kea_error"]})
    assert result["complete"] is True, f"Audit incomplete: {result['kea_error']}"


def test_audit_shows_stale_record(ssh, test_host, unbound, test_log):
    hostname = test_host["hostname"]
    ip = test_host["ip"]
    ssh(f"/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
        f"local_data '{hostname} 300 IN A {ip}'")
    test_log("injected", {"type": "stale_record", "hostname": hostname, "ip": ip})
    time.sleep(1)

    result = _run_audit(ssh)
    stale = [r for r in result["records"]
             if r["hostname"] == hostname and r["status"] == "stale"]
    test_log("observed", {"stale_count": len(stale)})
    assert len(stale) >= 1, f"Expected stale record for {hostname}, not found"

    ssh(f"/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
        f"local_data_remove {hostname}", check=False)
    test_log("cleaned", True)


def test_audit_shows_reservation_as_ok(ssh, kea, dhcp4_subnet_id,
                                        test_host, unbound, test_log):
    hostname = test_host["hostname"]
    ip = test_host["ip"]

    kea("subnet4-reservation-add", service="dhcp4", arguments={
        "reservation": {
            "subnet-id": dhcp4_subnet_id,
            "hw-address": "aa:bb:cc:66:00:01",
            "ip-address": ip,
            "hostname": hostname.replace(".lan", ""),
        }
    })
    ssh("/usr/local/sbin/configctl keaunbound sync_static")
    time.sleep(2)
    test_log("injected", {"type": "reservation", "hostname": hostname, "ip": ip})

    result = _run_audit(ssh)
    ok = [r for r in result["records"]
          if r["hostname"] == hostname and r["status"] in ("ok", "missing-PTR")]
    test_log("observed", {"ok_count": len(ok)})
    assert len(ok) >= 1, f"Expected ok/missing-PTR record for {hostname}"

    kea("subnet4-reservation-del", service="dhcp4",
        arguments={"subnet-id": dhcp4_subnet_id, "ip-address": ip})
    unbound.remove_record(hostname)
    test_log("cleaned", True)


def test_audit_shows_orphaned_ptr(ssh, test_host, unbound, test_log):
    import ipaddress
    hostname = test_host["hostname"]
    ip = test_host["ip"]
    ptr = str(ipaddress.ip_address(ip).reverse_pointer)

    ssh(f"/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
        f"local_data '{ptr} 300 IN PTR {hostname}.'")
    test_log("injected", {"type": "orphaned_ptr", "ptr": ptr})
    time.sleep(1)

    result = _run_audit(ssh)
    orphans = [o for o in result["orphaned_ptrs"] if o["ptr_name"] == ptr]
    test_log("observed", {"orphan_count": len(orphans)})
    assert len(orphans) == 1, f"Expected orphaned PTR {ptr}"

    ssh(f"/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
        f"local_data_remove {ptr}", check=False)
    test_log("cleaned", True)


def test_audit_record_fields(ssh, test_log):
    result = _run_audit(ssh)
    if not result["records"]:
        pytest.skip("No records in Unbound to validate field structure")
    r = result["records"][0]
    for field in ("hostname", "ip", "type", "ttl", "ptr_registered",
                  "ptr_state", "reserved", "leased", "override", "live",
                  "source", "in_unbound", "status"):
        assert field in r, f"Missing field: {field}"
    test_log("observed", {"first_record": r})
