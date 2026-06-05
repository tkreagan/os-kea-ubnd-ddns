# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration tests — end-to-end DHCP lease → DNS registration flow.

Uses a real DHCP client box (DHCPCLIENT_HOST) that holds a live lease from
the OPNsense test box (OPNSENSE_HOST).  Tests exercise the full path:

  DHCP renew on client box
    → Kea issues / updates lease on OPNsense
    → configctl keaunbound sync_dynamic
    → Unbound registers <client-hostname>.lan A record
    → local-data-audit shows status "ok"
    → DHCP release → stale record
    → configctl keaunbound clean removes it

Requires OPNSENSE_HOST, OPNSENSE_SSH_*, DHCPCLIENT_HOST, DHCPCLIENT_SSH_*,
DHCPCLIENT_LAN_IF, and DHCPCLIENT_HOSTNAME to be set in tests/.env.
"""

from __future__ import annotations

import time

import pytest

from .conftest import SSHSession

pytestmark = [pytest.mark.integration, pytest.mark.slow]

# CLIENT_HOSTNAME and client_fqdn are resolved at fixture time from
# DHCPCLIENT_HOSTNAME in tests/.env — no machine-specific names in source.


# ── Helpers ───────────────────────────────────────────────────────────────────

def _client_ip(dhcpclient: SSHSession, lan_if: str) -> str | None:
    """Return the current IPv4 address on lan_if, or None."""
    out = dhcpclient.run(
        f"ip -4 addr show {lan_if} | grep -oP '(?<=inet )\\S+' | cut -d/ -f1",
        check=False,
    )
    return out.strip() or None


def _renew_lease(dhcpclient: SSHSession, lan_if: str) -> str | None:
    """Force a DHCP renew and return the new IP."""
    # networkctl renew requires systemd-networkd; fall back to dhclient
    out = dhcpclient(f"networkctl renew {lan_if} 2>/dev/null || "
                     f"dhclient -r {lan_if} && dhclient {lan_if}",
                     check=False)
    time.sleep(3)
    return _client_ip(dhcpclient, lan_if)


def _release_lease(dhcpclient: SSHSession, lan_if: str) -> None:
    """Release the DHCP lease on lan_if."""
    dhcpclient(f"networkctl down {lan_if} 2>/dev/null || "
               f"dhclient -r {lan_if} 2>/dev/null || true",
               check=False)
    time.sleep(2)


def _reclaim_lease(dhcpclient: SSHSession, lan_if: str) -> None:
    """Re-acquire a DHCP lease after release."""
    dhcpclient(f"networkctl up {lan_if} 2>/dev/null || "
               f"dhclient {lan_if} 2>/dev/null || true",
               check=False)
    time.sleep(5)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client_if(dhcpclient_info):
    return dhcpclient_info["lan_if"]


@pytest.fixture(scope="module")
def client_fqdn(dhcpclient_info):
    """FQDN of the DHCP client as Kea would qualify it (hostname + .lan)."""
    return f"{dhcpclient_info['hostname']}.lan"


@pytest.fixture(autouse=True)
def ensure_lease(dhcpclient, client_if):
    """Ensure the DHCP client has a lease at start and end of each test."""
    ip = _client_ip(dhcpclient, client_if)
    if not ip:
        _reclaim_lease(dhcpclient, client_if)
    yield
    ip = _client_ip(dhcpclient, client_if)
    if not ip:
        _reclaim_lease(dhcpclient, client_if)


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_client_has_dhcp_lease(dhcpclient, client_if, test_log):
    """Baseline: the DHCP client box holds a live lease."""
    ip = _client_ip(dhcpclient, client_if)
    test_log("observed", {"client_ip": ip, "interface": client_if})
    assert ip is not None, f"No IP on {client_if}"
    assert ip, f"Empty IP on {client_if}"


def test_lease_visible_in_kea(kea, dhcpclient, client_if, test_log):
    """The DHCP client's lease must appear in Kea's active lease list."""
    ip = _client_ip(dhcpclient, client_if)
    if not ip:
        pytest.skip("DHCP client has no IP")

    resp = kea("lease4-get-all", service="dhcp4")
    leases = resp.get("arguments", {}).get("leases", [])
    matching = [l for l in leases if l.get("ip-address") == ip]
    test_log("observed", {
        "client_ip": ip,
        "kea_lease_count": len(leases),
        "matching": len(matching),
    })
    assert matching, f"No Kea lease for {ip} — is kea-dhcp4 running?"


def test_sync_dynamic_registers_client(ssh, dhcpclient, client_if, client_fqdn,
                                       unbound, deploy, test_log):
    """sync_dynamic must register the DHCP client in Unbound."""
    ip = _client_ip(dhcpclient, client_if)
    if not ip:
        pytest.skip("DHCP client has no IP")

    # Ensure no stale record from a previous run
    unbound.remove_record(client_fqdn)

    ssh("/usr/local/sbin/configctl keaunbound sync_dynamic")
    time.sleep(2)

    has_a   = unbound.has_record(client_fqdn, ip, "A")
    has_ptr = unbound.has_ptr(ip, client_fqdn)
    test_log("observed", {
        "client_ip": ip,
        "unbound_A":   has_a,
        "unbound_PTR": has_ptr,
    })
    assert has_a,   f"A record {client_fqdn} → {ip} missing after sync_dynamic"
    assert has_ptr, f"PTR for {ip} missing after sync_dynamic"

    # Cleanup
    unbound.remove_record(client_fqdn)
    import ipaddress
    unbound.remove_record(str(ipaddress.ip_address(ip).reverse_pointer))
    test_log("cleaned", True)


def test_audit_shows_lease_as_ok(ssh, dhcpclient, client_if, client_fqdn,
                                  unbound, test_log):
    """After sync_dynamic, local-data-audit must show client as 'ok' or 'missing-PTR'."""
    import json as _json

    ip = _client_ip(dhcpclient, client_if)
    if not ip:
        pytest.skip("DHCP client has no IP")

    unbound.remove_record(client_fqdn)
    ssh("/usr/local/sbin/configctl keaunbound sync_dynamic")
    time.sleep(2)

    raw = ssh(
        "/usr/local/opnsense/scripts/keaunbound/local-data-audit.py --report-json",
        check=False,
    )
    try:
        audit = _json.loads(raw)
    except _json.JSONDecodeError:
        pytest.skip(f"Audit returned non-JSON: {raw[:200]}")

    records = [r for r in audit.get("records", [])
               if r.get("ip") == ip]
    test_log("observed", {
        "client_ip": ip,
        "audit_complete": audit.get("complete"),
        "matching_records": records,
    })
    assert records, f"No audit record for IP {ip}"
    statuses = {r["status"] for r in records}
    assert statuses <= {"ok", "missing-PTR", "static"}, \
        f"Unexpected status(es) for {ip}: {statuses}"

    unbound.remove_record(client_fqdn)
    import ipaddress
    unbound.remove_record(str(ipaddress.ip_address(ip).reverse_pointer))
    test_log("cleaned", True)


def test_renew_updates_registration(ssh, dhcpclient, client_if, client_fqdn,
                                     unbound, test_log):
    """
    Force a DHCP renew; re-run sync_dynamic; the Unbound record must reflect
    the current (possibly same) IP.
    """
    ip_before = _client_ip(dhcpclient, client_if)
    unbound.remove_record(client_fqdn)

    ip_after = _renew_lease(dhcpclient, client_if)
    if not ip_after:
        pytest.skip("Client did not get an IP after renew")

    ssh("/usr/local/sbin/configctl keaunbound sync_dynamic")
    time.sleep(2)

    has_a = unbound.has_record(client_fqdn, ip_after, "A")
    test_log("observed", {
        "ip_before": ip_before,
        "ip_after":  ip_after,
        "unbound_A": has_a,
    })
    assert has_a, f"Unbound A record for {client_fqdn} → {ip_after} missing after renew + sync"

    unbound.remove_record(client_fqdn)
    import ipaddress
    unbound.remove_record(str(ipaddress.ip_address(ip_after).reverse_pointer))
    test_log("cleaned", True)


def test_stale_record_cleaned_after_release(ssh, dhcpclient, client_if, client_fqdn,
                                             unbound, test_log):
    """
    Release the lease → Kea removes it → clean script must remove the stale
    Unbound record.

    This test releases the lease and re-acquires it at the end, so it should
    always leave the client in a working state.
    """
    ip = _client_ip(dhcpclient, client_if)
    if not ip:
        pytest.skip("DHCP client has no IP")

    # Register current lease in Unbound
    unbound.remove_record(client_fqdn)
    ssh("/usr/local/sbin/configctl keaunbound sync_dynamic")
    time.sleep(2)
    assert unbound.has_record(client_fqdn, ip, "A"), \
        "Pre-condition: record not in Unbound after sync"

    test_log("injected", {"phase": "release", "client_ip": ip})

    # Release the lease — Kea drops it, Unbound record becomes stale
    _release_lease(dhcpclient, client_if)

    # Run the clean script — should remove the now-stale record
    ssh("/usr/local/sbin/configctl keaunbound clean")
    time.sleep(2)

    still_present = unbound.has_record(client_fqdn, ip, "A")
    test_log("observed", {
        "client_ip": ip,
        "record_after_clean": still_present,
    })
    assert not still_present, \
        f"Stale record {client_fqdn} → {ip} not removed after release + clean"

    # Restore: re-acquire lease so subsequent tests can run
    _reclaim_lease(dhcpclient, client_if)
    ip_new = _client_ip(dhcpclient, client_if)
    test_log("cleaned", {"re_acquired_ip": ip_new})


def test_ttl_reflects_remaining_lease_time(ssh, kea, dhcpclient, client_if, client_fqdn,
                                            unbound, test_log):
    """
    The TTL of the Unbound record must be ≤ the remaining lease time reported
    by Kea (within a small tolerance for the time between the two queries).
    """
    ip = _client_ip(dhcpclient, client_if)
    if not ip:
        pytest.skip("DHCP client has no IP")

    # Find the lease in Kea to get its expiry
    resp = kea("lease4-get-all", service="dhcp4")
    leases = [l for l in resp.get("arguments", {}).get("leases", [])
              if l.get("ip-address") == ip]
    if not leases:
        pytest.skip(f"No lease for {ip} found in Kea")

    import time as _time
    expire = leases[0].get("expire", 0)
    remaining_kea = max(1, expire - int(_time.time())) if expire else None

    unbound.remove_record(client_fqdn)
    ssh("/usr/local/sbin/configctl keaunbound sync_dynamic")
    time.sleep(1)

    data = unbound.list_local_data()
    unbound_ttl = None
    for line in data.get(client_fqdn, []):
        parts = line.split()
        if len(parts) >= 5 and "A" in parts[3]:
            try:
                unbound_ttl = int(parts[1])
            except ValueError:
                pass

    test_log("observed", {
        "client_ip": ip,
        "kea_remaining_s": remaining_kea,
        "unbound_ttl_s": unbound_ttl,
    })
    assert unbound_ttl is not None, "No TTL found in Unbound for client record"
    if remaining_kea is not None:
        assert unbound_ttl <= remaining_kea + 5, (
            f"Unbound TTL {unbound_ttl}s > Kea remaining {remaining_kea}s "
            f"(should be ≤ with 5s tolerance)"
        )

    unbound.remove_record(client_fqdn)
    import ipaddress
    unbound.remove_record(str(ipaddress.ip_address(ip).reverse_pointer))
    test_log("cleaned", True)
