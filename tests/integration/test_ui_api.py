# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration tests — OPNsense REST API endpoints (UI buttons).

All tests use the API key mechanism (requests.Session with HTTPDigestAuth).
Tests verify that each button / tab in the plugin UI has a corresponding
working API endpoint.
"""

from __future__ import annotations

import time

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]


def test_api_general_get_returns_schema(api, deploy, test_log):
    """Settings tab: GET /api/keaunbound/general/get returns expected fields."""
    result = api.api_get("general/get")
    test_log("observed", {"keys": list(result.keys())})
    assert "general" in result
    general = result["general"]
    for field in ("enabled", "port", "aggressive_cleanup", "sync_static_reservations",
                  "sync_dynamic_leases", "collision_policy",
                  "enable_auto_clean", "auto_clean_interval"):
        assert field in general, f"Missing field in general/get: {field}"


def test_api_general_set_roundtrip(api, test_log):
    """Settings: POST set then GET must return the posted value."""
    original = api.api_get("general/get")["general"]

    api.api_post("general/set", {
        "general": {"port": "53536"}
    })
    updated = api.api_get("general/get")["general"]
    test_log("observed", {"port_after": updated.get("port")})
    assert updated["port"] == "53536", "Port was not persisted"

    # Restore
    api.api_post("general/set", {"general": {"port": original.get("port", "53535")}})
    test_log("cleaned", True)


def test_api_service_start_stop(api, ssh, test_log):
    """Service control buttons: start → stop must work via API."""
    ssh("/usr/local/sbin/configctl keaunbound stop", check=False)
    time.sleep(0.5)

    r = api.api_post("service/start")
    test_log("observed", {"start_response": r})
    assert r.get("result", "").lower() in ("ok", "ok\n") or "started" in str(r).lower()
    time.sleep(2)

    r = api.api_post("service/stop")
    test_log("observed", {"stop_response": r})
    assert r.get("result", "").lower() in ("ok", "ok\n") or "stopped" in str(r).lower()


def test_api_service_restart(api, ssh, test_log):
    ssh("/usr/local/sbin/configctl keaunbound start", check=False)
    time.sleep(2)
    pid_before = ssh("cat /var/run/kea-unbound-ddns.pid 2>/dev/null || echo none",
                     check=False).strip()

    r = api.api_post("service/restart")
    time.sleep(3)
    pid_after = ssh("cat /var/run/kea-unbound-ddns.pid 2>/dev/null || echo none",
                    check=False).strip()

    test_log("observed", {"pid_before": pid_before, "pid_after": pid_after,
                          "response": r})
    assert pid_before != pid_after, "PID did not change after restart"

    ssh("/usr/local/sbin/configctl keaunbound stop", check=False)
    test_log("cleaned", True)


def test_api_audit_returns_json(api, test_log):
    """Lease Audit tab: status/audit must return valid audit JSON."""
    result = api.api_get("status/audit")
    test_log("observed", {"complete": result.get("complete"),
                          "record_count": len(result.get("records", []))})
    for key in ("complete", "records", "orphaned_ptrs"):
        assert key in result, f"Missing key in audit response: {key}"


def test_api_kcaconfig_check(api, test_log):
    """Kea Config Check tab: kcaconfig/check must return config summary."""
    result = api.api_get("kcaconfig/check")
    test_log("observed", {"keys": list(result.keys())})
    # Exact fields depend on KcaconfigController implementation;
    # at minimum it should not 404 or raise
    assert isinstance(result, dict)


def _find_kea_subnet(config_get_args, cidr, key="Dhcp4", subnet_key="subnet4"):
    """Locate a subnet (by CIDR) in a Kea config-get arguments payload."""
    cfg = config_get_args.get(key, {})
    for sn in cfg.get(subnet_key, []):
        if sn.get("subnet") == cidr:
            return sn
    for net in cfg.get("shared-networks", []):
        for sn in net.get(subnet_key, []):
            if sn.get("subnet") == cidr:
                return sn
    return None


def _pick_pushable_subnet(api):
    """Return (subnet_entry, listener_port) for a dhcp4 subnet with a config UUID."""
    check = api.api_get("kcaconfig/check")
    port = (check.get("our_listener") or {}).get("port", 53535)
    subs = [s for s in check.get("ipv4_subnets", []) if s.get("opnsense_uuid")]
    if not subs:
        pytest.skip("no dhcp4 subnet with an OPNsense UUID to push to")
    return subs[0], port


def _skip_if_d2_disabled(resp):
    """Push fails fast when the DDNS Agent is off — skip rather than fail."""
    if resp.get("status") == "error" and "DDNS Agent" in str(resp.get("message", "")):
        pytest.skip("Kea DDNS Agent not enabled on the rig")


class TestPushSettings:
    """Kea Config Check 'Apply Recommended Settings' push endpoint."""

    def test_push_subnet_sets_flags(self, api, kea, deploy, test_log):
        """scope=subnet writes the recommended DDNS flags; running Kea reflects them."""
        sub, port = _pick_pushable_subnet(api)
        cidr = sub["subnet"]

        resp = api.api_post("kcaconfig/push_settings", {
            "scope": "subnet",
            "service": sub["service"],
            "uuid": sub["opnsense_uuid"],
        })
        _skip_if_d2_disabled(resp)
        test_log("push_response", resp)
        assert resp.get("status") == "ok", resp
        assert cidr in resp.get("changed", []), resp

        time.sleep(3)  # let kea restart settle
        args = kea("config-get", "dhcp4").get("arguments", {})
        sn = _find_kea_subnet(args, cidr)
        assert sn is not None, f"subnet {cidr} not found in running Kea config"
        test_log("running_subnet", {k: sn.get(k) for k in (
            "ddns-send-updates", "ddns-override-no-update",
            "ddns-override-client-update", "ddns-update-on-renew",
            "ddns-conflict-resolution-mode")})
        assert sn.get("ddns-send-updates") is True
        assert sn.get("ddns-override-no-update") is True
        assert sn.get("ddns-override-client-update") is True
        assert sn.get("ddns-update-on-renew") is True
        assert sn.get("ddns-conflict-resolution-mode") == "no-check-without-dhcid"

    def test_push_d2_domain_targets_listener(self, api, ssh, test_log):
        """After a push, kea-dhcp-ddns.conf points the subnet's zone at our listener."""
        sub, port = _pick_pushable_subnet(api)
        resp = api.api_post("kcaconfig/push_settings", {
            "scope": "subnet",
            "service": sub["service"],
            "uuid": sub["opnsense_uuid"],
        })
        _skip_if_d2_disabled(resp)
        assert resp.get("status") == "ok", resp
        time.sleep(3)

        import json as _json
        raw = ssh("cat /usr/local/etc/kea/kea-dhcp-ddns.conf", check=False)
        conf = _json.loads(raw)
        domains = conf.get("DhcpDdns", {}).get("forward-ddns", {}).get("ddns-domains", [])
        servers = [s for d in domains for s in d.get("dns-servers", [])]
        test_log("d2_servers", servers)
        assert any(s.get("ip-address") == "127.0.0.1" and int(s.get("port", 0)) == int(port)
                   for s in servers), f"no D2 server entry for 127.0.0.1:{port}"

    def test_push_all_writes_subnets(self, api, test_log):
        """scope=all applies to every subnet and reports them in changed[]."""
        resp = api.api_post("kcaconfig/push_settings", {"scope": "all"})
        _skip_if_d2_disabled(resp)
        test_log("push_all_response", resp)
        assert resp.get("status") == "ok", resp
        assert len(resp.get("changed", [])) >= 1, resp

    def test_push_rejects_bad_scope(self, api, test_log):
        """An unknown scope is a clean error, not a 500 (no Kea restart)."""
        resp = api.api_post("kcaconfig/push_settings", {"scope": "bogus"})
        test_log("response", resp)
        assert resp.get("status") == "error", resp

    def test_push_rejects_unknown_uuid(self, api, test_log):
        """A non-existent subnet UUID returns 'not found' without touching config."""
        resp = api.api_post("kcaconfig/push_settings", {
            "scope": "subnet", "service": "dhcp4",
            "uuid": "00000000-0000-0000-0000-000000000000",
        })
        _skip_if_d2_disabled(resp)
        test_log("response", resp)
        assert resp.get("status") == "error", resp


def test_api_invalid_port_rejected(api, test_log):
    """Model validation should reject a non-numeric port."""
    import requests as req
    try:
        r = api.api_post("general/set", {"general": {"port": "not-a-port"}})
        test_log("observed", {"response": r})
        # OPNsense model validation returns a validations dict on error
        is_error = ("validations" in r or
                    r.get("result", "saved") not in ("saved",))
        assert is_error, f"Expected validation error, got: {r}"
    except req.HTTPError as e:
        # 422 or 400 is also acceptable
        assert e.response.status_code in (400, 422), f"Unexpected HTTP error: {e}"
