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
    for field in ("enabled", "port", "enable_tsig", "tsig_algorithm",
                  "aggressive_cleanup", "sync_static_reservations",
                  "sync_dynamic_leases", "enable_auto_clean", "auto_clean_interval"):
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


def test_api_tsig_fields_exposed_when_toggled(api, test_log):
    """TSIG enabled flag must surface in get response."""
    api.api_post("general/set", {"general": {"enable_tsig": "1",
                                              "tsig_key_name": "testkey",
                                              "tsig_key_secret": "dGVzdA=="}})
    result = api.api_get("general/get")
    g = result["general"]
    test_log("observed", {"enable_tsig": g.get("enable_tsig")})
    assert g.get("enable_tsig") in ("1", 1, True)

    api.api_post("general/set", {"general": {"enable_tsig": "0",
                                              "tsig_key_name": "",
                                              "tsig_key_secret": ""}})
    test_log("cleaned", True)


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
