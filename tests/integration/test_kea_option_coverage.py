# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration tests — Kea DHCP/DDNS option coverage audit.

Checks that the Kea configuration on the OPNsense box has the DDNS-related options
set in a way that is compatible with this plugin. This is an audit /
documentation test: failures are findings to review, not necessarily bugs.

Options checked:
  - ddns-send-updates (should be true for dynamic registration to work)
  - ddns-qualifying-suffix (should match system domain)
  - dhcp-ddns server-ip / server-port (should point to 127.0.0.1:53535)
  - D2 forward-ddns.ddns-domains (should be configured)
  - TSIG key consistency between D2 config and plugin settings
  - dhcid / conflict resolution flag
"""

from __future__ import annotations

import json

import pytest

pytestmark = [pytest.mark.integration]

LISTENER_PORT = 53535


def _read_kea_config(ssh, service: str) -> dict:
    paths = {
        "dhcp4": "/usr/local/etc/kea/kea-dhcp4.conf",
        "dhcp6": "/usr/local/etc/kea/kea-dhcp6.conf",
        "d2":    "/usr/local/etc/kea/kea-dhcp-ddns.conf",
    }
    raw = ssh(f"cat {paths[service]}", check=False)
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


@pytest.fixture(scope="module")
def dhcp4_conf(ssh, deploy):
    return _read_kea_config(ssh, "dhcp4")


@pytest.fixture(scope="module")
def d2_conf(ssh, deploy):
    return _read_kea_config(ssh, "d2")


def test_dhcp4_ddns_send_updates_enabled(dhcp4_conf, test_log):
    val = dhcp4_conf.get("Dhcp4", {}).get("ddns-send-updates")
    test_log("observed", {"ddns-send-updates": val})
    if val is None:
        pytest.skip("ddns-send-updates not set (may default to true in Kea 3.x)")
    assert val is True, (
        "ddns-send-updates is false — dynamic lease updates will NOT be sent to D2"
    )


def test_dhcp4_qualifying_suffix_set(dhcp4_conf, ssh, test_log):
    suffix = dhcp4_conf.get("Dhcp4", {}).get("ddns-qualifying-suffix", "")
    system_domain = ssh("grep -o '<domain>[^<]*</domain>' /conf/config.xml "
                        "| head -1 | sed 's/<[^>]*>//g'", check=False).strip()
    test_log("observed", {"ddns-qualifying-suffix": suffix, "system-domain": system_domain})
    if not suffix:
        pytest.skip("ddns-qualifying-suffix not set globally (may be per-subnet)")
    if system_domain:
        assert suffix == system_domain, (
            f"ddns-qualifying-suffix ({suffix!r}) ≠ system domain ({system_domain!r}): "
            "hostnames will not qualify correctly"
        )


def test_dhcp4_ddns_server_points_to_listener(dhcp4_conf, test_log):
    ddns = dhcp4_conf.get("Dhcp4", {}).get("dhcp-ddns", {})
    ip = ddns.get("server-ip", "")
    port = ddns.get("server-port", 0)
    test_log("observed", {"ddns-server-ip": ip, "ddns-server-port": port})
    if not ip and not port:
        pytest.skip("dhcp-ddns.server-ip/port not set in kea-dhcp4.conf "
                    "(may be using defaults or D2 not configured)")
    assert ip == "127.0.0.1", f"dhcp-ddns.server-ip should be 127.0.0.1, got {ip!r}"
    assert port == LISTENER_PORT, \
        f"dhcp-ddns.server-port should be {LISTENER_PORT}, got {port}"


def test_d2_forward_zones_configured(d2_conf, test_log):
    domains = (d2_conf.get("DhcpDdns", {})
               .get("forward-ddns", {})
               .get("ddns-domains", []))
    test_log("observed", {"forward_domain_count": len(domains)})
    if not d2_conf:
        pytest.skip("kea-dhcp-ddns.conf not found or empty")
    assert len(domains) >= 1, (
        "No forward DDNS domains configured in kea-dhcp-ddns.conf — "
        "D2 will not forward updates to the listener"
    )


def test_d2_listens_on_correct_port(d2_conf, test_log):
    port = d2_conf.get("DhcpDdns", {}).get("port", 0)
    test_log("observed", {"d2_port": port})
    if not d2_conf:
        pytest.skip("kea-dhcp-ddns.conf not found")
    if port:
        assert port == LISTENER_PORT, \
            f"D2 is listening on port {port}, but plugin expects {LISTENER_PORT}"


def test_dhcp4_conflict_resolution_flag(dhcp4_conf, test_log):
    val = dhcp4_conf.get("Dhcp4", {}).get("ddns-use-conflict-resolution")
    test_log("observed", {"ddns-use-conflict-resolution": val})
    # Document the value — not a hard failure, just informational
    # DHCID conflict resolution is cosmetic for Unbound (we ignore DHCID records)
    if val is False:
        pytest.skip("ddns-use-conflict-resolution disabled — no DHCID in updates (expected)")


def test_no_spdx_headers_missing(ssh, test_log):
    """All Python source files must have SPDX-License-Identifier headers."""
    out = ssh(
        "find /usr/local/opnsense/scripts/keaunbound /usr/local/sbin/kea-unbound-ddns.py "
        "-name '*.py' -not -name '__init__.py' | "
        "xargs grep -L 'SPDX-License-Identifier' 2>/dev/null || true",
        check=False,
    )
    missing = [l for l in out.splitlines() if l.strip()]
    test_log("observed", {"missing_spdx": missing})
    assert not missing, f"Files missing SPDX header: {missing}"
