# SPDX-License-Identifier: BSD-2-Clause
"""
Unit tests for lib/preconditions.py's pure resolvers -- the inheritance-aware
DDNS gate (spike V6) and the d2 forward-target check. Runs on macOS with
fixture dicts; check_preconditions() (which touches real files) is exercised on
the box.

Run:  python3 -m pytest tools/test_preconditions.py -v
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import types

_ROOT = pathlib.Path(__file__).parents[1]
_PC = _ROOT / "src/opnsense/scripts/keaubnd/lib/preconditions.py"

# Stub kea_transport (preconditions imports constants + enablement helpers).
_pkg = types.ModuleType("lib"); _pkg.__path__ = []
_kt = types.ModuleType("lib.kea_transport")
_kt._CONF_FILES = {"dhcp4": "/x/dhcp4", "dhcp6": "/x/dhcp6", "d2": "/x/d2"}
_kt._is_service_enabled = lambda s: True
_kt._is_manual_config = lambda s: False
_kt._MANUAL_XPATHS = {"dhcp4": "x", "dhcp6": "y"}
sys.modules["lib"] = _pkg
sys.modules["lib.kea_transport"] = _kt

_spec = importlib.util.spec_from_file_location("lib.preconditions", _PC)
pc = importlib.util.module_from_spec(_spec)
sys.modules["lib.preconditions"] = pc
_spec.loader.exec_module(pc)


# ── master switch ─────────────────────────────────────────────────────────────
def test_master_enabled_true():
    assert pc.ddns_master_enabled({"dhcp-ddns": {"enable-updates": True}}) is True


def test_master_enabled_false():
    assert pc.ddns_master_enabled({"dhcp-ddns": {"enable-updates": False}}) is False


def test_master_enabled_absent():
    assert pc.ddns_master_enabled({}) is False


# ── inheritance (the V6 crux) ─────────────────────────────────────────────────
def test_subnet_explicit_true():
    cfg = {"subnet4": [{"ddns-send-updates": True}]}
    assert pc.any_subnet_ddns_enabled(cfg, "subnet4") is True


def test_subnet_explicit_false_only():
    cfg = {"subnet4": [{"ddns-send-updates": False}]}
    assert pc.any_subnet_ddns_enabled(cfg, "subnet4") is False


def test_subnet_absent_inherits_global_true():
    # The case KcaconfigController's strict check would WRONGLY refuse.
    cfg = {"ddns-send-updates": True, "subnet4": [{"subnet": "192.168.1.0/24"}]}
    assert pc.any_subnet_ddns_enabled(cfg, "subnet4") is True


def test_subnet_absent_inherits_global_false():
    cfg = {"ddns-send-updates": False, "subnet4": [{"subnet": "192.168.1.0/24"}]}
    assert pc.any_subnet_ddns_enabled(cfg, "subnet4") is False


def test_subnet_absent_no_global_defaults_true():
    # Kea default: absent ddns-send-updates is true (master already confirmed on).
    cfg = {"subnet4": [{"subnet": "192.168.1.0/24"}]}
    assert pc.any_subnet_ddns_enabled(cfg, "subnet4") is True


def test_subnet_override_beats_global_false():
    cfg = {"ddns-send-updates": False,
           "subnet4": [{"ddns-send-updates": False},
                       {"ddns-send-updates": True}]}   # one overrides -> enabled
    assert pc.any_subnet_ddns_enabled(cfg, "subnet4") is True


def test_shared_network_subnet_counts():
    cfg = {"shared-networks": [{"subnet4": [{"ddns-send-updates": True}]}]}
    assert pc.any_subnet_ddns_enabled(cfg, "subnet4") is True


def test_no_subnets_global_true_is_ok():
    assert pc.any_subnet_ddns_enabled({"ddns-send-updates": True}, "subnet4") is True


def test_no_subnets_no_global_is_not_ok():
    assert pc.any_subnet_ddns_enabled({}, "subnet4") is False


# ── d2 forward target ─────────────────────────────────────────────────────────
def test_d2_forward_matches_port():
    d2 = {"forward-ddns": {"ddns-domains": [
        {"name": "x.", "dns-servers": [{"ip-address": "127.0.0.1", "port": 53535}]}]}}
    assert pc.d2_forward_targets_port(d2, 53535) is True


def test_d2_forward_wrong_port():
    d2 = {"forward-ddns": {"ddns-domains": [
        {"name": "x.", "dns-servers": [{"ip-address": "127.0.0.1", "port": 53}]}]}}
    assert pc.d2_forward_targets_port(d2, 53535) is False


def test_d2_forward_no_domains():
    assert pc.d2_forward_targets_port({}, 53535) is False
