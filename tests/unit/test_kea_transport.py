# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit tests for lib/kea_transport.py.

Covers: _is_service_enabled, _is_manual_config, _parse_conf_socket,
resolve_kea_connection waterfall, kea_query normalisation.
All socket and HTTP I/O is mocked.
"""

from __future__ import annotations

import json
import unittest.mock as mock

import pytest

from lib import kea_transport
from lib.kea_transport import (
    KeaServiceUnavailableError,
    KeaUnavailableError,
    HttpTransport,
    UnixSocketTransport,
    _build_connection,
    _is_manual_config,
    _is_service_enabled,
    _parse_conf_socket,
    kea_query,
    resolve_kea_connection,
)

pytestmark = pytest.mark.unit


# ── _is_service_enabled ───────────────────────────────────────────────────────

def test_service_enabled_explicit_one(fixture_dir, monkeypatch):
    monkeypatch.setattr(kea_transport, "CONFIG_XML",
                        str(fixture_dir / "config_full.xml"))
    assert _is_service_enabled("dhcp4") is True


def test_service_disabled_explicit_zero(fixture_dir, monkeypatch):
    # config_full.xml has dhcp4 enabled=1; use a temp file with 0
    import pathlib, tempfile
    xml = """<opnsense><OPNsense><Kea><dhcp4>
        <general><enabled>0</enabled></general></dhcp4></Kea></OPNsense></opnsense>"""
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(xml)
        name = f.name
    monkeypatch.setattr(kea_transport, "CONFIG_XML", name)
    assert _is_service_enabled("dhcp4") is False


def test_service_enabled_defaults_true_when_node_absent(fixture_dir, monkeypatch):
    # config_minimal has no dhcp6 section
    monkeypatch.setattr(kea_transport, "CONFIG_XML",
                        str(fixture_dir / "config_minimal.xml"))
    assert _is_service_enabled("dhcp6") is True


def test_service_enabled_d2_always_true(fixture_dir, monkeypatch):
    monkeypatch.setattr(kea_transport, "CONFIG_XML",
                        str(fixture_dir / "config_full.xml"))
    assert _is_service_enabled("d2") is True


# ── _is_manual_config ─────────────────────────────────────────────────────────

def test_manual_config_false_when_not_set(fixture_dir, monkeypatch):
    monkeypatch.setattr(kea_transport, "CONFIG_XML",
                        str(fixture_dir / "config_full.xml"))
    assert _is_manual_config("dhcp4") is False


def test_manual_config_true(tmp_path, monkeypatch):
    xml = """<opnsense><OPNsense><Kea><dhcp4>
        <general><manual_config>1</manual_config></general>
        </dhcp4></Kea></OPNsense></opnsense>"""
    cfg = tmp_path / "config.xml"
    cfg.write_text(xml)
    monkeypatch.setattr(kea_transport, "CONFIG_XML", str(cfg))
    assert _is_manual_config("dhcp4") is True


# ── _parse_conf_socket ────────────────────────────────────────────────────────

def test_parse_conf_socket_unix(fixture_dir, monkeypatch):
    monkeypatch.setitem(kea_transport._CONF_FILES, "dhcp4",
                        str(fixture_dir / "kea_dhcp4.conf"))
    desc = _parse_conf_socket("dhcp4")
    assert desc is not None
    assert desc["type"] == "unix"
    assert "kea4-ctrl-socket" in desc["path"]


def test_parse_conf_socket_http(tmp_path, monkeypatch):
    conf = {
        "Dhcp4": {
            "control-socket": {
                "socket-type": "http",
                "socket-address": "127.0.0.1",
                "socket-port": 8080,
            }
        }
    }
    cfg = tmp_path / "kea-dhcp4.conf"
    cfg.write_text(json.dumps(conf))
    monkeypatch.setitem(kea_transport._CONF_FILES, "dhcp4", str(cfg))
    desc = _parse_conf_socket("dhcp4")
    assert desc is not None
    assert desc["type"] == "http"
    assert desc["port"] == 8080


def test_parse_conf_socket_prefers_http_over_unix(tmp_path, monkeypatch):
    conf = {
        "Dhcp4": {
            "control-sockets": [
                {"socket-type": "unix", "socket-name": "/var/run/kea.sock"},
                {"socket-type": "http", "socket-address": "127.0.0.1", "socket-port": 8080},
            ]
        }
    }
    cfg = tmp_path / "kea-dhcp4.conf"
    cfg.write_text(json.dumps(conf))
    monkeypatch.setitem(kea_transport._CONF_FILES, "dhcp4", str(cfg))
    desc = _parse_conf_socket("dhcp4")
    assert desc["type"] == "http"


def test_parse_conf_socket_missing_file(monkeypatch):
    monkeypatch.setitem(kea_transport._CONF_FILES, "dhcp4", "/nonexistent.conf")
    assert _parse_conf_socket("dhcp4") is None


def test_parse_conf_socket_no_socket_stanza(tmp_path, monkeypatch):
    conf = {"Dhcp4": {"subnet4": []}}
    cfg = tmp_path / "kea.conf"
    cfg.write_text(json.dumps(conf))
    monkeypatch.setitem(kea_transport._CONF_FILES, "dhcp4", str(cfg))
    assert _parse_conf_socket("dhcp4") is None


# ── resolve_kea_connection waterfall ─────────────────────────────────────────

def test_resolve_skips_disabled_service(tmp_path, monkeypatch):
    xml = """<opnsense><OPNsense><Kea><dhcp4>
        <general><enabled>0</enabled></general></dhcp4></Kea></OPNsense></opnsense>"""
    cfg = tmp_path / "config.xml"
    cfg.write_text(xml)
    monkeypatch.setattr(kea_transport, "CONFIG_XML", str(cfg))
    with pytest.raises(KeaServiceUnavailableError, match="not enabled"):
        _build_connection("dhcp4", 5.0)


def test_resolve_uses_conf_file_socket(fixture_dir, monkeypatch):
    monkeypatch.setattr(kea_transport, "CONFIG_XML",
                        str(fixture_dir / "config_full.xml"))
    monkeypatch.setitem(kea_transport._CONF_FILES, "dhcp4",
                        str(fixture_dir / "kea_dhcp4.conf"))
    transport = _build_connection("dhcp4", 5.0)
    assert isinstance(transport, UnixSocketTransport)


def test_resolve_falls_back_to_default_socket(tmp_path, monkeypatch):
    xml = """<opnsense><OPNsense><Kea><dhcp4>
        <general><enabled>1</enabled></general></dhcp4></Kea></OPNsense></opnsense>"""
    cfg = tmp_path / "config.xml"
    cfg.write_text(xml)
    monkeypatch.setattr(kea_transport, "CONFIG_XML", str(cfg))
    # No conf file → falls back to default
    monkeypatch.setitem(kea_transport._CONF_FILES, "dhcp4", "/nonexistent.conf")
    transport = _build_connection("dhcp4", 5.0)
    assert isinstance(transport, UnixSocketTransport)
    assert "kea4-ctrl-socket" in transport.path


def test_resolve_manual_config_no_socket_raises(tmp_path, monkeypatch):
    xml = """<opnsense><OPNsense><Kea><dhcp4>
        <general><enabled>1</enabled><manual_config>1</manual_config></general>
        </dhcp4></Kea></OPNsense></opnsense>"""
    cfg = tmp_path / "config.xml"
    cfg.write_text(xml)
    monkeypatch.setattr(kea_transport, "CONFIG_XML", str(cfg))
    monkeypatch.setitem(kea_transport._CONF_FILES, "dhcp4", "/nonexistent.conf")
    with pytest.raises(KeaUnavailableError, match="manual configuration"):
        _build_connection("dhcp4", 5.0)


def test_resolve_memoized(fixture_dir, monkeypatch):
    monkeypatch.setattr(kea_transport, "CONFIG_XML",
                        str(fixture_dir / "config_full.xml"))
    monkeypatch.setitem(kea_transport._CONF_FILES, "dhcp4",
                        str(fixture_dir / "kea_dhcp4.conf"))
    t1 = resolve_kea_connection("dhcp4")
    t2 = resolve_kea_connection("dhcp4")
    assert t1 is t2


# ── kea_query normalisation ───────────────────────────────────────────────────

def test_kea_query_success_unix_response():
    transport = mock.MagicMock()
    transport.query.return_value = {
        "result": 0,
        "arguments": {"leases": []}
    }
    with mock.patch.object(kea_transport, "resolve_kea_connection",
                           return_value=transport):
        result = kea_query("lease4-get-all", service="dhcp4")
    assert result["result"] == 0


def test_kea_query_success_http_response_unwraps_list():
    transport = mock.MagicMock()
    transport.query.return_value = [{"result": 0, "arguments": {"leases": []}}]
    with mock.patch.object(kea_transport, "resolve_kea_connection",
                           return_value=transport):
        result = kea_query("lease4-get-all", service="dhcp4")
    assert result["result"] == 0


def test_kea_query_empty_http_raises():
    transport = mock.MagicMock()
    transport.query.return_value = []
    with mock.patch.object(kea_transport, "resolve_kea_connection",
                           return_value=transport):
        with pytest.raises(KeaUnavailableError, match="empty response"):
            kea_query("config-get", service="dhcp4")


def test_kea_query_rc1_raises_service_error():
    transport = mock.MagicMock()
    transport.query.return_value = {"result": 1, "text": "some error"}
    with mock.patch.object(kea_transport, "resolve_kea_connection",
                           return_value=transport):
        with pytest.raises(KeaServiceUnavailableError, match="some error"):
            kea_query("bad-command", service="dhcp4")


def test_kea_query_rc3_empty_treated_as_success():
    transport = mock.MagicMock()
    transport.query.return_value = {"result": 3, "text": "0 IPv4 leases found"}
    with mock.patch.object(kea_transport, "resolve_kea_connection",
                           return_value=transport):
        result = kea_query("lease4-get-all", service="dhcp4")
    assert result["result"] == 3


# ── UnixSocketTransport ───────────────────────────────────────────────────────

def test_unix_transport_missing_socket():
    t = UnixSocketTransport("/nonexistent/kea.sock")
    with pytest.raises(KeaUnavailableError, match="not found"):
        t.query("config-get")


# ── HttpTransport ─────────────────────────────────────────────────────────────

def test_http_transport_url_construction():
    t = HttpTransport("127.0.0.1", 8080, tls=False)
    assert t._url() == "http://127.0.0.1:8080/"


def test_https_transport_url_construction():
    t = HttpTransport("127.0.0.1", 8443, tls=True)
    assert t._url() == "https://127.0.0.1:8443/"
