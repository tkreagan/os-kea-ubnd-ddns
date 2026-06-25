# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit tests for lib/kea_transport.py.

Covers: _build_connection (runtime-config path), resolve_kea_connection
memoisation, kea_query normalisation, transport classes.

_build_connection now reads from keaubnd_runtime rather than config.xml or
Kea's own conf files (that logic moved to start.py).  Tests mock
lib.keaubnd_runtime.get_kea_socket to exercise the three code paths:
unix-socket path, http(s):// URL, and absent/disabled (None).
"""

from __future__ import annotations

import unittest.mock as mock

import pytest

from lib import kea_transport
from lib.kea_transport import (
    HttpTransport,
    KeaServiceUnavailableError,
    KeaUnavailableError,
    UnixSocketTransport,
    _build_connection,
    kea_query,
    resolve_kea_connection,
)

pytestmark = pytest.mark.unit


# ── _build_connection — runtime-config paths ──────────────────────────────────

def test_build_connection_unix_socket(monkeypatch):
    monkeypatch.setattr(
        "lib.keaubnd_runtime.get_kea_socket",
        lambda svc: "/var/run/kea/kea4-ctrl-socket",
    )
    t = _build_connection("dhcp4", 5.0)
    assert isinstance(t, UnixSocketTransport)
    assert t.path == "/var/run/kea/kea4-ctrl-socket"


def test_build_connection_http_url(monkeypatch):
    monkeypatch.setattr(
        "lib.keaubnd_runtime.get_kea_socket",
        lambda svc: "http://127.0.0.1:8080",
    )
    t = _build_connection("dhcp4", 5.0)
    assert isinstance(t, HttpTransport)
    assert t.tls is False
    assert t.host == "127.0.0.1"
    assert t.port == 8080


def test_build_connection_https_url(monkeypatch):
    monkeypatch.setattr(
        "lib.keaubnd_runtime.get_kea_socket",
        lambda svc: "https://127.0.0.1:8443",
    )
    t = _build_connection("dhcp4", 5.0)
    assert isinstance(t, HttpTransport)
    assert t.tls is True
    assert t.port == 8443


def test_build_connection_none_raises_service_unavailable(monkeypatch):
    """socket=None means the service is disabled — KeaServiceUnavailableError."""
    monkeypatch.setattr(
        "lib.keaubnd_runtime.get_kea_socket",
        lambda svc: None,
    )
    with pytest.raises(KeaServiceUnavailableError):
        _build_connection("dhcp4", 5.0)


def test_build_connection_runtime_error_propagates(monkeypatch):
    """RuntimeError from keaubnd_runtime (no keaubnd.json) propagates up."""
    def _raise(svc):
        raise RuntimeError("keaubnd.json not found")
    monkeypatch.setattr("lib.keaubnd_runtime.get_kea_socket", _raise)
    with pytest.raises(RuntimeError, match="keaubnd.json"):
        _build_connection("dhcp4", 5.0)


def test_build_connection_dhcp6_independent(monkeypatch):
    """dhcp6 and dhcp4 resolve independently."""
    def _sock(svc):
        return {
            "dhcp4": "/run/kea/kea4-ctrl-socket",
            "dhcp6": "/run/kea/kea6-ctrl-socket",
        }.get(svc)
    monkeypatch.setattr("lib.keaubnd_runtime.get_kea_socket", _sock)
    t4 = _build_connection("dhcp4", 5.0)
    t6 = _build_connection("dhcp6", 5.0)
    assert isinstance(t4, UnixSocketTransport)
    assert isinstance(t6, UnixSocketTransport)
    assert t4.path != t6.path


# ── resolve_kea_connection — memoisation ─────────────────────────────────────

def test_resolve_memoized(monkeypatch):
    calls = []
    def _sock(svc):
        calls.append(svc)
        return "/var/run/kea/kea4-ctrl-socket"
    monkeypatch.setattr("lib.keaubnd_runtime.get_kea_socket", _sock)
    t1 = resolve_kea_connection("dhcp4")
    t2 = resolve_kea_connection("dhcp4")
    assert t1 is t2
    assert calls.count("dhcp4") == 1  # resolved once, then memoized


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


def test_kea_query_rc1_raises_unavailable_error():
    """rc=1 (command error from a reachable daemon) must raise the base
    KeaUnavailableError — NOT the subclass KeaServiceUnavailableError.
    Callers that catch KeaServiceUnavailableError to silently skip a disabled
    service must NOT swallow a hard error from a reachable daemon."""
    transport = mock.MagicMock()
    transport.query.return_value = {"result": 1, "text": "some error"}
    with mock.patch.object(kea_transport, "resolve_kea_connection",
                           return_value=transport):
        with pytest.raises(KeaUnavailableError, match="some error") as exc_info:
            kea_query("bad-command", service="dhcp4")
    assert type(exc_info.value) is KeaUnavailableError, \
        "rc=1 must raise KeaUnavailableError, not the KeaServiceUnavailableError subclass"


def test_kea_query_rc2_raises_service_unavailable():
    """rc=2 (command unsupported — e.g. lease_cmds hook not loaded) raises
    KeaServiceUnavailableError so per-service skip logic treats it like a
    disabled service rather than a hard failure."""
    transport = mock.MagicMock()
    transport.query.return_value = {"result": 2, "text": "unsupported command"}
    with mock.patch.object(kea_transport, "resolve_kea_connection",
                           return_value=transport):
        with pytest.raises(KeaServiceUnavailableError, match="unsupported"):
            kea_query("lease4-get-all", service="dhcp4")


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
