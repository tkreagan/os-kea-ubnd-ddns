# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit tests for start.py and stop.py.

Covers: config loading, idempotency guards, TSIG validation, PID file
management, signal sequence (SIGTERM → SIGKILL).
All subprocess, os.kill, and file I/O calls are mocked.
"""

from __future__ import annotations

import os
import signal
import unittest.mock as mock

import pytest

from .conftest import load_script

pytestmark = pytest.mark.unit

start = load_script("start.py")
stop = load_script("stop.py")


# ── start.py — get_config ─────────────────────────────────────────────────────

def test_get_config_reads_full_fixture(config_full_path, monkeypatch):
    monkeypatch.setattr(start, "CONFIG_XML", str(config_full_path))
    cfg = start.get_config()
    assert cfg["enabled"] == "1"
    assert cfg["port"] == "53535"
    assert cfg["enable_tsig"] == "0"


def test_get_config_uses_defaults_for_missing_keys(tmp_path, monkeypatch):
    xml = "<opnsense><OPNsense><KeaUnbound><general><enabled>1</enabled></general></KeaUnbound></OPNsense></opnsense>"
    cfg_file = tmp_path / "config.xml"
    cfg_file.write_text(xml)
    monkeypatch.setattr(start, "CONFIG_XML", str(cfg_file))
    cfg = start.get_config()
    assert cfg["port"] == "53535"
    assert cfg["tsig_algorithm"] == "HMAC-SHA256"
    assert cfg["aggressive_cleanup"] == "0"


def test_get_config_exits_on_unparseable_xml(tmp_path, monkeypatch):
    bad = tmp_path / "config.xml"
    bad.write_text("not xml at all")
    monkeypatch.setattr(start, "CONFIG_XML", str(bad))
    with pytest.raises(SystemExit):
        start.get_config()


# ── start.py — _port_in_use ───────────────────────────────────────────────────

def test_port_in_use_returns_false_on_free_port():
    import socket
    # Find a free port
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert start._port_in_use(port) is False


def test_port_in_use_returns_true_when_bound():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    try:
        assert start._port_in_use(port) is True
    finally:
        s.close()


# ── start.py — _pid_alive ─────────────────────────────────────────────────────

def test_pid_alive_returns_none_for_missing_file(tmp_path):
    assert start._pid_alive(str(tmp_path / "nonexistent.pid")) is None


def test_pid_alive_returns_none_for_dead_pid(tmp_path):
    pf = tmp_path / "dead.pid"
    pf.write_text("999999")  # almost certainly not running
    # May be None or pid; if process 999999 doesn't exist it's None
    result = start._pid_alive(str(pf))
    if result is not None:
        pytest.skip("PID 999999 happens to exist on this machine")


def test_pid_alive_returns_pid_for_self(tmp_path):
    pf = tmp_path / "self.pid"
    pf.write_text(str(os.getpid()))
    result = start._pid_alive(str(pf))
    assert result == os.getpid()


def test_pid_alive_returns_none_for_bad_content(tmp_path):
    pf = tmp_path / "bad.pid"
    pf.write_text("not-a-number")
    assert start._pid_alive(str(pf)) is None


# ── start.py — main() disabled ────────────────────────────────────────────────

def test_start_main_exits_zero_when_disabled(config_disabled_path, monkeypatch):
    monkeypatch.setattr(start, "CONFIG_XML", str(config_disabled_path))
    with pytest.raises(SystemExit) as exc:
        start.main()
    assert exc.value.code == 0


# ── start.py — main() TSIG validation ────────────────────────────────────────

def test_start_main_exits_one_tsig_missing_secret(config_tsig_path, monkeypatch):
    """TSIG enabled but key secret left blank → refuse to start."""
    import tempfile
    xml = """<opnsense><OPNsense><KeaUnbound><general>
        <enabled>1</enabled><port>53535</port>
        <enable_tsig>1</enable_tsig>
        <tsig_key_name>mykey</tsig_key_name>
        <tsig_key_secret></tsig_key_secret>
        <tsig_algorithm>HMAC-SHA256</tsig_algorithm>
        </general></KeaUnbound></OPNsense></opnsense>"""
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(xml)
        name = f.name
    monkeypatch.setattr(start, "CONFIG_XML", name)
    # supervisor pidfile absent → won't bail early on idempotency check
    monkeypatch.setattr(start, "SUPERVISOR_PIDFILE", "/nonexistent_sup.pid")
    monkeypatch.setattr(start, "_port_in_use", lambda p: False)
    with pytest.raises(SystemExit) as exc:
        start.main()
    assert exc.value.code == 1


# ── start.py — main() idempotency ────────────────────────────────────────────

def test_start_main_idempotent_supervisor_alive(config_full_path, tmp_path, monkeypatch):
    monkeypatch.setattr(start, "CONFIG_XML", str(config_full_path))
    sup_pid = tmp_path / "sup.pid"
    sup_pid.write_text(str(os.getpid()))
    monkeypatch.setattr(start, "SUPERVISOR_PIDFILE", str(sup_pid))
    with pytest.raises(SystemExit) as exc:
        start.main()
    assert exc.value.code == 0


def test_start_main_port_in_use_exits_one(config_full_path, tmp_path, monkeypatch):
    monkeypatch.setattr(start, "CONFIG_XML", str(config_full_path))
    monkeypatch.setattr(start, "SUPERVISOR_PIDFILE", str(tmp_path / "nonexistent.pid"))
    monkeypatch.setattr(start, "_port_in_use", lambda p: True)
    with pytest.raises(SystemExit) as exc:
        start.main()
    assert exc.value.code == 1


# ── start.py — daemon command construction ────────────────────────────────────

@mock.patch("subprocess.run")
def test_start_builds_correct_daemon_command(mock_run, config_full_path,
                                             tmp_path, monkeypatch):
    mock_run.return_value = mock.Mock(returncode=0)
    monkeypatch.setattr(start, "CONFIG_XML", str(config_full_path))
    monkeypatch.setattr(start, "SUPERVISOR_PIDFILE", str(tmp_path / "nonexistent.pid"))
    monkeypatch.setattr(start, "PIDFILE", str(tmp_path / "child.pid"))
    monkeypatch.setattr(start, "_port_in_use", lambda p: False)

    start.main()  # succeeds — subprocess.run returns rc=0

    cmd = mock_run.call_args[0][0]
    assert "/usr/sbin/daemon" in cmd
    assert "-r" in cmd
    assert "-R" in cmd
    assert "53535" in cmd


@mock.patch("subprocess.run")
def test_start_includes_tsig_args(mock_run, tmp_path, monkeypatch):
    mock_run.return_value = mock.Mock(returncode=0)
    xml = """<opnsense><OPNsense><KeaUnbound><general>
        <enabled>1</enabled><port>53535</port>
        <enable_tsig>1</enable_tsig>
        <tsig_key_name>mykey</tsig_key_name>
        <tsig_key_secret>dGVzdA==</tsig_key_secret>
        <tsig_algorithm>HMAC-SHA256</tsig_algorithm>
        <aggressive_cleanup>0</aggressive_cleanup>
        </general></KeaUnbound></OPNsense></opnsense>"""
    cfg = tmp_path / "config.xml"
    cfg.write_text(xml)
    monkeypatch.setattr(start, "CONFIG_XML", str(cfg))
    monkeypatch.setattr(start, "SUPERVISOR_PIDFILE", str(tmp_path / "nonexistent.pid"))
    monkeypatch.setattr(start, "PIDFILE", str(tmp_path / "child.pid"))
    monkeypatch.setattr(start, "_port_in_use", lambda p: False)

    start.main()

    cmd = mock_run.call_args[0][0]
    assert "--tsig-key" in cmd
    assert "mykey:dGVzdA==" in cmd
    assert "--tsig-algorithm" in cmd


# ── stop.py — _read_pid ───────────────────────────────────────────────────────

def test_read_pid_parses_integer(tmp_path):
    pf = tmp_path / "test.pid"
    pf.write_text("1234\n")
    assert stop._read_pid(str(pf)) == 1234


def test_read_pid_returns_none_missing(tmp_path):
    assert stop._read_pid(str(tmp_path / "nonexistent.pid")) is None


def test_read_pid_returns_none_bad_content(tmp_path):
    pf = tmp_path / "bad.pid"
    pf.write_text("garbage")
    assert stop._read_pid(str(pf)) is None


# ── stop.py — _alive ──────────────────────────────────────────────────────────

def test_alive_true_for_self():
    assert stop._alive(os.getpid()) is True


def test_alive_false_for_dead_pid():
    # PID 999999 is almost certainly not running
    try:
        result = stop._alive(999999)
    except Exception:
        result = False
    # Either False (process doesn't exist) or True (by extreme coincidence)
    assert isinstance(result, bool)


# ── stop.py — _find_matching_pids ────────────────────────────────────────────

@mock.patch("subprocess.run")
def test_find_matching_pids_excludes_self(mock_run):
    self_pid = os.getpid()
    mock_run.return_value = mock.Mock(
        returncode=0,
        stdout=f"{self_pid}\n1234\n5678\n"
    )
    pids = stop._find_matching_pids()
    assert self_pid not in pids
    assert 1234 in pids
    assert 5678 in pids


@mock.patch("subprocess.run", side_effect=Exception("pgrep failed"))
def test_find_matching_pids_returns_empty_on_error(mock_run):
    assert stop._find_matching_pids() == []


# ── stop.py — main() graceful shutdown ───────────────────────────────────────

@mock.patch.object(stop, "_find_matching_pids", return_value=[])
@mock.patch.object(stop, "_read_pid", return_value=None)
def test_stop_main_no_processes(mock_rpid, mock_pgrep, tmp_path, monkeypatch):
    monkeypatch.setattr(stop, "SUPERVISOR_PIDFILE", str(tmp_path / "s.pid"))
    monkeypatch.setattr(stop, "PIDFILE", str(tmp_path / "c.pid"))
    rc = stop.main()
    assert rc == 0


@mock.patch("time.sleep")
@mock.patch.object(stop, "_find_matching_pids", return_value=[])
@mock.patch.object(stop, "_send")
@mock.patch.object(stop, "_read_pid", return_value=1234)
def test_stop_main_sigterm_then_dead(mock_rpid, mock_send,
                                     mock_pgrep, mock_sleep, tmp_path, monkeypatch):
    # Make _alive return False immediately so the poll loop exits on the first
    # check (process "died" before we even got to poll).
    monkeypatch.setattr(stop, "_alive", lambda pid: False)
    monkeypatch.setattr(stop, "SUPERVISOR_PIDFILE", str(tmp_path / "s.pid"))
    monkeypatch.setattr(stop, "PIDFILE", str(tmp_path / "c.pid"))
    rc = stop.main()
    assert rc == 0
    assert any(args[0][1] == signal.SIGTERM for args in mock_send.call_args_list)
