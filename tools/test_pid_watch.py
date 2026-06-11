# SPDX-License-Identifier: BSD-2-Clause
"""
Unit tests for lib/pid_watch.py's pure level-read (read_pid_state / _read_pid).
Runs on macOS with temp files -- no kqueue, no real services. The kqueue
PidWatcher class is exercised on the dev box, not here.

Run:  python3 -m pytest tools/test_pid_watch.py -v
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import types

_ROOT = pathlib.Path(__file__).parents[1]
_PW = _ROOT / "src/opnsense/scripts/keaunbound/lib/pid_watch.py"

# Stub the kea_transport relative import (pid_watch re-exports _is_service_enabled).
_pkg = types.ModuleType("lib"); _pkg.__path__ = []
_kt = types.ModuleType("lib.kea_transport")
_kt._is_service_enabled = lambda svc: True
sys.modules["lib"] = _pkg
sys.modules["lib.kea_transport"] = _kt

_spec = importlib.util.spec_from_file_location("lib.pid_watch", _PW)
pw = importlib.util.module_from_spec(_spec)
sys.modules["lib.pid_watch"] = pw
_spec.loader.exec_module(pw)


def test_absent_file_is_false_none(tmp_path):
    assert pw._read_pid(str(tmp_path / "nope.pid")) == (False, None)


def test_present_pid_parsed(tmp_path):
    p = tmp_path / "u.pid"; p.write_text("12345\n")
    assert pw._read_pid(str(p)) == (True, 12345)


def test_present_but_garbage_is_true_none(tmp_path):
    p = tmp_path / "g.pid"; p.write_text("not-a-pid\n")
    assert pw._read_pid(str(p)) == (True, None)


def test_empty_file_is_true_none(tmp_path):
    p = tmp_path / "e.pid"; p.write_text("")
    assert pw._read_pid(str(p)) == (True, None)


def test_pid_with_trailing_junk_takes_first_token(tmp_path):
    p = tmp_path / "j.pid"; p.write_text("999 extra stuff\n")
    assert pw._read_pid(str(p)) == (True, 999)


def test_read_pid_state_maps_all_services(tmp_path):
    a = tmp_path / "a.pid"; a.write_text("1\n")
    b = tmp_path / "b.pid"; b.write_text("2\n")
    paths = {"unbound": str(a), "d2": str(b), "dhcp4": str(tmp_path / "gone.pid")}
    state = pw.read_pid_state(paths)
    assert state == {"unbound": (True, 1), "d2": (True, 2), "dhcp4": (False, None)}


def test_pid_value_change_is_visible(tmp_path):
    # The in-place-rewrite case (unbound): same path, new value.
    p = tmp_path / "unbound.pid"; p.write_text("100\n")
    assert pw.read_pid_state({"unbound": str(p)})["unbound"] == (True, 100)
    p.write_text("200\n")
    assert pw.read_pid_state({"unbound": str(p)})["unbound"] == (True, 200)


def test_resolve_watched_services_includes_core_plus_enabled(monkeypatch):
    # _is_service_enabled stubbed to True -> all four watched.
    watched = pw.resolve_watched_services()
    assert set(watched) == {"unbound", "d2", "dhcp4", "dhcp6"}
    assert watched["unbound"] == pw.PIDFILES["unbound"]


def test_resolve_watched_services_skips_disabled(monkeypatch):
    monkeypatch.setattr(pw, "_is_service_enabled", lambda svc: svc == "dhcp4")
    watched = pw.resolve_watched_services()
    assert set(watched) == {"unbound", "d2", "dhcp4"}   # dhcp6 disabled -> omitted
