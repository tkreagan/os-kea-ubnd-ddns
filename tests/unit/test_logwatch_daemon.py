# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit tests for kea-ubnd-logwatch.py — LogTailer file discovery and rotation.

Tests focus on _latest_path() (the glob-based file picker that replaced the
old date-based _today_path()) and refresh() (rotation detection).  kqueue is
available on macOS and FreeBSD so we use real temp directories and a real kqueue
rather than mocking the filesystem.

Run:  python3 -m pytest tests/unit/test_logwatch_daemon.py -v
"""
from __future__ import annotations

import select
import unittest.mock as mock

import pytest

import subprocess

from .conftest import load_script

pytestmark = pytest.mark.unit

logwatch = load_script("kea-ubnd-logwatch.py")
LogTailer = logwatch.LogTailer


def _make_tailer(log_dir, prefix, startup_cutoff=False):
    """Create a LogTailer with a real kqueue against a temp directory."""
    kq = select.kqueue()
    logger = mock.MagicMock()
    tailer = LogTailer(str(log_dir), prefix, kq, logger, startup_cutoff=startup_cutoff)
    return tailer, kq


# ── _latest_path — basic discovery ──────────────────────────────────────────

def test_latest_path_none_empty_dir(tmp_path):
    tailer, kq = _make_tailer(tmp_path, "kea")
    assert tailer._latest_path() is None
    kq.close()


def test_latest_path_none_no_matching_prefix(tmp_path):
    (tmp_path / "other_20260101.log").write_text("x")
    tailer, kq = _make_tailer(tmp_path, "kea")
    assert tailer._latest_path() is None
    kq.close()


def test_latest_path_single_file(tmp_path):
    f = tmp_path / "kea_20260101.log"
    f.write_text("x")
    tailer, kq = _make_tailer(tmp_path, "kea")
    assert tailer._latest_path() == str(f)
    kq.close()


def test_latest_path_returns_lexicographic_max(tmp_path):
    (tmp_path / "kea_20260101.log").write_text("a")
    (tmp_path / "kea_20260315.log").write_text("b")
    (tmp_path / "kea_20260620.log").write_text("c")
    tailer, kq = _make_tailer(tmp_path, "kea")
    assert tailer._latest_path() == str(tmp_path / "kea_20260620.log")
    kq.close()


def test_latest_path_year_rollover(tmp_path):
    """Dec 31 of one year sorts before Jan 1 of the next."""
    (tmp_path / "kea_20261231.log").write_text("old year")
    (tmp_path / "kea_20270101.log").write_text("new year")
    tailer, kq = _make_tailer(tmp_path, "kea")
    assert tailer._latest_path() == str(tmp_path / "kea_20270101.log")
    kq.close()


def test_latest_path_prefix_isolation(tmp_path):
    """kea_ and keaubnd_ prefixes don't cross-contaminate each other."""
    kea_file = tmp_path / "kea_20260101.log"
    listener_file = tmp_path / "keaubnd_20260620.log"
    kea_file.write_text("kea")
    listener_file.write_text("listener")

    kea_tailer, kq1 = _make_tailer(tmp_path, "kea")
    listener_tailer, kq2 = _make_tailer(tmp_path, "keaubnd")

    assert kea_tailer._latest_path() == str(kea_file)
    assert listener_tailer._latest_path() == str(listener_file)
    kq1.close()
    kq2.close()


# ── refresh — rotation detection ────────────────────────────────────────────

def test_refresh_switches_to_newer_file(tmp_path):
    """refresh() transitions to a lexicographically later file when one appears."""
    old = tmp_path / "kea_20261231.log"
    old.write_text("old")
    tailer, kq = _make_tailer(tmp_path, "kea")
    assert tailer._file_path == str(old)

    new = tmp_path / "kea_20270101.log"
    new.write_text("new")
    tailer.refresh()
    assert tailer._file_path == str(new)
    kq.close()


def test_refresh_no_op_when_still_latest(tmp_path):
    """refresh() keeps the same file when no newer file has appeared."""
    f = tmp_path / "kea_20260620.log"
    f.write_text("current")
    tailer, kq = _make_tailer(tmp_path, "kea")
    assert tailer._file_path == str(f)

    tailer.refresh()
    assert tailer._file_path == str(f)
    kq.close()


def test_refresh_no_op_when_dir_empty(tmp_path):
    """refresh() does nothing (and doesn't crash) when no files exist yet."""
    tailer, kq = _make_tailer(tmp_path, "kea")
    assert tailer._file_path is None
    tailer.refresh()
    assert tailer._file_path is None
    kq.close()


# ── startup_cutoff — seeks to EOF on open ───────────────────────────────────

def test_startup_cutoff_seeks_to_end(tmp_path):
    """With startup_cutoff=True, read_lines() on a pre-existing file returns nothing."""
    f = tmp_path / "kea_20260620.log"
    f.write_text("pre-existing line\n")
    tailer, kq = _make_tailer(tmp_path, "kea", startup_cutoff=True)
    lines = tailer.read_lines()
    assert lines == []
    kq.close()


def test_no_startup_cutoff_reads_from_start(tmp_path):
    """With startup_cutoff=False, read_lines() returns content already in the file."""
    f = tmp_path / "kea_20260620.log"
    f.write_text("existing line\n")
    tailer, kq = _make_tailer(tmp_path, "kea", startup_cutoff=False)
    lines = tailer.read_lines()
    assert "existing line" in lines
    kq.close()


# ── _dispatch_sync_names — Finding 1 regression ──────────────────────────────

class TestDispatchSyncNames:
    """_dispatch_sync_names must call run-sync.py with no --mode argument.

    Finding 1: the old code passed '--mode=full' which kea-sync.py doesn't
    accept, causing rc=2 on every dispatch. The fix routes through run-sync.py
    (the config-reading wrapper) and drops the stale flag.
    """

    def _capture_dispatch(self, names, sync_script="run-sync.py"):
        """Run _dispatch_sync_names with mocked subprocess.run; return called argv."""
        captured = []

        def fake_run(args, **kwargs):
            captured.append(list(args))
            r = mock.MagicMock()
            r.returncode = 0
            r.stdout = ""
            r.stderr = ""
            return r

        with mock.patch.object(logwatch._rt, "get_logwatch_sync_script",
                               return_value=sync_script), \
             mock.patch("subprocess.run", side_effect=fake_run):
            logwatch._dispatch_sync_names(names, mock.MagicMock())

        return captured

    def test_no_mode_flag_with_names(self):
        """--mode must not appear in the argv when names are supplied."""
        called = self._capture_dispatch(["host.lan"])
        assert called, "subprocess.run was not called"
        argv = called[0]
        assert not any("--mode" in a for a in argv), \
            f"--mode must not appear in argv; got {argv}"

    def test_no_mode_flag_full_sync(self):
        """--mode must not appear in the argv for a full (nameless) dispatch."""
        called = self._capture_dispatch([])
        assert called
        argv = called[0]
        assert not any("--mode" in a for a in argv), \
            f"--mode must not appear in argv; got {argv}"

    def test_uses_run_sync_not_kea_sync(self):
        """The dispatched script must be run-sync.py, not kea-sync.py."""
        called = self._capture_dispatch(["host.lan"], sync_script="run-sync.py")
        assert called
        argv = called[0]
        assert any("run-sync.py" in a for a in argv), \
            f"argv must reference run-sync.py; got {argv}"
        assert not any("kea-sync.py" in a for a in argv), \
            f"argv must not reference kea-sync.py directly; got {argv}"

    def test_names_passed_as_flag(self):
        """Supplied names must appear as --names=<csv> in the argv."""
        called = self._capture_dispatch(["alpha.lan", "beta.lan"])
        assert called
        argv = called[0]
        names_args = [a for a in argv if a.startswith("--names=")]
        assert names_args, f"--names= not found in argv {argv}"
        names_val = names_args[0].split("=", 1)[1]
        assert "alpha.lan" in names_val
        assert "beta.lan" in names_val

    def test_no_names_arg_for_full_sync(self):
        """Full dispatch (empty names list) must not include --names at all."""
        called = self._capture_dispatch([])
        assert called
        argv = called[0]
        assert not any(a.startswith("--names") for a in argv), \
            f"--names must be absent for full dispatch; got {argv}"
