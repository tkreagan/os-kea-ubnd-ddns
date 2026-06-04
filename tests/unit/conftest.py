# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit test conftest: sys.path setup and shared fixtures.

All unit tests run on macOS (or any host).  External binaries and
FreeBSD-specific paths are mocked; no live services are required.

Import strategy
---------------
* lib/keaunbound_sync.py and lib/kea_transport.py are regular modules once
  SCRIPTS_DIR is on sys.path — import them directly.
* Scripts with hyphens in names (kea-unbound-ddns.py, reservation-sync.py,
  etc.) are loaded via importlib; we expose a load_script() helper.
* The syslog module is replaced with a MagicMock before any imports so that
  syslog.openlog() / syslog.syslog() never touch the host system.
* kea_transport caches resolved connections in _resolved; a fixture clears
  it before each test.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import types
import unittest.mock as mock

import pytest

REPO = pathlib.Path(__file__).parents[2]
SCRIPTS = REPO / "src" / "opnsense" / "scripts" / "keaunbound"
SBIN = REPO / "src" / "sbin"

# Insert BEFORE other manipulations so our path wins over the FreeBSD
# hardcoded path the scripts insert when they are executed.
sys.path.insert(0, str(SCRIPTS))

# Replace syslog with a mock before any plugin module is imported.
# This prevents openlog()/syslog() from writing to the host system and
# makes syslog calls inspectable in logging tests.
_syslog_mock = types.ModuleType("syslog")
for _attr in (
    "LOG_DEBUG", "LOG_INFO", "LOG_WARNING", "LOG_ERR", "LOG_CRIT",
    "LOG_DAEMON", "LOG_PID",
):
    setattr(_syslog_mock, _attr, 0)
_syslog_mock.openlog = mock.MagicMock()
_syslog_mock.syslog = mock.MagicMock()
_syslog_mock.closelog = mock.MagicMock()
sys.modules["syslog"] = _syslog_mock


def load_script(filename: str):
    """
    Load a hyphen-named Python script as a module.

    The script may do sys.path.insert(0, "/usr/local/...") — that path
    does not exist on macOS, but it is harmless because our SCRIPTS path
    is already in sys.path and Python will find the lib package there.
    """
    candidates = [SCRIPTS / filename, SBIN / filename]
    path = next((p for p in candidates if p.exists()), None)
    if path is None:
        raise FileNotFoundError(f"Script not found: {filename}")

    mod_name = filename.replace("-", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(mod_name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(autouse=True)
def clear_kea_transport_cache():
    """Clear the per-process memoized connection cache between tests."""
    from lib import kea_transport
    kea_transport._resolved.clear()
    yield
    kea_transport._resolved.clear()


@pytest.fixture
def fixture_dir():
    return REPO / "tests" / "fixtures"


@pytest.fixture
def host_entries_path(fixture_dir):
    return fixture_dir / "host_entries.conf"


@pytest.fixture
def config_full_path(fixture_dir):
    return fixture_dir / "config_full.xml"


@pytest.fixture
def config_disabled_path(fixture_dir):
    return fixture_dir / "config_disabled.xml"


@pytest.fixture
def config_tsig_path(fixture_dir):
    return fixture_dir / "config_tsig.xml"
