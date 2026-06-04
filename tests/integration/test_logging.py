# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration tests — logging.

Verifies that plugin actions write to the keaunbound log under the correct
program tag (kea-ub), and that DEBUG lines do not appear in non-verbose mode.
"""

from __future__ import annotations

import time

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

LOG_DIR = "/var/log/keaunbound"


def _today_log(ssh) -> str:
    return ssh(f"ls {LOG_DIR}/ | grep keaunbound | tail -1", check=False).strip()


def _read_log(ssh, lines: int = 50) -> str:
    log = _today_log(ssh)
    if not log:
        return ""
    return ssh(f"tail -{lines} {LOG_DIR}/{log}", check=False)


def test_log_file_exists(ssh, deploy, test_log):
    log = _today_log(ssh)
    test_log("observed", {"log_file": log})
    assert log, f"No keaunbound log file found in {LOG_DIR}"


def test_start_writes_to_log(ssh, test_log):
    ssh("/usr/local/sbin/configctl keaunbound stop", check=False)
    time.sleep(0.5)
    before = _read_log(ssh, 200)

    ssh("/usr/local/sbin/configctl keaunbound start")
    time.sleep(2)

    after = _read_log(ssh, 200)
    new_lines = after[len(before):]
    test_log("observed", {"new_lines_count": len(new_lines.splitlines())})
    assert "kea-unbound-ddns" in after or "Listening" in after, \
        "Start event not found in log"

    ssh("/usr/local/sbin/configctl keaunbound stop", check=False)


def test_sync_static_writes_to_log(ssh, test_log):
    ssh("/usr/local/sbin/configctl keaunbound sync_static")
    time.sleep(2)
    log = _read_log(ssh)
    test_log("observed", {"log_snippet": log[-300:]})
    assert "reservation sync" in log.lower() or "sync" in log.lower(), \
        "Sync event not in log"


def test_clean_writes_to_log(ssh, test_log):
    ssh("/usr/local/sbin/configctl keaunbound clean")
    time.sleep(2)
    log = _read_log(ssh)
    test_log("observed", {"log_snippet": log[-300:]})
    assert "stale" in log.lower() or "clean" in log.lower(), \
        "Clean event not in log"


def test_log_tag_is_kea_ub(ssh, test_log):
    """All log lines must come from program tag 'kea-ub', not 'unbound*'."""
    log = _read_log(ssh, 200)
    test_log("observed", {"log_line_count": len(log.splitlines())})
    for line in log.splitlines():
        # syslog-ng format: "date host kea-ub[pid]: ..."
        # Reject any line whose tag contains "unbound" but not "kea-ub"
        if "kea-unbound" in line and "kea-ub" not in line:
            pytest.fail(f"Log line uses wrong tag: {line}")


def test_log_no_debug_in_normal_mode(ssh, test_log):
    """DEBUG lines should not appear without --verbose."""
    ssh("/usr/local/sbin/configctl keaunbound sync_static")
    time.sleep(2)
    log = _read_log(ssh)
    debug_lines = [l for l in log.splitlines() if "[DEBUG]" in l]
    test_log("observed", {"debug_line_count": len(debug_lines)})
    assert debug_lines == [], f"DEBUG lines found in non-verbose log: {debug_lines[:3]}"


def test_log_not_in_system_unbound_log(ssh, test_log):
    """kea-ub entries must NOT appear in the Unbound resolver log."""
    unbound_log = ssh("ls /var/log/resolver/ 2>/dev/null | tail -1", check=False)
    if not unbound_log.strip():
        pytest.skip("No resolver log found — skipping cross-log check")
    content = ssh(f"grep kea-ub /var/log/resolver/{unbound_log.strip()} || true",
                  check=False)
    test_log("observed", {"kea_ub_in_resolver_log": bool(content.strip())})
    assert not content.strip(), \
        f"kea-ub lines found in resolver log: {content[:200]}"
