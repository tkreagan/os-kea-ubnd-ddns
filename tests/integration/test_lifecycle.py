# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Integration tests — service lifecycle (start / stop / restart).

Verifies that configctl keaunbound start/stop/restart behave correctly:
idempotency, PID file management, port binding, and service status.
"""

from __future__ import annotations

import time

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

PORT = 53535
PIDFILE = "/var/run/kea-unbound-ddns.pid"
SUP_PIDFILE = "/var/run/kea-unbound-ddns.supervisor.pid"


def _port_listening(ssh) -> bool:
    result = ssh(f"sockstat -4 -l -P udp | grep :{PORT}", check=False)
    return str(PORT) in result


def _pidfile_exists(ssh, path: str) -> bool:
    result = ssh(f"test -f {path} && echo yes || echo no", check=False)
    return result.strip() == "yes"


def _pgrep_count(ssh) -> int:
    result = ssh("pgrep -c -f kea-unbound-ddns.py || echo 0", check=False)
    try:
        return int(result.strip())
    except ValueError:
        return 0


@pytest.fixture(autouse=True)
def ensure_stopped(ssh, deploy):
    """Stop the daemon before and after each lifecycle test."""
    ssh("/usr/local/sbin/configctl keaunbound stop", check=False)
    time.sleep(1)
    yield
    ssh("/usr/local/sbin/configctl keaunbound stop", check=False)
    time.sleep(0.5)


def test_start_creates_pidfiles_and_binds_port(ssh, test_log):
    ssh("/usr/local/sbin/configctl keaunbound start")
    time.sleep(2)

    test_log("observed", {
        "port_listening": _port_listening(ssh),
        "supervisor_pidfile": _pidfile_exists(ssh, SUP_PIDFILE),
        "child_pidfile": _pidfile_exists(ssh, PIDFILE),
        "process_count": _pgrep_count(ssh),
    })

    assert _port_listening(ssh), f"Port {PORT} not bound after start"
    assert _pidfile_exists(ssh, SUP_PIDFILE), "Supervisor pidfile missing"
    assert _pidfile_exists(ssh, PIDFILE), "Child pidfile missing"
    assert _pgrep_count(ssh) >= 2, "Expected at least 2 processes (supervisor + child)"


def test_start_is_idempotent(ssh, test_log):
    """Second start must not spawn a second supervisor."""
    ssh("/usr/local/sbin/configctl keaunbound start")
    time.sleep(2)
    count_before = _pgrep_count(ssh)

    ssh("/usr/local/sbin/configctl keaunbound start")
    time.sleep(1)
    count_after = _pgrep_count(ssh)

    test_log("observed", {"count_before": count_before, "count_after": count_after})
    assert count_after == count_before, (
        f"Second start changed process count: {count_before} → {count_after}"
    )


def test_stop_removes_pidfiles_and_frees_port(ssh, test_log):
    ssh("/usr/local/sbin/configctl keaunbound start")
    time.sleep(2)
    ssh("/usr/local/sbin/configctl keaunbound stop")
    time.sleep(2)

    test_log("observed", {
        "port_listening": _port_listening(ssh),
        "supervisor_pidfile": _pidfile_exists(ssh, SUP_PIDFILE),
        "child_pidfile": _pidfile_exists(ssh, PIDFILE),
        "process_count": _pgrep_count(ssh),
    })

    assert not _port_listening(ssh), f"Port {PORT} still bound after stop"
    assert not _pidfile_exists(ssh, SUP_PIDFILE), "Supervisor pidfile still present"
    assert not _pidfile_exists(ssh, PIDFILE), "Child pidfile still present"
    assert _pgrep_count(ssh) == 0, "Processes still running after stop"


def test_restart_changes_pid(ssh, test_log):
    ssh("/usr/local/sbin/configctl keaunbound start")
    time.sleep(2)
    pid_before = ssh(f"cat {PIDFILE}", check=False).strip()

    ssh("/usr/local/sbin/configctl keaunbound restart")
    time.sleep(3)
    pid_after = ssh(f"cat {PIDFILE}", check=False).strip()

    test_log("observed", {"pid_before": pid_before, "pid_after": pid_after})
    assert pid_before != pid_after, "PID did not change after restart"
    assert _port_listening(ssh), f"Port {PORT} not bound after restart"


def test_status_reflects_running_state(ssh):
    ssh("/usr/local/sbin/configctl keaunbound start")
    time.sleep(2)
    status = ssh("/usr/local/sbin/pluginctl -s kea-unbound-ddns status",
                 check=False)
    assert "running" in status.lower() or pid_after, \
        f"Unexpected status output: {status!r}"


def test_stop_when_not_running_exits_cleanly(ssh):
    """Stop on an already-stopped daemon should succeed without error."""
    ssh("/usr/local/sbin/configctl keaunbound stop")
    # Second stop should also be clean
    ssh("/usr/local/sbin/configctl keaunbound stop")
