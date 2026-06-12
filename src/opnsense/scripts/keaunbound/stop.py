#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
stop.py -- Stop kea-unbound-ddns and kea-unbound-logwatch cleanly.

Called by configd actions [stop] and [restart].

Shutdown sequence (applied to each daemon independently):
  1. Collect all candidate PIDs: supervisor pidfile, child pidfile, pgrep scan.
  2. SIGTERM all (graceful — daemon(8) propagates to its child).
  3. Poll up to 3 s for graceful exit.
  4. SIGKILL anything still alive.
  5. Remove pidfiles.
"""

import os
import signal
import subprocess
import sys
import time

sys.path.insert(0, "/usr/local/opnsense/scripts/keaunbound")
from lib.keaunbound_sync import setup_logging  # noqa: E402

PIDFILE                     = "/var/run/kea-unbound-ddns.pid"
SUPERVISOR_PIDFILE          = "/var/run/kea-unbound-ddns.supervisor.pid"
LOGWATCH_PIDFILE            = "/var/run/kea-unbound-logwatch.pid"
LOGWATCH_SUPERVISOR_PIDFILE = "/var/run/kea-unbound-logwatch.supervisor.pid"
# Script paths — used by pgrep to find both the daemon(8) supervisor and Python
# child for each daemon without the self-match trap of pkill -f.
SCRIPT_PATH          = "/usr/local/sbin/kea-unbound-ddns.py"
LOGWATCH_SCRIPT_PATH = "/usr/local/sbin/kea-unbound-logwatch.py"

logger = setup_logging(verbose=True)


def _read_pid(pidfile: str) -> int | None:
    """Read PID from file; return None if missing, unreadable, or non-integer."""
    try:
        return int(open(pidfile).read().strip())
    except (FileNotFoundError, ValueError, OSError):
        return None


def _alive(pid: int) -> bool:
    """Return True if the process is alive (signal 0 existence check)."""
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, OSError):
        return False


def _send(pid: int, sig: int) -> None:
    """Send signal to pid, silently ignoring errors (process may be gone)."""
    try:
        os.kill(pid, sig)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _collect_pids(script_path: str, supervisor_pidfile: str,
                  child_pidfile: str) -> set[int]:
    """Collect all PIDs for one daemon (supervisor + child + pgrep scan)."""
    pids: set[int] = set()
    sup = _read_pid(supervisor_pidfile)
    if sup:
        pids.add(sup)
    child = _read_pid(child_pidfile)
    if child:
        pids.add(child)
    try:
        result = subprocess.run(["pgrep", "-f", script_path],
                                capture_output=True, text=True)
        for line in result.stdout.splitlines():
            try:
                pid = int(line.strip())
                if pid != os.getpid():
                    pids.add(pid)
            except ValueError:
                pass
    except Exception:
        pass
    return pids


def _stop_one(label: str, pids: set[int],
              pidfiles: tuple[str, ...]) -> bool:
    """Stop one set of PIDs.  Returns True on clean exit."""
    if not pids:
        logger.info("%s is not running", label)
        for pf in pidfiles:
            try:
                os.unlink(pf)
            except FileNotFoundError:
                pass
        return True

    logger.info("Stopping %s (pids: %s)", label, sorted(pids))
    for pid in pids:
        _send(pid, signal.SIGTERM)

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if not any(_alive(p) for p in pids):
            break
        time.sleep(0.25)

    stubborn = [p for p in pids if _alive(p)]
    if stubborn:
        logger.warning("%s: graceful shutdown timed out; force-killing: %s",
                       label, stubborn)
        for pid in stubborn:
            _send(pid, signal.SIGKILL)
        time.sleep(0.5)

    for pf in pidfiles:
        try:
            os.unlink(pf)
        except FileNotFoundError:
            pass

    remaining = [p for p in pids if _alive(p)]
    if remaining:
        logger.error("%s: failed to stop; still alive: %s", label, remaining)
        return False

    logger.info("%s stopped", label)
    return True


def main() -> int:
    listener_pids = _collect_pids(SCRIPT_PATH, SUPERVISOR_PIDFILE, PIDFILE)
    logwatch_pids = _collect_pids(LOGWATCH_SCRIPT_PATH,
                                  LOGWATCH_SUPERVISOR_PIDFILE, LOGWATCH_PIDFILE)

    ok1 = _stop_one("kea-unbound-ddns",
                    listener_pids, (SUPERVISOR_PIDFILE, PIDFILE))
    ok2 = _stop_one("kea-unbound-logwatch",
                    logwatch_pids, (LOGWATCH_SUPERVISOR_PIDFILE, LOGWATCH_PIDFILE))

    return 0 if (ok1 and ok2) else 1


if __name__ == "__main__":
    sys.exit(main())
