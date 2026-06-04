#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
stop.py -- Stop kea-unbound-ddns cleanly and reliably.

Called by configd actions [stop] and [restart]. Replaces the previous inline
pkill-F shell command, which was fragile: if the supervisor pidfile drifted
out of sync with the actual running supervisor (which happens whenever a
restart fails partway), pkill -F silently killed the wrong process and left
the real daemon running.

Shutdown sequence:
  1. Collect all candidate PIDs: supervisor pidfile, child pidfile, pgrep scan.
  2. SIGTERM all of them (graceful — daemon(8) propagates to its child).
  3. Poll up to 3 s for graceful exit.
  4. SIGKILL anything still alive.
  5. Remove pidfiles.

pgrep is used for discovery (not pkill) so the pattern string in argv does
not cause the process to match and kill itself — a problem inherent to using
pkill -f from a shell whose own argv contains the match string.
"""

import os
import signal
import subprocess
import sys
import time

sys.path.insert(0, "/usr/local/opnsense/scripts/keaunbound")
from lib.keaunbound_sync import setup_logging  # noqa: E402

PIDFILE            = "/var/run/kea-unbound-ddns.pid"
SUPERVISOR_PIDFILE = "/var/run/kea-unbound-ddns.supervisor.pid"
# The script path is a stable anchor — both the daemon(8) supervisor and the
# Python child have it in their argv, so pgrep -f finds both with one query.
SCRIPT_PATH        = "/usr/local/sbin/kea-unbound-ddns.py"

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


def _find_matching_pids() -> list[int]:
    """
    Return PIDs of all processes with SCRIPT_PATH in their argv, excluding
    this process. Uses pgrep (not pkill) to avoid the self-match trap where
    pkill -f matches its own parent shell because the pattern string appears
    in the shell's argv.
    """
    try:
        result = subprocess.run(
            ["pgrep", "-f", SCRIPT_PATH],
            capture_output=True, text=True
        )
        pids = []
        for line in result.stdout.splitlines():
            try:
                pid = int(line.strip())
                if pid != os.getpid():
                    pids.append(pid)
            except ValueError:
                pass
        return pids
    except Exception:
        return []


def _send(pid: int, sig: int) -> None:
    """Send signal to pid, silently ignoring errors (process may be gone)."""
    try:
        os.kill(pid, sig)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def main() -> int:
    # Collect every PID that might be part of this daemon: supervisor pidfile,
    # child pidfile, and a pgrep scan for anything else with the script in argv
    # (covers orphaned processes whose pidfile was already deleted).
    pids: set[int] = set()

    sup_pid = _read_pid(SUPERVISOR_PIDFILE)
    if sup_pid:
        pids.add(sup_pid)

    child_pid = _read_pid(PIDFILE)
    if child_pid:
        pids.add(child_pid)

    pids.update(_find_matching_pids())

    if not pids:
        logger.info("kea-unbound-ddns is not running")
        # Clean up any stale pidfiles that might confuse a subsequent start.
        for pf in (SUPERVISOR_PIDFILE, PIDFILE):
            try:
                os.unlink(pf)
            except FileNotFoundError:
                pass
        return 0

    # Phase 1: SIGTERM — let daemon(8) propagate gracefully to its child.
    logger.info("Stopping kea-unbound-ddns (pids: %s)", sorted(pids))
    for pid in pids:
        _send(pid, signal.SIGTERM)

    # Phase 2: Poll up to 3 s for graceful exit (child exits within ~1 s
    # once its 1-second socket timeout fires and it checks _running=False).
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if not any(_alive(p) for p in pids):
            break
        time.sleep(0.25)

    # Phase 3: SIGKILL anything still alive after the grace period.
    stubborn = [p for p in pids if _alive(p)]
    if stubborn:
        logger.warning("Graceful shutdown timed out; force-killing: %s", stubborn)
        for pid in stubborn:
            _send(pid, signal.SIGKILL)
        time.sleep(0.5)

    # Phase 4: Remove pidfiles — always, even if some processes couldn't be
    # killed, so a subsequent start.py doesn't see stale pidfiles as proof
    # that the daemon is running.
    for pf in (SUPERVISOR_PIDFILE, PIDFILE):
        try:
            os.unlink(pf)
        except FileNotFoundError:
            pass

    remaining = [p for p in pids if _alive(p)]
    if remaining:
        logger.error("Failed to stop all processes; still alive: %s", remaining)
        return 1

    logger.info("kea-unbound-ddns stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
