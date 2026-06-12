#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
kea-unbound-logwatch.py -- Kea log watcher for timely DNS cleanup.

Tails Kea's DHCP log and the kea-unbound-ddns listener log.  On each detected
lease release (DHCP4_RELEASE, DHCP6_RELEASE) or listener SERVFAIL (errors>0),
dispatches existing cleanup scripts via subprocess so all Unbound mutations go
through the shared advisory lock.

PRIMARY:  DHCP4/6_RELEASE → local-data-clean.py --purge-ip <ip>
SECONDARY: listener errors>0 → kea-sync.py --mode=full [--names=...]

Design principles:
  - Never touches unbound-control directly; always dispatches local-data-clean
    or kea-sync so the unbound_mutation_lock is always held during mutations.
  - Startup cutoff: seeks to end of each log file on startup so pre-start
    events (already handled by the main daemon's reconcile path) are ignored.
  - Log rotation: watches log directories with kqueue EVFILT_VNODE NOTE_WRITE
    to detect new dated files at midnight.  Computed filename: kea_YYYYMMDD.log.
  - Grace window: coalesces events per IP/name for 10 s before dispatching,
    preventing storms when Kea reclaims multiple leases in a burst.
  - Status gate: only dispatches when the main daemon status file reports
    "running" — avoids racing a concurrent reconcile during BLOCKED/alert states.
  - Lifecycle: launched by start.py after the main listener; stopped by stop.py.
    Own daemon(8) supervisor/child pidfiles under /var/run/.

Run directly for testing:
  /usr/local/sbin/kea-unbound-logwatch.py [--log-dir DIR] [--grace-secs N]
"""
from __future__ import annotations

import argparse
import os
import select
import signal
import subprocess
import sys
import time
from datetime import datetime
from typing import List, Optional

sys.path.insert(0, "/usr/local/opnsense/scripts/keaunbound")

from lib.keaunbound_sync import setup_logging  # noqa: E402
from lib.logwatch import (  # noqa: E402
    EventQueue, ReleaseEvent, ServfailEvent,
    parse_kea_line, parse_listener_line,
)
from lib.preconditions import STATUS_FILE  # noqa: E402

# ── Paths ────────────────────────────────────────────────────────────────────

KEA_LOG_DIR       = "/var/log/kea"
LISTENER_LOG_DIR  = "/var/log/keaunbound"
KEA_LOG_PREFIX    = "kea"
LISTENER_PREFIX   = "keaunbound"

CLEAN_SCRIPT  = "/usr/local/opnsense/scripts/keaunbound/local-data-clean.py"
SYNC_SCRIPT   = "/usr/local/opnsense/scripts/keaunbound/kea-sync.py"

# ── Internals ────────────────────────────────────────────────────────────────

_running = True


def _sigterm(_sig, _frame) -> None:
    global _running
    _running = False


# ── Status gate ──────────────────────────────────────────────────────────────

def _main_daemon_running() -> bool:
    """Return True only when the main daemon status file says 'running'."""
    try:
        with open(STATUS_FILE) as f:
            state = f.read().split("\t")[0].strip()
        return state == "running"
    except (FileNotFoundError, OSError):
        return False


# ── Log file tailer ──────────────────────────────────────────────────────────

class LogTailer:
    """
    Manages an open tail of a dated log file, including rotation detection.

    File naming: <log_dir>/<prefix>_YYYYMMDD.log
    Rotation: the log directory is watched with kqueue EVFILT_VNODE NOTE_WRITE;
    when a new dated file appears (midnight rollover), this tailer detects it
    and transitions to the new file.
    """

    _FILE_FFLAGS = select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND | select.KQ_NOTE_DELETE | select.KQ_NOTE_RENAME
    _DIR_FFLAGS  = select.KQ_NOTE_WRITE | select.KQ_NOTE_DELETE | select.KQ_NOTE_RENAME

    def __init__(self, log_dir: str, prefix: str, kq: select.kqueue,
                 logger, startup_cutoff: bool = True):
        self.log_dir = log_dir
        self.prefix = prefix
        self.kq = kq
        self.logger = logger
        self._startup_cutoff = startup_cutoff

        self._file_fd: Optional[int] = None
        self._file_path: Optional[str] = None
        self._dir_fd:  Optional[int] = None
        self.idents: set[int] = set()

        self._open_dir()
        self._open_today()

    def _today_path(self) -> str:
        return os.path.join(
            self.log_dir,
            f"{self.prefix}_{datetime.now().strftime('%Y%m%d')}.log"
        )

    def _open_dir(self) -> None:
        if not os.path.isdir(self.log_dir):
            return
        try:
            fd = os.open(self.log_dir, os.O_RDONLY)
        except OSError:
            return
        ev = select.kevent(fd, filter=select.KQ_FILTER_VNODE,
                           flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                           fflags=self._DIR_FFLAGS)
        self.kq.control([ev], 0, 0)
        self._dir_fd = fd
        self.idents.add(fd)

    def _open_today(self) -> None:
        path = self._today_path()
        if not os.path.exists(path):
            return
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError as e:
            self.logger.warning("logwatch: cannot open %s: %s", path, e)
            return

        # Startup cutoff: seek to end so we don't replay pre-start events.
        if self._startup_cutoff:
            size = os.fstat(fd).st_size
            os.lseek(fd, size, os.SEEK_SET)

        ev = select.kevent(fd, filter=select.KQ_FILTER_VNODE,
                           flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                           fflags=self._FILE_FFLAGS)
        self.kq.control([ev], 0, 0)

        if self._file_fd is not None:
            self._close_file()

        self._file_fd = fd
        self._file_path = path
        self.idents.add(fd)
        self.logger.debug("logwatch: watching %s", path)

    def _close_file(self) -> None:
        if self._file_fd is not None:
            self.idents.discard(self._file_fd)
            try:
                os.close(self._file_fd)
            except OSError:
                pass
            self._file_fd = None
            self._file_path = None

    def refresh(self) -> None:
        """
        Check for a log rotation: if today's dated file differs from the
        currently open file, transition to the new one.  Called every loop
        iteration (cheap — just a date comparison and stat).
        """
        today = self._today_path()
        if today != self._file_path and os.path.exists(today):
            self.logger.info("logwatch: rotating to %s", today)
            # Rotation: new file starts at the beginning (no startup cutoff).
            orig_cutoff, self._startup_cutoff = self._startup_cutoff, False
            self._open_today()
            self._startup_cutoff = orig_cutoff

    def read_lines(self) -> List[str]:
        """Read all available new lines from the current file."""
        if self._file_fd is None:
            self._open_today()
            if self._file_fd is None:
                return []
        lines = []
        buf = b""
        while True:
            try:
                chunk = os.read(self._file_fd, 65536)
            except BlockingIOError:
                break
            except OSError:
                self._close_file()
                break
            if not chunk:
                break
            buf += chunk
        for raw in buf.split(b"\n"):
            line = raw.decode("utf-8", errors="replace").strip()
            if line:
                lines.append(line)
        return lines

    def close(self) -> None:
        self._close_file()
        if self._dir_fd is not None:
            self.idents.discard(self._dir_fd)
            try:
                os.close(self._dir_fd)
            except OSError:
                pass
            self._dir_fd = None


# ── Dispatch ─────────────────────────────────────────────────────────────────

def _dispatch_purge_ip(ip: str, logger) -> None:
    """Run local-data-clean.py --purge-ip under its own mutex lock."""
    logger.info("logwatch: dispatch purge-ip %s", ip)
    try:
        r = subprocess.run(
            [sys.executable, CLEAN_SCRIPT, "--purge-ip", ip],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode != 0:
            logger.warning("logwatch: purge-ip %s failed (rc=%d): %s",
                           ip, r.returncode, r.stderr.strip())
    except subprocess.TimeoutExpired:
        logger.error("logwatch: purge-ip %s timed out", ip)
    except Exception as e:
        logger.error("logwatch: purge-ip %s error: %s", ip, e)


def _dispatch_sync_names(names: List[str], logger) -> None:
    """Run kea-sync.py --mode=full [--names=...] for SERVFAIL recovery."""
    if names:
        unique = sorted(set(names))
        args = [sys.executable, SYNC_SCRIPT, "--mode=full",
                "--names=" + ",".join(unique)]
        label = f"names={unique}"
    else:
        args = [sys.executable, SYNC_SCRIPT, "--mode=full"]
        label = "full"
    logger.info("logwatch: dispatch sync %s", label)
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            logger.warning("logwatch: sync %s failed (rc=%d): %s",
                           label, r.returncode, r.stderr.strip())
    except subprocess.TimeoutExpired:
        logger.error("logwatch: sync %s timed out", label)
    except Exception as e:
        logger.error("logwatch: sync %s error: %s", label, e)


def _dispatch_event(event, logger) -> None:
    if isinstance(event, ReleaseEvent):
        _dispatch_purge_ip(event.ip, logger)
    elif isinstance(event, ServfailEvent):
        _dispatch_sync_names(event.names, logger)


# ── Main loop ─────────────────────────────────────────────────────────────────

def run(grace_secs: float = 10.0) -> None:
    global _running
    signal.signal(signal.SIGTERM, _sigterm)
    signal.signal(signal.SIGINT, _sigterm)

    logger = setup_logging()
    logger.info("kea-unbound-logwatch starting")

    kq = select.kqueue()
    queue = EventQueue(grace_secs=grace_secs)

    kea_tailer      = LogTailer(KEA_LOG_DIR,      KEA_LOG_PREFIX,   kq, logger)
    listener_tailer = LogTailer(LISTENER_LOG_DIR,  LISTENER_PREFIX,  kq, logger)

    # State for correlating multi-line listener log batches
    _listener_pending_ops: List[Tuple[str, str]] = []

    all_idents = kea_tailer.idents | listener_tailer.idents

    # kqueue timeout: wake at least every 60 s for date-change / deadline checks
    _POLL_TIMEOUT = 60.0

    while _running:
        # Compute wait time: min(deadline, poll)
        dl = queue.next_deadline()
        timeout = min(_POLL_TIMEOUT, dl) if dl is not None else _POLL_TIMEOUT

        try:
            events = kq.control(None, 32, timeout)
        except (InterruptedError, OSError):
            events = []

        # Check for rotation on every iteration (cheap date comparison).
        kea_tailer.refresh()
        listener_tailer.refresh()

        # Read Kea log lines
        for line in kea_tailer.read_lines():
            ev = parse_kea_line(line)
            if ev is not None:
                queue.add(f"ip:{ev.ip}", ev)

        # Read listener log lines
        for line in listener_tailer.read_lines():
            ev = parse_listener_line(line, _listener_pending_ops)
            if ev is not None:
                # ServfailEvent: coalesce by set of names
                key = "servfail:" + ",".join(sorted(ev.names)) if ev.names else "servfail:full"
                queue.add(key, ev)
                _listener_pending_ops.clear()
            elif "NCR id=" in line:
                # New NCR boundary — clear accumulated ops
                _listener_pending_ops.clear()

        # Dispatch ready events (grace window expired) if main daemon is running
        ready = queue.ready()
        if ready:
            if _main_daemon_running():
                for event in ready:
                    _dispatch_event(event, logger)
            else:
                logger.debug("logwatch: main daemon not running — deferring %d event(s)", len(ready))
                # Re-queue with a fresh grace window so we retry
                for event in ready:
                    if isinstance(event, ReleaseEvent):
                        queue.add(f"ip:{event.ip}", event)
                    elif isinstance(event, ServfailEvent):
                        key = ("servfail:" + ",".join(sorted(event.names))
                               if event.names else "servfail:full")
                        queue.add(key, event)

    kea_tailer.close()
    listener_tailer.close()
    kq.close()
    logger.info("kea-unbound-logwatch stopped")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--grace-secs", type=float, default=10.0, metavar="N",
                        help="Seconds to wait after last event before dispatching "
                             "(coalesce window). Default 10.")
    args = parser.parse_args()
    run(grace_secs=args.grace_secs)


if __name__ == "__main__":
    main()
