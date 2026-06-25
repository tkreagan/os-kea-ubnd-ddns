#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
kea-ubnd-logwatch.py -- Kea log watcher for timely DNS cleanup.

Tails Kea's DHCP log and the kea-ubnd-ddns listener log.  On each detected
lease release (DHCP4_RELEASE*, DHCP6_RELEASE_NA*) or listener SERVFAIL (errors>0),
dispatches existing cleanup scripts via subprocess so all Unbound mutations go
through the shared advisory lock.

PRIMARY:  DHCP4/6_RELEASE → local-data-clean.py --purge-ip <ip>
SECONDARY: listener errors>0 → kea-sync.py --mode=full [--names=...]

Design principles:
  - Never touches unbound-control directly; always dispatches local-data-clean
    or kea-sync so the unbound_mutation_lock is always held during mutations.
  - Startup cutoff: seeks to end of each log file on startup so pre-start
    events (already handled by the main daemon's reconcile path) are ignored.
  - Log discovery: globs for the lexicographically latest <prefix>_*.log in
    the log directory rather than guessing a date-based name.  Handles both
    midnight rotation and pre-existing files from before daemon start.
  - Log rotation: watches log directories with kqueue EVFILT_VNODE NOTE_WRITE
    to detect new files.  On each directory event, refresh() re-globs and
    switches to a newer file if one appeared.
  - Grace window: coalesces events per IP/name for 10 s before dispatching,
    preventing storms when Kea reclaims multiple leases in a burst.
  - Status gate: only dispatches when the main daemon status file reports
    "running" — avoids racing a concurrent reconcile during BLOCKED/alert states.
  - Config: reads paths from keaubnd.json (written by start.py).  Pass
    --config to specify an alternative runtime config location.
  - Lifecycle: launched by start.py after the main listener; stopped by stop.py.
    Own daemon(8) supervisor/child pidfiles under /var/run/.

Run directly for testing:
  /usr/local/sbin/kea-ubnd-logwatch.py [--config PATH] [--grace-secs N]
"""
from __future__ import annotations

import argparse
import glob
import os
import select
import signal
import subprocess
import sys
from typing import List, Optional, Tuple

sys.path.insert(0, "/usr/local/opnsense/scripts/keaubnd")

from lib import keaubnd_runtime as _rt          # noqa: E402  # type: ignore[import]
from lib.keaubnd_sync import setup_logging      # noqa: E402  # type: ignore[import]
from lib.logwatch import (                      # noqa: E402  # type: ignore[import]
    AddOpSeen, EventQueue, MissedRemoveEvent, PendingRemoveTracker,
    ReleaseEvent, RemoveOpSeen, ServfailEvent,
    parse_kea_line, parse_listener_line,
)
from lib.preconditions import STATUS_FILE       # noqa: E402  # type: ignore[import]

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
    Manages an open tail of a log file, including rotation detection.

    File discovery: globs for <log_dir>/<prefix>_*.log and opens the
    lexicographically latest match (YYYYMMDD suffix → correct ordering).
    The log directory is watched with kqueue EVFILT_VNODE NOTE_WRITE; when
    a new file appears (e.g. midnight rollover), refresh() re-globs and
    transitions to the newer file.
    """

    _FILE_FFLAGS = (select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND
                    | select.KQ_NOTE_DELETE | select.KQ_NOTE_RENAME)
    _DIR_FFLAGS  = (select.KQ_NOTE_WRITE | select.KQ_NOTE_DELETE
                    | select.KQ_NOTE_RENAME)

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
        self._open_latest()

    def _latest_path(self) -> Optional[str]:
        """Return the lexicographically latest <prefix>_*.log in log_dir, or None."""
        try:
            files = glob.glob(os.path.join(self.log_dir, f"{self.prefix}_*.log"))
            return max(files) if files else None
        except OSError:
            return None

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

    def _open_latest(self) -> None:
        path = self._latest_path()
        if path is None:
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
        Check for a newer log file and transition to it if one appeared.
        Called on every directory VNODE event and every loop iteration.
        """
        latest = self._latest_path()
        if latest and latest != self._file_path:
            self.logger.info("logwatch: rotating to %s", latest)
            # New file: read from the beginning (no startup cutoff).
            orig_cutoff, self._startup_cutoff = self._startup_cutoff, False
            self._open_latest()
            self._startup_cutoff = orig_cutoff

    def read_lines(self) -> List[str]:
        """Read all available new lines from the current file."""
        if self._file_fd is None:
            self._open_latest()
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
    clean_script = _rt.get_logwatch_clean_script()
    logger.info("logwatch: dispatch purge-ip %s", ip)
    try:
        r = subprocess.run(
            [sys.executable, clean_script, "--purge-ip", ip],
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
    """Run run-sync.py [--names=...] for SERVFAIL/missed-remove recovery."""
    sync_script = _rt.get_logwatch_sync_script()
    if names:
        unique = sorted(set(names))
        args = [sys.executable, sync_script, "--names=" + ",".join(unique)]
        label = f"names={unique}"
    else:
        args = [sys.executable, sync_script]
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


def _dispatch_event(event, logger,
                    on_release: bool, on_servfail: bool, on_missed_remove: bool) -> None:
    if isinstance(event, ReleaseEvent) and on_release:
        _dispatch_purge_ip(event.ip, logger)
    elif isinstance(event, ServfailEvent) and on_servfail:
        _dispatch_sync_names(event.names, logger)
    elif isinstance(event, MissedRemoveEvent) and on_missed_remove:
        _dispatch_sync_names([event.hostname], logger)


# ── Main loop ─────────────────────────────────────────────────────────────────

def run(config: str,
        grace_secs: float = 10.0,
        on_release: bool = True,
        on_servfail: bool = True,
        on_missed_remove: bool = True) -> None:
    global _running
    signal.signal(signal.SIGTERM, _sigterm)
    signal.signal(signal.SIGINT, _sigterm)

    _rt.init(config)
    logger = setup_logging()
    logger.info(
        "kea-ubnd-logwatch starting (config=%s on_release=%s on_servfail=%s on_missed_remove=%s)",
        config, on_release, on_servfail, on_missed_remove,
    )

    kq = select.kqueue()
    queue = EventQueue(grace_secs=grace_secs)
    remove_tracker = PendingRemoveTracker(grace_secs=grace_secs)

    kea_tailer = LogTailer(
        _rt.get_logwatch_kea_log_dir(),
        _rt.get_logwatch_kea_log_prefix(),
        kq, logger,
    )
    listener_tailer = LogTailer(
        _rt.get_logwatch_listener_log_dir(),
        _rt.get_logwatch_listener_prefix(),
        kq, logger,
    )

    # Accumulated Add/Remove ops for the current NCR batch (SERVFAIL context).
    _listener_pending_ops: List[Tuple[str, str]] = []

    # kqueue timeout: wake at least every 60 s for rotation / deadline checks
    _POLL_TIMEOUT = 60.0

    while _running:
        # Compute wait: soonest of event queue, remove tracker, and poll interval.
        deadlines = [d for d in (queue.next_deadline(), remove_tracker.next_deadline())
                     if d is not None]
        timeout = min(_POLL_TIMEOUT, *deadlines) if deadlines else _POLL_TIMEOUT

        try:
            kq.control(None, 32, timeout)
        except (InterruptedError, OSError):
            pass

        # Check for a newer log file on every iteration (cheap glob).
        kea_tailer.refresh()
        listener_tailer.refresh()

        # Read Kea log lines (ReleaseEvents).
        for line in kea_tailer.read_lines():
            ev = parse_kea_line(line)
            if ev is not None:
                queue.add(f"ip:{ev.ip}", ev)

        # Read listener log lines (ServfailEvents + Remove/Add op signals).
        for line in listener_tailer.read_lines():
            result = parse_listener_line(line, _listener_pending_ops)
            if isinstance(result, ServfailEvent):
                key = ("servfail:" + ",".join(sorted(result.names))
                       if result.names else "servfail:full")
                queue.add(key, result)
                _listener_pending_ops.clear()
            elif isinstance(result, RemoveOpSeen) and on_missed_remove:
                remove_tracker.add_remove(result.hostname, result.ip)
            elif isinstance(result, AddOpSeen) and on_missed_remove:
                remove_tracker.cancel(result.hostname)
            elif result is None and "NCR id=" in line:
                _listener_pending_ops.clear()

        # Collect MissedRemoveEvents whose grace window expired and enqueue them.
        for missed in remove_tracker.ready():
            queue.add(f"missed:{missed.hostname}", missed)

        # Dispatch ready events if main daemon is running.
        ready = queue.ready()
        if ready:
            if _main_daemon_running():
                for event in ready:
                    _dispatch_event(event, logger, on_release, on_servfail, on_missed_remove)
            else:
                logger.debug("logwatch: main daemon not running — deferring %d event(s)", len(ready))
                for event in ready:
                    if isinstance(event, ReleaseEvent):
                        queue.add(f"ip:{event.ip}", event)
                    elif isinstance(event, ServfailEvent):
                        key = ("servfail:" + ",".join(sorted(event.names))
                               if event.names else "servfail:full")
                        queue.add(key, event)
                    elif isinstance(event, MissedRemoveEvent):
                        queue.add(f"missed:{event.hostname}", event)

    kea_tailer.close()
    listener_tailer.close()
    kq.close()
    logger.info("kea-ubnd-logwatch stopped")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", metavar="PATH",
                        default=_rt.RUNTIME_CONFIG_PATH,
                        help=f"Path to keaubnd.json "
                             f"(default: {_rt.RUNTIME_CONFIG_PATH})")
    parser.add_argument("--grace-secs", type=float, default=10.0, metavar="N",
                        help="Seconds to wait after last event before dispatching "
                             "(coalesce window). Default 10.")
    parser.add_argument("--no-on-release", dest="on_release", action="store_false",
                        help="Disable purge-ip on DHCP lease release.")
    parser.add_argument("--no-on-servfail", dest="on_servfail", action="store_false",
                        help="Disable targeted sync on listener SERVFAIL.")
    parser.add_argument("--no-on-missed-remove", dest="on_missed_remove", action="store_false",
                        help="Disable targeted sync on Remove-without-Add.")
    args = parser.parse_args()
    run(config=args.config,
        grace_secs=args.grace_secs,
        on_release=args.on_release,
        on_servfail=args.on_servfail,
        on_missed_remove=args.on_missed_remove)


if __name__ == "__main__":
    main()
