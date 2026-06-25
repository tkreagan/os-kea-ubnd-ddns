#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
pid_watch.py -- level-read of watched service pids + kqueue VNODE management.

The resident daemon's consistency machine is LEVEL-TRIGGERED: every wake it
re-reads the pid VALUE from each enabled service's pidfile and hands the result
to ConsistencySM.on_wake(). kqueue VNODE events are only "go look again" nudges.

Why read the pid VALUE (not just existence / inode)? Spike V1/R6 measured the two
restart styles on OPNsense:
  * Unbound rewrites its pidfile IN PLACE -- same inode, never absent, only the
    pid value changes. A stat()/inode check or a directory NOTE_WRITE both MISS
    it; only re-reading the file contents catches the restart.
  * Kea (dhcp4/dhcp6/d2) unlink+recreates -- inode changes, ~40 ms absent window,
    new pid. The parent-dir NOTE_WRITE fires and the file fd goes stale.
So the watch set must be per-file AND parent-directory, and the source of truth
is read_pid_state() reading the integer in each file.

The pure read (read_pid_state) is unit-tested with temp files; PidWatcher wraps
kqueue VNODE registration and is exercised on the box.
"""
from __future__ import annotations

import os
import select
from typing import Dict, List, Optional, Tuple

from . import keaubnd_runtime as _rt

# A service's pid sample: (exists, pid_or_None) -- the SM's PidState value type.
PidSample = Tuple[bool, Optional[int]]
PidState = Dict[str, PidSample]


def resolve_watched_services() -> Dict[str, str]:
    """Return {service: pidfile} for the services this daemon should watch.

    Always watches unbound (the flush source -- its restart wipes our local_data)
    and d2 (the NCR source). Watches dhcp4/dhcp6 only when the runtime config
    records a socket for them (i.e. they are enabled and started), so the SM's
    all-present check never waits on a service that will never appear.
    """
    watched: Dict[str, str] = {}

    # Unbound: always watch; its restart wipes our local_data
    watched["unbound"] = _rt.get_unbound_pid()

    # d2: always watch (NCR source); skip only if not configured
    d2_pid = _rt.get_kea_pid("d2")
    if d2_pid:
        watched["d2"] = d2_pid

    # dhcp4/dhcp6: watch only when enabled (has a socket in runtime config)
    for svc in ("dhcp4", "dhcp6"):
        if _rt.get_kea_socket(svc):
            pid = _rt.get_kea_pid(svc)
            if pid:
                watched[svc] = pid

    return watched


def _read_pid(path: str) -> PidSample:
    """Read one pidfile. (True, pid) if present and parseable, (True, None) if
    present but unreadable/garbage, (False, None) if absent."""
    try:
        with open(path) as f:
            text = f.read().strip()
    except FileNotFoundError:
        return (False, None)
    except OSError:
        # Present but unreadable (race with a rewrite, perms). Treat as present
        # with unknown pid -- the next wake re-reads; never crash the loop.
        return (True, None)
    try:
        return (True, int(text.split()[0]))
    except (ValueError, IndexError):
        return (True, None)


def read_pid_state(service_paths: Dict[str, str]) -> PidState:
    """Level read: stat+parse every watched pidfile into the SM's PidState.
    Pure w.r.t. the filesystem -- no caching, no side effects beyond reading."""
    return {svc: _read_pid(path) for svc, path in service_paths.items()}


class PidWatcher:
    """Manages kqueue EVFILT_VNODE registrations for the watched pidfiles.

    Registers into a kqueue OWNED BY THE CALLER (the daemon multiplexes the
    socket, timer, and reconcile-proc filters in the same kqueue). Watches:
      * each pidfile (NOTE_WRITE|EXTEND|DELETE|RENAME) -- catches unbound's
        in-place rewrite (NOTE_WRITE, same fd) and kea's unlink (NOTE_DELETE,
        fd goes stale -> we re-open on the next refresh).
      * each parent directory (NOTE_WRITE) -- catches first-ever creation and
        kea's recreate, when no file fd can be held.
    Events are wake nudges only; the daemon always re-reads via read_pid_state().
    """

    _FILE_FFLAGS = (select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND
                    | select.KQ_NOTE_DELETE | select.KQ_NOTE_RENAME)
    _DIR_FFLAGS = (select.KQ_NOTE_WRITE | select.KQ_NOTE_DELETE
                   | select.KQ_NOTE_RENAME)

    def __init__(self, kq: select.kqueue, service_paths: Dict[str, str]):
        self.kq = kq
        self.service_paths = dict(service_paths)
        self._file_fds: Dict[str, int] = {}   # service -> open fd
        self._dir_fds: Dict[str, int] = {}     # dir path -> open fd
        self.idents: set[int] = set()          # all fds we registered (for the loop)

    def register_all(self) -> None:
        """Open and register watches for every parent dir and every present
        pidfile. Idempotent -- safe to call again via refresh()."""
        for d in sorted({os.path.dirname(p) for p in self.service_paths.values()}):
            if d not in self._dir_fds and os.path.isdir(d):
                self._register_dir(d)
        self.refresh()

    def refresh(self) -> None:
        """Reconcile file watches with reality: open+register pidfiles that have
        appeared, drop watches whose fd went stale (kea unlink+recreate). Called
        after every VNODE wake so a recreated pidfile gets a fresh watch."""
        for svc, path in self.service_paths.items():
            have = svc in self._file_fds
            exists = os.path.exists(path)
            if exists and not have:
                self._register_file(svc, path)
            elif have and not exists:
                self._unregister_file(svc)

    def _register_dir(self, d: str) -> None:
        try:
            fd = os.open(d, os.O_RDONLY)
        except OSError:
            return
        ev = select.kevent(fd, filter=select.KQ_FILTER_VNODE,
                           flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                           fflags=self._DIR_FFLAGS)
        self.kq.control([ev], 0, 0)
        self._dir_fds[d] = fd
        self.idents.add(fd)

    def _register_file(self, svc: str, path: str) -> None:
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError:
            return
        ev = select.kevent(fd, filter=select.KQ_FILTER_VNODE,
                           flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                           fflags=self._FILE_FFLAGS)
        self.kq.control([ev], 0, 0)
        self._file_fds[svc] = fd
        self.idents.add(fd)

    def _unregister_file(self, svc: str) -> None:
        fd = self._file_fds.pop(svc, None)
        if fd is None:
            return
        # The kqueue registration is auto-removed when the fd closes; closing is
        # enough. (An explicit EV_DELETE would race a recreated inode.)
        self.idents.discard(fd)
        try:
            os.close(fd)
        except OSError:
            pass

    def close(self) -> None:
        for fd in list(self._file_fds.values()) + list(self._dir_fds.values()):
            try:
                os.close(fd)
            except OSError:
                pass
        self._file_fds.clear()
        self._dir_fds.clear()
        self.idents.clear()

    def read_state(self) -> PidState:
        """Convenience: the level read for the watched set."""
        return read_pid_state(self.service_paths)
