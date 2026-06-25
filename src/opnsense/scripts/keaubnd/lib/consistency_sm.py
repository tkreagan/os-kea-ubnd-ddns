#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
consistency_sm.py -- the BLOCKED/NORMAL consistency state machine for the
resident kea-ubnd-ddns daemon.

This is the production control logic, factored out of the daemon so it has NO
dependency on kqueue, real subprocesses, sockets, or module globals. The daemon
feeds it real pid-stats and real subprocess exits; the unit tests feed it fake
ones. Same code, both paths.

── Design (see int-docs/resident-daemon-design.md + -implementation-plan.md) ──
The daemon owns DNS consistency end to end. Kea-derived records live only in
Unbound's runtime local_data and are flushed on every Unbound/Kea restart, so a
restart must trigger a resync. The machine has two states:

  NORMAL   -- the world is up; live NCR applies go straight to Unbound.
  BLOCKED  -- a watched service restarted (pid absent/changed) and/or we are
              repopulating; live applies are deferred (the daemon ACK-fails d2
              and records the name as dirty).

Key invariants:
  * LEVEL-TRIGGERED. Transitions derive from a fresh stat() of the enabled
    pidfiles passed in on every wake -- kqueue events and timers are only
    "go look again" nudges. A changed pid value counts as a restart even if we
    never caught an "absent" sample (the fast-flap case a 1 Hz poll misses).
  * BLOCKED is triggered ONLY by pid absent/changed. Lock contention does NOT
    block (see below) -- that was an earlier design that forced a full resync on
    every external clean; rejected.
  * The shared Unbound-mutation lock is held by the *subprocesses* this machine
    spawns (kea-sync.py) and by external scripts (clean/UI). The live-apply path
    in the daemon takes the lock with a short bounded wait; if it can't get it in
    time it ACK-fails + marks the name dirty and STAYS NORMAL. Those dirty names
    are drained by a timer-driven targeted reconcile once the lock frees. This
    machine never needs the lock itself.
  * Durability is the resync. Never discard a dirty name without either applying
    it or handing it to a reconcile. On a drain/reconcile *failure* the snapshot
    is merged back into the dirty set (a subtlety the prose design omits).

── How the daemon drives it ──
  sm = ConsistencySM(config)
  for d in sm.start(now): execute(d)
  loop:
    ev = kevent()
    if pid-dir VNODE or timer:   ds = sm.on_wake(now, stat_pids())
    if reconcile child exited:   ds = sm.on_sync_exit(now, code, overflowed)
    if live NCR contended/blocked: sm.note_dirty_ncr(names, ips)  # no directives
    for d in ds: execute(d)

Directives the daemon must execute:
  Spawn(mode, names, purge_ips) -- Popen kea-sync.py [--names=...] [--purge-ip=...];
                         register NOTE_EXIT; feed the exit back via on_sync_exit().
                         names=None => full reconcile; a frozenset => targeted drain.
                         purge_ips=frozenset of IPs to purge-release in the same child.
  KillPending()       -- SIGTERM the running reconcile child and waitpid it.
  ScheduleWake(delay) -- arm an EVFILT_TIMER to call on_wake() after `delay` s.
  Terminate(reason)   -- watchdog fired: clean full stop of the whole plugin.
  Alert(message)      -- raise a loud, user-visible alert (UI status + log).
  FastReload()        -- Popen fast-reload.py; register NOTE_EXIT; feed the exit
                         back via on_sync_exit(). Emitted from NORMAL when the
                         daemon sets fast_reload_pending=True (mutation threshold
                         reached). fast-reload.py acquires the mutation lock,
                         calls unbound-control fast-reload (falling back to reload
                         on Unbound < 1.22), then runs a full kea-sync to
                         repopulate the runtime local_data records that a reload
                         clears. On success the SM stays NORMAL with _pending
                         cleared. On failure (reload succeeded but resync failed)
                         the SM stays NORMAL and forces a RECONCILE so
                         _after_reconcile can backoff-retry repopulation.
"""

from __future__ import annotations

import dataclasses
import enum
from typing import Dict, FrozenSet, List, Optional, Tuple


# ── Dirty-pool entry ────────────────────────────────────────────────────────
@dataclasses.dataclass(frozen=True)
class _DirtyEntry:
    kind: str   # "name" | "ip"
    value: str


# ── Directives (what the daemon must do) ────────────────────────────────────
@dataclasses.dataclass(frozen=True)
class Spawn:
    mode: str                      # "full" | "static" | "dynamic"
    names: Optional[FrozenSet[str]]  # None = full reconcile; set = targeted drain
    purge_ips: Optional[FrozenSet[str]] = None  # IPs to purge-release in the same child


@dataclasses.dataclass(frozen=True)
class KillPending:
    pass


@dataclasses.dataclass(frozen=True)
class ScheduleWake:
    delay: float                   # seconds


@dataclasses.dataclass(frozen=True)
class Terminate:
    reason: str


@dataclasses.dataclass(frozen=True)
class Alert:
    message: str


@dataclasses.dataclass(frozen=True)
class FastReload:
    pass


Directive = object  # one of the above


# ── State ───────────────────────────────────────────────────────────────────
class State(enum.Enum):
    BLOCKED = "blocked"
    NORMAL = "normal"


class _Pending(enum.Enum):
    NONE = "none"
    RECONCILE = "reconcile"      # a full (names=None) reconcile is running
    DRAIN = "drain"              # a targeted (names=snapshot) reconcile is running
    FAST_RELOAD = "fast_reload"  # fast-reload.py subprocess is running


@dataclasses.dataclass
class SMConfig:
    """Tunables (wired from advanced settings; see General.xml in Phase 5)."""
    dirty_cap: int = 50
    max_full_sync_attempts: int = 5
    watchdog_seconds: float = 600.0     # 0 == wait forever
    backoff_base: float = 0.25
    backoff_factor: float = 2.0
    backoff_cap: float = 60.0
    # In NORMAL, how soon after a pid-dir wake to retry if a drain is already
    # running.  Not a polling interval -- on_sync_exit drives the next drain.
    normal_drain_poll: float = 1.0


# pid_state maps an enabled service name -> (exists, pid_or_None).
PidState = Dict[str, Tuple[bool, Optional[int]]]


class ConsistencySM:
    """The consistency state machine. Pure: methods mutate self and return a
    list of Directives; they never perform side effects."""

    def __init__(self, config: Optional[SMConfig] = None):
        self.cfg = config or SMConfig()
        self.state = State.BLOCKED
        self._pending = _Pending.NONE
        # Unified dirty pool: deferred names (kind="name") and IPs from deferred
        # DELETE NCRs (kind="ip"). Names re-resolve from Kea at drain time;
        # IPs are passed as --purge-ip to the same drain child.
        self.dirty: set[_DirtyEntry] = set()
        # Snapshot of the dirty pool handed to the in-flight drain; merged back
        # on failure so a failed drain can never lose a deferred update.
        self._draining: set[_DirtyEntry] = set()
        self.overflowed = False
        self.full_sync_counter = 0
        self._drain_fail_counter = 0
        self.degraded = False           # hit max_full_sync_attempts; best-effort
        # Set by the daemon when the live-path mutation counter hits the threshold.
        # Cleared when a FastReload directive is emitted.
        self.fast_reload_pending: bool = False
        # backoff (consecutive failures against a *stable* pid set)
        self._backoff = self.cfg.backoff_base
        self._next_attempt_at = 0.0
        # watchdog
        self._blocked_since: Optional[float] = None
        # level memory
        self._last_pids: Optional[PidState] = None
        self._enabled: set[str] = set()

    # ── lifecycle ────────────────────────────────────────────────────────────
    def start(self, now: float) -> List[Directive]:
        """Enter BLOCKED immediately on daemon start (design: bind socket, then
        BLOCKED -- the first packet ACK-fails + dirty-records)."""
        self.state = State.BLOCKED
        self._blocked_since = now
        self._reset_backoff()
        # Nothing to spawn yet: we have no pid_state. The daemon will call
        # on_wake() with the first stat. Nudge it.
        return [ScheduleWake(0.0)]

    # ── inputs ────────────────────────────────────────────────────────────────
    def note_dirty_ncr(self, names, ips=()) -> None:
        """Record names and/or IPs from a deferred NCR into the unified dirty pool.
        Names are re-resolved from Kea at drain time; IPs are passed as --purge-ip
        to remove stale PTRs even if Kea briefly still shows the lease as active.
        Called by all four defer paths in _apply_or_defer so they are symmetric."""
        for n in names:
            self.dirty.add(_DirtyEntry("name", n))
        for ip in ips:
            self.dirty.add(_DirtyEntry("ip", ip))
        if len(self.dirty) > self.cfg.dirty_cap:
            self.overflowed = True

    def on_apply_failure(self, now: float) -> List[Directive]:
        """Unbound connection refused on the live path: enter BLOCKED.
        The caller must call note_dirty_ncr() first to record deferred names/IPs.
        Distinct from lock contention, which stays NORMAL and uses note_dirty_ncr
        directly without calling this."""
        if self.state is State.NORMAL:
            self.state = State.BLOCKED
            self._blocked_since = now
            self._reset_backoff()
        return [ScheduleWake(0.0)]

    def on_wake(self, now: float, pids: PidState) -> List[Directive]:
        """Re-evaluate from the current pid level. Called on every VNODE event
        and timer fire. `pids` covers exactly the ENABLED services."""
        ds: List[Directive] = []
        self._enabled = set(pids.keys())

        changed = self._pid_level_changed(pids)
        all_present = self._all_present(pids)
        self._last_pids = dict(pids)

        if changed:
            # A fresh restart: reset failure backoff and the overflow counter
            # (a new restart deserves prompt, fresh attempts). If we were NORMAL,
            # fall to BLOCKED. If a reconcile/drain is mid-flight, preempt it.
            self._reset_backoff()
            self.full_sync_counter = 0
            self._drain_fail_counter = 0
            self.degraded = False
            if self._pending is not _Pending.NONE:
                ds.append(KillPending())
                self._on_pending_aborted()
            if self.state is State.NORMAL:
                self.state = State.BLOCKED
                self._blocked_since = now

        if self.state is State.BLOCKED:
            ds += self._tick_blocked(now, all_present)
        else:
            ds += self._tick_normal(now, all_present)
        return ds

    def on_sync_exit(self, now: float, exit_code: int,
                     overflowed: bool = False) -> List[Directive]:
        """A reconcile/drain/fast-reload subprocess we spawned has exited."""
        if overflowed:
            self.overflowed = True
        pend, self._pending = self._pending, _Pending.NONE

        if pend is _Pending.RECONCILE:
            return self._after_reconcile(now, exit_code)
        if pend is _Pending.DRAIN:
            return self._after_drain(now, exit_code)
        if pend is _Pending.FAST_RELOAD:
            if exit_code != 0:
                # Unbound responded to the reload (so it is UP) but runtime
                # local_data was cleared and not repopulated. Force a full
                # reconcile; _after_reconcile owns backoff/retry on repeated
                # failure. Stay NORMAL — Unbound is up, so live NCRs keep
                # applying; BLOCKED would needlessly SERVFAIL them all.
                # Do NOT clear dirty: _after_reconcile clears on success.
                self._pending = _Pending.RECONCILE
                return [Spawn("full", None)]
            # Success: drain any names that accumulated while fast-reload ran.
            return self._spawn_drain_or_normal()
        # Spurious exit (e.g. we already preempted via KillPending). Ignore.
        return []

    # ── BLOCKED ───────────────────────────────────────────────────────────────
    def _tick_blocked(self, now: float, all_present: bool) -> List[Directive]:
        ds: List[Directive] = []

        # Watchdog: continuous time in BLOCKED without reaching NORMAL.
        if self.cfg.watchdog_seconds > 0 and self._blocked_since is not None:
            if now - self._blocked_since >= self.cfg.watchdog_seconds:
                return [Alert("stopped: Kea/Unbound not ready within "
                              f"{self.cfg.watchdog_seconds / 60:.0f}m"),
                        Terminate("watchdog")]

        # A reconcile/drain is already running -> just wait (re-arm a wake so the
        # watchdog can still fire while we wait).
        if self._pending is not _Pending.NONE:
            return ds + [ScheduleWake(self._watchdog_wake(now))]

        if not all_present:
            # Waiting on a pid to (re)appear. Not a sync failure -> no backoff.
            self._reset_backoff()
            return ds + [ScheduleWake(self._watchdog_wake(now))]

        # All enabled pids present. Honour backoff between failed attempts.
        if now < self._next_attempt_at:
            return ds + [ScheduleWake(self._next_attempt_at - now)]

        # Fire a full reconcile.
        self._pending = _Pending.RECONCILE
        return ds + [Spawn("full", None)]

    def _after_reconcile(self, now: float, exit_code: int) -> List[Directive]:
        if exit_code != 0:
            # Fail-fast die: back off, then re-evaluate the pid level (don't
            # blind-retry). A pid event during the backoff preempts us anyway.
            self._bump_backoff(now)
            return [ScheduleWake(self._next_attempt_at - now)]

        # Success.
        if self.overflowed:
            self.overflowed = False
            self.dirty.clear()
            self.full_sync_counter += 1
            if self.full_sync_counter < self.cfg.max_full_sync_attempts:
                # Network still churning; read latest state again.
                self._pending = _Pending.RECONCILE
                return [Spawn("full", None)]
            # Degrade: best-effort live; periodic clean is the anti-entropy floor.
            self.degraded = True
            return self._go_normal() + [
                Alert("degraded: repeated overflow during recovery; "
                      "relying on periodic clean")]

        # Not overflowed: reset the counter and begin the drain loop.
        self.full_sync_counter = 0
        self._reset_backoff()
        return self._spawn_drain_or_normal()

    # ── drain (shared by BLOCKED-recovery and NORMAL) ──────────────────────────
    def _spawn_drain_or_normal(self) -> List[Directive]:
        """Snapshot+clear the unified dirty pool; spawn a targeted drain if
        non-empty, else transition to NORMAL. Escalates to a full reconcile if
        the pool overflowed the cap (_after_reconcile clears overflowed on success)."""
        if self.overflowed:
            self._pending = _Pending.RECONCILE
            return [Spawn("full", None)]
        snapshot = set(self.dirty)
        self.dirty.clear()
        if not snapshot:
            return self._go_normal()
        self._draining = snapshot
        self._pending = _Pending.DRAIN
        names = frozenset(e.value for e in snapshot if e.kind == "name")
        ips   = frozenset(e.value for e in snapshot if e.kind == "ip")
        return [Spawn("full", names if names else None, ips if ips else None)]

    def _after_drain(self, now: float, exit_code: int) -> List[Directive]:
        snapshot, self._draining = self._draining, set()
        if exit_code != 0:
            # Durability: a failed drain must NOT lose deferred names or IPs.
            self.dirty |= snapshot
            self._drain_fail_counter += 1
            if self._drain_fail_counter >= self.cfg.max_full_sync_attempts:
                self._drain_fail_counter = 0
                self.dirty.difference_update(snapshot)
                self.degraded = True
                return self._go_normal() + [
                    Alert("degraded: targeted drain failed repeatedly; "
                          "check Unbound config and logs")]
            self._bump_backoff(now)
            return [ScheduleWake(self._next_attempt_at - now)]
        # Drained successfully; loop on anything that accumulated meanwhile.
        self._drain_fail_counter = 0
        return self._spawn_drain_or_normal()

    # ── NORMAL ──────────────────────────────────────────────────────────────
    def _tick_normal(self, now: float, all_present: bool) -> List[Directive]:
        # NORMAL live path: successful NCRs applied directly; no reconcile.
        # Deferred NCRs (lock-contention, BLOCKED, UnboundRefused, unexpected)
        # call note_dirty_ncr(); the drain re-resolves by name from Kea.
        if self._pending is not _Pending.NONE:
            # A drain or fast-reload is already in flight — on_sync_exit drives next.
            return []
        if self.dirty:
            if now < self._next_attempt_at:
                return [ScheduleWake(self._next_attempt_at - now)]
            return self._spawn_drain_or_normal()
        # Emit FastReload only when NORMAL, idle (no subprocess, no dirty names).
        # Dirty names drain first so records are correct before the reload clears
        # them, and so we don't lose dirty tracking across the reload.
        if self.fast_reload_pending:
            self.fast_reload_pending = False
            self._pending = _Pending.FAST_RELOAD
            return [FastReload()]
        return []

    def _go_normal(self) -> List[Directive]:
        self.state = State.NORMAL
        self._blocked_since = None
        self._reset_backoff()
        if self.fast_reload_pending:
            # A reload is queued; schedule an immediate wake so _tick_normal
            # can emit FastReload() now that we're idle.
            return [ScheduleWake(0.0)]
        return []

    # ── helpers ───────────────────────────────────────────────────────────────
    def _all_present(self, pids: PidState) -> bool:
        return bool(pids) and all(exists for exists, _pid in pids.values())

    def _pid_level_changed(self, pids: PidState) -> bool:
        """True if any enabled pid went absent or changed value vs last sample,
        or the enabled set itself changed. First sample is not a 'change'."""
        if self._last_pids is None:
            return False
        if set(pids.keys()) != set(self._last_pids.keys()):
            return True
        for svc, (exists, pid) in pids.items():
            prev_exists, prev_pid = self._last_pids[svc]
            if exists != prev_exists or pid != prev_pid:
                return True
        return False

    def _on_pending_aborted(self) -> None:
        """A pending reconcile/drain was preempted by KillPending. If it was a
        drain, restore its snapshot so those entries aren't lost."""
        if self._pending is _Pending.DRAIN or self._draining:
            self.dirty |= self._draining
            self._draining = set()
        self._pending = _Pending.NONE

    def _reset_backoff(self) -> None:
        self._backoff = self.cfg.backoff_base
        self._next_attempt_at = 0.0

    def _bump_backoff(self, now: float) -> None:
        self._next_attempt_at = now + self._backoff
        self._backoff = min(self._backoff * self.cfg.backoff_factor,
                            self.cfg.backoff_cap)

    def _watchdog_wake(self, now: float) -> float:
        """Delay until we should re-check (small while waiting; bounded so the
        watchdog still fires)."""
        base = max(self._backoff, self.cfg.backoff_base)
        if self.cfg.watchdog_seconds > 0 and self._blocked_since is not None:
            remaining = self.cfg.watchdog_seconds - (now - self._blocked_since)
            return max(0.0, min(base, remaining))
        return base
