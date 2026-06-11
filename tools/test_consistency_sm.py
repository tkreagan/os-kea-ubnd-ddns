# SPDX-License-Identifier: BSD-2-Clause
"""
Unit tests for lib/consistency_sm.py -- the BLOCKED/NORMAL consistency state
machine. These run on macOS with no dev box, no kqueue, no real subprocesses:
the machine is a pure functional core (methods return Directives), so we drive
it with a fake clock and synthetic pid-stats and assert on state + directives.

Run:  python3 -m pytest tools/test_consistency_sm.py -v
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest

# Load the module directly from the plugin source tree (it normally lives at
# /usr/local/opnsense/scripts/keaunbound/lib/ on the box). Register it in
# sys.modules before exec so dataclass type introspection can resolve it.
_SM_PATH = (pathlib.Path(__file__).parents[1]
            / "src/opnsense/scripts/keaunbound/lib/consistency_sm.py")
_spec = importlib.util.spec_from_file_location("consistency_sm", _SM_PATH)
sm_mod = importlib.util.module_from_spec(_spec)
sys.modules["consistency_sm"] = sm_mod
_spec.loader.exec_module(sm_mod)

ConsistencySM = sm_mod.ConsistencySM
SMConfig = sm_mod.SMConfig
State = sm_mod.State
Spawn = sm_mod.Spawn
KillPending = sm_mod.KillPending
ScheduleWake = sm_mod.ScheduleWake
Terminate = sm_mod.Terminate
Alert = sm_mod.Alert


# ── helpers ───────────────────────────────────────────────────────────────
def up(*svcs, **pids):
    """Build a pid_state. up('unbound','dhcp4') -> all present with synthetic
    pids; up(unbound=False) -> unbound absent; up(dhcp4=123) -> explicit pid."""
    state = {}
    for s in svcs:
        state[s] = (True, hash(s) & 0xffff)
    for s, v in pids.items():
        if v is False:
            state[s] = (False, None)
        elif v is True:
            state[s] = (True, hash(s) & 0xffff)
        else:
            state[s] = (True, int(v))
    return state


def kinds(ds):
    return [type(d) for d in ds]


def first(ds, cls):
    for d in ds:
        if isinstance(d, cls):
            return d
    return None


ENABLED = ("unbound", "d2", "dhcp4")


def quiesce(sm, t=0.0):
    """Drive the machine from start to NORMAL with a healthy world. Returns the
    time after quiescing."""
    sm.start(t)
    healthy = up(*ENABLED)
    sm.on_wake(t, healthy)            # all present -> spawn full reconcile
    sm.on_sync_exit(t, 0)            # reconcile ok, no dirty -> NORMAL
    assert sm.state is State.NORMAL
    return t


# ── 1. quiesce baseline ─────────────────────────────────────────────────────
def test_quiesce_to_normal():
    sm = ConsistencySM()
    ds = sm.start(0.0)
    assert sm.state is State.BLOCKED
    assert any(isinstance(d, ScheduleWake) for d in ds)

    ds = sm.on_wake(0.0, up(*ENABLED))
    assert first(ds, Spawn) == Spawn("full", None)   # all present -> reconcile

    ds = sm.on_sync_exit(0.0, 0)                       # success, no dirty
    assert sm.state is State.NORMAL


def test_blocked_waits_for_all_pids():
    sm = ConsistencySM()
    sm.start(0.0)
    # d2 not up yet -> no reconcile spawned, just a wake.
    ds = sm.on_wake(0.0, up("unbound", "dhcp4", d2=False))
    assert first(ds, Spawn) is None
    assert any(isinstance(d, ScheduleWake) for d in ds)
    assert sm.state is State.BLOCKED


# ── 2. single flap ──────────────────────────────────────────────────────────
def test_single_flap_recovers():
    sm = ConsistencySM()
    quiesce(sm)
    # unbound disappears.
    ds = sm.on_wake(1.0, up("d2", "dhcp4", unbound=False))
    assert sm.state is State.BLOCKED
    assert first(ds, Spawn) is None          # not all present
    # unbound returns with a new pid.
    ds = sm.on_wake(2.0, up(*ENABLED))
    assert first(ds, Spawn) == Spawn("full", None)
    sm.on_sync_exit(2.0, 0)
    assert sm.state is State.NORMAL


# ── 3. fast-flap (the 1 Hz-poll-miss case) ──────────────────────────────────
def test_fast_flap_changed_pid_blocks():
    sm = ConsistencySM()
    quiesce(sm)
    healthy = up(*ENABLED)
    sm.on_wake(1.0, healthy)                 # confirm NORMAL, record level
    assert sm.state is State.NORMAL
    # We NEVER saw 'absent', but dhcp4's pid changed -> down+up happened.
    flipped = dict(healthy)
    flipped["dhcp4"] = (True, flipped["dhcp4"][1] + 1)
    ds = sm.on_wake(1.5, flipped)
    assert sm.state is State.BLOCKED         # caught despite no absent sample
    assert first(ds, Spawn) == Spawn("full", None)  # all present -> reconcile


# ── 4. reconcile fails, then pid flaps mid-backoff ──────────────────────────
def test_reconcile_fail_backoff_then_flap():
    sm = ConsistencySM(SMConfig(backoff_base=0.25, backoff_factor=2.0))
    sm.start(0.0)
    sm.on_wake(0.0, up(*ENABLED))            # spawn reconcile
    ds = sm.on_sync_exit(0.0, 1)             # FAIL -> backoff
    wake = first(ds, ScheduleWake)
    assert wake is not None and wake.delay == pytest.approx(0.25)
    assert sm.state is State.BLOCKED

    # During backoff a pid drops -> stay BLOCKED, no blind retry, backoff reset.
    ds = sm.on_wake(0.1, up("d2", "dhcp4", unbound=False))
    assert sm.state is State.BLOCKED
    assert first(ds, Spawn) is None
    # Recovers cleanly.
    sm.on_wake(0.2, up(*ENABLED))
    sm.on_sync_exit(0.2, 0)
    assert sm.state is State.NORMAL


def test_backoff_grows_and_caps():
    sm = ConsistencySM(SMConfig(backoff_base=1.0, backoff_factor=2.0,
                                backoff_cap=4.0))
    sm.start(0.0)
    delays = []
    t = 0.0
    for _ in range(5):
        sm.on_wake(t, up(*ENABLED))          # honours backoff; spawns when due
        # force "due" by advancing past next_attempt_at
        ds = sm.on_sync_exit(t, 1)
        delays.append(first(ds, ScheduleWake).delay)
        t += 100  # jump past backoff so the next on_wake spawns immediately
        sm.on_wake(t, up(*ENABLED))
    assert delays[0] == pytest.approx(1.0)
    assert delays[1] == pytest.approx(2.0)
    assert delays[2] == pytest.approx(4.0)
    assert delays[3] == pytest.approx(4.0)   # capped


# ── 5. overflow loop + degrade ──────────────────────────────────────────────
def test_overflow_loop_then_degrade():
    sm = ConsistencySM(SMConfig(max_full_sync_attempts=3, dirty_cap=5))
    sm.start(0.0)
    sm.on_wake(0.0, up(*ENABLED))            # spawn reconcile #1
    # reconcile reports overflow each time -> loop, counter increments.
    ds = sm.on_sync_exit(0.0, 0, overflowed=True)   # #1 -> counter 1, respawn
    assert first(ds, Spawn) == Spawn("full", None)
    ds = sm.on_sync_exit(0.0, 0, overflowed=True)   # #2 -> counter 2, respawn
    assert first(ds, Spawn) == Spawn("full", None)
    ds = sm.on_sync_exit(0.0, 0, overflowed=True)   # #3 -> counter hits max
    assert sm.state is State.NORMAL
    assert sm.degraded
    assert first(ds, Alert) is not None


def test_overflow_counter_resets_on_pid_transition():
    sm = ConsistencySM(SMConfig(max_full_sync_attempts=3))
    sm.start(0.0)
    sm.on_wake(0.0, up(*ENABLED))
    sm.on_sync_exit(0.0, 0, overflowed=True)        # counter 1
    sm.on_sync_exit(0.0, 0, overflowed=True)        # counter 2
    assert sm.full_sync_counter == 2
    # A fresh restart deserves fresh attempts.
    sm.on_wake(1.0, up("d2", "dhcp4", unbound=False))
    assert sm.full_sync_counter == 0


# ── 6. watchdog ──────────────────────────────────────────────────────────────
def test_watchdog_terminates():
    sm = ConsistencySM(SMConfig(watchdog_seconds=600))
    sm.start(0.0)
    # Stuck: a pid never comes back.
    sm.on_wake(0.0, up("d2", "dhcp4", unbound=False))
    ds = sm.on_wake(600.0, up("d2", "dhcp4", unbound=False))
    assert first(ds, Terminate) is not None
    assert first(ds, Alert) is not None


def test_watchdog_zero_never_trips():
    sm = ConsistencySM(SMConfig(watchdog_seconds=0))
    sm.start(0.0)
    sm.on_wake(0.0, up("d2", "dhcp4", unbound=False))
    ds = sm.on_wake(10_000.0, up("d2", "dhcp4", unbound=False))
    assert first(ds, Terminate) is None


def test_watchdog_resets_on_recovery():
    sm = ConsistencySM(SMConfig(watchdog_seconds=600))
    sm.start(0.0)
    sm.on_wake(0.0, up("d2", "dhcp4", unbound=False))
    sm.on_wake(300.0, up(*ENABLED))          # recover at t=300
    sm.on_sync_exit(300.0, 0)
    assert sm.state is State.NORMAL
    # New flap; watchdog clock restarts from the flap, not from t=0.
    sm.on_wake(400.0, up("d2", "dhcp4", unbound=False))
    ds = sm.on_wake(900.0, up("d2", "dhcp4", unbound=False))  # 500s < 600
    assert first(ds, Terminate) is None
    ds = sm.on_wake(1001.0, up("d2", "dhcp4", unbound=False))  # 601s >= 600
    assert first(ds, Terminate) is not None


# ── 7. drain after recovery ──────────────────────────────────────────────────
def test_recovery_drains_dirty_then_normal():
    sm = ConsistencySM()
    sm.start(0.0)
    # Packets arrived while BLOCKED -> dirty.
    sm.note_dirty(["a.example", "b.example"])
    sm.on_wake(0.0, up(*ENABLED))            # spawn reconcile
    ds = sm.on_sync_exit(0.0, 0)             # success, dirty present -> drain
    drain = first(ds, Spawn)
    assert drain.names == frozenset({"a.example", "b.example"})
    assert sm.state is State.BLOCKED         # still BLOCKED during drain
    # Drain succeeds, nothing new accumulated -> NORMAL.
    ds = sm.on_sync_exit(0.0, 0)
    assert sm.state is State.NORMAL


def test_drain_loops_until_empty():
    sm = ConsistencySM()
    sm.start(0.0)
    sm.note_dirty(["a"])
    sm.on_wake(0.0, up(*ENABLED))
    sm.on_sync_exit(0.0, 0)                   # -> drain {a}
    sm.note_dirty(["b"])                      # arrived during drain
    ds = sm.on_sync_exit(0.0, 0)             # drain {a} done -> drain {b}
    assert first(ds, Spawn).names == frozenset({"b"})
    ds = sm.on_sync_exit(0.0, 0)             # drain {b} done -> NORMAL
    assert sm.state is State.NORMAL


def test_drain_failure_readds_names():
    sm = ConsistencySM()
    sm.start(0.0)
    sm.note_dirty(["keepme"])
    sm.on_wake(0.0, up(*ENABLED))
    sm.on_sync_exit(0.0, 0)                   # -> drain {keepme}, dirty cleared
    assert sm.dirty == set()
    ds = sm.on_sync_exit(0.0, 1)             # drain FAILS
    assert "keepme" in sm.dirty              # durability: name not lost
    assert any(isinstance(d, ScheduleWake) for d in ds)
    assert sm.state is State.BLOCKED


# ── 8. NORMAL dirty drain: lock-contention misses are re-resolved on next wake ──
def test_normal_idle_wake_spawns_nothing():
    sm = ConsistencySM()
    quiesce(sm)
    # No lock misses: every live apply succeeded. Timer wakes produce no spawns.
    for t in (1.0, 2.0, 3.0):
        ds = sm.on_wake(t, up(*ENABLED))
        assert first(ds, Spawn) is None
        assert sm.state is State.NORMAL


def test_lock_contention_normal_drains_on_wake():
    sm = ConsistencySM()
    quiesce(sm)
    # Daemon lost the advisory lock on a live apply -> note_dirty; state unchanged.
    sm.note_dirty(["missed.example"])
    assert sm.state is State.NORMAL
    # Next timer/vnode wake sees dirty and spawns a targeted drain.
    ds = sm.on_wake(1.0, up(*ENABLED))
    assert sm.state is State.NORMAL            # still NORMAL; drain ≠ restart
    drain = first(ds, Spawn)
    assert drain is not None
    assert drain.names == frozenset({"missed.example"})
    # Drain succeeds, nothing new accumulated -> stay NORMAL.
    ds = sm.on_sync_exit(1.0, 0)
    assert sm.state is State.NORMAL
    assert first(ds, Spawn) is None


def test_lock_contention_drain_failure_readds_names():
    sm = ConsistencySM()
    quiesce(sm)
    sm.note_dirty(["missed.example"])
    sm.on_wake(1.0, up(*ENABLED))              # spawn drain
    assert sm.dirty == set()                   # snapshot moved to _draining
    ds = sm.on_sync_exit(1.0, 1)              # drain FAILS
    assert "missed.example" in sm.dirty        # durability: not lost
    assert sm.state is State.NORMAL            # stays NORMAL; failure ≠ restart


def test_apply_failure_unbound_down_enters_blocked_and_drains():
    sm = ConsistencySM()
    quiesce(sm)
    # A live apply hit connection-refused (Unbound down) -> BLOCKED + dirty.
    ds = sm.on_apply_failure(5.0, ["host.example"])
    assert sm.state is State.BLOCKED
    assert "host.example" in sm.dirty
    assert any(isinstance(d, ScheduleWake) for d in ds)
    # Unbound's pid cycles; recovery drains the deferred name.
    sm.on_wake(6.0, up("d2", "dhcp4", unbound=False))   # confirm down
    sm.on_wake(7.0, up(*ENABLED))                        # back -> reconcile
    ds = sm.on_sync_exit(7.0, 0)                         # ok -> drain
    assert first(ds, Spawn).names == frozenset({"host.example"})
    sm.on_sync_exit(7.0, 0)                              # drain ok -> NORMAL
    assert sm.state is State.NORMAL


# ── 9. preempting an in-flight reconcile on a flap ──────────────────────────
def test_flap_during_reconcile_kills_pending():
    sm = ConsistencySM()
    sm.start(0.0)
    sm.on_wake(0.0, up(*ENABLED))            # reconcile running
    ds = sm.on_wake(0.5, up("d2", "dhcp4", unbound=False))  # pid drops
    assert first(ds, KillPending) is not None
    assert sm.state is State.BLOCKED
    # A late exit from the killed child is ignored (no crash, no spurious spawn).
    ds = sm.on_sync_exit(0.6, 0)
    assert first(ds, Spawn) is None


def test_flap_during_recovery_drain_preserves_names():
    sm = ConsistencySM()
    sm.start(0.0)
    sm.note_dirty(["x"])                      # deferred while BLOCKED
    sm.on_wake(0.0, up(*ENABLED))            # reconcile
    sm.on_sync_exit(0.0, 0)                   # ok -> drain {x} running
    assert sm._draining == {"x"}
    ds = sm.on_wake(1.0, up("d2", "dhcp4", unbound=False))  # flap mid-drain
    assert first(ds, KillPending) is not None
    assert "x" in sm.dirty                   # snapshot restored, not lost
    assert sm.state is State.BLOCKED
