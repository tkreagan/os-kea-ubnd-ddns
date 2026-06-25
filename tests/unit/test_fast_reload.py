# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
Unit tests for fast-reload.py and the Daemon mutation counter.

fast-reload.py architecture (dump-restore):
  Under the mutation lock:
    1. list_local_data  -- snapshot all current records
    2. unbound-control <reload_command>  -- clear heap
    3. local_datas  -- restore snapshot atomically (records passed as stdin)

  No post-reload sync, no retry loop, no subprocess to run-sync.py.
  reload_command comes from keaubnd_runtime.get_fast_reload_command()
  (currently hardcoded to "reload" in start.py pending upstream fix).

Daemon counter tests verify the mutation counter increments on NOERROR NCRs,
triggers fast_reload_pending at the threshold, and resets correctly.
"""

from __future__ import annotations

import unittest.mock as mock

import pytest

from .conftest import load_script

pytestmark = pytest.mark.unit

fast_reload_mod = load_script("fast-reload.py")


# ── helpers ───────────────────────────────────────────────────────────────────

_CONTROL = "/usr/local/sbin/unbound-control"
_CONF    = "/var/unbound/unbound.conf"

SAMPLE_RECORDS = (
    "host1.lan. 300 IN A 192.168.1.10\n"
    "10.1.168.192.in-addr.arpa. 300 IN PTR host1.lan.\n"
    "host2.lan. 300 IN A 192.168.1.20\n"
)


def _rt_patches(reload_cmd="reload"):
    """Return a context-manager stack that stubs all _rt calls."""
    return mock.patch.multiple(
        "lib.keaubnd_runtime",
        get_unbound_control=mock.Mock(return_value=_CONTROL),
        get_unbound_conf=mock.Mock(return_value=_CONF),
        get_fast_reload_command=mock.Mock(return_value=reload_cmd),
    )


def _make_args(dry_run=False, verbose=False, config=None):
    a = mock.MagicMock()
    a.dry_run = dry_run
    a.verbose = verbose
    a.config = config
    return a


def _drive_main(run_side_effect, reload_cmd="reload",
                dry_run=False) -> tuple[int, list]:
    """
    Drive fast_reload_mod.main() with mocked subprocess.run.

    run_side_effect: list of subprocess.run return-value mocks, consumed in order.
    Returns (exit_code, list_of_called_cmds).
    """
    called_cmds = []
    responses = iter(run_side_effect)

    def fake_run(full_cmd, **kwargs):
        called_cmds.append(full_cmd[3:])  # strip [control, "-c", conf]
        return next(responses)

    lock_cm = mock.MagicMock()
    lock_cm.__enter__ = mock.Mock(return_value=None)
    lock_cm.__exit__ = mock.Mock(return_value=False)

    with _rt_patches(reload_cmd=reload_cmd), \
         mock.patch("subprocess.run", side_effect=fake_run), \
         mock.patch.object(fast_reload_mod, "unbound_mutation_lock",
                           return_value=lock_cm), \
         mock.patch.object(fast_reload_mod, "parse_args",
                           return_value=_make_args(dry_run=dry_run)):
        try:
            fast_reload_mod.main()
            return 0, called_cmds
        except SystemExit as e:
            return (e.code or 0), called_cmds


def _ok(stdout=""):
    r = mock.Mock()
    r.returncode = 0
    r.stdout = stdout
    r.stderr = ""
    return r


def _fail(stderr="unbound error"):
    r = mock.Mock()
    r.returncode = 1
    r.stdout = ""
    r.stderr = stderr
    return r


# ── fast-reload.py: success path ─────────────────────────────────────────────

class TestFastReloadSuccess:
    def test_calls_list_then_reload_then_local_datas(self):
        rc, cmds = _drive_main([
            _ok(SAMPLE_RECORDS),   # list_local_data
            _ok(),                 # reload
            _ok(),                 # local_datas
        ])
        assert rc == 0
        assert cmds[0] == ["list_local_data"]
        assert cmds[1] == ["reload"]
        assert cmds[2][:1] == ["local_datas"]

    def test_uses_reload_command_from_runtime(self):
        """reload_command is read from keaubnd_runtime; currently 'reload'."""
        rc, cmds = _drive_main([_ok(SAMPLE_RECORDS), _ok(), _ok()],
                               reload_cmd="reload")
        assert cmds[1] == ["reload"]

    def test_uses_fast_reload_command_when_configured(self):
        """If runtime returns 'fast-reload', that subcommand is used."""
        rc, cmds = _drive_main([_ok(SAMPLE_RECORDS), _ok(), _ok()],
                               reload_cmd="fast-reload")
        assert cmds[1] == ["fast-reload"]

    def test_restored_records_passed_as_stdin(self):
        """The dumped records must be sent as stdin to local_datas."""
        stdin_received = []

        def fake_run(full_cmd, **kwargs):
            if full_cmd[3:4] == ["local_datas"]:
                stdin_received.append(kwargs.get("input", ""))
            r = mock.Mock()
            r.returncode = 0
            r.stdout = SAMPLE_RECORDS if full_cmd[3:4] == ["list_local_data"] else ""
            r.stderr = ""
            return r

        lock_cm = mock.MagicMock()
        lock_cm.__enter__ = mock.Mock(return_value=None)
        lock_cm.__exit__ = mock.Mock(return_value=False)

        with _rt_patches(), \
             mock.patch("subprocess.run", side_effect=fake_run), \
             mock.patch.object(fast_reload_mod, "unbound_mutation_lock",
                               return_value=lock_cm), \
             mock.patch.object(fast_reload_mod, "parse_args",
                               return_value=_make_args()):
            fast_reload_mod.main()

        assert stdin_received, "local_datas was never called with stdin"
        assert stdin_received[0] == SAMPLE_RECORDS

    def test_empty_unbound_succeeds(self):
        """Zero records (fresh Unbound) is not an error."""
        rc, cmds = _drive_main([_ok(""), _ok(), _ok()])
        assert rc == 0

    def test_exactly_three_subprocess_calls(self):
        rc, cmds = _drive_main([_ok(SAMPLE_RECORDS), _ok(), _ok()])
        assert len(cmds) == 3

    def test_all_three_ops_run_inside_lock(self):
        """All three uc() calls must happen between lock __enter__ and __exit__."""
        call_order = []

        lock_cm = mock.MagicMock()
        lock_cm.__enter__ = mock.Mock(side_effect=lambda: call_order.append("LOCK"))
        lock_cm.__exit__ = mock.Mock(side_effect=lambda *a: call_order.append("UNLOCK"))

        def fake_run(full_cmd, **kwargs):
            call_order.append(full_cmd[3])
            r = mock.Mock()
            r.returncode = 0
            r.stdout = SAMPLE_RECORDS if full_cmd[3] == "list_local_data" else ""
            r.stderr = ""
            return r

        with _rt_patches(), \
             mock.patch("subprocess.run", side_effect=fake_run), \
             mock.patch.object(fast_reload_mod, "unbound_mutation_lock",
                               return_value=lock_cm), \
             mock.patch.object(fast_reload_mod, "parse_args",
                               return_value=_make_args()):
            fast_reload_mod.main()

        lock_idx  = call_order.index("LOCK")
        unlock_idx = call_order.index("UNLOCK")
        for op in ("list_local_data", "reload", "local_datas"):
            idx = call_order.index(op)
            assert lock_idx < idx < unlock_idx, \
                f"{op} must run between LOCK and UNLOCK; order={call_order}"


# ── fast-reload.py: failure paths ────────────────────────────────────────────

class TestFastReloadFailure:
    def test_list_local_data_failure_exits_nonzero(self):
        rc, cmds = _drive_main([_fail()])
        assert rc == 1

    def test_reload_failure_exits_nonzero(self):
        rc, cmds = _drive_main([_ok(SAMPLE_RECORDS), _fail()])
        assert rc == 1

    def test_local_datas_failure_exits_nonzero(self):
        rc, cmds = _drive_main([_ok(SAMPLE_RECORDS), _ok(), _fail()])
        assert rc == 1

    def test_reload_failure_stops_before_local_datas(self):
        """If reload fails, local_datas must NOT be called (Unbound state unknown)."""
        rc, cmds = _drive_main([_ok(SAMPLE_RECORDS), _fail()])
        assert not any(c[:1] == ["local_datas"] for c in cmds), \
            "local_datas must not run after a failed reload"

    def test_list_failure_stops_before_reload(self):
        rc, cmds = _drive_main([_fail()])
        assert len(cmds) == 1


# ── fast-reload.py: dry-run mode ─────────────────────────────────────────────

class TestFastReloadDryRun:
    def test_dry_run_no_subprocess_calls(self):
        """--dry-run must not invoke subprocess.run at all."""
        with _rt_patches(), \
             mock.patch("subprocess.run") as mock_run, \
             mock.patch.object(fast_reload_mod, "unbound_mutation_lock",
                               return_value=mock.MagicMock(
                                   __enter__=mock.Mock(return_value=None),
                                   __exit__=mock.Mock(return_value=False))), \
             mock.patch.object(fast_reload_mod, "parse_args",
                               return_value=_make_args(dry_run=True)):
            fast_reload_mod.main()
        mock_run.assert_not_called()

    def test_dry_run_exits_zero(self):
        with _rt_patches(), \
             mock.patch("subprocess.run"), \
             mock.patch.object(fast_reload_mod, "unbound_mutation_lock",
                               return_value=mock.MagicMock(
                                   __enter__=mock.Mock(return_value=None),
                                   __exit__=mock.Mock(return_value=False))), \
             mock.patch.object(fast_reload_mod, "parse_args",
                               return_value=_make_args(dry_run=True)):
            try:
                fast_reload_mod.main()
                rc = 0
            except SystemExit as e:
                rc = e.code
        assert rc == 0


# ── Daemon mutation counter ───────────────────────────────────────────────────

daemon = load_script("kea-ubnd-ddns.py")
import lib.keaubnd_runtime as _rt_mod  # noqa: E402 (loaded after path setup)


class TestMutationCounter:
    """Verify counter increments on NOERROR and triggers fast_reload_pending."""

    def _make_daemon(self, threshold: int = 5):
        args = mock.MagicMock()
        args.fast_reload_threshold = threshold
        args.dirty_cap = None
        args.max_full_sync_attempts = None
        args.readiness_watchdog_minutes = None
        args.tsig_key = None
        args.tsig_algorithm = "HMAC-SHA256"
        args.no_synthesize_ptr = False
        args.collision_policy = "last_wins"
        args.magic_names = False
        args.laa_tag = False
        args.write_magic_ptrs = False
        args.clean_on_restart = False
        args.dry_run = False
        args.verbose = False
        args.unbound_conf = "/var/unbound/unbound.conf"
        args.host_entries = None
        args.port = 53535

        with mock.patch("lib.keaubnd_runtime.load", return_value={
            "unbound": {"control": "/usr/local/sbin/unbound-control",
                        "conf": "/var/unbound/unbound.conf",
                        "host-entries": "/var/unbound/host_entries.conf",
                        "pid": "/var/run/unbound.pid"},
            "kea": {},
            "fast-reload": {},
        }), mock.patch("lib.pid_watch.PidWatcher"):
            d = daemon.Daemon.__new__(daemon.Daemon)
            d.args = args
            d.log = mock.MagicMock()
            d.keyring = None
            d.synthesize_ptr = True
            d.collision_policy = "last_wins"
            d.unbound_conf = "/var/unbound/unbound.conf"
            d.cache = mock.MagicMock()
            d.cache.is_static.return_value = False
            import lib.consistency_sm as csm
            d.sm = csm.ConsistencySM(csm.SMConfig())
            d._fast_reload_threshold = max(0, threshold)
            d._mutation_count = 0
            d.child = None
            d._child_label = "kea-sync"
            d._child_overflow = False
            d.sock = mock.MagicMock()
            d.kq = mock.MagicMock()
            d.watcher = mock.MagicMock()
        return d

    def test_counter_increments_on_noerror(self):
        d = self._make_daemon(threshold=10)
        d.sm.state = __import__("lib.consistency_sm", fromlist=["State"]).State.NORMAL

        with mock.patch.object(daemon, "process_update",
                               return_value=__import__(
                                   "dns.rcode", fromlist=["NOERROR"]).NOERROR), \
             mock.patch.object(daemon, "unbound_mutation_lock",
                               return_value=mock.MagicMock(
                                   __enter__=mock.Mock(return_value=None),
                                   __exit__=mock.Mock(return_value=False))):
            msg = mock.MagicMock()
            msg.flags = 0
            msg.had_tsig = False
            d._apply_or_defer(msg)

        assert d._mutation_count == 1
        assert not d.sm.fast_reload_pending

    def test_threshold_triggers_pending(self):
        d = self._make_daemon(threshold=3)
        d.sm.state = __import__("lib.consistency_sm", fromlist=["State"]).State.NORMAL
        import dns.rcode

        with mock.patch.object(daemon, "process_update",
                               return_value=dns.rcode.NOERROR), \
             mock.patch.object(daemon, "unbound_mutation_lock",
                               return_value=mock.MagicMock(
                                   __enter__=mock.Mock(return_value=None),
                                   __exit__=mock.Mock(return_value=False))), \
             mock.patch.object(d, "_arm_timer"):
            msg = mock.MagicMock()
            msg.flags = 0
            msg.had_tsig = False
            d._apply_or_defer(msg)
            d._apply_or_defer(msg)
            assert not d.sm.fast_reload_pending
            assert d._mutation_count == 2
            d._apply_or_defer(msg)

        assert d.sm.fast_reload_pending is True
        assert d._mutation_count == 0

    def test_threshold_zero_never_triggers(self):
        d = self._make_daemon(threshold=0)
        d.sm.state = __import__("lib.consistency_sm", fromlist=["State"]).State.NORMAL
        import dns.rcode

        with mock.patch.object(daemon, "process_update",
                               return_value=dns.rcode.NOERROR), \
             mock.patch.object(daemon, "unbound_mutation_lock",
                               return_value=mock.MagicMock(
                                   __enter__=mock.Mock(return_value=None),
                                   __exit__=mock.Mock(return_value=False))), \
             mock.patch.object(d, "_arm_timer"):
            msg = mock.MagicMock()
            msg.flags = 0
            msg.had_tsig = False
            for _ in range(100):
                d._apply_or_defer(msg)

        assert not d.sm.fast_reload_pending
        assert d._mutation_count == 0

    def test_servfail_does_not_increment(self):
        """SERVFAIL responses must not count toward the fast-reload threshold."""
        d = self._make_daemon(threshold=3)
        d.sm.state = __import__("lib.consistency_sm", fromlist=["State"]).State.NORMAL
        import dns.rcode

        with mock.patch.object(daemon, "process_update",
                               return_value=dns.rcode.SERVFAIL), \
             mock.patch.object(daemon, "unbound_mutation_lock",
                               return_value=mock.MagicMock(
                                   __enter__=mock.Mock(return_value=None),
                                   __exit__=mock.Mock(return_value=False))):
            msg = mock.MagicMock()
            msg.flags = 0
            msg.had_tsig = False
            d._apply_or_defer(msg)

        assert d._mutation_count == 0
        assert not d.sm.fast_reload_pending


# ── SM on_sync_exit — FAST_RELOAD path ───────────────────────────────────────

import lib.consistency_sm as _csm  # noqa: E402


class TestFastReloadSMExit:
    """Verify the SM's on_sync_exit behavior for the FAST_RELOAD pending state."""

    def _make_sm(self):
        sm = _csm.ConsistencySM(_csm.SMConfig())
        sm.state = _csm.State.NORMAL
        sm._pending = _csm._Pending.FAST_RELOAD
        sm.dirty = {_csm._DirtyEntry("name", "host.lan")}
        return sm

    def test_fast_reload_exit_success_no_dirty_returns_empty(self):
        """Success with no accumulated dirty names → no drain needed."""
        sm = self._make_sm()
        sm.dirty = set()
        ds = sm.on_sync_exit(now=0.0, exit_code=0)
        assert ds == []
        assert sm.state is _csm.State.NORMAL

    def test_fast_reload_exit_success_with_dirty_spawns_drain(self):
        """Success with dirty names accumulated during fast-reload → drain issued."""
        sm = self._make_sm()
        ds = sm.on_sync_exit(now=0.0, exit_code=0)
        assert len(ds) == 1
        assert isinstance(ds[0], _csm.Spawn)
        assert ds[0].names == frozenset({"host.lan"})

    def test_fast_reload_exit_failure_spawns_full_reconcile(self):
        sm = self._make_sm()
        ds = sm.on_sync_exit(now=0.0, exit_code=1)
        assert len(ds) == 1
        assert isinstance(ds[0], _csm.Spawn)
        assert ds[0].mode == "full"
        assert ds[0].names is None

    def test_fast_reload_failure_sets_pending_reconcile(self):
        sm = self._make_sm()
        sm.on_sync_exit(now=0.0, exit_code=1)
        assert sm._pending is _csm._Pending.RECONCILE

    def test_fast_reload_failure_stays_normal(self):
        sm = self._make_sm()
        sm.on_sync_exit(now=0.0, exit_code=1)
        assert sm.state is _csm.State.NORMAL

    def test_fast_reload_failure_preserves_dirty(self):
        """dirty names must survive so _after_reconcile can clear on success."""
        sm = self._make_sm()
        sm.on_sync_exit(now=0.0, exit_code=1)
        assert any(e.value == "host.lan" for e in sm.dirty)
