#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
sync-debounce.py -- Coalescing, readiness-gated resync worker.

WHY THIS EXISTS
  Kea-derived records live ONLY in Unbound's runtime local-data (added via
  unbound-control local_data); they are written to no file Unbound loads at
  startup. Every Unbound restart/reconfigure therefore FLUSHES them — and
  OPNsense reconfigures Unbound through many events (dns / local / newwanip /
  unbound_start / bootup). Firing a full reservation+lease resync synchronously
  on each of those is both wasteful (the boot pass alone fires several within a
  few seconds) and racy: a resync that runs while Kea or Unbound is still
  restarting comes back "errors=1, added=0" and repopulates nothing, leaving DNS
  empty until some unrelated event happens to resync later.

  This worker decouples "a resync was requested" from "actually resync":

    1. Coalesce      -- collapse a burst of requests into a single run.
                        Trailing-edge debounce keyed on the request-file mtime:
                        wait until requests stop arriving for QUIET seconds.
    2. Readiness gate -- do not sync until Kea AND Unbound are *stably* up. Poll
                        real health and require STABLE_FOR consecutive good
                        samples (with a growing-uptime / same-pid check on
                        Unbound) so a restart flap can't fool a single probe.
    3. Run requested  -- run only the sync types the requester asked for, read
                        from the request file. Policy (plugin enabled? which
                        sync types?) is resolved UPSTREAM in keaunbound.inc; this
                        worker reads no config.xml and owns no domain knowledge.
    4. Reactive re-arm -- if a sync still fails, back off and retry rather than
                        leaving DNS empty until the next unrelated event.

DESIGN NOTES
  * Single-instance is guaranteed by the flock(1) wrapper in keaunbound.inc
    (`flock -n -E 0 -o <lock>`); the internal fcntl guard here just makes the
    script safe to run by hand too.
  * The launcher fires this DETACHED (mwexecfb), so all waiting happens in the
    background — boot/reconfigure is never blocked.
  * "Where/how to reach Kea/Unbound" is NOT reimplemented here: Kea health uses
    the existing transport (kea_query → resolve_kea_connection), Unbound health
    uses unbound-control. The actual syncs are delegated to the existing
    reservation-sync.py / lease-sync.py. This file is pure orchestration.
  * A hard watchdog (SIGALRM) bounds total runtime so a wedged sync can never
    hold the flock indefinitely (flock auto-releases on death, but not on hang).
"""

import fcntl
import os
import re
import signal
import subprocess
import sys
import time

sys.path.insert(0, "/usr/local/opnsense/scripts/keaunbound")
from lib.keaunbound_sync import (  # noqa: E402
    setup_logging,
    kea_query,
    KeaUnavailableError,
    KeaServiceUnavailableError,
    UNBOUND_CONTROL,
    UNBOUND_CONF,
)

RUN_DIR = "/var/run/keaunbound"
REQUEST = os.path.join(RUN_DIR, "sync.request")
LOCK    = os.path.join(RUN_DIR, "sync.lock")

RESERVATION_SYNC = "/usr/local/opnsense/scripts/keaunbound/reservation-sync.py"
LEASE_SYNC       = "/usr/local/opnsense/scripts/keaunbound/lease-sync.py"
VALID_TYPES      = ("static", "dynamic")

# --- coalescing (trailing-edge debounce) ---
QUIET        = 5     # seconds of no new request before a burst is "settled"
MAX_COALESCE = 120   # cap so a relentless storm still eventually syncs

# --- readiness gate ---
STABLE_FOR     = 2     # consecutive healthy samples required (flap resistance)
PROBE_INTERVAL = 1.0   # seconds between health samples
MIN_UPTIME     = 3     # min Unbound uptime (s) — don't trust an instance at t~0
READY_DEADLINE = 90    # give up waiting for readiness after this long

# --- reactive re-arm ---
MAX_ATTEMPTS = 4    # total gate+sync attempts before giving up
BACKOFF_BASE = 5    # first retry delay (s); doubles each attempt
BACKOFF_MAX  = 60

# --- watchdog ---
WORKER_HARD_TIMEOUT = 600   # absolute cap on the worker's lifetime (s)


def _gen():
    """Request 'generation' = the request file's mtime. 0.0 if absent."""
    try:
        return os.stat(REQUEST).st_mtime
    except FileNotFoundError:
        return 0.0


def _read_types(logger):
    """Read the requested sync types from the request file (NOT from config.xml).

    The upstream PHP requester writes the enabled sync types ('static',
    'dynamic') it resolved from plugin policy. If the file is missing/empty
    (e.g. run by hand), default to both so a manual invocation does something
    useful — this is a convenience default, not a policy read.
    """
    try:
        with open(REQUEST) as f:
            types = [t for t in f.read().split() if t in VALID_TYPES]
        if types:
            return types
    except FileNotFoundError:
        pass
    logger.info("[debounce] no/empty request file — defaulting to all sync types")
    return list(VALID_TYPES)


def _coalesce(gen, logger):
    """Trailing-edge debounce: return once no new request has arrived for QUIET
    seconds (or MAX_COALESCE elapses). `gen` is the generation observed on entry."""
    start = time.monotonic()
    while time.monotonic() - start < MAX_COALESCE:
        time.sleep(QUIET)
        cur = _gen()
        if cur == gen:
            return gen           # quiet window — burst settled
        gen = cur                # new request arrived — extend the window
    logger.info("[debounce] coalesce cap (%ds) reached — proceeding", MAX_COALESCE)
    return gen


def _unbound_probe():
    """One Unbound health sample. Returns (ok, pid, uptime).

    ok=False means the control socket / process is not answering. pid and uptime
    come from `unbound-control status` and are used to detect a restart flap:
    a changing pid or a tiny uptime means the instance isn't the settled one."""
    try:
        r = subprocess.run([UNBOUND_CONTROL, "-c", UNBOUND_CONF, "status"],
                           capture_output=True, text=True, timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        return (False, None, None)
    if r.returncode != 0:
        return (False, None, None)
    pid = uptime = None
    m = re.search(r"\(pid (\d+)\) is running", r.stdout)
    if m:
        pid = int(m.group(1))
    m = re.search(r"^uptime:\s*(\d+)", r.stdout, re.M)
    if m:
        uptime = int(m.group(1))
    return (True, pid, uptime)


def _kea_probe(service):
    """One Kea health sample via the existing transport.
    Returns 'up' (responds), 'down' (not reachable yet), or 'disabled'
    (service deliberately off — not something to wait on)."""
    try:
        kea_query("version-get", service=service, timeout=3)
        return "up"
    except KeaServiceUnavailableError:
        return "disabled"
    except KeaUnavailableError:
        return "down"


def _wait_until_ready(logger):
    """Block until Unbound AND every enabled Kea service are *stably* healthy,
    or READY_DEADLINE elapses. Returns True if ready, False on deadline.

    Stability (not just a single OK) is the point: the boot sequence flaps
    Unbound (start→stop→start), so we require STABLE_FOR consecutive samples
    with the same Unbound pid and a non-trivial uptime, and no Kea service
    reporting 'down'. A 'disabled' Kea service is skipped, not waited on."""
    start = time.monotonic()
    streak = 0
    last_pid = None
    while time.monotonic() - start < READY_DEADLINE:
        ub_ok, pid, uptime = _unbound_probe()
        ub_stable = (ub_ok and uptime is not None and uptime >= MIN_UPTIME
                     and pid is not None and pid == last_pid)
        last_pid = pid

        kea_states = [_kea_probe(s) for s in ("dhcp4", "dhcp6")]
        kea_ok = ("down" not in kea_states) and ("up" in kea_states)

        if ub_stable and kea_ok:
            streak += 1
            if streak >= STABLE_FOR:
                return True
        else:
            streak = 0
        time.sleep(PROBE_INTERVAL)

    logger.warning("[debounce] readiness deadline (%ds) hit "
                   "(unbound pid=%s uptime=%s, kea=%s) — deferring resync",
                   READY_DEADLINE, last_pid, uptime, kea_states)
    return False


def _run_script(path, logger):
    """Run one sync script as a child process. Returns its exit code (0 = ok)."""
    try:
        r = subprocess.run([path], capture_output=True, text=True, timeout=120)
        if r.returncode != 0 and r.stderr.strip():
            logger.warning("[debounce] %s stderr: %s",
                           os.path.basename(path), r.stderr.strip().splitlines()[-1])
        return r.returncode
    except subprocess.TimeoutExpired:
        logger.error("[debounce] %s timed out", os.path.basename(path))
        return 1
    except OSError as e:
        logger.error("[debounce] %s failed to run: %s", os.path.basename(path), e)
        return 1


def _run_syncs(types, logger):
    """Run the requested sync scripts. Returns the list of types that failed."""
    failed = []
    if "static" in types and _run_script(RESERVATION_SYNC, logger) != 0:
        failed.append("static")
    if "dynamic" in types and _run_script(LEASE_SYNC, logger) != 0:
        failed.append("dynamic")
    return failed


def _on_alarm(signum, frame):
    raise SystemExit("[debounce] hard watchdog timeout — exiting")


def main():
    logger = setup_logging()

    os.makedirs(RUN_DIR, exist_ok=True)

    # Internal single-instance guard. The flock(1) wrapper in keaunbound.inc is
    # the primary one; this makes a hand-run safe and harmless if the wrapper is
    # bypassed. flock is released automatically when this fd closes (incl. crash).
    lockf = open(LOCK, "w")
    try:
        fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return 0   # another worker holds it — it will observe our request bump

    # Hard cap on lifetime so a wedged sync can't hold the lock forever.
    signal.signal(signal.SIGALRM, _on_alarm)
    signal.alarm(WORKER_HARD_TIMEOUT)

    attempt = 0
    gen = _gen()
    while True:
        # 1. Coalesce the burst.
        gen = _coalesce(gen, logger)
        types = _read_types(logger)

        # 2. Wait until Kea + Unbound are stably ready.
        ready = _wait_until_ready(logger)

        # 3. Run the requested syncs (only if ready; otherwise treat as failed).
        failed = _run_syncs(types, logger) if ready else list(types)

        # 4. Tail race: a request that arrived during the gate/sync starts a
        #    fresh, fully-coalesced cycle (and resets the retry budget).
        if _gen() != gen:
            gen = _gen()
            attempt = 0
            continue

        # 5. Success.
        if ready and not failed:
            logger.info("[debounce] resync complete (%s)", " ".join(types))
            break

        # 6. Failure → bounded exponential backoff, then re-gate and retry.
        attempt += 1
        if attempt >= MAX_ATTEMPTS:
            logger.error("[debounce] giving up after %d attempt(s) "
                         "(ready=%s failed=%s)", attempt, ready, failed or types)
            break
        backoff = min(BACKOFF_BASE * (2 ** (attempt - 1)), BACKOFF_MAX)
        logger.warning("[debounce] resync incomplete (ready=%s failed=%s) — "
                       "retry %d/%d in %ds", ready, failed or types,
                       attempt, MAX_ATTEMPTS - 1, backoff)
        time.sleep(backoff)

    return 0


if __name__ == "__main__":
    sys.exit(main())
