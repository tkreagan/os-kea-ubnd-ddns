#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
kea-unbound-ddns.py — resident consistency daemon for Kea → Unbound DNS.

Listens on 127.0.0.1:53535 (UDP) for DNS UPDATE packets from kea-dhcp-ddns and
applies them to Unbound's runtime local_data, AND owns end-to-end consistency:
Kea-derived records live only in Unbound's runtime store and are flushed on every
Unbound restart, so the daemon watches the enabled service pidfiles and re-syncs
from Kea whenever one restarts.

── Architecture (see int-docs/resident-daemon-design.md + -implementation-plan) ──
A single-threaded select.kqueue() event loop multiplexes four sources:
  * EVFILT_READ  on the UDP socket  — live NCRs (drained to EWOULDBLOCK each wake)
  * EVFILT_VNODE on pidfiles + dirs — service restart detection (lib/pid_watch)
  * EVFILT_TIMER                    — backoff / watchdog / dirty-drain wakes
  * EVFILT_PROC  NOTE_EXIT          — the kea-sync reconcile subprocess finishing

All control logic lives in lib/consistency_sm.ConsistencySM (pure, unit-tested).
The loop feeds it level-read pid state and subprocess exits; it returns Directives
(Spawn / KillPending / ScheduleWake / Terminate / Alert) the loop executes.

Two states:
  NORMAL   — live NCRs apply straight to Unbound under the shared mutation lock.
  BLOCKED  — a watched service restarted (pid absent/changed); live applies are
             deferred (ACK-fail + the name is recorded dirty) until a reconcile
             repopulates Unbound, then the dirty names are drained.

The live path takes the shared Unbound-mutation lock NON-BLOCKING: if a reconcile
or external clean/sync holds it, the apply ACK-fails and records the name dirty
to re-resolve later — it never blocks the ACK budget. Reconciles run as
kea-sync.py subprocesses that hold the lock blocking for their whole run.

── Live ADD/DELETE handling ──────────────────────────────────────────────────
ADD A/AAAA: register forward + synthesized PTR; apply the collision policy inline
  (allow=additive, first_wins=reject a different IP, last_wins=replace). The
  inline last_wins replace subsumes the old --aggressive-cleanup (a host getting a
  new IP IS a same-FQDN collision), so there is no post-ADD cleanup subprocess.
DELETE A/AAAA: dual-stack preserve (local_data_remove wipes ALL types for a name),
  remove forward + PTR(s), restore the surviving family.

── Static guard ──────────────────────────────────────────────────────────────
host_entries.conf (OPNsense host overrides + regdhcpstatic) is OPNsense-owned;
we never touch any name in it. It is cached in memory and re-read on BLOCKED→
NORMAL. Spike V3 proved host_entries.conf can only change as part of an Unbound
stop→start (its sole writer runs inside unbound_generate_config, reached only
after unbound_service_stop), so every change is accompanied by a pid cycle the
daemon catches — the cache is always refreshed before live applies resume.

── Lifecycle ─────────────────────────────────────────────────────────────────
Launched by start.py via daemon(8) -r (respawn) -R 5. Stop/restart signal the
supervisor via stop.py. The readiness watchdog (Terminate directive) does a clean
full-plugin stop when Kea/Unbound never become ready.

Usage:
    kea-unbound-ddns.py [--port PORT] [--unbound-conf FILE] [--host-entries FILE]
                        [--tsig-key NAME:SECRET] [--tsig-algorithm ALGO]
                        [--no-synthesize-ptr] [--dry-run] [--verbose]
"""

from __future__ import annotations

import argparse
import errno
import ipaddress
import logging
import os
import re
import select
import signal
import socket
import subprocess
import sys
import time

_DNSPYTHON_MIN = (2, 8)

try:
    import dns.message
    import dns.exception
    import dns.name
    import dns.opcode
    import dns.rcode
    import dns.rdataclass
    import dns.rdatatype
    import dns.tsig
    import dns.tsigkeyring
    import dns.version
    _ver = tuple(int(x) for x in dns.version.version.split(".")[:2])
    if _ver < _DNSPYTHON_MIN:
        print(
            f"ERROR: dnspython {dns.version.version} is too old — "
            f"{_DNSPYTHON_MIN[0]}.{_DNSPYTHON_MIN[1]}+ required. "
            f"Upgrade with: pkg upgrade py{sys.version_info.major}{sys.version_info.minor}-dnspython",
            file=sys.stderr
        )
        sys.exit(1)
except ImportError:
    print(
        "ERROR: dnspython is not installed. "
        f"Install with: pkg install py{sys.version_info.major}{sys.version_info.minor}-dnspython",
        file=sys.stderr
    )
    sys.exit(1)

# Shared library: logging, host_entries parser, the mutation lock, the pure state
# machine, and the pid-watch level read. The plugin installs all halves together.
sys.path.insert(0, "/usr/local/opnsense/scripts/keaunbound")
from lib.keaunbound_sync import (  # noqa: E402
    _arpa_to_ip, setup_logging, get_collision_policy,
    read_host_entries, unbound_mutation_lock, MUTATION_LOCK_PATH,
)
from lib import consistency_sm as csm  # noqa: E402
from lib import pid_watch  # noqa: E402
from lib.preconditions import write_status  # noqa: E402

# ── Constants ─────────────────────────────────────────────────────────────────
DEFAULT_PORT         = 53535
DEFAULT_UNBOUND_CONF = "/var/unbound/unbound.conf"
DEFAULT_HOST_ENTRIES = "/var/unbound/host_entries.conf"
UNBOUND_CONTROL      = "/usr/local/sbin/unbound-control"
KEA_SYNC             = "/usr/local/opnsense/scripts/keaunbound/kea-sync.py"

# Live-path unbound-control timeout. Spike R5 measured status/local_data at 9–15 ms
# on a 446-record box; 300 ms is ~20x headroom and well under the 500 ms ACK budget.
# A *hung* (not refused) unbound-control during a restart is the real latency
# killer in a single-threaded loop; this caps it. Distinct from kea-sync's 10s.
LIVE_CONTROL_TIMEOUT = 0.3

# kqueue timer ident (we keep a single re-armed oneshot timer for SM wakes).
_TIMER_IDENT = 1


# ── Argument parsing ──────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--port", type=int, default=DEFAULT_PORT,
                   help=f"UDP port to listen on (default: {DEFAULT_PORT})")
    p.add_argument("--unbound-conf", default=DEFAULT_UNBOUND_CONF,
                   help=f"Unbound config file (default: {DEFAULT_UNBOUND_CONF})")
    p.add_argument("--host-entries", default=DEFAULT_HOST_ENTRIES,
                   help="Unbound host_entries.conf to guard against clobbering")
    p.add_argument("--tsig-key", default=None,
                   help="TSIG key in NAME:SECRET format (base64 secret)")
    p.add_argument("--tsig-algorithm", default="HMAC-SHA256",
                   help="TSIG algorithm (default: HMAC-SHA256)")
    p.add_argument("--no-synthesize-ptr", action="store_true",
                   help="Do not synthesize PTR records from forward A/AAAA ADDs. "
                        "Explicit PTR NCRs from kea-dhcp-ddns are still applied.")
    p.add_argument("--dry-run", "-n", action="store_true",
                   help="Parse and log updates but do not call unbound-control")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Log detailed information about each packet and call")
    return p.parse_args()


# ── host_entries cache (static guard) ─────────────────────────────────────────
class HostEntriesCache:
    """In-memory copy of host_entries.conf, re-read on BLOCKED→NORMAL.

    Replaces the old per-packet file reads. Type-agnostic name lookup, unified
    with the sync path's guard (lib.is_in_host_entries): a forward FQDN matches
    directly; a PTR arpa name matches via its decoded IP (host_entries stores
    PTRs keyed by IP).

    V3 guarantee: host_entries.conf only changes during an Unbound stop→start, so
    a pid cycle (→ BLOCKED→NORMAL → refresh()) always precedes a stale read. The
    optional cheap hedge against a future OPNsense refactor that decoupled the two
    would be an mtime stat here before each guard check; V3's structural guarantee
    makes it unnecessary today.
    """

    def __init__(self, path: str, logger: logging.Logger):
        self.path = path
        self.logger = logger
        self.entries: dict = {}
        self.refresh()

    def refresh(self) -> None:
        # read_host_entries() reads the module constant path; honor our --host-
        # entries override by temporarily pointing it there only if different.
        try:
            self.entries = _read_host_entries_at(self.path)
        except Exception as e:  # never let a guard refresh crash the loop
            self.logger.warning("host_entries refresh failed (%s): keeping cache", e)

    def is_static(self, name: str) -> bool:
        """True if name is OPNsense-owned (forward FQDN or PTR-by-IP)."""
        if name in self.entries:
            return True
        ip = _arpa_to_ip(name)
        return bool(ip) and ip in self.entries


def _read_host_entries_at(path: str) -> dict:
    """read_host_entries() keys off the lib's HOST_ENTRIES constant. The daemon's
    default matches it; if an override path is given, parse that file with the same
    logic by temporarily swapping the constant (single-threaded, safe)."""
    from lib import keaunbound_sync as kbs
    if path == kbs.HOST_ENTRIES:
        return read_host_entries()
    saved = kbs.HOST_ENTRIES
    try:
        kbs.HOST_ENTRIES = path
        return read_host_entries()
    finally:
        kbs.HOST_ENTRIES = saved


# ── DNS record helpers ────────────────────────────────────────────────────────
HANDLED_TYPES = {"A", "AAAA", "PTR"}
OTHER_FAMILY = {"A": "AAAA", "AAAA": "A"}
_NONSENSE_NAMES = {"", ".", "localhost", "localdomain"}
_LABEL_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')


def fqdn(name: dns.name.Name) -> str:
    return str(name).rstrip(".")


def is_sane_name(name: str, logger: logging.Logger) -> bool:
    if not name or name in _NONSENSE_NAMES:
        logger.warning("Rejecting nonsense name: %r", name)
        return False
    first_label = name.split(".")[0]
    if not first_label or not _LABEL_RE.match(first_label):
        logger.warning("Rejecting name with invalid first label: %r", name)
        return False
    if all(part.isdigit() for part in name.split(".")):
        logger.warning("Rejecting all-numeric name (looks like an IP): %r", name)
        return False
    return True


def reverse_ptr(ip: str):
    try:
        return str(ipaddress.ip_address(ip).reverse_pointer)
    except ValueError:
        return None


def extract_dirty_names(msg: dns.message.Message) -> set:
    """Forward FQDNs touched by an update, for note_dirty() when we defer it.
    A/AAAA → the owner name; PTR → the rdata target (a hostname). The drain
    re-resolves these by hostname from Kea, never replays the raw NCR."""
    names = set()
    for rrset in msg.authority:
        rdtype = dns.rdatatype.to_text(rrset.rdtype)
        if rdtype in ("A", "AAAA"):
            names.add(fqdn(rrset.name))
        elif rdtype == "PTR":
            for rr in rrset:
                t = str(rr).rstrip(".")
                if t:
                    names.add(t)
    return names


# ── unbound-control (live path) ───────────────────────────────────────────────
class UnboundRefused(Exception):
    """unbound-control could not reach the control channel — Unbound is down."""


def unbound_control(args: list, unbound_conf: str, dry_run: bool,
                    logger: logging.Logger) -> bool:
    """Run unbound-control on the LIVE path with a tight timeout. Raises
    UnboundRefused on connection failure (so the caller can enter BLOCKED);
    returns False on other non-zero exits, True on success."""
    cmd = [UNBOUND_CONTROL, "-c", unbound_conf] + args
    logger.debug("unbound-control %s", " ".join(args))
    if dry_run:
        logger.info("[dry-run] would run: unbound-control %s", " ".join(args))
        return True
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=LIVE_CONTROL_TIMEOUT)
        if result.returncode != 0:
            err = result.stderr.strip()
            # A refused/!connect error means the control channel is down.
            if "connect" in err.lower() or "ssl" in err.lower() or not err:
                raise UnboundRefused(err or "no error text")
            logger.error("unbound-control %s failed (rc=%d): %s",
                         " ".join(args), result.returncode, err)
            return False
        logger.debug("unbound-control ok: %s", result.stdout.strip())
        return True
    except subprocess.TimeoutExpired:
        logger.error("unbound-control %s timed out (%.0fms)",
                     " ".join(args), LIVE_CONTROL_TIMEOUT * 1000)
        raise UnboundRefused("timeout")
    except FileNotFoundError:
        logger.error("%s not found — is Unbound installed?", UNBOUND_CONTROL)
        raise UnboundRefused("unbound-control missing")


def query_unbound(name: str, record_type: str, logger: logging.Logger,
                  unbound_conf: str) -> list:
    """Local-data query for dual-stack preservation / collision checks. Returns
    [(ip, ttl)]. Best-effort: an empty list on failure (the in-memory store
    should never fail while Unbound is up; if it is down the mutation fails too)."""
    try:
        result = subprocess.run(
            [UNBOUND_CONTROL, "-c", unbound_conf, "list_local_data"],
            capture_output=True, text=True, timeout=LIVE_CONTROL_TIMEOUT)
        if result.returncode != 0:
            return []
        name_dot = name.rstrip(".") + "."
        records = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            if parts[0].lower() == name_dot.lower() and parts[3] == record_type:
                ip = parts[4]
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue
                try:
                    ttl = int(parts[1])
                except ValueError:
                    ttl = 3600
                records.append((ip, ttl))
        return records
    except Exception as e:
        logger.debug("list_local_data query for %s %s failed: %s",
                     name, record_type, e)
        return []


# ── Live update processing (lock already held by the caller) ──────────────────
def process_update(msg: dns.message.Message, unbound_conf: str, dry_run: bool,
                   logger: logging.Logger, cache: HostEntriesCache,
                   synthesize_ptr: bool, collision_policy: str) -> int:
    """Apply one DNS UPDATE to Unbound and return the DNS RCODE. The caller MUST
    already hold the mutation lock. Raises UnboundRefused if the control channel
    is down (the caller enters BLOCKED and records the names dirty)."""
    added = removed = skipped = errors = 0

    def uc(args):
        return unbound_control(args, unbound_conf, dry_run, logger)

    for rrset in msg.authority:
        name = fqdn(rrset.name)
        rdtype = dns.rdatatype.to_text(rrset.rdtype)

        if rdtype not in HANDLED_TYPES:
            logger.debug("Skipping unsupported record type %s for %s", rdtype, name)
            continue
        if rdtype != "PTR" and not is_sane_name(name, logger):
            skipped += 1
            continue
        if cache.is_static(name):
            logger.info("Skipping %s %s — static (host_entries)", rdtype, name)
            skipped += 1
            continue

        # RFC 2136 §2.5 delete: class ANY/NONE AND TTL=0.
        is_delete = (rrset.rdclass in (dns.rdataclass.ANY, dns.rdataclass.NONE)
                     and rrset.ttl == 0)

        if is_delete:
            if rdtype in ("A", "AAAA"):
                other_type = OTHER_FAMILY[rdtype]
                preserved = query_unbound(name, other_type, logger, unbound_conf)
                current_ips = [str(rr) for rr in rrset] or \
                    [ip for ip, _t in query_unbound(name, rdtype, logger, unbound_conf)]
                current_ptrs = [p for p in (reverse_ptr(ip) for ip in current_ips) if p]
                logger.info("Remove: %s %s (preserving %d %s)",
                            rdtype, name, len(preserved), other_type)
                if uc(["local_data_remove", name]):
                    if synthesize_ptr:
                        for ptr in current_ptrs:
                            if not cache.is_static(ptr):
                                logger.info("Remove PTR: %s", ptr)
                                uc(["local_data_remove", ptr])
                    for ip, ttl in preserved:
                        ptr = reverse_ptr(ip)
                        logger.info("Restore %s: %s -> %s (TTL %ds)",
                                    other_type, name, ip, ttl)
                        uc(["local_data", f"{name} {ttl} IN {other_type} {ip}"])
                        if synthesize_ptr and ptr and not cache.is_static(ptr):
                            uc(["local_data", f"{ptr} {ttl} IN PTR {name}."])
                    removed += 1
                else:
                    errors += 1
            elif rdtype == "PTR":
                logger.info("Remove PTR: %s (standalone)", name)
                if uc(["local_data_remove", name]):
                    removed += 1
                else:
                    errors += 1
        else:
            for rr in rrset:
                rdata = str(rr)
                if rdtype in ("A", "AAAA"):
                    if collision_policy != "allow":
                        existing = query_unbound(name, rdtype, logger, unbound_conf)
                        conflict_ips = {ip for ip, _t in existing if ip != rdata}
                        if conflict_ips:
                            if collision_policy == "first_wins":
                                logger.info("Collision: %s has %s; blocking %s (first_wins%s)",
                                            name, conflict_ips, rdata,
                                            ", YXRRSET" if len(msg.answer) > 0 else "")
                                skipped += 1
                                if len(msg.answer) > 0:
                                    logger.info("Update complete: added=%d removed=%d "
                                                "skipped=%d errors=%d",
                                                added, removed, skipped, errors)
                                    return dns.rcode.YXRRSET
                                continue
                            elif collision_policy == "last_wins":
                                other_type = OTHER_FAMILY[rdtype]
                                preserved = query_unbound(name, other_type, logger, unbound_conf)
                                all_old = {ip for ip, _t in existing}
                                logger.info("Collision: %s replacing %s with %s (last_wins)",
                                            name, conflict_ips, rdata)
                                uc(["local_data_remove", name])
                                if synthesize_ptr:
                                    for old_ip in all_old:
                                        op = reverse_ptr(old_ip)
                                        if op and not cache.is_static(op):
                                            uc(["local_data_remove", op])
                                for old_ip, old_ttl in preserved:
                                    uc(["local_data", f"{name} {old_ttl} IN {other_type} {old_ip}"])
                                    if synthesize_ptr:
                                        op = reverse_ptr(old_ip)
                                        if op and not cache.is_static(op):
                                            uc(["local_data", f"{op} {old_ttl} IN PTR {name}."])
                    record = f"{name} {rrset.ttl} IN {rdtype} {rdata}"
                    logger.info("Add: %s", record)
                    if uc(["local_data", record]):
                        if synthesize_ptr:
                            ptr = reverse_ptr(rdata)
                            if ptr and not cache.is_static(ptr):
                                logger.info("Add PTR: %s %s IN PTR %s.", ptr, rrset.ttl, name)
                                uc(["local_data", f"{ptr} {rrset.ttl} IN PTR {name}."])
                        added += 1
                    else:
                        errors += 1
                elif rdtype == "PTR":
                    if collision_policy == "first_wins":
                        ptr_ip = _arpa_to_ip(name)
                        target = rdata.rstrip(".")
                        if ptr_ip and target:
                            fwd = (query_unbound(target, "A", logger, unbound_conf) +
                                   query_unbound(target, "AAAA", logger, unbound_conf))
                            if fwd and not any(ip == ptr_ip for ip, _t in fwd):
                                logger.info("Collision: PTR %s skipped; %s already at %s (first_wins)",
                                            name, target, {ip for ip, _ in fwd})
                                skipped += 1
                                continue
                    record = f"{name} {rrset.ttl} IN PTR {rdata}"
                    logger.info("Add PTR (explicit): %s", record)
                    if uc(["local_data", record]):
                        added += 1
                    else:
                        errors += 1

    logger.info("Update complete: added=%d removed=%d skipped=%d errors=%d",
                added, removed, skipped, errors)
    return dns.rcode.NOERROR if errors == 0 else dns.rcode.SERVFAIL


# ── Response / TSIG helpers ───────────────────────────────────────────────────
def build_response(request: dns.message.Message, rcode: int) -> bytes:
    response = dns.message.make_response(request)
    response.set_rcode(rcode)
    return response.to_wire()


def parse_tsig_key(spec, algorithm: str = "HMAC-SHA256"):
    if not spec:
        return None
    if ":" not in spec:
        print("ERROR: --tsig-key must be NAME:SECRET (base64)", file=sys.stderr)
        sys.exit(1)
    name, secret = spec.split(":", 1)
    algo_map = {
        "HMAC-MD5": dns.tsig.HMAC_MD5, "HMAC-SHA1": dns.tsig.HMAC_SHA1,
        "HMAC-SHA224": dns.tsig.HMAC_SHA224, "HMAC-SHA256": dns.tsig.HMAC_SHA256,
        "HMAC-SHA384": dns.tsig.HMAC_SHA384, "HMAC-SHA512": dns.tsig.HMAC_SHA512,
    }
    algo = algo_map.get(algorithm.upper())
    if algo is None:
        print(f"ERROR: unknown TSIG algorithm {algorithm!r}. "
              f"Valid: {', '.join(algo_map)}", file=sys.stderr)
        sys.exit(1)
    return dns.tsigkeyring.from_text({name: (algo, secret)})


# ── Signal handling ───────────────────────────────────────────────────────────
_running = True


def handle_signal(signum, frame):
    global _running
    _running = False


# ── The daemon (kqueue loop + SM driver) ──────────────────────────────────────
class Daemon:
    def __init__(self, args, logger):
        self.args = args
        self.log = logger
        self.keyring = parse_tsig_key(args.tsig_key, args.tsig_algorithm)
        self.synthesize_ptr = not args.no_synthesize_ptr
        self.collision_policy = get_collision_policy()
        self.cache = HostEntriesCache(args.host_entries, logger)
        self.sm = csm.ConsistencySM(csm.SMConfig())
        self.sock = None
        self.kq = None
        self.watcher = None
        self.child = None           # the running kea-sync Popen, or None
        self._child_overflow = False

    # ── setup ──────────────────────────────────────────────────────────────────
    def setup(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.args.port))
        self.sock.setblocking(False)

        self.kq = select.kqueue()
        # Socket readable.
        self.kq.control([select.kevent(self.sock.fileno(),
                                       filter=select.KQ_FILTER_READ,
                                       flags=select.KQ_EV_ADD)], 0, 0)
        # Pidfile + directory VNODE watches.
        self.watcher = pid_watch.PidWatcher(self.kq, pid_watch.resolve_watched_services())
        self.watcher.register_all()

        self.log.info("Listening on 127.0.0.1:%d tsig=%s policy=%s watching=%s",
                      self.args.port,
                      self.args.tsig_algorithm if self.keyring else "disabled",
                      self.collision_policy,
                      ",".join(sorted(self.watcher.service_paths)))
        write_status("starting")

    # ── directive execution ─────────────────────────────────────────────────────
    def execute(self, directives):
        for d in directives:
            if isinstance(d, csm.Spawn):
                self._spawn(d)
            elif isinstance(d, csm.KillPending):
                self._kill_child()
            elif isinstance(d, csm.ScheduleWake):
                self._arm_timer(d.delay)
            elif isinstance(d, csm.Alert):
                self.log.error("ALERT: %s", d.message)
                write_status("alert", d.message)
            elif isinstance(d, csm.Terminate):
                self._terminate(d.reason)

    def _spawn(self, d: csm.Spawn):
        if self.child is not None:
            # Defensive: never run two reconciles. The SM emits KillPending first
            # on a flap, but guard anyway.
            self.log.warning("reconcile already running; ignoring spawn")
            return
        cmd = [sys.executable, KEA_SYNC, "--mode=full"]
        if d.names:
            cmd.append("--names=" + ",".join(sorted(d.names)))
        self.log.info("Spawn reconcile: %s", " ".join(cmd[2:]))
        try:
            self.child = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, text=True)
        except OSError as e:
            self.log.error("failed to spawn kea-sync: %s", e)
            self.child = None
            # Report a failure so the SM backs off and retries.
            self.execute(self.sm.on_sync_exit(time.time(), 1))
            return
        self._register_child(self.child.pid)

    def _register_child(self, pid: int):
        try:
            self.kq.control([select.kevent(pid, filter=select.KQ_FILTER_PROC,
                                           flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                                           fflags=select.KQ_NOTE_EXIT)], 0, 0)
        except OSError as e:
            # ESRCH: the child already exited before we registered. Reap now and
            # feed the exit synchronously instead of waiting for an event.
            if e.errno == errno.ESRCH:
                self.log.debug("child %d exited before registration; reaping", pid)
                self._reap_child()
            else:
                raise

    def _reap_child(self):
        if self.child is None:
            return
        out, err = self.child.communicate()
        code = self.child.returncode
        for line in (out or "").strip().splitlines():
            self.log.info("[kea-sync] %s", line)
        if (err or "").strip():
            self.log.debug("[kea-sync stderr] %s", err.strip())
        self.child = None
        self.log.info("reconcile exit code=%d", code)
        self.execute(self.sm.on_sync_exit(time.time(), code))

    def _kill_child(self):
        if self.child is None:
            return
        self.log.info("preempting running reconcile (pid %d)", self.child.pid)
        try:
            self.child.terminate()
            self.child.wait(timeout=5)
        except Exception:
            try:
                self.child.kill()
                self.child.wait(timeout=5)
            except Exception as e:
                self.log.warning("could not reap preempted reconcile: %s", e)
        # waitpid done -> the child's mutation-lock fd is closed -> lock free
        # before any replacement reconcile is spawned.
        self.child = None

    def _arm_timer(self, delay: float):
        # Single re-armed oneshot timer; data is in milliseconds (>=1).
        ms = max(1, int(delay * 1000))
        self.kq.control([select.kevent(_TIMER_IDENT, filter=select.KQ_FILTER_TIMER,
                                       flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                                       data=ms)], 0, 0)

    def _terminate(self, reason: str):
        global _running
        self.log.error("watchdog terminate: %s — stopping plugin", reason)
        write_status("stopped", reason)
        # configd runs stop.py independently of our process subtree (R1), so this
        # completes even though stop.py kills our supervisor + us.
        try:
            subprocess.Popen(["/usr/local/sbin/configctl", "keaunbound", "stop"])
        except OSError as e:
            self.log.error("could not request stop: %s", e)
        _running = False

    # ── live socket drain ───────────────────────────────────────────────────────
    def drain_socket(self):
        """Read and process all queued datagrams until EWOULDBLOCK (R10)."""
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except BlockingIOError:
                return
            except OSError as e:
                self.log.error("socket error: %s", e)
                return
            self._handle_packet(data, addr)

    def _handle_packet(self, data: bytes, addr):
        t0 = time.monotonic()
        try:
            if self.keyring:
                msg = dns.message.from_wire(data, keyring=self.keyring)
            else:
                msg = dns.message.from_wire(data)
        except dns.exception.DNSException as e:
            self.log.warning("failed to parse DNS message from %s: %s", addr, e)
            return

        if self.keyring and not msg.had_tsig:
            self.log.warning("rejecting unsigned UPDATE from %s — TSIG required", addr)
            self._respond(msg, dns.rcode.REFUSED, addr)
            return

        if dns.opcode.from_flags(msg.flags) != dns.opcode.UPDATE:
            return

        rcode = self._apply_or_defer(msg)
        self._respond(msg, rcode, addr)
        dt = (time.monotonic() - t0) * 1000
        # V5: per-NCR receive→respond latency, asserted on in the ACK-budget test.
        self.log.info("NCR id=%d rcode=%s latency=%.1fms", msg.id,
                      dns.rcode.to_text(rcode), dt)
        if dt > 500:
            self.log.warning("NCR id=%d exceeded 500ms ACK budget (%.1fms)", msg.id, dt)

    def _apply_or_defer(self, msg) -> int:
        """The heart of the live path. BLOCKED or lock-contended → defer (ACK-fail
        + dirty). Otherwise apply under the non-blocking lock; an Unbound-down
        failure enters BLOCKED."""
        names = extract_dirty_names(msg)

        if self.sm.state is csm.State.BLOCKED:
            self.sm.note_dirty(names)
            self.log.info("deferred (BLOCKED): %s", ",".join(sorted(names)) or "?")
            return dns.rcode.SERVFAIL

        try:
            with unbound_mutation_lock(blocking=False):
                try:
                    return process_update(msg, self.args.unbound_conf,
                                          self.args.dry_run, self.log, self.cache,
                                          self.synthesize_ptr, self.collision_policy)
                except UnboundRefused as e:
                    self.log.warning("apply failed, Unbound down (%s) — BLOCKED", e)
                    self.execute(self.sm.on_apply_failure(time.time(), names))
                    return dns.rcode.SERVFAIL
        except BlockingIOError:
            # A reconcile / external clean holds the lock. Defer + re-resolve on
            # the next drain; arm a near-term wake so the drain runs.
            self.sm.note_dirty(names)
            self._arm_timer(self.sm.cfg.normal_drain_poll)
            self.log.info("deferred (lock busy): %s", ",".join(sorted(names)) or "?")
            return dns.rcode.SERVFAIL

    def _respond(self, msg, rcode, addr):
        try:
            self.sock.sendto(build_response(msg, rcode), addr)
        except OSError as e:
            self.log.error("failed to send response to %s: %s", addr, e)

    # ── main loop ────────────────────────────────────────────────────────────────
    def run(self):
        self.execute(self.sm.start(time.time()))
        prev_state = self.sm.state
        while _running:
            try:
                events = self.kq.control(None, 16, 1.0)
            except OSError as e:
                if e.errno == errno.EINTR:
                    continue
                raise

            pid_wake = timer_wake = False
            for ev in events:
                if ev.filter == select.KQ_FILTER_READ:
                    self.drain_socket()
                elif ev.filter == select.KQ_FILTER_VNODE:
                    pid_wake = True
                elif ev.filter == select.KQ_FILTER_TIMER:
                    timer_wake = True
                elif ev.filter == select.KQ_FILTER_PROC:
                    self._reap_child()

            if pid_wake:
                self.watcher.refresh()
            if pid_wake or timer_wake:
                self.execute(self.sm.on_wake(time.time(), self.watcher.read_state()))

            # Refresh the static-guard cache on entering NORMAL (V3: a pid cycle
            # always precedes a host_entries change, so this is the right moment).
            if self.sm.state is csm.State.NORMAL and prev_state is not csm.State.NORMAL:
                self.cache.refresh()
                write_status("running")
                self.log.info("NORMAL — live applies resumed")
            elif self.sm.state is csm.State.BLOCKED and prev_state is not csm.State.BLOCKED:
                write_status("blocked")
            prev_state = self.sm.state

        self.shutdown()

    def shutdown(self):
        self.log.info("shutting down")
        self._kill_child()
        if self.watcher:
            self.watcher.close()
        if self.sock:
            self.sock.close()
        if self.kq:
            self.kq.close()


def main():
    args = parse_args()
    logger = setup_logging(args.verbose)
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    daemon = Daemon(args, logger)
    try:
        daemon.setup()
    except OSError as e:
        logger.error("cannot start: %s", e)
        write_status("stopped", str(e))
        sys.exit(1)

    if args.dry_run:
        logger.info("[dry-run] no unbound-control mutations will be made")

    daemon.run()


if __name__ == "__main__":
    main()
