#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
kea-ubnd-ddns.py — resident consistency daemon for Kea → Unbound DNS.

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
  PTR synthesis always issues local_data_remove <arpa> before local_data to prevent
  Unbound accumulating stale PTR targets when an IP is reassigned to a new hostname
  without a DELETE NCR for the previous hostname arriving first.
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
    kea-ubnd-ddns.py [--port PORT] [--unbound-conf FILE] [--host-entries FILE]
                        [--tsig-key NAME:SECRET] [--tsig-algorithm ALGO]
                        [--no-synthesize-ptr] [--dry-run] [--verbose]
"""

from __future__ import annotations

import argparse
import errno
import ipaddress
import logging
import os
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
sys.path.insert(0, "/usr/local/opnsense/scripts/keaubnd")
from lib.keaubnd_sync import (  # noqa: E402
    _arpa_to_ip, is_in_host_entries, normalize_hostname, reverse_ptr,
    setup_logging,
    read_host_entries, unbound_mutation_lock, MUTATION_LOCK_PATH,
    _evict_record, OTHER_FAMILY,
)
from lib import consistency_sm as csm  # noqa: E402
from lib import keaubnd_runtime as _rt  # noqa: E402
from lib import pid_watch  # noqa: E402
from lib.preconditions import write_status  # noqa: E402

# ── Constants ─────────────────────────────────────────────────────────────────
DEFAULT_PORT  = 53535
KEA_SYNC      = "/usr/local/opnsense/scripts/keaubnd/kea-sync.py"
FAST_RELOAD   = "/usr/local/opnsense/scripts/keaubnd/fast-reload.py"

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
    p.add_argument("--unbound-conf", default=None,
                   help="Unbound config file (default: from keaubnd.json → "
                        "/var/unbound/unbound.conf)")
    p.add_argument("--host-entries", default=None,
                   help="Unbound host_entries.conf to guard against clobbering "
                        "(default: from keaubnd.json → /var/unbound/host_entries.conf)")
    p.add_argument("--tsig-key", default=None,
                   help="TSIG key in NAME:SECRET format (base64 secret)")
    p.add_argument("--tsig-algorithm", default="HMAC-SHA256",
                   help="TSIG algorithm (default: HMAC-SHA256)")
    p.add_argument("--collision-policy", default="last_wins",
                   choices=["allow", "last_wins", "first_wins", "none"],
                   help="Collision resolution policy (default: last_wins)")
    p.add_argument("--magic-names", action="store_true", default=False,
                   help="Enable magic hostname collision disambiguation")
    p.add_argument("--laa-tag", action="store_true", default=False,
                   help="Apply LAA suffix detection to magic hostnames")
    p.add_argument("--write-magic-ptrs", action="store_true", default=False,
                   help="Write PTR records pointing to magic FQDNs for collision-group "
                        "IPs (only meaningful with --magic-names)")
    p.add_argument("--clean-stale-records", action="store_true", default=False,
                   help="Run stale-record sweep on every startup sync. "
                        "Overrides keaubnd.json; unset = read from keaubnd.json.")
    p.add_argument("--dirty-cap", type=int, default=None,
                   help="Max dirty names before triggering a full sync (SM tunable)")
    p.add_argument("--max-full-sync-attempts", type=int, default=None,
                   help="Full sync retry limit before entering BLOCKED (SM tunable)")
    p.add_argument("--readiness-watchdog-minutes", type=int, default=None,
                   help="Minutes before SM watchdog forces a sync (SM tunable)")
    p.add_argument("--fast-reload-threshold", type=int, default=None,
                   help="Number of live-path NCRs before triggering "
                        "unbound-control fast-reload to reclaim heap memory. "
                        "Overrides keaubnd.json; unset = read from keaubnd.json.")
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
        try:
            self.entries = read_host_entries(self.path)
        except Exception as e:  # never let a guard refresh crash the loop
            self.logger.warning("host_entries refresh failed (%s): keeping cache", e)

    def is_static(self, name: str) -> bool:
        """True if name is OPNsense-owned (forward FQDN or PTR-by-IP).

        Delegates to is_in_host_entries which handles both direct name lookup
        and arpa-name → IP decode, keeping the guard consistent with the sync path.
        """
        return is_in_host_entries(name, self.entries)


# ── DNS record helpers ────────────────────────────────────────────────────────
HANDLED_TYPES = {"A", "AAAA", "PTR"}


def fqdn(name: dns.name.Name) -> str:
    return str(name).rstrip(".")


def extract_dirty_names(msg: dns.message.Message) -> set:
    """Forward FQDNs touched by an update, for note_dirty_ncr() when we defer it.
    A/AAAA → the owner name; PTR → the rdata target (a hostname). The drain
    re-resolves these by hostname from Kea, never replays the raw NCR.
    Invalid or unsanitary names are dropped here — they can never be drained."""
    names = set()
    for rrset in msg.authority:
        rdtype = dns.rdatatype.to_text(rrset.rdtype)
        if rdtype in ("A", "AAAA"):
            n = normalize_hostname(fqdn(rrset.name))
            if n:
                names.add(n)
        elif rdtype == "PTR":
            for rr in rrset:
                n = normalize_hostname(str(rr).rstrip("."))
                if n:
                    names.add(n)
    return names


def extract_deleted_ips(msg: dns.message.Message) -> set:
    """IPs from specific-rdata NONE-class A/AAAA delete records in an update.
    D2 always sends specific-rdata deletes (RFC 4703 / RFC 2136 §2.5.4), so
    every real delete carries the IP. ANY/type-only deletes carry no IP — those
    fall back to the periodic clean as today (non-D2 defensive path only)."""
    ips = set()
    for rrset in msg.authority:
        if rrset.deleting is None:
            continue
        rdtype = dns.rdatatype.to_text(rrset.rdtype)
        if rdtype in ("A", "AAAA"):
            for rr in rrset:
                ip = str(rr)
                if ip:
                    ips.add(ip)
    return ips


# ── unbound-control (live path) ───────────────────────────────────────────────
class UnboundRefused(Exception):
    """unbound-control could not reach the control channel — Unbound is down."""


def unbound_control(args: list, unbound_conf: str, dry_run: bool,
                    logger: logging.Logger) -> bool:
    """Run unbound-control on the LIVE path with a tight timeout. Raises
    UnboundRefused on connection failure (so the caller can enter BLOCKED);
    returns False on other non-zero exits, True on success."""
    cmd = [_rt.get_unbound_control(), "-c", unbound_conf] + args
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
        logger.error("%s not found — is Unbound installed?", _rt.get_unbound_control())
        raise UnboundRefused("unbound-control missing")


def _filter_local_data(stdout: str, name: str, record_type: str) -> list:
    """Filter list_local_data stdout for (name, record_type). Returns [(ip, ttl)]."""
    name_dot = name.rstrip(".") + "."
    records = []
    for line in stdout.splitlines():
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


# ── Live update processing (lock already held by the caller) ──────────────────
def process_update(msg: dns.message.Message, unbound_conf: str, dry_run: bool,
                   logger: logging.Logger, cache: HostEntriesCache,
                   synthesize_ptr: bool = True,
                   collision_policy: str = "last_wins",
                   magic_names: bool = False,
                   dirty_out: "set | None" = None) -> int:
    """Apply one DNS UPDATE to Unbound and return the DNS RCODE. The caller MUST
    already hold the mutation lock. Raises UnboundRefused if the control channel
    is down (the caller enters BLOCKED and records the names dirty)."""
    added = removed = skipped = errors = 0

    def uc(args):
        return unbound_control(args, unbound_conf, dry_run, logger)

    # Fetch current Unbound state once. All reads within process_update() filter
    # this string rather than calling list_local_data again.
    # Skip the fetch only when allow policy is in use AND no magic AND no deletes.
    # magic_names needs the snapshot for allow ADDs to detect collisions for the
    # drain-defer trigger (even though allow itself never evicts).
    _has_deletes = any(rs.deleting is not None for rs in msg.authority)
    if collision_policy != "allow" or _has_deletes or magic_names:
        try:
            _r = subprocess.run(
                [_rt.get_unbound_control(), "-c", unbound_conf, "list_local_data"],
                capture_output=True, text=True, timeout=LIVE_CONTROL_TIMEOUT)
            snapshot = _r.stdout if _r.returncode == 0 else ""
        except Exception as e:
            logger.debug("list_local_data snapshot failed: %s", e)
            snapshot = ""
    else:
        snapshot = ""

    def qub(name: str, rtype: str) -> list:
        return _filter_local_data(snapshot, name, rtype)

    for rrset in msg.authority:
        rdtype = dns.rdatatype.to_text(rrset.rdtype)

        # dnspython exposes an UPDATE record's delete-class via rrset.deleting
        # (NONE = delete a specific RR, ANY = delete an RRset / all RRsets at the
        # name); it is non-None iff this record is a delete. rrset.rdclass is
        # NORMALIZED to the zone class (IN) on parsed updates, so it must NOT be
        # used to detect deletes — doing so silently dropped every delete d2
        # ever sent (see int-docs/kea-listener-delete-bug). ttl is 0 on deletes
        # but rrset.deleting is the authoritative signal.
        is_delete = rrset.deleting is not None

        # "delete all RRsets for a name" arrives as rdtype ANY; allow it through,
        # but only as a delete. Other types are restricted to what we manage.
        if rdtype not in HANDLED_TYPES and not (is_delete and rdtype == "ANY"):
            logger.debug("Skipping unsupported record type %s for %s", rdtype, fqdn(rrset.name))
            continue

        # normalize_hostname handles forward names and reverse PTR arpa names
        # uniformly: lowercase, strip, validate format. Returns None for garbage.
        name = normalize_hostname(fqdn(rrset.name), logger)
        if name is None:
            if not is_delete:
                skipped += 1
            continue

        if cache.is_static(name):
            logger.info("Skipping %s %s — static (host_entries)", rdtype, name)
            skipped += 1
            continue

        if is_delete:
            if rdtype in ("A", "AAAA"):
                deleting_ips = {str(rr) for rr in rrset}
                if not deleting_ips:
                    # Type-only delete (rdclass=ANY, no rdata): remove all of this family.
                    deleting_ips = {ip for ip, _t in qub(name, rdtype)}
                # PTRs to remove: only for the IPs actually being deleted.
                del_ptrs = [p for p in (reverse_ptr(ip) for ip in deleting_ips) if p]
                logger.info("Remove: %s %s", rdtype, name)
                if _evict_record(uc, qub, name, rdtype, deleting_ips, logger):
                    if synthesize_ptr:
                        for ptr in del_ptrs:
                            if not cache.is_static(ptr):
                                logger.info("Remove PTR: %s", ptr)
                                uc(["local_data_remove", ptr])
                    removed += 1
                else:
                    errors += 1
            elif rdtype == "PTR":
                logger.info("Remove PTR: %s (standalone)", name)
                if _evict_record(uc, qub, name, "PTR", None, logger):
                    removed += 1
                else:
                    errors += 1
            else:  # rdtype == "ANY": delete every RRset at this name
                # Snapshot IPs before removal to chase synthesized PTRs.
                # For reverse (arpa) names there are no A/AAAA so current_ips is empty.
                current_ips = [ip for t in ("A", "AAAA")
                               for ip, _t in qub(name, t)]
                logger.info("Remove all: %s", name)
                if _evict_record(uc, qub, name, "ANY", None, logger):
                    if synthesize_ptr:
                        for ip in current_ips:
                            ptr = reverse_ptr(ip)
                            if ptr and not cache.is_static(ptr):
                                logger.info("Remove PTR: %s", ptr)
                                uc(["local_data_remove", ptr])
                    removed += 1
                else:
                    errors += 1
        else:
            for rr in rrset:
                rdata = str(rr)
                if rdtype in ("A", "AAAA"):
                    _collision_detected = False
                    if collision_policy != "allow" or magic_names:
                        existing = qub(name, rdtype)
                        conflict_ips = {ip for ip, _t in existing if ip != rdata}
                        if conflict_ips:
                            _collision_detected = True
                            if collision_policy == "first_wins":
                                logger.info("Collision: %s has %s; blocking %s (first_wins%s)",
                                            name, conflict_ips, rdata,
                                            ", YXRRSET" if len(msg.answer) > 0 else "")
                                if magic_names and dirty_out is not None:
                                    dirty_out.add(name)
                                skipped += 1
                                if len(msg.answer) > 0:
                                    logger.info("Update complete: added=%d removed=%d "
                                                "skipped=%d errors=%d",
                                                added, removed, skipped, errors)
                                    return dns.rcode.YXRRSET
                                continue
                            elif collision_policy == "last_wins":
                                logger.info("Collision: %s replacing %s with %s (last_wins)",
                                            name, conflict_ips, rdata)
                                _evict_record(uc, qub, name, rdtype, conflict_ips, logger)
                                # Remove PTRs only for evicted IPs — not for the new rdata
                                # IP (added below) or preserved other-family IPs (those PTRs
                                # survive local_data_remove since they live at arpa names).
                                if synthesize_ptr:
                                    for old_ip in conflict_ips:
                                        op = reverse_ptr(old_ip)
                                        if op and not cache.is_static(op):
                                            uc(["local_data_remove", op])
                            elif collision_policy == "none":
                                # Evict the existing record; skip adding the new one. The
                                # slot stays empty until the drain resolves the full collision
                                # group from Kea state (drain is load-bearing for none — see
                                # int-docs/live-path-none-magic-design.md §3).
                                logger.info("Collision: %s evicting %s (none)",
                                            name, conflict_ips)
                                _evict_record(uc, qub, name, rdtype, conflict_ips, logger)
                                if synthesize_ptr:
                                    for old_ip in conflict_ips:
                                        op = reverse_ptr(old_ip)
                                        if op and not cache.is_static(op):
                                            uc(["local_data_remove", op])
                                if dirty_out is not None:
                                    dirty_out.add(name)
                                skipped += 1
                                continue
                    # When magic is on and a collision was detected for this name,
                    # defer magic-FQDN computation to the drain. (none/first_wins
                    # already marked dirty and continued above; this covers
                    # allow+magic and last_wins+magic.)
                    if magic_names and _collision_detected and dirty_out is not None:
                        dirty_out.add(name)
                    record = f"{name} {rrset.ttl} IN {rdtype} {rdata}"
                    logger.info("Add: %s", record)
                    if uc(["local_data", record]):
                        # Skip inline PTR when magic is on and a collision was detected
                        # for this name — the drain will write the appropriate PTR, and
                        # an inline PTR → bare name would need to be corrected ~1s later.
                        if synthesize_ptr and not (magic_names and _collision_detected):
                            ptr = reverse_ptr(rdata)
                            if ptr and not cache.is_static(ptr):
                                logger.info("Add PTR: %s %s IN PTR %s.", ptr, rrset.ttl, name)
                                uc(["local_data_remove", ptr])
                                uc(["local_data", f"{ptr} {rrset.ttl} IN PTR {name}."])
                        added += 1
                    else:
                        errors += 1
                elif rdtype == "PTR":
                    if collision_policy == "first_wins":
                        ptr_ip = _arpa_to_ip(name)
                        target = rdata.rstrip(".")
                        if ptr_ip and target:
                            fwd = (qub(target, "A") + qub(target, "AAAA"))
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
        self.collision_policy = args.collision_policy
        # Resolve unbound paths: CLI arg overrides → runtime config → hardcoded fallback.
        # All three resolve to the same value on OPNsense, but non-OPNsense deployments
        # can write custom paths to keaubnd.json and both paths (live + sync) will honor them.
        self.unbound_conf = args.unbound_conf or _rt.get_unbound_conf()
        host_entries_path = args.host_entries or _rt.get_host_entries()
        self.cache = HostEntriesCache(host_entries_path, logger)
        sm_cfg = csm.SMConfig()
        if args.dirty_cap is not None:
            sm_cfg.dirty_cap = args.dirty_cap
        if args.max_full_sync_attempts is not None:
            sm_cfg.max_full_sync_attempts = args.max_full_sync_attempts
        if args.readiness_watchdog_minutes is not None:
            sm_cfg.watchdog_seconds = float(args.readiness_watchdog_minutes * 60)
        self.sm = csm.ConsistencySM(sm_cfg)
        # Live-path mutation counter. Counts NCRs that returned NOERROR (each
        # NCR typically generates 1-3 unbound-control calls). When the counter
        # reaches _fast_reload_threshold a FastReload directive is emitted and
        # the counter resets. 0 means disabled.
        # CLI arg overrides keaubnd.json; if neither is set, threshold=0 (off).
        rt_threshold = _rt.get_fast_reload_threshold()
        cli_threshold = args.fast_reload_threshold
        self._fast_reload_threshold: int = max(
            0, cli_threshold if cli_threshold is not None else rt_threshold
        )
        self._mutation_count: int = 0
        self.sock = None
        self.kq = None
        self.watcher = None
        self.child = None           # the running subprocess Popen, or None
        self._child_label = "kea-sync"  # log prefix for the current child
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
            elif isinstance(d, csm.FastReload):
                self._spawn_fast_reload()
            elif isinstance(d, csm.KillPending):
                self._kill_child()
            elif isinstance(d, csm.ScheduleWake):
                self._arm_timer(d.delay)
            elif isinstance(d, csm.Alert):
                self.log.error("ALERT: %s", d.message)
                write_status("alert", d.message)
            elif isinstance(d, csm.Terminate):
                self._terminate(d.reason)

    def _spawn_fast_reload(self):
        if self.child is not None:
            self.log.warning("subprocess already running; ignoring fast-reload spawn")
            return
        cmd = [sys.executable, FAST_RELOAD]
        if self.args.dry_run:
            cmd.append("--dry-run")
        if self.args.verbose:
            cmd.append("--verbose")
        self.log.info("Spawn fast-reload")
        self._child_label = "fast-reload"
        try:
            self.child = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, text=True,
                                          start_new_session=True)
        except OSError as e:
            self.log.error("failed to spawn fast-reload: %s", e)
            self.child = None
            self.execute(self.sm.on_sync_exit(time.time(), 1))
            return
        self._register_child(self.child.pid)

    def _spawn(self, d: csm.Spawn):
        if self.child is not None:
            # Defensive: never run two reconciles. The SM emits KillPending first
            # on a flap, but guard anyway.
            self.log.warning("reconcile already running; ignoring spawn")
            return
        self._child_label = "kea-sync"
        cmd = [sys.executable, KEA_SYNC]
        if d.names:
            cmd.append("--names=" + ",".join(sorted(d.names)))
        elif self.args.clean_stale_records or _rt.get_clean_stale_records():
            cmd.append("--clean-stale")
        cmd.append("--collision-policy=" + self.args.collision_policy)
        if self.args.magic_names:
            cmd.append("--magic-names")
        if self.args.laa_tag:
            cmd.append("--laa-tag")
        if self.args.write_magic_ptrs:
            cmd.append("--write-magic-ptrs")
        if not self.synthesize_ptr:
            cmd.append("--no-synthesize-ptr")
        if d.purge_ips:
            cmd.append("--purge-ip=" + ",".join(sorted(d.purge_ips)))
        if self.args.dry_run:
            cmd.append("--dry-run")
        self.log.info("Spawn reconcile: %s", " ".join(cmd[2:]) or "(full)")
        try:
            self.child = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, text=True,
                                          start_new_session=True)
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
        label = self._child_label
        for line in (out or "").strip().splitlines():
            self.log.info("[%s] %s", label, line)
        if (err or "").strip():
            self.log.debug("[%s stderr] %s", label, err.strip())
        self.child = None
        if label == "fast-reload":
            if code != 0:
                self.log.error("fast-reload failed (rc=%d) — "
                               "mutation counter reset; cron will retry", code)
            else:
                self.log.info("fast-reload complete (rc=0)")
        else:
            self.log.info("reconcile exit code=%d", code)
        self._child_label = "kea-sync"  # reset for next child
        self.execute(self.sm.on_sync_exit(time.time(), code))

    def _kill_child(self):
        if self.child is None:
            return
        pid = self.child.pid
        self.log.info("preempting running %s (pid %d)", self._child_label, pid)
        try:
            # Send SIGTERM to the whole process group (start_new_session=True
            # makes the child a session/group leader, so os.killpg reaches any
            # grandchildren it may have spawned, e.g. kea-sync's unbound-control).
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            self.child.wait(timeout=5)
        except Exception:
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
                self.child.wait(timeout=5)
            except Exception as e:
                self.log.warning("could not reap preempted %s: %s", self._child_label, e)
        # waitpid done -> the child's mutation-lock fd is closed -> lock free
        # before any replacement subprocess is spawned.
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
            subprocess.Popen(["/usr/local/sbin/configctl", "keaubnd", "stop"])
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
            try:
                self._handle_packet(data, addr)
            except Exception as e:
                self.log.error("unhandled error in _handle_packet: %s (%s)",
                               e, type(e).__name__, exc_info=True)


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
        except Exception as e:
            # struct.error, ValueError, etc. from truly malformed wire data
            self.log.warning("unexpected parse error from %s: %s (%s)",
                             addr, e, type(e).__name__)
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
        deleted_ips = extract_deleted_ips(msg)

        if self.sm.state is csm.State.BLOCKED:
            self.sm.note_dirty_ncr(names, deleted_ips)
            self.log.info("deferred (BLOCKED): %s", ",".join(sorted(names)) or "?")
            return dns.rcode.SERVFAIL

        try:
            # Short bounded wait (~50ms): avoids missing NCRs when kea-sync
            # briefly holds the lock at startup while still serializing mutations.
            # On timeout the name goes dirty and the drain re-resolves it.
            with unbound_mutation_lock(blocking=True, timeout_secs=0.05):
                try:
                    dirty_out: set = set()
                    rcode = process_update(msg, self.unbound_conf,
                                           self.args.dry_run, self.log, self.cache,
                                           self.synthesize_ptr, self.collision_policy,
                                           magic_names=self.args.magic_names,
                                           dirty_out=dirty_out)
                    if dirty_out:
                        self.sm.note_dirty_ncr(dirty_out)
                        self._arm_timer(self.sm.cfg.normal_drain_poll)
                    elif rcode == dns.rcode.SERVFAIL:
                        self.log.warning("non-connection unbound-control failure; "
                                         "scheduling drain for %s",
                                         ",".join(sorted(names)) or "?")
                        self.sm.note_dirty_ncr(names, deleted_ips)
                        self._arm_timer(self.sm.cfg.normal_drain_poll)
                    t = self._fast_reload_threshold
                    if rcode == dns.rcode.NOERROR and t > 0:
                        self._mutation_count += 1
                        if self._mutation_count >= t:
                            self._mutation_count = 0
                            self.sm.fast_reload_pending = True
                            self._arm_timer(0.0)
                    return rcode
                except UnboundRefused as e:
                    self.log.warning("apply failed, Unbound down (%s) — BLOCKED", e)
                    self.sm.note_dirty_ncr(names, deleted_ips)
                    self.execute(self.sm.on_apply_failure(time.time()))
                    return dns.rcode.SERVFAIL
                except Exception as e:
                    # Unexpected error in process_update — log it, stay up.
                    self.log.error("process_update raised %s: %s",
                                   type(e).__name__, e, exc_info=True)
                    self.sm.note_dirty_ncr(names, deleted_ips)
                    self._arm_timer(self.sm.cfg.normal_drain_poll)
                    return dns.rcode.SERVFAIL
        except TimeoutError:
            # kea-sync or local-data-clean holds the lock; 50ms wait exhausted.
            self.sm.note_dirty_ncr(names, deleted_ips)
            self._arm_timer(self.sm.cfg.normal_drain_poll)
            self.log.info("deferred (lock timeout): %s", ",".join(sorted(names)) or "?")
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
                self.log.info("BLOCKED — live applies deferred pending reconcile")
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

    # keaubnd.json must exist before we create the Daemon: it carries Kea socket
    # paths, Unbound paths, and fast-reload tunables that the Daemon reads in
    # __init__. Fail fast here so the error is clear in the log rather than an
    # AttributeError or KeyError buried in Daemon.__init__.
    try:
        _rt.load()
    except RuntimeError as e:
        logger.error("cannot start: %s", e)
        write_status("stopped", str(e))
        sys.exit(1)

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
