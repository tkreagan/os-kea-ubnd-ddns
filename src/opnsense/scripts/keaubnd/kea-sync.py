#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
kea-sync.py -- Merged Kea → Unbound reconciler.

Reads Kea reservations (static) and/or active leases (dynamic) and writes
them to Unbound's local_data store, respecting the configured collision policy
and the host_entries.conf static guard.

Modes (only two in practice):
  --mode=static   Sync Kea reservations only (IPv4 + IPv6). The cheap "re-assert
                  the high-value records" path.
  --mode=full     Static first, then dynamic leases. Every daemon reconcile and
                  drain, and the general sync.

  There is deliberately NO dynamic-only mode: resolving lease conflicts correctly
  requires knowing the reservations (reservations beat leases), and reservations
  are few/idempotent to re-assert, so syncing leases always implies a full sync.

Options:
  --names=a,b,c   Targeted drain: re-resolve only these hostnames from Kea.
                  Filters the DYNAMIC pass only (static is always full — there is
                  no reservation-get-by-hostname in Kea). Passes the dirty-name
                  set from the consistency SM; re-resolves by hostname, never
                  replays the raw NCR.
  --dry-run       Log what would be done; make no changes to Unbound.
  --verbose       Also write log lines to stderr.

Collision policy (from config.xml collision_policy):
  allow       Always write; no conflict checking.
  first_wins  Skip a new record if the FQDN already maps to a different IP
              (for the same address family). Static pass always precedes dynamic
              in full mode, so reservations beat leases.
  last_wins   Replace an existing record if the new lease has a higher cltt
              (expire − valid_lifetime). Leases are sorted oldest-first so
              the most recently active client wins within a pass. Reservations
              always win over leases regardless of cltt.

The shared Unbound-mutation lock (/var/run/keaubnd/unbound-mutation.lock)
is acquired for the whole run. The daemon live path holds the same lock with a
non-blocking acquire; on contention it ACK-fails and marks the name dirty for
re-resolution on the next wake.

Fail-fast: any Kea connectivity error exits non-zero immediately. The
consistency SM interprets a non-zero exit as a reconcile failure and retries
with backoff.
"""

import argparse
import sys
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

sys.path.insert(0, "/usr/local/opnsense/scripts/keaubnd")

from lib.keaubnd_sync import (
    KeaUnavailableError,
    KeaServiceUnavailableError,
    forward_ips_by_type,
    get_collision_policy,
    get_synthesize_ptr,
    is_in_host_entries,
    is_sane_name,
    query_kea_leases,
    query_kea_leases_by_hostname,
    query_kea_reservations,
    read_host_entries,
    reverse_ptr,
    setup_logging,
    unbound_control,
    unbound_list_local_data,
    unbound_local_datas_batch,
    unbound_mutation_lock,
)


# ── record tuple type ────────────────────────────────────────────────────────
# (hostname, ip, record_type, ttl_or_none)
_Record = Tuple[str, str, str, Optional[int]]


# ── core collision + write logic ─────────────────────────────────────────────

def _collect_writes(
    records: List[_Record],
    rtype: str,
    host_entries: Dict,
    policy: str,
    synthesize_ptr: bool,
    unbound_fwd: Dict[str, Set[str]],
    prior_claim_keys: Set[str],
    logger,
) -> Tuple[List[str], List[str], Set[str], int, int]:
    """Compute the unbound-control adds + removes for ONE pass (one rtype).

    Returns (to_add, to_remove, won_keys, n_added, n_skipped). Pure: no
    unbound-control calls; the caller executes the results.

    Two phases so conflict resolution and dedup finish BEFORE any write is
    emitted (a single record-set per FQDN goes out, never an add-then-remove
    race within the same batch):

      Phase 1 -- filter (sanity / host_entries / prior_claim_keys) then resolve a
                 SINGLE winner per FQDN under the policy.
      Phase 2 -- emit one A/AAAA (+PTR) per winner; emit a remove first only when
                 Unbound currently holds something other than exactly the winner.

    Arguments:
      rtype             "A" or "AAAA" -- every record in `records` is this family.
      prior_claim_keys  lower-cased FQDNs already claimed by a higher-priority
                        source IN THIS FAMILY (reservations, for the dynamic
                        pass). A lease for such a name is skipped -- reservations
                        beat leases. Family-scoped: a v4 reservation does NOT
                        block a v6 lease.
      unbound_fwd       {key -> {ip}} snapshot for THIS family only, so collision
                        checks never cross A/AAAA.

    `allow` policy is purely additive (no dedup, no removes, no snapshot) and
    returns an empty won_keys -- leases are never blocked by reservations under
    allow, matching its "add everything, accept round-robin" contract.
    """
    to_add: List[str] = []
    to_remove: List[str] = []
    won_keys: Set[str] = set()
    n_added = n_skipped = 0

    def _emit_add(hostname: str, ip: str, ttl: Optional[int]) -> None:
        nonlocal n_added
        ttl_part = f" {ttl}" if ttl is not None else ""
        to_add.append(f"{hostname}{ttl_part} IN {rtype} {ip}")
        n_added += 1
        # PTR guard keys on IP (host_entries stores PTRs by IP, not arpa name).
        if synthesize_ptr:
            ptr = reverse_ptr(ip)
            if ptr and not is_in_host_entries(ip, host_entries):
                to_add.append(f"{ptr}{ttl_part} IN PTR {hostname}.")

    # allow: additive, no dedup.
    if policy == "allow":
        for hostname, ip, _rt, ttl in records:
            if not is_sane_name(hostname, logger):
                n_skipped += 1
                continue
            if is_in_host_entries(hostname, host_entries):
                n_skipped += 1
                continue
            _emit_add(hostname, ip, ttl)
        return to_add, to_remove, won_keys, n_added, n_skipped

    # first_wins / last_wins: Phase 1 -- resolve one winner per FQDN.
    winners: Dict[str, Tuple[str, str, Optional[int]]] = {}
    order: List[str] = []  # first-seen key order, for deterministic emit
    for hostname, ip, _rt, ttl in records:
        key = hostname.lower()
        if not is_sane_name(hostname, logger):
            n_skipped += 1
            continue
        if is_in_host_entries(hostname, host_entries):
            logger.debug("Skipping %s — host_entries.conf", hostname)
            n_skipped += 1
            continue
        if key in prior_claim_keys:
            logger.debug("Reservation beats lease for %s", hostname)
            n_skipped += 1
            continue
        if key not in winners:
            winners[key] = (hostname, ip, ttl)
            order.append(key)
        elif policy == "last_wins":
            # records are pre-sorted by cltt ascending, so a later entry has the
            # higher cltt and wins.
            logger.info("Collision last_wins: %s -> %s (was %s)",
                        hostname, ip, winners[key][1])
            winners[key] = (hostname, ip, ttl)
            n_skipped += 1
        else:  # first_wins: keep the earliest-seen (lowest cltt)
            logger.info("Collision first_wins: %s keeps %s, skips %s",
                        hostname, winners[key][1], ip)
            n_skipped += 1

    # Phase 2 -- emit. Replace only when Unbound's current set for this name
    # differs from exactly {winner}; otherwise the add alone is idempotent.
    for key in order:
        hostname, ip, ttl = winners[key]
        existing = unbound_fwd.get(key, set())
        if existing and existing != {ip}:
            to_remove.append(hostname)
            if synthesize_ptr:
                for old_ip in existing - {ip}:
                    ptr = reverse_ptr(old_ip)
                    if ptr:
                        to_remove.append(ptr)
        _emit_add(hostname, ip, ttl)
        won_keys.add(key)

    return to_add, to_remove, won_keys, n_added, n_skipped


def _execute_writes(to_remove: List[str], to_add: List[str],
                    dry_run: bool, logger) -> int:
    """Execute the computed removes + batch-add. Returns error count."""
    errors = 0
    for name in to_remove:
        if dry_run:
            logger.info("[dry-run] local_data_remove %s", name)
        elif not unbound_control(["local_data_remove", name]):
            logger.error("Failed local_data_remove %s", name)
            errors += 1

    if to_add:
        if dry_run:
            for r in to_add:
                logger.info("[dry-run] local_data %s", r)
        elif not unbound_local_datas_batch(to_add):
            logger.error("local_datas batch failed (%d records)", len(to_add))
            errors += 1

    return errors


# Family-scoped claim set: {"A": {keys...}, "AAAA": {keys...}}.
_Claims = Dict[str, Set[str]]


def _empty_claims() -> _Claims:
    return {"A": set(), "AAAA": set()}


# ── static pass ──────────────────────────────────────────────────────────────

def sync_static(
    host_entries: Dict,
    policy: str,
    synthesize_ptr: bool,
    unbound_snapshot: Dict,
    dry_run: bool,
    logger,
) -> Tuple[_Claims, int, int, int]:
    """Sync Kea static reservations. Returns (claims, added, skipped, errors).

    claims is family-scoped (so the dynamic pass blocks leases only in the same
    family). Reservations never block each other across families: each
    service's pass runs with an empty prior-claim set.
    """
    all_to_add: List[str] = []
    all_to_remove: List[str] = []
    claims = _empty_claims()
    total_added = total_skipped = total_errors = 0

    for service in ("dhcp4", "dhcp6"):
        rtype = "A" if service == "dhcp4" else "AAAA"
        unbound_fwd = (forward_ips_by_type(unbound_snapshot, rtype)
                       if policy != "allow" else {})

        try:
            reservations = query_kea_reservations(service=service)
        except KeaServiceUnavailableError as e:
            logger.info("Skipping %s reservations: %s", service, e)
            continue
        # KeaUnavailableError propagates — fail-fast.

        records: List[_Record] = []
        for res in reservations:
            hostname = res["hostname"]
            ip = res["ip"] if service == "dhcp4" else res["ipv6"]
            if hostname and ip:
                records.append((hostname, ip, rtype, None))

        to_add, to_remove, won, n_added, n_skipped = _collect_writes(
            records, rtype, host_entries, policy, synthesize_ptr,
            unbound_fwd, set(), logger,
        )
        all_to_add.extend(to_add)
        all_to_remove.extend(to_remove)
        claims[rtype] |= won
        total_added += n_added
        total_skipped += n_skipped

    total_errors += _execute_writes(all_to_remove, all_to_add, dry_run, logger)
    logger.info("static: added=%d skipped=%d errors=%d",
                total_added, total_skipped, total_errors)
    return claims, total_added, total_skipped, total_errors


# ── dynamic pass ─────────────────────────────────────────────────────────────

def sync_dynamic(
    host_entries: Dict,
    policy: str,
    synthesize_ptr: bool,
    unbound_snapshot: Dict,
    claims: _Claims,
    names_filter: Optional[FrozenSet[str]],
    dry_run: bool,
    logger,
) -> Tuple[int, int, int]:
    """Sync Kea active leases. Returns (added, skipped, errors).

    Only ever called from full mode, after sync_static — so `claims` (the
    family-scoped reservation FQDNs that beat leases) is always populated. There
    is no dynamic-only mode, so no need to rebuild reservation claims here.
    """
    import time as _time
    now = int(_time.time())

    all_to_add: List[str] = []
    all_to_remove: List[str] = []
    total_added = total_skipped = total_errors = 0

    for service in ("dhcp4", "dhcp6"):
        rtype = "A" if service == "dhcp4" else "AAAA"
        unbound_fwd = (forward_ips_by_type(unbound_snapshot, rtype)
                       if policy != "allow" else {})

        try:
            if names_filter:
                leases: List[Dict] = []
                for name in names_filter:
                    leases.extend(
                        query_kea_leases_by_hostname(name, service=service))
            else:
                leases = query_kea_leases(service=service)
        except KeaServiceUnavailableError as e:
            logger.info("Skipping %s leases: %s", service, e)
            continue
        # KeaUnavailableError propagates — fail-fast.

        # Sort by cltt ascending so last-active wins (last_wins) or first-active
        # wins (first_wins).  For allow, ordering is irrelevant.
        leases.sort(key=lambda r: r.get("expires", 0) - r.get("valid_lifetime", 0))

        records: List[_Record] = []
        for lease in leases:
            hostname = lease["hostname"]
            ip = lease["ip"] if service == "dhcp4" else lease["ipv6"]
            if hostname and ip:
                ttl = max(1, lease["expires"] - now)
                records.append((hostname, ip, rtype, ttl))

        to_add, to_remove, _, n_added, n_skipped = _collect_writes(
            records, rtype, host_entries, policy, synthesize_ptr,
            unbound_fwd, claims.get(rtype, set()), logger,
        )
        all_to_add.extend(to_add)
        all_to_remove.extend(to_remove)
        total_added += n_added
        total_skipped += n_skipped

    total_errors += _execute_writes(all_to_remove, all_to_add, dry_run, logger)
    logger.info("dynamic: added=%d skipped=%d errors=%d",
                total_added, total_skipped, total_errors)
    return total_added, total_skipped, total_errors


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=("static", "full"),
                        default="full", help="Which records to sync (default: full)")
    parser.add_argument("--names",
                        help="Comma-separated hostnames for targeted dynamic drain "
                             "(filters the dynamic pass in full mode)")
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="Log what would be done; make no changes")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Also write log lines to stderr")
    args = parser.parse_args()

    names_filter: Optional[FrozenSet[str]] = None
    if args.names:
        names_filter = frozenset(n.strip() for n in args.names.split(",") if n.strip())

    logger = setup_logging(args.verbose)
    logger.info("kea-sync mode=%s names=%s dry_run=%s",
                args.mode, "all" if names_filter is None else len(names_filter),
                args.dry_run)

    host_entries = read_host_entries()
    policy = get_collision_policy()
    synthesize_ptr = get_synthesize_ptr()

    # Preflight: Unbound's control channel must be reachable, or every write
    # below would fail one by one. Fail fast and loud instead. (`status` is a
    # read-only no-op; a connection refusal means Unbound is down/restarting.)
    if not args.dry_run and not unbound_control(["status"]):
        logger.error("unbound-control unavailable — aborting (Unbound down?)")
        return 1

    try:
        with unbound_mutation_lock(blocking=True):
            # Snapshot Unbound once before any writes (used for collision checks).
            unbound_snapshot = (unbound_list_local_data()
                                if policy != "allow" else {})

            total_errors = 0

            # Both modes run static. Full then runs dynamic with static's claims,
            # so reservations are always known before leases are resolved.
            claims, _, _, errs = sync_static(
                host_entries, policy, synthesize_ptr,
                unbound_snapshot, args.dry_run, logger,
            )
            total_errors += errs

            if args.mode == "full":
                _, _, errs = sync_dynamic(
                    host_entries, policy, synthesize_ptr,
                    unbound_snapshot, claims, names_filter,
                    args.dry_run, logger,
                )
                total_errors += errs

    except KeaUnavailableError as e:
        logger.error("Kea unavailable: %s", e)
        return 1
    except BlockingIOError:
        logger.error("Could not acquire mutation lock — another sync is running")
        return 1
    except Exception as e:
        logger.error("Sync failed: %s", e)
        return 1

    return 0 if total_errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
