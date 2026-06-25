#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
kea-sync.py -- Merged Kea → Unbound reconciler.

Reads Kea reservations (static) and/or active leases (dynamic) and writes
them to Unbound's local_data store, respecting the configured collision policy
and the host_entries.conf static guard.

Flags:
  (default)       Full sync: static reservations then dynamic leases. Used by
                  the daemon for every reconcile, drain, and the configd
                  sync_full action.
  --static-only   Sync static reservations only; skip active leases.
                  Available for scripting; not exposed in the UI.
                  Mutually exclusive with --clean-stale.
  --clean-stale   After the full sync, sweep Unbound for records no longer
                  backed by any Kea reservation or active lease and remove them.
                  Passed by the daemon when clean_stale_records is enabled.
                  Mutually exclusive with --static-only.

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

import lib.keaubnd_runtime as _rt
from lib.keaubnd_sync import (
    MAGIC_STATE_PATH,
    KeaUnavailableError,
    KeaServiceUnavailableError,
    clean_stale_records,
    collect_kea_pairs,
    compute_magic_names,
    find_stale_records,
    forward_ips_by_type,
    identifier_tail,
    ip_suffix,
    is_in_host_entries,
    duid_extract_mac,
    is_laa,
    normalize_hostname,
    protected_magic_from_state,
    purge_released_ip,
    query_kea_leases,
    query_kea_leases_by_hostname,
    query_kea_reservations,
    read_d2_reverse_zones,
    read_host_entries,
    read_magic_state,
    reverse_ptr,
    setup_logging,
    unbound_control,
    unbound_list_local_data,
    unbound_local_datas_batch,
    unbound_mutation_lock,
    write_magic_state,
)


# ── record tuple type ────────────────────────────────────────────────────────
# (hostname, ip, record_type, ttl_or_none)
_Record = Tuple[str, str, str, Optional[int]]


# ── core collision + write logic ─────────────────────────────────────────────

def _best_identifier(entry: Dict) -> Tuple[str, str]:
    """Return (id_type, id_value) for a reservation or lease dict using Kea's priority order."""
    if entry.get("hw_address"):
        return "hw-address", entry["hw_address"]
    if entry.get("duid"):
        return "duid", entry["duid"]
    if entry.get("circuit_id"):
        return "circuit-id", entry["circuit_id"]
    if entry.get("client_id"):
        return "client-id", entry["client_id"]
    ip = entry.get("ip") or entry.get("ipv6") or ""
    return "ip", ip


def _magic_prepass(
    records: List[_Record],
    raw_entries: List[Dict],
    host_entries: Dict,
    laa_tag: bool,
    logger,
) -> Dict[str, str]:
    """Detect hostname collisions and compute magic FQDNs for all collision groups.

    Returns {ip: qualified_magic_fqdn} for every IP in a collision group.
    raw_entries must be parallel to records (same order, same length), carrying
    the full reservation/lease dict so we can extract the hardware identifier.

    Hostnames in records are qualified FQDNs (e.g. 'laptop.home.lan'). We group
    by the full lowercased FQDN so that 'printer.floor1.lan' and 'printer.floor2.lan'
    are treated as distinct names, not a single collision. compute_magic_names works
    on the bare first label; the domain suffix is stripped before that call and
    reattached after, producing 'laptop-mAABBCC.home.lan'.
    """
    from collections import defaultdict
    # Group by full lowercased FQDN; track existing bare labels for squatting check.
    groups: Dict[str, List[Dict]] = defaultdict(list)
    existing_bare: Set[str] = set()
    for (hostname, ip, _rt, _ttl), raw in zip(records, raw_entries):
        if normalize_hostname(hostname) is None or is_in_host_entries(hostname, host_entries):
            continue
        dot = hostname.find(".")
        bare = hostname[:dot] if dot != -1 else hostname
        domain = hostname[dot:] if dot != -1 else ""   # ".home.lan" or ""
        existing_bare.add(bare.lower())
        id_type, id_value = _best_identifier(raw)
        groups[hostname.lower()].append({
            "hostname": bare,
            "ip": ip,
            "id_type": id_type,
            "id_value": id_value,
            "_domain": domain,
        })

    magic_fqdns: Dict[str, str] = {}
    for fqdn_key, entries in groups.items():
        unique_ips = {e["ip"] for e in entries}
        if len(unique_ips) < 2:
            continue
        # compute_magic_names works on bare labels; returns {ip: bare_magic_label}
        group_result = compute_magic_names(entries, laa_tag, existing_bare, logger)
        # All entries share fqdn_key so the domain suffix is provably uniform.
        domain = entries[0].get("_domain", "")
        for ip, magic_label in group_result.items():
            magic_fqdns[ip] = magic_label + domain   # "laptop-mAABBCC.home.lan"

    return magic_fqdns


def _accumulate_magic_state(
    magic_fqdns: Dict[str, str],
    raw_entries: List[Dict],
    records: List[_Record],
    source: str,
    state: Dict[str, list],
) -> None:
    """Populate the magic state dict with entries for this pass.

    state is mutated in-place: {fqdn: [{ip, magic_fqdn, id_type, id_tail, laa, source}]}.
    Only IPs that have a magic FQDN are recorded.
    """
    for (hostname, ip, _rt, _ttl), raw in zip(records, raw_entries):
        if ip not in magic_fqdns:
            continue
        id_type, id_value = _best_identifier(raw)
        if id_type == "hw-address":
            laa = is_laa(id_value)
        elif id_type == "duid":
            _mac = duid_extract_mac(id_value)
            laa = bool(_mac and is_laa(_mac))
        else:
            laa = False
        _TAG_MAP = {"hw-address": "m", "duid": "d", "client-id": "c", "circuit-id": "r", "ip": "i"}
        if id_type == "ip":
            tail = ip_suffix(id_value)
        else:
            tail = identifier_tail(id_value)
        type_tag = _TAG_MAP.get(id_type, "m")
        state.setdefault(hostname.lower(), []).append({
            "ip": ip,
            "magic_fqdn": magic_fqdns[ip],
            "id_type": type_tag,
            "id_tail": tail,
            "laa": laa,
            "source": source,
        })


def _prune_departed_magic(
    old_state: Dict,
    new_state: Dict,
    restrict_keys,
    dry_run: bool,
    logger,
) -> None:
    """Remove Unbound local_data for magic FQDNs that left old_state vs new_state.

    restrict_keys=None  — full sync: authoritative for all old keys.
    restrict_keys=<set> — targeted drain: only touch these FQDN keys;
                          skip all others (they are not our drain's responsibility).

    Prune is keyed on magic FQDN survival, not IP: a device that keeps its magic
    name but renews into a new IP should NOT have its magic FQDN removed.
    """
    surviving = {e["magic_fqdn"]
                 for entries in new_state.values() for e in entries}
    for hostname_key, old_entries in old_state.get("magic_names", {}).items():
        if restrict_keys is not None and hostname_key not in restrict_keys:
            continue
        for old_entry in old_entries:
            magic_fqdn = old_entry["magic_fqdn"]
            if magic_fqdn not in surviving:
                logger.info("[magic] removing departed magic name: %s", magic_fqdn)
                if not dry_run:
                    unbound_control(["local_data_remove", magic_fqdn])


def _collect_writes(
    records: List[_Record],
    rtype: str,
    host_entries: Dict,
    policy: str,
    synthesize_ptr: bool,
    unbound_fwd: Dict[str, Set[str]],
    prior_claim_keys: Set[str],
    logger,
    allow_multi_ip: bool = False,
    magic_fqdns: Optional[Dict[str, str]] = None,
    write_magic_ptrs: bool = False,
) -> Tuple[List[str], List[str], Set[str], int, int]:
    """Compute the unbound-control adds + removes for ONE pass (one rtype).

    Returns (to_add, to_remove, won_keys, n_added, n_skipped). Pure: no
    unbound-control calls; the caller executes the results.

    Two phases so conflict resolution and dedup finish BEFORE any write is
    emitted (a single record-set per FQDN goes out, never an add-then-remove
    race within the same batch):

      Phase 1 -- filter (sanity / host_entries / prior_claim_keys) then resolve a
                 SINGLE winner per FQDN under the policy (or ALL IPs when
                 allow_multi_ip=True, for multi-address static reservations).
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
      allow_multi_ip    When True, multiple IPs for the same hostname are all
                        emitted rather than resolved to one winner. Used for the
                        static reservation pass where a single DHCPv6 reservation
                        can legitimately carry multiple addresses.
      magic_fqdns       {ip -> magic_hostname} for IPs in collision groups. When
                        set, each winner also gets a parallel magic A/AAAA record.
      write_magic_ptrs  When True (dynamic pass with magic_names enabled), PTR
                        points to the magic FQDN for IPs in a collision group.
                        When False, PTR always points to the bare hostname (for
                        winners) or is omitted (for losers). Static passes always
                        pass False regardless of user config.

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
        # Emit parallel magic A record if this IP is in a collision group.
        # Pre-remove when Unbound holds a stale IP for this magic name so old
        # and new IPs don't accumulate; skip when already correct (idempotent).
        if magic_fqdns and ip in magic_fqdns:
            magic_name = magic_fqdns[ip]
            existing_magic = unbound_fwd.get(magic_name.lower())
            if existing_magic is not None and existing_magic != {ip}:
                to_remove.append(magic_name)
            to_add.append(f"{magic_name}{ttl_part} IN {rtype} {ip}")
        # PTR target: magic FQDN when write_magic_ptrs is on and this IP is in a
        # collision group; bare hostname otherwise. Always clear the arpa slot first
        # so Unbound never accumulates stale targets from a previous hostname at
        # this IP (IP reassignment without a DELETE NCR). to_remove runs before
        # to_add in _execute_writes so the remove-then-add is safe within a batch.
        if synthesize_ptr:
            ptr = reverse_ptr(ip)
            if ptr and not is_in_host_entries(ip, host_entries):
                ptr_target = (magic_fqdns[ip]
                              if write_magic_ptrs and magic_fqdns and ip in magic_fqdns
                              else hostname)
                to_remove.append(ptr)
                to_add.append(f"{ptr}{ttl_part} IN PTR {ptr_target}.")

    # allow: additive, no dedup.
    if policy == "allow":
        for hostname, ip, _rt, ttl in records:
            if normalize_hostname(hostname, logger) is None:
                n_skipped += 1
                continue
            if is_in_host_entries(hostname, host_entries):
                n_skipped += 1
                continue
            _emit_add(hostname, ip, ttl)
        return to_add, to_remove, won_keys, n_added, n_skipped

    # first_wins / last_wins / none: Phase 1 -- resolve winner(s) per FQDN.
    # allow_multi_ip: collect all IPs per key (multi-address static reservation).
    # otherwise: resolve a single winner under the collision policy.
    winners_multi: Dict[str, List[Tuple[str, str, Optional[int]]]] = {}
    winners: Dict[str, Tuple[str, str, Optional[int]]] = {}
    collided_keys: Set[str] = set()  # keys that had >1 candidate (for none policy)
    # All loser (hostname, ip, ttl) per key — needed to emit their magic records.
    loser_ips_by_key: Dict[str, List[Tuple[str, str, Optional[int]]]] = {}
    order: List[str] = []  # first-seen key order, for deterministic emit
    for hostname, ip, _rt, ttl in records:
        key = hostname.lower()
        if normalize_hostname(hostname, logger) is None:
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
        if allow_multi_ip:
            if key not in winners_multi:
                winners_multi[key] = []
                order.append(key)
            winners_multi[key].append((hostname, ip, ttl))
        else:
            if key not in winners:
                winners[key] = (hostname, ip, ttl)
                order.append(key)
            elif policy == "last_wins":
                logger.info("Collision last_wins: %s -> %s (was %s)",
                            hostname, ip, winners[key][1])
                # Old winner becomes a loser; track it for magic emit.
                loser_ips_by_key.setdefault(key, []).append(winners[key])
                winners[key] = (hostname, ip, ttl)
                collided_keys.add(key)
                n_skipped += 1
            elif policy == "none":
                logger.info("Collision none: evicting %s (conflict: %s vs %s)",
                            hostname, winners[key][1], ip)
                # On first collision, also move the initial entry to losers.
                if key not in collided_keys:
                    loser_ips_by_key.setdefault(key, []).append(winners[key])
                loser_ips_by_key.setdefault(key, []).append((hostname, ip, ttl))
                collided_keys.add(key)
                n_skipped += 1
            else:  # first_wins: keep the earliest-seen (lowest cltt)
                logger.info("Collision first_wins: %s keeps %s, skips %s",
                            hostname, winners[key][1], ip)
                loser_ips_by_key.setdefault(key, []).append((hostname, ip, ttl))
                collided_keys.add(key)
                n_skipped += 1

    # Phase 2 -- emit. Replace only when Unbound's current set for this name
    # differs from exactly the winner set; otherwise the add alone is idempotent.
    if allow_multi_ip:
        for key in order:
            entries = winners_multi[key]
            new_ips = {e[1] for e in entries}
            existing = unbound_fwd.get(key, set())
            if existing and existing != new_ips:
                to_remove.append(entries[0][0])
                if synthesize_ptr:
                    for old_ip in existing - new_ips:
                        ptr = reverse_ptr(old_ip)
                        if ptr:
                            to_remove.append(ptr)
            for hostname, ip, ttl in entries:
                _emit_add(hostname, ip, ttl)
            won_keys.add(key)
    else:
        for key in order:
            hostname, ip, ttl = winners[key]
            existing = unbound_fwd.get(key, set())
            if policy == "none" and key in collided_keys:
                # No dynamic lease wins the bare hostname. Remove any existing record.
                if existing:
                    logger.info("none policy: removing existing record for %s", hostname)
                    to_remove.append(hostname)
                    if synthesize_ptr:
                        for old_ip in existing:
                            ptr = reverse_ptr(old_ip)
                            if ptr:
                                to_remove.append(ptr)
                n_skipped += 1
                # Emit magic records for every IP in this evicted group.
                if magic_fqdns:
                    for _lhn, lip, lttl in loser_ips_by_key.get(key, []):
                        if lip in magic_fqdns:
                            mname = magic_fqdns[lip]
                            tp = f" {lttl}" if lttl is not None else ""
                            existing_magic = unbound_fwd.get(mname.lower())
                            if existing_magic is not None and existing_magic != {lip}:
                                to_remove.append(mname)
                            to_add.append(f"{mname}{tp} IN {rtype} {lip}")
                            if write_magic_ptrs and synthesize_ptr and not is_in_host_entries(lip, host_entries):
                                ptr = reverse_ptr(lip)
                                if ptr:
                                    to_add.append(f"{ptr}{tp} IN PTR {mname}.")
                continue
            if existing and existing != {ip}:
                to_remove.append(hostname)
                if synthesize_ptr:
                    for old_ip in existing - {ip}:
                        ptr = reverse_ptr(old_ip)
                        if ptr:
                            to_remove.append(ptr)
            _emit_add(hostname, ip, ttl)
            # Emit magic records for loser IPs — _emit_add only covers the winner.
            if magic_fqdns:
                for _lhn, lip, lttl in loser_ips_by_key.get(key, []):
                    if lip in magic_fqdns:
                        mname = magic_fqdns[lip]
                        tp = f" {lttl}" if lttl is not None else ""
                        existing_magic = unbound_fwd.get(mname.lower())
                        if existing_magic is not None and existing_magic != {lip}:
                            to_remove.append(mname)
                        to_add.append(f"{mname}{tp} IN {rtype} {lip}")
                        if write_magic_ptrs and synthesize_ptr and not is_in_host_entries(lip, host_entries):
                            ptr = reverse_ptr(lip)
                            if ptr:
                                to_add.append(f"{ptr}{tp} IN PTR {mname}.")
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
    magic_names: bool = False,
    laa_tag: bool = False,
) -> Tuple[_Claims, int, int, int, Dict[str, list]]:
    """Sync Kea static reservations. Returns (claims, added, skipped, errors, magic_state_entries).

    claims is family-scoped (so the dynamic pass blocks leases only in the same
    family). Reservations never block each other across families: each
    service's pass runs with an empty prior-claim set.

    magic_state_entries is a dict of {fqdn: [{ip, magic_fqdn, id_type, id_tail, laa, source}]}
    for all magic names written during this pass. Merged into the full state file by the caller.
    """
    all_to_add: List[str] = []
    all_to_remove: List[str] = []
    claims = _empty_claims()
    total_added = total_skipped = total_errors = 0
    magic_state_entries: Dict[str, list] = {}

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
        raw_entries: List[Dict] = []
        for res in reservations:
            hostname = res["hostname"]
            ip = res["ip"] if service == "dhcp4" else res["ipv6"]
            if hostname and ip:
                records.append((hostname, ip, rtype, None))
                raw_entries.append(res)

        magic_fqdns: Dict[str, str] = {}
        if magic_names and records:
            magic_fqdns = _magic_prepass(records, raw_entries, host_entries, laa_tag, logger)
            _accumulate_magic_state(magic_fqdns, raw_entries, records,
                                    "static", magic_state_entries)

        to_add, to_remove, won, n_added, n_skipped = _collect_writes(
            records, rtype, host_entries, policy, synthesize_ptr,
            unbound_fwd, set(), logger, allow_multi_ip=True,
            magic_fqdns=magic_fqdns, write_magic_ptrs=False,
        )
        all_to_add.extend(to_add)
        all_to_remove.extend(to_remove)
        claims[rtype] |= won
        total_added += n_added
        total_skipped += n_skipped

    total_errors += _execute_writes(all_to_remove, all_to_add, dry_run, logger)
    logger.info("static: added=%d skipped=%d errors=%d",
                total_added, total_skipped, total_errors)
    return claims, total_added, total_skipped, total_errors, magic_state_entries


# ── dynamic pass ─────────────────────────────────────────────────────────────

def sync_full(
    host_entries: Dict,
    policy: str,
    synthesize_ptr: bool,
    unbound_snapshot: Dict,
    claims: _Claims,
    names_filter: Optional[FrozenSet[str]],
    dry_run: bool,
    logger,
    magic_names: bool = False,
    laa_tag: bool = False,
    write_magic_ptrs: bool = False,
) -> Tuple[int, int, int, Dict[str, list]]:
    """Sync Kea active leases. Returns (added, skipped, errors, magic_state_entries).

    Only ever called from full mode, after sync_static — so `claims` (the
    family-scoped reservation FQDNs that beat leases) is always populated. There
    is no dynamic-only mode, so no need to rebuild reservation claims here.
    """
    import time as _time
    now = int(_time.time())

    all_to_add: List[str] = []
    all_to_remove: List[str] = []
    total_added = total_skipped = total_errors = 0
    magic_state_entries: Dict[str, list] = {}

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
        raw_entries: List[Dict] = []
        for lease in leases:
            hostname = lease["hostname"]
            ip = lease["ip"] if service == "dhcp4" else lease["ipv6"]
            if hostname and ip:
                ttl = max(1, lease["expires"] - now)
                records.append((hostname, ip, rtype, ttl))
                raw_entries.append(lease)

        magic_fqdns: Dict[str, str] = {}
        if magic_names and records:
            magic_fqdns = _magic_prepass(records, raw_entries, host_entries, laa_tag, logger)
            _accumulate_magic_state(magic_fqdns, raw_entries, records,
                                    "lease", magic_state_entries)

        to_add, to_remove, _, n_added, n_skipped = _collect_writes(
            records, rtype, host_entries, policy, synthesize_ptr,
            unbound_fwd, claims.get(rtype, set()), logger,
            magic_fqdns=magic_fqdns, write_magic_ptrs=write_magic_ptrs,
        )
        all_to_add.extend(to_add)
        all_to_remove.extend(to_remove)
        total_added += n_added
        total_skipped += n_skipped

    total_errors += _execute_writes(all_to_remove, all_to_add, dry_run, logger)
    logger.info("dynamic: added=%d skipped=%d errors=%d",
                total_added, total_skipped, total_errors)
    return total_added, total_skipped, total_errors, magic_state_entries


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--static-only", action="store_true",
                            help="Sync static reservations only; skip active leases")
    mode_group.add_argument("--clean-stale", action="store_true",
                            help="After the full sync, sweep and remove records no "
                                 "longer backed by any Kea reservation or lease")
    parser.add_argument("--names",
                        help="Comma-separated hostnames for targeted dynamic drain "
                             "(filters the dynamic pass in full mode)")
    parser.add_argument("--purge-ip",
                        help="Comma-separated IPs to purge-release inside the "
                             "mutation lock after the sync pass (deferred DELETE "
                             "recovery path; called by the daemon drain)")
    parser.add_argument("--collision-policy", default="last_wins",
                        choices=["allow", "last_wins", "first_wins", "none"],
                        help="Collision resolution policy (default: last_wins)")
    parser.add_argument("--magic-names", action="store_true", default=False,
                        help="Enable magic hostname collision disambiguation")
    parser.add_argument("--laa-tag", action="store_true", default=False,
                        help="Apply LAA suffix detection to magic hostnames")
    parser.add_argument("--write-magic-ptrs", action="store_true", default=False,
                        help="Write PTR records pointing to magic FQDNs for "
                             "collision-group IPs (overrides keaubnd.json; "
                             "only meaningful with --magic-names)")
    parser.add_argument("--no-synthesize-ptr", action="store_true", default=False,
                        help="Disable PTR synthesis from forward records")
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="Log what would be done; make no changes")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Also write log lines to stderr")
    args = parser.parse_args()

    names_filter: Optional[FrozenSet[str]] = None
    if args.names:
        names_filter = frozenset(n.strip() for n in args.names.split(",") if n.strip())

    logger = setup_logging(args.verbose)
    mode = "static" if args.static_only else "full"
    logger.info("kea-sync mode=%s names=%s clean_stale=%s dry_run=%s",
                mode, "all" if names_filter is None else len(names_filter),
                args.clean_stale, args.dry_run)

    host_entries = read_host_entries()
    policy = args.collision_policy
    synthesize_ptr = not args.no_synthesize_ptr
    magic = args.magic_names
    laa_tag = args.laa_tag if magic else False
    write_magic_ptrs = (args.write_magic_ptrs or _rt.get_write_magic_ptrs()) if magic and synthesize_ptr else False

    # Preflight: Unbound's control channel must be reachable, or every write
    # below would fail one by one. Fail fast and loud instead. (`status` is a
    # read-only no-op; a connection refusal means Unbound is down/restarting.)
    if not args.dry_run and not unbound_control(["status"]):
        logger.error("unbound-control unavailable — aborting (Unbound down?)")
        return 1

    try:
        with unbound_mutation_lock(blocking=True):
            # Snapshot Unbound once before any writes (collision checks + stale sweep).
            # Always fetch when --clean-stale is set even if policy is 'allow'
            # (allow mode skips the snapshot for the sync pass, but the stale sweep
            # needs the real local_data regardless of collision policy).
            unbound_snapshot = (unbound_list_local_data()
                                if policy != "allow" or args.clean_stale else {})

            # Load existing magic state so we can detect departed entries later.
            old_magic_state = read_magic_state() if magic else {}
            new_magic_state: Dict[str, list] = {}

            total_errors = 0

            # Both modes run static. Full then runs dynamic with static's claims,
            # so reservations are always known before leases are resolved.
            claims, _, _, errs, static_magic = sync_static(
                host_entries, policy, synthesize_ptr,
                unbound_snapshot, args.dry_run, logger,
                magic_names=magic, laa_tag=laa_tag,
            )
            total_errors += errs
            for k, v in static_magic.items():
                new_magic_state.setdefault(k, []).extend(v)

            if mode == "full":
                _, _, errs, dyn_magic = sync_full(
                    host_entries, policy, synthesize_ptr,
                    unbound_snapshot, claims, names_filter,
                    args.dry_run, logger,
                    magic_names=magic, laa_tag=laa_tag,
                    write_magic_ptrs=write_magic_ptrs,
                )
                total_errors += errs
                for k, v in dyn_magic.items():
                    new_magic_state.setdefault(k, []).extend(v)

            # Remove magic FQDNs that were in the old state but not the new state
            # (departed devices whose collision has resolved).
            if magic and old_magic_state.get("magic_names"):
                if names_filter is None:
                    # Full sync: authoritative for all old keys.
                    _prune_departed_magic(old_magic_state, new_magic_state,
                                         None, args.dry_run, logger)
                else:
                    # Targeted drain: only prune magic for the drained FQDN keys.
                    # Other hosts' magic records are not this drain's concern
                    # — they are covered by the next full sync / clean-stale cron.
                    drained_keys = frozenset(n.lower() for n in names_filter)
                    _prune_departed_magic(old_magic_state, new_magic_state,
                                         drained_keys, args.dry_run, logger)

            # Write updated magic state file (inside the mutation lock).
            if magic and not args.dry_run:
                if names_filter is None:
                    # Full sync: write the complete new state.
                    write_magic_state({"magic_names": new_magic_state})
                else:
                    # Targeted drain: merge the drained hosts' new entries into the
                    # existing state; leave every other host's entries untouched.
                    drained_keys = frozenset(n.lower() for n in names_filter)
                    merged = dict(old_magic_state.get("magic_names", {}))
                    for k in drained_keys:
                        if k in new_magic_state:
                            merged[k] = new_magic_state[k]
                        else:
                            merged.pop(k, None)
                    write_magic_state({"magic_names": merged})

            # Purge-release pass: remove Unbound records for IPs whose DELETE NCR
            # was deferred due to lock contention. Runs inside the same mutation
            # lock hold as the sync so no interleaving is possible. Each IP is
            # purged independently (best-effort); errors are logged but do not
            # increment total_errors (consistent with clean_ip's return-0 contract).
            if args.purge_ip and not args.dry_run:
                purge_ips = frozenset(
                    p.strip() for p in args.purge_ip.split(",") if p.strip()
                )
                purge_data = unbound_list_local_data()
                purge_host_entries = read_host_entries()
                for ip in sorted(purge_ips):
                    purge_released_ip(ip, purge_data, purge_host_entries, logger)

            if args.clean_stale:
                # Re-read Unbound after the sync so the restore-valid pass in
                # clean_stale_records sees the actual current state, not the
                # pre-sync snapshot (which predates collision-handling removes).
                current_data = unbound_list_local_data() if not args.dry_run else unbound_snapshot
                kea_pairs = collect_kea_pairs(logger)
                # Magic state was written above (when magic=True); read it back so
                # protected_magic_from_state applies source-based filtering (lease
                # magic names are only protected while their backing lease is active).
                # When magic=False, any magic state on disk from a previous run is
                # still read and handled correctly.
                protected_magic = protected_magic_from_state(
                    read_magic_state(), kea_pairs, logger)
                stale_pairs, orphaned_ptrs = find_stale_records(
                    current_data, kea_pairs, host_entries, synthesize_ptr,
                    d2_reverse_zones=read_d2_reverse_zones(),
                    protected_magic_fqdns=protected_magic,
                )
                if stale_pairs or orphaned_ptrs:
                    logger.info("clean-stale: %d stale address(es), %d orphaned PTR(s)",
                                len(stale_pairs), len(orphaned_ptrs))
                errs = clean_stale_records(
                    current_data, stale_pairs, orphaned_ptrs, args.dry_run, logger,
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
