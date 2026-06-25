#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
local-data-clean.py -- Remove stale records from Unbound local_data.

NOTE: This script is designed for the OPNsense environment and has two
hard dependencies that will not be present on a generic system:
  1. /usr/local/sbin/unbound-control (Unbound's control utility)
  2. /var/unbound/host_entries.conf   (written by OPNsense to track its
     own managed entries; required for the static-entry guard)
  3. Kea DHCP control socket(s) readable by the scripts user
     (resolved automatically via kea_transport / config.xml)
Running outside OPNsense will fail or produce incorrect results.

Two modes:

  Bulk mode (default): identify ALL stale records in Unbound — entries not
  backed by any Kea reservation, active lease, or OPNsense-managed host
  override — and remove them. Stale/orphan detection uses
  keaubnd_sync.find_stale_records(), the same function the Lease Audit
  tab uses, so the "stale"/"orphaned" rows shown there are exactly what this
  script removes. Designed for cron and GUI (the [clean] configd action).

  Targeted mode (--hostname): remove only IPs for one specific hostname that
  are no longer in Kea. Leaves all other hostnames untouched. Available for
  manual/scripted use; not called by the daemon (which handles IP replacement
  inline via last_wins collision policy).

Usage:
  local-data-clean.py                            # Bulk: remove all stale records
  local-data-clean.py --dry-run                  # Bulk: preview without removing
  local-data-clean.py --confirm                  # Bulk: prompt before removing
  local-data-clean.py --hostname HOST            # Targeted: clean one hostname
  local-data-clean.py --hostname HOST --keep-ip IP  # Targeted: always preserve IP
  local-data-clean.py --purge-ip IP              # IP-targeted: clean one released IP
"""

import argparse
import sys
from typing import Optional

# Add parent directory to path so we can import lib
sys.path.insert(0, "/usr/local/opnsense/scripts/keaubnd")

from lib.keaubnd_sync import (
    KeaUnavailableError,
    KeaServiceUnavailableError,
    clean_stale_records,
    discover_stale,
    is_in_host_entries,
    kea_ips_for_hostname,
    purge_released_ip,
    query_kea_leases,
    query_kea_reservations,
    read_host_entries,
    reverse_ptr,
    setup_logging,
    unbound_control,
    unbound_list_local_data,
    unbound_local_datas_batch,
    unbound_mutation_lock,
)


def _kea_ips_for_hostname(hostname: str, logger) -> Optional[set]:
    """Thin wrapper around the shared keaubnd_sync.kea_ips_for_hostname."""
    return kea_ips_for_hostname(hostname, logger)


def clean_host(hostname: str, keep_ip: Optional[str] = None,
               verbose: bool = False) -> int:
    """
    Targeted cleanup: remove IPs for one hostname that are no longer in Kea.

    Handles the case where a client received a new IP without Kea sending a
    DNS DELETE for the old one. Available for manual/scripted use via
    --hostname; the daemon handles same-FQDN replacement inline.

    hostname: FQDN to clean (trailing dot optional).
    keep_ip:  always treat this IP as valid even if not yet in Kea's lease DB
              (e.g. pass the just-added IP to avoid an immediate self-removal).

    Returns 0 always. Errors are logged; cleanup is best-effort.
    """
    logger = setup_logging(verbose)
    hn = hostname.rstrip(".")
    logger.info("[cleanup] Checking %s for stale IPs", hn)

    # Belt and suspenders: never touch a hostname managed by OPNsense via
    # host_entries.conf. The daemon's ADD guard should already have skipped
    # static entries before calling us, but local_data_remove affects BOTH
    # runtime-added entries AND config-file-sourced entries in Unbound's
    # in-memory local zone — so an accidental removal would take the record
    # offline until the next Unbound reload. Guard explicitly here so this
    # function is safe regardless of its call site.
    host_entries = read_host_entries()
    if is_in_host_entries(hn, host_entries):
        logger.info("[cleanup] %s is in host_entries.conf — skipping", hn)
        return 0

    # Query Kea for the IPs this hostname legitimately holds right now.
    valid_ips = _kea_ips_for_hostname(hn, logger)
    if valid_ips is None:
        # Kea unreachable — abort rather than risk removing active records.
        logger.warning("[cleanup] Aborting cleanup for %s — Kea unavailable", hn)
        return 0

    # Always keep the IP we just added. Kea's lease DB may not have fully
    # committed the new binding by the time we query, so this prevents us
    # from immediately re-removing the record we just registered.
    if keep_ip:
        valid_ips.add(keep_ip)

    # Get what Unbound currently has for this hostname.
    unbound_data = unbound_list_local_data()
    ub_lines = unbound_data.get(hn, [])

    # Parse current A/AAAA records and their TTLs.
    ub_records = []  # list of (ip, ttl, rdtype)
    for line in ub_lines:
        parts = line.split()
        if len(parts) >= 5 and parts[3] in ("A", "AAAA"):
            ub_records.append((parts[4], parts[1], parts[3]))

    ub_ips = {ip for ip, _, _ in ub_records}
    stale_ips = ub_ips - valid_ips

    if not stale_ips:
        logger.info("[cleanup] No stale IPs for %s", hn)
        return 0

    # Safety: only proceed if there are valid records to re-add after the
    # remove-all step. In the ADD path keep_ip guarantees at least one, but
    # guard anyway so this function is safe if called from other contexts.
    valid_records = [(ip, ttl, rtype) for ip, ttl, rtype in ub_records
                     if ip in valid_ips]
    if not valid_records:
        logger.warning("[cleanup] No valid records to restore for %s — "
                       "refusing to remove all forward records", hn)
        return 0

    logger.info("[cleanup] Removing stale IPs for %s: %s (keeping: %s)",
                hn, sorted(stale_ips),
                [ip for ip, _, _ in valid_records])

    # unbound-control local_data_remove wipes ALL A/AAAA for the name —
    # remove all then re-add only the valid ones with their original TTLs.
    if not unbound_control(["local_data_remove", hn]):
        logger.error("[cleanup] Failed to remove records for %s — aborting", hn)
        return 0

    rrs = [f"{hn} {ttl} IN {rtype} {ip}" for ip, ttl, rtype in valid_records]
    if not unbound_local_datas_batch(rrs):
        logger.error("[cleanup] Failed to re-add records for %s", hn)

    # Remove PTRs for stale IPs — but only if the PTR in Unbound points TO
    # this hostname. A PTR pointing elsewhere is owned by a different hostname
    # and must not be touched.
    for ip in stale_ips:
        ptr_name = reverse_ptr(ip)
        if not ptr_name:
            continue
        ptr_lines = unbound_data.get(ptr_name, [])
        targets = set()
        for line in ptr_lines:
            parts = line.split()
            if len(parts) >= 5 and parts[3] == "PTR":
                targets.add(parts[4].rstrip(".").lower())
        if hn.lower() not in targets:
            continue  # PTR points elsewhere — leave it alone
        # Belt and suspenders: don't remove a PTR managed by OPNsense.
        if is_in_host_entries(ptr_name, host_entries):
            logger.info("[cleanup] PTR %s is static — skipping", ptr_name)
            continue
        logger.info("[cleanup] Removing stale PTR: %s -> %s", ptr_name, hn)
        if not unbound_control(["local_data_remove", ptr_name]):
            logger.error("[cleanup] Failed to remove PTR %s", ptr_name)

    return 0


def clean_ip(ip: str, verbose: bool = False) -> int:
    """IP-targeted cleanup: remove every Unbound record for a released IP.

    Delegates to keaubnd_sync.purge_released_ip, which is also called by
    kea-sync.py's --purge-ip pass.  Returns 0 always (best-effort).
    """
    logger = setup_logging(verbose)
    host_entries = read_host_entries()
    unbound_data = unbound_list_local_data()
    purge_released_ip(ip, unbound_data, host_entries, logger)
    return 0


def _print_stale_summary(stale_pairs, orphaned_ptrs) -> None:
    total = len(stale_pairs) + len(orphaned_ptrs)
    if total == 0:
        print("No stale records found")
        return
    print(f"Found {len(stale_pairs)} stale address(es), {len(orphaned_ptrs)} orphaned PTR(s):")
    print()
    if stale_pairs:
        print(f"Stale addresses ({len(stale_pairs)}):")
        for name, ip in sorted(stale_pairs):
            print(f"  {name} [{ip}]")
    if orphaned_ptrs:
        print(f"Orphaned PTRs ({len(orphaned_ptrs)}):")
        for ptr in sorted(orphaned_ptrs):
            print(f"  {ptr}")
    print()


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    # Targeted mode
    parser.add_argument("--hostname", default=None, metavar="HOSTNAME",
                        help="Targeted mode: remove only stale IPs for this "
                             "hostname. Ignores --confirm and --dry-run.")
    parser.add_argument("--keep-ip", default=None, metavar="IP",
                        help="With --hostname: always treat this IP as valid "
                             "(use when calling immediately after a DDNS ADD "
                             "so the new IP is never removed even if Kea has "
                             "not yet committed the lease).")
    parser.add_argument("--purge-ip", default=None, metavar="IP",
                        help="IP-targeted mode: find and remove all Unbound "
                             "records for one specific released IP address. "
                             "Verifies with Kea that the IP is gone before "
                             "removing. Called by kea-ubnd-logwatch on "
                             "DHCP4_RELEASE / DHCP6_RELEASE log events.")
    # Bulk mode
    parser.add_argument("--confirm", action="store_true",
                        help="Bulk mode: prompt before removing (manual debugging only)")
    parser.add_argument("--no-synthesize-ptr", action="store_true", default=False,
                        help="Treat PTR records as D2-managed; do not synthesize or clean them")
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="Bulk mode: preview what would be removed without making changes")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Log additional details to stderr")
    args = parser.parse_args()
    synthesize_ptr = not args.no_synthesize_ptr

    # Bulk dry-run: discovery only, no lock needed, no writes.
    if args.dry_run and not args.hostname and not args.purge_ip:
        logger = setup_logging(args.verbose)
        logger.info("Starting stale record cleanup (dry run)")
        try:
            _, stale_pairs, orphaned_ptrs = discover_stale(synthesize_ptr, logger)
        except KeaUnavailableError as e:
            logger.error("Kea unavailable: %s", e)
            return 1
        _print_stale_summary(stale_pairs, orphaned_ptrs)
        if stale_pairs or orphaned_ptrs:
            print("[dry-run] Would remove the above records")
        return 0

    try:
        with unbound_mutation_lock(blocking=True):
            if args.purge_ip:
                return clean_ip(ip=args.purge_ip, verbose=args.verbose)
            if args.hostname:
                return clean_host(hostname=args.hostname, keep_ip=args.keep_ip,
                                  verbose=args.verbose)

            # Bulk clean.
            logger = setup_logging(args.verbose)
            logger.info("Starting stale record cleanup")
            try:
                unbound_data, stale_pairs, orphaned_ptrs = discover_stale(
                    synthesize_ptr, logger)
            except KeaUnavailableError as e:
                logger.error("Kea unavailable: %s — aborting", e)
                return 1

            _print_stale_summary(stale_pairs, orphaned_ptrs)
            total = len(stale_pairs) + len(orphaned_ptrs)
            if total == 0:
                return 0

            if args.confirm:
                try:
                    response = input(f"Remove {total} stale record(s)? [y/N] ")
                except EOFError:
                    print("No input available — aborting (use the default mode for unattended runs)")
                    return 0
                if response.lower() != "y":
                    print("Aborted")
                    return 0

            print("Removing stale records...")
            errors = clean_stale_records(unbound_data, stale_pairs, orphaned_ptrs,
                                         dry_run=False, logger=logger)
            logger.info("Cleanup complete: removed=%d errors=%d", total, errors)
            print(f"\nCleanup complete: removed {total}, errors {errors}")
            return 0 if errors == 0 else 1

    except Exception as e:
        setup_logging(args.verbose).error("clean failed acquiring lock: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
