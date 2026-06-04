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
  keaunbound_sync.find_stale_records(), the same function the Lease Audit
  tab uses, so the "stale"/"orphaned" rows shown there are exactly what this
  script removes. Designed for cron and GUI (the [clean] configd action).

  Targeted mode (--hostname): remove only IPs for one specific hostname that
  are no longer in Kea. Leaves all other hostnames untouched. Called by the
  DDNS listener daemon after a successful ADD when aggressive_cleanup is
  enabled, to clean up old IPs that Kea did not send a DELETE for.

Usage:
  local-data-clean.py                            # Bulk: remove all stale records
  local-data-clean.py --dry-run                  # Bulk: preview without removing
  local-data-clean.py --confirm                  # Bulk: prompt before removing
  local-data-clean.py --hostname HOST            # Targeted: clean one hostname
  local-data-clean.py --hostname HOST --keep-ip IP  # Targeted: always preserve IP
"""

import argparse
import sys
from typing import Optional

# Add parent directory to path so we can import lib
sys.path.insert(0, "/usr/local/opnsense/scripts/keaunbound")

from lib.keaunbound_sync import (
    KeaUnavailableError,
    KeaServiceUnavailableError,
    read_host_entries,
    unbound_list_local_data,
    unbound_control,
    collect_kea_pairs,
    find_stale_records,
    setup_logging,
    query_kea_reservations,
    query_kea_leases,
    reverse_ptr,
    is_in_host_entries,
)


def _kea_ips_for_hostname(hostname: str, logger) -> Optional[set]:
    """
    Query Kea (both dhcp4 and dhcp6, leases and reservations) for all IPs
    currently associated with hostname.

    Returns a set of IP strings (possibly empty if Kea has no record of this
    hostname), or None if Kea is unreachable — callers must treat None as
    "abort cleanup, do not remove anything."

    KeaServiceUnavailableError (service offline / not configured) is silently
    skipped so a DHCPv4-only setup doesn't abort when dhcp6 isn't running.
    KeaUnavailableError (daemon unreachable) aborts the entire query because
    we cannot safely identify stale records without authoritative data.
    """
    hn = hostname.rstrip(".").lower()
    valid_ips: set = set()
    for service in ("dhcp4", "dhcp6"):
        try:
            for res in query_kea_reservations(service=service):
                if res["hostname"].rstrip(".").lower() == hn:
                    for ip in (res.get("ip"), res.get("ipv6")):
                        if ip:
                            valid_ips.add(ip)
            for lease in query_kea_leases(service=service):
                if lease["hostname"].rstrip(".").lower() == hn:
                    for ip in (lease.get("ip"), lease.get("ipv6")):
                        if ip:
                            valid_ips.add(ip)
        except KeaServiceUnavailableError:
            pass  # service not running / not configured — skip it
        except KeaUnavailableError as e:
            logger.warning("[cleanup] Kea unreachable querying %s for %s: %s",
                           service, hostname, e)
            return None  # cannot safely clean without authoritative data
    return valid_ips


def clean_host(hostname: str, keep_ip: Optional[str] = None,
               verbose: bool = False) -> int:
    """
    Targeted cleanup: remove IPs for one hostname that are no longer in Kea.

    Called by the DDNS listener daemon after a successful A/AAAA ADD when
    aggressive_cleanup is enabled. Handles the common case where Kea issues a
    client a new IP without sending a DNS DELETE for the old one.

    hostname: the FQDN just registered (trailing dot optional).
    keep_ip:  always treat this IP as valid, even if not yet committed to
              Kea's lease DB — ensures the just-added IP is never removed.

    Returns 0 always. Errors are logged but cleanup is best-effort; the
    ADD and its DDNS response are unaffected regardless of outcome.

    NOTE: This script requires the OPNsense environment. See module docstring.
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

    for ip, ttl, rtype in valid_records:
        rr = f"{hn} {ttl} IN {rtype} {ip}"
        if not unbound_control(["local_data", rr]):
            logger.error("[cleanup] Failed to re-add %s", rr)

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


def clean_stale_records(interactive: bool = False, dry_run: bool = False, verbose: bool = False) -> int:
    """
    Identify and remove stale records from Unbound local_data.
    Returns 0 on success, non-zero on error.
    """
    logger = setup_logging(verbose)
    logger.info("Starting stale record cleanup")

    host_entries = read_host_entries()
    unbound_data = unbound_list_local_data()

    # Stale detection requires authoritative Kea data; never guess without it.
    try:
        kea_pairs = collect_kea_pairs()
    except KeaUnavailableError as e:
        logger.error(f"Kea unavailable: {e}")
        logger.error("Cannot safely identify stale records without Kea data — aborting")
        return 1

    stale_names, orphaned_ptrs = find_stale_records(unbound_data, kea_pairs, host_entries)

    total_stale = len(stale_names) + len(orphaned_ptrs)

    if total_stale == 0:
        logger.info("No stale records found")
        print("No stale records found")
        return 0

    print(f"Found {total_stale} stale record(s):")
    print()

    if stale_names:
        print(f"Stale hostnames ({len(stale_names)}):")
        for name in sorted(stale_names):
            print(f"  {name}")

    if orphaned_ptrs:
        print(f"Orphaned PTRs ({len(orphaned_ptrs)}):")
        for ptr in sorted(orphaned_ptrs):
            print(f"  {ptr}")

    print()

    if dry_run:
        logger.info(f"[dry-run] Would remove {total_stale} stale record(s)")
        print("[dry-run] Would remove the above records")
        return 0

    # Interactive confirmation (manual use only). Guard against no stdin so a
    # stray --confirm under a non-interactive context fails safe instead of
    # raising EOFError.
    if interactive:
        try:
            response = input(f"Remove {total_stale} stale record(s)? [y/N] ")
        except EOFError:
            print("No input available — aborting (use the default mode for unattended runs)")
            return 0
        if response.lower() != "y":
            print("Aborted")
            return 0

    print("Removing stale records...")

    removed = 0
    errors = 0

    for name in sorted(stale_names | orphaned_ptrs):
        if unbound_control(["local_data_remove", name]):
            logger.info(f"Removed: {name}")
            print(f"  removed {name}")
            removed += 1
        else:
            logger.error(f"Failed to remove: {name}")
            print(f"  FAILED {name}")
            errors += 1

    print()
    logger.info(f"Cleanup complete: removed={removed} errors={errors}")
    print(f"Cleanup complete: removed {removed}, errors {errors}")
    return 0 if errors == 0 else 1


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
    # Bulk mode
    parser.add_argument("--confirm", action="store_true",
                        help="Bulk mode: prompt before removing (manual debugging only)")
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="Bulk mode: preview what would be removed without making changes")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Log additional details to stderr")
    args = parser.parse_args()

    if args.hostname:
        return clean_host(hostname=args.hostname, keep_ip=args.keep_ip,
                          verbose=args.verbose)
    return clean_stale_records(interactive=args.confirm, dry_run=args.dry_run,
                               verbose=args.verbose)


if __name__ == "__main__":
    sys.exit(main())
