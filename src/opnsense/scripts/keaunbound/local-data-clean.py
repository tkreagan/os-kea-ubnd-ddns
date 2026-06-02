#!/usr/local/bin/python3
"""
local-data-clean.py -- Remove stale records from Unbound local_data.

Identifies stale records (in local_data but not in any Kea source or
host_entries.conf) and orphaned PTRs, then removes them and reports results.

Designed to be called by cron — removes stale records and logs what was cleaned.
Use --dry-run to preview without removing, or --confirm for interactive prompting.

Stale record detection:
  - Records in Unbound local_data that don't match:
    - Any Kea static reservation
    - Any Kea active lease
    - Any entry in host_entries.conf (OPNsense-managed)

Orphaned PTRs:
  - PTR records with no corresponding A/AAAA record

Usage:
  local-data-clean.py                    # Remove stale records (cron-friendly)
  local-data-clean.py --dry-run          # Preview without removing
  local-data-clean.py --confirm --dry-run # Interactive preview with prompts
"""

import argparse
import sys

# Add parent directory to path so we can import lib
sys.path.insert(0, "/usr/local/opnsense/scripts/keaunbound")

from lib.keaunbound_sync import (
    KeaUnavailableError,
    query_kea_reservations,
    query_kea_leases,
    read_host_entries,
    reverse_ptr,
    unbound_list_local_data,
    is_in_host_entries,
    unbound_control,
    setup_logging,
)

def clean_stale_records(interactive: bool = False, dry_run: bool = False, verbose: bool = False) -> int:
    """
    Identify and remove stale records from Unbound local_data.
    Returns 0 on success, non-zero on error.
    """
    logger = setup_logging(verbose)
    logger.info("Starting stale record cleanup")

    # Read static sources
    host_entries = read_host_entries()
    unbound_data = unbound_list_local_data()

    # Try to read dynamic sources from Kea
    kea_ips = set()  # All IPs that Kea knows about

    try:
        for service in ["dhcp4", "dhcp6"]:
            for res in query_kea_reservations(service=service):
                if res["ip"]:
                    kea_ips.add(res["ip"])
                if res["ipv6"]:
                    kea_ips.add(res["ipv6"])

            for lease in query_kea_leases(service=service):
                if lease["ip"]:
                    kea_ips.add(lease["ip"])
                if lease["ipv6"]:
                    kea_ips.add(lease["ipv6"])
    except KeaUnavailableError as e:
        logger.error(f"Kea unavailable: {e}")
        logger.error("Cannot safely identify stale records without Kea data — aborting")
        return 1

    # Identify stale records
    stale_names = set()
    orphaned_ptrs = set()

    for name in unbound_data:
        # Check if this name is in host_entries.conf (OPNsense owns it)
        if is_in_host_entries(name, host_entries):
            continue

        # Check if any IP for this name is in Kea
        has_kea_ip = False
        for line in unbound_data[name]:
            parts = line.split()
            if len(parts) >= 5:
                rdtype = parts[3]
                if rdtype in ("A", "AAAA"):
                    ip = parts[4]
                    if ip in kea_ips:
                        has_kea_ip = True
                        break

        # If no IPs are in Kea, the whole name is stale
        if not has_kea_ip:
            is_ptr = name.endswith(".in-addr.arpa") or name.endswith(".ip6.arpa")
            if is_ptr:
                orphaned_ptrs.add(name)
            else:
                stale_names.add(name)

    # Report findings
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

    # If interactive mode, prompt for confirmation
    if interactive:
        response = input(f"Remove {total_stale} stale record(s)? [y/N] ")
        if response.lower() != 'y':
            print("Aborted")
            return 0

    print("Removing stale records...")

    removed = 0
    errors = 0

    for name in sorted(stale_names | orphaned_ptrs):
        if unbound_control(["local_data_remove", name]):
            logger.info(f"Removed: {name}")
            print(f"  ✓ {name}")
            removed += 1
        else:
            logger.error(f"Failed to remove: {name}")
            print(f"  ✗ {name} (failed)")
            errors += 1

    print()
    logger.info(f"Cleanup complete: removed={removed} errors={errors}")
    print(f"Cleanup complete: removed {removed}, errors {errors}")
    return 0 if errors == 0 else 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", action="store_true",
                        help="Interactive mode: prompt before removing (useful for debugging)")
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="Preview what would be removed without making changes")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Log additional details to stderr")
    args = parser.parse_args()

    return clean_stale_records(interactive=args.confirm, dry_run=args.dry_run, verbose=args.verbose)

if __name__ == "__main__":
    sys.exit(main())
