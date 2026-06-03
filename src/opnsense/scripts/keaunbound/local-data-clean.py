#!/usr/local/bin/python3
"""
local-data-clean.py -- Remove stale records from Unbound local_data.

Identifies stale records (in local_data but not backed by any Kea reservation
or active lease, and not OPNsense-managed) plus orphaned PTRs, removes them,
and reports results.

Stale/orphan detection lives in keaunbound_sync.find_stale_records(), the same
function the audit uses — so the Lease Audit "stale"/orphaned rows are exactly
what this script removes.

Designed to be called by cron (default mode) or from the GUI via the
[clean] configd action. Use --dry-run to preview, or --confirm for an
interactive prompt (manual debugging only — never under configd).

Usage:
  local-data-clean.py                     # Remove stale records (cron-friendly)
  local-data-clean.py --dry-run           # Preview without removing
  local-data-clean.py --confirm           # Prompt before removing (interactive)
"""

import argparse
import sys

# Add parent directory to path so we can import lib
sys.path.insert(0, "/usr/local/opnsense/scripts/keaunbound")

from lib.keaunbound_sync import (
    KeaUnavailableError,
    read_host_entries,
    unbound_list_local_data,
    unbound_control,
    collect_kea_ips,
    find_stale_records,
    setup_logging,
)


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
        kea_ips = collect_kea_ips()
    except KeaUnavailableError as e:
        logger.error(f"Kea unavailable: {e}")
        logger.error("Cannot safely identify stale records without Kea data — aborting")
        return 1

    stale_names, orphaned_ptrs = find_stale_records(unbound_data, kea_ips, host_entries)

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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", action="store_true",
                        help="Interactive mode: prompt before removing (manual debugging only)")
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="Preview what would be removed without making changes")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Log additional details to stderr")
    args = parser.parse_args()

    return clean_stale_records(interactive=args.confirm, dry_run=args.dry_run, verbose=args.verbose)


if __name__ == "__main__":
    sys.exit(main())
