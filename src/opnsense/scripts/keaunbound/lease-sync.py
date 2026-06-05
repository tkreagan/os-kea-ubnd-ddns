#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
lease-sync.py -- Register Kea active leases in Unbound.

Queries Kea for all currently active leases and registers them in Unbound's
local_data store with TTL matching the lease expiration time. Skips any that
already exist in host_entries.conf (which are managed by OPNsense directly).

For each lease:
  - Add A/AAAA record with TTL = remaining lease lifetime
  - Add corresponding PTR record

Used to:
  - Repopulate Unbound after startup (via keaunbound_lease_sync hook)
  - Restore dynamic entries after an Unbound reload wipes local_data

Usage:
  lease-sync.py [--dry-run] [--verbose]
"""

import argparse
import sys
import time

# Add parent directory to path so we can import lib
sys.path.insert(0, "/usr/local/opnsense/scripts/keaunbound")

from lib.keaunbound_sync import (
    KeaUnavailableError,
    KeaServiceUnavailableError,
    query_kea_leases,
    read_host_entries,
    reverse_ptr,
    unbound_control,
    is_in_host_entries,
    is_sane_name,
    setup_logging,
)

def sync_leases(dry_run: bool = False, verbose: bool = False) -> int:
    """
    Sync all active Kea leases to Unbound.
    Returns 0 on success, non-zero on error.
    """
    logger = setup_logging(verbose)
    logger.info("Starting lease sync")

    host_entries = read_host_entries()
    added = 0
    skipped = 0
    errors = 0
    now = int(time.time())

    try:
        # Query both IPv4 and IPv6 leases
        for service in ["dhcp4", "dhcp6"]:
            leases = None
            for _attempt in range(3):
                try:
                    leases = query_kea_leases(service=service)
                    break
                except KeaServiceUnavailableError as e:
                    logger.debug(f"Skipping {service}: {e}")
                    break
                except KeaUnavailableError as e:
                    if _attempt < 2:
                        logger.debug(f"Kea not ready for {service}, retrying in 5s: {e}")
                        time.sleep(5)
                        continue
                    logger.warning(f"Kea unavailable for {service}: {e}")
                    errors += 1
            if leases is None:
                continue

            for lease in leases:
                hostname = lease["hostname"]
                ip = lease["ip"] if service == "dhcp4" else lease["ipv6"]
                expires = lease["expires"]

                if not hostname or not ip:
                    continue

                # Skip implausible hostnames (same hygiene as the live listener)
                if not is_sane_name(hostname, logger):
                    skipped += 1
                    continue

                # Skip if in host_entries.conf (OPNsense manages it)
                if is_in_host_entries(hostname, host_entries):
                    logger.debug(f"Skipping {hostname} — in host_entries.conf")
                    skipped += 1
                    continue

                # Calculate TTL as remaining lease lifetime
                ttl = max(1, expires - now)  # At least 1 second

                # Add A/AAAA record
                record_type = "A" if service == "dhcp4" else "AAAA"
                record = f"{hostname} {ttl} IN {record_type} {ip}"

                if dry_run:
                    logger.info(f"[dry-run] would add: local_data {record}")
                else:
                    if unbound_control(["local_data", record]):
                        logger.info(f"Added {record_type}: {hostname} -> {ip} (TTL {ttl}s)")
                        added += 1
                    else:
                        logger.error(f"Failed to add {record_type}: {hostname}")
                        errors += 1

                # Add PTR record (unless already in host_entries)
                ptr_name = reverse_ptr(ip)
                if ptr_name and not is_in_host_entries(ptr_name, host_entries):
                    ptr_record = f"{ptr_name} {ttl} IN PTR {hostname}."

                    if dry_run:
                        logger.info(f"[dry-run] would add: local_data {ptr_record}")
                    else:
                        if unbound_control(["local_data", ptr_record]):
                            logger.info(f"Added PTR: {ptr_name} -> {hostname} (TTL {ttl}s)")
                            added += 1
                        else:
                            logger.error(f"Failed to add PTR: {ptr_name}")
                            errors += 1

        logger.info(f"Lease sync complete: added={added} skipped={skipped} errors={errors}")
        return 0 if errors == 0 else 1

    except Exception as e:
        logger.error(f"Lease sync failed: {e}")
        return 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="Log what would be done without making changes")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Log additional details to stderr")
    args = parser.parse_args()

    return sync_leases(dry_run=args.dry_run, verbose=args.verbose)

if __name__ == "__main__":
    sys.exit(main())
