#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
reservation-sync.py -- Register Kea static reservations in Unbound.

Queries Kea for all static reservations and registers them in Unbound's
local_data store, skipping any that already exist in host_entries.conf
(which are managed by OPNsense directly).

For each reservation:
  - Add A/AAAA record
  - Add corresponding PTR record (unless already in host_entries.conf)

Respects the is_static_entry guard — if a hostname appears in
host_entries.conf, we don't touch it (OPNsense owns it).

Usage:
  reservation-sync.py [--dry-run] [--verbose]
"""

import argparse
import sys
import time

# Add parent directory to path so we can import lib
sys.path.insert(0, "/usr/local/opnsense/scripts/keaunbound")

from lib.keaunbound_sync import (
    KeaUnavailableError,
    KeaServiceUnavailableError,
    query_kea_reservations,
    read_host_entries,
    reverse_ptr,
    unbound_control,
    unbound_list_local_data,
    is_in_host_entries,
    is_sane_name,
    setup_logging,
    get_synthesize_ptr,
    get_collision_policy,
    _forward_ips,
)

def sync_reservations(dry_run: bool = False, verbose: bool = False,
                      synthesize_ptr: bool = True) -> int:
    """
    Sync all Kea static reservations to Unbound.
    Returns 0 on success, non-zero on error.
    """
    logger = setup_logging(verbose)
    logger.info("Starting reservation sync")

    host_entries = read_host_entries()
    collision_policy = get_collision_policy()
    # Snapshot Unbound state once for collision checks; also track names added
    # during this run so same-FQDN conflicts within the sync are detected.
    unbound_fwd = _forward_ips(unbound_list_local_data()) if collision_policy != "allow" else {}
    added_this_run: dict = {}  # name.lower() -> ip
    added = 0
    skipped = 0
    errors = 0

    try:
        # Query both IPv4 and IPv6 reservations
        for service in ["dhcp4", "dhcp6"]:
            reservations = None
            for _attempt in range(3):
                try:
                    reservations = query_kea_reservations(service=service)
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
            if reservations is None:
                continue

            for res in reservations:
                hostname = res["hostname"]
                ip = res["ip"] if service == "dhcp4" else res["ipv6"]

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

                # Add A/AAAA record
                record_type = "A" if service == "dhcp4" else "AAAA"

                # Collision check: same name already registered to a different IP
                if collision_policy != "allow":
                    key = hostname.lower()
                    existing_ips = (unbound_fwd.get(key, set())
                                    | ({added_this_run[key]} if key in added_this_run else set()))
                    conflict_ips = existing_ips - {ip}
                    if conflict_ips:
                        if collision_policy == "first_wins":
                            logger.info(
                                f"Collision: {hostname} already has {conflict_ips}; "
                                f"skipping {ip} (first_wins)"
                            )
                            skipped += 1
                            continue
                        elif collision_policy == "last_wins":
                            logger.info(
                                f"Collision: {hostname} replacing {conflict_ips} with {ip} (last_wins)"
                            )
                            if not dry_run:
                                unbound_control(["local_data_remove", hostname])
                                if synthesize_ptr:
                                    for old_ip in conflict_ips:
                                        ptr = reverse_ptr(old_ip)
                                        if ptr:
                                            unbound_control(["local_data_remove", ptr])

                record = f"{hostname} IN {record_type} {ip}"

                if dry_run:
                    logger.info(f"[dry-run] would add: local_data {record}")
                else:
                    if unbound_control(["local_data", record]):
                        logger.info(f"Added {record_type}: {hostname} -> {ip}")
                        added += 1
                        if collision_policy != "allow":
                            added_this_run[hostname.lower()] = ip
                    else:
                        logger.error(f"Failed to add {record_type}: {hostname}")
                        errors += 1

                # Add PTR record (unless synthesis disabled or already in host_entries)
                if synthesize_ptr:
                    ptr_name = reverse_ptr(ip)
                    if ptr_name and not is_in_host_entries(ptr_name, host_entries):
                        ptr_record = f"{ptr_name} IN PTR {hostname}."

                        if dry_run:
                            logger.info(f"[dry-run] would add: local_data {ptr_record}")
                        else:
                            if unbound_control(["local_data", ptr_record]):
                                logger.info(f"Added PTR: {ptr_name} -> {hostname}")
                                added += 1
                            else:
                                logger.error(f"Failed to add PTR: {ptr_name}")
                                errors += 1

        logger.info(f"Reservation sync complete: added={added} skipped={skipped} errors={errors}")
        return 0 if errors == 0 else 1

    except Exception as e:
        logger.error(f"Reservation sync failed: {e}")
        return 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="Log what would be done without making changes")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Log additional details to stderr")
    parser.add_argument("--no-synthesize-ptr", dest="no_synthesize_ptr",
                        action="store_true",
                        help="Skip synthesizing PTR records (overrides config.xml)")
    args = parser.parse_args()

    synthesize_ptr = get_synthesize_ptr() and not args.no_synthesize_ptr
    return sync_reservations(dry_run=args.dry_run, verbose=args.verbose,
                              synthesize_ptr=synthesize_ptr)

if __name__ == "__main__":
    sys.exit(main())
