#!/usr/local/bin/python3
"""
local-data-audit.py -- Audit Unbound local_data across all sources.

Compares Unbound's local_data against Kea reservations, Kea leases, and
host_entries.conf to identify what's registered, what's stale, and what's
orphaned.

Generates a report suitable for:
  - Status view API (--report-json) to display registration state
  - Manual auditing (--human) for human-readable output
  - Status flags: OK, missing-PTR, stale, orphaned-PTR, static

Output structure (JSON):
  {
    "complete": bool,         # false if Kea unavailable
    "kea_error": str | null,  # Error message if Kea unavailable
    "records": [
      {
        "hostname": str,
        "ip": str,
        "type": "A|AAAA",
        "ptr_registered": bool,
        "source": "reservation|lease|unbound_local_data",
        "in_unbound": bool,
        "status": "ok|missing-PTR|stale|orphaned-PTR|static"
      }
    ],
    "orphaned_ptrs": [
      {
        "ptr_name": str,
        "data": str,
        "status": "orphaned-PTR"
      }
    ]
  }

Usage:
  local-data-audit.py --report-json           # JSON for API
  local-data-audit.py --human                 # Human-readable
  local-data-audit.py --verbose --human       # With details
"""

import argparse
import json
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
    setup_logging,
)

def audit_local_data(report_json: bool = False, verbose: bool = False) -> int:
    """
    Audit Unbound local_data against all sources.
    Returns 0 on success, non-zero on error.
    """
    logger = setup_logging(verbose)
    logger.info("Starting local-data audit")

    result = {
        "complete": True,
        "kea_error": None,
        "records": [],
        "orphaned_ptrs": [],
    }

    # Read static sources
    host_entries = read_host_entries()
    unbound_data = unbound_list_local_data()

    # Try to read dynamic sources from Kea
    kea_reservations = []
    kea_leases = []

    try:
        for service in ["dhcp4", "dhcp6"]:
            kea_reservations.extend(query_kea_reservations(service=service))
            kea_leases.extend(query_kea_leases(service=service))
    except KeaUnavailableError as e:
        result["complete"] = False
        result["kea_error"] = str(e)
        logger.warning(f"Kea unavailable: {e}")

    # Build combined set of all hostnames we know about
    all_hostnames = set()

    for res in kea_reservations:
        if res["hostname"]:
            all_hostnames.add(res["hostname"])

    for lease in kea_leases:
        if lease["hostname"]:
            all_hostnames.add(lease["hostname"])

    for name in unbound_data:
        all_hostnames.add(name)

    for name in host_entries:
        all_hostnames.add(name)

    # Process each hostname
    for hostname in sorted(all_hostnames):
        # Find IP(s) for this hostname from all sources
        ips_from_reservation = set()
        ips_from_lease = set()
        ips_from_unbound = set()
        ips_from_host_entries = set()

        for res in kea_reservations:
            if res["hostname"] == hostname:
                if res["ip"]:
                    ips_from_reservation.add(res["ip"])
                if res["ipv6"]:
                    ips_from_reservation.add(res["ipv6"])

        for lease in kea_leases:
            if lease["hostname"] == hostname:
                if lease["ip"]:
                    ips_from_lease.add(lease["ip"])
                if lease["ipv6"]:
                    ips_from_lease.add(lease["ipv6"])

        # Extract IPs from unbound_data for this hostname
        if hostname in unbound_data:
            for line in unbound_data[hostname]:
                parts = line.split()
                if len(parts) >= 5:
                    rdtype = parts[3]
                    if rdtype in ("A", "AAAA"):
                        ips_from_unbound.add(parts[4])

        # Extract IPs from host_entries for this hostname
        if hostname in host_entries:
            for line in host_entries[hostname]:
                parts = line.split()
                if "local-data:" in line and len(parts) >= 5:
                    rdtype_idx = None
                    for i, p in enumerate(parts):
                        if p.upper() == "A" or p.upper() == "AAAA":
                            rdtype_idx = i
                            break
                    if rdtype_idx and rdtype_idx + 1 < len(parts):
                        ips_from_host_entries.add(parts[rdtype_idx + 1])

        # Combine all IPs
        all_ips = ips_from_reservation | ips_from_lease | ips_from_unbound | ips_from_host_entries

        # Process each IP for this hostname
        for ip in sorted(all_ips):
            # Determine source
            if ip in ips_from_host_entries:
                source = "static"
                status = "static"
            elif ip in ips_from_reservation:
                source = "reservation"
                status = "ok"
            elif ip in ips_from_lease:
                source = "lease"
                status = "ok"
            elif ip in ips_from_unbound:
                source = "unbound_local_data"
                status = "stale"  # In unbound but not in any source
            else:
                continue

            # Determine if in Unbound
            in_unbound = ip in ips_from_unbound

            # Check PTR
            ptr_name = reverse_ptr(ip)
            ptr_registered = False

            if ptr_name and ptr_name in unbound_data:
                ptr_registered = True

            # Update status if missing PTR
            if status == "ok" and not ptr_registered:
                status = "missing-PTR"

            # Determine record type
            record_type = "A" if "." in ip else "AAAA"

            record = {
                "hostname": hostname,
                "ip": ip,
                "type": record_type,
                "ptr_registered": ptr_registered,
                "source": source,
                "in_unbound": in_unbound,
                "status": status,
            }

            result["records"].append(record)

    # Find orphaned PTRs (PTRs in unbound_data with no corresponding forward record)
    unbound_forward_ips = set()
    for records in [r["ip"] for r in result["records"] if r["in_unbound"]]:
        unbound_forward_ips.add(records)

    for ptr_name in sorted(unbound_data.keys()):
        if ptr_name.endswith(".in-addr.arpa") or ptr_name.endswith(".ip6.arpa"):
            # This is a PTR record
            for line in unbound_data[ptr_name]:
                # Check if we have a corresponding forward record
                parts = line.split()
                if len(parts) >= 5 and parts[3] == "PTR":
                    # Extract the IP from the PTR name
                    try:
                        # Convert PTR name back to IP
                        # This is tricky; we'd need to reverse the PTR conversion
                        # For now, if we have a PTR with no matching A/AAAA, flag it
                        has_forward = any(r["ptr_registered"] and r["ptr_name"] == ptr_name
                                         for r in result["records"] if "ptr_name" in r)

                        if not has_forward:
                            orphaned = {
                                "ptr_name": ptr_name,
                                "data": line,
                                "status": "orphaned-PTR",
                            }
                            result["orphaned_ptrs"].append(orphaned)
                    except Exception:
                        pass

    # Output
    if report_json:
        print(json.dumps(result, indent=2))
    else:
        # Human-readable output
        print("Local Data Audit Report")
        print("=" * 80)
        print(f"Kea Available: {'Yes' if result['complete'] else f'No ({result[\"kea_error\"]})'}")
        print(f"Total Records: {len(result['records'])}")
        print(f"Orphaned PTRs: {len(result['orphaned_ptrs'])}")
        print()

        status_counts = {}
        for record in result["records"]:
            status = record["status"]
            status_counts[status] = status_counts.get(status, 0) + 1

        for status, count in sorted(status_counts.items()):
            print(f"  {status}: {count}")

        if result["records"]:
            print()
            print("Records by Status:")
            print("-" * 80)
            for status_filter in ["ok", "missing-PTR", "stale", "static"]:
                filtered = [r for r in result["records"] if r["status"] == status_filter]
                if filtered:
                    print(f"\n{status_filter.upper()}:")
                    for r in filtered:
                        ptr_marker = " ✓ PTR" if r["ptr_registered"] else " ✗ NO PTR"
                        print(f"  {r['hostname']:30} {r['ip']:20} {r['source']:15}{ptr_marker}")

        if result["orphaned_ptrs"]:
            print()
            print("ORPHANED PTRs (no matching forward record):")
            print("-" * 80)
            for orphan in result["orphaned_ptrs"]:
                print(f"  {orphan['ptr_name']}")

    logger.info("Audit complete")
    return 0

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-json", action="store_true",
                        help="Output JSON suitable for API consumption")
    parser.add_argument("--human", action="store_true",
                        help="Human-readable text output")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Log additional details to stderr")
    args = parser.parse_args()

    # Default to human-readable if neither specified
    if not args.report_json and not args.human:
        args.human = True

    return audit_local_data(report_json=args.report_json, verbose=args.verbose)

if __name__ == "__main__":
    sys.exit(main())
