#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
local-data-audit.py -- Audit Unbound local_data across all sources.

Compares Unbound's local_data against Kea reservations, Kea leases, and
host_entries.conf to identify what's registered, what's stale, and what's
orphaned.

Stale/orphan detection is delegated to keaunbound_sync.find_stale_records(),
the same function the cleanup script uses — so the "stale" rows and orphaned
PTRs shown here are exactly what a cleanup would remove.

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
        "source": "reservation|lease|unbound_local_data|static",
        "in_unbound": bool,
        "status": "ok|missing-PTR|stale|orphaned-PTR|static|unknown"
      }
    ],
    "orphaned_ptrs": [
      {"ptr_name": str, "data": str, "status": "orphaned-PTR"}
    ]
  }

Usage:
  local-data-audit.py --report-json           # JSON for API
  local-data-audit.py --human                 # Human-readable
  local-data-audit.py --verbose --human       # With details
"""

import argparse
import ipaddress
import json
import sys

# Add parent directory to path so we can import lib
sys.path.insert(0, "/usr/local/opnsense/scripts/keaunbound")

from lib.keaunbound_sync import (
    KeaUnavailableError,
    KeaServiceUnavailableError,
    query_kea_reservations,
    query_kea_leases,
    read_host_entries,
    reverse_ptr,
    unbound_list_local_data,
    is_ptr_name,
    find_stale_records,
    setup_logging,
)


def _forward_ips_from_lines(lines):
    """Extract A/AAAA IPs from a list of 'name TTL IN TYPE rdata' lines."""
    ips = set()
    for line in lines:
        parts = line.split()
        if len(parts) >= 5 and parts[3] in ("A", "AAAA"):
            ips.add(parts[4])
    return ips


def _ip_from_ptr(ptr_name):
    """Convert a reverse-DNS name back to its IP address string, or '' if it
    isn't a full, parseable in-addr.arpa / ip6.arpa name (e.g. a delegation)."""
    name = ptr_name.rstrip(".")
    if name.endswith(".in-addr.arpa"):
        labels = name[:-len(".in-addr.arpa")].split(".")
        if len(labels) == 4 and all(l.isdigit() for l in labels):
            return ".".join(reversed(labels))
    elif name.endswith(".ip6.arpa"):
        nibbles = name[:-len(".ip6.arpa")].split(".")
        if len(nibbles) == 32 and all(len(n) == 1 for n in nibbles):
            rev = "".join(reversed(nibbles))
            groups = [rev[i:i + 4] for i in range(0, 32, 4)]
            try:
                return str(ipaddress.ip_address(":".join(groups)))
            except ValueError:
                return ""
    return ""


def _ttl_for_ip(lines, ip):
    """Return the TTL (as a string) of the A/AAAA local_data line for ip, or
    None. Lines are 'name. TTL IN TYPE rdata' from unbound list_local_data."""
    for line in lines:
        parts = line.split()
        if len(parts) >= 5 and parts[3] in ("A", "AAAA") and parts[4] == ip:
            return parts[1]
    return None


def _ptr_targets(unbound_data, ip):
    """Return the set of target hostnames (lowercased, no trailing dot) of the
    PTR records for ip, read from Unbound's local_data. Empty if no reverse."""
    targets = set()
    ptr_name = reverse_ptr(ip)
    if not ptr_name:
        return targets
    for line in unbound_data.get(ptr_name, []):
        parts = line.split()
        if len(parts) >= 5 and parts[3] == "PTR":
            targets.add(parts[4].rstrip(".").lower())
    return targets


def _host_entry_ips(lines):
    """Extract A/AAAA IPs from host_entries.conf local-data lines for a name."""
    ips = set()
    for line in lines:
        if "local-data:" not in line:
            continue
        parts = line.split()
        for i, p in enumerate(parts):
            if p.upper() in ("A", "AAAA") and i + 1 < len(parts):
                ips.add(parts[i + 1].strip('"'))
    return ips


def audit_local_data(report_json: bool = False, verbose: bool = False) -> int:
    """
    Audit Unbound local_data against all sources.
    Returns 0 on success, non-zero on error.
    """
    logger = setup_logging(verbose)
    logger.debug("Starting local-data audit")

    result = {
        "complete": True,
        "kea_error": None,
        "records": [],
        "orphaned_ptrs": [],
        "ptr_records": [],
    }

    host_entries = read_host_entries()
    unbound_data = unbound_list_local_data()

    kea_reservations = []
    kea_leases = []
    any_service_ok = False
    for service in ("dhcp4", "dhcp6"):
        try:
            reservations = query_kea_reservations(service=service)
        except KeaServiceUnavailableError as e:
            # Service offline / config unreadable (e.g. dhcp6 not running) — skip.
            logger.debug(f"Skipping {service}: {e}")
            continue
        except KeaUnavailableError as e:
            # Kea daemon unreachable — cannot complete the audit.
            result["complete"] = False
            result["kea_error"] = str(e)
            logger.warning(f"Kea unavailable: {e}")
            break
        any_service_ok = True
        kea_reservations.extend(reservations)
        try:
            kea_leases.extend(query_kea_leases(service=service))
        except KeaServiceUnavailableError as e:
            # Service is up but leases can't be read (e.g. lease_cmds missing).
            # Mark incomplete so cleanup stays disabled — deleting without lease
            # data would wrongly remove live lease records.
            result["complete"] = False
            result["kea_error"] = f"Active leases unavailable for {service}: {e}"
            logger.warning(result["kea_error"])
        except KeaUnavailableError as e:
            result["complete"] = False
            result["kea_error"] = str(e)
            logger.warning(f"Kea unavailable: {e}")
            break

    # If no service responded at all, we have no Kea data — mark incomplete so
    # the Clean button stays disabled (cleanup needs authoritative Kea data).
    if not any_service_ok and result["complete"]:
        result["complete"] = False
        result["kea_error"] = result["kea_error"] or "No Kea service (dhcp4/dhcp6) responded"

    # IP indexes per hostname, by source
    kea_pairs = set()
    res_ips_by_host = {}
    lease_ips_by_host = {}
    for res in kea_reservations:
        for ip in (res["ip"], res["ipv6"]):
            if ip:
                res_ips_by_host.setdefault(res["hostname"], set()).add(ip)
                if res["hostname"]:
                    kea_pairs.add((res["hostname"], ip))
    for lease in kea_leases:
        for ip in (lease["ip"], lease["ipv6"]):
            if ip:
                lease_ips_by_host.setdefault(lease["hostname"], set()).add(ip)
                if lease["hostname"]:
                    kea_pairs.add((lease["hostname"], ip))

    unbound_ips_by_host = {}
    for name, lines in unbound_data.items():
        if is_ptr_name(name):
            continue
        ips = _forward_ips_from_lines(lines)
        if ips:
            unbound_ips_by_host[name] = ips

    host_ips_by_host = {}
    for name, lines in host_entries.items():
        ips = _host_entry_ips(lines)
        if ips:
            host_ips_by_host[name] = ips

    unbound_ptr_names = {n for n in unbound_data if is_ptr_name(n)}

    # Authoritative stale/orphan set — only meaningful with complete Kea data.
    stale_names = set()
    orphaned_ptr_names = set()
    if result["complete"]:
        stale_names, orphaned_ptr_names = find_stale_records(unbound_data, kea_pairs, host_entries)

    all_hostnames = (set(res_ips_by_host) | set(lease_ips_by_host)
                     | set(unbound_ips_by_host) | set(host_ips_by_host))

    for hostname in sorted(all_hostnames):
        res_ips = res_ips_by_host.get(hostname, set())
        lease_ips = lease_ips_by_host.get(hostname, set())
        ub_ips = unbound_ips_by_host.get(hostname, set())
        he_ips = host_ips_by_host.get(hostname, set())

        for ip in sorted(res_ips | lease_ips | ub_ips | he_ips):
            if ip in he_ips:
                source, status = "static", "static"
            elif ip in res_ips:
                source, status = "reservation", "ok"
            elif ip in lease_ips:
                source, status = "lease", "ok"
            elif ip in ub_ips:
                source = "unbound_local_data"
                if not result["complete"]:
                    status = "unknown"  # cannot judge staleness without Kea
                elif hostname in stale_names:
                    status = "stale"
                else:
                    status = "ok"
            else:
                continue

            in_unbound = ip in ub_ips
            ptr_name = reverse_ptr(ip)
            ptr_registered = bool(ptr_name and ptr_name in unbound_ptr_names)

            # Per-host reverse state: does a PTR for this IP name THIS host?
            #   none     - no PTR for the IP
            #   correct  - exactly one PTR, and it names this host
            #   multiple - IP has >1 PTR and this host is among them (supersedes correct)
            #   wrong    - PTR(s) exist for the IP but none name this host
            ptr_targets = _ptr_targets(unbound_data, ip)
            hn = hostname.rstrip(".").lower()
            if not ptr_targets:
                ptr_state = "none"
            elif hn in ptr_targets:
                ptr_state = "multiple" if len(ptr_targets) > 1 else "correct"
            else:
                ptr_state = "wrong"

            if status == "ok" and not ptr_registered:
                status = "missing-PTR"

            try:
                record_type = "A" if ipaddress.ip_address(ip).version == 4 else "AAAA"
            except ValueError:
                record_type = "A"

            # TTL is only meaningful for records actually present in Unbound.
            ttl = _ttl_for_ip(unbound_data.get(hostname, []), ip) if in_unbound else None

            result["records"].append({
                "hostname": hostname,
                "ip": ip,
                "type": record_type,
                "ttl": ttl,
                "ptr_registered": ptr_registered,
                "ptr_state": ptr_state,
                # Independent attributes (not mutually exclusive) — an entry can
                # be e.g. both a reservation and a live record. The UI shows these
                # as columns; "status"/"source" remain for the summary roll-up.
                "reserved": ip in res_ips,        # Kea static reservation
                "leased": ip in lease_ips,        # client currently holds it
                "override": ip in he_ips,         # config-persistent (host_entries.conf)
                "live": in_unbound,               # resolvable in Unbound right now
                "source": source,
                "in_unbound": in_unbound,
                "status": status,
            })

    for ptr_name in sorted(orphaned_ptr_names):
        lines = unbound_data.get(ptr_name, [])
        raw = lines[0] if lines else ""
        # Parse 'ptr. TTL IN PTR target.' for TTL and the target hostname.
        ttl = None
        target = ""
        parts = raw.split()
        if len(parts) >= 5 and parts[3] == "PTR":
            ttl = parts[1]
            target = parts[4].rstrip(".")
        result["orphaned_ptrs"].append({
            "ptr_name": ptr_name,
            "address": _ip_from_ptr(ptr_name),
            "data": raw,
            "ttl": ttl,
            "target": target,
            "status": "orphaned-PTR",
        })

    # ── Reverse (PTR) records: every PTR in Unbound, with forward consistency ──
    # Forward A/AAAA map from Unbound runtime data (name -> set of IPs).
    fwd_ips_by_name = {}
    for name, lines in unbound_data.items():
        if is_ptr_name(name):
            continue
        ips = set()
        for line in lines:
            parts = line.split()
            if len(parts) >= 5 and parts[3] in ("A", "AAAA"):
                ips.add(parts[4])
        if ips:
            fwd_ips_by_name[name.rstrip(".").lower()] = ips
    names_by_ip = {}
    for name, ips in fwd_ips_by_name.items():
        for ip in ips:
            names_by_ip.setdefault(ip, set()).add(name)

    for ptr_name in sorted(n for n in unbound_data if is_ptr_name(n)):
        ip = _ip_from_ptr(ptr_name)
        covered = _ptr_targets(unbound_data, ip) if ip else set()
        uncovered = (names_by_ip.get(ip, set()) - covered) if ip else set()
        # One entry per reverse name; each target it points to is its own line.
        targets = []
        for line in unbound_data.get(ptr_name, []):
            parts = line.split()
            if len(parts) < 5 or parts[3] != "PTR":
                continue
            target = parts[4].rstrip(".")
            target_ips = fwd_ips_by_name.get(target.lower(), set())
            if not target_ips:
                fwd_state = "orphan"      # red: target has no forward A/AAAA at all
            elif ip and ip not in target_ips:
                fwd_state = "mismatch"    # amber: forward points to a different IP
            elif uncovered:
                fwd_state = "partial"     # amber: other names on this IP have no PTR
            else:
                fwd_state = "match"       # green: forward matches, full coverage
            targets.append({
                "target": target,
                "ttl": parts[1],
                "fwd_state": fwd_state,
            })
        if targets:
            result["ptr_records"].append({
                "ip": ip,
                "ptr_name": ptr_name,
                "targets": targets,
            })

    if report_json:
        print(json.dumps(result, indent=2))
    else:
        print("Local Data Audit Report")
        print("=" * 80)
        if result["complete"]:
            print("Kea Available: Yes")
        else:
            print(f"Kea Available: No ({result['kea_error']})")
        print(f"Total Records: {len(result['records'])}")
        print(f"Orphaned PTRs: {len(result['orphaned_ptrs'])}")
        print()

        status_counts = {}
        for record in result["records"]:
            status_counts[record["status"]] = status_counts.get(record["status"], 0) + 1
        for status, count in sorted(status_counts.items()):
            print(f"  {status}: {count}")

        if result["records"]:
            print()
            print("Records by Status:")
            print("-" * 80)
            for status_filter in ["ok", "missing-PTR", "stale", "unknown", "static"]:
                filtered = [r for r in result["records"] if r["status"] == status_filter]
                if filtered:
                    print(f"\n{status_filter.upper()}:")
                    for r in filtered:
                        ptr_marker = " +PTR" if r["ptr_registered"] else " -no PTR"
                        print(f"  {r['hostname']:30} {r['ip']:20} {r['source']:18}{ptr_marker}")

        if result["orphaned_ptrs"]:
            print()
            print("ORPHANED PTRs (no matching forward record):")
            print("-" * 80)
            for orphan in result["orphaned_ptrs"]:
                print(f"  {orphan['ptr_name']}")

    logger.debug("Audit complete")
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
