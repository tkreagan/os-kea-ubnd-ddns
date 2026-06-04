#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
kea-unbound-ddns.py — RFC 2136 stub listener for Kea → Unbound DNS registration.

Listens on 127.0.0.1:53535 (UDP), receives DNS UPDATE packets from kea-dhcp-ddns,
and translates them into unbound-control local_data / local_data_remove calls.

── Role in the plugin ────────────────────────────────────────────────────────────
This script is the real-time path. It handles individual lease events as they
happen. It does NOT do bulk operations:

  This script        → real-time ADD/DELETE per DDNS UPDATE packet
  reservation-sync.py→ one-shot bulk import of all Kea static reservations
  lease-sync.py      → one-shot bulk import of all active Kea leases
  local-data-audit.py→ read-only comparison of Unbound vs Kea (no writes)
  local-data-clean.py→ bulk removal of stale records (scheduled or on demand)

The sync scripts repopulate Unbound after a restart (Unbound's local_data is
runtime-only and does not survive a reload). This daemon handles all updates
that arrive while Unbound is running.

── ADD handling ──────────────────────────────────────────────────────────────────
For each A/AAAA ADD:
  1. Register the forward record: unbound-control local_data "name TTL IN A ip"
  2. Register the reverse record: unbound-control local_data "ptr TTL IN PTR name."
  3. If --aggressive-cleanup is set: call local-data-clean.py --hostname to remove
     any older IPs for the same hostname that Kea no longer recognises. This handles
     the common Kea behaviour of issuing a new IP without DELETEing the old one.
     The ADD always succeeds regardless of cleanup outcome.

── DELETE handling ───────────────────────────────────────────────────────────────
For each A/AAAA DELETE:
  1. Preserve any sibling address family (IPv6 if deleting A, IPv4 if deleting AAAA)
     by querying Unbound first — local_data_remove wipes ALL records for a name.
  2. Remove the forward record: unbound-control local_data_remove name
  3. Remove the PTR record(s) for the deleted IP(s).
  4. Re-add the preserved sibling record and its PTR with the original TTL.

── Static entry guard ────────────────────────────────────────────────────────────
Before every ADD and DELETE, is_static_entry() checks host_entries.conf. Records
managed by OPNsense via Unbound Host Overrides (or "Register DHCP Static Mappings")
live in that file and must never be touched by this daemon. Note: unbound-control
local_data_remove affects BOTH runtime-added entries AND config-file-sourced entries
in Unbound's in-memory zone — not just runtime entries — so this guard is essential.

── Lifecycle ─────────────────────────────────────────────────────────────────────
Launched by start.py via daemon(8) with -r (auto-respawn on crash) and -R 5 (5s
backoff). Stop and restart use stop.py, which signals the daemon(8) supervisor
(not just the child) and waits for clean exit. Do not run this script directly in
production — always use the configd actions (keaunbound start/stop/restart).

Usage:
    kea-unbound-ddns.py [--port PORT] [--unbound-conf FILE] [--host-entries FILE]
                        [--tsig-key NAME:SECRET] [--tsig-algorithm ALGO]
                        [--aggressive-cleanup] [--dry-run] [--verbose]
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import re
import signal
import socket
import subprocess
import sys

_DNSPYTHON_MIN = (2, 8)

try:
    import dns.message
    import dns.exception
    import dns.name
    import dns.opcode
    import dns.rcode
    import dns.rdataclass
    import dns.rdatatype
    import dns.tsig
    import dns.tsigkeyring
    import dns.version
    _ver = tuple(int(x) for x in dns.version.version.split(".")[:2])
    if _ver < _DNSPYTHON_MIN:
        print(
            f"ERROR: dnspython {dns.version.version} is too old — "
            f"{_DNSPYTHON_MIN[0]}.{_DNSPYTHON_MIN[1]}+ required. "
            f"Upgrade with: pkg upgrade py{sys.version_info.major}{sys.version_info.minor}-dnspython",
            file=sys.stderr
        )
        sys.exit(1)
except ImportError:
    print(
        "ERROR: dnspython is not installed. "
        f"Install with: pkg install py{sys.version_info.major}{sys.version_info.minor}-dnspython",
        file=sys.stderr
    )
    sys.exit(1)

# Shared logging setup lives with the sync utilities so every plugin component
# (daemon, sync/audit/clean scripts, start.py) logs with one program tag to the
# single keaunbound log. The plugin always installs both halves together.
sys.path.insert(0, "/usr/local/opnsense/scripts/keaunbound")
from lib.keaunbound_sync import setup_logging  # noqa: E402

# ── Constants ─────────────────────────────────────────────────────────────────
DEFAULT_PORT         = 53535
DEFAULT_UNBOUND_CONF = "/var/unbound/unbound.conf"
# /var/unbound/host_entries.conf is written by OPNsense and contains:
#   1. Manual host overrides configured in Services → Unbound DNS → Host Overrides
#   2. Static DHCP reservation hostnames, IF "Register DHCP Static Mappings"
#      is enabled in Services → Unbound DNS → General (regdhcpstatic=1)
# Both categories are written to this single file by unbound_add_host_entries()
# in unbound.inc and included into unbound.conf at startup.
# We must not touch any record in this file — it is entirely OPNsense-managed.
DEFAULT_HOST_ENTRIES = "/var/unbound/host_entries.conf"
UNBOUND_CONTROL      = "/usr/local/sbin/unbound-control"

# ── Argument parsing ──────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port",         type=int, default=DEFAULT_PORT,
                   help=f"UDP port to listen on (default: {DEFAULT_PORT})")
    p.add_argument("--unbound-conf", default=DEFAULT_UNBOUND_CONF,
                   help=f"Unbound config file (default: {DEFAULT_UNBOUND_CONF})")
    p.add_argument("--host-entries", default=DEFAULT_HOST_ENTRIES,
                   help=f"Unbound host entries file to guard against clobbering (default: {DEFAULT_HOST_ENTRIES})")
    p.add_argument("--tsig-key",       default=None,
                   help="TSIG key in NAME:SECRET format (base64 secret)")
    p.add_argument("--tsig-algorithm", default="HMAC-SHA256",
                   help="TSIG algorithm (default: HMAC-SHA256)")
    p.add_argument("--aggressive-cleanup", action="store_true",
                   help="After a successful A/AAAA ADD, remove stale IPs for "
                        "that hostname from Unbound (IPs no longer in Kea). "
                        "Best-effort: ADD outcome is unaffected if cleanup fails.")
    p.add_argument("--dry-run", "-n", action="store_true",
                   help="Parse and log updates but do not call unbound-control")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Log detailed information about each packet and call")
    return p.parse_args()

# ── Logging ───────────────────────────────────────────────────────────────────
# setup_logging() is imported from lib.keaunbound_sync (above) so the daemon and
# the sync/audit/clean scripts share one implementation and one program tag
# ('kea-ub'), all landing in the keaunbound log registered by keaunbound_syslog()
# in keaunbound.inc. The tag is 'kea-ub' rather than anything containing "unbound"
# because OPNsense's core resolver filter is program("unbound") — an unanchored
# substring match — which would swallow our log lines into the resolver log.
# It logs via libc syslog (LOG_DAEMON) and, in verbose mode, also mirrors to
# stderr for manual testing.

# ── unbound-control wrapper ───────────────────────────────────────────────────
def unbound_control(args: list[str], unbound_conf: str, dry_run: bool,
                    logger: logging.Logger) -> bool:
    cmd = [UNBOUND_CONTROL, "-c", unbound_conf] + args
    logger.debug("unbound-control %s", " ".join(args))
    if dry_run:
        logger.info("[dry-run] would run: unbound-control %s", " ".join(args))
        return True
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            logger.error("unbound-control %s failed (rc=%d): %s",
                         " ".join(args), result.returncode, result.stderr.strip())
            return False
        logger.debug("unbound-control ok: %s", result.stdout.strip())
        return True
    except subprocess.TimeoutExpired:
        logger.error("unbound-control %s timed out", " ".join(args))
        return False
    except FileNotFoundError:
        logger.error("%s not found — is Unbound installed?", UNBOUND_CONTROL)
        return False

# ── DNS record helpers ────────────────────────────────────────────────────────

# Record types we handle. Everything else is logged and skipped.
HANDLED_TYPES = {"A", "AAAA", "PTR"}

# The "other" address family for dual-stack preservation
OTHER_FAMILY = {"A": "AAAA", "AAAA": "A"}

# Hostname sanity checks — names that are technically valid DNS but
# meaningless or dangerous for our purposes.
_NONSENSE_NAMES = {
    "",           # empty
    ".",          # DNS root
    "localhost",  # loopback alias — should never come from kea-dhcp-ddns
    "localdomain",
}
# Valid hostname label characters per RFC 1123
_LABEL_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')

def fqdn(name: dns.name.Name) -> str:
    """Return fully-qualified name string without trailing dot."""
    return str(name).rstrip(".")

def is_sane_name(name: str, logger: logging.Logger) -> bool:
    """
    Return True if name is a plausible hostname we should act on.
    Rejects empty strings, the DNS root, reserved names, and names
    whose first label (the hostname part) contains invalid characters.
    dnspython has already validated wire-format correctness; this is a
    semantic sanity check for our specific use case.
    """
    if not name or name in _NONSENSE_NAMES:
        logger.warning("Rejecting nonsense name: %r", name)
        return False

    # Check the leftmost label — the actual hostname
    first_label = name.split(".")[0]
    if not first_label or not _LABEL_RE.match(first_label):
        logger.warning("Rejecting name with invalid first label: %r", name)
        return False

    # Reject names that are purely numeric (e.g. "192.168.1.1") —
    # these are IPs accidentally used as hostnames
    if all(part.isdigit() for part in name.split(".")):
        logger.warning("Rejecting all-numeric name (looks like an IP): %r", name)
        return False

    return True

def reverse_ptr(ip: str) -> str | None:
    """
    Return the PTR name for an IP address.
    Works for both IPv4 (in-addr.arpa) and IPv6 (ip6.arpa) — Python's
    ipaddress module handles both correctly.
    """
    try:
        return str(ipaddress.ip_address(ip).reverse_pointer)
    except ValueError:
        return None

def is_static_entry(name: str, rdtype: str, logger: logging.Logger,
                    static_files: list[str]) -> bool:
    """
    Return True if name+type appears in host_entries.conf (or any file in
    static_files), meaning we must not add or remove it.

    host_entries.conf is written entirely by OPNsense and contains:
      1. Manual host overrides from Services → Unbound DNS → Host Overrides
      2. Static DHCP reservation hostnames IF "Register DHCP Static Mappings"
         is enabled (regdhcpstatic=1) — in which case OPNsense has already
         registered them and we should step aside to avoid a conflict.
         If regdhcpstatic is disabled, static reservations arrive via
         kea-dhcp-ddns UPDATE packets and pass through this guard normally.

    Known limitation — stale host_entries.conf:
    OPNsense only rewrites host_entries.conf when Unbound reconfigures, not
    when Kea config changes. This means if a static reservation is removed
    from Kea, host_entries.conf may still contain it until the next Unbound
    reconfigure — causing this guard to incorrectly block the corresponding
    DELETE UPDATE from kea-dhcp-ddns.

    Our plugin's keaunbound_configure() hook on kea_sync calls
    unbound_add_host_entries() to rewrite host_entries.conf whenever Kea
    config changes, keeping the file current and eliminating this issue.

    Checks for:
      - Forward records: local-data: "name ... IN TYPE ..."
      - PTR records:     local-data-ptr: "ip ..."
    """
    # For PTR records the name IS the PTR (e.g. 1.0.168.192.in-addr.arpa)
    # For forward records check for the FQDN in a local-data line
    forward_pattern = re.compile(
        r'^local-data:\s+"' + re.escape(name) +
        rf'\.?\s+.*\bIN\s+{re.escape(rdtype)}\b',
        re.IGNORECASE
    )
    # PTR guard: for A/AAAA this checks the reverse PTR name;
    # for PTR records it checks the name directly as a local-data-ptr entry
    ptr_pattern = re.compile(
        r'^local-data-ptr:\s+"' + re.escape(name) + r'\b',
        re.IGNORECASE
    )

    for filepath in static_files:
        try:
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if forward_pattern.match(line) or ptr_pattern.match(line):
                        logger.info(
                            "Skipping %s %s — static entry found in %s",
                            rdtype, name, filepath
                        )
                        return True
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.warning("Cannot read %s: %s", filepath, e)

    return False

def query_unbound(name: str, record_type: str, logger: logging.Logger,
                  unbound_conf: str = DEFAULT_UNBOUND_CONF) -> list[tuple[str, int]]:
    """
    Query Unbound's local data store for records of record_type for name.
    Returns a list of (ip, ttl) tuples (e.g. [('10.0.0.1', 3600)]).

    Used exclusively for dual-stack preservation: before removing a name
    (which wipes ALL records for it via local_data_remove), we query for
    the other address family so we can restore it afterward.

    Uses unbound-control list_local_data rather than a DNS query because:
    - Queries the local data store directly — exactly where our injected
      records live, no risk of upstream cached answers interfering
    - Instantaneous local control socket operation, no DNS resolution overhead
    - Output is bounded by the number of active leases we've registered,
      so filtering in Python is trivial

    IMPORTANT — data loss risk on failure:
    If this query fails, we return an empty list and the delete proceeds —
    the other family's record will be silently wiped by local_data_remove.
    This is acceptable since list_local_data is a local in-memory operation
    that should never fail while Unbound is running. If Unbound is down,
    local_data_remove would also fail, so no records are lost in practice.
    """
    try:
        result = subprocess.run(
            [UNBOUND_CONTROL, "-c", unbound_conf, "list_local_data"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            logger.warning("list_local_data failed (rc=%d): %s",
                           result.returncode, result.stderr.strip())
            return []

        # list_local_data output: "name. TTL IN TYPE rdata"
        # Filter to lines matching our name and record type
        name_dot = name.rstrip(".") + "."
        records = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            if parts[0].lower() == name_dot.lower() and parts[3] == record_type:
                ip = parts[4]
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    logger.warning(
                        "Unexpected non-IP value in list_local_data output: %r", ip
                    )
                    continue
                try:
                    ttl = int(parts[1])
                except ValueError:
                    ttl = 3600
                records.append((ip, ttl))
        return records
    except Exception as e:
        logger.debug("list_local_data query for %s %s failed: %s",
                     name, record_type, e)
        return []

# ── Update processing ─────────────────────────────────────────────────────────
CLEANUP_SCRIPT = "/usr/local/opnsense/scripts/keaunbound/local-data-clean.py"


def _cleanup_host(hostname: str, new_ip: str, logger: logging.Logger) -> None:
    """
    Invoke local-data-clean.py --hostname after a successful A/AAAA ADD to
    remove stale IPs for that hostname from Unbound.

    Best-effort: errors are logged but never propagate — the ADD already
    succeeded and the DDNS response has been (or will be) sent. The new_ip
    is passed via --keep-ip so it is always preserved even if Kea's lease DB
    hasn't fully committed the new binding yet.
    """
    cmd = [sys.executable, CLEANUP_SCRIPT,
           "--hostname", hostname, "--keep-ip", new_ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        for line in result.stdout.strip().splitlines():
            logger.info("[cleanup] %s", line)
        if result.returncode != 0:
            logger.warning("[cleanup] script exited %d for %s", result.returncode, hostname)
        if result.stderr.strip():
            logger.debug("[cleanup] stderr: %s", result.stderr.strip())
    except subprocess.TimeoutExpired:
        logger.warning("[cleanup] timed out for %s", hostname)
    except Exception as e:
        logger.warning("[cleanup] failed for %s: %s", hostname, e)


def process_update(msg: dns.message.Message, unbound_conf: str,
                   dry_run: bool, logger: logging.Logger,
                   static_files: list[str],
                   aggressive_cleanup: bool = False) -> int:
    """
    Process a DNS UPDATE message. Returns DNS RCODE to send back.
    Update section lives in msg.authority for dnspython parsed UPDATE messages.

    Handles:
      - A, AAAA: forward record add/remove with dual-stack preservation and
                 automatic PTR add/remove for both IPv4 and IPv6
      - PTR: direct add/remove, no secondary effects
        Note: standalone PTR deletes are not expected from kea-dhcp-ddns in
        normal operation — PTRs are always cleaned up as a side effect of
        A/AAAA removal. The case is handled for correctness only.
      - All other types: logged and skipped

    Guard: before any operation, check whether the name/type is owned by a
    static Unbound config file (host overrides, OPNsense static DHCP
    mappings). If so, skip both adds and deletes to avoid clobbering records
    we don't own.

    Dual-stack preservation: unbound-control local_data_remove removes ALL
    records for a name, not just one type. When removing one address family
    (e.g. A), first query Unbound for the other family (AAAA), remove the
    name, then re-add the preserved record.
    """
    added = 0
    removed = 0
    skipped = 0
    errors = 0

    for rrset in msg.authority:
        name   = fqdn(rrset.name)
        rdtype = dns.rdatatype.to_text(rrset.rdtype)

        # Skip record types we don't handle
        if rdtype not in HANDLED_TYPES:
            logger.debug("Skipping unsupported record type %s for %s", rdtype, name)
            continue

        # Sanity check the name — PTR names (in-addr.arpa / ip6.arpa) are
        # exempt since they don't look like hostnames but are always valid
        # if dnspython accepted them from the wire format.
        if rdtype != "PTR" and not is_sane_name(name, logger):
            skipped += 1
            continue

        # Guard: skip anything owned by static Unbound config files.
        # Check BEFORE is_delete so we never clobber on either add or delete.
        if is_static_entry(name, rdtype, logger, static_files):
            skipped += 1
            continue

        # RFC 2136 §2.5: deletion requires BOTH class ANY/NONE AND TTL=0.
        # Three delete forms:
        #   1. Delete RRset:       class=ANY,  type=<specific>, TTL=0, no rdata
        #   2. Delete all RRsets:  class=ANY,  type=ANY,        TTL=0, no rdata
        #   3. Delete specific RR: class=NONE, type=<specific>, TTL=0, with rdata
        # unbound-control only supports name-level removal, so all three are
        # handled identically. TTL=0 alone is not sufficient.
        is_delete = (
            rrset.rdclass in (dns.rdataclass.ANY, dns.rdataclass.NONE)
            and rrset.ttl == 0
        )

        if is_delete:
            if rdtype in ("A", "AAAA"):
                other_type = OTHER_FAMILY[rdtype]

                # Preserve the other address family (with its TTL) before
                # removing the name. local_data_remove wipes ALL records for the
                # name, so we must re-add any surviving family record afterward.
                preserved = query_unbound(name, other_type, logger, unbound_conf)

                # Find PTR(s) for the records being removed so we can clean
                # them up. For delete forms 1&2 the rrset has no rdata, so
                # query Unbound for the current value before removing.
                current_ips = [str(rr) for rr in rrset] or \
                    [ip for ip, _ttl in query_unbound(name, rdtype, logger, unbound_conf)]
                current_ptrs = [p for p in (reverse_ptr(ip) for ip in current_ips) if p]

                logger.info("Remove: %s %s (preserving %d %s record(s))",
                            rdtype, name, len(preserved), other_type)
                ok = unbound_control(["local_data_remove", name],
                                     unbound_conf, dry_run, logger)
                if ok:
                    # Remove PTR records for the deleted address(es)
                    for ptr in current_ptrs:
                        if not is_static_entry(ptr, "PTR", logger, static_files):
                            logger.info("Remove PTR: %s", ptr)
                            unbound_control(["local_data_remove", ptr],
                                            unbound_conf, dry_run, logger)
                    # Re-add preserved other-family forward and PTR records,
                    # carrying the original TTL so dynamic leases keep expiring.
                    for ip, ttl in preserved:
                        ptr = reverse_ptr(ip)
                        logger.info("Restore %s: %s -> %s (TTL %ds)", other_type, name, ip, ttl)
                        unbound_control(["local_data", f"{name} {ttl} IN {other_type} {ip}"],
                                        unbound_conf, dry_run, logger)
                        if ptr and not is_static_entry(ptr, "PTR", logger, static_files):
                            logger.info("Restore PTR: %s -> %s", ptr, name)
                            unbound_control(["local_data", f"{ptr} {ttl} IN PTR {name}."],
                                            unbound_conf, dry_run, logger)
                    removed += 1
                else:
                    errors += 1

            elif rdtype == "PTR":
                # Standalone PTR delete — not expected from kea-dhcp-ddns in
                # normal operation but handled for correctness.
                # The name IS the PTR (e.g. 1.0.168.192.in-addr.arpa)
                logger.info("Remove PTR: %s (standalone)", name)
                ok = unbound_control(["local_data_remove", name],
                                     unbound_conf, dry_run, logger)
                if ok:
                    removed += 1
                else:
                    errors += 1

        else:
            # Addition
            for rr in rrset:
                rdata = str(rr)

                if rdtype in ("A", "AAAA"):
                    record = f"{name} {rrset.ttl} IN {rdtype} {rdata}"
                    logger.info("Add: %s", record)
                    ok = unbound_control(["local_data", record],
                                         unbound_conf, dry_run, logger)
                    if ok:
                        # Add PTR — works for both IPv4 and IPv6 via reverse_ptr()
                        ptr = reverse_ptr(rdata)
                        if ptr and not is_static_entry(ptr, "PTR", logger, static_files):
                            ptr_record = f"{ptr} {rrset.ttl} IN PTR {name}."
                            logger.info("Add PTR: %s", ptr_record)
                            unbound_control(["local_data", ptr_record],
                                            unbound_conf, dry_run, logger)
                        added += 1
                        # After registering the new IP, remove any stale IPs
                        # for this hostname that Kea did not DELETE (e.g. when
                        # a client renews at a new address). Best-effort: the
                        # ADD already succeeded; cleanup failures are logged only.
                        if aggressive_cleanup:
                            _cleanup_host(name, rdata, logger)
                    else:
                        errors += 1

                elif rdtype == "PTR":
                    # Explicit PTR from kea-dhcp-ddns — add directly.
                    # Not expected in normal operation (we generate PTRs
                    # automatically from A/AAAA adds) but handled for
                    # correctness if kea-dhcp-ddns is configured to send them.
                    record = f"{name} {rrset.ttl} IN PTR {rdata}"
                    logger.info("Add PTR (explicit): %s", record)
                    ok = unbound_control(["local_data", record],
                                         unbound_conf, dry_run, logger)
                    if ok:
                        added += 1
                    else:
                        errors += 1

    logger.info("Update complete: added=%d removed=%d skipped=%d errors=%d",
                added, removed, skipped, errors)
    return dns.rcode.NOERROR if errors == 0 else dns.rcode.SERVFAIL

# ── Response builder ──────────────────────────────────────────────────────────
def build_response(request: dns.message.Message, rcode: int) -> bytes:
    response = dns.message.make_response(request)
    response.set_rcode(rcode)
    return response.to_wire()

# ── TSIG keyring ──────────────────────────────────────────────────────────────
def parse_tsig_key(spec: str | None, algorithm: str = "HMAC-SHA256") -> dict | None:
    if not spec:
        return None
    if ":" not in spec:
        print("ERROR: --tsig-key must be NAME:SECRET (base64)", file=sys.stderr)
        sys.exit(1)
    name, secret = spec.split(":", 1)

    # Map algorithm name to dnspython constant
    algo_map = {
        "HMAC-MD5":    dns.tsig.HMAC_MD5,
        "HMAC-SHA1":   dns.tsig.HMAC_SHA1,
        "HMAC-SHA224": dns.tsig.HMAC_SHA224,
        "HMAC-SHA256": dns.tsig.HMAC_SHA256,
        "HMAC-SHA384": dns.tsig.HMAC_SHA384,
        "HMAC-SHA512": dns.tsig.HMAC_SHA512,
    }
    algo = algo_map.get(algorithm.upper())
    if algo is None:
        print(f"ERROR: unknown TSIG algorithm {algorithm!r}. "
              f"Valid options: {', '.join(algo_map)}", file=sys.stderr)
        sys.exit(1)

    # dns.tsigkeyring.from_text() accepts {name: (algorithm, base64_secret)}
    # and returns a keyring usable by dnspython's TSIG implementation.
    return dns.tsigkeyring.from_text({name: (algo, secret)})

# ── Signal handling ───────────────────────────────────────────────────────────
_running = True

def handle_signal(signum, frame):
    global _running
    _running = False

# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    args = parse_args()
    logger = setup_logging(args.verbose)
    keyring = parse_tsig_key(args.tsig_key, args.tsig_algorithm)

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # Bind socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)  # allows checking _running periodically
        sock.bind(("127.0.0.1", args.port))
    except OSError as e:
        logger.error("Cannot bind to 127.0.0.1:%d — %s", args.port, e)
        sys.exit(1)

    static_files = [args.host_entries]

    logger.info("Listening on 127.0.0.1:%d dry_run=%s tsig=%s host_entries=%s",
                args.port, args.dry_run,
                args.tsig_algorithm if keyring else "disabled",
                args.host_entries)

    if args.dry_run:
        logger.info("[dry-run] No unbound-control calls will be made")

    global _running
    while _running:
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError as e:
            if _running:
                logger.error("Socket error: %s", e)
            break

        logger.debug("Received %d bytes from %s", len(data), addr)

        # Parse DNS message
        try:
            if keyring:
                msg = dns.message.from_wire(data, keyring=keyring)
            else:
                msg = dns.message.from_wire(data)
        except dns.exception.DNSException as e:
            logger.warning("Failed to parse DNS message from %s: %s", addr, e)
            continue

        # Enforce TSIG when a key is configured: an unsigned packet must be
        # refused, otherwise TSIG provides no authentication. (A signed packet
        # with a wrong/unknown key already raised above and was dropped.)
        if keyring and not msg.had_tsig:
            logger.warning("Rejecting unsigned UPDATE from %s — TSIG required", addr)
            try:
                sock.sendto(build_response(msg, dns.rcode.REFUSED), addr)
            except OSError as e:
                logger.error("Failed to send REFUSED to %s: %s", addr, e)
            continue

        # Only handle UPDATE (opcode 5) — drop everything else silently
        opcode = dns.opcode.from_flags(msg.flags)
        if opcode != dns.opcode.UPDATE:
            logger.debug("Ignoring opcode %s from %s", dns.opcode.to_text(opcode), addr)
            continue

        logger.debug("DNS UPDATE from %s id=%d", addr, msg.id)

        # Process the update
        rcode = process_update(msg, args.unbound_conf, args.dry_run, logger,
                               static_files, args.aggressive_cleanup)

        # Send response
        try:
            response = build_response(msg, rcode)
            sock.sendto(response, addr)
        except OSError as e:
            logger.error("Failed to send response to %s: %s", addr, e)

    # Shutdown
    logger.info("Shutting down")
    sock.close()

if __name__ == "__main__":
    main()
