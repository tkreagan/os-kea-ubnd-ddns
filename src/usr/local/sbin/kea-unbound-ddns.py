#!/usr/local/bin/python3
"""
kea-unbound-ddns.py — RFC 2136 stub listener for Kea → Unbound DNS registration.

Listens on localhost:53535 (UDP), receives DNS UPDATE packets from kea-dhcp-ddns,
and translates them into unbound-control local_data / local_data_remove calls.

All other DNS opcodes are ignored. TSIG authentication is supported optionally.

Usage:
    kea-unbound-ddns.py [--port PORT] [--pidfile FILE] [--logfile FILE]
                        [--unbound-conf FILE] [--host-entries FILE]
                        [--tsig-key NAME:SECRET] [--dry-run] [--verbose]
"""

import argparse
import ipaddress
import logging
import os
import re
import signal
import socket
import subprocess
import sys

_DNSPYTHON_MIN = (2, 8)

try:
    import dns.message
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
            f"Upgrade with: pkg upgrade py313-dnspython",
            file=sys.stderr
        )
        sys.exit(1)
except ImportError:
    print(
        "ERROR: dnspython is not installed. "
        "Install with: pkg install py313-dnspython",
        file=sys.stderr
    )
    sys.exit(1)

# ── Constants ─────────────────────────────────────────────────────────────────
DEFAULT_PORT         = 53535
DEFAULT_PIDFILE      = "/var/run/kea-unbound-ddns.pid"
DEFAULT_LOGFILE      = "/var/log/kea-unbound.log"
DEFAULT_UNBOUND_CONF = "/var/unbound/unbound.conf"
DEFAULT_HOST_ENTRIES = "/var/unbound/host_entries.conf"
UNBOUND_CONTROL      = "/usr/local/sbin/unbound-control"
LOG_PREFIX           = "[kea-unbound-ddns]"

# ── Argument parsing ──────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port",         type=int, default=DEFAULT_PORT,
                   help=f"UDP port to listen on (default: {DEFAULT_PORT})")
    p.add_argument("--pidfile",      default=DEFAULT_PIDFILE,
                   help=f"PID file path (default: {DEFAULT_PIDFILE})")
    p.add_argument("--logfile",      default=DEFAULT_LOGFILE,
                   help=f"Log file path (default: {DEFAULT_LOGFILE})")
    p.add_argument("--unbound-conf", default=DEFAULT_UNBOUND_CONF,
                   help=f"Unbound config file (default: {DEFAULT_UNBOUND_CONF})")
    p.add_argument("--host-entries", default=DEFAULT_HOST_ENTRIES,
                   help=f"Unbound host entries file to guard against clobbering (default: {DEFAULT_HOST_ENTRIES})")
    p.add_argument("--tsig-key",     default=None,
                   help="TSIG key in NAME:SECRET format (base64 secret)")
    p.add_argument("--dry-run", "-n", action="store_true",
                   help="Parse and log updates but do not call unbound-control")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Log detailed information about each packet and call")
    return p.parse_args()

# ── Logging ───────────────────────────────────────────────────────────────────
def setup_logging(logfile: str, verbose: bool) -> logging.Logger:
    logger = logging.getLogger("kea-unbound-ddns")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s " + LOG_PREFIX + " [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    # File handler
    try:
        fh = logging.FileHandler(logfile)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except OSError as e:
        print(f"WARNING: cannot open logfile {logfile}: {e}", file=sys.stderr)
    # Stderr handler
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    return logger

# ── PID file ──────────────────────────────────────────────────────────────────
def write_pidfile(path: str):
    try:
        with open(path, "w") as f:
            f.write(str(os.getpid()))
    except OSError as e:
        print(f"ERROR: cannot write pidfile {path}: {e}", file=sys.stderr)
        sys.exit(1)

def remove_pidfile(path: str):
    try:
        os.unlink(path)
    except OSError:
        pass

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
    Return True if name+type appears as a static entry in any of the
    Unbound config files we don't own. Protects against clobbering manual
    host overrides and OPNsense-managed static DHCP mappings on both add
    and delete operations.

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

def query_unbound(name: str, record_type: str, logger: logging.Logger) -> list[str]:
    """
    Query Unbound's local data store for records of record_type for name.
    Returns a list of IP address strings (e.g. ['10.0.0.1']).

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
            [UNBOUND_CONTROL, "list_local_data"],
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
                    records.append(ip)
                except ValueError:
                    logger.warning(
                        "Unexpected non-IP value in list_local_data output: %r", ip
                    )
        return records
    except Exception as e:
        logger.debug("list_local_data query for %s %s failed: %s",
                     name, record_type, e)
        return []

# ── Update processing ─────────────────────────────────────────────────────────
def process_update(msg: dns.message.Message, unbound_conf: str,
                   dry_run: bool, logger: logging.Logger,
                   static_files: list[str]) -> int:
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

                # Preserve the other address family before removing the name.
                # local_data_remove wipes ALL records for the name, so we
                # must re-add any surviving family record afterward.
                preserved = query_unbound(name, other_type, logger)
                preserved_ptrs = [
                    (ip, ptr)
                    for ip in preserved
                    for ptr in [reverse_ptr(ip)]
                    if ptr
                ]

                # Find PTR(s) for the records being removed so we can clean
                # them up. For delete forms 1&2 the rrset has no rdata, so
                # query Unbound for the current value before removing.
                current_ips = [str(rr) for rr in rrset] or query_unbound(name, rdtype, logger)
                current_ptrs = [p for p in (reverse_ptr(ip) for ip in current_ips) if p]

                logger.info("Remove: %s %s (preserving %d %s record(s))",
                            rdtype, name, len(preserved), other_type)
                ok = unbound_control(["local_data_remove", name],
                                     unbound_conf, dry_run, logger)
                if ok:
                    # Remove PTR records for the deleted address(es)
                    for ptr in current_ptrs:
                        if not is_static_entry(ptr, "PTR", logger):
                            logger.info("Remove PTR: %s", ptr)
                            unbound_control(["local_data_remove", ptr],
                                            unbound_conf, dry_run, logger)
                    # Re-add preserved other-family forward and PTR records
                    for ip, ptr in preserved_ptrs:
                        logger.info("Restore %s: %s -> %s", other_type, name, ip)
                        unbound_control(["local_data", f"{name} IN {other_type} {ip}"],
                                        unbound_conf, dry_run, logger)
                        if not is_static_entry(ptr, "PTR", logger):
                            logger.info("Restore PTR: %s -> %s", ptr, name)
                            unbound_control(["local_data", f"{ptr} IN PTR {name}."],
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
                        if ptr and not is_static_entry(ptr, "PTR", logger):
                            ptr_record = f"{ptr} {rrset.ttl} IN PTR {name}."
                            logger.info("Add PTR: %s", ptr_record)
                            unbound_control(["local_data", ptr_record],
                                            unbound_conf, dry_run, logger)
                        added += 1
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
def parse_tsig_key(spec: str | None) -> dict | None:
    if not spec:
        return None
    if ":" not in spec:
        print("ERROR: --tsig-key must be NAME:SECRET (base64)", file=sys.stderr)
        sys.exit(1)
    name, secret = spec.split(":", 1)
    return dns.tsigkeyring.make_keyring({name: secret})

# ── Signal handling ───────────────────────────────────────────────────────────
_running = True

def handle_signal(signum, frame):
    global _running
    _running = False

# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    args = parse_args()
    logger = setup_logging(args.logfile, args.verbose)
    keyring = parse_tsig_key(args.tsig_key)

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # Write PID file
    write_pidfile(args.pidfile)

    # Bind socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)  # allows checking _running periodically
        sock.bind(("127.0.0.1", args.port))
    except OSError as e:
        logger.error("Cannot bind to 127.0.0.1:%d — %s", args.port, e)
        remove_pidfile(args.pidfile)
        sys.exit(1)

    static_files = [args.host_entries]

    logger.info("Listening on 127.0.0.1:%d (dry_run=%s tsig=%s host_entries=%s)",
                args.port, args.dry_run, "yes" if keyring else "no", args.host_entries)

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

        # Only handle UPDATE (opcode 5) — drop everything else silently
        opcode = dns.opcode.from_flags(msg.flags)
        if opcode != dns.opcode.UPDATE:
            logger.debug("Ignoring opcode %s from %s", dns.opcode.to_text(opcode), addr)
            continue

        logger.debug("DNS UPDATE from %s id=%d", addr, msg.id)

        # Process the update
        rcode = process_update(msg, args.unbound_conf, args.dry_run, logger, static_files)

        # Send response
        try:
            response = build_response(msg, rcode)
            sock.sendto(response, addr)
        except OSError as e:
            logger.error("Failed to send response to %s: %s", addr, e)

    # Shutdown
    logger.info("Shutting down")
    sock.close()
    remove_pidfile(args.pidfile)

if __name__ == "__main__":
    main()
