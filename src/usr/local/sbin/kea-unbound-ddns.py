#!/usr/local/bin/python3
"""
kea-unbound-ddns.py — RFC 2136 stub listener for Kea → Unbound DNS registration.

Listens on localhost:53535 (UDP), receives DNS UPDATE packets from kea-dhcp-ddns,
and translates them into unbound-control local_data / local_data_remove calls.

All other DNS opcodes are ignored. TSIG authentication is supported optionally.

Usage:
    kea-unbound-ddns.py [--port PORT] [--pidfile FILE] [--logfile FILE]
                        [--unbound-conf FILE] [--tsig-key NAME:SECRET]
                        [--dry-run] [--verbose]
"""

import argparse
import ipaddress
import logging
import os
import signal
import socket
import subprocess
import sys
import time

try:
    import dns.message
    import dns.opcode
    import dns.rcode
    import dns.rdataclass
    import dns.rdatatype
    import dns.tsig
    import dns.tsigkeyring
except ImportError:
    print("ERROR: dnspython is required. Install with: pkg install py311-dnspython", file=sys.stderr)
    sys.exit(1)

# ── Constants ─────────────────────────────────────────────────────────────────
DEFAULT_PORT        = 53535
DEFAULT_PIDFILE     = "/var/run/kea-unbound-ddns.pid"
DEFAULT_LOGFILE     = "/var/log/kea-unbound.log"
DEFAULT_UNBOUND_CONF = "/var/unbound/unbound.conf"
LOG_PREFIX          = "[kea-unbound-ddns]"

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
    cmd = ["unbound-control", "-c", unbound_conf] + args
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
        logger.error("unbound-control not found in PATH")
        return False

# ── DNS record helpers ────────────────────────────────────────────────────────

# Record types we handle. Everything else is logged and skipped.
HANDLED_TYPES = {"A", "AAAA", "PTR"}
# The "other" address family for dual-stack preservation
OTHER_FAMILY = {"A": "AAAA", "AAAA": "A"}

def fqdn(name: dns.name.Name) -> str:
    """Return fully-qualified name string without trailing dot."""
    return str(name).rstrip(".")

def reverse_ptr(ip: str) -> str | None:
    """Return the PTR name for an IP address."""
    try:
        return str(ipaddress.ip_address(ip).reverse_pointer)
    except ValueError:
        return None

def query_unbound(name: str, rdtype: str, logger: logging.Logger) -> list[str]:
    """
    Query Unbound via unbound-control lookup for existing records of a given
    type for a name. Returns a list of rdata strings (e.g. ['10.0.0.1']).
    Used to preserve dual-stack records when removing one address family.
    """
    try:
        result = subprocess.run(
            ["unbound-control", "lookup", name],
            capture_output=True, text=True, timeout=5
        )
        records = []
        for line in result.stdout.splitlines():
            # unbound-control lookup output: "name TTL class type rdata"
            parts = line.split()
            if len(parts) >= 5 and parts[3] == rdtype:
                records.append(parts[4])
        return records
    except Exception as e:
        logger.debug("unbound-control lookup %s %s failed: %s", name, rdtype, e)
        return []

# ── Update processing ─────────────────────────────────────────────────────────
def process_update(msg: dns.message.Message, unbound_conf: str,
                   dry_run: bool, logger: logging.Logger) -> int:
    """
    Process a DNS UPDATE message. Returns DNS RCODE to send back.
    Update section lives in msg.authority for dnspython parsed UPDATE messages.

    Handles:
      - A, AAAA: forward record add/remove with dual-stack preservation and
                 automatic PTR add/remove
      - PTR: direct add/remove, no secondary effects
      - All other types: logged and skipped

    Dual-stack preservation: unbound-control local_data_remove removes ALL
    records for a name. When removing one address family (e.g. A), we first
    query Unbound for the other family (AAAA), remove the name, then re-add
    the preserved record so the other family survives.
    """
    added = 0
    removed = 0
    errors = 0

    for rrset in msg.authority:
        name   = fqdn(rrset.name)
        rdtype = dns.rdatatype.to_text(rrset.rdtype)

        # Skip record types we don't handle
        if rdtype not in HANDLED_TYPES:
            logger.debug("Skipping unsupported record type %s for %s", rdtype, name)
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
                # Preserve the other address family before removing the name.
                # local_data_remove wipes ALL records for the name, so we
                # must re-add any surviving family record afterward.
                other_type = OTHER_FAMILY[rdtype]
                preserved = query_unbound(name, other_type, logger)
                preserved_ptrs = []
                for ip in preserved:
                    ptr = reverse_ptr(ip)
                    if ptr:
                        preserved_ptrs.append((ip, ptr))

                # Find the PTR(s) for the record(s) being removed so we can
                # clean them up. For delete forms 1&2 the rrset has no rdata,
                # so query Unbound for the current value before removing.
                current_ips = [str(rr) for rr in rrset] or query_unbound(name, rdtype, logger)
                current_ptrs = [p for p in (reverse_ptr(ip) for ip in current_ips) if p]

                logger.info("Remove: %s %s (preserving %d %s record(s))",
                            rdtype, name, len(preserved), other_type)
                ok = unbound_control(["local_data_remove", name],
                                     unbound_conf, dry_run, logger)
                if ok:
                    # Remove PTR records for the deleted address(es)
                    for ptr in current_ptrs:
                        logger.info("Remove PTR: %s", ptr)
                        unbound_control(["local_data_remove", ptr],
                                        unbound_conf, dry_run, logger)
                    # Re-add preserved other-family records
                    for ip, ptr in preserved_ptrs:
                        logger.info("Restore %s: %s -> %s", other_type, name, ip)
                        unbound_control(["local_data", f"{name} IN {other_type} {ip}"],
                                        unbound_conf, dry_run, logger)
                        logger.info("Restore PTR: %s -> %s", ptr, name)
                        unbound_control(["local_data", f"{ptr} IN PTR {name}."],
                                        unbound_conf, dry_run, logger)
                    removed += 1
                else:
                    errors += 1

            elif rdtype == "PTR":
                # PTR delete: the name IS the PTR (e.g. 1.0.0.10.in-addr.arpa)
                logger.info("Remove PTR: %s", name)
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
                        ptr = reverse_ptr(rdata)
                        if ptr:
                            ptr_record = f"{ptr} {rrset.ttl} IN PTR {name}."
                            logger.info("Add PTR: %s", ptr_record)
                            unbound_control(["local_data", ptr_record],
                                            unbound_conf, dry_run, logger)
                        added += 1
                    else:
                        errors += 1

                elif rdtype == "PTR":
                    # Explicit PTR from kea-dhcp-ddns — add directly
                    record = f"{name} {rrset.ttl} IN PTR {rdata}"
                    logger.info("Add PTR: %s", record)
                    ok = unbound_control(["local_data", record],
                                         unbound_conf, dry_run, logger)
                    if ok:
                        added += 1
                    else:
                        errors += 1

    logger.info("Update complete: added=%d removed=%d errors=%d", added, removed, errors)
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
        print(f"ERROR: --tsig-key must be NAME:SECRET (base64)", file=sys.stderr)
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

    logger.info("Listening on 127.0.0.1:%d (dry_run=%s tsig=%s)",
                args.port, args.dry_run, "yes" if keyring else "no")

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
        rcode = process_update(msg, args.unbound_conf, args.dry_run, logger)

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
