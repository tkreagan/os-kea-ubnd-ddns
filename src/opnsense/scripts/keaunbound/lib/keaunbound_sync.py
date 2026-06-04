#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
keaunbound_sync.py -- Shared library for Kea-Unbound sync utilities.

Provides:
  - Kea queries (reservations, leases) via the transport layer (kea_transport)
  - Unbound control wrapper
  - host_entries.conf parser
  - Stale/orphaned record detection (shared by audit and clean)
  - Hostname sanity checks
  - Error handling for missing/unavailable services
  - Syslog logging

Uses only the Python standard library (no third-party dependencies) so it runs
on a stock OPNsense install without extra packages.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
import sys
import syslog
import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set, Tuple

# Kea connection lives in the transport layer (unix socket / HTTP, with the
# config-reading resolver). The exception types are defined there and re-exported
# here so existing callers can keep importing them from keaunbound_sync.
from .kea_transport import (  # noqa: F401
    KeaUnavailableError,
    KeaServiceUnavailableError,
    kea_query,
)

# Constants
CONFIG_XML = "/conf/config.xml"
HOST_ENTRIES = "/var/unbound/host_entries.conf"
UNBOUND_CONTROL = "/usr/local/sbin/unbound-control"
UNBOUND_CONF = "/var/unbound/unbound.conf"
# "kea-ub" deliberately avoids the substring "unbound": OPNsense's core resolver
# syslog-ng filter is program("unbound"), which matches as an unanchored substring,
# so any tag containing "unbound" would be routed into the resolver log instead of ours.
SYSLOG_IDENT = "kea-ub"

# Kea lease "state" enum: 0 = default/active (the only one we register),
# 1 = declined, 2 = expired-reclaimed.
LEASE_STATE_DEFAULT = 0

# Valid hostname label characters per RFC 1123 (first label / hostname part)
_LABEL_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')

# Names that are technically valid DNS but meaningless/dangerous for our use.
_NONSENSE_NAMES = {"", ".", "localhost", "localdomain"}


# Map Python logging levels to syslog priorities.
_SYSLOG_PRIORITY = {
    logging.DEBUG:    syslog.LOG_DEBUG,
    logging.INFO:     syslog.LOG_INFO,
    logging.WARNING:  syslog.LOG_WARNING,
    logging.ERROR:    syslog.LOG_ERR,
    logging.CRITICAL: syslog.LOG_CRIT,
}


class SyslogHandler(logging.Handler):
    """logging.Handler that writes to syslog via the libc syslog module.

    Used in preference to logging.handlers.SysLogHandler because the latter
    emits only "<PRI>ident: message" over the socket with no real program tag
    or PID, which syslog-ng mis-attributes — in our case routing our lines into
    the resolver log (its filter matches the substring "unbound") and never into
    the keaunbound log. libc syslog() sets a proper program tag via openlog()
    and includes the PID. Every plugin component (daemon, sync/audit/clean
    scripts, start.py) shares this handler so all logs carry the same
    SYSLOG_IDENT tag and land in the one keaunbound log.
    """
    def emit(self, record: logging.LogRecord):
        priority = _SYSLOG_PRIORITY.get(record.levelno, syslog.LOG_INFO)
        try:
            syslog.syslog(priority, self.format(record))
        except Exception:
            self.handleError(record)


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Set up syslog logging (program tag = SYSLOG_IDENT) via libc syslog, with
    optional stderr output in verbose mode. Safe to call once per process."""
    syslog.openlog(SYSLOG_IDENT, syslog.LOG_PID, syslog.LOG_DAEMON)

    logger = logging.getLogger(SYSLOG_IDENT)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    # Drop handlers from any earlier call so a repeated setup_logging() in one
    # process doesn't duplicate every log line.
    logger.handlers.clear()

    formatter = logging.Formatter("[%(levelname)s] %(message)s")

    handler = SyslogHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Stderr handler for verbose mode
    if verbose:
        stderr = logging.StreamHandler(sys.stderr)
        stderr.setFormatter(formatter)
        logger.addHandler(stderr)

    return logger


def query_kea_api(command: str, arguments: Optional[Dict] = None,
                  service: str = "dhcp4", timeout: float = 5.0) -> Dict:
    """
    Run a Kea command against the given daemon (dhcp4/dhcp6) and return the
    normalized response map.

    Thin wrapper over the transport layer (kea_transport.kea_query): the layer
    resolves the unix-socket/HTTP connection for the service from configuration,
    sends the command directly to the daemon (no Control Agent, no per-command
    "service" routing field), and normalizes/validates the response. Raises
    KeaUnavailableError / KeaServiceUnavailableError on failure.
    """
    return kea_query(command, arguments=arguments, service=service, timeout=timeout)


def get_system_domain() -> str:
    """Read the OPNsense system domain (//system/domain). Empty if unset."""
    try:
        node = ET.parse(CONFIG_XML).getroot().find("system/domain")
        return (node.text or "").strip() if node is not None else ""
    except Exception:
        return ""


def qualify_hostname(hostname: str, suffix: str) -> str:
    """
    Return an FQDN for a (possibly bare) hostname so the sync path produces the
    same names as the live kea-dhcp-ddns path. A name that already contains a dot
    is treated as already-qualified and returned as-is; a bare name gets the
    suffix appended; with no suffix the bare name is kept.
    """
    hostname = (hostname or "").rstrip(".")
    if not hostname or "." in hostname:
        return hostname
    suffix = (suffix or "").strip(".")
    return f"{hostname}.{suffix}" if suffix else hostname


def _iter_kea_subnets(dhcp_config: Dict, subnet_key: str):
    """
    Yield (subnet, inherited_suffix) for every subnet, where inherited_suffix is
    the parent shared-network's ddns-qualifying-suffix ('' for top-level subnets).
    """
    for subnet in dhcp_config.get(subnet_key, []):
        yield subnet, ""
    for shared in dhcp_config.get("shared-networks", []):
        net_suffix = shared.get("ddns-qualifying-suffix", "") or ""
        for subnet in shared.get(subnet_key, []):
            yield subnet, net_suffix


def _effective_suffix(subnet: Dict, net_suffix: str, global_suffix: str,
                      system_domain: str) -> str:
    """Resolve a subnet's qualifying suffix: subnet -> shared-network -> global
    -> system domain -> '' (bare)."""
    return ((subnet.get("ddns-qualifying-suffix") or "")
            or net_suffix or global_suffix or system_domain or "")


def query_kea_reservations(service: str = "dhcp4") -> List[Dict]:
    """
    Read static reservations from the running Kea configuration.

    OPNsense stores reservations in the config (subnet[].reservations[]), not a
    host-database backend, so we read them via {service}-get-config rather than
    reservation-get-all (which needs host_cmds + a host DB). Returns a list of
    dicts with keys: hostname, ip, ipv6.
    """
    is_v4 = service == "dhcp4"
    # config-get returns the running daemon config under arguments.Dhcp4/Dhcp6.
    # (There is no 'dhcp4-get-config' command on Kea.)
    root_key = "Dhcp4" if is_v4 else "Dhcp6"
    subnet_key = "subnet4" if is_v4 else "subnet6"

    resp = query_kea_api("config-get", service=service)
    dhcp_config = resp.get("arguments", {}).get(root_key, {})
    global_suffix = dhcp_config.get("ddns-qualifying-suffix", "") or ""
    system_domain = get_system_domain()

    reservations = []
    # Per-subnet reservations (incl. shared-networks), each qualified with that
    # subnet's effective DDNS suffix; then any global reservations.
    sources = [(subnet, _effective_suffix(subnet, net_suffix, global_suffix, system_domain))
               for subnet, net_suffix in _iter_kea_subnets(dhcp_config, subnet_key)]
    sources.append((dhcp_config, global_suffix or system_domain or ""))
    for source, suffix in sources:
        for res in source.get("reservations", []):
            hostname = qualify_hostname(res.get("hostname", ""), suffix)
            res_dict = {"hostname": hostname, "ip": None, "ipv6": None}
            if is_v4:
                res_dict["ip"] = res.get("ip-address")
            else:
                addrs = res.get("ip-addresses") or []
                res_dict["ipv6"] = addrs[0] if addrs else None
            if hostname and (res_dict["ip"] or res_dict["ipv6"]):
                reservations.append(res_dict)

    return reservations


def query_kea_leases(service: str = "dhcp4") -> List[Dict]:
    """
    Query active leases from Kea.

    Only returns leases in the active (default) state with a future expiry;
    declined and expired-reclaimed leases are skipped so we never publish DNS
    for an address a client no longer holds.

    Returns list of lease dicts with keys: hostname, ip, ipv6, expires
    (expires is an absolute unix timestamp). Raises KeaUnavailableError if Kea
    is unavailable.
    """
    now = int(time.time())
    is_v4 = service == "dhcp4"
    root_key = "Dhcp4" if is_v4 else "Dhcp6"
    subnet_key = "subnet4" if is_v4 else "subnet6"

    # Build a subnet-id -> qualifying-suffix map from the running config so each
    # lease is named the same way the live kea-dhcp-ddns path would name it.
    cfg = query_kea_api("config-get", service=service)
    dhcp_config = cfg.get("arguments", {}).get(root_key, {})
    global_suffix = dhcp_config.get("ddns-qualifying-suffix", "") or ""
    system_domain = get_system_domain()
    suffix_by_subnet = {}
    for subnet, net_suffix in _iter_kea_subnets(dhcp_config, subnet_key):
        sid = subnet.get("id")
        if sid is not None:
            suffix_by_subnet[sid] = _effective_suffix(subnet, net_suffix, global_suffix, system_domain)
    default_suffix = global_suffix or system_domain or ""

    command = "lease4-get-all" if is_v4 else "lease6-get-all"
    resp = query_kea_api(command, service=service)
    leases = []

    for lease in resp.get("arguments", {}).get("leases", []):
        # Skip non-active leases (declined / expired-reclaimed).
        try:
            state = int(lease.get("state", LEASE_STATE_DEFAULT))
        except (TypeError, ValueError):
            state = LEASE_STATE_DEFAULT
        if state != LEASE_STATE_DEFAULT:
            continue

        # "expire" is an absolute unix timestamp. 0/-1 are sometimes used to
        # mean "infinite"; map those to a long horizon. Skip already-expired.
        expire = lease.get("expire", 0)
        if expire in (0, -1, None):
            expires = now + 86400
        else:
            try:
                expire = int(expire)
            except (TypeError, ValueError):
                continue
            if expire <= now:
                continue
            expires = expire

        suffix = suffix_by_subnet.get(lease.get("subnet-id"), default_suffix)
        lease_dict = {
            "hostname": qualify_hostname(lease.get("hostname", ""), suffix),
            "ip": None,
            "ipv6": None,
            "expires": expires,
        }

        if service == "dhcp4":
            lease_dict["ip"] = lease.get("ip-address")
        if service == "dhcp6":
            lease_dict["ipv6"] = lease.get("ip-address")

        if lease_dict["hostname"] and (lease_dict["ip"] or lease_dict["ipv6"]):
            leases.append(lease_dict)

    return leases


def read_host_entries() -> Dict[str, List[str]]:
    """
    Parse host_entries.conf and return dict of {name: [entries]}.
    Each entry is a raw line from the config (local-data or local-data-ptr).
    Returns empty dict if file doesn't exist.
    """
    entries: Dict[str, List[str]] = {}

    try:
        with open(HOST_ENTRIES) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if line.startswith("local-data:"):
                    # Format: local-data: "name TTL IN TYPE rdata"
                    match = re.search(r'local-data:\s+"([^"\s]+)', line)
                    if match:
                        name = match.group(1).rstrip(".")
                        entries.setdefault(name, []).append(line)

                elif line.startswith("local-data-ptr:"):
                    # Format: local-data-ptr: "ip rdata"; the "name" is the IP
                    match = re.search(r'local-data-ptr:\s+"([^\s"]+)', line)
                    if match:
                        ip = match.group(1)
                        entries.setdefault(ip, []).append(line)
    except FileNotFoundError:
        pass
    except Exception as e:
        logging.getLogger(SYSLOG_IDENT).warning(f"Error reading {HOST_ENTRIES}: {e}")

    return entries


def reverse_ptr(ip: str) -> Optional[str]:
    """
    Return the PTR name for an IP address (IPv4 in-addr.arpa or IPv6 ip6.arpa).
    Returns None if IP is invalid.
    """
    try:
        return str(ipaddress.ip_address(ip).reverse_pointer)
    except ValueError:
        return None


def is_ptr_name(name: str) -> bool:
    """True if name is a reverse-DNS owner name."""
    return name.endswith(".in-addr.arpa") or name.endswith(".ip6.arpa")


def is_sane_name(name: str, logger: Optional[logging.Logger] = None) -> bool:
    """
    Return True if name is a plausible hostname we should register.

    Rejects empty strings, the DNS root, reserved names, names whose first
    label contains invalid characters, and all-numeric names (IPs mistaken for
    hostnames). Mirrors the daemon's check so the sync path applies the same
    hygiene as the live listener.
    """
    if not name or name in _NONSENSE_NAMES:
        if logger:
            logger.warning("Rejecting nonsense name: %r", name)
        return False

    first_label = name.split(".")[0]
    if not first_label or not _LABEL_RE.match(first_label):
        if logger:
            logger.warning("Rejecting name with invalid first label: %r", name)
        return False

    if all(part.isdigit() for part in name.split(".")):
        if logger:
            logger.warning("Rejecting all-numeric name (looks like an IP): %r", name)
        return False

    return True


def unbound_control(args: List[str], timeout: float = 10.0) -> bool:
    """
    Call unbound-control with given arguments.
    Always passes -c UNBOUND_CONF so the remote-control socket is found even
    when the caller's environment doesn't have the default config in scope.
    Returns True on success, False on failure.
    """
    cmd = [UNBOUND_CONTROL, "-c", UNBOUND_CONF] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logging.getLogger(SYSLOG_IDENT).error(f"unbound-control timeout: {' '.join(args)}")
        return False
    except Exception as e:
        logging.getLogger(SYSLOG_IDENT).error(f"unbound-control failed: {e}")
        return False


def unbound_list_local_data() -> Dict[str, List[str]]:
    """
    Query Unbound's local_data store via list_local_data.
    Returns dict of {name: [entries]} for all A/AAAA/PTR records.
    """
    local_data: Dict[str, List[str]] = {}

    try:
        result = subprocess.run(
            [UNBOUND_CONTROL, "-c", UNBOUND_CONF, "list_local_data"],
            capture_output=True, text=True, timeout=10.0
        )
        if result.returncode != 0:
            return local_data

        # Format: "name. TTL IN TYPE rdata"
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue

            name = parts[0].rstrip(".")
            rdtype = parts[3]

            if rdtype in ("A", "AAAA", "PTR"):
                local_data.setdefault(name, []).append(line)

    except Exception as e:
        logging.getLogger(SYSLOG_IDENT).warning(f"Failed to query list_local_data: {e}")

    return local_data


def is_in_host_entries(name: str, host_entries: Dict[str, List[str]]) -> bool:
    """Check if name appears in host_entries.conf."""
    return name in host_entries


def _forward_ips(unbound_data: Dict[str, List[str]]) -> Dict[str, Set[str]]:
    """Map each forward (non-PTR) owner name to the set of its A/AAAA IPs."""
    forward_ips: Dict[str, Set[str]] = {}
    for name, lines in unbound_data.items():
        if is_ptr_name(name):
            continue
        ips: Set[str] = set()
        for line in lines:
            parts = line.split()
            if len(parts) >= 5 and parts[3] in ("A", "AAAA"):
                ips.add(parts[4])
        if ips:
            forward_ips[name] = ips
    return forward_ips


def find_stale_records(unbound_data: Dict[str, List[str]],
                       kea_pairs: Set[Tuple[str, str]],
                       host_entries: Dict[str, List[str]]) -> Tuple[Set[str], Set[str]]:
    """
    Single source of truth for what cleanup removes — used by both the audit
    (to show the preview) and the clean script (to act). Returns
    (stale_names, orphaned_ptrs):

      stale_names   -- forward (A/AAAA) owner names where no (name, ip) pair is
                       known to Kea and which are not OPNsense-managed.
      orphaned_ptrs -- PTR owner names not backed by a *surviving* forward
                       record (i.e. no forward maps to them once stale forwards
                       are removed), and not OPNsense-managed.

    Using per-(hostname, ip) pairs rather than a flat IP set means a record like
    "host-A → IP-X" is correctly flagged stale when Kea's IP-X is leased to a
    different host-B — IP-X is in Kea's address space, but not for host-A.

    Computing orphans against surviving forwards means a PTR whose only forward
    is itself stale is correctly flagged for removal alongside it, while a PTR
    backed by a live record is preserved.
    """
    forward_ips = _forward_ips(unbound_data)

    # Stale forwards: no (name, ip) pair backed by Kea, not OPNsense-managed.
    stale_names: Set[str] = set()
    for name, ips in forward_ips.items():
        if is_in_host_entries(name, host_entries):
            continue
        if not any((name, ip) in kea_pairs for ip in ips):
            stale_names.add(name)

    # PTR names that a surviving (kept) forward still points to.
    surviving_ptr_names: Set[str] = set()
    for name, ips in forward_ips.items():
        if name in stale_names:
            continue
        for ip in ips:
            ptr = reverse_ptr(ip)
            if ptr:
                surviving_ptr_names.add(ptr)

    orphaned_ptrs: Set[str] = set()
    for name in unbound_data:
        if not is_ptr_name(name):
            continue
        if is_in_host_entries(name, host_entries):
            continue
        if name not in surviving_ptr_names:
            orphaned_ptrs.add(name)

    return stale_names, orphaned_ptrs


def collect_kea_pairs(logger: Optional[logging.Logger] = None) -> Set[Tuple[str, str]]:
    """
    Collect every (hostname, ip) pair Kea knows about (reservations + active
    leases, v4 and v6).  Raises KeaUnavailableError if Kea cannot be reached —
    callers that clean records must not proceed without this data.
    """
    kea_pairs: Set[Tuple[str, str]] = set()
    any_ok = False
    for service in ("dhcp4", "dhcp6"):
        try:
            reservations = query_kea_reservations(service=service)
        except KeaServiceUnavailableError as e:
            if logger:
                logger.info(f"Skipping {service} (offline/unavailable): {e}")
            continue
        # Service responded — leases must be readable to clean safely. If they
        # are not, the error propagates so the caller aborts rather than
        # deleting live lease records it cannot see.
        leases = query_kea_leases(service=service)
        any_ok = True
        for res in reservations:
            for ip in (res["ip"], res["ipv6"]):
                if ip and res["hostname"]:
                    kea_pairs.add((res["hostname"], ip))
        for lease in leases:
            for ip in (lease["ip"], lease["ipv6"]):
                if ip and lease["hostname"]:
                    kea_pairs.add((lease["hostname"], ip))
    if not any_ok:
        raise KeaUnavailableError("No Kea service (dhcp4/dhcp6) responded")
    return kea_pairs
