#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
keaubnd_sync.py -- Shared library for Kea-Unbound sync utilities.

Provides:
  - Kea queries (reservations, leases) via the transport layer (kea_transport)
  - Unbound control wrapper
  - host_entries.conf parser
  - Stale/orphaned record detection (shared by audit and clean)
  - Hostname sanity checks and IP/PTR conversion
  - Error handling for missing/unavailable services
  - Syslog logging

Requires dnspython (py3X-dnspython) which is a package dependency — all scripts
that import this lib run in the same environment as the daemon and have access
to it.
"""

from __future__ import annotations

import contextlib
import fcntl
import ipaddress
import logging
import os
import re
import subprocess
import sys
import syslog
import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set, Tuple

import dns.exception
import dns.name
import dns.reversename

# Kea connection lives in the transport layer (unix socket / HTTP, with the
# config-reading resolver). The exception types are defined there and re-exported
# here so existing callers can keep importing them from keaubnd_sync.
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
# "kea-ubnd" deliberately avoids the substring "unbound": OPNsense's core resolver
# syslog-ng filter is program("unbound"), which matches as an unanchored substring,
# so any tag containing "unbound" would be routed into the resolver log instead of ours.
SYSLOG_IDENT = "kea-ubnd"
MUTATION_LOCK_DIR = "/var/run/keaubnd"
MUTATION_LOCK_PATH = f"{MUTATION_LOCK_DIR}/unbound-mutation.lock"

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
    the keaubnd log. libc syslog() sets a proper program tag via openlog()
    and includes the PID. Every plugin component (daemon, sync/audit/clean
    scripts, start.py) shares this handler so all logs carry the same
    SYSLOG_IDENT tag and land in the one keaubnd log.
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


@contextlib.contextmanager
def unbound_mutation_lock(blocking: bool = True):
    """Advisory flock over MUTATION_LOCK_PATH.

    All Unbound-mutation callers (kea-sync.py, local-data-clean.py, daemon live
    path) hold this lock for their whole run so unbound-control mutations are
    serialized. The daemon live path uses blocking=False: on BlockingIOError it
    ACK-fails and calls note_dirty rather than waiting.

    Creates MUTATION_LOCK_DIR on first use; idempotent.
    """
    os.makedirs(MUTATION_LOCK_DIR, mode=0o700, exist_ok=True)
    with open(MUTATION_LOCK_PATH, "w") as f:
        flag = fcntl.LOCK_EX if blocking else (fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(f, flag)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


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


def get_synthesize_ptr() -> bool:
    """Return the synthesize_ptr plugin setting (default True when absent)."""
    try:
        node = ET.parse(CONFIG_XML).getroot().find(
            "OPNsense/KeaUbnd/general/synthesize_ptr"
        )
        if node is not None and node.text:
            return node.text.strip() == "1"
    except Exception:
        pass
    return True


def get_collision_policy() -> str:
    """Return the collision_policy setting: 'allow', 'first_wins', or 'last_wins'.
    Defaults to 'last_wins' when absent."""
    try:
        node = ET.parse(CONFIG_XML).getroot().find(
            "OPNsense/KeaUbnd/general/collision_policy"
        )
        if node is not None and node.text:
            return node.text.strip()
    except Exception:
        pass
    return "last_wins"


def get_clean_on_restart() -> bool:
    """Return True when clean_on_restart is enabled in config.xml."""
    try:
        node = ET.parse(CONFIG_XML).getroot().find(
            "OPNsense/KeaUbnd/general/clean_on_restart"
        )
        if node is not None and node.text:
            return node.text.strip() == "1"
    except Exception:
        pass
    return False


def get_sm_config():
    """Read advanced SM tunables from config.xml and return a populated SMConfig.
    Falls back to SMConfig defaults on any read/parse error."""
    from .consistency_sm import SMConfig  # local import to avoid circular dependency
    defaults = SMConfig()
    try:
        node = ET.parse(CONFIG_XML).getroot().find("OPNsense/KeaUbnd/general")
        if node is None:
            return defaults

        def _int(name, default):
            child = node.find(name)
            if child is not None and child.text:
                try:
                    v = int(child.text.strip())
                    if v >= 0:
                        return v
                except ValueError:
                    pass
            return default

        cfg = SMConfig()
        cfg.dirty_cap = _int("dirty_set_cap", defaults.dirty_cap)
        cfg.max_full_sync_attempts = _int("max_full_sync_attempts", defaults.max_full_sync_attempts)
        minutes = _int("readiness_watchdog_minutes", int(defaults.watchdog_seconds // 60))
        cfg.watchdog_seconds = float(minutes * 60)
        return cfg
    except Exception:
        return defaults


# Path to kea-dhcp-ddns.conf — read directly because D2 has no control socket
# in the OPNsense provisioning (same approach as ConfigCheckController.php).
D2_CONF = "/usr/local/etc/kea/kea-dhcp-ddns.conf"


def _arpa_to_ip(ptr_name: str) -> str:
    """
    Decode a reverse-DNS name (in-addr.arpa / ip6.arpa) back to its IP address
    string, or '' if the name is not a full, parseable PTR owner name.

    Used to bridge OPNsense's IP-keyed local-data-ptr format:
      local-data-ptr: "192.168.1.1 hostname."
    when the caller holds only the arpa form "1.1.168.192.in-addr.arpa".

    Delegates the arpa→address decoding to dns.reversename (dnspython), then
    normalises through ipaddress to get canonical form (e.g. "::1" not
    "0:0:0:0:0:0:0:1").  Returns '' on any parse or conversion failure so
    callers can use a simple truthiness check.
    """
    try:
        raw = dns.reversename.to_address(dns.name.from_text(ptr_name))
        return str(ipaddress.ip_address(raw))
    except (dns.exception.DNSException, ValueError):
        return ""


def read_d2_reverse_zones() -> Set[str]:
    """
    Return the set of reverse-DNS zone names configured in kea-dhcp-ddns.conf
    (from reverse-ddns.ddns-domains[].name, trailing dot stripped).

    Returns empty set if the file is absent, unparseable, or has no reverse
    domains. Callers treat an empty set as "D2 is not managing any reverse zones."
    """
    try:
        import json as _json
        with open(D2_CONF) as f:
            conf = _json.load(f)
        domains = conf.get("DhcpDdns", {}).get("reverse-ddns", {}).get("ddns-domains", [])
        return {d["name"].rstrip(".") for d in domains if d.get("name")}
    except Exception:
        return set()


def ip_covered_by_d2_reverse(ip: str, zones: Set[str]) -> bool:
    """
    Return True if the given IP's arpa form (in-addr.arpa / ip6.arpa) is a
    sub-domain of any zone in *zones*.

    D2 matches reverse zones by suffix: 192.168.1.1 → "1.1.168.192.in-addr.arpa"
    is covered by zone "1.168.192.in-addr.arpa" (192.168.1.0/24 delegation).
    """
    if not zones:
        return False
    arpa = reverse_ptr(ip)
    if not arpa:
        return False
    arpa = arpa.rstrip(".")
    for zone in zones:
        zone = zone.rstrip(".")
        if arpa == zone or arpa.endswith("." + zone):
            return True
    return False


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


def _iter_kea_subnets(dhcp_config: Dict, subnet_key: str, global_send: bool = True):
    """
    Yield (subnet, net_suffix, net_send) for every subnet.
    net_suffix: parent shared-network's ddns-qualifying-suffix ('' for top-level).
    net_send:   parent's ddns-send-updates value for inheritance (global for top-level).
    """
    for subnet in dhcp_config.get(subnet_key, []):
        yield subnet, "", global_send
    for shared in dhcp_config.get("shared-networks", []):
        net_suffix = shared.get("ddns-qualifying-suffix", "") or ""
        net_send = bool(shared.get("ddns-send-updates", global_send))
        for subnet in shared.get(subnet_key, []):
            yield subnet, net_suffix, net_send


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
    global_send = bool(dhcp_config.get("ddns-send-updates", True))
    system_domain = get_system_domain()

    reservations = []
    # Per-subnet reservations (incl. shared-networks), each qualified with that
    # subnet's effective DDNS suffix; then any global reservations.
    # Subnets where ddns-send-updates resolves to false are skipped entirely.
    sources = [
        (subnet,
         _effective_suffix(subnet, net_suffix, global_suffix, system_domain),
         bool(subnet.get("ddns-send-updates", net_send)))
        for subnet, net_suffix, net_send in _iter_kea_subnets(dhcp_config, subnet_key, global_send)
    ]
    sources.append((dhcp_config, global_suffix or system_domain or "", global_send))
    for source, suffix, send in sources:
        if not send:
            continue
        for res in source.get("reservations", []):
            hostname = qualify_hostname(res.get("hostname", ""), suffix)
            if not hostname:
                continue
            if is_v4:
                ip = res.get("ip-address")
                if ip:
                    reservations.append({"hostname": hostname, "ip": ip, "ipv6": None})
            else:
                # DHCPv6 reservations carry a list of addresses — emit one dict
                # per address so every reserved IP gets a DNS record.
                for addr in (res.get("ip-addresses") or []):
                    if addr:
                        reservations.append({"hostname": hostname, "ip": None, "ipv6": addr})

    return reservations


def _build_suffix_map(service: str, dhcp_config: Dict) -> Tuple[Dict, str, Set]:
    """Build subnet-id → ddns-qualifying-suffix map and DDNS-disabled subnet set.
    Returns (suffix_by_subnet, default_suffix, ddns_disabled_subnets).
    ddns_disabled_subnets: IDs of subnets where ddns-send-updates resolves to false.
    """
    is_v4 = service == "dhcp4"
    subnet_key = "subnet4" if is_v4 else "subnet6"
    global_suffix = dhcp_config.get("ddns-qualifying-suffix", "") or ""
    global_send = bool(dhcp_config.get("ddns-send-updates", True))
    system_domain = get_system_domain()
    suffix_by_subnet: Dict = {}
    ddns_disabled_subnets: Set = set()
    for subnet, net_suffix, net_send in _iter_kea_subnets(dhcp_config, subnet_key, global_send):
        sid = subnet.get("id")
        if sid is not None:
            suffix_by_subnet[sid] = _effective_suffix(
                subnet, net_suffix, global_suffix, system_domain)
            if not bool(subnet.get("ddns-send-updates", net_send)):
                ddns_disabled_subnets.add(sid)
    return suffix_by_subnet, (global_suffix or system_domain or ""), ddns_disabled_subnets


def _normalize_raw_lease(lease: Dict, is_v4: bool,
                          suffix_by_subnet: Dict, default_suffix: str,
                          now: int,
                          ddns_disabled_subnets: Optional[Set] = None) -> Optional[Dict]:
    """Normalize a raw Kea lease dict to our internal format.
    Returns None if the lease should be skipped (wrong state, expired, no hostname/IP,
    or subnet has ddns-send-updates disabled).
    """
    try:
        state = int(lease.get("state", LEASE_STATE_DEFAULT))
    except (TypeError, ValueError):
        state = LEASE_STATE_DEFAULT
    if state != LEASE_STATE_DEFAULT:
        return None

    # Only IA_NA leases (type=0) carry host addresses that belong in DNS.
    # IA_TA (type=1) are temporary addresses not intended for stable DNS entries.
    # IA_PD (type=2) are delegated prefixes — the "address" is a network prefix,
    # not a host, and registering it would produce a semantically wrong record.
    try:
        lease_type = int(lease.get("type", 0))
    except (TypeError, ValueError):
        lease_type = 0
    if lease_type != 0:
        return None

    if ddns_disabled_subnets and lease.get("subnet-id") in ddns_disabled_subnets:
        return None

    expire = lease.get("expire", 0)
    if expire in (0, -1, None):
        # Kea API (lease4-get, lease4-get-all) returns "cltt" (client last
        # transaction time) and "valid-lft" but not "expire" directly in most
        # responses.  Compute the expiry from those fields if available.
        try:
            cltt = int(lease.get("cltt", 0))
            vlft = int(lease.get("valid-lft", 0))
        except (TypeError, ValueError):
            cltt, vlft = 0, 0
        if cltt > 0 and vlft > 0:
            expire = cltt + vlft
        else:
            expires = now + 86400
            expire = None  # skip the convert/check below
    if expire is not None:
        try:
            expire = int(expire)
        except (TypeError, ValueError):
            return None
        if expire <= now:
            return None
        expires = expire

    suffix = suffix_by_subnet.get(lease.get("subnet-id"), default_suffix)
    try:
        valid_lifetime = int(lease.get("valid-lft", 0))
    except (TypeError, ValueError):
        valid_lifetime = 0

    lease_dict: Dict = {
        "hostname": qualify_hostname(lease.get("hostname", ""), suffix),
        "ip": None,
        "ipv6": None,
        "expires": expires,
        "valid_lifetime": valid_lifetime,
    }
    if is_v4:
        lease_dict["ip"] = lease.get("ip-address")
    else:
        lease_dict["ipv6"] = lease.get("ip-address")

    if lease_dict["hostname"] and (lease_dict["ip"] or lease_dict["ipv6"]):
        return lease_dict
    return None


def query_kea_leases(service: str = "dhcp4") -> List[Dict]:
    """
    Query active leases from Kea.

    Only returns leases in the active (default) state with a future expiry;
    declined and expired-reclaimed leases are skipped so we never publish DNS
    for an address a client no longer holds.

    Returns list of lease dicts with keys: hostname, ip, ipv6, expires,
    valid_lifetime (expires is an absolute unix timestamp).
    Raises KeaUnavailableError if Kea is unavailable.
    """
    now = int(time.time())
    is_v4 = service == "dhcp4"
    root_key = "Dhcp4" if is_v4 else "Dhcp6"
    cfg = query_kea_api("config-get", service=service)
    dhcp_config = cfg.get("arguments", {}).get(root_key, {})
    suffix_by_subnet, default_suffix, ddns_disabled_subnets = _build_suffix_map(service, dhcp_config)

    command = "lease4-get-all" if is_v4 else "lease6-get-all"
    resp = query_kea_api(command, service=service)
    leases = []
    for raw in resp.get("arguments", {}).get("leases", []):
        ld = _normalize_raw_lease(raw, is_v4, suffix_by_subnet, default_suffix, now,
                                  ddns_disabled_subnets)
        if ld is not None:
            leases.append(ld)
    return leases


def query_kea_leases_by_hostname(hostname: str,
                                  service: str = "dhcp4") -> List[Dict]:
    """Query active leases for a specific hostname (lease4/6-get-by-hostname).

    Returns a list in the same format as query_kea_leases(). Used by kea-sync.py
    for targeted drain (--names filter) so only the dirty names are re-fetched
    rather than the full lease table.
    """
    now = int(time.time())
    is_v4 = service == "dhcp4"
    root_key = "Dhcp4" if is_v4 else "Dhcp6"
    cfg = query_kea_api("config-get", service=service)
    dhcp_config = cfg.get("arguments", {}).get(root_key, {})
    suffix_by_subnet, default_suffix, ddns_disabled_subnets = _build_suffix_map(service, dhcp_config)

    command = "lease4-get-by-hostname" if is_v4 else "lease6-get-by-hostname"
    resp = query_kea_api(command, arguments={"hostname": hostname}, service=service)
    leases = []
    for raw in resp.get("arguments", {}).get("leases", []):
        ld = _normalize_raw_lease(raw, is_v4, suffix_by_subnet, default_suffix, now,
                                  ddns_disabled_subnets)
        if ld is not None:
            leases.append(ld)
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
    Return True if *name* is a plausible hostname suitable for registration in
    Unbound's local zone.  Called on every name before any write; both the live
    listener (kea-ubnd-ddns.py) and the sync path (kea-sync.py) use this
    single implementation so the two paths accept exactly the same set of names.

    Three-layer filter:

    Layer 1 — semantic fast-path
        Rejects names that are structurally valid DNS but meaningless or
        dangerous here: the empty string, the DNS root, and bare stub hostnames
        ("localhost", "localdomain") that should never appear in our zone.

    Layer 2 — structural validity (via dnspython + _LABEL_RE)
        dns.name.from_text() enforces label length ≤ 63 bytes and total wire
        length ≤ 255 bytes (RFC 1035 §2.3.4) without us reimplementing it.
        _LABEL_RE then checks RFC 1123 §2.1 character-set constraints
        (alphanumeric + hyphen, not starting or ending with a hyphen) because
        dnspython's parser accepts a wider character set than we want.  Every
        label is validated — not just the first — because unbound-control
        silently accepts records with invalid middle labels and this is the only
        gate that stops garbage entering the local zone.

    Layer 3 — DHCP-artifact filter
        Rejects names whose first label is all-numeric.  This is not a DNS
        rule; it is specific to Kea behaviour: when a DHCP client sends a bare
        integer as DHCP option 12 (hostname), or when Kea generates a synthetic
        hostname from the lease sequence number, qualify_hostname() appends the
        domain suffix and produces "123456789.lan" — structurally valid DNS but
        never a real hostname.  Checking only labels[0] is intentional: the
        domain-suffix labels ("lan", "local", …) are legitimately non-numeric.
    """
    # Layer 1: semantic fast-path
    if not name or name in _NONSENSE_NAMES:
        if logger:
            logger.warning("Rejecting nonsense name: %r", name)
        return False

    # Layer 2a: structural validity — length and empty-label detection
    try:
        dns.name.from_text(name if name.endswith(".") else name + ".")
    except dns.exception.DNSException as exc:
        if logger:
            logger.warning("Rejecting structurally invalid name %r: %s", name, exc)
        return False

    # Layer 2b: character-set check (dnspython does not enforce RFC 1123 chars)
    labels = [l for l in name.split(".") if l]
    for label in labels:
        if not _LABEL_RE.match(label):
            if logger:
                logger.warning("Rejecting name with invalid label %r in: %r", label, name)
            return False

    # Layer 3: DHCP-artifact filter
    if labels[0].isdigit():
        if logger:
            logger.warning("Rejecting all-numeric first label (looks like IP/counter): %r", name)
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


def unbound_local_datas_batch(records: List[str], timeout: float = 30.0) -> bool:
    """Add multiple records to Unbound via local_datas (stdin protocol).

    Equivalent to repeated local_data calls but uses a single unbound-control
    exec, which is significantly faster for bulk adds (full reconcile).
    Returns True if all records were accepted, False on any error.
    """
    if not records:
        return True
    cmd = [UNBOUND_CONTROL, "-c", UNBOUND_CONF, "local_datas"]
    data = "\n".join(records) + "\n"
    try:
        result = subprocess.run(cmd, input=data, capture_output=True, text=True,
                                timeout=timeout)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logging.getLogger(SYSLOG_IDENT).error("unbound-control local_datas timeout")
        return False
    except Exception as e:
        logging.getLogger(SYSLOG_IDENT).error(f"unbound-control local_datas failed: {e}")
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


def forward_ips_by_type(unbound_data: Dict[str, List[str]],
                        rtype: str) -> Dict[str, Set[str]]:
    """Like _forward_ips but filtered to a single record type ('A' or 'AAAA').

    Used by kea-sync.py so collision checks compare within the same address
    family only — avoids false conflicts when a host has both A and AAAA records.
    """
    result: Dict[str, Set[str]] = {}
    for name, lines in unbound_data.items():
        if is_ptr_name(name):
            continue
        ips: Set[str] = set()
        for line in lines:
            parts = line.split()
            if len(parts) >= 5 and parts[3] == rtype:
                ips.add(parts[4])
        if ips:
            result[name] = ips
    return result


def find_stale_records(unbound_data: Dict[str, List[str]],
                       kea_pairs: Set[Tuple[str, str]],
                       host_entries: Dict[str, List[str]],
                       synthesize_ptr: bool = True,
                       d2_reverse_zones: Optional[Set[str]] = None) -> Tuple[Set[Tuple[str, str]], Set[str]]:
    """
    Single source of truth for what cleanup removes — used by both the audit
    (to show the preview) and the clean script (to act). Returns
    (stale_pairs, orphaned_ptrs):

      stale_pairs   -- (name, ip) tuples where that specific IP is not backed by
                       Kea for that name, and the name is not OPNsense-managed.
                       Per-IP rather than per-name: a dual-stack host with a
                       valid A but stale AAAA produces one stale pair for the
                       AAAA only — the surviving family is left untouched.
      orphaned_ptrs -- PTR owner names not backed by any surviving (non-stale)
                       (name, ip) pair, not OPNsense-managed, and (when
                       synthesize_ptr is False) not covered by a D2 reverse
                       zone (those are D2's responsibility, not ours).

    Using per-(name, ip) pairs rather than per-name means a record like
    "host-A → IP-X" is correctly flagged stale when Kea's IP-X is leased to a
    different host-B — IP-X is in Kea's address space, but not for host-A.

    Computing orphans against surviving (non-stale) (name, ip) pairs means
    a PTR for a stale IP is correctly orphaned even when that name still has a
    valid record in the other address family. A PTR backed by any live pair is
    preserved.

    Synthesis-aware PTR cleanup rules (applied only to PTR records):
      1. OPNsense host-override guard: skip if arpa name OR decoded IP appears
         in host_entries (host_entries is IP-keyed for PTRs; the arpa check is a
         belt-and-suspenders fallback).
      2. If synthesize_ptr is False AND the PTR's IP is not covered by any D2
         reverse zone: orphan unconditionally — neither synthesis nor D2 should
         be producing it, so it is a leftover that must be removed.
      3. Otherwise: orphan only if no surviving forward record points to it.
    """
    _d2_zones: Set[str] = d2_reverse_zones if d2_reverse_zones is not None else set()

    forward_ips = _forward_ips(unbound_data)

    # Stale forwards: per (name, ip) — each IP judged independently against Kea.
    stale_pairs: Set[Tuple[str, str]] = set()
    for name, ips in forward_ips.items():
        if is_in_host_entries(name, host_entries):
            continue
        for ip in ips:
            if (name, ip) not in kea_pairs:
                stale_pairs.add((name, ip))

    # PTR names that a surviving (non-stale) (name, ip) pair still points to.
    surviving_ptr_names: Set[str] = set()
    for name, ips in forward_ips.items():
        for ip in ips:
            if (name, ip) not in stale_pairs:
                ptr = reverse_ptr(ip)
                if ptr:
                    surviving_ptr_names.add(ptr)

    orphaned_ptrs: Set[str] = set()
    for name in unbound_data:
        if not is_ptr_name(name):
            continue

        # Host-override guard: host_entries PTRs are IP-keyed (e.g. "192.168.1.1"),
        # not arpa-keyed, so we must decode the arpa name back to an IP to match.
        # Keep the arpa-name check too as a belt-and-suspenders fallback.
        if is_in_host_entries(name, host_entries):
            continue
        decoded_ip = _arpa_to_ip(name)
        if decoded_ip and is_in_host_entries(decoded_ip, host_entries):
            continue

        # Synthesis-aware unconditional orphan: if synthesis is OFF and D2 does
        # not cover this IP, there is no legitimate source for this PTR — remove
        # it even if a forward record still exists.
        if not synthesize_ptr and not ip_covered_by_d2_reverse(decoded_ip, _d2_zones):
            orphaned_ptrs.add(name)
            continue

        # Orphan if no surviving (non-stale) forward points to this PTR.
        if name not in surviving_ptr_names:
            orphaned_ptrs.add(name)

    return stale_pairs, orphaned_ptrs


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


def clean_stale_records(
    unbound_data: Dict[str, List[str]],
    stale_pairs: Set[Tuple[str, str]],
    orphaned_ptrs: Set[str],
    dry_run: bool,
    logger: logging.Logger,
) -> int:
    """Remove stale (name, ip) pairs and orphaned PTRs from Unbound's local_data.

    unbound_control local_data_remove wipes ALL record types for a name, so
    partial-stale names (e.g. valid A, stale AAAA) require a remove-all then
    restore-valid dance.  unbound_data must reflect the current Unbound state
    so the surviving records can be re-added correctly.

    Returns the number of unbound-control errors encountered.
    """
    errors = 0

    stale_ips_by_name: Dict[str, Set[str]] = {}
    for name, ip in stale_pairs:
        stale_ips_by_name.setdefault(name, set()).add(ip)

    for name in sorted(stale_ips_by_name):
        stale_ips = stale_ips_by_name[name]
        valid_records = []
        for line in unbound_data.get(name, []):
            parts = line.split()
            if len(parts) >= 5 and parts[3] in ("A", "AAAA") and parts[4] not in stale_ips:
                valid_records.append((parts[4], parts[1], parts[3]))  # ip, ttl, rtype

        if dry_run:
            logger.info("[dry-run] local_data_remove %s (stale: %s)", name, sorted(stale_ips))
            continue

        if not unbound_control(["local_data_remove", name]):
            logger.error("clean-stale: failed to remove %s", name)
            errors += 1
            continue

        if valid_records:
            rrs = [f"{name} {ttl} IN {rtype} {ip}" for ip, ttl, rtype in valid_records]
            if not unbound_local_datas_batch(rrs):
                logger.error("clean-stale: failed to restore valid records for %s", name)
                errors += 1

        logger.info("clean-stale: removed stale address(es) for %s [%s]",
                    name, ", ".join(sorted(stale_ips)))

    for ptr in sorted(orphaned_ptrs):
        if dry_run:
            logger.info("[dry-run] local_data_remove %s (orphaned PTR)", ptr)
        elif not unbound_control(["local_data_remove", ptr]):
            logger.error("clean-stale: failed to remove PTR %s", ptr)
            errors += 1
        else:
            logger.info("clean-stale: removed orphaned PTR %s", ptr)

    return errors
