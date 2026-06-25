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
import json
import logging
import os
import re
import signal
import subprocess
import sys
import syslog
import time
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
from . import keaubnd_runtime as _rt

# HOST_ENTRIES kept as a module-level variable for compatibility with the daemon's
# _read_host_entries_at() swap trick. Functions that read Unbound paths call _rt.*
# directly; this constant matches the default so the swap condition is always met.
HOST_ENTRIES = "/var/unbound/host_entries.conf"
# "kea-ubnd" deliberately avoids the substring "unbound": OPNsense's core resolver
# syslog-ng filter is program("unbound"), which matches as an unanchored substring,
# so any tag containing "unbound" would be routed into the resolver log instead of ours.
SYSLOG_IDENT = "kea-ubnd"
MUTATION_LOCK_DIR = "/var/run/keaubnd"
MUTATION_LOCK_PATH = f"{MUTATION_LOCK_DIR}/unbound-mutation.lock"
MAGIC_STATE_PATH = f"{MUTATION_LOCK_DIR}/magic-state.json"

# Kea lease "state" enum: 0 = default/active (the only one we register),
# 1 = declined, 2 = expired-reclaimed.
LEASE_STATE_DEFAULT = 0

# Valid hostname label characters per RFC 1123 (first label / hostname part)
_LABEL_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')

# Names that are technically valid DNS but meaningless/dangerous for our use.
_NONSENSE_NAMES = {"", ".", "localhost", "localdomain"}

# Helpers for reverse PTR name validation (used by normalize_hostname).
_IPV6_NIBBLE = frozenset("0123456789abcdef")


def _is_ipv4_octet(s: str) -> bool:
    """True iff s is a decimal string representing 0–255 with no leading zeros."""
    return bool(s) and s.isdigit() and (s == "0" or (s[0] != "0" and int(s) <= 255))


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
def unbound_mutation_lock(blocking: bool = True, timeout_secs: float = 300):
    """Advisory flock over MUTATION_LOCK_PATH.

    All Unbound-mutation callers (kea-sync.py, local-data-clean.py, daemon live
    path) hold this lock for their whole run so unbound-control mutations are
    serialized.

    When blocking=True (default), the caller waits up to timeout_secs for the
    lock. A SIGALRM-based timeout (via setitimer for sub-second precision)
    prevents waiting forever if the lock holder hangs. On timeout, raises
    TimeoutError. kea-sync.py and local-data-clean.py use the default 300s.

    The daemon live path uses blocking=True, timeout_secs=~0.05 (50ms): a short
    bounded wait that avoids missing NCRs when kea-sync briefly holds the lock at
    startup. On timeout the name is marked dirty and the drain re-resolves it.

    Creates MUTATION_LOCK_DIR on first use; idempotent.
    """
    os.makedirs(MUTATION_LOCK_DIR, mode=0o700, exist_ok=True)
    acquired = False  # set True once flock returns; suppresses a spurious SIGALRM

    def _alarm_handler(signum, frame):
        if acquired:
            # flock returned before the signal was delivered (signal was already
            # queued when setitimer(0) cancelled the timer) — safe to ignore.
            return
        raise TimeoutError(
            f"unbound_mutation_lock: timed out waiting for lock after {timeout_secs}s"
        )

    with open(MUTATION_LOCK_PATH, "w") as f:
        flag = fcntl.LOCK_EX if blocking else (fcntl.LOCK_EX | fcntl.LOCK_NB)
        if blocking and timeout_secs > 0:
            old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
            signal.setitimer(signal.ITIMER_REAL, timeout_secs)
        try:
            fcntl.flock(f, flag)
            acquired = True
        except TimeoutError:
            logging.getLogger(SYSLOG_IDENT).error(
                "unbound_mutation_lock: gave up waiting after %gs — another "
                "process may be hung holding the lock", timeout_secs
            )
            raise
        finally:
            if blocking and timeout_secs > 0:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, old_handler)
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
    """Return the OPNsense system domain used as a last-resort FQDN suffix.
    Reads from the runtime config written by start.py; empty if unset."""
    return _rt.get_fallback_system_domain()


# ---------------------------------------------------------------------------
# Magic hostname helpers
# ---------------------------------------------------------------------------

def is_laa(mac_hex: str) -> bool:
    """Return True if the MAC address has the locally administered bit set (bit 1 of byte 0).

    Accepts colon-separated or bare hex strings. Returns False on any parse error.
    """
    try:
        first_byte = int(mac_hex.replace(":", "").replace("-", "")[:2], 16)
        return bool(first_byte & 0x02)
    except (ValueError, IndexError):
        return False


# Hardware types (IANA ARP) whose link-layer address is a 6-byte Ethernet MAC.
_ETHERNET_HW_TYPES: frozenset = frozenset([1, 6])


def duid_extract_mac(duid_hex: str) -> Optional[str]:
    """Extract the embedded MAC from a DUID-LLT (type 1) or DUID-LL (type 3).

    Wire layout:
      DUID-LLT: type(2B) + hw-type(2B) + time(4B) + mac(6B)
      DUID-LL:  type(2B) + hw-type(2B) + mac(6B)

    Returns a colon-separated lowercase MAC string when the DUID type is 1 or 3
    and the hardware type is Ethernet (hw-type 1 or 6). Returns None for DUID-EN,
    DUID-UUID, unsupported hardware types, or malformed input.
    """
    try:
        raw = bytes.fromhex(duid_hex.replace(":", "").replace("-", ""))
    except ValueError:
        return None
    if len(raw) < 4:
        return None

    duid_type = (raw[0] << 8) | raw[1]
    hw_type   = (raw[2] << 8) | raw[3]

    if hw_type not in _ETHERNET_HW_TYPES:
        return None

    if duid_type == 1:      # DUID-LLT
        mac_start = 8
    elif duid_type == 3:    # DUID-LL
        mac_start = 4
    else:
        return None

    if len(raw) < mac_start + 6:
        return None

    return ":".join(f"{b:02x}" for b in raw[mac_start:mac_start + 6])


def identifier_tail(id_value: str) -> str:
    """Strip separators from id_value and return the last 6 chars, uppercased."""
    clean = id_value.replace(":", "").replace("-", "").replace(".", "")
    return clean[-6:].upper()


def ip_suffix(ip: str) -> str:
    """Return last two octets of an IPv4 address, each zero-padded to 3 decimal digits, concatenated.

    Example: '192.168.1.50' → '001050'
    Returns '' for IPv6 or unparseable input (IP suffix is IPv4-only).
    """
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return ""
        octets = str(addr).split(".")
        return f"{int(octets[2]):03d}{int(octets[3]):03d}"
    except ValueError:
        return ""


def compute_magic_suffix(id_type: str, id_value: str, laa_tag: bool) -> str:
    """Return the full suffix block for a magic hostname.

    Examples:
      hw-address, aa:bb:cc:dd:ee:ff, laa_tag=False → 'mDDEEFF'
      hw-address, aa:bb:cc:dd:ee:ff, laa_tag=True  → 'laa-mDDEEFF'  (if LAA bit set)
      duid, ...                                     → 'd......'
      client-id, ...                                → 'c......'
      circuit-id, ...                               → 'r......'
      ip, 192.168.1.50                              → 'i001050'
    """
    if id_type == "ip":
        return f"i{ip_suffix(id_value)}"

    tag_map = {
        "hw-address": "m",
        "duid":       "d",
        "client-id":  "c",
        "circuit-id": "r",
    }
    tag = tag_map.get(id_type, "m")
    tail = identifier_tail(id_value)

    if laa_tag:
        if tag == "m" and is_laa(id_value):
            return f"laa-{tag}{tail}"
        if tag == "d":
            embedded_mac = duid_extract_mac(id_value)
            if embedded_mac and is_laa(embedded_mac):
                return f"laa-{tag}{tail}"
    return f"{tag}{tail}"


def compute_magic_names(
    collision_group: List[Dict],
    laa_tag: bool,
    existing_hostnames: Set[str],
    logger=None,
) -> Dict[str, str]:
    """Assign a magic FQDN (unqualified hostname) to each IP in a collision group.

    Each entry in collision_group must have:
      ip, id_type ('hw-address'|'duid'|'client-id'|'circuit-id'|'ip'), id_value, hostname

    Returns {ip: magic_hostname} (unqualified, no domain suffix).

    Handles:
    - Meta-collision: two entries produce the same suffix → deterministic counter
      appended (lexicographic sort on full id_value, 1-indexed).
    - Magic name squatting: computed name already in existing_hostnames → fall
      through to counter and log a prominent warning.
    """
    if not collision_group:
        return {}

    base_hostname = collision_group[0]["hostname"]

    # First pass: compute raw suffix for each entry.
    entries = []
    for entry in collision_group:
        suffix = compute_magic_suffix(entry["id_type"], entry["id_value"], laa_tag)
        entries.append({**entry, "_suffix": suffix})

    # Second pass: detect meta-collisions (same suffix from different entries).
    # Group by suffix; if >1 entry shares a suffix, assign counter by id_value sort.
    from collections import defaultdict
    suffix_groups: Dict[str, List[Dict]] = defaultdict(list)
    for e in entries:
        suffix_groups[e["_suffix"]].append(e)

    ip_to_magic: Dict[str, str] = {}
    for suffix, group in suffix_groups.items():
        if len(group) == 1:
            candidates = [(group[0], None)]
        else:
            # Meta-collision: sort by id_value for deterministic counter assignment.
            sorted_group = sorted(group, key=lambda e: e["id_value"])
            candidates = [(e, i + 1) for i, e in enumerate(sorted_group)]

        for entry, counter in candidates:
            if counter is None:
                magic_name = f"{base_hostname}-{suffix}"
            else:
                magic_name = f"{base_hostname}-{suffix}-{counter}"
                if logger:
                    logger.warning(
                        "[magic] meta-collision on suffix %s for hostname %s "
                        "(ids: %s) — using counter %d",
                        suffix, base_hostname,
                        ", ".join(e["id_value"] for e in group),
                        counter,
                    )

            # Squatting check: does this magic name collide with a real hostname?
            if magic_name in existing_hostnames:
                original = magic_name
                magic_name = f"{magic_name}-1"
                if logger:
                    logger.warning(
                        "[magic] magic name conflict: %s already exists as a real hostname "
                        "— possible squatting. Falling back to %s",
                        original, magic_name,
                    )

            ip_to_magic[entry["ip"]] = magic_name

    return ip_to_magic


def read_magic_state(path: str = MAGIC_STATE_PATH) -> dict:
    """Load the magic state file. Returns {} on any error (logs warning if logger provided)."""
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        # Log via syslog directly since we may not have a logger instance here.
        syslog.syslog(syslog.LOG_WARNING, f"kea-ubnd: failed to read magic state file: {e}")
        return {}


def write_magic_state(state: dict, path: str = MAGIC_STATE_PATH) -> None:
    """Atomically write the magic state file via tmp+rename."""
    import datetime
    state["version"] = 1
    state["ts"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(state, f, indent=2)
        os.rename(tmp, path)
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR, f"kea-ubnd: failed to write magic state file: {e}")




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
        d2_conf_path = _rt.get_kea_conf("d2") or "/usr/local/etc/kea/kea-dhcp-ddns.conf"
        with open(d2_conf_path) as f:
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

    Output is always lowercased — DNS names are case-insensitive and every
    downstream consumer (Unbound, dirty pool, kea_pairs lookup) expects lowercase.
    """
    hostname = (hostname or "").strip().rstrip(".").lower()
    if not hostname or "." in hostname:
        return hostname
    suffix = (suffix or "").strip(".").lower()
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
            # Capture all four identifier fields — present in reservation config,
            # used by magic name computation to pick the right suffix type.
            identifiers = {
                "hw_address": res.get("hw-address") or "",
                "duid":       res.get("duid") or "",
                "circuit_id": res.get("circuit-id") or "",
                "client_id":  res.get("client-id") or "",
            }
            if is_v4:
                # ip may be absent for hostname-only reservations; callers that
                # write DNS records already gate on ip being non-None.
                ip = res.get("ip-address") or None
                reservations.append({"hostname": hostname, "ip": ip,
                                     "ipv6": None, **identifiers})
            else:
                # DHCPv6 reservations carry a list of addresses — emit one dict
                # per address so every reserved IP gets a DNS record.
                for addr in (res.get("ip-addresses") or []):
                    if addr:
                        reservations.append({"hostname": hostname, "ip": None,
                                             "ipv6": addr, **identifiers})

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
        "hw_address": lease.get("hw-address") or "",   # v4: from Ethernet frame
        "duid":       lease.get("duid") or "",           # v6: always present; v4: always ""
        "circuit_id": lease.get("circuit-id") or "",     # always "": relay option, not stored in leases
        "client_id":  lease.get("client-id") or "",      # v4 Option 61 if client sent it; v6: ""
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


def read_host_entries(path: Optional[str] = None) -> Dict[str, List[str]]:
    """
    Parse host_entries.conf and return dict of {name: [entries]}.
    Each entry is a raw line from the config (local-data or local-data-ptr).
    Returns empty dict if file doesn't exist.

    The optional `path` argument overrides the runtime-config path (used by
    the daemon's HostEntriesCache to read an alternate --host-entries file).
    """
    entries: Dict[str, List[str]] = {}

    host_entries_path = path if path is not None else _rt.get_host_entries()
    try:
        with open(host_entries_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if line.startswith("local-data:"):
                    # Format: local-data: "name TTL IN TYPE rdata"
                    rest = line[len("local-data:"):].strip().lstrip('"')
                    name = rest.split()[0].rstrip(".") if rest else ""
                    if name:
                        entries.setdefault(name, []).append(line)

                elif line.startswith("local-data-ptr:"):
                    # Format: local-data-ptr: "ip rdata"; the "name" is the IP
                    rest = line[len("local-data-ptr:"):].strip().lstrip('"')
                    ip = rest.split()[0] if rest else ""
                    if ip:
                        entries.setdefault(ip, []).append(line)
    except FileNotFoundError:
        pass
    except Exception as e:
        logging.getLogger(SYSLOG_IDENT).warning(f"Error reading {host_entries_path}: {e}")

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


def normalize_hostname(raw: str,
                       logger: Optional[logging.Logger] = None) -> Optional[str]:
    """Normalize and validate a DNS name for use in Unbound local_data.

    Handles two name classes:

      Forward hostnames — e.g. "Laptop.Home.LAN": lowercased, labels restricted
        to letters/digits/hyphens (RFC 1123), first label must not be all-numeric
        (DHCP artifact filter).

      Reverse PTR names — in-addr.arpa (exactly 4 decimal octets 0-255, no
        leading zeros) and ip6.arpa (exactly 32 lowercase hex nibbles).

    Returns the canonical lowercase name, or None if the name is empty, a known
    DHCP artifact ("localhost" etc.), structurally invalid, or fails the
    format-specific rules above.  Applied at every Kea input boundary.
    """
    name = (raw or "").strip().rstrip(".").lower()
    if not name or name in _NONSENSE_NAMES:
        if logger:
            logger.warning("Rejecting nonsense name: %r", raw)
        return None

    # Reverse PTR: IPv4 — exactly "o1.o2.o3.o4.in-addr.arpa"
    if name.endswith(".in-addr.arpa"):
        parts = name[:-len(".in-addr.arpa")].split(".")
        if len(parts) == 4 and all(_is_ipv4_octet(p) for p in parts):
            return name
        if logger:
            logger.warning("Rejecting malformed in-addr.arpa name: %r", raw)
        return None

    # Reverse PTR: IPv6 — exactly 32 single hex nibbles followed by ".ip6.arpa"
    if name.endswith(".ip6.arpa"):
        nibbles = name[:-len(".ip6.arpa")].split(".")
        if len(nibbles) == 32 and all(len(n) == 1 and n in _IPV6_NIBBLE for n in nibbles):
            return name
        if logger:
            logger.warning("Rejecting malformed ip6.arpa name: %r", raw)
        return None

    # Forward hostname: structural validity via dnspython
    try:
        dns.name.from_text(name if name.endswith(".") else name + ".")
    except dns.exception.DNSException as exc:
        if logger:
            logger.warning("Rejecting structurally invalid name %r: %s", raw, exc)
        return None
    # RFC 1123 character-set check per label
    labels = [lbl for lbl in name.split(".") if lbl]
    for label in labels:
        if not _LABEL_RE.match(label):
            if logger:
                logger.warning("Rejecting name with invalid label %r in: %r", label, raw)
            return None
    # DHCP-artifact filter: all-numeric first label (e.g. "123456789.lan")
    if labels[0].isdigit():
        if logger:
            logger.warning("Rejecting all-numeric first label: %r", raw)
        return None
    return name




def unbound_control(args: List[str], timeout: float = 10.0) -> bool:
    """
    Call unbound-control with given arguments.
    Always passes -c <conf> so the remote-control socket is found even
    when the caller's environment doesn't have the default config in scope.
    Returns True on success, False on failure.
    """
    cmd = [_rt.get_unbound_control(), "-c", _rt.get_unbound_conf()] + args
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
    cmd = [_rt.get_unbound_control(), "-c", _rt.get_unbound_conf(), "local_datas"]
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
            [_rt.get_unbound_control(), "-c", _rt.get_unbound_conf(), "list_local_data"],
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
    """Return True if name is protected by host_entries.conf.

    host_entries uses two key formats:
      * forward names  — keyed by the bare FQDN (e.g. "router.lan")
      * PTR entries    — keyed by the raw IP string (e.g. "192.168.1.1")

    To let callers pass either an arpa name OR a raw IP for PTR protection
    (both are used in different places), this function:
      1. Checks name directly (handles forward names and raw-IP PTR keys).
      2. If name looks like an arpa reverse name, decodes it to an IP and
         checks the IP key — this makes both is_in_host_entries(ip, ...) and
         is_in_host_entries(arpa_name, ...) equivalent for PTR entries.
    """
    if name in host_entries:
        return True
    ip = _arpa_to_ip(name)
    return bool(ip) and ip in host_entries


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


# Maps each address family to its sibling — used by _evict_record to preserve
# the other family's records when local_data_remove wipes the whole name.
OTHER_FAMILY: Dict[str, str] = {"A": "AAAA", "AAAA": "A"}


def _qub_from_data(
    unbound_data: Dict[str, List[str]], name: str, rtype: str
) -> List[Tuple[str, int]]:
    """Return [(ip, ttl), ...] for name+rtype from an unbound_data snapshot dict.

    Parallel to the daemon's _filter_local_data but operates on the parsed dict
    returned by unbound_list_local_data() rather than the raw list_local_data
    stdout string.  Used to build the `qub` closure for _evict_record callers
    that work from a pre-fetched snapshot rather than the daemon's per-NCR string.
    """
    results: List[Tuple[str, int]] = []
    for line in unbound_data.get(name, []):
        parts = line.split()
        if len(parts) >= 5 and parts[3] == rtype:
            try:
                ttl = int(parts[1])
            except ValueError:
                ttl = 0
            results.append((parts[4], ttl))
    return results


def _evict_record(uc, qub, name, rdtype, evict_rdata, logger):
    """Remove evict_rdata of rdtype from name in Unbound, restoring all other
    records at that name.

    unbound-control's local_data_remove operates at the name level — it wipes
    every RRset at the name in one call. This wrapper snapshots the surviving
    records before the remove, then re-adds them afterward, so callers get
    targeted record removal even though the underlying API can only clear names.

    Arguments:
      uc           callable(args_list) → truthy on success; wraps unbound_control.
      qub          callable(name, rtype) → [(ip, ttl), ...]; reads current state.
                   May query Unbound live (daemon path) or filter a pre-fetched
                   snapshot dict (sync/clean path via _qub_from_data).
      name         DNS owner name to operate on.
      rdtype       Record type being evicted ('A', 'AAAA', 'PTR', 'ANY').
      evict_rdata  Iterable of rdata strings (IPs) to remove, or None/empty to
                   remove all records of rdtype.  Ignored for PTR and ANY which
                   always clear the name entirely.
      logger       Standard logger instance.

    PTR records at reverse arpa names are NOT touched — they live at different
    names and are the caller's responsibility.

    Returns True if local_data_remove succeeded, False otherwise.

    LOCKING: The caller MUST hold unbound_mutation_lock across the entire call.
    This function issues multiple unbound-control calls that are not individually
    atomic.  Do NOT acquire the lock inside this function.
    """
    other_type = OTHER_FAMILY.get(rdtype)

    if other_type is not None:
        preserved_other = qub(name, other_type)
        preserved_same = (
            [(ip, ttl) for ip, ttl in qub(name, rdtype) if ip not in evict_rdata]
            if evict_rdata else []
        )
    else:
        preserved_other = []
        preserved_same = []

    if not uc(["local_data_remove", name]):
        return False

    for ip, ttl in preserved_other:
        logger.info("Restore %s: %s -> %s (TTL %ds)", other_type, name, ip, ttl)
        uc(["local_data", f"{name} {ttl} IN {other_type} {ip}"])
    for ip, ttl in preserved_same:
        logger.info("Restore %s sibling: %s -> %s (TTL %ds)", rdtype, name, ip, ttl)
        uc(["local_data", f"{name} {ttl} IN {rdtype} {ip}"])

    return True


def find_stale_records(unbound_data: Dict[str, List[str]],
                       kea_pairs: Set[Tuple[str, str]],
                       host_entries: Dict[str, List[str]],
                       synthesize_ptr: bool = True,
                       d2_reverse_zones: Optional[Set[str]] = None,
                       protected_magic_fqdns: Optional[Set[str]] = None) -> Tuple[Set[Tuple[str, str]], Set[str]]:
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

    _protected = protected_magic_fqdns or set()

    # Stale forwards: per (name, ip) — each IP judged independently against Kea.
    stale_pairs: Set[Tuple[str, str]] = set()
    for name, ips in forward_ips.items():
        if is_in_host_entries(name, host_entries):
            continue
        if name.rstrip(".").lower() in _protected:
            continue  # live magic FQDN — intentionally written; not stale
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

        # Host-override guard: is_in_host_entries checks both the arpa name and
        # the decoded IP (host_entries PTR entries are IP-keyed), so one call suffices.
        if is_in_host_entries(name, host_entries):
            continue
        decoded_ip = _arpa_to_ip(name)

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


def protected_magic_from_state(
    magic_state: dict,
    kea_pairs: Set[Tuple[str, str]],
    logger: Optional[logging.Logger] = None,
) -> Set[str]:
    """Compute the set of magic FQDNs that should survive a stale-clean run.

    Source-based rules:
      override / static -- always protected (no expiring lease)
      lease             -- protected only while the backing lease is still in kea_pairs
    """
    protected: Set[str] = set()
    for fqdn_key, entries in magic_state.get("magic_names", {}).items():
        for entry in entries:
            magic_fqdn = entry.get("magic_fqdn", "").rstrip(".").lower()
            if not magic_fqdn:
                continue
            source = entry.get("source", "lease")
            if source in ("override", "static"):
                protected.add(magic_fqdn)
            else:
                ip = entry.get("ip", "")
                if (fqdn_key, ip) in kea_pairs:
                    protected.add(magic_fqdn)
    if protected and logger:
        logger.info("Protecting %d active/static magic FQDN(s) from stale-clean",
                    len(protected))
    return protected


def kea_ips_for_hostname(hostname: str, logger: Optional[logging.Logger] = None) -> Optional[Set[str]]:
    """Return the set of IPs Kea currently associates with hostname (all services).

    Returns an empty set if Kea knows the host but has no IPs for it, None if
    Kea is unreachable (callers must abort cleanup when None — no authoritative data).
    KeaServiceUnavailableError (service offline) is silently skipped so a
    DHCPv4-only setup doesn't abort when dhcp6 isn't running.
    """
    hn = hostname.rstrip(".").lower()
    valid_ips: Set[str] = set()
    for service in ("dhcp4", "dhcp6"):
        try:
            for res in query_kea_reservations(service=service):
                if res["hostname"].rstrip(".").lower() == hn:
                    for ip in (res.get("ip"), res.get("ipv6")):
                        if ip:
                            valid_ips.add(ip)
            for lease in query_kea_leases(service=service):
                if lease["hostname"].rstrip(".").lower() == hn:
                    for ip in (lease.get("ip"), lease.get("ipv6")):
                        if ip:
                            valid_ips.add(ip)
        except KeaServiceUnavailableError:
            pass
        except KeaUnavailableError as e:
            if logger:
                logger.warning("[cleanup] Kea unreachable querying %s for %s: %s",
                               service, hostname, e)
            return None
    return valid_ips


def purge_released_ip(
    ip: str,
    unbound_data: Dict[str, List[str]],
    host_entries: Dict[str, List[str]],
    logger: Optional[logging.Logger] = None,
) -> None:
    """Remove every Unbound record for a specific IP that is no longer in Kea.

    Called with the mutation lock already held (by kea-sync.py's purge pass).
    Locates forward names that have this IP as A/AAAA, confirms with Kea the IP
    is gone, then removes it with the remove+restore dance and drops the PTR.
    Best-effort: individual name errors are logged but do not abort the loop.
    """
    _log = logger or logging.getLogger(__name__)
    _log.info("[purge] purging released IP: %s", ip)

    affected_names: List[str] = []
    for name, lines in unbound_data.items():
        for line in lines:
            parts = line.split()
            if len(parts) >= 5 and parts[3] in ("A", "AAAA") and parts[4] == ip:
                affected_names.append(name)
                break

    if not affected_names:
        _log.info("[purge] IP %s not found in Unbound — nothing to do", ip)
        return

    for name in affected_names:
        if is_in_host_entries(name, host_entries):
            _log.info("[purge] %s is in host_entries.conf — skipping", name)
            continue

        valid_kea_ips = kea_ips_for_hostname(name, _log)
        if valid_kea_ips is None:
            _log.warning("[purge] Kea unavailable for %s — skipping", name)
            continue
        if ip in valid_kea_ips:
            _log.info("[purge] IP %s still valid in Kea for %s — skipping", ip, name)
            continue

        all_records = []
        for line in unbound_data.get(name, []):
            parts = line.split()
            if len(parts) >= 5 and parts[3] in ("A", "AAAA"):
                all_records.append((parts[4], parts[1], parts[3]))

        valid_records = [(r_ip, ttl, rtype) for r_ip, ttl, rtype in all_records
                         if r_ip in valid_kea_ips]

        if not unbound_control(["local_data_remove", name]):
            _log.error("[purge] failed to remove records for %s", name)
            continue

        if valid_records:
            rrs = [f"{name} {ttl} IN {rtype} {r_ip}" for r_ip, ttl, rtype in valid_records]
            unbound_local_datas_batch(rrs)

        _log.info("[purge] removed IP %s from %s (restored %d record(s))",
                  ip, name, len(valid_records))

        ptr_name = reverse_ptr(ip)
        if ptr_name and ptr_name in unbound_data:
            if not is_in_host_entries(ptr_name, host_entries):
                # Guard: only remove the PTR if it still targets one of the
                # names we just purged.  The IP may have been reassigned before
                # the logwatcher fires, in which case the PTR already points at
                # the new host and must not be touched.
                ptr_targets = set()
                for _line in unbound_data.get(ptr_name, []):
                    _parts = _line.split()
                    if len(_parts) >= 5 and _parts[3] == "PTR":
                        ptr_targets.add(_parts[4].rstrip(".").lower())
                if ptr_targets & {n.lower() for n in affected_names}:
                    _log.info("[purge] removing PTR for released IP: %s", ptr_name)
                    unbound_control(["local_data_remove", ptr_name])
                else:
                    _log.info("[purge] PTR %s no longer targets purged host(s) — leaving", ptr_name)


def discover_stale(
    synthesize_ptr: bool = True,
    logger: Optional[logging.Logger] = None,
) -> Tuple[Dict[str, List[str]], Set[Tuple[str, str]], Set[str]]:
    """Full discovery for a standalone stale-clean run.

    Reads Unbound's current local_data, all Kea reservations and active leases,
    D2 reverse zones, and the magic state file. Returns (unbound_data,
    stale_pairs, orphaned_ptrs) ready to pass to clean_stale_records().

    Raises KeaUnavailableError if Kea cannot be reached — do not proceed with
    cleanup without authoritative data.
    """
    host_entries = read_host_entries()
    unbound_data = unbound_list_local_data()
    kea_pairs = collect_kea_pairs(logger)
    d2_reverse_zones = read_d2_reverse_zones()
    protected = protected_magic_from_state(read_magic_state(), kea_pairs, logger)
    stale_pairs, orphaned_ptrs = find_stale_records(
        unbound_data, kea_pairs, host_entries,
        synthesize_ptr=synthesize_ptr,
        d2_reverse_zones=d2_reverse_zones,
        protected_magic_fqdns=protected,
    )
    return unbound_data, stale_pairs, orphaned_ptrs
