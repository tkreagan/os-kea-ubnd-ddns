#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
logwatch.py -- Pure log-parsing helpers for kea-ubnd-logwatch.py.

No I/O here: parse single log lines, classify events, maintain a grace-window
coalesce queue.  Designed to be unit-tested independently of the daemon.

Kea log format on OPNsense (syslog-ng RFC5424):
  <PRI>1 <ISO8601-TS> <host> <app> <pid> - [meta sequenceId="N"] <LEVEL>  [<logger>] <MSG_ID> <message>

  app is one of: kea-dhcp4, kea-dhcp6, kea-dhcp-ddns
  MSG_IDs we care about:
    DHCP4_RELEASE         -- normal release success (DEBUG 50 — only visible if Kea
                             logging is configured at debug level 50 or higher; absent
                             in default INFO-only deployments)
    DHCP4_RELEASE_DELETED -- lease deleted on release (INFO; fires when Kea's
                             delete-lease-on-quit is enabled)
    DHCP4_RELEASE_EXPIRED -- DHCPRELEASE received but lease had already expired (INFO)
    DHCP6_RELEASE_NA         -- normal IA_NA release success (INFO)
    DHCP6_RELEASE_NA_DELETED -- IA_NA lease deleted on release (INFO)
    DHCP6_RELEASE_NA_EXPIRED -- IA_NA release of already-expired lease (INFO)

  DHCP6_RELEASE_PD (prefix delegation) is NOT watched — we create no DNS A/AAAA
  records for delegated prefixes, so there is nothing to clean up.

  Lease expirations reached by timeout (as opposed to an explicit RELEASE) are NOT
  handled here.  Those stale records are cleaned by the periodic cron job
  (configctl keaubnd clean).  The logwatcher's scope is explicit client releases only.

Listener log format (syslog-ng → /var/log/keaubnd/):
  <PRI>1 <ISO8601-TS> <host> kea-ubnd <pid> - [meta sequenceId="N"] <LEVEL>  [<logger>] <message>

  Lines we care about:
    "Add: <hostname> <TTL> IN A|AAAA <ip>"   -- forward record added
    "Remove: A|AAAA <hostname> (preserving …)"  -- forward record removed (no IP in line)
    "Update complete: ... errors=N" (N > 0)   -- reconcile that name
"""
from __future__ import annotations

import re
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union


# ── IP validation ─────────────────────────────────────────────────────────────

def _valid_ipv4(s: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except OSError:
        return False


def _valid_ipv6(s: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except OSError:
        return False


# ── Kea log regexes ──────────────────────────────────────────────────────────

# Confirmed format from real Kea logs (OPNsense 26.1.x / Kea 2.x):
#   DHCP4_RELEASE         [hwtype=1 <mac>], cid=[...], tid=0x...: address <ip> was released properly.
#   DHCP4_RELEASE_DELETED [hwtype=1 <mac>], cid=[...], tid=0x...: address <ip> was deleted on release.
#   DHCP4_RELEASE_EXPIRED [hwtype=1 <mac>], cid=[...], tid=0x...: address <ip> expired on release.
# The IP follows the keyword "address" (space-separated, not "addr=" or "address=").
# NOTE: DHCP4_RELEASE is DEBUG(50); it is absent from default INFO-level Kea logs.
# DHCP4_RELEASE_DELETED and _EXPIRED are INFO and are the reliable triggers in
# production.  We match all three so any configuration is covered.
_DHCP4_RELEASE_RE = re.compile(
    r'\bDHCP4_RELEASE(?:_EXPIRED|_DELETED)?\b.*?\baddress\s+(\S+)'
)

# Confirmed format from real Kea logs (OPNsense 26.1.x / Kea 2.x):
#   DHCP6_RELEASE_NA         duid=[...], tid=0x...: binding for address fd00:cafe::100 and iaid=... was released properly
#   DHCP6_RELEASE_NA_DELETED duid=[...], tid=0x...: binding for address fd00:cafe::100 and iaid=... was deleted on release
#   DHCP6_RELEASE_NA_EXPIRED duid=[...], tid=0x...: binding for address fd00:cafe::100 and iaid=... expired on release
# MSG_ID is DHCP6_RELEASE_NA (not DHCP6_RELEASE); IP follows "address" (not "addr=").
# DHCP6_RELEASE_PD (prefix delegation) is intentionally not matched.
_DHCP6_RELEASE_RE = re.compile(
    r'\bDHCP6_RELEASE_NA(?:_EXPIRED|_DELETED)?\b.*?\baddress\s+(\S+)'
)

# Listener log: "Update complete: added=N removed=N skipped=N errors=N"
# We only act when errors > 0.
_LISTENER_UPDATE_RE = re.compile(
    r'Update complete:.*?\berrors=([1-9]\d*)\b'
)

# Listener log: Add op — "Add: hostname TTL IN A|AAAA ip"
# Group 1: hostname, group 2: ip.
_LISTENER_ADD_RE = re.compile(
    r'\bAdd:\s+(\S+)\s+\d+\s+IN\s+(?:A|AAAA)\s+(\S+)'
)

# Listener log: Remove op — "Remove: A|AAAA hostname (preserving …)"
# The daemon logs rdtype before hostname and omits the IP; hostname is group 1.
# PTR removes ("Remove PTR: …") don't start with "Remove: " so they never match.
_LISTENER_REMOVE_RE = re.compile(
    r'\bRemove:\s+(?:A|AAAA)\s+(\S+)'
)


# ── Event types ──────────────────────────────────────────────────────────────

@dataclass
class ReleaseEvent:
    """An IP address was released or expired in Kea."""
    ip: str
    source: str  # "dhcp4" | "dhcp6"
    when: float = field(default_factory=time.monotonic)


@dataclass
class ServfailEvent:
    """Our listener returned SERVFAIL with errors > 0 for a set of names."""
    names: List[str]   # FQDNs that were being processed
    errors: int
    when: float = field(default_factory=time.monotonic)


@dataclass
class MissedRemoveEvent:
    """A Remove op with no paired Add within the grace window (LEASE_REUSE gap)."""
    hostname: str
    ip: str
    when: float = field(default_factory=time.monotonic)


# Signals returned by parse_listener_line for individual op lines.
# Not dispatched directly — they feed PendingRemoveTracker.
@dataclass
class RemoveOpSeen:
    hostname: str
    ip: str

@dataclass
class AddOpSeen:
    hostname: str
    ip: str


LogEvent = Union[ReleaseEvent, ServfailEvent, MissedRemoveEvent]
ListenerLineResult = Union[None, ServfailEvent, RemoveOpSeen, AddOpSeen]


# ── Line parsers ─────────────────────────────────────────────────────────────

def parse_kea_line(line: str) -> Optional[ReleaseEvent]:
    """
    Parse one line from Kea's log file.  Returns a ReleaseEvent if the line
    records a DHCPv4 or DHCPv6 lease release, else None.

    Captured IP tokens are validated with inet_pton before returning so that
    unexpected Kea log format changes produce no event rather than a bad dispatch.
    """
    m = _DHCP4_RELEASE_RE.search(line)
    if m:
        ip = m.group(1).rstrip(".,;")
        if _valid_ipv4(ip):
            return ReleaseEvent(ip=ip, source="dhcp4")
    m = _DHCP6_RELEASE_RE.search(line)
    if m:
        ip = m.group(1).rstrip(".,;")
        if _valid_ipv6(ip):
            return ReleaseEvent(ip=ip, source="dhcp6")
    return None


def parse_listener_line(line: str,
                        pending_ops: List[Tuple[str, str]]) -> ListenerLineResult:
    """
    Parse one line from the kea-ubnd-ddns listener log.

    pending_ops is a caller-maintained list of (name, ip) pairs accumulated
    from preceding Add:/Remove: lines for the current NCR batch.  The caller
    should clear this list after a ServfailEvent is returned or whenever an
    NCR boundary (a new 'NCR id=' line) is seen.

    Returns:
      RemoveOpSeen  -- a Remove: op line; caller should feed PendingRemoveTracker
      AddOpSeen     -- an Add: op line; caller should cancel pending remove
      ServfailEvent -- 'Update complete: errors=N' (N>0); caller clears pending_ops
      None          -- unrecognized line
    """
    m = _LISTENER_REMOVE_RE.search(line)
    if m:
        hostname = m.group(1)
        pending_ops.append((hostname, ""))
        return RemoveOpSeen(hostname=hostname, ip="")

    m = _LISTENER_ADD_RE.search(line)
    if m:
        hostname, ip = m.group(1), m.group(2)
        pending_ops.append((hostname, ip))
        return AddOpSeen(hostname=hostname, ip=ip)

    m = _LISTENER_UPDATE_RE.search(line)
    if m:
        errors = int(m.group(1))
        names = [name for name, _ip in pending_ops]
        return ServfailEvent(names=names, errors=errors)

    return None


# ── Grace-window coalesce queue ───────────────────────────────────────────────

class EventQueue:
    """
    Coalesce events by key (IP or FQDN), dispatching only after a quiet
    grace window.  Prevents a burst of log lines from triggering redundant
    cleanup runs.

    Thread-unsafe: designed for single-threaded kqueue event loops.
    """

    def __init__(self, grace_secs: float = 10.0):
        self.grace_secs = grace_secs
        # key -> (event, deadline_monotonic)
        self._pending: Dict[str, Tuple[LogEvent, float]] = {}

    def add(self, key: str, event: LogEvent) -> None:
        """Record or refresh an event.  Resets the deadline on every add."""
        self._pending[key] = (event, time.monotonic() + self.grace_secs)

    def ready(self) -> List[LogEvent]:
        """Return and remove events whose grace window has expired."""
        now = time.monotonic()
        due = [ev for key, (ev, dl) in self._pending.items() if now >= dl]
        for ev in due:
            # remove by value (may have been superseded — find matching deadline)
            self._pending = {k: v for k, v in self._pending.items()
                             if v[0] is not ev}
        return due

    def next_deadline(self) -> Optional[float]:
        """Seconds until the earliest pending deadline, or None if empty."""
        if not self._pending:
            return None
        earliest = min(dl for _, (_, dl) in self._pending.items())
        return max(0.0, earliest - time.monotonic())

    def __len__(self) -> int:
        return len(self._pending)


# ── Remove-without-Add tracker ────────────────────────────────────────────────

class PendingRemoveTracker:
    """
    Track DNS Remove ops that have not been followed by an Add within the
    grace window.  When the window expires, emit a MissedRemoveEvent so the
    caller can trigger a targeted kea-sync for that hostname.

    Covers the LEASE_REUSE gap: kea-dhcp-ddns sends a CHG_REMOVE for a
    hostname/IP and then, because the lease record looks unchanged to D2,
    skips the follow-up CHG_ADD.  The DNS record disappears until the next
    full reconcile.  With this tracker the gap is closed within grace_secs.

    Keyed by hostname alone: any Add for the same hostname cancels the pending
    remove regardless of IP (handles the case where the IP changed too).

    Thread-unsafe: designed for single-threaded kqueue event loops.
    """

    def __init__(self, grace_secs: float = 10.0):
        self.grace_secs = grace_secs
        # hostname -> (ip, deadline_monotonic)
        self._pending: Dict[str, Tuple[str, float]] = {}

    def add_remove(self, hostname: str, ip: str) -> None:
        """Record a pending remove.  Resets the deadline if already pending."""
        self._pending[hostname] = (ip, time.monotonic() + self.grace_secs)

    def cancel(self, hostname: str) -> None:
        """Cancel a pending remove — the paired Add arrived in time."""
        self._pending.pop(hostname, None)

    def ready(self) -> List[MissedRemoveEvent]:
        """Return and remove entries whose grace window has expired."""
        now = time.monotonic()
        due = [(h, ip) for h, (ip, dl) in self._pending.items() if now >= dl]
        for hostname, _ in due:
            del self._pending[hostname]
        return [MissedRemoveEvent(hostname=h, ip=ip) for h, ip in due]

    def next_deadline(self) -> Optional[float]:
        """Seconds until the earliest pending deadline, or None if empty."""
        if not self._pending:
            return None
        earliest = min(dl for _, dl in self._pending.values())
        return max(0.0, earliest - time.monotonic())

    def __len__(self) -> int:
        return len(self._pending)
