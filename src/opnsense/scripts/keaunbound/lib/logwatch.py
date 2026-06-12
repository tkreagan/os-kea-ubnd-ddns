#!/usr/local/bin/python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Thomas Reagan
"""
logwatch.py -- Pure log-parsing helpers for kea-unbound-logwatch.py.

No I/O here: parse single log lines, classify events, maintain a grace-window
coalesce queue.  Designed to be unit-tested independently of the daemon.

Kea log format on OPNsense (syslog-ng RFC5424):
  <PRI>1 <ISO8601-TS> <host> <app> <pid> - [meta sequenceId="N"] <LEVEL>  [<logger>] <MSG_ID> <message>

  app is one of: kea-dhcp4, kea-dhcp6, kea-dhcp-ddns
  MSG_IDs we care about:
    DHCP4_RELEASE         -- explicit DHCPv4 client release
    DHCP4_RELEASE_EXPIRED -- DHCPRELEASE received but lease had already expired
    DHCP6_RELEASE         -- explicit DHCPv6 client release
    DHCP6_LEASE_NA_EXPIRE -- IA_NA lease expired (no NCR on ELP at INFO)
    DHCP6_LEASE_PD_EXPIRE -- IA_PD lease expired

Listener log format (syslog-ng → /var/log/keaunbound/):
  <PRI>1 <ISO8601-TS> <host> kea-ub <pid> - [meta sequenceId="N"] <LEVEL>  [<logger>] <message>

  Lines we care about:
    "Update complete: ... errors=N" (N > 0) -> reconcile that name
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple


# ── Kea log regexes ──────────────────────────────────────────────────────────

# Kea's DHCP4_RELEASE and DHCP4_RELEASE_EXPIRED both include the IPv4 address
# as either "addr=X.X.X.X" or "address=X.X.X.X" depending on Kea version.
# The rest of the message is variable (client-id, hwaddr, etc.) so we just
# anchor on the MSG_ID and capture the first IPv4 that follows an addr= keyword.
_DHCP4_RELEASE_RE = re.compile(
    r'\bDHCP4_RELEASE(?:_EXPIRED)?\b.*?\baddr(?:ess)?=(\d{1,3}(?:\.\d{1,3}){3})\b'
)

# DHCPv6 RELEASE: Kea 2.x logs
#   DHCP6_RELEASE ... IA_NA addr=2001:db8::1 ...
# IPv6 address after addr=
_DHCP6_RELEASE_RE = re.compile(
    r'\bDHCP6_RELEASE\b.*?\baddr=([0-9a-fA-F:]+(?::[0-9a-fA-F]{0,4}){1,7})\b'
)

# Listener log: "Update complete: added=N removed=N skipped=N errors=N"
# We only act when errors > 0.
_LISTENER_UPDATE_RE = re.compile(
    r'Update complete:.*?\berrors=([1-9]\d*)\b'
)

# Listener log: name/IP being processed (lines preceding Update complete).
# "Add: hostname.example.com A 192.168.1.1" or "Remove: hostname.example.com A 192.168.1.1"
_LISTENER_OP_RE = re.compile(
    r'\b(?:Add|Remove):\s+(\S+)\s+(?:A|AAAA)\s+(\S+)'
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


LogEvent = ReleaseEvent | ServfailEvent


# ── Line parsers ─────────────────────────────────────────────────────────────

def parse_kea_line(line: str) -> Optional[LogEvent]:
    """
    Parse one line from Kea's log file.  Returns a ReleaseEvent if the line
    records a DHCPv4 or DHCPv6 lease release, else None.
    """
    m = _DHCP4_RELEASE_RE.search(line)
    if m:
        return ReleaseEvent(ip=m.group(1), source="dhcp4")
    m = _DHCP6_RELEASE_RE.search(line)
    if m:
        return ReleaseEvent(ip=m.group(1), source="dhcp6")
    return None


def parse_listener_line(line: str,
                        pending_ops: List[Tuple[str, str]]) -> Optional[LogEvent]:
    """
    Parse one line from the kea-unbound-ddns listener log.

    pending_ops is a caller-maintained list of (name, ip) pairs accumulated
    from preceding Add:/Remove: lines for the current NCR batch.  The caller
    should clear this list after a ServfailEvent is returned or whenever an
    NCR boundary (a new 'NCR id=' line) is seen.

    Returns a ServfailEvent when 'Update complete: ... errors=N' (N>0) is seen,
    else None.  Also appends to pending_ops when an Add:/Remove: op line is seen
    (no return value for those lines — caller accumulates).
    """
    # Accumulate op lines so we know which names were being processed.
    m = _LISTENER_OP_RE.search(line)
    if m:
        pending_ops.append((m.group(1), m.group(2)))
        return None

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
