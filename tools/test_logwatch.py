# SPDX-License-Identifier: BSD-2-Clause
"""
Unit tests for lib/logwatch.py — log line parsing and event queue.

The parsers must handle the syslog-ng RFC5424 format used by OPNsense:
  <PRI>1 <ISO8601-TS> <host> <app> <pid> - [meta sequenceId="N"] LEVEL  [logger] MSG_ID message

Run:  python3 -m pytest tools/test_logwatch.py -v
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import time

_LIB_DIR = pathlib.Path(__file__).parents[1] / "src/opnsense/scripts/keaunbound"
if str(_LIB_DIR) not in sys.path:
    sys.path.insert(0, str(_LIB_DIR))

from lib.logwatch import (
    EventQueue, ReleaseEvent, ServfailEvent,
    parse_kea_line, parse_listener_line,
)


# ── Sample log lines (syslog-ng RFC5424 format from dev-opnsense) ──────────

# DHCPv4 explicit release — Kea 2.x format with "address=" keyword
_RELEASE4_LINE = (
    '<134>1 2026-06-12T10:15:30+00:00 dev-opnsense.plhm.rgn.cm kea-dhcp4 90190 - '
    '[meta sequenceId="7"] INFO  [kea-dhcp4.packets.0x52203626c008] '
    'DHCP4_RELEASE [hwaddr=aa:bb:cc:dd:ee:ff, client-id=ff:aa, '
    'subnet-id=1, subnet=192.168.1.0/24, address=192.168.1.100]'
)

# DHCPv4 release where lease had already expired (addr= variant)
_RELEASE4_EXPIRED_LINE = (
    '<134>1 2026-06-12T10:15:31+00:00 dev-opnsense.plhm.rgn.cm kea-dhcp4 90190 - '
    '[meta sequenceId="8"] INFO  [kea-dhcp4.packets.0x52203626c008] '
    'DHCP4_RELEASE_EXPIRED [hwaddr=aa:bb:cc:dd:ee:ff, addr=192.168.1.101]'
)

# DHCPv6 explicit release
_RELEASE6_LINE = (
    '<134>1 2026-06-12T10:15:32+00:00 dev-opnsense.plhm.rgn.cm kea-dhcp6 90191 - '
    '[meta sequenceId="1"] INFO  [kea-dhcp6.packets.0x...] '
    'DHCP6_RELEASE [duid=00:01:..., ia_na=[iaid=1, addr=2001:db8::cafe]]'
)

# Unrelated Kea log line — must not match
_UNRELATED_LINE = (
    '<134>1 2026-06-12T00:00:00+00:00 dev-opnsense.plhm.rgn.cm kea-dhcp4 90190 - '
    '[meta sequenceId="1"] INFO  [kea-dhcp4.commands.0x...] '
    'COMMAND_RECEIVED Received command config-get'
)

# Listener log lines
_LISTENER_OP_ADD = (
    '<30>1 2026-06-12T10:15:00+00:00 dev-opnsense.plhm.rgn.cm kea-ub 12345 - '
    '[meta sequenceId="1"] INFO  [keaunbound] Add: host1.dev.plhm.rgn.cm A 192.168.1.100'
)
_LISTENER_UPDATE_ERRORS = (
    '<30>1 2026-06-12T10:15:00+00:00 dev-opnsense.plhm.rgn.cm kea-ub 12345 - '
    '[meta sequenceId="3"] INFO  [keaunbound] Update complete: added=1 removed=0 skipped=0 errors=2'
)
_LISTENER_UPDATE_OK = (
    '<30>1 2026-06-12T10:15:00+00:00 dev-opnsense.plhm.rgn.cm kea-ub 12345 - '
    '[meta sequenceId="3"] INFO  [keaunbound] Update complete: added=1 removed=0 skipped=0 errors=0'
)


# ── Kea log parsing ──────────────────────────────────────────────────────────

def test_parse_dhcp4_release():
    ev = parse_kea_line(_RELEASE4_LINE)
    assert isinstance(ev, ReleaseEvent)
    assert ev.ip == "192.168.1.100"
    assert ev.source == "dhcp4"


def test_parse_dhcp4_release_expired():
    ev = parse_kea_line(_RELEASE4_EXPIRED_LINE)
    assert isinstance(ev, ReleaseEvent)
    assert ev.ip == "192.168.1.101"
    assert ev.source == "dhcp4"


def test_parse_dhcp6_release():
    ev = parse_kea_line(_RELEASE6_LINE)
    assert isinstance(ev, ReleaseEvent)
    assert ev.ip == "2001:db8::cafe"
    assert ev.source == "dhcp6"


def test_unrelated_line_returns_none():
    assert parse_kea_line(_UNRELATED_LINE) is None


def test_empty_line_returns_none():
    assert parse_kea_line("") is None


# ── Listener log parsing ─────────────────────────────────────────────────────

def test_listener_op_line_accumulates():
    pending: list = []
    ev = parse_listener_line(_LISTENER_OP_ADD, pending)
    assert ev is None
    assert len(pending) == 1
    assert pending[0][0] == "host1.dev.plhm.rgn.cm"
    assert pending[0][1] == "192.168.1.100"


def test_listener_errors_produces_servfail():
    pending: list = []
    parse_listener_line(_LISTENER_OP_ADD, pending)
    ev = parse_listener_line(_LISTENER_UPDATE_ERRORS, pending)
    assert isinstance(ev, ServfailEvent)
    assert ev.errors == 2
    assert "host1.dev.plhm.rgn.cm" in ev.names


def test_listener_no_errors_returns_none():
    pending: list = []
    parse_listener_line(_LISTENER_OP_ADD, pending)
    ev = parse_listener_line(_LISTENER_UPDATE_OK, pending)
    assert ev is None


# ── EventQueue ───────────────────────────────────────────────────────────────

def test_queue_not_ready_before_grace():
    q = EventQueue(grace_secs=60)
    ev = ReleaseEvent(ip="192.168.1.1", source="dhcp4")
    q.add("ip:192.168.1.1", ev)
    assert q.ready() == []
    assert len(q) == 1


def test_queue_ready_after_grace():
    q = EventQueue(grace_secs=0.0)
    ev = ReleaseEvent(ip="192.168.1.1", source="dhcp4")
    q.add("ip:192.168.1.1", ev)
    time.sleep(0.01)
    ready = q.ready()
    assert len(ready) == 1
    assert ready[0].ip == "192.168.1.1"
    assert len(q) == 0


def test_queue_coalesces_same_ip():
    q = EventQueue(grace_secs=60)
    ev1 = ReleaseEvent(ip="192.168.1.1", source="dhcp4")
    ev2 = ReleaseEvent(ip="192.168.1.1", source="dhcp4")
    q.add("ip:192.168.1.1", ev1)
    q.add("ip:192.168.1.1", ev2)
    assert len(q) == 1  # same key → last one wins


def test_queue_next_deadline_none_when_empty():
    q = EventQueue(grace_secs=10)
    assert q.next_deadline() is None


def test_queue_next_deadline_positive():
    q = EventQueue(grace_secs=10)
    q.add("ip:192.168.1.1", ReleaseEvent(ip="192.168.1.1", source="dhcp4"))
    dl = q.next_deadline()
    assert dl is not None
    assert 0 < dl <= 10.1


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
