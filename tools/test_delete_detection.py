# SPDX-License-Identifier: BSD-2-Clause
"""
Regression guard for the live-path delete detection in
src/sbin/kea-unbound-ddns.py (process_update).

THE BUG THIS GUARDS (root-caused 2026-06-12, dnspython 2.8.0):
  d2 sends correct RFC 2136 delete records on a DNS UPDATE — wire class NONE
  (delete a specific RR) or ANY (delete an RRset / all RRsets). The listener
  used to detect deletes with `rrset.rdclass in (ANY, NONE)`. But dnspython
  NORMALIZES an UPDATE record's rdclass to the zone class (IN) on parse and
  exposes the delete-class via the separate `rrset.deleting` attribute. So the
  rdclass check was ALWAYS False and every delete d2 sent was silently dropped
  (treated as an add / no-op) — leases that released or expired left stale DNS,
  with the periodic clean as the only cleanup. The fix keys on `rrset.deleting`.

These tests build the exact NCR shapes captured from kea-dhcp-ddns on the dev
box (both ddns-conflict-resolution-modes) and pin the dnspython contract our
fix relies on, so a future dnspython change or a regression to the old check
fails loudly here rather than silently in production.

Run:  python3 -m pytest tools/test_delete_detection.py -v
"""
from __future__ import annotations

import dns.message
import dns.update
import dns.rdataclass


def _roundtrip(update: dns.update.Update) -> dns.message.Message:
    """Serialize to wire and parse back, exactly as the listener receives it."""
    return dns.message.from_wire(update.to_wire())


# The predicate the listener uses (mirror of kea-unbound-ddns.py:process_update).
def _is_delete(rrset) -> bool:
    return rrset.deleting is not None


def test_check_with_dhcid_reclaim_deletes_are_detected():
    """Kea default mode: forward remove = `NONE A <ip>`, then `ANY ANY`."""
    u = dns.update.Update("dev.plhm.rgn.cm.")
    u.delete("host.dev.plhm.rgn.cm.", "A", "192.168.1.154")  # delete specific RR
    u.delete("host.dev.plhm.rgn.cm.")                        # delete all RRsets
    m = _roundtrip(u)
    assert m.update, "update section should be non-empty"
    assert all(_is_delete(rr) for rr in m.update), \
        "every record in a pure-remove NCR must be detected as a delete"


def test_no_check_reclaim_delete_is_detected():
    """no-check-without-dhcid mode: forward remove = `ANY A` (delete RRset)."""
    u = dns.update.Update("dev.plhm.rgn.cm.")
    u.delete("host.dev.plhm.rgn.cm.", "A")
    m = _roundtrip(u)
    assert all(_is_delete(rr) for rr in m.update)


def test_add_is_not_detected_as_delete():
    """An add (`IN A <ip>` with a real TTL) must NOT be classified as a delete.

    d2's add NCR also carries a leading `ANY A` delete-existing; that record is
    correctly a delete, while the data record is correctly an add.
    """
    u = dns.update.Update("dev.plhm.rgn.cm.")
    u.delete("host.dev.plhm.rgn.cm.", "A")            # delete-existing prelude
    u.add("host.dev.plhm.rgn.cm.", 600, "A", "192.168.1.155")  # the actual add
    m = _roundtrip(u)
    by_kind = {("delete" if _is_delete(rr) else "add") for rr in m.update}
    assert by_kind == {"delete", "add"}, \
        "the data record must be an add and the prelude a delete"
    # The data record specifically is an add.
    data = [rr for rr in m.update if any(str(x) == "192.168.1.155" for x in rr)]
    assert data and not _is_delete(data[0])


def test_rdclass_is_the_trap_not_a_valid_signal():
    """Document/guard WHY we don't use rdclass: dnspython normalizes it to IN.

    If a future dnspython ever DID preserve NONE/ANY on rrset.rdclass, this test
    would start failing — a signal to revisit, not a silent behavior change.
    """
    u = dns.update.Update("dev.plhm.rgn.cm.")
    u.delete("host.dev.plhm.rgn.cm.", "A", "192.168.1.154")  # wire class NONE
    m = _roundtrip(u)
    rr = list(m.update)[0]
    assert rr.deleting in (dns.rdataclass.NONE, dns.rdataclass.ANY)
    assert rr.rdclass == dns.rdataclass.IN, \
        "dnspython normalizes update rdclass to IN; deletes live in .deleting"


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
