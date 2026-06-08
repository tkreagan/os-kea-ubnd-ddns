# PTR Record Handling — Notes & Open Decisions

> **Superseded by `ptr-testing-plan.md`** (June 2026). The open decisions below
> were resolved during implementation; key outcomes:
> - Decision 2 (synthesis flag): implemented as `general.synthesize_ptr` (default ON)
> - Decision 1 / F4 (custom reverse zone): **cannot occur** — D2 zone matching is
>   arpa-suffix based so non-arpa zone names (e.g. `home.arpa`) never fire. The
>   entire "custom reverse zone problem" section below is moot.
> - Decisions 4 & 5 (Config Check advisories): implemented per-subnet in
>   `KcaconfigController.php` — a per-subnet `info` advisory fires when synthesis
>   is ON and a D2 reverse zone covers that subnet.
> - Decision 3 (cleanup posture): synthesis-aware `find_stale_records()` with
>   `synthesize_ptr` + `d2_reverse_zones` params is the authoritative answer;
>   see `lib/keaunbound_sync.py`.
>
> This document is kept for historical context only.

> Original notes: documents the current PTR behavior, the gap cases identified in
> analysis, and the decisions that need to be made before closing the PTR testing
> round. Companion to `kea-ddns-options-reference.md` and `kea-tsig-testing.md`.

---

## How PTRs currently get into Unbound — two paths

### Path 1: Synthesized from forward NCR (always active)

When the listener receives a forward A/AAAA ADD update from D2, it automatically
synthesizes and registers the corresponding PTR (`kea-unbound-ddns.py:521-526`):

```python
ptr = reverse_ptr(rdata)          # Python ipaddress.ip_address().reverse_pointer
if ptr and not is_static_entry(...):
    unbound_control(["local_data", f"{ptr} {rrset.ttl} IN PTR {name}."])
```

`reverse_ptr()` **always produces the standard form**: `x.x.x.x.in-addr.arpa` for IPv4,
`x.x...ip6.arpa` for IPv6. It is unconditional — it fires regardless of whether a
reverse zone is configured in D2 or not.

### Path 2: Explicit reverse NCR from D2 (active when `ddns_reverse_zone` is set)

When `ddns_reverse_zone` is configured in OPNsense, D2 generates a separate reverse
NCR — a DNS UPDATE packet containing a PTR record — and sends it to the listener.
The listener handles it through the `rdtype == "PTR"` branch of `process_update()`.
`"PTR"` is in `HANDLED_TYPES`; the record is registered directly.

### What happens when both paths are active

In the standard OPNsense setup (`ddns_reverse_zone = "1.168.192.in-addr.arpa."`):
- Forward NCR arrives → listener adds A record + synthesizes `100.1.168.192.in-addr.arpa.`
- Reverse NCR arrives → listener adds `100.1.168.192.in-addr.arpa.` again

The reverse NCR's owner name matches what we synthesized. `local_data` is idempotent —
the second write just overwrites. **Net effect: harmless double-write.** This has been
the implicit behavior throughout all Group 1-3 testing (the dev config had
`ddns_reverse_zone` set the whole time).

On DELETE: forward NCR delete removes A record and synthesized PTR; reverse NCR delete
tries to remove an already-gone PTR. `local_data_remove` on a nonexistent name is a
no-op in Unbound. Also harmless.

---

## The custom reverse zone problem

### What happens with a non-standard reverse zone (e.g. `home.arpa`)

Some users configure a custom reverse zone like `1.168.192.home.arpa.` instead of the
standard `1.168.192.in-addr.arpa.`. D2 uses the configured zone name to construct the
PTR owner name and routes the NCR accordingly. The UPDATE it sends contains:

```
100.1.168.192.home.arpa.  TTL  IN  PTR  hostname.domain.
```

Our listener registers that PTR at `100.1.168.192.home.arpa.` — correct for the
custom zone.

**But Path 1 also fires.** It synthesizes `100.1.168.192.in-addr.arpa.` from the
forward NCR regardless. So Unbound ends up with:

```
100.1.168.192.in-addr.arpa.   → hostname  (synthesized, Path 1)
100.1.168.192.home.arpa.      → hostname  (from reverse NCR, Path 2)
```

These are two different names. A standard PTR lookup (`dig -x 192.168.1.100`) hits
`in-addr.arpa` — our synthesized record answers correctly. A lookup against the custom
zone answers from the explicit record. So far arguably OK (both resolve).

### The delete gap

When the lease expires or is released, D2 sends a DELETE NCR for the custom zone only:

```
DELETE 100.1.168.192.home.arpa.
```

Our listener removes `100.1.168.192.home.arpa.` — correct.

**The `in-addr.arpa` PTR we synthesized gets no delete NCR.** D2 only manages the zone
it was configured with. The synthesized record is orphaned. It persists in Unbound until
`local-data-clean.py` runs on schedule and finds it no longer backed by a Kea pair.

### Decision needed: what to do about the custom zone case

**Option A — Document as unsupported; do nothing.**
Custom reverse zones are uncommon and require manual Kea config (not OPNsense GUI).
The `in-addr.arpa` orphan is cleaned up by the scheduled cleanup. Standard PTR lookups
still resolve correctly during the stale window. Cost: zero code change.

**Option B — Suppress Path 1 when an explicit reverse NCR has been received for that IP.**
Track a per-IP "explicit PTR received" flag and skip synthesis for those IPs. Complex to
implement correctly: the forward NCR and reverse NCR are separate packets that arrive
at different times; you'd need state across packets. Not worth it.

**Option C — When processing a forward NCR ADD, check if the D2 reverse domain for
this IP matches `in-addr.arpa`; if not, skip synthesis.**
Would require reading the D2 config at runtime to know what zone is configured.
Tight coupling between listener and D2 config; fragile.

**Option D — Accept the double-register in the standard case; for custom zones, rely on
cleanup. Add a Config Check advisory warning when `ddns_reverse_zone` is set to a
non-standard (non-`in-addr.arpa` / non-`ip6.arpa`) value.**
Low engineering cost. Surfaces the issue to the user at configuration time rather than
silently handling it imperfectly.

**Tentative recommendation: Option A + Option D.** Document clearly that custom reverse
zones result in a stale `in-addr.arpa` PTR that persists until the next cleanup cycle.
Add a Config Check advisory for non-standard reverse zone names.

---

## The D2 delete reliability problem

D2 does send DELETE NCRs — but not reliably in all real-world scenarios.

### Cases where deletes are reliable
- Client sends DHCPRELEASE explicitly → D2 sends DELETE immediately ✓
- Client renews with a different FQDN → D2 sends DELETE for old name + ADD for new name ✓

### Cases where deletes are unreliable or absent

**D2 down during lease expiry.**
When Kea's expired lease processing (ELP) reclaims an expired lease, it generates a
DELETE NCR. But if D2 is not running at that moment, the NCR is dropped on the floor —
no queuing, no retry. D2 does not replay missed NCRs on restart; it only processes
NCRs as they arrive from the DHCP server in real time.

**Client gets a new IP without releasing the old one.**
Common on real networks: client moves, changes identifier, or just doesn't send
DHCPRELEASE (mobile devices, buggy DHCP stacks, power-cycled hardware). Kea allocates
the new IP and sends an ADD NCR for the new name/IP. It does **not** send a DELETE NCR
for the old IP. This is the case the listener's `--aggressive-cleanup` flag exists for.
It is described in the daemon docstring as "common Kea behaviour."

**Implication for PTR records:**
When a DELETE NCR for an A record is missed, the PTR cleanup from Path 1 (synthesized
PTR removal as a side effect of A delete) is also missed. And for a custom reverse zone,
the explicit PTR DELETE from Path 2 is also missed. The result is orphaned records in
Unbound that only disappear when `local-data-clean.py` runs.

### How the plugin compensates

1. **`--aggressive-cleanup`** (`kea-unbound-ddns.py`): after each A record ADD, calls
   `local-data-clean.py --hostname --keep-ip` to remove any older IPs for that hostname
   that Kea no longer knows about. Best-effort; does not help for missed DELETE NCRs.

2. **`local-data-clean.py`** (scheduled via cron): periodically collects all (hostname,
   ip) pairs from Kea (reservations + active leases), compares with Unbound's
   `list_local_data`, and removes records not backed by any current Kea pair. This is
   the real cleanup safety net for all missed-delete scenarios.

3. **`ddns-update-on-renew: ON`**: ensures that records for active clients are
   periodically re-asserted. Doesn't fix stale records from gone clients, but keeps
   current clients' records fresh and prevents TTL-expiry noise.

### Decision needed: is the current cleanup posture sufficient?

Current model: rely on scheduled cleanup as the safety net for all missed deletes.
The cleanup interval is configurable but defaults to something on the order of
once per hour (verify actual cron schedule in `actions_keaunbound.conf`).

**Questions to answer during testing:**
- Does D2 reliably send DELETE NCRs when leases are released via DHCPRELEASE? (Test explicitly.)
- Does D2 send DELETE NCRs when leases expire via ELP (hold-reclaimed-time path)?
- What is the actual gap window between a lease expiring and cleanup running?
- Is `--aggressive-cleanup` enabled in the default production start args?

---

## PTR test cases needed

These are the test scenarios that need to be exercised in the PTR/listener test round.
Group with conflict-resolution-mode tests since the harness is the same.

### Standard reverse zone (`in-addr.arpa`) — confirm current behavior

| Test | Setup | Action | Expected | Verifies |
|------|-------|--------|----------|---------|
| P1a | `ddns_reverse_zone` set | DORA | A + PTR at in-addr.arpa | double-write is harmless |
| P1b | `ddns_reverse_zone` set | DHCPRELEASE | A + PTR both removed | DELETE NCR path works |
| P1c | `ddns_reverse_zone` NOT set | DORA | A + PTR at in-addr.arpa (Path 1 only) | synthesis alone works |
| P1d | `ddns_reverse_zone` NOT set | DHCPRELEASE | A + PTR both removed | forward-NCR delete cleans up PTR |

### Custom reverse zone — confirm and document the gap

| Test | Setup | Action | Expected | Verifies |
|------|-------|--------|----------|---------|
| P2a | reverse zone `1.168.192.home.arpa.` | DORA | A record + PTR at BOTH in-addr.arpa AND home.arpa | double PTR confirmed |
| P2b | same | DHCPRELEASE | home.arpa PTR removed; in-addr.arpa PTR **orphaned** | gap confirmed |
| P2c | same | cleanup run after P2b | in-addr.arpa PTR removed | cleanup as safety net |

### Delete reliability

| Test | Setup | Action | Expected | Verifies |
|------|-------|--------|----------|---------|
| P3a | standard | DHCPRELEASE | DELETE NCR fires immediately | explicit release path |
| P3b | standard | lease expiry (short valid-lifetime) | DELETE NCR fires via ELP | ELP delete path |
| P3c | standard | D2 stopped, lease expires, D2 restarted | record persists after D2 restart | missed-delete gap |
| P3d | standard | client moves to new IP (no release) | old record lingers; new record added | new-IP-without-delete gap |

### Bulk path PTR behavior

| Test | Setup | Action | Expected | Verifies |
|------|-------|--------|----------|---------|
| P4a | standard | Unbound restart → lease-sync runs | PTR recreated at in-addr.arpa | bulk path synthesizes PTR |
| P4b | custom reverse zone | Unbound restart → lease-sync runs | PTR at in-addr.arpa only (no home.arpa) | bulk path is zone-agnostic |

Note P4b: after an Unbound restart with a custom reverse zone, the home.arpa PTR is gone
(local_data is runtime-only) and the bulk path only re-adds at in-addr.arpa. The
custom-zone PTR only comes back on the next live NCR from D2 (i.e., next renewal with
UOR=ON). This is another reason to keep UOR=ON when using custom reverse zones.

---

## Audit implications

The audit (`local-data-audit.py`) tracks `ptr_state` per forward record:
`none / wrong / correct / multiple`. With a custom reverse zone, a client would show:

- `ptr_state: multiple` (two PTRs for the same IP, at different names)
  OR
- `ptr_state: correct` for `in-addr.arpa` and the `home.arpa` PTR is invisible to the
  audit (depends on whether audit compares PTR names or just checks existence)

Need to verify which case actually occurs when testing P2a. The audit's PTR logic
should probably emit an advisory if it sees PTR records in non-standard namespaces.

---

## Open decisions summary

| # | Decision | Options | Recommendation |
|---|----------|---------|---------------|
| 1 | Custom reverse zone: what to do about orphaned in-addr.arpa PTR | A (doc only), B (stateful suppress), C (D2 config coupling), D (Config Check advisory) | A + D |
| 2 | Should synthesis (Path 1) be suppressible? | Flag to disable PTR synthesis on forward NCR | Defer; only add if custom-zone testing shows real user pain |
| 3 | Is scheduled cleanup sufficient for missed-delete gap? | Current posture vs shorter cleanup interval vs aggressive-cleanup default | Verify cleanup interval; consider enabling aggressive-cleanup by default |
| 4 | Should Config Check warn on missing `ddns_reverse_zone`? | Yes / No | Yes — missing reverse zone = PTR-only-via-synthesis, no D2 managed lifecycle |
| 5 | Should Config Check warn on non-standard reverse zone name? | Yes / No | Yes (part of Option D above) |

---

## TODO — Config Check implementation (decisions 4 and 5)

Both advisories read from the D2 conf (`kea-dhcp-ddns.conf`), which is already parsed
in `KcaconfigController::buildDomainMap()`. Add a companion `d2Advisories()` method
that returns global (not per-subnet) advisories, and surface them in the `checkAction()`
result as a `d2_advisories` array.

**Decision 4 — missing reverse zone:**
Read `DhcpDdns.reverse-ddns.ddns-domains`. If the array is empty **and** at least one
subnet has `ddns-send-updates: true`, emit an Info advisory:
> No reverse zone configured in DHCP-DDNS — PTR records will be synthesized by the
> plugin but their lifecycle is not managed by D2. Records will persist until the next
> cleanup run after a lease expires.

**Decision 5 — non-standard reverse zone:**
For each name in `reverse-ddns.ddns-domains`, check whether `rtrim($name, '.')` ends
with `.in-addr.arpa` or `.ip6.arpa` (case-insensitive). If not, emit a Warning:
> Reverse zone "{name}" is not a standard in-addr.arpa / ip6.arpa zone. PTR records
> synthesized at in-addr.arpa on each forward NCR will be orphaned when the lease
> expires because D2 only sends DELETE NCRs for the configured zone. Orphaned records
> persist until the next scheduled cleanup run.

Both advisories should also appear in `kcaconfig.volt` — add them to the D2 section
alongside the existing `d2_reachable` banner.
