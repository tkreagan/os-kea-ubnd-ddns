# Kea DDNS Subnet Override Options — Test Results

> Functional/conformance results. Design + methodology: `kea-ddns-design-notes.md`.
> Rig: dev-opnsense (192.168.1.0/24, forward `dev.plhm.rgn.cm.`, reverse
> `1.168.192.in-addr.arpa.`, target `127.0.0.1:53535`) + dev-dhcpclient (`ens19`, scapy).
> Conflict-resolution-mode pinned to default (`check-with-dhcid`) throughout.
> Flag legend: S=server-does-A, N=no-update, O=override(server-set in reply), E=encoding.

## Smoke test (baseline, pre-matrix)
V-S1 cooperative (S=1) → assigned .150, ACK S=1/O=0/N=0; A + PTR resolved in unbound;
D2 `DHCP_DDNS_ADD_SUCCEEDED (CHG_ADD)`. Chain verified end-to-end. ✅

## Group 1 — `ddns-override-no-update` (ONU) ✅ all pass

Config: OCU=OFF, UOR=OFF throughout; only ONU varied. Conflict-mode default.

| Test | ONU | Client sends | ACK reply flags | Forward A | Reverse PTR | Expected | Result |
|---|---|---|---|---|---|---|---|
| T1a | OFF | FQDN N=1 (.161, t1a) | S=0, O=0, **N=1** | NXDOMAIN | NXDOMAIN | no records (honor N) | ✅ PASS |
| T1b | ON | FQDN N=1 (.162, t1b) | **S=1, O=1, N=0** | .162 ✓ | t1b ✓ | A+PTR, override (O=1) | ✅ PASS |
| T1c | ON | FQDN S=1 (.163, t1c) | S=1, **O=0**, N=0 | .163 ✓ | t1c ✓ | A+PTR, no regression/no spurious O | ✅ PASS |

**Evidence:** T1a — no `t1a` in listener log, Kea log shows only `DHCP4_LEASE_ALLOC` (no
`DHCP_DDNS_ADD`). T1b — listener `Add: t1b ... A 192.168.1.162` + `Add PTR`. T1c — A+PTR
resolve; `O=0` confirms the override flag is set *only* when the server actually overrode.

**Conclusion:** `ddns-override-no-update` behaves exactly as documented — the surgical
override of the client `N=1` row, with the reply `O` flag correctly signalling override only
when it occurred.

## Group 2 — `ddns-override-client-update` (OCU) ✅ all pass

Config: ONU=OFF, UOR=OFF throughout; only OCU varied. Conflict-mode default.

| Test | OCU | Client sends | ACK reply flags | Forward A | Reverse PTR | Expected | Result |
|---|---|---|---|---|---|---|---|
| T2a | OFF | FQDN S=0 (.171, t2a) | **S=0**, O=0 | NXDOMAIN | present (t2a) | PTR only, server defers A | ✅ PASS |
| T2b | ON | FQDN S=0 (.172, t2b) | **S=1, O=1** | .172 ✓ | present (t2b) | A+PTR, server takes over A | ✅ PASS |
| T2c | ON | FQDN N=1 (.173, t2c) | N=1, O=0 | NXDOMAIN | NXDOMAIN | **no records** (OCU ≠ N override) | ✅ PASS |

**Evidence:** T2a — `list_local_data` shows only the PTR (no A); listener log has only
`Add PTR (explicit)`. T2b — `list_local_data` shows both A and PTR; listener `Add: t2b ... A`
+ `Add PTR`. T2c — `list_local_data` empty for t2c, no listener Add, both queries NXDOMAIN.

**Conclusion:** `ddns-override-client-update` surgically overrides only the client `S=0` row
(server assumes the forward A and signals `S=1,O=1`), and **does not** override `N=1`
(T2c) — the orthogonality of the two override flags is confirmed empirically.

## Methodology note — `drill -x` is unreliable here; use direct PTR queries

`drill -x <ip>` returned a **false NXDOMAIN** for a PTR that is actually present and
resolvable (this box has unbound's RFC6303 `static` reverse zones for private space, and
ldns's `-x` shortcut trips over them). The **direct** form
`drill @127.0.0.1 <reversed-name> PTR` returns it correctly (NOERROR), matching
`unbound-control -c /var/unbound/unbound.conf list_local_data`. All reverse checks use the
direct query + `list_local_data`; `-x` is avoided.

## Group 3 — `ddns-update-on-renew` (UOR) ✅ both pass (after defeating lease caching)

Method: DORA creates record → delete record from unbound out-of-band (keep lease) →
RENEWING-state request → observe whether the record reappears.

**⚠ Key finding — Kea lease caching masks renewals.** First attempt (4000s lease) FAILED to
show any difference: both UOR off/on left the record gone after renew. Kea log showed
`DHCP4_LEASE_REUSE`. Cause: **`cache-threshold: 0.25` is in effect** (a Kea 3.0 default; NOT
written into the generated conf — found via `config-get` on the control socket). With a 4000s
lease that's a **1000-second reuse window**: any renew within ~17 min is "reused" and Kea does
**no DDNS at all**, so `update-on-renew` cannot fire. Retested with subnet `valid-lifetime=40s`
(→ 10s reuse window), renewing at ~15s to land outside it (Kea log then shows a real
`DHCP4_LEASE_ALLOC`, no `LEASE_REUSE`).

| Test | UOR | Renewal | Record after renew | Listener Δ | Renew-time NCR | Result |
|---|---|---|---|---|---|---|
| T3a | OFF | genuine (past reuse window) | NXDOMAIN (stays gone) | none | none | ✅ PASS |
| T3b | ON | genuine (past reuse window) | **recreated** (A .184) | +adds | `DHCP_DDNS_ADD (CHG_ADD)` | ✅ PASS |

**Conclusion:** `ddns-update-on-renew` works as documented — ON re-asserts DNS on genuine
renewals; OFF skips them. **But its real-world self-heal cadence is gated by lease caching:**
renewals inside `cache-threshold × valid-lifetime` are reused with no DDNS, so the record is
only refreshed on renewals that fall *outside* that window. With OPNsense defaults
(threshold 0.25, lifetime 4000s → 1000s window) and a typical T1 renewal at 50% of lifetime
(2000s), renewals do land outside the window, so it functions — but this interaction belongs
in the recommendation/docs (esp. if anyone shortens lease times or relies on frequent
renewals for self-healing).

## Methodology note 2 — lease caching (`DHCP4_LEASE_REUSE`)
When testing anything renewal-related on Kea 3.0, account for `cache-threshold` (default
0.25). Verify a renewal is genuine via the Kea log (`DHCP4_LEASE_ALLOC` without a following
`DHCP4_LEASE_REUSE`). For tests, shorten `valid-lifetime` so the reuse window is small.

## C4 — incoherent corner `ONU=1, OCU=0` ✅ inversion demonstrated

Config: ONU=ON, OCU=OFF, UOR=OFF. Fired two clients with opposite-strength opt-outs.

| Client | Opt-out | ACK reply flags | Forward A | Reverse PTR | Observation |
|---|---|---|---|---|---|
| N=1 (.191, c4n) | strong ("no DNS at all") | S=1, O=1, N=0 | .191 ✓ | c4n ✓ | **full A+PTR** |
| S=0 (.192, c4s) | weak ("I'll do my own A") | S=0, O=0 | NXDOMAIN | c4s ✓ | **PTR only** |

`list_local_data`: c4n has A+PTR; c4s has only a PTR (no A). **The stronger opt-out (N=1) got
a complete record; the weaker opt-out (S=0) got less.** This is backwards — empirical proof
that `(ONU=1, OCU=0)` is incoherent. **Recommendation/UI rule: `override-no-update` should
imply `override-client-update`** (warn or auto-enable OCU when ONU is set).

## G1 — nameless client under recommended ON/ON/ON ✅ gap confirmed

Config: ONU=ON, OCU=ON, UOR=ON. Client sent **no FQDN and no hostname**.

Result: lease allocated (.195) but **no DNS records** — `reply_fqdn` null, A/PTR absent,
`list_local_data` empty for .195, lease row hostname field empty, Kea log shows only
`LEASE_ALLOC` (no NCR). **Even with all three overrides on, a nameless client gets nothing** —
the override flags only act when the client supplies a name. Catching these needs
`ddns-generated-prefix` + `ddns-replace-client-name` (out of scope; document as a known gap).

---

## Phase 3/4 — charset scrubbing and replace-client-name (2026-06-08)

Rig: same as Groups 1-3. Config modified per-test via control socket `config-reload`.
MACs `02:00:00:02:00:XX` (charset), `02:00:00:03:00:XX` (replace-client-name),
`02:00:00:04:00:XX` (generated-prefix). Lease CSV consulted for each to verify what
`lease4-get-all` (the bulk path source) actually returns.

**Key finding — original "Unsupported" assessments were wrong.** The assumption that the
bulk path would see a raw/unprocessed hostname was incorrect. Kea stores the processed
FQDN (scrubbed, qualified, or generated) in the lease. The bulk path reads this and works
correctly in all common cases. See the "single-label opt81" note for the one real edge case.

### Charset scrubbing (`hostname-char-set` / `hostname-char-replacement`)

Config: `"hostname-char-set": "[^A-Za-z0-9.-]"`, `"hostname-char-replacement": "-"`.

| Test | Mode | Sent name | Lease stores | Live path | Bulk path | Result |
|---|---|---|---|---|---|---|
| CS-1 | option 12 | `test_host` | `test-host.dev.plhm.rgn.cm` (qualified, scrubbed) | ✅ `test-host.dev.plhm.rgn.cm` | ✅ reads FQDN, returns as-is | ✅ no divergence |
| CS-2 | option 81 single-label | `test_host` | `test-host.` (scrubbed, not qualified) | ❌ D2 NO_MATCH, no record | ⚠ strips dot, qualifies → ghost `test-host.dev.plhm.rgn.cm` | ⚠ ghost record (client bug — opt81 single-label; see note) |
| CS-3 | option 81 FQDN | `test_host.dev.plhm.rgn.cm` | `test-host.dev.plhm.rgn.cm.` (scrubbed, trailing dot) | ✅ `test-host.dev.plhm.rgn.cm` | ✅ strips trailing dot, returns as-is | ✅ no divergence |

### `ddns-replace-client-name` modes

| Test | Mode | Client sends | Lease stores | Live path | Bulk path | Result |
|---|---|---|---|---|---|---|
| RC-1 | `always` | `clientname` (opt81) | `myhost-192-168-1-110.dev.plhm.rgn.cm.` | ✅ generated FQDN | ✅ reads FQDN as-is | ✅ works |
| RC-2 | `always` | nothing | `myhost-192-168-1-111.dev.plhm.rgn.cm` | ✅ generated FQDN | ✅ reads FQDN as-is | ✅ works |
| RC-3 | `when-present` | `clientname` (opt81) | `myhost-192-168-1-112.dev.plhm.rgn.cm.` | ✅ generated FQDN | ✅ reads FQDN as-is | ✅ works |
| RC-4 | `when-present` | nothing | `` (empty) | ❌ no record | ❌ skips (empty) | ✅ consistent: no record |
| RC-5 | `when-not-present` | `clientname` (opt81 single-label) | `clientname.` | ❌ D2 NO_MATCH | ⚠ qualifies → ghost | ⚠ same single-label opt81 edge case |
| RC-6 | `when-not-present` | nothing | `myhost-192-168-1-115.dev.plhm.rgn.cm` | ✅ generated FQDN | ✅ reads FQDN as-is | ✅ works — **recommended for nameless clients** |

### `ddns-generated-prefix`

| Test | Prefix | Client sends | Lease stores | Result |
|---|---|---|---|---|
| GP-1 | `dhcp` | nothing (when-not-present) | `dhcp-192-168-1-116.dev.plhm.rgn.cm` | ✅ custom prefix works; bulk reads FQDN correctly |
| GP-2 | `dhcp` | `mypc` (opt81 single-label, when-not-present) | `mypc.` | ⚠ same single-label opt81 edge case |

### Single-label opt81 edge case (applies to all modes)

When a client sends a **single-label name via option 81** and Kea does not replace it:
Kea does not append the qualifying suffix (treats opt81 names as absolute FQDNs). D2
receives `label.`, logs `DHCP_DDNS_NO_MATCH`, drops the NCR. Lease stores `label.`
The bulk path strips the trailing dot, sees no dot, qualifies → creates a ghost record.

This is a client protocol violation (RFC 4702 requires an FQDN in option 81). Real-world
prevalence is low — workgroup Windows is the main case. Ghost records are removed by the
next `local-data-clean.py` run after lease expiry. No code action needed; document as known.

### Recommended posture

- `ddns-replace-client-name`: `when-not-present` (generates names for nameless clients;
  leaves named clients alone). Combined with `ddns-generated-prefix` of your choice.
- `ddns-replace-client-name: never` (default): clean and consistent — nameless clients
  get no DNS on either path.
- `always` and `when-present` work correctly but are unusual operational choices.

---

## Summary

| Group | Tests | Result |
|---|---|---|
| 1 — override-no-update | T1a/T1b/T1c | ✅ all pass |
| 2 — override-client-update | T2a/T2b/T2c | ✅ all pass (incl. N-independence) |
| 3 — update-on-renew | T3a/T3b | ✅ both pass (lease-caching caveat) |
| C4 — incoherent corner | ONU=1/OCU=0 | ✅ inversion demonstrated |
| G1 — nameless client | ON/ON/ON | ✅ gap confirmed |
| Phase 3/4 — charset | CS-1/CS-2/CS-3 | ✅ common cases work; single-label opt81 ghost (client bug) |
| Phase 3/4 — replace-client-name | RC-1 through RC-6 | ✅ all modes work; single-label opt81 edge case consistent |
| Phase 3/4 — generated-prefix | GP-1/GP-2 | ✅ prefix transparent to bulk path |
| Phase 5 — conflict-resolution-mode | CR-1–CR-4 | ✅ all modes pass; A+PTR land; no listener errors |
| Phase 5 — same-FQDN collision | CR-5 | ✅ accumulation confirmed; no DHCID protection in any mode |
| Phase 5 — ncr-protocol TCP | NCP-1/NCP-2 | ✅ D2 hard-fails on TCP (not silent); UDP restore recovers |
| Phase 6 — collision policy `first_wins` + check-with-dhcid | CR-6 | ✅ YXRRSET returned; original protected |
| Phase 6 — collision policy `first_wins` + no-check (no prereqs) | CR-6c | ✅ A and PTR both blocked silently; no YXRRSET |
| Phase 6 — collision policy `last_wins` | CR-7 | ✅ existing replaced; only new IP in Unbound |

All three subnet override options behave exactly as documented; the OPNsense→Kea model wiring
(previously "Not tested in v0.9") is correct. Headline operational finding: **lease caching
(`cache-threshold` 0.25) gates `update-on-renew`**. Recommended posture: OCU/ONU/UOR all ON,
with the `ONU⇒OCU` constraint and the nameless-client + cache-window caveats documented.

---

## Phase 5 — DHCID / conflict-resolution-mode + ncr-protocol (2026-06-08)

Rig: same as Groups 1–3. OCU/ONU/UOR all ON throughout. MACs `02:00:00:05:00:XX` (CR tests),
`02:00:00:06:00:XX` (NCP tests). Conflict mode set by direct edit of generated
`kea-dhcp4.conf` (bypassing the config.xml model, which is unreliable for this field due to
`configctl kea restart` resetting it through the PHP model layer); kea-dhcp4 restarted via
`keactrl` only after each injection to preserve the hand-edited conf.

### CR-1 through CR-4 — all four `ddns-conflict-resolution-mode` values

Methodology: cooperative V-S1 DORA, fresh MAC/lease before each test. All four modes tested
against the same FQDN `cr1.dev.plhm.rgn.cm`.

| Test | Mode | D2 log confirms mode | A record | PTR record | Listener errors | Result |
|---|---|---|---|---|---|---|
| CR-1 | `check-with-dhcid` (default) | ✅ `Conflict Resolution Mode: check-with-dhcid` | ✅ `.101` | ✅ `cr1` | none | ✅ PASS |
| CR-2 | `no-check-with-dhcid` | ✅ `Conflict Resolution Mode: no-check-with-dhcid` | ✅ `.101` | ✅ `cr1` | none | ✅ PASS |
| CR-3 | `check-exists-with-dhcid` | ✅ `Conflict Resolution Mode: check-exists-with-dhcid` | ✅ `.101` | ✅ `cr1` | none | ✅ PASS |
| CR-4 | `no-check-without-dhcid` | ✅ `Conflict Resolution Mode: no-check-without-dhcid` | ✅ `.101` | ✅ `cr1` | none | ✅ PASS |

**Listener log (all four modes):** `Add: cr1... A`, `Add PTR: ...`, `Update complete:
added=1 removed=0 skipped=0 errors=0` × 2. No "Skipping unsupported record type" at INFO
level — that log line is `logger.debug()` (only visible at DEBUG level).

**DHCID log note (CR-4):** D2 logs a DHCID value in its `DHCP_DDNS_ADD_SUCCEEDED` entry even
under `no-check-without-dhcid`. This is D2 computing the DHCID for audit purposes regardless
of mode — it does not mean a DHCID record is included in the RFC 2136 UPDATE packet.

**Conclusion:** all four conflict-resolution modes are functionally identical from the
plugin's perspective. The listener silently ignores prerequisites and DHCID records in all
modes (confirmed by `logger.debug()` path), returns NOERROR unconditionally, and D2
proceeds to log `DHCP_DDNS_ADD_SUCCEEDED`. The options reference entry is confirmed:
*"the plugin silently downgrades every mode to `no-check-without-dhcid`."*

### CR-5 — Same-FQDN collision under `no-check-without-dhcid` then `check-with-dhcid`

Two distinct clients (different MACs, different IPs) both claim `cr5.dev.plhm.rgn.cm`.

**Under `no-check-without-dhcid`:**

| Step | Client | IP | Action | Unbound state |
|---|---|---|---|---|
| 1 | A (`...:02`) | `.102` | DORA | `cr5 A .102`, PTR .102 |
| 2 | B (`...:03`) | `.103` | DORA (same name) | `cr5 A .102`, `cr5 A .103`, PTR .102, PTR .103 |

**Under `check-with-dhcid`:**

Identical outcome — both A records accumulated, both PTRs present, D2 logged
`DHCP_DDNS_ADD_SUCCEEDED` for B with no prerequisite rejection.

**Key finding — accumulation, not overwrite.** The listener's `unbound-control local_data`
ADD operation is additive: adding a record for a name that already has an A record creates a
second A record (round-robin). The listener does not first remove the existing record.
The stale-IP cleanup (`[cleanup] Checking cr5... No stale IPs`) correctly left both records
because both leases were active — cleanup only removes A records whose corresponding IP has
no active Kea lease.

**Conclusion:** `check-with-dhcid`'s DHCID prerequisite provides no protection. The
listener returns NOERROR unconditionally without checking prerequisites, so D2 treats the
update as successful regardless of which client owns the name. Both modes produce identical
accumulation behavior. This is an explicit, documented design decision for an Unbound-only
deployment where we are the sole writer — `no-check-without-dhcid` is the appropriate mode
precisely because the check cannot work here.

### NCP-1 / NCP-2 — `ncr-protocol: TCP` vs UDP

**Background:** `ncr-protocol` lives in `kea-dhcp-ddns.conf` (D2's own config). D2 currently
supports only UDP for NCR delivery. Our listener is `SOCK_DGRAM` only. Tested by injecting
`"ncr-protocol": "TCP"` into `/usr/local/etc/kea/kea-dhcp-ddns.conf` (parsed via Python JSON)
and restarting D2 via `keactrl`.

**NCP-1 — TCP causes D2 hard-fail at startup:**

Expected behavior (per options reference): silent drop.
Actual behavior: **D2 refuses to start** with:

```
FATAL [kea-dhcp-ddns] DCTL_CONFIG_FILE_LOAD_FAIL DhcpDdns reason:
    ncr-protocol : TCP is not yet supported
```

D2 exits immediately. Port 53001 goes dark. kea-dhcp4 still runs and serves leases normally
(`DHCP4_LEASE_ALLOC` in log, ACK with `S=1` returned to client), but generates **no
`DHCP_DDNS_*` log entries at INFO level** when the NCR channel is down. The failure is
completely invisible to the operator from kea-dhcp4's log. DNS result: NXDOMAIN for
`ncr1.dev.plhm.rgn.cm`; Unbound has no record; listener received nothing.

**NCP-2 — UDP restore recovers immediately:**

Restored `/usr/local/etc/kea/kea-dhcp-ddns.conf` from backup (no `ncr-protocol` key =
UDP default). Restarted D2. Deleted the stale lease (to avoid `DHCP4_LEASE_REUSE` blocking
DDNS — the lease from NCP-1 was within the cache-threshold reuse window). Fresh DORA →
`DHCP_DDNS_ADD_SUCCEEDED` in D2 log; A + PTR appeared in Unbound immediately.

**Conclusion:** `ncr-protocol: TCP` in `kea-dhcp-ddns.conf` is **not** a "silent drop" —
it is a hard D2 startup failure. This is actually more visible than predicted (the D2 process
won't run at all, which `keactrl status` / `pgrep` / missing port 53001 make obvious), but
kea-dhcp4 itself logs nothing about the failure. **The operator must monitor D2 separately.**
Documentation note: TCP is not supported by Kea 3.0 for `ncr-protocol` at all —
attempting it takes D2 entirely offline, not just silently broken.

### Methodology note — `configctl kea restart` resets `ddns-conflict-resolution-mode`

When `configctl kea restart` runs, the OPNsense PHP model layer regenerates `kea-dhcp4.conf`
from `config.xml`. Direct writes to `config.xml` via Python regex were unreliable: the regex
`[^/]*` matched across tag content for non-empty values. More importantly, `configctl kea
restart` appeared to reset the field through the model save path. For these tests, the mode
was injected directly into the generated `kea-dhcp4.conf` and kea-dhcp4 restarted via
`keactrl stop/start` only — this bypasses the OPNsense model regeneration and preserves the
hand-edited value.

---

## Phase 6 — Plugin-level collision policy (2026-06-09)

Rig: same as Phase 5. OCU/ONU/UOR all ON. Conflict-resolution mode set directly in
`kea-dhcp4.conf` via `/tmp/inject_nocheck.py`; collision policy set via
`/tmp/set_collision_policy.py`; daemon restarted between tests.

Collision simulated: inject a "client A" record pointing to `192.168.1.199` directly
into Unbound via `unbound-control local_data`; then trigger dev-dhcpclient DORA (which
receives `.100` or `.101`). D2 sends RFC 2136 UPDATE for the same FQDN (`dev-dhcpclient.dev.plhm.rgn.cm`)
with the new IP — this is the colliding registrant.

### CR-6 — `first_wins` + `check-with-dhcid` (prereqs present in packet)

D2 in `check-with-dhcid` mode includes RFC 2136 prerequisites (answer section) in the
UPDATE packet.

| Step | Action | Unbound state | Listener log |
|---|---|---|---|
| Setup | Inject `.199`; set `first_wins`; kea in `check-with-dhcid` | `dev-dhcpclient A .199` | — |
| 1 | dev-dhcpclient DORA → gets `.101`; D2 sends UPDATE with prereqs | `dev-dhcpclient A .199` (unchanged) | `Collision: dev-dhcpclient already has {'.199'}; blocking .101 (first_wins, returning YXRRSET)` |
| 2 | D2 logs `DHCP_DDNS_UPDATE_FAILED`; DHCP lease unaffected | | `Update complete: added=0 skipped=1` |

**Result:** ✅ YXRRSET returned; original `.199` protected; PTR unchanged.

### CR-6c — `first_wins` + `no-check-without-dhcid` (no prereqs in packet)

D2 in `no-check-without-dhcid` sends a plain A/PTR UPDATE with no prerequisites.

| Step | Action | Unbound state | Listener log |
|---|---|---|---|
| Setup | Inject `.199`; set `first_wins`; kea in `no-check-without-dhcid` | `dev-dhcpclient A .199` | — |
| 1 | dev-dhcpclient DORA → gets `.101`; D2 sends A UPDATE (no prereqs) | `dev-dhcpclient A .199` (unchanged) | `Collision: dev-dhcpclient already has {'.199'}; blocking .101 (first_wins)` |
| 2 | A packet result | | `Update complete: added=0 skipped=1` |
| 3 | D2 sends explicit PTR UPDATE `101.1.168.192.in-addr.arpa → dev-dhcpclient` | no PTR for `.101` added | `Collision: PTR 101.1.168.192.in-addr.arpa skipped; dev-dhcpclient already registered to {'.199'} (first_wins)` |
| 4 | PTR packet result | | `Update complete: added=0 skipped=1` |

**Result:** ✅ A blocked; no YXRRSET (correct — no prereqs, first_wins policy enforced
at plugin level); PTR packet also blocked. No `.101` leak in Unbound.

**Incidental fix discovered in first run:** explicit PTR ADD packets from D2 arrived as a
separate UDP packet after the A was blocked. Initial code only checked the A/AAAA path
— the PTR slipped through and a stale `101.in-addr.arpa → dev-dhcpclient` record
appeared in Unbound. Fixed: `process_update()` explicit PTR ADD branch now also checks
`first_wins` collision — if the PTR target name is registered to a different IP, the PTR
is also skipped.

### CR-7 — `last_wins` + `check-with-dhcid`

| Step | Action | Unbound state | Listener log |
|---|---|---|---|
| Setup | Inject `.199`; set `last_wins`; kea in `check-with-dhcid` | `dev-dhcpclient A .199` | — |
| 1 | dev-dhcpclient DORA → gets `.101`; D2 sends UPDATE | `dev-dhcpclient A .101` | `Collision: dev-dhcpclient replacing {'.199'} with .101 (last_wins)` |
| 2 | Old `.199` PTR removed; new `.101` PTR synthesized | `dev-dhcpclient A .101`, PTR .101 | `Update complete: added=1 removed=0 skipped=0` |

**Result:** ✅ old record replaced; only new IP in Unbound.

---

## Skipped / deferred tests (documented for future sessions)

**Skipped interaction cases (redundant superposition — would pass; not run):**
- **C1** — ONU+OCU both ON, fire V-S0 and V-N → both override behaviors active at once.
  Skipped: it's the superposition of T2b (OCU forwards an S=0 client) + T1b (ONU updates an
  N=1 client), each already confirmed independently. (C4 already exercised both flags together.)
- **C2** — UOR+OCU ON, V-S0 then renew → the overridden forward update re-applied on renewal.
  Skipped: superposition of T2b + T3b; also subject to the lease-cache caveat from Group 3.
- **C3** — OCU ON, V-S1 → confirm no spurious `O` flag / correct record. Skipped: equivalent
  to T1c (override ON + cooperative S=1 → normal update, `O=0`), already confirmed.

To run later: same harness/loop; use fresh (MAC, IP, name) tuples and the relevant
`set_overrides` combination.

**Deferred to a future LISTENER round (these test the plugin's OWN logic, not Kea):**
- Malformed / oversized / unauthenticated RFC 2136 updates to the listener on `:53535`.
- Client-controlled FQDN/hostname → `unbound-control local_data` **injection/sanitization**
  (partial mitigation: listener parses RFC 2136 with dnspython, not hand-rolled).
- **Nameless-client closure** — validate `ddns-generated-prefix` + `ddns-replace-client-name`
  to give MAC-randomizing/nameless clients a synthesized name (G1 documented the gap).
- **TSIG end-to-end** — implementation present but unvalidated; disabled in v0.9.

## Documentation & GUI work (step 1 — recommended-settings rollout)

Done after the matrix, to surface the recommended settings:
1. **Plugin `README.md`** (repo `/Users/tkr/code/os-kea-unbound`, `main`): Step-1 table now
   shows recommended values (overrides On; reverse zone required for PTR); added a
   "Recommended DDNS settings" callout (all-three-ON, `ONU⇒OCU` rule, cache-window caveat,
   nameless gap); updated two stale "Known issues" bullets (reverse zones + override options
   now verified; conflict-modes still deferred).
2. **Homelab `kea-dhcp.md`**: added "DDNS (Kea → Unbound) — recommended settings" section.
3. **Kea Config Check tab** (`KcaconfigController.php` + `kcaconfig.volt`): new per-subnet
   `advisories` — a **warning** on the incoherent `ONU=1/OCU=0` combo and **info**
   recommendations to enable OCU/ONU/UOR (only when DDNS is enabled on the subnet).

**Deploy method for plugin PHP/volt to dev-opnsense** (manual, pre-package): `scp` to `/tmp` →
`sudo cp` into `/usr/local/opnsense/mvc/app/{controllers,views}/OPNsense/KeaUnbound/...` →
clear volt cache (`/usr/local/opnsense/mvc/app/cache/*.volt.php`, auto-recompiles anyway).
**Verify a controller method without API creds:** reflection through the Phalcon bootstrap —
`php -r 'require_once("/usr/local/opnsense/mvc/script/load_phalcon.php"); $r=new
ReflectionClass("OPNsense\\KeaUnbound\\Api\\KcaconfigController"); $m=$r->getMethod("...");
$m->setAccessible(true); $m->invoke($r->newInstanceWithoutConstructor(), ...);'`.

**Status:** deployed + verified on dev-opnsense (controller via reflection: warning/info logic
correct). The Config Check **visual** (volt rendering) not yet eyeballed in a browser.
**Repo changes are UNCOMMITTED** in `/Users/tkr/code/os-kea-unbound` (README + controller +
volt) and in this homelab repo (docs + harness).
