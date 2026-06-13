# Kea DDNS Options — Plugin Impact Reference

> Internal reference for `os-kea-unbound`. Combines results from the OCU/ONU/UOR
> test matrix (June 2026) with analysis of all other DDNS-related Kea options and
> their impact on this plugin's two name-producing paths.
>
> Test rig: dev-opnsense (OPNsense 26.1.9, Kea 3.0.3, kea-unbound 0.9)
> + dev-dhcpclient (Debian 13, scapy 2.6.1). Forward zone `dev.plhm.rgn.cm.`,
> reverse `1.168.192.in-addr.arpa.`, listener at `127.0.0.1:53535`.

---

## OPNsense config.xml settability (as of OPNsense 26.1.9)

Options split into two groups: those accessible via the OPNsense GUI / config.xml
and those that require manual configuration mode.

**`manual_config` is per-service and independent:** you can enable manual config for
`dhcp4` while leaving `dhcp6` GUI-managed, and vice versa. Options below are in
`KeaDhcpv4.xml` / `KeaDhcpv6.xml` (model) and `KeaDhcpv4.php` / `KeaDhcpv6.php`
(code generator) on the live OPNsense box.

### Settable via OPNsense GUI (config.xml, per-subnet, both v4 and v6)

| config.xml field | Kea option emitted | Notes |
|---|---|---|
| `ddns_forward_zone` | forward zone name in D2 | Required for any DDNS; dependency for `ddns_dns_server` |
| `ddns_reverse_zone` | reverse zone name in D2 | Optional; must be set explicitly for PTR NCRs to fire |
| `ddns_qualifying_suffix` | `ddns-qualifying-suffix` | Appended to bare hostnames before FQDN |
| `ddns_dns_server` | implies `ddns-send-updates: true` | Derived — not a separate field; presence = true |
| `ddns_dns_port` | DNS server port in D2 domain | |
| `ddns_domain_key_name` | per-domain TSIG key name | |
| `ddns_domain_key_secret` | per-domain TSIG secret | |
| `ddns_domain_key_algorithm` | per-domain TSIG algorithm | |
| `ddns_override_no_update` | `ddns-override-no-update` | Boolean: empty tag = false, `1` = true |
| `ddns_override_client_update` | `ddns-override-client-update` | Boolean: same encoding |
| `ddns_update_on_renew` | `ddns-update-on-renew` | Boolean: same encoding |
| `ddns_conflict_resolution_mode` | `ddns-conflict-resolution-mode` | OptionField |
| `manual_config` | switches off PHP config generation | Per-service; independent for dhcp4 and dhcp6 |

**`ddns-send-updates` is not an independent GUI field.** PHP emits
`'ddns-send-updates' => !$subnet->ddns_dns_server->isEmpty()`. If no DNS server is
set for a subnet, DDNS is disabled for it at the Kea level regardless of other settings.

### Not settable via OPNsense GUI — manual config mode only

These options are not in the OPNsense Kea model XML. To use them, `manual_config`
must be enabled for the service, and you hand-edit the generated conf or provide your
own. They only appear in `kea-dhcp4.conf` or `kea-dhcp6.conf` if you put them there.

- `ddns-replace-client-name` (and its modes)
- `ddns-generated-prefix`
- `hostname-char-set` / `hostname-char-replacement`
- `ddns-ttl-percent` / `ddns-ttl` / `ddns-ttl-min` / `ddns-ttl-max`
- `ddns-use-conflict-resolution` (older boolean form, superseded by the mode field above)
- `cache-threshold` (per-pool Kea default; not in conf but active at 0.25)
- Global reservations (top-level `reservations[]` at Dhcp4/Dhcp6 level)
- `shared-networks[]`
- `reservations-global` / `reservations-in-subnet` / `reservations-out-of-pool`
- `match-client-id` (present in the subnet config but not in DDNS context)

---

## The NCR pipeline: where each option lives

Understanding which service owns which option avoids confusing "why isn't this working"
debugging. Three separate config files, three separate gates.

```
kea-dhcp4.conf (per-subnet)          kea-dhcp4.conf (top-level)    kea-dhcp-ddns.conf (D2)
──────────────────────────           ───────────────────────────   ───────────────────────
ddns-send-updates              →→→   dhcp-ddns {                →→→  forward-ddns {
ddns-qualifying-suffix                 enable-updates: true             ddns-domains [{
ddns-override-no-update                server-ip: 127.0.0.1              name: "zone."
ddns-override-client-update            server-port: 53001                dns-servers: [{
ddns-update-on-renew           }       }                                   ip: 127.0.0.1
ddns-conflict-resolution-mode                                              port: 53535
ddns-replace-client-name                                               }]
ddns-generated-prefix                                              }]
hostname-char-set                                                  }
hostname-char-replacement                                          reverse-ddns { ... }
                                                                   ncr-protocol: UDP
```

**`ddns-send-updates`** (dhcp4.conf subnet): gates NCR production per subnet.
OPNsense derives it from whether `ddns_dns_server` is set (not a separate GUI field).

**`enable-updates`** (dhcp4.conf `dhcp-ddns {}` block): gates the NCR channel from
the DHCP daemon to D2. OPNsense emits this entire block only when `KeaDdns.general.enabled`
is set. Without it, no NCRs ever leave the DHCP daemon regardless of subnet settings.

**Everything in `kea-dhcp-ddns.conf`** (D2's own config): controls how D2 routes and
delivers NCRs to DNS servers. Includes `ncr-protocol`, domain name matching,
`dns-servers`, and TSIG per domain.

All three must be configured and active for an NCR to travel the full path to our listener.

---

## Why this matters: two paths, one name

The plugin registers hostnames in Unbound two ways. Any Kea option that makes them
disagree causes audit mismatches, stale records, and cleanup churn.

**Live path** (`kea-unbound-ddns.py`): receives RFC 2136 UPDATE packets from D2 and
registers the FQDN verbatim from the packet. Kea computed the name; the daemon just
executes it. It ignores prerequisite/DHCID sections entirely.

**Bulk path** (`lease-sync.py` / `reservation-sync.py`): re-derives the name from
`config-get` + `lease4-get-all`, applying only `qualify_hostname()` with the
`ddns-qualifying-suffix` waterfall. It does NOT reproduce generated-prefix,
replace-client-name, or hostname scrubbing.

**Explicit scope limitation:** the bulk path is intentionally scoped to OPNsense
standard configuration only — i.e., `replace-client-name: never` (default), no charset
scrubbing, no generated names. If you enable those via manual config, the bulk sync
becomes unreliable by design and should be treated as best-effort. This is documented,
not a bug to fix.

Why not model Kea's name logic in the bulk path? We'd be reimplementing Kea's internal
name-crafting in Python — C++ regex for charset scrubbing, exact dashed-IP construction
for generated names, and their interactions. Any subtle divergence silently produces wrong
names. The live path always gets it right for free. If generated names are in use, keep
`ddns-update-on-renew: true` so the live path re-asserts on renewals, shrinking the
window where a stale bulk sync matters.

---

## Background: how DHCP DDNS divides the work

A DHCP lease drives two DNS records:

- **Forward `A`** — name → IP (ownership is negotiable)
- **Reverse `PTR`** — IP → name (server always owns this)

The client expresses its intent via **FQDN option 81** flags:

| Flag | Meaning |
|------|---------|
| `S` (Server) | `S=1`: "server, do my forward A." `S=0`: "I, the client, will do my own A." |
| `N` (No-update) | `N=1`: "no DNS updates at all." When `N=1`, `S` is moot. |
| `O` (Override) | Set by the **server in the ACK reply** to signal "I overrode your request." |
| `E` (Encoding) | Canonical wire format vs ASCII. |

Hostname option 12 has no S/N flags — treated as `S=1` (server does both records).

### Baseline behavior (no override options set, name present)

| Client sends | Server writes | ACK reply |
|---|---|---|
| FQDN `S=1, N=0` | A + PTR | `S=1, O=0, N=0` |
| FQDN `S=0, N=0` | PTR only | `S=0, O=0` |
| FQDN `N=1` | nothing | `N=1` |
| Hostname (12) only | A + PTR | — |
| No name | nothing | — |

Everything the override options do is a surgical deviation from this table.

---

## Tier 1 — Name-shaping options (highest impact)

These change what FQDN ends up in Unbound. The live path obeys them automatically.
The bulk path reproduces only qualifying-suffix. Any of these set to non-default under
manual config can cause live/bulk path divergence.

**Testing note:** group all Tier 1 options together with hostname-weirdness cases
(hostname-less reservations, invalid characters, dotted-name edge cases) in the same
test session — they share the same failure mode and the same harness.

### `ddns-replace-client-name` — STATUS: UNTESTED | OPNsense: manual config only

**Default:** `never`  
**Modes:**

| Mode | What Kea does |
|------|---------------|
| `never` | Use the client-supplied name as-is (default) |
| `always` | Discard the client name; generate a synthetic name every time |
| `when-present` | Replace a supplied name with a generated one |
| `when-not-present` | Generate a name only if the client sent none |

**Plugin impact:** With `always` or `when-present`, the FQDN in the NCR packet differs
from `lease["hostname"]` in the Kea lease database. Live path registers the generated
name; bulk path registers the raw `hostname` field. Guaranteed audit mismatch and
stale-record churn after every Unbound reload.

### `ddns-generated-prefix` — STATUS: UNTESTED | OPNsense: manual config only

**Default:** `myhost`  
**Generated FQDN format:** `<prefix>-<dashed-IP>.<qualifying-suffix>`  
**Example:** `myhost-192-168-1-123.dev.plhm.rgn.cm`

**Plugin impact:** When a name must be generated, the live path registers
`<prefix>-<dashed-IP>.<suffix>`. The bulk path sees `lease["hostname"] == ""` and skips
the lease entirely (`if not hostname ... continue`). The record exists via live path but
is invisible to bulk sync → vanishes on the next Unbound reload and never returns until
the next NCR. `is_sane_name()` accepts generated names (first label e.g. `myhost` is
valid RFC 1123), so the live path registers them correctly.

This is the closure for the **nameless-client gap** confirmed in test G1.

### `hostname-char-set` / `hostname-char-replacement` — STATUS: UNTESTED | OPNsense: manual config only

When set, Kea scrubs characters not matching `hostname-char-set` from the client name
before building the FQDN. The live path registers the scrubbed name (from the NCR packet).
The bulk path uses the raw `hostname` — no scrubbing.

Any client with underscores, spaces, or non-LDH characters causes path divergence.
Additionally, `is_sane_name()` may reject the raw name in the bulk path while the live
path accepts the scrubbed version — **asymmetric registration**: record exists via live
path, bulk sync can't see it, drops on next Unbound reload.

### `ddns-qualifying-suffix` — STATUS: TESTED (working) | OPNsense: GUI settable

**Scope:** global, shared-network, subnet  
Suffix appended to unqualified (no-dot) client names to form the FQDN. The precedence
waterfall: subnet → shared-network → global → OPNsense system domain → bare name.

The bulk path in `keaunbound_sync.py:_effective_suffix()` and `qualify_hostname()`
models this waterfall correctly. Tested implicitly in all Group 1-3 tests.

**`qualify_hostname()` behavior:** any name containing a dot is returned as-is (treated
as already qualified). Kea does the same. The edge case to test: a client sends a dotted
name that is NOT under the qualifying suffix (e.g. `foo.bar` with suffix
`plhm.rgn.cm`). Both sides should leave it as `foo.bar` — verify they agree and the name
isn't rejected by D2's forward-domain matching.

**Shared-network suffix inheritance: TESTED ✅** — verified on dev-opnsense (June 2026)
by injecting a shared-network structure into the real `config-get` response and running
`_build_suffix_map` + `_normalize_raw_lease` against it. Both inheritance (subnet with
no explicit suffix gets the shared-network's suffix) and per-subnet override (subnet
with explicit suffix ignores shared-network's value) pass. `ddns-send-updates`
inheritance through shared-networks also confirmed in the same test.

**Untested branches:** the dotted-name edge case above.

### Reservation hostname presence — STATUS: UNTESTED | OPNsense: GUI settable

A reservation may have `ip-address` but no `hostname`. `reservation-sync.py` skips any
such reservation (`if not hostname or not ip: continue`). Such a host gets no forward
record from the bulk path. If Kea is also generating a name for it via DDNS
(generated-prefix), only the live path covers it.

Group with Tier 1 testing: hostname-less reservation, reservation with invalid
characters, dotted-name reservation, reservation whose hostname is rejected by
`is_sane_name()`.

---

## Tier 2 — Update-triggering options

These gate whether an NCR fires at all, and on what events.

### `ddns-override-no-update` (ONU) — STATUS: TESTED ✅ | OPNsense: GUI settable

**What it does:** Ignores `N=1` from the client; server does A + PTR anyway. Reply
flips to `N=0, S=1, O=1`. The `O` flag signals override occurred.

**Tested results (Group 1):**

| Test | ONU | Client sends | ACK flags | Forward A | PTR | Result |
|------|-----|-------------|-----------|-----------|-----|--------|
| T1a | OFF | FQDN N=1 (.161, t1a) | `S=0, O=0, N=1` | NXDOMAIN | NXDOMAIN | ✅ PASS |
| T1b | ON | FQDN N=1 (.162, t1b) | `S=1, O=1, N=0` | .162 ✓ | t1b ✓ | ✅ PASS |
| T1c | ON | FQDN S=1 (.163, t1c) | `S=1, O=0, N=0` | .163 ✓ | t1c ✓ | ✅ PASS |

T1a: no listener log entry, Kea shows `DHCP4_LEASE_ALLOC` only (no `DHCP_DDNS_ADD`).
T1b: listener `Add: t1b ... A 192.168.1.162` + PTR. T1c: `O=0` confirms override flag
only set when override actually occurred.

**Conclusion:** behaves exactly as documented.

### `ddns-override-client-update` (OCU) — STATUS: TESTED ✅ | OPNsense: GUI settable

**What it does:** Ignores `S=0` from the client; server performs the forward A itself.
Reply flips to `S=1, O=1`. Does **not** override `N=1` — that requires ONU.

**Tested results (Group 2):**

| Test | OCU | Client sends | ACK flags | Forward A | PTR | Result |
|------|-----|-------------|-----------|-----------|-----|--------|
| T2a | OFF | FQDN S=0 (.171, t2a) | `S=0, O=0` | NXDOMAIN | present ✓ | ✅ PASS |
| T2b | ON | FQDN S=0 (.172, t2b) | `S=1, O=1` | .172 ✓ | present ✓ | ✅ PASS |
| T2c | ON | FQDN N=1 (.173, t2c) | `N=1, O=0` | NXDOMAIN | NXDOMAIN | ✅ PASS |

T2a: `list_local_data` shows PTR only (no A). T2b: A + PTR both present. T2c: both
absent (OCU does not override N=1 — flag orthogonality confirmed empirically).

**Conclusion:** OCU overrides exactly the `S=0` row and nothing else.

### `ddns-update-on-renew` (UOR) — STATUS: TESTED ✅ | OPNsense: GUI settable

**What it does:** Re-sends the NCR on lease renewals (not just new allocations).

**Why it matters for this plugin:** Unbound `local_data` is runtime-only and does not
survive an Unbound restart. UOR causes Kea to re-assert DNS on each genuine renewal
(~T1, half lease-time), providing self-healing without waiting for the next new lease.

**⚠ Key finding — Kea lease caching gates UOR.** Kea 3.0 default includes
`cache-threshold: 0.25` (NOT written into generated `kea-dhcp4.conf`; only visible via
`config-get`). A renewal arriving within `0.25 × valid-lifetime` is "reused"
(`DHCP4_LEASE_REUSE`) and triggers **no DDNS at all** — UOR cannot fire within this
window. With default 4000s lease: 1000s reuse window (~17 min). With typical T1 at
50% of lifetime (2000s), renewals land outside the window and UOR fires normally.

**Tested results (Group 3):**

| Test | UOR | Renewal | Record after renew | NCR fired | Result |
|------|-----|---------|-------------------|-----------|--------|
| T3a | OFF | genuine (past reuse window) | NXDOMAIN (stays gone) | none | ✅ PASS |
| T3b | ON | genuine (past reuse window) | recreated (A .184) | `CHG_ADD` | ✅ PASS |

Method: DORA creates record → delete record from Unbound out-of-band (keep lease) →
issue renewal → observe. Used `valid-lifetime=40s` for tests (10s reuse window);
renewals sent at ~15s to land outside it. Verified genuine renewal via `DHCP4_LEASE_ALLOC`
in Kea log (not `LEASE_REUSE`).

**Conclusion:** works as documented; the lease-cache interaction is the critical
operational caveat. Document for anyone shortening lease times or relying on frequent
renewals for self-healing.

### `ddns-send-updates` — STATUS: TESTED ✅ | OPNsense: GUI (derived, not explicit)

OPNsense derives this from `ddns_dns_server`: if a DNS server is configured for the
subnet, the PHP emits `ddns-send-updates: true`; otherwise `false`. It is not an
independent GUI field. It lives in `kea-dhcp4.conf` per-subnet.

If false for a subnet, no NCR is sent for leases in that subnet → live path never fires.
**The bulk sync path also respects this flag** (`_build_suffix_map` in
`lib/keaunbound_sync.py` reads `ddns-send-updates` per subnet and builds a
`ddns_disabled_subnets` set; `_normalize_raw_lease` returns `None` for any lease whose
`subnet-id` is in that set). Both `query_kea_leases()` and `query_kea_reservations()`
honour per-subnet and shared-network inheritance, so a subnet with
`ddns-send-updates: false` is excluded from sync, clean, and audit — matching the live
NCR path.

**Inheritance chain:** subnet → shared-network → global, in that order. A subnet with
no explicit value inherits from its shared-network parent; a shared-network with no
explicit value inherits from the global Dhcp4/Dhcp6 level (default true).

**Operational note:** this setting is the correct way to exclude a subnet from DNS
registration. Setting it to false on a subnet stops the plugin from syncing those leases
in all three paths (live NCR, bulk sync, and clean). Records already in Unbound from
before the change are cleaned up on the next scheduled run of `local-data-clean.py`.

### `enable-updates` (in `dhcp-ddns {}` block) — STATUS: TESTED | OPNsense: GUI (via KeaDdns.enabled)

Lives in `kea-dhcp4.conf` top-level (not per-subnet). OPNsense emits the entire
`dhcp-ddns {}` block only when `KeaDdns.general.enabled` is set. Without it, no NCRs
leave the DHCP daemon regardless of subnet settings. Discovered during Phase 0 — the
first D2 enable also requires `configctl template reload OPNsense/Kea` to regenerate
the `keactrl.conf` that gates which daemons start.

---

## Tier 3 — Conflict resolution / DHCID

### `ddns-conflict-resolution-mode` — STATUS: TESTED ✅ | OPNsense: GUI settable

**Default:** `check-with-dhcid`  
**Supersedes:** `ddns-use-conflict-resolution` (older boolean; still accepted by Kea)

**Modes and what they send in the NCR packet:**

| Mode | DHCID in update? | Prerequisites in packet? | Effective behavior at our listener |
|------|-----------------|--------------------------|-----------------------------------|
| `check-with-dhcid` | Yes (A record in update section) | Yes (in answer/question section) | Prereqs ignored; DHCID record skipped; update proceeds |
| `no-check-with-dhcid` | Yes | No | DHCID record skipped; update proceeds normally |
| `check-exists-with-dhcid` | Yes | Yes (existence-only) | Same as check-with-dhcid — prereqs ignored |
| `no-check-without-dhcid` | No | No | Cleanest — plain A/PTR update only |

**How our listener handles each:** `process_update()` iterates only `msg.authority`
(the update section). `msg.question` and `msg.answer` (where RFC 2136 prerequisites
live) are completely ignored. DHCID records in the update section hit
`if rdtype not in HANDLED_TYPES` (`HANDLED_TYPES = {"A", "AAAA", "PTR"}`) and are
logged as "Skipping unsupported record type DHCID" at `logger.debug()` — no crash,
no effect, not visible at INFO level.

**Result (empirically confirmed — Phase 5, 2026-06-08):** all four modes produce
identical behavior. A + PTR land in Unbound; D2 logs `DHCP_DDNS_ADD_SUCCEEDED`; no
listener errors. The plugin silently downgrades every mode to `no-check-without-dhcid`.

**Same-FQDN collision (empirically confirmed — CR-5):** two clients claiming the same
FQDN under both `no-check-without-dhcid` and `check-with-dhcid` produced identical
results — both A records accumulated (Unbound `local_data` ADD is additive), both PTRs
present, no prerequisite rejection. The stale-IP cleanup left both records because both
leases were active. `check-with-dhcid`'s DHCID prerequisite provides zero protection
because the listener returns NOERROR unconditionally.

**For same-FQDN collision control, use `collision_policy`** (the plugin's own setting,
described in the next section) — not this Kea field.

**D2 DHCID log note:** D2 logs a DHCID value even under `no-check-without-dhcid` (for
audit purposes). This is informational — it does not mean a DHCID record is in the
RFC 2136 UPDATE packet.

**Recommendation: `no-check-without-dhcid`.** No DHCID records sent at all → simplest,
no unnecessary records in the update, cleanest for our use case. The existing
`kcaconfig.volt` fix guide recommends `no-check-with-dhcid` (citing OPNsense issue #10212
/ dual-stack problems with `check-with-dhcid`). That's a useful intermediate step, but
`no-check-without-dhcid` is the fully correct answer for this deployment.

**Important:** `ddns-conflict-resolution-mode` has no effect on same-FQDN collision
handling in this plugin. Use the plugin's own `collision_policy` setting for that
(described below).

### `collision_policy` (plugin setting) — STATUS: TESTED ✅ | Location: plugin Settings UI

**Default:** `allow`  
**Location:** OPNsense → Services → Kea Unbound DDNS → Settings → Hostname collision policy  
**Stored in:** `config.xml` at `OPNsense/KeaUnbound/general/collision_policy`

This is a plugin-level setting, independent of Kea's `ddns-conflict-resolution-mode`.
It controls what happens when a DHCP client attempts to register a hostname that is
already registered to a different IP in Unbound.

| Policy | Behavior | YXRRSET returned? |
|--------|----------|-------------------|
| `allow` (default) | Both records coexist; Unbound round-robins them | Never |
| `first_wins` | Existing record is kept; new registrant's A and PTR are blocked | Only if prereqs present in UPDATE packet (D2 in `check-*` mode) |
| `last_wins` | Existing record is replaced by new registrant's IP | Never (always succeeds) |

**YXRRSET gate in `first_wins`:** The plugin always blocks the add under `first_wins`.
Whether it returns YXRRSET (rcode 9) to D2 depends on whether the RFC 2136 UPDATE
packet includes prerequisites (`msg.answer` section non-empty). Prereqs are present only
when Kea is in `check-with-dhcid` or `check-exists-with-dhcid` mode. With
`no-check-without-dhcid` (recommended), no prereqs → YXRRSET is not returned; the add
is silently skipped and D2 sees NOERROR. In both cases the **A and PTR are not added**.

**PTR consistency:** explicit PTR ADD packets from D2 are also checked under `first_wins`.
If the PTR target name is already registered to a different IP, the PTR is skipped — this
prevents a stale PTR record from leaking even when the corresponding A was blocked.

**Sync scripts:** `reservation-sync.py` and `lease-sync.py` both respect `collision_policy`.
They snapshot Unbound state at the start of each run and apply the same allow/first_wins/last_wins
logic before each `local_data` call. PTR synthesis in the sync scripts is part of the same
loop iteration, so it is naturally skipped when the A is blocked — no separate PTR check needed.

**Static reservation precedence with `first_wins`:** `reservation-sync.py` runs before
`lease-sync.py` at startup. Static reservations are loaded first → they win naturally
under `first_wins` without any special-casing. No hard guarantee on ordering relative to
live D2 NCRs at startup, but it is the design intent (documented, not enforced in code).

**Tested results (Phase 6, 2026-06-09):**

| Test | Policy | Kea mode | Prereqs? | A outcome | PTR outcome | YXRRSET? |
|------|--------|----------|----------|-----------|-------------|----------|
| CR-6 | `first_wins` | `check-with-dhcid` | Yes | Blocked | Blocked | ✅ Yes |
| CR-6c | `first_wins` | `no-check-without-dhcid` | No | Blocked | Blocked | No |
| CR-7 | `last_wins` | `check-with-dhcid` | Yes | Replaced | Replaced | No |

---

## Tier 4 — D2 (kea-dhcp-ddns) routing options

These live in `kea-dhcp-ddns.conf` and determine whether packets reach
`127.0.0.1:53535` at all.

### `forward-ddns.ddns-domains[].name` — STATUS: TESTED | OPNsense: GUI (via ddns_forward_zone)

D2 matches the client FQDN against domain names using longest-match. If a subnet's
`ddns-qualifying-suffix` produces an FQDN not under any configured forward domain, D2
drops the NCR — no forward update, but a reverse update may still fire. This is a
**user/Kea misconfiguration** — not a plugin failure. Our Config Check tab detects it
(`wrong_target` status) and provides a fix guide.

**Note:** trailing dot required on zone names (`dev.plhm.rgn.cm.` not
`dev.plhm.rgn.cm`). D2 silently drops updates when the dot is missing.

### `reverse-ddns.ddns-domains[].name` — STATUS: TESTED | OPNsense: GUI (via ddns_reverse_zone)

D2 sends a separate reverse NCR for each lease event. It routes them to whichever
reverse domain matches the IP's in-addr.arpa name. If `ddns_reverse_zone` is empty in
OPNsense, D2 generates no reverse domain → **no reverse NCRs at all**.

However, **our listener generates PTR records automatically for every A record ADD it
processes** (forward NCR path → `reverse_ptr()` → `local_data`). So even with no
reverse zone configured, PTR records appear in Unbound — synthesized from the forward
NCR, not from a dedicated reverse NCR. The `ptr_state` logic in the audit should be
tested against subnets with a missing reverse zone to confirm it handles this correctly.

OPNsense **does not auto-derive** the reverse zone from the subnet address. It must be
set explicitly. This is a frequent configuration gap. Our Config Check tab should warn
when DDNS is enabled on a subnet but `ddns_reverse_zone` is empty.

### `ncr-protocol` — STATUS: TESTED ✅ | OPNsense: manual config only

D2 supports only UDP for NCR delivery. The listener is `SOCK_DGRAM` only. Setting
`ncr-protocol: TCP` in `kea-dhcp-ddns.conf` does **not** silently drop updates — it
causes **D2 to hard-fail at startup**:

```
FATAL DCTL_CONFIG_FILE_LOAD_FAIL: ncr-protocol : TCP is not yet supported
```

D2 exits immediately; port 53001 goes dark. kea-dhcp4 continues to serve leases normally
but logs **no NCR-related errors** at INFO level when the D2 channel is down — the failure
is invisible from kea-dhcp4's perspective. DNS: NXDOMAIN; no records in Unbound; listener
receives nothing. Restoring UDP and restarting D2 recovers immediately (confirmed in NCP-2).

**Operator impact:** TCP in `ncr-protocol` takes D2 entirely offline (not just broken).
The failure is visible via `keactrl status` (D2 inactive), missing port 53001, or D2
log, but kea-dhcp4 gives no alert. Monitor D2 status independently.

**Config Check tab:** a check for `ncr-protocol != "UDP"` would be useful but is not yet
implemented. For now, document as a README advisory: UDP only, TCP causes D2 hard-fail.

### TSIG (`tsig-keys[]` + per-domain `key-name`) — STATUS: UNTESTED | OPNsense: GUI settable

See `int-docs/kea-tsig-testing.md` for full TSIG testing notes and the end-to-end
validation plan.

**Summary:** listener enforces TSIG as all-or-nothing. If started with `--tsig-key`,
any unsigned packet is REFUSED. If no key, unsigned-only accepted. D2 key / daemon key
mismatch or algorithm mismatch → all records fail silently. The implementation is
present; end-to-end is unvalidated.

---

## Tier 5 — Reservation / lease structural options

### Multiple IPv6 addresses per reservation — STATUS: TESTED ✅ | OPNsense: GUI (v6 only)

DHCPv4 reservations: one `ip-address`. DHCPv6 reservations: `ip-addresses` list (can
have multiple). `query_kea_reservations()` emits one result dict per address in the
`ip-addresses` list — a reservation with two addresses produces two independent AAAA +
PTR registrations. Previously the code took `addrs[0]` only and silently dropped all but
the first; this was fixed and verified against the live test environment (v6res2-multiaddr
reservation). Covered by the `ipv6_multiple_addresses` scenario.

### Global reservations — STATUS: UNTESTED | OPNsense: manual config only

Legal in Kea — reservations at the top level of `Dhcp4`/`Dhcp6`, matched to any client
regardless of which subnet they come in on. Require `reservations-global: true` to be
active (see below). Not available in OPNsense GUI; manual config only.

`query_kea_reservations()` already reads them (the `sources.append((dhcp_config, ...))
` line). Low real-world risk for standard OPNsense installs.

### `shared-networks[]` — STATUS: UNTESTED | OPNsense: manual config only

A shared network groups multiple subnets on the same physical link. Example: two
different IP ranges (`192.168.1.0/24` and `10.0.0.0/24`) both on `em1`. Each child
subnet can have its own `ddns-qualifying-suffix`. OPNsense GUI does not support
creating shared networks. `_iter_kea_subnets()` handles them in code but this branch
has never been exercised with real data.

### `reservations-global` / `reservations-in-subnet` / `reservations-out-of-pool` — STATUS: N/A | OPNsense: manual config only

These boolean flags control which reservation arrays Kea looks at when processing a
client request — they don't change what we read from `config-get`. We read all arrays.
But they change which reservations are **active**:

- `reservations-in-subnet` (default true): check per-subnet `reservations[]`
- `reservations-global` (default false): also check top-level `reservations[]`
- `reservations-out-of-pool` (default false): allow reserved addresses outside the pool

If `reservations-in-subnet: false`, subnet reservations exist in the config but Kea
ignores them for lease allocation → we'd sync them to Unbound but they'd never be used.
Not a concern for standard OPNsense installs.

### `subnet-id` mismatch — STATUS: N/A (low risk)

`query_kea_leases()` maps each lease's `subnet-id` to its qualifying suffix. If a
lease's `subnet-id` isn't in the map (subnet was deleted or renumbered after the lease
was created), it falls back to `default_suffix`. This is only possible if:
- A subnet is deleted from Kea config while leases from it are still active in the lease DB
- OPNsense doesn't delete leases when subnets are removed via GUI

Low risk, low priority.

### `match-client-id` — STATUS: N/A (cleanup path concern)

Doesn't affect what *name* gets registered. Affects which identifier Kea uses to key
leases. Changing it can cause a client to get a new IP without releasing the old one →
stale record for the old IP. This is a `--aggressive-cleanup` / `local-data-clean.py`
path concern, not a name-crafting issue.

### `decline-probation-period` / declined leases — STATUS: N/A

When a client sends DHCPDECLINE (IP in use on network), Kea marks the lease as state 1
(declined) and quarantines the IP for `decline-probation-period` seconds (default 600s).
`query_kea_leases()` filters to `state == 0` only — declined leases are never registered
in DNS. Kea should send a DELETE NCR when a lease is declined; if that NCR arrives, the
listener removes it correctly. If missed, `local-data-clean.py` removes it on the next
scheduled run. No action needed.

---

## Tier 6 — TTL options

### `valid-lifetime` / `ddns-ttl-percent` / `ddns-ttl` / `ddns-ttl-min` / `ddns-ttl-max`

**`valid-lifetime`** is GUI settable. **The `ddns-ttl-*` family** is manual config only
— not in the OPNsense Kea model XML.

Unbound does store and serve TTLs from `local_data` entries; DNS clients use them for
their local cache. For LAN DNS the practical importance is low — records get refreshed
or cleaned up well before TTL-scale issues matter.

**Live path:** TTL comes verbatim from the NCR packet. D2 computes it as: `ddns-ttl` if
set, else `ddns-ttl-percent × valid-lifetime`, else `valid-lifetime` (possibly clamped
by min/max). The listener gets the full result of these settings for free.

**Bulk path:** TTL = `expire - now` (remaining lease lifetime at sync time). This is
a reasonable approximation. To exactly match the live path's TTL, we'd need to read all
the `ddns-ttl-*` params from `config-get` and replicate the formula. Not worth the
complexity — the current approach errs toward shorter TTLs (correct direction).

**Bulk path sets TTL from remaining lease time; live path uses Kea's calculated TTL.
The two will differ for the same record and that is intentional and acceptable.**

---

## Incoherent corner: `ONU=1, OCU=0` — STATUS: TESTED ✅

**Config:** ONU=ON, OCU=OFF, UOR=OFF.

| Client | Opt-out | ACK flags | Forward A | PTR | Observation |
|--------|---------|-----------|-----------|-----|-------------|
| N=1 (.191, c4n) | strong ("no DNS") | `S=1, O=1, N=0` | .191 ✓ | c4n ✓ | full A+PTR |
| S=0 (.192, c4s) | weak ("I'll do my own A") | `S=0, O=0` | NXDOMAIN | c4s ✓ | PTR only |

The stronger opt-out (N=1) got a complete record; the weaker opt-out (S=0) got less —
empirical proof that `(ONU=1, OCU=0)` is incoherent. **Rule: `ONU=1` should imply
`OCU=1`.** The Config Check tab warns on this combination.

---

## Gap: nameless clients — STATUS: CONFIRMED ✅

**Test G1 (Config: ONU=ON, OCU=ON, UOR=ON):** Client sent no FQDN and no hostname.

**Result:** lease allocated (.195), no DNS records. Even with all three overrides ON, a
nameless client gets nothing — the override flags only act when the client supplies a
name. Closure requires `ddns-generated-prefix` + `ddns-replace-client-name` (both
manual config only in OPNsense 26.1.9).

---

## Recommended posture for this deployment

| Option | Recommended | Config location | Rationale |
|--------|-------------|-----------------|-----------|
| `ddns-override-client-update` | **ON** | GUI, per-subnet | No DDNS server for S=0 clients to self-register against. |
| `ddns-override-no-update` | **ON** | GUI, per-subnet | Visibility policy: every device resolvable. ONU implies OCU. |
| `ddns-update-on-renew` | **ON** | GUI, per-subnet | Unbound `local_data` not persistent. Subject to cache-threshold caveat. |
| `ddns-conflict-resolution-mode` | `no-check-without-dhcid` | GUI, per-subnet | We're the sole writer; no DHCID needed; cleanest. Collision protection is handled by `collision_policy` below, not by this field. |
| `collision_policy` (plugin) | `first_wins` (recommended for most deployments) | Plugin Settings UI | Protects existing registrations; static reservations win naturally since reservation-sync runs first. Use `allow` only if you want Unbound to round-robin multiple IPs for a name. |
| `ddns-replace-client-name` | `never` (default) | manual config only | Defer until bulk-path divergence is addressed. |
| `ddns-generated-prefix` | (not yet) | manual config only | Defer until bulk-path gap is addressed. |

**`cache-threshold` caveat (Kea 3.0 default 0.25):** Renewals within
`0.25 × valid-lifetime` are "reused" with no DDNS. With 4000s lease that's ~17 min.
Typical T1 renewals at 50% of lifetime are outside it and fire normally.

---

## Methodology notes (operational lessons learned)

**`drill -x` is unreliable.** Unbound's RFC6303 `static` reverse zones for private
space cause false NXDOMAIN. Use `drill @127.0.0.1 <reversed-name> PTR` or
`unbound-control -c /var/unbound/unbound.conf list_local_data`.

**Lease caching verification:** confirm a renewal is genuine via Kea log —
`DHCP4_LEASE_ALLOC` without following `DHCP4_LEASE_REUSE` = genuine. For tests,
shorten `valid-lifetime` to shrink the reuse window.

**Two-step D2 apply:** `configctl kea restart` regenerates PHP-model confs but NOT the
`.tpl` `keactrl.conf`/`rc.conf.d` that gate which daemons start. To enable D2 the
first time: `configctl template reload OPNsense/Kea` then `configctl kea restart`.
Per-test flag toggles only: `configctl kea restart` suffices.

**Boolean semantics:** OPNsense model uses `!isEmpty()` → OFF = empty tag `<x/>`,
ON = `<x>1</x>`.

**`configctl kea restart` triggers lease-sync.** Plugin's kea_sync hook re-registers
active leases. Use unique (MAC, IP, name) tuples per test and clean up leases before
restart to avoid cross-test contamination.

---

## Deferred test round: listener-level behavior

- **`ddns-conflict-resolution-mode`**: ✅ completed Phase 5 — all 4 modes confirmed.
- **`collision_policy` (plugin setting)**: ✅ completed Phase 6 — `allow`, `first_wins` (with and without prereqs), and `last_wins` all confirmed. PTR consistency fix included.
- **`ddns-generated-prefix` + `ddns-replace-client-name`**: validate bulk-path
  divergence; decide whether to scope bulk sync as "standard config only" (document) or
  fix (don't, per architecture decision above).
- **TSIG end-to-end**: see `int-docs/kea-tsig-testing.md`.
- **`hostname-char-set` / `hostname-char-replacement`**: raw vs scrubbed divergence;
  `is_sane_name()` asymmetry.
- **Hostname-less reservation**: correct skip, no crash.
- **`ddns-qualifying-suffix` dotted-name edge case**: client sends dotted name not under
  suffix; verify Kea and plugin agree.
- **Shared-network suffix inheritance**: exercise with real config data.
- **Missing reverse zone with DDNS enabled**: confirm PTRs still appear via listener
  synthesis; verify audit `ptr_state` handles it correctly.
- **`ncr-protocol` check**: ✅ behavior confirmed Phase 5 (D2 hard-fail on TCP). Config Check tab warning is a future nice-to-have.
- **Malformed / oversized / unauthenticated RFC 2136 packets** to the listener.
- **Client-name → `unbound-control` injection / sanitization** (partial mitigation:
  listener uses dnspython; `is_sane_name()` applied).
