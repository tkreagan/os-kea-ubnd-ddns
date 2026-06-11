# Kea Options — Plugin Support Reference

> Documents which Kea DHCP/DDNS configuration options are fully supported, partially
> supported, or unsupported by the os-kea-unbound plugin. "Supported" means both the
> live path (kea-unbound-ddns.py) AND the bulk path (kea-sync.py /
> local-data-audit / local-data-clean) handle the option correctly and consistently.
>
> See `kea-ddns-options-reference.md` for the full analysis behind each entry.

---

## Architectural scope limitation (locked decision)

The bulk sync path (`kea-sync.py`) is explicitly scoped to
**OPNsense standard configuration** — i.e., options that are settable via the OPNsense
GUI / config.xml. It does not attempt to replicate Kea's internal name-crafting logic
(charset scrubbing, generated-prefix construction, replace-client-name modes).

The live path (`kea-unbound-ddns.py`) always gets name-shaping options correct for
free — it receives whatever FQDN Kea computed in the NCR packet and registers it
verbatim. The bulk path is used only for repopulation after Unbound restarts.

If a non-standard option is enabled via manual Kea configuration, the live path
continues to work correctly. The bulk path may produce wrong or missing names, causing
audit mismatches that resolve on the next live NCR. This is documented behavior, not
a bug to fix. The Config Check tab detects and warns on unsupported options.

---

## Option support matrix

### DDNS name-shaping options

> **Key finding (2026-06-08 Phase 3/4 tests):** The original assumption "bulk uses raw
> hostname" was wrong for most cases. Kea stores the processed FQDN (scrubbed, qualified,
> or generated) in the lease, so the bulk path reads it correctly. The one true divergence
> case is **single-label name sent via option 81 that Kea does not replace** — Kea stores
> `label.` in the lease; `qualify_hostname` strips the trailing dot, sees no dots, qualifies
> to `label.suffix` creating a ghost record the live path never registered. This is an edge
> case: real-world clients that use option 81 typically send a proper FQDN, not a bare label.
> See "Single-label opt81 divergence" section below.

| Kea option | OPNsense GUI? | Live path | Bulk path | Config Check | Status |
|---|---|---|---|---|---|
| `ddns-qualifying-suffix` | Yes | ✅ Full | ✅ Full (waterfall modeled) | n/a | **Supported** |
| `ddns-replace-client-name: never` | No (default) | ✅ Full | ✅ Full | n/a | **Supported (default only)** |
| `ddns-replace-client-name: always` | No | ✅ Full | ✅ Full (lease stores generated FQDN) | ⚠ Warning | **Supported (manual config only)** |
| `ddns-replace-client-name: when-present` | No | ✅ Full | ✅ Full (lease stores generated FQDN) | ⚠ Warning | **Supported (manual config only)** |
| `ddns-replace-client-name: when-not-present` | No | ✅ Full | ✅ Full (lease stores generated FQDN) | ⚠ Warning | **Supported (manual config only)** |
| `ddns-generated-prefix` | No | ✅ Full | ✅ Full (lease stores prefixed FQDN) | ⚠ Warning (if replace-mode active) | **Supported (manual config only)** |
| `hostname-char-set` | No | ✅ Full (Kea scrubs before NCR) | ✅ Full for opt12 + opt81 FQDN (lease stores scrubbed name); ⚠ ghost record for single-label opt81 | ⚠ Warning | **Supported (common cases); single-label opt81 edge case** |
| `hostname-char-replacement` | No | ✅ Full | same as hostname-char-set above | ⚠ Warning | **Supported (common cases)** |

### Single-label opt81 divergence (all name-shaping modes)

When a client sends a **single-label name via option 81** (e.g. `mypc` not `mypc.example.com`)
AND Kea does not replace it (mode is `never` or `when-not-present` with a name present):

- Kea does NOT append the qualifying suffix to option 81 names (treats them as absolute FQDNs)
- The resulting `label.` FQDN is not under any configured D2 forward zone → D2 logs
  `DHCP_DDNS_NO_MATCH` and drops the NCR
- Lease stores `label.` (single label + trailing dot)
- **Bulk path**: `qualify_hostname` strips the trailing dot, sees no dot → qualifies to
  `label.suffix` → **registers a ghost record** the live path never created

**Real-world impact is low**: most clients that use option 81 send a proper FQDN (they know
their domain). Clients using option 12 are unaffected — Kea qualifies those correctly and
stores the full FQDN in the lease. The divergence is cleaned up by the scheduled
`local-data-clean.py` run.

**Config Check advisory (planned)**: no current advisory covers this because it is a
client-side behavior issue, not a config option. Could be detected if any lease hostname
field in `lease4-get-all` matches the pattern `^[^.]+\.$` (single label with dot), but
that is per-lease runtime detection, not config-time detection.

### DDNS update-triggering options

| Kea option | OPNsense GUI? | Live path | Bulk path | Config Check | Status |
|---|---|---|---|---|---|
| `ddns-send-updates` | Yes (derived) | ✅ Full | ✅ Full | n/a | **Supported** |
| `ddns-override-no-update` | Yes | ✅ Full | ✅ Full | ⚠ Advisory (ONU⇒OCU rule) | **Supported** |
| `ddns-override-client-update` | Yes | ✅ Full | ✅ Full | n/a | **Supported** |
| `ddns-update-on-renew` | Yes | ✅ Full | n/a | n/a | **Supported** |

### Conflict resolution

| Kea option | OPNsense GUI? | Live path | Bulk path | Config Check | Status |
|---|---|---|---|---|---|
| `ddns-conflict-resolution-mode: no-check-without-dhcid` | Yes | ✅ Full | n/a | n/a | **Supported (recommended)** |
| `ddns-conflict-resolution-mode: no-check-with-dhcid` | Yes | ✅ Full (DHCID skipped) | n/a | n/a | **Supported** |
| `ddns-conflict-resolution-mode: check-with-dhcid` | Yes | ⚠ Prereqs ignored | n/a | ⚠ Advisory | **Partial (default; prereqs not enforced)** |
| `ddns-conflict-resolution-mode: check-exists-with-dhcid` | Yes | ⚠ Prereqs ignored | n/a | ⚠ Advisory | **Partial (prereqs not enforced)** |

### TTL options

| Kea option | OPNsense GUI? | Live path | Bulk path | Config Check | Status |
|---|---|---|---|---|---|
| `valid-lifetime` | Yes | ✅ Full (TTL via NCR) | ✅ Approx (expire - now) | n/a | **Supported (bulk path approximate)** |
| `ddns-ttl-percent` | No | ✅ Full (TTL via NCR) | ❌ Not applied | n/a | **Live only** |
| `ddns-ttl` / `ddns-ttl-min` / `ddns-ttl-max` | No | ✅ Full (TTL via NCR) | ❌ Not applied | n/a | **Live only** |

### Reservation structure

| Kea option | OPNsense GUI? | Live path | Bulk path | Config Check | Status |
|---|---|---|---|---|---|
| Per-subnet reservations (hostname + ip-address) | Yes | ✅ Full | ✅ Full | n/a | **Supported** |
| Per-subnet reservations (no hostname) | Yes | ✅ Full (no NCR sent) | ✅ Skipped correctly | n/a | **Supported** |
| DHCPv6 multiple ip-addresses per reservation | Yes | ✅ Full | ⚠ First address only | n/a | **Partial** |
| Global reservations | No | ✅ Full | ✅ Read (manual config only) | n/a | **Supported (manual config only)** |
| Shared-network reservations | No | ✅ Full | ✅ Read (untested) | n/a | **Untested** |

---

## Config Check advisory rules

Implemented checks are in `KcaconfigController::ddnsAdvisories()` (per-subnet) or
`d2Advisories()` (global D2 config). Planned checks are noted below.

| Condition | Level | Message | Status |
|---|---|---|---|
| `ONU=1, OCU=0` on same subnet | Warning | Override-no-update without override-client-update is incoherent — enable override-client-update | ✅ Implemented |
| OCU or ONU or UOR not set | Info | Recommend enabling … | ✅ Implemented |
| `ddns-qualifying-suffix` ends with `.` | Warning | Trailing dot breaks Kea's name qualification — single-label hostnames get no DNS record | ✅ Implemented |
| subnet `option-data domain-name` ≠ `ddns-qualifying-suffix` | Info | option 15 differs from qualifying suffix — clients using option 81 constructed from option 15 will send names D2 cannot route and will not get DNS records. Fix: align option 15 with the qualifying suffix; add option 119 if a broader search domain is also needed. | ✅ Implemented |
| `ddns-conflict-resolution-mode` = `check-with-dhcid` or `check-exists-with-dhcid` | Info | Prerequisites are not enforced by this plugin's listener — use no-check-without-dhcid for this deployment | ⏳ Planned (deferred) |
| `ddns_reverse_zone` empty with DDNS enabled | Info | No reverse zone configured — PTR records will be synthesized by the plugin but not managed by Kea's DDNS agent | ⏳ Planned — see `ptr-handling-notes.md` TODO section |
| `ddns_reverse_zone` not matching `in-addr.arpa` / `ip6.arpa` | Warning | Custom reverse zone — synthesized PTR records at in-addr.arpa may persist as stale after lease expiry | ⏳ Planned — see `ptr-handling-notes.md` TODO section |
| `ncr-protocol` ≠ `UDP` in D2 config | Warning | D2 NCR protocol is not UDP — plugin listener will not receive updates | ⏳ Planned — see TODO below |

### TODO — ncr-protocol check

Read `DhcpDdns.ncr-protocol` from `kea-dhcp-ddns.conf` in a new `d2Advisories()` method
in `KcaconfigController.php`. The default is `UDP`; any other value means the listener
will never receive NCR packets.

```
if (strtoupper($d2['ncr-protocol'] ?? 'UDP') !== 'UDP') {
    Warning: "DHCP-DDNS ncr-protocol is \"{value}\" — plugin listener only supports UDP.
              DNS updates will not be received."
}
```

Wire `d2_advisories` into the `checkAction()` result and surface it in `kcaconfig.volt`.

---

## Qualifying-suffix edge cases — Phase 1 results (2026-06-08)

Phase 1 observational tests complete. Rig: dev-opnsense (suffix `dev.plhm.rgn.cm`,
forward zone `dev.plhm.rgn.cm.`), option 81 (Client FQDN) unless noted.
`qualify_hostname()` = bulk sync helper in `keaunbound_sync.py`.

| Case | Kea behavior | D2 behavior | Plugin (live) | Plugin (bulk) | Decision |
|---|---|---|---|---|---|
| Client sends dotted name not under suffix (`foo.bar`) | Allocates lease; echoes `foo.bar.` in ACK opt81; sends NCR with `FQDN: [foo.bar.]` | `DHCP_DDNS_NO_MATCH` — discards NCR | No record registered | `qualify_hostname` returns `foo.bar` as-is (has dot) → bulk also skips (no suffix appended; D2 never stored it) | **No action needed.** Kea echoes the name but D2 drops it. No DNS record. Bulk path matches: returns name unchanged but lease has no backing DNS record. Document as expected. |
| Client sends name already under suffix (`foo.dev.plhm.rgn.cm`) | Allocates lease; echoes `foo.dev.plhm.rgn.cm.` in ACK opt81; sends NCR | D2 matches zone → registers `foo.dev.plhm.rgn.cm. A .102` + PTR | ✅ Registers A + PTR correctly | `qualify_hostname("foo.dev.plhm.rgn.cm", "dev.plhm.rgn.cm")` → `foo.dev.plhm.rgn.cm` (has dot, returned as-is) ✅ matches | **No action needed.** Kea does not double-qualify. `qualify_hostname` matches. |
| Client sends name one level above suffix (`foo.plhm.rgn.cm`) | Allocates lease; echoes `foo.plhm.rgn.cm.` in ACK; sends NCR | `DHCP_DDNS_NO_MATCH` — discards NCR | No record registered | `qualify_hostname("foo.plhm.rgn.cm", ...)` → returns as-is (has dot) → no DNS record in bulk either | **No action needed.** Consistent no-record on both paths. Document as expected. |
| Client sends name with trailing dot via opt 12 (`foo.`) | Allocates lease; treats it as absolute FQDN `foo.`; sends NCR with `FQDN: [foo.]` | `DHCP_DDNS_NO_MATCH` — discards NCR | No record registered | `qualify_hostname` strips trailing dot: gets `foo`, has no dot → qualifies to `foo.dev.plhm.rgn.cm` — **diverges from live** | **Config Check advisory:** hostname with trailing dot via opt 12 bypasses suffix qualification (Kea treats as absolute). Rare real-world case; bulk path would diverge if it ever sees such a lease hostname. No code fix needed. |
| Client sends name matching suffix exactly (`dev.plhm.rgn.cm`) | Allocates lease; echoes `dev.plhm.rgn.cm.` in ACK; sends NCR | D2 matches forward zone → registers `dev.plhm.rgn.cm. A .105` + PTR | ✅ Registers A + PTR (zone apex A record) | `qualify_hostname("dev.plhm.rgn.cm", ...)` → returns as-is (has dot) ✅ | **No action needed.** Kea registers an A record at the zone apex — unusual but harmless. Both paths consistent. |
| Qualifying suffix configured with trailing dot (`dev.plhm.rgn.cm.`) | Kea config reloads fine. Allocates lease. Echoes single label `qs6host.` in ACK — **does not qualify** | `DHCP_DDNS_NO_MATCH` for `qs6host.` — discards | No record registered | `qualify_hostname` strips trailing dot from suffix → would qualify correctly, **diverging from live (which has no record)** | **Config Check warning:** trailing dot on `ddns-qualifying-suffix` breaks Kea's name qualification — no DNS records registered for single-label hostnames. `qualify_hostname` strips trailing dot and would produce records that the live path never creates. **Add detection in Config Check.** |

### Findings summary

1. **`qualify_hostname` dotted-name bypass is correct.** Kea itself passes dotted names
   through unchanged. When D2 drops them (not under the zone), bulk is also
   consistent (no backing record). No divergence.

2. **`qualify_hostname` already handles trailing-dot suffix correctly** via `.strip(".")`.
   If the OPNsense model strips the trailing dot before writing the config (which it
   should — verify), users can't trigger this from the GUI. The trailing dot is a
   manual-config-only footgun.

3. **Trailing dot on the suffix is a live-path killer.** Add a Config Check warning:
   if `ddns-qualifying-suffix` ends with `.`, emit a warning that qualification is
   broken and all single-label hostnames will be unregistered.

4. **Zone-apex name (`dev.plhm.rgn.cm` as FQDN) works fine.** Unusual but both paths
   handle it consistently.

---

## option_data_autocollect — what it sets and why option 15 matters

The OPNsense Kea subnet form has an **Auto-collect option data** toggle
(`option_data_autocollect`). When enabled, it fills in common DHCP options
automatically from the running system rather than requiring manual entry.

### What autocollect sets at save time

`KeaDhcpv4::setNodes()` runs when the subnet is saved and `option_data_autocollect`
is enabled. It looks up the OPNsense interface IP that falls within the subnet CIDR
and writes these three options directly into the config model:

| DHCP option | Field | Source |
|---|---|---|
| Option 3 — Router | `routers` | First interface IP inside the subnet CIDR |
| Option 6 — DNS Servers | `domain_name_servers` | Same interface IP (Unbound) |
| Option 42 — NTP Servers | `ntp_servers` | Same interface IP (ntpd) |

These are written at save time and stored in `config.xml`. They are not re-derived
at config-generation time — if you later change the interface IP, you need to
re-save the subnet to update them.

### What autocollect sets at config-generation time

`collectOptionData()` runs when generating `kea-dhcp4.conf`. For each option_data
field, if the value is non-empty it is written as-is. There is one special case:

| DHCP option | Field | Condition | Source |
|---|---|---|---|
| Option 15 — Domain Name | `domain_name` | Empty **and** called with `defaults=true` (subnet-level only) | `<system><domain>` from `config.xml` |

This is the autocollect fallback for option 15. Subnet-level option-data is always
collected with `defaults=true`; reservation-level option-data is not. So:

- If the subnet's `Domain Name` field is empty, option 15 = **system domain**
  (`System → General → Domain`)
- If the subnet's `Domain Name` field has a value, that value is used instead

### The full list of option_data fields

These are all the fields available in the subnet `option_data` block. Fields not
listed here (raw custom options) go through the separate `option` relation.

| Field | DHCP option | Notes |
|---|---|---|
| `domain_name_servers` | Option 6 | Set by autocollect; can be overridden |
| `domain_search` | Option 119 | Domain Search List — NOT set by autocollect |
| `routers` | Option 3 | Set by autocollect |
| `static_routes` | Option 33 | Comma-separated; not set by autocollect |
| `classless_static_route` | Option 121 | Not set by autocollect |
| `domain_name` | Option 15 | Empty → falls back to system domain at gen time |
| `ntp_servers` | Option 42 | Set by autocollect |
| `time_servers` | Option 37 | Not set by autocollect |
| `tftp_server_name` | Option 66 | Not set by autocollect |
| `boot_file_name` | Option 67 | Not set by autocollect |
| `v6_only_preferred` | Option 108 | Not set by autocollect |
| `v4_dnr` | Option 162 | Not set by autocollect |

### Implication for the option 15 / DDNS advisory

On most standard OPNsense installs the system domain and the DDNS qualifying suffix
are the same. The advisory fires when they differ — the most common real-world case
being a dev or staging environment where:

- System domain = `example.com` (the organisation-wide domain)
- DDNS qualifying suffix = `dev.example.com` (a sub-zone for the test environment)

The fix is to explicitly set the `Domain Name` field on the subnet to match the
qualifying suffix (`dev.example.com`). The system domain is left alone — it
controls the OPNsense hostname, not DHCP option 15. If clients also need to search
the parent domain, add `domain_search` = `dev.example.com, example.com` (option 119).

**Note:** option 119 (`domain_search`) is intentionally NOT set by autocollect —
it is left empty so that clients receive a single search domain from option 15.
If you populate `domain_search`, most clients will use that list in preference to
option 15, which is the correct behavior for the split search domain + DHCP zone
topology described in the next section.

---

## Option 15, option 81, and the split search domain pattern

### The protocol sequence

When a client requests a DHCP lease, name registration flows through three parties:

1. **Client** — sends its hostname in one or both of:
   - Option 12 (Hostname): a bare label, e.g. `mypc`
   - Option 81 (Client FQDN): a dotted FQDN the client constructed, e.g. `mypc.corp.com`

2. **Kea** — decides what FQDN to register. By default (`ddns-replace-client-name: never`):
   - If option 81 is present: use its FQDN verbatim (does NOT append `ddns-qualifying-suffix`)
   - If only option 12 is present: append `ddns-qualifying-suffix` to get the FQDN

3. **D2** — routes the NCR to a forward zone by prefix-matching the FQDN against configured
   `ddns-domains`. If no zone matches: `DHCP_DDNS_NO_MATCH` — the update is silently dropped.

**Option 15** (Domain Name) is separate from registration: it tells the client what DNS search
domain to append when resolving short names (ends up as `search` / `domain` in `/etc/resolv.conf`).
Crucially, clients typically **construct their option 81 FQDN by combining their hostname with
option 15**. So the value of option 15 directly determines what name they send in option 81.

### Why option 15 ≠ qualifying-suffix breaks DDNS

A common topology:

```
option 15  (search domain)      = corp.com
ddns-qualifying-suffix          = dhcp.corp.com
D2 forward zone                 = dhcp.corp.com.
```

The intent is clean — users resolve short names against the whole `corp.com` zone, while
dynamically-assigned hosts are isolated under `dhcp.corp.com`. But the protocol does not
support this split cleanly:

1. Client `mypc` sees option 15 = `corp.com`, constructs option 81 = `mypc.corp.com`
2. Kea receives option 81 = `mypc.corp.com`, stores it in the lease, sends NCR with that FQDN
3. D2 forward zone is `dhcp.corp.com` → `DHCP_DDNS_NO_MATCH` → NCR dropped
4. **No DNS record registered, on either the live path or the bulk path**

There is no Kea option that says "strip the option-15 suffix from an option-81 name and
requalify with the DDNS suffix." Kea can only use the option-81 name verbatim, or replace
it entirely with a generated `prefix-IP.suffix` name (losing the client's hostname).
A plugin-level workaround would require parsing both the DHCP conf and the D2 conf at
runtime to detect and rewrite NCR FQDNs — fragile, non-standard, and not implemented.

**Clients using only option 12 are unaffected** — Kea qualifies bare hostnames with
`ddns-qualifying-suffix` before sending to D2, so they go to the right zone regardless
of option 15.

### The correct designs for this plugin

**Simple case — single search domain:**

Set option 15 = `ddns-qualifying-suffix`. Clients search under the DHCP zone, short
names resolve correctly, option 81 FQDNs land in the right D2 zone.

```
option 15                   = dhcp.corp.com
ddns-qualifying-suffix      = dhcp.corp.com
D2 forward zone             = dhcp.corp.com.
```

**Common case — separate search domain + DHCP zone:**

Set option 15 = `ddns-qualifying-suffix` AND send option 119 (Domain Search List) with
both domains. Option 119 gives clients a multi-domain search list; option 15 (which most
stacks still read as the primary domain) stays aligned with the DDNS zone.

```
option 15   (domain-name)      = dhcp.corp.com
option 119  (domain-search)    = dhcp.corp.com, corp.com
ddns-qualifying-suffix         = dhcp.corp.com
D2 forward zone                = dhcp.corp.com.
```

Clients resolve `mypc` → tries `mypc.dhcp.corp.com` (found), also searches `mypc.corp.com`
for anything in the parent zone. DHCP registration works because option 81 = `mypc.dhcp.corp.com`.

**Complex case — DHCP zone under a parent zone, clients must search only the parent:**

If clients must have option 15 = `corp.com` (not `dhcp.corp.com`) and option 81 must still
land in `dhcp.corp.com`, there is no clean solution within Kea + this plugin. Options:

- Use a full-featured authoritative DNS server (BIND, Knot) alongside Unbound, with D2
  writing to an authoritative zone and Unbound forwarding to it. D2 can then handle the
  zone routing independently of what the resolver serves.
- Accept that DHCP clients will not have live-path DNS registration and rely on the
  bulk path + scheduled sync (which also does not help here, since bulk has the same
  constraint as live: it only registers names that Kea stored in the lease, which are the
  wrong-zone FQDNs D2 already dropped).

### Config Check behavior

The Config Check tab emits an Info advisory whenever `option-data domain-name` (option 15)
differs from `ddns-qualifying-suffix` on a subnet. The advisory message names the specific
values and recommends aligning option 15 with the qualifying suffix, with option 119 as the
escape hatch for multi-domain search lists.

This advisory fires even when the mismatch is intentional (e.g. a dev environment using a
sub-zone for testing). It is Info-level, not Warning — no action is required unless clients
are expected to use option 81 and are not getting DNS records.

---

## What "unsupported" means for operators

If you are using OPNsense's standard Kea GUI (not manual configuration mode), none of
the unsupported options are reachable — the GUI does not expose them. You are not
affected by any of these limitations.

If you have enabled manual configuration mode for kea-dhcp4 or kea-dhcp6 and are
setting `ddns-replace-client-name`, `hostname-char-set`, or `ddns-generated-prefix`:

- DNS records will be registered correctly in real-time via the live path
- After an Unbound restart, the bulk re-sync may produce wrong or missing names
- Records will self-correct on the next genuine lease renewal (sooner with `ddns-update-on-renew: true`)
- The Kea Config Check tab will display a warning for the affected subnets
- Running `configctl keaunbound sync_dynamic` manually after an Unbound restart will
  re-sync active leases (with the same bulk-path limitation, but reduces the stale window)
