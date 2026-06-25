# Magic Collision Policy — Design Document

Internal design reference for the `magic` hostname feature and the revised
collision policy system. Captures all decisions made during design; serves
as the basis for implementation and later user-facing documentation.

---

## Overview

### Collision policy (revised — four options)

`collision_policy` governs what happens to the **bare hostname A/AAAA
record** when multiple entries claim the same hostname. Four options:

| Policy | Behaviour |
|--------|-----------|
| `first_wins` | First active dynamic lease to register keeps the hostname. Static leases always beat dynamic. |
| `last_wins` | Latest active dynamic lease holds the hostname. Static leases always beat dynamic. |
| `allow` | All entries registered; multiple A records for the same hostname (round-robin). |
| `none` | On any dynamic conflict, no dynamic lease gets the bare hostname; existing dynamic records are deleted. Hostname becomes available again when all competing leases expire. |

### Magic hostnames (separate boolean toggle)

`magic_names` is a boolean toggle **orthogonal to** `collision_policy`. When
on, every entry involved in a hostname collision receives an additional
disambiguated forward record — a *magic hostname* — derived from its
hardware identifier or IP. The magic hostname is a parallel entry; it does
not replace the bare hostname entry whose winner is still determined by
`collision_policy`.

Magic applies to **all tiers**: host overrides, static reservations, and
dynamic leases all receive magic names when involved in a collision. The
bare hostname A records of host overrides and static reservations are never
modified — magic adds parallel entries only.

---

## Definitions

### Static leases (in decreasing precedence)
- Host overrides (OPNsense Unbound UI / `host_entries.conf`)
- Static reservations with IP when `sync_static_reservations` is **on**

### Dynamic leases (in decreasing precedence)
- Static reservations with IP when `sync_static_reservations` is **off**
- Static reservations without IP
- Dynamic leases (Kea lease file)

Static leases are inviolate for `collision_policy` purposes: no dynamic
lease can ever displace a static lease's bare hostname record. Static-vs-static
collisions always coexist (round-robin / allow_multi_ip) regardless of
`collision_policy`.

---

## A/AAAA Record Rules by Policy

`collision_policy` only governs dynamic lease collisions. Static leases are
always written; dynamic lease behaviour varies by policy.

| Policy | Dynamic lease behaviour | Static lease behaviour |
|--------|------------------------|----------------------|
| `first_wins` | First active dynamic lease registered holds the hostname, but no dynamic lease can displace a static lease. If the winner expires, hostname is available for the next active dynamic lease, but previous dynamic leases are not automaticallypromoted. | Always written; coexist via round-robin if multiple statics share a hostname. |
| `last_wins` | Latest active dynamic lease holds the hostname, but no dynamic lease can displace a static lease. Superseded leases are removed. If the winner expires, previous losers are not automatically promoted; the next renewal or registration wins.  | Same as above. |
| `allow` | All active dynamic leases are registered. Expired leases become stale and eligible for deletion. | Same as above. |
| `none` | If a new dynamic lease conflicts with an existing static lease or active dynamic lease, it is skipped and any active dynamic lease records for that hostname are deleted. Once all competing dynamic leases expire, the hostname is available again, but previous dynamic leases are not automatically promoted. A surviving lease can re-register at the next sync or renewal. | Static lease records can never be deleted. |

---

## Design Decisions

### D1 — Suffix source: always from the END of the identifier

All DHCP client identifiers are more unique at the end than the beginning:

- **hw-address (MAC)**: first 3 octets are the OUI (manufacturer-assigned).
  Last 3 octets are NIC-specific. Take from the **end**.
- **duid**: DUID-LLT format begins with type + hardware type + timestamp,
  then the MAC. Take from the **end**.
- **circuit-id**: relay agent opaque blob; structured formats encode
  port/unit specificity at the end. Take from the **end**.
- **client-id**: typically `01` (type byte) followed by MAC. First 2 chars
  are always `01`. Take from the **end**.
- **IP (host overrides / static entries without DHCP identifier)**: use last
  two octets of the IP address, each zero-padded to 3 decimal digits,
  concatenated without separator. Take from the **end** of the address.

The rule is uniform: strip separators, take the last 6 chars of the
identifier payload.

### D2 — Suffix length: always 6, not configurable

6 chars (hex or decimal digits) per identifier type. 

### D3 — Identifier type tags

Each magic suffix is prefixed with a single-character type tag, fused
directly to the payload with no separator. All hex characters are capitalized. The hyphen appears only between
the hostname and the type+payload block, and between the block and the
optional counter.

| Identifier | Tag | Payload | Example suffix |
|------------|-----|---------|----------------|
| `hw-address` (MAC) | `m` | last 6 hex chars | `maabbcc` |
| `duid` | `d` | last 6 hex chars | `daabbcc` |
| `client-id` | `c` | last 6 hex chars | `caabbcc` |
| `circuit-id` | `r` | last 6 hex chars | `raabbcc` |
| IP address | `i` | last 2 octets, 3-padded each, concatenated | `i001050` |

`r` for circuit-id: circuit IDs appear almost exclusively when traffic
arrives via a relay agent; `r` encodes the relay
context and avoids a potential collision with `client-id`.

Identifier priority when multiple fields present (Kea's own default order):
`hw-address` → `duid` → `circuit-id` → `client-id`. IP fallback used
only when no DHCP identifier is available (host overrides, static
reservations without hardware binding).

### D4 — LAA (Locally Administered Address) tagging

Optional flag. When on, magic names for devices whose MAC has the locally
administered bit set (`mac_bytes[0] & 0x02`) include an `-laa-` infix
between the hostname and the type+payload block.

- Term: **LAA** (Locally Administered Address), per IEEE and RFCs 9724 /
  9797. Chosen over `rcm`, `r`, `p` after reviewing RFC terminology.
- Default: **off**.
- Signals to the administrator that the suffix may not be stable across
  reconnections (iOS, Android, Windows randomize MACs per network/day).
- Explainer text in the UI settings will describe what LAA means.

### D5 — Meta-collision handling

A meta-collision occurs when two different devices produce the same 6-char
payload (identical last 3 octets / last 2 IP octets). Taking more chars
from the end does not help — those chars are likely already identical.

**Resolution**: keep the 6-char payload as the stable base, append a
numeric counter: `{hostname}-{type+payload}-{n}`.

Counter assignment: sort all full identifiers in the collision group
lexicographically; assign 1-indexed positions. Deterministic from data
alone — no state file needed for counter assignment.

Log a warning with full identifiers on any meta-collision.

### D6 — Suffix format table

| Case | Format | Example |
|------|--------|---------|
| Normal MAC collision | `{host}-m{6hex}` | `laptop-maabbcc` |
| LAA MAC | `{host}-laa-m{6hex}` | `laptop-laa-maabbcc` |
| DUID | `{host}-d{6hex}` | `laptop-daabbcc` |
| client-id | `{host}-c{6hex}` | `laptop-caabbcc` |
| circuit-id | `{host}-r{6hex}` | `laptop-raabbcc` |
| IP (override / no DHCP id) | `{host}-i{oct3}{oct4}` | `laptop-i001050` |
| Meta-collision | `{host}-{type+payload}-{n}` | `laptop-maabbcc-1` |
| LAA meta-collision | `{host}-laa-m{6hex}-{n}` | `laptop-laa-maabbcc-1` |

All hex characaters are capitalized.  Octets in the IP suffix are zero-padded to 3 decimal digits and
concatenated without a separator (`001050` not `001-050`).

### D7 — Bare hostname record: winner determined by collision policy

The bare `{hostname}` A record is always kept (except under none; see below). Its winner is determined
entirely by `collision_policy` — magic is orthogonal to this. DNS does not
define a canonical hostname; there is no RFC that requires suppressing the
bare record in a collision scenario. Administrators who have not taken steps
to assign explicit hostnames have implicitly accepted this behaviour.

Under `none`, if a dynamic conflict exists, no dynamic lease holds the bare
hostname (it is deleted). Once the conflict resolves, the bare hostname
becomes available again.

### D8 — Hostname-only reservations (no IP) are not a concern

A Kea reservation with a hostname but no `ip-address` field is silently
skipped by the sync (`if hostname and ip:`). It produces no DNS entry and
cannot participate in a collision. Any entry that reaches magic name
computation has an IP — by definition.

The IP-based suffix (`i` type tag) is used only for entries that have an
IP but no DHCP hardware identifier (host overrides, certain static
reservations). This is distinct from hostname-only reservations.

### D9 — All tiers receive magic names; bare records remain inviolate

Magic applies to all colliding entries, including host overrides and static
reservations. A magic hostname is a *parallel forward record* added by the
sync — it does not modify or remove the original entry.

**Host overrides**: the override's A record in `host_entries.conf` is never
touched. The sync writes an additional `local_data` entry for the magic
FQDN. The admin may intentionally configure multiple overrides for the same
hostname (round-robin); all are respected and all receive magic names.

**Static reservations with IP**: the reservation's A record is written
as-is (existing behaviour). An additional magic FQDN entry is written
alongside it.

**Dynamic leases**: magic FQDN written alongside whatever the collision
policy determines for the bare hostname.

Static-vs-static collisions (two static entries sharing a hostname) continue
to use `allow_multi_ip=True` behaviour for the bare hostname. If magic is
on, both also receive magic names.

Note: the `write_ptrs` settings label currently reads "Synthesize PTR
records from DDNS updates" — should be shortened to "Synthesize PTR
records". Tracked in Implementation Plan.

### D10 — PTR behaviour when write_ptrs is on

PTR conflicts among active leases cannot occur in normal operation: DHCP
guarantees each active lease has a unique IP. The rules are simple.

**If write_ptrs is off**: nothing written.

**If write_ptrs is on (magic off)**:

1. If `sync_static_reservations` is on: pre-write PTRs for all static
   reservations with IP addresses, before dynamic lease processing.
2. Write PTRs for active dynamic leases as processed.
3. Do not clobber explicit PTRs in host-entries (OPNsense PTR checkbox),
   or PTRs pre-written in step 1.
4. Host override A records without an explicit PTR: **no PTR synthesized**.
   Not ticking the PTR checkbox is explicit intent. Common case: virtual-host
   overrides where many names point to one IP — synthesizing a PTR would be
   arbitrary.

**If write_ptrs is on (magic on)**:

- **Static leases** (host-override defined PTRs + static res with IP when
  `sync_static_reservations` is on): PTR continues to point to the
  **original hostname**. Static entries retain their A records even under
  collision (round-robin), so the original hostname PTR remains valid.
- **Dynamic leases**: PTR is **rewritten to the magic FQDN**. The bare
  hostname is ambiguous (may resolve to a different IP depending on collision
  policy); the magic FQDN is the stable, unambiguous name for that IP.
- Explicit PTRs in host-entries remain inviolate regardless of magic mode.

### D11 — Magic name lifecycle

Magic names are **not** removed eagerly when a collision resolves. Removing
a magic name the moment the collision resolves would vaporise a DNS name
that an SSH session, monitoring system, or cached reference may be actively
using.

**Removal paths**:

1. **Lease expires naturally**: stale-clean detects no backing lease →
   removes the magic record in the normal stale-clean pass. This is the
   common path for dynamic lease magic names.

2. **Departed devices (collision partially resolves)**: when the collision
   goes from N → (N-1) active entries, the departed entries have no active
   leases. Their magic names are removed at the next sync via state file
   diff. The surviving entries' magic names are left alone.

3. **Host override / static reservation magic names**: these entries never
   expire. Their magic names can only be removed via path 2 (state file diff
   detects the collision has fully resolved).

**Surviving device magic name**: when a collision fully resolves to one
remaining entry, that entry's magic name is left in place. It will be
cleaned up by stale-clean when its lease eventually expires (dynamic), or
retained until a future collision brings it back (static). People may be
using the magic name via cached references; do not vaporise it.

**PTR cleanup during magic A-record removal**: no special handling needed.
When a collision resolves and kea-sync runs, it immediately rewrites the
surviving dynamic lease's PTR to point to the bare hostname (collision is
gone, so normal PTR rules apply again). The magic A record is still present
at that point (non-eager), but the PTR has already moved on. When stale-clean
eventually removes the magic A record, there is no associated PTR to clean —
the cleanup step only issues `local_data_remove` for the magic FQDN A/AAAA
records.

### D12 — State file

**Purpose**: track which magic FQDNs the sync created, so that:
- Departed devices' magic names can be removed safely (without
  pattern-matching Unbound's local_data, which risks false positives
  against legitimate records that happen to look like magic names).
- The sync can distinguish its own magic records from any user-created
  records with similar names.

**Location**: `/var/run/keaubnd/magic-state.json`

Ephemeral (`/var/run/`) is intentional. On reboot, Unbound's `local_data`
is also cleared. Both reset together; the sync rebuilds from scratch.

**Contents**:

```json
{
  "version": 1,
  "ts": "2026-06-17T10:00:00Z",
  "magic_names": {
    "laptop.home.arpa.": [
      {
        "ip": "192.168.1.100",
        "magic_fqdn": "laptop-maabbcc.home.arpa.",
        "id_type": "m",
        "id_tail": "aabbcc",
        "laa": false,
        "source": "lease"
      },
      {
        "ip": "192.168.1.50",
        "magic_fqdn": "laptop-i001050.home.arpa.",
        "id_type": "i",
        "id_tail": "001050",
        "laa": false,
        "source": "override"
      }
    ]
  }
}
```

`source` distinguishes lease-backed entries (removed by stale-clean or
state diff) from override/static entries (removed only by state diff).

**Locking**: reads and writes inside the existing `unbound_mutation_lock`
(blocking advisory lock at `/var/run/keaubnd/unbound-mutation.lock`).
No additional file-level locking needed.

**Write discipline**: write to `magic-state.json.tmp`, then `os.rename()`
(POSIX-atomic on same filesystem).

**Read failure**: treat as empty state, log warning, proceed. Worst case:
departed devices' magic names linger until stale-clean catches them.

### D13 — Collision resolution and state file cleanup

When the sync detects a collision has partially resolved (fewer active
entries than the state file records for that hostname):

1. Query Kea for all active leases with the bare hostname.
2. **If count > 1**: collision still active (or a new entrant arrived).
   Abort cleanup for this hostname, log a warning, try next cycle.
3. **If count = 1**: collision resolved to one survivor.
   - Identify the survivor's magic FQDN from its identifier.
   - Remove magic FQDNs for all **departed** entries (those in the state
     file but not the survivor) from Unbound.
   - Leave the survivor's magic FQDN in place (non-eager removal).
   - Update the state file to reflect the new state.
4. **If count = 0**: all leases expired. Magic names will be caught by
   stale-clean. Remove all entries for this hostname from the state file.

### D14 — Magic name conflict detection (hostile or accidental squatting)

A client could register a hostname that matches a magic FQDN we intend to
generate (e.g., a client naming itself `iphone-maabbcc`). This is
effectively impossible by accident and almost certainly deliberate if it
occurs.

**Handling**: before assigning a magic FQDN, check whether that exact
hostname already exists as a real active lease or static entry in the
current sync dataset. If it does:

- Fall through to the meta-collision counter: `iphone-maabbcc-1`.
- Log a prominent warning: "magic name conflict on {fqdn} — possible
  hostname squatting detected."

The check is O(1) — the full hostname set is already in memory during the
sync's collision-detection pass.

---

## Configuration Surface

| Setting | Type | Default | Notes |
|---------|------|---------|-------|
| `collision_policy` | enum | `last_wins` | `first_wins` / `last_wins` / `allow` / `none`. Existing field; add `none`. |
| `magic_names` | boolean | `0` | New field. Orthogonal to `collision_policy`. |
| `magic_laa_tag` | boolean | `0` | New field. Shown only when `magic_names` is on. |

`magic_names` replaces the previously considered `collision_policy = magic`
approach. Magic is a separate toggle, not a peer of the collision policies.
No suffix-length toggle (always 6). No PTR-behavior toggle for magic.

---

## Known Limitations

These are inherent to operating at the DHCP→DNS layer. The correct
mitigation in all cases is to give the affected host an explicit reservation
with a hardware identifier, removing it from the collision space entirely.

**TLS certificates**: a host's cert is typically issued for its bare
hostname. Under magic, its PTR returns the magic FQDN. Tooling that does
reverse-lookup-then-cert-verify will see a name mismatch.

**HTTP virtual hosting**: services routing by `Host:` header from DNS may
reach the wrong device if the bare hostname resolves to a different machine.

**ACME / certificate issuance**: forward/reverse consistency checks may
fail when PTR does not match the expected hostname.

**Randomized MACs (LAA devices)**: magic names for LAA-tagged devices
cycle as the MAC changes (iOS, Android privacy mode). The LAA tag signals
this instability. These names should not be used in long-lived references.

**Cross-family dual-stack collisions (v1 limitation — v2 todo)**: collision
detection is family-scoped. If two different physical devices both register
the hostname `laptop` — one via DHCPv4 (A record) and one via DHCPv6 (AAAA
record) — this is not detected as a collision and magic names are not
generated for either. A resolver asking for `laptop` receives both records;
which device is actually reached depends on client address-selection
behaviour (RFC 6724 / Happy Eyeballs) and is indeterminate.

Kea has no mechanism to correlate v4 and v6 leases for the same host across
its separate lease files. The only natural correlation point is the hostname
field; a single dual-stack device registering `laptop` in both families
looks identical to two separate devices doing the same. A cross-family
conflict warning in the audit would fire on every dual-stack host and
produce noise rather than signal.

v1 behaviour: the audit displays both the A and AAAA records for any
hostname, which gives the administrator the information needed to
investigate. No warning is raised.

v2 consideration: attempt DUID-to-MAC correlation for DUID-LLT (type 1)
and DUID-LL (type 3) subtypes, which embed the MAC address. If the embedded
MAC matches the v4 lease MAC, the entries are the same device and no flag
is raised. If they differ, or if the DUID type does not embed a MAC
(DUID-EN, DUID-UUID), surface an informational note in the audit.
Mitigation in all cases: assign distinct hostnames to the affected devices.

**Mitigation**: assign the affected host a static reservation with a
hardware identifier and a unique hostname. Magic is appropriate for devices
the administrator has not explicitly named — not a substitute for proper
hostname management on name-sensitive services.

---

## Implementation Plan

### Phase 1 — Core library (`lib/keaubnd_sync.py`)

- `is_laa(mac_hex: str) -> bool` — detect locally administered bit.
- `identifier_tail(id_type: str, id_value: str) -> str` — strip separators,
  return last 6 chars of payload.
- `ip_suffix(ip: str) -> str` — last two octets of IP, each 3-padded,
  concatenated (`001050`).
- `compute_magic_suffix(id_type, id_value, laa: bool) -> str` — produce
  full suffix block (`laa-m{tail}`, `i{tail}`, etc.).
- `compute_magic_names(collision_group: list[dict], laa_tag: bool, existing_hostnames: set) -> dict`
  — given `{ip, id_type, id_value, source}` dicts, return `{ip: magic_fqdn}`.
  Handles meta-collision (duplicate tails → counter), magic name conflict
  detection (clash with existing hostname → counter + warning).
- `read_magic_state(path) -> dict` — load state file; `{}` on any error.
- `write_magic_state(path, state: dict)` — atomic write via tmp+rename.

### Phase 2 — Sync pre-pass (`kea-sync.py`)

- Load old state file at start of sync (inside mutation lock).
- After building full records list: collision-detection pre-pass.
  - Group by FQDN; identify groups with >1 IP.
  - Call `compute_magic_names()` for each collision group.
  - Inject magic-named records into records list.
- After Unbound writes: query Kea for each hostname in old state file to
  detect resolved collisions; run D13 cleanup logic.
- Write new state file (inside mutation lock).
- PTR rewrite: for dynamic lease entries in a collision, write PTR →
  magic FQDN instead of bare hostname.

### Phase 3 — Stale clean (`local-data-clean.py`)

- Read state file to identify magic-created FQDNs.
- Magic FQDNs whose backing lease is gone: stale candidates, removed
  normally.
- Magic FQDNs for `source = "override"` or `"static"`: not stale-cleaned
  (no lease to expire); only removed via state file diff in Phase 2.

### Phase 4 — Audit (`local-data-audit.py`)

- Cross-reference state file to identify magic FQDNs in Unbound snapshot.
- Annotate collision entries with magic FQDNs.
- Include `magic_fqdn` field in JSON report output.

### Phase 5 — Config model and form

- `models/General.xml`: add `none` to `collision_policy` enum; add
  `magic_names` boolean; add `magic_laa_tag` boolean.
- `forms/generalSettings.xml`: add `none` option; add magic toggle with
  description; add LAA toggle (shown only when magic on) with explainer
  text referencing IEEE/IETF LAA terminology.
- `forms/generalSettings.xml` (cleanup): rename `write_ptrs` label from
  "Synthesize PTR records from DDNS updates" → "Synthesize PTR records".

### Phase 6 — UI (`views/status.volt`)

- Display magic FQDNs in Lease Audit for colliding hosts.
- Visual distinction TBD (inline annotation preferred over separate panel).

---

## Implementation Entry Points

Specific file locations and function signatures for each phase. Start with
Phase 1 (pure additions, zero risk to existing behaviour) before touching
any sync logic.

### Phase 1 — `src/opnsense/scripts/keaubnd/lib/keaubnd_sync.py`

**Add constant** near line 58 alongside `MUTATION_LOCK_PATH`:
```python
MAGIC_STATE_PATH = f"{MUTATION_LOCK_DIR}/magic-state.json"
```

**Extend `get_collision_policy()`** at line 186 — add `'none'` as a valid
return value (already handles unknown values via default; just update the
docstring and the XML enum in Phase 5).

**`query_kea_leases_by_hostname()`** at line 539 — used as-is for D13
collision-resolution detection. Signature:
```python
def query_kea_leases_by_hostname(hostname: str, service: str = "dhcp4") -> List[Dict]:
```

**New functions to add** (after `get_sm_config()` at line 213 is a clean
insertion point):

```python
def is_laa(mac_hex: str) -> bool:
    """Return True if MAC has the locally administered bit set (bit 1 of byte 0)."""

def identifier_tail(id_value: str) -> str:
    """Strip separators (: - .) from id_value and return the last 6 chars, uppercased."""

def ip_suffix(ip: str) -> str:
    """Last two octets of IPv4, each zero-padded to 3 decimal digits, concatenated."""

def compute_magic_suffix(id_type: str, id_value: str, laa_tag: bool) -> str:
    """Return the full suffix block, e.g. 'laa-mAABBCC', 'i001050'."""

def compute_magic_names(
    collision_group: list[dict],   # [{ip, id_type, id_value, laa, source}, ...]
    laa_tag: bool,
    existing_hostnames: set[str],  # full hostname set in memory — squatting check
) -> dict[str, str]:               # {ip -> magic_fqdn (unqualified)}
    """
    Assign a magic FQDN to each IP in the collision group.
    Handles meta-collision (duplicate tails -> append counter) and squatting
    detection (magic FQDN clashes existing hostname -> counter + warning).
    """

def read_magic_state(path: str = MAGIC_STATE_PATH) -> dict:
    """Load state file; return {} on any error (log warning)."""

def write_magic_state(state: dict, path: str = MAGIC_STATE_PATH) -> None:
    """Atomic write via path+'.tmp' then os.rename()."""
```

### Phase 2 — `src/opnsense/scripts/keaubnd/kea-sync.py`

**`_collect_writes()` at line 92** — add `magic_fqdns: dict[str, str]` param
(`{ip: magic_fqdn}`). When `synthesize_ptr` is True and a hostname is in a
collision, emit PTR → magic_fqdn instead of PTR → bare hostname. Signature
becomes:
```python
def _collect_writes(records, rtype, host_entries, policy, synthesize_ptr,
                    unbound_fwd, won_keys, logger, allow_multi_ip=False,
                    magic_fqdns=None):
```

**`sync_static()` at line 270** and **`sync_dynamic()` at line 326** — add
magic pre-pass: group records by FQDN, call `compute_magic_names()` for each
group with >1 IP, inject magic-named records.

**`main()` at line 396**:
- Load old magic state before sync (inside mutation lock).
- Load `magic_names` and `magic_laa_tag` settings (new `get_magic_names()` /
  `get_magic_laa_tag()` getters to add to keaubnd_sync.py in Phase 1).
- After writes: run D13 resolution logic for any hostname in old state that
  is now down to ≤1 active lease.
- Write new state file.

**`policy = get_collision_policy()` at line 425** — add `none` branch to
`_collect_writes()`. Under `none`, if a new dynamic lease collides with any
existing entry: skip it and queue existing dynamic records for removal
(mirror the `first_wins` skip path, but also purge the existing winner).

### Phase 3 — `src/opnsense/scripts/keaubnd/local-data-clean.py`

**`clean_stale_records()` at line 301** — before stale-clean loop, load state
file. Filter the `stale_pairs` set: any entry whose FQDN is in the state file
with `source = "override"` or `source = "static"` must not be stale-cleaned
(it has no expiring lease; removal is only via state diff in Phase 2).

Dynamic-backed magic FQDNs (`source = "lease"`) proceed through normal
stale-clean as-is — their backing lease will disappear from `kea_pairs` when
expired, triggering removal.

### Phase 4 — `src/opnsense/scripts/keaubnd/local-data-audit.py`

**`audit_local_data()` at line 115** — load state file early. Build a
reverse index: `{magic_fqdn: {ip, id_type, id_tail, laa, source}}`.

**`identifier_by_host_ip` at line 182** — annotate any FQDN found in the
reverse index with `"magic": True` and `"magic_fqdn": ...` in the per-record
output dict. Include `magic_fqdn` in the JSON report at line ~322.

### Phase 5 — Config model and form

**`src/opnsense/mvc/app/models/OPNsense/KeaUbnd/General.xml:64`** — add
`none` to `collision_policy` OptionValues:
```xml
<none>None — evict all dynamic records on conflict</none>
```

Add after the `clean_on_restart` field (line ~79):
```xml
<magic_names type="BooleanField">
    <Default>0</Default>
</magic_names>
<magic_laa_tag type="BooleanField">
    <Default>0</Default>
</magic_laa_tag>
```

**`src/opnsense/mvc/app/controllers/OPNsense/KeaUbnd/forms/generalSettings.xml:93`** —
`synthesize_ptr` label: change "Synthesize PTR records from DDNS updates" →
"Synthesize PTR records".

**line 99** — add `none` option to collision_policy `<help>` block. Add new
`magic_names` and `magic_laa_tag` fields after the collision_policy field.
`magic_laa_tag` should use `show` condition tied to `magic_names` being
enabled (standard OPNsense form conditional display pattern).

### Phase 6 — UI (`src/opnsense/mvc/app/views/OPNsense/KeaUbnd/status.volt`)

Note: this file has unrelated uncommitted changes on branch `0.97`. Branch
`0.98` is cut from `main` — Phase 6 UI work will need to be rebased or
cherry-picked onto `0.97` changes when merging. Do not start Phase 6 until
`0.97` work is merged to `main`.

Magic FQDN display: for each colliding host row in the Lease Audit table,
add an inline annotation showing the magic FQDN (sourced from `magic_fqdn`
field in the JSON report). Visual treatment TBD (see Open Questions #1).

---

## Open Questions (deferred to implementation)

| # | Question |
|---|----------|
| 1 | Exact UI presentation of magic names in Lease Audit. |
| 2 | LAA explainer text wording — confirm alignment with RFC 9724 / RFC 9797. |
| 3 | Whether stale-clean identifies magic records via state file cross-reference or pattern matching. State file is cleaner; pattern-match is more resilient to state file loss. |
