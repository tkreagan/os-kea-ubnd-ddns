# Advanced Topics

Operator and developer reference for edge cases, known limitations, and
non-obvious behavior in the kea-ubnd-ddns plugin. Covers shared networks,
clients without hostnames, IPv6/DHCPv6 specifics, dual-stack coexistence,
DNS suffix lifecycle, and Kea DDNS configuration options with subtle effects
on the live and sync paths.

---

## DHCPv6 Lease Types — What Gets Processed

Kea DHCPv6 has three lease types. The plugin explicitly filters on the `type`
field returned by `lease6-get-all` and stored in `kea-leases6.csv`:

| Type | Name | Processing |
|------|------|------------|
| 0 | IA_NA (Non-temporary Address) | **Processed.** Standard host address. Produces AAAA and PTR records. |
| 1 | IA_TA (Temporary Address) | **Blocked.** Temporary addresses are not intended for stable DNS entries. |
| 2 | IA_PD (Prefix Delegation) | **Blocked.** The "address" field is a network prefix, not a host address. |

The filter is in `_normalize_raw_lease()` in `lib/keaubnd_sync.py`. Any lease
with `type != 0` returns `None` immediately, before hostname or IP validation.

**Why IA_TA?** IA_TA is essentially unused in production — SLAAC privacy
extensions (RFC 4941) replaced it. Blocking it explicitly is defensive coding
and documents the intent: only stable host addresses get DNS records.

**Why IA_PD?** The Kea lease record for a delegated prefix contains the prefix's
network address (e.g., `fd01::` for a `/60` delegation) in the `ip-address`
field. Without the filter, a PD lease with a hostname would register
`hostname AAAA fd01::` — the prefix address, not any host on that prefix. PD
leases typically have no hostname anyway, but the type guard is explicit
defense-in-depth.

---

## DHCPv6 Reservations — Multiple Addresses Per Reservation

Unlike DHCPv4, where a reservation has exactly one `ip-address`, a DHCPv6
reservation can carry multiple addresses in `ip-addresses: [...]`. A client can
hold multiple IA_NA addresses simultaneously.

The plugin handles this correctly: `query_kea_reservations("dhcp6")` emits one
result dict per address entry. A reservation with two addresses produces two
entries, each of which gets its own AAAA record and synthesized PTR.

This is implemented as a loop over `res.get("ip-addresses") or []` in
`query_kea_reservations()`.

**Collision policy applies per-address within the same family.** If both
addresses map to the same FQDN, only one wins under `first_wins` / `last_wins`.
Under `allow`, both are written. This is the same collision behavior as two
leases for the same hostname.

---

## Reservation Identifier Precedence

Kea DHCPv4 supports four ways to identify a host for reservation matching.
When more than one identifier is present in a reservation record, Kea uses a
fixed priority order to decide which one to match incoming clients against.
The plugin's audit and UI follow the **same order** when deciding which
identifier to display.

| Priority | Kea JSON field | Display label | Notes |
|----------|---------------|---------------|-------|
| 1 | `hw-address` | `mac` | Hardware/MAC address — most common for DHCPv4 |
| 2 | `duid` | `duid` | DHCP Unique Identifier; native to DHCPv6 but valid in v4 |
| 3 | `circuit-id` | `circuit-id` | Relay agent Option 82 sub-option 1; only meaningful when traffic arrives through a DHCP relay |
| 4 | `client-id` | `client-id` | DHCP client identifier sent by the client |
| — | (none present) | `(hostname only)` | Reservation carries only a hostname; no hardware binding |

Reference: https://kea.readthedocs.io/en/latest/arm/dhcp4-srv.html#fine-tuning-dhcpv4-host-reservation

**In code**: `query_kea_reservations()` in `lib/keaubnd_sync.py` captures all four
fields as `hw_address`, `duid`, `circuit_id`, `client_id`. `local-data-audit.py`
builds `identifier_by_host_ip` using the priority above and stores
`{"type": ..., "value": ...}` per `(hostname, ip)` pair. The Lease Audit UI
renders the type as a small prefix label (`mac aa:bb:cc:…`, `duid 00:01:…`, etc.).

**DHCPv6**: `duid` is the primary identifier; `hw-address` is also valid.
`circuit-id` and `client-id` are rarely used in v6. All four fields are captured
for v6 reservations but `circuit-id` in particular will almost never be populated.

**Hostname-only reservations** (no IP address, no hardware identifier) are silently
skipped by `query_kea_reservations()` because there is no IP to pre-populate in DNS.
They still work through the live d2 path when the client comes online.

---

## IPv6 PTR Records — Encoding and Parsing

IPv6 PTR records use the `ip6.arpa` zone with a 32-nibble reversed encoding.
Each nibble (4-bit hex digit) of the full 128-bit address becomes a single DNS
label, reversed, then `.ip6.arpa` is appended.

```
fd00::1ab
  → expanded:  fd00:0000:0000:0000:0000:0000:0000:01ab
  nibbles (reversed): b.a.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa
```

**In code:** `ipaddress.ip_address(addr).reverse_pointer` generates this
correctly for any valid IPv6 address. Do not hand-roll this calculation.

**Decoding arpa → IP:** `_arpa_to_ip(ptr_name)` in `lib/keaubnd_sync.py`
reverses this and normalizes via `ipaddress.ip_address()`. The result is always
Python's compressed canonical form (e.g., `fd00::1ab`), which matches the form
Kea uses in its lease and reservation data.

**`list_local_data` output:** `unbound-control list_local_data` returns AAAA
rdata in compressed form and PTR owner names in full 32-nibble form. The
plugin's `unbound_list_local_data()` parser reads both correctly.

**`_arpa_to_ip` is the single canonical implementation.** It lives in
`lib/keaubnd_sync.py` and is imported by both `kea-ubnd-ddns.py` and
`local-data-audit.py`. Do not add local copies.

---

## Dual-Stack Hosts — A and AAAA Coexistence

A host can simultaneously hold a DHCPv4 lease (→ A record) and a DHCPv6 lease
(→ AAAA record) for the same FQDN. The plugin preserves both.

**Collision policy is family-scoped.** The sync path uses `forward_ips_by_type()`
to build separate A-only and AAAA-only snapshots of Unbound's current state.
Collision checks for A records never compare against AAAA records. A DHCPv4
reservation for `host.example.com` does not block a DHCPv6 lease for the same
name.

**`local_data_remove` removes all families at once.** Unbound's
`local_data_remove name` wipes ALL rrsets for that owner name — A, AAAA, and
anything else. Any code path that removes a forward name must restore the
surviving family:

- **Daemon live DELETE path:** `process_update()` reads the other family via
  `query_unbound(name, other_type)` before removing, then restores it after.
- **Sync path `_collect_writes`:** emits `local_data_remove name` only when
  replacing a winner with a different IP; the removal is immediately followed
  by the new add.
- **Bulk clean `clean_stale_records`:** groups stale (name, ip) pairs by name,
  calls `local_data_remove` once, then re-adds all non-stale records.

**Staleness is per (name, ip) pair, not per name.** `find_stale_records()`
returns a set of `(name, ip)` tuples. A dual-stack host with a valid A and a
stale AAAA produces exactly one stale pair — `(name, stale_ipv6)` — without
touching the A record.

---

## Magic Hostnames — Dual-Stack and Happy Eyeballs

Magic hostnames (`magic_names` setting) create disambiguated parallel forward
records for hosts involved in a hostname collision. They are inherently
**family-scoped** — a dual-stack device in a collision receives two *different*
magic FQDNs, one per address family, not a single name with both an A and AAAA
record.

### Why magic FQDNs are family-scoped

Collision detection runs independently per family (see *Dual-Stack Hosts* above).
More importantly, the suffix is derived from the hardware identifier that the DHCP
daemon actually sees:

- **DHCPv4** always provides `hw-address` (the MAC from the Ethernet frame) →
  suffix is `m{6hex}`, e.g. `laptop-mAABBCC`
- **DHCPv6** provides a DUID, not a MAC → suffix is `d{6hex}`, e.g.
  `laptop-dXXXXXX`

The same physical device produces different suffixes in each family, so the
resulting magic FQDNs are different names. There is no mechanism in v1 to
correlate them into a shared name.

### Consequence for Happy Eyeballs (RFC 8305)

Happy Eyeballs works by querying a **single FQDN** for both A and AAAA records
simultaneously and using whichever family connects first. This requires the FQDN
to have records in both families.

Magic FQDNs do not satisfy this requirement for dual-stack devices:

- `laptop-mAABBCC` has only an A record (v4 magic)
- `laptop-dXXXXXX` has only an AAAA record (v6 magic)

A client that looks up `laptop-mAABBCC` gets v4 only and connects over IPv4.
A client that looks up `laptop-dXXXXXX` gets v6 only and connects over IPv6.
Happy Eyeballs cannot operate across family boundaries here because the two names
are unrelated from DNS's perspective.

**This is by design.** Magic FQDNs are collision-resolution metadata, not
production endpoints. The correct endpoint for application traffic is the **bare
hostname** (`laptop`), which receives A and AAAA records from normal sync
processing and works correctly with Happy Eyeballs. Magic names answer the
question *"which specific physical device won the collision?"* — a question that
is inherently per-family.

### LAA tagging and dual-stack

LAA tagging (`magic_laa_tag` setting) marks magic FQDNs for devices whose MAC
has the locally administered bit set (iOS, Android, Windows MAC randomization).
LAA detection requires reading the MAC and checking bit 1 of the first byte.

- **v4 entries** (`hw-address` type): LAA detection works directly. The tag is
  applied: `laptop-laa-mAABBCC`.
- **v6 entries** (`duid` type): LAA detection is **not applied in v1**. DUID is
  an opaque blob from this plugin's perspective. DUID-LLT (type 1) and DUID-LL
  (type 3) embed a link-layer address at a known offset, from which the LAA bit
  could be extracted, but this requires DUID structure parsing and only works for
  two of the four DUID subtypes. DUID-EN and DUID-UUID have no embedded MAC.

The result in a dual-stack collision: the v4 magic FQDN may carry `-laa-` while
the v6 magic FQDN does not. This is an informational asymmetry rather than a
functional problem — the LAA infix signals instability, and a device that
randomizes its v4 MAC is also likely rotating its v6 DUID, which has the same
instability property regardless of whether it is tagged.

v2 consideration: parse DUID-LLT and DUID-LL to extract the embedded MAC and
check the LAA bit. This would enable consistent tagging for the common case. The
same DUID parsing could also enable cross-family collision detection (correlating
v4 and v6 leases that embed the same MAC), closing the gap described in the
Known Limitations table.

---

## SLAAC — Not Supported (Intentional Non-Goal)

IPv6 addresses assigned by SLAAC (RFC 4862) are invisible to this plugin. SLAAC
clients derive their addresses from the network prefix advertised by `radvd` —
they never talk to Kea, so no lease is created and no DDNS update is sent.

There is no plan to support SLAAC-sourced DNS registration. Doing so would
require intercepting RA messages or running separate neighbor-discovery
monitoring, neither of which fits this plugin's architecture.

---

## DHCPv6 Configuration Options That Affect the Plugin

Most Kea DHCPv6 options govern address assignment mechanics and have no effect
on the plugin. The ones that do matter:

### Hostname Construction

- **`ddns-qualifying-suffix`** (global and per-subnet): suffix appended to bare
  hostnames. Must be consistent across subnets so the live path and sync path
  produce the same FQDNs.

- **`ddns-replace-client-name`**: controls whether the server uses the
  client-supplied hostname or generates one using `ddns-generated-prefix`. The
  plugin sees only the post-replacement name. More relevant for DHCPv6 than
  DHCPv4 because DHCPv6 clients less consistently send option 39 (Client FQDN).

- **`ddns-generated-prefix`** (default `"myhost"`): prefix for server-generated
  hostnames when clients don't supply one. Generated FQDNs follow the format
  `<prefix>-<dashed-IP>.<qualifying-suffix>` — e.g.,
  `kea6host-fd00--102.home.lan`. These pass the plugin's `is_sane_name()` check.

  > **Sync path gap with generated names:** Kea stores the *original client
  > name* (or empty string) in the lease database, not the generated name. The
  > sync path reads the lease database and skips leases without a hostname. This
  > means: after an Unbound restart, generated-name records cannot be restored
  > by the sync path — they stay gone until the client's next renewal triggers a
  > new NCR. Mitigation: enable `ddns-update-on-renew: true` on affected subnets.

### NCR Generation Control

- **`ddns-send-updates`**: the sync path **respects this flag**.
  `_build_suffix_map()` reads it per subnet (with shared-network and global
  inheritance) and passes a `ddns_disabled_subnets` set to
  `_normalize_raw_lease()`, which returns `None` for leases from disabled
  subnets. The clean path and audit both apply the same exclusion.

- **`ddns-override-no-update`**: if false (default), a client that sets the
  DHCPv6 N-bit opts out of DDNS. The live NCR path respects this. The sync path
  does not — if the lease has a hostname, it is synced regardless.

- **`ddns-update-on-renew`** (default false): if false, D2 sends NCRs only on
  new leases, not renewals. TTLs in live-path records age without refresh between
  scheduled syncs. The sync path independently computes TTL from remaining lease
  time, so periodic reconciles keep TTLs accurate regardless.

### TTL

- **`ddns-ttl-percent` / `ddns-ttl` / `ddns-ttl-min` / `ddns-ttl-max`**: control
  the TTL in NCRs that D2 sends. The daemon applies the NCR TTL directly. The
  sync path uses `max(1, lease["expires"] - now)` (remaining lifetime) instead.
  After any reconcile, the sync-computed TTL overwrites the NCR TTL.

**How Unbound handles local-data TTLs (by design):** Unbound serves `local-data`
records as authoritative zone data — the `aa` (Authoritative Answer) flag is set
in every response. Authoritative DNS servers return their configured TTL on every
query; they do not decrement it as time passes. This is confirmed by observation:
`unbound-control list_local_data` returns the same TTL value 5 seconds, 30
seconds, or 10 minutes after a record was added.

This has two consequences worth knowing:

1. **TTL countdown happens in DNS resolvers and clients, not in Unbound.** A
   caching resolver querying Unbound will cache the record and decrement its copy.
   Unbound itself always returns the full configured value. This is correct and
   standard for authoritative servers.

2. **Dual-stack sibling preservation on live DELETE does not inflate TTLs.**
   When the daemon's live path receives a DELETE for one address family, it reads
   the surviving sibling's TTL from `list_local_data`, removes the name entirely
   (Unbound has no per-RR remove), then re-adds the sibling with the same TTL. A
   concern might be that this "resets" a TTL that was counting down. It does not —
   Unbound was already serving the full static TTL to every querier, so the
   re-add produces identical behaviour. The next scheduled reconcile will
   overwrite the TTL with the remaining lease lifetime anyway.

### Conflict Resolution

- **`ddns-use-conflict-resolution`**: Kea D2 may include DHCID prerequisites in
  DNS UPDATE messages. The daemon ignores them and always returns NOERROR. Kea's
  conflict resolution is effectively bypassed — the plugin's own collision policy
  (`first_wins` / `last_wins` / `allow`) is the sole conflict mechanism. See
  README.md for the full collision policy description.

---

## DDNS Suffix Staleness — Old Records After a Suffix Change

**What happens:** Kea writes the full FQDN into the lease record at grant time,
derived from the client hostname and the subnet's `ddns-qualifying-suffix` at
that moment. If the suffix is later changed, existing leases still carry the
old FQDN. When D2 sends NCRs for renewals or the sync path reads those leases,
it uses the stale FQDN — so old-suffix DNS records remain and appear to be
backed by active leases.

**Why the plugin cannot auto-detect this:** `find_stale_records()` compares
Unbound records against Kea leases. An old-suffix record
(`host.old.example.com → 192.168.1.100`) is backed by the lease for that IP,
whose `hostname` field still reads `host.old.example.com`. From the plugin's
perspective the record is correct — Kea says so. The plugin treats Kea's lease
as authoritative for the hostname; removing a record that Kea says is valid
would violate that invariant.

**How it resolves on its own:**

1. The client renews. If `ddns-update-on-renew: true`, D2 sends a fresh NCR
   with the new suffix and a REMOVE for the old one. With the default
   (`false`), renewal does not trigger NCRs and the old record persists.
2. The lease expires. Kea's ELP queues a REMOVE NCR for the old FQDN. D2
   delivers it and the listener removes the record.
3. The next scheduled bulk clean runs after the lease expires — at that point
   there is no Kea record protecting the old name.

**Manual remediation:** after changing `ddns-qualifying-suffix`:

```sh
configctl keaubnd sync_dynamic   # repopulate new-suffix records
unbound-control local_data_remove host.old.example.com
unbound-control local_data_remove <PTR for old name>
```

**Configuration advice:** change `ddns-qualifying-suffix` during a maintenance
window, set `ddns-update-on-renew: true` temporarily, and wait for all clients
to renew. D2 sends REMOVE NCRs for the old suffix as each client renews,
cleaning up automatically within one lease period. Then disable
`ddns-update-on-renew` again.

---

## Shared Networks (Manual Config)

OPNsense does not expose shared-network configuration in its Kea DHCP GUI
([opnsense/core#9427](https://github.com/opnsense/core/issues/9427)). If you
configure shared networks by hand with `manual_config` enabled, here is what the
plugin supports and what it does not.

**What works:**

- **Subnet-level `ddns-qualifying-suffix` inside shared networks** — the plugin
  reads each subnet's suffix from Kea's `config-get` response, including subnets
  that live inside a shared-network object. Suffix inheritance follows the standard
  waterfall: subnet → shared-network → global → OPNsense system domain. A subnet
  with no explicit suffix inherits from the shared-network; a subnet with an
  explicit suffix uses that, ignoring the shared-network's value.

- **Subnet-level `ddns-send-updates` inside shared networks** — the same
  inheritance applies. A shared-network with `"ddns-send-updates": false` disables
  DDNS registration for all child subnets unless a subnet explicitly overrides it
  back to `true`. Both the sync path and the clean path honour this.

- **Subnet-level reservations inside shared networks** — reservations placed inside
  a subnet that is itself inside a shared-network (`shared-networks[].subnet4[].reservations[]`)
  are picked up correctly. The sync path walks the nested structure.

**What does not work:**

- **Shared-network-level reservations** — reservations placed *directly on the
  shared-network object* (`shared-networks[].reservations[]`, not inside a child
  subnet) are not supported and will be silently ignored. Kea allows this placement
  but ISC recommends against it for IP-address reservations. OPNsense does not
  generate this structure. If you have such reservations, move them to the
  appropriate child subnet.

- **DDNS for subnets inside shared networks is not end-to-end tested** — Kea's D2
  routes NCRs by matching the FQDN against configured forward domains; as long as
  the qualifying suffix for a shared-network subnet matches a D2 forward domain, NCRs
  should route correctly. However, this path has only been verified via the sync
  path, not via a live DHCP exchange from a client in a shared-network subnet.

The **Config Check** tab flags shared-network subnets with an advisory notice.

---

## Clients Without Hostnames and Generated Names

**The problem:** every DNS record the plugin creates is derived from a hostname.
A client that sends no hostname in its DHCP request — common on phones and devices
with MAC address randomization — gets no DNS record, regardless of the override
settings (`ddns-override-no-update`, `ddns-override-client-update`). Those flags
only act when the client supplies a name; they cannot manufacture one from nothing.

**Kea's solution:** two options work together to generate names for nameless
clients. Both are available only in manual config mode (OPNsense does not expose
them in the GUI as of 26.1).

`ddns-replace-client-name` controls when Kea generates a synthetic name:

| Mode | When Kea generates a name |
|------|--------------------------|
| `never` *(default)* | Never — use the client-supplied name as-is |
| `when-not-present` | When the client sends no name |
| `always` | Always — discard whatever the client sends |
| `when-present` | Only when the client sends a name (replace it) |

`ddns-generated-prefix` sets the prefix for generated names (default `"myhost"`).
Generated FQDNs follow the format `<prefix>-<dashed-IP>.<qualifying-suffix>` — for
example, `myhost-192-168-1-100.home.lan` for a client at `192.168.1.100`. For IPv6,
the dashed form uses `--` where `::` appears: `kea6host-fd00--102.home.lan`.

**Sync path gap:** when Kea generates a name, it places the generated FQDN in the
NCR packet (so the live path — `kea-dhcp-ddns` → listener — registers it
correctly). However, Kea stores the *original client name* (or empty string) in
the lease database. The sync path reads the lease database; it sees an empty
hostname and skips the lease. This means:

- While Kea and D2 are running: the generated name is in Unbound, registered via
  the live path.
- After an Unbound restart (which flushes all runtime `local_data`): the sync path
  cannot restore the record. It stays gone until the client's next lease renewal
  triggers a new NCR.

**Mitigation:** enable `ddns-update-on-renew: true` on subnets that use generated
names. This causes Kea to re-assert DNS on every genuine renewal, which limits the
window after an Unbound restart where records are missing to at most one lease T1
interval.

> **Cache-threshold caveat:** Kea's lease caching (`cache-threshold`, default
> `0.25`) reuses a lease renewed within `0.25 × valid-lifetime` and performs *no*
> DDNS, so DNS is only refreshed on renewals outside that window (~1000s with a
> 4000s lease). A normal renewal at half the lease lifetime is outside the window
> and works.

**Recommendation:** if every device must be resolvable, configure
`ddns-replace-client-name: when-not-present` and `ddns-generated-prefix:
<something>` in manual config mode, combined with `ddns-update-on-renew: true`.
Devices that supply a real hostname continue to use it; nameless devices get a
deterministic generated name that the live path keeps fresh.

---

## Consistency Model — What Keeps Kea and Unbound in Sync

The plugin maintains DNS consistency through four independent layers. Understanding
what each layer covers — and what it does not — helps you choose the right settings
for your network.

### The four layers

**Layer 1: Restart reconcile (always on)**

The resident daemon (`kea-ubnd-ddns.py`) holds kqueue watches on the Kea and
Unbound service pidfiles. Whenever either service restarts, the daemon detects the
pidfile change and automatically runs a full reconcile: it queries Kea for all
active leases and reservations and repopulates Unbound from scratch. This is the
foundational safety net — even with all other layers disabled, a restart always
brings Kea and Unbound back into agreement.

**Layer 2: Live DDNS path (always on while kea-dhcp-ddns is running)**

`kea-dhcp-ddns` delivers RFC 2136 DNS UPDATE packets to the plugin's stub listener
the moment a lease is issued or released. The listener translates each packet into
an `unbound-control` call — typically sub-millisecond. This is the primary real-time
path for active networks.

**Layer 3: Scheduled sync / clean (on by default)**

A cron job runs on the configured schedule (default every 6 hours). Two independent
operations can be scheduled:

- **Full sync** (`kea-sync.py`): reads all Kea leases and reservations and adds any
  records missing from Unbound. This catches drift in either direction that the live
  path missed — including leases registered while `kea-dhcp-ddns` was temporarily
  down. Recommended for all deployments.

- **Stale-record clean** (`local-data-clean.py`): sweeps Unbound for records not
  backed by any Kea lease, reservation, or Unbound Host Override and removes them.
  This is the only path that removes records left behind by leases that expired
  naturally (no explicit DHCPRELEASE from the client). Off by default — use the
  Lease Audit tab to preview what would be removed before enabling.

Note that sync and clean cover complementary failure modes. Sync adds records that
should exist; clean removes records that should not. Neither substitutes for the
other. Running sync without clean means stale records accumulate indefinitely from
naturally expired leases. Running clean without sync means newly issued leases may
remain unregistered until the next restart reconcile or cron interval.

**Layer 4: Log watcher (off by default)**

A secondary daemon (`kea-ubnd-logwatch.py`) tails both the Kea DHCP log and the
listener log. It reacts to three categories of event, each independently
configurable:

- **Lease release** (`logwatch_on_release`): on `DHCP4_RELEASE` or `DHCP6_RELEASE`,
  immediately runs `local-data-clean.py --purge-ip` for the released address. DNS
  records for that IP disappear within seconds of the client releasing its lease,
  rather than waiting for the next scheduled clean.

- **Listener SERVFAIL** (`logwatch_on_servfail`): when the DDNS listener returns
  SERVFAIL (Unbound was briefly unavailable or locked during an update), triggers a
  targeted `kea-sync --names=...` for the affected hostnames. This supplements the
  dirty-name drain path so missed adds and removes are recovered quickly.

- **Remove without Add** (`logwatch_on_missed_remove`): when a DNS Remove is seen in
  the listener log without a paired Add within a short grace window (default 10s),
  triggers a targeted `kea-sync --names=hostname`. This closes the LEASE_REUSE gap
  described below.

### The LEASE_REUSE gap

Kea has a lease-cache optimization: when a client requests a lease and its existing
lease is still valid (same client, same IP, not near expiry), Kea serves it without
writing to the lease database. Because no database write occurs, `kea-dhcp-ddns` may
not consider this a meaningful change and may skip the DDNS update entirely — or in
some cases, send a `CHG_REMOVE` (to clear the old registration) but no follow-up
`CHG_ADD` (because the lease looks unchanged).

The result: the DNS record for that hostname disappears and is not immediately
re-registered. The record is absent until one of these occurs:

- The lease reaches its T/2 renewal point (typically half the lease lifetime) and
  the client sends a proper RENEW, which triggers a normal DDNS cycle.
- A restart reconcile or scheduled sync runs.
- The log watcher's `logwatch_on_missed_remove` fires (closes the gap in ~10s).

The gap is therefore **not permanent** — it is bounded by at most half the lease
lifetime. But on a network with long leases (24h is common), that can mean many
hours without a working forward or reverse record for an active device.

**Does `ddns-update-on-renew` fix this?** Partially. `update-on-renew: true` causes
`kea-dhcp-ddns` to send a DDNS update on lease renewals. However, LEASE_REUSE
specifically bypasses the renewal path — no database write, no renewal event — so
`update-on-renew` may not cover it. Production testing has confirmed the gap can
still occur with `update-on-renew` enabled. The log watcher's missed-remove detection
is the most reliable plugin-side mitigation.

### What drifts without each layer

| Scenario | Covered by |
|---|---|
| Unbound flushes records on restart | Layer 1 (restart reconcile) |
| Kea restarts and lease state changes | Layer 1 (restart reconcile) |
| New lease issued in real time | Layer 2 (live DDNS) |
| Lease released explicitly by client | Layer 2 (live DDNS) + Layer 4 release purge |
| `kea-dhcp-ddns` was down when lease was issued | Layer 3 (scheduled sync) |
| DDNS update SERVFAIL'd due to lock contention | Layer 2 dirty-drain + Layer 4 SERVFAIL resync |
| LEASE_REUSE: Remove fired, Add skipped | Layer 4 missed-remove, or Layer 3, or T/2 renewal |
| Lease expired naturally, no DHCPRELEASE | Layer 3 (scheduled clean) only |
| Reservation removed from Kea config | Layer 1 (next restart) or Layer 3 (sync + clean) |

---

## Live Path Performance — `list_local_data` Call Budget

The daemon's live NCR path (`process_update`) needs to read the current Unbound
state for two purposes: **collision detection** (is this FQDN already mapped to a
different IP?) and **dual-stack preservation** (what other-family records exist for
this name so we can restore them after a remove-all?). Both are served by
`unbound-control list_local_data`, which returns all local_data and is then filtered
in-process.

Spike R5 measured `list_local_data` at **9–15 ms** on a 446-record box. The live
path must reply to each NCR within 500 ms (Kea's hardcoded ACK timeout), so this
is real but bounded overhead.

### Per-NCR `list_local_data` call count

`process_update()` fetches `list_local_data` once at the top and caches the output
as a plain string. Every read within the call — collision checks, other-family
preservation, sibling guards — filters that string in-process. The result is always
**1 call per DNS UPDATE**, regardless of collision policy or NCR type.

| NCR type | Policy | list_local_data calls |
|---|---|---|
| ADD A/AAAA | `allow` | **0** — no collision check, no other-family read needed |
| ADD A/AAAA | `first_wins` / `last_wins` | **1** |
| ADD PTR | `allow` | **0** |
| ADD PTR | `first_wins` | **1** — forward A/AAAA lookup to detect PTR conflict |
| ADD PTR | `last_wins` | **0** — PTR adds are always accepted |
| DELETE A/AAAA | any | **1** — always needs other-family siblings to preserve them |
| DELETE ANY | any | **1** |

The snapshot is fetched once before any mutation, giving a consistent pre-mutation
view. It is skipped entirely when `allow` policy is in use and the message contains
no deletes — the only case where no Unbound reads are needed at all.

### Worst-case latency

One snapshot at 15 ms plus 1–3 mutation calls (local_data_remove, local_data) at
~5 ms each gives roughly **25–35 ms** end-to-end — well inside the 500 ms budget
even at 10× the measured record count.

### Future optimization note

If `list_local_data` latency grew (very large Unbound datasets, slow control socket),
the next step would be to maintain an **in-memory forward map** in the daemon,
updated by every mutation and invalidated on BLOCKED→NORMAL (when a reconcile
runs). This would reduce the snapshot cost to a dict lookup.

---

## Unbound `local_data_remove` Memory Growth

Unbound does not immediately free the memory for a name removed via
`local_data_remove` — the removed entry can persist in Unbound's internal
allocator pools until the next full reload. On installations with high lease
churn (many clients obtaining and releasing addresses over hours or days), this
can cause steady Unbound RSS growth.

### Practical impact

On typical home/small-office networks with tens to low hundreds of DHCP clients
and moderate turnover, RSS growth is negligible — Unbound's allocator pools are
small and well-bounded. This becomes material only on networks with hundreds of
clients and daily lease cycles.

### What the plugin does to minimize removes

The live path and sync path both avoid unnecessary `local_data_remove` calls:

- **Sync path** (`kea-sync.py`): when replacing a record with a new IP under
  `first_wins` / `last_wins`, it removes only the PTRs for IPs that are actually
  being replaced (`existing - {new_ip}`), not the new IP's PTR (which is
  immediately re-added).

- **Live path** (`process_update`): same — the `last_wins` collision handler
  removes PTRs only for `conflict_ips` (the old IPs that lose), not for the
  incoming `rdata` IP. This avoids the earlier remove+readd cycle for the new
  IP's PTR that was present in an older code version.

- **Stale-clean** (`--clean-stale`, `local-data-clean.py`): the remove+restore
  dance for partially-stale names (valid A, stale AAAA) is unavoidable since
  `local_data_remove` is name-scoped, not record-scoped. But clean sweeps are
  infrequent (daemon startup or manual trigger).

### If memory growth becomes a concern

The recommended mitigation on Unbound ≥ 1.17 is `local-zone` with
`local-data-limit`; on older Unbound, a periodic `unbound-control reload` (which
flushes all local_data — the daemon's reconcile re-populates it immediately after)
is the bluntest but most effective tool. A future daemon option for scheduled
periodic reconcile+reload is tracked in the Someday/Maybe list in CLAUDE.md.

---

## Known Limitations Summary

| Limitation | Notes |
|---|---|
| **SLAAC addresses** | Not supported by design — Kea never sees SLAAC clients |
| **DDNS suffix staleness** | Changing `ddns-qualifying-suffix` leaves old-suffix records until leases expire. Not auto-detectable; see section above |
| **Shared-network-level reservations** | `shared-networks[].reservations[]` (not inside a child subnet) are silently ignored. Subnet-level reservations inside shared networks work correctly |
| **DDNS for shared-network subnets** | Not end-to-end tested via a live DHCP exchange; verified via the sync path only |
| **Clients without hostnames** | No DNS record is created — override flags only act when the client supplies a name. Use `ddns-replace-client-name` + `ddns-generated-prefix` in manual config mode; see section above |
| **`ddns-override-no-update` N-bit** | The sync path does not respect a client's explicit opt-out. If the lease has a hostname, it is synced |
| **IA_TA and IA_PD leases** | Explicitly blocked. Only IA_NA (type 0) produces DNS records |
| **Generated names after restart** | Kea stores the original client name in the lease, not the generated one. The sync path cannot restore generated-name records after an Unbound restart |
| **Multiple `ip-addresses` in DHCPv6 reservations** | Fully supported — one AAAA + PTR per address |
| **TSIG authentication** | Partially implemented in the daemon; deferred indefinitely — see README.md |
| **Magic FQDNs and Happy Eyeballs** | Magic FQDNs are family-scoped: a dual-stack device in a collision gets separate A-only and AAAA-only magic names. No single magic FQDN carries both record types. Use the bare hostname for application traffic; magic names are for collision identification only |
| **LAA tagging on IPv6** | LAA detection requires reading the MAC, which is not directly available from DUIDs without parsing DUID-LLT/LL structure. v1 applies LAA tagging to `hw-address` entries only; DUID-identified entries are never tagged regardless of whether the underlying MAC is locally administered |
| **Cross-family collision detection** | Collision detection is per address family. Two physical devices each claiming the same hostname via DHCPv4 and DHCPv6 respectively are not detected as a collision and receive no magic names |
