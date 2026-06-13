# Advanced Topics

Developer and operator reference for edge cases, known limitations, and
non-obvious behavior in the kea-unbound plugin. Covers IPv6/DHCPv6 specifics,
dual-stack coexistence, DNS suffix lifecycle, and configuration options with
subtle effects on the live and sync paths. Companion to
`kea-ddns-options-reference.md`.

---

## DHCPv6 Lease Types — What Gets Processed

Kea DHCPv6 has three lease types. The plugin explicitly filters on the `type`
field returned by `lease6-get-all` and stored in `kea-leases6.csv`:

| Type | Name | Processing |
|------|------|------------|
| 0 | IA_NA (Non-temporary Address) | **Processed.** Standard host address. Produces AAAA and PTR records. |
| 1 | IA_TA (Temporary Address) | **Blocked.** Temporary addresses are not intended for stable DNS entries. |
| 2 | IA_PD (Prefix Delegation) | **Blocked.** The "address" field is a network prefix, not a host address. Registering it would produce a semantically wrong AAAA pointing to the prefix's zero address. |

The filter is in `_normalize_raw_lease()` in `lib/keaunbound_sync.py`. Any lease
with `type != 0` returns `None` immediately, before hostname or IP validation.

**Why IA_TA?** IA_TA is essentially unused in production — SLAAC privacy
extensions (RFC 4941) replaced it. Blocking it explicitly is defensive coding
and documents the intent: only stable host addresses get DNS records.

**Why IA_PD?** The Kea lease record for a delegated prefix contains the prefix's
network address (e.g., `fd01::` for a `/60` delegation) in the `ip-address`
field. `reverse_ptr("fd01::")` returns a valid `ip6.arpa` name, so without the
filter a PD lease with a hostname would register `hostname AAAA fd01::` — the
prefix address, not any host on that prefix. PD leases typically have no hostname
anyway (the `hostname` check would also skip them), but the type guard is
explicit defense-in-depth.

---

## DHCPv6 Reservations — Multiple Addresses Per Reservation

Unlike DHCPv4, where a reservation has exactly one `ip-address`, a DHCPv6
reservation can carry multiple addresses in `ip-addresses: [...]`. A client can
hold multiple IA_NA addresses simultaneously (via multiple IA_NA IAs in a single
exchange).

The plugin handles this correctly: `query_kea_reservations("dhcp6")` emits one
result dict per address entry. A reservation with two addresses produces two
`{"hostname": "host.example.com", "ip": None, "ipv6": "..."}` entries, each of
which gets its own AAAA record and synthesized PTR.

This is implemented as a loop over `res.get("ip-addresses") or []` in
`query_kea_reservations()`, replacing the earlier `addrs[0]` that silently
dropped all but the first address.

**Collision policy applies per-address within the same family.** Two AAAA
records for the same hostname from one reservation are both written under
`allow` policy. Under `first_wins` / `last_wins`, the collision logic is
per-FQDN within one family — if both addresses map to the same FQDN, only one
wins. This is the same collision behavior as two leases for the same hostname.

---

## IPv6 PTR Records — Encoding and Parsing

IPv6 PTR records use the `ip6.arpa` zone with a 32-nibble reversed encoding.
Each nibble (4-bit hex digit) of the full 128-bit address becomes a single DNS
label, reversed, then `.ip6.arpa` is appended.

```
fd00::1ab
  → expanded:  fd00:0000:0000:0000:0000:0000:0000:01ab
  → all hex:   fd000000000000000000000000001ab
                                                   wait, expand properly:
  fd00:0000:0000:0000:0000:0000:0000:01ab
  nibbles: f d 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 a b
  reversed: b a 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 d f
  result: b.a.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa
```

The result is a 63-character owner name (32 single-character labels + `.ip6.arpa`).

**In code:** `ipaddress.ip_address(addr).reverse_pointer` in Python generates
this correctly for any valid IPv6 address regardless of input format (compressed,
expanded, mixed-case). This is the canonical source of PTR names throughout the
plugin — do not hand-roll this calculation.

**Decoding arpa → IP:** The function `_arpa_to_ip(ptr_name)` in
`lib/keaunbound_sync.py` reverses this: splits on `.`, reverses the 32 nibbles,
groups into 4-nibble words, joins with `:`, and normalizes via
`ipaddress.ip_address()`. The result is always Python's compressed canonical
form (e.g., `fd00::1ab`, not `fd00:0000:...:01ab`). This is the same form Kea
uses in its lease and reservation data, so comparisons are safe.

**`list_local_data` output format:** `unbound-control list_local_data` returns
AAAA rdata in compressed form and PTR owner names in full 32-nibble form. The
plugin's `unbound_list_local_data()` parser reads both correctly because it uses
`parts[4]` for the AAAA rdata (the compressed IP) and the owner name (full arpa)
as the dict key.

**`_arpa_to_ip` is the single canonical implementation.** It lives in
`lib/keaunbound_sync.py` and is imported by both `kea-unbound-ddns.py` and
`local-data-audit.py`. Do not add local copies.

---

## Dual-Stack Hosts — A and AAAA Coexistence

A host can simultaneously hold a DHCPv4 lease (→ A record) and a DHCPv6 lease
(→ AAAA record) for the same FQDN. The plugin is designed to preserve both.

**Collision policy is family-scoped.** The sync path uses `forward_ips_by_type()`
to build separate A-only and AAAA-only snapshots of Unbound's current state.
Collision checks for A records never compare against AAAA records and vice versa.
A DHCPv4 reservation for `host.example.com` does not block a DHCPv6 lease for
the same name — they are in separate families and both are written.

**Reservation claims are also family-scoped.** In a full sync, the static pass
populates `claims["A"]` (from dhcp4 reservations) and `claims["AAAA"]` (from
dhcp6 reservations) independently. The dynamic pass checks claims only within the
same family, so a v4 reservation winning a name does not prevent a v6 lease from
being written for that name.

**`local_data_remove` removes all families at once.** Unbound's `local_data_remove
name` wipes ALL rrsets for that owner name — A, AAAA, and anything else. Any
code path that removes a forward name must restore the surviving family:

- **Daemon live DELETE path:** `process_update()` in `kea-unbound-ddns.py` reads
  the other family via `query_unbound(name, other_type)` before removing, then
  restores it after. This handles both "DELETE A, preserve AAAA" and the reverse.
- **Sync path `_collect_writes`:** emits `local_data_remove name` only when
  replacing a winner with a different IP in the same family. The other family is
  unaffected because the removal is immediately followed by the new add, and
  unbound treats an add for an existing rrset as idempotent.
- **Bulk clean `clean_stale_records`:** groups stale (name, ip) pairs by name,
  calls `local_data_remove` once, then re-adds all non-stale records. For a host
  with a valid A and stale AAAA, the A is re-added after the bulk remove.

**Staleness is per (name, ip) pair, not per name.** `find_stale_records()` in
`lib/keaunbound_sync.py` returns a set of `(name, ip)` tuples, not a set of
names. A dual-stack host with a valid A and a stale AAAA produces exactly one
stale pair — `(name, stale_ipv6)` — without touching the A record. The stale
AAAA's PTR is correspondingly orphaned and cleaned up by the PTR pass.

---

## Live NCR Path — Tested ✅ (June 2026)

A real `dhclient -6` exchange on dev-dhcpclient triggered the full path:
- DHCPv6 SOLICIT → ADVERTISE → REQUEST → REPLY from kea-dhcp6
- D2 sent a forward NCR → listener registered `kea6host-fd00--102.dev.plhm.rgn.cm AAAA fd00::102` (latency 29ms)
- Listener synthesized PTR from the forward NCR
- D2 also sent a reverse NCR for the same PTR (handled as idempotent double-write)

The generated hostname (`kea6host-fd00--102`) is the `ddns-generated-prefix` default
in the test config — the client sent no FQDN option (option 39). This also confirms the
live path correctly handles Kea-generated names for nameless IPv6 clients.

---

## SLAAC — Not Supported (Intentional Non-Goal)

IPv6 addresses assigned by SLAAC (Stateless Address Autoconfiguration, RFC 4862)
are invisible to this plugin. SLAAC clients derive their addresses from the
network prefix advertised by `radvd` — they never talk to Kea, so no lease is
created and no DDNS update is sent. The plugin can only register what Kea tells
it about.

There is no plan to support SLAAC-sourced DNS registration. Doing so would
require intercepting RA messages or running separate neighbor-discovery
monitoring, neither of which fits this plugin's architecture.

---

## DHCPv6 Configuration Options That Affect the Plugin

Most Kea DHCPv6 options govern address assignment mechanics and have no effect
on the plugin. The ones that do matter:

### Hostname Construction (determines what FQDN lands in DNS)

- **`ddns-qualifying-suffix`** (global and per-subnet): suffix appended to bare
  hostnames from clients. Must match across subnets so that the NCR path and the
  sync path produce the same FQDNs. Per-subnet suffixes are read from Kea's
  running config via `config-get` and mapped by subnet-id.

- **`ddns-replace-client-name`**: controls whether the server uses the
  client-supplied hostname or generates one using `ddns-generated-prefix`. The
  plugin sees only the post-replacement name — it has no visibility into what the
  client originally sent. More relevant for DHCPv6 than DHCPv4 because DHCPv6
  clients less consistently send option 39 (Client FQDN).

- **`ddns-generated-prefix`** (default `"myhost"`): prefix for server-generated
  hostnames when clients don't supply one. Common in DHCPv6. Generated names pass
  `is_sane_name()` after Kea's `hostname-char-replacement` sanitizes separators.

### NCR Generation Control (determines whether updates are sent)

- **`ddns-send-updates`**: the sync path **respects this flag**. `_build_suffix_map()`
  reads `ddns-send-updates` per subnet (with shared-network and global inheritance) and
  passes a `ddns_disabled_subnets` set to `_normalize_raw_lease()`, which returns `None`
  for leases from disabled subnets. `query_kea_reservations()` applies the same check
  per source. Result: leases and reservations from a subnet with
  `ddns-send-updates: false` are excluded from kea-sync.py, local-data-clean.py, and
  local-data-audit.py — consistent with the live NCR path.

- **`ddns-override-no-update`**: if false (default), a client that sets the DHCPv6
  N-bit opts out of DDNS. The live NCR path respects this (no update is sent).
  The sync path does not — if the lease has a hostname, it is synced regardless.

- **`ddns-update-on-renew`** (default false): if false, D2 sends NCRs only on new
  leases, not renewals. TTLs in the live-path records age without refresh between
  scheduled syncs. The sync path independently computes TTL from remaining lease
  time, so periodic reconciles keep TTLs accurate.

### TTL

- **`ddns-ttl-percent` / `ddns-ttl` / `ddns-ttl-min` / `ddns-ttl-max`**: control
  the TTL in NCRs that D2 sends. The daemon applies the NCR TTL directly. The
  sync path uses `max(1, lease["expires"] - now)` (remaining lifetime) instead.
  After any reconcile, the sync-computed TTL overwrites the NCR TTL.

### Conflict Resolution

- **`ddns-use-conflict-resolution`**: Kea D2 may include DHCID prerequisites in
  the DNS UPDATE message. The daemon ignores prereqs (they are in `msg.answer`;
  the daemon processes `msg.authority`) and always returns NOERROR. Kea's
  conflict resolution is effectively bypassed — the plugin's own collision policy
  (`first_wins` / `last_wins` / `allow`) is the sole conflict mechanism.

---

## DDNS Suffix Staleness — Old Records After a Suffix Change

**What happens:** Kea writes the full FQDN into the lease record at grant time,
derived from the client-supplied hostname and the subnet's `ddns-qualifying-suffix`
at that moment. If `ddns-qualifying-suffix` is later changed, existing leases still
carry the old FQDN. When D2 sends NCRs for renewals or the sync path reads those
leases, it uses the stale FQDN — so the old-suffix DNS records remain and appear to
be backed by active leases.

**Why the plugin cannot auto-detect this:** `find_stale_records()` compares Unbound
records against Kea leases. An old-suffix record (e.g.,
`host.old.example.com → 192.168.1.100`) is backed by the lease for `192.168.1.100`,
whose `hostname` field is still `host.old.example.com`. From the plugin's perspective
the record is correct — Kea says so. The new-suffix record (`host.new.example.com →
192.168.1.100`) also exists, backed by a fresh NCR or reconcile. Both look valid.

**Why auto-remediation is not safe:** The plugin treats Kea's lease as authoritative
for the hostname. Removing a record that Kea says is valid would violate that
invariant and could delete a legitimately active name if the admin intentionally
configured two different suffixes for two different subnets.

**How it resolves over time (on its own):**
1. The client renews its lease. If `ddns-update-on-renew` is true (not the Kea
   default), D2 sends a fresh NCR with the new suffix and a REMOVE for the old one.
   With the default (`ddns-update-on-renew: false`), renewal does not trigger NCRs,
   so the old record persists for the life of the lease.
2. The lease expires. Kea's ELP queues a REMOVE NCR for the old FQDN. D2 delivers
   it and the listener removes the record.
3. The next scheduled bulk clean (`local-data-clean.py`) runs after the lease
   expires — at that point there is no Kea record to protect the old name.

**Manual remediation:** If you change `ddns-qualifying-suffix` and want immediate
cleanup without waiting for lease expiry, run:
```
configctl keaunbound sync_dynamic   # repopulates new-suffix records
unbound-control local_data_remove host.old.example.com
unbound-control local_data_remove <PTR for the old name>
```
Or trigger a full clean after deleting the old leases from Kea. There is no bulk
"remove all records for suffix X" operation.

**Configuration advice:** change `ddns-qualifying-suffix` during a maintenance
window, set `ddns-update-on-renew: true` temporarily, and wait for all clients to
renew before turning it off. This causes D2 to send REMOVE NCRs for the old suffix
as each client renews, cleaning up automatically within one lease period.

---

## Known Limitations

- **SLAAC addresses:** not supported, by design. See above.
- **DDNS suffix staleness:** changing `ddns-qualifying-suffix` leaves old-suffix
  records in Unbound for the duration of existing leases. Not auto-detectable
  because the record appears backed by an active lease. See the section above.
- **Shared-network-level reservations** (`shared-networks[].reservations[]`, not
  inside a subnet): not picked up by `query_kea_reservations()`. Subnet-level
  reservations inside shared networks work correctly.
- **`ddns-override-no-update` N-bit:** the sync path does not respect a client's
  explicit opt-out of DDNS. If the lease has a hostname, it is synced.
- **IA_TA and IA_PD leases:** explicitly blocked. See the lease type table above.
- **Multiple `ip-addresses` in DHCPv6 reservations:** all addresses are synced
  (one AAAA + PTR per address). The collision policy applies per-address within
  the same family. Covered by the `ipv6_multiple_addresses` scenario.
