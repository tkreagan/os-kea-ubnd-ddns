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
