# Kea DDNS Subnet Override Options — Design Notes & Test Plan

> Internal working notes for the os-kea-unbound DDNS testing exercise.
> Companion results file: `kea-ddns-test-results.md` (produced by the test runs).
> Started 2026-06-05. Test rig: `dev-opnsense` + `dev-dhcpclient` (creds `dev`/`dev`).

## Insights & Lessons Learned (read this first)

**What these tests actually are.** The three override flags + conflict-mode are decided
entirely by **Kea** (and the OPNsense→Kea config translation) *before* our daemon is involved
— the listener just executes the RFC 2136 update it receives. So Groups 1–3 are
**conformance tests of Kea + the OPNsense model wiring**, not tests of the plugin's own logic.
They were still worth running because the OPNsense wiring for these fields was "Not tested in
v0.9," and they surfaced real operational interactions (below). The plugin's *own* logic gets
stressed in the deferred **listener round** (malformed/oversized RFC 2136, client-name →
`unbound-control` injection, same-FQDN collisions, and `conflict-resolution-mode` — which only
does anything if our listener honors RFC 2136 prerequisites/DHCID).

**Biggest finding — lease caching gates `update-on-renew`.** Kea 3.0 runs with
`cache-threshold: 0.25` by default (it is NOT written into the generated `kea-dhcp4.conf`;
only visible via `config-get` on the control socket). A renewal arriving within
`0.25 × valid-lifetime` is *reused* (`DHCP4_LEASE_REUSE`) and triggers **no DDNS at all** — so
`update-on-renew` can only refresh DNS on renewals that fall *outside* that window. With the
default 4000s lease that window is **1000s (~17 min)**; a typical T1 renewal at 50% of lifetime
(2000s) is outside it, so it works — but this MUST be documented, especially for anyone using
short lease times or relying on frequent renewals for self-healing.

**Recommended posture for this unbound-bridge deployment** (to document in README + GUI help +
`kea-dhcp.md`): **`override-client-update = ON`** (no DDNS server for an `S=0` client to
self-register against, so honoring it leaves no A record), **`override-no-update = ON`**
(visibility policy — every device resolvable on a trusted LAN), **`update-on-renew = ON`**
(self-heal the volatile unbound `local_data`, subject to the cache-window caveat above).
`conflict-resolution-mode = check-with-dhcid` (default) until the listener round validates the
alternatives. Constraint to enforce/warn in the UI: **`override-no-update` implies
`override-client-update`** — the `(ONU=1, OCU=0)` combination is incoherent (see C4).

**Known gap:** the override flags only act when the client supplies a name. **Nameless
clients** (MAC-randomizing phones, no option 12/81) bypass all three — would need
`ddns-generated-prefix` + `ddns-replace-client-name`. (See G1.)

**Operational gotchas (also methodology):**
- **Two-step apply:** `configctl kea restart` regenerates the PHP-model confs, but the FIRST
  D2 enable also needs `configctl template reload OPNsense/Kea` to render
  `keactrl.conf dhcp_ddns=yes`. Per-test flag toggles need only `kea restart`.
- **Boolean semantics:** generation uses `!isEmpty()` → OFF = empty tag `<x/>`, ON = `<x>1</x>`.
- **Reverse PTR requires `ddns_reverse_zone` set explicitly** (no auto-derivation in D2 gen).
- **`configctl kea restart` runs the plugin's lease-sync hook** → it re-registers ACTIVE
  leases in DNS. Use a unique (MAC, IP, name) per test and delete leases before restart.
- **Reverse lookups:** use `drill @127.0.0.1 <reversed-name> PTR`, NOT `drill -x` (false
  NXDOMAIN from unbound's RFC6303 `static` private-reverse zones). Authoritative cross-check:
  `unbound-control -c /var/unbound/unbound.conf list_local_data`.
- **Lease caching** (`cache-threshold` 0.25 default) — verify a renewal is genuine via the Kea
  log (`DHCP4_LEASE_ALLOC` with NO following `DHCP4_LEASE_REUSE`); shorten `valid-lifetime` for
  renewal tests.

## 1. Background: how DHCPv4 DDNS divides the work

A DHCP lease can drive two DNS records:

- **Forward `A`** — name → IP
- **Reverse `PTR`** — IP → name

The server always knows the IP, so **the server always owns the PTR**. Ownership of the
**`A` record is negotiable**, expressed by the client via the **FQDN option (81)** flags:

| Flag | Meaning |
|---|---|
| **`S` (Server)** | `S=1`: "server, please do my forward `A` update." `S=0`: "I, the client, will do my own `A`." |
| **`N` (No-update)** | `N=1`: "do no DNS updates at all." When `N=1`, `S` is moot. |
| **`O` (Override)** | Set by the **server in its reply** to signal "I overrode what you asked." |
| **`E` (Encoding)** | Canonical wire format vs ASCII. |

The older **Hostname option (12)** has no S/N flags, so a hostname-only client is treated
as `S=1` (server does both records).

### Baseline behavior (all override options OFF, a name present, `ddns-send-updates` on)

| Client sends | Intent | Server writes | Reply |
|---|---|---|---|
| FQDN `S=1, N=0` | "server, you do the A" | **A + PTR** | `S=1` |
| FQDN `S=0, N=0` | "I'll do my own A" | **PTR only** | `S=0` |
| FQDN `N=1` | "no DNS at all" | **nothing** | `N=1` |
| Hostname (12) only | (no S/N) | treated `S=1` → **A + PTR** | — |
| No name | — | **nothing** (default `replace-client-name=never`) | — |

Everything the three options do is a deviation from this table.

## 2. The three subnet-scope options

Each override flag is **surgical** — it rewrites exactly one row of the baseline table.

### `ddns-override-no-update` (ONU) → the **N** flag

- **Operation:** ignore client `N=1`; do updates anyway. Reply flips to `N=0, S=1, O=1`.
- **Why:** authoritative DNS hygiene / visibility — every lease resolvable regardless of
  client wishes (reverse lookups, monitoring, logs, ACLs).
- **Caveat:** most aggressive option; overrides an explicit opt-out. A *policy* choice.
- **Touches only the `N=1` row.**

### `ddns-override-client-update` (OCU) → the **S** flag

- **Operation:** ignore client `S=0`; server performs the forward `A` itself. Reply flips
  to `S=1, O=1`.
- **Why:** single source of truth for forward records. Client self-updates often fail (no
  TSIG creds, wrong zone, NAT) and leave no/stale `A`. Forcing server ownership keeps them
  consistent and lifecycle-managed.
- **Critical limit:** overrides **only the `S` flag, never `N=1`.** A client saying "no
  updates" is still honored unless `ONU` is also set.
- **Touches only the `S=0` row.**

### `ddns-update-on-renew` (UOR) → the **timing** axis (orthogonal)

- **Operation:** redo the DNS update on lease **renewal**, not just on new allocation /
  changed FQDN. Default Kea skips DDNS on a plain renewal.
- **Why (esp. here):** resilience against DNS drift. If records vanish out-of-band, default
  behavior waits until the next *new* lease to repair. UOR re-asserts on every renewal
  (~T1, half lease time) — self-healing. **Directly relevant to our pipeline** because the
  unbound `local_data` store is not guaranteed persistent across an unbound restart.
- **Cost:** every renewal emits a redundant `CHG_ADD` NCR — negligible at homelab scale.
- **Changes *when* the Table-1 action re-fires, never *what* it does.**

## 3. How they interact

The two override flags are **orthogonal axes** — one governs `N`, the other governs `S`.

| ONU (N) | OCU (S) | Meaning | Verdict |
|---|---|---|---|
| 0 | 0 | Honor client fully | ✅ coherent |
| 0 | 1 | Take over A from self-managing clients, but honor a total opt-out | ✅ coherent |
| **1** | **0** | Override the **strong** opt-out (`N=1`) but honor the **weak** one (`S=0`) | ❌ **incoherent** |
| 1 | 1 | Force complete A+PTR for everyone | ✅ coherent (most authoritative) |

**The `(ONU=1, OCU=0)` corner should be impossible as a policy:** `N=1` is a *stronger*
opt-out than `S=0`, so overriding the strong one while honoring the weak one is backwards.
Rule of thumb: **`ONU=1` should imply `OCU=1`.**

**Kea does NOT enforce this**, and OPNsense likely won't either — so the inverted behavior
is reachable on a live network. We test it explicitly to document the real outcome.

`update-on-renew` composes freely with all four override combos (it's the timing axis), so
of the 8 total combinations, the 2 incoherent ones are `(ONU=1, OCU=0)` × {UOR off, on}.

### Gating / scope
- All gated by `ddns-send-updates` (off ⇒ nothing happens).
- Subnet-scope values must override global — to be confirmed during testing.

## 4. Recommended posture for THIS environment (unbound bridge, no formal DDNS server)

| Option | Recommend | Rationale |
|---|---|---|
| **OCU** | **ON** | There is no DDNS server for an `S=0` client to self-register against — the only path to DNS is the Kea→D2→unbound bridge. Honoring `S=0` would leave the client with **no forward A at all**. Technically well-motivated. |
| **ONU** | **ON** | Visibility *policy*: on a trusted management LAN we want every device resolvable/loggable regardless of request. More opinionated than OCU; consistent with "ONU implies OCU." |
| **UOR** | **ON** | unbound `local_data` not guaranteed persistent → re-assert on renewal for self-healing. |

**TODO once tests confirm behavior:** document these recommended settings in the plugin
**README**, the **web GUI** help text / tooltips on the ddns subnet form, and repo docs
(`network/opnsense/kea-dhcp.md`).

### Known gap: nameless clients
`ONU`/`OCU` only force a record when the client supplies a **name**. The genuinely stealthy
pattern is *omission* — MAC-randomizing phones (iOS/Android) and privacy-hardened clients
send **no option 12 / 81 at all**, so there's nothing to build an `A` from. (Explicit `N=1`
is visible, not stealthy.) Catching nameless clients needs `ddns-generated-prefix` +
`ddns-replace-client-name` (`always`/`when-not-present`) to *synthesize* a name — a separate
lever, out of scope for these three options. We are currently observing nameless-client
behavior in our environment, so this is on the deferred list to test.

## 5. Test nature & scope

This exercise is **functional / conformance testing** — "does observed behavior match the
documented behavior for each flag and combination." It is **not** fault-injection or
security testing:

- Every flag combination is a valid, supported Kea code path; Kea validates `ddns-*` config
  at load, so flipping these cannot crash the daemon.
- The incoherent `(1,0)` corner is a legal config with a *policy* inconsistency, not a fault.
- All client vectors are well-formed, legal DHCP.

### Deferred to a later LISTENER test round (NOT this matrix)
- Client-controlled FQDN/hostname → `unbound-control local_data` **sanitization / injection**
  check. (Partial mitigation already considered: the listener parses RFC2136 with a
  well-tested Python library — **dnspython** — not hand-rolled parsing.)
- Listener handling of **malformed / oversized / unauthenticated** RFC2136 updates on `:53535`.
- **Hostname path:** two clients claiming the **same FQDN** (collision); full options/flags/
  behavior when **no hostname** is provided.
- **`ddns-conflict-resolution-mode`** (4 options: `check-with-dhcid` [default],
  `no-check-with-dhcid`, `check-exists-with-dhcid`, `no-check-without-dhcid`). Deferred here
  because its observable effect runs through RFC2136 **prerequisites** D2 sets — and whether
  those do anything depends on whether **our bridge honors prereqs** (a listener behavior),
  and it's inseparable from the same-FQDN collision test. During this round, **pin
  conflict-resolution-mode to its default and record it as a controlled constant**; use
  distinct FQDNs/MACs per vector (or fully clear records between tests) so conflict logic
  doesn't confound override-flag results.

## 6. Client stimulus (test vectors)

Driven from **dev-dhcpclient**, primary tool **scapy** for precise option-81 flag-byte
control (`[flags][rcode1][rcode2][fqdn]`); `dhclient`/`dhcpcd` as fallback.

| ID | Client sends |
|---|---|
| **V-S1** | FQDN `S=1, N=0` — "server, please update" |
| **V-S0** | FQDN `S=0, N=0` — "client will do the A" |
| **V-N** | FQDN `N=1` — "no updates" |
| **V-H** | Hostname option (12) only |
| **V-none** | no name (baseline / nameless gap) |

Each vector uses a dedicated test MAC + fixed requested IP. **Distinct FQDNs per vector** to
avoid conflict-resolution confounding.

## 7. Test matrix

**`ddns-override-no-update`**
- T1a (OFF, control) · V-N → expect **no records**
- T1b (ON) · V-N → expect **A + PTR**, reply `N=0, S=1, O=1`
- T1c (ON) · V-S1 → no regression, normal update

**`ddns-override-client-update`**
- T2a (OFF, control) · V-S0 → expect **PTR only**, reply `S=0`
- T2b (ON) · V-S0 → expect **A + PTR**, reply `S=1, O=1`
- T2c (ON) · V-N → expect **no records** (proves it does NOT override N)

**`ddns-update-on-renew`**
- T3a (OFF, control): DORA creates record → delete record out-of-band from unbound → RENEW
  → expect record **not** recreated
- T3b (ON): same setup → RENEW → expect record **recreated**

**Interactions**
- C1: ONU + OCU both ON → V-S0 forwards **and** V-N updates (both active)
- C2: UOR + OCU ON → V-S0, then renew → server-side forward update persists across renew
- C3: OCU ON · V-S1 → confirm no spurious O flag / correct record
- **C4 (incoherent corner):** ONU=ON, OCU=OFF → fire **both** V-N and V-S0 → document the
  inversion (N-client gets full update, S0-client gets only PTR); note whether OPNsense UI
  even lets you reach this state

**Gap probe**
- G1: V-none under recommended ON/ON/ON → confirm nameless client gets **no record**
  (documents the generated-prefix gap)

## 8. Per-test execution loop

1. **Reset state:** delete the test MAC's lease in Kea; `unbound-control local_data_remove`
   any stale A/PTR.
2. **Edit config** on dev-opnsense (subnet ddns fields) → reload Kea via configctl.
   - *Open item:* confirm whether the three fields are model-backed in `/conf/config.xml`
     (survive template regen) or must be set in the generated `kea-dhcp4.conf` + restarted
     via `service kea-dhcp4 restart` (no regen).
3. **Arm observation** (tail in parallel):
   - `kea-dhcp4` DEBUG (`kea-dhcp4.ddns`, `.dhcpsrv`) — lease + whether/which NCR queued
   - `kea-dhcp-ddns` (D2) — NCR received, forward/reverse change, RFC2136 send result
   - **kea-unbound-ddns** daemon (`kea-ub` tag, `/var/log/keaunbound/`) — RFC2136 in → local_data
   - `tcpdump` on dev-dhcpclient — capture OFFER/ACK
4. **Fire** the DHCP exchange from dev-dhcpclient with the chosen vector.
5. **Capture evidence:** returned option-81 flags (S/O/N) in the ACK; `dig @<unbound> <fqdn> A`;
   `dig @<unbound> -x <ip> PTR`; `unbound-control list_local_data | grep`.
6. **Record** result vs expectation → mark desired / undesired.
7. **Restore baseline** before next test.

## 9. Phase 0 — environment discovery (before running the matrix)

- Log into dev-opnsense; confirm the os-kea-unbound package is the **latest build** and the
  DDNS chain is live: D2 (`kea-dhcp-ddns`) running, listener on `:53535`, forward + reverse
  zones configured for the dev subnet.
- Confirm dev-dhcpclient is L2-adjacent to the dev subnet; install/verify scapy.
- Map dev subnet/pool, DNS domain + reverse zone, safe block of test IPs/MACs.
- Resolve the config-edit mechanism (config.xml model-backed vs generated conf) — see step 2.
- Record the in-effect `ddns-conflict-resolution-mode` as the controlled constant.

## 10. Phase 0 findings (dev-opnsense, 2026-06-05)

**Box:** OPNsense 26.1.9, user `dev` in `wheel`, passwordless sudo. `kea-3.0.3`,
`os-kea-unbound-0.9` (= source version, repo `/Users/tkr/code/os-kea-unbound` @ main, clean),
`unbound-1.25.1`, `py313-dnspython` present.

**Chain state = NOT live yet:**
- kea-dhcp4 running (subnet `192.168.1.0/24`, iface `lan`/em1, pool .100–.200, domain
  `plhm.rgn.cm`, `match-client-id: true`). Its generated conf has **no `dhcp-ddns` block**.
- **D2 (kea-dhcp-ddns) INACTIVE**; its conf is the stock sample (port 53001, empty domains).
- Plugin listener `kea-unbound-ddns` **running** (pid from manual start); 7 configd actions
  registered. Plugin config node `<KeaUnbound>` is **empty → plugin "enabled"=default 0**
  (per model: when disabled, daemon doesn't auto-start and cron/sync/clean hooks are no-ops;
  the listener is up only because it was started manually).

**Config model facts (the edit targets):**
- `<Kea><ddns><general>`: `enabled` (0→1 to start D2), `server_ip` 127.0.0.1, `server_port`
  **53001** = the dhcp4→D2 NCR channel (NOT the RFC2136 target).
- Per-subnet (`<Kea><dhcp4><subnets><subnet4 uuid=...>`): the RFC2136 target + behavior.
  Model `KeaDhcpv4.xml` HAS all fields (forward_zone, reverse_zone, qualifying_suffix,
  dns_server, dns_port, override_no_update, override_client_update, **update_on_renew**,
  **conflict_resolution_mode**, TSIG). The persisted config.xml is an older model version so
  several tags are absent until written — add them directly.
- **Boolean semantics:** generation uses `!isEmpty()`, so **OFF = empty tag `<x/>`, ON = `<x>1</x>`.**
  `ddns-send-updates` is auto-true simply by setting `ddns_dns_server`.
- **D2 config is PHP-generated** by `KeaDdns::generateConfig` (not a .tpl). It emits a
  forward-ddns domain per subnet that has BOTH `ddns_forward_zone` and `ddns_dns_server`, and
  a reverse-ddns domain **only if `ddns_reverse_zone` is non-empty** → **reverse zone MUST be
  set explicitly for PTR tests.** dns-servers point at `ddns_dns_server:ddns_dns_port`.
- Reload/restart: `configctl kea restart` (verify it regenerates D2 conf + starts D2).

**Planned setup values (dev subnet 192.168.1.0/24):**
- forward zone `plhm.rgn.cm.` (trailing dot — required, else D2 silently drops updates)
- reverse zone `1.168.192.in-addr.arpa.` (trailing dot)
- qualifying suffix `plhm.rgn.cm`
- dns server `127.0.0.1`, dns port `53535`
- overrides all OFF initially; conflict mode default (`check-with-dhcid`)

**Test-hygiene decisions:**
- Keep the plugin's scheduled **sync + auto-clean OFF during the flag tests** (leave plugin
  `enabled`=0 with the listener daemon running) so the ONLY thing creating/removing records is
  the DDNS dynamic path under test — otherwise lease-sync could re-register the record and mask
  attribution. Full plugin enable is the production step, done after the matrix.
- OFF = empty tag, ON = `1` (per `!isEmpty()` logic above).
- Distinct MAC + FQDN per vector; pin conflict-mode to default as a controlled constant.

## 11. Phase 0 RESULTS — chain wired + apparatus validated (2026-06-05)

**Setup applied to dev-opnsense** (config.xml backup at `/conf/config.xml.bak-ddns-*`):
- `<Kea><ddns><general><enabled>` → `1`; subnet `192.168.1.0/24` DDNS fields set
  (forward `dev.plhm.rgn.cm.`, reverse `1.168.192.in-addr.arpa.`, suffix `dev.plhm.rgn.cm`,
  server `127.0.0.1:53535`, overrides empty/OFF, conflict default).
- **Two-step apply learned:** `configctl kea restart` regenerates the PHP-model configs
  (kea-dhcp4.conf, kea-dhcp-ddns.conf) but NOT the `.tpl` `keactrl.conf`/`rc.conf.d` that gate
  which daemons keactrl starts. To start D2 the first time, run
  **`configctl template reload OPNsense/Kea`** (renders `dhcp_ddns=yes`) THEN
  `configctl kea restart`. For later per-test FLAG toggles, only `configctl kea restart` is
  needed (override booleans live in kea-dhcp4.conf, PHP-generated).
- Result: kea-dhcp4 active (DDNS enabled), **D2 active** (pid, NCR channel 127.0.0.1:53001),
  listener up (127.0.0.1:53535).

**Smoke test PASSED (V-S1, cooperative):** scapy DORA from dev-dhcpclient `ens19`
(MAC 02:00:00:00:00:01, name test1.dev.plhm.rgn.cm, req .150) → assigned 192.168.1.150,
ACK FQDN flags **S=1,O=0,N=0**. End-to-end verified: `host test1.dev.plhm.rgn.cm 127.0.0.1`
→ A 192.168.1.150; reverse → PTR test1.dev.plhm.rgn.cm. Listener log + D2 log both show the
add (CHG_ADD success).

**dev-dhcpclient:** Debian 13, iface **ens19 = 192.168.1.100/24** (L2-adjacent to Kea subnet;
avoid requesting .100). scapy 2.6.1 + dnsutils installed. sudo needs password (`dev`).
Harness `/tmp/ddns_test.py` (also kept in repo, see below): crafts option-81 with exact
S/O/E/N flag bytes (canonical E=1, wire-format FQDN), does DORA or RENEWING-state request,
prints assigned IP + reply FQDN flags as JSON. Run as root: `echo dev | sudo -S python3 ...`.

**Validated per-test loop:**
1. Edit override booleans in config.xml (OFF=`<x/>`, ON=`<x>1</x>`) for the test.
2. `configctl kea restart` (applies flags; NOTE its kea_sync hook lease-syncs ACTIVE leases
   into DNS — so use a UNIQUE (MAC, IP, name) per test and clean up leases after each test).
3. Post-restart clean slate for this test's tuple: `configctl kea delete lease <ip>` +
   `unbound-control -c /var/unbound/unbound.conf local_data_remove <fwd>` and `<ptr>`.
4. Fire from dev-dhcpclient: `sudo python3 /tmp/ddns_test.py --iface ens19 --mac <m>
   --mode fqdn|hostname|none --flags S|N|SN --name <n> --req-ip <ip>` (or `--renew --lease-ip`).
5. Observe: harness JSON (ACK S/O/N) + on dev-opnsense `host <n> 127.0.0.1` (fwd) and
   `host <ip> 127.0.0.1` (PTR) + `sudo grep <n> /var/log/keaunbound/latest.log` +
   `sudo grep -iE "DHCP_DDNS_ADD|DDNS" /var/log/kea/latest.log` (D2 NCR success / absence).
6. Record result vs expectation → desired/undesired. Clean up lease + records.

**Logs:** kea daemons (dhcp4 + D2) → `/var/log/kea/latest.log`; listener (`kea-ub`) →
`/var/log/keaunbound/latest.log`. `host`/`drill` against 127.0.0.1 is the reliable record
check (NOT `unbound-control` without `-c /var/unbound/unbound.conf`).
