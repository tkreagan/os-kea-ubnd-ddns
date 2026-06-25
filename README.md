# os-kea-ubnd-ddns

An [OPNsense](https://opnsense.org) plugin that automatically registers Kea DHCP
leases and static reservations in the Unbound DNS resolver. Hostnames resolve the
moment a lease is issued — with minimal drift between your DHCP and DNS tables.

## How it works

Four layers work together to keep Kea and Unbound in sync:

```
┌────────────────────────────────────────────────────────────┐
│  OPNsense                                                  │
│                                                            │
│  kea-dhcp4/6 ───────────────────── kea-dhcp-ddns           │
│       │                                     │              │
│       │ [Reconcile / on demand]             │ [Live DDNS]  │
│       │                                     │              │
│  Kea reservations                   RFC 2136 UPDATE        │
│  Kea active leases                          │              │
│       │                                     │              │
│       └────────► kea-ubnd-ddns ◄────────────┘              │
│                  (127.0.0.1:53535)                         │
│                         │                                  │
│                   unbound-control                          │
│                         │                                  │
│                Unbound local_data                          │
└────────────────────────────────────────────────────────────┘
```

**Layer 0 — Restart reconcile (always on):** The resident daemon watches the Kea
and Unbound service pidfiles. Whenever either service restarts — flushing Unbound's
runtime records or invalidating Kea's lease state — the daemon automatically runs a
full reconcile from Kea, repopulating Unbound without any manual intervention.

**Layer 1 — Live DDNS path (always on when kea-dhcp-ddns is running):**
`kea-dhcp-ddns` sends RFC 2136 DNS UPDATE packets to the plugin's stub listener the
moment a lease is issued or released. Each packet is immediately translated into an
`unbound-control local_data` or `local_data_remove` call — A, AAAA, and PTR records
are handled automatically.

**Layer 2 — Scheduled sync / clean (on by default):** A cron job runs a full
Kea → Unbound reconcile on a schedule (default every 6 hours). An optional stale-
record sweep can also run on the same schedule, removing Unbound entries no longer
backed by any Kea lease, reservation, or Host Override.

**Layer 3 — Log watcher (off by default):** A secondary daemon tails the Kea DHCP
log and the listener log. It reacts to three types of event: lease releases
(immediately purges the DNS records for that IP), listener SERVFAILs (triggers a
targeted resync for the affected names), and DNS removes without a follow-up add
(closes the LEASE_REUSE gap — see [Advanced Topics](ADVANCED-TOPICS.md)).

OPNsense Unbound Host Overrides and "Register DHCP Static Mappings" entries are
never touched by any of these paths.

### Default settings and how to tune them

Out of the box the plugin runs layer 1 automatically and layer 2 (scheduled
sync only, no clean) every 6 hours. This is a **conservative** default: Kea and
Unbound stay broadly in sync, but stale records from expired leases may accumulate until
you the next scheduled clean, and any drift since the last cron run persists until
the next one.

To tighten the coupling progressively:

| Goal | What to enable |
|---|---|
| Clean up missing leases  automatically | Enable **Full sync** in DNS Record Cleaning / Enable scheduled sync / clean (same cron interval as sync) |
| Attempt to clean up immediately when a lease is released | Enable **Log Watcher** → **Purge IP on lease release** |
| Recover immediately after a transient SERVFAIL | Enable **Log Watcher** → **Re-sync names after listener SERVFAIL** |
| Close the LEASE_REUSE gap within seconds | Enable **Log Watcher** → **Re-sync on missed DNS removes** |

The trade-off of aggressive coupling: with the log watcher's release purge enabled,
a DNS record for a released IP disappears almost immediately — which is correct
behaviour on a well-managed network but may briefly break anything still using that
address during the grace window. Review [Advanced Topics](ADVANCED-TOPICS.md) for a
full discussion of what each layer covers, what drifts without it, and known gaps.

## Requirements

- OPNsense 26.1 or later (OPNsense 24.7+ should have the necessary capabilities,
  but nothing prior to 26.1 has been tested)
- Kea DHCP4 and/or Kea DHCP6 (built into OPNsense) — enabled and serving leases
- Unbound DNS resolver (built into OPNsense) — must be the active resolver
- `kea-dhcp-ddns` configured and running (for the dynamic path; the static sync
  path works without it)
- `py313-dnspython` — listed in `PLUGIN_DEPENDS`, installed automatically by `pkg`

> **High availability / multi-router setups are not supported.** The plugin
> assumes a single OPNsense instance is the sole writer to Unbound's runtime
> local_data. Running two plugin instances against a shared Unbound is untested
> and will produce split-brain DNS. CARP failover (active/passive with a single
> active node at a time) is not affected by this limitation.

## Installation

### Option A — pre-built package (recommended)

Download the `.pkg` file from the
[latest release](https://github.com/tkreagan/os-kea-ubnd-ddns/releases/latest)
and copy it to your OPNsense box (e.g. via `scp`). Then install it from the
directory where you saved it:

```sh
# On OPNsense, in the directory where you copied the file (as root or via sudo):
pkg install ./os-kea-ubnd-ddns-0.98.pkg
```

No package repository is required — OPNsense's `pkg` accepts a local `.pkg` file
directly. The `./` prefix tells `pkg` to use the local file rather than searching
a repository. The plugin appears under **Services → Kea Unbound DDNS** after
installation.

### Option B — build from source

Building requires an OPNsense
[`plugins`](https://github.com/opnsense/plugins) tree checked out on an OPNsense
host (or a FreeBSD build host that matches your OPNsense version).

```sh
# 1. Check out the OPNsense plugins tree
git clone https://github.com/opnsense/plugins /usr/plugins

# 2. Clone this repository into the correct category directory
git clone https://github.com/tkreagan/os-kea-ubnd-ddns /usr/plugins/net/kea-ubnd-ddns

# 3. Build the package
cd /usr/plugins/net/kea-ubnd-ddns
make package
# → work/pkg/os-kea-ubnd-ddns-0.98.pkg

# 4. Install
pkg add work/pkg/os-kea-ubnd-ddns-0.98.pkg
```

> **macOS / Linux cross-build note:** The `make package` target must run on a
> FreeBSD host — OPNsense itself works fine. If you are iterating on the source
> from a Mac, copy the `src/` tree to your OPNsense box, place it inside a
> plugins checkout, and run `make upgrade` there.

## Setup

### Before you begin

Confirm the following before enabling the plugin:

- **Kea DHCP is enabled and running.** Go to **Services → Kea DHCP → DHCPv4** (and/or DHCPv6). The service status must show running and you should have at least one subnet configured with an address pool.
- **Unbound is the active DNS resolver.** Go to **Services → Unbound DNS → General** and confirm it is enabled. The plugin writes directly to Unbound's runtime and does not work with any other resolver.
- **Clients send hostnames.** The plugin creates DNS records from DHCP-provided hostnames. Clients that send no hostname — common with MAC address randomization — will not get a record. See [Clients without hostnames and generated names](#clients-without-hostnames-and-generated-names) for options.

### Plugin setup

Go to **Services → Kea Unbound DDNS → Settings**. The plugin ships with all sync
and cleanup settings defaulted to **on**. Review the [Settings reference](#settings-reference)
below, but the defaults are appropriate for most deployments.

Do not click **Apply** yet — finish the Kea configuration below first, then come
back to check **Enabled** and apply.

### Kea setup

#### Option A — configure via the plugin (recommended)

Open the **Config Check** tab (**Services → Kea Unbound DDNS → Kea Config
Check**) and click **Configure All Subnets for Kea Unbound DDNS**. The plugin
reads your live Kea configuration, fills in the correct DDNS settings for every
subnet (server address, port, forward zone, qualifying suffix, and recommended
override flags), and saves the changes. Individual subnets can also be configured
one at a time using the per-subnet buttons on the same page.

Once that completes, skip to [Enable kea-dhcp-ddns](#enable-kea-dhcp-ddns) below.

#### Option B — configure manually

Go to **Services → Kea DHCP → DHCPv4 (or DHCPv6) → Subnets**, edit each subnet
that should register DNS entries, and switch to **Advanced** mode. Under the
**Dynamic DNS** section, configure:

| Field | Value | Notes |
|---|---|---|
| DNS forward zone | `home.lan.` | **Trailing dot required** — see note below |
| DNS reverse zone | e.g. `1.168.192.in-addr.arpa.` | Set (with trailing dot) to register PTR records — required for reverse DNS. |
| DNS qualifying suffix | `home.lan` | No trailing dot — appended to bare hostnames (e.g. `myhost` → `myhost.home.lan`) |
| DNS server address | `127.0.0.1` | |
| DNS server port | `53535` | Must match the plugin's listen port (configurable in **Settings**) |
| TSIG key name / secret / algorithm | *(leave blank)* | TSIG support is deferred — leave blank |
| Override no update | **On** (recommended) | Server registers DNS even if the client requests no updates. **Implies "Override client update"** — see below. |
| Override client update | **On** (recommended) | Server owns the forward (A) record. Recommended: there is no external DDNS server for clients to self-register against. |
| Update on renew | **On** (recommended) | Re-asserts DNS on lease renewal — self-heals if Unbound's runtime data is lost. Subject to the lease-cache caveat below. |
| Conflict resolution mode | `no-check-without-dhcid` (recommended) | The plugin silently ignores DHCID and prerequisites regardless of which mode is set, so the mode only affects what D2 includes in the packet. `no-check-without-dhcid` is cleanest: no DHCID records sent. Collision protection is handled by the plugin's own **Hostname collision policy** setting (below), not by this Kea field. |

Save and apply after editing each subnet.

> **Trailing dot required on the forward zone:** The DNS forward zone field must
> end with a trailing dot — `home.lan.` not `home.lan`. Without it, kea-dhcp-ddns
> silently drops every DNS UPDATE and nothing is registered. This is the most
> common configuration mistake.

> **Recommended DDNS settings:** For this plugin's target
> architecture — Unbound is updated via the bridge and there is no external DDNS
> server — enable **all three** override options together:
>
> - **Override client update = On** — the server assumes the forward (A) update.
>   Without it, a client that asks to do its own update (FQDN `S=0`) leaves *no* A
>   record, because it has nowhere to register.
> - **Override no update = On** — every device is registered (visibility / reverse
>   lookups) even if it requests no updates. **This should imply Override client
>   update:** enabling it while leaving Override client update *off* is an incoherent
>   combination — the server overrides the *stronger* "no updates" request but honors
>   the *weaker* "I'll do my own A" request (backwards). Always enable both together.
> - **Update on renew = On** — re-registers on renewal so records self-heal.
>   **Caveat:** Kea's lease caching (`cache-threshold`, default `0.25`) reuses a lease
>   renewed within `0.25 × valid-lifetime` and performs *no* DDNS, so DNS is only
>   refreshed on renewals outside that window (~1000s with a 4000s lease). A normal
>   renewal at half the lease lifetime is outside the window and works.
>
> **Known gap:** these options only act when the client sends a name. Clients that
> send no hostname/FQDN at all get no record; closing
> that would require `ddns-generated-prefix` + `ddns-replace-client-name`.

#### Enable kea-dhcp-ddns

Go to **Services → Kea DHCP → DHCP-DDNS**, enable the daemon, and save. The
default settings are correct — no port or forward zone configuration is needed
here. The per-subnet DDNS settings configured above tell kea-dhcp-ddns where to
send updates.

#### Validate your Kea configuration

Open the **Config Check** tab (**Services → Kea Unbound DDNS → Kea Config
Check**). It reads the live Kea configuration and flags common problems — missing
trailing dots on zone names, subnets with DDNS disabled, kea-dhcp-ddns listener
state. Resolve any errors shown before proceeding.

### Unbound setup

No changes to Unbound are required. The plugin discovers and writes to Unbound
automatically.

**Optional — disable "Register DHCP Static Mappings":** After enabling this
plugin's static reservation sync, the built-in Unbound setting at **Services →
Unbound DNS → General → Register DHCP Static Mappings** becomes redundant — both
features register the same Kea reservations in DNS. Disabling the built-in setting
is recommended to avoid duplication, but the plugin guards OPNsense-registered
entries and will never overwrite them, so leaving it on is safe if you prefer a
gradual transition.

### Enable the plugin

Go back to **Services → Kea Unbound DDNS → Settings**, check **Enabled**, and
click **Apply**.

### After enabling

Once running, active leases and static reservations should appear in the
**Lease Audit** tab within a few seconds of the daemon starting. Each row shows
the hostname, IP, record source (reservation or lease), and current DNS
registration state. If the tab is empty or shows unexpected gaps, see
[Troubleshooting](#troubleshooting) below.

## Troubleshooting

**Logs** are written to `/var/log/keaubnd/` and are also visible in the
**Log File** tab. All components — the daemon, sync scripts, and audit/cleanup
jobs — write to the same log facility.

**Common problems and where to look:**

| Symptom | Likely cause | Where to check |
|---|---|---|
| No records appear after a new lease | kea-dhcp-ddns not running, or forward zone missing trailing dot | **Config Check** tab — look for errors |
| Daemon shows stopped / not running | Startup preconditions not met (e.g., no DDNS-enabled subnet found, or Unbound not reachable) | **Log File** tab for the specific precondition failure |
| PTR records missing | Reverse zone not set on the subnet, or **Synthesize PTR records** disabled | Subnet DDNS settings → DNS reverse zone; **Settings** tab |
| Records disappear after Unbound restart | Expected — Unbound flushes runtime `local_data` on restart; the daemon detects the restart and reconciles within seconds | **Lease Audit** tab should repopulate automatically |
| Leases visible but not registering via DDNS | `update-on-renew` not set and lease has not renewed since enabling the plugin | Wait for a lease renewal, or use the **Sync** button on the Lease Audit tab to force a static reconcile |

## Settings reference

| Setting | Default | Notes |
|---|---|---|
| Enabled | **off** | Master switch for the daemon and all sync jobs |
| Synthesize PTR records | **on** | Automatically create the `in-addr.arpa`/`ip6.arpa` PTR for every A/AAAA update. Works without a reverse zone in kea-dhcp-ddns. Disable only if you manage reverse DNS separately — explicit PTR updates from kea-dhcp-ddns are always applied regardless |
| Hostname collision policy | **Last wins** | Action when a hostname is already registered to a different IP — see [Hostname collision policy](#hostname-collision-policy) below |
| **Magic hostnames** | **off** | Create parallel per-MAC FQDNs for all hosts in a collision group — see [Magic hostnames](#magic-hostnames) below |
| → LAA tag in magic suffix | off | Insert `-laa-` into the magic hostname when the MAC has the locally-administered bit set (iOS/Android random MACs), signalling the suffix may not be stable |
| → PTRs point to magic FQDN | off | On collision: write PTR records pointing to the magic FQDN rather than the bare hostname. No effect unless both Magic hostnames and Synthesize PTR records are enabled |
| **Log Watcher** | **off** | Secondary daemon that tails Kea and listener logs for missed events. Enable sub-options to choose which events trigger action — see [Log watcher](#log-watcher) below |
| → Purge IP on lease release | on | On DHCP4/6_RELEASE: immediately purge all DNS records for that IP |
| → Re-sync names after SERVFAIL | on | On listener SERVFAIL: trigger targeted kea-sync for the affected names |
| → Re-sync on missed DNS removes | on | On Remove-without-Add: trigger targeted kea-sync for that hostname (LEASE_REUSE gap) |
| **Scheduled sync / clean** | **on** | Run sync and/or clean on a cron schedule |
| → Full sync | **off** | Reconcile all Kea leases and reservations into Unbound at each interval |
| → Clean stale records | on | Remove Unbound records not backed by Kea — review Lease Audit before enabling |
| Schedule frequency | **6 hours** | How often the scheduled jobs run. Options: every 1/3/6/12 hours or daily at a specific hour |
| **Fast reload** | **on** | Periodically run `unbound-control reload` under the mutation lock to reclaim Unbound heap memory fragmented by repeated `local_data` add/remove calls |
| → Reload threshold *(advanced)* | `5000` NCRs | Number of successfully processed DNS UPDATE packets before the daemon triggers a reload. Each NCR typically generates 1–3 `unbound-control` calls |
| → Safety-net cron | **off** | Scheduled reload that fires even when the daemon counter has not been reached — catches daemon restarts that reset the counter while Unbound heap continues to accumulate |
| → Cron schedule *(advanced)* | Weekly | How often the safety-net cron fires. Options: daily / every 3 days / weekly / every 14 days / monthly |
| → Cron hour *(advanced)* | `3` (03:00) | Hour of day the safety-net cron fires |
| Port *(advanced)* | `53535` | UDP port for DNS UPDATE packets from kea-dhcp-ddns |
| Dirty-set cap *(advanced)* | `50` | Max deferred hostnames before the next reconcile becomes a full sync |
| Max reconcile attempts *(advanced)* | `5` | Failed reconciles before the daemon marks itself degraded |
| Readiness watchdog *(advanced)* | `10 min` | Time to wait for Kea/Unbound before the watchdog restarts the daemon. 0 = wait forever |

### Hostname collision policy

When a DHCP client registers a hostname that is already in Unbound for a
different IP address, the plugin applies one of four policies:

| Policy | Behaviour | Use when |
|---|---|---|
| **Last wins** *(default)* | The existing A/AAAA and its synthesized PTR are removed; the new IP is registered | Normal roaming network — a device that moves or gets a new lease should resolve to its current address |
| **Allow** | Both records coexist — Unbound round-robins between them | Dual-stack hosts with separate DHCPv4 + DHCPv6 leases; or you intentionally want multiple A records per name |
| **First wins** | Existing record is kept; the new registrant is rejected | You want static reservations to be immutable — reservations are always synced before dynamic leases, so they win naturally |
| **None** | All dynamic records for the conflicting hostname are evicted from Unbound — the name resolves to nothing until the next kea-sync resolves who actually holds the address | You want to guarantee no stale address is ever served, even briefly — prefer a gap in resolution over a wrong answer |

**Why no DHCID?** Kea sends DHCID records in RFC 2136 UPDATE packets when
configured with a `check-with-dhcid` or `check-exists-with-dhcid`
conflict-resolution mode. This plugin silently ignores them. DHCID was designed
to prevent two different DHCP servers from fighting over a hostname; since a
single plugin instance is the sole DNS writer, DHCID adds no value and is
deliberately omitted.

**First wins caveats:** On a live DDNS stream, First wins is reliable — the
first registrant holds the name until it sends a DELETE. After a full reconcile
(daemon restart, Kea or Unbound restart), ordering is deterministic within the
reconcile run (reservations beat leases) but not guaranteed across restarts.
On networks where clients randomize their MAC address, First wins can permanently
block a hostname from updating if the original registrant's lease expired without
sending a DELETE.

**None caveats:** The live path evicts all records on conflict and marks the
hostname dirty, but does not immediately re-register the winner. Re-registration
happens during the next dirty-drain (`kea-sync --names=...`), which runs after
the mutation lock is released. The name will be absent from DNS during that
window. `kea-dhcp-ddns` does not retry SERVFAIL, so the dirty-drain is the sole
recovery path for the evicted name.

### Magic hostnames

Magic hostnames are optional parallel FQDNs that exist alongside (and
independently of) whatever the collision policy does to the bare hostname. When
enabled, every host involved in a collision — winner and loser alike — gets a
stable, per-identifier FQDN of the form:

```
<hostname>-m<AABBCC>.<domain>   # MAC-identified host, last 6 hex chars
<hostname>-d<XXXXXX>.<domain>   # DUID-identified host, last 6 hex chars
```

For example, if two devices both claim the name `laptop.home.lan`:

```
laptop.home.lan       → 192.168.1.42    (last_wins: the most recent registrant)
laptop-mAABBCC.home.lan → 192.168.1.42
laptop-mDDEEFF.home.lan → 192.168.1.75  (the displaced device still has a name)
```

Magic FQDNs are written regardless of which collision policy is active and are
never displaced by a subsequent collision. They give administrators a stable name
to reach any device in a collision group, even when the bare hostname flaps.

**LAA tag:** When the **LAA tag** sub-option is enabled, devices whose MAC has
the locally-administered bit set (common with iOS, Android, and Windows MAC
randomization) get `-laa-` inserted into their magic suffix:
`laptop-laa-mAABBCC.home.lan`. This signals that the suffix encodes a randomized
MAC and may change when the device rotates it.

**PTRs to magic FQDNs:** When **PTRs point to magic FQDN** is enabled (requires
both Magic hostnames and Synthesize PTR records to also be on), PTR records for
IPs in a collision group point to the magic FQDN rather than the bare hostname.
IPs that are not in a collision group are unaffected.

**Interaction with collision policies:** For `none` and `first_wins`, magic FQDN
computation is deferred to the dirty-drain rather than computed inline on the
live path.

### Log watcher

The log watcher is an optional secondary daemon (`kea-ubnd-logwatch`) that tails
the Kea DHCP log and the listener log. It provides three fast-path triggers that
do not require waiting for the next cron run:

| Trigger | Event watched | Action |
|---|---|---|
| **Purge IP on release** | `DHCP4_RELEASE` / `DHCP6_RELEASE_NA` in the Kea log | Immediately purge all Unbound records for that IP via `local-data-clean.py --purge-ip` |
| **Re-sync after SERVFAIL** | Listener SERVFAIL logged by the daemon | Trigger `kea-sync --names=<name>` for the affected hostname as a recovery path alongside the daemon's built-in dirty-drain |
| **Re-sync on missed removes** | A DNS Remove with no follow-up Add within a short grace window | Trigger `kea-sync --names=<name>` to catch the LEASE_REUSE gap where `kea-dhcp-ddns` sends a Remove for an IP that is immediately re-leased to the same client but skips the Add |

> **IPv4 release log level caveat:** `DHCP4_RELEASE` (a normal successful DHCPv4
> release) is logged by Kea at **DEBUG level 50**, not INFO. In a default
> OPNsense Kea deployment (INFO-only logging), a healthy v4 release produces
> **no log line the watcher can see**, so the release-purge trigger is silently
> ineffective. Cleanup for released IPv4 addresses falls back to the next
> scheduled cron run. To get fast purge on every v4 release, either:
> - Set Kea DHCP4 logging to DEBUG level 50, or
> - Set `"delete-lease-on-quit": true` in `kea-dhcp4.conf` — this causes Kea to
>   emit `DHCP4_RELEASE_DELETED` (INFO) instead of `DHCP4_RELEASE` (DEBUG).
>
> DHCPv6 (`DHCP6_RELEASE_NA`) is always logged at INFO and is unaffected by
> this limitation.

### Warning: settings that can remove DNS entries from other sources

**Auto-clean** calls `unbound-control local_data_remove`, which removes records
from Unbound's **runtime in-memory zone** — including entries sourced from config
files, not just dynamically added ones.

The following entries are **protected** — if removed from Unbound's runtime
cache by a cleanup operation, the plugin automatically adds them back:

- OPNsense **Unbound Host Overrides**
- OPNsense **Kea Reservations**

They may be briefly absent from the in-memory cache during a cleanup run, but are restored automatically.

The following entries are **not protected** and will be permanently removed if
auto-clean is enabled:

- Records added manually via `unbound-control local_data`
- Records injected by another script or plugin that does not write to
  `/var/unbound/host_entries.conf`

If another tool re-creates such records on its own schedule, they will return on
that tool's next run. If they are one-off manual entries, they will not return
unless manually re-added.

Use the **Lease Audit** tab to preview exactly which records would be removed
before enabling either cleanup setting.

### TSIG authentication

TSIG support is partially implemented in the daemon (`kea-ubnd-ddns.py`) and
daemon-start code, but has not been tested end-to-end and is not configurable via
the Settings UI. It is deferred indefinitely. The listener only accepts
connections from `127.0.0.1`, so unsigned updates from kea-dhcp-ddns are safe
for the standard single-host deployment and TSIG provides no additional security
in that topology.

## UI tabs

| Tab | Purpose |
|---|---|
| **Settings** | Enable/disable the plugin; configure sync, cleanup, and listen port |
| **Config Check** | Verify DDNS is configured in each Kea subnet; shows the kea-dhcp-ddns listener state and flags common mistakes (missing trailing dots, missing forward zones) |
| **Lease Audit** | Full view of all DNS records across Kea reservations, active leases, Unbound local_data, and Host Overrides; previews what cleanup would remove; manual sync/clean buttons |
| **Log File** | Unified log for the daemon, sync, audit, and cleanup scripts |

## Feature status

Tested on OPNsense 26.1 with Kea DHCP4 and DHCP6:

- RFC 2136 stub listener with A, AAAA, and PTR record handling
- Static reservation sync (IPv4 and IPv6)
- Active lease sync with TTL matching remaining lease lifetime
- Lease Audit tab with per-record PTR state, collision state, and magic FQDN annotations
- Config Check tab (forward zones, TSIG key detection, trailing-dot validation)
- Scheduled stale-record cleanup
- OPNsense Host Override guard (never removes managed entries)
- Resident daemon with self-healing: detects Kea/Unbound restarts and automatically reconciles DNS records
- Four hostname collision policies: last wins (default), allow, first wins, none
- Magic hostname disambiguation: stable per-MAC FQDNs for all hosts in a collision group
- Log watcher with configurable triggers: release purge, SERVFAIL recovery, missed-remove detection
- Periodic Unbound heap reclaim via `unbound-control reload` (threshold-triggered + safety-net cron)

## Known issues and roadmap

- **`unbound-control fast-reload` memory leak** — Unbound's `fast-reload` subcommand
  (available since Unbound 1.22) has a confirmed upstream memory leak. As a workaround,
  the periodic heap-reclaim feature currently uses `unbound-control reload` instead of
  `fast-reload`, which is safe but causes a brief resolution gap during the reload window.
  Re-enabling `fast-reload` requires a one-line change in `start.py` once the upstream
  fix lands.
- **DHCPv4 release purge requires DEBUG logging or `delete-lease-on-quit`** — the log
  watcher's "purge IP on release" trigger for IPv4 depends on the `DHCP4_RELEASE` log
  message, which Kea emits at DEBUG level 50. Default OPNsense Kea logging is INFO-only,
  so a normal v4 release is invisible to the watcher and cleanup falls back to the next
  cron run. See [Log watcher](#log-watcher) for workarounds. DHCPv6 is unaffected.
- **Global reservations not tested** — ISC recommends against assigning IP addresses in Kea's
  global reservation scope (`Dhcp4.reservations`); that scope is designed for options and
  hostname assignment only, not IP binding. The plugin's static sync reads `ip-address` from
  global reservations and silently skips entries without one, so a correctly-used global
  reservation (no IP) produces no DNS record. This configuration is not tested. The Kea Config
  Check tab flags it when detected.
- **Shared networks — partial support** — The OPNsense GUI does not expose shared-network
  configuration for Kea DHCP (see
  [opnsense/core#9427](https://github.com/opnsense/core/issues/9427), no committed timeline).
  If you configure shared networks manually, see [Shared networks (manual config)](#shared-networks-manual-config) below.
- **Not yet in OPNsense community plugins** — installation is manual for now (see
  [Installation](#installation)).

## Advanced topics

Shared networks, clients without hostnames, DHCPv6 behavior, IPv6 PTR encoding,
DNS suffix staleness, and a known-limitations summary are covered in
[ADVANCED-TOPICS.md](ADVANCED-TOPICS.md).

## Development and testing

```sh
# Install test dependencies (Python 3.11+)
pip install -r requirements-test.txt

# Unit tests (no OPNsense required)
./tests/run_unit.sh

# Integration tests (require a real OPNsense + Kea box)
cp tests/.env.example tests/.env
# Edit tests/.env with your box's address and credentials
./tests/run_integration.sh
```

The test suite has 235 unit tests. Integration tests deploy the
current source to the target box via SFTP and run against a live Kea installation.
See [`tests/.env.example`](tests/.env.example) for the full list of required
variables.

## License

BSD 2-Clause — see [LICENSE](LICENSE).
