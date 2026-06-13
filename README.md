# os-kea-unbound

An [OPNsense](https://opnsense.org) plugin that automatically registers Kea DHCP
leases and static reservations in the Unbound DNS resolver. Hostnames resolve the
moment a lease is issued — with minimal drift between your DHCP and DNS tables.

## How it works

Two synchronization paths run in parallel:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  OPNsense                                                                    │
│                                                                              │
│  kea-dhcp4/6 ─────────────────────────────────────── kea-dhcp-ddns           │
│       │                                                     │                │
│       │  [Static Path]                     [Dynamic Path]   │                │
│       │                                                     │                │
│  Kea reservations                                     RFC 2136 UPDATE        │
│  Kea active leases                                          │                │
│       │                                                     │                │
│       └────────────────────► kea-unbound-ddns ◄─────────────┘                │
│                              (127.0.0.1:53535)                               │
│                                     │                                        │
│                               unbound-control                                │
│                                     │                                        │
│                            Unbound local_data                                │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Dynamic path (real-time):** `kea-dhcp-ddns` sends RFC 2136 DNS UPDATE packets to
the plugin's stub listener. Each packet is immediately translated into an
`unbound-control local_data` or `local_data_remove` call — A, AAAA, and PTR records
are handled automatically.

**Static path (reconcile / on demand):** The resident daemon watches the Kea and
Unbound service pidfiles. Whenever either service restarts — flushing Unbound's
runtime records — the daemon automatically runs a full reconcile from Kea,
repopulating Unbound without any manual intervention. The Lease Audit tab also
provides manual Sync and Clean buttons.

OPNsense Unbound Host Overrides and "Register DHCP Static Mappings" entries are
never touched by either path.

## Requirements

- OPNsense 26.1 or later (OPNsense 24.7+ should have the necessary capabilities,
  but nothing prior to 26.1 has been tested)
- Kea DHCP4 and/or Kea DHCP6 (built into OPNsense)
- `kea-dhcp-ddns` configured and running (for the dynamic path; the static sync
  path works without it)
- Unbound DNS resolver (built into OPNsense, must be the active resolver)
- `py313-dnspython` — listed in `PLUGIN_DEPENDS`, installed automatically by `pkg`

> **High availability / multi-router setups are not supported.** The plugin
> assumes a single OPNsense instance is the sole writer to Unbound's runtime
> local_data. Running two plugin instances against a shared Unbound is untested
> and will produce split-brain DNS. CARP failover (active/passive with a single
> active node at a time) is not affected by this limitation.

## Installation

### Option A — pre-built package (recommended)

Download `os-kea-unbound-0.9.pkg` from the
[latest release](https://github.com/tkreagan/os-kea-unbound/releases/latest),
copy it to your OPNsense box, and install it with `pkg`:

```sh
# On OPNsense (as root or via sudo):
pkg add os-kea-unbound-0.9.pkg
```

No package repository is required — OPNsense's `pkg` accepts a local `.pkg` file
directly. The plugin appears under **Services → Kea Unbound DDNS** after
installation.

### Option B — build from source

Building requires an OPNsense
[`plugins`](https://github.com/opnsense/plugins) tree checked out on an OPNsense
host (or a FreeBSD build host that matches your OPNsense version).

```sh
# 1. Check out the OPNsense plugins tree
git clone https://github.com/opnsense/plugins /usr/plugins

# 2. Clone this repository into the correct category directory
git clone https://github.com/tkreagan/os-kea-unbound /usr/plugins/net/kea-unbound

# 3. Build the package
cd /usr/plugins/net/kea-unbound
make package
# → work/pkg/os-kea-unbound-0.9.pkg

# 4. Install
pkg add work/pkg/os-kea-unbound-0.9.pkg
```

> **macOS / Linux cross-build note:** The `make package` target must run on a
> FreeBSD host — OPNsense itself works fine. If you are iterating on the source
> from a Mac, copy the `src/` tree to your OPNsense box, place it inside a
> plugins checkout, and run `make upgrade` there.

## Configuration

### Step 1 — Configure Kea subnets for DDNS

Go to **Services → Kea DHCP → DHCPv4 (or DHCPv6) → Subnets**, edit each subnet
that should register DNS entries, and switch to **Advanced** mode. Under the
**Dynamic DNS** section, configure:

| Field | Value | Notes |
|---|---|---|
| DNS forward zone | `home.lan.` | **Trailing dot required** — see note below |
| DNS reverse zone | e.g. `1.168.192.in-addr.arpa.` | Set (with trailing dot) to register PTR records — required for reverse DNS. Verified working in v0.9 testing. |
| DNS qualifying suffix | `home.lan` | No trailing dot — appended to bare hostnames (e.g. `myhost` → `myhost.home.lan`) |
| DNS server address | `127.0.0.1` | |
| DNS server port | `53535` | Must match the plugin's listen port (configurable in **Settings**) |
| TSIG key name / secret / algorithm | *(leave blank)* | Not tested in v0.9 |
| Override no update | **On** (recommended) | Server registers DNS even if the client requests no updates. **Implies "Override client update"** — see below. |
| Override client update | **On** (recommended) | Server owns the forward (A) record. Recommended: there is no external DDNS server for clients to self-register against. |
| Update on renew | **On** (recommended) | Re-asserts DNS on lease renewal — self-heals if Unbound's runtime data is lost. Subject to the lease-cache caveat below. |
| Conflict resolution mode | `no-check-without-dhcid` (recommended) | All four modes tested in v0.9 — the plugin silently ignores DHCID and prerequisites regardless of which mode is set, so the mode only affects what D2 includes in the packet. `no-check-without-dhcid` is cleanest: no DHCID records sent. Collision protection is handled by the plugin's own **Hostname collision policy** setting (below), not by this Kea field. |

Save and apply after editing each subnet.

> **Trailing dot required on the forward zone:** The DNS forward zone field must
> end with a trailing dot — `home.lan.` not `home.lan`. Without it, kea-dhcp-ddns
> silently drops every DNS UPDATE and nothing is registered. This is the most
> common configuration mistake. The **Kea Config Check** tab detects and flags it.

> **Recommended DDNS settings (verified in v0.9 testing):** For this plugin's
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
> send no hostname/FQDN at all (e.g. MAC-randomizing phones) get no record; closing
> that would require `ddns-generated-prefix` + `ddns-replace-client-name`.

### Step 2 — Enable kea-dhcp-ddns

Go to **Services → Kea DHCP → DHCP-DDNS**, enable the daemon, and save. The
default settings are correct — no port or forward zone configuration is needed
here. The per-subnet DDNS settings configured in Step 1 tell kea-dhcp-ddns where
to send updates.

### Step 3 — Enable the plugin

Go to **Services → Kea Unbound DDNS → Settings**.

All sync and cleanup settings default to **on**. The only required action is to
check **Enabled** and click **Apply**. Review the other settings and adjust if
needed before applying.

Use the **Kea Config Check** tab to verify your Kea DDNS configuration, and the
**Lease Audit** tab to inspect current DNS registration status.

### Step 4 — Optionally disable "Register DHCP Static Mappings" in Unbound

After enabling the plugin's static reservation sync, you can turn off Unbound's
built-in **Register DHCP Static Mappings** setting (**Services → Unbound DNS →
General → Register DHCP Static Mappings**). Both features register the same Kea
reservations in DNS, so running both is redundant. The plugin provides additional
visibility — per-reservation status, PTR tracking, and the Lease Audit view — that
the built-in setting does not.

OPNsense-registered entries are always guarded and never overwritten by the plugin,
so leaving the built-in setting on is safe if you prefer a gradual transition.

### Settings reference

| Setting | Default | Notes |
|---|---|---|
| Enabled | **off** | Master switch for the daemon and all sync jobs |
| Sync Kea static reservations | **on** | Registers reservations in Unbound during each reconcile and on demand |
| Sync Kea active leases | **on** | Registers active leases; TTL = remaining lease time |
| Synthesize PTR records | **on** | Automatically create the `in-addr.arpa`/`ip6.arpa` PTR for every A/AAAA update. Works without a reverse zone in kea-dhcp-ddns. Disable only if you manage reverse DNS separately — explicit PTR updates from kea-dhcp-ddns are always applied regardless |
| Hostname collision policy | **Last wins** | Action when a hostname is already registered to a different IP — see [Hostname collision policy](#hostname-collision-policy) below |
| Automatically clean stale DNS records | **on** | Scheduled bulk removal of entries not backed by Kea — see warning below |
| Auto-clean frequency | **6 hours** | How often the scheduled bulk cleanup runs. Options: every 1/3/6/12 hours or daily at a specific hour |
| Port *(advanced)* | `53535` | UDP port for DNS UPDATE packets from kea-dhcp-ddns |
| Dirty-set cap *(advanced)* | `100` | Max deferred hostnames before the next reconcile becomes a full sync |
| Max reconcile attempts *(advanced)* | `5` | Failed reconciles before the daemon marks itself degraded |
| Readiness watchdog *(advanced)* | `10 min` | Time to wait for Kea/Unbound before the watchdog restarts the daemon. 0 = wait forever |

#### Hostname collision policy

When a DHCP client registers a hostname that is already in Unbound for a
different IP address, the plugin applies one of three policies:

| Policy | Behaviour | Use when |
|---|---|---|
| **Last wins** *(default)* | The existing A/AAAA and its synthesized PTR are removed; the new IP is registered | Normal roaming network — a device that moves or gets a new lease should resolve to its current address |
| **Allow** | Both records coexist — Unbound round-robins between them | Dual-stack hosts with separate DHCPv4 + DHCPv6 leases; or you intentionally want multiple A records per name |
| **First wins** | Existing record is kept; the new registrant is rejected | You want static reservations to be immutable — reservations are always synced before dynamic leases, so they win naturally |

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

#### Warning: settings that can remove DNS entries from other sources

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

TSIG support is partially implemented in the daemon (`kea-unbound-ddns.py`) and
daemon-start code, but has not been tested end-to-end and is not configurable via
the Settings UI. It is deferred indefinitely. The listener only accepts
connections from `127.0.0.1`, so unsigned updates from kea-dhcp-ddns are safe
for the standard single-host deployment and TSIG provides no additional security
in that topology.

## UI tabs

| Tab | Purpose |
|---|---|
| **Settings** | Enable/disable the plugin; configure sync, cleanup, and listen port |
| **Kea Config Check** | Verify DDNS is configured in each Kea subnet; shows the kea-dhcp-ddns listener state and flags common mistakes (missing trailing dots, missing forward zones) |
| **Lease Audit** | Full view of all DNS records across Kea reservations, active leases, Unbound local_data, and Host Overrides; previews what cleanup would remove; manual sync/clean buttons |
| **Log File** | Unified log for the daemon, sync, audit, and cleanup scripts |

## Current status — v0.9

This is the initial public release. The following are working and tested on
OPNsense 26.1 with Kea DHCP4:

- RFC 2136 stub listener with A, AAAA, and PTR record handling
- Static reservation sync (IPv4 and IPv6)
- Active lease sync with TTL matching remaining lease lifetime
- Lease Audit tab with per-record PTR state tracking
- Kea Config Check tab (forward zones, TSIG key detection, trailing-dot validation)
- Scheduled stale-record cleanup
- OPNsense Host Override guard (never removes managed entries)
- Resident daemon with self-healing: detects Kea/Unbound restarts and automatically reconciles DNS records

## Known issues and roadmap

- **TSIG authentication** — partially implemented in the listener and startup code; not tested end-to-end, not configurable via Settings UI. Deferred indefinitely — the listener only accepts connections from `127.0.0.1`, so unsigned updates are safe for all standard single-host deployments.
- **Reverse zones verified** — the DNS reverse zone field is tested and working;
  PTR records register correctly when it is set (with a trailing dot).
- **Override options verified** — `override-no-update`, `override-client-update`,
  and `update-on-renew` were validated end-to-end in v0.9 testing and behave per the
  recommended-settings note above.
- **All four conflict-resolution modes tested** — the plugin silently ignores DHCID
  records and RFC 2136 prerequisites in all modes; all four produce identical A + PTR
  registration. The plugin's own **Hostname collision policy** setting is the correct
  way to control same-name conflict handling. Recommended mode: `no-check-without-dhcid`.
- **DHCID records not stored** — the plugin accepts and silently skips DHCID records
  in RFC 2136 UPDATE packets; hostname ownership is tracked via the plugin's collision
  policy, not via DHCID. This is an intentional design decision for Unbound-only
  deployments where the plugin is the sole DNS writer.
- **`ncr-protocol: TCP` hard-fails D2** — setting `ncr-protocol: TCP` in
  `kea-dhcp-ddns.conf` causes D2 to refuse to start entirely (`TCP is not yet
  supported`). UDP is the only supported protocol. kea-dhcp4 continues to serve leases
  with no log warning when D2 is down; monitor D2 separately.
- **Kea connection auto-discovery** — the plugin reads each Kea daemon's active config file to find its control socket (unix or HTTP) and falls back to the standard OPNsense socket paths. Manual connection override is not exposed in the UI and is deferred; it may not be necessary given reliable auto-discovery. HTTP socket support is deferred until OPNsense enables HTTP control sockets or deprecates unix sockets.
- **kea-dhcp-ddns connection** — the Kea Config Check tab reads `kea-dhcp-ddns.conf` directly rather than querying a control socket, because OPNsense does not provision a control socket or HTTP listener for `kea-dhcp-ddns` (it is not exposed in the web GUI and requires a manual config edit to enable).
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

## Advanced configuration notes

### Shared networks (manual config)

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
  explicit suffix uses that, ignoring the shared-network's value. Verified on real
  Kea API responses in testing.

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
  path, not via a live DHCPv6/DHCPv4 exchange from a client in a shared-network subnet.

The Kea Config Check tab flags shared-network subnets with an advisory notice.

---

### Clients without hostnames and generated names

**The problem:** every DNS record the plugin creates is derived from a hostname.
A client that sends no hostname in its DHCP request — common on phones and devices
with MAC address randomization — gets no DNS record, regardless of the override
settings (`ddns-override-no-update`, `ddns-override-client-update`). Those flags
only act when the client supplies a name; they cannot manufacture one from nothing.
This was confirmed in testing (test G1: all three override flags ON, client sent no
name, result: lease allocated, no DNS record).

**Kea's solution:** two options work together to generate names for nameless clients.
Both are available only in manual config mode (OPNsense does not expose them in the
GUI as of 26.1).

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

**Important limitation — sync path divergence:** when Kea generates a name, it
places the generated FQDN in the NCR packet (so the live path — `kea-dhcp-ddns` →
listener — registers it correctly). However, Kea stores the *original client name*
(or empty string) in the lease database. The sync path (`kea-sync.py`) reads the
lease database; it sees an empty hostname and skips the lease. This means:

- While Kea and D2 are running: the generated name is in Unbound, registered via the live path.
- After an Unbound restart (which flushes all runtime `local_data`): the sync path
  cannot restore the record. It stays gone until the client's next lease renewal
  triggers a new NCR — or until `ddns-update-on-renew` fires a renewal-triggered NCR.

**Mitigation:** enable `ddns-update-on-renew: true` on subnets that use generated
names. This causes Kea to re-assert DNS on every genuine renewal (subject to the
`cache-threshold` caveat noted in the configuration guide above), which limits the
window after an Unbound restart where records are missing. The window is at most
one lease T1 interval.

**Recommendation for this deployment:** if every device must be resolvable, the
most reliable approach is to configure `ddns-replace-client-name: when-not-present`
and `ddns-generated-prefix: <something>` in manual config mode, combined with
`ddns-update-on-renew: true`. Devices that supply a real hostname continue to use
it; nameless devices get a deterministic generated name that the live path keeps
fresh.

---

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
