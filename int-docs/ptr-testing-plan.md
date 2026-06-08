# PTR Record Handling — Analysis, Design Decisions, and Test Plan

> Reference for `os-kea-unbound` PTR / reverse-DNS behavior.  Companion to
> `ptr-handling-notes.md` (gap cases) and `kea-ddns-options-reference.md`
> (option-by-option breakdown).
>
> Last updated: June 2026.  Test rig: dev-opnsense (OPNsense 26.1.9, Kea 3.0.3,
> kea-unbound 0.9) + dev-dhcpclient (Debian 13, scapy 2.6.1).

---

## Part A — How Kea PTR/DDNS is supposed to work

A DHCP lease drives two DNS records: a **forward A/AAAA** (name→IP, ownership
negotiable) and a **reverse PTR** (IP→name, the server always owns this).

### A.1 — The three-config NCR pipeline

All three of the following must be active for a PTR record to be set:

```
kea-dhcp{4,6}.conf per-subnet      kea-dhcp{4,6}.conf top-level   kea-dhcp-ddns.conf (D2)
──────────────────────────────     ─────────────────────────────  ─────────────────────────
ddns-send-updates: true       →→→  dhcp-ddns {               →→→  reverse-ddns {
  (derived from ddns_dns_server        enable-updates: true             ddns-domains: [{
   being set; not a direct GUI         server-ip: 127.0.0.1              name: "1.168.192.in-addr.arpa."
   field in OPNsense)                  server-port: 53535                dns-servers: [{
                                   }                                       ip: 127.0.0.1
                                                                           port: 53535
                                                                         }]
                                                                       }]
                                                                   }
```

**Kea has no standalone "send PTR" boolean.** `ddns-send-updates` gates forward
AND reverse together. The only reverse-specific control is `reverse-ddns.ddns-domains[]`
in `kea-dhcp-ddns.conf` (D2). If that array is empty, D2 generates no reverse NCR
even though the DHCP server still emits one in the NCR it sends to D2.

### A.2 — OPNsense config.xml / GUI settability (as of OPNsense 26.1.9)

| Option | config.xml location | GUI settable |
|--------|---------------------|--------------|
| Forward zone | `ddns_forward_zone` per-subnet | Yes |
| **Reverse zone** | `ddns_reverse_zone` per-subnet | Yes — but **not auto-derived from subnet** |
| Qualifying suffix | `ddns_qualifying_suffix` | Yes |
| ONU / OCU / UOR / conflict-mode | per-subnet booleans | Yes |
| TSIG key/algorithm | per-domain | Yes |
| `ddns-replace-client-name` | — | **Manual config only** |
| `ddns-generated-prefix` | — | **Manual config only** |
| `hostname-char-set/replacement` | — | **Manual config only** |
| `ddns-ttl-*` family | — | **Manual config only** |
| `ncr-protocol` | — | **Manual config only** (must be UDP) |

`ddns-send-updates` is **derived**, not a separate field: OPNsense PHP emits it as
`!$subnet->ddns_dns_server->isEmpty()`. The reverse zone must always be set
explicitly — OPNsense never auto-derives it from the subnet CIDR.

### A.3 — FQDN option 81 flag semantics

| Flag | Meaning | Notes |
|------|---------|-------|
| `S=1` | Server does the forward A | |
| `S=0` | Client will do its own forward A | Server always owns PTR regardless |
| `N=1` | No DNS updates at all | Overrides S; no PTR either |
| `O` | Set in ACK: server overrode client's preference | |

Hostname option 12 has no flags — treated as `S=1` (server does both). When `N=1`
and `ddns-override-no-update` is OFF, neither A nor PTR is registered.

---

## Part B — How this plugin handles PTRs

### B.1 — Two paths to PTR registration

**Path 1 — synthesized PTR (live path, always on by default):**
`kea-unbound-ddns.py` synthesizes the standard `in-addr.arpa`/`ip6.arpa` PTR on
every A/AAAA ADD via `reverse_ptr()` (Python `ipaddress.ip_address().reverse_pointer`),
independent of whether D2 has a reverse zone configured. Controlled by the
`synthesize_ptr` flag (default ON).

**Path 2 — explicit reverse NCR (live path, conditional):**
When `ddns_reverse_zone` is set in OPNsense, D2 sends a separate PTR UPDATE.
The listener handles it via the `rdtype=="PTR"` branch in `process_update()`.
Path-2 PTRs are always applied regardless of `synthesize_ptr`.

**Bulk path (restart recovery):**
`lease-sync.py` and `reservation-sync.py` re-synthesize PTRs from Kea state after
an Unbound restart using `unbound_add_records()` in `keaunbound_sync.py`.  This
path is zone-agnostic: it only synthesizes `in-addr.arpa`/`ip6.arpa` PTRs.

### B.2 — Synthesize-PTR flag (new in 0.9)

A global plugin toggle (`general.synthesize_ptr`, default ON) controls Path-1:

- **ON (default):** PTRs appear in Unbound immediately, even with no reverse zone
  configured in D2. Current behaviour preserved for upgrades.
- **OFF:** No PTRs are added or removed via the forward-NCR path. Explicit PTR NCRs
  from D2 (Path 2) are still applied. Use when you manage reverse DNS with another
  authoritative server for `in-addr.arpa` / `ip6.arpa`.

When OFF, PTR removal is also suppressed on A/AAAA DELETE — there is no synthesized
PTR to remove. The explicit reverse NCR delete (if D2 sends one) is still handled.

Config path: `//OPNsense/KeaUnbound/general/synthesize_ptr`.
Daemon arg: `--no-synthesize-ptr` (appended by `start.py` when the flag is 0).

### B.3 — Static-entry guard (fixed in 0.9)

`is_static_entry(name, rdtype)` protects records in `host_entries.conf`
(OPNsense-managed host overrides and registered DHCP static mappings) from being
clobbered or deleted by the live or bulk paths.

**F1 (confirmed working):** A static PTR on an IP does NOT block a different
hostname's forward A from being registered. The forward guard uses only
`local-data: "name ... IN A ..."` matching; the PTR guard is separate.

**F2 (fixed in 0.9 — previously broken):** OPNsense writes static reverse mappings
as **IP-keyed** entries:
```
local-data-ptr: "192.168.1.1 router.lan."
```
The pre-fix code checked for `local-data-ptr: "1.1.168.192.in-addr.arpa ..."` —
which never matched OPNsense's format. Result: the daemon would clobber the static
PTR on the next DDNS A-add for any host with that IP.

The fix: `_arpa_to_ip()` decodes the reverse-arpa name to its IP at check time,
and the guard checks BOTH the arpa-name form AND the IP-keyed form. IPv4 and IPv6
are both handled. `_arpa_to_ip()` lives in the shared lib
(`lib/keaunbound_sync.py`) and is imported by both the daemon and the cleanup
path; `is_static_entry()` in `kea-unbound-ddns.py` is the call site for the
daemon guard.

### B.4 — Audit `ptr_state`

`local-data-audit.py --report-json` classifies each forward record's PTR status:

| `ptr_state` | Meaning |
|-------------|---------|
| `correct` | PTR present and pointing back to this hostname |
| `wrong` | PTR present but points elsewhere |
| `multiple` | Multiple PTRs for this IP (different hostnames) |
| `none` | No PTR in Unbound's local_data for this IP |

With a custom reverse zone (F4), the audit may report `correct` for `in-addr.arpa`
while the `home.arpa` PTR is invisible to it (depends on IP rather than owner
name). Verify during testing.

---

## Part C — Known gaps / open issues

### C.1 — Custom reverse zone orphan (F4) — NOT A REAL SCENARIO

**This gap cannot occur.** D2 matches a reverse zone by checking whether the arpa
form of the lease IP is a suffix of the configured zone name. A zone name like
`1.168.192.home.arpa.` can never match any IP's arpa form (which always ends in
`.in-addr.arpa` or `.ip6.arpa`), so D2 simply never fires for it — and no NCR is
sent. All D2-written PTRs are unconditionally `in-addr.arpa`/`ip6.arpa`.

The only PTR paths are:
- Standard zone (e.g. `1.168.192.in-addr.arpa.`) → double-write with synthesis;
  harmless, per-subnet advisory in Config Check.
- No zone configured → synthesis only; no D2 lifecycle management.

F4 is closed; test cases D3/C1–C3 below are vacuous and kept for reference only.

### C.2 — Missing reverse zone (F5)

When no `ddns_reverse_zone` is set, D2 sends no reverse NCR at all. PTRs still
appear via Path-1 synthesis, but their lifecycle is not managed by D2 — there is
no DELETE NCR when the lease expires. The record persists until `local-data-clean.py`
runs. Config Check advisory recommended.

### C.3 — D2 delete reliability

D2 does not queue NCRs — if D2 is down at the moment a lease expires, the DELETE
NCR is dropped. Orphaned records linger until `local-data-clean.py` runs.
The `--aggressive-cleanup` flag handles the IP-change-without-release case.

### C.4 — Bulk-path PTR after Unbound restart

After a restart, the bulk path re-synthesizes `in-addr.arpa`/`ip6.arpa` PTRs only.
Custom-zone PTRs (Path 2) are NOT restored — they only come back on the next live
NCR (on the next renewal if UOR=ON). Keep `ddns-update-on-renew: ON` when using
custom reverse zones.

---

## Part D — Test matrix

All PTR verification uses `unbound-control -c /var/unbound/unbound.conf list_local_data`
(NOT `drill -x` — RFC6303 static zones for private space return NXDOMAIN from
Unbound's built-in RFC 6303 answer, causing false negatives).

### D1 — Static-PTR guard (unit + integration, v4 + v6)

**Unit tests** (implemented in `tests/unit/test_daemon.py`):

| Test | Verifies |
|------|----------|
| `test_is_static_entry_ptr_arpa_name_matches_ip_keyed_form` | F2 fix: arpa-name matches OPNsense IP-keyed PTR (IPv4) |
| `test_is_static_entry_ptr_arpa_name_matches_ip_keyed_form_v6` | F2 fix: ip6.arpa name matches IP-keyed PTR (IPv6) |
| `test_is_static_entry_ptr_unrelated_ip_not_blocked` | Unrelated static PTR does not block a different IP |
| `test_is_static_entry_ptr_raw_ip_form_still_works` | Raw-IP call still works (internal use) |
| `test_is_static_entry_forward_a_not_blocked_by_ptr` | F1 regression: static PTR does not block forward A |
| `test_process_update_static_ptr_preserved_on_a_add` | F2 e2e: static PTR not clobbered when different host uses same IP |

**Integration tests** (`tests/integration/test_ddns_listener.py`, D1 group):

| ID | Setup | Action | Expected |
|----|-------|--------|----------|
| S1 | host_entries: `local-data-ptr: "192.168.1.1 router.lan."` | DDNS A-add for `other.lan → 192.168.1.1` | forward A `other.lan` registered (F1) |
| S2 | same | check PTR for `192.168.1.1` | PTR still points to `router.lan` (F2 fix) |
| S3 | host_entries: `local-data: "static-host.lan. IN A 192.168.1.50"` | DDNS A-add for `static-host.lan → .50` | add skipped (forward static guard) |
| S4 | host_entries: `local-data-ptr: "2001:db8::1 ipv6-static.lan."` | DDNS AAAA-add, different host, same IP | F1 + F2 for IPv6 |

### D2 — Standard reverse zone lifecycle (v4 + v6)

Tests live in `tests/integration/test_ptr_lifecycle.py`.

| ID | Setup | Action | Expected |
|----|-------|--------|----------|
| P1a | `ddns_reverse_zone` set | DORA / SARR | A/AAAA + PTR at standard zone (Path 1 + Path 2 double-write, harmless) |
| P1b | set | DHCPRELEASE | A + PTR both removed |
| P1c | reverse zone **unset** | DORA / SARR | A + PTR via Path-1 synthesis only (F5) |
| P1d | unset | DHCPRELEASE | forward NCR delete removes synthesized PTR |

### D3 — Custom reverse zone gap (F4) — VACUOUS, cannot occur

D2 zone matching is arpa-suffix based, so a non-arpa zone name (e.g. `home.arpa`)
can never match any IP and D2 never fires for it. These test cases are kept for
historical reference but should not be run; they would produce the wrong setup.

| ID | Setup | Action | Expected | Status |
|----|-------|--------|----------|--------|
| C1 | `ddns_reverse_zone: "1.168.192.home.arpa."` | DORA | (D2 would never fire for this zone) | vacuous |
| C2 | same | DHCPRELEASE | — | vacuous |
| C3 | after C2 | run `local-data-clean.py` | — | vacuous |

### D4 — Delete reliability / bulk-path PTR (v4 + v6)

| ID | Action | Expected |
|----|--------|----------|
| R1 | lease expiry via short `valid-lifetime` (ELP path) | DELETE NCR fires → PTR removed |
| R2 | D2 stopped during expiry, restarted | record persists → cleanup removes it |
| R3 | client moves to new IP without release | old PTR lingers; cleanup / aggressive-cleanup removes it |
| R4 | Unbound restart → `lease-sync.py` | PTR recreated at standard zone (bulk path) |
| R5 | custom zone + Unbound restart | only `in-addr.arpa`/`ip6.arpa` PTR returns; custom-zone PTR waits for next renewal NCR |

### D5 — Audit `ptr_state` accuracy

For each terminal state above, assert `local-data-audit.py --report-json` reports
the correct `ptr_state` (`none/wrong/correct/multiple`).  Specific items to verify:
- Custom-zone double PTR (C1) → confirm `correct` or `multiple` in audit output
- Missing-reverse-zone synthesized PTR (P1c) → `correct`
- Orphaned `in-addr.arpa` PTR (after C2, before cleanup) → `correct` for the
  `in-addr.arpa` PTR (since the IP still points at the hostname)
- After lease is gone → `wrong` or `none` (stale record no longer backed by Kea)

### D5b — PTR-synthesis flag

**Unit tests** (implemented in `tests/unit/test_daemon.py`):

| Test | Verifies |
|------|----------|
| `test_process_update_no_synthesize_ptr_skips_ptr` | flag OFF: no PTR added on A-add |
| `test_process_update_synthesize_ptr_on_adds_ptr` | flag ON (default): PTR synthesized |
| `test_process_update_no_synthesize_ptr_v6` | flag OFF: no ip6.arpa PTR on AAAA-add |
| `test_process_update_no_synthesize_ptr_delete_no_ptr_removal` | flag OFF: no PTR removal on A-delete |
| `test_get_config_synthesize_ptr_default` | start.py default is "1" |
| `test_start_no_synthesize_ptr_arg_when_disabled` | flag "0" → `--no-synthesize-ptr` in cmd |
| `test_start_no_synthesize_ptr_arg_absent_when_enabled` | flag "1" → no `--no-synthesize-ptr` |
| `test_start_no_synthesize_ptr_arg_absent_by_default` | absent from XML → no `--no-synthesize-ptr` |

**Integration tests** (`tests/integration/test_ptr_lifecycle.py`, D5b group):

| ID | Setup | Action | Expected |
|----|-------|--------|----------|
| F-off | daemon started with `--no-synthesize-ptr` | DORA | A registered; `list_local_data` has NO `in-addr.arpa` entry |
| F-off2 | `--no-synthesize-ptr` + reverse zone set (Path 2) | DORA | PTR present via explicit reverse NCR only |
| F-adv | custom / missing reverse zone + synthesis ON | Config Check tab API call | F4/F5 advisory present in `d2_advisories` response |

### D6 — DHCPv6 end-to-end (rig buildout required — see Part E)

For each relevant D2/D3/D4/D5b test above, a v6 analogue is run using:
- `kea-dhcp6` on dev-opnsense with ULA/GUA subnet on `em1`
- `tests/ddns6_test.py` SARR harness on dev-dhcpclient
- `kea6` / `dhcp6_subnet_id` fixtures in `tests/integration/conftest.py`

IPv6 PTR owner names use `ip6.arpa` (128-nibble reverse); the daemon's `reverse_ptr()`
and `_arpa_to_ip()` handle both families identically, so the test assertions mirror
v4 with `ip6.arpa` substituted for `in-addr.arpa`.

---

## Part E — DHCPv6 rig buildout runbook

The rig currently runs `kea-dhcp4` only; `kea-dhcp-ddns` is not started and there
is no DHCPv6 client. Full v6 e2e requires:

### E.1 — dev-opnsense

1. Enable `kea-dhcp6` in OPNsense GUI:
   - Add a DHCPv6 subnet on `em1` (e.g. `fd00:db8:1::/64` or a real GUA if available)
   - Set pool and `ddns-qualifying-suffix`
   - Set `ddns_forward_zone` (same zone as v4 or a v6-specific zone)
   - Set `ddns_reverse_zone` (e.g. `1.0.0.0.8.b.d.0.0.0.0.0.0.0.0.f.d.ip6.arpa.`)
2. Confirm `KeaDdns.general.enabled` — if enabling for the first time:
   ```sh
   echo dev | sudo -S configctl template reload OPNsense/Kea
   echo dev | sudo -S configctl kea restart
   ```
3. Verify `kea-dhcp6` and `kea-dhcp-ddns` are running:
   ```sh
   echo dev | sudo -S pluginctl -s kea-dhcp6 status
   echo dev | sudo -S pluginctl -s kea-dhcp-ddns status
   ```
4. Enable IPv6 RA/forwarding on `em1` (if not already) so the v6 client can
   complete SARR without static config.

### E.2 — dev-dhcpclient

1. Enable DHCPv6 on `ens19`:
   ```sh
   sudo dhclient -6 ens19
   ```
   OR use the new `tests/ddns6_test.py` scapy harness with a specific ULA prefix.
2. Verify lease acquisition:
   ```sh
   ip -6 addr show ens19
   ```

### E.3 — New test harness files

- `tests/ddns6_test.py` — scapy DHCPv6 SOLICIT/REQUEST/RELEASE with Client-FQDN
  option 39 (v6 equivalent of option 81). Mirrors `tests/ddns_test.py` structure.
- `tests/integration/conftest.py` — add `kea6` and `dhcp6_subnet_id` fixtures
  (mirroring `kea` / `dhcp4_subnet_id`), a `v6_lease_release` helper, and a
  pytest mark `v6` to skip when kea-dhcp6 is not running.
- `tests/integration/test_ptr_lifecycle.py` — D2/D3/D4/D5b and D6 cases.

---

## Part F — Verification summary

| Phase | Command | What it checks |
|-------|---------|----------------|
| Unit fast | `source .venv/bin/activate && python3 -m pytest tests/unit/ -v -m unit` | All D1/D5b unit cases, F1/F2 regression, synthesis flag gating |
| Lint | `bash tests/run_lint.sh` | Code quality |
| Integration v4 | `bash tests/run_integration.sh` | D1–D5 over real DHCPv4 on dev-opnsense |
| Integration v6 | `bash tests/run_integration.sh -m v6` | D6 cases after Part E buildout |
| Manual F2 spot-check | See below | Confirms F1 + F2 fix end-to-end on production Unbound |

**Manual F2 spot-check** on dev-opnsense:
```sh
# Pre-seed a static PTR for a reserved IP
echo 'local-data-ptr: "192.168.1.99 reserved-host.dev.plhm.rgn.cm."' >> \
    /var/unbound/host_entries.conf
echo dev | sudo -S pluginctl -s unbound reload

# Send a DDNS A-add for a different hostname at the same IP
# (use tests/ddns_test.py on dev-dhcpclient with --req-ip 192.168.1.99)

# Verify: forward A registered, static PTR intact
echo dev | sudo -S unbound-control -c /var/unbound/unbound.conf list_local_data \
    | grep -E "99|reserved-host|other"
# Expected:
#   other.lan. 300 IN A 192.168.1.99
#   99.1.168.192.in-addr.arpa. 300 IN PTR reserved-host.dev.plhm.rgn.cm.
```
