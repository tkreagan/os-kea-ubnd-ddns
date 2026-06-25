# Changelog — os-kea-ubnd-ddns

## Release process

Before tagging a release, verify each item:

- [ ] `PLUGIN_VERSION` bumped in `Makefile`
- [ ] If any model field was added, renamed, or removed:
  - [ ] `<version>` bumped in `src/opnsense/mvc/app/models/OPNsense/KeaUbnd/General.xml`
  - [ ] `Migrations/M<model_version>.php` added (e.g. `M1_0_2.php` for model version `1.0.2`)
  - [ ] Migration tested on a box running the previous schema (see [Schema version history](#schema-version-history))
- [ ] `build_package.sh` produces a clean package (`pkg info -l -F` shows no macOS artifacts)
- [ ] Integration tests pass on a rolled-back test OPNsense box
- [ ] Package installs cleanly from scratch and via upgrade on a rolled-back dev VM

### Schema version history

Model schema version (`<version>` in `General.xml`) is independent of the plugin package
version. The table below maps each schema version to the package release that introduced it.

| Model version | Package version | Changes |
|---|---|---|
| 1.0.0 | 0.9 (initial) | Initial model schema |
| 1.0.1 | 0.98 | `clean_on_restart` renamed to `clean_stale_records`; added `write_magic_ptrs`, `enable_fast_reload`, `fast_reload_threshold`, `enable_fast_reload_cron`, `fast_reload_cron_days`, `fast_reload_cron_hour` |

---

## [0.98] — 2026-06-24

**Model schema: 1.0.1** (migration `M1_0_1` required on upgrade from 0.9x)

### Added
- Magic collision names (`--magic-names`, `--laa-tag`): automatic per-MAC disambiguation FQDNs for hostnames that collide across multiple IPs
- Magic PTR option (`write_magic_ptrs`): optionally point PTR records at the magic FQDN rather than the original hostname on collision
- `fast-reload`: periodic `unbound-control reload` under the mutation lock to reclaim heap memory fragmented by repeated `local_data` operations; configurable threshold (default 5000 NCRs) and weekly cron safety net
- `none` collision policy: evict all dynamic records when a hostname conflict is detected
- `kea-ubnd-logwatch` daemon: fast-path DNS cleanup triggered by Kea log events (DHCP release, SERVFAIL, missed removes) without waiting for the next cron run
- Lease Audit tab in web UI (`status.volt`): live JSON-driven table of all Unbound records with Kea lease/reservation status, PTR state, collision state, and magic FQDN annotations
- Kea Config Check tab in web UI (`configcheck.volt`)
- Unified `kea-sync.py` replacing separate `reservation-sync.py` and `lease-sync.py`
- `lib/keaubnd_runtime.py`: single source of truth for all external paths; written once at daemon start, read by all lib modules
- `lib/consistency_sm.py`: pure tested state machine (BLOCKED/NORMAL) with dirty-name drain
- `lib/pid_watch.py`: kqueue EVFILT_VNODE pidfile watcher for Kea/Unbound pid cycles
- `--clean-stale` on every startup full sync when `clean_stale_records` is enabled
- `_evict_record` shared helper in `keaubnd_sync` for typed per-IP removal with sibling-family preservation
- Advisory mutation lock (`/var/run/keaubnd/unbound-mutation.lock`) shared across daemon and sync scripts
- `build_package.sh`: standalone FreeBSD package builder (no OPNsense build tree required)

### Changed
- `clean_on_restart` renamed to `clean_stale_records` (migration `M1_0_1` carries the saved value)
- `collision_policy` default changed from `allow` to `last_wins`
- Daemon lifecycle: stop/restart targets the supervisor pidfile, not the child, to avoid dueling supervisors under `daemon -r`
- All external path lookups moved to `lib/keaubnd_runtime.py`; config.xml reads confined to `start.py` and `preconditions.py`
- `fast-reload` reload command hardcoded to `reload` (not `fast-reload`) pending upstream fix for `unbound-control fast-reload` memory leak

### Fixed
- Correctness audit findings A–J (unified dirty pool, normalize_hostname, PTR target guard, stale-clean over-prune, magic FQDN keying by FQDN not IP, logwatch `--mode` flag)
- Audit `local-data-audit.py`: magic FQDN protection check used `bare_key + domain` (double-appending the domain suffix), causing magic FQDNs to appear as `stale` in the Lease Audit page

---

## [0.9] — 2026 (initial release)

**Model schema: 1.0.0**

- RFC 2136 DNS UPDATE stub listener (`kea-ubnd-ddns.py`) on `127.0.0.1:53535`
- Static reservation sync (`reservation-sync.py`) and dynamic lease sync (`lease-sync.py`)
- Stale record audit (`local-data-audit.py`) and cleanup (`local-data-clean.py`)
- OPNsense web UI: Settings tab and Log File tab
- Syslog integration (`kea-ubnd` program tag, `/var/log/keaubnd/`)
- `synthesize_ptr`: automatic PTR record synthesis alongside A/AAAA registration
- `allow` / `first_wins` / `last_wins` collision policies
- `host_entries.conf` static-guard: Unbound host overrides are never modified by the daemon
