# Implementation & test plan: resident-daemon consistency authority

> **STATUS: ALL PHASES COMPLETE (2026-06-11).** Phases 1–7 and all verification
> spikes (V1–V6) are implemented and committed. All open risks (R1–R11) are
> resolved — see the "Open risks" section for the DECISION recorded against each.
> This document is a historical record; read `resident-daemon-design.md` for the
> current architectural reference.

Companion to `resident-daemon-design.md`. The design says "no design questions
remain open — the rest is implementation." This document is that implementation
plan, **plus a critical pass that surfaces the implementation-level problems the
design glossed** (the design reasons at the architecture level; several of its
load-bearing claims need a verification spike or a concrete mechanism before
code). Read the "Open risks" section first — it gates Phase 0.

---

## Guiding constraints (carried from the design)

- **ACK d2 within 500 ms, unconditionally.** The single-threaded event loop must
  never block long on any apply. This is the dominant correctness constraint and
  it dictates timeouts everywhere on the live path.
- **Resync is the sole durability layer.** d2 drops failed updates with no replay,
  so a missed live apply is only ever healed by a reconcile. Never "abandon" — the
  safe direction is always *more complete*.
- **Level-triggered, never edge-triggered.** kqueue events are wake-ups only;
  ground truth is `stat()` of the enabled pidfiles each pass.
- **Pure, injectable state machine.** The watcher/state-machine logic must be
  unit-testable on macOS with no dev box, no real kqueue, no real subprocesses.

---

## Phase 0 — Verification spikes (BLOCKING; do before any code)

Each item is a load-bearing assumption in the design that is *asserted* but not
proven in-repo. Resolve them on dev-opnsense first; a wrong assumption here
invalidates a whole subsystem.

| # | Assumption to verify | Why it gates | How |
|---|---|---|---|
| V1 | ✅ **ANSWERED (see R6).** Measured: **Unbound rewrites its pidfile in place** (same inode, no absence → dir watch MISSES it); **Kea unlink+recreates** (inode changes, ~40 ms absent → dir watch fires, file fd goes stale). ⇒ watch set must be **per-file + directory**, not directories only. | The design watched directories only; this would have silently missed every unbound restart. | Done via inode/absence/pid-value polling across real restarts on dev-opnsense. |
| V2 | ✅ **ANSWERED — GREEN.** `/var/run` is **idle**: a `KQ_FILTER_VNODE` watch on the directory logged **0 events over 30 s** on a quiescent box. No wakeup storm — watching the `unbound.pid` dir + per-file is cheap. (`unbound.pid` → `/var/run`; kea pids → `/var/run/kea/*.pid`.) | unbound.pid lives in `/var/run`; a wakeup storm would burn CPU re-stat'ing every pass. | Measured via a kqueue NOTE_WRITE/EXTEND/DELETE/RENAME watch on `/var/run`, 30 s idle. |
| V3 | ✅ **ANSWERED — GREEN.** `host_entries.conf` is written by exactly ONE function (`unbound_add_host_entries`, the sole caller is line 284 **inside `unbound_generate_config()`**), and `unbound_configure_do` reaches `generate_config` only **after** its interface early-return **and after `unbound_service_stop()`** — always followed by a start. So **host_entries can never change without an Unbound stop→start (pid cycle)**. Empirically confirmed: a host-override reconfigure cycled the pid (8360→3991, same inode = in-place rewrite) and rewrote host_entries. ⇒ the daemon's cache re-read on BLOCKED→NORMAL is **sufficient**; no separate invalidation required. *(Optional belt-and-suspenders: a cheap mtime stat on the live path would harden against a future OPNsense refactor of this call order.)* | If host_entries could change without a restart, the in-memory cache (re-read only on BLOCKED→NORMAL) would go stale and the static guard would read wrong data. | Read the OPNsense unbound.inc call graph + empirical pid/mtime/inode before+after `pluginctl -c unbound_start`. |
| V4 | ✅ **ANSWERED — GREEN.** `lease4-get-by-hostname` verified against the live kea4 control socket (result 0, returned 2 leases for a real hostname). `kea-sync.py`'s targeted drain (`query_kea_leases_by_hostname`) works. Still **no `reservation-get-by-hostname`** → static drain re-asserts all reservations (R8, cheap/idempotent). Bonus: the test host held **two** active leases on one FQDN (.100/.101, both state 0) — the exact same-FQDN dedup case the two-phase `_collect_writes` resolves (higher-cltt wins under last_wins). | "O(dirty) cheap" drain assumes by-name lookups exist. | Raw unix-socket call to `/var/run/kea/kea4-ctrl-socket`. |
| V5 | ✅ **ANSWERED — methodology decided (not a runnable spike).** d2 has **no control socket** on OPNsense, so its internal failed-update counter is not queryable — there is nothing to measure standalone. **DECISION:** instrument the Phase-3 daemon to log per-NCR **receive→sendto latency**; the ACK-budget scenario (Phase 6 #6) asserts on **our** latency (< 500 ms) and cross-checks d2's log for DROP/timeout lines. Carried as a Phase-3 implementation task + Phase-6 assertion, not a Phase-0 measurement. | d2's failed-update counter is not observable on OPNsense. | n/a — decision, executed in Phase 3/6. |
| V6 | ⚠️ **ANSWERED — needs inheritance-aware precondition (don't reuse the strict check).** `KcaconfigController.php:511,693` gate on `isset($subnet['ddns-send-updates']) && === true` — **per-subnet only**, so absent/global/inherited reads as "no DDNS." On the dev box it passes only because subnet 1 sets it explicitly; a valid config that sets `ddns-send-updates` globally (or relies on the Kea default of `true`) would **false-refuse startup**. The real master switch is global `dhcp-ddns.enable-updates` (true here) + the d2 forward target (correctly `127.0.0.1:53535`). **DECISION:** the Phase-4 startup precondition must resolve effective DDNS as `dhcp-ddns.enable-updates` (global master) AND d2 forward → our port AND ≥1 subnet **not explicitly disabled** (treat absent as inherited/enabled). Keep the strict per-subnet check only as a Config-Check advisory. | `ddns-send-updates` can be set globally / left to default; a per-subnet-only check false-refuses a valid global config. | Read the running kea-dhcp4.conf + kea-dhcp-ddns.conf placement and the existing PHP parser. |

**Exit criteria:** V1 and V3 must be GREEN or the design's watch-set / cache
model changes. V4–V6 may downgrade to documented fallbacks.
**STATUS: all spikes resolved.** V1 ✅ (per-file + dir watch, read pid value),
V2 ✅ (`/var/run` idle, no storm), V3 ✅ (host_entries change ⇒ guaranteed pid
cycle; cache re-read sufficient), V4 ✅ (`lease-get-by-hostname` exists; static
drain re-asserts all), V5 ✅ (instrument per-NCR latency), V6 ⚠️ (precondition
needs inheritance-aware resolution; strict per-subnet check stays advisory-only).
Phase 3 is unblocked.

---

## Phase 1 — Factor out the state machine as a pure, unit-testable module

No behavior change to the running plugin yet. This is the highest-leverage step:
the state machine is where all the subtle logic lives, and it must be testable
without FreeBSD or a dev box.

**New: `src/opnsense/scripts/keaunbound/lib/consistency_sm.py`**
- A class implementing the BLOCKED/NORMAL machine from design §3, taking **all
  side effects as injected callables**:
  - `stat_pids() -> dict[svc, (exists, pid)]` (the level read)
  - `spawn_reconcile(mode, names) -> handle` and `reap(handle) -> exit_code`
  - `now() -> float`, `acquire_lock_nb() -> bool`, `release_lock()`
  - `mark_ack_fail(names)`, logger
- Owns: dirty-key **set** (deduped, bounded by cap), `full_sync_counter`,
  backoff state (0.25 s ×2, cap 60 s), watchdog clock, overflow flag handling,
  drain loop (snapshot+clear → spawn → on-exit repeat → empty ⇒ NORMAL).
- **No** kqueue, **no** real subprocess, **no** module globals (design Risks bullet).

**New: `tools/test_consistency_sm.py`** (pytest, runs on macOS):
- Quiesce: healthy stat → one reconcile → NORMAL.
- Single flap: pid disappears → BLOCKED; reappears → reconcile → NORMAL.
- **Fast-flap:** pid value changes between two passes with no "absent" sample
  caught — assert level read still forces BLOCKED (the 1 Hz-poll-miss case).
- Reconcile-fails-then-pid-flaps-mid-backoff → stays BLOCKED, no blind retry.
- **Overflow:** dirty set hits cap during reconcile → discard + counter++;
  counter ≥ max → NORMAL + alert flag set.
- **Watchdog:** stuck in BLOCKED past deadline → terminate signal emitted;
  `0` ⇒ never trips.
- **Drain idempotency:** names already healed re-resolve to no-op; non-empty
  snapshot loops until empty.
- **Lock contention:** `acquire_lock_nb()` returns False on a live apply →
  ACK-fail + dirty + BLOCKED (see Risk R3 for the recovery-cost caveat).

---

## Phase 2 — Merged reconciler `kea-sync.py` + shared mutation lock

**New: `src/opnsense/scripts/keaunbound/kea-sync.py`**
- `--mode=static|dynamic|full` and `--names=<comma-list>` (drain filter).
- `full` = **static before dynamic** (high-value records survive a flaky dynamic
  pass).
- **Fail-fast** (design §4): Kea socket/query fail, host_entries read-error/locked,
  or `unbound-control` connection-refused → exit non-zero immediately (die-retry).
  `host_entries` **missing ≠ die** (empty guard). No probes, no per-service retry
  loops (delete the `range(3)` retry in `reservation-sync.py:68`).
- **Acquires the shared Unbound-mutation lock** for the whole run.
- **Batch via `local_datas`** (stdin) — one exec for many records, chunked to
  bound a single command's size. (Big full-sync win; no ACK pending on this path.)

**Shared lock — new helper in `lib/keaunbound_sync.py`:**
- `unbound_mutation_lock()` context manager over a fixed path
  (`/var/run/keaunbound/unbound-mutation.lock`), `flock(2)` advisory.
- Blocking acquire for standalone scripts; the daemon live path uses a
  **non-blocking** variant.
- Retrofit it into: `kea-sync.py`, `local-data-clean.py`, and the daemon.

**Conflict-policy dedup in the reconciler:**
The reconciler must group leases by `fqdn_fwd` and resolve conflicts before
writing to Unbound — writing two A records for the same FQDN produces
non-deterministic round-robin answers. Policy determines the selection rule:
- `first_wins` / `E`: take the first lease encountered in Kea's iteration order
  (deterministic first-seen); log any skipped collisions.
- `last_wins`: take the lease with the highest `cltt` (`= expire - valid_lifetime`,
  the client's last-transaction time); log skipped collisions with both cltt values.
- `always` (always overwrite): **no dedup** — write every lease from Kea as-is.
  Round-robin or last-write behavior in Unbound is accepted. No ownership logic.

Reservations (`static`) are always written without dedup (Kea validates uniqueness
there). Dedup applies only to the dynamic lease pass.

**Targeted lookups (lib):** add `query_kea_lease_by_hostname(service, host)`
(`lease{4,6}-get-by-hostname`). For static, **no by-name Kea call exists** — drain
checks a cached `reservation-get-all` snapshot (see V4). Document that drain is
effectively dynamic-targeted + static-from-cache.

**Call-site sweep (atomic with the above):**
- `actions_keaunbound.conf`: `sync_static` → `kea-sync.py --mode=static`,
  `sync_dynamic` → `kea-sync.py --mode=dynamic`. (Keep action names — the UI and
  `tools/base.py` call them.)
- Delete `reservation-sync.py`, `lease-sync.py`, `sync-debounce.py` (and stale
  `.pyc`). Grep for every reference first (`keaunbound.inc`, `actions`, tools).

---

## Phase 3 — Daemon rewrite: kqueue loop + integrate the state machine

**`src/sbin/kea-unbound-ddns.py`** — replace the blocking `recvfrom` loop
(currently `:741`) with a single `select.kqueue` loop multiplexing:
- `EVFILT_READ` on the UDP socket (now **non-blocking**; on wake, **drain all
  datagrams** until `EWOULDBLOCK` — don't leave packets queued between passes).
- `EVFILT_VNODE`/`NOTE_WRITE` on the enabled pidfile **directories** (+ per-file
  watches if V1 says in-place rewrite happens), scoped to enabled services.
- `EVFILT_TIMER` for backoff/watchdog.
- `EVFILT_PROC`/`NOTE_EXIT` on the reconcile subprocess PID. **Handle the ESRCH
  race**: if the child exits before `kevent()` registration, registration fails
  with ESRCH → reap immediately and treat as completion (don't hang).

**Live apply path (the 500 ms budget):**
- One NCR's forward + PTR(s) → **one `local_datas` exec** (intra-NCR batch only;
  never coalesce across NCRs — the Nagle trap). One result → one RCODE.
- **Short, explicit timeout on the live-path `unbound-control`** — well under
  500 ms (e.g. 300 ms), *distinct from* the sync path's 10 s. A hang (not a
  refusal) of unbound-control is the real latency killer in a single-threaded
  loop; the current code's 10 s timeout (`kea-unbound-ddns.py:169`) would blow
  the budget and stall every other pending ACK.
- Decision precedes exec: static-guard + BLOCKED check first. BLOCKED or
  lock-contended → ACK-fail + dirty + BLOCKED. Refused on apply → ACK-fail +
  dirty + BLOCKED. Skip-per-policy → ACK without mutating.
- **Apply the collision policy inline on the live path** (same logic as
  `kea-sync._collect_writes`): an ADD for `host→newIP` when `host→oldIP` exists is
  a same-FQDN collision. `last_wins` → remove-then-add (replaces the stale IP, all
  under the one lock we already hold); `first_wins` → reject if a different IP
  exists; `allow` → additive.
- Lock: **non-blocking** `unbound_mutation_lock(blocking=False)`; on
  `BlockingIOError` → ACK-fail + `note_dirty(name)` + stay NORMAL (re-resolved on
  the next wake drain). Held only for the duration of one synchronous apply
  (sub-300 ms), so dropping to BLOCKED never has to "release a long-held daemon
  lock" — the daemon never holds it across event-loop turns.
- **RETIRE the daemon's aggressive-cleanup subprocess (DECISION — with TR).** The
  current daemon spawns `local-data-clean.py --hostname` after an ADD
  (`kea-unbound-ddns.py:382`) to drop a stale old IP Kea didn't DELETE. That is
  now fully subsumed by the inline collision policy above (the stale old IP *is*
  the same-FQDN collision the live ADD resolves). Dropping it (a) removes a fork
  from the latency-sensitive live path, (b) **eliminates the clean-subprocess
  deadlock hazard entirely** (the daemon no longer spawns clean while holding the
  lock), and (c) collapses the overlapping `aggressive_cleanup` and
  `collision_policy` settings into one. Cron clean remains the floor for *orphan*
  stale records (different-hostname leftovers the live path never sees). Remove
  `--aggressive-cleanup`, `_cleanup_host`, and `CLEANUP_SCRIPT` from the daemon;
  evaluate removing the `aggressive_cleanup` model field (or fold its meaning into
  `collision_policy`).
- **KillPending must `waitpid` the killed child** so its lock fd is fully closed
  before a replacement reconcile is spawned. flock is released by the kernel on
  process death (no explicit unlock needed), but the wait avoids two transient
  holders. External clean/sync are NOT daemon-owned — never killed; the daemon
  defers / queues behind them (blocking-acquire reconcile waits for the external
  holder to finish; no deadlock since external runs are bounded).

**host_entries cache:** in-memory copy, re-read once on BLOCKED→NORMAL (before
resuming live applies). Replaces the per-packet file reads
(`kea-unbound-ddns.py:243` and its 6 call sites). **Conditional on V3.**

**Wire the Phase-1 state machine** with real implementations of the injected
callables (kqueue stat, Popen spawn, NOTE_EXIT completion, flock).

**Enabled-set change on recovery (design §6/§7) — RESOLVE THE LIFECYCLE (Risk R1):**
Recommended: **re-derive in-process** — on recovery, re-read only the enabled
flags from `config.xml`; if changed, re-resolve the watch set and preconditions
**without** a process restart. This avoids the self-restart race entirely (a
daemon under `daemon -r` that exits gets respawned with the *same* args, not a
re-run of `start.py`). If a full restart is truly required, it must go through a
clean `configctl keaunbound restart` with a documented handshake — but in-process
re-derivation is strongly preferred.

**Watchdog expiry:** clean full stop — kill the supervisor **before** the child
exits (so `-r` can't respawn), write the UI status file, leave stopped. Reuse
`stop.py`'s supervisor-pidfile logic; sequence carefully (Risk R2).

**Startup:** bind socket, enter **BLOCKED immediately**, run the machine.

---

## Phase 4 — `start.py` preconditions, resolved conf, UI status

**`start.py`** (design §2, "Process orchestration"):
1. Clean leftover pidfiles (already done, `:122`).
2. **Hard gate:** `unbound-control` present/executable. Missing ⇒ refuse + UI reason.
3. **Enablement/wiring gate** (reuse `kea_transport._is_service_enabled` /
   `_is_manual_config`): Unbound enabled, d2 enabled, ≥1 of dhcp4/dhcp6, ≥1
   subnet DDNS-enabled & pointed at our port. `manual_config` ⇒ downgrade the d2
   gate to a Config-Check advisory, don't refuse (V6 for inheritance).
4. **Write a resolved conf file** the daemon reads (single resolver; daemon does
   not parse `config.xml` except the enabled-flags recheck in Phase 3).
5. Launch via `daemon(8)` (unchanged flags).
- On any refusal: write the reason to a **status file**; do not start.

**Status surfacing:** `StatusController` reads the status file; `index.volt`
shows the banner ("not running: Unbound disabled" / "stopped: not ready within
N m"). Two states: *refused-to-start* (Phase 4) and *watchdog-stopped* (Phase 3).

---

## Phase 5 — Hooks, cron scheduling UI, advanced settings

**`keaunbound.inc`:**
- **Retire ALL resync configure-hooks** (`kea_start`, `kea_sync`, `unbound_start`,
  `dns`, `local`, `newwanip`) and the whole `keaunbound_request_sync` + debounce
  machinery (`:169`–`:214`). Pidfile-watching is the primary trigger and makes
  them redundant (Risk R4 / DECISION). This is a net simplification, not a gate.
- **Keep `keaunbound_start_do` on `bootup:2`** (daemon launch — not a resync hook).
- The plugin's own settings change still restarts the daemon via the service hook
  (reconfigure → restart → startup reconcile); unaffected.
- **`keaunbound_cron` stays clean-only** (see R4 — cron full reconcile removed).

**New scheduling UI** (`General.xml` + `generalSettings.xml` + `index.volt` +
`keaunbound_cron`): two modes — *"every N hours"* (presets **1/3/6/12**,
default **6**) or *"daily at <time>"*. **Config migration required** (Risk R7):
existing `auto_clean_interval` = h6/h12/h24 must map to the new mode field
(OPNsense `Migrations/M1_0_1.php`), or default gracefully.

**Advanced settings** (`General.xml`): `dirty_set_cap` (100),
`max_full_sync_attempts` (5), `readiness_watchdog_minutes` (10, `0`=forever),
with help text on the terminate-vs-auto-recover tradeoff.

**Model: remove `aggressive_cleanup`; change `collision_policy` default to
`last_wins` (DECISION — with TR).** `aggressive_cleanup` and `collision_policy`
both govern the *same* decision — what happens to a host's old IP when a new one
arrives — and can contradict (e.g. `aggressive_cleanup=ON` + `collision_policy=
allow` = "remove old IP" AND "keep both"). With the live path applying
`collision_policy` inline (the change that retired the daemon's cleanup
subprocess), `aggressive_cleanup` has no independent behavior left.
  - **Remove** the `aggressive_cleanup` `<BooleanField>` from `General.xml`, its
    row in `generalSettings.xml`, the `start.py` arg-passing
    (`start.py:72,146-147`), and the daemon's `--aggressive-cleanup` flag +
    `_cleanup_host`/`CLEANUP_SCRIPT` (Phase 3).
  - **Change `collision_policy` Default from `allow` to `last_wins`** — preserves
    today's effective behaviour (old default was `aggressive ON` + `allow` ≈
    last_wins) and matches the R11 recommendation (MAC-randomization-safe,
    deterministic). Single-knob story: `last_wins` (one current IP, default) /
    `allow` (multi-IP coexist, the old `aggressive OFF`) / `first_wins`
    (best-effort, R11 caveats).
  - No migration (R7: reset to defaults on upgrade).

---

## Phase 6 — Integration testing on dev-opnsense

Update the harness first, then add scenarios.

**Harness updates (`tools/`):**
- `base.py:run_sync` still calls `configctl ... sync_static|sync_dynamic` — works
  unchanged once Phase 2 repoints the actions. Verify.
- Add a `ChaosContext` helper to read the daemon's per-transition log + status file.

**New / updated scenarios (map to design §"Verification" 1–9):**
1. Quiesce baseline → NORMAL.
2. Flap each component (`service kea_dhcp4 onerestart`, dhcp6, unbound, d2) →
   immediate BLOCKED, dirty recording, recovery → NORMAL. (Extend
   `service_resilience.py`, which currently still drives the manual-sync model.)
3. **Fast-flap** down+up inside ~1 s → still caught (the 1 Hz-miss case).
4. **Flush recovery, no PHP hook:** populate, restart Unbound, assert
   `list_local_data` repopulates **and** confirm no `keaunbound_request_sync`/hook
   fired (grep log).
5. **d2-drop recovery:** lease change while Unbound mid-restart → record restored
   from Kea by the resync.
6. **d2 ACK budget:** assert daemon receive→sendto latency < 500 ms during a
   sync (self-instrumented per V5; cross-check d2 log for drops).
7. **Dynamic enablement:** enable dhcp6 → daemon re-derives → watches/syncs v6
   (per Phase 3 in-process re-derive).
8. **Preconditions:** disable Unbound / both DHCP → daemon refuses to start, UI
   banner shows reason.
9. Drive the state machine against **simulated pidfile churn** — but note this is
   mostly covered by the Phase-1 unit tests; the dev-box scenario covers the real
   kqueue wiring.

Run order: Phase-1 unit tests gate every commit; full chaos suite on dev box
after Phases 3–5 land (`make upgrade`, then `configctl keaunbound restart`).

---

## Phase 7 — Cleanup & docs

- Update `CLAUDE.md` (layout, "when to restart what", the retired scripts, the
  new lock, the new schedule model).
- **Update README:**
  - Add **HA (high availability) not supported** notice — plugin reads from the
    local Kea instance only; Kea HA pairs with divergent lease databases are
    undefined and untested (R11).
  - Add **conflict policy explainer** — describe `always`, `last_wins`, and
    `first_wins`/E modes, why DHCID is not used, and the `first_wins` caveats for
    MAC-randomizing or roaming clients (R11).
- Update any int-docs that reference `sync-debounce`/the old scripts.
- Remove committed `__pycache__`/`.pyc`.

---

## Open risks & problems (the design's implementation-level gaps)

Ordered by how badly a wrong call hurts.

- **R1 — Self-restart on enabled-set change is a lifecycle trap (design §6/§7).**
  A daemon under `daemon -r` that exits is respawned with the *same args*; it does
  **not** re-run `start.py`, so "restart ourselves to re-resolve watches" as
  written can't re-resolve. Calling `configctl keaunbound restart` from inside the
  daemon runs `stop.py`, which kills the supervisor, which kills the daemon —
  *including the `configctl` child it just spawned* — before `start.py` runs, so
  the restart never completes.
  **VERIFIED ON DEV BOX — the trap mostly isn't one.** `configctl` is a thin
  client (symlink → `configd_ctl.py`) that only relays to the independent
  **`configd`** service (pid 7638); `configd` runs `stop.py ; start.py`, **not**
  our process subtree. So when `stop.py` kills our supervisor/daemon, `configd`
  carries on and runs `start.py` — the restart completes. No `setsid`/double-fork
  needed (my earlier "restart never completes" assumed `configctl` itself ran the
  action; it doesn't).
  **DECISION (with TR): keep the full-plugin restart**, fire it **once** and
  **without blocking** the event loop — `subprocess.Popen(["configctl","keaunbound",
  "restart"])` and continue (the incoming SIGTERM from `stop.py` kills us). Guard:
  debounce the enabled-set-change detection so we issue exactly one restart per
  change, not one per recovery wake. `stop.py ; start.py` is sequential and
  `stop.py` waits for clean exit, so the port is released before `start.py` binds.

- **R2 — Watchdog "kill the supervisor too" sequencing.** The child must kill the
  `daemon -r` supervisor *before* it exits, or `-r` respawns it. Get the order
  wrong and you either orphan the child or crash-loop. Reuse `stop.py`'s
  supervisor-pidfile signaling and verify the sequence under test.

- **R3 — Lock contention must NOT block the daemon (RESOLVED — design changed).**
  Original design: block-trigger set = `{pid absent/changed} ∪ {lock held
  externally}`, unblock requires a successful full sync — so a routine 2-second
  cron `clean` would push the daemon BLOCKED → full reservation+lease resync every
  clean interval. **DECISION (with TR): lock contention is a NORMAL-state concern,
  not a BLOCKED trigger.** A live apply takes the shared mutation lock with a
  *short bounded wait* (~100 ms, inside the 500 ms ACK budget); if it can't get it
  it ACK-fails and **stays NORMAL**. BLOCKED is triggered **only** by pid
  absent/changed. The lock's sole job is keeping unbound-control mutations atomic
  between the daemon's live path, `kea-sync`, and `clean`. **Implemented in
  `consistency_sm.py`.**

  **FINAL POLICY (with TR): save name on contention, re-resolve on next wake.**
  The live path uses plain **`flock -n`** (non-blocking; holding it longer than
  ~100 ms would blow the 500 ms ACK budget anyway):
  - Got the lock → apply + release → ACK d2.
  - Contended → ACK-fail d2 + call **`note_dirty([name])`** → stay NORMAL.
    The name is re-resolved from Kea by hostname on the next `on_wake` drain —
    safe and idempotent because re-resolve reads current Kea truth, not the raw NCR.
  - This means `dirty` is used in BOTH states: BLOCKED (deferred NCRs during a
    restart) and NORMAL (lock-contention misses). `_tick_normal` checks `self.dirty`
    and spawns a targeted drain on the next wake; `on_sync_exit` loops until empty
    then stays NORMAL.
  - The one NORMAL apply-failure that enters BLOCKED instead is `unbound-control`
    **connection-refused** (Unbound actually down) — `on_apply_failure()`, distinct
    from lock contention.
  - **Implemented in `consistency_sm.py`**; covered by
    `test_lock_contention_normal_drains_on_wake`,
    `test_lock_contention_drain_failure_readds_names`, and
    `test_apply_failure_unbound_down_enters_blocked_and_drains`.

- **R4 — Retire the Kea/Unbound resync hooks entirely (DECISION — with TR).**
  Originally I proposed gating the belt-and-suspenders hooks on "daemon-down" to
  avoid a boot storm. **Better: with pidfile-watching as the primary trigger, the
  resync configure-hooks are redundant and should be removed outright.** Every
  Kea/Unbound restart that those hooks accompany *is* a pid cycle the daemon
  already catches; keeping them only risks the storm. Concretely in
  `keaunbound.inc`:
  - **Remove** the resync hooks: `kea_start`, `kea_sync`, `unbound_start`, `dns`,
    `local`, `newwanip` → `keaunbound_request_sync` (and the whole
    request_sync/debounce machinery).
  - **Keep `bootup` → `keaunbound_start_do`** (this is how the daemon launches at
    boot — not a resync hook).
  - **Keep the plugin's own service-restart path** (settings change → reconfigure →
    daemon restart → startup reconcile). Unaffected by the above.
  - **Cron stays clean-only (DECISION — with TR).** A periodic full reconcile was
    considered as an anti-entropy floor, but the SM already reconciles on every
    Kea/Unbound restart (the primary drift source), the lock-contention dirty drain
    covers missed live applies, and a cron-fired full reconcile would silently
    override the live first_wins decisions the conflict policy makes. Not worth it.
    Cron keeps its existing `local-data-clean.py` role only.

- **R5 — Live-path `unbound-control` hang stalls all ACKs (RESOLVED — 300 ms).**
  Single-threaded loop + synchronous `subprocess.run`. A *hung* (not refused)
  unbound-control during an Unbound restart, at today's 10 s timeout
  (`kea-unbound-ddns.py:169`), blows the 500 ms budget for that NCR **and** delays
  every queued NCR's ACK. **Measured on dev-opnsense (446 local_data lines):**
  `status`/`list_local_data`/`local_data` all run **9–15 ms** (median ~10 ms, max
  15 ms; mostly fork/exec, not Unbound work). **DECISION: live-path timeout = 300 ms**
  (~20× headroom over worst normal case), distinct from the sync path's 10 s (no
  ACK pending there). Connection-refused (Unbound down) returns near-instantly via
  RST; the 300 ms cap only bounds the rare half-up "accepted-but-silent" case.

- **R6 — Watch set MUST be per-file + directory (RESOLVED — measured on dev box;
  design's "directories only" is WRONG).** The two services differ:
  - **Unbound** restarts by rewriting its pidfile **in place** — *same inode*
    (11618605), pid value changes (61686→8360), **never goes absent**. A directory
    `NOTE_WRITE` does NOT fire (no entry add/remove/rename), and the inode is
    unchanged, so a **dir-only watch misses every unbound restart** — the exact
    "permanently stale DNS" failure the design set out to prevent.
  - **Kea (d2)** restarts by **unlink+recreate** — *inode changes* (…795→…799),
    ~40 ms ABSENT window, new pid. Dir `NOTE_WRITE` fires; the file fd goes stale.
  - **DECISION:** watch **both** — per-file `NOTE_WRITE|NOTE_DELETE|NOTE_RENAME` on
    each pidfile (catches unbound's in-place rewrite; on kea's `NOTE_DELETE`
    re-register on the recreated file) **and** the parent directory `NOTE_WRITE`
    (catches first-ever creation when no fd can be opened, e.g. kea-dhcp4 cold
    start). The **level read reads the pid VALUE from file contents** each pass
    (stat alone is insufficient — unbound keeps the same inode). The SM already
    models pid as a value, so this is consistent. `/var/run/kea` may not exist
    before Kea's first start → open lazily / register the dir watch and add the
    file watch on appearance.

- **R7 — Schedule-model migration: NONE (DECISION — with TR: blow it away).** Cron
  jobs reconcile by origin, so no stale-file cleanup. And we will **not** migrate
  the stored `auto_clean_interval` value — upgraded boxes reset to the new default
  schedule. No migration code; just define the new fields with sane defaults in
  `General.xml`. R7 closed.

- **R8 — `--names` filters the DYNAMIC pass only; static is always full (DECISION —
  with TR: doc issue, not functional).** No `reservation-get-by-hostname` exists, so
  the drain's static pass re-asserts ALL reservations (idempotent, few, even heals
  missing static records); `--names` filters only the dynamic pass (via
  `lease-get-by-hostname`). Functionally fine. **Action: document this in
  `kea-sync.py`** so nobody expects `--names` to filter the static side.

- **R9 — d2 ACK-budget is a TEST-METHODOLOGY note, not a design risk.** The obvious
  check (query d2's failed-update counter) is impossible — OPNsense provisions no
  control socket for d2. So verification step #6 instead asserts on the **daemon's
  own per-NCR receive→respond latency** (< 500 ms) and cross-checks d2's *log* for
  drop/timeout lines. **Action: add per-NCR latency logging in the Phase 3 daemon**
  so the test has a signal.

- **R11 — Conflict policy design (DECIDED — with TR).** The `collision_policy`
  setting controls what happens when two DHCP clients request the same FQDN.
  Three modes:

  | Policy | Live path | Reconciler |
  |--------|-----------|------------|
  | `always` | Always overwrites — last NCR wins | Write all leases; no dedup |
  | `last_wins` | Always overwrites | Dedup by highest `cltt` (`expire − valid_lifetime`) — most recently active client wins |
  | `first_wins` / E | Rejects if FQDN already maps to a *different* IP | Dedup by first-in-iteration order |

  **Why not DHCID (RFC 4701)?** DHCID is constructed from MAC address or
  client-id. MAC randomization (iOS 14+, Android 10+, Windows 10+) means the same
  device presents a new random MAC on every reconnect — its DHCID changes every
  time, so DHCID-based ownership proof breaks immediately. ISC's own documentation
  acknowledges this; no IETF RFC update has addressed it. DHCID is not implemented.

  **E / `first_wins` guarantees:**
  - *Live, steady state*: correct — new claimants for an occupied FQDN are blocked
    until the original record is deleted (DHCPRELEASE or lease expiry + clean).
  - *After any reconcile (restart, admin sync)*: indeterminate — the reconciler uses
    first-in-iteration order from Kea's lease file, which is not creation-time order.
  - *Production risk*: hosts that move subnets, change MACs, or use MAC
    randomization may fail to acquire their FQDN after reconnect if an old lease
    for the same name is still live. Operators should use reservations (static) for
    production hosts that must retain a specific FQDN.

  **`last_wins` guarantees:**
  - Correct and deterministic at both live time and reconcile (`cltt` gives a
    comparable timestamp for all leases on the same server regardless of clock drift).
  - A renewing device stays ahead of a stale competitor (its `cltt` advances on
    every renewal). The "ghost" lease naturally loses as it coasts toward expiry.
  - **Default**: `last_wins` is the simplest policy that is both correct and immune
    to MAC-randomization problems.

  **HA (Kea high-availability mode) — NOT SUPPORTED.** Kea HA pairs maintain
  separate lease databases that may diverge; this plugin reads from the local Kea
  instance only. Behavior with HA is undefined and untested. Document in README.

- **R10 — kqueue READ must drain (Phase-3 implementation checklist item).** Today's
  socket is blocking (one packet per `recvfrom`). Under kqueue the socket is
  non-blocking and one `EVFILT_READ` event covers *all* queued datagrams. **Rule:
  on each readable event, loop `recvfrom` until `EWOULDBLOCK`** before returning to
  `kevent()`, or NCRs pile up between passes and ACK latency grows under burst.
  Trivial if known; subtle latency bug if not.

---

## Suggested commit sequence

1. Phase 0 spike notes committed to int-docs (record V1–V6 outcomes).
2. Phase 1 state-machine module + unit tests (no runtime change). ✅ green CI gate.
3. Phase 2 `kea-sync.py` + lock + call-site sweep + delete old scripts.
4. Phase 3 daemon rewrite (the big one) — behind a working `make upgrade`.
5. Phase 4 start.py + status UI.
6. Phase 5 hooks + schedule model + migration + advanced settings.
7. Phase 6 chaos scenarios; Phase 7 docs cleanup.

Phases 1–2 are independently shippable and de-risk the rewrite. Phase 3 is the
high-risk core; do it only after the state machine is proven in unit tests.
