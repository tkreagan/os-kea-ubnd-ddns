# Plan: resident-daemon consistency authority for Kea ↔ Unbound

## Context — the problem

Kea-derived DNS records live **only** in Unbound's runtime `local_data`; they are
**flushed on every Unbound restart/reconfigure** and written to no file Unbound reloads.
OPNsense reconfigures Unbound and restarts Kea through many lifecycle events that fire in
bursts at boot and on every "Apply." A full reservation+lease resync run while Kea or
Unbound is still flapping returns "errors=1, added=0" and repopulates nothing — leaving
DNS empty until some later, unrelated event happens to resync.

Today this is handled by `sync-debounce.py`: a short-lived, flock-guarded worker spawned
per PHP hook that coalesces a request burst, runs a **polled** readiness gate (1 Hz
probes, stability streaks, `MIN_UPTIME`, 90 s deadline), then syncs with backoff. This
plan replaces that with a **resident daemon** that owns DNS consistency end to end, and
adds **coordination between the live DDNS path and the resync path**.

## Why this design (the reasoning, condensed)

- **DDNS is best-effort *by design*** (Kea ARM + RFC 4703). Kea emits NCRs from DHCP
  lease events + policy, **never querying DNS state**. RFC 4703 conflict resolution is
  *"advisory only,"* scoped to *"prevent different clients mapping to the same FQDN at the
  same time,"* and *"does not address recovery from lost updates, durability, or
  reconciliation."* So the protocol gives best-effort increments + advisory collision
  avoidance — it does **not** promise DNS converges to the lease table.
- **Our resync IS the anti-entropy layer the protocol omits.** This is why it is
  load-bearing, why resync-on-flush is the right shape, and why a best-effort live path is
  legitimate (it matches the protocol's own model).
- **d2 drops failed updates — no requeue, no replay** (verified). `dns-server-timeout`
  ≈ 500 ms; d2 walks its one-server list once, then drops; the queue is in-memory; a later
  renewal does **not** re-trigger a missed update. ⇒ We must **ACK d2 within 500 ms
  unconditionally**, and **our resync is the sole durability mechanism**.
- **Three accuracy boundaries**, none ever "wrong IP" (Kea's lease is authoritative for
  the value) — all are precedence/convergence:
  1. **client vs. client** → DHCID + RFC 2136 prereqs (d2, advisory). **Our posture: honor
     only YXRRSET; apply our own override/collision policy** (decided).
  2. **DHCP vs. admin override** → our `host_entries.conf` guard.
  3. **DHCP vs. lease-table drift** → our full resync (anti-entropy).

## Architecture overview

Fold everything into the **already-resident daemon** (`kea-unbound-ddns.py`), which must be
alive anyway to receive NCRs. It becomes the single process that owns DNS consistency. A
**single kqueue** multiplexes, in one event loop (no threads), replacing today's blocking
`recvfrom`:

- `EVFILT_READ` on the UDP socket → inbound NCRs (live path).
- `EVFILT_VNODE` on the **pidfile directories** → restart/flush edges (PIDFILES ONLY —
  conf watches dropped, see §1/§6).
- `EVFILT_TIMER` → the backoff / watchdog timers.
- `EVFILT_PROC / NOTE_EXIT` on the sync subprocess PID → sync completion/failure.

The daemon triggers **`kea-sync.py`** (the merged reconciler, see below) — it does **not**
reimplement reconciliation in the latency-sensitive loop. The elaborate readiness machinery
(probes, streaks, `MIN_UPTIME`) is **deleted** in favour of **fail-fast** (below).
`sync-debounce.py` is **retired**.

## The control model

### 1. Watch set + path/enabled resolution (in `start.py`, not hardcoded)

`start.py` (or a shared resolver) resolves, from config — reusing the
`kea_transport.resolve_kea_connection()` / `_is_service_enabled()` pattern:
- **enabled-ness** ← `config.xml` (`//OPNsense/Kea/dhcp{4,6}/general/enabled`, DDNS agent,
  `manual_config`),
- **paths** ← derived from live confs/conventions: Unbound pidfile from `unbound.conf`'s
  `pidfile:` line (`/var/run/unbound.pid`); Kea pidfiles `/var/run/kea/<svc>.<svc>.pid`;
  conf paths fixed (`/usr/local/etc/kea/kea-dhcp{4,6}.conf`, `/var/unbound/host_entries.conf`).

**Watch set — PIDFILES ONLY (scoped to ENABLED services):** the enabled daemons' pidfiles —
{unbound, d2, dhcp4 and/or dhcp6} — observed via `EVFILT_VNODE`/`NOTE_WRITE` on their
directories (`/var/run/kea`, `/var/run`) so we see appear / disappear / PID-change. Scoping
to enabled services is what lets "wait for all pids" terminate (a disabled dhcp6 isn't
waited on).

**No conf/file watches (simplified — verified).** We do NOT watch kea confs, host_entries,
unbound.conf, lease CSVs, or sockets:
- *kea-dhcp{4,6}.conf* — `rc.d/kea`'s `reload` is **stock kea (pkg kea-3.0.3); OPNsense
  never invokes it** (verified — no `reload` in `kea.inc`/actions). So a conf change ALWAYS
  goes through `rc.d/kea restart` → PID cycle, caught by the pidfile watch. Redundant.
- *host_entries.conf* — written only inside `unbound_configure_do` (which restarts Unbound →
  PID cycle), AND the override-accuracy window is already closed by *block-until-sync-success*
  (we don't resume live applies until a sync that read the fresh file succeeds). Redundant.
- *kea-leases{4,6}.csv* — **decided NO**: changes every DHCP transaction; would fire syncs
  continuously and defeat the live-NCR design. *unbound.conf*, *kea-dhcp-ddns.conf*, control
  sockets — redundant/irrelevant.

### 2. Startup preconditions (`start.py` refuses to start, when our plugin is enabled)

- **Unbound enabled** (write target; absent if box uses Dnsmasq).
- **d2 / kea-dhcp-ddns enabled** (live-update source). *Nuance:* this is required for the LIVE path
  only — the sync path reads Kea directly and could run "sync-only"; but requiring d2 is a
  product choice (the plugin is fundamentally a DDNS bridge).
- **≥1 of dhcp4 / dhcp6** (lease/reservation source). **Dual-stack (both enabled) is valid
  — confirmed.**
- **≥1 subnet actually wired to us** — at least one subnet with `ddns-send-updates: true`
  AND a d2 forward/reverse zone whose `dns-server` targets our listener port (parse
  `kea-dhcp-ddns.conf`, already read by the resolver). Confirms there's DDNS traffic to
  bridge and that it reaches us. **Respect `manual_config`** — we don't hard-gate on d2 in a hand-rolled
  Kea setup (same exemption the socket resolver honors); for manual configs, downgrade to a
  Config-Check advisory rather than a start refusal.
- **`unbound-control` binary present/executable** (the unrecoverable-install gate). Verify
  the *tooling exists*, NOT that Unbound is up (blocking on liveness would reintroduce a
  readiness gate; fail-fast owns liveness).
- On any failure: **do not start, surface the reason in the UI** — write a reason to a
  status file; the existing status API reads it; Settings shows a banner ("not running:
  Unbound disabled" / "no DHCP server enabled"). Fail loudly, not silently.

### 3. Block/sync state machine (PID presence drives the block; sync SUCCESS unblocks)

A restart is `pidfile present(old) → disappears → reappears(new PID)` — treat **both**
disappearance and a changed PID value as the restart signal. PID-present is *necessary but
not sufficient* to unblock (the pidfile is written before the control socket is ready), so
the **successful sync** is the real unblock gate; fail-fast bridges the readiness gap.

**LEVEL-triggered, not rising-edge.** Each loop pass **re-stats the enabled pidfiles** →
`(exists, pid-value)` per daemon and derives state from *that*. kqueue VNODE events and the
backoff timer are only **wake-ups** ("go re-evaluate"). This is required: (a) at startup the
pidfiles may already exist (no "appear" edge to catch), and (b) edges coalesce/can be missed
— file existence + pid value is the ground truth. "Present" = same pid still there; a
changed pid value counts as a restart (absent→present).

```
BLOCKED   (live → ACK-fail to d2 + record dirty name)
  ├─ enter on: startup, OR any enabled pid absent/changed (SIGTERM the sync subprocess if
  │     one is running; waitpid to reap; flock releases on process exit — no lock cleanup needed)
  ├─ on any kea pid (re)appear → re-read config.xml:
  │     enabled-set changed (service on/off) → RESTART self (re-derive watches/paths/§2)
  ├─ when ALL enabled pids present → spawn `kea-sync.py --mode=full` via Popen (non-blocking);
  │     register subprocess PID with EVFILT_PROC/NOTE_EXIT; return to kevent() wait
  │     sync FAILS → exponential backoff (≈0.25 s ×2, cap 60 s), then RE-EVALUATE the pid
  │        level (do NOT blind-retry): pid absent/changed (flapped) → stay BLOCKED;
  │        all still present → try again
  │     sync succeeds → check overflow flag:
  │        OVERFLOWED: discard dirty set; increment full_sync_counter (reset on any
  │          pid-level transition — a new restart deserves fresh attempts);
  │          counter < max_full_sync_attempts → spawn another full sync;
  │          counter ≥ max_full_sync_attempts → ► NORMAL + loud alert (degrade to
  │          best-effort live, periodic clean is anti-entropy floor)
  │        NOT overflowed: reset full_sync_counter; begin drain loop (same Popen +
  │          EVFILT_PROC/NOTE_EXIT; daemon tracks sync vs. drain pass):
  │          snapshot dirty set + clear it → if snapshot non-empty: spawn
  │            `kea-sync.py --mode=full --names=<snapshot>`, register EVFILT_PROC/NOTE_EXIT,
  │            return to kevent() (NCRs during drain still ACK-fail + dirty-record into the
  │            now-empty set); on subprocess exit → repeat snapshot+clear check;
  │          snapshot empty → ► NORMAL
  └─ WATCHDOG (default 10 min stuck in BLOCKED; configurable; 0 = wait forever):
        expire → log + UI alert + TERMINATE (clean full stop, no respawn). See Failure bounds.
NORMAL    (live → apply directly)
  └─ any enabled pid absent/changed → ► BLOCKED
```
The backoff timer and the pid-watch share one event loop, so a pid dropping *during* the
backoff fires first and preempts straight to BLOCKED — there is no separate retry loop
fighting the flap; one loop re-derives its state from current pid presence every pass.
"Retry forever" = re-evaluate forever, bounded only by the watchdog. Backoff is exponential
(≈0.25 s, doubling, **hard cap 60 s**), **reset on a successful sync or any pid-level
transition** (a fresh restart deserves a prompt attempt; only consecutive failures against a
*stable* pid set back off), and interruptible by pid events. The small starting interval
doubles as a **dependency-free readiness accelerator** — 250 ms polling catches the
"ready" moment within a quarter-second, capturing ~all of what a log-watcher would.
The config.xml recheck on recovery is the enabled-set detector (§7): a service turning on
appears as a new/changed pid set; a service turning off means its pid never returns — the
recheck drops it from the expected set so the watchdog doesn't false-fire.

Conservative simplification: block on ANY enabled pid absent (even a Kea-only restart while
Unbound is up — a few live updates get deferred/dirty-recorded/re-resolved). Simpler than
per-daemon block scoping; revisit only if the deferral matters.

### 4. Fail-fast sync (replaces the readiness-probe machinery)

The sync just attempts the real operations and **dies cheaply** if anything isn't ready; a
retrigger retries. Stronger than probing (no probe→op TOCTOU gap). The "settle" is
**emergent**: attempts die fast through the flap until the world is up, then one succeeds;
a later flush is another PID change → another sync, and the **last** one wins.

Rules (in the sync script):
- No Kea control socket / Kea query fails → **die-retry**.
- `host_entries.conf` **read error / locked-for-write** → **die-retry**. But **missing ≠
  die** — missing means "no overrides to protect" ⇒ proceed with an empty guard.
  (Confirmed: host_entries is essentially always present — minimum `localhost` + the
  firewall's own A/PTR.)
- `unbound-control` **connection error/refused** → **die-retry** (Unbound down/restarting).
  This is the only unbound-control case the sync handles — no halt logic in the sync path
  (the binary-missing/halt case is filtered once in `start.py`, §2).

We should check the rules (in particular the sockets, host_entries.conf, and unbound-controlas quickly as possible so that we can fail quickly.  

### 5. Conf monitors — DROPPED (verified unnecessary)

We watch no conf files. *conf change ⟹ regenerate ⟹ restart ⟹ PID cycle*, and the in-place
reload that would bypass this is **stock-kea capability OPNsense never invokes** (verified:
`rc.d/kea` is from pkg kea-3.0.3; no `reload` in OPNsense's `kea.inc`/actions). So the
pidfile watch catches every config change — conf watches add nothing. Watch surface stays
pidfiles only.

### 6. Dynamic enablement → re-derive on block-recovery (in the daemon, no hook needed)

If the enabled set changes (e.g. dhcp6 flips on), a watch set frozen at startup would
**silently miss the new daemon's restarts** → permanently stale v6 DNS. Handle it on the
**blocking side**, self-contained in the daemon: enabling/disabling any kea service does a
full `rc.d/kea restart` → our watched pids cycle → BLOCKED. On recovery, when any kea pid
(re)appears, **re-read `config.xml`**; if the enabled-set differs from ours, **restart
ourselves** (start.py re-resolves watches + paths + preconditions). This also handles the
*disable* case (drop the removed service from the expected set so the watchdog doesn't wait
forever for a pid that won't return). No dependency on the `kea_sync` PHP hook — the
block/recovery cycle already in progress is the trigger.

## Process orchestration (start.py → daemon lifecycle)

**`start.py`** (fail → stop + clean up + write UI "not running: reason" + leave stopped):
1. Clean up leftovers from prior runs/crashes (our pidfile + supervisor pidfile).
2. Check hard tooling — `unbound-control` present/executable (the unrecoverable-install gate).
3. Check enablement + wiring — d2 **and** Unbound **and** ≥1 of dhcp4/dhcp6 **and** ≥1
   subnet DDNS-enabled & pointed at us (§2 preconditions; manual_config exempted).
4. Resolve sockets/paths/enabled-set (+ tunables: dirty cap, watchdog) from `config.xml` and
   **write a resolved conf file** the daemon reads (start.py is the single resolver; the
   daemon never re-parses config.xml — this is also what the self-restart in §7 rewrites).
5. Start `kea-unbound-ddns.py`.

**`kea-unbound-ddns.py`** on start: bind the UDP socket and enter **BLOCKED immediately**
(ACK-fail d2 + record dirty from the first packet) → run the block/sync state machine → on a
clean sync, **unblock + drain dirty → NORMAL** → on **watchdog expiry** (only failure mode;
`0`=forever never trips), call `stop.py` and stop.

## Live ↔ sync coordination (the shared lock, and dirty-name record-and-drain)

**Constraint:** ACK d2 within 500 ms unconditionally — the *application* to Unbound may be
deferred; the *response* may not. (Within 500 ms we ACK and *decide* apply-vs-defer.)

**Apply mechanism + ACK semantics (live path):** an NCR's records (forward A/AAAA + its
PTR(s)) go into **one `local_datas` exec** — intra-NCR batch: one fork/exec, one result.
**Never coalesce across NCRs** — bundling NCR #1 with #2/#3 to batch them would defer #1's
ACK and blow the 500 ms budget (the Nagle trap). Each NCR is decided and ACKed
independently. The single batch result maps cleanly to **one RCODE**:
- The apply-vs-skip **decision precedes the exec** — static-guard ownership and BLOCKED
  state are checked first. Skip-per-policy (override owns the name) → ACK without mutating.
- Decide-to-apply → run `local_datas` → `ok` → **ACK success**; **error** (unbound
  down/restarting — connection refused) → **ACK-fail + mark name(s) dirty + go BLOCKED**
  (a pid event is incoming anyway). Batching collapses the partial-failure ambiguity
  (forward ok / PTR fails across separate execs) into one all-or-nothing result.

**Problem:** today there is **no lock** between the daemon and the sync scripts (verified) —
the sync's **stale-removal** step can clobber a concurrent live **add** (and a live delete
can be undone by a re-add from a stale snapshot). The remove path is the one that bites.
This also applies to syncs/clean invoked **outside** the daemon (UI buttons, cron, manual).

**Model — ONE shared "Unbound-mutation lock" everything respects:**
1. **Standalone scripts** (`kea-sync` / `local-data-clean`, however invoked) acquire the
   lock for their whole run.
2. **Daemon reconciles** hold the lock.
3. **Daemon live applies** use a **non-blocking** acquire (`flock -n`): got it → apply +
   release (fast); **contended → do NOT wait** (must ACK d2 in time) → ACK-fail + mark the
   name(s) dirty in a **deduped dirty-key SET**, and go BLOCKED.
4. So the BLOCK trigger set is `{any enabled pid absent/changed} ∪ {mutation-lock held
   externally}`; unblock = all pids present **and** lock acquirable **and** a sync succeeds →
   then **drain the dirty set** by running the **same reconciler filtered to those names**.
   An external sync/clean thus looks just like a flush to the daemon — same machinery; the UI
   buttons stay plain configd actions and the lock does the coordination.

**Dirty NAMES + re-resolve, NOT replay-the-NCR (the staleness trap):** an NCR is an ordered
mutation, not an idempotent fact — replaying a deferred NCR after newer state exists
*regresses* state (reconcile reads L=B; queued NCR carries L=A; replaying A clobbers B). So
we trust only the NCR's *name* (a hint of where to look) and re-resolve from Kea (truth) at
drain time. Re-resolving L returns B; stale A is never applied. Staleness becomes
*impossible*; DELETE handled (no active lease ⇒ remove); the static guard is re-checked;
order-free (names are idempotent keys). It **unifies with the full reconcile** — same
reconciler, name-filtered: full = all names, drain = dirty names.

**Post-sync recovery — overflow check then drain:**

After a full sync succeeds, check the overflow flag:

- **Overflowed** (dirty set hit the cap during the sync): discard the dirty set, increment
  `full_sync_counter`. If counter < `max_full_sync_attempts` → spawn another full sync (the
  network is still churning; each sync reads the latest state). If counter ≥ limit →
  degrade: go NORMAL + loud alert; the periodic clean is the anti-entropy floor.
  Reset `full_sync_counter` on any pid-level transition (a new restart deserves fresh
  attempts, not a counter already at 4).

- **Not overflowed**: reset `full_sync_counter`; run the drain loop. Drain is dispatched
  (Popen + EVFILT_PROC/NOTE_EXIT, same mechanism — daemon tracks sync vs. drain pass):
  1. Snapshot the dirty set and clear it (atomic in the single-threaded loop).
  2. If snapshot non-empty: spawn `kea-sync.py --mode=full --names=<snapshot>`, return to
     `kevent()`. NCRs arriving while the subprocess runs are ACK-failed and added to the
     now-empty dirty set.
  3. On subprocess exit: go to step 1. Snapshot empty → NORMAL.

  The loop is self-correcting: if the network calms, each pass accumulates fewer names
  until the snapshot is empty. Idempotent by construction — names already resolved by the
  recovery sync re-resolve to "already correct" and do nothing.

The dirty set is **in-memory only, no timestamps**. Lost on daemon restart, but startup
always runs a full reconcile so nothing is missed.

**Bounds:** dirty set is bounded (dedup caps it at the working-set size). Internal
isolation between the live path and the sync/drain path is provided structurally by the
state machine (BLOCKED → no live applies; NORMAL → no reconcile runs) — no additional
lock needed. The shared Unbound-mutation lock exists only to serialize external scripts
(cron, UI) against the daemon's live path in NORMAL state.

**Requires:** targeted Kea lookups so O(dirty) is cheap — `lease{4,6}-get-by-hostname`,
`reservation-get` (host_cmds + lease_cmds hooks confirmed loaded on dev box).

## Accuracy gate — host_entries.conf override boundary

The guard (`is_static_entry`, `kea-unbound-ddns.py:243`) reads `host_entries.conf` on every
ADD/DELETE — **multiple times per packet** (forward name + each PTR check, lines 461/505/
517/583/594/611). The one accuracy risk — a live update winning a name before the file
reflects a just-added override — is **already closed by the block/sync model**: the override
change restarts Unbound → BLOCKED; we don't resume live applies until a full sync (which read
the fresh host_entries with correct precedence) succeeds; dirty names re-resolved during the
block also re-check the guard. So **no separate host_entries watch is needed** — the PID cycle
+ block-until-sync handle it.

**Cache host_entries in memory (perf, safe by structure).** Replace the per-packet file reads
with an in-memory copy, **re-read once on every recovery** (BLOCKED→NORMAL, before resuming
live applies). Safe because `host_entries.conf` is rewritten ONLY by `unbound_configure_do`
(Unbound restart) and our `kea_sync` hook's `unbound_add_host_entries()` (Kea restart) — **both
cause a pid cycle that blocks us first**, so the cache can never be stale while we're actually
applying live updates. (We do NOT separately cache the Kea *reservation list* in the listener:
its only static-side lookup is this `host_entries` file — which already contains reservation
hostnames when regdhcpstatic is on — so there is no hot-path consumer for a reservation cache;
the reservation list is read only by the separate `reservation-sync.py` reconciler.)

**Write-atomicity (resolved, no action):** OPNsense writes the file **non-atomically** —
`unbound.inc:681` is a bare `file_put_contents(...)` (truncate-then-write), so a torn read
is possible *in principle*. But it's **mooted by timing**: the file is rewritten inside
`unbound_configure_do` *between* `unbound_service_stop()` and `start.sh` — i.e. while Unbound
is DOWN, which means we're already BLOCKED and not reading the guard in the live path. By the
time we resume live applies the file is complete; the sync's read happens post-recovery and
is fail-fast-protected. So the non-atomic write is harmless here.

## Failure bounds

- **Overflow / network storm:** if the dirty set hits the cap during a sync, the overflow
  loop kicks in (see "Post-sync recovery" in the coordination section): discard dirty set,
  full sync again. Self-correcting — if the network quiesces, the next accumulation fits
  under the cap and the drain loop finishes it. **`max_full_sync_attempts` (default 5,
  tunable)** caps the loop; on exhaustion → degrade to NORMAL + loud alert, periodic clean
  is the anti-entropy floor. Never crash-loop. Principle: the safe direction is *more
  complete*, never *abandon*.
- **Dirty-set cap:** threshold at which targeted drain gives way to another full sync.
  **Default 100, configurable via advanced settings.** In normal operation a restart
  generates <50 dirty names; 100 is a generous threshold. Dedup keeps the set tiny;
  overflow only occurs during a genuine network storm while services are restarting.
- **Stuck-in-BLOCKED watchdog (configurable):** clock = continuous time in BLOCKED without
  reaching NORMAL (a successful sync resets it). **Default 10 min; configurable; `0` = wait
  forever.** On expiry → **clean full stop** (kill the supervisor too — no `daemon -r`
  respawn loop) + **loud UI alert** ("stopped: Kea/Unbound not ready within Nm"); recoverable
  via plugin restart or the belt-and-suspenders hook. Tradeoff (surface in UI help):
  *terminate* fails the fault loudly but won't auto-recover; `0` auto-recovers but waits
  silently (with alert) — and stays memory-safe via the dirty cap above.
- **Readiness via logs — NOT the gate (good markers exist, but fail-fast still wins).**
  Empirically (dev-box logs), strong **stable** markers DO exist: Kea `DHCP4_STARTED` /
  `DHCP4_CONFIG_COMPLETE` ("completed configuration"), `DHCP_DDNS_STARTED` /
  `DCTL_CONFIG_COMPLETE` ("listening on 127.0.0.1, port 53001"), `DCTL_SHUTDOWN` (with pid);
  Unbound `info: start of service` / `info: service stopped`. These are symbolic IDs (not
  fragile free-text) and `CONFIG_COMPLETE` is a true readiness signal. **Still not used as
  the gate**, because: (a) all are **INFO-level** and Kea's severity is a user knob
  (`"severity":"INFO"` in the conf) — set to WARN and they vanish ⇒ wait-forever (the
  confirmed real failure mode); (b) fail-fast tests the **real capability** directly (no
  syslog-routing/severity dependency); the win would only be skipping ~2 cheap retries.
  **Decided NOT to build the accelerator:** the small starting backoff (≈250 ms) already
  catches the ready moment within a quarter-second, so a log-watcher would save only ~0.5 s
  once per restart — not worth a permanent log-tailing dependency (rotated filenames, syslog
  parsing, severity-disable, rotation-mid-tail). Marker strings kept here only as a
  *revisit-if-measured* option should some platform show a painfully long readiness gap.
  (Logs also confirmed d2 `max-queue-size: 1024` and literally show the Unbound boot-flap:
  start→stop→start within seconds.)
- **Unbound/Kea down during an outage:** governed by the two knobs above — keep recording
  dirty (bounded by the cap), bounded in time by the watchdog. On recovery: if the cap was
  hit, discard and rely on the full sync + periodic clean; otherwise drain normally (see
  "Drain vs. discard" in the coordination section).

## Verified facts (dev-box review)

- **Restart ⟺ PID change (the linchpin):** Unbound's `unbound_configure_do` does a real
  stop → start → `waitforpid` (new PID); **no in-place `unbound-control reload`** (the
  "non-interface reload" path merely *skips* irrelevant changes ⇒ no flush). Kea's
  `kea_configure_do` runs `generateConfig()` (rewrites `kea-dhcp*.conf`) + `rc.d/kea
  restart` (new PIDs + changed conf); reservations are config-file-driven, not pushed via
  the runtime host_cmds API. `rc.d/kea` (stock, pkg kea-3.0.3) *exposes* a `reload` but
  **OPNsense never invokes it** (verified: no `reload` in `kea.inc`/actions) — every kea
  config change goes through restart (new PIDs). **Pidfile watching alone is complete.**
- **Paths:** `/var/run/unbound.pid`; `/var/run/kea/<svc>.<svc>.pid` (e.g.
  `kea-dhcp-ddns.kea-dhcp-ddns.pid`); kea4 control socket `/var/run/kea/kea4-ctrl-socket`.
- **host_cmds + lease_cmds hooks loaded** ⇒ targeted Kea lookups available for the drain.
- d2 on `127.0.0.1:53001/udp`; our listener on `127.0.0.1:53535/udp`.

## Relationship to existing code

- **PHP hooks: keep as belt-and-suspenders.** The daemon's watches are primary and more
  robust (catch restarts from any cause); the existing hooks remain a cheap independent
  trigger that still fires if the **daemon itself is down/mid-upgrade** (the one gap a
  watches-only model has; the daemon's own startup reconcile covers cold start). Not locked.
- **`kea-sync.py --mode=static|dynamic|full [--names=...]`: merged reconciler** replacing
  the old `reservation-sync.py` / `lease-sync.py` pair. One subprocess, one PID to track,
  one lock acquisition for the whole run. `full` runs static (reservations) before dynamic
  (leases) — **order: static BEFORE dynamic** — so high-value static records resolve first
  and survive a flaky dynamic pass for free. `--names=` enables the dirty-drain filtered
  mode. UI buttons call `--mode=static` or `--mode=dynamic` directly. Per-service retry
  logic in the old scripts is dropped; fail-fast + the state machine own readiness.
  (This is all that remains of the "early static-only pass" idea — no separate pass or
  partial-unblock needed.)
- **`sync-debounce.py`: retired** — its responsibilities (coalesce, readiness gate) are
  gone; PHP hooks call `kea-sync.py` directly.
- **`local-data-clean.py` periodic clean: stays EXTERNAL (cron), NOT folded into the daemon**
  — keep the listener focused on its DDNS job. This periodic stale-clean is the anti-entropy
  floor. (Optional: make the periodic job a full *reconcile* rather than clean-only, so it
  also heals lost ADDs, not just stale removes — but it stays a cron/configd job, outside the
  daemon.) It (and the manual clean/sync buttons) acquire the shared Unbound-mutation lock.
- **Config Check / Lease Audit pages are independent of the daemon (verified).**
  `KcaconfigController` reaches Kea **directly** (`resolveKeaSocket` + `curl` to the control
  sockets, `config-get`); its only touch of us is an informational `keaunbound status` dot
  (line 841), handled gracefully when we're down. So the daemon correctly refusing to start
  (Kea unconfigured) does **not** disable Config Check — the admin uses it to fix Kea, then
  our preconditions pass on the next start. No chicken-and-egg.

## Critical files

- `src/sbin/kea-unbound-ddns.py` — single kqueue loop (READ + pidfile-dir VNODE + TIMER +
  EVFILT_PROC/NOTE_EXIT on sync subprocess); the block/sync state machine (level-triggered;
  config.xml recheck on recovery; watchdog); the **shared Unbound-mutation lock**
  (non-blocking acquire on live applies) + dirty-set record-and-drain; spawn `kea-sync.py`;
  initial reconcile on start. **Live apply batches each NCR's records (forward + PTR) into
  one `local_datas` exec** (intra-NCR only — never coalesce across NCRs), giving one result
  → one d2 RCODE. (Periodic stale-clean stays external — the daemon is NOT a GC timer.)
- `src/opnsense/scripts/keaunbound/start.py` — resolve enabled-set + paths from config;
  startup preconditions (incl. `unbound-control` presence) + UI status-file on refusal.
- **NEW** `lib/` watcher/state-machine module — the kqueue watch + state machine, factored
  out so it's unit-testable independent of the daemon.
- `src/opnsense/scripts/keaunbound/kea-sync.py` — merged reconciler; `--mode=static|dynamic|full`,
  `--names=` for dirty-drain; fail-fast die-on-not-ready; acquires the shared mutation lock.
  **Batch records through `local_datas` (stdin)** — one exec for many records instead of one
  exec per record (the big full-sync win; no d2 ACK is pending on the sync path, so batch
  freely, chunking only to bound a single command's size).
- `src/etc/inc/plugins.inc.d/keaunbound.inc` — keep hooks only as belt-and-suspenders
  (trigger a reconcile when the daemon is down). Enabled-set re-derive is NOT here anymore —
  it's handled in the daemon on block-recovery (§7). **Keep `keaunbound_cron`** (the periodic
  stale-clean / anti-entropy floor) — external, as today. **New scheduling UI:** two modes —
  *"every N hours"* (presets **1 / 3 / 6 / 12**, default **6**) or *"daily at <time>"*;
  `keaunbound_cron` builds the autocron schedule from whichever mode (hour-list for the
  interval, `minute hour` for daily). Replaces today's `h6/h12/h24` `auto_clean_interval`.
- `{kea-sync,local-data-clean}.py` + `actions_keaunbound.conf` — these standalone scripts
  must **acquire the shared Unbound-mutation lock** (so UI/cron/manual runs serialize with
  the daemon's live path).
- `src/opnsense/mvc/app/.../index.volt` + status API — surface the "not running: reason"
  and "stopped: not ready within Nm" banners.
- `General.xml` + `generalSettings.xml` — **advanced** settings: **dirty-set cap**
  (default 100), **max full-sync attempts** on overflow (default 5), and **readiness
  watchdog** minutes (default 10, `0` = forever), with help text on the
  terminate-vs-auto-recover tradeoff. (Periodic-clean interval stays the existing
  `auto_clean_interval` cron setting.)

## Optional future module — log-watch stale-cleanup accelerator (off by default)

A **separate, optional, off-by-default** daemon (keeps the listener clean) that tails Kea's
log and accelerates stale-record removal. Verified feasible: events are INFO-level with stable
IDs and the IP — `DHCP4_RELEASE`/`DHCP4_RELEASE_EXPIRED` ("address 192.168.1.101 …
released/expired").

**Flow:** on a release/expiry → wait a **grace window** (~30 s, configurable) → if the
corresponding A/AAAA/PTR delete wasn't handled, run a **record-specific targeted clean via an
existing script** (under the shared lock). Notes:
- The targeted clean is **idempotent** (re-resolves that IP/name against Kea, removes only if
  no active lease), so "release → grace → clean" is correct *by itself*; the "was it handled?"
  check is just an **optimization** to skip redundant clean invocations.
- For that skip-check, prefer **our own log** (we control it; emit a clean `removed A <ip>
  <name>` line) over d2's (opaque request-ID hash). Or skip the check entirely and let the
  idempotent clean run.
- **Skip while the daemon is BLOCKED** — a delete that arrived during a block is already in the
  dirty set and lands on unblock; the watcher would only race it.

**Honest scope (narrow):** normal deletes go via the live NCR path; blocked-deletes are
dirty-tracked. So this only helps deletes that **never reached us at all** (d2
`max-queue-size: 1024` overflow / delivery failure) — which the periodic clean already covers,
just slower. **Dependency:** Kea severity ≤ INFO (external) — detect on enable and alert/warn;
the periodic clean is the floor, so a log-misconfig degrades, not breaks. **Recommendation:
optional module, not core v1.** (Alt signal to consider: d2 `*_FAILED` events — the precise
lost-NCRs both directions — if the FAILED line carries the FQDN; unverified.)

## Open items / to confirm

*All prior open items resolved:*
- **Early static-only pass** → reservations-before-leases ordering in the reconciler (see
  Relationship to existing code). Done — no separate pass needed.
- **host_entries.conf atomicity** → confirmed non-atomic but mooted by block timing (see
  Accuracy gate). No action.
- **YXRRSET** → settled; current behavior is correct (return YXRRSET when first-wins is set,
  a conflict occurs, and prereqs were sent). Orthogonal to this work.

No design questions remain open — the rest is implementation.

## Verification (end-to-end, on dev-opnsense via `make upgrade`)

1. **Quiesce baseline:** healthy world → one full sync completes; state → NORMAL.
2. **Flap each component** (`service kea_dhcp4 onerestart`, dhcp6, Unbound, d2): confirm an
   immediate PID-down edge → BLOCKED, dirty recording, and recovery → NORMAL after a clean
   sync.
3. **Fast-flap:** down+up inside ~1 s → still caught (where a 1 Hz poll would miss it).
4. **Flush recovery:** populate DNS, restart Unbound → the daemon's PID edge re-triggers
   resync and `list_local_data` repopulates, with **no PHP hook firing**.
5. **d2-drop recovery:** lease change while Unbound mid-restart (NCR dropped by d2) → the
   resync restores the record from Kea state.
6. **d2 ACK budget:** daemon answers d2 within 500 ms even mid-sync (no d2 failure-counter
   increments).
7. **Dynamic enablement:** enable dhcp6 → daemon self-restarts → now watches/syncs v6.
8. **Preconditions:** disable Unbound / both DHCP servers → daemon refuses to start, UI
   banner shows the reason.
9. Extend integration tests (`tools/` tree) to drive the state machine against simulated
   pidfile churn.

## Appendix — why Kea "flaps" at startup (partly needs observation)

The repo documents only the Unbound flap; the Kea flap is undocumented (definitive
attribution needs a dev-box boot trace, which the new per-transition logging produces).
Two compounding causes: **(A) external configd cascade** — one boot/Apply fires several
configure events, core restarts Kea/Unbound multiple times (likely dominant); **(B) Kea's
multi-process restart** — dhcp4/6/ddns cycle independently, so "is Kea up?" oscillates by
process skew. The watch is agnostic to which; its timestamped PID-edge log vs. configd
event timestamps will let us finally measure (A) vs (B).

## Risks / notes

- The daemon loop must never block long on an apply while an NCR ACK is pending — ACK
  first, apply second.
- `/var/run/kea` is low-churn; if a watched pidfile dir is busier, react only to PID
  changes for the specific files tracked, ignoring unrelated dir writes.
- Keep the watcher/state-machine module free of daemon-specific globals so it stays
  unit-testable.
