## Purpose

Many later work packages need "do X at time T": ticket expiry (1.14), the outbox relay (1.23), epoch-lease sweeps
(1.25), backups (1.29), hook delivery (M3), verification slices (M4), GC (M5). This WP builds the one scheduling
facility they all register with:
- timer rows in each partition;
- a core `run_due` that fires due timers through registered, idempotent handlers under a fair per-tick budget;
- two drivers:
  - Workers: each Durable Object's single alarm is set to the earliest timer;
  - native: a tokio driver over an in-memory directory rebuilt from SQLite at startup.

This WP registers **no production timer kind**. Only a test kind, compiled only under `test-faults`, exercises the
machinery end to end.

## A. Fixed by the plan and specs (do not change)

1. **Plan:** `docs/plans/mkit-server/m1-m2-breakdown.md` "WP-1.24"; `00-plan.md` C-2 (timers: alarm = min(due_at),
   idempotent handlers), R-26 and R-36.
2. **Key layout (reserved in M0-02a, already in `store/keys.rs`):**
   - `w 00 <due_at:be64> <kind:u8> <ref>`, built by `keys::timer(due_at_ms, kind, reference)` and parsed as
     `ParsedKey::Timer`.
   - The value is opaque to the core ("codec per kind").
   - Do not change the layout, the tag or the parser. Update the `keys.rs` doc table from "reserved, WP-1.24" to
     owned by `timers`.
3. **Store contract (`store/kv.rs` rules 1–8):**
   - Timers use only `get`/`scan`/`apply`.
   - A handler's effects commit in one batch in the timer's own partition (rule 6: no cross-partition atomicity).
     Cross-partition effects are outbox rows (later WPs).
   - `FsLayoutStore` (`RefsOnly`) cannot hold `w` rows: timers need a store whose `KeyClasses` admits them.
4. **Durable Object semantics:**
   - one alarm per object;
   - `alarm()` is at-least-once, with up to 6 automatic retries on error and a 15 min wall limit;
   - an alarm set in the past fires immediately.
   - Handlers MUST tolerate re-delivery.
5. **Storage enumeration rule (`store/partition.rs`, `store/maintenance.rs`):** the `NamespaceStore` trait never lists
   partitions. Do not add a listing method to the trait. B.6's SQL helper is an inherent method on the SQL backend,
   not a trait method.

## B. Decided by the orchestrator (do not change)

### B.1 Module layout

- `rust/crates/mkit-server/src/timers/mod.rs` holds `run_due` and the types in B.3–B.5.
- `timers/registry.rs` holds `TimerKind`, `TimerHandler` and `TimerRegistry`.
- `timers/test_kind.rs` holds the `#[cfg(feature = "test-faults")]` test kind.
- Export from `lib.rs` as `mkit_server::timers` (a public module). Re-export only `run_due`, `TimerKind`,
  `TimerRegistry` and `TickBudget` at the crate root if that matches how `lib.rs` treats other modules; otherwise
  none.

### B.2 Kinds

- `pub struct TimerKind(u8)` has `const fn new(u8)` and `fn get(self) -> u8`, and derives Copy, Eq, Ord, Hash and
  Debug.
- Allocation rules:
  - `0` is invalid, and `run_due` treats it as unknown;
  - `1..=0xEF` are production kinds, each allocated by the WP that adds it as a `pub const` in
    `timers::registry::kinds`;
  - `0xF0..=0xFF` are reserved for tests.
- This WP allocates exactly one kind: `kinds::TEST = TimerKind::new(0xFF)`, under `test-faults`.
- Put a doc table at `kinds` listing the allocations and the rule: "a new kind takes the next free number; numbers
  are never reused".

### B.3 Handler trait and registry (exact shapes; doc comments are yours)

```rust
pub struct DueTimer {            // #[non_exhaustive], Debug, Clone
    pub due_at_ms: u64,
    pub kind: TimerKind,
    pub reference: Bytes,
    pub value: Value,
}
pub struct TimerCtx<'a, S> {     // #[non_exhaustive]
    pub store: &'a S,
    pub partition: &'a Partition,
    pub now_ms: u64,
}
pub enum Fired {                 // #[non_exhaustive]
    /// Commit `batch` and delete the timer, atomically.
    Done(Batch),
    /// Commit `batch`, delete the timer and put it again at `due_at_ms` with `value`, atomically.
    Reschedule { due_at_ms: u64, value: Value, batch: Batch },
    /// No effect now; try again later (counts as a failure for backoff).
    Retry,
}
pub trait TimerHandler<S: NamespaceStore>: MaybeSend + MaybeSync {
    fn kind(&self) -> TimerKind;
    /// Overrides `TickBudget::max_per_kind` for this kind.
    fn max_per_tick(&self) -> Option<u32> { None }
    fn fire<'a>(&'a self, ctx: &'a TimerCtx<'a, S>, timer: &'a DueTimer)
        -> BoxFuture<'a, Result<Fired, StoreError>>;
}
pub struct TimerRegistry<S> { /* Vec<Box<dyn TimerHandler<S>>> or a map by kind */ }
impl<S: NamespaceStore> TimerRegistry<S> {
    pub fn new() -> Self;
    /// Panics if the kind is already registered or is kind 0 (a programming error at startup).
    pub fn register(self, handler: impl TimerHandler<S> + 'static) -> Self;
}
```

- `BoxFuture`, `MaybeSend` and `MaybeSync` are the existing `crate::rt` items. `S` is the store the handler reads
  and writes, so each driver builds a registry for its own concrete store type.
- Put this idempotency rule in the trait docs: **`fire` may run more than once for the same timer. Every effect
  outside the returned batch MUST be idempotent. Effects inside the batch are applied at most once per timer row**
  (by B.4's precondition).

### B.4 `run_due`

```rust
pub async fn run_due<S: NamespaceStore>(
    store: &S, p: &Partition, registry: &TimerRegistry<S>,
    clock: &dyn Clock, now_ms: u64, budget: &TickBudget,
) -> Result<RunReport, StoreError>
```

**The tick:**
- Scan `w 00 ..= w 00 <now_ms:be64> ff…`, i.e. every timer with `due_at_ms <= now_ms`, in key order (due order), in
  pages.
- For each timer, in order:
  1. Stop, with reason `Budget`, if any of these holds: `fired == max_fired`, `scanned == max_scanned`, or
     `clock.now_ms() - start >= max_elapsed_ms`.
  2. Unregistered kind (including 0): count it as `unknown`, log at `warn` (once per kind per tick), leave the row
     untouched, and continue. **Never delete an unknown kind's timer** (a newer binary may own it).
  3. The kind has reached its per-tick cap (`handler.max_per_tick().unwrap_or(budget.max_per_kind)`): count it as
     `deferred`, and continue.
  4. Call `fire`. `Err` or `Fired::Retry` counts as `failed`: leave the row and continue.
  5. `Done`/`Reschedule`:
     - Append to the handler's batch, in this order:
       1. `Precondition::Equals(timer_key, value)`;
       2. `Write::Delete(timer_key)`;
       3. for `Reschedule`, `Write::Put(keys::timer(new_due, kind, ref), new_value)`.
     - A `Reschedule` whose new key equals the old key counts as `failed`, with the batch not applied.
     - Then `apply`:
       - `Committed` counts as `fired`;
       - `PreconditionFailed` counts as `raced` (another run already handled it: this is the idempotency path);
       - `DeadlinePassed`, `Err`, including `Full`, counts as `failed`.
- Keep the earliest `due_at` of any `w` Put in a batch the tick committed (from reschedules or the handlers'
  batches).
- After the due range, read the first timer with `due_at > now_ms`: one `scan` with limit 1 from
  `w 00 <now_ms+1:be64>` to the end of the `w` class. If the tick stopped on the budget, don't read it.

**`RunReport`** (`#[non_exhaustive]`, Debug, Clone, PartialEq, Eq) has:
- `fired`, `raced`, `failed`, `unknown`, `deferred`, `scanned` (all `u32`);
- `stopped_on_budget: bool`;
- `next_wake_ms: Option<u64>`.

**`next_wake_ms`, exactly:**
- a. `(stopped_on_budget || deferred > 0) && fired > 0` gives `Some(now_ms)`: more work is fireable now.
- b. Otherwise, if `failed + unknown > 0` or `stopped_on_budget`, it gives
  `Some(min(first_future_due, now_ms + RETRY_BACKOFF_MS))`. An unread `first_future_due` counts as +∞.
- c. Otherwise it gives `first_future_due`, which is `None` when no timer remains.
- d. In every case, take the min with the earliest committed `w` Put from above, and never go below `now_ms`.

**Constants and errors:**
- `pub const RETRY_BACKOFF_MS: u64 = 5_000;`
- `run_due` returns `Err` only when a `scan` fails. Per-timer errors are counted, never propagated.

### B.5 `TickBudget`

- `#[non_exhaustive]`, Debug, Clone, Copy. Fields `max_fired: u32`, `max_per_kind: u32`, `max_scanned: u32`,
  `max_elapsed_ms: u64`.
- `impl Default` gives `128, 32, 512, 10_000`.
- Provide `pub const fn new(max_fired, max_per_kind, max_scanned, max_elapsed_ms)`, which clamps each to ≥ 1.

### B.6 SQL backend: timer index and heads (`mkit-server/src/sql/`)

1. **Migration `version: 2`** (`sql/schema.rs`; `SCHEMA_VERSION = 2`), which adds exactly:
   ```sql
   CREATE INDEX IF NOT EXISTS kv_timers ON kv (key, part) WHERE key >= x'7700' AND key < x'7701'
   ```
   `x'77'` is `w` and `x'00'` the terminator. Existing databases (native files, vcs-worker DOs) migrate on open,
   through the existing loop.
2. **An inherent method** on `SqlKvStore<C>`:
   `pub fn timer_heads(&self) -> Result<Vec<(Partition, u64)>, StoreError>`. It returns the earliest `due_at` per
   partition, from:
   ```sql
   SELECT part, MIN(key) FROM kv WHERE key >= x'7700' AND key < x'7701' GROUP BY part
   ```
   - The query MUST repeat the partial-index predicate verbatim, so the planner can use it.
   - Decode `part` with `Partition::decode` and the key with `keys::parse` (or equivalent).
   - A row that doesn't decode is `StoreError::Corrupt`/`Invalid`, matching how `sql/kv.rs` reports corrupt rows.
3. **Not a trait method** (A.5). It is the SQL backend's own admission that its rows carry the partition.

### B.7 Workers driver (`mkit-server-worker/src/alarm.rs`, `ns_object.rs`, `apps/vcs-worker/src/worker_impl.rs`)

1. **Pure logic in `alarm.rs`,** host-testable, with no `worker` types:
   - `fn earliest_timer_put(batch: &Batch) -> Option<u64>`: the min `due_at` over `Write::Put` keys that parse as
     `ParsedKey::Timer`.
   - `fn alarm_after_put(current: Option<i64>, earliest: u64, now_ms: u64) -> Option<i64>`: `Some(max(earliest,
     now))` when there is no current alarm or the new one is earlier; otherwise `None` (leave it).
   - `fn alarm_after_tick(next_wake: Option<u64>, now_ms: u64) -> AlarmAction { Set(i64), Delete }`.
2. **`NsObject` keeps the object's `worker::Storage`,** from the `State` it already receives.
   - After `NsCall::Apply` returns `Committed` for a batch where `earliest_timer_put` is `Some`, it calls
     `get_alarm`, then `set_alarm` if `alarm_after_put` says so.
   - Deletes never move the alarm. A stale early alarm is harmless: the tick finds nothing and reschedules.
   - An alarm-API failure is logged via the existing `crate::log_failure` path, and does NOT fail the already
     committed apply.
3. **`NsObject::alarm(&self) -> worker::Result<worker::Response>`:**
   - Open the store, and call `timer_heads()`. A Durable Object holds one partition, so zero or one row is expected;
     if there are several, run each.
   - For each head, call `run_due(store, &p, &registry, &clock, now, &TickBudget::default())`. `now` comes from the
     object's clock (`crate::clock`).
   - Then set or delete the alarm from the earliest `next_wake_ms` across heads, per `alarm_after_tick`.
   - Return `Ok` unless the store fails to open or a `scan` fails. In that case return `Err` and let Cloudflare's
     retry apply.
4. **Registry:**
   - `NsObject` builds its `TimerRegistry<SqlKvStore<DoConn>>` at construction.
   - Under `test-faults` it registers `TestTimer` (B.9); in release builds it is empty.
   - Construction stays in `adapter::ns_object(state, &env)`. Later WPs add handlers there.
5. **`apps/vcs-worker/src/worker_impl.rs`:** `RefStore` implements `async fn alarm(&self) -> Result<Response> {
   self.object.alarm().await }`. No wrangler config change: alarms need none, and the class and its migration are
   unchanged.

### B.8 Native driver (`mkit-server-native/src/timers.rs`)

1. **Directory:**
   - An in-memory directory: `partition → next due (u64)`, plus an ordered view by due.
   - At startup it is rebuilt from `SqlKvStore::timer_heads()`, run on the blocking pool.
   - **This supersedes the breakdown's "native-only helper partition".** A helper partition is a second,
     non-atomic write per timer batch and doesn't survive a restore, while the `kv` table already knows.
   - Add a row `R-89` to `docs/plans/mkit-server/00-plan.md`'s reconciliation table saying exactly that.
2. **`TimerNotifying<N>`,** a native-only wrapper implementing `NamespaceStore` by delegation:
   - after a `Committed` `apply` whose batch has a timer Put, it lowers that partition's directory entry to
     `earliest_timer_put` and wakes the driver (`tokio::sync::Notify`);
   - reuse B.7.1's `earliest_timer_put` by moving it to `mkit_server::timers` as a pub fn, so both adapters share it.
3. **Wiring:**
   - Only the **SQLite metadata choice** gets timers. In `server.rs` `with_meta`, the SQLite branch wraps the store
     in `TimerNotifying` before `build_services`, and a driver is created over the same store.
   - `MetaChoice::FsLayout` gets no driver: it cannot hold timers (A.3).
   - `build_services`'s generic signature and the native test wrappers (`SlowKv`, `SlowCommit`, …) stay unchanged.
4. **Loop:**
   - Sleep until the earliest directory due, capped at 60 s, or until notified, or until shutdown.
   - On wake, for every partition whose due ≤ now, in due order, call `run_due(…, TickBudget::default())`.
   - Set the partition's entry to `report.next_wake_ms`, or remove it on `None`.
   - If `run_due` returns `Err`: log it, and set that partition's entry to now + `RETRY_BACKOFF_MS`.
5. **Spawn and shutdown:**
   - The driver is spawned on the server's runtime and stopped by the existing `Shutdown`.
   - On shutdown it finishes the `run_due` in progress (it "drains the current tick"), starts no new one, and exits.
   - `serve_services` awaits it after the listeners drain.
6. **Registry:** under `test-faults` it registers `TestTimer`; in release it is empty.

### B.9 Test kind and test directives (`test-faults` only)

1. **`TestTimer`,** `impl<S: NamespaceStore> TimerHandler<S>`, kind `kinds::TEST`:
   - Its `reference` is `<repo name> 00 <refname>`.
   - `fire` returns `Fired::Done(Batch::new().delete(keys::ref_key(&repo, refname)))`: it deletes that ref.
   - A malformed reference gives `Ok(Fired::Retry)`.
2. **Two new directives** in `pipeline/faults.rs` `TestDirectives`, following `CLOCK_SKEW_HEADER`:
   - `x-mkit-test-timer-ms: <u64 delay>`, honoured on a **committed `UpdateRef`** only.
     - After the write commits, the pipeline applies one extra batch
       `Batch::new().put(keys::timer(business_now + delay, TEST, <repo 00 ref>), Value::new(Bytes::new()))`.
     - It targets the ref's shard partition (`self.shards.ref_shard(&repo, ref)`).
     - It is not atomic with the ref write, which is acceptable for a test directive.
     - A failure of that extra batch gives `internal`.
   - `x-mkit-test-run-timers: <refname>`, honoured on **`ListRefs`**.
     - Before listing, the pipeline runs
       `run_due(meta, &ref_shard(repo, refname), &test_registry, clock, business_now, &TickBudget::default())`,
       where `business_now` includes `x-mkit-test-clock-skew-ms`.
     - It ignores the report and then lists as normal.
   - A malformed value is `invalid_argument`, like the skew header.
   - Both are compiled out without `test-faults`, like the existing directives.
3. **No test-kind code or directive exists in a release build.** A test asserts that the release-feature build of
   `mkit-server` rejects or ignores both headers exactly as it does any unknown header today.

### B.10 Conformance

1. **New feature:** `Feature::Timers`, spelled `"timers"`, in `wire/profile.rs`, documented as: "the server fires due
   timers on its own clock (a driver runs)". Update `FEATURE_NAMES` (19 → 20).
2. **Declarations:**
   - the spawned native binary baseline (SQLite meta) and the vcs-worker `--test-faults` run declare it;
   - the in-process `baseline_pipeline_memory` does NOT (it has no driver).
3. **New file `wire/cases/timers.rs`,** registered in `cases/mod.rs`:
   - `timers.directive_fires_due` (requires `TestFaults`):
     1. create ref `X` with `x-mkit-test-timer-ms: 600000`;
     2. `ListRefs` with `x-mkit-test-run-timers: X` and no skew: `X` is listed;
     3. `ListRefs` with `x-mkit-test-run-timers: X` and `x-mkit-test-clock-skew-ms: 1200000`: `X` is gone;
     4. `ReadRef X`: absent.
   - `timers.fire_on_schedule` (requires `TestFaults` + `Timers`):
     1. create ref `Y` with `x-mkit-test-timer-ms: 1000`;
     2. poll `ReadRef Y` every 250 ms for up to 20 s until it's absent;
     3. fail if it's still present after 20 s.
   - `timers.redelivery_is_idempotent` (requires `TestFaults`): run step 3 of the first case twice more. Both extra
     runs succeed, with no error and no change.
4. The vcs-worker `--test-faults` phase declares `timers`: run `scripts/vcs-worker-conformance.sh --test-faults`
   locally, where `wrangler dev` runs alarms. Adjust the script's feature list only by adding `timers` to the
   test-faults phase.

## C. Your decisions (record each in the PR under "Executor decisions")

- `TimerRegistry`'s internal storage and lookup.
- Paging size for the due scan (≤ `max_scanned`), and the per-kind "warn once" mechanism.
- How `NsObject` holds `Storage` and the clock, and how the alarm path shares the store instance with `handle`.
- The native directory's data structure, and how the driver hands off to `serve_services` (a join handle, a struct
  field, etc.).
- Test organisation and helper names.

## Tests (required)

**Core** (`timers/`), over the memory store with `ManualClock`:
1. Due timers fire, and future ones are untouched. `next_wake_ms` is the first future due, or `None` when empty.
2. **Idempotency:**
   - a second `run_due` at the same `now` fires nothing;
   - a timer whose row changed between scan and apply (simulate with a store wrapper) counts as `raced`, and the
     handler's batch is not applied.
3. **Atomicity:** a `Done` batch with an extra Put commits together with the timer delete. With a failing
   precondition in the handler's batch, neither commits and the timer remains (`raced`).
4. **Fairness:**
   - 100 due timers of kind A before 5 of kind B, with `max_per_kind = 10`: one tick fires 10 A and 5 B, `deferred =
     90`, and `next_wake_ms = Some(now)`;
   - repeated ticks drain everything.
5. **Budget stop:** the `max_fired`, `max_scanned` and `max_elapsed_ms` stops each work. For elapsed, use a handler
   that advances the `ManualClock`.
6. **Unknown kinds and failures:**
   - 600 unknown-kind timers with `max_scanned = 512` gives `fired = 0`, `next_wake_ms = now + RETRY_BACKOFF_MS`, and
     no row deleted;
   - a failing handler gives the same backoff, and the row remains.
7. `Reschedule` moves the row; a same-key reschedule counts as `failed`.
8. A handler that puts a new timer earlier than the first future due lowers `next_wake_ms` to it.

**SQL.** `mkit-server/src/sql/tests.rs` is pure: it holds statement texts, with no engine. The engine-backed tests
live in `mkit-server-native/src/sqlite/tests.rs`.
- **Pure, in `sql/tests.rs`:**
  - add the heads statement, as a `const` in `sql/kv.rs`, to `statements()`, so the existing
    "no transaction control" and placeholder checks cover it;
  - assert that the heads statement contains the index's `WHERE` predicate verbatim.
- **Engine, in `mkit-server-native/src/sqlite/tests.rs`:**
  1. The v1→v2 migration applies to a v1 database, and re-opening is idempotent.
  2. `timer_heads` returns one row per partition with its minimum.
  3. `EXPLAIN QUERY PLAN` of the heads statement, run through `RusqliteConn::query` in the test, names `kv_timers`.
     This pins the partial-index use.

**Worker:** host tests for the pure `alarm.rs` functions. The wasm path is covered by the vcs-worker conformance run.

**Native** (`mkit-server-native/tests/timers.rs`):
1. Restart rebuilds the directory: write a due timer, stop the server, restart over the same database, and it fires.
2. A newly put earlier timer wakes a sleeping driver before its 60 s cap (use a short delay and a bounded wait).
3. Shutdown drains the tick in progress: a handler that blocks until released; trigger shutdown; release; the fire
   commits; the driver exits.
4. FsLayout meta: no driver starts, and serving is unchanged.

**Wire:** B.10 on every baseline that declares the features.

**Unchanged behaviour:**
- all existing tests pass;
- the goldens are unchanged (`git diff --exit-code rust/tests/golden/`);
- the ssh goldens pass.

## D. Escalate (stop and report, do not improvise) if

- workers-rs 0.8.6's `alarm`/`set_alarm`/`get_alarm` can't be used from `NsObject`, e.g. because `Storage` is
  unavailable after `DoSqlConn::from_state`.
- The partial-index migration fails on the DO SQLite dialect, or `EXPLAIN QUERY PLAN` shows the index unused and no
  predicate spelling fixes it.
- Implementing B.4 exactly would violate a store-contract rule (A.3), or `run_due` needs a trait change to
  `NamespaceStore`.
- A `test-faults` directive can't be honoured without changing a public pipeline signature.

## Gate additions

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance --all-features`, and the
  same without `--all-features` for `mkit-server` (release-feature build, for B.9.3)
- the wasm32 check of `mkit-server`; the build of `mkit-server-worker`; the wasm32 build of `apps/vcs-worker`
- `scripts/vcs-worker-conformance.sh --test-faults`: wrangler has been available locally to earlier executors. If it
  isn't, say so explicitly in the PR.
