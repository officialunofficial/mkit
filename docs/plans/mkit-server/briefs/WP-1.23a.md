## Purpose

Under D34, a write commits in its ref shard. Its effects on other partitions (repository-index membership now; ref-name
index, object index and content holders later) are **outbox relay rows** that WP-1.7 laid out
(`or 00 <seq>` → `RelayV1 { target, puts }`), delivered **at least once, idempotently**.

Nothing delivers them yet, and nothing schedules delivery. This WP builds the delivery engine:
- a source-side relay timer (kind 3) that pushes rows to their targets in sequence order;
- a per-(source, target) high-water mark `rh` in the target, so re-delivery is a no-op;
- chunking so that one row always fits one target batch;
- a pre-delivery hook for later consumers.

Writers of relay rows (WP-1.10), the ref-name index (WP-1.28) and reads (WP-1.23b) come later. Tests here use
synthetic rows.

## A. Fixed by the plan, specs and merged code (do not change)

1. **Plan:** `m1-m2-breakdown.md` "WP-1.23" (≈ lines 220–247); `00-plan.md` R-82 and P-15 (relay-lag bound 60 s).
   The P-23 watermark part is split out, see B.8.
2. **WP-1.7 (merged):**
   - `store/outbox.rs`: `OutboxBuilder`, `relay()`, `try_finish` (one `or` row per distinct target per batch), and the
     shared `os` sequence, which is monotonic but not contiguous;
   - `store/codec.rs` `RelayV1`: upserts only, `deny_unknown_fields`;
   - `store/tickets.rs` `plan_membership`: relays only when `shards.membership(..) != source`.
3. **Store contract:** one batch is one partition. `MAX_BATCH_OPS` 100, `MAX_BATCH_BYTES` 1 MiB, `MAX_VALUE_BYTES`
   512 KiB.
4. **Timers (WP-1.24):**
   - handler contract (`timers/registry.rs:42-48`): `fire` may run more than once; any effect outside the returned
     batch must be idempotent;
   - `fire_timer` guards the timer row with `Equals` and deletes it with the returned batch;
   - kinds: 1 = `LEASE_SWEEP` (#1150), 2 = `TICKET_EXPIRY` (merged), **3 = `RELAY` (this WP)**.
5. **Partitions are never enumerated,** so a target can't pull from sources. Delivery is a **push from the source**.

## B. Decided by the orchestrator (do not change)

### B.1 Module and API (`rust/crates/mkit-server/src/relay/{mod.rs, deliver.rs, hook.rs}`, exported `mkit_server::relay`)

```rust
pub trait RelayHook: MaybeSend + MaybeSync {
    /// Called once per target batch before apply; may add writes/preconditions, or fail (= delivery failure, retried).
    fn before_apply<'a>(&'a self, target: &'a Partition, rows: &'a [(u64, RelayV1)],
                        pre: &'a mut Vec<Precondition>, writes: &'a mut Vec<Write>)
        -> BoxFuture<'a, Result<(), StoreError>>;
}
pub struct NoHook;   // default: Ok(()) and adds nothing
pub struct RelayHandler<T, H = NoHook> { target: T, hook: H, budget: RelayBudget }
impl<S: NamespaceStore, T: NamespaceStore, H: RelayHook> TimerHandler<S> for RelayHandler<T, H> { /* kind = RELAY */ }
pub struct RelayBudget { pub max_rows: u32 /* 256 */, pub max_targets: u32 /* 16 */ }  // #[non_exhaustive], Default
pub const RELAY_LAG_BOUND_MS: u64 = 60_000;   // P-15; exported for WP-1.10 / 4.4 / 4.7
pub async fn relay_watermark<S: NamespaceStore>(store: &S, p: &Partition, now_ms: u64) -> Result<u64, StoreError>;
```

### B.2 Delivery algorithm (inside `RelayHandler::fire`)

For the source partition `ctx.partition`:
1. Read `os` (the value is kept as `observed_os`).
2. Scan `or` rows in ascending order, up to `budget.max_rows`. Decode each `RelayV1`: an undecodable row is `Corrupt`,
   logged, and the tick stops with `Retry`, because the row is never skipped.
3. Group rows by `target`, preserving seq order. Take at most `budget.max_targets` targets. The rest wait for the next
   tick. Process targets **sequentially**.
4. For each target:
   1. `get(rh 00 <Partition::encode(source)>)` from the target store gives `hw`, or 0 if absent.
   2. Drop rows with `seq <= hw`: they are duplicates, already applied.
   3. Build **one** target batch:
      - `Equals(rh, observed)` or `Absent(rh)`;
      - all the puts of the remaining rows, in seq order (a later put of the same key wins);
      - `Put(rh, be64(max seq))`;
      - whatever `hook.before_apply` adds.
   4. Apply it to the target.
      - `PreconditionFailed` (a concurrent deliverer advanced `rh`): re-read `rh` and retry once.
      - Any other failure: this target stops for this tick. Its later rows stay, and the other targets continue.
5. For every row whose delivery committed, or was skipped as a duplicate: delete it at the source, in batches, with
   `Equals(or seq, value)` and `Delete`, committed **via `ctx.store.apply` inside `fire`**. This is idempotent, and
   keeps progress even if the timer's own batch later races.
6. Return:
   - `Fired::Reschedule { due_at_ms: now, … }` if rows remain (because of the budget, or a failed target, which
     retries under the timer's normal backoff);
   - otherwise `Fired::Done(Batch::new().require(Precondition::Equals(os_key, observed_os)))`. If a writer appended
     rows (and moved `os`) during the fire, this batch fails as *raced*, and the timer row stays. That guards the
     same-millisecond timer-key collision that would otherwise lose a wake-up.
   - A missing `os` with no rows returns `Done(Batch::new())`.

**Chunk guarantee (B.4):** every stored `RelayV1` fits one target batch, together with the `rh` guard and put. So a
single row never needs splitting at delivery time.

- If the combined puts of several rows for one target would exceed `MAX_BATCH_OPS` or `MAX_BATCH_BYTES`, deliver
  them in several target batches.
- Each batch advances `rh` to its own max seq, in seq order.

### B.3 Relay timer (kind 3), scheduled by the writer

- Add `kinds::RELAY = TimerKind::new(3)`, with a kinds-table row.
- **`OutboxBuilder` gains `pub fn relay_at(&mut self, now_ms: u64)`.** When the builder holds any relay rows,
  `try_finish` also puts `keys::timer(now_ms, RELAY, b"")` with an empty value.
  - It returns `Invalid("relay rows need relay_at")` if relays are present and `relay_at` was never called.
  - This timer is the "immediate kick" on both backends: the native driver notify, and the DO `lower_alarm`.
- **Budget:** `ADVANCE_SHARED_OPS` becomes **22**, and the `const` assert holds: 7 × 11 + 22 = 99 ≤ 100. Update the
  budget comment.

### B.4 Chunking in `try_finish`

- Add `pub const MAX_RELAY_PUTS: usize = 96`.
- `try_finish` splits one target's puts into several `or` rows (each its own seq) so that each row has at most
  `MAX_RELAY_PUTS` puts, and its encoded size plus a target batch's overhead fits `MAX_BATCH_BYTES`.
- Assert this with a `const` and a test that builds the maximal row and runs `Batch::validate` on its target batch.

### B.5 `rh` layout (`store/keys.rs`)

- `rh 00 <Partition::encode(source)>` → be64 last applied seq.
- Remove `"rh"` from `RESERVED_TAGS`. Add the constructor, the `ParsedKey` variant, the parse arm, golden bytes and
  `class_scans_never_overlap` coverage (next to `r`/`rr`/`rk`).
- Assert that the worst-case key fits `MAX_KEY_BYTES`: a `Ref` partition with a 255-byte repo name and a 512-byte
  ref name, ≈ 846 bytes.
- Document that `rh` rows are never pruned: they're bounded by the number of source shards.

### B.6 Commit-time stamp and local watermark

- `RelayV1` gains `at_ms: u64`: the writer's plan-time lower bound on commit time, set from `relay_at`'s `now_ms`.
  Nothing is deployed, so update the V1 codec and its golden in place, and document why.
- **`relay_watermark(store, p, now)`:**
  - if there are no `or` rows → `now`;
  - otherwise → `min(at_ms of undelivered rows) − 1`, via one ascending scan with limit 1. Rows are appended in
    commit order, so the first row is the oldest.
- Unit-test both cases.

### B.7 Registration and wiring (this WP)

- **Native:** register `RelayHandler { target: <a clone of the timer store>, hook: NoHook, budget: default }` in
  `mkit-server-native/src/server.rs`'s registry, unconditionally.
- **Worker: do not change the adapter in this WP.** Add `// TODO(WP-1.23b)` at `adapter::ns_object`'s registry.
  WP-1.23b registers `RelayHandler<DoNamespaceStore<StubTransport>>` for `ShardClass::RefShard`, after #1151.

### B.8 Out of scope, recorded as R rows in `00-plan.md`

- **R-101:**

  > WP-1.23 is split. 1.23a is the relay core (this WP). 1.23b, after #1150 and #1151 merge, adds:
  > - the Worker `RelayHandler` registration on `RefShard`;
  > - `is_member` and the `X-Mkit-Ref` read path, and Multi `PackExists`/`DownloadPack` wired to membership
  >   (replacing `require_pack_membership` for reads; UploadPack stays WP-1.9);
  > - the coordinator watermark (P-23: renewal payload, `ls` retention while a shard's outbox is undelivered,
  >   `namespace_relay_watermark`).
  >
  > WP-1.9 depends on 1.23a only.

- **R-102:**

  > `RelayV1` is upserts-only. Index deletes (ref deletion, WP-1.10/1.28) are designed by WP-1.28, either as
  > tombstone values or as a `RelayV2` with deletes. `rh` ordering keeps them safe, because each key has exactly one
  > source. A source restored to an older snapshot regresses `os`, and its new rows could be dropped as duplicates:
  > WP-1.29 restore MUST set each restored source's `os` above every target's `rh` for that source, or re-key it.
  > There is no relay-backlog bound yet (the PRD bound is for outcomes); `RELAY_LAG_BOUND_MS` exceeded is logged.

- **Lag observability:** when the oldest undelivered row is older than `RELAY_LAG_BOUND_MS` at fire time, emit
  `tracing::warn!` with the source and the age. Add no metric plumbing.

## C. Your decisions

- The internal structure of `deliver.rs`, and the batching of source deletes.
- Whether the Reschedule on target failure uses `now + RETRY_BACKOFF_MS`, or `now` plus reliance on the core backoff.
  State which, and why.
- Test organisation.

## Tests (required)

1. **Core, with a two-store harness** (source `MemoryKv`/SQLite, target `MemoryKv`/SQLite; `D34Shards` with synthetic
   rows from `OutboxBuilder` + `plan_membership`):
   - rows delivered in seq order, `rh` advanced, source rows deleted;
   - **re-delivery of the same rows is a no-op** (`rh`);
   - a **crash between the target apply and the source delete** (inject a failure on the source delete) leads to the
     next fire skipping the duplicates and deleting them;
   - a **failing target blocks only its own later rows**, and other targets are delivered;
   - **no lost wake-up:** a writer commits new rows and a same-millisecond timer during a fire (store-wrapper
     barrier), and the timer's `Done` batch fails as raced, so the new rows are delivered on the next fire;
   - the budget (`max_rows`, `max_targets`) causes a Reschedule;
   - an undecodable row causes `Retry` and is never skipped;
   - the hook's added writes commit atomically with the target batch, and a hook error blocks only that target;
   - the maximal chunk fits one target batch;
   - `relay_watermark` on empty and non-empty sources;
   - under `SinglePartition` nothing is relayed.
2. **Worker shape, host:** use `mkit-server-worker/tests/common` `Loopback` for the target
   (`DoNamespaceStore<Loopback>`) and a local `SqlKvStore` for the source, then drive `RelayHandler::fire` directly and
   assert DO call counts per delivery. Add a `pub(crate)` or test accessor to `Loopback` only if needed. The adapter
   is not touched.
3. **Native driver:** a relay row written with its kind-3 timer is delivered by the running driver without a sleep
   loop (bounded wait on the target's `rh`).
4. **Keys and codecs:** the `rh` golden; the `RelayV1` golden updated for `at_ms`; the kinds table.
5. **Unchanged:** every existing test, and the `const` budget assert (99 ≤ 100).

## D. Escalate (stop and report) if

- B.2's `Done`-with-`Equals(os)` guard can't be expressed through `Fired` without a timers-core change.
- Chunking (B.4) would require changing `OutboxBuilder`'s public signatures beyond adding `relay_at`.
- The Worker-shape host test needs changes to `mkit-server-worker`'s non-test code.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance -p mkit-server-worker --all-features`
- the wasm32 check of `mkit-server`; the build of `mkit-server-worker`
- goldens: only the new and updated key and codec entries change
