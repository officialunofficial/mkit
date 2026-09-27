## Purpose

The grant epoch `e 00` lives in the namespace coordinator. Under D34, writes commit in per-branch ref shards, which
can't read the coordinator atomically, so today a D34 write reads `e` from its own ref shard, where nothing writes it:
the epoch is always 0 (`pipeline/mod.rs:879`, `TODO(WP-1.25)`).

This WP gives each ref shard a time-bounded **epoch lease**:
- the coordinator records which shards hold a lease on which epoch, until when;
- a shard's write commits only if its lease is valid at commit time (a `NotAfter` deadline), and only against the
  leased epoch;
- bumping the epoch pushes the new value to every leased shard, and completes only when each has taken it or its
  lease has expired.

The **Single** path stays exactly as today: one partition, and `e` is read directly.

## A. Fixed by the plan and specs (do not change)

1. **Specs:**
   - SPEC-WRITE-GRANTS §1.1 (parameters: `epoch_lease` 30 s, `margin` 5 s, `MAX_APPLY_WINDOW` 10 s);
   - §5.4–§5.6 (lease rules):
     - record a lease durably before returning it;
     - serialize lease grants with epoch changes;
     - a coordinator that lost its lease table waits `epoch_lease + margin` before reporting completion;
     - a shard renews on its next write;
     - the deadline is `min(lease_expires − margin, plan_time + MAX_APPLY_WINDOW)`;
     - a miss is `unavailable` and may be re-planned once.
2. **STC §5.1 "No state on challenge":** a challenged or denied request MUST NOT change any state. Lease rows count
   as state.
3. **Store contract (`store/kv.rs` rules 6, 8):** one batch is one partition. `NotAfter` is evaluated on the backend's
   clock.
4. **Timers (WP-1.24):**
   - a handler touches only its own partition (the Worker DO's store is its own);
   - kinds are allocated in `timers/registry.rs::kinds`, taking the next free number: **this WP allocates kind 1**.
5. **`l` is reserved for WP-5.2** (lifecycle leases). **Do not use it.**
6. **Single sharding (`Sharding::Single`) is unchanged,** and so are all its tests.

## B. Decided by the orchestrator (do not change)

### B.1 Parameters (`PipelineConfig`, with defaults)

- `epoch_lease_ms: u64 = 30_000`
- `lease_margin_ms: u64 = 5_000`
- `min_lease_budget_ms: u64 = 1_000`

`Pipeline::new` refuses (constructor error):
- `epoch_lease_ms <= lease_margin_ms + min_lease_budget_ms`;
- `lease_margin_ms == 0`.

### B.2 Key layouts (`store/keys.rs`, codecs in `store/codec.rs`: versioned JSON, `deny_unknown_fields`, with goldens)

| Class | Partition | Key | Value |
|---|---|---|---|
| epoch lease (the shard's copy) | ref shard | `el 00` | `EpochLease { epoch: u64, expires_at_ms: u64, config_version: u64 }` |
| leased-shard row | coordinator | `ls 00 <repo> 00 <shard_ref>` | `LeasedShard { epoch: u64, expires_at_ms: u64, acked_epoch: u64 }` |

- `el`: move it out of `RESERVED_TAGS` and give it a `TAG_EPOCH_LEASE` constant. `ls` is a new tag. Add `ParsedKey`
  variants, `parse` arms, golden bytes and `all_tags`.
- `<shard_ref>` is the `Partition::Ref.shard_ref`.

### B.3 Write path under `Sharding::D34` (the only path that changes)

1. **`read_ahead`** (the ref shard's single `get_many`) reads `el 00` instead of `e 00`. `rk` stays as WP-1.22 made it.
2. **Usability:**
   - the lease is *usable* iff `el` is present and `el.expires_at_ms − lease_margin_ms − plan_time ≥ min_lease_budget_ms`;
   - `plan_time` is the pipeline clock, never the business-skew clock (P-21).
3. **Usable lease:**
   - no coordinator call (creation facts are `default`; a lease implies the repo is registered);
   - `leased_epoch = el.epoch`;
   - `lease_deadline = el.expires_at_ms − lease_margin_ms`.
4. **No usable lease:**
   - One coordinator `get_many` of `[nr 00, rr 00 <repo>, e 00, ls 00 <repo> 00 <shard_ref>]`. It replaces WP-1.22's
     `read_creation` for this case, so there is still one read.
   - The creation facts come from `nr`/`rr`, as today.
   - Keep the observed `e` and `ls`.
   - **Nothing is written before authorize and admit.**
5. **After admission returns `Allow`, only if step 4 ran:** one coordinator batch that **also** carries WP-1.22's
   creation rows when creating. It holds:
   - the creation `Absent`/`Put` for `nr`/`rr` when creating, otherwise `Present(nr)` and `Present(rr)`;
   - `Equals(e, observed)` or `Absent(e)` when unobserved;
   - `Equals(ls, observed)` or `Absent(ls)`;
   - `Put(ls, LeasedShard { epoch: observed e (0 if absent), expires_at_ms: max(observed.expires, now + epoch_lease_ms),
     acked_epoch: observed e })`;
   - the sweep timer move (B.6);
   - no `NotAfter`.

   `PreconditionFailed` → re-read the four keys and rebuild, with the same bounded retry loop as
   `commit_creation` (3 attempts), then `internal`. `leased_epoch` and `lease_deadline` come from the committed
   `ls`. `commit_creation` is folded into this batch under D34. It stays as is under Single.
6. **The ref-shard write batch** (`plan_and_apply`) additionally carries:
   - the guard `Equals(el, observed el)` or `Absent(el)`;
   - when step 5 ran, `Put(el, EpochLease { epoch: leased_epoch, expires_at_ms: ls.expires_at_ms, config_version:
     nr.config_version })`.
7. **Epoch check and deadline:**
   - `plan_write` compares a grant's epoch with **`leased_epoch`** under D34 (`e` under Single). This is unchanged
     semantics: M1 has no grants, so it only matters from WP-2.6.
   - The deadline cap is `min(existing replay cap, lease_deadline)` (`pipeline/mod.rs:1128-1138`).
   - `NotAfter` stays the first precondition.
8. **Failures in `apply_loop`:**
   - a failure of the **`el` guard** → **re-plan** (re-read `el`, renewing if unusable), counted toward `MAX_REPLAN`.
     It never maps to `permission_denied`. Keep the existing `epoch_index` mapping only for the Single-path `e` guard;
   - `DeadlinePassed` → the existing re-plan-once path, which renews if the lease became unusable.
9. **`Operation` gains `pub leased_epoch: Option<u64>`,** for WP-2.6.

**Resulting store-call counts under D34** (update `d34_creation.rs` to assert exactly):

| Write | Store calls |
|---|---|
| Steady state (usable lease) | 2 |
| New ref shard of an existing repo, or an expired lease | 4: read-ahead, coordinator `get_many`, coordinator `apply`, ref `apply` |
| First write creating the repo | 4 (creation folded into the lease batch) |
| Denied or challenged write | exactly the reads (read-ahead plus the coordinator `get_many`); **no `apply`** |

Record the deviation from the plan's "3 for a new shard" as row `R-97` in `00-plan.md`:

> WP-1.25 renews with exact coordinator reads, after admission, so no lease state is written for a challenged or
> denied request (STC §5.1). A new or expired shard costs 4 calls, not 3. Steady state stays 2. An optimistic
> single-call renewal can come later if measured load needs it.

### B.4 Epoch bump and completion (core only; the RPC is WP-2.8)

**`pub async fn bump_epoch(&self, ns, new_epoch) -> Result<(), ServerError>` on `Pipeline`:**
- One coordinator batch: `Equals/Absent(e, current)` + `Put(e, new_epoch)`.
- `new_epoch` must be greater than `current` and at most `current + MAX_EPOCH_STEP (1024)`. Otherwise
  `invalid_argument`.

**`pub async fn revoke_step(&self, ns, budget) -> Result<RevokeProgress, ServerError>`:**
1. Scan `ls` rows (paged).
2. For each row with `acked_epoch < e` and `expires_at_ms > now`: write
   `Put(el, EpochLease { epoch: e, same expires, config_version })` to that ref shard.
   - Guard it with `Equals` on the `el` value just read, or with `Absent(el)` when absent.
   - **Always write it, even when `el` is absent or older**, so an in-flight batch guarded on the old `el` can't
     commit.
   - Then set `acked_epoch = e` in the `ls` row (a coordinator batch with an `Equals` guard).
3. Stop after the budget: at most 4 shards per call, and at most `budget.max_elapsed_ms`.
4. Return `RevokeProgress::{Complete, Pending { remaining }}`.
   - `Complete` iff every `ls` row has `acked_epoch == e` or `expires_at_ms <= now`.
   - If the coordinator has no `ls` rows but `nr.created_at_ms` is newer than `now − (epoch_lease_ms +
     lease_margin_ms)`, return `Pending`, because a lost-table restart must wait (SPEC-WRITE-GRANTS §5.4).

Driving these from a real RPC is WP-2.8. This WP drives them from the test hook (B.7).

### B.5 Reads

**Unchanged.** Read-path renewal is WP-2.9. `require_repository` stays a coordinator `get(rr)`.

**The `config_version` isolate cache (R-90) is deferred again,** to WP-2.9 (visibility), because it only pays off once
reads carry config. Add row `R-98`:

> R-90's `config_version` cache is deferred to WP-2.9. M1 reads keep one coordinator `get`.

### B.6 Sweep timer (`timers::registry::kinds::LEASE_SWEEP = TimerKind::new(1)`)

- One timer row per `ls` row, in the coordinator partition. Its reference is `<repo> 00 <shard_ref>`, and it's due at
  `ls.expires_at_ms`.
- Every lease batch (B.3.5) deletes the old timer row and puts the new one, in the same batch.
- The handler `LeaseSweep`: if the real `now ≥ ls.expires_at_ms`, return `Fired::Done(Batch` deleting the `ls` row,
  guarded with `Equals` on it`)`. Otherwise `Reschedule` to `ls.expires_at_ms`.
- Register it **unconditionally** (release builds too):
  - native: `mkit-server-native/src/server.rs` registry;
  - Worker: `mkit-server-worker/src/adapter.rs` `ns_object`.
- Update the kinds doc table.

### B.7 Test hook (`test-faults` only)

- A pipeline fn `test_bump_epoch(ns, new_epoch)` that runs `bump_epoch`, then `revoke_step` until `Complete` or 10
  s.
- Expose it as a directive: `x-mkit-test-bump-epoch: <u64>` on `ListRefs`, following WP-1.24's directives in
  `pipeline/faults.rs`. It runs before listing.
- **No new HTTP route.**
- Add a conformance feature `epoch-leases` (M1, **not** the M5 `leases`), with one wire case:
  - `leases.bump_completes_and_writes_continue`: write, bump, then write again. The write succeeds, and under D34
    the second write renewed.
- The native spawned binary's D34 run declares the feature. The Worker doesn't yet (WP-1.8 adds Worker D34; a
  later WP declares it there).

### B.8 Out of scope (state it in the PR)

- read renewal (2.9);
- visibility;
- restore and the lost-table rule in backup (1.29);
- relay watermark fields (1.23);
- quota fields (1.26);
- ticketed uploads using the lease (1.9);
- the `SetGrantEpoch`/`GetGrantEpoch` RPCs (2.8);
- the Worker D34 conformance run for leases.

## C. Your decisions

- Module layout (e.g. `pipeline/lease.rs`) and helper names.
- How `read_ahead` threads `el` versus `e` by sharding mode.
- `RevokeProgress` fields beyond `Complete`/`Pending { remaining }`.
- Test organisation.

## Tests (required)

1. **Codecs and keys:** goldens, and class disjointness (`e` vs `el` vs `ls`).
2. **Lease lifecycle**, D34, over memory and SQLite, with `ManualClock` for the pipeline and a separate store clock:
   - first write grants: 4 calls;
   - steady state: 2 calls;
   - after `epoch_lease_ms` has passed: 4 calls (renewal);
   - the deadline equals `min(replay cap, expires − margin)`;
   - a lease whose remaining budget is below `min_lease_budget_ms` renews.
3. **No state on rejection:** a challenged, and a denied, D34 write on an existing repo without a usable lease makes
   reads only. No coordinator `apply`, and no `el`/`ls` change.
4. **`el` guard race:** a concurrent revoke push changes `el` between plan and apply. The write re-plans and commits
   against the new epoch, and is never `permission_denied`.
5. **Revocation safety:**
   - a batch planned under epoch N and delayed past the push can't commit (the guard fails, or the deadline passes);
   - `revoke_step` completes only when every shard has acked or expired;
   - an absent-`el` shard still gets the push;
   - the lost-table rule returns `Pending`.
6. **Sweep:** an `ls` row is deleted after expiry by the timer. A renewal moves the timer row atomically.
7. **Single unchanged:** every existing Single test passes unmodified, and a Single write reads `e` directly with no
   `el`.
8. **Wire:** `leases.bump_completes_and_writes_continue` on the in-process baseline (with D34) and the native binary's
   D34 run.

## D. Escalate (stop and report) if

- B.3's ordering can't keep "no state before admission" with WP-1.22's `commit_creation` placement.
- Any B.4 step would need an atomic write across the coordinator and a ref shard.
- A rule in SPEC-WRITE-GRANTS §5.4–§5.6 isn't satisfied by B.3–B.4. Quote it.
- Folding creation into the lease batch changes any WP-1.22 creation-race outcome (the two-repo race must still give
  one namespace creator and two repo creators).

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance -p mkit-server-worker --all-features`
- the wasm32 check of `mkit-server`; the build of `mkit-server-worker`
- the native wire suite with `--sharding d34`
- goldens unchanged except the new key and codec entries

## Amendment 1

Correct stop, and thank you for the executable counterexamples: both are real defects in the brief. This amendment
replaces the named parts of B.3.5 and B.4. Everything else in the brief stands.

Continue in the same worktree and branch (`.claude/worktrees/wp-1-25`, `mkit-server/wp-1-25-epoch-leases`). The
definition of done is an **open PR**. Fold this into `docs/plans/mkit-server/briefs/WP-1.25.md` as "Amendment 1".
Delete `docs/plans/mkit-server/WP-1.25-escalation.md` from the branch, and put its model and counterexamples into the
PR body and into regression tests (§3).

## 1. Acknowledgement means "installed in the shard" (replaces B.3.5's `acked_epoch` rule)

**Invariant, to put in rustdoc and INVARIANTS:**
- `ls.acked_epoch = n` only if either:
  - the shard's `el` durably holds epoch ≥ n; or
  - every write the shard could still commit under an older epoch is already past its deadline.

**Renewal (B.3.5) `Put(ls, …)` sets `acked_epoch` as follows:**
- **observed `ls` is present and live** (`observed.expires_at_ms > now`): `acked_epoch = observed.acked_epoch`. It is
  **preserved, never raised by renewal**.
- **observed `ls` is absent, or expired** (`observed.expires_at_ms <= now`): `acked_epoch = observed e`. This is
  safe:
  - any older `el` on that shard has `expires_at_ms <= ls.expires_at_ms <= now`;
  - so every in-flight write guarded by it has a `NotAfter` deadline of at most `expires − margin < now`, and it
    fails on the backend clock (margin ≥ skew, SPEC-WRITE-GRANTS §1.1).
  - Rely on the invariant `el.expires_at_ms == ls.expires_at_ms` at grant. Revoke pushes keep `expires` unchanged.
    Assert it in debug builds.

**`ls.epoch`** still records the epoch granted by this renewal. B.3.6's `Put(el, …)` is unchanged.

**Revocation (B.4) consequences:**
- `revoke_step` pushes to every live row with `acked_epoch < e`, including a row a renewal just wrote with
  `epoch == e` but a preserved lower `acked_epoch`. Re-pushing the same epoch is harmless: an `Equals`-guarded write
  of the same value.
- **Push race.** If the push's `Equals(el, read)` fails because a concurrent B.3.6 ref batch changed `el`, re-read
  `el` and retry the push within the step's budget. Only after a push **commits** does the coordinator batch set
  `acked_epoch = e`, guarded with `Equals(ls, read)`. On `PreconditionFailed`, re-read, and ack only if the row is
  still live and still below `e`.
- `Complete` iff every `ls` row has `acked_epoch == e` or `expires_at_ms <= now`, and the recovery hold-off (§2) has
  passed.

## 2. Lost-table recovery (replaces B.4's `nr.created_at_ms` check)

A namespace record's creation time says nothing about when a coordinator resumed. Loss of the lease table only
happens through restore or recovery; normal operation never loses committed rows. So recovery is **declared**, not
inferred.

- **New key** in the coordinator: `lr 00` → codec `LeaseRecovery { resumed_at_ms: u64 }`, versioned JSON with
  `deny_unknown_fields`, plus a golden and `class_scans_never_overlap` coverage.
- **`pub async fn mark_lease_table_recovered(&self, ns) -> Result<(), ServerError>`:** puts
  `lr = { resumed_at_ms: now }`, overwriting.
  - Rustdoc: any procedure that restores or rebuilds a coordinator partition MUST call it **before** serving writes
    for that namespace.
  - Also expose it under the `test-faults` directive set as `x-mkit-test-lease-recovered: 1` on `ListRefs`,
    alongside `x-mkit-test-bump-epoch`.
- **`revoke_step`:** if `lr` is present and `now < lr.resumed_at_ms + epoch_lease_ms + lease_margin_ms`, return
  `Pending`, regardless of the rows (SPEC-WRITE-GRANTS §5.4).
- The `lr` row is never deleted. It's one row per namespace, and a later recovery overwrites it.
- Add row `R-100` to `00-plan.md`:

  > WP-1.25: lease-table loss is declared through `mark_lease_table_recovered` (coordinator `lr 00` marker).
  > WP-1.29's restore, and any coordinator rebuild, MUST call it before serving writes; revocation completion waits
  > `epoch_lease + margin` after it (SPEC-WRITE-GRANTS §5.4).

## 3. Regression tests (required, in addition to the brief's)

1. **Your first counterexample, as a pipeline-level test** (memory and SQLite, D34), using `ManualClock` and the fault
   hooks to pause A before apply and pause B between B.3.5 and B.3.6:
   - `revoke_step` does **not** return `Complete` while A's `el` is still at the old epoch;
   - A's batch fails (the `el` guard, or the deadline).
   - Also the variant where B is cancelled after B.3.5 and never runs B.3.6: `revoke_step` pushes and acks, and A
     fails.
2. **Your second counterexample:** a namespace with `nr.created_at_ms = 0` and `mark_lease_table_recovered` at
   `100000`:
   - `revoke_step` is `Pending` until `135000` and `Complete` afterwards (with no live rows);
   - without the marker, and with no rows, it is `Complete` immediately. That is correct: nothing was lost.
3. **The expired-row renewal case:** an `ls` row expired but not yet swept → renewal sets `acked_epoch = e`, and an
   in-flight write planned under the old `el` fails its deadline.
4. **Push race:** a concurrent B.3.6 changes `el` during `revoke_step`'s push → the push retries, then acks, and never
   acks without a committed push.

Also port your Python protocol model to a Rust property test over random interleavings of {plan write, renew,
bump, push, ack, apply, sweep, advance clock}. The property is SPEC-WRITE-GRANTS §5.6: once `Complete`, no write
planned under an older epoch commits.

## 4. Unchanged

Call counts (B.3), "no state before admission", the Single path, the sweep timer (kind 1), and the out-of-scope list.
If any of §1–§2 forces a call-count change, stop and report it.
