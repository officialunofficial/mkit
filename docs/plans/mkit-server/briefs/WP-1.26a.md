## Purpose

Under D34 today, a signer's quota lives in each ref shard, so it multiplies by the number of branches. This WP adds a
namespace-wide total:
- exact within each shard;
- rolled up to the coordinator periodically;
- checked approximately on writes from a local view, with a bounded overshoot and no extra DO call on the write path.

## A. Fixed (do not change)

1. **PRD D27/D34:** exact per ref shard, with per-shard counters reconciled into a namespace total.
2. **STC.**
   - Quota exhaustion is `resource_exhausted`.
   - Quota commits in the same transaction as the write (§7.1).
   - A failed quota read fails closed (§7.1).
   - Replays, live-ticket answers and `AlreadyPresent` answers run no admission and are never charged (§7.7).
3. **R-97:** admission runs before lease renewal. Any namespace view comes from the ref-shard read-ahead: one
   `get_many`, no extra call.
4. **Existing per-(namespace, signer) quota** (`quota.rs`, `DefaultAdmission`). It stays as it is.

## B. Decided (do not change)

### B.1 Namespace charge

In D34 **ref shards**, keep one all-signer counter per window W, where `W = floor(business_now / window)`:
- key `qs 00 <W:be64>`;
- the window in the key means no index is needed;
- stale windows are dropped by a range delete.

Cost per write:
- 2 ops (guard + put);
- 3 ops when a window opens (plus the rollup timer put).

Add a const assert that the maximal *admitted* write still fits `MAX_BATCH_OPS`. Ticketed advances are uncharged, so
they are unaffected.

### B.2 Coordinator and Single partitions

These charge the namespace total **exactly**, with no rollup. This covers Single sharding and the coordinator-partition
un-ticketed UploadPack path.

### B.3 Rollup timer, kind 5 (`QUOTA_ROLLUP`)

**Arming and schedule:**
- It is armed by the batch that opens a window, and fires every R. R is a named constant, default 60 s.

**On each fire:**
1. Read `qs[W]`.
2. In the coordinator, write under guards:
   - the per-source cumulative `qc 00 <W> <source>`;
   - the aggregate `qt 00 <W>`, adding the delta between the new and old `qc`. This makes at-least-once re-fires
     idempotent.
3. Write the local view `qv 00 <W>` = `{total, pushed}`.
4. Prune older windows on both sides.

**Stopping:** once the window has ended and everything is pushed.

**Native:** the handler gets a coordinator client, as the relay does. Workers registration is 1.26b.

### B.4 Enforcement

- The check lives in `plan_write` and runs before anything is written.
- The estimate is `qv.total − qv.pushed + local qs`.
- If the estimate exceeds the cap, the answer is `resource_exhausted` with the message: "namespace write op/byte quota
  exceeded for this window; try again later".
- The view read is unguarded: 0 ops and 0 calls.

### B.5 Views and faults

- Views live in `qv` rows, **not** in `el`. Writing into `el` would force a re-plan every R.
- A missing or stale view **allows** the write and emits a metric. It does not fail closed: a coordinator outage
  already stops writes within one lease period.

### B.6 Overshoot bound (documented, and tested in simulation)

The overshoot is at most the writes each other active shard admits in 2R, and each shard is also capped by its exact
per-signer limits.

### B.7 Defaults

- **Multi addressing:** the namespace cap equals the per-signer limits. M1 is owner-only, so this restores today's
  budget across refs.
- **Single addressing:** the namespace cap is **off**. Every signer shares `root` there, so a shared cap would let one
  signer lock out the rest.
- Per-signer quota on Single-addressing D34 becomes per (signer, branch). This is **accepted and documented** in M1.

### B.8 Plan

Add row **R-126**:

> WP-1.26 split: 1.26a is core and native; 1.26b is the Worker and conformance.
>
> - Namespace charges live in `qs` rows per window.
> - Rollup timer kind 5 every R = 60 s writes the coordinator aggregates `qc` / `qt` and the local view `qv`.
> - Overshoot is at most 2R of the other shards' admitted writes.
> - Default namespace cap: equal to the per-signer limits in Multi; off in Single.
> - On Single-addressing D34 the per-signer quota is per (signer, branch), which is accepted.
> - The rollup adds one coordinator write per active shard per R, which lowers the R-76 ceiling by about a third;
>   folding the rollup into lease renewal is a later optimisation.

Also update:
- the registry: split 1.26 into 1.26a and 1.26b (1.26b depends on 1.26a and 1.8, and adds the `workers` gate);
- the Worker conformance note in `scripts/vcs-worker-conformance.sh`. It keeps skipping until 1.26b.

## C. Your decisions

- The value of the R constant, within 30–120 s.
- Codec layout.
- Test organisation.

## D. Escalate (stop and report) if

- The admitted-write batch doesn't fit `MAX_BATCH_OPS` with the new ops.
- Production changes exceed 1,500 lines.

## Tests (required)

1. Exhaustion is exact within one shard.
2. The aggregate converges across N shards.
3. A simulation shows overshoot within the bound.
4. Re-fires are idempotent, including a crash between the coordinator apply and the local view write.
5. Window rollover works, and the partition shrinks after load.
6. A namespace-cap denial allocates nothing.
7. Replays are not charged.
8. Single and coordinator paths are exact.
9. The op-budget const assert holds.
10. No timers are left after idle.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance --all-features`
- the wasm32 check
