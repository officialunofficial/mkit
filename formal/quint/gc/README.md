# Garbage collection and the recovery log (MKIT-21)

A Quint model of `mkit gc` as specified in
[SPEC-GC](../../../docs/specs/SPEC-GC.md). It covers retention roots, the
fail-closed requirement, recording to and expiring the recovery log, the
expire → collect roots → prune sequence and the object grace window. Locking
follows [SPEC-CONCURRENCY §3.1, §3.2 and §4](../../../docs/specs/SPEC-CONCURRENCY.md).
The model is aligned with `rust/crates/mkit-core/src/ops/gc.rs`
(`collect_roots`, `live_objects`, `run_gc`), `ops/recovery.rs` (`record`,
`expire`, `is_retained`) and `rust/crates/mkit-cli/src/commands/gc.rs`.

| File | Contents |
|---|---|
| `gc.qnt` | `gcCore` is the state machine. `gc` is the conforming instance (supported deployment) with scenario tests. `gcGrace0` is the same instance with `--grace-secs 0`. `gcPush*` add a concurrent file-transport push. `mut*` are mutants. |
| `check.sh` | Reruns every check. `APALACHE=1` adds the bounded Apalache runs. |

## Model

- **gc** runs through `GcLock`, `GcExpireRead`, `GcExpireWrite`, `GcMark`,
  `GcSweep(o)` (one listed object per step) and `GcDone`. `GcLock` takes
  `worktrees.lock` plus every `worktree.lock` (§4), then reads `now`. Expire is
  split into a read step and a rewrite step because `expire` reads, filters and
  then atomically rewrites the log. The log is rewritten only when the snapshot
  dropped entries. `GcMark` runs the strict `collect_roots` plus the closure: if
  any root source is unreadable, or an object in the roots' closure is
  missing from the store (`ObjectNotFound`), gc aborts before deleting
  anything. Each sweep
  step reads that object's mtime and deletes it if it is unreachable and
  `now - mtime >= GRACE`.
- **Producer** (amend/reset/rebase on `main`) runs through `ProdBegin`,
  `ProdRecord` and `ProdMove` under its tree's `worktree.lock`. It writes the new
  tip's objects, records the superseded tip (`record` is durable, so this is one
  step), then moves the ref.
- **Push** through the file transport runs `PushWrite` (all of the tip's
  objects) then `PushPublish`. It takes none of gc's locks (§3.1). A push that
  misses its timing assumption runs `PushAbort` instead.
- **Environment:** `Tick(d)`, and `Corrupt(s)`/`Repair(s)` for the root sources
  `main`, `tag`, `pushed` and `rlog`.
- **Objects:** there are 7 objects in a fixed DAG. Writes are content-addressed.
  A dedup hit leaves the existing mtime unchanged, as in `ObjectStore::write`
  (`final_path.exists()`), unless `FRESHEN` is set.

**Bounds:** 7 objects, 3 refs plus the recovery log, 1 producer, 1 push, clock
0..6, `GRACE = 2` (0 in `gcGrace0`), `RETAIN = 2`, `KEEP_LAST = 1`, at most 3
recovery records. `quint run` uses 20000 samples of up to 30 steps with seed
0x1. Apalache checks safe instances to length 10 and mutants/canaries at the
length of their shortest counterexample. With 5 objects present, one tick plus a whole gc run up to its last sweep
takes 10 steps. Longer runs that interleave several producer or push steps
with a gc run are covered only by `quint run`.

## Invariants

| Invariant | Meaning (spec) | Non-vacuity (checker falsifies) |
|---|---|---|
| `NoLivePruned` | gc never deletes an object that is reachable from the true root set when it is deleted (SPEC-GC Invariants, row 1) | `mutLenient` |
| `NoDangling` | everything reachable from a ref or a recovery entry is present | `gcPushRaw`, `gcPushFast`, `gcPushRawFreshen` |
| `UnreadableAborts` | nothing is deleted after a mark that saw an unreadable source or a missing closure object (fail-closed) | `mutLenient`; the missing-object branch is pinned by `fastPushDedupLossTest` (the next gc after the dangling publish aborts) |
| `SupersededRetained` | a record inside the policy (age ≤ RETAIN, or the newest) is in the log and its closure is present (Recovery log) | `mutNoRecord`, `mutNoKeepLast`, `mutNoLock` (a `record` append is lost to an `expire` rewrite) |
| `LockExclusion` | a producer mid-rewrite never overlaps an active gc run (§3.2 lock superset) | `mutNoLock` |

`Safety` is the conjunction of these invariants. `mutNoLockGrace0`
(`--grace-secs 0` with gc not excluding the producer) violates `NoDangling`
and `NoLivePruned`, so the grace-0 result depends on the §3.2/§4 lock set.
`MAX_REACHABLE` truncation and crash durability of `record` are not modelled.

**Canaries (each must be violated):** `CanaryNoPrune`, `CanaryNoAbort`,
`CanaryNoExpire`, `CanaryNoPrunedRecord` (an expired record's commit really gets
pruned), `CanaryNoPushPublished`, `CanaryNoPruneDuringPush`.

## GC vs. concurrent push (SPEC-CONCURRENCY §3.1)

| Instance | Push assumption | Result |
|---|---|---|
| `gcPushRaw`, `gcPushRawFreshen` | none | `NoDangling` and `NoLivePruned` are violated. The push writes at t, gc runs with `now ≥ t + GRACE`, and the push then publishes. |
| `gcPushFast` | publish < GRACE after the push's write | Violated, even with a zero-duration push. The object is an old orphan, so the push's write is a dedup hit that keeps mtime 0 (`fastPushDedupLossTest`). |
| `gcPushFastFreshen` | as above, with mtime refreshed on dedup | Safe |
| `gcPushBounded` | at publish time T, every object o the tip reaches is present with `T - mtime(o) < GRACE` (on-disk mtime) | Safe |

**The exact safety condition:** a publish at instant T is safe iff every
object it makes reachable, and that is not otherwise live, has on-disk mtime
`> T - GRACE`. `gcPushBounded` checks sufficiency of the slightly stronger
form over every object the tip reaches. Necessity is shown by the
`gcPushFast`/`gcPushRaw*` counterexamples; the "not otherwise live" refinement
is argued by hand. This works because gc's `now` is read before its mark, so any
gc whose mark precedes the publish has `now ≤ T`. The push's duration bounds
this only when a dedup hit refreshes mtime. `--grace-secs 0` is never safe
against a concurrent push.

## Commands

```
./check.sh              # quint typecheck/test/run (~5 min)
APALACHE=1 ./check.sh   # + Apalache 0.47.2 (1.5 to 7.5 h, depending on load)
```
