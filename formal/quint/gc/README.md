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
| `check.sh` | Reruns every check. `APALACHE=1` adds the bounded Apalache runs; `TLC=1` adds exhaustive TLC runs. |

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
- **Objects:** there are 8 objects in a fixed DAG. Objects 5 and 7 start as old
  orphans; 5 is in the push's closure, 7 is garbage nobody writes, so a gc can
  delete something while a push is in flight. Writes are content-addressed.
  A dedup hit leaves the existing mtime unchanged, as in `ObjectStore::write`
  (`final_path.exists()`), unless `FRESHEN` is set.

**Bounds:** 8 objects, 3 refs plus the recovery log, 1 producer, 1 push, clock
0..6, `GRACE = 2` (0 in `gcGrace0`), `RETAIN = 2`, `KEEP_LAST = 1`, at most 3
recovery records. The instances are finite, so TLC explores **every**
reachable state of them (`TLC=1`; see Results). `quint run` uses 20000 samples
of up to 30 steps with seed 0x1. Apalache checks safe instances to length 10
and mutants/canaries at the length of their shortest counterexample.

The TLC runs use a `VIEW` that drops only state no guard and no `Safety`
conjunct reads (counters, `lastAction`, gc scratch outside the phase that
reads it, mtimes of absent objects, `pushStart` outside `"wrote"`). This is
sound for `Safety` and its conjuncts, not for the canaries, which are checked
with `quint run` and Apalache.

## Invariants

| Invariant | Meaning (spec) | Non-vacuity (checker falsifies) |
|---|---|---|
| `NoLivePruned` | gc never deletes an object that is reachable from the true root set when it is deleted (SPEC-GC Invariants, row 1) | `mutLenient` |
| `NoDangling` | everything reachable from a ref or a recovery entry is present | `gcPushRaw`, `gcPushFast`, `gcPushRawFreshen`, `mutBoundedLax` |
| `UnreadableAborts` | nothing is deleted after a mark that saw an unreadable source or a missing closure object (fail-closed) | `mutLenient`; the missing-object branch is pinned by `fastPushDedupLossTest` (the next gc after the dangling publish aborts) |
| `SupersededRetained` | a record inside the policy (age ≤ RETAIN, or the newest) is in the log and its closure is present (Recovery log) | `mutNoRecord`, `mutNoKeepLast`, `mutNoLock` (a `record` append is lost to an `expire` rewrite) |
| `LockExclusion` | a producer mid-rewrite never overlaps an active gc run (§3.2 lock superset) | `mutNoLock` |

`Safety` is the conjunction of these invariants. `mutNoLockGrace0`
(`--grace-secs 0` with gc not excluding the producer) violates `NoDangling`
and `NoLivePruned`, so the grace-0 result depends on the §3.2/§4 lock set.
`MAX_REACHABLE` truncation and crash durability of `record` are not modelled.

**Canaries (each must be violated):** `CanaryNoPrune`, `CanaryNoAbort`,
`CanaryNoExpire`, `CanaryNoPrunedRecord` (an expired record's commit really gets
pruned), `CanaryNoPushPublished`, `CanaryNoPruneDuringPush`,
`CanaryNoPrunedPushPublished` (gc deletes an object while a push is in flight
and that push then publishes; this is the interleaving the safe push modes
must survive, pinned by `prunedDuringSafePushTest`).

## GC vs. concurrent push (SPEC-CONCURRENCY §3.1)

| Instance | Push assumption | Result |
|---|---|---|
| `gcPushRaw`, `gcPushRawFreshen` | none | `NoDangling` and `NoLivePruned` are violated. The push writes at t, gc runs with `now ≥ t + GRACE`, and the push then publishes. |
| `gcPushFast` | publish < GRACE after the push's write | Violated, even with a zero-duration push. The object is an old orphan, so the push's write is a dedup hit that keeps mtime 0 (`fastPushDedupLossTest`). |
| `gcPushFastFreshen` | as above, with mtime refreshed on dedup | Safe |
| `gcPushBounded` | at publish time T, every object o the tip makes newly reachable (not already live) is present with `T - mtime(o) < GRACE` (on-disk mtime) | Safe |
| `mutBoundedLax` | the same with `T - mtime(o) <= GRACE` | Violated (`boundaryLossTest`, 8 steps): the bound is tight |

**The exact safety condition:** a publish at instant T is safe iff every
object it makes newly reachable (not otherwise live) is present with on-disk
mtime `> T - GRACE`. `gcPushBounded` checks sufficiency of exactly this form
(earlier revisions required it of every object in the tip's closure; since
the shared history 0..3 has mtime 0 that only allowed publishing before any
gc could delete anything, so the safe result never exercised a prune during
the push). Necessity is shown by counterexamples, not proved in general:
`mutBoundedLax` (the boundary), `gcPushFast` and `gcPushRaw*`. The condition works because gc's `now` is read before its mark, so any
gc whose mark precedes the publish has `now ≤ T`, and the other roots are
frozen during a gc run (producers are excluded, expire precedes mark). The push's duration bounds
this only when a dedup hit refreshes mtime. `--grace-secs 0` is never safe
against a concurrent push.

## Results

`quint test` (8 tests) and all `quint run` checks come out as expected.

Exhaustive TLC (tla2tools 2026.09.23, `TLC=1`), no state left on the queue:

| Check | Result |
|---|---|
| `gc::Safety` | ok, 19,621,072 distinct states, depth 44 |
| `gcGrace0::Safety` | ok, 19,679,216 distinct states, depth 44 |
| `gcPushBounded::Safety`, ≤ 2 producer rewrites, no corrupt source | ok, 9,525,536 distinct states, depth 42 |
| `gcPushFastFreshen::Safety`, same constraint | ok, 11,886,758 distinct states, depth 31 |
| `mutLenient::NoLivePruned`, `mutNoLock::SupersededRetained`, `mutBoundedLax::NoDangling`, `gcPushFast::NoDangling` | violated |

Unconstrained, the push instances were OOM-killed at about 40M states.

## Commands

```
./check.sh              # quint typecheck/test/run (~5 min)
APALACHE=1 ./check.sh   # + Apalache 0.47.2 (1.5 to 7.5 h, depending on load)
TLC=1 ./check.sh        # + exhaustive TLC (hours; ~6 GB heap per run)
```
