# Garbage collection, the recovery log and the server GC primitive (formal verification effort)

Two Quint models.

- `gc.qnt` models `mkit gc` as specified in
  [SPEC-GC](../../../docs/specs/SPEC-GC.md): retention roots, the fail-closed
  requirement, recording to and expiring the recovery log, the expire →
  collect roots → prune sequence, the object grace window, and writers that
  do not hold gc's locks ("Concurrent writers and the grace window"). Locking
  follows [SPEC-CONCURRENCY §3.1, §3.2 and §4](../../../docs/specs/SPEC-CONCURRENCY.md).
  It is aligned with `rust/crates/mkit-core/src/ops/gc.rs` (`collect_roots`,
  `live_objects`, `run_gc`), `ops/recovery.rs` (`record`, `expire`,
  `is_retained`), `store.rs` (`ObjectStore::write`, `BulkWriter::write`,
  `object_metadata`, `remove_object`) and `rust/crates/mkit-cli/src/commands/gc.rs`,
  `tag.rs`, `attest.rs`.
- `contentIndex.qnt` models the server-side GC primitive,
  `rust/crates/mkit-server/src/store/content_index.rs` ("GC ordering (R-64)",
  steps 1 to 4), against an upload of the same blob
  (`mkit-server/src/fs/blob.rs`). There is no normative text for it yet
  (SPEC-SERVER's server-GC section is WP-5.1a) and nothing calls
  `collectable`/`commit_collect` yet (the driver is WP-5.3a/b), so this model
  states the contract a future caller must meet rather than checking a
  shipped path.

| File | Contents |
|---|---|
| `gc.qnt` | `gcCore` is the state machine. `gc` is the conforming instance (supported deployment) with scenario tests. `gcGrace0` is the same with `--grace-secs 0`. `gcPush*` add a concurrent writer outside gc's lock set. `gcTag*` add a later root publish under the lock. `mut*` are mutants. |
| `contentIndex.qnt` | `ciCore` is the state machine. `ciHoldFirst` and `ciShortTtlGrace` are safe orderings; `ciBytesFirst`, `ciShortTtl` are unsafe caller orderings; `ciMut*` are mutants of the primitive. |
| `check.sh` | Reruns every check with its expected outcome. `APALACHE=1` adds the bounded Apalache runs, `TLC=1` the exhaustive TLC runs. `ONLY=gc`/`ONLY=ci` picks a model, `SEL=regex` picks checks. |

## Tool pins (verification toolchain)

| Tool | Version | Use |
|---|---|---|
| Quint | 0.32.0 | typecheck, `quint test`, `quint run` (Rust backend); `quint compile --target tlaplus`, which transpiles with its bundled Apalache 0.56.1 (transpiler only, no checking) |
| Apalache | 0.62.2 | `apalache-mc check` run directly on the compiled TLA+, one named invariant per run. `quint verify` is not used for results (its bundled Apalache predates 0.62.2's FoldSet fixes; the models use `fold`) |
| TLC | `tlc2.TLC` from the Apalache 0.62.2 jar (reports `TLC2 Version 2026.09.26.233837`; jar sha256 `079b6c23…efaa8`) | exhaustive runs, one named invariant per run |
| Java | OpenJDK 21.0.12.1 (Homebrew `openjdk@21`) | Apalache, TLC, and `quint compile` |

Host for the timings below: macOS arm64, 15 cores, 24 GB, shared with five
other verification jobs (load average 9 to 15). TLC ran with `-Xmx4g` and 2
workers, Apalache with `-Xmx4g`; one JVM at a time.

`check.sh` finds the tools at `${FV_HOME:-$HOME/.local/share/mkit-fv}/apalache-0.62.2/`
(`APALACHE_MC`, `TLA2TOOLS` override), and Java at `$JAVA_HOME`, else
`/usr/libexec/java_home -v 21`, else Homebrew's `openjdk@21`.

## gc.qnt

### Model

- **gc** runs through `GcLock`, `GcExpireRead`, `GcExpireWrite`, `GcMark`,
  `GcSweep(o)` (one listed object per step) and `GcDone`. `GcLock` takes
  `worktrees.lock` plus every `worktree.lock` (SPEC-CONCURRENCY §4), then reads
  `now` (commands/gc.rs reads the clock after the locks and before expire, as
  SPEC-GC now requires). Expire is split into a read step and a rewrite step
  because `expire` reads, filters and then atomically rewrites the log; the
  log is rewritten only when the snapshot dropped entries (`pruned == 0`).
  `is_retained` is "age ≤ grace or among the last `keep_last`", as in
  recovery.rs. `GcMark` runs the strict `collect_roots` plus the closure: an
  unreadable root source, or a closure object missing from the store
  (`ObjectNotFound`), aborts before anything is deleted. Each sweep step reads
  that object's mtime and deletes it if it is unreachable and
  `now - mtime >= GRACE`.
- **Producer** (amend/reset/rebase on `main`): `ProdBegin`, `ProdRecord`,
  `ProdMove` under its tree's `worktree.lock`. It writes the new tip's
  objects, records the superseded tip (`record` is durable, so one step),
  then moves the ref.
- **Writer outside gc's lock set** (`PushWrite` then `PushPublish`, or
  `PushAbort`): writes all of the tip's objects into the store gc sweeps and
  later publishes a root. It takes none of gc's locks. On this branch that
  writer is the import phase of `mkit git import`/`fetch`/`pull`
  (`BulkWriter` under `git-<remote>.lock` only). See "Which writers race gc"
  below for why file-transport and served pushes are not.
- **Later root publish under the lock** (`TagPublish`, `TAG_CHECK`): one step
  under this tree's `worktree.lock` that re-verifies its target and publishes
  a root, as `tag <name> <hash>`, `attest` and `update-ref` do (#267).
- **Environment:** `Tick(d)`; `Corrupt(s)`/`Repair(s)` for the root sources
  `main`, `tag`, `pushed` and `rlog`.
- **Objects:** 8 objects in a fixed DAG. Objects 5 and 7 start as old orphans;
  5 is in the writer's closure, 7 is garbage nobody writes, so a gc can
  delete something while a writer is in flight. Writes are content-addressed:
  a dedup hit leaves the existing mtime unchanged unless `FRESHEN` is set.
  The model's writer is the one outside gc's lock set, git import.
  `FRESHEN = true` is the implementation since MKIT-55: `BulkWriter::write`
  (byte-equal existing file), the writer git import uses, sets the existing
  file's mtime to now on a dedup hit, and rewrites the object if it cannot.
  `FRESHEN = false` is the implementation before MKIT-55. `ObjectStore::write`
  and `WriteBatch` do not refresh mtime; their callers hold `worktree.lock`,
  which gc also takes, so they are not the model's writer.

**Bounds:** 8 objects, 3 refs plus the recovery log, 1 producer, 1 writer,
1 tag publisher, clock 0..6, `GRACE = 2` (0 in `gcGrace0`), `RETAIN = 2`,
`KEEP_LAST = 1`, at most 3 recovery records. `quint run`: 20000 samples of up
to 30 steps, seed 0x1. Apalache: safe instances to length 8, mutants and
canaries at (or above) the length of their shortest counterexample. TLC: every
reachable state of the instance under the stated `CONSTRAINT` (see Results).

The TLC runs use a `VIEW` that drops only state no guard and no `Safety` or
`Progress` conjunct reads (counters, `lastAction`, gc scratch outside the
phase that reads it, mtimes of absent objects, `pushStart` outside
`"wrote"`). This is sound for `Safety`, `Progress` and their conjuncts, not for
the canaries, which are checked with `quint run` and Apalache.

### Invariants

| Invariant | Meaning (spec) | Non-vacuity (checker falsifies) |
|---|---|---|
| `NoLivePruned` | gc never deletes an object reachable from the true root set when it is deleted (SPEC-GC Invariants, row 1) | `mutLenient`, `mutNoLockGrace0`, `gcPushRaw*`, `gcPushFast` |
| `NoDangling` | everything reachable from a ref or a recovery entry is present | `gcPushRaw`, `gcPushFast`, `gcPushRawFreshen`, `mutBoundedLax`, `gcTagRoot`, `mutNoLockGrace0` |
| `UnreadableAborts` | nothing is deleted after a mark that saw an unreadable source or a missing closure object (Fail-closed requirement) | `mutLenient`; the missing-object branch is pinned by `fastPushDedupLossTest` (the next gc aborts on the dangling ref) |
| `SupersededRetained` | a record inside the policy (age ≤ RETAIN, or the newest) is in the log with its closure present (Recovery log) | `mutNoRecord`, `mutNoKeepLast`, `mutNoLock` (a `record` append lost to an `expire` rewrite) |
| `LockExclusion` | a producer mid-rewrite never overlaps an active gc run (SPEC-CONCURRENCY §3.2) | `mutNoLock` |
| `NoLeakedLock` (progress) | a held worktree lock always belongs to an active gc or producer | `mutLeakLock` (the expire-abort path keeps the locks) |
| `NoStuckPush` (progress) | an in-flight writer can always publish or abort | `mutStuckPush` (a fast writer with no abort) |

`Safety` is the conjunction of the first five, `Progress` of the last two, and
`All = Safety and Progress`. Progress is stated as invariants because TLC's
deadlock check (`-deadlock`/`CHECK_DEADLOCK FALSE`) would be vacuous here in
any case: `Corrupt`/`Repair` are always enabled. gc and producer steps are
guarded by their phase alone, so the non-trivial stuck states are a leaked
lock and a writer with no enabled step.

**Canaries (each must be violated):** `CanaryNoPrune`, `CanaryNoAbort`,
`CanaryNoExpire`, `CanaryNoPrunedRecord`, `CanaryNoPushPublished`,
`CanaryNoPruneDuringPush`, `CanaryNoPrunedPushPublished` (gc deletes an
object while a writer is in flight and that writer then publishes; pinned by
`prunedDuringSafePushTest`), `CanaryNoYoungOverPruned` (gc keeps a young
object and deletes an old one in its closure), `CanaryNoTagPublished`.

### GC vs. a writer outside gc's lock set (SPEC-GC "Concurrent writers and the grace window")

| Instance | Writer assumption | Result |
|---|---|---|
| `gcPushRaw`, `gcPushRawFreshen` | none | `NoDangling` and `NoLivePruned` violated: the writer writes at t, gc runs with `now ≥ t + GRACE`, the writer then publishes |
| `gcPushFast` | publish < GRACE after the write | Violated even with a zero-duration writer: 5 is an old orphan, the write is a dedup hit that keeps mtime 0 (`fastPushDedupLossTest`). The implementation before MKIT-55 |
| `gcPushFastFreshen` | as above, mtime refreshed on dedup | Safe. The implementation since MKIT-55, except gc's mtime-read-then-unlink window (below) |
| `gcPushBounded` | at publish time T, every object the tip makes newly reachable is present with `T - mtime < GRACE` (on-disk mtime) | Safe |
| `mutBoundedLax` | the same with `T - mtime <= GRACE` | Violated (`boundaryLossTest`): the bound is tight |

**Safety condition.** A publish at instant T by a writer outside gc's lock
set cannot lose an object iff every object it makes newly reachable (not
reachable from roots that stay unchanged during the gc run) is present at T
with on-disk `mtime > T - GRACE`. `gcPushBounded` checks sufficiency of
exactly this form; necessity is shown by counterexamples (`mutBoundedLax` at
the boundary, `gcPushFast`, `gcPushRaw*`), not proved in general. It works
because gc reads `now` before its mark, so a gc whose mark precedes the
publish has `now ≤ T`, and the other roots are frozen during a gc run
(producers are excluded, expire precedes mark). The writer's duration bounds
this only when a dedup hit refreshes mtime (`gcPushFastFreshen`), which the
object writers do since MKIT-55. The model's `GcSweep(o)` reads o's mtime and
deletes o in one step; `run_gc` reads `object_metadata` and later calls
`remove_object`, so a refresh that lands between the two still loses the
object. That window is not modelled, and closing it needs a gc-side change.
`--grace-secs 0` is never safe against such a writer. This is the condition
SPEC-GC now states as normative.

### Later root publish under the lock (`gcTagRoot`, `gcTagClosure`)

The grace window is per object, not per closure. A young unreachable object
survives a gc while an old object in its closure is deleted (Git, by
contrast, keeps objects reachable from recent unreachable objects).
`CanaryNoYoungOverPruned` shows the state is reachable in the supported
deployment: a writer that wrote a tip and its closure and never published
(a crash, an error, or the abandoned import in `PushAbort`) leaves the young
tip 6 over the old dedup-hit 5. A later `mkit tag <name> <hash>` (or `attest`,
`update-ref`) takes its lock, so no gc runs concurrently, but re-verifies only
the target itself (`store.contains`). `gcTagRoot` publishes a root whose
closure is incomplete (`tagAfterGraceTest`, `NoDangling` violated). Checking
the closure under the lock (`gcTagClosure`) is safe: the lock excludes gc, so
a closure present under the lock stays present until the publish.

### Which writers race gc (server-era review)

- **git-bridge import:** `mkit git import`/`fetch`/`pull` writes loose objects
  through `BulkWriter` and publishes tags and remote-tracking refs under
  `git-<remote>.lock` only (git_import.rs), outside gc's lock set.
  Since MKIT-55 `BulkWriter::write` refreshes the mtime of a byte-equal
  existing object, so for the objects it writes the importer is
  `gcPushFastFreshen` (`gcPushFast` before MKIT-55; `gcPushRaw*` if its
  write-to-publish window can exceed GRACE). The model's writer writes every
  object of its tip. The importer does not: an object its map cache already
  translated is not written at all and keeps its old mtime, which is the
  `gcPushFast` behaviour for that object. SPEC-GC keeps the operator rule
  against running gc concurrently with a git import for this reason.
- **File-transport and served pushes do not race `mkit gc` on this branch.**
  `FileTransport` and `mkit serve`/`mkit-server` (`FsBlobStore`,
  `FsLayoutStore`) store `<root>/packs/<64-hex>` and `<root>/refs/...`.
  `mkit gc` sweeps only loose objects in `<root>/.mkit/objects/<2>/<62>`
  (`iter_object_hashes`) and collects roots only under `<root>/.mkit`
  (`RepoLayout` has no bare form). The sets are disjoint, so gc cannot delete
  a pushed object, and a pushed ref is not one of its roots. SPEC-GC's
  "Concurrent writers" section and SPEC-CONCURRENCY §3.1 now say so.
- **`mkit serve`'s startup sweep** (`FsBlobStore::sweep_stale_uploads`, under
  an exclusive non-blocking `serve.lock`, SPEC-CONCURRENCY §2, §3.1) removes
  only regular files named exactly `.<64-hex>.tmp.<pid>.<seq>` in `packs/`
  with mtime at least 1 h old. It never removes a blob or a ref, so it cannot
  make a published object dangle. Its only effect on a concurrent writer is
  on liveness: a `FileTransport` upload (no `serve.lock`) whose temp file is
  older than 1 h at its rename gets `ENOENT` and fails before it publishes
  anything. `mkit serve`'s doc says `FileTransport` writes "each temp file in
  one go" (true: `write_atomic` is create, write_all, fsync, rename), so this
  needs a writer stalled for an hour inside that sequence. Not modelled.
- **`pack::rewrite_excluding`** (WP-5.7a) is a pure function over pack bytes
  with no I/O and no callers outside tests. It cannot delete anything; the
  takedown flow that would publish its output is WP-5.7b. Not modelled.
- **`ContentIndex` GC (R-64)** can delete bytes a concurrent upload relies on,
  depending on the caller's ordering: modelled in `contentIndex.qnt` below.

## contentIndex.qnt

One object, one upload, one GC. The upload takes a hold (`add_hold`, refused
while `deleting`), writes or dedups the bytes (`AlreadyPresent`/`Created`),
applies the ref-shard write with `NotAfter = hold time + APPLY_WINDOW` or gives
up and releases the hold; the relay records the holder row and releases the
hold within `RELAY_LAG` of the apply (an assumption on time). GC runs
`collectable` (no holders, no live hold, `now - changed >= GRACE`),
`commit_collect` (guarded by `Equals` on the state row), the blob delete and
`finish_collect`; it may crash after the mark and resume at the delete. Every
index mutation bumps `seq`, sets `changed = max(changed, now)` and prunes an
expired hold, as `mutate` does. Bounds: clock 0..7, `GRACE = 2`, `TTL = 3`,
`APPLY_WINDOW = 1`, `RELAY_LAG = 1` unless stated.

| Invariant | Meaning | Falsified by |
|---|---|---|
| `NoReachableLoss` | a published object's bytes are present | `ciBytesFirst`, `ciShortTtl`, `ciMutNoDeletingGuard` |
| `NoLiveDelete` | GC never deletes bytes that are published, held or in a holder row | `ciMutNoSeqGuard` |
| `DeletingClears` (progress) | a `deleting` mark always has a GC step towards clearing it | `ciMutNoResume` |
| `UploadCanStep` (progress) | an in-flight upload has a step, or waits only on a `deleting` mark | `ciMutNoGiveUp` |

Canaries (violated): `CanaryNoDelete`, `CanaryNoPublish`, `CanaryNoHolder`,
`CanaryNoDeleteThenPublish` (GC deletes the old blob and the upload still
publishes, after its refused hold is retried: `gcFirstTest`).

**Contract for a caller of the R-64 primitive** (checked, bounded):

1. Take the hold **before** relying on the bytes, that is before the
   `AlreadyPresent` dedup or the blob write. With the bytes first
   (`ciBytesFirst`, `dedupThenCollectTest`), a whole GC cycle (plan, mark,
   delete, clear) fits between the dedup and the hold, the hold then succeeds,
   and the apply publishes a lost object. `add_hold`'s doc says only "taken
   before the ref-shard apply", which permits this order.
2. From the hold, GC is kept off the object until `max(hold expiry, last
   change + GRACE)`; the apply is a ref-shard write and does not touch the
   state row. So `APPLY_WINDOW + RELAY_LAG < max(TTL, GRACE)` is needed:
   `ciShortTtl` (TTL = GRACE = 2 = window + lag) loses the object;
   `ciShortTtlGrace` (GRACE = 3) and `ciHoldFirst` (TTL = 3) are safe. The
   `add_hold` doc states the TTL half ("TTL must exceed MAX_APPLY_WINDOW plus
   the relay-lag bound").
3. The primitive's own guards are load-bearing: without the `deleting` refusal
   (`ciMutNoDeletingGuard`) or the `Equals` guard on the plan
   (`ciMutNoSeqGuard`) the object is lost even with the right ordering.

The R-64 driver's root re-check and relay watermark wait are not modelled
(not implemented yet).

## Results

All results below are from the final state of `gc.qnt`, `contentIndex.qnt`
and `check.sh` on 2026-09-26. Times are wall clock on the shared host.

**quint** (`./check.sh`): all 13 `quint test` scenarios pass and all 48
`quint run` checks come out as expected (gc model 2 min 23 s, ContentIndex
model under 30 s).

**TLC** (`TLC=1`), exhaustive, no state left on the queue, `-Xmx4g`, 2 workers:

| Check | Constraint | Result |
|---|---|---|
| `gc::All` | none | ok, 19,621,072 distinct states, 700 s |
| `gcGrace0::All` | none | ok, 19,679,216 distinct states, 631 s |
| `gcTagClosure::All` | ≤ 2 producer rewrites, no corrupt source | ok, 13,480,960 distinct states, 512 s |
| `gcPushBounded::All` | same | ok, 9,525,536 distinct states, 387 s |
| `gcPushFastFreshen::All` | same | ok, 11,886,758 distinct states, 473 s |
| `mutLenient::NoLivePruned`, `mutLenient::UnreadableAborts`, `mutNoLock::SupersededRetained`, `mutNoLock::LockExclusion`, `mutNoRecord::SupersededRetained`, `mutNoKeepLast::SupersededRetained`, `mutLeakLock::NoLeakedLock` | none | each violated, naming that invariant (5 to 18 s) |
| `mutStuckPush::NoStuckPush`, `mutBoundedLax::NoDangling`, `gcPushFast::NoDangling`, `gcTagRoot::NoDangling` | ≤ 2 rewrites, no corrupt source | each violated (5 to 16 s) |
| `ciHoldFirst::All`, `ciShortTtlGrace::All` | none | ok, 2,868 and 1,958 distinct states, 4 s each |
| `ciBytesFirst::NoReachableLoss`, `ciShortTtl::NoReachableLoss`, `ciMutNoDeletingGuard::NoReachableLoss`, `ciMutNoSeqGuard::NoLiveDelete`, `ciMutNoResume::DeletingClears`, `ciMutNoGiveUp::UploadCanStep` | none | each violated (4 s) |

The state counts for `gc`, `gcGrace0`, `gcPushBounded` and
`gcPushFastFreshen` equal the earlier tla2tools runs: the new actor and
invariants are disabled or read-only in those instances. The constraint on
the writer instances is what keeps them inside 4 GB; unconstrained they were
OOM-killed at about 40M states. Bounded ≠ proved: the constrained runs cover
every state with at most two producer rewrites and no corrupt source.

**Apalache 0.62.2** (`APALACHE=1`), `-Xmx4g`:

| Check | Length | Result |
|---|---|---|
| `gc::All`, `gcGrace0::All` | 8 | ok, 124 s, 116 s |
| `gcTagClosure::All` | 8 | ok, 551 s |
| `gcPushFastFreshen::All` | 8 | ok, 355 s |
| `gcPushBounded::All` | 8 | ok, 1,043 s |
| `gc::CanaryNoPrune` / `CanaryNoExpire` | 6 / 10 | violated, 15 s / 72 s |
| `gcTagClosure::CanaryNoYoungOverPruned` | 11 | violated, 22 s |
| `gcPushFast::NoDangling`, `gcPushRawFreshen::NoDangling`, `gcPushFast::NoLivePruned` | 8 | violated, 197 s, 185 s, 51 s |
| `gcPushBounded::CanaryNoPruneDuringPush` / `CanaryNoPrunedPushPublished` | 8 / 10 | violated, 25 s / 163 s |
| `gcPushFastFreshen::CanaryNoPrunedPushPublished` | 9 | violated, 36 s |
| `mutNoLock::LockExclusion` / `SupersededRetained` | 4 / 12 | violated, 7 s / 1,250 s |
| `mutNoLockGrace0::NoDangling` | 8 | violated, 91 s |
| `mutLenient::NoLivePruned` / `UnreadableAborts` | 7 | violated, 11 s each |
| `mutBoundedLax::NoDangling` | 8 | violated, 379 s |
| `mutNoRecord::SupersededRetained`, `mutNoKeepLast::SupersededRetained` | 3, 7 | violated, 7 s, 16 s |
| `mutLeakLock::NoLeakedLock`, `mutStuckPush::NoStuckPush` | 3, 4 | violated, 8 s, 7 s |
| `ciHoldFirst::All`, `ciShortTtlGrace::All` | 16 | ok, 33 s, 36 s |
| every `ci*` mutant and unsafe ordering above, `ciHoldFirst::CanaryNoDeleteThenPublish` | 10, 12 | violated, 5 to 9 s |

**MKIT-55 re-run (2026-09-27)**, after `BulkWriter` began refreshing
mtime on a dedup hit (the model is unchanged; this confirms the instance the
code now matches): `ONLY=gc SEL='^gcPushFast' APALACHE=1 ./check.sh` exits 0.
All 8 gc `quint test` scenarios pass; `quint run` `gcPushFastFreshen::All` and
`::NoLivePruned` ok, `gcPushFast::NoDangling`/`::NoLivePruned` and the
`gcPushFastFreshen` canaries `CanaryNoPruneDuringPush`/`CanaryNoPrunedPushPublished`
violated as expected; Apalache `gcPushFastFreshen::All` length 8 ok (450 s),
`gcPushFast::NoDangling` / `::NoLivePruned` length 8 violated (174 s / 67 s),
`gcPushFastFreshen::CanaryNoPrunedPushPublished` length 9 violated (41 s).
Bounded, not proved.

`gcTagRoot::NoDangling` is not run under Apalache: its shortest
counterexample is 16 steps (gc must sweep all seven objects and finish before
the tag can take the lock), and a length-12 run found nothing in 19 minutes,
as expected. TLC, `quint run` and `tagAfterGraceTest` cover it. The safe gc
instances were checked to length 10 with Apalache 0.47.2 in the previous
revision; with 0.62.2 they are checked to length 8 to stay under 30 minutes
per check on the shared host (`GC_DEPTH=10` restores the old bound).

## Commands

```
./check.sh                  # quint typecheck/test/run, both models (~3 min)
APALACHE=1 ./check.sh       # + Apalache 0.62.2 (~2 h on the shared host)
TLC=1 ./check.sh            # + TLC from the Apalache jar (~50 min)
ONLY=ci TLC=1 APALACHE=1 ./check.sh   # ContentIndex model only (~2 min)
SEL='^gc::All$' TLC=1 ONLY=gc ./check.sh   # one check
```

## Not modelled

`MAX_REACHABLE` truncation (same abort as `ObjectNotFound`), crash
durability of `record`, several producers in different linked worktrees
appending to the shared recovery log concurrently (each holds only its own
tree's lock; `O_APPEND` appends are not modelled), the R-64 driver, relay
watermark and root re-check, and the blocklist.
