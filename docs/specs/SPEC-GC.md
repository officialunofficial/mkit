---
spec: SPEC-GC
version: 1
status: stable-normative
audience: implementers of gc/recovery and reviewers of object pruning
---

# SPEC-GC &mdash; garbage-collection retention roots and recovery

Status: **Normative** for mkit v1; **implemented** (see below). See
SPEC-CONVENTIONS §2 for the maturity/bindingness status vocabulary this
frontmatter uses. Concurrency: see SPEC-CONCURRENCY (this document no
longer states its own lock model). The recovery model (#260) &mdash; Part 1 (retention
roots + live closure, `ops::gc`), Part 2a (recovery log + retention
policy, `ops::recovery`), Part 2b (producers &mdash; amend/reset/rebase record
the superseded tip) &mdash; **and the `mkit gc` command itself (#233)** are all
shipped. `mkit gc` runs `recovery::expire` → `ops::gc::run_gc`
(`live_objects` then prune `store ∖ live`, skipping objects within the
grace window) under the locks SPEC-CONCURRENCY §4 assigns to `gc`
(the worktree registry lock, then every registered tree's per-tree
lock &mdash; no separate lock guards the recovery-log expire step; the
per-tree locks gc already holds are what serializes it, see §3.2).

## Why this spec exists

mkit's object store is append-only and never prunes, so unreachable
objects accumulate (notably the commits superseded by `commit --amend`,
`reset`, and `rebase`). `mkit gc` (#233) reclaims them. Pruning is
safe **only** against a complete, exact retention root set: anything
reachable from a root is live; everything else is reclaimable. An
incomplete root set means deleting a live object &mdash; silent corruption.
This spec pins that root set so gc has one normative definition to honor.

## Retention roots

`ops::gc::collect_roots(mkit_dir)` returns the complete set. A root is an
object hash that must be kept along with its full reachable closure. The
all-zero hash (an unset ref / `ORIG_HEAD`) is excluded.

| Source | On-disk | Roots contributed |
|--------|---------|-------------------|
| HEAD | `.mkit/HEAD` | current tip (covers a detached HEAD) |
| Branches | `.mkit/refs/heads/*` | each branch tip |
| Tags | `.mkit/refs/tags/*` | each tag target |
| Remote-tracking | `.mkit/refs/remotes/<remote>/*` | each remote ref |
| Staging index | `.mkit/index` | each entry's `object_hash` (staged-but-uncommitted content) |
| Stash | `.mkit/stash` | each entry's `commit_hash` + `parent_hash` |
| Reset/op backup | `.mkit/ORIG_HEAD` | the saved pre-op HEAD |
| Merge in progress | `.mkit/MERGE_HEAD` (+`ORIG_HEAD`) | `merge_head`, `orig_head` |
| Cherry-pick in progress | `.mkit/CHERRY_PICK_HEAD` (+`ORIG_HEAD`) | `cherry_pick_head`, `orig_head` |
| Revert in progress | `.mkit/REVERT_HEAD` (+`ORIG_HEAD`) | `revert_head`, `orig_head` |
| Rebase in progress | `.mkit/rebase-apply/{orig-head,onto,todo,done}` | `orig_head`, `onto`, every `todo` + `done` commit |
| Conflict sidecar | `.mkit/mkit-conflicts` and `.mkit/rebase-apply/mkit-conflicts` | each record's `base`/`ours`/`theirs` blob (when present) |
| Attestations | `.mkit/attestations/<commit-hex>/` | each attested commit (dir name) |
| Pending history publication | `.mkit/history-v1/branches/<ref-key>/transaction` | previous and target ref values; strict parse even without `history-mmr` |
| Recovery log | `.mkit/recovery-log` | each superseded commit (until expired) |

A present empty, corrupt, oversized or unsupported staging index MUST abort GC
before sweeping. An absent index alone means no staging roots. Only the current
index format is supported (SPEC-INDEX).

The live keep-set is the reachable closure over those roots:
`ops::gc::live_objects(store, mkit_dir)` = `reachable_closure(store,
collect_roots(...))`. Walk semantics match `reachable_objects`
(commits/remixes → tree + parents, trees → entries, chunked-blobs →
chunks, tags → target; blobs/deltas are leaves), capped at
`MAX_REACHABLE`.

## Fail-closed requirement

`collect_roots` returns an error if **any** source cannot be read, and
`gc` MUST abort on that error rather than prune against a partial root
set. In particular:

- Refs are walked **strictly** (not via the lenient `refs::list_*`): an
  unreadable file, undecodable content, or a ref tree deeper than the
  walk depth cap is an error, never a silent skip. (Dot-prefixed
  atomic-write temp files are ignored.)
- A root or referenced object missing from the store during the closure
  walk (`StoreError::ObjectNotFound`) propagates.
- If the closure hits the [`MAX_REACHABLE`] cap, `live_objects` returns
  `GcRootsError::Truncated` &mdash; beyond the cap the "unreachable" verdict is
  unsound, so gc must abort rather than prune. (The push path, by
  contrast, tolerates cap truncation and splits the push.)

## Recovery log (Part 2)

Commits superseded by `commit --amend`, `reset`, or `rebase` remain recoverable
through the **recovery log** (`.mkit/recovery-log`, `ops::recovery`). Each rewrite
appends the superseded tip (`<unix_ts>\t<op>\t<64-hex>\t<branch>`), every
logged hash is a GC root (clock-free, strict/fail-closed parse), and
`recovery::expire(now, policy)` drops entries past the retention policy
(default: younger than 90 days **or** among the most recent 50) so they
stop pinning objects. A gc run expires first, then computes roots.

`record` is durable &mdash; it `fsync`s the log file and its parent directory
before returning &mdash; so a crash cannot leave a ref rewrite persisted while
its recovery entry is lost. `record` and `expire` are **not** internally
synchronized: `ops::recovery`'s own concurrency note requires callers to
hold "the repo lock" &mdash; in practice each producer's per-tree
`worktree.lock` (see SPEC-CONCURRENCY §3.2). gc's "expire → collect
roots → prune" sequence runs under the full lock set SPEC-CONCURRENCY §4
assigns to `gc` &mdash; every registered tree's `worktree.lock`, a superset of
any single producer's one tree &mdash; so a producer append can never race an
`expire` rewrite and vanish, without either side needing a distinct,
dedicated recovery-log lock.

**Status:** complete. The recovery log (Part 2a) and its producers
(Part 2b) are implemented &mdash; `commit --amend`, `reset`, and `rebase` each
record the superseded tip (op tokens `amend`/`reset`/`rebase`) before
moving the ref, and `stash pop` records the popped commit (op token
`stash-pop`) before restoring the worktree and dropping the manifest
entry &mdash; each per the lock set SPEC-CONCURRENCY §4 assigns to that
command &mdash; and the **`mkit gc` command** (#233) consumes them: under
gc's lock set (SPEC-CONCURRENCY §4) it expires the recovery log,
computes `live_objects`, then prunes `store ∖ live`, keeping unreachable
objects younger than the grace window (default 14 days; `--grace-secs 0`
prunes all, `--dry-run` previews).

Versioned ancestry snapshots (`history-v1`) are described in SPEC-HISTORY-PROOF.
Archived generation snapshots are evidence, not additional retention roots.
Only unfinished publication intents add roots; this lets recovery rebuild the
complete target ancestry even when its ref had not yet become visible.

## Concurrent writers and the grace window

gc's lock set (SPEC-CONCURRENCY §4) excludes every writer that holds a
`worktree.lock` or `worktrees.lock` for the span from its first object
write to its ref, index or recovery-log publication. Such a writer
publishes either before gc collects its roots or after gc's sweep ends.
Writers outside that lock set are not excluded, and for them the grace
window is the only protection. The one such writer into the object store
gc sweeps is the import phase of `mkit git import`/`fetch`/`pull`, which
writes objects and then tags and remote-tracking refs under
`git-<remote>.lock` only (SPEC-CONCURRENCY §4).

A push through the file transport (`mkit push mkit+file://...`) or one
received by `mkit serve` or `mkit-server` is not such a writer. It stores
packs as `<root>/packs/<hex>` and refs as `<root>/<name>` under the
transport root, while gc sweeps only loose objects in
`<common_dir>/objects` and takes roots only from `<common_dir>`. The two
are disjoint, so gc cannot delete a pushed object, and a pushed ref is not
a gc root.

`mkit gc` reads its clock once, as `now`, after it takes its locks and
before it expires the recovery log and computes `live_objects`. Its sweep
deletes an unreachable object when `now - mtime >= grace`, where `mtime`
is the object file's on-disk modification time, and keeps any object
whose `mtime` cannot be read (`ops::gc::run_gc`). An implementation MUST
read `now` no later than the start of the mark; the safety condition
below depends on it.

**Hazard: an object whose `mtime` is not refreshed.** Object writes
are content-addressed and idempotent. When the object's file already
exists (for `BulkWriter::write`, with the same bytes),
`ObjectStore::write`, `WriteBatch` and `BulkWriter::write` return without
rewriting it. `BulkWriter::write`, the writer git import uses, first sets
the object's `mtime` to the current time, and rewrites the object if it
cannot (MKIT-55). `ObjectStore::write` and `WriteBatch` leave `mtime`
alone: their callers hold `worktree.lock`, which gc also takes, so they
never race a sweep. An object that a
writer does not write at all because it already has it (a git import
skips every object its map cache already translated) is left with its
old `mtime`. So when a concurrent writer's closure includes an object that
already exists as an old unreachable object (such as a commit superseded
by a rewrite whose recovery-log entry has expired, then pushed again, or
a blob identical to one in such a commit) and the writer does not write
it, this interleaving loses it however quickly the writer runs:

1. The writer skips the object, so its `mtime` stays old.
2. gc reads `now` and computes its live set; the object is unreachable.
3. gc's sweep sees `now - mtime >= grace` and deletes the object.
4. The writer publishes a ref whose closure contains the object.

The published ref now dangles. The next `mkit gc` aborts with
`ObjectNotFound` ("Fail-closed requirement"), so no further object is
lost, but the deleted object is not recovered. The Quint model in
`formal/quint/gc` reproduces this as the `gcPushFast` instance (a write
that keeps the old `mtime`) and the `fastPushDedupLossTest` scenario;
`gcPushFastFreshen`, a write that refreshes it as `BulkWriter` now
does, is safe.

**Safety condition (normative).** Let a writer that does not hold gc's
locks publish a ref at instant `T`. The publication cannot lose an object
to any gc run, whether that run's mark precedes `T` or follows it, when
every object the publication makes newly reachable (not reachable from
roots that stay unchanged during the gc run) is present at `T` with

```text
T - mtime < grace
```

using the object file's on-disk `mtime`. This holds because a gc whose
mark precedes the publication read `now <= T`, so it keeps every such
object, and a gc whose mark follows the publication sees the new ref as a
root. The bound is tight: with `T - mtime <= grace` instead, a gc can
delete an object at the boundary (the model's `mutBoundedLax` mutant and
`boundaryLossTest`). Consequences:

- A writer outside gc's lock set MUST NOT rely on the duration of its own
  write-to-publish window to meet this condition, because a skipped
  object keeps its old `mtime`. The condition is met by
  a write-to-publish window shorter than `grace` only when every object
  the writer relies on had its `mtime` set within that window.
- `--grace-secs 0` is never safe against a concurrent writer outside gc's
  lock set.
- `BulkWriter`, the only object writer outside gc's lock set, refreshes
  `mtime` on a dedup hit, so an object a git import writes meets the
  condition when its write-to-publish window is
  shorter than `grace`, unless the refresh lands after gc's sweep read
  the old `mtime` and before it unlinks the object (`ops::gc::run_gc`
  does not do the two atomically). A git import does not write objects its map cache
  already covers, so it does not meet the condition for such an object.
  Operators MUST NOT run `mkit gc` concurrently with git imports into the
  same repository unless the condition is otherwise guaranteed.

## Invariants

| Invariant | Enforced by |
|---|---|
| No live object is ever pruned | prune set is `store ∖ live_objects`, the reachable closure over the complete `collect_roots` set ("Retention roots") |
| gc never prunes against a partial root set | `collect_roots` errors if **any** source is unreadable &mdash; strict ref walk, no lenient skips &mdash; and gc MUST abort on that error ("Fail-closed requirement") |
| gc never prunes on an unsound "unreachable" verdict | a closure hitting `MAX_REACHABLE` returns `GcRootsError::Truncated`; gc aborts ("Fail-closed requirement") |
| A missing root or referenced object aborts gc | `StoreError::ObjectNotFound` propagates from the closure walk ("Fail-closed requirement") |
| A superseded tip stays recoverable until the retention policy expires it | amend/reset/rebase/stash-pop append to `.mkit/recovery-log` before moving the ref or dropping the stash entry; every logged hash is a root ("Recovery log") |
| A crash cannot persist a ref rewrite while losing its recovery entry | `record` fsyncs the log file and its parent directory before returning ("Recovery log") |
| A producer append cannot race an `expire` rewrite and vanish | callers hold the repo lock; gc runs expire → collect roots → prune under the same lock ("Recovery log") |
| Recently-orphaned objects survive a gc run | unreachable objects younger than the grace window (default 14 days) are skipped ("Status") |
| A writer outside gc's lock set never publishes a dangling ref | only when every object its publication makes newly reachable has an on-disk `mtime` within `grace` of the publication; a dedup hit refreshes `mtime`, but an object a git import skips via its map cache keeps its old `mtime`, so this is not guaranteed today ("Concurrent writers and the grace window") |
| An unset ref never pins an object | the all-zero hash is excluded from roots ("Retention roots") |

The load-bearing rule is the fail-closed requirement: every guarantee
above degrades to "gc aborts" rather than "gc guesses" whenever any
input cannot be read completely.
