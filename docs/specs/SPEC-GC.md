---
spec: SPEC-GC
version: 1
status: stable-normative
audience: implementers of gc / recovery and reviewers of object pruning
---

# SPEC-GC — garbage-collection retention roots & recovery

Status: **Normative** for mkit v1; **implemented** (see below). See
SPEC-CONVENTIONS §2 for the maturity/bindingness status vocabulary this
frontmatter uses. Concurrency: see SPEC-CONCURRENCY (this document no
longer states its own lock model). The recovery model (#260) — Part 1 (retention
roots + live closure, `ops::gc`), Part 2a (recovery log + retention
policy, `ops::recovery`), Part 2b (producers — amend/reset/rebase record
the superseded tip) — **and the `mkit gc` command itself (#233)** are all
shipped. `mkit gc` runs `recovery::expire` → `ops::gc::run_gc`
(`live_objects` then prune `store ∖ live`, skipping objects within the
grace window) under the locks SPEC-CONCURRENCY §4 assigns to `gc`
(the worktree registry lock, then every registered tree's per-tree lock,
then the ref-history lock for the recovery-log expire step).

## Why this spec exists

mkit's object store is append-only and never prunes, so unreachable
objects accumulate (notably the commits superseded by `commit --amend`,
`reset`, and `rebase`). `mkit gc` (#233) will reclaim them. Pruning is
safe **only** against a complete, exact retention root set: anything
reachable from a root is live; everything else is reclaimable. An
incomplete root set means deleting a live object — silent corruption.
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
| Reset / op backup | `.mkit/ORIG_HEAD` | the saved pre-op HEAD |
| Merge in progress | `.mkit/MERGE_HEAD` (+`ORIG_HEAD`) | `merge_head`, `orig_head` |
| Cherry-pick in progress | `.mkit/CHERRY_PICK_HEAD` (+`ORIG_HEAD`) | `cherry_pick_head`, `orig_head` |
| Revert in progress | `.mkit/REVERT_HEAD` (+`ORIG_HEAD`) | `revert_head`, `orig_head` |
| Rebase in progress | `.mkit/rebase-apply/{orig-head,onto,todo,done}` | `orig_head`, `onto`, every `todo` + `done` commit |
| Conflict sidecar | `.mkit/mkit-conflicts` and `.mkit/rebase-apply/mkit-conflicts` | each record's `base`/`ours`/`theirs` blob (when present) |
| Attestations | `.mkit/attestations/<commit-hex>/` | each attested commit (dir name) |
| Recovery log | `.mkit/recovery-log` | each superseded commit (until expired) |

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
  `GcRootsError::Truncated` — beyond the cap the "unreachable" verdict is
  unsound, so gc must abort rather than prune. (The push path, by
  contrast, tolerates cap truncation and splits the push.)

## Recovery log (Part 2)

The per-branch history journal (`.mkit/history/…`, the MMR behind
`reflog`) stores **only opaque digests**; its leaves cannot be decoded
back to commit hashes. So commits superseded by `commit --amend`,
`reset`, or `rebase` cannot be recovered from it. The **recovery log**
(`.mkit/recovery-log`, `ops::recovery`) closes that gap: each rewrite
appends the superseded tip (`<unix_ts>\t<op>\t<64-hex>\t<branch>`), every
logged hash is a GC root (clock-free, strict/fail-closed parse), and
`recovery::expire(now, policy)` drops entries past the retention policy
(default: younger than 90 days **or** among the most recent 50) so they
stop pinning objects. A gc run expires first, then computes roots.

`record` is durable — it `fsync`s the log file and its parent directory
before returning — so a crash cannot leave a ref rewrite persisted while
its recovery entry is lost. `record` and `expire` are **not** internally
synchronized: callers MUST hold `refs-history.lock` (see SPEC-CONCURRENCY
§3.2 — the recovery log is common-dir state shared by every linked
worktree, so a per-tree lock cannot serialize it), and gc MUST run its
"expire → collect roots → prune" sequence under the full lock set
SPEC-CONCURRENCY §4 assigns to `gc`, so a producer append cannot race an
`expire` rewrite and vanish.

**Status:** complete. The recovery log (Part 2a) and its producers
(Part 2b) are implemented — `commit --amend`, `reset`, and `rebase` each
record the superseded tip (op tokens `amend`/`reset`/`rebase`) before
moving the ref, and `stash pop` records the popped commit (op token
`stash-pop`) before restoring the worktree and dropping the manifest
entry — each per the lock set SPEC-CONCURRENCY §4 assigns to that
command — and the **`mkit gc` command** (#233) consumes them: under
gc's lock set (SPEC-CONCURRENCY §4) it expires the recovery log,
computes `live_objects`, then prunes `store ∖ live`, keeping unreachable
objects younger than the grace window (default 14 days; `--grace-secs 0`
prunes all, `--dry-run` previews).

## Invariants

| Invariant | Enforced by |
|---|---|
| No live object is ever pruned | prune set is `store ∖ live_objects`, the reachable closure over the complete `collect_roots` set ("Retention roots") |
| gc never prunes against a partial root set | `collect_roots` errors if **any** source is unreadable — strict ref walk, no lenient skips — and gc MUST abort on that error ("Fail-closed requirement") |
| gc never prunes on an unsound "unreachable" verdict | a closure hitting `MAX_REACHABLE` returns `GcRootsError::Truncated`; gc aborts ("Fail-closed requirement") |
| A missing root or referenced object aborts gc | `StoreError::ObjectNotFound` propagates from the closure walk ("Fail-closed requirement") |
| A superseded tip stays recoverable until the retention policy expires it | amend/reset/rebase/stash-pop append to `.mkit/recovery-log` before moving the ref or dropping the stash entry; every logged hash is a root ("Recovery log") |
| A crash cannot persist a ref rewrite while losing its recovery entry | `record` fsyncs the log file and its parent directory before returning ("Recovery log") |
| A producer append cannot race an `expire` rewrite and vanish | callers hold the repo lock; gc runs expire → collect roots → prune under the same lock ("Recovery log") |
| Recently-orphaned objects survive a gc run | unreachable objects younger than the grace window (default 14 days) are skipped ("Status") |
| An unset ref never pins an object | the all-zero hash is excluded from roots ("Retention roots") |

The load-bearing rule is the fail-closed requirement: every guarantee
above degrades to "gc aborts" rather than "gc guesses" whenever any
input cannot be read completely.
