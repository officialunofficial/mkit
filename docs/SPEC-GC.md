# SPEC-GC — garbage-collection retention roots & recovery

Status: **draft**. Part 1 (retention roots + live closure) is implemented
in `mkit-core` (`ops::gc`). Part 2 (recovery log + retention policy) and
the `mkit gc` command itself are not yet shipped. Tracks #260 → #233.

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
| Stash | `.mkit/stash` | each entry's `commit_hash` + `parent_hash` |
| Reset / op backup | `.mkit/ORIG_HEAD` | the saved pre-op HEAD |
| Merge in progress | `.mkit/MERGE_HEAD` (+`ORIG_HEAD`) | `merge_head`, `orig_head` |
| Cherry-pick in progress | `.mkit/CHERRY_PICK_HEAD` (+`ORIG_HEAD`) | `cherry_pick_head`, `orig_head` |
| Rebase in progress | `.mkit/rebase-apply/{orig-head,onto,todo,done}` | `orig_head`, `onto`, every `todo` + `done` commit |
| Conflict sidecar | `.mkit/mkit-conflicts` | each record's `base`/`ours`/`theirs` blob (when present) |
| Attestations | `.mkit/attestations/<commit-hex>/` | each attested commit (dir name) |

The live keep-set is the reachable closure over those roots:
`ops::gc::live_objects(store, mkit_dir)` = `reachable_closure(store,
collect_roots(...))`. Walk semantics match `reachable_objects`
(commits/remixes → tree + parents, trees → entries, chunked-blobs →
chunks, tags → target; blobs/deltas are leaves), capped at
`MAX_REACHABLE`.

## Fail-closed requirement

`collect_roots` returns an error if **any** source cannot be read, and
`gc` MUST abort on that error rather than prune against a partial root
set. The same applies to a root or referenced object missing from the
store during the closure walk (`StoreError::ObjectNotFound` propagates):
gc must not delete based on an incomplete walk.

## Recovery gap (Part 2 — not yet implemented)

The per-branch history journal (`.mkit/history/…`, the MMR behind
`reflog`) stores **only opaque digests**; its leaves cannot be decoded
back to commit hashes. Therefore commits superseded by `commit --amend`,
`reset`, or `rebase` are **not** recoverable from any on-disk source once
they fall out of the root set above — and they are intentionally **not**
roots here (that is exactly what gc reclaims).

Before `mkit gc` may delete such commits, Part 2 must add:

1. a **recovery log** that records superseded tips (hash + timestamp)
   when a history-rewriting command moves a branch, so they can be
   surfaced and restored; and
2. a **retention / grace policy** (e.g. keep entries younger than a grace
   window, and keep the last N superseded tips) so a recent mistake is
   recoverable.

Until Part 2 lands, gc must treat the recovery-log entries (once they
exist) as additional roots, and document that pre-recovery-log superseded
commits are unrecoverable. See #260.
