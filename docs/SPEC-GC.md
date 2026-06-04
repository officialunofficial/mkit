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

**Status:** the log format, store, retention policy, and gc-root
integration are implemented (Part 2a). The **producers** — recording at
the `commit --amend` / `reset` / `rebase` rewrite sites — are Part 2b.
Until producers land the log is empty, so pre-producer superseded commits
remain unrecoverable; `mkit gc` (#233) stays sequenced behind Part 2b.
