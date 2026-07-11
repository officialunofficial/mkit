---
spec: SPEC-WORKTREE
version: 1
status: draft-normative
audience: implementers of repository layout, discovery, and gc
---

# SPEC-WORKTREE — linked working trees

Status: **Normative** for the state/locking/discovery model specified
here; **Draft** because §5's out-of-scope surface (`worktree
move`/`lock`/`repair`) is not yet covered by this document.
Scope: the common-dir / per-worktree state split, the linked-tree
pointer-file format, the `worktrees/` registry, repository discovery,
cross-worktree locking, and gc root-collection semantics. Issue #493.

Reference implementation: `mkit-core/src/layout.rs` (the
`RepoLayout` type is the single path-resolution authority; every
repo-state API takes it).

---

## 1. State classification

Every piece of repository state under `.mkit/` belongs to exactly one
of two classes:

| Class | Contents |
|---|---|
| **common dir** (shared by all trees) | `objects/`, `format`, `refs/` (`heads`, `tags`, `remotes`), `shallow`, `config`, `keys/`, `history/`, `recovery-log`, `attestations/`, `applied-packs/`, `git/`, `sparse/`, `pack-shards/`, `worktrees/`, `refs-history.lock`, `worktrees.lock` |
| **worktree state dir** (private to one tree) | `HEAD`, `index`, `ORIG_HEAD`, `MERGE_HEAD`/`MERGE_MSG`, `CHERRY_PICK_HEAD`/`CHERRY_PICK_MSG`, `REVERT_HEAD`/`REVERT_MSG`, `mkit-conflicts`, `MKIT_OP_RESULT`, `rebase-apply/`, `bisect`, `stash`, `sparse-checkout`, `worktree.lock` |

In the classic single-worktree layout both directories are the same
`<root>/.mkit/`; the two-directory model is byte-identical there.

Divergences from git, both deliberate:

- **`shallow` is shared** (git: per-repo too, listed here because it is
  per-worktree-adjacent in some git docs): it constrains the one object
  graph every tree reads.
- **The stash is per-worktree.** git's stash is a shared ref
  (`refs/stash`); mkit's is a worktree-state manifest, and #493
  specifies tree-local stash semantics (`stash` in a linked tree never
  touches a sibling's entries).

Relative signing-key paths in config (`.mkit/keys/…`) resolve their
`.mkit/` prefix against the **common dir**, so every tree signs with
the one shared repo key store.

## 2. On-disk model

```
<main>/.mkit/                       # common dir
  worktrees/<id>/                   # one per linked tree (the registry)
    commondir                       # path to the common dir
    mkitdir                         # abs path of the tree's pointer file
    HEAD, index, ORIG_HEAD, ...     # that tree's per-worktree state
<linked-tree>/.mkit                 # pointer FILE (not a directory)
```

### 2.1 Pointer file

A linked tree's `.mkit` is a regular file containing exactly one line:

```
mkitdir: <path>\n
```

- `<path>` names the tree's state dir; absolute, or relative to the
  linked tree root.
- UTF-8, LF-terminated (a trailing CR before the LF is tolerated and
  stripped), no second line, at most **4096 bytes**
  (`MAX_POINTER_FILE_BYTES`).
- MUST be a **regular file**. Readers MUST reject a symlinked pointer
  (likewise `commondir` and the back-pointer): the size cap is checked
  against the file itself, and following a hostile link (e.g.
  `.mkit -> /dev/zero` in an untarred tree) would turn discovery into
  an unbounded read.
- Writers MUST produce the canonical form (prefix `mkitdir: `, one
  trailing `\n`); `layout::write_pointer_file` is the single writer.

### 2.2 State-dir metadata files

- `commondir` — path from the state dir back to the common dir;
  absolute or relative to the state dir. `worktree add` writes
  `../..\n`. When ABSENT, readers MUST default to `../..` (the layout
  `worktree add` produces). Same single-line/size rules as the pointer
  file.
- `mkitdir` — the absolute path of the linked tree's pointer file (the
  back-pointer `worktree prune` verifies). Same single-line/size rules.

### 2.3 Worktree ids

The registry directory name `<id>` MUST match: non-empty, ≤ 255 bytes,
ASCII alphanumeric plus `.`, `_`, `-`, and not `.` or `..`
(`validate_worktree_id`). Ids derive from the target path's basename,
sanitized (invalid bytes → `-`) and uniquified git-style
(`name`, `name-1`, `name-2`, …).

## 3. Discovery

Given a working directory `W` (mkit treats the invocation directory as
the worktree root; there is no upward search):

1. If `W/.mkit` is a **directory** or **absent** → the single-worktree
   layout (`common dir = state dir = W/.mkit`). Absence is not a
   discovery error; "not a repository" surfaces from the store open,
   unchanged from pre-worktree behavior.
2. If `W/.mkit` is a **file** → parse it as a pointer file. Then:
   - the state dir is the pointer target (resolved against `W` if
     relative); it MUST exist and is canonicalized;
   - the common dir comes from `<state>/commondir` (default `../..`),
     resolved against the state dir, canonicalized; it MUST exist.
3. **Every failure in step 2 is fatal** (typed `DiscoverError`):
   malformed/oversized/non-UTF-8/multi-line pointer, dangling state
   dir, unreadable or dangling `commondir`. A broken linked tree MUST
   NOT silently degrade to operating on some other directory.

A registry entry is **prunable** when its back-pointer is missing or
unreadable, its tree is gone, or the tree's pointer no longer names
that state dir (a moved or re-created tree MUST NOT be claimed by a
stale entry). `worktree list` reports prunable entries; only
`worktree prune` deletes them.

## 4. Semantics

### 4.1 Sharing

Linked trees share the object store and every common-dir source of
truth: refs, config, keys, history MMR, recovery log, attestations,
transport caches. An object written from any tree is immediately
visible to all; a ref moved from any tree moves for all.

### 4.2 Single writer per branch

A branch may be checked out in **at most one** worktree. `worktree
add`, `checkout`/`switch` (including `-b`/`-B`), `branch -d`/`-D`, and
`branch -m` MUST refuse (naming the holding tree) when the branch is
checked out in another tree. Rationale: branch moves flow through the
history-MMR ref-write path (SPEC-HISTORY-PROOF), which assumes one
writer per branch. Detached HEADs are unconstrained.

The guard reads sibling HEADs via the registry and MUST fail closed if
the registry cannot be enumerated.

### 4.3 Locks

This document originates the `worktree.lock`/`worktrees.lock` primitives
and their per-command holder details below; the total lock order across
*all* mkit locks (including `refs-history.lock` and the file-transport's
`refs/.lock`), and the enumeration of every writer, is owned by
SPEC-CONCURRENCY — see that document for the authoritative order. This
section states only the two locks this document defines and how the
commands specified here use them.

| Lock | Location | Guards |
|---|---|---|
| `worktree.lock` | each tree's state dir | that tree's worktree/index read-modify-write |
| `worktrees.lock` | common dir | registry mutations (`worktree add`/`remove`/`prune`) |

Per-command holders:

- gc takes the registry lock first (freezing the worktree set — a
  concurrent `worktree add` cannot register a tree between root
  collection and the sweep), then every tree's `worktree.lock` in
  deterministic order — main tree first, then registry ids ascending —
  and holds them all through the sweep.
- `checkout`/`switch` hold the registry lock across the
  branch-checked-out-elsewhere guard and the HEAD write, making
  §4.2's check-then-write atomic against racing checkouts and
  `worktree add`s; `branch -d`/`-m` do the same around their guard +
  ref mutation; `worktree add` re-verifies the guard after acquiring
  the registry lock.
- `worktree remove` holds the registry lock plus the condemned tree's
  own `worktree.lock` before deleting; `worktree prune` snapshots the
  registry only AFTER acquiring the registry lock (a pre-lock snapshot
  could condemn a mid-`add` entry).

### 4.4 gc root collection

Shared sources are read once: the strict refs walk, attestations, and
the recovery log. Per-tree sources are unioned over the main tree and
**every** registry entry whose state dir exists — including prunable
entries (until `worktree prune` reaps a state dir, whatever it pins
stays pinned): HEAD, staging index, `ORIG_HEAD`, in-progress
merge/cherry-pick/revert/rebase state, conflict sidecars, and the
tree-local stash.

Fail closed: a registry enumeration error or an unreadable sibling
source aborts collection; gc never prunes on a partial view. The
applied-packs record is a redownload-avoidance cache and MUST NOT be a
root source (#409); gc may delete it freely.

### 4.5 `worktree add` write ordering (crash safety)

1. state dir fully populated (`commondir`, `mkitdir` back-pointer,
   `HEAD`) — before any pointer to it exists;
2. branch ref creation (new-branch form), through the history-recording
   ref path;
3. the tree: pointer file, then materialization via the shared
   checkout/restore path.

A crash between (1) and (3) leaves a prunable registry orphan, never a
live tree pointing at half-built state. `worktree remove` deletes the
tree before the state dir for the same reason.

## 5. Out of scope (v1)

`worktree move` / `lock` / `repair` (follow-ups), submodule interplay
(submodules are a non-goal), and sharing a repository between mkit
versions with and without worktree support while linked trees exist.

## 6. Test anchors

- `mkit-core/src/layout.rs` unit tests: accessor/classification
  goldens, discovery fail-closed matrix, pointer-file golden bytes,
  id grammar.
- `mkit-cli/tests/layout_phase0_pin.rs`: the single-worktree `.mkit`
  shape is a compatibility surface; it must never drift.
- `mkit-cli/tests/linked_worktree_discovery.rs`,
  `worktree_command.rs`, `worktree_gc_cross_tree.rs`: shared-store,
  tree-locality, guard, gc-survival, and lock-contention behavior
  through the real binary.
