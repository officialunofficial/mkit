---
spec: SPEC-CONCURRENCY
version: 1
status: stable-normative
audience: implementers of any command that mutates refs, the history MMR, the recovery log, worktree state, or runs gc
---

# SPEC-CONCURRENCY — repository-wide lock order and writer enumeration

Status: **Normative** for mkit v1.
Scope: the total lock order across every mkit-owned lock, and the
enumeration of every writer that must participate in it. This document
does not introduce a new lock; every lock it names already exists,
specified at its point of use (SPEC-WORKTREE §4.3, SPEC-REFS §5.1,
SPEC-HISTORY-PROOF §4.3, SPEC-GC "Recovery log"). It exists because those
four documents each described a different, partial slice of the same
model, and two of the corpus's known concurrency bugs live exactly in the
seams between them. SPEC-REFS, SPEC-GC, SPEC-WORKTREE, and
SPEC-HISTORY-PROOF each defer their own "Locks"/"Concurrency" section to
this document rather than restating it.

See RFC 2119/8174 boilerplate at SPEC-CONVENTIONS §1.

---

## 1. Lock inventory

| Lock | Location | Guards | Specified at |
|---|---|---|---|
| `worktree.lock` | each tree's state dir | that tree's worktree/index read-modify-write | SPEC-WORKTREE §4.3 |
| `worktrees.lock` | common dir | registry mutations (`worktree add`/`remove`/`prune`) | SPEC-WORKTREE §4.3 |
| `refs-history.lock` | common dir | ref-write + history-MMR append critical section, **and** (as of this document) recovery-log record/expire and the v0.1.x→v0.2.x rebuild shim — see §3 | SPEC-HISTORY-PROOF §4.3 |
| `refs/.lock` | common dir, file-transport only | the file transport backend's own CAS read-check-write for a single ref update | SPEC-REFS §5.1 |

`refs/.lock` is scoped to the file transport's own conditional-write
implementation (`O_EXCL` create); it is not, by itself, part of the
worktree/history critical section. §3 states the rule that keeps it from
being a second, uncoordinated entry point into ref mutation.

## 2. Global lock order

A process that acquires more than one of the locks above MUST acquire
them in this order, and MUST NOT hold a lock further left in this list
while blocking to acquire one further right without releasing first
(no lock inversion):

```
worktrees.lock  ≺  per-tree worktree.lock(s)  ≺  refs-history.lock  ≺  refs/.lock
```

- `worktrees.lock` before any `worktree.lock`: freezes the registered-tree
  set before touching any individual tree, so a concurrent `worktree add`
  cannot register between an enumeration and a per-tree operation.
- Per-tree `worktree.lock`(s) before `refs-history.lock`: a command that
  needs both (e.g. `commit --amend`, which touches the worktree/index and
  then rewrites a ref + appends to the recovery log) takes its own tree's
  lock first.
- `refs-history.lock` before `refs/.lock`: see §3 — this is the fix for a
  previously-undocumented gap, not a restatement of prior text.

## 3. Closing the two known gaps

Two real races have been found in this area (mtime-based data races, not
hypothetical): a `branch -m` racing a concurrent `commit` on the same
branch, and the history-MMR v0.1.x→v0.2.x backfill shim double-running
under concurrent first-writes. Both traced to the same root cause — a
writer touching shared, common-dir state without holding the lock that
guards it — which this section closes normatively.

### 3.1 The file transport MUST NOT be a second, uncoordinated ref-mutation path

`refs/.lock` alone serializes the file transport's own reads and writes
against *itself*, but a repository can be operated on locally (via the
`worktrees.lock`/`worktree.lock`/`refs-history.lock` path) while
simultaneously serving as the target of a `mkit+file://` remote push (via
the `refs/.lock` path) — for example, a bare mirror that is also opened
directly for maintenance. As specified prior to this document, those two
paths do not coordinate at all.

**Fix, normative as of this document:** any process driving a ref mutation
through the file transport backend against a directory that is also a
live worktree's common dir MUST additionally acquire `refs-history.lock`
around its CAS operation, nested as the innermost lock per §2's order
(i.e. `refs-history.lock` held, then `refs/.lock` taken and released for
the single conditional write). A file-transport target that is guaranteed
never to be concurrently opened as a live worktree (a pure mirror with no
local commands ever run against it) MAY skip this — but a conforming
implementation MUST NOT assume that without a way to tell the two cases
apart; the default MUST be to take both locks.

*Implementation status: this is a specification fix, not yet reflected in
`mkit-transport-file`. Tracked as a follow-up code change — the file
transport's ref-write path does not currently acquire `refs-history.lock`.*

### 3.2 Recovery-log mutation MUST be guarded by `refs-history.lock`, not a per-tree lock

The recovery log (`.mkit/recovery-log`) is common-dir state — shared by
every linked worktree — but its producers (`commit --amend`, `reset`,
`rebase`, `stash pop`) have been described as running "under the repo
lock (`worktree.lock`)," which is now a **per-tree** lock under the
multi-worktree model (SPEC-WORKTREE §4.3). Two linked trees performing an
amend/reset each hold their own, different `worktree.lock`, and both can
append to the one shared recovery-log file at the same time.

**Fix, normative as of this document:** every `record`/`expire` call
against `.mkit/recovery-log` MUST be performed while holding
`refs-history.lock`, not (only) the calling tree's `worktree.lock`. This
is a natural fit rather than a new lock, since every recovery-log producer
is already rewriting a ref through the history-aware ref-write path that
takes `refs-history.lock` for the same operation (SPEC-HISTORY-PROOF §4.3)
— the fix folds recovery-log mutation into that same critical section
instead of introducing a fifth lock.

*Implementation status: follow-up code change against `ops::recovery` and
its callers.*

### 3.3 The v0.1.x→v0.2.x rebuild shim MUST run inside the lock, with a re-check

SPEC-HISTORY-PROOF §4.5's rebuild shim currently runs *before*
`refs-history.lock` is acquired ("before delegating to
`update_ref_with_history`"), so two processes can both observe an empty
journal and both backfill, producing duplicate leaves.

**Fix, normative as of this document:** the emptiness check that triggers
the shim MUST be re-performed after `refs-history.lock` is acquired (i.e.
inside the critical section SPEC-HISTORY-PROOF §4.3 already defines), and
the backfill MUST only proceed if the journal is *still* empty under the
lock. A process that loses the race (finds a non-empty journal on
re-check) MUST skip the backfill and proceed directly to its own append.

*Implementation status: follow-up code change against
`write_ref_recording_history`.*

## 4. Writer enumeration

Every command that mutates ref, history, recovery-log, or worktree-registry
state, and the locks it MUST take, per §2's order:

| Writer | Locks taken |
|---|---|
| `commit` (incl. `--amend`), `reset`, `rebase`, `stash pop` | own tree's `worktree.lock` → `refs-history.lock` (recovery-log append folds into the same critical section, §3.2) |
| `checkout`/`switch` (incl. `-b`/`-B`) | `worktrees.lock` (branch-elsewhere guard + HEAD write) → own tree's `worktree.lock` |
| `branch -d`/`-D`/`-m` | `worktrees.lock` (branch-elsewhere guard) → `refs-history.lock` (ref mutation) |
| `worktree add` | `worktrees.lock` (guard re-verify + registration) → new tree's `worktree.lock` → `refs-history.lock` (new-branch form only) |
| `worktree remove` | `worktrees.lock` → condemned tree's `worktree.lock` |
| `worktree prune` | `worktrees.lock` (registry snapshotted only after acquiring) |
| `gc` | `worktrees.lock` → every registered tree's `worktree.lock`, deterministic order (main first, then registry ids ascending) → `refs-history.lock` (recovery-log expire, §3.2) |
| file-transport ref write (`update_ref` over `mkit+file://`) | `refs-history.lock` (§3.1) → `refs/.lock` |
| s3 / http / ssh transport ref write | backend's own conditional-write primitive (SPEC-REFS §5.2); no mkit-owned common-dir lock is taken because the backend's CAS is the coordination mechanism |

A writer not in this table that mutates any lock-guarded state is
non-conforming; add it here when it's added to the CLI.

## Invariants

| Invariant | Enforced by |
|---|---|
| No process holds a lock while acquiring one earlier in the order (no inversion) | §2's total order, MUST-level |
| A live worktree's ref state cannot be corrupted by a concurrent incoming file-transport push | §3.1's nested-lock requirement |
| Two linked worktrees' recovery-log producers cannot interleave and corrupt the shared log | §3.2's common-dir-lock requirement |
| The v0.1.x rebuild shim cannot double-run and produce duplicate MMR leaves | §3.3's re-check-under-lock requirement |
| Every ref/history/recovery-log/registry mutation is traceable to a locks-taken entry | §4's writer enumeration |

## Non-goals

- This document does not define the byte format of any lock file, or
  gc's retention-root semantics (SPEC-GC), or the worktree registry's
  on-disk layout (SPEC-WORKTREE) — only the order in which locks are
  acquired and which writers participate.
- Cross-repository coordination (two independent `.mkit/` repos) is out of
  scope; every lock here is common-dir-local to one repository.
