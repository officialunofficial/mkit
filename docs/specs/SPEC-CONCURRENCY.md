---
spec: SPEC-CONCURRENCY
version: 1
status: draft-normative
audience: implementers of any lock-taking mkit-core/mkit-cli code path; reviewers of concurrency-sensitive changes
---

# SPEC-CONCURRENCY &mdash; the total mkit lock order

Status: **Normative** for lock naming, location, and acquisition order.
**Draft** because §3.1 documents an open coordination gap this document
does not resolve. See SPEC-CONVENTIONS §2 for what draft/normative mean.

Scope: this document is the single owner of the total lock order across
*every* lock any mkit process takes &mdash; repo-local locks defined in
SPEC-WORKTREE §4.3, the ref-history locks defined in `mkit-core::refs`,
and the file-transport's own CAS lock defined in SPEC-TRANSPORT. Any
other `SPEC-*.md` document that mentions a lock cross-references this
one rather than restating the order; this document does not restate
those other documents' non-locking content.

---

## 1. Why this document exists

Nearly a dozen `SPEC-*.md` documents each independently described a
slice of mkit's locking model, using inconsistent names for the same
lock and never stating the total acquisition order a multi-lock caller
must follow. That let deadlock-shaped bugs (two processes taking the
same two locks in opposite order) hide in the gap between documents.
This spec is the one place that total order lives; every other
document points here.

## 2. Lock inventory

| Lock | Location | Scope | Guards | Defined in |
|---|---|---|---|---|
| `worktree.lock` | each tree's state dir | per-tree | that tree's worktree/index read-modify-write | SPEC-WORKTREE §4.3 |
| `worktrees.lock` | common dir | per-repo | linked-worktree registry mutations, branch-checked-out-elsewhere guard + HEAD write | SPEC-WORKTREE §4.3 |
| `refs-history-<branch>.lock` | common dir, keyed on the branch name | per-branch | ref-write + history-MMR-append critical section for one branch (`mkit_core::refs::history_lock_name`) | §3.2, §3.3 (this document) |
| `refs-<ref>.lock` | common dir, keyed on the full ref path | per-ref | `mkit_core::refs::cas_write`'s `Match` CAS arm for direct on-disk ref mutation outside the file transport (`mkit_core::refs::cas_lock_name`) | SPEC-REFS §5.1 |
| `<root>/.mkit/refs/.lock` | transport root | per-repo, **local to the file transport only** | the file transport's own `Match` CAS critical section (`mkit-transport-file`'s `RefLock`) | SPEC-TRANSPORT, §3.1 (this document) |
| `serve.lock` | common dir | per-repo, **detection only, not a critical-section lock** | held **shared** by every live `mkit serve` process for its whole lifetime; probed non-blocking-exclusive by `worktree.lock`/`worktrees.lock` acquisition to warn when a root is concurrently served (MKIT-11/#655) | §3.1 (this document) |

The recovery log (`.mkit/recovery-log`) has **no dedicated lock** &mdash; see
§3.2.

## 3. Cross-subsystem interactions

### 3.1 File-transport CAS vs. local worktree operations (detected, not coordinated)

`<root>/.mkit/refs/.lock` (fourth row of §2) serializes the file
transport's own `Match` CAS critical section against **other file
transport instances pointed at the same root** &mdash; nothing more. It does
not coordinate with `worktree.lock`, `worktrees.lock`, or
`refs-history-<branch>.lock` in any way, because the file transport has
no knowledge of those locks or of the `RepoLayout` abstraction they're
keyed on.

This is a real, permanent gap, not one this document closes: a local
`mkit commit`/`checkout`/`gc` running directly against a directory that
is *simultaneously* being served by `mkit serve` (a file-transport
listener) over that same directory is not coordinated against by the
transport's lock, and vice versa &mdash; a `gc` sweep can still race a
concurrent push's object write, or a local ref write can still race a
client's CAS update. mkit's supported deployment shape for the file
transport is a bare/shared remote a worktree-owning process does not
also mutate directly. Running local worktree commands directly against
a live `mkit serve` root remains unsupported.

**MKIT-11/#655 turned this from silent into detected**, without closing
it: every live `mkit serve` process holds a **shared** kernel lock
(`std::fs::File::lock_shared`, never exclusive &mdash; SPEC-TRANSPORT
documents multiple concurrent `serve` processes against one root, e.g.
one per SSH forced-command connection, as a supported deployment, so
`serve` instances must not exclude each other) on `serve.lock` (fifth
row of §2, in the common dir) for its whole lifetime. `worktree.lock`
and `worktrees.lock` acquisition (`mkit-cli`'s `acquire_worktree_lock`
and `acquire_worktrees_registry_lock`) each follow up with a
non-blocking exclusive probe of that same `serve.lock`
(`mkit_core::repo_lock::probe_exclusive`); when the probe finds it busy
(i.e. at least one `serve` is alive), the command prints a warning to
stderr and proceeds anyway &mdash; it does not refuse or block. This makes
every worktree-mutating command and `gc` (which takes both locks) emit
the warning; commands that skip both helpers (`tag`, `fetch`/`pull`,
`attest` &mdash; see §4's per-command table) do not.

Residual gaps this warning does **not** close:

- A push made directly against the file transport (`mkit push
  mkit+file:///path`, bypassing `mkit serve` entirely) is not detected
  &mdash; nothing takes `serve.lock` on that path.
- Detection is one-directional: a `mkit serve` that starts *during* a
  local command's already-in-flight critical section is not itself
  warned, since `serve` does not probe the worktree locks.

### 3.2 Recovery-log `record`/`expire` synchronization

`ops::recovery::record` and `ops::recovery::expire` are not internally
synchronized (see that module's own concurrency note) and have no
dedicated lock of their own. Correctness instead relies on lock
**superset** containment:

- Every producer (`commit --amend`, `reset`, `rebase`, `stash pop`)
  calls `record` while already holding *its own tree's* `worktree.lock`
  &mdash; the same lock it took for the read-modify-write the recovery entry
  is about.
- `mkit gc` calls `expire` while holding `worktrees.lock` **and every
  registered tree's `worktree.lock`** (SPEC-WORKTREE §4.3's holder
  list) &mdash; a strict superset of any single producer's one lock.

Because gc's lock set always contains whichever single `worktree.lock`
a producer would be holding, a producer's `record` append and gc's
`expire` rewrite can never interleave &mdash; without a separate recovery-log
lock being necessary. `ops::recovery`'s module doc calls this "the repo
lock" generically rather than naming a specific lock file, precisely
because the guarantee comes from lock containment, not from a
dedicated primitive.

### 3.3 History-MMR empty-journal-then-backfill race

`mkit-cli`'s `write_ref_recording_history` backfills a branch's
history-MMR journal from the object store the first time a
never-before-journaled branch is written (a v0.1.x-era repo enabling
`history-mmr`, or a crash on a branch's first tracked write) &mdash; see
SPEC-HISTORY-PROOF §4.5.

The empty-journal check and the backfill loop MUST both run *inside*
`refs-history-<branch>.lock`'s critical section
(`mkit_core::refs::update_ref_with_history_and_backfill`), never before
it. Only the
first writer to acquire the lock for a given branch may observe an
empty journal and perform the backfill; every subsequent concurrent
writer reopens the journal after acquiring the same lock and finds it
already non-empty, skipping straight to its own append.

Checking before the lock is acquired is insufficient: two ref-only
writers on the same never-before-journaled branch &mdash; for example, two
concurrent `update-ref` calls, which deliberately skip `worktree.lock`
&mdash; could both observe an empty journal and both independently backfill,
writing to overlapping journal leaf positions from two disagreeing
in-memory MMR states (invariant INV-18).

## 4. Global lock order and per-command lock sets

A process that takes more than one lock from §2 MUST acquire them in
this order:

```
worktrees.lock  ≺  per-tree worktree.lock(s)  ≺  refs-history-<branch>.lock(s)
```

`refs-<ref>.lock` (the `cas_write` CAS lock) and
`<root>/.mkit/refs/.lock` (the file-transport lock) are leaves &mdash; no
documented code path takes either alongside any other lock in this
table, so they have no ordering constraint relative to the chain above.

`serve.lock` is never held alongside another lock in this table by the
same process &mdash; a `serve` process holds only `serve.lock` for its
whole lifetime, and a local command only ever *probes* it (non-blocking,
released immediately) rather than holding it, from inside its own
`worktree.lock`/`worktrees.lock` critical section. It therefore has no
ordering constraint either, and is excluded from the per-command lock
sets below (every command that takes `worktree.lock` or
`worktrees.lock` probes it implicitly &mdash; see §3.1).

Per-command lock sets (extends SPEC-WORKTREE §4.3's holder list with
the history lock):

| Command/path | Lock set, in acquisition order |
|---|---|
| `add`, `commit`, `merge`, `checkout`, `rebase`, `cherry-pick`, `revert`, `reset`, `restore`, `rm`, `mv`, `stash`, `sparse-checkout`, `update-ref` | this tree's `worktree.lock`, then (if the command moves a branch ref and history-mmr is enabled) that branch's `refs-history-<branch>.lock` |
| `checkout`/`switch` (branch-checked-out-elsewhere guard), `branch -d`/`-m` | `worktrees.lock`, then (branch-moving forms) `refs-history-<branch>.lock` |
| `worktree add` | `worktrees.lock` (guard re-verified after acquiring), then the new tree's `worktree.lock` |
| `worktree remove` | `worktrees.lock`, then the condemned tree's `worktree.lock` |
| `gc` | `worktrees.lock` first (freezes the worktree set), then every registered tree's `worktree.lock`, deterministic order (main tree first, then registry ids ascending) |

A process that violates this order and blocks on two locks acquired in
opposite order by two racing processes will each time out independently
(`repo_lock`'s default 5s timeout) rather than deadlock indefinitely &mdash;
but SHOULD NOT rely on the timeout as a substitute for correct
ordering; a timed-out multi-lock command leaves its already-acquired
locks released (RAII drop) but may leave mid-sequence on-disk state
requiring the caller to retry.
