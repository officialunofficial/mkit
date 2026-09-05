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
| `refs-history-<branch>.lock` | common dir, keyed on the branch name | per-branch | ancestry intent + ref + descriptor publication for one branch (`mkit_core::refs::history_lock_name`) | §3.2, §3.3 (this document) |
| `refs-<ref>.lock` | common dir, keyed on the full ref path | per-ref | every direct on-disk ref mutation: Any, Missing, Match, delete, tags, remote refs and batch writes (`mkit_core::refs::cas_lock_name`) | SPEC-REFS §5.1 |
| `<root>/.mkit/refs/.lock` | transport root | per-repo, **local to the file transport only** | the file transport's own Any/Missing/Match critical sections (`mkit-transport-file`'s `RefLock`) | SPEC-TRANSPORT, §3.1 (this document) |
| `serve.lock` | common dir | per-repo, **detection only, not a critical-section lock** | held **shared** by every live `mkit serve` process for its whole lifetime; probed non-blocking-exclusive by `worktree.lock`/`worktrees.lock` acquisition to warn when a root is concurrently served (MKIT-11/#655) | §3.1 (this document) |

The recovery log (`.mkit/recovery-log`) has **no dedicated lock** &mdash; see
§3.2.

## 3. Cross-subsystem interactions

### 3.1 File-transport CAS vs. local worktree operations (detected, not coordinated)

`<root>/.mkit/refs/.lock` serializes all file-transport Any, Missing and
Match writes against other file-transport instances pointed at the same root.
Direct local ref mutations instead share the full-ref
`<common_dir>/refs-<ref>.lock`, including unconditional writes and deletes.
Each domain therefore prevents its own unconditional writer from bypassing a
concurrent conditional write. The two domains use different lock files:
the file transport does not acquire the local full-ref lock, `worktree.lock`,
`worktrees.lock`, or `refs-history-<branch>.lock`.

The cross-domain gap remains: local `mkit commit`/`checkout`/`gc` against a
directory simultaneously served by `mkit serve` is not coordinated with the
transport. A local ref mutation can race a client CAS, and a GC sweep can race
a push's object publication. The supported file-transport deployment is a
bare/shared remote that a worktree-owning process does not also mutate directly.
Local worktree commands against a live `mkit serve` root remain unsupported.

**MKIT-11/#655 turned this from silent into detected**, without closing
it: every live `mkit serve` process holds a **shared** kernel lock
(`std::fs::File::lock_shared`, never exclusive &mdash; SPEC-TRANSPORT
documents multiple concurrent `serve` processes against one root, e.g.
one per SSH forced-command connection, as a supported deployment, so
`serve` instances must not exclude each other) on `serve.lock` (in the common dir) for its whole lifetime. `worktree.lock`
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

### 3.3 First-parent history publication

The history-enabled CLI uses `refs::update_ref_with_ancestry`, taking the
branch history lock and then its full-ref mutation lock before reading state.
Initial ancestry construction, multi-commit fast-forward, generation selection,
intent persistence, ref publication and descriptor publication all run within
these guards. Snapshot readers take the same pair, and reject pending intent.
Guarded internal ref primitives MUST NOT reacquire the held mutation lock.

Pending intent retains both its old and target ref as GC roots, even in a build
without `history-mmr`; all raw mutation paths reject stepping over that intent.
The exact durable state machine and generation semantics are
SPEC-HISTORY-PROOF §4. Legacy event-journal APIs remain explicit low-level
interfaces and do not establish first-parent ancestry.

## 4. Global lock order and per-command lock sets

A process that takes more than one lock from §2 MUST acquire them in
this order:

```
worktrees.lock  ≺  per-tree worktree.lock(s)  ≺  refs-history-<branch>.lock(s)  ≺  refs-<ref>.lock(s)
```

All direct local mutations of a full ref path MUST hold its `refs-<ref>.lock`, including
unconditional writes and deletes. An Any condition removes the value
precondition, never the serialization requirement. The lock is nested inside
history guards by history-aware writers; guarded internal primitives MUST NOT
reacquire it. Multiple locks within a class MUST be acquired in canonical
order before proceeding to the next class: main worktree first then registry
IDs, branch names lexicographically, and full ref paths lexicographically.
Current rename operations publish individual refs; this order does not promise
an atomic multi-ref transaction.

The file transport's `<root>/.mkit/refs/.lock` serializes every write condition
within that transport. It is not composed with the local chain above; the
served-root/local-worktree deployment restriction in §3.1 still applies.

`serve.lock` is a lifetime detection guard, excluded from this acquisition
chain. A server holds it shared while handling requests, including requests
that acquire the file transport's `refs/.lock`. A local command only probes
it non-blocking from inside its `worktree.lock`/`worktrees.lock` critical
section and immediately releases a successful probe. Neither path waits for
exclusive ownership of `serve.lock`, so detection introduces no blocking
lock-order dependency. The per-command sets below omit these implicit probes
(see §3.1).

Per-command lock sets (extends SPEC-WORKTREE §4.3's holder list with
the history lock):

| Command/path | Lock set, in acquisition order |
|---|---|
| `add`, `commit`, `merge`, `checkout`, `rebase`, `cherry-pick`, `revert`, `reset`, `restore`, `rm`, `mv`, `stash`, `sparse-checkout`, `update-ref` | this tree's `worktree.lock`, then (if the command moves a branch ref and history-mmr is enabled) that branch's `refs-history-<branch>.lock`, then the full ref's mutation lock |
| `checkout`/`switch` (branch-checked-out-elsewhere guard), `branch -d`/`-m` | `worktrees.lock`, then (branch-moving forms) `refs-history-<branch>.lock`, then the full-ref mutation lock |
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
