# Invariants

> Properties that must ALWAYS hold. A violation is a bug, by definition.
> Scope: mkit's storage layers under review in [Epic #634](https://github.com/officialunofficial/mkit/issues/634) — the content-addressed object store (`store.rs`, `pack.rs`, `pack_shard.rs`, `delta.rs`, `chunker.rs`), the journaled commit-history MMR (`history.rs`), and the mutable refs/locking subsystem (`refs.rs`, `repo_lock.rs`, `atomic.rs`).

## System invariants

### INV-1: An object's identity is always its content hash

- **Always:** For any object `O` stored at path `objects/<h[0:2]>/<h[2:64]>`, `BLAKE3(canonical_bytes(O)) == h` (or the BMT root, for `Tree`/`ChunkedBlob`).
- **Because:** Content-addressing is mkit's entire trust model — dedup, tamper evidence, and cross-repo object identity all derive from this.
- **If violated:** Silent corruption goes undetected; two different objects could collide at the same path, or an object's contents could diverge from what its hash promises without any signal.

### INV-2: Written objects are never mutated in place

- **Always:** Once `objects/<hash>` exists and is durable, its bytes never change until the object is deleted (by GC).
- **Because:** This is the "immutable" half of mkit's immutable/mutable split — every other subsystem (packing, delta encoding, MMR leaves referencing commit hashes) assumes an object's bytes are stable for its lifetime.
- **If violated:** Cached hashes, delta bases, and MMR proofs all silently desync from what's actually on disk.

### INV-3: GC never deletes a reachable object

- **Always:** For any object `O` reachable from any ref (including one written concurrently with a GC pass, protected by the mtime grace window), `O` survives GC's sweep.
- **Because:** GC's correctness contract — an unreachable-turned-reachable-again race (e.g. a concurrent commit referencing a freshly-written blob) must not be treated as garbage.
- **If violated:** Data loss — a ref points at a commit whose tree/blob objects no longer exist.

### INV-4: MMR leaf positions are append-only and never reordered

- **Always:** For a given branch's journal, leaf `N`'s content and position, once durable, never change; new leaves only ever append at the next position.
- **Because:** This is the entire basis for "commit X was leaf N" inclusion proofs — SPEC-HISTORY-PROOF's light-client guarantee assumes append-only history.
- **If violated:** A previously-valid inclusion proof could stop verifying, or verify against the wrong leaf.

### INV-5: Producer and verifier fold MMR peaks identically

- **Always:** The bagging policy (`Bagging::ForwardFold`) used to compute a root when appending is the same one used to verify an inclusion proof against that root, for the lifetime of a journal.
- **Because:** `history.rs:93-100`'s own comment calls this out as "load-bearing" — if producer and verifier ever disagree, every proof against that root silently fails to verify.
- **If violated:** Every inclusion proof for the affected journal breaks, with no error pointing at the actual cause (the mismatch, not the proof).

### INV-6: A ref's value only changes through its declared CAS contract

- **Always:** `RefWriteCondition::Any` always succeeds and clobbers; `Missing` only succeeds if the ref did not exist at the moment of write; `Match(H)` only succeeds if the ref's value was exactly `H` at the moment of write — and when it succeeds, no other writer's concurrently-successful `Match` on the same ref is silently overwritten.
- **Because:** CAS is the only concurrency-safety mechanism mkit offers for refs; every caller (commit, branch, merge, rebase, fetch) trusts that a returned `Ok` means its precondition genuinely held.
- **If violated:** Lost updates — a caller believes its write landed cleanly on top of a known prior state, but a concurrent writer's change was discarded without either side erroring.

### INV-7: At most one process holds the repo mutation lock at a time

- **Always:** Two processes never simultaneously believe they hold `worktree.lock` / `worktrees.lock` / `refs-history.lock` for the same partition.
- **Because:** Every write path (refs, index, history journal) assumes exclusive access while the lock is held; this is the sole serialization mechanism.
- **If violated:** Torn writes, interleaved partial updates to refs/index/journal.

### INV-8: Every lock acquisition attempt eventually resolves

- **Always:** A process attempting to acquire a repo lock either succeeds within a bounded time, or fails with a clear "busy" error it can act on — it is never left waiting indefinitely on a lock nobody actually holds.
- **Because:** This is the liveness half of locking correctness (distinct from INV-7's safety half) — a lock primitive can correctly enforce mutual exclusion while still failing this if it can't tell "held" from "abandoned."
- **If violated:** A crashed process's leftover lockfile wedges every future command indefinitely (see Enforceable, GAP below) — the system is safe but not live.

## Enforceable invariants

- [x] **INV-9:** Reading an object always re-verifies its hash against its path before returning content — enforced by `read_object`'s full-verify path in `store.rs` (~`store.rs:395-421`).
- [x] **INV-10:** Object writes are atomic (no reader ever observes a partial file) — enforced by temp-file + rename in `store.rs`/`atomic.rs`.
- [x] **INV-11 (INV-5):** Producer/verifier bagging-policy agreement — enforced by `history_hasher()` being the single source of truth for `Bagging::ForwardFold`, consumed by both `CommitHistory::root`/`prove` and `verify_inclusion` (`history.rs:93-114`).
- [x] **INV-12 (INV-4):** MMR crash recovery never loses a durable leaf or exposes a torn tail — enforced by commonware's journal recovery, pinned by a dedicated test (`history.rs:1070-1158`).
- [x] **INV-13:** A ref's on-disk content is always exactly the 65-byte wire form after a successful write — enforced by strict validation before `write_atomic` in `refs.rs`; malformed content is never durably written.
- [ ] **INV-14 (INV-3):** GC's mark phase treats every reachable object as reachable, at the actual cost of reading full content to classify it — **partial GAP**: the invariant *holds* today, but only by paying full-content reads for every node including leaf blobs (`gc.rs:246`, via `read_object`-per-node), rather than the cheap `object_type()` prologue check. Not a correctness gap; a cost-of-enforcement gap that makes the invariant expensive to maintain at scale. Suggested: short-circuit blobs via `object_type()` (tracked: [#636](https://github.com/officialunofficial/mkit/issues/636)).
- [ ] **INV-15 (INV-6):** CAS `Match` correctness across processes — **GAP**: `Match`'s read-compare-write (`refs.rs:852-868`) has no filesystem-level atomicity of its own and relies entirely on the *caller* holding a lock that happens to cover both racing writers. Two concrete counter-scenarios found: `branch -m` (holds `worktrees.lock`) racing `commit` (holds `worktree.lock`) on the same branch — different locks, so the race window is real; and `update-ref` from two linked worktrees, each with its own `worktree.lock`, racing on the shared `refs/heads/*`. Suggested: serialize `Match` under one shared refs-scoped lock regardless of caller (tracked: [#637](https://github.com/officialunofficial/mkit/issues/637)).
- [ ] **INV-16 (INV-8):** Lock-acquisition liveness — **GAP**: `repo_lock.rs`'s wait loop (`repo_lock.rs:137-156`) polls `O_EXCL` creation every 50ms and never actually blocks on the kernel lock the winner holds, despite the module's own doc comment (`repo_lock.rs:9-14`) claiming it does. A lockfile orphaned by a killed process is indistinguishable from a live holder — every later acquire attempt burns the full timeout and fails, forever, until a human deletes the file. Suggested: adopt the blocking-`flock` + never-unlinked-sentinel pattern already implemented correctly in `mkit-transport-file`'s `RefLock` (tracked: [#635](https://github.com/officialunofficial/mkit/issues/635)).
- [ ] **INV-17 (INV-7, release side):** Lock release never removes another holder's lockfile — **GAP**: `repo_lock.rs:94-99` unlinks by path after dropping the kernel lock, reasoning (incorrectly, since INV-16 is a gap) that the kernel lock prevents a stale-vs-live confusion race. It doesn't. Same fix as INV-16 removes this too.
- [ ] **INV-18 (derived from INV-4 + INV-6):** A branch's ref value and its MMR journal state are updated atomically with respect to other `history-mmr` writers — **GAP**: the empty-journal check and full backfill-from-object-store run in `write_ref_recording_history` *before* `refs-history.lock` is acquired (`mkit-cli/src/commands/mod.rs:648-652` runs before `refs.rs:496`). Two concurrent ref-only writers on the same branch can both observe an empty journal and both append, corrupting the journal's node positions. Suggested: move the empty-check and backfill inside the locked section (tracked: [#638](https://github.com/officialunofficial/mkit/issues/638)).
- [ ] **INV-19:** Delta round-trip — `delta::decode(delta::encode(base, target)) == target` for all valid `(base, target)` pairs, including adversarial/malformed encoded deltas (must error, not corrupt or overrun). **Partial GAP**: the decoder is well-guarded against allocation blowups (`delta.rs:211-242`, allocation cap independent of `base.len()`), but this repo has no explicit property-based test asserting the round-trip identity itself. Suggested: a proptest over `(base, target)` pairs.
- [ ] **INV-20 (bounded memory):** Pack processing never exceeds `MAX_TOTAL_PAYLOAD` (4 GiB) in resident memory — **GAP as stated**: the *nominal* cap is enforced at the wire-format level (`pack.rs:50`), but `PackReader`/`PackWriter` double-buffer payloads (kept in both `in_pack` and `pending_writes` until commit; `finish()` copies every entry into one more contiguous buffer), so actual peak RSS is ~2x the nominal cap — the invariant as *documented* ("streaming-style packfile reader", `pack.rs:286`) does not hold; the invariant as *enforced* is weaker than assumed. Suggested: stream entries into `WriteBatch` as parsed instead of buffering the whole pack (tracked: part of the object-store findings, not yet a standalone issue).

## Assumptions & non-invariants

- **NOT an invariant:** "`repo_lock` waiters block on the kernel lock." The module's own doc comment (`repo_lock.rs:9-14`) states this; the code does not do it (see INV-16). Anything reasoning about lock behavior from that comment alone will be wrong.
- **NOT an invariant:** "Every branch-advancing operation appends exactly one MMR leaf per commit." True only at the granularity of one leaf per `write_ref_recording_history` *call* (roughly, one per CLI invocation) — a multi-commit `rebase` replaying N commits appends exactly one leaf (the final tip), not N. `reflog.rs`'s doc comment ("on *every* branch advance ... the new tip hash is appended as one leaf") reads as the stronger, false claim; the true invariant is narrower and should be documented as such.
- **NOT an invariant (today):** "Concurrent CAS-conditioned ref writes across processes never lose updates." True only when both writers happen to be serialized by the *same* lock (the common single-worktree case for most command pairs) — false across linked worktrees, and false for `branch -m` vs `commit` even in the single-worktree case (different locks). See INV-15.
- **Conditional, not absolute:** "GC never deletes a reachable object" (INV-3) holds *given* the mtime grace window exceeds the maximum plausible write-to-mark latency for any concurrent writer. Under extreme clock skew, a paused/suspended writer process, or a grace window misconfigured too short, this could be violated. The invariant should be read as conditioned on that assumption, not as unconditionally true.
- **NOT yet decided as an invariant:** whether the object store's on-disk *format* stays loose-files-forever. [Epic #634](https://github.com/officialunofficial/mkit/issues/634) / [#650](https://github.com/officialunofficial/mkit/issues/650) treat this as an open migration (to `commonware-storage::Freezer`/`Archive`) — INV-1, INV-2, and INV-3 above are format-independent and must hold regardless of which storage engine backs them; INV-9/INV-10's specific *enforcement sites* would change under a migration and need re-verification against the new backend, not assumed to carry over.
