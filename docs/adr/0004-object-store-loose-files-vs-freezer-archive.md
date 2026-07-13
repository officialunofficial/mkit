# ADR 0004 &mdash; Object store stays loose files; `Freezer`/`Archive` rejected on GC-unlink grounds

- Status: Accepted
- Date: 2026-07-10
- Supersedes: n/a
- Spike: `rust/crates/mkit-core/tests/freezer_archive_spike.rs` (`cargo test -p
  mkit-core --features history-mmr --test freezer_archive_spike`)

## Context

mkit's object store (`store.rs`) is a hand-rolled loose-file design: one file per
object, BLAKE3-named, atomic rename, per-shard-directory fsync. `commonware-storage`
v2026.5.0 &mdash; already a dependency for the commit-history MMR (`history.rs`) and the
vendored-BMT cross-check (`merkle.rs`) &mdash; ships two write-once key-value primitives at
BETA stability that overlap conceptually: `Freezer` and `archive::prunable::Archive`.
Issue #634's performance review flagged that mkit's `WriteBatch` plus per-shard fsync
machinery hand-rebuilds, less efficiently, what a value-journal-backed store gives
structurally.

Issue #650 was reframed from a neutral comparison into a spike-and-migrate-plan task,
under a project-wide directive to prefer Commonware's own primitives over hand-rolled
storage wherever there is a reasonable fit &mdash; defaulting to migration unless the spike
surfaces a genuine blocker.

The precedent for this ADR's rigor is `merkle.rs:10-29`: it documents *why* mkit
diverges from `commonware_storage::bmt` (wasm/std constraints) and cross-verifies the
vendored construction byte-for-byte against the house primitive
(`merkle.rs:497-519`). This ADR follows the same standard: read the real API at the
pinned version, build a runnable prototype against mkit's real object shapes, and
answer the open question with evidence rather than assumption.

### What the spike did

`freezer_archive_spike.rs` builds real `Blob`/`Tree`/`Commit` objects through mkit's
actual `ObjectStore` (so ids and canonical bytes are exactly what production code
produces &mdash; a 15-byte blob, a 64 KiB blob, a tree, and two commits), then exercises:

1. **`freezer_put_get_byte_identical`** &mdash; puts all five objects into a `Freezer`
   keyed by their real BLAKE3-domain ids (`FixedBytes<32>`), with values as
   `bytes::Bytes` and zstd compression enabled (`value_compression: Some(3)`).
   Reads back byte-identical to the canonical serialization. **Passes.**
2. **`freezer_has_no_per_key_delete`** &mdash; documents, and asserts the observable
   consequence of, a fact read directly from `storage/src/freezer/storage.rs` (BETA,
   v2026.5.0): `Freezer`'s complete public API is `init`, `init_with_checkpoint`,
   `put`, `get`, `sync`, `close`, `destroy`. `destroy(self)` consumes the whole
   structure and removes all three on-disk components (table blob, key-index
   journal, value journal) together. There is no `remove(key)` or equivalent.
3. **`archive_prune_deletes_a_prefix_not_a_single_index`** &mdash; the concrete
   "delete one object while others remain" experiment the issue asked for. Puts 5
   real objects at sequential indices 0–4 (`items_per_section: 1`, the *finest*
   granularity `Archive` supports). Index 2 stands in for an object mkit's GC has
   determined is unreachable; indices 0, 1, 3, 4 stand in for objects that are still
   live. The only removal primitive on `prunable::Archive` (it is not even on the
   `archive::Archive` trait &mdash; see `archive/mod.rs`'s trait definition, which has no
   delete/prune method at all) is the inherent `prune(min_index)`, which removes
   every index `< min_index`. `prune(3)` (the smallest prune point that reaches
   index 2) also deletes indices 0 and 1, which were live. Indices 3 and 4 survive.
   Re-inserting index 0 afterward is rejected (`Error::AlreadyPrunedTo`) &mdash; a pruned
   index cannot be resurrected. **Passes**, and the assertions are written to fail
   loudly if a future `commonware-storage` release changes this behavior.

## Decision

**Keep the loose-file object store. Do not migrate `store.rs` to `Freezer` or
`Archive`.**

This is the "keep loose files, here's why" outcome the issue explicitly allows, and
it departs from the directive's default-to-migrate stance for one concrete,
spike-verified reason:

### The blocker: neither primitive supports per-object deletion

mkit's GC (`ops/gc.rs`) is mark-and-sweep over the entire BLAKE3 keyspace:
`collect_roots` computes a root set from refs/stash/index/in-progress-op state,
`reachable_closure_checked` walks it, and `run_gc` deletes every object hash in the
store that isn't in the live set &mdash; via `store.remove_object(&h)`, one `fs::remove_file`
per hash, O(1) each, independent of every other object. Unreachable objects are
**scattered arbitrarily** across the keyspace: an object's liveness depends on
whether anything in the current ref/stash/index graph still points to it, which has
no relationship whatsoever to *when* the object was written. A blob committed first
can easily outlive a commit written an hour later once the later commit is
`reset --hard`'d away.

Both Commonware primitives are fundamentally incompatible with that access pattern:

- **`Freezer`** has no deletion primitive at all short of destroying the entire
  structure. It is described in its own module doc as "written once and never
  modified" and "avoids ever rewriting (i.e. compacting) inserted data" &mdash; this is
  not an oversight, it is the design. There is no `Freezer` configuration or
  companion type that adds per-key removal.
- **`Archive`** (the prunable variant &mdash; the only one with any removal capability)
  supports exactly one primitive: `prune(min_index)`, a **monotonic prefix
  truncation** over the index space. This is the right tool for a workload where
  liveness *is* correlated with insertion order (block/consensus history: "keep the
  last N blocks, drop everything older" &mdash; see the module doc's "Querying for Gaps"
  and the `next_gap` API, clearly designed for exactly that access pattern). It is
  the wrong tool for content-addressed reachability-based GC, where the set of
  indices to delete is an arbitrary subset with no contiguous relationship to the
  set retained. The spike shows this concretely: isolating one dead object at index
  2 while keeping live objects at both 0/1 (older) and 3/4 (newer) is not
  expressible &mdash; `prune` always takes a *prefix*, never an arbitrary subset.

The only way to actually reclaim space for an arbitrary dead subset under either
primitive is to **rebuild**: create a fresh `Freezer`/`Archive`, copy every live
object into it (an O(live-set) rewrite, not O(dead-set) like today's unlink), and
swap. That is a fundamentally different GC architecture &mdash; compaction-based instead
of unlink-based &mdash; with materially different cost (proportional to *retained* data,
not *reclaimed* data) and a transient ~2x disk requirement during rebuild. That is
not "migrate the object store," it is "replace mark-and-sweep GC with
copying-collector GC," which is a much larger and riskier change than issue #650
scoped, and isn't something the spike's data supports recommending on its own
(no measurement here shows it's actually *worse* than today's approach at any given
repo size &mdash; only that it's a different, larger commitment than a store swap).

### Other considerations from the original ADR framing (weighed, not blockers)

- **Sync/async bridge cost.** `commonware-storage` is async-over-tokio;
  `store.rs`'s API is synchronous. `history.rs` already pays this exact bridge cost
  for the journaled MMR (`crate::protocol::async_shim::Executor`,
  `executor.block_on(...)`, a dedicated tokio runtime bootstrapped on a background
  thread). This is a known, already-amortized cost class, not a novel one &mdash; it would
  not by itself have blocked migration.
- **wasm target support.** Verified by grep: `mkit-wasm/src/**` has zero references
  to `store::` or `ObjectStore` (`objects.rs` only handles hashing/serialization, not
  storage). The object store is never compiled to wasm today, so this is a
  **non-issue** for this decision &mdash; consistent with the issue's own hint to verify
  rather than assume.
- **On-disk transparency/debuggability.** Not decisive on its own (git-like loose
  files are nice for `ls`/`cat`-level debugging, but `Freezer`/`Archive` are
  reasonably inspectable too), but it's a real, if minor, point in the loose-file
  design's favor that compounds with the blocker above rather than fighting it.
- **Built-in zstd compression.** `Freezer`/`Archive` both support per-value zstd
  (`value_compression`/`compression` config, exercised in the spike at level 3).
  This is a genuine capability loose files don't have today, and remains attractive
  &mdash; but it is available independently of the store's file-vs-journal question (see
  Consequences).

## Consequences

- `store.rs` is unchanged by this ADR. No migration issue is filed for the object
  store as a whole.
- **#646 (pack payload compression) is *not* resequenced behind a migration**,
  because there is no migration. The original resequencing concern &mdash; that
  `Freezer`/`Archive`'s built-in zstd might reshape #646's scope &mdash; does not
  materialize under this decision. #646 remains a **wire-format** (packfile
  transfer) concern, orthogonal to at-rest object storage; it can proceed on its
  original schedule. If mkit later wants **at-rest** object compression independent
  of this ADR's GC finding, that is a separable, much smaller change (for example,
  compressing loose-file bytes before the atomic rename) that doesn't require
  adopting `Freezer`/`Archive`'s journal model &mdash; and is out of scope here.
- The spike test (`freezer_archive_spike.rs`) is retained in-tree, gated behind
  `--features history-mmr` (which already pulls the needed `commonware-storage`,
  `commonware-runtime`, and `commonware-utils` optional deps). It exists to keep
  the evidence for this decision runnable and re-verifiable against future
  `commonware-storage` releases, the same role `merkle.rs`'s cross-check test plays
  for the BMT divergence. If a future `commonware-storage` release adds true
  per-key deletion to `Freezer` or `Archive`, `freezer_has_no_per_key_delete` and
  `archive_prune_deletes_a_prefix_not_a_single_index` are exactly the tests that
  would need updating, and their failure is the trigger to revisit this ADR.
- **If this decision is ever revisited**, a real migration issue would need to
  scope at least: (a) which GC architecture replaces mark-and-sweep-with-unlink &mdash;
  almost certainly a periodic copying/compaction collector, since per-object delete
  doesn't exist; (b) the disk headroom and pause/throughput budget for a rebuild
  proportional to live-set size instead of dead-set size; (c) the sync/async bridge
  design for the object-store hot path (write/read on every command), following
  `history.rs`'s `Executor` pattern; (d) a migration/compat story for existing
  on-disk loose-file repos (this would be a breaking on-disk format change, like
  ADR 0001); (e) whether `Freezer` (BLAKE3-key lookup, no ordering) or `Archive`
  (adds an ordered index dimension mkit doesn't currently need) is the better fit
  absent the GC blocker &mdash; the spike used `Archive` only to test prune semantics;
  `Freezer` is the closer conceptual match to mkit's key-value shape otherwise.
