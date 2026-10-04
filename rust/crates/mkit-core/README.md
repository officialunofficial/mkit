# mkit-core

Content-addressed VCS primitives for mkit: BLAKE3 hashing, canonical objects,
refs, packs, and the transport trait every backend implements.

The byte layout this crate produces is defined, normatively, in
`docs/specs/SPEC-OBJECTS.md` (version `0x01`, magic `"MKT1"`) &mdash; any change here
must update the spec in the same PR. The crate depends only on `std`: no
`serde`, no `anyhow`, no panics on unchecked input.

## What's in here

- `hash` / `object` &mdash; BLAKE3 hashing and the canonical v1 byte encoding for
  blobs, trees, commits, remixes, and chunked blobs.
- `pack` / `index` &mdash; packfile format and the index over it.
- `refs` &mdash; ref storage semantics shared by every transport.
- `store` &mdash; the on-disk object store (worktree, `.mkit/` layout, `ignore`,
  `repo_lock`).
- `sign` &mdash; Ed25519 signing/verification for commits and remixes (see
  `docs/specs/SPEC-SIGNING.md`).
- `protocol` &mdash; the `Transport` trait (`list_refs`, `read_ref`, `write_ref`,
  `pack_exists`, `download_pack`, `upload_pack`) every `mkit-transport-*`
  crate implements.
- `chunker` / `delta` &mdash; `FastCDC` content-defined chunking and delta encoding
  for large blobs.
- `ops` &mdash; the higher-level repository operations (`commit`, `merge`,
  `rebase`, `cherry-pick`, …) `mkit-cli` drives.

Optional features (`history-mmr`, `sparse-checkout`, `pack-shards`) gate
heavier `commonware-*`-backed paths &mdash; see the crate's `Cargo.toml` for what
each pulls in.

`pack-ruzstd` (pure-Rust zstd decoding, for targets without the C `zstd`)
relies on a bounded-decode patch to ruzstd 0.9 that is applied only inside this
repository's workspace. Cargo does not inherit a dependency's patches, so a
crates.io consumer that enables `pack-ruzstd` must add, in its own workspace,
until upstream releases the fix:

```toml
[patch.crates-io]
ruzstd = { git = "https://github.com/officialunofficial/mkit", tag = "v0.5.0" }
```

Upstreaming is in progress. Without the patch the feature decodes through
the unbounded upstream path.

Upstream tracking: [KillingSpark/zstd-rs #124, "Refuse blocks that decode past
Block_Maximum_Size"](https://github.com/KillingSpark/zstd-rs/pull/124) is open. Keep the patch until a released
version includes the bound; the tracked PR does not establish released coverage.

## Merge operations without a filesystem

`ops::{merge_trees, revert, cherry_pick}` accept any `ObjectSource + ObjectSink`.
`find_merge_base`, `is_ancestor` and `collect_ancestor_set` only need reads.
Successful sink writes must be immediately readable by that source. Existing
`ObjectStore` calls work unchanged. The caller owns signing, refs, locks,
conflict handling and publication; rebase workflow remains separate.

Prefetch verified canonical objects into `MemorySource`, then move it into a
bounded overlay. For example:

```rust
use mkit_core::ops::merge_trees;
use mkit_core::store::{MemoryOverlay, MemoryOverlayLimits, MemorySource};

let source = MemorySource::default(); // Insert prefetched canonical inputs here.
let objects = MemoryOverlay::new(source, MemoryOverlayLimits {
    read_calls: 10_000,
    read_bytes: 32 * 1024 * 1024,
    written_bytes: 8 * 1024 * 1024,
    written_objects: 10_000,
});
let merged = merge_trees(&objects, None, None, None)?;
assert!(!merged.has_conflicts());
# Ok::<(), mkit_core::store::StoreError>(())
```

Choose budgets for the host, including separate limits on prefetch bytes,
object count and maximum individual object size. `MemorySource` enforces the
core per-object ceiling (1 GiB), not an aggregate prefetch budget. The overlay
bounds read calls (including misses), cumulative successful-read bytes and
retained output bytes/objects. Outputs deduplicate against other outputs;
writing a prefetched input again also consumes output retention. `has` reports
only emitted objects. Limits last for the overlay's lifetime, including later
operations; create a fresh overlay for a fresh budget.

Exhaustion returns `StoreError::OperationLimitExceeded`, never a successful
partial merge/ancestry answer. The existing ancestor-set walk still truncates
at 10,000 inserts; this pre-existing behavior is separate from budget errors.
Tree recursion returns `TreeTooDeep` beyond 128 levels. Generic algorithms do
not impose new aggregate limits on arbitrary custom sources/sinks; wrap them
or enforce equivalent budgets in their implementations. A source read can
allocate before its byte debit; decode, conflict storage and text merge also
have temporary allocations proportional to the input. These budgets are not
a hard heap ceiling. Errors do not roll back earlier output writes or reset
consumed budgets. Discard an abandoned overlay and publish only a result the
host accepts, reading its tree/blob closure through `ObjectSource`.

For wasm32, depend on `mkit-core` with `default-features = false` to disable
C-backed `pack-zstd`. The `ci-scripts` gate compiles that configuration and runs
merge/revert/cherry-pick plus ancestry with `MemorySource` and `MemoryOverlay`
on wasm32 through the existing `mkit-core-wasm-check` harness.
