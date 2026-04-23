# Phase 5a golden vectors

Phase 5a (`diff` / `graph` / `merge` / `cherry_pick`) is a **behavioral**
phase: it composes already-pinned byte formats (the `Tree` and `Commit`
encodings from Phase 1) into history operations. The on-disk byte
format is therefore already pinned by `phase1/tree*` vectors — there
is no new wire format to harvest from Zig.

What we *do* pin in Phase 5a — via Rust-side regression tests —
is the **deterministic outcome** of operations on fixed inputs:

- For a fixed (`base`, `ours`, `theirs`) set of tree entry hashes, the
  3-way merge produces a tree with a deterministic content-addressed
  hash. Any drift in the merge decision matrix flips that hash.
- For a fixed cherry-pick `(target, ours)` pair, the merged tree's
  hash is likewise deterministic.

These hashes are baked into the test in `crates/mkit-core/tests/ops_integration.rs`
(see the `merge_uses_find_merge_base_on_diamond` and
`cherry_pick_target_then_diff_picks_only_target_changes` tests).

If you ever need a byte-vector regression guard here (e.g. for a
cross-impl future port), the simplest extension is to add a vector to
`scripts/harvest/harvest.zig` that:

1. Constructs `(base, ours, theirs)` trees with stable child hashes
   (no real blobs needed — `Tree` only references hashes).
2. Calls the merge decision matrix manually (no tempdir needed for
   purely-additive cases) to produce the merged entries.
3. Serialises the resulting `Tree` and emits its bytes.

Skipped here because the merge algorithm needs an `ObjectStore` for
recursive subtree merges, which would push the harvest harness into
real filesystem I/O. The behavioral tests already cover the matrix
exhaustively.
