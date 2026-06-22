# Diff / merge golden vectors

`diff` / `graph` / `merge` / `cherry_pick` are **behavioral**: they
compose already-pinned byte formats (the `Tree` and `Commit` encodings)
into history operations. The on-disk byte format is therefore already
pinned by the `objects/tree*` vectors — there is no new wire format to
pin here.

What we *do* pin here — via regression tests — is the
**deterministic outcome** of operations on fixed inputs:

- For a fixed (`base`, `ours`, `theirs`) set of tree entry hashes, the
  3-way merge produces a tree with a deterministic content-addressed
  hash. Any drift in the merge decision matrix flips that hash.
- For a fixed cherry-pick `(target, ours)` pair, the merged tree's
  hash is likewise deterministic.

These hashes are baked into the test in `crates/mkit-core/tests/ops_integration.rs`
(see the `merge_uses_find_merge_base_on_diamond` and
`cherry_pick_target_then_diff_picks_only_target_changes` tests).

Byte-vector regression guards are not needed here because the merge
algorithm requires an `ObjectStore` for recursive subtree merges — the
behavioural tests with real `TempDir`-backed stores already cover the
decision matrix exhaustively.
