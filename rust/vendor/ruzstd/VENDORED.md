# ruzstd 0.9.0

Pristine source: crates.io ruzstd 0.9.0 (MIT, see LICENSE).
Upstream: https://github.com/KillingSpark/zstd-rs
Commit: f833802b674e6b9360a259d25c20940e25a54e79 (v0.9.0, package `ruzstd`).
The published Cargo.toml and source files are retained. Registry cache metadata
and the package's Cargo.lock are omitted.

The only Rust changes enforce RFC 8878 §3.1.1.2.4:
`Block_Maximum_Size = min(Window_Size, 128 KiB)`. Raw/RLE blocks and regenerated
literals are checked before materialization; compressed sequence output is
preflighted with checked arithmetic before any history-buffer expansion.
Error variants describe the rejection. No decoder algorithm is changed.

The mkit caller separately sets a fixed 8 MiB window limit. Its output remains
bounded by the caller's claim; decoder working allocations have a fixed 28 MiB
allowance, including transient old/new ring allocations. Native `pack-zstd`
continues to use the C decoder. Independent Worker workspaces repeat the patch
because dependency-workspace patches are not inherited by Cargo.

Upstream tracking: [KillingSpark/zstd-rs #124, "Refuse blocks that decode past
Block_Maximum_Size"](https://github.com/KillingSpark/zstd-rs/pull/124) is open. Keep the patch until a released
version includes the bound; the tracked PR does not establish released coverage.
Independent embedder workspaces must retain their own `[patch.crates-io]`;
this repository's resolution does not verify an external deployment's graph.
