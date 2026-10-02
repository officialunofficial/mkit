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

Upstream this small patch and replace the vendor when a release incorporates it.
A draft upstream report and reproducer are provided in the R-203 PR body.
