# mkit-ruzstd 0.9.1

Pristine source: crates.io ruzstd 0.9.1 (MIT, see LICENSE).
Upstream: https://github.com/KillingSpark/zstd-rs
Published package commit: aa145e8757c6982aab6a8336d3bba43d1a4c6fae
(from the archive's `.cargo_vcs_info.json`, package `ruzstd`). The upstream
manifest is retained as **Cargo.upstream.toml**. The fork manifest
uses the package name `mkit-ruzstd`, retaining the library name `ruzstd`, the
MIT license, and the complete copyright notice in **LICENSE**. Its standalone
lockfile supports the release verification build. Registry cache metadata is
omitted.

Version 0.9.1 includes the fix for RUSTSEC-2026-0344:
[d3907c9, "assert that a block will not generate more decoded bytes than the
maximum would allow"](https://github.com/KillingSpark/zstd-rs/commit/d3907c960ca4a1aa44cc38340137c5679dd98f5a).
It checks raw/RLE regenerated sizes before materialization and checks sequence
output after each match. The raw/RLE portion of the former local patch is now
redundant and is dropped.

The remaining local changes enforce RFC 8878 §3.1.1.2.4:
`Block_Maximum_Size = min(Window_Size, 128 KiB)` before allocation:

- `block_decoder.rs` checks the compressed block body size before its buffer is
  resized, and regenerated literals before they are materialized. Upstream's
  fixed 128 KiB input ceiling does not cover a smaller declared window, and its
  sequence-output check does not bound the literals allocation.
- `sequence_execution.rs` preflights all match lengths plus all literals using
  checked arithmetic before any sequence expands the history buffer. This also
  counts trailing literals and fails closed on 32-bit overflow. Upstream's
  check runs after `repeat`, which can already have grown history. The local
  preflight replaces that now-redundant per-sequence check and reuses upstream's
  `TooManyBytesGenerated` error; no local error variants remain.

The mkit caller separately sets a fixed 8 MiB window limit. Its output remains
bounded by the caller's claim; decoder working allocations have a fixed 28 MiB
allowance, including transient old/new ring allocations. Native `pack-zstd`
continues to use the C decoder. Both backends apply the same window and RFC
block-size limits.

The shared allocator regression in `rust/tests/support/zstd_heap_bounds.rs`
runs through mkit-core on native and wasm32. Its advisory input class uses a
compressed block smaller than 128 KiB whose sequences exceed the declared
window's block maximum; it must fail before match output grows history.

mkit-core selects this package with `package = "mkit-ruzstd"`, a path, and a
version, keeping the import name `ruzstd`. Publication rewrites the path to
the named registry dependency. Independent workspaces need no `[patch]` table.
The release workflow publishes this standalone package before the workspace.
The fork remains separate from the workspace because the upstream test corpus
is not vendored; integration regressions run through mkit-core natively and on
wasm32. A later change can remove the fork after an upstream release includes
all remaining bounds.
