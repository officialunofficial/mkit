# mkit-core

Content-addressed VCS primitives for mkit: BLAKE3 hashing, canonical objects,
refs, packs, and the transport trait every backend implements.

The byte layout this crate produces is defined, normatively, in
`docs/specs/SPEC-OBJECTS.md` (version `0x01`, magic `"MKT1"`) — any change here
must update the spec in the same PR. The crate depends only on `std`: no
`serde`, no `anyhow`, no panics on unchecked input.

## What's in here

- `hash` / `object` — BLAKE3 hashing and the canonical v1 byte encoding for
  blobs, trees, commits, remixes, and chunked blobs.
- `pack` / `index` — packfile format and the index over it.
- `refs` — ref storage semantics shared by every transport.
- `store` — the on-disk object store (worktree, `.mkit/` layout, `ignore`,
  `repo_lock`).
- `sign` — Ed25519 signing/verification for commits and remixes (see
  `docs/specs/SPEC-SIGNING.md`).
- `protocol` — the `Transport` trait (`list_refs`, `read_ref`, `write_ref`,
  `pack_exists`, `download_pack`, `upload_pack`) every `mkit-transport-*`
  crate implements.
- `chunker` / `delta` — `FastCDC` content-defined chunking and delta encoding
  for large blobs.
- `ops` — the higher-level repository operations (`commit`, `merge`,
  `rebase`, `cherry-pick`, …) `mkit-cli` drives.

Optional features (`history-mmr`, `sparse-checkout`, `pack-shards`) gate
heavier `commonware-*`-backed paths — see the crate's `Cargo.toml` for what
each pulls in.
