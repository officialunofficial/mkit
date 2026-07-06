# mkit (Rust workspace)

This directory holds the `mkit` Cargo workspace.

## Toolchain

- **Rust** `1.95.0` (pinned in `rust-toolchain.toml`)
- **Edition** `2024` (workspace default)
- **Resolver** `3`

## Workspace layout

```
rust/
├── crates/
│   ├── mkit-core/              # hash, object, serialize, store, chunker,
│   │                           # pack, delta, refs, index, worktree,
│   │                           # ignore, repo_lock, ops/*, sign, protocol
│   ├── mkit-transport-memory/
│   ├── mkit-transport-file/
│   ├── mkit-transport-http/
│   ├── mkit-transport-s3/
│   ├── mkit-transport-ssh/
│   ├── mkit-transport-enc/     # mkit+enc:// no-OpenSSH encrypted transport
│   ├── mkit-attest/            # jcs, statement, envelope, signers, verify
│   ├── mkit-keystore/          # signing-key vault interface + backends
│   ├── mkit-git-bridge/        # git import/export bridge
│   ├── mkit-rpc/               # protobuf wire schemas + stdio framing
│   ├── mkit-wasm/              # wasm-bindgen surface for browsers / Workers
│   └── mkit-cli/               # bin "mkit"
└── fuzz/                       # 8 cargo-fuzz targets (delta, pack, tree,
                                #   software_key_record, rpc_decode,
                                #   git_commit_parse, git_tag_parse,
                                #   git_tree_parse)
```

## Gates

```sh
cd rust
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

CI runs the above matrix on ubuntu-latest + macos-latest
(`.github/workflows/rust.yml`). A weekly job runs `cargo audit` and
`cargo deny check` (`.github/workflows/rust-security.yml`). A
reproducible-build smoke test diffs two sequential release builds
(`.github/workflows/reproducible-build.yml`).

## Contracts

- Every on-disk / wire byte is pinned by golden vectors under
  `tests/golden/`. Any change must update both the vector and the
  relevant `docs/specs/SPEC-*.md` in the same PR.
- `mkit version` emits exactly `mkit <X.Y.Z>\n` — asserted by both a
  snapshot test in `crates/mkit-cli/tests/version_snapshot.rs` and a CI
  step that runs the release binary.
- Fuzz harnesses enforce the six guardrails documented in
  `docs/FUZZ.md` (≤100 iterations, ≤64 KiB input, bounded per-op
  allocations, 100 ms per-iteration cap, no unbounded loops, seeded
  PRNG).
