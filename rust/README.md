# mkit — Rust rewrite (in progress)

This tree is the in-progress Rust port of `mkit`, tracked on the `rewrite/rust`
branch. The Zig implementation on `main` remains the shipping binary until the
Phase 10 cutover in the rewrite plan.

## Toolchain

- **Rust** `1.95.0` (pinned in `rust-toolchain.toml`)
- **Edition** `2024` (workspace default)
- **Resolver** `3`

## Workspace layout (target)

```
rust/
├── crates/
│   ├── mkit-core/              # hash, object, serialize, store, chunker,
│   │                           # pack, delta, refs, index, ops/*, sign, protocol
│   ├── mkit-transport-memory/
│   ├── mkit-transport-file/
│   ├── mkit-transport-http/
│   ├── mkit-transport-s3/
│   ├── mkit-transport-ssh/
│   ├── mkit-attest/            # jcs, statement, envelope, signer, verify, store
│   ├── mkit-cli/               # bin "mkit"
│   └── mkit-bench/             # Criterion harness
└── fuzz/                       # cargo-fuzz targets
```

Phase 0 lands the workspace scaffold and golden-vector harvest. Subsequent
phases (1–10) follow the TDD plan; see the draft PR for the checklist.

## Non-negotiables

- Every on-disk / wire byte must match the Zig v0.2.x output. Golden-vector
  tests enforce this per phase.
- `NullNotary` only in the public binary. No notary-submission CLI surface
  (see `scripts/verify-rename.sh` for the forbidden-token list).
- Fuzz guardrails from `docs/FUZZ.md` are carried over: ≤100 iterations,
  ≤64 KiB input, fixed-size arena, 100 ms per-iteration wall-clock cap,
  seeded PRNG, no unbounded loops.
- `mkit version` must emit exactly `mkit <X.Y.Z>\n`.
