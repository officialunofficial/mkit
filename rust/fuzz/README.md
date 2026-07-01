# mkit-fuzz

Bounded property tests for mkit-core, cargo-fuzz compatible. A workspace
member (not published), so `libfuzzer-sys` stays behind the optional
`libfuzzer` feature and the default `cargo build` / `cargo test` never pulls
it in.

## Targets

`delta`, `pack`, `tree`, `merkle_packlist`, `merkle_proof`,
`software_key_record`, `rpc_decode`, `git_commit_parse`, `git_tag_parse`,
`git_tree_parse`.

## Two execution paths

```sh
# libfuzzer-sys harness (nightly)
cd rust/fuzz && cargo +nightly fuzz run delta

# plain unit-test harness over the same target bodies — what CI runs,
# no nightly required
cd rust && cargo test --manifest-path fuzz/Cargo.toml
```

Every target enforces the guardrails documented in `docs/FUZZ.md`: ≤100
iterations per invocation, ≤64 KiB input per iteration, bounded per-op
allocations, a 100 ms per-iteration cap, no unbounded loops, seeded PRNG.
