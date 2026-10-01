# Executor prompt: bounded memory on corrupt zstd frames (R-203, launch blocker)

Run locally in `/Users/vitormarthendalnunes/Documents/21.Uno/04.Mkit/mkit`.

**Definition of done:** an open PR into `feat/mkit-server`. Don't merge it.

**Read first:**
- `~/.cache/mkit-orch/scratchpad/prompts/executor-common-external.md`;
- the finding and reproducer, `~/.cache/mkit-test-tmp/wp-5-6a-2-review/review.md` ("High, open: corrupted zstd
  acquisition exceeds the Worker resident allowance", plus `corrupt-zstd.rs` in that directory);
- `rust/crates/mkit-core/src/pack.rs` (the `decode_frame_with` / ruzstd path, around lines 741–960);
- `rust/crates/mkit-core/Cargo.toml` (`pack-zstd` vs `pack-ruzstd`);
- `apps/vcs-worker/Cargo.toml` (its `pack-ruzstd` feature);
- #1249's `rust/crates/mkit-server/src/indexed/resolve.rs` (the new preservation acquisition call).

**Setup:**
- **Worktree:** `.claude/worktrees/wp-zstd-bound`, from a fresh `origin/feat/mkit-server`. Merge #1249 into it once
  that has merged; until then, reproduce against the #1249 branch `mkit-server/wp-5-6a-2-preservation` as well.
- **Branch:** `mkit-server/wp-zstd-bound`.
- **PR title:** `fix(core): bound decoder memory on corrupt zstd frames`.
- **Cap:** 500 non-test Rust lines.

## The problem

With `pack-ruzstd` (the pure-Rust decoder, used on wasm), a 4,524-byte corrupt frame allocated about 201 MB before
rejection: ruzstd expands a whole malformed block (thousands of RLE sequences) into its internal buffer before
`decode_frame_with`'s output cap applies. The Worker isolate is 128 MB, and a crash on an uncheckpointed frame repeats
forever. Anything that runs ruzstd on the Worker over stored or pushed frames is exposed.

## Decided: pick the first option that holds, with evidence

1. **First establish the facts,** and write them in the PR body:
   - Which launch builds enable `pack-ruzstd`: the release vcs-worker, mkit-server-worker, and #1249's new
     `mkit-server` `pack-ruzstd` feature.
   - Which code paths decode zstd on the Worker: push verification (4.8), extraction (4.10b), preservation
     acquisition (5.6a-2), HTTP serving and scanner retrieval.
   - Whether the launch Worker ever **admits** zstd-compressed packs. If verification rejects compressed frames
     today, they can only appear through storage corruption.
2. **Option A, preferred if the facts allow:** if the launch Worker doesn't need to decode zstd at all, because
   compressed packs are refused at admission and verification, then remove `pack-ruzstd` from every launch Worker
   graph. Every decode path treats a compressed frame as a fail-closed "unsupported compression" error, with denial
   intact and no retry storm: record a terminal state, not an endless retry. Native keeps the C `pack-zstd` decoder,
   which enforces block limits.
3. **Option B, if the Worker must decode zstd:** enforce RFC 8878 limits **before** or **during** decoding, so peak
   allocation is bounded by the output cap plus a small constant:
   - `Block_Maximum_Size` is `min(Window_Size, 128 KiB)`;
   - reject windows above a documented cap, for example 8 MiB;
   - check the frame content size against the claim.

   In order of preference:
   1. a ruzstd version that enforces this, if one exists; check upstream releases and changelogs;
   2. a minimal upstreamable patch via `[patch.crates-io]` to a vendored copy, with the diff limited to the
      block-size check, and a note to upstream it;
   3. a per-block decode loop, if ruzstd's API lets you cap growth before a block is materialized.

   No C code on wasm.
4. **Regardless of the option:** add an allocator-measured regression, using a counting global allocator in a test
   binary. The reviewer's reproducer frame, plus variants (RLE flood, a raw block over 128 KiB, a huge window, a
   lying content size), must keep peak allocation at or below cap plus a small constant, and must fail closed. Add it
   on the native `pack-ruzstd` build and the wasm check crate (`mkit-core-wasm-check`).
5. **Scope:** no protocol, key or timer change. If Option A changes what the Worker admits, say so explicitly. That
   would be a behavior change for clients pushing zstd packs to a Worker, so check what `mkit push` does against a
   Worker today, and escalate before changing admission.

## Gates

- the common gates;
- wasm32 clippy;
- the `mkit-core-wasm-check` build;
- `just ci-server`;
- the vcs-worker default conformance on a free port.

Do the self-review, then open the PR.
