# WP-4.1: mkit-core `pack-ruzstd` decode feature and dep-graph check

- **Milestone/track:** M4 / core (pure mkit-core; may land during M0; recommended as the first M4 PR)
- **Base:** `feat/mkit-server` at `392072d3` or later; **branch:** `mkit-server/wp-4-1-pack-ruzstd`
- **Depends on:** P1 (merged)
- **Unblocks:** 4.7 (indexed ingestion), 4.8a (windowed reader), 4.8 (Workers verification)
- **Parallel with:** 1.3, 2.3, 2.4a, 4.3. **File overlap with 4.2** (`rust/crates/mkit-core/src/pack.rs`): merge 4.1
  first; 4.2 rebases. Also overlaps with M0-16/M0-17 on `scripts/check-wasm-dep-graph.sh`: merge in registry order.
- **Size:** S (~350–450 changed lines incl. tests; binary fixtures excluded)
- **Area gates (registry):** `rust`, `wasm`, `sec`

## Conventions

- `git fetch origin && git switch -c mkit-server/wp-4-1-pack-ruzstd origin/feat/mkit-server`.
- `export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"` before tests.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`. Don't poll CI or comment on
  GitHub or Linear.
- **No CI on `feat/mkit-server`.** Paste the local gate output into the PR body.
- Pre-production policy; `CHANGELOG.md`; workspace lints; no `unsafe`; no proto change; stop above ~1500 lines.
- Carry-forward notes:
  - `connectrpc` 0.9.1 must not move. The `rust/Cargo.lock` diff should add only `ruzstd` (0.9.x) and `twox-hash`
    (2.x).
  - wasm32 clippy needs `--no-deps`. mkit-core has **6 pre-existing wasm32 lints** (`ops/restore.rs:647/707/789`,
    `repo_lock.rs:136/216`, `protocol.rs:458`); add none.
  - The optional dependency does **not** change `apps/*/Cargo.lock` or `contrib/signers/Cargo.lock`. Non-activated
    optional deps of a path dependency are not locked downstream: today `commonware-coding` and `zstd` are absent from
    `apps/vcs-worker/Cargo.lock`. Confirm `git status` shows no app lockfile change.
  - Test timeouts under load also happen on the base branch.

## Goal

Add `pack-ruzstd`, a **decode-only** pure-Rust zstd path. With it, a `wasm32-unknown-unknown` build of mkit-core can
read SPEC-PACKFILE v2 `0x03`/`0x04` entries under exactly the same bomb guards and length checks as the C path, while
`PackWriter` still never compresses without `pack-zstd`.

- Prove the two backends agree with a differential test suite and committed C-produced v2 fixtures.
- Make both backends enforce the spec's "one zstd frame" rule.
- Extend the wasm dep-graph check so the `pack-ruzstd` graph is proven C-free.

## PRD and spec refs

- PRD §6.5 ("a decode-only `ruzstd` feature in `mkit-core` for wasm"), §4 ("the wasm build has no zstd decoder"),
  §5.1, D3, D14; M3-a (the Workers memory decision builds on this).
- **SPEC-PACKFILE §3.3** (normative): the payload is `[u32 LE uncompressed_len][one zstd frame]`.
  - Check the claim ≤ `MAX_RAW_OBJECT_SIZE` (1 GiB) **before allocating**.
  - Decompression is bounded to the claim.
  - The actual length must equal the claim exactly.
  - A failure rejects the whole pack before any store write.
  - Any level a compliant decoder reads is valid.
- **§3.4** (`0x04`: `base_hash` uncompressed, then the same rules).
- **§10** (inline test vectors #13–#18), **§12** (invariants, "Resource use is bounded on decompression").
- SPEC-DISCLOSURE §7.2: the closure profile is raw-only, and a verifier rejects compressed entries **without
  decompressing**. That must still hold when `pack-ruzstd` is on.

## Scope

**IN**
- The `pack-ruzstd` feature and the ruzstd decode function.
- Backend selection.
- The exactly-one-frame rule on both backends.
- Committed v2 fixtures produced by C zstd.
- The differential suite.
- Dep-graph script extension, the INVARIANTS text, a SPEC-PACKFILE §10 vector entry, CHANGELOG.

**OUT**
- Enabling `pack-ruzstd` in any consumer. `mkit-wasm` stays raw-only (SPEC-DISCLOSURE §7.2 decision); `mkit-server`
  and the workers enable it in 4.7/4.8.
- Windowed/streaming decode (4.8a).
- Any writer change.

## Files and symbols (tip `392072d3`)

| File | What exists | Change |
|---|---|---|
| `rust/crates/mkit-core/Cargo.toml` | `zstd = { version = "0.14", optional = true }` :89; `[features]` :106; `default = ["pack-zstd"]` :115; `pack-zstd = ["dep:zstd"]` :122 | Add `ruzstd = { version = "0.9", optional = true, default-features = false, features = ["std", "hash"] }` (the `hash` feature enables frame-checksum support through the pure-Rust `twox-hash`), and `pack-ruzstd = ["dep:ruzstd"]`, with a comment block in the style of the existing ones |
| `rust/crates/mkit-core/src/pack.rs` | `ZSTD_LEN_PREFIX` :121; `maybe_compress` :608/:643 (writer; unchanged); `decompress_zstd_entry` :658 (claim check → `zstd_decompress_capped` → exact-length check); `zstd_decompress_capped` C :681–684 and stub :686–691; `PackEntries::next_entry` :1289 (calls `decompress_zstd_entry` for `0x03`/`0x04` at :1326/:1337); v2 unit tests :2402–2593 (all `#[cfg(feature = "pack-zstd")]`) | Backend selection (below); the exactly-one-frame check on the C path; a `pub(crate) fn ruzstd_decompress_capped`; tests |
| `rust/crates/mkit-core/tests/golden_pack.rs` | v2 pins at :271 and :320 are **writer-driven** (they build the pack with `PackWriter`, so they need `pack-zstd`) | Keep them. Add a reader-only test over committed fixtures that runs under `any(pack-zstd, pack-ruzstd)`. |
| `rust/tests/golden/pack-v2/{*.bin,*.json,MANIFEST.txt}` | — | New: C-produced v2 packs (see the golden plan) |
| `scripts/check-wasm-dep-graph.sh` | `check_tree()` :34 runs `cargo tree --target wasm32-unknown-unknown -e normal --prefix none` in a manifest dir, with forbidden lists at :67–69 for mkit-wasm, repo-worker and mkit-server | Add optional extra cargo args and a "required" list. New check: mkit-core `--no-default-features --features pack-ruzstd` **requires** `ruzstd` and forbids `zstd-sys`, `blst`, `commonware-runtime` and `commonware-storage`. Add `ruzstd` to mkit-wasm's forbidden list, which makes the raw-only decision explicit; remove it when mkit-wasm opts in. |
| `docs/INVARIANTS.md` | "wasm32 dependency graphs contain no C-toolchain crates" (:346) | Mention the `pack-ruzstd` graph, and that both zstd backends accept exactly one frame |
| `docs/specs/SPEC-PACKFILE.md` §10 | vectors #1–#18 | Add #19 (a payload with two frames, trailing bytes or a skippable frame → rejected) and #20 (C-produced v2 fixtures decode byte-identically under a decode-only backend). Informative list only; no normative change. |
| `CHANGELOG.md` | | `### Added` (+ `### Changed` if the C path tightens; see Design) |

## Design

```rust
// Backend selection (exactly one active decoder; pack-zstd wins when both are on, for native speed):
#[cfg(feature = "pack-zstd")]
fn zstd_decompress_capped(frame: &[u8], capacity: usize) -> Result<Vec<u8>, PackError>;   // C, + one-frame check
#[cfg(all(not(feature = "pack-zstd"), feature = "pack-ruzstd"))]
fn zstd_decompress_capped(frame: &[u8], capacity: usize) -> Result<Vec<u8>, PackError> {
    ruzstd_decompress_capped(frame, capacity)
}
#[cfg(not(any(feature = "pack-zstd", feature = "pack-ruzstd")))]
fn zstd_decompress_capped(..) -> Result<Vec<u8>, PackError>;  // existing stub; message names both features

/// Pure-Rust decode of exactly one zstd frame, bounded to `capacity` output bytes.
/// Compiled whenever `pack-ruzstd` is on (also alongside `pack-zstd`, so the differential tests can call both).
#[cfg(feature = "pack-ruzstd")]
pub(crate) fn ruzstd_decompress_capped(frame: &[u8], capacity: usize) -> Result<Vec<u8>, PackError>;
```

Rules both backends must satisfy. Differential tests enforce them.

1. **Exactly one frame, fully consumed.** SPEC-PACKFILE §3.3 says "one zstd frame".
   - Reject trailing bytes after the frame, a second concatenated frame, and a skippable frame (magic
     `0x184D2A5?`), with `PackError::ZstdDecompress(..)`.
   - C path: before decompressing, require `zstd::zstd_safe::find_frame_compressed_size(frame) == Ok(frame.len())`,
     and reject a skippable-frame magic.
   - ruzstd path: after decoding, the input slice must be empty.
   - **This is likely a behavior change on the C path.** `ZSTD_decompressDCtx` (behind `zstd::bulk::decompress`)
     decodes concatenated and skippable frames. Prove the old behavior with a test first. If it did accept them,
     record the change in `CHANGELOG.md` `### Changed`: pre-production policy, and the spec already requires one frame.
2. **Bounded output.** Never produce or buffer more than `capacity + 1` bytes: `take(capacity as u64 + 1)` over the
   ruzstd reader, then let the existing exact-length check in `decompress_zstd_entry` reject any mismatch.
   - **Don't pre-allocate `capacity`** on the ruzstd path. The claim is attacker-chosen and up to 1 GiB, and a Workers
     isolate has 128 MB. Grow with the decoded output.
   - The C path keeps its current behavior (`bulk::decompress` allocates `capacity`; that's fine on native).
3. **Checksums.** If the frame has a content checksum, it must match: the C decoder verifies it. With ruzstd, compare
   the calculated and stored checksum explicitly if `StreamingDecoder` doesn't. Check ruzstd 0.9's API
   (`FrameDecoder::get_checksum_from_data`/`get_calculated_checksum`, or equivalent).
4. **Frame content size.** If the frame header declares a content size, it must equal the claim, as the C decoder
   requires. Otherwise → `DecompressedSizeMismatch`/`ZstdDecompress`, matching the C variant class.
5. **Errors.** The variant must match between backends: `ZstdEntryTruncated`, `DecompressedSizeOverCap`,
   `DecompressedSizeMismatch` or `ZstdDecompress(_)`. The message string inside `ZstdDecompress` may differ.
6. **Closure profile untouched.** `PackEntries::is_raw_only` and `first_non_raw_index` (:1269/:1275) still scan types
   without decompressing. A `verify_closure_packs` test under `pack-ruzstd` proves a `0x03` entry is still a profile
   violation, not decoded.

## Tests to write first

In `pack.rs` `mod tests` (or `tests/zstd_differential.rs`), gated on `all(feature = "pack-zstd", feature = "pack-ruzstd")`,
so it runs under `--all-features` and in the workspace clippy/test runs:
- `ruzstd_matches_c_on_writer_output`: proptest over objects of 0–256 KiB (compressible, incompressible and mixed),
  pushed through `PackWriter` (C compression). Every `PackEntry` from `PackEntries` must be byte-identical when decoded
  via C and via `ruzstd_decompress_capped`. Call both functions directly on each `0x03`/`0x04` payload.
- `backends_agree_on_adversarial_frames`: each case gives the same accept/reject decision and the same variant class:
  - a truncated frame; one bit flipped in the frame body
  - two concatenated frames; a valid frame plus 1 trailing byte; a lone skippable frame
  - a checksum mismatch (frame with the checksum flag set)
  - frame content size ≠ claim; claim < actual; claim > actual
  - claim = `MAX_RAW_OBJECT_SIZE + 1` (rejected before any decode)
- `backends_agree_on_committed_v2_fixtures`.

Gated on `feature = "pack-ruzstd"` only, so it also runs in the `--no-default-features --features pack-ruzstd` job:
- `pack_v2_fixtures_decode_without_c_zstd` (golden reader test in `golden_pack.rs`, `cfg(any(pack-zstd,
  pack-ruzstd))`): each committed `.bin` pack goes through `PackEntries` and `PackReader::read` into a temp store. The
  recovered object ids and bytes must equal the sidecar JSON.
- `ruzstd_rejects_over_cap_without_allocating` (the claim is checked before decode; assert the returned error
  variant).
- `closure_profile_still_rejects_compressed_entries` (`verify_closure_packs` over a fixture containing `0x03`).

Gated on `not(pack-zstd)`: `raw_only_writer_when_no_c_zstd` (`PackWriter` never emits `0x03`/`0x04` under
`pack-ruzstd` alone; `maybe_compress` returns `None`).

## Golden-vector plan

The v2 decode path had no committed bytes: the existing "pins" are generated by `PackWriter` at test time, so a
decode-only build had nothing real to read.
- Add `rust/tests/golden/pack-v2/`, containing:
  - `raw_4k_repeat.bin`: the `0x03` pack from `pack_v2_compressed_raw_pin_bytes_roundtrip`'s inputs
  - `delta_repeat.bin`: the `0x04` pack from `:320`'s inputs
  - `mixed.bin`: raw, `0x03`, `0x02` and `0x04` in one pack, with an in-pack delta chain
  - `tree_and_commit.bin`: a compressible tree, plus a signed commit from the existing object goldens' fixed seed
- Each `.bin` has a `.json` sidecar: `{ entries: [{ type, id, len, blake3_of_bytes }], pack_key }`. `MANIFEST.txt`
  pins the BLAKE3 of every file.
- Generate with `( cd rust && MKIT_WRITE_GOLDEN=1 cargo test -p mkit-core --test golden_pack )`, using default
  features, so C zstd produces them.
- Independent cross-check: `zstd -d` (the reference CLI). Extract each frame with a short script (header offsets are
  in the sidecar), then `zstd -d --no-check`/`zstd -t` on the frame. The decompressed bytes' BLAKE3 must equal the
  sidecar. Record the commands in the PR body.

## Gate commands (repo root)

```bash
export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"
( cd rust && cargo fmt --check )
( cd rust && cargo clippy --all-targets --all-features --workspace -- -D warnings )            # differential tests compile here
( cd rust && cargo clippy -p mkit-core --all-targets --no-default-features --features pack-ruzstd -- -D warnings )
( cd rust && cargo nextest run -p mkit-core )                                                  # default (C)
( cd rust && cargo nextest run -p mkit-core --all-features )                                   # differential suite
( cd rust && cargo nextest run -p mkit-core --no-default-features --features pack-ruzstd )     # the real ruzstd path
( cd rust && cargo nextest run -p mkit-core --no-default-features )                            # stub path still fails closed
( cd rust && cargo test --doc -p mkit-core )
( cd rust && cargo nextest run -p mkit-server -p mkit-wasm -p mkit-transport-connect -p mkit-cli )  # reverse deps
# wasm
( cd rust && cargo check -p mkit-core --no-default-features --features pack-ruzstd --target wasm32-unknown-unknown )
( cd rust && cargo clippy -p mkit-core --no-default-features --features pack-ruzstd --target wasm32-unknown-unknown --no-deps -- -D warnings 2>&1 \
    | grep -E '^ +--> ' | sort -u )   # ONLY the 6 baseline sites
( cd rust && cargo clippy -p mkit-server -p mkit-wasm --target wasm32-unknown-unknown --no-deps -- -D warnings )
bash scripts/check-wasm-dep-graph.sh        # includes the new pack-ruzstd check
just ci-scripts
# security (new dependencies ruzstd, twox-hash: both MIT, allowed by rust/deny.toml:74-77 and rust/about.toml)
just ci-security
just ci                                     # rust/Cargo.lock changed
```

## Acceptance checklist

- [ ] `pack-ruzstd` decodes every C-produced v2 fixture byte-identically. The differential proptest and the
      adversarial table agree on accept/reject and variant class.
- [ ] Both backends reject trailing bytes, concatenated frames and skippable frames (SPEC-PACKFILE §3.3 "one frame").
      Any C-path behavior change is in the CHANGELOG.
- [ ] The ruzstd path never pre-allocates the claimed size, and never yields more than `capacity + 1` bytes.
- [ ] `PackWriter` behavior is unchanged in every feature combination. The closure profile still rejects compressed
      entries without decoding.
- [ ] The wasm32 check passes for `--no-default-features --features pack-ruzstd`. The dep-graph script proves
      `ruzstd` is present and `zstd-sys` absent in that graph, and `ruzstd` absent from mkit-wasm.
- [ ] `just ci-security` passes. The lockfile diff adds only `ruzstd` and `twox-hash`. No app lockfile changes.
- [ ] INVARIANTS and SPEC-PACKFILE §10 are updated.

## Risks

- **Divergence as a security bug.** If native (C) and Workers (ruzstd) disagree on one pack, a push accepted on one
  runtime is rejected on the other, and indexed-mode state diverges. Fail-closed disagreements (ruzstd rejects) are
  tolerable but must be documented; fail-open ones (ruzstd accepts what C rejects) are not.
- **Window size and memory.** ruzstd rejects windows above its internal maximum (check the pinned constant), while C
  `bulk::decompress` into a fixed buffer may not. mkit's own writer (level 3, pledged size) uses windows of at most
  2^21 or the content size, so legitimate frames agree. Document the residual fail-closed divergence for exotic
  frames with huge windows and no content size. Add a test that a "2 GiB window, 1 KiB content" frame is rejected, or
  decoded without a large allocation, on ruzstd.
- **Performance.** ruzstd is 2–4× slower than C. It only matters on wasm; native keeps C (`pack-zstd` wins). This
  feeds M3-a/4.8a sizing.
- **Supply chain.** New crates `ruzstd` and `twox-hash`. Pin the minor (`0.9`), and run `cargo deny` and
  `cargo audit`.

## Spec vs breakdown (specs win)

1. The breakdown asks the dep-graph script to "assert `ruzstd` is present and `zstd-sys` absent for
   `mkit-server-worker` (indexed feature) and `vcs-worker`". Neither can be asserted yet:
   - `mkit-server-worker` doesn't exist until M0-16.
   - No crate enables `pack-ruzstd` until 4.7/4.8.
   - `vcs-worker` isn't in the script at all (:67–69 cover mkit-wasm, repo-worker and mkit-server).

   This WP proves the mkit-core `pack-ruzstd` graph directly and adds the required-crate mechanism. **4.8** (the first
   consumer that enables the feature) adds the positive assertion for `mkit-server-worker`/`vcs-worker`.
2. SPEC-PACKFILE §3.3 says each entry carries "one zstd frame". The breakdown only asks for "the same `capacity` cap
   and `ZstdLengthMismatch` checks". The spec rule also requires rejecting multi-frame, skippable-frame and
   trailing-byte payloads on **both** backends, which likely tightens the existing C path.
3. The breakdown's name `ZstdLengthMismatch` doesn't exist; the variants are `DecompressedSizeMismatch` and
   `DecompressedSizeOverCap` (`pack.rs:164–180`). Use the existing ones.
4. SPEC-DISCLOSURE §7.2's rationale says compressed entries "error in that build via the existing stub". With
   `pack-ruzstd` on, the stub is gone, but the raw-only rule is still enforced by the type scan. Leave the normative
   text unchanged. Optionally add an informative note there; that decision belongs to whichever WP first enables
   `pack-ruzstd` in mkit-wasm.
