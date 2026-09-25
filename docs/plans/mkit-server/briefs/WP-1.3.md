# WP-1.3: mkit-core `part:` commitment and BLAKE3 subtree module

- **Milestone/track:** M1 / core (pure mkit-core; may land during M0)
- **Base:** `feat/mkit-server` at `392072d3` or later; **branch:** `mkit-server/wp-1-3-part-commitment`
- **Depends on:** S1 (merged, `0c74dd59`; SPEC-TRANSPORT-CONNECT §7.1 and §7.6 are normative)
- **Unblocks:** 1.11 (server part path), 1.18 (client part upload)
- **Parallel with:** 2.3, 2.4a, 4.1, 4.2, 4.3 (no file overlap except `CHANGELOG.md`)
- **Size:** M (~700–800 changed lines incl. tests and the Python reference; goldens excluded)
- **Area gates (registry):** `rust`, `wasm`, `golden` (+ `docs`, because this WP edits SPEC-TRANSPORT-CONNECT §7.6)

## Conventions

- `git fetch origin && git switch -c mkit-server/wp-1-3-part-commitment origin/feat/mkit-server`.
- Before any test: `export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"` (macOS `/tmp` is a symlink and
  breaks ~20 sign/attest tests).
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`. Don't poll CI and don't
  comment on GitHub or Linear.
- **No CI runs on `feat/mkit-server`.** The evidence is your local gate output, pasted into the PR body. Ignore the
  `actionlint`/`docs-lint`/`crypto-stack-version` workflows if they fire.
- Pre-production policy: no compatibility shims; record the change in `CHANGELOG.md` under `[Unreleased]`.
- Workspace lints apply (`unwrap_used = deny`, `unreachable_pub`, clippy pedantic). No `unsafe`.
- No proto change: `git diff origin/feat/mkit-server -- proto/` stays empty.
- If the diff exceeds ~1500 changed lines (excluding goldens), stop and propose a split.
- Carry-forward notes:
  - `connectrpc` is 0.9.1 (`2a3b9941`, RUSTSEC-2026-0304). Don't let a `Cargo.lock` refresh move it.
  - wasm32 clippy needs `--no-deps`. Even with it, `mkit-core` has **6 pre-existing wasm32 lints**:
    `ops/restore.rs:647`, `:707`, `:789`, `repo_lock.rs:136`, `:216`, `protocol.rs:458`. Your code must add none.
  - nextest timeouts under load also happen on the base branch. Re-run a timed-out test alone. If it also times out
    on `origin/feat/mkit-server`, note that in the PR; it isn't a regression.

## Goal

Give the part path its two pure building blocks, both wasm-safe:

1. The `part:<ticket>:<index>:<subtree-hash>:<len>` auth v2 content commitment. It is parsed, formatted and accepted by
   the canonical validator, and a streaming verifier entry point accepts it for `UploadPart`.
2. A BLAKE3 subtree module. It validates the part geometry, hashes a part as a non-root subtree while streaming (never
   panicking on attacker input), and merges part chaining values into the pack id by the left-balanced rule.

Both get golden vectors per SPEC-CONVENTIONS §5, cross-checked against an independent implementation. The WP then
replaces the §7.6 placeholder "Golden vectors (informative): they land with WP-1.3" with the fixture list.

## PRD and spec refs

- PRD §6.2 (resumable parts: power-of-two parts of at least 8 MiB, subtree hashing, a new commitment kind), §8 M1, D34.
- **SPEC-TRANSPORT-CONNECT §7.1** "Auth v2 contract": the eight-field canonical string, and "An UploadPart commitment
  is `part:<ticket>:<index>:<subtree-hash>:<len>` (§7.6)".
- **SPEC-TRANSPORT-CONNECT §7.6** "Parts" (normative):
  - `<ticket>` = ticket id, **64 lowercase hex**
  - `<index>` = zero-based decimal
  - `<subtree-hash>` = the part's BLAKE3 chaining value as a non-root subtree at offset `index × part_size`, 64
    lowercase hex
  - `<len>` = decimal byte count
  - every part but the last is exactly `part_size`, a power of two ≥ 8 MiB; the last is non-empty
  - at most `max_parts` parts
  - parts merge by BLAKE3's left-balanced tree rule
  - a pack of at most `part_size` bytes uses `UploadPack`, never parts
- SPEC-CONVENTIONS §5 (golden vectors live under `rust/tests/golden/<area>/`; a spec that lists vectors names fixtures
  that already exist).

## Scope

**IN**
- A typed commitment parser/formatter in `write_auth`, used by `Operation::canonical`.
- An additive verifier entry point for part streams.
- The new module `upload_parts.rs`: geometry, streaming part hasher, merge.
- Goldens for the auth v2 `part:` envelope and the subtree merge.
- A pure-Python BLAKE3 reference script used for the cross-check.
- The spec §7.6 fixture list, and a CHANGELOG line.

**OUT**
- Any server handler, ticket token, receipt or `MultipartBlobStore` (1.11).
- The `mkit-server::op::Commitment::Part` variant (`rust/crates/mkit-server/src/op.rs:88`). That is **1.11's**, so this
  WP stays out of `mkit-server` while M0 is editing it. Until 1.11, `VerifiedAuth::try_from` (`op.rs:164`) keeps
  rejecting `part:`, which is correct because no server route accepts parts yet.
- The client (1.18), and proto (1.2).

## Files and symbols (tip `392072d3`)

| File | What exists | Change |
|---|---|---|
| `rust/crates/mkit-core/src/write_auth.rs` | `DOMAIN` :11; `Operation` :30 (commitment doc :35 says only `body:`/`pack:`); `component` :50; `is_hex` :56; `Operation::canonical` :140 with the ad hoc `body:`/`pack:` checks at :158–174; `Headers` :367; `Authorized` :392 (a plain pub struct built by literal in `mkit-server/src/op.rs:386,477–489`); `decimal` :407; `verify_headers` :444, which with `expected_commitment = None` requires `pack:` (:477–479) | Add `ContentCommitment`, `PartCommitment`, `CommitmentKind`, `ExpectedCommitment`, `verify_headers_with`, `Authorized::content_commitment()`. `canonical` delegates to `ContentCommitment::parse` and keeps the **exact** existing error strings. Update the `Operation.commitment` doc. **Don't add a field to `Authorized`**: that would break the struct literals in `mkit-server` tests and the three `apps/*/src/envelope.rs` users. |
| `rust/crates/mkit-core/src/upload_parts.rs` | — | New module (below). |
| `rust/crates/mkit-core/src/lib.rs` | module list :35–62 (`pub mod write_auth;` :62) | `pub mod upload_parts;` |
| `rust/crates/mkit-core/tests/golden_uploads.rs` | — | New. Reads committed fixtures only. `MKIT_WRITE_GOLDEN=1` regenerates them (the `golden_disclosure.rs` convention, see its :51 `writing()`). |
| `rust/tests/golden/auth-v2/part.json` | `unary.json` is the schema model | New |
| `rust/tests/golden/uploads/{subtree-merge.json,MANIFEST.txt}` | — | New |
| `scripts/golden/blake3_subtree_ref.py` | — | New: an independent pure-Python BLAKE3 tree (see the golden plan) |
| `docs/specs/SPEC-TRANSPORT-CONNECT.md` | §7.6 placeholder "Golden vectors (informative): they land with WP-1.3" | Replace it with the fixture list. No normative change. |
| `CHANGELOG.md` | `[Unreleased]` | One `### Added` line |

Reference facts:
- `blake3` is 1.8.7 (`rust/Cargo.lock:532`).
- `blake3::hazmat` provides `HasherExt::{set_input_offset, finalize_non_root}`, `merge_subtrees_{root,non_root}`,
  `left_subtree_len` and `Mode::Hash`.
- `pack_key` is plain `blake3::hash` (`pack.rs:593`).

## Design

### Commitment types (`write_auth.rs`)

```rust
/// A parsed auth v2 content commitment (SPEC-TRANSPORT-CONNECT §7.1, §7.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentCommitment {
    /// `body:<64 hex>`
    Body(Hash),
    /// `pack:<64 hex>:<decimal len>`
    Pack { id: Hash, len: u64 },
    /// `part:<64 hex ticket>:<decimal index>:<64 hex subtree>:<decimal len>`
    Part(PartCommitment),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartCommitment {
    pub ticket: [u8; 32],
    pub index: u32,
    pub subtree: [u8; 32],
    pub len: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentKind { Body, Pack, Part }

impl ContentCommitment {
    /// Strict canonical parse: lowercase fixed-length hex; canonical decimals (no sign, no leading zero, `0` allowed
    /// for `index`); `part` `len >= 1`; `index` fits `u32`; exactly five `:`-separated fields for `part:`.
    /// # Errors
    /// `AuthError("invalid body commitment" | "invalid pack commitment" | "invalid part commitment" | "unknown content commitment")`.
    pub fn parse(text: &str) -> Result<Self, AuthError>;
    #[must_use] pub fn kind(&self) -> CommitmentKind;
}
impl core::fmt::Display for ContentCommitment { /* the canonical text; parse(to_string(c)) == c */ }

/// What a verifier expects the signed commitment to be.
#[derive(Clone, Copy, Debug)]
pub enum ExpectedCommitment<'a> {
    /// Unary: exactly this text (plus the X-Digest check for `body:`), as `verify_headers(.., Some(c), ..)` does today.
    Exact(&'a str),
    /// `UploadPack` stream: any well-formed `pack:` (today's `None`).
    PackStream,
    /// `UploadPart` stream: any well-formed `part:`. The caller compares the ticket id and index with the first
    /// stream message itself (§7.6 "the header's token ticket id and index MUST equal ...").
    PartStream,
}

/// Additive; `verify_headers(e, p, Some(c), n, h)` == `verify_headers_with(e, p, ExpectedCommitment::Exact(c), n, h)`
/// and `None` == `PackStream`. Every existing caller compiles unchanged (mkit-server, apps/{vcs,repo,keys}-worker).
pub fn verify_headers_with(
    expected: Context<'_>,
    procedure: &str,
    commitment: ExpectedCommitment<'_>,
    now: i64,
    headers: &Headers,
) -> Result<Authorized, AuthError>;

impl Authorized {
    /// Typed view of `self.commitment` (always canonical when produced by the verifier).
    pub fn content_commitment(&self) -> Result<ContentCommitment, AuthError>;
}
```

- A `PackStream` expectation with a `part:` commitment fails with the existing string "stream requires a pack
  commitment". `PartStream` with anything else fails with "stream requires a part commitment".
- The scope, fingerprint and replay derivation (`:486–496`) are unchanged. The part path records no replay entry
  (§7.1), but `Authorized` is still produced uniformly.

### Subtree module (`upload_parts.rs`)

```rust
/// Smallest legal part size (SPEC-TRANSPORT-CONNECT §7.6).
pub const MIN_PART_SIZE: u64 = 8 * 1024 * 1024;
pub type ChainingValue = [u8; 32];

/// Validated part geometry for one multi-part upload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartPlan { total: u64, part_size: u64, count: u32 }

impl PartPlan {
    /// `part_size` a power of two >= MIN_PART_SIZE; `total > part_size` (else `NotMultipart`: single-part packs use
    /// UploadPack); `count = ceil(total / part_size) <= max_parts` (and fits u32). All arithmetic checked.
    pub fn new(total: u64, part_size: u64, max_parts: u32) -> Result<Self, PartError>;
    #[must_use] pub fn count(&self) -> u32;
    #[must_use] pub fn part_size(&self) -> u64;
    #[must_use] pub fn total(&self) -> u64;
    pub fn offset(&self, index: u32) -> Result<u64, PartError>;        // index * part_size
    pub fn expected_len(&self, index: u32) -> Result<u64, PartError>;  // part_size, or the non-empty remainder for the last
    /// Test-only geometry: any power-of-two part_size >= blake3::CHUNK_LEN. Used only for fast vectors and proptests.
    #[cfg(test)] pub(crate) fn new_small(total: u64, part_size: u64) -> Result<Self, PartError>;
}

/// Streams one part's bytes into its non-root subtree chaining value.
pub struct PartHasher { hasher: blake3::Hasher, expected: u64, seen: u64 }
impl PartHasher {
    pub fn new(plan: &PartPlan, index: u32) -> Result<Self, PartError>;  // set_input_offset(offset) before any input
    /// Rejects (never panics) input that would exceed `expected_len`: the check runs BEFORE `Hasher::update`, because
    /// hazmat asserts on a subtree overrun.
    pub fn update(&mut self, data: &[u8]) -> Result<(), PartError>;
    /// `LengthMismatch` unless exactly `expected_len` bytes were seen.
    pub fn finalize(self) -> Result<ChainingValue, PartError>;
}
pub fn part_subtree_cv(plan: &PartPlan, index: u32, bytes: &[u8]) -> Result<ChainingValue, PartError>;

/// Merge `cvs` (index order, len == plan.count()) into the root, which is the pack id.
/// Recursive: a range of parts [lo, hi) with byte length L splits at left_subtree_len(L) / part_size parts;
/// the top merge uses `merge_subtrees_root(.., Mode::Hash)`, inner merges `merge_subtrees_non_root`.
pub fn merge_to_root(plan: &PartPlan, cvs: &[ChainingValue]) -> Result<Hash, PartError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PartError {
    PartSizeNotPowerOfTwo, PartSizeTooSmall, NotMultipart, TooManyParts,
    IndexOutOfRange, Overrun, LengthMismatch, WrongPartCount,
}
```

Notes:
- Every hazmat precondition must hold by construction, so no attacker input reaches an `assert!`. The preconditions
  are: the offset is a multiple of `CHUNK_LEN` (the offset is `index × part_size` with `part_size` a power of two ≥
  1024); `set_input_offset` comes before any `update`; the subtree length is at most `max_subtree_len(offset)`, which
  holds because `part_size` is a power of two and the offset a multiple of it; and `left_subtree_len` is only called
  with `len > CHUNK_LEN`.
- Why the split is always on a part boundary: `left_subtree_len(L)` is the largest power of two below `L`, and
  `L > part_size`, so the split is a multiple of `part_size`.

## Tests to write first

In `write_auth.rs` `mod tests`:
- `part_commitment_roundtrip`: `parse(c.to_string()) == c` for index 0, 1 and `u32::MAX`, and len 1 and `u64::MAX`.
- `body_and_pack_parse_unchanged`: every reject case already in `mkit-server/src/op.rs:455–470` (uppercase, short hex,
  `012`, `+12`, empty length, missing length, `2^64`, `part:<64>:1`) is still rejected by `Operation::canonical`, with
  the same message as before.
- `part_commitment_rejects`, each with message "invalid part commitment":
  - uppercase or 63-hex ticket
  - uppercase subtree
  - index `01`, `+1` or `4294967296`
  - len `0` or `007`
  - 3, 4 or 6 fields
  - a trailing `:`
  - an empty field
- `verify_headers_with_part_stream_accepts_part_golden`, and `verify_headers_none_still_rejects_part`
  (`"stream requires a pack commitment"`).
- `part_stream_rejects_pack_and_body`.
- `authorized_content_commitment_roundtrip`.

In `upload_parts.rs` `mod tests`:
- `plan_rejects_*`: part size not a power of two; 4 MiB; `total == part_size` (`NotMultipart`); `total` at or below
  `part_size`; count > `max_parts`; overflow near `u64::MAX`.
- `expected_len_last_part_is_remainder`, `index_out_of_range`.
- `hasher_overrun_is_error_not_panic` (feed `expected + 1` bytes in one call and in two).
- `hasher_short_is_length_mismatch`.
- `streaming_split_equals_one_shot`: proptest over random chunkings of a part.
- `merge_matches_blake3_hash_small_geometry`: proptest, `new_small` with `part_size ∈ {1 KiB … 64 KiB}` and random
  `total`, asserting `merge_to_root == blake3::hash(whole)`.
- `merge_rejects_wrong_count`, `swapped_cvs_do_not_match_root`.

In `tests/golden_uploads.rs`:
- `subtree_merge_vectors_verify`: for every vector, regenerate the input from its rule, recompute each CV and the root,
  compare them with the fixture, and assert `root == blake3::hash(input) == pack_key(input)`.
- `auth_v2_part_golden_verifies`: parses `part.json`, rebuilds the canonical string, verifies the digest and signature
  through `Operation::verify` and through `verify_headers_with(.., PartStream, ..)`.

## Golden-vector plan (SPEC-CONVENTIONS §5; mandatory)

**Fixtures**

1. `rust/tests/golden/uploads/subtree-merge.json`. Inputs are never stored. The rule is `byte[i] = (i % 251) as u8`,
   the BLAKE3 test-vector convention. Each vector is
   `{ name, part_size, total, parts: [{ index, offset, len, cv }], root }`.
   - **Normative geometry** (`part_size = 8 MiB`): 2 parts with a 1-byte last part; 3 parts with last len 1023, 1024
     and 1025; 5 parts with last len `8 MiB − 1`; 8 parts all full (total exactly 64 MiB).
   - **Small geometry** (`part_size = 1 KiB` and `4 KiB`, clearly labelled `"test_geometry": true` and produced via
     `new_small`): 2, 3, 5, 8, 9 and 17 parts, with short last parts. This makes the independent cross-check fast and
     covers deeper, unbalanced trees.
   - `MANIFEST.txt` pins the BLAKE3 of the JSON file, in `golden_disclosure`'s format.
2. `rust/tests/golden/auth-v2/part.json`. Same schema as `unary.json`, same seed `07…07` (public key
   `ea4a6c63…d22c`), audience `https://api.example.test`, same timestamps and nonce, plus:
   - repository `ed25519-ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c/demo` (the §7.4 form)
   - procedure `/mkit.transport.v1.TransportService/UploadPart`
   - ticket `5a…5a` (64 hex), index `1`
   - subtree and len taken from the 8 MiB `2 parts` vector
   - `commitment`, `canonical`, `signing_digest`, `signature`

**Generation.** `( cd rust && MKIT_WRITE_GOLDEN=1 cargo test -p mkit-core --test golden_uploads )`. The normal run
reads committed files only and never regenerates.

**Independent cross-check** (record the commands, tool versions and outputs in the PR body):
- `scripts/golden/blake3_subtree_ref.py` is a pure-Python BLAKE3 transcribed from the BLAKE3 paper §2 (IV, message
  permutation, `CHUNK_START`/`CHUNK_END`/`PARENT`/`ROOT` flags, chunk chaining, parent nodes). It shares no code with
  the `blake3` crate.
  - It computes each part's non-root CV from the chunk counter `offset / 1024`, and the root by the left-balanced
    merge. It asserts equality with the fixture.
  - It self-checks its whole-input root against `b3sum` (the official CLI) for every vector.
  - It must cover every small-geometry vector, and at least the 8 MiB `2 parts` and `3 parts` vectors. Pure Python
    manages roughly 5–10 s per 8 MiB part; say which vectors you ran.
- `part.json`: rebuild the canonical string in Python from the spec text (§7.1 field order, `\n`-joined, no final
  newline). Hash it with the reference script's BLAKE3. Sign it with pycryptodome
  (`Crypto.Signature.eddsa.new(key, 'rfc8032')`) from the seed. Compare digest and signature byte for byte.

**Spec update.** Replace the §7.6 "Golden vectors (informative): they land with WP-1.3" sentence with a short list:
each fixture path and what it pins, noting that small-geometry vectors are test-only geometry. No other normative text
changes.

## Gate commands (repo root)

```bash
export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"
( cd rust && cargo fmt --check )
( cd rust && cargo clippy --all-targets --all-features --workspace -- -D warnings )
( cd rust && cargo nextest run -p mkit-core -p mkit-server -p mkit-transport-connect )
( cd rust && cargo test --doc -p mkit-core )
# wasm
( cd rust && cargo check -p mkit-core --no-default-features --target wasm32-unknown-unknown )
( cd rust && cargo clippy -p mkit-server -p mkit-wasm --target wasm32-unknown-unknown --no-deps -- -D warnings )
( cd rust && cargo clippy -p mkit-core --no-default-features --target wasm32-unknown-unknown --no-deps -- -D warnings 2>&1 \
    | grep -E '^ +--> ' | sort -u )   # must list ONLY the 6 baseline sites (restore.rs:647/707/789, repo_lock.rs:136/216, protocol.rs:458)
( cd rust && cargo build -p mkit-wasm --target wasm32-unknown-unknown )
bash scripts/check-wasm-dep-graph.sh
just ci-scripts                        # spec status + dep graph + wasm checks (docs gate: spec edited)
# golden cross-check (one-off evidence for the PR body)
python3 scripts/golden/blake3_subtree_ref.py rust/tests/golden/uploads/subtree-merge.json
# sanity: path-dependent workers still compile against the additive API (no lock change expected)
( cd apps/vcs-worker && cargo check --target wasm32-unknown-unknown )
just ci                                # mkit-core public API changed
```

## Acceptance checklist

- [ ] `ContentCommitment`/`PartCommitment` parse and format canonically. `Operation::canonical` accepts `part:` and
      still rejects everything it rejected before, with identical messages.
- [ ] `verify_headers` behaves exactly as before, and `verify_headers_with(PartStream)` accepts only `part:`. No
      existing caller changed.
- [ ] No input to `PartPlan`/`PartHasher`/`merge_to_root` can panic. The proptests and the overrun tests prove it.
- [ ] `merge_to_root == blake3::hash(whole)` for every vector and proptest case.
- [ ] Goldens committed, with `MANIFEST.txt`. The Python cross-check passed; command and output are in the PR body.
- [ ] SPEC-TRANSPORT-CONNECT §7.6 lists the fixtures. `check-spec-status.sh` passes.
- [ ] wasm32 check/build pass. wasm clippy shows only the 6 baseline mkit-core sites.
- [ ] `git diff --stat` touches only `rust/crates/mkit-core/**`, `rust/tests/golden/{auth-v2,uploads}/**`,
      `scripts/golden/**`, `docs/specs/SPEC-TRANSPORT-CONNECT.md`, `CHANGELOG.md`.

## Risks

- **hazmat panics.** `set_input_offset` asserts on a non-chunk-aligned offset and on prior input, and `update`
  asserts on a subtree overrun. All validation happens in `PartPlan`/`PartHasher` before hazmat is touched. Keep a
  test that feeds one byte too many.
- **Root vs non-root.** Only the top merge uses `merge_subtrees_root`. A single-part "merge" is impossible by
  construction (`NotMultipart`). Never call `finalize()` on a subtree.
- **Error-string drift.** The apps map `AuthError` strings. Keep the existing ones byte for byte.
- **Scope creep into `mkit-server`.** `Commitment::Part` belongs to 1.11. Don't touch `op.rs`.

## Spec vs breakdown (specs win)

- The breakdown says "a `CommitmentKind` in `Authorized`". Adding a field breaks the struct literals at
  `mkit-server/src/op.rs:386,477–489` and in the apps. This brief uses the accessor
  `Authorized::content_commitment()` instead. There is no spec conflict.
- The breakdown's grammar `part:<ticket>:<index>:<64hex>:<len>` matches S1. S1 also fixes `<ticket>` to 64 lowercase
  hex, and multi-part only for `bytes > part_size`. Both are enforced here (`NotMultipart`).
