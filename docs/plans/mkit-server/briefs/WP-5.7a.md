## Purpose

Takedown (M5) must remove a tombstoned object X from every pack that holds it, without breaking any other object. If a
delta entry uses X as its base, dropping X would make that delta undecodable, so it must be re-emitted as a raw object.
WP-5.7b orchestrates this per holder repo: it finds the affected packs, rebuilds packlist chains and CASes packmaps.
This WP is the pure primitive underneath: one pack in, one rewritten pack out.

## A. Fixed by the plan and specs (do not change)

1. **Format:** `docs/specs/SPEC-PACKFILE.md`.
   - §4 ordering: every delta's base precedes it in the pack, or already exists in the destination store.
   - §1 writer version selection: v1 if there are no `0x03`/`0x04` entries, v2 otherwise.
   - §3.3 compression policy.
   - The output MUST be a valid pack that `PackReader::read` and `PackEntries` accept.
2. **Semantics:** the rewritten pack decodes to exactly the original pack's object set minus the entries whose id is in
   `excluded`, with every surviving object byte-identical.
3. **No existence oracle** (PRD §6.5, and `DeltaBaseSource`'s contract in `pack.rs`):
   - external bases come only from the caller's repo-scoped `DeltaBaseSource`;
   - "not permitted" and "absent" are indistinguishable;
   - an id in `excluded` that is neither an entry nor a base in this pack is silently ignored, never an error.
4. **Compatibility:**
   - mkit-core is published, so the API is additive only.
   - `PackError` is **not** `#[non_exhaustive]`, so you MUST NOT add variants. Reuse existing ones.
   - No new dependencies and no async.
   - Must compile for `wasm32-unknown-unknown` with `--no-default-features --features pack-ruzstd`.
5. **Module location:**
   - The module is `mkit_core::pack::rewrite`, in the file `rust/crates/mkit-core/src/pack/rewrite.rs`.
   - `src/pack.rs` gets exactly two added lines: `pub mod rewrite;` and
     `pub use rewrite::{rewrite_excluding, Rewritten};`.
   - Do **NOT** convert `pack.rs` into `pack/mod.rs`. WP-4.8a adds `pack/window.rs` the same way, in parallel.

## B. Decided by the orchestrator (do not change)

1. **API:**
   ```rust
   #[derive(Debug, Clone, PartialEq, Eq)]
   #[non_exhaustive]
   pub struct Rewritten {
       /// The rewritten pack. Equal to the input bytes when `unchanged`.
       pub bytes: Vec<u8>,
       /// Ids dropped: every id in `excluded` that occurred as an entry, deduplicated, in first-occurrence pack order.
       pub removed: Vec<Hash>,
       /// Ids of delta entries re-emitted as raw, in pack order.
       pub rawified: Vec<Hash>,
       /// True when nothing was removed or rawified.
       pub unchanged: bool,
   }

   pub fn rewrite_excluding<B: DeltaBaseSource>(
       pack: &[u8],
       excluded: &std::collections::HashSet<Hash>,
       bases: &mut B,
       limits: DecodeLimits,
   ) -> Result<Rewritten, PackError>;
   ```
2. **Rawify rule (a plan correction, recorded as orchestrator decision R-87):**
   - A delta entry is re-emitted raw **iff its direct base id is in `excluded`**, whether that base is in the pack or
     external.
   - A delta whose base is a *rawified* entry stays a delta: its base object is still present, as raw, earlier in the
     pack.
   - The breakdown's wording ("base chain passes through") is replaced by this rule. Direct-base is sufficient for
     decodability, and transitive rawification would bloat packs for no correctness gain.
   - A delta entry whose own id is in `excluded` is dropped, not rawified.
3. **Entry handling:**
   - Keep the original relative order.
   - Drop every occurrence of an excluded id; duplicates of non-excluded ids are kept as in the input.
   - Retained raw entries are re-emitted with `PackWriter::push_raw(id, canonical_bytes)`.
   - Retained deltas are re-emitted with `PackWriter::push_delta(&base, &stream)`, using the *uncompressed* delta stream.
   - Rawified entries use `push_raw(id, resolved_bytes)`.
   - Use `PackWriter::new()`: it compresses per §3.3 under `pack-zstd`; on wasm without `pack-zstd` everything is
     uncompressed.
4. **Unchanged shortcut:** if nothing is removed or rawified, return the input bytes verbatim with `unchanged = true`,
   so the pack id is stable and WP-5.7b can skip it.
5. **Determinism:**
   - For a given build (feature set), the same inputs always give byte-identical output.
   - Native (`pack-zstd`) and wasm (no zstd) outputs may differ byte-wise, but decode to identical objects. Document this:
     WP-5.7b pins rewrites to the native path.
6. **Resolving bases:**
   - Rawifying needs the resolved target bytes, which requires the excluded base's bytes. That base is available either
     in the pack (decode it even though it is dropped) or from `bases`, which WP-5.7b supplies from the preservation
     store.
   - If it's unavailable, the error is `DeltaBaseMissing`, exactly as in the decoder.
7. **Memory:**
   - All decoding goes through the existing budgeted machinery (`decode_entries_with` / `DecodeLimits` semantics:
     charge claims before decompressing, charge external bases, release after last use).
   - Resident memory stays within `limits.max_decoded_bytes` plus the input pack plus the output buffer.
   - The output is bounded by `PackWriter`'s own caps (`MAX_ENTRIES`, `MAX_TOTAL_PAYLOAD`); going over is the writer's
     existing error.
8. **Errors:**
   - An invalid input pack gives the same error the decoder returns.
   - No new variants.
   - Errors never reveal whether an excluded id exists outside the pack.
9. **32-bit safety:** all offset and length arithmetic on untrusted input is checked (`overflow-checks` is on in release),
   with conversions through `try_from`.

## C. Your decisions (record each in the PR under "Executor decisions")

- How entries are walked. Preferred: one pass of `decode_entries_with`, advancing a lockstep `PackEntries` iterator in
  the sink to obtain each entry's wire form (raw, or delta with base and stream). Don't materialise all frames twice.
  Any approach is fine if it meets B.7 and doesn't change `decode_entries_with`'s or `PackEntries`'s public behaviour.
- Whether a small crate-private helper in `pack.rs` is needed. If so, list it.
- The proptest strategies and corpus sizes.

## Tests (required)

1. **Property, over packs built with `PackWriter`:** raw, delta and zstd entries; in-pack and external bases (a test
   `DeltaBaseSource` backed by a map); delta chains of depth 1–5; random `excluded` subsets.
   - The rewritten pack decodes (`decode_entries_with` with the same bases minus nothing).
   - Its object set equals original minus excluded, byte-identical.
   - `removed` and `rawified` exactly match the rule in B.2.
   - The output is deterministic across two runs.
2. **Exit criterion (named test `rewrite_through_taken_down_base_still_decodes`):** a pack with X, then D1 = delta(X),
   then D2 = delta(D1), with X excluded. The result is X dropped, D1 rawified and D2 kept as a delta, and the pack
   decodes with `NoExternalBases`.
3. **External excluded base:** D = delta(E) with E external and excluded. D is rawified using `bases`, and the output
   decodes with `NoExternalBases`.
4. **Unchanged:** an empty `excluded`, or ids not in the pack, give `unchanged = true` and bytes equal to the input.
5. **No oracle:**
   - an excluded id absent from the pack and from `bases` gives the same result as not passing it;
   - `DeltaBaseMissing` text is identical whether the source "has" the base (denied) or not.
6. **Budget:** a bomb test (a tiny pack whose deltas declare huge results) gives `PackfileTooLarge` before allocation.
7. **32-bit:** a hostile `payload_len = u32::MAX` gives a clean error. Add a rewrite round trip to the wasm32 harness
   (`rust/crates/mkit-core-wasm-check`, run via `scripts/wasm-ruzstd-check.sh`) if it fits without zstd encode. On
   wasm the writer emits raw, so round trip a raw/delta pack.

## D. Escalate (stop and report, do not improvise) if

- Meeting B.7 would require changing `decode_entries_with`'s public signature or behaviour.
- `PackWriter::new()` output is non-deterministic for identical input on the same build.
- Any part of A/B contradicts the spec or itself.

## Gate additions

- `cargo nextest run -p mkit-core --all-features -E 'test(/pack|rewrite/)'`
- `cargo nextest run -p mkit-core --no-default-features --features pack-ruzstd`
- `bash scripts/wasm-ruzstd-check.sh`
- the goldens unchanged: `git diff --exit-code rust/tests/golden/`
