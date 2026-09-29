## Purpose

Clients, including browsers and Workers through `mkit-wasm`, can verify a byte range of a file that spans several
chunks of a ChunkedBlob against a trusted commit id, using the MKDS v1 container of MKDP v2 bundles. The core can build
the smallest correct proof for a range (MKDP within one chunk or a plain Blob, MKDS across chunks), reading only the
chunks it needs, for WP-4.14b's HTTP serving to call.

## A. Fixed (do not change)

1. **SPEC-DISCLOSURE §8.1 and §8.2:**
   - the MKDS v1 layout;
   - every reject reason and its label;
   - the **order** of checks;
   - canonical Blob lengths (not `chunk_size`) determine chunk boundaries;
   - the 64 MiB container cap and the 1,000,000 chunk-count cap.
2. **SPEC-HTTP-OBJECTS §5.2:**
   - MKDP Range, with the complete preceding length-proof set, when the range falls within one chunk or a plain Blob;
   - MKDS otherwise.
   - The complete preceding length-proof set is a MUST.
3. **The committed goldens in `rust/tests/golden/http-objects/` are the contract.** Existing bytes and sidecars don't
   change.
4. **The test-local reference verifier stays independent:** `rust/crates/mkit-core/tests/http_objects/span.rs`
   (SPEC-HTTP-OBJECTS §9). It never calls product MKDS code.
5. **MKDP v2 verification (`verify_disclosure`) and its public types stay unchanged.**
6. **`mkit-wasm` keeps `mkit-core` with `default-features = false`,** and the wasm dep-graph check stays clean.

## B. Decided (do not change)

- **B1. Module.** Put it in a new `mkit-core/src/verify/span.rs`, next to `closure.rs`/`push.rs`. Don't grow
  `verify.rs`.
- **B2. Codec.**
  - `encode_span(commit, offset, len, anchor: &[u8], chunks: &[&[u8]]) -> Vec<u8>`.
  - **Decoding runs in two passes.** First, a zero-copy **structural pass** that runs before any crypto, checking in
    this order:
    1. the size is at most 64 MiB;
    2. the magic;
    3. the version;
    4. every field and varint. Use MKDS's **own strict LEB128 reader**: minimal encoding only, at most u32, each
       length ≤ remaining input and ≤ 64 MiB, and a chunk count ≤ 1,000,000 **and** ≤ remaining input;
    5. no trailing bytes.

    Then the verification pass iterates the borrowed slices. Don't rely on commonware-codec for minimality; a vector
    pins it (B7).
  - No preallocation from untrusted counts.
- **B3. Verifier.** `verify_disclosure_span(trusted: &Hash, bytes: &[u8]) -> Result<DisclosedSpan, SpanError>`.
  - `SpanError` is **its own type** (D6). It has one variant per §8.2 reason, and `reason() -> &'static str` returns
    the exact golden label. The anchor-invalid and inner-invalid variants carry the underlying `VerifyError` as their
    `source`.
  - **Check order is the spec's table order across all bundles.** Stream within that order:
    - verify the anchor;
    - verify each chunk bundle in sequence, keeping only a small per-bundle summary;
    - copy only the overlapping bytes into the output;
    - then run the cross-bundle checks over the summaries.

    Peak memory is one chunk bundle plus the output plus O(count) summaries.
  - **Chunk bytes** decode through the strict canonical `serialize::deserialize` into a non-empty `Blob`.
  - Arithmetic is checked everywhere.
  - On any error, return no partial bytes.
  - **Commit context reuse (D3):** verify the anchor's commit once (decode and Ed25519). For each chunk bundle,
    require `hash(commit_bytes) == trusted`, and reuse the verified context through a `pub(crate)` path verifier.
    `Disclosed` and the public MKDP API stay unchanged. **Test** that a bundle with different commit bytes is rejected
    even though the anchor was valid.
  - **`DisclosedSpan`** has these fields:
    - `commit_id`
    - `tree_hash`
    - `path`
    - `leaf_id`
    - `signer`
    - `signature_valid`
    - `offset`
    - `bytes`
    - `first`
    - `last`
    - `span_start`
    - `chunk_inner_root`

    Mark it `#[non_exhaustive]`.
- **B4. Builder (D2).**
  - `pub enum RangeProof { Mkdp(Vec<u8>), Mkds(Vec<u8>) }`.
  - `build_range_proof_from<S: ObjectSource>(src, commit, path, offset, len, boundaries: Option<&[u64]>)`.
  - A pure `plan_range_proof(chunk_lengths, offset, len) -> Plan { kind, first, last, needed_chunk_indices }` for
    4.14b's prefetch.
  - **Boundaries** are chunk content boundaries: prefix sums of canonical Blob lengths.
    - Hints are untrusted. Cross-check every hint against the bytes actually read; a mismatch is a typed error, never
      a wrong bundle.
    - With no hints, derive lengths one chunk at a time.
  - **Reading:** read only the preceding chunks, one at a time (build the length proof, then drop the bytes), and the
    chunks in the span. Never read a chunk after the span.
  - **MKDS shape:** the anchor is `Range{offset: start(first), len: 1, with_offsets: true}`, and the bundles are
    `Chunk(first..=last)`.
  - A zero-length range is refused, with a typed error.
  - **Byte identity:** the builder reproduces `span_two_chunks.bin`, `span_first_zero.bin`, `span_three_chunks.bin`,
    `in_chunk_range.bin` and `blob_range.bin` exactly from the fixture inputs.
- **B5. wasm (D5).**
  - Export `verify_disclosure_span(commit_hex, bytes) -> Result<VerifiedSpan, String>`. `VerifiedSpan` is a
    `#[wasm_bindgen]` struct with `json()` and `bytes()` getters, verified once (the `BaoEncoded` pattern).
  - Error strings start with the §8.2 reason label.
  - Input is capped at 64 MiB.
  - Nothing may panic.
  - Don't export the builder to wasm.
  - Update the `mkit-wasm` README export list.
- **B6. Spec note (D1).** Amend the informative note in SPEC-HTTP-OBJECTS §5.2. The boundary-aware builder fixes read
  and memory cost, **not** bundle size: the complete preceding length-proof set keeps the size O(chunk index), so
  416 on oversize stays.
  - Add a version-history row, newest first.
  - Record the size limitation as a carry-forward (a format change would need its own issue).
- **B7. Goldens.**
  - `committed_http_object_goldens_verify` also runs the product verifier on every vector, and requires the **same
    outcome and the same reason label** as `span::verify`.
  - Add reject vectors in write mode, regenerating `MANIFEST.txt` with the existing entries unchanged:
    - a non-minimal varint;
    - a varint over u32;
    - an MKDP bundle presented as MKDS (`span_magic`);
    - an MKDS container in the anchor slot (`span_anchor_invalid`);
    - a chunk count of 1,000,001.
  - Check mode must show a zero diff on the existing artifacts.
- **B8. Registry and plan.**
  - Split the registry row `4.14` into:
    - **`4.14a`:** this WP, M4, Stage 2, deps 4.3 and 4.11;
    - **`4.14b`:** the query ranges, 416 mapping, ETag, `declared_bytes` before Admission and Workers prefetch; M4,
      Stage 2; deps 4.12, 4.10 and 4.14a.
  - Update every dependent that named 4.14: point each at 4.14b unless it only needs the verifier.
  - Update the 00-plan tables.
  - **R-161:** B1–B7, the split, the D1 note, and D4 (encoded-size and `declared_bytes` precomputation deferred to
    4.14b).
  - Add a CHANGELOG line.

## C. Your decisions

- The per-bundle summary struct and the internal streaming shape, within B3's memory bound.
- The `SpanError` variant names. The labels are fixed by the goldens.
- The builder's internal error type, as long as it is typed and documented.
- The fuzz helper layout.

## D. Escalate (stop and report) if

- The spec's check order can't be met with streaming, i.e. some reject requires holding every chunk.
- Reusing the commit context (B3) would need a change to MKDP v2's public API.
- The builder can't reproduce a committed golden byte-for-byte.
- Production code passes 1,500 lines.

## Tests (required)

**Unit (`verify/span.rs`):**
- One case per §8.2 reason, including the defence-in-depth reasons.
- A container that is wrong in two ways reports the earlier reason.
- **Varints:** `0x80 0x00`, a fifth byte > 15, a length > remaining, a count > remaining.
- **Arithmetic:** `offset + len` overflow, `len == 0`, an end exactly at the last chunk's start (`span_last_unneeded`),
  an end at the span's end.
- The commit-context reuse rejection (B3).
- **Builder:**
  - kind selection at exact chunk edges (an end on a boundary gives MKDP);
  - `first = 0` and `first > 0`;
  - a plain Blob;
  - bad hints give a typed error;
  - a counting `ObjectSource` asserts that no chunk after the span is read and at most one preceding chunk is held at
    a time.

**Golden:**
- the B7 product-vs-reference parity;
- the B4 byte identity;
- the new reject vectors.

**wasm (`mkit-wasm/tests/verify.rs`):**
- Every http-objects span vector, including recipe reconstruction and `expand_to`: accept fields, the BLAKE3 of the
  bytes, and the reason prefix.
- Oversize input gives `Err`.
- MKDP passed to the span export is rejected, and MKDS passed to the MKDP export is rejected.

**Fuzz and proptest:**
- New fuzz targets `span_decode` and `verify_span`, with helpers in `rust/fuzz/src/lib.rs` and rows in
  `docs/FUZZ.md`. They check that nothing panics, a freshly built span verifies, and a mutated span rejects.
- **Differential proptest:** random mutations (flips, truncation, swaps, duplicates, splices) give the same reason from
  the product verifier and `span.rs`.
- **Round-trip proptest:** a random `(offset, len)` over the fixture's chunked file is built, then verified, and yields
  the plaintext slice. The result is MKDP exactly when the range falls within one chunk.

## Gates

- The common gate set.
- `cargo nextest run --locked -p mkit-core -p mkit-wasm --all-features`, and the golden check mode.
- wasm32 clippy for `mkit-wasm` and `mkit-core`, plus `scripts/check-wasm-dep-graph.sh`.
- The new fuzz targets build (`cargo +nightly fuzz build` for them, or the repo's fuzz build recipe). Run each for a
  short smoke run of at least 60 s.
