# mkit Kani harnesses

Bounded model checking of mkit's untrusted-input decoders with
[Kani](https://github.com/model-checking/kani) (pin: **Kani 0.68.0**,
CBMC 6.11.0, MKIT-17). The harnesses live next to the code they check,
in `#[cfg(kani)] mod kani_proofs` blocks:

| File | Spec |
|---|---|
| `rust/crates/mkit-core/src/delta.rs` | SPEC-DELTA §2, §4 |
| `rust/crates/mkit-core/src/merkle.rs` | SPEC-MERKLE-OBJECTS §1.1, §2, §5.2–§5.5 |
| `rust/crates/mkit-core/src/pack.rs` | SPEC-PACKFILE §1–§3, §6, §8, §11 |
| `rust/crates/mkit-core/src/serialize.rs` | SPEC-OBJECTS §2–§8, §4.1, §11 |
| `rust/crates/mkit-keystore/src/encrypted_record.rs` | SPEC-KEYSTORE §6.1.1 |
| `rust/crates/mkit-rpc/src/framing.rs` | SPEC-RPC §1 (wire framing, `MAX_FRAME_BYTES`) |

Every result below is **bounded**: a harness checks every input up to the
stated size (every byte symbolic unless said otherwise), not every input.
Nothing here is a proof for unbounded inputs; the fuzz targets
(`docs/FUZZ.md`) and proptests cover larger inputs by sampling.

## Running

```sh
cargo install --locked kani-verifier --version 0.68.0 && cargo kani setup
cd rust

# mkit-core: always --no-default-features (with the default `pack-zstd`
# feature the C zstd dependency is linked in and CBMC ran out of memory on
# most harnesses). -Z stubbing is needed by every harness that uses
# #[kani::stub] (harmless for the others).
cargo kani -p mkit-core --no-default-features -Z stubbing --harness delta_decode_no_panic

# merkle_verify_*, merkle_roundtrip_*, merkle_canary_*, pack_*: add the
# 32-byte digest/trailer comparison bound
cargo kani -p mkit-core --no-default-features -Z stubbing \
  --harness pack_entries_one_frame \
  -Z unstable-options --cbmc-args --unwindset memcmp.0:33

cargo kani -p mkit-keystore -Z stubbing --harness software_key_record_roundtrip
cargo kani -p mkit-rpc --harness rpc_read_frame_no_panic
```

Run **one harness at a time** (`--harness` is a substring match; every
name below is unique as a substring except where noted). Peak CBMC memory
was ~5.4 GB (`pack_window_cursor_decode`); most harnesses stay under 2 GB.

**Expected-outcome convention** (same as the Quint `check.sh` scripts):
a `*_canary_*` harness is `#[kani::should_panic]` and must report
`VERIFICATION:- SUCCESSFUL (encountered one or more panics as expected)`:
the checker has falsified a deliberately wrong statement, which shows the
property it mirrors is checkable at that bound. Every other harness must
report `VERIFICATION:- SUCCESSFUL`, except the two marked **FINDING**
below, which fail on purpose until the production code is fixed.
`kani::cover!` sites must be `satisfied` (Kani prints `N of N cover
properties satisfied`); they show the asserted `Ok` paths are reachable.

## Results (2026-09-26, macOS arm64, 15 cores, shared with other jobs)

Time is wall-clock per `cargo kani` invocation including the (cached)
build. Cap: 15 min per harness.

### mkit-core: delta (`--no-default-features -Z stubbing`)

| Harness | Property | Bound | Result | Time |
|---|---|---|---|---|
| `delta_decode_no_panic` | `decode` never panics/overflows/reads OOB; `Ok` output length = header `result_len` (§2) | base ≤ 4 B, stream ≤ 20 B, unwind 7 | pass, 3/3 covers | 51 s |
| `delta_spec_header` | `decode` = §4 reference algorithm (bytes or error class) | base ≤ 3 B, stream 8 and 9 B | pass | 5 s |
| `delta_spec_insert` | as above | stream 10 and 11 B | pass, 1/1 cover | 450 s |
| `delta_spec_copy` | as above | stream 16 B (header + one COPY) | pass, 1/1 cover | 199 s |
| `delta_decode_canary_wrong_length` | canary: "output is one byte longer than declared" | stream ≤ 20 B | falsified (expected) | 51 s |
| `delta_encode_decode_roundtrip` | `decode(b, encode(b, r)) == r` | `b`, `r` ≤ 3 B each (INSERT-only writer path) | pass | 37 s |

### mkit-core: serialize

| Harness | Property | Bound | Result | Time |
|---|---|---|---|---|
| `serialize_prologue_no_panic` | prologue/dispatch/§11 trailing rule never panic, per-type readers stubbed nondeterministically | input ≤ 12 B | pass, 1/1 cover | 89 s |
| `serialize_read_other_types_no_panic` | blob/commit/remix/tag/chunked/delta readers never panic | body ≤ 12 B | pass, 1/1 cover | 125 s |
| `serialize_read_tree_one_entry` | `read_tree` in bounds; `Ok` ⇒ 1 entry matching the wire `name_len`/hash (§4.1 stubbed) | 42-B body, count pinned to 1 | pass, 1/1 cover | 33 s |
| `serialize_validate_name_matches_spec` | `TreeEntry::validate_name` = §4.1 model | names ≤ 6 B | pass, 1/1 cover | 25 s |
| `serialize_blob_roundtrip` | `deserialize(serialize(blob)) == blob` | blob ≤ 4 B | pass | 95 s |
| `serialize_canary_trailing_byte_accepted` | canary: "one trailing byte still deserializes" | 1-B blob + 1 B | falsified (expected) | 40 s |

### mkit-core: merkle (BLAKE3 stubbed by a deterministic mixer)

| Harness | Property | Bound | Result | Time |
|---|---|---|---|---|
| `merkle_proof_decode_no_panic` | `Proof::decode(_, 1)` never panics and rejects all | input 0–4 B | pass (its covers are `Ok` sites, unreachable by design at < 5 B) | 49 s |
| `merkle_proof_decode_empty_proof` | accepts exactly `be32(n) ‖ varint(0)` (§5.2) | 5 B | pass, 1/1 cover | 11 s |
| `merkle_proof_decode_one_sibling` | 1-sibling proof decodes to the wire count/digest | 37 B, varint pinned to 1 | pass | 5 s |
| `merkle_verify_s0` | fold succeeds iff `pos < leaf_count` and sibling count = §5.3; chunk pos 0 rejected (§5.5) | 0 siblings, any `u32` leaf count/position, unwind 34 | pass | 92 s |
| `merkle_verify_s1` | as above | 1 sibling, leaf count ≤ 8 | pass, 1/1 cover | 19 s |
| `merkle_verify_s2` | as above | 2 siblings, leaf count ≤ 8 | pass, 1/1 cover | 23 s |
| `merkle_roundtrip_one_chunk` | independent §1.1/§5.3 builder's proof accepted by `verify_chunk` | 1 symbolic chunk | pass | 11 s |
| `merkle_roundtrip_two_chunks` | as above, both positions | 2 symbolic chunks | pass | 26 s |
| `merkle_canary_tampered_leaf_verifies` | canary: "any leaf verifies under a genuine proof" | 2 chunks | falsified (expected) | 15 s |
| `merkle_builder_empty_tree_refuses` | **new**: §5.4 builder rule (added on this branch): every single-leaf, multi-leaf and range request against the empty `Tree` is refused | any `u32` position/start/end | **FAILS — FINDING 1** (counterexample `start = end = 0`), 1/1 cover | 7 s |

### mkit-core: pack (BLAKE3 → `toy_hash`, zstd decompression stubbed)

| Harness | Property | Bound | Result | Time |
|---|---|---|---|---|
| `pack_entries_one_frame` | `PackEntries::new` + iteration never panic; on `Ok`: magic/version (§1), trailer (§8), v1 yields exactly `entry_count` items ending at the trailer (§3, §6), payload ranges inside the entry area (§2), raw-only ⇒ no delta | 5-B entry area, header/trailer symbolic | pass | 273 s |
| `pack_entries_two_entries` | as above | 10-B entry area | pass | 267 s |
| `pack_writer_roundtrip_raw` | `PackWriter` → `PackEntries` round-trip, v1 | one 1-B raw entry | pass | 144 s |
| `pack_canary_mutation_still_parses` | canary: "every 1-byte mutation of a valid pack still parses" | 2-B raw pack | falsified (expected) | 34 s |
| `pack_window_cursor_decode` | **new**: windowed reader's resumable cursor decoder (`WindowCursor::from_bytes`, §11) never panics/overflows/reads OOB on a checksum-valid encoding with every numeric field and digest symbolic | 125-B body, layout A (anchor + prefix digests, no first-non-raw, empty trees) | pass, 1/1 cover (acceptance reachable) | 636 s |
| `pack_window_cursor_flip_rejected` | **new**: a concrete valid cursor decodes iff unmodified; every nonzero XOR of its `pack_len` low byte is rejected | 256 masks | pass | 589 s |
| `pack_window_cursor_canary_flip_accepted` | canary: "a flipped `pack_len` byte still decodes" | 255 masks | falsified (expected) | 520 s |

### mkit-keystore (`-Z stubbing`; `format!` and `from_utf8` stubbed)

| Harness | Property | Bound | Result | Time |
|---|---|---|---|---|
| `software_key_record_decode_len_0` | `decode` never panics; input rejected | 0 B | pass | 62 s |
| `software_key_record_decode_len_1_2` | as above | 1, 2 B | pass | 135 s |
| `software_key_record_decode_len_3_4` | as above | 3, 4 B | pass | 131 s |
| `software_key_record_decode_len_5_6` | as above | 5, 6 B | pass | 127 s |
| `software_key_record_decode_len_7` | as above | 7 B | pass | 59 s |
| `software_key_record_decode_magic_no_panic` | as above | 8, 9 B | pass | 134 s |
| `software_key_record_decode_header_no_panic` | as above | 10, 11 B | pass | 119 s |
| `software_key_record_decode_15b_no_panic` | as above | 15 B | pass | 58 s |
| `software_key_record_roundtrip` | `decode(encode(r)) == r` | empty variable fields, any algorithm 1–3, attrs, nonce | pass | 27 s |
| `software_key_record_rejects_algorithm_4` | §6.1.1 "MUST reject id `0x04`" | minimal record, symbolic attrs/nonce | pass (default features) | 23 s |
| same, `--features bls-threshold` | as above | as above | **FAILS — FINDING 2** | 45 s |
| `software_key_record_canary_trailing_byte_accepted` | canary: "valid record + 1 trailing byte still decodes" | 59 + 1 B | falsified (expected) | 21 s |

### mkit-rpc

| Harness | Property | Bound | Result | Time |
|---|---|---|---|---|
| `rpc_read_frame_no_panic` | `read_frame` never panics; accepts iff full prefix, in-cap length and full body; `BodyTruncated.actual` is the true count | streams ≤ 6 B, opaque message | pass | 17 s |
| `rpc_canary_over_cap_length_accepted` | canary: "an over-cap length prefix is accepted" | 4-B prefix | falsified (expected) | 6 s |

## Findings

1. **SPEC-MERKLE-OBJECTS §5.4 builder rule vs `BmtTree::range_proof`.**
   The spec now says a builder asked for position 0 of an empty `Tree`,
   "including the range `0..=0`, MUST refuse rather than return the
   all-default proof". `merkle.rs` `BmtTree::range_proof` still has
   `if self.empty { if start == 0 && end == 0 { return Ok(Proof::default()); } ... }`,
   so `build_tree_entries_range_proof(&Tree { entries: vec![] }, 0, 0)`
   returns `Ok(Proof { leaf_count: 0, siblings: [] })`.
   `merkle_builder_empty_tree_refuses` reports this counterexample
   (`start = 0, end = 0`; the single-leaf and multi-leaf builders refuse
   correctly). Production code was left unchanged; the harness passes
   once the builder refuses.
2. **SPEC-KEYSTORE §6.1.1 algorithm id `0x04` under `bls-threshold`.**
   The spec says a `MKITKSV1` decoder MUST reject id `0x04`.
   `algorithm_from_id` maps `4 => Algorithm::Bls12381Threshold` when the
   `bls-threshold` feature is on, so `EncryptedKeyRecord::decode` accepts
   such a record; rejection only happens later, in `decrypt`'s plaintext
   length check. `software_key_record_rejects_algorithm_4` holds in the
   default build and fails with `--features bls-threshold`.

## Dropped or narrowed (did not finish within 15 min)

- `WindowCursor` decoding with every body byte symbolic (125 B): symbolic
  option tags or tree depths make CBMC explore every layout after them.
  The harnesses fix the layout (tag and depth bytes) and keep every value
  symbolic. Invalid-tag and invalid-depth rejection is not covered here.
- A second layout (pack-id-bound cursor with a first-non-raw index), and
  the canonical re-encoding check (`to_bytes(from_bytes(b)) == b`):
  both timed out (900 s). Each `from_bytes` call costs ~7 min of symbolic
  execution (~6.8M steps), and a harness with two calls did not finish.
- `PackReader::read` (needs an on-disk `ObjectStore`), builder-side
  `build_chunk_proof` / `compute_chunked_id`, buffa message decoding in
  `read_frame`, non-empty keystore round-trip fields, and multi-entry
  trees: see the doc comments on each module. They are left to the fuzz
  targets and proptests.
- The §3.3 writer rule added on this branch ("a writer MUST NOT emit a
  `0x03`/`0x04` entry whose `uncompressed_len` would exceed
  `MAX_RAW_OBJECT_SIZE`") is enforced in `maybe_compress_capped`, behind
  the `pack-zstd` C compressor that Kani cannot model. It is not
  model-checked. `append_raw_frame` itself does not re-check the claim
  against the cap; it relies on `maybe_compress`.

## Harness fixes in this pass

- Every stub-using harness needs `-Z stubbing` under Kani 0.68 (the
  earlier runs did not document it). Without it compilation fails with
  "Using the stub attribute requires activating the unstable `stubbing`
  feature".
- `encrypted_record.rs`: `#[allow(invalid_from_utf8)]` on the `from_utf8`
  stub, which builds its error value from a known-invalid literal.
