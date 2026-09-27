# mkit Lean models

A Lean 4 package (`mkit_formal`, library `MkitFormal`) of mkit's formal
models. Core Lean only (no Mathlib, no Lake dependencies). The root
`MkitFormal.lean` imports every model. `lean-toolchain` pins
`leanprover/lean4:v4.34.0` (the MKIT-17 tool pin).

## Install and build

Install [elan](https://github.com/leanprover/elan), the Lean toolchain
manager; it reads `lean-toolchain` and fetches 4.34.0 on first use. On macOS:

```sh
brew install elan-init            # or: curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none
elan toolchain install leanprover/lean4:v4.34.0
cd formal/lean
lake build                        # every proof, canary and #guard replay
```

`elan show` in this directory should report `leanprover/lean4:v4.34.0`.
To use a Lean installed some other way, put its `bin/` first on `PATH` or
set `LAKE=/path/to/lake` for the scripts below. The difftest scripts also
need `cargo` (the Rust workspace under `rust/`).

Audit rules: no `sorry`, `admit`, `native_decide` or `axiom` anywhere in
`MkitFormal/` (hash injectivity and the like are explicit hypotheses of the
theorems that need them); `#print axioms` of every theorem shows only
`propext`, `Classical.choice` and `Quot.sound` (`scripts/merkle_axioms.lean`,
`MkitFormal/DeltaAxioms.lean`; the difftest scripts enforce both).

## Merkle objects (MKIT-24)

This part models [SPEC-MERKLE-OBJECTS](../../docs/specs/SPEC-MERKLE-OBJECTS.md)
v2 and is aligned with `rust/crates/mkit-core/src/merkle.rs`.

| File | Contents |
|---|---|
| `MkitFormal/MerkleModel.lean` | Executable model over an abstract `Hasher`: §1.1 construction, §2 id wrap, §4 empty objects, §5.1 `Proof`, §5.3 sibling selection (`selPath` for one position, `selMulti` for several, `selRange` for a range), §5.4 single-leaf, multi-leaf and range verification, §5.5 chunk position-0 rules. |
| `MkitFormal/MerkleProofs.lean` | Theorems for every `n` and `i < n`. |
| `MkitFormal/MerkleCanaries.lean` | Non-vacuity witnesses, mutants, and bounded `#guard` replays. |
| `MkitFormal/MerkleDifftest.lean` | `lake exe merkle_difftest`: replays Rust-exported vectors through the model. |
| `scripts/difftest-merkle.sh` | Reruns everything (build, axiom audit, Rust export, difftest, canaries). |
| `scripts/merkle_axioms.lean` | `#print axioms` for each theorem. |

Theorems. The injectivity assumptions are the hypotheses `NodeInj`,
`LeafInj`, `FinInj` and `WrapInj`. None of them is an axiom.

- **Completeness.** `complete`, `complete_id` and `complete_chunk`: the proof
  generated for leaf `i` of `n` verifies against the root, against the id,
  and as a chunk proof for `i ≥ 1`.
- **Soundness and binding.** `sound` and `sound_id`: a proof that verifies
  for `(i, x)` forces all of the following:
  - the proof's `leaf_count` equals `n`;
  - `i < n`;
  - `x = leaves[i]`;
  - the claimed kind is correct.

  `unique_proof`: the siblings are exactly the generated ones.
  `cross_kind_rejected`: a proof never verifies against another kind's id
  (§2). `empty_tree_no_proof`: nothing verifies against an empty tree (§4).
  `chunk_pos0_rejected`: a chunk proof at position 0 is rejected (§5.5).
- **Exact sibling consumption (§5.4).** `accepted_length`,
  `extra_sibling_rejected` and `dropped_sibling_rejected`.
- **Counts and bounds (§5.2, §5.3).** `halvings_eq_levelsInTree`: the
  verifier's loop and `levels_in_tree - 1` agree.
  `proof_length_le_maxLevels`: a proof has at most `levels_in_tree(n) - 1`
  siblings, and that is at most 32 for `n ≤ 2^32`. `selPath_bounds`: each
  sibling is a real node of its level, is not the proven node, and shares
  its parent. `selPath_levels_increasing`: siblings are ordered by level.
  `selMulti_singleton`: the multi-position selection agrees with `selPath`
  on a single position. `prove_eq_sibsAux`: indexing the level table
  (Rust's `levels[l][k]`) gives the same list as the recursive definition.
- **Multi-leaf and range (§5.4).** `reconstructMulti_nil`,
  `reconstructMulti_dup` and `reconstructMulti_oob`: zero, repeated and
  out-of-range positions are rejected. `reconstructRange_nil`,
  `verifyRangeId_nil` and `verifyMultiId_nil`: a proof over zero positions
  (empty range or empty set) never verifies, not even the all-default proof
  against the empty Tree's id (§4/§5.4 "MUST be rejected"). `verifyChunksMulti_pos0` and
  `verifyChunksRange_pos0`: the §5.5 rule. `reconstructMulti_singleton`: a
  one-element multi-proof verifies exactly like a single-leaf proof, which
  gives `complete_multi_singleton` and `sound_multi_singleton`. General
  multi/range completeness is only checked by bounded `#guard` replays:
  every subset for `n ≤ 9`, every range for `n ≤ 24`, and
  `selRange = selMulti` for `n ≤ 48`.

Non-vacuity. `termHasher` is a free term algebra. It satisfies every
hypothesis (`termHasher_inj`), so `sound_nonvacuous` and `complete_witness`
really apply. `vacuous_accepts_empty_tree` shows the zero-position theorems
are load-bearing: a verifier that folds zero positions into `H("")`
accepts the all-default proof against the empty Tree's id. `*_needed` shows that each hypothesis is load-bearing: drop
one and a wrong leaf, a wrong `leaf_count` or a wrong kind verifies.
`mutant_*` shows that the §5.8 provisional selection, a verifier without
the parity swap, and a verifier that consumes a sibling at the odd
trailing node all break completeness or are rejected. Two more `#guard`
mutants cover multi-proofs: a selection that re-sends already-proven
siblings, and a verifier that skips the sort.

Differential test. `rust/crates/mkit-core/tests/formal_merkle_vectors.rs`
is `#[ignore]`d. It exports two sets of cases:

- golden cases: the empty Tree, which checks `TREE_EMPTY_ID` and the §5.4
  all-default zero-position proof; every position for `n ≤ 33`, for both
  kinds; every range for `n ≤ 12`; every position subset for `n ≤ 5`;
- seeded-random cases: sizes at 2^k ± 1 up to 1025, plus uniform sizes up
  to 1100, each with single, multi and range proofs;
- adversarial variants of every proof (`ADV` lines): the §6 tamper rows
  (`leaf_count` ± 1, a dropped, extra, swapped or substituted sibling),
  reversed, repeated and empty position sets, and shifted ranges.

Each case carries the BLAKE3 oracle table. `merkle_difftest` checks:

- roots and ids;
- per proof: `leaf_count`, the `(level, index)` of each sibling (range
  proofs against both `selRange` and `selMulti`), and the sibling digests;
- every verdict (single, multi, range, wrong-position, adversarial),
  including the §5.5 position-0 rules.

The script requires two model mutants (`--mutant`, the §5.8 selection;
`--mutant-verify`, no exact sibling consumption) and two corrupted Rust
verdicts to be detected.

```sh
./scripts/difftest-merkle.sh        # MKIT_FORMAL_SEED=0x.. MKIT_FORMAL_TREES=N to vary
```

Not modelled: the §5.2 wire bytes and decode bound, and the §3 leaf
encodings (they are opaque digests). Multi and range verification are
modelled and difftested, but proved only for the rejection rules and the
singleton case.

Empty-tree range proofs. An earlier review flagged the §5.4 zero-position
rule for range proofs against the empty Tree. Status: resolved and checked.
`merkle::verify_tree_entries_range` sends an empty leaf slice to
`reconstruct_multi_root`, which returns `NoPositions` (with a non-zero
`start` it returns `PositionOutOfRange`; both reject). The model rejects it
too, proved by `verifyRangeId_nil`. The exporter's `golden-empty-tree` case
has two `ADV` lines (`multi -` and `range 0,0`, all-default proof), and Rust
and the model both reject them in the difftest. The builder side is fixed
too (MKIT-56): SPEC-MERKLE-OBJECTS §5.4 requires builders to refuse it, and
`merkle.rs`'s range builder now returns `PositionOutOfRange` for every range
of the empty Tree (Kani harness `merkle_builder_empty_tree_refuses` passes).

## Delta (MKIT-25)

This part models [SPEC-DELTA](../../docs/specs/SPEC-DELTA.md) v1 and is
aligned with `rust/crates/mkit-core/src/delta.rs`.

| File | Contents |
|---|---|
| `MkitFormal/DeltaModel.lean` | Executable model: §2 header, §3 COPY/INSERT encoding (`encode`, `decode`), §4 `apply` (checks in the §4 / `delta::decode` order, with a model-only `oob` error for an unguarded read), §5 writer `encodeWith` over any match oracle, and `encodeRust` (the Rust writer's aligned-block index as an oracle). |
| `MkitFormal/DeltaProofs.lean` | Codec, bounds, soundness, completeness and writer theorems. |
| `MkitFormal/DeltaRunning.lean` | Error kind of decoded streams, the per-opcode running-count bound, and truncation. |
| `MkitFormal/DeltaCanaries.lean` | Non-vacuity: a reader mutant per §4 check (`applyMut`), plus witnesses. |
| `MkitFormal/DeltaDifftest.lean` | `lake exe delta_difftest`: replays Rust-exported vectors through the model. |
| `MkitFormal/DeltaAxioms.lean` | `#print axioms` for each theorem (not part of the library). |
| `scripts/difftest-delta.sh` | Reruns everything (build, axiom audit, Rust export, difftest, canaries). |

Theorems (for every base and every byte string; no hypotheses beyond the
stated premises):

- **Codec (§2, §3).** `decode_encode`: a well-formed delta (`wf`: field
  widths, `COPY` length ≥ 1, `INSERT` 1..127) round-trips.
  `encode_decode`: anything `decode` accepts re-encodes byte-identically, so
  the encoding is canonical and reserved COPY bits never decode.
  `topBit_iff` and `reservedBits_iff` relate the spec's bit tests to the
  model's comparisons.
- **No out-of-bounds read (§8 vector 15, §10).** `apply_ne_oob`: every read
  of the stream and of the base is in bounds.
- **Soundness (§2, §4).** `apply_sound`: an accepted stream decodes, its
  `base_len` is the supplied base's length, every COPY is inside the base,
  and the output is the instructions' semantics with length `result_len`.
  `apply_rejects_copy_oob`, `apply_rejects_len_mismatch`, `apply_ok_length`.
- **Completeness (§4).** `apply_complete`: every stream that decodes,
  targets this base, keeps COPYs inside it and emits exactly `result_len`
  bytes is accepted with that output.
- **Error kind and running count (§2, §8 vector 8, §10).** `apply_decoded`,
  `apply_overrun` and `apply_underrun` show that a decoded in-base stream
  ends in exactly one of three ways. It is accepted, or rejected with
  `ResultLenOverrun` as soon as the output would pass `result_len`, or
  rejected with `ResultLenUnderrun` at end of stream. `runT_fst` and
  `runT_bounded` (via `apply_running_le`) show that the emitted-byte count
  at every loop iteration is ≤ `result_len`.
- **Truncation (§2, §10).** `apply_prefix`: every proper prefix of an
  accepted stream is rejected, as `UnexpectedEof` or as
  `ResultLenUnderrun`.
- **Writer (§5).** `apply_encodeWith`: for any match oracle, the greedy
  writer's stream is well-formed and reconstructs the target. This holds for
  bases and targets under 2^32 bytes. `apply_encodeInsertOnly` covers the
  all-INSERT writer and `apply_encodeRust` the Rust writer's oracle.

Non-vacuity (`DeltaCanaries`). Each reader mutant drops one §4 check, and a
concrete stream then falsifies the matching theorem:

- `noInsertEof_reads_oob` and `noCopyBound_reads_oob` falsify
  `apply_ne_oob`;
- `noFinalLen_accepts_short` falsifies `apply_ok_length`, and
  `noFinalLen_accepts_prefix` falsifies `apply_prefix`;
- `noBaseLen_accepts` falsifies the `base_len` conjunct of `apply_sound`;
- `overrun_kind_only` with `apply_overrun_sLong` falsifies `apply_overrun`,
  and `runT_noOverrun_exceeds` falsifies `runT_bounded`.

`decode_encode_needs_wf` and `decode_encode_needs_wf'` show that `wf` is
needed. `decodeLax_not_canonical` shows that canonicity needs the
reserved-bit check. `trusting_roundtrip_fails` shows that the writer's
byte re-verification is needed.

Differential test. `rust/crates/mkit-core/tests/formal_delta_vectors.rs` is
`#[ignore]`d. It exports golden and seeded-random base/target pairs:

- the Rust writer's stream;
- `A` lines, each a stream (the writer's, or a mutated or malformed one)
  with Rust's `delta::decode` verdict.

`delta_difftest` requires the model to agree on acceptance, output bytes and
error kind for every `A` line. It also checks that the writer's stream
decodes, re-encodes byte-identically and equals `encodeRust`. The script
requires each of the five `--mutant` readers and one corrupted Rust verdict
to be detected.

```sh
./scripts/difftest-delta.sh   # MKIT_FORMAL_SEED=0x.. MKIT_FORMAL_DELTA_CASES=N to vary
```

Findings against the spec:

- §10 says truncation is distinguishable from corruption. That holds only
  for a cut inside an instruction. A cut at an instruction boundary is
  reported as `DeltaCorrupt(ResultLenUnderrun)`, not as `UnexpectedEof`
  (`boundary_cut_is_underrun`); `apply_prefix` states exactly what holds.
- §2 and §4 order the checks as version first, then length. The Rust
  reader, and this model, return `UnexpectedEof` for any stream shorter than
  9 bytes, even when its version byte is not `0x01`.

Not modelled: the §4 capacity hint (implementation guidance); the §7
1 GiB `result_len` cap (enforced outside `delta.rs`); `usize` overflow
(the model uses unbounded `Nat`, and Rust uses checked addition);
`DeltaLengthOverflow` in `encode` (§8 vector 13).
