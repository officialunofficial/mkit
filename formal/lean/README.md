# mkit Lean models

A Lean 4 package (`mkit_formal`, library `MkitFormal`) of mkit's formal
models. Core Lean 4.23.0 only (no Mathlib). The root `MkitFormal.lean`
imports every model. `lean-toolchain` pins `leanprover/lean4:v4.23.0`. If
elan cannot reach `release.lean-lang.org` but GitHub is reachable, install
the same release from GitHub by hand:

```sh
curl -sSL -o /tmp/lean.tar.zst \
  https://github.com/leanprover/lean4/releases/download/v4.23.0/lean-4.23.0-linux.tar.zst
tar --use-compress-program=unzstd -xf /tmp/lean.tar.zst -C /tmp
mv /tmp/lean-4.23.0-linux ~/.elan/toolchains/leanprover--lean4---v4.23.0
```

Otherwise put an installed 4.23.0 `bin/` first on `PATH` or set
`LAKE=/path/to/lake`.

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
  out-of-range positions are rejected. `verifyChunksMulti_pos0` and
  `verifyChunksRange_pos0`: the §5.5 rule. `reconstructMulti_singleton`: a
  one-element multi-proof verifies exactly like a single-leaf proof, which
  gives `complete_multi_singleton` and `sound_multi_singleton`. General
  multi/range completeness is only checked by bounded `#guard` replays:
  every subset for `n ≤ 9`, every range for `n ≤ 24`, and
  `selRange = selMulti` for `n ≤ 48`.

Non-vacuity. `termHasher` is a free term algebra. It satisfies every
hypothesis (`termHasher_inj`), so `sound_nonvacuous` and `complete_witness`
really apply. `*_needed` shows that each hypothesis is load-bearing: drop
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
