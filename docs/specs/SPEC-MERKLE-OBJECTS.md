---
spec: SPEC-MERKLE-OBJECTS
version: 2
status: stable-normative
audience: implementers of compatible mkit object stores
---

# SPEC-MERKLE-OBJECTS &mdash; merkelized Tree and ChunkedBlob identity

Status: **Normative** for mkit v1.
Scope: the Binary Merkle Tree construction used to compute `Tree` and
`ChunkedBlob` object ids.

mkit content-addresses two object types &mdash; `Tree` and `ChunkedBlob` &mdash; by a
**Binary Merkle Tree (BMT) root** rather than by `BLAKE3` of their
serialized bytes. Every other object type (`Blob`, `Commit`, `Remix`,
`Tag`) keeps the flat scheme of [SPEC-OBJECTS](SPEC-OBJECTS.md) §10
(`id = BLAKE3(canonical bytes)`).

Addressing a chunked file or a directory by its Merkle root makes the
inclusion of any chunk or entry provable, and turns a reconstructed
object's read-time id check into a free completeness proof for its whole
child set: if the root matches, every child is present and correctly
ordered.

This is a **breaking** change relative to the all-flat-hash scheme; it is
not byte-compatible with pre-merkle repositories. See §7.

## 1. Primitive

The Merkle primitive is a **stateless Binary Merkle Tree** built with the
canonical `BLAKE3` hasher, identical in construction to
`commonware_storage::bmt` (the Commonware house primitive; mkit vendors
the identical construction over the `blake3` crate so object identity has
no `std`/`zstd` dependency and compiles to `wasm32` &mdash; a native test
cross-verifies the two roots byte-for-byte).

BMT is chosen over the MMR family because an object's child set is **fixed
and known up front**, so the append-only / range-proof properties of an
MMR add no value &mdash; the same reasoning the Commonware/makechain
`transactions_root` commitment uses.

### 1.1 Construction

Given an ordered list of **leaf digests** `L[0..N]`:

1. **Position-hash** each leaf: `node[i] = BLAKE3(be32(i) ‖ L[i])`.
   An empty list (`N = 0`) starts from a single node `BLAKE3("")`.
2. **Fold** level by level: each parent is `BLAKE3(left ‖ right)`; if a
   level has an odd node count, the last node is duplicated
   (`BLAKE3(left ‖ left)`).
3. **Finalize**: `tree_root = BLAKE3(be32(N) ‖ level0_or_folded_root)`.
   Binding `N` defeats the odd-node-duplication malleability (a length-`N`
   tree can never collide with a length-`N+1` tree whose last leaf was
   duplicated).

All integers are big-endian, matching commonware.

## 2. Identity

A merkelized object's id is the **domain-bound** BMT root:

```
id = domain_digest(TYPE_DOMAIN, tree_root)
```

where `domain_digest(d, b) = BLAKE3(le16(len(d)) ‖ d ‖ b)` (SPEC-OBJECTS
§9 / `hash::domain_digest`) and:

| Type        | `TYPE_DOMAIN`        |
|-------------|----------------------|
| ChunkedBlob | `b"mkit.chunked\x00"` |
| Tree        | `b"mkit.tree\x00"`    |

The outer domain wrap makes the id **type-distinct**. A bare BMT root over
identical leaf streams would collide across types (the prologue type byte
is not part of the root), so an empty `Tree` and an empty `ChunkedBlob`,
or a 1-entry `Tree` and a 1-chunk `ChunkedBlob` carrying the same child
hash, would otherwise share an id. The wrap costs one `BLAKE3` over 32
bytes.

## 3. Leaf schemes

### 3.1 ChunkedBlob

`ChunkedBlob { total_size: u64, chunk_size: u32, chunks: [Hash; N] }`.
Leaves, in order:

```
L[0]        = domain_digest(b"mkit-cblob-meta-v1", le64(total_size) ‖ le32(chunk_size))
L[1..=N]    = chunks[0], chunks[1], ..., chunks[N-1]   (raw 32-byte chunk ids)
```

- Chunk `i` is at BMT **position `i + 1`** &mdash; position 0 is the metadata
  leaf. Inclusion-proof builders apply this `+1` offset.
- The metadata leaf binds `total_size` and `chunk_size`, neither of which
  is derivable from the chunk list; without it they could be forged (a
  second-preimage hole).

### 3.2 Tree

`Tree { entries: [TreeEntry{ name, mode, object_hash }; M] }`, entries in
the existing lex-by-name canonical order (SPEC-OBJECTS §4). One leaf per
entry:

```
L[i] = domain_digest(b"mkit-tree-entry-v1", le32(len(name)) ‖ name ‖ u8(mode) ‖ object_hash)
```

- The `le32(len(name))` prefix is the anti-ambiguity guard so
  `("ab", m, h)` and `("a", m, "b"‖h…)` cannot alias.
- The leaf binds the full `(name, mode, object_hash)` triple, so a Tree
  inclusion proof attests the entire entry, not just "this child hash
  appears at position `i`".

## 4. Empty objects

The empty `Tree` (`entries = []`, common) has the fixed id
`domain_digest(b"mkit.tree\x00", BLAKE3(be32(0) ‖ BLAKE3("")))`. This
constant is pinned from a real computation (`merkle::TREE_EMPTY_ID`),
never transcribed by hand. The empty `ChunkedBlob` (`N = 0`, a meta-only
1-leaf tree) is well-defined but not produced in practice.

## 5. Inclusion proofs

Status: **stable**. Wire bytes and sibling selection are pinned to
§5.7's upstream train and to the golden vectors in §5.6; this section no
longer carries the "provisional" carve-out earlier revisions of this
document used, and the wire format is a breaking change from that
provisional iteration (§5.8). Object identity (§2) was already stable and
is unaffected.

### 5.1 Proof struct

A `Proof` for one or more leaves is:

```
Proof {
  leaf_count: u32,
  siblings:   [Hash],   // deduplicated sibling digests, see §5.3
}
```

`leaf_count` is the object's leaf count at proof-build time. It is bound
into the finalized root (§1.1 step 3), so a proof built against one tree
size cannot be replayed against a differently-sized one even if the
sibling digests happened to coincide.

### 5.2 Wire bytes

```
proof_bytes = be32(leaf_count) ‖ varint(len(siblings)) ‖ siblings[0] ‖ siblings[1] ‖ … ‖ siblings[n-1]
```

- `leaf_count` is a **big-endian** `u32` — an exception, matching the
  big-endian integers §1.1 already feeds the hasher (SPEC-CONVENTIONS
  §3's little-endian default governs *this* wire encoding, not the
  hash-input bytes §1.1 specifies separately).
- The sibling count is an unsigned LEB128 variable-length integer
  (`varint`), the same length-prefix convention used elsewhere in this
  corpus for a variable-length list.
- Each sibling is a raw 32-byte digest with no per-element length prefix
  (a fixed-size field).

A decoder MUST bound allocation *before* reading any sibling digest.
Given `max_items` — the number of leaf positions the caller is about to
verify (1 for a single-leaf proof, the range length for a range proof,
the position count for a multi-proof) — the decoded sibling count MUST be
rejected if it exceeds `max_items * MAX_LEVELS`, where `MAX_LEVELS = 32`
(`u32::BITS`: a tree can have at most `u32::MAX` leaves, which needs at
most `u32::BITS` sibling levels per proven item). Trailing bytes after
the declared sibling list MUST be rejected.

### 5.3 Sibling selection

Siblings are collected **level-major, bottom-up** — level 0 is the
position-hashed leaves of §1.1 step 1, and the last level folded before
finalization is level `levels_in_tree(leaf_count) - 1` — and, within a
level, **by ascending index**. For the set of positions `P` being proven
at a given level (starting from the leaf positions and halving each
level, per below):

- for each `p ∈ P`, its sibling index at this level is `p + 1` when `p`
  is even and `p + 1` is a real node (`p + 1 < level_size`); `p` itself
  when `p` is even and `p + 1 >= level_size` (the odd trailing node,
  whose "sibling" is its own duplicate); otherwise (`p` odd) `p - 1`;
- the sibling is **omitted** from the wire when it would be the node's
  own duplicate (`sibling_index == p`), or when `sibling_index` is
  itself already in `P` (its digest is being independently reconstructed
  by the same proof, so re-sending it is redundant);
- `P` then advances to the next level as the deduplicated set
  `{p / 2 : p ∈ P}`, and `level_size` becomes `ceil(level_size / 2)`.

A verifier reconstructs an omitted self-duplicate as `H(computed,
computed)` without consuming a proof entry, and reconstructs an omitted
already-proven sibling from the other branch of the same range/multi
proof rather than from the wire.

`levels_in_tree(leaf_count) = 32 - leading_zeros(leaf_count.saturating_sub(1)) + 1`
for `leaf_count >= 1` (so a 1-leaf tree has 1 level and its only
position needs zero siblings — `rust/tests/golden/proofs/tree_1entry_pos0.*`
pins this case).

### 5.4 Verification

**Single-leaf**: given `leaf`, `position`, and a `Proof`, a verifier
position-hashes `leaf` (§1.1 step 1), then folds up through `siblings` in
level-major order — at each level, an even `position` combines as
`H(computed, sibling)`, an odd `position` as `H(sibling, computed)`, and
the odd-trailing case (§5.3) as `H(computed, computed)` without
consuming a sibling — halving `position` and `level_size` at each step,
then finalizes as `H(be32(leaf_count) ‖ folded)` (§1.1 step 3). Every
sibling in the proof MUST be consumed exactly once; a proof with too few
or too many siblings for the claimed `leaf_count`/position MUST be
rejected.

**Range and multi-leaf**: a range proof (a contiguous `start..=end`) and
a multi-leaf proof (an arbitrary position set — sorted internally; a
repeated position MUST be rejected) fold every proven leaf up
level-by-level together, consuming exactly the siblings §5.3 selected —
reusing an already-computed digest from elsewhere in the same proof
wherever §5.3 omitted it as already-proven, rather than expecting it on
the wire.

**A proof over zero positions MUST be rejected**, regardless of
`leaf_count` — including against the empty `Tree`'s id (§4) with the
all-default proof (`leaf_count: 0, siblings: []`). Nothing about a
zero-length entries/chunks slice constitutes a proof of anything, so a
verifier MUST NOT special-case it into a vacuous success; a builder
given zero positions MUST likewise refuse to construct a proof rather
than emit one. `merkle::tests::verify_rejects_empty_element_set` pins
this (no golden vector: every vector under `rust/tests/golden/proofs/`
proves at least one position by construction).

**Normative — verify against the object id, never the bare root.**
Every verification in this document is stated against the object's
**id**, not the bare (pre-domain-wrap) value §1.1/§2 folds a leaf stream
into. A verifier reconstructs the folded value as above, applies
`id = domain_digest(TYPE_DOMAIN, folded)` for the type it claims to be
proving (§2's table), and compares the result to the id it already
trusts (from a commit, a ref, or another proof) — never to a bare folded
value handed to it separately. Comparing against a bare root instead
discards the very type-distinction §2 exists to provide: whenever two
different objects' folded values coincide at a checked position (nothing
in §1.1's construction rules this out — the type domain is what makes it
matter), a `Tree` proof would verify against a value the caller believed
belonged to a `ChunkedBlob`, or vice versa.
`rust/tests/golden/proofs/neg_id_vs_inner_root.*` pins a rejection vector
for exactly this mistake.

### 5.5 Position semantics

- **Tree**: position = the entry's index in the canonical order of §3.2,
  `0..M`.
- **ChunkedBlob**: position = chunk index **+ 1** (§3.1's offset);
  position 0 is the metadata leaf. It has a structurally valid BMT proof
  like any other leaf, but chunk-proof verification MUST reject position
  0 specifically — it is never a valid proof that a *chunk* exists.
  `rust/tests/golden/proofs/chunked_blob_cs0_3chunks_metapos0_reject.*`
  pins this rejection.

### 5.6 Golden vectors

`rust/tests/golden/proofs/` (SPEC-CONVENTIONS §5) carries the
authoritative pinned bytes, each `<name>.bin` (the encoded `Proof`) paired
with a `<name>.json` sidecar recording the object id to verify against,
the proven position(s)/leaf data, the `max_items` decode bound, and the
expected accept/reject outcome (with a reason for every reject).
`MANIFEST.txt` pins every vector's BLAKE3 digest. The set covers: tree
entry proofs (single-leaf, including the odd-trailing-node case at
several tree sizes; a range proof; a multi-leaf proof; and the real
`tree_single_file` object from `rust/tests/golden/objects/`), chunk
proofs (single-leaf, a range proof, and the metadata-leaf rejection of
§5.5, all against the real `chunked_blob_cs0_3chunks` object), and
negative vectors for a wrong position, a swapped sibling, a truncated
proof, an off-by-one `leaf_count`, an inner-root-vs-id confusion (§5.4),
and a trailing byte after the encoded proof.

### 5.7 Compatibility with commonware

This wire format and sibling-selection algorithm are, deliberately,
byte-identical to the upstream Binary Merkle Tree proof construction that
mkit's BMT primitive already mirrors for root computation (§1), at the
release train mkit currently cross-verifies against (pinned in
`rust/Cargo.toml`'s workspace dependencies). A verifier already built
against that upstream construction can decode an mkit proof with its own
type directly and run its own verification unmodified — but that
verification checks against the **bare folded value**, not the object
id; a caller in that position MUST still apply this section's
`domain_digest(TYPE_DOMAIN, folded)` wrap (§5.4) before comparing to an
id, exactly as an mkit-native verifier does. A native-only cross-check
test in `rust/crates/mkit-core/src/merkle.rs` pins this byte-identity and
cross-acceptance claim across many tree sizes and proof shapes
(single/range/multi), including that a mutated proof is rejected by
both sides.

### 5.8 Change from the prior provisional format

The provisional iteration of this section (`version: 1`) specified a
different, non-commonware-aligned wire format
(`u32 LE leaf_count ‖ u32 LE sibling_count ‖ siblings`) whose sibling
selection always emitted an entry for an odd trailing node — including
its own duplicate, which §5.3 now omits — and whose verification checked
the bare inner root rather than the object id. It had no consumer
(SPEC-TRANSPORT does not transport proofs) and was never wire-compatible
with anything outside this repository, so this is a breaking change with
no migration shim, under SPEC-CONVENTIONS §2.2's "explicitly document a
deliberate breaking change" allowance for a provisional format's first
stabilization. Object identity (§2) and every other golden vector in
this corpus are unaffected.

## 6. Invariants

| Mutation | Detected because |
|---|---|
| any chunk / entry field changed | the leaf digest changes |
| chunk / entry reorder | leaves are position-hashed |
| chunk / entry count changed | the finalized root binds `leaf_count` |
| ChunkedBlob `total_size`/`chunk_size` forged | the position-0 meta leaf changes |
| Tree name/mode/hash boundary ambiguity | the `name_len` prefix in the entry leaf |
| cross-type collision | the `TYPE_DOMAIN` wrap |
| inclusion-proof sibling/position/leaf tampered | the folded value no longer matches (§5.4) |
| inclusion-proof `leaf_count` tampered | the finalize step binds it, same as §1.1 step 3 |
| inclusion proof checked against the wrong object id (bare root, or another type's id) | the `domain_digest(TYPE_DOMAIN, …)` wrap in the comparison (§5.4) |
| inclusion-proof sibling count forged to force large allocation | the `max_items * MAX_LEVELS` decode bound (§5.2) |
| chunk proof of position 0 (the metadata leaf) accepted as a chunk | chunk verification rejects position 0 explicitly (§5.5) |

Roots are deterministic across machines (all length/position fields are
fixed big- or little-endian as specified; no host-endian leakage).

## 7. Compatibility

The serialized **byte layout** of `Tree` and `ChunkedBlob` is unchanged
(SPEC-OBJECTS §4/§7); only the bytes→id function changes, and only for
these two types. `schema_version` therefore stays `0x01`. A repository
written under the all-flat-hash scheme is **not** readable by a
merkle-addressing implementation: every `Tree`/`ChunkedBlob` (and thus
every `Commit` and ref reachable through one) re-addresses. Pre-1.0 there
is no migration; a conformant store MUST refuse to open a repository whose
on-disk format marker does not declare merkle addressing rather than
silently mis-reading it (SPEC-OBJECTS §10).
