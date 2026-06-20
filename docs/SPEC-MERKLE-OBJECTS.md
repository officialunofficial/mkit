---
title: SPEC-MERKLE-OBJECTS
status: stable
version: 1
audience: implementers of compatible mkit object stores
---

# SPEC-MERKLE-OBJECTS

mkit content-addresses two object types — `Tree` and `ChunkedBlob` — by a
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
no `std`/`zstd` dependency and compiles to `wasm32` — a native test
cross-verifies the two roots byte-for-byte).

BMT is chosen over the MMR family because an object's child set is **fixed
and known up front**, so the append-only / range-proof properties of an
MMR add no value — the same reasoning the Commonware/makechain
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

- Chunk `i` is at BMT **position `i + 1`** — position 0 is the metadata
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

A single-leaf inclusion proof is the leaf count plus the bottom-up sibling
digests. Wire form: `[u32 LE leaf_count][u32 LE n_siblings][n × 32B]`.
Verification position-hashes the supplied leaf, folds up with the
siblings, finalizes with `leaf_count`, and compares to the **bare**
`tree_root` (the pre-domain-wrap root). Proofs are **not** shipped over
the transport (see SPEC-TRANSPORT); they exist for light-client / API use.

## 6. Invariants

| Mutation | Detected because |
|---|---|
| any chunk / entry field changed | the leaf digest changes |
| chunk / entry reorder | leaves are position-hashed |
| chunk / entry count changed | the finalized root binds `leaf_count` |
| ChunkedBlob `total_size`/`chunk_size` forged | the position-0 meta leaf changes |
| Tree name/mode/hash boundary ambiguity | the `name_len` prefix in the entry leaf |
| cross-type collision | the `TYPE_DOMAIN` wrap |

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
