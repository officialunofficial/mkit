//! Merkle (BMT) content-addressing for `ChunkedBlob` and `Tree`.
//!
//! A merkelized object's content-address **is** its Binary Merkle Tree
//! root: the object id is `domain_digest(TYPE_DOMAIN, bmt_root(leaves))`
//! where the BMT is built over the object's child stream. This makes
//! inclusion of any chunk/entry provable, and makes a reconstructed
//! object's read-time id check a free completeness proof for its whole
//! child set.
//!
//! ## Primitive — a vendored BMT, byte-identical to `commonware_storage::bmt`
//!
//! The house idiom (makechain `transactions_root.rs`) uses
//! `commonware_storage::bmt`. We do **not** depend on it for object identity:
//! `merkle.rs` lives in `mkit-core` and `Object::id` calls it, so this module
//! must compile to `wasm32` for `mkit-core` *itself* to — independent of any
//! wasm caller. At the pinned `commonware =2026.5.0`, `bmt` is gated behind
//! `commonware-storage/std`, which unconditionally pulls `zstd-sys` (a C
//! library with no `wasm32-unknown-unknown` target). Instead this module
//! vendors the *identical* BMT construction over the `blake3` crate (already a
//! mkit dependency, wasm-clean). A native-only test
//! (`tests::vendored_root_matches_commonware`) cross-verifies the vendored
//! root byte-for-byte against `commonware_storage::bmt`, so the two never
//! drift.
//!
//! TODO(commonware#4089): the upstream PR commonwarexyz/monorepo#4090 makes
//! `bmt` `no_std` (it has no real `std` dependency — only an incidental
//! `commonware-runtime` re-export of `bytes::{Buf, BufMut}`). Once that
//! releases, this vendored copy can be dropped for a direct
//! `commonware-storage` dependency; the cross-check test already pins equality.
//!
//! The construction (matching commonware):
//! * leaf at index `i` is hashed with its position: `H(i_be32 ‖ leaf)`;
//! * each level pairs nodes `H(left ‖ right)`, duplicating the last node
//!   `H(left ‖ left)` when a level has an odd count;
//! * an empty tree is a single node `H("")`;
//! * the finalized root is `H(leaf_count_be32 ‖ tree_root)`, which binds
//!   the leaf count and defeats the odd-node-duplication malleability.
//!
//! Normative crypto: `docs/specs/SPEC-MERKLE-OBJECTS.md`.
//!
//! ## Identity formulas
//!
//! ```text
//! id            = domain_digest(TYPE_DOMAIN, bmt_root(leaves))
//!
//! ChunkedBlob   leaves = [meta_leaf] ++ chunks
//!   meta_leaf   = domain_digest("mkit-cblob-meta-v1", total_size_le ‖ chunk_size_le)
//!   chunk i     -> BMT position i+1   (meta is position 0)
//!
//! Tree          leaves = entries (existing lex order)
//!   entry leaf  = domain_digest("mkit-tree-entry-v1", name_len_le ‖ name ‖ mode ‖ object_hash)
//! ```
//!
//! The outer `domain_digest` wrap makes the id type-distinct: a bare BMT
//! root over identical leaf streams would collide across types (the
//! prologue type byte is not in the root), so an empty `Tree` and an empty
//! `ChunkedBlob`, or a 1-entry `Tree` and a 1-chunk `ChunkedBlob` with the
//! same child hash, would otherwise share an id.
//!
//! ## Provisional — inclusion proofs
//!
//! Object identity (`compute_tree_id` / `compute_chunked_id`) is stable and on
//! the hot path. The inclusion-proof API — `build_`/`verify_chunk_inclusion_proof`,
//! `build_`/`verify_tree_inclusion_proof`, and the proof wire format
//! `[leaf_count_le:u32][n:u32][n × 32B sibling]` (`docs/specs/SPEC-MERKLE-OBJECTS.md`
//! §5) — is **provisional**. It is foundation for a future light-client / API
//! consumer and has no in-tree reader yet; proofs are **not** transported
//! today. The construction is tested and fuzzed, but the wire format may change
//! incompatibly before its first consumer pins it — do not treat it as stable.

use crate::hash::{HASH_LEN, Hash, Hasher, domain_digest, hash};
use crate::object::{ChunkedBlob, Tree, TreeEntry};

/// Type domain for the outer identity wrap of a `ChunkedBlob`.
const CHUNKED_TYPE_DOMAIN: &[u8] = b"mkit.chunked\x00";
/// Type domain for the outer identity wrap of a `Tree`.
const TREE_TYPE_DOMAIN: &[u8] = b"mkit.tree\x00";
/// Leaf domain binding a `ChunkedBlob`'s `total_size`/`chunk_size`.
const CBLOB_META_DOMAIN: &[u8] = b"mkit-cblob-meta-v1";
/// Leaf domain for a `Tree` entry's `(name, mode, object_hash)` triple.
const TREE_ENTRY_DOMAIN: &[u8] = b"mkit-tree-entry-v1";

/// Errors building or verifying a merkle inclusion proof.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MerkleError {
    /// The requested leaf position is outside the object's leaf range.
    #[error("merkle position {0} is out of range")]
    PositionOutOfRange(u32),
    /// The proof bytes were malformed.
    #[error("merkle proof is malformed")]
    MalformedProof,
    /// The proof did not verify against the given root/leaf/position.
    #[error("merkle proof verification failed")]
    VerificationFailed,
}

// ---------------------------------------------------------------------------
// Vendored BMT primitive (over `blake3`)
// ---------------------------------------------------------------------------

/// Leaf/index count as `u32`. Objects are decode-capped at 1M
/// entries/chunks (see `serialize.rs`), far below `u32::MAX`, so this
/// only panics on a programmer error that bypassed those caps.
fn u32_of(n: usize) -> u32 {
    u32::try_from(n).expect("merkle leaf/index count fits u32 (objects capped at 1M)")
}

/// `BLAKE3(a ‖ b)`.
fn h2(a: &[u8], b: &[u8]) -> Hash {
    let mut h = Hasher::new();
    h.update(a).update(b);
    h.finalize()
}

/// Position-hash a leaf: `H(index_be32 ‖ leaf)` (matches commonware
/// `Builder::add`).
fn position_leaf(index: u32, leaf: &Hash) -> Hash {
    h2(&index.to_be_bytes(), leaf)
}

/// The finalized BMT root over `leaves` (raw, pre-position-hash digests),
/// identical to `commonware_storage::bmt::Builder::<Blake3>` + `root()`.
fn bmt_root(leaves: &[Hash]) -> Hash {
    let leaf_count = u32_of(leaves.len());
    // Level 0: position-hashed leaves, or a single empty node when there
    // are no leaves.
    let mut level: Vec<Hash> = if leaves.is_empty() {
        vec![hash(b"")]
    } else {
        leaves
            .iter()
            .enumerate()
            .map(|(i, l)| position_leaf(u32_of(i), l))
            .collect()
    };
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = if pair.len() == 2 { &pair[1] } else { &pair[0] };
            next.push(h2(&pair[0], right));
        }
        level = next;
    }
    // Finalize: bind the leaf count (malleability guard).
    h2(&leaf_count.to_be_bytes(), &level[0])
}

/// A single-leaf inclusion proof: the leaf count plus the bottom-up
/// sibling digests. Wire form: `[u32 LE leaf_count][u32 LE n][n*32]`.
fn bmt_prove(leaves: &[Hash], mut idx: usize) -> Result<Vec<u8>, MerkleError> {
    if idx >= leaves.len() {
        return Err(MerkleError::PositionOutOfRange(u32_of(idx)));
    }
    let leaf_count = u32_of(leaves.len());
    let mut level: Vec<Hash> = leaves
        .iter()
        .enumerate()
        .map(|(i, l)| position_leaf(u32_of(i), l))
        .collect();
    let mut siblings: Vec<Hash> = Vec::new();
    while level.len() > 1 {
        let sib = if idx.is_multiple_of(2) {
            // Even index: right sibling, or self when it's the odd last node.
            if idx + 1 < level.len() {
                level[idx + 1]
            } else {
                level[idx]
            }
        } else {
            level[idx - 1]
        };
        siblings.push(sib);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = if pair.len() == 2 { &pair[1] } else { &pair[0] };
            next.push(h2(&pair[0], right));
        }
        idx /= 2;
        level = next;
    }
    let mut out = Vec::with_capacity(8 + siblings.len() * HASH_LEN);
    out.extend_from_slice(&leaf_count.to_le_bytes());
    out.extend_from_slice(&u32_of(siblings.len()).to_le_bytes());
    for s in &siblings {
        out.extend_from_slice(s);
    }
    Ok(out)
}

/// Verify a single-leaf inclusion proof produced by [`bmt_prove`] against
/// `root` (a bare [`bmt_root`], pre domain-wrap).
fn bmt_verify(root: &Hash, leaf: &Hash, position: u32, proof: &[u8]) -> Result<(), MerkleError> {
    if proof.len() < 8 {
        return Err(MerkleError::MalformedProof);
    }
    let leaf_count = u32::from_le_bytes(proof[0..4].try_into().expect("4 bytes"));
    let n = u32::from_le_bytes(proof[4..8].try_into().expect("4 bytes")) as usize;
    if proof.len() != 8 + n * HASH_LEN {
        return Err(MerkleError::MalformedProof);
    }
    if position >= leaf_count {
        return Err(MerkleError::PositionOutOfRange(position));
    }
    let mut acc = position_leaf(position, leaf);
    let mut idx = position as usize;
    for k in 0..n {
        let off = 8 + k * HASH_LEN;
        let sib: Hash = proof[off..off + HASH_LEN].try_into().expect("32 bytes");
        acc = if idx.is_multiple_of(2) {
            h2(&acc, &sib)
        } else {
            h2(&sib, &acc)
        };
        idx /= 2;
    }
    let recomputed = h2(&leaf_count.to_be_bytes(), &acc);
    if &recomputed == root {
        Ok(())
    } else {
        Err(MerkleError::VerificationFailed)
    }
}

// ---------------------------------------------------------------------------
// Leaf digests
// ---------------------------------------------------------------------------

/// The position-0 metadata leaf for a `ChunkedBlob`, binding its
/// `total_size` and `chunk_size` (neither is derivable from the chunk
/// list, so without this they could be forged — a second-preimage hole).
fn chunked_meta_leaf(cb: &ChunkedBlob) -> Hash {
    let mut body = [0u8; 12];
    body[..8].copy_from_slice(&cb.total_size.to_le_bytes());
    body[8..].copy_from_slice(&cb.chunk_size.to_le_bytes());
    domain_digest(CBLOB_META_DOMAIN, &body)
}

/// The leaf digest for one `Tree` entry. The `name_len` u32-LE prefix is
/// the anti-ambiguity guard so `("ab", m, h)` and `("a", m, "b"‖…)` cannot
/// alias. Feeding this triple (not the raw `object_hash`) means a Tree
/// inclusion proof attests the full `(name, mode, object_hash)`.
fn tree_entry_leaf(e: &TreeEntry) -> Hash {
    let mut body = Vec::with_capacity(4 + e.name.len() + 1 + HASH_LEN);
    body.extend_from_slice(&u32_of(e.name.len()).to_le_bytes());
    body.extend_from_slice(&e.name);
    body.push(e.mode as u8);
    body.extend_from_slice(&e.object_hash);
    domain_digest(TREE_ENTRY_DOMAIN, &body)
}

fn chunked_leaves(cb: &ChunkedBlob) -> Vec<Hash> {
    let mut leaves = Vec::with_capacity(1 + cb.chunks.len());
    leaves.push(chunked_meta_leaf(cb));
    leaves.extend_from_slice(&cb.chunks);
    leaves
}

fn tree_leaves(tree: &Tree) -> Vec<Hash> {
    tree.entries.iter().map(tree_entry_leaf).collect()
}

// ---------------------------------------------------------------------------
// Inner roots + identity
// ---------------------------------------------------------------------------

/// Bare (pre-wrap) BMT root over a `ChunkedBlob`'s leaves (`[meta] ++
/// chunks`). Inclusion proofs verify against this.
#[must_use]
pub fn chunked_inner_root(cb: &ChunkedBlob) -> Hash {
    bmt_root(&chunked_leaves(cb))
}

/// Bare (pre-wrap) BMT root over a `Tree`'s entry leaves.
#[must_use]
pub fn tree_inner_root(tree: &Tree) -> Hash {
    bmt_root(&tree_leaves(tree))
}

/// The content-address (object id) of a `ChunkedBlob`.
#[must_use]
pub fn compute_chunked_id(cb: &ChunkedBlob) -> Hash {
    domain_digest(CHUNKED_TYPE_DOMAIN, &chunked_inner_root(cb))
}

/// The content-address (object id) of a `Tree`.
#[must_use]
pub fn compute_tree_id(tree: &Tree) -> Hash {
    domain_digest(TREE_TYPE_DOMAIN, &tree_inner_root(tree))
}

/// The id of the empty `Tree` (`entries = []`) — a real, common object.
/// Pinned from a test run (see `empty_tree_id_matches_constant`); the
/// empty BMT root is `H(leaf_count ‖ H(""))`, NOT `H(0 ‖ 0)`.
pub const TREE_EMPTY_ID: Hash = [
    0x1a, 0xb8, 0xd0, 0x78, 0x8b, 0x29, 0xfe, 0x59, 0x92, 0x01, 0x1e, 0x64, 0xd6, 0xc9, 0x22, 0xec,
    0x93, 0xf4, 0x24, 0x8b, 0x37, 0x55, 0xb9, 0x2b, 0x15, 0xb0, 0x7e, 0x66, 0x4c, 0xb1, 0x56, 0x52,
];

// ---------------------------------------------------------------------------
// Position lookup (mirror makechain `message_index`)
// ---------------------------------------------------------------------------

/// BMT position of `chunk_hash` within `cb`, or `None` if absent. The
/// returned position is the chunk index **+ 1** (the metadata leaf
/// occupies position 0).
#[must_use]
pub fn chunk_position(cb: &ChunkedBlob, chunk_hash: &Hash) -> Option<u32> {
    cb.chunks
        .iter()
        .position(|c| c == chunk_hash)
        .map(|i| u32_of(i + 1))
}

/// BMT position (= entry index) of the entry named `name` within `tree`,
/// or `None` if absent.
#[must_use]
pub fn tree_entry_position(tree: &Tree, name: &[u8]) -> Option<u32> {
    tree.entries.iter().position(|e| e.name == name).map(u32_of)
}

// ---------------------------------------------------------------------------
// Inclusion proofs
// ---------------------------------------------------------------------------

/// Build an inclusion proof that the chunk at `position` (= chunk index +
/// 1, per [`chunk_position`]) belongs to `cb`. Verify against
/// [`chunked_inner_root`].
pub fn build_chunk_inclusion_proof(
    cb: &ChunkedBlob,
    position: u32,
) -> Result<Vec<u8>, MerkleError> {
    bmt_prove(&chunked_leaves(cb), position as usize)
}

/// Verify a chunk inclusion proof from [`build_chunk_inclusion_proof`].
pub fn verify_chunk_inclusion_proof(
    inner_root: &Hash,
    chunk_hash: &Hash,
    position: u32,
    proof: &[u8],
) -> Result<(), MerkleError> {
    bmt_verify(inner_root, chunk_hash, position, proof)
}

/// Build an inclusion proof that the entry at `position` (= entry index)
/// belongs to `tree`. Verify against [`tree_inner_root`].
pub fn build_tree_inclusion_proof(tree: &Tree, position: u32) -> Result<Vec<u8>, MerkleError> {
    bmt_prove(&tree_leaves(tree), position as usize)
}

/// Verify a tree inclusion proof from [`build_tree_inclusion_proof`].
pub fn verify_tree_inclusion_proof(
    inner_root: &Hash,
    entry: &TreeEntry,
    position: u32,
    proof: &[u8],
) -> Result<(), MerkleError> {
    bmt_verify(inner_root, &tree_entry_leaf(entry), position, proof)
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::EntryMode;

    fn cb(total: u64, chunk_size: u32, chunks: &[u8]) -> ChunkedBlob {
        ChunkedBlob {
            total_size: total,
            chunk_size,
            chunks: chunks.iter().map(|b| [*b; 32]).collect(),
        }
    }

    fn entry(name: &[u8], mode: EntryMode, h: u8) -> TreeEntry {
        TreeEntry {
            name: name.to_vec(),
            mode,
            object_hash: [h; 32],
        }
    }

    fn tree(entries: Vec<TreeEntry>) -> Tree {
        Tree { entries }
    }

    #[test]
    fn id_changes_when_a_leaf_changes() {
        let a = cb(100, 0, &[1, 2, 3]);
        let b = cb(100, 0, &[1, 2, 4]);
        assert_ne!(compute_chunked_id(&a), compute_chunked_id(&b));
    }

    #[test]
    fn id_changes_when_leaf_count_changes() {
        let a = cb(100, 0, &[1, 2, 3]);
        let b = cb(100, 0, &[1, 2, 3, 3]); // duplicated last — must not collide
        assert_ne!(compute_chunked_id(&a), compute_chunked_id(&b));
    }

    #[test]
    fn chunked_id_changes_when_metadata_changes() {
        let a = cb(100, 0, &[1, 2, 3]);
        let b = cb(101, 0, &[1, 2, 3]);
        let c = cb(100, 64, &[1, 2, 3]);
        assert_ne!(compute_chunked_id(&a), compute_chunked_id(&b));
        assert_ne!(compute_chunked_id(&a), compute_chunked_id(&c));
    }

    #[test]
    fn tree_ordering_matters() {
        let a = tree(vec![
            entry(b"a", EntryMode::Blob, 1),
            entry(b"b", EntryMode::Blob, 2),
        ]);
        let b = tree(vec![
            entry(b"b", EntryMode::Blob, 2),
            entry(b"a", EntryMode::Blob, 1),
        ]);
        assert_ne!(compute_tree_id(&a), compute_tree_id(&b));
    }

    #[test]
    fn empty_tree_id_matches_constant() {
        let got = compute_tree_id(&tree(vec![]));
        assert_eq!(got, TREE_EMPTY_ID, "update TREE_EMPTY_ID to {got:02x?}");
    }

    #[test]
    fn type_binding_no_cross_collisions() {
        let empty_tree = compute_tree_id(&tree(vec![]));
        let empty_cblob = compute_chunked_id(&cb(0, 0, &[]));
        assert_ne!(empty_tree, empty_cblob);

        let t = tree(vec![entry(b"x", EntryMode::Blob, 9)]);
        let c = cb(10, 0, &[9]);
        assert_ne!(compute_tree_id(&t), compute_chunked_id(&c));
    }

    #[test]
    fn id_ne_flat_blake3_of_serialized_bytes() {
        let c = cb(100, 0, &[1, 2, 3]);
        let serialized =
            crate::serialize::serialize(&crate::object::Object::ChunkedBlob(c.clone())).unwrap();
        assert_ne!(compute_chunked_id(&c), crate::hash::hash(&serialized));
    }

    #[test]
    fn chunk_position_offsets_by_one() {
        let c = cb(100, 0, &[7, 8, 9]);
        assert_eq!(chunk_position(&c, &[7; 32]), Some(1));
        assert_eq!(chunk_position(&c, &[9; 32]), Some(3));
        assert_eq!(chunk_position(&c, &[0; 32]), None);
    }

    #[test]
    fn chunk_inclusion_proof_round_trips() {
        let c = cb(100, 0, &[10, 20, 30, 40]);
        let root = chunked_inner_root(&c);
        for (idx, byte) in [(0usize, 10u8), (2, 30), (3, 40)] {
            let pos = chunk_position(&c, &[byte; 32]).unwrap();
            assert_eq!(pos, u32_of(idx) + 1);
            let proof = build_chunk_inclusion_proof(&c, pos).unwrap();
            verify_chunk_inclusion_proof(&root, &[byte; 32], pos, &proof).unwrap();
            assert!(verify_chunk_inclusion_proof(&root, &[0xFF; 32], pos, &proof).is_err());
        }
    }

    #[test]
    fn tree_inclusion_proof_round_trips() {
        let t = tree(vec![
            entry(b"a", EntryMode::Blob, 1),
            entry(b"b", EntryMode::Tree, 2),
            entry(b"c", EntryMode::Executable, 3),
        ]);
        let root = tree_inner_root(&t);
        let pos = tree_entry_position(&t, b"b").unwrap();
        assert_eq!(pos, 1);
        let proof = build_tree_inclusion_proof(&t, pos).unwrap();
        verify_tree_inclusion_proof(&root, &t.entries[1], pos, &proof).unwrap();
        let wrong = entry(b"b", EntryMode::Blob, 2);
        assert!(verify_tree_inclusion_proof(&root, &wrong, pos, &proof).is_err());
    }

    #[test]
    fn out_of_range_position_rejected() {
        let c = cb(10, 0, &[1]);
        assert_eq!(
            build_chunk_inclusion_proof(&c, 2),
            Err(MerkleError::PositionOutOfRange(2))
        );
    }

    /// Cross-verify the vendored BMT against `commonware_storage::bmt`
    /// (native-only dev-dep) for several leaf counts incl. odd ones — the
    /// guard that the wasm-path vendored construction never drifts from the
    /// house primitive.
    #[test]
    fn vendored_root_matches_commonware() {
        use commonware_cryptography::blake3::{Blake3, Digest};
        use commonware_storage::bmt::Builder;

        for n in [1usize, 2, 3, 4, 5, 7, 8, 9, 16, 33] {
            let leaves: Vec<Hash> = (0..n)
                .map(|i| hash(&[u8::try_from(i % 256).unwrap(); 4]))
                .collect();

            let mut builder = Builder::<Blake3>::new(n);
            for l in &leaves {
                builder.add(&Digest(*l));
            }
            let cw_root = builder.build().root().0;
            let ours = bmt_root(&leaves);
            assert_eq!(ours, cw_root, "vendored BMT root diverged at n={n}");
        }
    }
}
