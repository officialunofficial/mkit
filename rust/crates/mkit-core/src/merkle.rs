//! Merkle (BMT) content-addressing for `ChunkedBlob` and `Tree`.
//!
//! A merkelized object's content-address **is** its Binary Merkle Tree
//! root: the object id is `wrap_id(kind, bmt_root(leaves))` where the BMT
//! is built over the object's child stream. This makes inclusion of any
//! chunk/entry provable, and makes a reconstructed object's read-time id
//! check a free completeness proof for its whole child set.
//!
//! ## Primitive — a vendored BMT, byte-identical to `commonware_storage::bmt`
//!
//! The house idiom (makechain `transactions_root.rs`) uses
//! `commonware_storage::bmt`. We do **not** depend on it for object identity:
//! `merkle.rs` lives in `mkit-core` and `Object::id` calls it, so this module
//! must compile to `wasm32` for `mkit-core` *itself* to — independent of any
//! wasm caller. Instead this module vendors the *identical* BMT construction
//! over the `blake3` crate (already a mkit dependency, wasm-clean). A
//! native-only test (`tests::vendored_root_matches_commonware`) cross-verifies
//! the vendored root byte-for-byte against `commonware_storage::bmt`, and
//! `tests::proofs_match_commonware` extends that guarantee to inclusion
//! proofs (bytes and cross-verifier acceptance) — so the two never drift.
//!
//! RESOLVED (commonware#4089 / commonwarexyz/monorepo#4090, shipped in
//! `commonware =2026.7.0`): `bmt` itself is now genuinely `no_std` — that
//! part of the original TODO held. It is *not* enough to drop the vendored
//! copy, though: `commonware_storage::bmt::Builder<H: Hasher>` is generic
//! over `commonware_cryptography::Hasher`, so reaching a concrete hasher
//! (e.g. `Blake3`) means depending on the `commonware-cryptography` crate —
//! and that crate's `blst` dependency (BLS12-381) is **not** feature-gated;
//! it compiles unconditionally for every consumer, wasm or not. Confirmed
//! empirically: `blst`'s C sources fail to build for
//! `wasm32-unknown-unknown` wherever the local `clang` has no WASM LLVM
//! backend registered (e.g. stock Xcode clang on macOS — `clang
//! --print-targets` lists no `wasm32` entry). Even on a toolchain where it
//! *does* build, making `commonware-storage` (and therefore
//! `commonware-cryptography`/`blst`) a mandatory dependency of `mkit-core`'s
//! object-identity path would impose that C library's build/binary-size
//! cost on every consumer, not just wasm callers — the same reason
//! `mkit-attest` keeps `blst` behind an opt-in `bls-threshold` feature
//! instead of pulling it in by default. So the vendored construction stays;
//! the cross-check test is what keeps it honest against upstream.
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
//! id            = wrap_id(kind, bmt_root(leaves))
//!               = domain_digest(TYPE_DOMAIN, bmt_root(leaves))
//!
//! ChunkedBlob   leaves = [meta_leaf] ++ chunks
//!   meta_leaf   = domain_digest("mkit-cblob-meta-v1", total_size_le ‖ chunk_size_le)
//!   chunk i     -> BMT position i+1   (meta is position 0)
//!
//! Tree          leaves = entries (existing lex order)
//!   entry leaf  = domain_digest("mkit-tree-entry-v1", name_len_le ‖ name ‖ mode ‖ object_hash)
//! ```
//!
//! The outer `wrap_id` wrap makes the id type-distinct: a bare BMT root
//! over identical leaf streams would collide across types (the prologue
//! type byte is not in the root), so an empty `Tree` and an empty
//! `ChunkedBlob`, or a 1-entry `Tree` and a 1-chunk `ChunkedBlob` with the
//! same child hash, would otherwise share an id.
//!
//! ## Inclusion proofs — stable, commonware-aligned
//!
//! Object identity (`compute_tree_id` / `compute_chunked_id`) and the
//! inclusion-proof construction below are both stable
//! (`docs/specs/SPEC-MERKLE-OBJECTS.md` §5). [`Proof`]'s bytes and sibling
//! selection are byte-identical to `commonware_storage::bmt::Proof` at the
//! pinned `2026.9.0` train: a commonware-based verifier can decode a
//! mkit-produced proof with the upstream type and run its own
//! `verify_element_inclusion` / `verify_range_inclusion` /
//! `verify_multi_inclusion` against the **inner root** (see
//! [`chunked_inner_root`] / [`tree_inner_root`]), then apply [`wrap_id`] to
//! compare against the object id. `tests::proofs_match_commonware` pins
//! this claim; `rust/tests/golden/proofs/` carries fixed vectors.
//!
//! Verification in this crate is always stated against the **object id**
//! (`verify_tree_entry`, `verify_chunk`, and their range/multi
//! counterparts), never the bare inner root — passing a caller the inner
//! root invited skipping the type-domain wrap and accepting, say, a
//! `Tree` proof against a `ChunkedBlob` id (issue #1015 §Security). The
//! inner-root-comparing primitives (`Proof::verify_element_inclusion` and
//! friends) stay `pub(crate)`, kept only so the cross-check test can
//! compare directly against upstream's verifiers.

use std::collections::BTreeSet;

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, ReadRangeExt, Write};

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

/// Upper bound on sibling levels in a [`Proof`]: `u32::BITS`, matching
/// `commonware_storage::bmt::MAX_LEVELS`. Because [`Proof::leaf_count`] is a
/// `u32`, a tree can have at most `u32::MAX` leaves, which requires at most
/// `u32::BITS` sibling hashes per proven item.
pub const MAX_LEVELS: usize = u32::BITS as usize;

/// The two object kinds addressed by a BMT root (`crate::merkle`), keying
/// [`wrap_id`]'s type-domain wrap. A versioned, supported accessor for the
/// outer identity wrap — the alternative (exposing the raw `TYPE_DOMAIN`
/// byte strings) would make them de facto ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// A [`Tree`]'s entry list.
    Tree,
    /// A [`ChunkedBlob`]'s `[meta, chunks…]` list.
    ChunkedBlob,
}

impl ObjectKind {
    fn type_domain(self) -> &'static [u8] {
        match self {
            Self::Tree => TREE_TYPE_DOMAIN,
            Self::ChunkedBlob => CHUNKED_TYPE_DOMAIN,
        }
    }
}

/// Apply the outer type-domain wrap to a bare BMT inner root, producing the
/// object id. The inverse does not exist — `wrap_id` is a one-way hash —
/// so a verifier holding `(inner_root, proof)` reconstructs the inner root
/// from the proof and wraps it with the *expected* kind to compare against
/// a claimed id, rather than trying to "unwrap" the id.
#[must_use]
pub fn wrap_id(kind: ObjectKind, inner_root: &Hash) -> Hash {
    domain_digest(kind.type_domain(), inner_root)
}

/// Errors building or verifying a merkle inclusion proof.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MerkleError {
    /// The requested leaf position is outside the object's leaf range.
    #[error("merkle position {0} is out of range")]
    PositionOutOfRange(u32),
    /// The same position was requested more than once in a multi-proof.
    #[error("merkle position {0} is duplicated")]
    DuplicatePosition(u32),
    /// No positions were given to prove/verify.
    #[error("no merkle positions given")]
    NoPositions,
    /// A range's `start` is greater than its `end`.
    #[error("merkle range start {start} is greater than end {end}")]
    InvalidRange {
        /// The range's start position.
        start: u32,
        /// The range's end position.
        end: u32,
    },
    /// The proof bytes were malformed (bad codec payload or trailing bytes).
    #[error("merkle proof is malformed")]
    MalformedProof,
    /// The proof's sibling count does not match what the position(s)
    /// require — too few, too many, or misordered.
    #[error("merkle proof is unaligned with the requested position(s)")]
    UnalignedProof,
    /// The proof did not verify against the given root/id.
    #[error("merkle proof verification failed")]
    VerificationFailed,
}

impl From<CodecError> for MerkleError {
    fn from(_: CodecError) -> Self {
        Self::MalformedProof
    }
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

/// Returns the number of levels in a tree with `leaf_count` leaves
/// (level 0 = leaves, last level = the pre-finalize root). A tree with 1
/// leaf has 1 level, a tree with 2 leaves has 2 levels, etc. Ported from
/// `commonware_storage::bmt::levels_in_tree`.
fn levels_in_tree(leaf_count: u32) -> usize {
    (u32::BITS - leaf_count.saturating_sub(1).leading_zeros() + 1) as usize
}

/// A built BMT: every level from the position-hashed leaves up to the
/// single pre-finalize root node, plus the finalized root. Kept around so
/// one build serves many proofs cheaply — mirrors commonware's
/// `Builder`/`Tree` split.
struct BmtTree {
    /// The real leaf count (0 for an empty tree, even though `levels[0]`
    /// then holds a single placeholder node).
    leaf_count: u32,
    /// `true` when built from zero leaves — no position is ever provable.
    empty: bool,
    /// `levels[0]` = position-hashed leaves (or the single `H("")`
    /// placeholder); `levels[levels.len() - 1]` = the single pre-finalize
    /// tree root node.
    levels: Vec<Vec<Hash>>,
    /// The finalized root: `H(leaf_count_be32 ‖ levels.last()[0])`.
    root: Hash,
}

fn build_bmt(leaves: &[Hash]) -> BmtTree {
    let leaf_count = u32_of(leaves.len());
    let empty = leaves.is_empty();
    let position_hashed: Vec<Hash> = if empty {
        vec![hash(b"")]
    } else {
        leaves
            .iter()
            .enumerate()
            .map(|(i, l)| position_leaf(u32_of(i), l))
            .collect()
    };
    let mut levels = vec![position_hashed];
    while levels.last().expect("levels is never empty").len() > 1 {
        let cur = levels.last().expect("levels is never empty");
        let mut next = Vec::with_capacity(cur.len().div_ceil(2));
        for pair in cur.chunks(2) {
            let right = if pair.len() == 2 { &pair[1] } else { &pair[0] };
            next.push(h2(&pair[0], right));
        }
        levels.push(next);
    }
    let tree_root = levels.last().expect("levels is never empty")[0];
    let root = h2(&leaf_count.to_be_bytes(), &tree_root);
    BmtTree {
        leaf_count,
        empty,
        levels,
        root,
    }
}

/// Returns the sorted, deduplicated `(level, index)` positions of siblings
/// required to prove inclusion of leaves at the given `positions`. A
/// sibling is omitted when it would be the node's own duplicate (an odd
/// trailing node) or is already covered by another proven position —
/// verifiers reconstruct `H(computed, computed)` / skip re-deriving it
/// without consuming a proof entry. Ported from
/// `commonware_storage::bmt::siblings_required_for_multi_proof`.
fn siblings_required_for_multi_proof(
    leaf_count: u32,
    positions: impl IntoIterator<Item = u32>,
) -> Result<BTreeSet<(usize, usize)>, MerkleError> {
    let mut current = BTreeSet::new();
    for pos in positions {
        if pos >= leaf_count {
            return Err(MerkleError::PositionOutOfRange(pos));
        }
        if !current.insert(pos as usize) {
            return Err(MerkleError::DuplicatePosition(pos));
        }
    }
    if current.is_empty() {
        return Err(MerkleError::NoPositions);
    }

    let mut sibling_positions = BTreeSet::new();
    let levels_count = levels_in_tree(leaf_count);
    let mut level_size = leaf_count as usize;
    for level in 0..levels_count.saturating_sub(1) {
        for &index in &current {
            let sibling_index = if index.is_multiple_of(2) {
                if index + 1 < level_size {
                    index + 1
                } else {
                    index
                }
            } else {
                index - 1
            };
            if sibling_index != index && !current.contains(&sibling_index) {
                sibling_positions.insert((level, sibling_index));
            }
        }
        current = current.iter().map(|idx| idx / 2).collect();
        level_size = level_size.div_ceil(2);
    }
    Ok(sibling_positions)
}

/// Returns the sorted, deduplicated `(level, index)` positions of siblings
/// required to prove inclusion of a contiguous range of leaves from
/// `start` to `end` (inclusive). Ported from
/// `commonware_storage::bmt::siblings_required_for_range_proof`.
fn siblings_required_for_range_proof(
    leaf_count: u32,
    start: u32,
    end: u32,
) -> Result<BTreeSet<(usize, usize)>, MerkleError> {
    if leaf_count == 0 {
        return Err(MerkleError::NoPositions);
    }
    if start > end {
        return Err(MerkleError::InvalidRange { start, end });
    }
    if start >= leaf_count {
        return Err(MerkleError::PositionOutOfRange(start));
    }
    if end >= leaf_count {
        return Err(MerkleError::PositionOutOfRange(end));
    }

    let mut sibling_positions = BTreeSet::new();
    let levels_count = levels_in_tree(leaf_count);
    let mut level_start = start as usize;
    let mut level_end = end as usize;
    let mut level_size = leaf_count as usize;
    for level in 0..levels_count.saturating_sub(1) {
        if !level_start.is_multiple_of(2) {
            sibling_positions.insert((level, level_start - 1));
        }
        if level_end.is_multiple_of(2) {
            let right = level_end + 1;
            if right < level_size {
                sibling_positions.insert((level, right));
            }
        }
        level_start /= 2;
        level_end /= 2;
        level_size = level_size.div_ceil(2);
    }
    Ok(sibling_positions)
}

impl BmtTree {
    /// Generates a proof for the leaf at `position`. A single-element
    /// multi-proof.
    fn proof(&self, position: u32) -> Result<Proof, MerkleError> {
        self.multi_proof(core::iter::once(position))
    }

    /// Generates a range proof for the contiguous leaves `start..=end`.
    fn range_proof(&self, start: u32, end: u32) -> Result<Proof, MerkleError> {
        if self.empty {
            if start == 0 && end == 0 {
                return Ok(Proof::default());
            }
            return Err(MerkleError::PositionOutOfRange(start));
        }
        if start > end {
            return Err(MerkleError::InvalidRange { start, end });
        }
        let leaf_count = self.leaf_count;
        if start >= leaf_count {
            return Err(MerkleError::PositionOutOfRange(start));
        }
        if end >= leaf_count {
            return Err(MerkleError::PositionOutOfRange(end));
        }
        let sibling_positions = siblings_required_for_range_proof(leaf_count, start, end)?;
        let siblings = sibling_positions
            .iter()
            .map(|&(level, index)| self.levels[level][index])
            .collect();
        Ok(Proof {
            leaf_count,
            siblings,
        })
    }

    /// Generates a proof for the non-contiguous leaves at `positions`.
    /// Positions may be given in any order; duplicates are rejected.
    fn multi_proof(&self, positions: impl IntoIterator<Item = u32>) -> Result<Proof, MerkleError> {
        let mut positions = positions.into_iter().peekable();
        let first = *positions.peek().ok_or(MerkleError::NoPositions)?;
        if self.empty {
            return Err(MerkleError::PositionOutOfRange(first));
        }
        let leaf_count = self.leaf_count;
        let sibling_positions = siblings_required_for_multi_proof(leaf_count, positions)?;
        let siblings = sibling_positions
            .iter()
            .map(|&(level, index)| self.levels[level][index])
            .collect();
        Ok(Proof {
            leaf_count,
            siblings,
        })
    }
}

// ---------------------------------------------------------------------------
// Proof: wire format + verification
// ---------------------------------------------------------------------------

/// A BMT inclusion proof for one or more leaves: the tree's leaf count
/// plus the deduplicated sibling digests needed to reconstruct the root,
/// ordered level-major (bottom-up) then index-ascending.
///
/// Bytes are `u32 BE leaf_count ‖ LEB128-varint(n) ‖ n × 32-byte digest` —
/// byte-identical to `commonware_storage::bmt::Proof<D>` at the pinned
/// `2026.9.0` train (`tests::proofs_match_commonware` pins this; see also
/// `rust/tests/golden/proofs/`). A commonware-based verifier can decode
/// these bytes with the upstream type directly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Proof {
    /// The number of leaves in the tree. Incorporated into the finalized
    /// root, so a mismatched `leaf_count` fails verification rather than
    /// being silently accepted (malleability guard).
    pub leaf_count: u32,
    /// The deduplicated sibling digests, level-major bottom-up then
    /// index-ascending, with self-duplicate and already-proven siblings
    /// omitted (see `docs/specs/SPEC-MERKLE-OBJECTS.md` §5.3).
    pub siblings: Vec<Hash>,
}

impl Write for Proof {
    fn write(&self, writer: &mut impl BufMut) {
        self.leaf_count.write(writer);
        self.siblings.write(writer);
    }
}

impl EncodeSize for Proof {
    fn encode_size(&self) -> usize {
        self.leaf_count.encode_size() + self.siblings.encode_size()
    }
}

impl Read for Proof {
    /// The maximum number of items being proven. The upper bound on
    /// sibling hashes is derived as `max_items * MAX_LEVELS`, bounding
    /// allocation before any hashing happens.
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, max_items: &Self::Cfg) -> Result<Self, CodecError> {
        let leaf_count = u32::read(reader)?;
        let max_siblings = max_items.saturating_mul(MAX_LEVELS);
        let siblings = Vec::<Hash>::read_range(reader, ..=max_siblings)?;
        Ok(Self {
            leaf_count,
            siblings,
        })
    }
}

impl Proof {
    /// Encode to the commonware-identical wire bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encode_size());
        self.write(&mut out);
        out
    }

    /// Decode from the commonware-identical wire bytes, bounding the
    /// sibling count to `max_items * MAX_LEVELS`. `max_items` should be the
    /// number of positions the caller is about to verify (1 for a
    /// single-leaf proof, the range length for a range proof, the position
    /// count for a multi-proof). Rejects trailing bytes.
    ///
    /// # Errors
    ///
    /// [`MerkleError::MalformedProof`] on a truncated buffer, an
    /// over-`max_items` sibling count, or trailing bytes.
    pub fn decode(bytes: &[u8], max_items: usize) -> Result<Self, MerkleError> {
        let mut buf = bytes;
        let proof = Self::read_cfg(&mut buf, &max_items)?;
        if buf.has_remaining() {
            return Err(MerkleError::MalformedProof);
        }
        Ok(proof)
    }

    /// Reconstructs the tree's inner (pre-wrap) root implied by this proof
    /// for `leaf` at `position`, without comparing it to anything. The
    /// shared building block for both the inner-root-comparing
    /// (commonware-parity) verifiers below and the public id-based
    /// verifiers.
    fn reconstruct_element_root(
        &self,
        leaf: &Hash,
        mut position: u32,
    ) -> Result<Hash, MerkleError> {
        if position >= self.leaf_count {
            return Err(MerkleError::PositionOutOfRange(position));
        }
        let mut computed = position_leaf(position, leaf);
        let mut level_size = self.leaf_count as usize;
        let mut sibling_iter = self.siblings.iter();

        while level_size > 1 {
            let is_last_odd = position.is_multiple_of(2) && position as usize + 1 >= level_size;
            let (left, right) = if is_last_odd {
                (computed, computed)
            } else if position.is_multiple_of(2) {
                let sib = *sibling_iter.next().ok_or(MerkleError::UnalignedProof)?;
                (computed, sib)
            } else {
                let sib = *sibling_iter.next().ok_or(MerkleError::UnalignedProof)?;
                (sib, computed)
            };
            computed = h2(&left, &right);
            position /= 2;
            level_size = level_size.div_ceil(2);
        }

        if sibling_iter.next().is_some() {
            return Err(MerkleError::UnalignedProof);
        }
        Ok(h2(&self.leaf_count.to_be_bytes(), &computed))
    }

    /// Reconstructs the tree's inner (pre-wrap) root implied by this proof
    /// for the non-contiguous `elements` (leaf, position pairs). Elements
    /// may be given in any order; duplicate positions are rejected.
    fn reconstruct_multi_root(&self, elements: &[(Hash, u32)]) -> Result<Hash, MerkleError> {
        // A proof over zero positions is rejected unconditionally, even
        // when `leaf_count == 0` and `siblings` is empty (upstream's
        // `Default` proof, which would otherwise trivially "reconstruct"
        // the empty tree's root). Accepting it here would let a caller
        // verify zero proven entries/chunks against any id whose inner
        // root happens to equal the empty tree's — most notably the
        // real `TREE_EMPTY_ID` — without ever having proven anything.
        // Builders already refuse to construct such a proof
        // (`BmtTree::multi_proof`'s `NoPositions` on an empty position
        // iterator); this is the matching verification-side rule (see
        // `tests::verify_rejects_empty_element_set` and
        // SPEC-MERKLE-OBJECTS §5.4).
        if elements.is_empty() {
            return Err(MerkleError::NoPositions);
        }
        for (_, position) in elements {
            if *position >= self.leaf_count {
                return Err(MerkleError::PositionOutOfRange(*position));
            }
        }

        let mut sorted: Vec<(u32, Hash)> = elements
            .iter()
            .map(|(leaf, pos)| (*pos, position_leaf(*pos, leaf)))
            .collect();
        sorted.sort_unstable_by_key(|(pos, _)| *pos);
        for i in 1..sorted.len() {
            if sorted[i - 1].0 == sorted[i].0 {
                return Err(MerkleError::DuplicatePosition(sorted[i].0));
            }
        }

        let levels = levels_in_tree(self.leaf_count);
        let mut level_size = self.leaf_count;
        let mut sibling_iter = self.siblings.iter();
        let mut current = sorted;

        for _ in 0..levels.saturating_sub(1) {
            let mut next_level: Vec<(u32, Hash)> = Vec::with_capacity(current.len().div_ceil(2));
            let mut idx = 0;
            while idx < current.len() {
                let (pos, digest) = current[idx];
                let parent_pos = pos / 2;
                let (left, right) = if pos.is_multiple_of(2) {
                    let left = digest;
                    let right = if idx + 1 < current.len() && current[idx + 1].0 == pos + 1 {
                        idx += 1;
                        current[idx].1
                    } else if pos + 1 >= level_size {
                        left
                    } else {
                        *sibling_iter.next().ok_or(MerkleError::UnalignedProof)?
                    };
                    (left, right)
                } else {
                    // The left child was missing from `current`, so it must
                    // be a sibling.
                    let right = digest;
                    let left = *sibling_iter.next().ok_or(MerkleError::UnalignedProof)?;
                    (left, right)
                };
                next_level.push((parent_pos, h2(&left, &right)));
                idx += 1;
            }
            current = next_level;
            level_size = level_size.div_ceil(2);
        }

        if sibling_iter.next().is_some() {
            return Err(MerkleError::UnalignedProof);
        }
        if current.len() != 1 {
            return Err(MerkleError::UnalignedProof);
        }
        Ok(h2(&self.leaf_count.to_be_bytes(), &current[0].1))
    }

    /// Reconstructs the inner root for a contiguous range of `leaves`
    /// starting at `position`. A convenience wrapper over
    /// [`Self::reconstruct_multi_root`].
    fn reconstruct_range_root(&self, position: u32, leaves: &[Hash]) -> Result<Hash, MerkleError> {
        if leaves.is_empty() && position != 0 {
            return Err(MerkleError::PositionOutOfRange(position));
        }
        if !leaves.is_empty() {
            let leaves_len = u32_of(leaves.len());
            let end = position
                .checked_add(leaves_len - 1)
                .ok_or(MerkleError::PositionOutOfRange(position))?;
            if end >= self.leaf_count {
                return Err(MerkleError::PositionOutOfRange(end));
            }
        }
        let elements: Vec<(Hash, u32)> = leaves
            .iter()
            .enumerate()
            .map(|(i, l)| (*l, position + u32_of(i)))
            .collect();
        self.reconstruct_multi_root(&elements)
    }

    /// Verify against the bare (pre-wrap) inner root — matches
    /// `commonware_storage::bmt::Proof::verify_element_inclusion` exactly.
    /// `cfg(test)`: kept only for the commonware cross-check test
    /// (`tests::proofs_match_commonware`) and `tests::verify_chunk_rejects_meta_leaf`,
    /// which need to show the *bare* BMT proof accepts a position/leaf the
    /// id-based verifier must still reject. Every real caller MUST use the
    /// id-based [`verify_tree_entry`] / [`verify_chunk`], which close the
    /// inner-root-vs-id confusion footgun (issue #1015 §Security) — so this
    /// is deliberately not reachable outside tests, not just `pub(crate)`.
    #[cfg(test)]
    pub(crate) fn verify_element_inclusion(
        &self,
        leaf: &Hash,
        position: u32,
        inner_root: &Hash,
    ) -> Result<(), MerkleError> {
        let got = self.reconstruct_element_root(leaf, position)?;
        if &got == inner_root {
            Ok(())
        } else {
            Err(MerkleError::VerificationFailed)
        }
    }

    /// Verify a multi-leaf proof against the bare inner root. `cfg(test)`
    /// for the same reason as [`Self::verify_element_inclusion`].
    #[cfg(test)]
    pub(crate) fn verify_multi_inclusion(
        &self,
        elements: &[(Hash, u32)],
        inner_root: &Hash,
    ) -> Result<(), MerkleError> {
        let got = self.reconstruct_multi_root(elements)?;
        if &got == inner_root {
            Ok(())
        } else {
            Err(MerkleError::VerificationFailed)
        }
    }

    /// Verify a range proof against the bare inner root. `cfg(test)` for
    /// the same reason as [`Self::verify_element_inclusion`].
    #[cfg(test)]
    pub(crate) fn verify_range_inclusion(
        &self,
        position: u32,
        leaves: &[Hash],
        inner_root: &Hash,
    ) -> Result<(), MerkleError> {
        let got = self.reconstruct_range_root(position, leaves)?;
        if &got == inner_root {
            Ok(())
        } else {
            Err(MerkleError::VerificationFailed)
        }
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
/// chunks`). A commonware-based verifier's `verify_*_inclusion` checks
/// against this; mkit callers use the id-based [`verify_chunk`] instead.
#[must_use]
pub fn chunked_inner_root(cb: &ChunkedBlob) -> Hash {
    build_bmt(&chunked_leaves(cb)).root
}

/// Bare (pre-wrap) BMT root over a `Tree`'s entry leaves. A
/// commonware-based verifier's `verify_*_inclusion` checks against this;
/// mkit callers use the id-based [`verify_tree_entry`] instead.
#[must_use]
pub fn tree_inner_root(tree: &Tree) -> Hash {
    build_bmt(&tree_leaves(tree)).root
}

/// The content-address (object id) of a `ChunkedBlob`.
#[must_use]
pub fn compute_chunked_id(cb: &ChunkedBlob) -> Hash {
    wrap_id(ObjectKind::ChunkedBlob, &chunked_inner_root(cb))
}

/// The content-address (object id) of a `Tree`.
#[must_use]
pub fn compute_tree_id(tree: &Tree) -> Hash {
    wrap_id(ObjectKind::Tree, &tree_inner_root(tree))
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
// Proof construction
// ---------------------------------------------------------------------------

/// Build an inclusion proof that the chunk at `position` (= chunk index +
/// 1, per [`chunk_position`]) belongs to `cb`.
pub fn build_chunk_proof(cb: &ChunkedBlob, position: u32) -> Result<Proof, MerkleError> {
    build_bmt(&chunked_leaves(cb)).proof(position)
}

/// Build a range proof that the chunks at `start..=end` belong to `cb`.
pub fn build_chunks_range_proof(
    cb: &ChunkedBlob,
    start: u32,
    end: u32,
) -> Result<Proof, MerkleError> {
    build_bmt(&chunked_leaves(cb)).range_proof(start, end)
}

/// Build a multi-leaf proof that the chunks at `positions` belong to `cb`.
pub fn build_chunks_multi_proof(
    cb: &ChunkedBlob,
    positions: impl IntoIterator<Item = u32>,
) -> Result<Proof, MerkleError> {
    build_bmt(&chunked_leaves(cb)).multi_proof(positions)
}

/// Build an inclusion proof that the entry at `position` (= entry index)
/// belongs to `tree`.
pub fn build_tree_entry_proof(tree: &Tree, position: u32) -> Result<Proof, MerkleError> {
    build_bmt(&tree_leaves(tree)).proof(position)
}

/// Build a range proof that the entries at `start..=end` belong to `tree`.
pub fn build_tree_entries_range_proof(
    tree: &Tree,
    start: u32,
    end: u32,
) -> Result<Proof, MerkleError> {
    build_bmt(&tree_leaves(tree)).range_proof(start, end)
}

/// Build a multi-leaf proof that the entries at `positions` belong to
/// `tree`.
pub fn build_tree_entries_multi_proof(
    tree: &Tree,
    positions: impl IntoIterator<Item = u32>,
) -> Result<Proof, MerkleError> {
    build_bmt(&tree_leaves(tree)).multi_proof(positions)
}

// ---------------------------------------------------------------------------
// Proof verification — against the object id
// ---------------------------------------------------------------------------

/// Verify that `entry` at `position` belongs to the `Tree` whose id is
/// `tree_id`.
pub fn verify_tree_entry(
    tree_id: &Hash,
    entry: &TreeEntry,
    position: u32,
    proof: &Proof,
) -> Result<(), MerkleError> {
    let root = proof.reconstruct_element_root(&tree_entry_leaf(entry), position)?;
    check_wrapped(ObjectKind::Tree, &root, tree_id)
}

/// Verify that `entries` (in tree order, starting at `start`) belong to
/// the `Tree` whose id is `tree_id`.
pub fn verify_tree_entries_range(
    tree_id: &Hash,
    start: u32,
    entries: &[TreeEntry],
    proof: &Proof,
) -> Result<(), MerkleError> {
    let leaves: Vec<Hash> = entries.iter().map(tree_entry_leaf).collect();
    let root = proof.reconstruct_range_root(start, &leaves)?;
    check_wrapped(ObjectKind::Tree, &root, tree_id)
}

/// Verify that `entries` (each with its own position, any order) belong to
/// the `Tree` whose id is `tree_id`.
pub fn verify_tree_entries_multi(
    tree_id: &Hash,
    entries: &[(TreeEntry, u32)],
    proof: &Proof,
) -> Result<(), MerkleError> {
    let elements: Vec<(Hash, u32)> = entries
        .iter()
        .map(|(e, pos)| (tree_entry_leaf(e), *pos))
        .collect();
    let root = proof.reconstruct_multi_root(&elements)?;
    check_wrapped(ObjectKind::Tree, &root, tree_id)
}

/// Verify that the chunk `chunk_hash` at `position` belongs to the
/// `ChunkedBlob` whose id is `chunked_id`. Rejects `position == 0`: that
/// position is the metadata leaf, not a chunk, so a valid BMT proof of it
/// must never be accepted as a chunk proof (see `verify_chunk_rejects_meta_leaf`).
pub fn verify_chunk(
    chunked_id: &Hash,
    chunk_hash: &Hash,
    position: u32,
    proof: &Proof,
) -> Result<(), MerkleError> {
    if position == 0 {
        return Err(MerkleError::PositionOutOfRange(0));
    }
    let root = proof.reconstruct_element_root(chunk_hash, position)?;
    check_wrapped(ObjectKind::ChunkedBlob, &root, chunked_id)
}

/// Verify that `chunk_hashes` (in chunk order, starting at `start`) belong
/// to the `ChunkedBlob` whose id is `chunked_id`. Rejects a range whose
/// `start` is 0 (the metadata leaf).
pub fn verify_chunks_range(
    chunked_id: &Hash,
    start: u32,
    chunk_hashes: &[Hash],
    proof: &Proof,
) -> Result<(), MerkleError> {
    if start == 0 {
        return Err(MerkleError::PositionOutOfRange(0));
    }
    let root = proof.reconstruct_range_root(start, chunk_hashes)?;
    check_wrapped(ObjectKind::ChunkedBlob, &root, chunked_id)
}

/// Verify that `chunks` (each with its own position, any order) belong to
/// the `ChunkedBlob` whose id is `chunked_id`. Rejects any position `== 0`
/// (the metadata leaf).
pub fn verify_chunks_multi(
    chunked_id: &Hash,
    chunks: &[(Hash, u32)],
    proof: &Proof,
) -> Result<(), MerkleError> {
    if chunks.iter().any(|(_, pos)| *pos == 0) {
        return Err(MerkleError::PositionOutOfRange(0));
    }
    let elements: Vec<(Hash, u32)> = chunks.to_vec();
    let root = proof.reconstruct_multi_root(&elements)?;
    check_wrapped(ObjectKind::ChunkedBlob, &root, chunked_id)
}

/// Wrap `root` with `kind`'s type domain and compare to `expected_id`.
fn check_wrapped(kind: ObjectKind, root: &Hash, expected_id: &Hash) -> Result<(), MerkleError> {
    if &wrap_id(kind, root) == expected_id {
        Ok(())
    } else {
        Err(MerkleError::VerificationFailed)
    }
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
        let id = compute_chunked_id(&c);
        for (idx, byte) in [(0usize, 10u8), (2, 30), (3, 40)] {
            let pos = chunk_position(&c, &[byte; 32]).unwrap();
            assert_eq!(pos, u32_of(idx) + 1);
            let proof = build_chunk_proof(&c, pos).unwrap();
            verify_chunk(&id, &[byte; 32], pos, &proof).unwrap();
            assert!(verify_chunk(&id, &[0xFF; 32], pos, &proof).is_err());
        }
    }

    #[test]
    fn verify_chunk_rejects_meta_leaf() {
        let c = cb(100, 0, &[10, 20, 30]);
        let id = compute_chunked_id(&c);
        let meta_leaf = chunked_meta_leaf(&c);
        // Position 0 is a *valid* raw BMT proof of the meta leaf...
        let proof = build_chunk_proof(&c, 0).unwrap();
        proof
            .verify_element_inclusion(&meta_leaf, 0, &chunked_inner_root(&c))
            .expect("meta leaf is a valid BMT element at position 0");
        // ...but `verify_chunk` MUST reject it: position 0 is never a chunk.
        assert_eq!(
            verify_chunk(&id, &meta_leaf, 0, &proof),
            Err(MerkleError::PositionOutOfRange(0))
        );
    }

    #[test]
    fn tree_inclusion_proof_round_trips() {
        let t = tree(vec![
            entry(b"a", EntryMode::Blob, 1),
            entry(b"b", EntryMode::Tree, 2),
            entry(b"c", EntryMode::Executable, 3),
        ]);
        let id = compute_tree_id(&t);
        let pos = tree_entry_position(&t, b"b").unwrap();
        assert_eq!(pos, 1);
        let proof = build_tree_entry_proof(&t, pos).unwrap();
        verify_tree_entry(&id, &t.entries[1], pos, &proof).unwrap();
        let wrong = entry(b"b", EntryMode::Blob, 2);
        assert!(verify_tree_entry(&id, &wrong, pos, &proof).is_err());
    }

    #[test]
    fn range_and_multi_proofs_round_trip() {
        let t = tree(
            (0..9)
                .map(|i| entry(&[b'a' + i], EntryMode::Blob, i))
                .collect(),
        );
        let id = compute_tree_id(&t);

        let range_proof = build_tree_entries_range_proof(&t, 2, 4).unwrap();
        verify_tree_entries_range(&id, 2, &t.entries[2..=4], &range_proof).unwrap();
        assert!(verify_tree_entries_range(&id, 2, &t.entries[2..4], &range_proof).is_err());

        let multi_proof = build_tree_entries_multi_proof(&t, [0, 4, 8]).unwrap();
        let elements = [
            (t.entries[0].clone(), 0),
            (t.entries[4].clone(), 4),
            (t.entries[8].clone(), 8),
        ];
        verify_tree_entries_multi(&id, &elements, &multi_proof).unwrap();
        let wrong_elements = [
            (t.entries[0].clone(), 0),
            (t.entries[4].clone(), 5), // wrong position
            (t.entries[8].clone(), 8),
        ];
        assert!(verify_tree_entries_multi(&id, &wrong_elements, &multi_proof).is_err());
    }

    #[test]
    fn chunk_range_and_multi_proofs_reject_position_zero() {
        let c = cb(100, 0, &[1, 2, 3]);
        let id = compute_chunked_id(&c);
        let proof = build_chunks_range_proof(&c, 0, 1).unwrap();
        assert_eq!(
            verify_chunks_range(&id, 0, &c.chunks[..2], &proof),
            Err(MerkleError::PositionOutOfRange(0))
        );
        let multi = build_chunks_multi_proof(&c, [0, 2]).unwrap();
        assert_eq!(
            verify_chunks_multi(&id, &[(c.chunks[0], 0), (c.chunks[1], 2)], &multi),
            Err(MerkleError::PositionOutOfRange(0))
        );
    }

    #[test]
    fn single_leaf_tree_proof_has_no_siblings() {
        // Odd trailing node at every level up to the root: the proof must
        // omit the self-duplicate sibling entirely (issue #1015: the old
        // format wrongly emitted it).
        let t = tree(vec![entry(b"only", EntryMode::Blob, 1)]);
        let id = compute_tree_id(&t);
        let proof = build_tree_entry_proof(&t, 0).unwrap();
        assert!(
            proof.siblings.is_empty(),
            "single-leaf tree proof must have zero siblings"
        );
        verify_tree_entry(&id, &t.entries[0], 0, &proof).unwrap();
    }

    #[test]
    fn verify_rejects_empty_element_set() {
        // A "proof" over zero positions must never verify — not even
        // against the real empty tree id with the trivial
        // `Proof::default()` (`leaf_count: 0, siblings: []`). Upstream's
        // own `verify_multi_inclusion` treats exactly this input as a
        // valid proof that a tree is empty; mkit's id-based verifiers
        // reject it unconditionally instead, so a caller can never
        // "verify" zero proven entries/chunks against an id merely
        // because that id's inner root happens to fold the same way
        // (SPEC-MERKLE-OBJECTS §5.4).
        assert_eq!(
            verify_tree_entries_range(&TREE_EMPTY_ID, 0, &[], &Proof::default()),
            Err(MerkleError::NoPositions)
        );
        assert_eq!(
            verify_tree_entries_multi(&TREE_EMPTY_ID, &[], &Proof::default()),
            Err(MerkleError::NoPositions)
        );

        // The rule holds regardless of `leaf_count`: an empty
        // entries/positions slice is rejected even against a genuinely
        // non-empty tree with an otherwise-valid proof.
        let t = tree(vec![entry(b"a", EntryMode::Blob, 1)]);
        let id = compute_tree_id(&t);
        let real_proof = build_tree_entry_proof(&t, 0).unwrap();
        assert_eq!(
            verify_tree_entries_range(&id, 0, &[], &real_proof),
            Err(MerkleError::NoPositions)
        );
        assert_eq!(
            verify_tree_entries_multi(&id, &[], &real_proof),
            Err(MerkleError::NoPositions)
        );
    }

    #[test]
    fn out_of_range_position_rejected() {
        let c = cb(10, 0, &[1]);
        assert_eq!(
            build_chunk_proof(&c, 2),
            Err(MerkleError::PositionOutOfRange(2))
        );
    }

    #[test]
    fn proof_round_trips_through_encode_decode() {
        let t = tree(
            (0..7)
                .map(|i| entry(&[b'a' + i], EntryMode::Blob, i))
                .collect(),
        );
        let proof = build_tree_entry_proof(&t, 6).unwrap();
        let bytes = proof.encode();
        let decoded = Proof::decode(&bytes, 1).unwrap();
        assert_eq!(proof, decoded);

        // Trailing byte must be rejected.
        let mut truncated_extra = bytes.clone();
        truncated_extra.push(0);
        assert_eq!(
            Proof::decode(&truncated_extra, 1),
            Err(MerkleError::MalformedProof)
        );

        // A truncated buffer must be rejected.
        assert_eq!(
            Proof::decode(&bytes[..bytes.len() - 1], 1),
            Err(MerkleError::MalformedProof)
        );

        // An over-tight `max_items` bound must be rejected.
        assert_eq!(Proof::decode(&bytes, 0), Err(MerkleError::MalformedProof));
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
            let ours = build_bmt(&leaves).root;
            assert_eq!(ours, cw_root, "vendored BMT root diverged at n={n}");
        }
    }

    /// Strategy for `(leaf_count, single_pos, (range_start, range_end),
    /// multi_positions)`, weighted towards odd counts and powers-of-two ±1
    /// (where the odd-trailing-node dedup logic is most exercised) on top
    /// of a broad uniform range.
    fn tree_and_positions()
    -> impl proptest::strategy::Strategy<Value = (usize, u32, (u32, u32), Vec<u32>)> {
        use proptest::prelude::*;

        let boundary_counts: Vec<usize> = [1usize, 2, 4, 8, 16, 32, 64, 128, 256]
            .into_iter()
            .flat_map(|p| [p.saturating_sub(1).max(1), p, p + 1])
            .chain([
                3usize, 5, 7, 9, 15, 17, 31, 33, 63, 65, 127, 129, 255, 257, 300,
            ])
            .collect();

        prop_oneof![
            3 => 1usize..=300,
            2 => proptest::sample::select(boundary_counts),
        ]
        .prop_flat_map(|n| {
            let n_u32 =
                u32::try_from(n).expect("n is bounded well under u32::MAX by the strategy above");
            (
                Just(n),
                0..n_u32,
                (0..n_u32).prop_flat_map(move |s| (Just(s), s..n_u32)),
                proptest::collection::vec(0..n_u32, 1..=n.min(6)).prop_map(|mut v| {
                    v.sort_unstable();
                    v.dedup();
                    v
                }),
            )
        })
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(400))]

        /// Cross-verify [`Proof`] against `commonware_storage::bmt::Proof`
        /// (native-only dev-dep): for many randomised trees and randomised
        /// single/range/multi positions, mkit's encoded bytes must equal
        /// upstream's, and each side's verifier must accept the other's
        /// bytes/positions against the (matching) inner root. A mutated
        /// proof must be rejected by both. Pins issue #1015's
        /// "commonware-aligned bytes" claim beyond the root-only check
        /// above.
        #[test]
        fn proofs_match_commonware((n, pos, (start, end), positions) in tree_and_positions()) {
            use commonware_cryptography::blake3::{Blake3, Digest};
            use commonware_storage::bmt::Builder;

            let leaves: Vec<Hash> = (0..n).map(|i| hash(&(i as u64).to_le_bytes())).collect();

            let ours = build_bmt(&leaves);
            let mut cw_builder = Builder::<Blake3>::new(n);
            for l in &leaves {
                cw_builder.add(&Digest(*l));
            }
            let cw_tree = cw_builder.build();
            let cw_root = cw_tree.root();
            assert_eq!(ours.root, cw_root.0, "root mismatch at n={n}");

            // --- single position ---
            let our_proof = ours.proof(pos).unwrap();
            let cw_proof = cw_tree.proof(pos).unwrap();
            assert_eq!(
                our_proof.encode(),
                commonware_codec::Encode::encode(&cw_proof).to_vec(),
                "single-proof bytes diverged at n={n} pos={pos}"
            );
            cw_proof
                .verify_element_inclusion::<Blake3>(&Digest(leaves[pos as usize]), pos, &cw_root)
                .expect("upstream must accept its own proof");
            our_proof
                .verify_element_inclusion(&leaves[pos as usize], pos, &ours.root)
                .expect("ours must accept its own proof");
            // Cross-accept: decode the other side's bytes with our type.
            let cw_bytes = commonware_codec::Encode::encode(&cw_proof).to_vec();
            let our_decoded = Proof::decode(&cw_bytes, 1).unwrap();
            our_decoded
                .verify_element_inclusion(&leaves[pos as usize], pos, &ours.root)
                .expect("ours must accept upstream's proof bytes");
            // Cross-accept the other way: upstream decodes our bytes.
            let our_bytes = our_proof.encode();
            let mut our_bytes_buf: &[u8] = &our_bytes;
            let cw_decoded =
                <commonware_storage::bmt::Proof<Digest> as commonware_codec::Read>::read_cfg(
                    &mut our_bytes_buf,
                    &1usize,
                )
                .unwrap();
            cw_decoded
                .verify_element_inclusion::<Blake3>(&Digest(leaves[pos as usize]), pos, &cw_root)
                .expect("upstream must accept our proof bytes");

            // --- mutation must be rejected by both ---
            if !our_proof.siblings.is_empty() {
                let mut mutated = our_proof.clone();
                mutated.siblings[0][0] ^= 0x01;
                assert!(
                    mutated
                        .verify_element_inclusion(&leaves[pos as usize], pos, &ours.root)
                        .is_err()
                );

                let mut dropped = our_proof.clone();
                dropped.siblings.pop();
                assert!(
                    dropped
                        .verify_element_inclusion(&leaves[pos as usize], pos, &ours.root)
                        .is_err()
                );

                let mut extra = our_proof.clone();
                extra.siblings.push(hash(b"extra"));
                assert!(
                    extra
                        .verify_element_inclusion(&leaves[pos as usize], pos, &ours.root)
                        .is_err()
                );
            }
            let mut wrong_count = our_proof.clone();
            wrong_count.leaf_count = wrong_count.leaf_count.wrapping_add(1);
            assert!(
                wrong_count
                    .verify_element_inclusion(&leaves[pos as usize], pos, &ours.root)
                    .is_err()
            );

            if n >= 2 {
                // --- range ---
                let our_range = ours.range_proof(start, end).unwrap();
                let cw_range = cw_tree.range_proof(start, end).unwrap();
                assert_eq!(
                    our_range.encode(),
                    commonware_codec::Encode::encode(&cw_range).to_vec(),
                    "range-proof bytes diverged at n={n} start={start} end={end}"
                );
                let range_leaves: Vec<Hash> = leaves[start as usize..=end as usize].to_vec();
                let cw_range_leaves: Vec<Digest> =
                    range_leaves.iter().map(|h| Digest(*h)).collect();
                cw_range
                    .verify_range_inclusion::<Blake3>(start, &cw_range_leaves, &cw_root)
                    .expect("upstream must accept its own range proof");
                our_range
                    .verify_range_inclusion(start, &range_leaves, &ours.root)
                    .expect("ours must accept its own range proof");

                // --- multi ---
                if !positions.is_empty() {
                    let our_multi = ours.multi_proof(positions.iter().copied()).unwrap();
                    let cw_multi = cw_tree.multi_proof(positions.iter().copied()).unwrap();
                    assert_eq!(
                        our_multi.encode(),
                        commonware_codec::Encode::encode(&cw_multi).to_vec(),
                        "multi-proof bytes diverged at n={n} positions={positions:?}"
                    );
                    let elements: Vec<(Hash, u32)> =
                        positions.iter().map(|&p| (leaves[p as usize], p)).collect();
                    let cw_elements: Vec<(Digest, u32)> = positions
                        .iter()
                        .map(|&p| (Digest(leaves[p as usize]), p))
                        .collect();
                    cw_multi
                        .verify_multi_inclusion::<Blake3>(&cw_elements, &cw_root)
                        .expect("upstream must accept its own multi proof");
                    our_multi
                        .verify_multi_inclusion(&elements, &ours.root)
                        .expect("ours must accept its own multi proof");
                }
            }
        }
    }
}
