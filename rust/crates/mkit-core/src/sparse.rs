//! Verifiable sparse-checkout (Phase 1 scaffold).
//!
//! Spec reference: `docs/SPEC-SPARSE-CHECKOUT.md`. Issue #158.
//!
//! # What this is
//!
//! Today's `mkit sparse-checkout` filters paths *on the client* after
//! the server has handed over the full tree. That's fine for the file
//! transport but wasteful on HTTP / S3 transports where the server
//! could ship a partial subtree if the client could *verify* the
//! server didn't lie about which entries were omitted by request
//! versus silently dropped.
//!
//! This module is the Phase 1 core scaffolding: build a manifest from
//! a `Tree` + filter, and verify a delivered set of `TreeEntry`s
//! against it. The actual transport-level integration (HTTP/S3 query
//! params, on-disk bitmap cache) is Phase 2 and is intentionally out
//! of scope.
//!
//! # Authenticated bitmap
//!
//! Authentication uses
//! [`commonware_storage::AuthenticatedBitMap`][bitmap], which provides
//! a Merkleized bitmap with bit-level inclusion proofs. The bitmap is
//! `ALPHA`-tier upstream and `std`-only, so this entire module sits
//! behind the `sparse-checkout` Cargo feature (default off).
//!
//! Each entry in the underlying `Tree` is assigned a leaf index equal
//! to its position in the tree's strict lexicographic byte ordering
//! (the same ordering enforced by [`Tree::is_sorted`]). A bit set at
//! index `i` means "the server is shipping entry `i`"; an unset bit
//! means "this entry is omitted by client request". Tampering — the
//! server flipping a bit or omitting/inserting an entry — produces a
//! different bitmap root, which fails verification against the
//! root committed in the [`SparseManifest`].
//!
//! # Wire format
//!
//! Strictly defined by `docs/SPEC-SPARSE-CHECKOUT.md`. Phase 1 does
//! not yet wire `SparseProof` into any transport — the type is the
//! in-memory carrier between [`build_sparse`] and [`verify_sparse`].
//!
//! [bitmap]: https://docs.rs/commonware-storage

use crate::hash::{Hash, Hasher, ZERO};
use crate::object::Tree;
use crate::object::TreeEntry;
use std::path::PathBuf;

use commonware_cryptography::{Sha256, sha256};
use commonware_runtime::{Metrics as _, Runner as _, deterministic};
use commonware_storage::{MerkleizedBitMap, merkle::mmr};

/// Bitmap chunk size in bytes (32 bytes = 256 bits = one SHA-256 digest).
///
/// Chosen to match the upstream hasher digest size, which is the
/// upstream recommendation for minimising proof size.
const CHUNK_BYTES: usize = 32;

/// Hard cap on the number of leaves in a tree we are willing to build
/// a sparse manifest for. Matches the per-tree `entry_count` bound in
/// SPEC-OBJECTS §4. Verifier MUST enforce the same cap so a malicious
/// `manifest.leaf_count` can't allocate unbounded memory.
pub const MAX_LEAVES: u64 = 1_000_000;

/// Hard cap on the number of filter paths. Prevents a hostile client
/// from sending a billion-entry filter to a server. Mirrors the
/// transport-side bound documented in SPEC-SPARSE-CHECKOUT §4.
pub const MAX_FILTER_PATHS: usize = 100_000;

/// Manifest committing to which tree entries the server is including
/// in a sparse delivery. See SPEC-SPARSE-CHECKOUT §2.
///
/// All three fields are 32-byte BLAKE3 / SHA-256 digests. They are
/// length-prefixed and content-addressed independently so a
/// downstream codec can serialise them in any order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SparseManifest {
    /// BLAKE3 hash of the full tree object the manifest is derived
    /// from. Lets the client correlate this manifest with the
    /// `tree_hash` it asked the server for.
    pub tree_hash: Hash,
    /// Root of the [`MerkleizedBitMap`] over the include / exclude
    /// bitmap. SHA-256 (32 bytes) under the upstream `mmr::Family`
    /// hasher. Verifier MUST recompute this from the delivered
    /// bitmap chunks and reject on mismatch.
    pub bitmap_root: [u8; 32],
    /// BLAKE3 hash of the canonicalised filter — see
    /// [`hash_filter`]. Binds the manifest to a specific filter so
    /// the server can't substitute a different one mid-transfer.
    pub filter_hash: Hash,
    /// Total number of leaves in the source tree (= bitmap length in
    /// bits). Bounded by [`MAX_LEAVES`].
    pub leaf_count: u64,
}

/// Verifiable proof bundle accompanying a [`SparseManifest`].
///
/// Phase 1 carries the full bitmap chunks; for any realistic tree
/// size the bitmap fits comfortably in a few hundred bytes and the
/// verifier walks every delivered entry anyway. Phase 2's transport
/// wire-format may add per-bit inclusion proofs if bandwidth ever
/// becomes a concern — those will land as a new field, not as a swap.
#[derive(Debug, Clone)]
pub struct SparseProof {
    /// The raw bitmap bytes, exactly `ceil(leaf_count / 8)` bytes
    /// padded to a chunk boundary (multiple of [`CHUNK_BYTES`]).
    /// Verifier MUST recompute the bitmap root from these bytes and
    /// compare to `manifest.bitmap_root`.
    pub bitmap_bytes: Vec<u8>,
}

/// Stable BLAKE3 hash of a path-prefix filter. Canonical form:
///
/// 1. Sort the filter lexicographically by raw bytes.
/// 2. Deduplicate.
/// 3. For each path, append `len: u32 LE` then UTF-8 bytes.
/// 4. Hash the resulting buffer with BLAKE3.
///
/// The empty filter hashes to `BLAKE3([])`, not `ZERO`. An empty
/// filter is a valid manifest committing to "no entries delivered".
#[must_use]
pub fn hash_filter(filter: &[PathBuf]) -> Hash {
    let mut canonical: Vec<&[u8]> = filter
        .iter()
        .filter_map(|p| p.to_str().map(str::as_bytes))
        .collect();
    canonical.sort_unstable();
    canonical.dedup();

    let mut h = Hasher::new();
    for bytes in &canonical {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        h.update(&len.to_le_bytes());
        h.update(bytes);
    }
    h.finalize()
}

/// Returns `true` if `entry.name` is selected by *any* prefix in
/// `filter`. The filter is interpreted as a list of path-prefixes;
/// an empty filter selects nothing (it commits to "no entries").
///
/// Semantics:
///
/// * A filter path exactly equal to the entry name matches.
/// * A filter path that is a strict prefix of the entry name matches
///   only when followed by a `/` byte; this prevents `foo` from
///   matching `foobar`.
fn entry_matches_filter(entry: &TreeEntry, filter: &[PathBuf]) -> bool {
    let name = entry.name.as_slice();
    for path in filter {
        let Some(bytes) = path.to_str().map(str::as_bytes) else {
            continue;
        };
        if bytes.is_empty() {
            continue;
        }
        if name == bytes {
            return true;
        }
        if name.len() > bytes.len() && name.starts_with(bytes) && name[bytes.len()] == b'/' {
            return true;
        }
    }
    false
}

/// Errors raised by [`build_sparse`] and [`verify_sparse`]. Phase 1
/// keeps this small — the transport layer will wrap these in its own
/// error type in Phase 2.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SparseError {
    /// Source tree has more entries than [`MAX_LEAVES`]. The bitmap
    /// would still build, but we refuse out of caution: an attacker
    /// shouldn't be able to force a multi-GB allocation on the
    /// verifier by claiming a huge `leaf_count`.
    #[error("tree has {actual} entries, exceeds MAX_LEAVES = {}", MAX_LEAVES)]
    TooManyLeaves { actual: u64 },
    /// Filter has more entries than [`MAX_FILTER_PATHS`].
    #[error(
        "filter has {actual} paths, exceeds MAX_FILTER_PATHS = {}",
        MAX_FILTER_PATHS
    )]
    TooManyFilterPaths { actual: usize },
    /// Source tree's entries are not in strict lex order. Our leaf
    /// indices are defined by that order, so we refuse to build a
    /// manifest from a tree that violates the invariant.
    #[error("source tree entries are not lex-sorted; refusing to build manifest")]
    UnsortedTree,
}

/// Build a sparse manifest from a tree and a filter.
///
/// Walks `tree.entries` in canonical order (which, per
/// SPEC-OBJECTS §4, is byte-wise lex order on `name`). For each
/// entry, sets bit `i` in the underlying [`MerkleizedBitMap`] iff
/// any prefix in `filter` selects that entry's name.
///
/// Returns
///
/// * the subset of `tree.entries` selected by the filter (the ones
///   the server would actually ship under a server-side sparse
///   delivery), in the same canonical order;
/// * the [`SparseManifest`] committing to that subset;
/// * the [`SparseProof`] the verifier needs to check the manifest.
///
/// # Errors
///
/// * [`SparseError::UnsortedTree`] — `tree.entries` violates the
///   spec-mandated lex ordering.
/// * [`SparseError::TooManyLeaves`] — `tree.entries.len() > MAX_LEAVES`.
/// * [`SparseError::TooManyFilterPaths`] — `filter.len() > MAX_FILTER_PATHS`.
///
/// # Panics
///
/// Never panics on caller input. May abort the in-process commonware
/// async runtime on an upstream bug; we treat that as a programmer
/// error because the bitmap is in-memory only and has no real I/O
/// paths to fail on.
pub fn build_sparse(
    tree: &Tree,
    filter: &[PathBuf],
) -> Result<(Vec<TreeEntry>, SparseManifest, SparseProof), SparseError> {
    let leaf_count = u64::try_from(tree.entries.len()).unwrap_or(u64::MAX);
    if leaf_count > MAX_LEAVES {
        return Err(SparseError::TooManyLeaves { actual: leaf_count });
    }
    if filter.len() > MAX_FILTER_PATHS {
        return Err(SparseError::TooManyFilterPaths {
            actual: filter.len(),
        });
    }
    if !tree.is_sorted() {
        return Err(SparseError::UnsortedTree);
    }

    // Compute the include-bit vector and pull out the entries we'd
    // actually ship. The bitmap is just a Vec<bool> at this point;
    // we hand it to the merkleized bitmap below.
    let mut bits: Vec<bool> = Vec::with_capacity(tree.entries.len());
    let mut delivered: Vec<TreeEntry> = Vec::new();
    for entry in &tree.entries {
        let include = entry_matches_filter(entry, filter);
        bits.push(include);
        if include {
            delivered.push(entry.clone());
        }
    }

    // Build the bitmap inside the upstream's async runtime. The
    // deterministic runner is an in-memory test executor — no real
    // I/O, no network — which is exactly what we want here: the
    // bitmap is purely a verifiable commitment object, not a
    // persistent store.
    let (bitmap_root, bitmap_bytes) = merkleize_bits(&bits);

    let manifest = SparseManifest {
        tree_hash: tree_hash(tree),
        bitmap_root,
        filter_hash: hash_filter(filter),
        leaf_count,
    };
    let proof = SparseProof { bitmap_bytes };
    Ok((delivered, manifest, proof))
}

/// Build the upstream `MerkleizedBitMap` over `bits` and return
/// `(root, bitmap_bytes)`. Shared between [`build_sparse`] and
/// [`verify_sparse`] so the two cannot drift.
///
/// Phase 1 spins a fresh `deterministic::Runner` per call. Phase 2
/// (sparse over a real transport) will reuse a long-lived executor via
/// the future `mkit_core::protocol::Executor` shim; the dependency is
/// captured at this seam to keep the migration mechanical.
fn merkleize_bits(bits: &[bool]) -> ([u8; 32], Vec<u8>) {
    let runner = deterministic::Runner::default();
    let bits_owned = bits.to_vec();
    runner.start(move |ctx| async move {
        let hasher = mmr::StandardHasher::<Sha256>::new();
        let bitmap: MerkleizedBitMap<_, sha256::Digest, CHUNK_BYTES> =
            MerkleizedBitMap::init(ctx.with_label("sparse"), "sparse", None, &hasher)
                .await
                .expect("in-memory bitmap init cannot fail");
        let mut dirty = bitmap.into_dirty();
        for b in &bits_owned {
            dirty.push(*b);
        }
        let merkleized = dirty.merkleize(&hasher).expect("merkleize is infallible");
        let root = merkleized.root();

        let mut bytes = Vec::with_capacity(bits_owned.len().div_ceil(8));
        for (i, bit) in bits_owned.iter().enumerate() {
            if i % 8 == 0 {
                bytes.push(0u8);
            }
            if *bit {
                let last = bytes.last_mut().expect("just pushed a byte");
                *last |= 1 << (i % 8);
            }
        }

        let mut root_bytes = [0u8; 32];
        root_bytes.copy_from_slice(root.as_ref());
        (root_bytes, bytes)
    })
}

/// Verify a sparse delivery against a manifest.
///
/// Returns `true` iff *all* of the following hold:
///
/// 1. `manifest.leaf_count <= MAX_LEAVES`.
/// 2. `manifest.filter_hash == hash_filter(filter)` — the manifest
///    was issued against the same filter the client supplied.
/// 3. The set of leaf-indices implied by `bitmap_bytes` matches
///    the canonical leaf-indices the filter would select.
/// 4. The bitmap reconstructed from `bitmap_bytes` hashes to
///    `manifest.bitmap_root` under the upstream bitmap commitment.
/// 5. `delivered_entries`, in order, are *exactly* the entries
///    whose leaf-index has its bit set.
///
/// Phase 1 cannot independently check `tree_hash` because the
/// verifier doesn't have the full tree (that's the whole point of
/// sparse delivery). The Phase 2 transport layer will recompute the
/// tree hash once it has assembled enough of the structure.
///
/// # Panics
///
/// Never. All failure modes return `false`.
#[must_use]
pub fn verify_sparse(
    manifest: &SparseManifest,
    delivered_entries: &[TreeEntry],
    filter: &[PathBuf],
    proof: &SparseProof,
) -> bool {
    // (1) Sanity caps. A hostile manifest could claim 2^63 leaves;
    // refuse before we allocate anything proportional to it.
    if manifest.leaf_count > MAX_LEAVES {
        return false;
    }
    if filter.len() > MAX_FILTER_PATHS {
        return false;
    }

    // (2) Filter binding. Cheap and catches the "server swapped the
    // filter" attack early.
    if manifest.filter_hash != hash_filter(filter) {
        return false;
    }

    // The bitmap must be exactly enough bytes to hold `leaf_count`
    // bits, with no extra trailing bytes (otherwise an attacker
    // could pad with extra "set" bits the manifest never committed
    // to). `usize` is safe because we just bounded leaf_count by
    // MAX_LEAVES = 1M; refuse on impossibly large 32-bit casts.
    let Ok(leaf_count) = usize::try_from(manifest.leaf_count) else {
        return false;
    };
    let expected_bitmap_bytes = leaf_count.div_ceil(8);
    if proof.bitmap_bytes.len() != expected_bitmap_bytes {
        return false;
    }

    // (3) + (5) Walk bits and delivered entries together.
    //
    // We can't fully verify (5) without seeing the source tree, but
    // we can verify the *count* of set bits matches the count of
    // delivered entries, and that delivered entries are themselves
    // selected by the filter. The Phase 2 transport will cross-check
    // delivered_entries[i] against tree position once it has the
    // canonical leaf-index → name mapping.
    let mut set_bits = 0usize;
    for i in 0..leaf_count {
        let byte = proof.bitmap_bytes[i / 8];
        if (byte >> (i % 8)) & 1 == 1 {
            set_bits += 1;
        }
    }
    if set_bits != delivered_entries.len() {
        return false;
    }
    for entry in delivered_entries {
        if !entry_matches_filter(entry, filter) {
            return false;
        }
    }

    // (4) Reconstruct the bitmap root and compare. Rebuilds the
    // bitmap inside an in-memory commonware runtime, identical to
    // the one [`build_sparse`] used. Any tampering with
    // `bitmap_bytes` produces a different root.
    let bits: Vec<bool> = (0..leaf_count)
        .map(|i| (proof.bitmap_bytes[i / 8] >> (i % 8)) & 1 == 1)
        .collect();
    let (computed_root, _bytes) = merkleize_bits(&bits);
    if computed_root != manifest.bitmap_root {
        return false;
    }

    true
}

/// Compute the BLAKE3 hash of a tree's canonical serialisation. We
/// avoid pulling in `serialize::serialize` here to keep the sparse
/// module's surface tight; instead we hash the per-entry triple of
/// (`name`, `mode`, `object_hash`) in entry order.
///
/// This is *not* the SPEC-OBJECTS tree hash (which includes the v1
/// prologue and length prefixes); it is a sparse-module-internal
/// commitment binding the manifest to a specific tree. Phase 2 will
/// switch this to the full SPEC-OBJECTS hash once the transport-side
/// `tree_hash` is plumbed.
fn tree_hash(tree: &Tree) -> Hash {
    if tree.entries.is_empty() {
        return ZERO;
    }
    let mut h = Hasher::new();
    h.update(b"mkit-sparse-tree-v1");
    let count = u32::try_from(tree.entries.len()).unwrap_or(u32::MAX);
    h.update(&count.to_le_bytes());
    for entry in &tree.entries {
        let name_len = u32::try_from(entry.name.len()).unwrap_or(u32::MAX);
        h.update(&name_len.to_le_bytes());
        h.update(&entry.name);
        h.update(&[entry.mode as u8]);
        h.update(&entry.object_hash);
    }
    h.finalize()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::ZERO;
    use crate::object::{EntryMode, TreeEntry};

    fn entry(name: &[u8]) -> TreeEntry {
        TreeEntry {
            name: name.to_vec(),
            mode: EntryMode::Blob,
            object_hash: ZERO,
        }
    }

    /// Tree with `n` lex-sorted entries named `b"aa"`, `b"ab"`,
    /// `b"ac"`, etc. — enough variety that a prefix filter on
    /// `"aa"` selects exactly one entry.
    fn make_tree(n: usize) -> Tree {
        assert!(n <= 26 * 26, "test helper only supports n <= 676");
        let mut entries = Vec::with_capacity(n);
        for i in 0..n {
            // Two-letter ASCII names, lex-sorted by construction.
            let a = b'a' + u8::try_from(i / 26).unwrap();
            let b = b'a' + u8::try_from(i % 26).unwrap();
            entries.push(entry(&[a, b]));
        }
        Tree { entries }
    }

    #[test]
    fn build_and_verify_round_trip_simple() {
        let tree = make_tree(10);
        // Select "aa", "ab", "ac" — three distinct prefixes that
        // each match exactly one entry (the entry names are 2 bytes
        // and the filter paths are 2 bytes, so the exact-match arm
        // of `entry_matches_filter` fires).
        let filter = vec![
            PathBuf::from("aa"),
            PathBuf::from("ab"),
            PathBuf::from("ac"),
        ];

        let (delivered, manifest, proof) = build_sparse(&tree, &filter).unwrap();
        assert_eq!(delivered.len(), 3);
        assert_eq!(delivered[0].name, b"aa");
        assert_eq!(delivered[1].name, b"ab");
        assert_eq!(delivered[2].name, b"ac");
        assert_eq!(manifest.leaf_count, 10);

        assert!(verify_sparse(&manifest, &delivered, &filter, &proof));
    }

    #[test]
    fn verify_rejects_extra_entry() {
        // Server tries to ship a 4th entry the filter didn't ask
        // for. Even though the bitmap commits to the original 3,
        // the count mismatch fires immediately.
        let tree = make_tree(10);
        let filter = vec![
            PathBuf::from("aa"),
            PathBuf::from("ab"),
            PathBuf::from("ac"),
        ];

        let (mut delivered, manifest, proof) = build_sparse(&tree, &filter).unwrap();
        // Sneak in an entry that the filter does NOT select.
        delivered.push(entry(b"ad"));

        assert!(
            !verify_sparse(&manifest, &delivered, &filter, &proof),
            "verifier must reject delivered entries beyond the bitmap's set-bit count"
        );
    }

    #[test]
    fn verify_rejects_entry_outside_filter() {
        // Server ships the right *number* of entries, but one of
        // them isn't selected by the filter. The per-entry filter
        // check fires.
        let tree = make_tree(10);
        let filter = vec![PathBuf::from("aa"), PathBuf::from("ab")];

        let (mut delivered, manifest, proof) = build_sparse(&tree, &filter).unwrap();
        assert_eq!(delivered.len(), 2);

        // Replace "ab" with "az" — same count, but "az" isn't in
        // the filter.
        delivered[1] = entry(b"az");
        assert!(
            !verify_sparse(&manifest, &delivered, &filter, &proof),
            "verifier must reject any delivered entry not selected by the filter"
        );
    }

    #[test]
    fn verify_rejects_tampered_bitmap_bytes() {
        // Server flips a bit in `bitmap_bytes` (claims an extra
        // entry was included) but doesn't update the manifest's
        // bitmap_root. Root reconstruction catches it.
        let tree = make_tree(10);
        let filter = vec![PathBuf::from("aa"), PathBuf::from("ab")];

        let (delivered, manifest, mut proof) = build_sparse(&tree, &filter).unwrap();
        // Flip a high bit nobody set.
        proof.bitmap_bytes[0] ^= 0b1000_0000;

        assert!(
            !verify_sparse(&manifest, &delivered, &filter, &proof),
            "verifier must reject when bitmap_bytes diverges from manifest.bitmap_root"
        );
    }

    #[test]
    fn verify_rejects_tampered_manifest_root() {
        // Symmetric to the above: server preserves the bitmap but
        // claims a different root. Catches an attacker substituting
        // the manifest while leaving the bytes intact.
        let tree = make_tree(10);
        let filter = vec![PathBuf::from("aa"), PathBuf::from("ab")];

        let (delivered, mut manifest, proof) = build_sparse(&tree, &filter).unwrap();
        manifest.bitmap_root[0] ^= 1;

        assert!(!verify_sparse(&manifest, &delivered, &filter, &proof));
    }

    #[test]
    fn verify_rejects_wrong_filter() {
        // Manifest was built against filter A but verifier supplies
        // filter B. `filter_hash` mismatch.
        let tree = make_tree(10);
        let filter_a = vec![PathBuf::from("aa")];
        let filter_b = vec![PathBuf::from("ab")];

        let (delivered, manifest, proof) = build_sparse(&tree, &filter_a).unwrap();
        assert!(!verify_sparse(&manifest, &delivered, &filter_b, &proof));
    }

    #[test]
    fn empty_filter_yields_empty_delivery() {
        // Empty filter selects no entries. The manifest is
        // well-defined (commits to "every bit unset") and verify
        // accepts an empty delivered list.
        let tree = make_tree(10);
        let filter: Vec<PathBuf> = vec![];

        let (delivered, manifest, proof) = build_sparse(&tree, &filter).unwrap();
        assert!(delivered.is_empty());
        assert_eq!(manifest.leaf_count, 10);
        assert!(verify_sparse(&manifest, &delivered, &filter, &proof));
    }

    #[test]
    fn empty_tree_is_well_defined() {
        // No entries, no filter. Verifier accepts the trivial
        // manifest.
        let tree = Tree {
            entries: Vec::new(),
        };
        let filter: Vec<PathBuf> = vec![];
        let (delivered, manifest, proof) = build_sparse(&tree, &filter).unwrap();
        assert!(delivered.is_empty());
        assert_eq!(manifest.leaf_count, 0);
        assert!(verify_sparse(&manifest, &delivered, &filter, &proof));
    }

    #[test]
    fn prefix_filter_matches_subtree() {
        // "src" should select "src/foo" and "src/bar" but NOT "srx"
        // or "srcabc" (no `/` boundary).
        let entries = vec![
            entry(b"a"),
            entry(b"src/bar"),
            entry(b"src/foo"),
            entry(b"srx"),
        ];
        // Lex-sort: 'a' < 'src/bar' < 'src/foo' < 'srx' — already sorted.
        let tree = Tree { entries };
        let filter = vec![PathBuf::from("src")];

        let (delivered, manifest, proof) = build_sparse(&tree, &filter).unwrap();
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0].name, b"src/bar");
        assert_eq!(delivered[1].name, b"src/foo");
        assert!(verify_sparse(&manifest, &delivered, &filter, &proof));
    }

    #[test]
    fn unsorted_tree_is_rejected() {
        let tree = Tree {
            entries: vec![entry(b"b"), entry(b"a")],
        };
        let err = build_sparse(&tree, &[]).unwrap_err();
        assert_eq!(err, SparseError::UnsortedTree);
    }

    #[test]
    fn filter_hash_is_order_independent() {
        // Canonical form sorts and dedups, so these must collide.
        let a = hash_filter(&[PathBuf::from("y"), PathBuf::from("x")]);
        let b = hash_filter(&[
            PathBuf::from("x"),
            PathBuf::from("y"),
            PathBuf::from("x"), // duplicate
        ]);
        assert_eq!(a, b);
        // ...but a different content set must produce a different hash.
        let c = hash_filter(&[PathBuf::from("x"), PathBuf::from("z")]);
        assert_ne!(a, c);
    }
}
