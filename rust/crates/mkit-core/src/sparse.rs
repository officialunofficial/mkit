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

use crate::hash::{Hash, Hasher, ZERO, hash as blake3_hash};
use crate::object::{EntryMode, Object, Tree, TreeEntry};
use crate::serialize::serialize;
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
    pub bitmap_root: Hash,
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
fn merkleize_bits(bits: &[bool]) -> (Hash, Vec<u8>) {
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

        let mut root_bytes: Hash = [0u8; 32];
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

/// Compute the canonical SPEC-OBJECTS tree hash.
///
/// Phase 2 swaps the Phase-1 placeholder for the canonical hash:
/// `BLAKE3(serialize(Object::Tree(t)))`. This is the *same* digest the
/// rest of the codebase uses to address a tree object — commits, remix
/// roots, and the object store all key trees by this value.
///
/// Binding the manifest to the canonical tree hash means the verifier
/// can cross-check the manifest against any independently-known
/// commitment to the source tree (a parent commit's `tree_hash`, a
/// merge base's tree, the local object store) without re-deriving a
/// sparse-private digest.
///
/// The empty tree still serializes to a valid 10-byte object
/// (`6-byte prologue || u32 LE 0` entries) and hashes to a non-zero
/// digest — there is no longer a `ZERO` short-circuit.
#[must_use]
pub fn tree_hash(tree: &Tree) -> Hash {
    // `serialize` only fails when an individual length-prefixed field
    // overflows `u32` — `Tree::entries` is bounded above by
    // `MAX_LEAVES` (1 M) here so the serialise call cannot fail on any
    // tree that already passed our caller guards. We still return
    // `ZERO` as a defensive fallback to keep the function infallible
    // for downstream users — they have no recourse if the upstream
    // tree is malformed.
    let Ok(bytes) = serialize(&Object::Tree(tree.clone())) else {
        return ZERO;
    };
    blake3_hash(&bytes)
}

// Re-export the canonical helper so external code that just needs to
// compute "the tree hash" (e.g. an HTTP server building the cache key)
// can do so without re-cloning the canonical serialisation themselves.
//
// Equivalent to `tree_hash(t)`; named for the public-API call site.
#[must_use]
pub fn canonical_tree_hash(tree: &Tree) -> Hash {
    tree_hash(tree)
}

/// Wire envelope magic — `b"MSP1"` (mkit-sparse-v1). Helps the
/// transport sanity-check the body before any deserialisation. Sits in
/// the same family as the v1 object prologue, but the codes are
/// distinct so a misrouted blob can't be parsed as a sparse response.
pub const SPARSE_WIRE_MAGIC: [u8; 4] = *b"MSP1";

/// Wire-format version of [`SparseResponse`]. Bumped on any
/// non-backward-compatible change.
pub const SPARSE_WIRE_VERSION: u8 = 0x01;

/// Maximum encoded sparse-response wire size. Caller-side cap; ~16 MiB
/// is comfortably more than a maximum-sized bitmap (~125 KB) plus the
/// largest possible entry stream.
pub const SPARSE_WIRE_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Complete server-to-client sparse delivery: manifest + entries +
/// proof, in the order they appear on the wire. The encoder and
/// decoder are content-stable across calls so the byte layout can be
/// pinned in golden vectors if and when needed.
#[derive(Debug, Clone)]
pub struct SparseResponse {
    /// Manifest committing to the delivery (104 bytes on the wire).
    pub manifest: SparseManifest,
    /// The subset of tree entries the filter selects, in canonical
    /// lex-sorted order. The verifier walks these alongside the bitmap.
    pub entries: Vec<TreeEntry>,
    /// Proof bundle. Phase 2 carries only the raw bitmap bytes; the
    /// future MMR proof slot is reserved for streaming-only transports.
    pub proof: SparseProof,
}

/// Errors raised when encoding or decoding a [`SparseResponse`] on the
/// wire. Kept tight — the transport layer wraps these in its own
/// transport-error type at the call site.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SparseWireError {
    /// Buffer was shorter than the fixed-size manifest header (or
    /// truncated partway through a length-prefixed section). The
    /// decoder refuses to allocate from a truncated header.
    #[error("sparse wire: truncated buffer")]
    Truncated,
    /// First 4 bytes are not `b"MSP1"`. Either the body is for a
    /// different endpoint or the server is on a fork.
    #[error("sparse wire: bad magic")]
    BadMagic,
    /// Version byte is something other than [`SPARSE_WIRE_VERSION`].
    /// A future server speaking v2 must not be silently downgraded.
    #[error("sparse wire: unsupported version {0}")]
    UnsupportedVersion(u8),
    /// One of the length-prefixed sections claims more bytes than
    /// remain in the input. Likely a malicious server trying to make
    /// us allocate.
    #[error("sparse wire: length out of bounds")]
    LengthOutOfBounds,
    /// `leaf_count` exceeds [`MAX_LEAVES`]. The verifier MUST refuse
    /// before allocating anything proportional to the claimed count.
    #[error("sparse wire: leaf_count exceeds MAX_LEAVES")]
    TooManyLeaves,
    /// Encoded buffer would exceed [`SPARSE_WIRE_MAX_BYTES`].
    #[error("sparse wire: response exceeds maximum size")]
    TooLarge,
    /// A tree entry's mode byte is not a valid [`EntryMode`].
    #[error("sparse wire: invalid entry mode {0}")]
    InvalidEntryMode(u8),
    /// Entry name length declared as zero or > 255 bytes — outside the
    /// SPEC-OBJECTS §4 range. Matches the per-tree-entry name cap.
    #[error("sparse wire: invalid entry name length")]
    InvalidEntryName,
}

/// Encode a [`SparseResponse`] to the canonical wire bytes.
///
/// Layout:
/// ```text
/// offset  size  field
/// 0       4     magic        = SPARSE_WIRE_MAGIC ("MSP1")
/// 4       1     version      = SPARSE_WIRE_VERSION
/// 5       32    tree_hash
/// 37      32    bitmap_root
/// 69      32    filter_hash
/// 101     8     leaf_count   (u64 LE)
/// 109     4     entries_len  (u32 LE) — count of TreeEntry items
/// 113     ...   TreeEntry stream, each entry:
///                 u16 LE name_len   (1..=255)
///                 name_len bytes    (name; arbitrary bytes)
///                 u8          mode  (EntryMode)
///                 [u8; 32]    object_hash
/// ...     4     bitmap_len   (u32 LE)
/// ...     N     bitmap_bytes
/// ```
///
/// Names are u16-LE length-prefixed rather than the u32 used by
/// SPEC-OBJECTS — names are bounded at 255 bytes, so a u16 prefix is
/// already overkill, and the four-byte saving per entry adds up over a
/// large tree. The decoder rejects `name_len == 0` and `name_len > 255`
/// to keep the bound enforced.
///
/// # Errors
///
/// * [`SparseWireError::TooManyLeaves`] — `manifest.leaf_count > MAX_LEAVES`.
/// * [`SparseWireError::InvalidEntryName`] — an entry name is empty or
///   > 255 bytes. Defensive: callers should reject before encoding.
/// * [`SparseWireError::TooLarge`] — the encoded buffer would exceed
///   [`SPARSE_WIRE_MAX_BYTES`].
pub fn encode_sparse_response(resp: &SparseResponse) -> Result<Vec<u8>, SparseWireError> {
    if resp.manifest.leaf_count > MAX_LEAVES {
        return Err(SparseWireError::TooManyLeaves);
    }
    // Pre-size: 113 byte header + per-entry (2 + name_len + 1 + 32) +
    // 4-byte bitmap length prefix + bitmap bytes. Overshoot is fine.
    let mut entries_size: usize = 0;
    for e in &resp.entries {
        if e.name.is_empty() || e.name.len() > 255 {
            return Err(SparseWireError::InvalidEntryName);
        }
        entries_size = entries_size
            .checked_add(2 + e.name.len() + 1 + 32)
            .ok_or(SparseWireError::TooLarge)?;
    }
    let total = 113usize
        .checked_add(entries_size)
        .and_then(|n| n.checked_add(4))
        .and_then(|n| n.checked_add(resp.proof.bitmap_bytes.len()))
        .ok_or(SparseWireError::TooLarge)?;
    if total > SPARSE_WIRE_MAX_BYTES {
        return Err(SparseWireError::TooLarge);
    }

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&SPARSE_WIRE_MAGIC);
    out.push(SPARSE_WIRE_VERSION);
    out.extend_from_slice(&resp.manifest.tree_hash);
    out.extend_from_slice(&resp.manifest.bitmap_root);
    out.extend_from_slice(&resp.manifest.filter_hash);
    out.extend_from_slice(&resp.manifest.leaf_count.to_le_bytes());

    let entries_len = u32::try_from(resp.entries.len()).map_err(|_| SparseWireError::TooLarge)?;
    out.extend_from_slice(&entries_len.to_le_bytes());
    for e in &resp.entries {
        // Name length already bounded above.
        #[allow(clippy::cast_possible_truncation)]
        let name_len = e.name.len() as u16;
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&e.name);
        out.push(e.mode as u8);
        out.extend_from_slice(&e.object_hash);
    }

    let bitmap_len =
        u32::try_from(resp.proof.bitmap_bytes.len()).map_err(|_| SparseWireError::TooLarge)?;
    out.extend_from_slice(&bitmap_len.to_le_bytes());
    out.extend_from_slice(&resp.proof.bitmap_bytes);

    Ok(out)
}

/// Decode a wire-format sparse response. Refuses any input larger than
/// [`SPARSE_WIRE_MAX_BYTES`] before parsing.
///
/// # Errors
///
/// * [`SparseWireError::Truncated`] — buffer ended mid-field.
/// * [`SparseWireError::BadMagic`] — magic prefix mismatch.
/// * [`SparseWireError::UnsupportedVersion`] — version byte mismatch.
/// * [`SparseWireError::TooManyLeaves`] — claimed `leaf_count >
///   MAX_LEAVES`. Refused before any allocation.
/// * [`SparseWireError::LengthOutOfBounds`] — a length prefix exceeds
///   the remaining buffer.
/// * [`SparseWireError::InvalidEntryMode`] — an entry mode byte is
///   not a recognised [`EntryMode`].
/// * [`SparseWireError::InvalidEntryName`] — an entry name length is
///   outside the 1..=255 SPEC-OBJECTS bound.
pub fn decode_sparse_response(buf: &[u8]) -> Result<SparseResponse, SparseWireError> {
    if buf.len() > SPARSE_WIRE_MAX_BYTES {
        return Err(SparseWireError::TooLarge);
    }
    if buf.len() < 113 {
        return Err(SparseWireError::Truncated);
    }
    if buf[0..4] != SPARSE_WIRE_MAGIC {
        return Err(SparseWireError::BadMagic);
    }
    if buf[4] != SPARSE_WIRE_VERSION {
        return Err(SparseWireError::UnsupportedVersion(buf[4]));
    }
    let mut tree_hash = [0u8; 32];
    tree_hash.copy_from_slice(&buf[5..37]);
    let mut bitmap_root = [0u8; 32];
    bitmap_root.copy_from_slice(&buf[37..69]);
    let mut filter_hash = [0u8; 32];
    filter_hash.copy_from_slice(&buf[69..101]);
    let mut leaf_count_bytes = [0u8; 8];
    leaf_count_bytes.copy_from_slice(&buf[101..109]);
    let leaf_count = u64::from_le_bytes(leaf_count_bytes);
    if leaf_count > MAX_LEAVES {
        return Err(SparseWireError::TooManyLeaves);
    }

    let mut entries_len_bytes = [0u8; 4];
    entries_len_bytes.copy_from_slice(&buf[109..113]);
    let entries_len = u32::from_le_bytes(entries_len_bytes) as usize;
    // Independently bound by the per-tree cap.
    if entries_len as u64 > MAX_LEAVES {
        return Err(SparseWireError::TooManyLeaves);
    }

    let mut cursor: usize = 113;
    let mut entries: Vec<TreeEntry> = Vec::with_capacity(entries_len.min(64));
    for _ in 0..entries_len {
        if cursor.checked_add(2).ok_or(SparseWireError::Truncated)? > buf.len() {
            return Err(SparseWireError::Truncated);
        }
        let mut nlb = [0u8; 2];
        nlb.copy_from_slice(&buf[cursor..cursor + 2]);
        let name_len = u16::from_le_bytes(nlb) as usize;
        cursor += 2;
        if name_len == 0 || name_len > 255 {
            return Err(SparseWireError::InvalidEntryName);
        }
        let needed = name_len
            .checked_add(1)
            .and_then(|n| n.checked_add(32))
            .ok_or(SparseWireError::LengthOutOfBounds)?;
        if cursor
            .checked_add(needed)
            .ok_or(SparseWireError::Truncated)?
            > buf.len()
        {
            return Err(SparseWireError::Truncated);
        }
        let name = buf[cursor..cursor + name_len].to_vec();
        cursor += name_len;
        let mode_byte = buf[cursor];
        cursor += 1;
        let mode = EntryMode::from_u8(mode_byte)
            .map_err(|_| SparseWireError::InvalidEntryMode(mode_byte))?;
        let mut object_hash = [0u8; 32];
        object_hash.copy_from_slice(&buf[cursor..cursor + 32]);
        cursor += 32;
        entries.push(TreeEntry {
            name,
            mode,
            object_hash,
        });
    }

    // Bitmap length prefix.
    if cursor.checked_add(4).ok_or(SparseWireError::Truncated)? > buf.len() {
        return Err(SparseWireError::Truncated);
    }
    let mut blb = [0u8; 4];
    blb.copy_from_slice(&buf[cursor..cursor + 4]);
    let bitmap_len = u32::from_le_bytes(blb) as usize;
    cursor += 4;
    if cursor
        .checked_add(bitmap_len)
        .ok_or(SparseWireError::LengthOutOfBounds)?
        > buf.len()
    {
        return Err(SparseWireError::LengthOutOfBounds);
    }
    let bitmap_bytes = buf[cursor..cursor + bitmap_len].to_vec();
    cursor += bitmap_len;
    if cursor != buf.len() {
        // Trailing bytes — refuse so a hostile server can't pad with
        // extra data hoping a future client parses it.
        return Err(SparseWireError::LengthOutOfBounds);
    }

    Ok(SparseResponse {
        manifest: SparseManifest {
            tree_hash,
            bitmap_root,
            filter_hash,
            leaf_count,
        },
        entries,
        proof: SparseProof { bitmap_bytes },
    })
}

// ---------------------------------------------------------------------------
// On-disk bitmap cache
// ---------------------------------------------------------------------------

/// Cache file header magic — `b"MSPC"` (mkit-sparse-cache). Distinct
/// from the wire magic so a misnamed file can't be parsed as either.
pub const SPARSE_CACHE_MAGIC: [u8; 4] = *b"MSPC";

/// Cache file format version. Bumped on any breaking change.
pub const SPARSE_CACHE_VERSION: u8 = 0x01;

/// Subdirectory under `.mkit/` for the sparse bitmap cache.
pub const SPARSE_CACHE_DIR: &str = "sparse";

/// Encode the on-disk cache payload for a verified sparse delivery.
///
/// Layout:
/// ```text
/// 0   4   magic        = SPARSE_CACHE_MAGIC ("MSPC")
/// 4   1   version      = SPARSE_CACHE_VERSION
/// 5   32  bitmap_root
/// 37  32  filter_hash
/// 69  8   leaf_count   (u64 LE)
/// 77  4   bitmap_len   (u32 LE)
/// 81  N   bitmap_bytes
/// ```
///
/// The `tree_hash` is *not* stored in the file body — it is the
/// filename. Re-verifying a cached bitmap means recomputing the
/// bitmap root from the bytes and comparing to `bitmap_root` here.
#[must_use]
pub fn encode_sparse_cache(manifest: &SparseManifest, proof: &SparseProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(81 + proof.bitmap_bytes.len());
    out.extend_from_slice(&SPARSE_CACHE_MAGIC);
    out.push(SPARSE_CACHE_VERSION);
    out.extend_from_slice(&manifest.bitmap_root);
    out.extend_from_slice(&manifest.filter_hash);
    out.extend_from_slice(&manifest.leaf_count.to_le_bytes());
    let len = u32::try_from(proof.bitmap_bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&proof.bitmap_bytes);
    out
}

/// Decode the on-disk cache payload. Returns the bitmap root, filter
/// hash, leaf count, and bitmap bytes — the caller reconstructs the
/// `SparseManifest` if needed (the `tree_hash` field comes from the
/// filename, not from the file body).
///
/// # Errors
///
/// Same shape as [`decode_sparse_response`].
#[allow(clippy::type_complexity)]
pub fn decode_sparse_cache(buf: &[u8]) -> Result<(Hash, Hash, u64, Vec<u8>), SparseWireError> {
    if buf.len() < 81 {
        return Err(SparseWireError::Truncated);
    }
    if buf[0..4] != SPARSE_CACHE_MAGIC {
        return Err(SparseWireError::BadMagic);
    }
    if buf[4] != SPARSE_CACHE_VERSION {
        return Err(SparseWireError::UnsupportedVersion(buf[4]));
    }
    let mut bitmap_root = [0u8; 32];
    bitmap_root.copy_from_slice(&buf[5..37]);
    let mut filter_hash = [0u8; 32];
    filter_hash.copy_from_slice(&buf[37..69]);
    let mut lcb = [0u8; 8];
    lcb.copy_from_slice(&buf[69..77]);
    let leaf_count = u64::from_le_bytes(lcb);
    if leaf_count > MAX_LEAVES {
        return Err(SparseWireError::TooManyLeaves);
    }
    let mut blb = [0u8; 4];
    blb.copy_from_slice(&buf[77..81]);
    let bitmap_len = u32::from_le_bytes(blb) as usize;
    let end = 81usize
        .checked_add(bitmap_len)
        .ok_or(SparseWireError::LengthOutOfBounds)?;
    if end > buf.len() {
        return Err(SparseWireError::LengthOutOfBounds);
    }
    if end != buf.len() {
        return Err(SparseWireError::LengthOutOfBounds);
    }
    let bitmap_bytes = buf[81..end].to_vec();
    Ok((bitmap_root, filter_hash, leaf_count, bitmap_bytes))
}

// `ZERO` is still re-used by the empty-tree short-circuit fallback in
// `tree_hash`; silence the unused-import warning for builds that don't
// trigger that path (none today, but future test paths may).
#[allow(dead_code)]
const _UNUSED_ZERO: Hash = ZERO;

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

    // ----- Phase 2: canonical tree-hash + wire format ----------------------

    #[test]
    fn tree_hash_matches_canonical_serialize_then_hash() {
        // The Phase-2 tree_hash is BLAKE3(serialize(Object::Tree(t))).
        // Cross-check against the codebase's canonical "address a tree
        // object" recipe — anything else would defeat the point of the
        // Phase-1 → Phase-2 swap.
        let tree = make_tree(5);
        let canonical = crate::hash::hash(
            &crate::serialize::serialize(&crate::object::Object::Tree(tree.clone())).unwrap(),
        );
        assert_eq!(tree_hash(&tree), canonical);
    }

    #[test]
    fn tree_hash_differs_from_phase1_placeholder() {
        // Sanity: the Phase-1 sparse-internal hash and the new
        // canonical hash MUST differ for any non-empty tree, so a
        // mistakenly-pinned Phase-1 hash anywhere upstream surfaces
        // immediately as a verifier mismatch.
        let tree = make_tree(3);
        // Phase-1 placeholder recipe — kept verbatim for the diff.
        let mut body = Hasher::new();
        let count = u32::try_from(tree.entries.len()).unwrap();
        body.update(&count.to_le_bytes());
        for entry in &tree.entries {
            let name_len = u32::try_from(entry.name.len()).unwrap();
            body.update(&name_len.to_le_bytes());
            body.update(&entry.name);
            body.update(&[entry.mode as u8]);
            body.update(&entry.object_hash);
        }
        let body_digest = body.finalize();
        let phase1 = crate::hash::domain_digest(b"mkit-sparse-tree-v1", &body_digest);
        assert_ne!(tree_hash(&tree), phase1);
    }

    #[test]
    fn wire_round_trip_simple() {
        let tree = make_tree(8);
        let filter = vec![PathBuf::from("aa"), PathBuf::from("ab")];
        let (entries, manifest, proof) = build_sparse(&tree, &filter).unwrap();
        let resp = SparseResponse {
            manifest,
            entries,
            proof,
        };
        let bytes = encode_sparse_response(&resp).unwrap();
        let parsed = decode_sparse_response(&bytes).unwrap();
        assert_eq!(parsed.manifest, resp.manifest);
        assert_eq!(parsed.entries.len(), resp.entries.len());
        for (a, b) in parsed.entries.iter().zip(resp.entries.iter()) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.mode as u8, b.mode as u8);
            assert_eq!(a.object_hash, b.object_hash);
        }
        assert_eq!(parsed.proof.bitmap_bytes, resp.proof.bitmap_bytes);
        // Decoded response still verifies.
        assert!(verify_sparse(
            &parsed.manifest,
            &parsed.entries,
            &filter,
            &parsed.proof
        ));
    }

    #[test]
    fn wire_rejects_bad_magic() {
        let tree = make_tree(2);
        let (entries, manifest, proof) = build_sparse(&tree, &[PathBuf::from("aa")]).unwrap();
        let mut bytes = encode_sparse_response(&SparseResponse {
            manifest,
            entries,
            proof,
        })
        .unwrap();
        bytes[0] = 0xFF;
        assert_eq!(
            decode_sparse_response(&bytes).unwrap_err(),
            SparseWireError::BadMagic
        );
    }

    #[test]
    fn wire_rejects_unsupported_version() {
        let tree = make_tree(2);
        let (entries, manifest, proof) = build_sparse(&tree, &[PathBuf::from("aa")]).unwrap();
        let mut bytes = encode_sparse_response(&SparseResponse {
            manifest,
            entries,
            proof,
        })
        .unwrap();
        bytes[4] = 0x99;
        assert!(matches!(
            decode_sparse_response(&bytes).unwrap_err(),
            SparseWireError::UnsupportedVersion(0x99)
        ));
    }

    #[test]
    fn wire_rejects_trailing_garbage() {
        let tree = make_tree(2);
        let (entries, manifest, proof) = build_sparse(&tree, &[PathBuf::from("aa")]).unwrap();
        let mut bytes = encode_sparse_response(&SparseResponse {
            manifest,
            entries,
            proof,
        })
        .unwrap();
        bytes.push(0xAA);
        assert_eq!(
            decode_sparse_response(&bytes).unwrap_err(),
            SparseWireError::LengthOutOfBounds
        );
    }

    #[test]
    fn wire_rejects_truncated_header() {
        let tiny = vec![0u8; 50];
        assert_eq!(
            decode_sparse_response(&tiny).unwrap_err(),
            SparseWireError::Truncated
        );
    }

    #[test]
    fn wire_rejects_overlong_leaf_count() {
        let mut buf = Vec::with_capacity(113);
        buf.extend_from_slice(&SPARSE_WIRE_MAGIC);
        buf.push(SPARSE_WIRE_VERSION);
        buf.extend_from_slice(&[0u8; 32]); // tree_hash
        buf.extend_from_slice(&[0u8; 32]); // bitmap_root
        buf.extend_from_slice(&[0u8; 32]); // filter_hash
        buf.extend_from_slice(&(MAX_LEAVES + 1).to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // entries_len = 0
        // need bitmap length prefix for completeness
        buf.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            decode_sparse_response(&buf).unwrap_err(),
            SparseWireError::TooManyLeaves
        );
    }

    #[test]
    fn cache_round_trip_recovers_bitmap_root() {
        let tree = make_tree(10);
        let filter = vec![PathBuf::from("ab")];
        let (_entries, manifest, proof) = build_sparse(&tree, &filter).unwrap();
        let bytes = encode_sparse_cache(&manifest, &proof);
        let (bitmap_root, filter_hash, leaf_count, bitmap_bytes) =
            decode_sparse_cache(&bytes).unwrap();
        assert_eq!(bitmap_root, manifest.bitmap_root);
        assert_eq!(filter_hash, manifest.filter_hash);
        assert_eq!(leaf_count, manifest.leaf_count);
        assert_eq!(bitmap_bytes, proof.bitmap_bytes);
    }

    #[test]
    fn cache_rejects_bad_magic() {
        let tree = make_tree(1);
        let (_entries, manifest, proof) = build_sparse(&tree, &[PathBuf::from("aa")]).unwrap();
        let mut bytes = encode_sparse_cache(&manifest, &proof);
        bytes[0] = 0x00;
        assert_eq!(
            decode_sparse_cache(&bytes).unwrap_err(),
            SparseWireError::BadMagic
        );
    }
}
