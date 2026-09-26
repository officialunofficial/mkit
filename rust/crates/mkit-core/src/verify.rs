//! Partial-disclosure verification: prove and verify that a single path,
//! chunk, or byte range belongs to a commit id, with proof bytes on the
//! order of a few KiB regardless of repository size.
//!
//! ## Trust model
//!
//! A verified [`Disclosed`] proves that its `payload` bytes are exactly
//! the content the given `commit_id` commits to at `path` — nothing more.
//! It does **not** prove:
//!
//! * that the disclosed path is the *only* thing at that location (no
//!   sibling-completeness claim — see the closure profile, issue #1015
//!   PR 3, for that);
//! * anything about who the signer *is* — `signer`/`signature_valid`
//!   report whether the embedded Ed25519 signature verifies against the
//!   embedded public key; binding that key to an identity or trust level
//!   is application policy (trust roots), exactly as
//!   [`crate::sign::verify_commit`] already documents.
//!
//! Every function in this module verifies against an **object id**, never
//! a bare (pre-domain-wrap) inner root or an unauthenticated byte range —
//! see [`crate::merkle`]'s module docs for why that distinction matters.
//!
//! Wire format, verification algorithm, and bounds are pinned in
//! `docs/specs/SPEC-DISCLOSURE.md`; golden vectors live under
//! `rust/tests/golden/disclosure/`. See issue #1015 (verifier kit) PR 2.
//!
//! ## Layering
//!
//! [`verify_object_id`], [`verify_path`], [`verify_chunk_with_meta`],
//! [`verify_blob_slice`], and [`verify_blob_len_proof`] are the small,
//! independently-useful primitives (each corresponds to one hop of the
//! authentication chain: commit → tree steps → leaf → chunk/slice).
//! [`verify_disclosure`] decodes a self-contained wire bundle (§ below)
//! and composes them into one call. [`build_disclosure_from`] is the
//! producer side, generic over any verifying [`crate::store::ObjectSource`]
//! (the on-disk store, an in-memory overlay, or a server-side index or
//! object CAS); [`build_disclosure`] is its thin wrapper over
//! [`crate::store::ObjectStore`]. The builder's source trait is distinct
//! from this module's [`ObjectSource`], the non-verifying
//! `fetch(&mut self)` trait the closure walker reads through. Full
//! disclosure — every reachable object against a commit id — is
//! [`verify_closure`], [`verify_closure_streaming`],
//! [`verify_closure_packs`], and [`verify_closure_manifest`], with
//! [`verify_closure_store`] and [`export_closure`] as native store-backed
//! operations (issue #1015 PR 3).
//!
//! Everything here, the builder included, compiles with
//! `--no-default-features` and targets `wasm32-unknown-unknown`; no
//! separate feature gate is needed since `mkit-core` itself is a `std`
//! crate (see the crate root docs).
//!
//! ## Wire bundle (`verify_disclosure` / `build_disclosure`)
//!
//! ```text
//! magic   = "MKDP"            (4 raw bytes)
//! version: u8 = 2
//! commit_id: [u8; 32]
//! commit_bytes: Vec<u8>        <= 4 MiB
//! steps: Vec<Step>             <= MAX_TREE_DEPTH (128), root first
//!   Step { name: Vec<u8> (1..=255), mode: u8, child_id: [u8; 32],
//!          inner_root: [u8; 32], position: u32, proof: Proof (max_items = 1) }
//! payload_kind: u8
//!   0 Object { bytes: Vec<u8> <= MAX_RAW_OBJECT_SIZE }
//!   1 Chunk  { total_size: u64, chunk_size: u32, index: u32,
//!              inner_root: [u8; 32], proof: Proof (max_items = 2),
//!              bytes: Vec<u8> }
//!   2 Range  { chunk: Option<ChunkHdr>, offset_in_blob: u64, len: u64,
//!              slice: Vec<u8>, chunk_len_proofs: Vec<LenProof> }
//!     ChunkHdr { total_size: u64, chunk_size: u32, index: u32,
//!                inner_root: [u8; 32], chunk_id: [u8; 32],
//!                proof: Proof (max_items = 2) }
//!     LenProof { index: u32, chunk_id: [u8; 32],
//!                proof: Proof (max_items = 1), slice: Vec<u8> }
//! ```
//!
//! All integers are big-endian, every length is an LEB128 varint, arrays
//! are raw — `commonware-codec` conventions (SPEC-CONVENTIONS §3;
//! `crate::transfer`'s packlist node is the existing precedent for this
//! house style). The whole bundle is capped at [`MAX_BUNDLE_BYTES`];
//! trailing bytes are rejected.
//!
//! `ChunkHdr.chunk_id` is not literal to issue #1015's original design
//! note, which omitted it: without an explicit chunk id, a verifier
//! reading a byte-range bundle would have no value to check the Bao slice
//! against before folding it into the enclosing `ChunkedBlob`'s multi-proof
//! (Bao's `SliceDecoder` always requires the expected root up front — it
//! cannot recover an unknown one from the slice, by construction). Adding
//! this field closes that gap; it is exactly the value
//! [`verify_chunk_with_meta`]'s multi-proof authenticates, so a forged
//! `chunk_id` fails to fold to the enclosing `ChunkedBlob`'s id.

use std::collections::BTreeMap;
use std::io::Read as _;

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, ReadRangeExt, Write};

use crate::hash::{Hash, hash};
use crate::merkle::{self, MerkleError, ObjectKind, Proof};
use crate::object::{EntryMode, MAGIC, MkitError, Object, ObjectType, SCHEMA_VERSION, TreeEntry};
use crate::sign::{verify_commit, verify_remix};
use crate::store::MAX_TREE_DEPTH;

/// Hard cap on a whole encoded disclosure bundle, checked before any
/// decode work happens. `mkit-wasm` additionally caps decoded objects at
/// 16 MiB; this 64 MiB ceiling is the wasm32-agnostic bound this crate
/// itself enforces.
pub const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;

/// Fixed 4-byte magic at the start of every disclosure bundle.
const BUNDLE_MAGIC: &[u8; 4] = b"MKDP";
/// Current (and only) bundle version byte. v1 is rejected with
/// [`VerifyError::UnsupportedBundleVersion`]; there is no compatibility
/// decoder (SPEC-DISCLOSURE v2, issue #1024).
const BUNDLE_VERSION: u8 = 2;
/// Cap on `commit_bytes` — comfortably above any real commit (~250 B) or
/// remix (larger, due to `sources`), far below `MAX_RAW_OBJECT_SIZE`.
const MAX_COMMIT_BYTES: usize = 4 * 1024 * 1024;
/// Cap on a single length-proof's Bao slice. Proving 10 bytes needs one
/// 1 KiB Bao leaf chunk plus at most `MAX_LEVELS` (32) 64-byte parent
/// hashes plus an 8-byte header — comfortably under 4 KiB; 8 KiB leaves
/// headroom without opening a real allocation hazard.
const MAX_LEN_PROOF_SLICE_BYTES: usize = 8 * 1024;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors verifying (or, natively, building) a disclosure.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The encoded bundle exceeds [`MAX_BUNDLE_BYTES`].
    #[error("disclosure bundle exceeds the {MAX_BUNDLE_BYTES} byte cap")]
    BundleTooLarge,
    /// The bundle is shorter than the fixed magic+version header, or the
    /// magic bytes are not `"MKDP"`.
    #[error("disclosure bundle magic is not \"MKDP\"")]
    BadMagic,
    /// The bundle's version byte is not `2`. A version byte of `1` is
    /// this error with payload `1`; there is no v1 compatibility decoder.
    #[error("disclosure bundle version {0} is not supported (v2 only)")]
    UnsupportedBundleVersion(u8),
    /// A step's or chunk header's declared `inner_root` does not wrap to
    /// the expected object id (`Tree` domain for steps, `ChunkedBlob` domain
    /// for chunk headers). Checked before the field is used for anything.
    #[error("declared inner root does not wrap to the expected object id")]
    InnerRootMismatch {
        /// The parent `Tree` id (steps) or `ChunkedBlob` leaf id (chunk headers).
        expected: Hash,
        /// The prover-supplied inner root that failed the wrap check.
        inner_root: Hash,
    },
    /// The proof folds to a different root than the bundle declared,
    /// even though the declared root wraps to the expected id (or vice
    /// versa). Both must agree.
    #[error("proof fold does not equal the declared inner root")]
    InnerRootFoldMismatch,
    /// The codec body is malformed: truncated, an over-cap length, an
    /// invalid varint, or trailing bytes after the declared body.
    #[error("disclosure bundle body is malformed (bad codec payload or trailing bytes)")]
    Malformed,
    /// The bundle's embedded `commit_id` field does not match the id the
    /// caller asked to verify against.
    #[error("disclosure bundle's embedded commit_id does not match the requested commit id")]
    CommitIdMismatch,
    /// `BLAKE3(commit_bytes)` does not equal the commit id being verified.
    #[error("commit_bytes do not hash to the commit id being verified")]
    CommitBytesHashMismatch,
    /// `commit_bytes` decoded to an object type other than `Commit` or
    /// `Remix` — the only two kinds that carry a `tree_hash` a path can
    /// be walked from.
    #[error("commit_bytes decode to a {0:?}, which is not a Commit or Remix")]
    NotACommitOrRemix(ObjectType),
    /// More steps than [`crate::store::MAX_TREE_DEPTH`] were supplied.
    #[error("{0} steps exceeds MAX_TREE_DEPTH ({MAX_TREE_DEPTH})")]
    TooManySteps(usize),
    /// The entry name at the given step index fails SPEC-OBJECTS §4.1
    /// name validation ([`TreeEntry::validate_name`]).
    #[error("step {0}'s entry name fails SPEC-OBJECTS §4.1 validation")]
    InvalidEntryName(usize),
    /// A non-final step's mode is not [`EntryMode::Tree`] — every step
    /// but the last MUST descend into a directory.
    #[error("step {0} is not the final step but its mode is not Tree")]
    NonFinalStepNotTree(usize),
    /// A step's, or the payload's, merkle inclusion proof failed to
    /// verify — wraps every [`MerkleError`] variant (out-of-range
    /// position, unaligned proof, or a folded value that does not match
    /// the expected id).
    #[error("merkle proof verification failed: {0}")]
    Merkle(#[from] MerkleError),
    /// The bundle's `payload_kind` byte is not one of the three defined
    /// kinds (`0` Object, `1` Chunk, `2` Range).
    #[error("payload_kind byte {0:#04x} is not a recognized disclosure payload kind")]
    InvalidPayloadKind(u8),
    /// An `Object` payload's `BLAKE3`/merkle id does not equal the
    /// authenticated leaf id.
    #[error("disclosed Object payload's id does not equal the authenticated leaf id")]
    PayloadIdMismatch,
    /// A chunk `index` (or a length-proof's `index`) is out of range for
    /// the `ChunkedBlob`'s proven `leaf_count`.
    #[error("chunk index {index} is out of range for a {leaf_count}-leaf ChunkedBlob proof")]
    ChunkIndexOutOfRange {
        /// The out-of-range chunk index.
        index: u32,
        /// The proof's claimed `leaf_count` (chunk count + 1, for the
        /// metadata leaf).
        leaf_count: u32,
    },
    /// A proof's implied chunk count (`leaf_count - 1`) exceeds
    /// `serialize::MAX_CHUNKS` (crate-private, not linkable from here).
    #[error("proof leaf_count implies more chunks than MAX_CHUNKS allows")]
    TooManyChunks,
    /// A `Range` payload's `len` is zero — there is nothing to disclose
    /// or verify.
    #[error("byte range length is zero")]
    ZeroLengthRange,
    /// `chunk_len_proofs` was non-empty but did not cover exactly
    /// `0..index` with no gaps or duplicates — an incomplete or malformed
    /// set is a typed error, never silently treated as "absent".
    #[error("chunk_len_proofs does not cover exactly indices 0..{0} with no gaps or duplicates")]
    IncompleteLengthProofSet(u32),
    /// `chunk_len_proofs` was non-empty on a `Range` payload that has no
    /// chunk before it to describe: either the leaf is a plain `Blob` (no
    /// chunk at all), or the disclosed chunk is index 0 (nothing precedes
    /// the first chunk).
    #[error("chunk_len_proofs is only meaningful for a ChunkedBlob range at chunk index > 0")]
    UnexpectedLengthProofs,
    /// A Bao slice failed to verify against the expected root/offset/len.
    #[error("Bao slice verification failed: {0}")]
    Bao(String),
    /// A Bao slice decoded to fewer bytes than the claimed `len`.
    #[error("Bao slice yielded {got} bytes, expected {expected}")]
    ShortSlice {
        /// The requested length.
        expected: u64,
        /// The number of bytes the slice actually decoded to.
        got: usize,
    },
    /// [`verify_blob_len_proof`]'s bytes 0..6 are not a valid v1 Blob
    /// prologue (wrong object type, magic, or schema version byte).
    #[error("blob length-proof bytes are not a valid v1 Blob prologue")]
    InvalidBlobPrologue,
    /// An offset/length computation would overflow `u64`.
    #[error("offset/length computation overflowed u64")]
    OffsetOverflow,
    /// A byte range's canonical decode/serialize error.
    #[error(transparent)]
    Decode(#[from] MkitError),
    /// [`Selector::Chunk`]/[`Selector::Range`] was used against a leaf
    /// whose object type does not support that selector (e.g. `Chunk` on
    /// a plain `Blob`, or either on a `Tree`).
    #[error("selector does not match the disclosed leaf's object type")]
    SelectorLeafMismatch,
    /// [`build_disclosure`]: the requested range crosses a `ChunkedBlob`
    /// chunk boundary — unsupported in this (v1) profile.
    #[error("byte range crosses a chunk boundary, which this profile does not support")]
    RangeCrossesChunkBoundary,
    /// [`build_disclosure`]: the requested range is out of bounds for the
    /// leaf's actual content length.
    #[error("byte range is out of bounds for the leaf's content length")]
    RangeOutOfBounds,
    /// [`build_disclosure`]: a path component was not found in its
    /// parent tree.
    #[error("path component {0} was not found in its parent tree")]
    PathNotFound(usize),
    /// [`build_disclosure`]: the path continues past a non-`Tree` entry,
    /// or the requested selector needs a leaf that isn't reached because
    /// an intermediate component isn't a directory.
    #[error("path continues past a non-Tree entry")]
    PathThroughNonTree,
    /// [`build_disclosure`]: the underlying object store returned an
    /// error.
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    /// The supplied object set exceeds [`crate::pack::MAX_ENTRIES`].
    #[error("closure object set exceeds the pack MAX_ENTRIES cap")]
    TooManyClosureObjects,
    /// The closure root deserialized but is not a `Commit`, `Remix`, or `Tag`.
    #[error("closure root is a {0:?}, which is not a Commit, Remix, or Tag")]
    ClosureRootWrongType(ObjectType),
    /// A pack in the closure profile contained a delta or compressed entry.
    #[error(
        "closure pack {pack_index} entry {entry_index} is not a raw (0x00) entry (closure profile is raw-only)"
    )]
    ClosureProfileViolation {
        /// Index of the offending pack in the caller-supplied list.
        pack_index: usize,
        /// Index of the offending entry inside that pack.
        entry_index: usize,
    },
    /// The encoded closure manifest is shorter than the magic+version
    /// header, or the magic bytes are not `"MKCL"`.
    #[error("closure manifest magic is not \"MKCL\"")]
    ClosureManifestBadMagic,
    /// The manifest's version byte is not `1`.
    #[error("closure manifest version {0} is not supported (v1 only)")]
    ClosureManifestUnsupportedVersion(u8),
    /// The manifest body is malformed: truncated, an over-cap pack
    /// list, an unknown mode byte, or trailing bytes.
    #[error(
        "closure manifest body is malformed (bad codec payload, unknown mode, or trailing bytes)"
    )]
    ClosureManifestMalformed,
    /// The number of packs supplied does not match the manifest.
    #[error("closure manifest lists {expected} packs but {got} were supplied")]
    ClosurePackCountMismatch {
        /// Pack count recorded in the manifest.
        expected: usize,
        /// Number of pack buffers the caller handed the verifier.
        got: usize,
    },
    /// `pack_key(packs[index])` does not equal the manifest entry.
    #[error("pack {index} hash does not match the closure manifest")]
    ClosurePackKeyMismatch {
        /// Index of the mismatched pack.
        index: usize,
    },
    /// The manifest's `root` does not equal the caller-supplied trusted root.
    /// The manifest is a locator, never a trust anchor.
    #[error("closure manifest root does not match the caller's trusted root")]
    ClosureRootMismatch {
        /// Root the caller asked to verify against.
        expected: Hash,
        /// Root the manifest named.
        got: Hash,
    },
    /// A packfile framing/decode error while iterating a closure pack.
    #[error(transparent)]
    Pack(#[from] crate::pack::PackError),
}

impl From<CodecError> for VerifyError {
    fn from(_: CodecError) -> Self {
        // Mirrors `merkle::MerkleError`'s `From<CodecError>`: every codec
        // failure (truncation, an over-cap length, a bad varint, trailing
        // bytes) collapses to one "malformed" outcome — the caller never
        // needs to distinguish which codec primitive tripped, only that
        // decode failed rather than that verification failed.
        Self::Malformed
    }
}

mod closure;
pub use closure::{
    ClosureExport, ClosureManifest, ClosureReport, MAX_CLOSURE_PACKS, ObjectSource, export_closure,
    verify_closure, verify_closure_manifest, verify_closure_packs, verify_closure_store,
    verify_closure_streaming,
};
mod push;
pub use push::{PushReport, verify_push};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// One authenticated hop of a path: the entry `name`/`mode` proven at
/// `position` under its parent (a commit's `tree_hash`, or the previous
/// step's `child_id`), via a single-leaf [`Proof`].
///
/// This is both the in-memory type [`verify_path`] takes and the wire
/// representation inside a disclosure bundle (§ module docs) — there is
/// no separate internal wire struct to keep in sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// The entry's name (1..=255 bytes; SPEC-OBJECTS §4.1 rules apply).
    pub name: Vec<u8>,
    /// The entry's mode.
    pub mode: EntryMode,
    /// The entry's child object id.
    pub child_id: Hash,
    /// Bare BMT root of the **parent** Tree this step's proof is verified
    /// against (the tree whose id is the commit's `tree_hash` for step 0,
    /// or the previous step's `child_id`). Wrap-checked against that id
    /// before use; never a second trust anchor.
    pub inner_root: Hash,
    /// The entry's BMT position (= index) within its parent `Tree`.
    pub position: u32,
    /// Single-leaf inclusion proof (`max_items = 1`) that `(name, mode,
    /// child_id)` is the entry at `position` in the parent tree.
    pub proof: Proof,
}

/// The result of walking and verifying a path from a commit's
/// `tree_hash` down to a leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathVerified {
    /// The commit's (or remix's) root tree id.
    pub tree_hash: Hash,
    /// The authenticated path, root first: each entry's `(name, mode)` —
    /// never a caller-claimed path string. Callers compare this against
    /// what they requested; this module never trusts a claimed path.
    pub path: Vec<(Vec<u8>, EntryMode)>,
    /// The id of the object at the end of the path (`tree_hash` itself
    /// when `path` is empty).
    pub leaf_id: Hash,
    /// The commit/remix's embedded Ed25519 public key.
    pub signer: [u8; 32],
    /// Whether the commit/remix's embedded signature verifies against
    /// `signer`. Does **not** say anything about who `signer` belongs to
    /// — that is application policy (see the module docs).
    pub signature_valid: bool,
}

/// A verified partial disclosure: `payload` is exactly the content
/// `commit_id` commits to at `path`, and nothing more. See the module
/// docs for the precise trust model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosed {
    /// The commit id the disclosure was verified against.
    pub commit_id: Hash,
    /// The commit's (or remix's) root tree id.
    pub tree_hash: Hash,
    /// The authenticated path, root first (see [`PathVerified::path`]).
    pub path: Vec<(Vec<u8>, EntryMode)>,
    /// The id of the disclosed leaf object.
    pub leaf_id: Hash,
    /// The disclosed content.
    pub payload: DisclosedPayload,
    /// The commit/remix's embedded Ed25519 public key.
    pub signer: [u8; 32],
    /// Whether the commit/remix's embedded signature verifies. See
    /// [`PathVerified::signature_valid`].
    pub signature_valid: bool,
    /// Authenticated bare BMT inner root of each step's parent Tree,
    /// root first. Empty when `steps` is empty (root-tree disclosure).
    /// Each value has been wrap-checked against the parent id and
    /// cross-checked against the proof fold.
    pub step_inner_roots: Vec<Hash>,
    /// Authenticated bare BMT inner root of the leaf `ChunkedBlob`, when
    /// the payload is `Chunk` or a `Range` over a chunk. `None` for an
    /// `Object` payload or a `Range` over a plain `Blob`.
    pub chunk_inner_root: Option<Hash>,
}

/// The disclosed content of a [`Disclosed`] result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisclosedPayload {
    /// The leaf's full canonical object bytes; `hash`/`id_from_object` of
    /// `bytes` equals `Disclosed::leaf_id`.
    Object {
        /// Canonical object bytes.
        bytes: Vec<u8>,
    },
    /// One whole chunk of a `ChunkedBlob` leaf, plus its authenticated
    /// manifest metadata.
    Chunk {
        /// The `ChunkedBlob`'s authenticated total content size.
        total_size: u64,
        /// The `ChunkedBlob`'s authenticated chunk-size marker (`0` =
        /// content-defined chunking).
        chunk_size: u32,
        /// The chunk's index within the manifest.
        index: u32,
        /// The chunk's canonical `Blob` bytes.
        bytes: Vec<u8>,
    },
    /// A byte range of a `Blob`, or of one chunk of a `ChunkedBlob`.
    Range {
        /// The id of the object the range was sliced from: the leaf
        /// itself when it is a plain `Blob`, or the containing chunk's
        /// id when the leaf is a `ChunkedBlob`.
        blob_id: Hash,
        /// `Some((index, total_size, chunk_size))` when the leaf is a
        /// `ChunkedBlob` (the authenticated manifest metadata for the
        /// containing chunk); `None` when the leaf is a plain `Blob`.
        chunk: Option<(u32, u64, u32)>,
        /// The range's offset within `blob_id`'s content (the chunk's
        /// content when `chunk` is `Some`, the blob's content otherwise).
        offset_in_blob: u64,
        /// The range's offset within the *whole* disclosed file, when
        /// provable: `Some(offset_in_blob)` for a plain `Blob` (nothing
        /// further to prove) or for a `ChunkedBlob` at `index == 0`
        /// (nothing precedes the first chunk, so no proof set is needed —
        /// and [`VerifyError::UnexpectedLengthProofs`] rejects a
        /// non-empty one there rather than silently ignoring it); for a
        /// `ChunkedBlob` at `index > 0`, `Some(sum of every preceding
        /// chunk's authenticated length + offset_in_blob)` when a complete
        /// `0..index` length-proof set was supplied, else `None` (not
        /// requested).
        absolute_offset: Option<u64>,
        /// The disclosed bytes.
        bytes: Vec<u8>,
    },
}

/// What [`build_disclosure`] discloses about the leaf its `path` reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selector {
    /// Disclose the leaf's full canonical object bytes.
    Object,
    /// Disclose one whole chunk of a `ChunkedBlob` leaf, by index.
    Chunk(u32),
    /// Disclose a byte range of a `Blob`/`ChunkedBlob` leaf's content.
    Range {
        /// Start offset within the leaf's content.
        offset: u64,
        /// Range length in bytes (MUST be non-zero).
        len: u64,
        /// When the leaf is a `ChunkedBlob`, also emit length proofs for
        /// every chunk before the one containing `offset`, so a verifier
        /// can compute an absolute file offset.
        with_offsets: bool,
    },
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/// Deserialize `bytes` and check that its content-address (BLAKE3 of the
/// bytes, or the merkle BMT root for a `Tree`/`ChunkedBlob`) equals
/// `expected`.
///
/// # Errors
///
/// [`VerifyError::Decode`] if `bytes` does not decode; otherwise
/// [`VerifyError::PayloadIdMismatch`] if the derived id disagrees with
/// `expected`.
/// Wrap-check-first: `domain_digest(TYPE_DOMAIN, inner_root) == expected_id`.
/// The declared field is never a second trust anchor.
fn check_inner_root_wrap(
    kind: ObjectKind,
    expected_id: &Hash,
    inner_root: &Hash,
) -> Result<(), VerifyError> {
    if merkle::wrap_id(kind, inner_root) == *expected_id {
        Ok(())
    } else {
        Err(VerifyError::InnerRootMismatch {
            expected: *expected_id,
            inner_root: *inner_root,
        })
    }
}

/// Proof fold equals the declared inner root, then wrap of the fold
/// equals `expected_id` (today's id check). Both must hold.
fn check_inner_root_fold(
    folded: Hash,
    declared: &Hash,
    expected_id: &Hash,
    kind: ObjectKind,
) -> Result<(), VerifyError> {
    if folded != *declared {
        return Err(VerifyError::InnerRootFoldMismatch);
    }
    if merkle::wrap_id(kind, &folded) == *expected_id {
        Ok(())
    } else {
        Err(VerifyError::Merkle(MerkleError::VerificationFailed))
    }
}

pub fn verify_object_id(bytes: &[u8], expected: &Hash) -> Result<Object, VerifyError> {
    let obj = crate::serialize::deserialize(bytes)?;
    let got = crate::object::id_from_object(&obj, bytes);
    if &got == expected {
        Ok(obj)
    } else {
        Err(VerifyError::PayloadIdMismatch)
    }
}

/// Verify a path of [`Step`]s from a commit/remix's `tree_hash` down to a
/// leaf id, checking each step's proof against the previous step's
/// `child_id` (the first against `tree_hash` itself).
///
/// `commit_bytes` MUST hash to `commit_id` and decode to a `Commit` or
/// `Remix` — every other object kind has no `tree_hash` to walk from.
/// Every non-final step MUST have `mode == Tree`. The returned `path` is
/// the authenticated `(name, mode)` sequence; callers compare it against
/// whatever path string they requested — this function never trusts one.
///
/// # Errors
///
/// See [`VerifyError`]'s variant docs for the specific failure reported.
pub fn verify_path(
    commit_id: &Hash,
    commit_bytes: &[u8],
    steps: &[Step],
) -> Result<PathVerified, VerifyError> {
    if hash(commit_bytes) != *commit_id {
        return Err(VerifyError::CommitBytesHashMismatch);
    }
    if steps.len() > MAX_TREE_DEPTH {
        return Err(VerifyError::TooManySteps(steps.len()));
    }
    let obj = crate::serialize::deserialize(commit_bytes)?;
    let (tree_hash, signer, signature_valid) = match &obj {
        Object::Commit(c) => (c.tree_hash, c.signer, verify_commit(c).is_ok()),
        Object::Remix(r) => (r.tree_hash, r.signer, verify_remix(r).is_ok()),
        other => return Err(VerifyError::NotACommitOrRemix(other.object_type())),
    };

    let mut expected_parent = tree_hash;
    let mut leaf_id = tree_hash;
    let mut path = Vec::with_capacity(steps.len());
    let last = steps.len().wrapping_sub(1);
    for (i, step) in steps.iter().enumerate() {
        if !TreeEntry::validate_name(&step.name) {
            return Err(VerifyError::InvalidEntryName(i));
        }
        if i != last && step.mode != EntryMode::Tree {
            return Err(VerifyError::NonFinalStepNotTree(i));
        }
        let entry = TreeEntry {
            name: step.name.clone(),
            mode: step.mode,
            object_hash: step.child_id,
        };
        check_inner_root_wrap(ObjectKind::Tree, &expected_parent, &step.inner_root)?;
        let folded = step
            .proof
            .reconstruct_element_root(&merkle::tree_entry_leaf(&entry), step.position)?;
        check_inner_root_fold(folded, &step.inner_root, &expected_parent, ObjectKind::Tree)?;
        path.push((step.name.clone(), step.mode));
        expected_parent = step.child_id;
        leaf_id = step.child_id;
    }

    Ok(PathVerified {
        tree_hash,
        path,
        leaf_id,
        signer,
        signature_valid,
    })
}

/// Verify that a `ChunkedBlob`'s claimed `total_size`/`chunk_size` and
/// the chunk `chunk_hash` at `index` both belong to the `ChunkedBlob`
/// whose id is `chunked_id`, via one multi-proof over BMT positions `{0,
/// index + 1}`.
///
/// The metadata leaf (position 0) is computed here from `total_size`/
/// `chunk_size` — never accepted as an externally supplied leaf digest —
/// so a forged pair fails to fold to `chunked_id`.
///
/// # Errors
///
/// [`VerifyError::ChunkIndexOutOfRange`]/[`VerifyError::TooManyChunks`]
/// for an out-of-bound `index` or an implausible `proof.leaf_count`;
/// otherwise [`VerifyError::Merkle`] if the multi-proof does not verify.
pub fn verify_chunk_with_meta(
    chunked_id: &Hash,
    total_size: u64,
    chunk_size: u32,
    chunk_hash: &Hash,
    index: u32,
    proof: &Proof,
) -> Result<(), VerifyError> {
    let chunk_count = proof
        .leaf_count
        .checked_sub(1)
        .ok_or(VerifyError::ChunkIndexOutOfRange {
            index,
            leaf_count: proof.leaf_count,
        })?;
    if chunk_count > crate::serialize::MAX_CHUNKS {
        return Err(VerifyError::TooManyChunks);
    }
    let position = index
        .checked_add(1)
        .filter(|&p| p < proof.leaf_count)
        .ok_or(VerifyError::ChunkIndexOutOfRange {
            index,
            leaf_count: proof.leaf_count,
        })?;
    merkle::verify_chunk_with_meta_leaf(
        chunked_id, total_size, chunk_size, chunk_hash, position, proof,
    )
    .map_err(VerifyError::from)
}

/// Like [`verify_chunk_with_meta`], plus the two SPEC-DISCLOSURE v2
/// inner-root rules: wrap-check-first against `chunked_id`, then the
/// multi-proof fold equals `inner_root`.
fn verify_chunk_with_declared_root(
    chunked_id: &Hash,
    inner_root: &Hash,
    total_size: u64,
    chunk_size: u32,
    chunk_hash: &Hash,
    index: u32,
    proof: &Proof,
) -> Result<(), VerifyError> {
    let chunk_count = proof
        .leaf_count
        .checked_sub(1)
        .ok_or(VerifyError::ChunkIndexOutOfRange {
            index,
            leaf_count: proof.leaf_count,
        })?;
    if chunk_count > crate::serialize::MAX_CHUNKS {
        return Err(VerifyError::TooManyChunks);
    }
    let position = index
        .checked_add(1)
        .filter(|&p| p < proof.leaf_count)
        .ok_or(VerifyError::ChunkIndexOutOfRange {
            index,
            leaf_count: proof.leaf_count,
        })?;
    check_inner_root_wrap(ObjectKind::ChunkedBlob, chunked_id, inner_root)?;
    let meta_leaf = merkle::chunked_meta_leaf_raw(total_size, chunk_size);
    let folded = proof.reconstruct_multi_root(&[(meta_leaf, 0u32), (*chunk_hash, position)])?;
    check_inner_root_fold(folded, inner_root, chunked_id, ObjectKind::ChunkedBlob)
}

/// Verify a Bao slice against `root`/`bao_offset`/`len`, returning the
/// decoded bytes. Shared by [`verify_blob_slice`] (content offset + 10)
/// and [`verify_blob_len_proof`] (raw offset 0, len 10 — the canonical
/// prologue itself).
fn bao_verify_slice(
    root: &Hash,
    bao_offset: u64,
    len: u64,
    slice: &[u8],
) -> Result<Vec<u8>, VerifyError> {
    let h: bao::Hash = (*root).into();
    let mut decoder =
        bao::decode::SliceDecoder::new(std::io::Cursor::new(slice), &h, bao_offset, len);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| VerifyError::Bao(e.to_string()))?;
    if out.len() as u64 != len {
        return Err(VerifyError::ShortSlice {
            expected: len,
            got: out.len(),
        });
    }
    Ok(out)
}

/// Verify a Bao slice proving `len` content bytes at `content_offset`
/// belong to the object (`Blob`, or one `ChunkedBlob` chunk) whose
/// canonical-bytes BLAKE3 is `blob_id`. `slice` is expected in the format
/// `bao::encode::SliceExtractor` produces over the object's **canonical**
/// bytes (prologue ‖ `le32(len)` ‖ data) — so a Bao-authenticated content
/// offset `o` maps to Bao offset `o + 10`, and the returned root equals
/// the object's own id (SPEC-OBJECTS §3).
///
/// # Errors
///
/// [`VerifyError::ZeroLengthRange`] if `len == 0`;
/// [`VerifyError::OffsetOverflow`] if `content_offset + 10` overflows
/// `u64`; [`VerifyError::Bao`]/[`VerifyError::ShortSlice`] if the slice
/// does not verify or yields fewer bytes than `len`.
pub fn verify_blob_slice(
    blob_id: &Hash,
    content_offset: u64,
    len: u64,
    slice: &[u8],
) -> Result<Vec<u8>, VerifyError> {
    if len == 0 {
        return Err(VerifyError::ZeroLengthRange);
    }
    let bao_offset = content_offset
        .checked_add(10)
        .ok_or(VerifyError::OffsetOverflow)?;
    bao_verify_slice(blob_id, bao_offset, len, slice)
}

/// Verify a Bao slice over canonical bytes `0..10` of the object whose
/// id is `blob_id`, and return the `le32` length field at bytes `6..10`
/// — the object's own declared content length, authenticated by the
/// first Bao leaf chunk (Bao's *encoding header* is not what is trusted
/// here; the canonical prologue bytes themselves are).
///
/// # Errors
///
/// [`VerifyError::InvalidBlobPrologue`] if the authenticated bytes are
/// not a valid v1 Blob prologue; otherwise the same Bao-decode errors as
/// [`verify_blob_slice`].
///
/// # Panics
///
/// Never in practice: `bao_verify_slice` (crate-private) guarantees
/// exactly 10 returned bytes for a requested `len` of 10, so the
/// `bytes[6..10]` slice always converts to `[u8; 4]`.
pub fn verify_blob_len_proof(blob_id: &Hash, slice: &[u8]) -> Result<u32, VerifyError> {
    let bytes = bao_verify_slice(blob_id, 0, 10, slice)?;
    if bytes[0] != ObjectType::Blob as u8 || bytes[1..5] != MAGIC || bytes[5] != SCHEMA_VERSION {
        return Err(VerifyError::InvalidBlobPrologue);
    }
    let len_bytes: [u8; 4] = bytes[6..10]
        .try_into()
        .expect("bao_verify_slice guarantees exactly 10 bytes");
    Ok(u32::from_le_bytes(len_bytes))
}

// ---------------------------------------------------------------------------
// Bundle: decode + verify
// ---------------------------------------------------------------------------

/// Wire representation of the `ChunkHdr` sub-message (Range payload,
/// chunked case). Kept private: callers see the authenticated
/// [`DisclosedPayload::Range`] fields, never this wire shape directly.
#[derive(Debug, Clone)]
struct ChunkHdr {
    total_size: u64,
    chunk_size: u32,
    index: u32,
    inner_root: Hash,
    chunk_id: Hash,
    proof: Proof,
}

impl Write for ChunkHdr {
    fn write(&self, writer: &mut impl BufMut) {
        self.total_size.write(writer);
        self.chunk_size.write(writer);
        self.index.write(writer);
        self.inner_root.write(writer);
        self.chunk_id.write(writer);
        self.proof.write(writer);
    }
}

impl EncodeSize for ChunkHdr {
    fn encode_size(&self) -> usize {
        self.total_size.encode_size()
            + self.chunk_size.encode_size()
            + self.index.encode_size()
            + self.inner_root.encode_size()
            + self.chunk_id.encode_size()
            + self.proof.encode_size()
    }
}

impl Read for ChunkHdr {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, (): &Self::Cfg) -> Result<Self, CodecError> {
        let total_size = u64::read(reader)?;
        let chunk_size = u32::read(reader)?;
        let index = u32::read(reader)?;
        let inner_root = Hash::read(reader)?;
        let chunk_id = Hash::read(reader)?;
        let proof = Proof::read_cfg(reader, &2usize)?;
        Ok(Self {
            total_size,
            chunk_size,
            index,
            inner_root,
            chunk_id,
            proof,
        })
    }
}

/// Wire representation of one `LenProof` entry (Range payload,
/// `with_offsets`). Kept private for the same reason as [`ChunkHdr`].
#[derive(Debug, Clone)]
struct LenProof {
    index: u32,
    chunk_id: Hash,
    proof: Proof,
    slice: Vec<u8>,
}

impl Write for LenProof {
    fn write(&self, writer: &mut impl BufMut) {
        self.index.write(writer);
        self.chunk_id.write(writer);
        self.proof.write(writer);
        self.slice.as_slice().write(writer);
    }
}

impl EncodeSize for LenProof {
    fn encode_size(&self) -> usize {
        self.index.encode_size()
            + self.chunk_id.encode_size()
            + self.proof.encode_size()
            + self.slice.as_slice().encode_size()
    }
}

impl Read for LenProof {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, (): &Self::Cfg) -> Result<Self, CodecError> {
        let index = u32::read(reader)?;
        let chunk_id = Hash::read(reader)?;
        let proof = Proof::read_cfg(reader, &1usize)?;
        let slice = Vec::<u8>::read_range(reader, ..=MAX_LEN_PROOF_SLICE_BYTES)?;
        Ok(Self {
            index,
            chunk_id,
            proof,
            slice,
        })
    }
}

impl Write for Step {
    fn write(&self, writer: &mut impl BufMut) {
        self.name.as_slice().write(writer);
        (self.mode as u8).write(writer);
        self.child_id.write(writer);
        self.inner_root.write(writer);
        self.position.write(writer);
        self.proof.write(writer);
    }
}

impl EncodeSize for Step {
    fn encode_size(&self) -> usize {
        self.name.as_slice().encode_size()
            + 1
            + self.child_id.encode_size()
            + self.inner_root.encode_size()
            + self.position.encode_size()
            + self.proof.encode_size()
    }
}

impl Read for Step {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, (): &Self::Cfg) -> Result<Self, CodecError> {
        let name = Vec::<u8>::read_range(reader, 1..=255)?;
        let mode_byte = u8::read(reader)?;
        let mode = EntryMode::from_u8(mode_byte).map_err(|_| CodecError::InvalidEnum(mode_byte))?;
        let child_id = Hash::read(reader)?;
        let inner_root = Hash::read(reader)?;
        let position = u32::read(reader)?;
        let proof = Proof::read_cfg(reader, &1usize)?;
        Ok(Self {
            name,
            mode,
            child_id,
            inner_root,
            position,
            proof,
        })
    }
}

/// Wire payload variants (`payload_kind` byte). Kept private: the public
/// surface is [`DisclosedPayload`] (verified) and [`Selector`] (build
/// request); this is only the on-wire shape between them.
enum PayloadWire {
    Object {
        bytes: Vec<u8>,
    },
    Chunk {
        total_size: u64,
        chunk_size: u32,
        index: u32,
        inner_root: Hash,
        proof: Proof,
        bytes: Vec<u8>,
    },
    Range {
        chunk: Option<ChunkHdr>,
        offset_in_blob: u64,
        len: u64,
        slice: Vec<u8>,
        chunk_len_proofs: Vec<LenProof>,
    },
}

/// Decode a disclosure bundle's fixed header plus codec body. Returns the
/// bundle's own embedded `commit_id` (still to be checked against the
/// caller's expected id by [`verify_disclosure`]), `commit_bytes`,
/// `steps`, and the decoded payload.
fn decode_disclosure(bytes: &[u8]) -> Result<(Hash, Vec<u8>, Vec<Step>, PayloadWire), VerifyError> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(VerifyError::BundleTooLarge);
    }
    if bytes.len() < 5 || bytes[..4] != *BUNDLE_MAGIC {
        return Err(VerifyError::BadMagic);
    }
    let version = bytes[4];
    if version != BUNDLE_VERSION {
        return Err(VerifyError::UnsupportedBundleVersion(version));
    }
    let mut r: &[u8] = &bytes[5..];
    let commit_id = Hash::read(&mut r)?;
    let commit_bytes = Vec::<u8>::read_range(&mut r, ..=MAX_COMMIT_BYTES)?;
    let steps = Vec::<Step>::read_range(&mut r, ..=MAX_TREE_DEPTH)?;
    let payload_kind = u8::read(&mut r)?;
    let payload = match payload_kind {
        0 => {
            let bytes = Vec::<u8>::read_range(&mut r, ..=crate::store::MAX_RAW_OBJECT_SIZE)?;
            PayloadWire::Object { bytes }
        }
        1 => {
            let total_size = u64::read(&mut r)?;
            let chunk_size = u32::read(&mut r)?;
            let index = u32::read(&mut r)?;
            let inner_root = Hash::read(&mut r)?;
            let proof = Proof::read_cfg(&mut r, &2usize)?;
            let bytes = Vec::<u8>::read_range(&mut r, ..=crate::store::MAX_RAW_OBJECT_SIZE)?;
            PayloadWire::Chunk {
                total_size,
                chunk_size,
                index,
                inner_root,
                proof,
                bytes,
            }
        }
        2 => {
            let chunk = Option::<ChunkHdr>::read(&mut r)?;
            let offset_in_blob = u64::read(&mut r)?;
            let len = u64::read(&mut r)?;
            let slice = Vec::<u8>::read_range(&mut r, ..=MAX_BUNDLE_BYTES)?;
            let chunk_len_proofs =
                Vec::<LenProof>::read_range(&mut r, ..=crate::serialize::MAX_CHUNKS as usize)?;
            PayloadWire::Range {
                chunk,
                offset_in_blob,
                len,
                slice,
                chunk_len_proofs,
            }
        }
        other => return Err(VerifyError::InvalidPayloadKind(other)),
    };
    if r.has_remaining() {
        return Err(VerifyError::Malformed);
    }
    Ok((commit_id, commit_bytes, steps, payload))
}

/// Encode a disclosure bundle. The inverse of [`decode_disclosure`].
fn encode_disclosure(
    commit_id: &Hash,
    commit_bytes: &[u8],
    steps: &[Step],
    payload: &PayloadWire,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(BUNDLE_MAGIC);
    out.push(BUNDLE_VERSION);
    commit_id.write(&mut out);
    commit_bytes.write(&mut out);
    steps.write(&mut out);
    match payload {
        PayloadWire::Object { bytes } => {
            out.push(0);
            bytes.as_slice().write(&mut out);
        }
        PayloadWire::Chunk {
            total_size,
            chunk_size,
            index,
            inner_root,
            proof,
            bytes,
        } => {
            out.push(1);
            total_size.write(&mut out);
            chunk_size.write(&mut out);
            index.write(&mut out);
            inner_root.write(&mut out);
            proof.write(&mut out);
            bytes.as_slice().write(&mut out);
        }
        PayloadWire::Range {
            chunk,
            offset_in_blob,
            len,
            slice,
            chunk_len_proofs,
        } => {
            out.push(2);
            chunk.write(&mut out);
            offset_in_blob.write(&mut out);
            len.write(&mut out);
            slice.as_slice().write(&mut out);
            chunk_len_proofs.write(&mut out);
        }
    }
    out
}

/// Verify each preceding chunk's authenticated length and, if the set is
/// complete, sum them. See [`DisclosedPayload::Range::absolute_offset`]
/// for the precise semantics (including the `index == 0` special case).
///
/// # Errors
///
/// [`VerifyError::IncompleteLengthProofSet`] if `chunk_len_proofs` is
/// non-empty but does not cover exactly `0..index`; propagates
/// [`VerifyError::Merkle`]/Bao errors from an individual proof.
fn resolve_absolute_offset(
    chunked_id: &Hash,
    index: u32,
    chunk_len_proofs: &[LenProof],
    offset_in_blob: u64,
) -> Result<Option<u64>, VerifyError> {
    if index == 0 {
        // Nothing precedes the first chunk; the offset is already
        // absolute regardless of whether the caller bothered to ask. A
        // non-empty `chunk_len_proofs` here has no chunk before index 0 to
        // describe, so it is rejected the same way the plain-blob path
        // rejects one — never silently ignored.
        if !chunk_len_proofs.is_empty() {
            return Err(VerifyError::UnexpectedLengthProofs);
        }
        return Ok(Some(offset_in_blob));
    }
    if chunk_len_proofs.is_empty() {
        return Ok(None);
    }
    let mut by_index: BTreeMap<u32, u32> = BTreeMap::new();
    for lp in chunk_len_proofs {
        if lp.index >= index || by_index.contains_key(&lp.index) {
            return Err(VerifyError::IncompleteLengthProofSet(index));
        }
        merkle::verify_chunk(chunked_id, &lp.chunk_id, lp.index + 1, &lp.proof)?;
        let len_j = verify_blob_len_proof(&lp.chunk_id, &lp.slice)?;
        by_index.insert(lp.index, len_j);
    }
    if u32::try_from(by_index.len()).unwrap_or(u32::MAX) != index {
        // Distinct, all < index, but fewer than `index` of them: a gap.
        return Err(VerifyError::IncompleteLengthProofSet(index));
    }
    let sum: u64 = by_index.values().map(|&l| u64::from(l)).sum();
    let absolute = sum
        .checked_add(offset_in_blob)
        .ok_or(VerifyError::OffsetOverflow)?;
    Ok(Some(absolute))
}

fn compose_payload(leaf_id: Hash, payload: PayloadWire) -> Result<DisclosedPayload, VerifyError> {
    match payload {
        PayloadWire::Object { bytes } => {
            verify_object_id(&bytes, &leaf_id)?;
            Ok(DisclosedPayload::Object { bytes })
        }
        PayloadWire::Chunk {
            total_size,
            chunk_size,
            index,
            inner_root,
            proof,
            bytes,
        } => {
            let chunk_hash = hash(&bytes);
            verify_chunk_with_declared_root(
                &leaf_id,
                &inner_root,
                total_size,
                chunk_size,
                &chunk_hash,
                index,
                &proof,
            )?;
            Ok(DisclosedPayload::Chunk {
                total_size,
                chunk_size,
                index,
                bytes,
            })
        }
        PayloadWire::Range {
            chunk: None,
            offset_in_blob,
            len,
            slice,
            chunk_len_proofs,
        } => {
            if !chunk_len_proofs.is_empty() {
                return Err(VerifyError::UnexpectedLengthProofs);
            }
            let bytes = verify_blob_slice(&leaf_id, offset_in_blob, len, &slice)?;
            Ok(DisclosedPayload::Range {
                blob_id: leaf_id,
                chunk: None,
                offset_in_blob,
                absolute_offset: Some(offset_in_blob),
                bytes,
            })
        }
        PayloadWire::Range {
            chunk: Some(hdr),
            offset_in_blob,
            len,
            slice,
            chunk_len_proofs,
        } => {
            // SPEC-DISCLOSURE §4: `len == 0` is rejected before the
            // wrap/fold checks below, so it wins over e.g. InnerRootMismatch
            // when a bundle is malformed both ways.
            if len == 0 {
                return Err(VerifyError::ZeroLengthRange);
            }
            verify_chunk_with_declared_root(
                &leaf_id,
                &hdr.inner_root,
                hdr.total_size,
                hdr.chunk_size,
                &hdr.chunk_id,
                hdr.index,
                &hdr.proof,
            )?;
            let bytes = verify_blob_slice(&hdr.chunk_id, offset_in_blob, len, &slice)?;
            let absolute_offset =
                resolve_absolute_offset(&leaf_id, hdr.index, &chunk_len_proofs, offset_in_blob)?;
            Ok(DisclosedPayload::Range {
                blob_id: hdr.chunk_id,
                chunk: Some((hdr.index, hdr.total_size, hdr.chunk_size)),
                offset_in_blob,
                absolute_offset,
                bytes,
            })
        }
    }
}

/// Decode and fully verify a disclosure bundle against `commit_id`.
///
/// # Errors
///
/// See [`VerifyError`]'s variant docs. In particular: a bundle whose
/// embedded `commit_id` disagrees with the argument, whose `commit_bytes`
/// does not hash to it, or whose payload fails its merkle/Bao check, is
/// rejected with a specific typed error — never a bare "invalid".
pub fn verify_disclosure(commit_id: &Hash, bundle: &[u8]) -> Result<Disclosed, VerifyError> {
    let (wire_commit_id, commit_bytes, steps, payload) = decode_disclosure(bundle)?;
    if wire_commit_id != *commit_id {
        return Err(VerifyError::CommitIdMismatch);
    }
    let verified = verify_path(commit_id, &commit_bytes, &steps)?;
    let step_inner_roots: Vec<Hash> = steps.iter().map(|s| s.inner_root).collect();
    let chunk_inner_root = match &payload {
        PayloadWire::Chunk { inner_root, .. } => Some(*inner_root),
        PayloadWire::Range {
            chunk: Some(hdr), ..
        } => Some(hdr.inner_root),
        _ => None,
    };
    let payload = compose_payload(verified.leaf_id, payload)?;
    Ok(Disclosed {
        commit_id: *commit_id,
        tree_hash: verified.tree_hash,
        path: verified.path,
        leaf_id: verified.leaf_id,
        payload,
        signer: verified.signer,
        signature_valid: verified.signature_valid,
        step_inner_roots,
        chunk_inner_root,
    })
}

// ---------------------------------------------------------------------------
// Builder (generic over `crate::store::ObjectSource`)
// ---------------------------------------------------------------------------

/// Build a Bao outboard encoding of `bytes` and extract a slice proving
/// `len` bytes at `bao_offset`.
fn extract_bao_slice(bytes: &[u8], bao_offset: u64, len: u64) -> Result<Vec<u8>, VerifyError> {
    let (outboard, _root) = bao::encode::outboard(bytes);
    let mut extractor = bao::encode::SliceExtractor::new_outboard(
        std::io::Cursor::new(bytes),
        std::io::Cursor::new(outboard),
        bao_offset,
        len,
    );
    let mut out = Vec::new();
    extractor
        .read_to_end(&mut out)
        .map_err(|e| VerifyError::Bao(e.to_string()))?;
    Ok(out)
}

/// Build a disclosure bundle proving `selector`'s content at `path` under
/// `commit_id`, reading only from `store`. `path` empty with
/// [`Selector::Object`] discloses the root tree.
///
/// A thin wrapper over [`build_disclosure_from`] for the on-disk
/// [`crate::store::ObjectStore`]; the bundle bytes are identical.
///
/// # Errors
///
/// [`VerifyError::Store`] for any missing/corrupt object; typed errors
/// (see [`VerifyError`]) for a path that does not resolve, a selector
/// that does not match the leaf's object type, an out-of-bounds range, or
/// a range that crosses a `ChunkedBlob` chunk boundary (unsupported in
/// this profile).
pub fn build_disclosure(
    store: &crate::store::ObjectStore,
    commit_id: &Hash,
    path: &[&[u8]],
    selector: Selector,
) -> Result<Vec<u8>, VerifyError> {
    build_disclosure_from(store, commit_id, path, selector)
}

/// Build a disclosure bundle proving `selector`'s content at `path` under
/// `commit_id`, reading only through `source`: any
/// [`crate::store::ObjectSource`] (the on-disk store, an
/// [`crate::store::EphemeralSink`], or a server-side repository index or
/// object CAS). Not to be confused with [`ObjectSource`], this module's
/// non-verifying closure-walker trait (`fetch(&mut self)`).
///
/// `source` MUST return verified bytes from `read`/`read_object` (the
/// [`crate::store::ObjectSource`] contract). The builder never calls
/// `read_unverified` and adds no verification of its own, so the bundle
/// bytes are identical to [`build_disclosure`]'s for the same objects.
/// [`crate::store::DisplaySource`] is therefore not a valid source: its
/// `read` skips verification.
///
/// A source that breaks the contract (returns bytes that do not hash to
/// the requested id) still cannot make the builder panic, and cannot make
/// it emit a bundle that verifies for content `commit_id` does not commit
/// to, because the bundle is self-authenticating against `commit_id`. The
/// build then either fails with a typed [`VerifyError`] or yields a bundle
/// that [`verify_disclosure`] rejects. It can still waste work: the
/// builder bounds nothing beyond what the objects themselves declare.
///
/// A source reports an absent object as
/// [`crate::store::StoreError::ObjectNotFound`], which surfaces as
/// [`VerifyError::Store`] exactly as on the store path.
///
/// # Errors
///
/// As [`build_disclosure`].
pub fn build_disclosure_from<S: crate::store::ObjectSource + ?Sized>(
    source: &S,
    commit_id: &Hash,
    path: &[&[u8]],
    selector: Selector,
) -> Result<Vec<u8>, VerifyError> {
    let commit_bytes = source.read(commit_id)?;
    let commit_obj = crate::serialize::deserialize(&commit_bytes)?;
    let tree_hash = match &commit_obj {
        Object::Commit(c) => c.tree_hash,
        Object::Remix(r) => r.tree_hash,
        other => return Err(VerifyError::NotACommitOrRemix(other.object_type())),
    };

    let mut steps = Vec::with_capacity(path.len());
    let mut current_tree_id = tree_hash;
    let mut leaf_id = tree_hash;
    for (i, &name) in path.iter().enumerate() {
        let Object::Tree(tree) = source.read_object(&current_tree_id)? else {
            return Err(VerifyError::PathThroughNonTree);
        };
        let position =
            merkle::tree_entry_position(&tree, name).ok_or(VerifyError::PathNotFound(i))?;
        let entry = tree.entries[position as usize].clone();
        let proof = merkle::build_tree_entry_proof(&tree, position)?;
        steps.push(Step {
            name: name.to_vec(),
            mode: entry.mode,
            child_id: entry.object_hash,
            inner_root: merkle::tree_inner_root(&tree),
            position,
            proof,
        });
        leaf_id = entry.object_hash;
        let is_last = i + 1 == path.len();
        if entry.mode == EntryMode::Tree {
            current_tree_id = entry.object_hash;
        } else if !is_last {
            return Err(VerifyError::PathThroughNonTree);
        }
    }

    let payload = build_payload(source, &leaf_id, selector)?;
    Ok(encode_disclosure(
        commit_id,
        &commit_bytes,
        &steps,
        &payload,
    ))
}

fn build_payload<S: crate::store::ObjectSource + ?Sized>(
    source: &S,
    leaf_id: &Hash,
    selector: Selector,
) -> Result<PayloadWire, VerifyError> {
    match selector {
        Selector::Object => {
            let bytes = source.read(leaf_id)?;
            Ok(PayloadWire::Object { bytes })
        }
        Selector::Chunk(index) => {
            let Object::ChunkedBlob(cb) = source.read_object(leaf_id)? else {
                return Err(VerifyError::SelectorLeafMismatch);
            };
            let leaf_count = u32::try_from(cb.chunks.len())
                .ok()
                .and_then(|n| n.checked_add(1))
                .ok_or(VerifyError::TooManyChunks)?;
            let chunk_id = *cb
                .chunks
                .get(index as usize)
                .ok_or(VerifyError::ChunkIndexOutOfRange { index, leaf_count })?;
            let position = index
                .checked_add(1)
                .ok_or(VerifyError::ChunkIndexOutOfRange { index, leaf_count })?;
            let proof = merkle::build_chunks_multi_proof(&cb, [0, position])?;
            let bytes = source.read(&chunk_id)?;
            Ok(PayloadWire::Chunk {
                total_size: cb.total_size,
                chunk_size: cb.chunk_size,
                index,
                inner_root: merkle::chunked_inner_root(&cb),
                proof,
                bytes,
            })
        }
        Selector::Range {
            offset,
            len,
            with_offsets,
        } => {
            if len == 0 {
                return Err(VerifyError::ZeroLengthRange);
            }
            match source.read_object(leaf_id)? {
                Object::Blob(b) => {
                    let end = offset.checked_add(len).ok_or(VerifyError::OffsetOverflow)?;
                    if end > b.data.len() as u64 {
                        return Err(VerifyError::RangeOutOfBounds);
                    }
                    let canonical = source.read(leaf_id)?;
                    let bao_offset = offset.checked_add(10).ok_or(VerifyError::OffsetOverflow)?;
                    let slice = extract_bao_slice(&canonical, bao_offset, len)?;
                    Ok(PayloadWire::Range {
                        chunk: None,
                        offset_in_blob: offset,
                        len,
                        slice,
                        chunk_len_proofs: Vec::new(),
                    })
                }
                Object::ChunkedBlob(cb) => {
                    build_chunked_range_payload(source, &cb, offset, len, with_offsets)
                }
                _ => Err(VerifyError::SelectorLeafMismatch),
            }
        }
    }
}

fn build_chunked_range_payload<S: crate::store::ObjectSource + ?Sized>(
    source: &S,
    cb: &crate::object::ChunkedBlob,
    offset: u64,
    len: u64,
    with_offsets: bool,
) -> Result<PayloadWire, VerifyError> {
    // Read every chunk's canonical bytes once, up front: needed both to
    // locate the containing chunk (chunk lengths aren't in the manifest)
    // and, when `with_offsets` is set, to build each preceding chunk's
    // length proof.
    let chunk_bytes: Vec<Vec<u8>> = cb
        .chunks
        .iter()
        .map(|id| source.read(id))
        .collect::<Result<_, _>>()?;

    // Every length and offset below is checked: `source` bytes and the
    // caller's `offset`/`len` are both untrusted here, and a panic (the
    // release profile has `overflow-checks = true`) is never acceptable.
    let mut cumulative: u64 = 0;
    let mut located = None;
    for (idx, bytes) in chunk_bytes.iter().enumerate() {
        // A chunk is a `Blob`: 10-byte prologue (6-byte header + u32
        // length) then content. Anything shorter is a truncated object.
        let content_len = bytes
            .len()
            .checked_sub(10)
            .ok_or(VerifyError::Decode(MkitError::UnexpectedEof))? as u64;
        let chunk_end = cumulative
            .checked_add(content_len)
            .ok_or(VerifyError::OffsetOverflow)?;
        if offset < chunk_end {
            located = Some((idx, cumulative, content_len));
            break;
        }
        cumulative = chunk_end;
    }
    let (index, chunk_start, content_len) = located.ok_or(VerifyError::RangeOutOfBounds)?;
    let offset_in_chunk = offset
        .checked_sub(chunk_start)
        .ok_or(VerifyError::OffsetOverflow)?;
    let range_end = offset_in_chunk
        .checked_add(len)
        .ok_or(VerifyError::OffsetOverflow)?;
    if range_end > content_len {
        return Err(VerifyError::RangeCrossesChunkBoundary);
    }

    let index_u32 = u32::try_from(index).map_err(|_| VerifyError::TooManyChunks)?;
    let position = index_u32.checked_add(1).ok_or(VerifyError::TooManyChunks)?;
    let proof = merkle::build_chunks_multi_proof(cb, [0, position])?;
    let bao_offset = offset_in_chunk
        .checked_add(10)
        .ok_or(VerifyError::OffsetOverflow)?;
    let slice = extract_bao_slice(&chunk_bytes[index], bao_offset, len)?;

    let mut chunk_len_proofs = Vec::new();
    if with_offsets {
        for (j, preceding_bytes) in chunk_bytes.iter().enumerate().take(index) {
            let j_u32 = u32::try_from(j).map_err(|_| VerifyError::TooManyChunks)?;
            let position_j = j_u32.checked_add(1).ok_or(VerifyError::TooManyChunks)?;
            let proof_j = merkle::build_chunk_proof(cb, position_j)?;
            let slice_j = extract_bao_slice(preceding_bytes, 0, 10)?;
            chunk_len_proofs.push(LenProof {
                index: j_u32,
                chunk_id: cb.chunks[j],
                proof: proof_j,
                slice: slice_j,
            });
        }
    }

    Ok(PayloadWire::Range {
        chunk: Some(ChunkHdr {
            total_size: cb.total_size,
            chunk_size: cb.chunk_size,
            index: index_u32,
            inner_root: merkle::chunked_inner_root(cb),
            chunk_id: cb.chunks[index],
            proof,
        }),
        offset_in_blob: offset_in_chunk,
        len,
        slice,
        chunk_len_proofs,
    })
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
mod tests {
    use super::*;
    use crate::hash::ZERO;
    use crate::layout::RepoLayout;
    use crate::object::{Commit, Identity, Tree};
    use crate::sign::{KeyPair, sign_commit};
    use crate::store::ObjectStore;
    use crate::worktree::store_file_object;

    /// A small deterministic repo: root tree with a shallow file, a
    /// 3-level-nested file, an executable file, and a chunked (> 1 MiB)
    /// file, committed under a fixed signer. Built fresh (native
    /// `ObjectStore`, no golden files) for this module's own unit tests;
    /// `tests/golden_disclosure.rs` carries the pinned wire-byte fixture.
    struct Fixture {
        _dir: tempfile::TempDir,
        store: ObjectStore,
        commit_id: Hash,
        chunked_bytes: Vec<u8>,
    }

    fn build_fixture() -> Fixture {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("store init");

        let shallow = store_file_object(&store, b"shallow file content").unwrap();
        let deep_file = store_file_object(&store, b"three levels deep").unwrap();
        let exec = store_file_object(&store, b"#!/bin/sh\necho hi\n").unwrap();

        // Deterministic pseudo-random 2 MiB stream so FastCDC yields
        // several chunks.
        let mut chunked_bytes = vec![0u8; 2 * 1024 * 1024];
        let mut x: u64 = 0x1234_5678_9abc_def0;
        for b in &mut chunked_bytes {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            *b = (x >> 56) as u8;
        }
        let chunked_id = store_file_object(&store, &chunked_bytes).unwrap();

        let deep_tree = Tree {
            entries: vec![TreeEntry {
                name: b"deep.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: deep_file,
            }],
        };
        let deep_tree_id = store
            .write(&crate::serialize::serialize(&Object::Tree(deep_tree)).unwrap())
            .unwrap();

        let mid_tree = Tree {
            entries: vec![TreeEntry {
                name: b"deep".to_vec(),
                mode: EntryMode::Tree,
                object_hash: deep_tree_id,
            }],
        };
        let mid_tree_id = store
            .write(&crate::serialize::serialize(&Object::Tree(mid_tree)).unwrap())
            .unwrap();

        let root_tree = Tree {
            entries: vec![
                TreeEntry {
                    name: b"chunked.bin".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: chunked_id,
                },
                TreeEntry {
                    name: b"exec.sh".to_vec(),
                    mode: EntryMode::Executable,
                    object_hash: exec,
                },
                TreeEntry {
                    name: b"shallow.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: shallow,
                },
                TreeEntry {
                    name: b"sub".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: mid_tree_id,
                },
            ],
        };
        let tree_hash = store
            .write(&crate::serialize::serialize(&Object::Tree(root_tree)).unwrap())
            .unwrap();

        let kp = KeyPair::from_seed([0x07; 32]);
        let mut commit = Commit {
            tree_hash,
            parents: vec![],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"disclosure fixture".to_vec(),
            timestamp: 1_726_300_000,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0u8; 64],
        };
        commit.signature = sign_commit(&commit, &kp).unwrap().0;
        let commit_bytes = crate::serialize::serialize(&Object::Commit(commit)).unwrap();
        let commit_id = store.write(&commit_bytes).unwrap();

        Fixture {
            _dir: dir,
            store,
            commit_id,
            chunked_bytes,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // exercises every Selector against one fixture, kept together for auditability
    fn round_trips_every_selector() {
        let f = build_fixture();

        // Root tree, via Object.
        let bundle = build_disclosure(&f.store, &f.commit_id, &[], Selector::Object).unwrap();
        let d = verify_disclosure(&f.commit_id, &bundle).unwrap();
        assert!(d.path.is_empty());
        assert_eq!(d.leaf_id, d.tree_hash);
        assert!(d.signature_valid);

        // Shallow file, via Object.
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();
        let d = verify_disclosure(&f.commit_id, &bundle).unwrap();
        assert_eq!(d.path, vec![(b"shallow.txt".to_vec(), EntryMode::Blob)]);
        let DisclosedPayload::Object { bytes } = d.payload else {
            panic!("expected Object payload");
        };
        assert_eq!(
            bytes,
            crate::serialize::serialize(&Object::Blob(crate::object::Blob {
                data: b"shallow file content".to_vec()
            }))
            .unwrap()
        );

        // Nested (3-level) file.
        let bundle = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"sub", b"deep", b"deep.txt"],
            Selector::Object,
        )
        .unwrap();
        let d = verify_disclosure(&f.commit_id, &bundle).unwrap();
        assert_eq!(
            d.path,
            vec![
                (b"sub".to_vec(), EntryMode::Tree),
                (b"deep".to_vec(), EntryMode::Tree),
                (b"deep.txt".to_vec(), EntryMode::Blob),
            ]
        );

        // Executable-mode file.
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"exec.sh"], Selector::Object).unwrap();
        let d = verify_disclosure(&f.commit_id, &bundle).unwrap();
        assert_eq!(d.path, vec![(b"exec.sh".to_vec(), EntryMode::Executable)]);

        // One chunk of the chunked file.
        let bundle = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"chunked.bin"],
            Selector::Chunk(1),
        )
        .unwrap();
        let d = verify_disclosure(&f.commit_id, &bundle).unwrap();
        let DisclosedPayload::Chunk { index, .. } = d.payload else {
            panic!("expected Chunk payload");
        };
        assert_eq!(index, 1);

        // Range inside a chunk, without offsets.
        let bundle = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"chunked.bin"],
            Selector::Range {
                offset: 200_000,
                len: 64,
                with_offsets: false,
            },
        )
        .unwrap();
        let d = verify_disclosure(&f.commit_id, &bundle).unwrap();
        let DisclosedPayload::Range {
            chunk,
            absolute_offset,
            bytes,
            ..
        } = d.payload
        else {
            panic!("expected Range payload");
        };
        assert!(chunk.is_some());
        assert_eq!(bytes.len(), 64);

        // Same range, with offsets: absolute_offset must be provable
        // (this fixture's chosen offset lands past chunk 0).
        let bundle_off = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"chunked.bin"],
            Selector::Range {
                offset: 200_000,
                len: 64,
                with_offsets: true,
            },
        )
        .unwrap();
        let d_off = verify_disclosure(&f.commit_id, &bundle_off).unwrap();
        let DisclosedPayload::Range {
            absolute_offset: abs_off,
            bytes: bytes_off,
            chunk: chunk_off,
            ..
        } = d_off.payload
        else {
            panic!("expected Range payload");
        };
        assert_ne!(chunk_off.map(|(idx, _, _)| idx), Some(0));
        assert_eq!(abs_off, Some(200_000));
        assert_eq!(bytes_off, f.chunked_bytes[200_000..200_064]);
        // The no-offsets bundle for the same range discloses the same
        // bytes either way.
        assert_eq!(bytes, bytes_off);
        assert_eq!(absolute_offset, None);

        // Range covering a whole small blob.
        let bundle = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"shallow.txt"],
            Selector::Range {
                offset: 0,
                len: "shallow file content".len() as u64,
                with_offsets: false,
            },
        )
        .unwrap();
        let d = verify_disclosure(&f.commit_id, &bundle).unwrap();
        let DisclosedPayload::Range { bytes, chunk, .. } = d.payload else {
            panic!("expected Range payload");
        };
        assert!(chunk.is_none());
        assert_eq!(bytes, b"shallow file content");
    }

    #[test]
    fn verify_object_id_rejects_mismatch() {
        let f = build_fixture();
        let bytes = f
            .store
            .read(&f.commit_id)
            .expect("commit_id was just written");
        assert!(matches!(
            verify_object_id(&bytes, &ZERO),
            Err(VerifyError::PayloadIdMismatch)
        ));
        verify_object_id(&bytes, &f.commit_id).expect("matches itself");
    }

    #[test]
    fn verify_path_rejects_wrong_commit_bytes_hash() {
        let f = build_fixture();
        let commit_bytes = f.store.read(&f.commit_id).unwrap();
        assert!(matches!(
            verify_path(&ZERO, &commit_bytes, &[]),
            Err(VerifyError::CommitBytesHashMismatch)
        ));
    }

    #[test]
    fn verify_path_rejects_non_final_non_tree_mode() {
        let f = build_fixture();
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();
        // A second, non-final step whose mode is Blob (not Tree) must be
        // rejected — the wire-level decode bound (steps <= 128) doesn't
        // catch this; only the semantic check does.
        let (_id, commit_bytes, mut steps, _payload) = decode_disclosure(&bundle).unwrap();
        assert_eq!(steps.len(), 1);
        let dup = steps[0].clone();
        steps.push(dup);
        assert!(matches!(
            verify_path(&f.commit_id, &commit_bytes, &steps),
            Err(VerifyError::NonFinalStepNotTree(0))
        ));
    }

    #[test]
    fn verify_path_rejects_too_many_steps() {
        let f = build_fixture();
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();
        let (_id, commit_bytes, steps, _payload) = decode_disclosure(&bundle).unwrap();
        let too_many: Vec<Step> =
            std::iter::repeat_n(steps[0].clone(), MAX_TREE_DEPTH + 1).collect();
        assert!(matches!(
            verify_path(&f.commit_id, &commit_bytes, &too_many),
            Err(VerifyError::TooManySteps(_))
        ));
    }

    #[test]
    fn verify_path_rejects_invalid_entry_name() {
        let f = build_fixture();
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();
        let (_id, commit_bytes, mut steps, _payload) = decode_disclosure(&bundle).unwrap();
        steps[0].name = b"trailing space ".to_vec();
        assert!(matches!(
            verify_path(&f.commit_id, &commit_bytes, &steps),
            Err(VerifyError::InvalidEntryName(0))
        ));
    }

    #[test]
    fn verify_path_rejects_swapped_step_proof() {
        let f = build_fixture();
        let bundle = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"sub", b"deep", b"deep.txt"],
            Selector::Object,
        )
        .unwrap();
        let (_id, commit_bytes, mut steps, _payload) = decode_disclosure(&bundle).unwrap();
        assert_eq!(steps.len(), 3);
        steps.swap(0, 1);
        assert!(matches!(
            verify_path(&f.commit_id, &commit_bytes, &steps),
            Err(VerifyError::InnerRootMismatch { .. } | VerifyError::Merkle(_))
        ));
    }

    #[test]
    fn verify_path_rejects_non_commit_non_remix() {
        let f = build_fixture();
        // A Tag targeting the commit: valid bytes, wrong object kind.
        let tag = crate::object::Tag {
            target: f.commit_id,
            target_type: ObjectType::Commit,
            name: b"v1".to_vec(),
            tagger: Identity::ed25519([9u8; 32]),
            signer: [9u8; 32],
            message: Vec::new(),
            timestamp: 0,
            signature: [0u8; 64],
        };
        let tag_bytes = crate::serialize::serialize(&Object::Tag(tag)).unwrap();
        let tag_id = crate::hash::hash(&tag_bytes);
        assert!(matches!(
            verify_path(&tag_id, &tag_bytes, &[]),
            Err(VerifyError::NotACommitOrRemix(ObjectType::Tag))
        ));
    }

    #[test]
    fn verify_chunk_with_meta_bounds() {
        let f = build_fixture();
        let bundle = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"chunked.bin"],
            Selector::Chunk(1),
        )
        .unwrap();
        let (_id, _commit_bytes, steps, payload) = decode_disclosure(&bundle).unwrap();
        let leaf_id = steps[0].child_id;
        let PayloadWire::Chunk {
            total_size,
            chunk_size,
            index,
            proof,
            bytes,
            ..
        } = payload
        else {
            panic!("expected Chunk payload");
        };
        let chunk_hash = hash(&bytes);

        verify_chunk_with_meta(&leaf_id, total_size, chunk_size, &chunk_hash, index, &proof)
            .expect("freshly built chunk proof must verify");
        // Forged total_size.
        assert!(matches!(
            verify_chunk_with_meta(
                &leaf_id,
                total_size + 1,
                chunk_size,
                &chunk_hash,
                index,
                &proof
            ),
            Err(VerifyError::Merkle(_))
        ));
        // Out-of-range index (one past the last valid position).
        assert!(matches!(
            verify_chunk_with_meta(
                &leaf_id,
                total_size,
                chunk_size,
                &chunk_hash,
                proof.leaf_count,
                &proof
            ),
            Err(VerifyError::ChunkIndexOutOfRange { .. })
        ));
    }

    #[test]
    fn verify_blob_slice_and_len_proof_round_trip() {
        let content = b"the quick brown fox jumps over the lazy dog";
        let canonical = {
            let prologue = crate::serialize::blob_prologue(content.len()).unwrap();
            let mut v = prologue.to_vec();
            v.extend_from_slice(content);
            v
        };
        let blob_id = crate::hash::hash(&canonical);
        let (outboard, _root) = bao::encode::outboard(&canonical);

        let mut extractor = bao::encode::SliceExtractor::new_outboard(
            std::io::Cursor::new(&canonical),
            std::io::Cursor::new(&outboard),
            10, // content offset 0 -> bao offset 10
            content.len() as u64,
        );
        let mut slice = Vec::new();
        std::io::Read::read_to_end(&mut extractor, &mut slice).unwrap();

        let got = verify_blob_slice(&blob_id, 0, content.len() as u64, &slice).unwrap();
        assert_eq!(got, content);

        // Zero length is always rejected, regardless of slice bytes.
        assert!(matches!(
            verify_blob_slice(&blob_id, 0, 0, &slice),
            Err(VerifyError::ZeroLengthRange)
        ));

        // Length proof over bytes 0..10.
        let mut len_extractor = bao::encode::SliceExtractor::new_outboard(
            std::io::Cursor::new(&canonical),
            std::io::Cursor::new(&outboard),
            0,
            10,
        );
        let mut len_slice = Vec::new();
        std::io::Read::read_to_end(&mut len_extractor, &mut len_slice).unwrap();
        let len = verify_blob_len_proof(&blob_id, &len_slice).unwrap();
        assert_eq!(len as usize, content.len());
    }

    #[test]
    fn zero_length_range_rejected_end_to_end() {
        let f = build_fixture();
        assert!(matches!(
            build_disclosure(
                &f.store,
                &f.commit_id,
                &[b"shallow.txt"],
                Selector::Range {
                    offset: 0,
                    len: 0,
                    with_offsets: false
                }
            ),
            Err(VerifyError::ZeroLengthRange)
        ));
    }

    #[test]
    fn range_crossing_chunk_boundary_rejected() {
        let f = build_fixture();
        // The full 2 MiB span certainly crosses at least one chunk
        // boundary (chunks average well under 1 MiB).
        assert!(matches!(
            build_disclosure(
                &f.store,
                &f.commit_id,
                &[b"chunked.bin"],
                Selector::Range {
                    offset: 0,
                    len: f.chunked_bytes.len() as u64,
                    with_offsets: false,
                }
            ),
            Err(VerifyError::RangeCrossesChunkBoundary)
        ));
    }

    #[test]
    fn incomplete_length_proof_set_is_rejected() {
        let f = build_fixture();
        let bundle = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"chunked.bin"],
            Selector::Range {
                offset: 700_000,
                len: 16,
                with_offsets: true,
            },
        )
        .unwrap();
        let (commit_id, commit_bytes, steps, payload) = decode_disclosure(&bundle).unwrap();
        let PayloadWire::Range {
            chunk,
            offset_in_blob,
            len,
            slice,
            mut chunk_len_proofs,
        } = payload
        else {
            panic!("expected Range payload");
        };
        let hdr = chunk.clone().expect("chunked leaf");
        assert!(hdr.index > 0, "test fixture assumption: chunk index > 0");
        // Drop one proof: incomplete coverage of 0..index.
        chunk_len_proofs.remove(0);
        let tampered = encode_disclosure(
            &commit_id,
            &commit_bytes,
            &steps,
            &PayloadWire::Range {
                chunk,
                offset_in_blob,
                len,
                slice,
                chunk_len_proofs,
            },
        );
        assert!(matches!(
            verify_disclosure(&f.commit_id, &tampered),
            Err(VerifyError::IncompleteLengthProofSet(_))
        ));
    }

    #[test]
    fn resolve_absolute_offset_rejects_overflow() {
        // `resolve_absolute_offset` sums verified preceding-chunk lengths
        // and adds `offset_in_blob`; that final addition must be checked
        // like every neighbouring offset computation, not silently wrap.
        let f = build_fixture();
        let bundle = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"chunked.bin"],
            Selector::Range {
                offset: 700_000,
                len: 16,
                with_offsets: true,
            },
        )
        .unwrap();
        let (_id, _commit_bytes, steps, payload) = decode_disclosure(&bundle).unwrap();
        let leaf_id = steps[0].child_id;
        let PayloadWire::Range {
            chunk,
            offset_in_blob,
            chunk_len_proofs,
            ..
        } = payload
        else {
            panic!("expected Range payload");
        };
        let hdr = chunk.expect("chunked leaf");
        assert!(hdr.index > 0, "test fixture assumption: chunk index > 0");

        assert!(matches!(
            resolve_absolute_offset(&leaf_id, hdr.index, &chunk_len_proofs, u64::MAX),
            Err(VerifyError::OffsetOverflow)
        ));

        // Sanity: the same, real proof set still resolves with a
        // non-overflowing offset.
        resolve_absolute_offset(&leaf_id, hdr.index, &chunk_len_proofs, offset_in_blob)
            .expect("freshly built length proofs must resolve");
    }

    #[test]
    fn len_proofs_on_chunk0_are_rejected() {
        // Chunk 0 has nothing preceding it, so `chunk_len_proofs` MUST be
        // empty there too — the same rule the plain-`Blob` path already
        // enforces (`UnexpectedLengthProofs`). `resolve_absolute_offset`'s
        // `index == 0` early return must not silently ignore a non-empty
        // set (SPEC-DISCLOSURE §4).
        let f = build_fixture();
        let bundle = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"chunked.bin"],
            Selector::Range {
                offset: 0,
                len: 8,
                with_offsets: false,
            },
        )
        .unwrap();
        let (commit_id, commit_bytes, steps, payload) = decode_disclosure(&bundle).unwrap();
        let PayloadWire::Range {
            chunk,
            offset_in_blob,
            len,
            slice,
            chunk_len_proofs,
        } = payload
        else {
            panic!("expected Range payload");
        };
        let hdr = chunk.clone().expect("chunked leaf");
        assert_eq!(hdr.index, 0, "test fixture assumption: offset 0 is chunk 0");
        assert!(
            chunk_len_proofs.is_empty(),
            "builder never emits proofs for chunk 0"
        );

        // Forge a bogus (but structurally valid) length-proof entry — its
        // content doesn't matter, because it must be rejected before any
        // proof inside it is even checked.
        let forged = vec![LenProof {
            index: 0,
            chunk_id: [0u8; 32],
            proof: Proof::default(),
            slice: Vec::new(),
        }];
        let tampered = encode_disclosure(
            &commit_id,
            &commit_bytes,
            &steps,
            &PayloadWire::Range {
                chunk,
                offset_in_blob,
                len,
                slice,
                chunk_len_proofs: forged,
            },
        );
        assert!(matches!(
            verify_disclosure(&f.commit_id, &tampered),
            Err(VerifyError::UnexpectedLengthProofs)
        ));
    }

    #[test]
    fn decode_rejects_bad_magic_version_and_trailing_bytes() {
        let f = build_fixture();
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();

        let mut bad_magic = bundle.clone();
        bad_magic[0] = b'X';
        assert!(matches!(
            verify_disclosure(&f.commit_id, &bad_magic),
            Err(VerifyError::BadMagic)
        ));

        let mut bad_version = bundle.clone();
        bad_version[4] = 1;
        assert!(matches!(
            verify_disclosure(&f.commit_id, &bad_version),
            Err(VerifyError::UnsupportedBundleVersion(1))
        ));

        let mut trailing = bundle.clone();
        trailing.push(0);
        assert!(matches!(
            verify_disclosure(&f.commit_id, &trailing),
            Err(VerifyError::Malformed)
        ));

        let oversize = vec![0u8; MAX_BUNDLE_BYTES + 1];
        assert!(matches!(
            verify_disclosure(&f.commit_id, &oversize),
            Err(VerifyError::BundleTooLarge)
        ));
    }

    #[test]
    fn decode_rejects_unknown_payload_kind() {
        let f = build_fixture();
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();
        let (commit_id, commit_bytes, steps, _payload) = decode_disclosure(&bundle).unwrap();

        // Recompute the prefix (magic + version + commit_id +
        // commit_bytes + steps) to find the payload_kind byte's offset
        // in the real bundle, rather than hand-computing it.
        let mut prefix = Vec::new();
        prefix.extend_from_slice(BUNDLE_MAGIC);
        prefix.push(BUNDLE_VERSION);
        commit_id.write(&mut prefix);
        commit_bytes.as_slice().write(&mut prefix);
        steps.as_slice().write(&mut prefix);
        let kind_offset = prefix.len();
        assert_eq!(bundle[kind_offset], 0, "Object payload_kind must be 0");

        let mut tampered = bundle.clone();
        tampered[kind_offset] = 0xFF;
        assert!(matches!(
            verify_disclosure(&f.commit_id, &tampered),
            Err(VerifyError::InvalidPayloadKind(0xFF))
        ));
    }

    #[test]
    fn payload_id_mismatch_is_rejected() {
        let f = build_fixture();
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();
        let (commit_id, commit_bytes, steps, payload) = decode_disclosure(&bundle).unwrap();
        let PayloadWire::Object { mut bytes } = payload else {
            panic!("expected Object payload");
        };
        *bytes.last_mut().unwrap() ^= 0xFF;
        let tampered = encode_disclosure(
            &commit_id,
            &commit_bytes,
            &steps,
            &PayloadWire::Object { bytes },
        );
        assert!(matches!(
            verify_disclosure(&f.commit_id, &tampered),
            Err(VerifyError::PayloadIdMismatch)
        ));
    }

    #[test]
    fn commit_id_mismatch_is_rejected() {
        let f = build_fixture();
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();
        assert!(matches!(
            verify_disclosure(&ZERO, &bundle),
            Err(VerifyError::CommitIdMismatch)
        ));
    }

    #[test]
    fn inner_root_forged_is_rejected() {
        let f = build_fixture();
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();
        let (commit_id, commit_bytes, mut steps, payload) = decode_disclosure(&bundle).unwrap();
        steps[0].inner_root[0] ^= 0xFF;
        let tampered = encode_disclosure(&commit_id, &commit_bytes, &steps, &payload);
        assert!(matches!(
            verify_disclosure(&f.commit_id, &tampered),
            Err(VerifyError::InnerRootMismatch { .. })
        ));
    }

    #[test]
    fn inner_root_fold_mismatch_is_rejected() {
        let f = build_fixture();
        let nested = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"sub", b"deep", b"deep.txt"],
            Selector::Object,
        )
        .unwrap();
        let shallow =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();
        let (commit_id, commit_bytes, mut steps, payload) = decode_disclosure(&shallow).unwrap();
        let (_, _, nested_steps, _) = decode_disclosure(&nested).unwrap();
        // Keep the wrap-correct inner_root of the root tree, but swap in
        // a proof built against a different tree so the fold disagrees.
        steps[0].proof = nested_steps[1].proof.clone();
        steps[0].position = nested_steps[1].position;
        let tampered = encode_disclosure(&commit_id, &commit_bytes, &steps, &payload);
        assert!(matches!(
            verify_disclosure(&f.commit_id, &tampered),
            Err(VerifyError::InnerRootFoldMismatch)
        ));
    }

    // --- `build_disclosure_from` over a generic `store::ObjectSource` ---

    use crate::store::StoreError;

    /// A verifying in-memory [`crate::store::ObjectSource`]: every `read`
    /// re-derives the object id (the trait contract), so it stands in for
    /// a server-side per-repository index or global CAS.
    struct MapSource(BTreeMap<Hash, Vec<u8>>);

    impl MapSource {
        /// Every object currently in `store`.
        fn from_store(store: &ObjectStore) -> Self {
            let map = store
                .iter_object_hashes()
                .unwrap()
                .into_iter()
                .map(|h| (h, store.read(&h).unwrap()))
                .collect();
            Self(map)
        }
    }

    impl crate::store::ObjectSource for MapSource {
        fn read(&self, h: &Hash) -> crate::store::StoreResult<Vec<u8>> {
            let bytes = self
                .0
                .get(h)
                .ok_or_else(|| StoreError::ObjectNotFound(crate::hash::to_hex(h)))?;
            verify_object_id(bytes, h).map_err(|_| StoreError::HashMismatch {
                expected: crate::hash::to_hex(h),
                actual: String::from("<mismatch>"),
            })?;
            Ok(bytes.clone())
        }
    }

    /// A deliberately NON-verifying source (violates the
    /// `store::ObjectSource` contract): serves `lie`'s bytes for `target`.
    struct LyingSource<'a> {
        inner: &'a MapSource,
        target: Hash,
        lie: Vec<u8>,
    }

    impl crate::store::ObjectSource for LyingSource<'_> {
        fn read(&self, h: &Hash) -> crate::store::StoreResult<Vec<u8>> {
            if *h == self.target {
                return Ok(self.lie.clone());
            }
            crate::store::ObjectSource::read(self.inner, h)
        }
    }

    /// Another contract-violating source: `read_object(target)` decodes
    /// `object_lie`, while `read(target)` still returns the honest bytes,
    /// so the two methods disagree about the same id.
    struct SplitSource<'a> {
        inner: &'a MapSource,
        target: Hash,
        object_lie: Object,
    }

    impl crate::store::ObjectSource for SplitSource<'_> {
        fn read(&self, h: &Hash) -> crate::store::StoreResult<Vec<u8>> {
            crate::store::ObjectSource::read(self.inner, h)
        }

        fn read_object(&self, h: &Hash) -> crate::store::StoreResult<Object> {
            if *h == self.target {
                return Ok(self.object_lie.clone());
            }
            crate::store::ObjectSource::read_object(self.inner, h)
        }
    }

    /// Id of the entry `name` in the tree `tree_id`.
    fn entry_id(store: &ObjectStore, tree_id: &Hash, name: &[u8]) -> Hash {
        let Object::Tree(tree) = store.read_object(tree_id).unwrap() else {
            panic!("expected a tree");
        };
        tree.entries
            .iter()
            .find(|e| e.name == name)
            .unwrap()
            .object_hash
    }

    fn root_tree_id(store: &ObjectStore, commit_id: &Hash) -> Hash {
        let Object::Commit(c) = store.read_object(commit_id).unwrap() else {
            panic!("expected a commit");
        };
        c.tree_hash
    }

    /// A second commit (in the fixture store) whose root holds one plain,
    /// multi-Bao-block `Blob`, so small-blob ranges span block boundaries.
    fn medium_blob_commit(f: &Fixture) -> Hash {
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let blob = store_file_object(&f.store, &data).unwrap();
        assert!(matches!(
            f.store.read_object(&blob).unwrap(),
            Object::Blob(_)
        ));
        let tree = Tree {
            entries: vec![TreeEntry {
                name: b"medium.bin".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        };
        let tree_hash = f
            .store
            .write(&crate::serialize::serialize(&Object::Tree(tree)).unwrap())
            .unwrap();
        let kp = KeyPair::from_seed([0x07; 32]);
        let mut commit = Commit {
            tree_hash,
            parents: vec![],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"medium blob".to_vec(),
            timestamp: 1_726_300_001,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0u8; 64],
        };
        commit.signature = sign_commit(&commit, &kp).unwrap().0;
        f.store
            .write(&crate::serialize::serialize(&Object::Commit(commit)).unwrap())
            .unwrap()
    }

    type Case = (Hash, Vec<&'static [u8]>, Selector);

    /// Every selector kind the builder supports, as `(commit, path,
    /// selector)` cases over the fixture plus [`medium_blob_commit`].
    fn equivalence_cases(f: &Fixture, medium: Hash) -> Vec<Case> {
        let range = |offset, len, with_offsets| Selector::Range {
            offset,
            len,
            with_offsets,
        };
        let c = f.commit_id;
        let mut cases: Vec<Case> = vec![
            (c, vec![], Selector::Object),
            (c, vec![b"shallow.txt"], Selector::Object),
            (c, vec![b"sub", b"deep", b"deep.txt"], Selector::Object),
            (c, vec![b"sub"], Selector::Object),
            (c, vec![b"exec.sh"], Selector::Object),
            (c, vec![b"chunked.bin"], Selector::Object),
            (c, vec![b"shallow.txt"], range(0, 20, false)),
            (c, vec![b"shallow.txt"], range(8, 4, false)),
            // Plain blob: first block, last partial block, a range across a
            // block boundary, and the whole content.
            (medium, vec![b"medium.bin"], range(0, 1024, false)),
            (medium, vec![b"medium.bin"], range(4096, 904, false)),
            (medium, vec![b"medium.bin"], range(1000, 100, false)),
            (medium, vec![b"medium.bin"], range(0, 5000, false)),
            // Chunked blob: a range inside chunk 0 and one past it, each
            // with and without offset proofs.
            (c, vec![b"chunked.bin"], range(10, 64, false)),
            (c, vec![b"chunked.bin"], range(10, 64, true)),
            (c, vec![b"chunked.bin"], range(200_000, 64, false)),
            (c, vec![b"chunked.bin"], range(200_000, 64, true)),
        ];
        let chunked_id = entry_id(&f.store, &root_tree_id(&f.store, &c), b"chunked.bin");
        let Object::ChunkedBlob(cb) = f.store.read_object(&chunked_id).unwrap() else {
            panic!("expected a chunked blob");
        };
        assert!(cb.chunks.len() > 1, "fixture must yield several chunks");
        for i in 0..cb.chunks.len() {
            let index = u32::try_from(i).unwrap();
            cases.push((c, vec![b"chunked.bin"], Selector::Chunk(index)));
        }
        cases
    }

    fn assert_source_matches_store<S: crate::store::ObjectSource + ?Sized>(
        f: &Fixture,
        source: &S,
        medium: Hash,
    ) {
        for (commit, path, selector) in equivalence_cases(f, medium) {
            let expected = build_disclosure(&f.store, &commit, &path, selector).unwrap();
            let got = build_disclosure_from(source, &commit, &path, selector).unwrap();
            assert_eq!(
                got, expected,
                "bundle bytes differ for {path:?} / {selector:?}"
            );
            verify_disclosure(&commit, &got).unwrap();
        }
    }

    #[test]
    fn disclosure_from_map_source_equals_store_builder() {
        let f = build_fixture();
        let medium = medium_blob_commit(&f);
        let map = MapSource::from_store(&f.store);
        assert_source_matches_store(&f, &map, medium);
        // Also through a trait object (`?Sized`).
        let dyn_source: &dyn crate::store::ObjectSource = &map;
        assert_source_matches_store(&f, dyn_source, medium);
    }

    #[test]
    fn disclosure_from_ephemeral_sink_equals_store_builder() {
        let f = build_fixture();
        let medium = medium_blob_commit(&f);
        let sink = crate::store::EphemeralSink::new(&f.store);
        assert_source_matches_store(&f, &sink, medium);
    }

    #[test]
    fn disclosure_from_missing_object_is_store_error() {
        let f = build_fixture();
        let sub_id = entry_id(&f.store, &root_tree_id(&f.store, &f.commit_id), b"sub");
        let path: [&[u8]; 3] = [b"sub", b"deep", b"deep.txt"];

        let mut map = MapSource::from_store(&f.store);
        assert!(map.0.remove(&sub_id).is_some());
        let from_map =
            build_disclosure_from(&map, &f.commit_id, &path, Selector::Object).unwrap_err();

        f.store.remove_object(&sub_id).unwrap();
        let from_store =
            build_disclosure(&f.store, &f.commit_id, &path, Selector::Object).unwrap_err();

        let VerifyError::Store(StoreError::ObjectNotFound(map_hex)) = &from_map else {
            panic!("expected Store(ObjectNotFound), got {from_map:?}");
        };
        let VerifyError::Store(StoreError::ObjectNotFound(store_hex)) = &from_store else {
            panic!("expected Store(ObjectNotFound), got {from_store:?}");
        };
        assert_eq!(map_hex, store_hex);
        assert_eq!(map_hex, &crate::hash::to_hex(&sub_id));
        assert_eq!(from_map.to_string(), from_store.to_string());
    }

    #[test]
    fn disclosure_from_lying_leaf_fails_verification() {
        let f = build_fixture();
        let root = root_tree_id(&f.store, &f.commit_id);
        let shallow_id = entry_id(&f.store, &root, b"shallow.txt");
        let exec_id = entry_id(&f.store, &root, b"exec.sh");
        let map = MapSource::from_store(&f.store);
        let liar = LyingSource {
            inner: &map,
            target: shallow_id,
            // A different, well-formed blob.
            lie: f.store.read(&exec_id).unwrap(),
        };
        let bundle =
            build_disclosure_from(&liar, &f.commit_id, &[b"shallow.txt"], Selector::Object)
                .unwrap();
        assert!(matches!(
            verify_disclosure(&f.commit_id, &bundle),
            Err(VerifyError::PayloadIdMismatch)
        ));
    }

    #[test]
    fn disclosure_from_lying_tree_fails_at_that_path_step() {
        let f = build_fixture();
        let root = root_tree_id(&f.store, &f.commit_id);
        let sub_id = entry_id(&f.store, &root, b"sub");
        let deep_tree_id = entry_id(&f.store, &sub_id, b"deep");
        let shallow_id = entry_id(&f.store, &root, b"shallow.txt");
        // A well-formed forgery of `sub`: it still has the `deep` entry the
        // path needs, plus an extra one, so the builder walks straight
        // through it.
        let forged = Tree {
            entries: vec![
                TreeEntry {
                    name: b"aaa.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: shallow_id,
                },
                TreeEntry {
                    name: b"deep".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: deep_tree_id,
                },
            ],
        };
        let map = MapSource::from_store(&f.store);
        let liar = LyingSource {
            inner: &map,
            target: sub_id,
            lie: crate::serialize::serialize(&Object::Tree(forged)).unwrap(),
        };
        let path: [&[u8]; 3] = [b"sub", b"deep", b"deep.txt"];
        let bundle = build_disclosure_from(&liar, &f.commit_id, &path, Selector::Object).unwrap();
        // Step 0 (root → sub) is honest; step 1 carries the forged tree's
        // inner root, which does not wrap to `sub`'s real id.
        let err = verify_disclosure(&f.commit_id, &bundle).unwrap_err();
        let VerifyError::InnerRootMismatch { expected, .. } = err else {
            panic!("expected InnerRootMismatch at the `sub` step, got {err:?}");
        };
        assert_eq!(expected, sub_id);
    }

    #[test]
    fn disclosure_from_short_chunk_is_error_not_panic() {
        let f = build_fixture();
        let root = root_tree_id(&f.store, &f.commit_id);
        let chunked_id = entry_id(&f.store, &root, b"chunked.bin");
        let Object::ChunkedBlob(cb) = f.store.read_object(&chunked_id).unwrap() else {
            panic!("expected a chunked blob");
        };
        let map = MapSource::from_store(&f.store);
        for short_len in [0usize, 1, 9] {
            let liar = LyingSource {
                inner: &map,
                target: cb.chunks[0],
                lie: vec![0u8; short_len],
            };
            for with_offsets in [false, true] {
                let selector = Selector::Range {
                    offset: 200_000,
                    len: 64,
                    with_offsets,
                };
                let err = build_disclosure_from(&liar, &f.commit_id, &[b"chunked.bin"], selector)
                    .unwrap_err();
                assert!(
                    matches!(err, VerifyError::Decode(MkitError::UnexpectedEof)),
                    "{short_len}-byte chunk: got {err:?}"
                );
            }
        }
    }

    #[test]
    fn disclosure_range_len_u64_max_is_error_not_panic() {
        let f = build_fixture();
        let map = MapSource::from_store(&f.store);
        let huge = |offset| Selector::Range {
            offset,
            len: u64::MAX,
            with_offsets: false,
        };
        for (path, offset) in [
            (b"chunked.bin".as_slice(), 10),
            (b"chunked.bin".as_slice(), 200_000),
            (b"shallow.txt".as_slice(), 1),
        ] {
            for result in [
                build_disclosure(&f.store, &f.commit_id, &[path], huge(offset)),
                build_disclosure_from(&map, &f.commit_id, &[path], huge(offset)),
            ] {
                let err = result.unwrap_err();
                assert!(
                    matches!(err, VerifyError::OffsetOverflow),
                    "{path:?} @ {offset}: got {err:?}"
                );
            }
        }
        // An offset at the very top of u64 is simply out of bounds.
        let top = Selector::Range {
            offset: u64::MAX,
            len: 1,
            with_offsets: true,
        };
        let err = build_disclosure(&f.store, &f.commit_id, &[b"chunked.bin"], top).unwrap_err();
        assert!(matches!(err, VerifyError::RangeOutOfBounds), "got {err:?}");
    }

    #[test]
    fn disclosure_from_split_blob_source_is_error_not_panic() {
        let f = build_fixture();
        let root = root_tree_id(&f.store, &f.commit_id);
        let shallow_id = entry_id(&f.store, &root, b"shallow.txt");
        let map = MapSource::from_store(&f.store);
        // `read_object` claims a 4 KiB blob; `read` returns the real
        // 20-byte one, so the range is past the canonical bytes.
        let liar = SplitSource {
            inner: &map,
            target: shallow_id,
            object_lie: Object::Blob(crate::object::Blob {
                data: vec![0u8; 4096],
            }),
        };
        let selector = Selector::Range {
            offset: 2048,
            len: 512,
            with_offsets: false,
        };
        // Either a typed error or a bundle the verifier rejects; never a
        // panic, never a verifying bundle.
        if let Ok(bundle) = build_disclosure_from(&liar, &f.commit_id, &[b"shallow.txt"], selector)
        {
            assert!(verify_disclosure(&f.commit_id, &bundle).is_err());
        }
    }
}
