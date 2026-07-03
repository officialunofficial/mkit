//! Blame proof: build/verify a tamper-evident blame-result predicate.
//!
//! Normative spec: `docs/SPEC-BLAME-PROOF.md` (SPEC-BLAME-PROOF v1). This
//! module is PR B (deliverable 2 of 3) for issue #495 — the `mkit-core`
//! build/verify functions and their golden / tamper-matrix tests. PR C
//! (`mkit-attest` / `mkit-cli`) wires [`BlameProofPredicate`] into a signed
//! DSSE envelope (`mkit_attest::statement`) and the `mkit blame --prove` /
//! `mkit verify-attest` CLI surface.
//!
//! `mkit-core` has no `serde` dependency, so [`BlameProofPredicate`] and its
//! nested types are plain Rust structs, not `serde`-derived wire types.
//! Field names/shapes mirror `docs/SPEC-BLAME-PROOF.md` §6 closely enough
//! that PR C's JCS-canonical-JSON encoder (reusing `mkit-attest`'s
//! canonicalisation, the same way every other predicate producer does) is a
//! near-mechanical field-by-field mapping.
//!
//! ## Commit identity — derived identities (spec §6.3a; read this before touching `commit`/`origins`)
//!
//! Every commit-identity field in the predicate — `commit`,
//! `origins[].commit`, each `attributions` origin hex, and every header
//! `parents` entry — is the proof's **derived identity** per
//! `SPEC-BLAME-PROOF.md` §6.3a: `hash(commit_signing_bytes(header))`,
//! *distinct* from `Object::id()`. The real store object id is `BLAKE3` of
//! the **full** serialized commit (`docs/SPEC-OBJECTS.md` §10 /
//! `serialize::write_commit`), which includes `signature` / `message_hash`
//! / `content_digest` — three fields `commitHeader` deliberately omits
//! (§6.3) because they aren't part of `sign::commit_signing_bytes` — so a
//! verifier holding only a header can never reconstruct the real object id.
//! The derived preimage is exactly what the commit's Ed25519 signature
//! attests, so the binding is precisely as strong as the signature itself.
//!
//! Header `parents` carry each **parent's own derived identity** (applied
//! recursively from the roots up), so a store-less verifier can match a
//! header's parent pointers directly against `origins[]` keys, the way
//! §8.1 describes ("walk parent pointers through the `origins[]` map").
//! `tree` and the blob/tree-path hashes are unaffected — those are BMT
//! roots, not signature-dependent, so they equal the real
//! `Commit.tree_hash` / real object ids verbatim.
//!
//! One consequence: the store-holding ancestry shortcut (§8.1's shortcut
//! note) can't call `ops::merge::is_ancestor` directly with derived
//! identities (it expects real, store-addressable hashes).
//! [`verify_blame_proof`]'s store-holding path instead resolves each
//! derived identity back to a real object-store hash by scanning the
//! store's commit objects (see `store_locate_real_hash`) and *then* calls
//! `ops::merge::is_ancestor` — `O(store size)` rather than `O(1)`, since
//! the predicate carries no real-hash anchor. The spec flags this as a
//! known v1 cost; a real anchor (e.g. the caller separately supplying the
//! real commit hash) would remove it at the price of a wider API.
//!
//! Everything else in `docs/SPEC-BLAME-PROOF.md` (predicate shape, tree-path
//! wire format, `chunkLayout`, `blameOptions`, the tamper-matrix error
//! surface) is implemented per the spec as written.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use crate::hash::{self, Hash};
use crate::merkle;
use crate::object::{
    ChunkedBlob, EntryMode, Identity, MAGIC, MkitError, Object, ObjectType, SCHEMA_VERSION, Tree,
    TreeEntry,
};
use crate::ops::merge;
use crate::serialize;
use crate::store::{ObjectStore, StoreError};

use super::{BlameError, BlameOptions, CopyDetection, MoveDetection};

/// The only predicate format version this module implements (§6.1's `v`).
pub const BLAME_PROOF_VERSION: u32 = 1;

/// `usize -> u32`, for values already bounded by an existing cap
/// ([`super::BLAME_MAX_LINES`], object-size limits, etc.) far below
/// `u32::MAX` — panics only on a programmer error that bypassed those caps.
fn u32_len(n: usize) -> u32 {
    u32::try_from(n).expect("value fits u32 (bounded by an existing size cap)")
}

/// `usize -> u16`, for an `Identity` payload length (capped at
/// `IDENTITY_MAX_LEN` = 4 KiB, comfortably under `u16::MAX`).
fn u16_len(n: usize) -> u16 {
    u16::try_from(n).expect("Identity payload is capped at IDENTITY_MAX_LEN, fits u16")
}

/// `chunkLayout` (§6.1): present only when the blamed blob is a
/// `ChunkedBlob`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkLayout {
    pub total_size: u64,
    /// `0` = content-defined (`FastCDC` v1), otherwise fixed-size chunking
    /// at this width.
    pub chunk_size: u32,
}

/// One leaf→root `treePath` entry (§6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreePathEntry {
    pub entry_name: Vec<u8>,
    pub entry_mode: EntryMode,
    pub child_id: Hash,
    pub inner_root: Hash,
    pub position: u32,
    pub proof: Vec<u8>,
}

/// `commitHeader` / `origins[].header` (§6.3). `parents` holds each
/// parent's *own* blame-proof derived identity — see the module-level
/// deviation note, not the raw real `Commit.parents` hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitHeader {
    pub tree: Hash,
    pub parents: Vec<Hash>,
    pub author: Identity,
    pub message: Vec<u8>,
    pub timestamp: u64,
    pub signer: Hash,
}

/// One `origins[]` entry (§6.1): a claimed derived commit identity plus the
/// header that must rehash to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginHeader {
    pub commit: Hash,
    pub header: CommitHeader,
}

/// git `-M` knob, mirrored (§9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveRecord {
    pub threshold: u32,
}

/// git `-C` knob, mirrored (§9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyRecord {
    pub level: u8,
    pub threshold: u32,
}

/// `blameOptions` (§9): [`BlameOptions`] mirrored field-for-field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlameOptionsRecord {
    pub ignore_whitespace: bool,
    pub moves: Option<MoveRecord>,
    pub copies: Option<CopyRecord>,
    /// Sorted ascending (§9) — `BlameOptions::ignore_revs` is an unordered
    /// set; JCS needs deterministic array order.
    pub ignore_revs: Vec<Hash>,
    pub ignore_rev_precise: bool,
    pub first_parent: bool,
}

impl BlameOptionsRecord {
    fn from_opts(opts: &BlameOptions) -> Self {
        let mut ignore_revs: Vec<Hash> = opts.ignore_revs.iter().copied().collect();
        ignore_revs.sort_unstable();
        Self {
            ignore_whitespace: opts.ignore_whitespace,
            moves: match opts.moves {
                MoveDetection::Off => None,
                MoveDetection::On { threshold } => Some(MoveRecord {
                    threshold: u32_len(threshold),
                }),
            },
            copies: match opts.copies {
                CopyDetection::Off => None,
                CopyDetection::On { level, threshold } => Some(CopyRecord {
                    level,
                    threshold: u32_len(threshold),
                }),
            },
            ignore_revs,
            ignore_rev_precise: opts.ignore_rev_precise,
            first_parent: opts.first_parent,
        }
    }
}

/// The blame-proof predicate (§6). Produced by [`build_blame_proof`],
/// checked by [`verify_blame_proof`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlameProofPredicate {
    pub v: u32,
    /// This proof's derived identity for the blamed commit — see the
    /// module-level deviation note. NOT `Object::id()`.
    pub commit: Hash,
    pub path: String,
    pub blob: Hash,
    pub chunk_layout: Option<ChunkLayout>,
    /// Dense, 1-based `(line_num, origin derived-identity)` pairs, in line
    /// order (§6.1).
    pub attributions: Vec<(u32, Hash)>,
    pub blame_options: BlameOptionsRecord,
    pub tree_path: Vec<TreePathEntry>,
    pub commit_header: CommitHeader,
    pub origins: Vec<OriginHeader>,
}

/// Errors from [`build_blame_proof`] / [`verify_blame_proof`]. Distinct
/// variants per failure class — `docs/SPEC-BLAME-PROOF.md` §7's tamper
/// matrix requires a verifier to report *which* step failed, not just that
/// verification failed.
#[derive(Debug, thiserror::Error)]
pub enum BlameProofError {
    #[error(transparent)]
    Blame(#[from] BlameError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Object(#[from] MkitError),
    #[error("requested object is not a commit")]
    NotACommit,
    #[error("blob object is neither a Blob nor a ChunkedBlob")]
    NotABlob,
    #[error("path does not resolve to a blob under the commit's tree")]
    PathNotFound,
    #[error("unsupported blame-proof version {0} (only v1 is implemented)")]
    UnsupportedVersion(u32),
    /// Step 1 (§7): recomputed blob id from the supplied file bytes does
    /// not match `predicate.blob`. Covers both "wrong file bytes" and a
    /// tampered `blob` field.
    #[error("recomputed blob id {got} does not match predicate.blob {expected}")]
    BlobMismatch { expected: String, got: String },
    /// `chunkLayout.totalSize` disagrees with the supplied file bytes'
    /// length, before any chunk-level recomputation is attempted.
    #[error("predicate.chunkLayout.totalSize does not match the supplied file bytes")]
    ChunkLayoutMismatch,
    #[error("treePath is empty")]
    TreePathEmpty,
    /// Step 2 (§7): the BMT inclusion proof itself failed to verify at this
    /// level.
    #[error("tree inclusion proof failed to verify at treePath level {level}")]
    TreePathInvalid { level: usize },
    /// Step 2 (§7): this level's `childId` does not match the previous
    /// level's derived id (or, at level 0, `predicate.blob`) — a dropped or
    /// reordered `treePath` entry.
    #[error("treePath level {level}'s childId does not chain from the previous level")]
    TreePathBroken { level: usize },
    /// Step 2 (§7): the final level's derived tree id does not match
    /// `commitHeader.tree`.
    #[error("final treePath level's derived tree id does not match commitHeader.tree")]
    TreeRootMismatch,
    /// Step 3 (§7): `commitHeader` does not rehash to `predicate.commit`.
    #[error("commitHeader rehash does not match predicate.commit")]
    CommitIdentityMismatch,
    /// §8.1 point 1: an `origins[]` entry's header does not rehash to its
    /// own claimed `commit`.
    #[error("origins[] header claiming commit {0} does not rehash to that identity")]
    OriginHeaderMismatch(String),
    /// `attributions` has a gap or duplicate — must be dense `1..=N`.
    #[error("attributions has a gap or duplicate at line {0} (must be dense 1..=N)")]
    AttributionsMalformed(u32),
    /// `attributions.len()` does not match the verifier's own line split of
    /// the supplied file bytes.
    #[error("attributions covers {got} lines but the supplied file has {expected}")]
    AttributionLineCountMismatch { expected: usize, got: usize },
    /// Step 5 (§8): an attribution's origin identity does not appear
    /// anywhere in the proof's header set (`commitHeader` or `origins[]`)
    /// and no store resolved it either.
    #[error("attribution origin {0} does not appear anywhere in the proof's header set")]
    AttributionOriginUnknown(String),
    /// Step 5 (§8): the origin's header is present in `origins[]` but is
    /// not reachable from `commitHeader` via parent pointers — the
    /// connecting path was truncated.
    #[error(
        "origin {0} is present in origins[] but unreachable from commit (truncated ancestry path)"
    )]
    AncestryPathTruncated(String),
}

/// Fallible-result alias for this module.
pub type BlameProofOutcome<T> = Result<T, BlameProofError>;

// ===========================================================================
// Build
// ===========================================================================

/// Build a [`BlameProofPredicate`] for `path` at `commit`, per
/// `docs/SPEC-BLAME-PROOF.md` §6–§8.
///
/// Runs [`super::blame_file_with`], collects the tree-inclusion path from
/// the blamed blob up to `commit`'s tree, the blob's chunk layout, the
/// commit-header preimage, and the deduplicated union of ancestor headers
/// connecting `commit` to every distinct attribution origin (§8's D5).
///
/// # Errors
/// [`BlameProofError::Blame`] if the underlying blame fails (see
/// [`super::blame_file_with`]); [`BlameProofError::Store`] /
/// [`BlameProofError::Object`] on store/object errors; [`BlameProofError::NotACommit`]
/// if `commit` is not a commit object; [`BlameProofError::PathNotFound`] if
/// `path` cannot be resolved to a blob under `commit`'s tree.
///
/// # Panics
/// Never in practice: `commit_digest_and_header(store, commit, &mut memo)`
/// always inserts `commit`'s entry into `memo` before returning `Ok`, so the
/// immediately-following `memo.get(&commit)` lookup always hits.
pub fn build_blame_proof(
    store: &ObjectStore,
    opts: &BlameOptions,
    commit: Hash,
    path: &str,
) -> BlameProofOutcome<BlameProofPredicate> {
    let blame_result = super::blame_file_with(store, commit, path, opts)?;

    let Object::Commit(head_commit) = store.read_object(&commit)? else {
        return Err(BlameProofError::NotACommit);
    };

    let mut memo: HashMap<Hash, (Hash, CommitHeader)> = HashMap::new();
    let top_digest = commit_digest_and_header(store, commit, &mut memo)?;
    let commit_header = memo
        .get(&commit)
        .expect("just inserted by commit_digest_and_header")
        .1
        .clone();

    let (tree_path, blob_hash) = build_tree_path(store, head_commit.tree_hash, path)?;

    let chunk_layout = match store.read_object(&blob_hash)? {
        Object::Blob(_) => None,
        Object::ChunkedBlob(cb) => Some(ChunkLayout {
            total_size: cb.total_size,
            chunk_size: cb.chunk_size,
        }),
        _ => return Err(BlameProofError::NotABlob),
    };

    let mut attributions = Vec::with_capacity(blame_result.lines.len());
    let mut distinct_origins: BTreeSet<Hash> = BTreeSet::new();
    for line in &blame_result.lines {
        let d = commit_digest_and_header(store, line.commit_hash, &mut memo)?;
        attributions.push((u32_len(line.line_num), d));
        if d != top_digest {
            distinct_origins.insert(d);
        }
    }

    let origins = collect_origin_headers(store, commit, &distinct_origins, &mut memo)?;

    Ok(BlameProofPredicate {
        v: BLAME_PROOF_VERSION,
        commit: top_digest,
        path: path.to_string(),
        blob: blob_hash,
        chunk_layout,
        attributions,
        blame_options: BlameOptionsRecord::from_opts(opts),
        tree_path,
        commit_header,
        origins,
    })
}

/// This proof's derived identity for `real_hash` (a real, store-addressable
/// commit hash): `hash(commit_signing_bytes-equivalent(header))`, where
/// `header`'s `parents` are themselves derived identities (recursively).
/// Memoized in `memo`, keyed by the real hash.
fn commit_digest_and_header(
    store: &ObjectStore,
    root: Hash,
    memo: &mut HashMap<Hash, (Hash, CommitHeader)>,
) -> BlameProofOutcome<Hash> {
    if let Some((d, _)) = memo.get(&root) {
        return Ok(*d);
    }
    // Iterative post-order (parents before children) to avoid recursion
    // depth scaling with history length.
    let mut stack: Vec<(Hash, bool)> = vec![(root, false)];
    while let Some((h, expanded)) = stack.pop() {
        if memo.contains_key(&h) {
            continue;
        }
        let Object::Commit(c) = store.read_object(&h)? else {
            return Err(BlameProofError::NotACommit);
        };
        if expanded {
            let parents: Vec<Hash> = c
                .parents
                .iter()
                .map(|p| memo.get(p).expect("parent processed before child").0)
                .collect();
            let header = CommitHeader {
                tree: c.tree_hash,
                parents,
                author: c.author.clone(),
                message: c.message.clone(),
                timestamp: c.timestamp,
                signer: c.signer,
            };
            let digest = hash_header(&header);
            memo.insert(h, (digest, header));
        } else {
            stack.push((h, true));
            for &p in &c.parents {
                if !memo.contains_key(&p) {
                    stack.push((p, false));
                }
            }
        }
    }
    Ok(memo.get(&root).expect("root processed by the loop above").0)
}

/// `hash(commit_header_signing_bytes(header))` — the module's derived
/// commit identity (§7 step 3 / §8.1 point 1).
fn hash_header(header: &CommitHeader) -> Hash {
    hash::hash(&commit_header_signing_bytes(header))
}

/// Mirrors `sign::commit_signing_bytes`'s byte layout, operating on a
/// [`CommitHeader`] (whose `parents` are derived identities, not real
/// hashes — see the module-level deviation note) rather than a real
/// `Commit`.
fn commit_header_signing_bytes(header: &CommitHeader) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        6 + 32
            + 4
            + header.parents.len() * 32
            + 3
            + header.author.bytes.len()
            + 4
            + header.message.len()
            + 8
            + 32,
    );
    buf.push(ObjectType::Commit as u8);
    buf.extend_from_slice(&MAGIC);
    buf.push(SCHEMA_VERSION);
    buf.extend_from_slice(&header.tree);
    buf.extend_from_slice(&u32_len(header.parents.len()).to_le_bytes());
    for p in &header.parents {
        buf.extend_from_slice(p);
    }
    buf.push(header.author.kind as u8);
    buf.extend_from_slice(&u16_len(header.author.bytes.len()).to_le_bytes());
    buf.extend_from_slice(&header.author.bytes);
    buf.extend_from_slice(&u32_len(header.message.len()).to_le_bytes());
    buf.extend_from_slice(&header.message);
    buf.extend_from_slice(&header.timestamp.to_le_bytes());
    buf.extend_from_slice(&header.signer);
    buf
}

/// One resolved tree level while walking `path` down from `root_tree`.
struct LevelInfo {
    tree_obj: Tree,
    position: u32,
    entry: TreeEntry,
}

/// Walk `path`'s components down from `root_tree`, then emit `treePath`
/// entries leaf → root (§6.2), plus the resolved blob hash.
fn build_tree_path(
    store: &ObjectStore,
    root_tree: Hash,
    path: &str,
) -> BlameProofOutcome<(Vec<TreePathEntry>, Hash)> {
    let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    if components.is_empty() {
        return Err(BlameProofError::PathNotFound);
    }

    let mut levels: Vec<LevelInfo> = Vec::with_capacity(components.len());
    let mut current_tree_hash = root_tree;
    for (i, component) in components.iter().enumerate() {
        let Object::Tree(tree) = store.read_object(&current_tree_hash)? else {
            return Err(BlameProofError::PathNotFound);
        };
        let position = merkle::tree_entry_position(&tree, component.as_bytes())
            .ok_or(BlameProofError::PathNotFound)?;
        let entry = tree.entries[position as usize].clone();
        let is_last = i == components.len() - 1;
        if !is_last {
            if entry.mode != EntryMode::Tree {
                return Err(BlameProofError::PathNotFound);
            }
            current_tree_hash = entry.object_hash;
        }
        levels.push(LevelInfo {
            tree_obj: tree,
            position,
            entry,
        });
        if is_last {
            break;
        }
    }

    let blob_hash = levels
        .last()
        .expect("components is non-empty, so at least one level was pushed")
        .entry
        .object_hash;

    let mut tree_path = Vec::with_capacity(levels.len());
    for level in levels.iter().rev() {
        let inner_root = merkle::tree_inner_root(&level.tree_obj);
        let proof = merkle::build_tree_inclusion_proof(&level.tree_obj, level.position)
            .map_err(|_| BlameProofError::PathNotFound)?;
        tree_path.push(TreePathEntry {
            entry_name: level.entry.name.clone(),
            entry_mode: level.entry.mode,
            child_id: level.entry.object_hash,
            inner_root,
            position: level.position,
            proof,
        });
    }
    Ok((tree_path, blob_hash))
}

/// Collect the deduplicated union of ancestor headers connecting `commit`
/// to every digest in `distinct_origins` (§8's D5). Real-hash BFS from
/// `commit` over the actual store graph, converting each visited real hash
/// to its derived identity via `memo`.
fn collect_origin_headers(
    store: &ObjectStore,
    commit: Hash,
    distinct_origins: &BTreeSet<Hash>,
    memo: &mut HashMap<Hash, (Hash, CommitHeader)>,
) -> BlameProofOutcome<Vec<OriginHeader>> {
    if distinct_origins.is_empty() {
        return Ok(Vec::new());
    }
    let mut remaining: BTreeSet<Hash> = distinct_origins.clone();
    let mut visited: HashSet<Hash> = HashSet::from([commit]);
    let mut prev: HashMap<Hash, Hash> = HashMap::new();
    let mut found_real: HashMap<Hash, Hash> = HashMap::new();
    let mut queue: VecDeque<Hash> = VecDeque::from([commit]);

    while let Some(x) = queue.pop_front() {
        if remaining.is_empty() {
            break;
        }
        let Object::Commit(cx) = store.read_object(&x)? else {
            return Err(BlameProofError::NotACommit);
        };
        for &p in &cx.parents {
            if visited.insert(p) {
                prev.insert(p, x);
                let pd = commit_digest_and_header(store, p, memo)?;
                if remaining.remove(&pd) {
                    found_real.insert(pd, p);
                }
                queue.push_back(p);
            }
        }
    }

    if let Some(&missing) = remaining.iter().next() {
        // Should not happen for honest blame output — attributions only
        // ever come from commits actually visited during the blame walk,
        // which are by construction ancestors of `commit`. Surface
        // distinctly rather than panicking if it ever does.
        return Err(BlameProofError::AttributionOriginUnknown(hash::to_hex(
            &missing,
        )));
    }

    let mut needed_real: BTreeSet<Hash> = BTreeSet::new();
    for real in found_real.values() {
        let mut cur = *real;
        while cur != commit {
            needed_real.insert(cur);
            cur = *prev
                .get(&cur)
                .expect("every visited non-root node has a discoverer");
        }
    }

    let mut origins: Vec<OriginHeader> = needed_real
        .into_iter()
        .map(|r| {
            let (digest, header) = memo.get(&r).expect("visited during BFS above").clone();
            OriginHeader {
                commit: digest,
                header,
            }
        })
        .collect();
    origins.sort_by_key(|o| o.commit);
    Ok(origins)
}

// ===========================================================================
// Verify
// ===========================================================================

/// Verify a [`BlameProofPredicate`] against `file_bytes`, the verifier's own
/// copy of the blamed file at `predicate.commit` (§4's D3 assumption).
///
/// Implements `docs/SPEC-BLAME-PROOF.md` §7 steps 1–3 and 5 (step 4, DSSE
/// envelope signature verification, is out of scope for `mkit-core` — see
/// `mkit_attest::verify`; PR C wires that layer in before dispatching here).
///
/// `store`, if given, lets the ancestry check (step 5) use the store-holding
/// shortcut (§8.2) instead of requiring `predicate.origins` to carry the
/// full connecting-path bundle; see the module-level deviation note for how
/// this module resolves that shortcut against its derived-identity scheme.
///
/// # Errors
/// Returns a distinct [`BlameProofError`] variant per failing step — see the
/// variant docs. `Ok(())` means all steps in scope passed.
pub fn verify_blame_proof(
    predicate: &BlameProofPredicate,
    file_bytes: &[u8],
    store: Option<&ObjectStore>,
) -> BlameProofOutcome<()> {
    if predicate.v != BLAME_PROOF_VERSION {
        return Err(BlameProofError::UnsupportedVersion(predicate.v));
    }

    // Step 1: blob identity.
    let recomputed_blob = recompute_blob_id(file_bytes, predicate.chunk_layout.as_ref())?;
    if recomputed_blob != predicate.blob {
        return Err(BlameProofError::BlobMismatch {
            expected: hash::to_hex(&predicate.blob),
            got: hash::to_hex(&recomputed_blob),
        });
    }

    // Step 2: tree path, leaf -> root.
    if predicate.tree_path.is_empty() {
        return Err(BlameProofError::TreePathEmpty);
    }
    let mut expected_child = predicate.blob;
    let n = predicate.tree_path.len();
    for (level, entry) in predicate.tree_path.iter().enumerate() {
        if entry.child_id != expected_child {
            return Err(BlameProofError::TreePathBroken { level });
        }
        let tree_entry = TreeEntry {
            name: entry.entry_name.clone(),
            mode: entry.entry_mode,
            object_hash: entry.child_id,
        };
        merkle::verify_tree_inclusion_proof(
            &entry.inner_root,
            &tree_entry,
            entry.position,
            &entry.proof,
        )
        .map_err(|_| BlameProofError::TreePathInvalid { level })?;
        let derived_tree_id = merkle::tree_id_from_inner_root(&entry.inner_root);
        if level + 1 == n {
            if derived_tree_id != predicate.commit_header.tree {
                return Err(BlameProofError::TreeRootMismatch);
            }
        } else {
            expected_child = derived_tree_id;
        }
    }

    // Step 3: commit identity.
    if hash_header(&predicate.commit_header) != predicate.commit {
        return Err(BlameProofError::CommitIdentityMismatch);
    }

    // Attribution shape (dense 1..=N, matching the verifier's own line
    // split of `file_bytes` — §6.1).
    verify_attributions_shape(&predicate.attributions, file_bytes)?;

    // Step 5: ancestry.
    verify_ancestry(predicate, store)?;

    Ok(())
}

/// Recompute the blob id from `file_bytes` per §6.1 / §7 step 1: the flat
/// SPEC-OBJECTS §10 hash when `chunk_layout` is `None`, else
/// `merkle::compute_chunked_id` over a freshly-chunked `ChunkedBlob`.
fn recompute_blob_id(
    file_bytes: &[u8],
    chunk_layout: Option<&ChunkLayout>,
) -> BlameProofOutcome<Hash> {
    match chunk_layout {
        None => {
            let prologue = serialize::blob_prologue(file_bytes.len())?;
            let mut hasher = hash::Hasher::new();
            hasher.update(&prologue);
            hasher.update(file_bytes);
            Ok(hasher.finalize())
        }
        Some(cl) => {
            if cl.total_size != file_bytes.len() as u64 {
                return Err(BlameProofError::ChunkLayoutMismatch);
            }
            let cb = if cl.chunk_size == 0 {
                crate::worktree::chunked_blob_from_bytes(file_bytes)
                    .map_err(|_| BlameProofError::ChunkLayoutMismatch)?
            } else {
                fixed_size_chunked_blob(file_bytes, cl.chunk_size)?
            };
            Ok(merkle::compute_chunked_id(&cb))
        }
    }
}

/// Fixed-size (non-content-defined) chunking, for `chunkLayout.chunkSize >
/// 0` (§6.1) — a wire shape `mkit`'s own producers never emit today
/// (`store_file_object` always uses `FastCdc::v1`, `chunk_size = 0`), but
/// the spec allows it, so a verifier must support it.
fn fixed_size_chunked_blob(data: &[u8], chunk_size: u32) -> BlameProofOutcome<ChunkedBlob> {
    let cs = chunk_size as usize;
    let mut chunks = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let end = (offset + cs).min(data.len());
        let chunk = &data[offset..end];
        let prologue = serialize::blob_prologue(chunk.len())?;
        let mut hasher = hash::Hasher::new();
        hasher.update(&prologue);
        hasher.update(chunk);
        chunks.push(hasher.finalize());
        offset = end;
    }
    Ok(ChunkedBlob {
        total_size: data.len() as u64,
        chunk_size,
        chunks,
    })
}

/// `attributions` must be dense 1-based and cover exactly the verifier's
/// own line count for `file_bytes` (§6.1) — a gap or duplicate is a
/// proof-shape error, not silently ignored.
fn verify_attributions_shape(
    attributions: &[(u32, Hash)],
    file_bytes: &[u8],
) -> BlameProofOutcome<()> {
    let expected = super::split_lines(file_bytes).len();
    if attributions.len() != expected {
        return Err(BlameProofError::AttributionLineCountMismatch {
            expected,
            got: attributions.len(),
        });
    }
    for (i, (line_num, _)) in attributions.iter().enumerate() {
        if *line_num as usize != i + 1 {
            return Err(BlameProofError::AttributionsMalformed(*line_num));
        }
    }
    Ok(())
}

/// Step 5 (§8): every distinct attribution origin must be provably an
/// ancestor of `predicate.commit`. Store-less: chain-walk `origins[]`
/// (§8.1). Store-holding: fall back to a store-based check for anything the
/// chain-walk didn't reach (§8.2 / the module's deviation note).
fn verify_ancestry(
    predicate: &BlameProofPredicate,
    store: Option<&ObjectStore>,
) -> BlameProofOutcome<()> {
    let mut origins_by_digest: HashMap<Hash, &CommitHeader> =
        HashMap::with_capacity(predicate.origins.len());
    for o in &predicate.origins {
        if hash_header(&o.header) != o.commit {
            return Err(BlameProofError::OriginHeaderMismatch(hash::to_hex(
                &o.commit,
            )));
        }
        origins_by_digest.insert(o.commit, &o.header);
    }

    // Reachability from `commitHeader` via parent pointers, restricted to
    // headers present in `origins_by_digest` (the store-less chain-walk,
    // §8.1).
    let mut reachable: HashSet<Hash> = HashSet::new();
    let mut queue: VecDeque<Hash> = predicate.commit_header.parents.iter().copied().collect();
    while let Some(d) = queue.pop_front() {
        if !reachable.insert(d) {
            continue;
        }
        if let Some(h) = origins_by_digest.get(&d) {
            for &p in &h.parents {
                queue.push_back(p);
            }
        }
    }

    let distinct_origins: BTreeSet<Hash> = predicate.attributions.iter().map(|(_, o)| *o).collect();
    for origin in distinct_origins {
        if origin == predicate.commit || reachable.contains(&origin) {
            continue;
        }
        if let Some(s) = store
            && store_holding_ancestor_check(s, predicate.commit, origin)?
        {
            continue;
        }
        if origins_by_digest.contains_key(&origin) {
            return Err(BlameProofError::AncestryPathTruncated(hash::to_hex(
                &origin,
            )));
        }
        return Err(BlameProofError::AttributionOriginUnknown(hash::to_hex(
            &origin,
        )));
    }
    Ok(())
}

/// The store-holding ancestry shortcut (§8.2), adapted to this module's
/// derived-identity scheme (see the module-level deviation note): resolve
/// both `predicate_commit_digest` and `origin_digest` back to real,
/// store-addressable hashes (`store_locate_real_hash`), then defer to
/// [`merge::is_ancestor`] exactly as the spec names.
fn store_holding_ancestor_check(
    store: &ObjectStore,
    predicate_commit_digest: Hash,
    origin_digest: Hash,
) -> BlameProofOutcome<bool> {
    let Some(real_commit) = store_locate_real_hash(store, predicate_commit_digest)? else {
        return Ok(false);
    };
    let Some(real_origin) = store_locate_real_hash(store, origin_digest)? else {
        return Ok(false);
    };
    Ok(merge::is_ancestor(store, real_origin, real_commit)?)
}

/// Find the real, store-addressable commit hash whose derived identity
/// (`hash_header`) equals `target`. `O(store size)` — the predicate carries
/// no real-hash anchor for its derived identities (see the module-level
/// deviation note), so a store-holding verifier must search for one.
fn store_locate_real_hash(store: &ObjectStore, target: Hash) -> BlameProofOutcome<Option<Hash>> {
    let mut memo: HashMap<Hash, (Hash, CommitHeader)> = HashMap::new();
    for h in store.iter_object_hashes()? {
        if matches!(store.read_object(&h), Ok(Object::Commit(_))) {
            let d = commit_digest_and_header(store, h, &mut memo)?;
            if d == target {
                return Ok(Some(h));
            }
        }
    }
    Ok(None)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{Blob, Commit, Identity, Tree, TreeEntry};
    use crate::serialize;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(dir.path()).unwrap();
        (dir, store)
    }

    fn put_blob(store: &ObjectStore, data: &[u8]) -> Hash {
        let bytes = serialize::serialize(&Object::Blob(Blob {
            data: data.to_vec(),
        }))
        .unwrap();
        store.write(&bytes).unwrap()
    }

    /// Build a single-file tree under `dir_name` (empty = file at repo
    /// root), returning the root tree hash.
    fn put_single_file_tree(
        store: &ObjectStore,
        dir_name: &str,
        filename: &str,
        blob: Hash,
    ) -> Hash {
        let file_entry = TreeEntry {
            name: filename.as_bytes().to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob,
        };
        if dir_name.is_empty() {
            let tree = Object::Tree(Tree {
                entries: vec![file_entry],
            });
            return store.write(&serialize::serialize(&tree).unwrap()).unwrap();
        }
        let subtree = Object::Tree(Tree {
            entries: vec![file_entry],
        });
        let subtree_hash = store
            .write(&serialize::serialize(&subtree).unwrap())
            .unwrap();
        let root = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: dir_name.as_bytes().to_vec(),
                mode: EntryMode::Tree,
                object_hash: subtree_hash,
            }],
        });
        store.write(&serialize::serialize(&root).unwrap()).unwrap()
    }

    fn put_commit(
        store: &ObjectStore,
        tree: Hash,
        parents: Vec<Hash>,
        author_mid: u64,
        ts: u64,
    ) -> Hash {
        let commit = Object::Commit(Commit::new_unannotated(
            tree,
            parents,
            Identity::opaque(author_mid.to_le_bytes()),
            [0x11; 32],
            b"msg".to_vec(),
            ts,
            [0u8; 64],
        ));
        store
            .write(&serialize::serialize(&commit).unwrap())
            .unwrap()
    }

    /// Commit a file at `dir_name/filename` (or repo root when `dir_name`
    /// is empty), one parent chain step.
    fn commit_file(
        store: &ObjectStore,
        dir_name: &str,
        filename: &str,
        content: &[u8],
        parents: Vec<Hash>,
        author_mid: u64,
        ts: u64,
    ) -> Hash {
        let blob = put_blob(store, content);
        let tree = put_single_file_tree(store, dir_name, filename, blob);
        put_commit(store, tree, parents, author_mid, ts)
    }

    // -----------------------------------------------------------------
    // Golden round-trip.
    // -----------------------------------------------------------------

    #[test]
    fn round_trip_build_verify_honest_input() {
        let (_d, store) = fresh_store();
        let c1 = commit_file(&store, "src", "lib.rs", b"a\nb\nc\n", vec![], 1, 100);
        let c2 = commit_file(&store, "src", "lib.rs", b"a\nB\nc\n", vec![c1], 2, 200);

        let opts = BlameOptions::default();
        let predicate = build_blame_proof(&store, &opts, c2, "src/lib.rs").unwrap();

        assert_eq!(predicate.v, BLAME_PROOF_VERSION);
        assert_eq!(predicate.path, "src/lib.rs");
        assert_eq!(
            predicate.tree_path.len(),
            2,
            "two path components -> two levels"
        );
        assert_eq!(predicate.attributions.len(), 3);
        // Line 2 changed in c2, lines 1/3 are still c1's.
        assert_eq!(predicate.attributions[0].0, 1);
        assert_eq!(predicate.attributions[2].0, 3);

        verify_blame_proof(&predicate, b"a\nB\nc\n", None).expect("store-less verify passes");
        verify_blame_proof(&predicate, b"a\nB\nc\n", Some(&store))
            .expect("store-holding verify passes");
    }

    #[test]
    fn round_trip_survives_serialize_deserialize_style_clone() {
        // No serde in mkit-core (see module docs) — "round trip through
        // serialization" is exercised as a clone, standing in for PR C's
        // JCS encode/decode.
        let (_d, store) = fresh_store();
        let c1 = commit_file(&store, "", "f.txt", b"one\ntwo\n", vec![], 1, 100);
        let predicate = build_blame_proof(&store, &BlameOptions::default(), c1, "f.txt").unwrap();
        let cloned = predicate.clone();
        assert_eq!(predicate, cloned);
        verify_blame_proof(&cloned, b"one\ntwo\n", None).unwrap();
    }

    #[test]
    fn merge_commit_ancestry_union_of_paths() {
        // A merge: c3's parents are c1 (direct) and c2 (which descends from
        // c1 too) — exercises the union-of-connecting-paths dedup (D5).
        let (_d, store) = fresh_store();
        let c1 = commit_file(&store, "", "f.txt", b"base\n", vec![], 1, 100);
        let c2 = commit_file(&store, "", "f.txt", b"base\nside\n", vec![c1], 2, 200);
        // Merge commit: first-parent c2 still has the file; simulate a
        // trivial merge by reusing c2's tree with c1 as a second parent.
        let Object::Commit(c2_obj) = store.read_object(&c2).unwrap() else {
            unreachable!()
        };
        let c3 = put_commit(&store, c2_obj.tree_hash, vec![c2, c1], 3, 300);

        let predicate = build_blame_proof(&store, &BlameOptions::default(), c3, "f.txt").unwrap();
        verify_blame_proof(&predicate, b"base\nside\n", None).expect("store-less verify passes");
        verify_blame_proof(&predicate, b"base\nside\n", Some(&store))
            .expect("store-holding verify passes");
    }

    // -----------------------------------------------------------------
    // Tamper matrix — each case must fail with its own distinct variant.
    // -----------------------------------------------------------------

    fn honest_fixture() -> (TempDir, ObjectStore, BlameProofPredicate, Vec<u8>) {
        let (dir, store) = fresh_store();
        let c1 = commit_file(&store, "src", "lib.rs", b"a\nb\nc\n", vec![], 1, 100);
        let c2 = commit_file(&store, "src", "lib.rs", b"a\nB\nc\n", vec![c1], 2, 200);
        let predicate =
            build_blame_proof(&store, &BlameOptions::default(), c2, "src/lib.rs").unwrap();
        (dir, store, predicate, b"a\nB\nc\n".to_vec())
    }

    #[test]
    fn tamper_wrong_file_bytes_fails_blob_identity() {
        let (_d, _store, predicate, _bytes) = honest_fixture();
        let err = verify_blame_proof(&predicate, b"a\nWRONG\nc\n", None).unwrap_err();
        assert!(matches!(err, BlameProofError::BlobMismatch { .. }));
    }

    #[test]
    fn tamper_flipped_attribution_line_fails_ancestry_unknown_origin() {
        let (_d, _store, mut predicate, bytes) = honest_fixture();
        predicate.attributions[0].1 = hash::hash(b"not a real commit anywhere in this proof");
        let err = verify_blame_proof(&predicate, &bytes, None).unwrap_err();
        assert!(matches!(err, BlameProofError::AttributionOriginUnknown(_)));
    }

    #[test]
    fn tamper_dropped_tree_path_step_fails_tree_path_broken() {
        let (_d, _store, mut predicate, bytes) = honest_fixture();
        assert_eq!(predicate.tree_path.len(), 2, "src/lib.rs has 2 levels");
        // Drop the leaf-most (innermost) level so the remaining level's
        // childId no longer chains from predicate.blob.
        predicate.tree_path.remove(0);
        let err = verify_blame_proof(&predicate, &bytes, None).unwrap_err();
        assert!(matches!(err, BlameProofError::TreePathBroken { level: 0 }));
    }

    #[test]
    fn tamper_swapped_origin_header_fails_origin_header_mismatch() {
        let (_d, store) = fresh_store();
        let c1 = commit_file(&store, "", "f.txt", b"base\n", vec![], 1, 100);
        let c2 = commit_file(&store, "", "f.txt", b"base\nchanged\n", vec![c1], 2, 200);
        let c3 = commit_file(&store, "", "f.txt", b"base\nCHANGED\n", vec![c2], 3, 300);
        let mut predicate =
            build_blame_proof(&store, &BlameOptions::default(), c3, "f.txt").unwrap();
        assert!(
            !predicate.origins.is_empty(),
            "c1/c2 ancestry must be bundled for this fixture"
        );
        // Swap in an unrelated header content for one origins[] entry,
        // keeping its claimed `commit` label the same.
        let victim = &mut predicate.origins[0];
        victim.header.timestamp = victim.header.timestamp.wrapping_add(1);

        let err = verify_blame_proof(&predicate, b"base\nCHANGED\n", None).unwrap_err();
        assert!(matches!(err, BlameProofError::OriginHeaderMismatch(_)));
    }

    #[test]
    fn tamper_truncated_ancestry_path_fails_path_truncated() {
        let (_d, store) = fresh_store();
        let c1 = commit_file(&store, "", "f.txt", b"base\n", vec![], 1, 100);
        let c2 = commit_file(&store, "", "f.txt", b"base\nchanged\n", vec![c1], 2, 200);
        let c3 = commit_file(&store, "", "f.txt", b"base\nCHANGED\n", vec![c2], 3, 300);
        let mut predicate =
            build_blame_proof(&store, &BlameOptions::default(), c3, "f.txt").unwrap();
        assert_eq!(
            predicate.origins.len(),
            2,
            "c1 and c2 are both distinct origins reachable from c3"
        );
        // Remove the *intermediate* header (c2, the one directly reachable
        // from commitHeader.parents) so the origin further back (c1) is
        // still present in origins[] but disconnected from commitHeader.
        let commit_header_parent = predicate.commit_header.parents[0];
        let intermediate_index = predicate
            .origins
            .iter()
            .position(|o| o.commit == commit_header_parent)
            .expect("c2's header must be directly reachable from commitHeader");
        predicate.origins.remove(intermediate_index);

        let err = verify_blame_proof(&predicate, b"base\nCHANGED\n", None).unwrap_err();
        assert!(matches!(err, BlameProofError::AncestryPathTruncated(_)));
    }

    #[test]
    fn ancestry_store_holding_shortcut_recovers_from_missing_origins() {
        // Same setup as the truncation tamper case, but this time pass the
        // store: the store-holding shortcut must recover the disconnected
        // origin even though origins[] no longer connects it.
        let (_d, store) = fresh_store();
        let c1 = commit_file(&store, "", "f.txt", b"base\n", vec![], 1, 100);
        let c2 = commit_file(&store, "", "f.txt", b"base\nchanged\n", vec![c1], 2, 200);
        let c3 = commit_file(&store, "", "f.txt", b"base\nCHANGED\n", vec![c2], 3, 300);
        let mut predicate =
            build_blame_proof(&store, &BlameOptions::default(), c3, "f.txt").unwrap();
        predicate.origins.clear();

        verify_blame_proof(&predicate, b"base\nCHANGED\n", Some(&store))
            .expect("store-holding shortcut recovers ancestry without origins[]");
        let err = verify_blame_proof(&predicate, b"base\nCHANGED\n", None).unwrap_err();
        assert!(matches!(
            err,
            BlameProofError::AttributionOriginUnknown(_)
                | BlameProofError::AncestryPathTruncated(_)
        ));
    }

    #[test]
    fn tamper_commit_header_fails_commit_identity() {
        let (_d, _store, mut predicate, bytes) = honest_fixture();
        predicate.commit_header.timestamp = predicate.commit_header.timestamp.wrapping_add(1);
        let err = verify_blame_proof(&predicate, &bytes, None).unwrap_err();
        assert!(matches!(err, BlameProofError::CommitIdentityMismatch));
    }

    #[test]
    fn unsupported_version_rejected() {
        let (_d, _store, mut predicate, bytes) = honest_fixture();
        predicate.v = 2;
        let err = verify_blame_proof(&predicate, &bytes, None).unwrap_err();
        assert!(matches!(err, BlameProofError::UnsupportedVersion(2)));
    }

    #[test]
    fn attributions_gap_rejected() {
        let (_d, _store, mut predicate, bytes) = honest_fixture();
        predicate.attributions[1].0 = 5;
        let err = verify_blame_proof(&predicate, &bytes, None).unwrap_err();
        assert!(matches!(err, BlameProofError::AttributionsMalformed(_)));
    }
}
