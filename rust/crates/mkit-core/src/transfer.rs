//! Transfer-layer helpers: delta-aware pack planning and the packlist
//! discovery wire format.
//!
//! These sit ABOVE the on-disk pack format (SPEC-PACKFILE / SPEC-DELTA)
//! and below the transport. The push path uses [`plan_pack`] to decide
//! which objects of a ref's closure to send, and how — raw, or as a delta
//! against a base the remote already holds. The plan is then serialised
//! with [`crate::pack::PackWriter`] and uploaded as a single pack keyed by
//! its own BLAKE3 digest.
//!
//! Because a delta-encoded pack is keyed by the pack digest (not by the
//! reconstructed object's hash), the fetch side can no longer find it by
//! walking object hashes. Each push records a [`PackListNode`] — this
//! module's small versioned wire format — holding the pack(s) it added plus
//! a `prev` pointer to the previous node, forming a per-branch chain. The
//! push side advertises the chain head through a `refs/mkit/packmap/<branch>`
//! metadata ref whose value is the BLAKE3 of the head node (itself stored as
//! a pack object). The fetch side reads that ref, walks the chain, and
//! unpacks every pack oldest-first. Chaining keeps each push O(1) on the
//! wire rather than re-uploading the whole history's list.
//!
//! Content addressing is unchanged: delta is a transfer encoding only. The
//! reconstructed object's id is still BLAKE3 of its canonical bytes, which
//! `PackReader` re-verifies before storing.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::delta;
use crate::hash::{self, Hash};
use crate::object::{Object, ObjectType};
use crate::store::{ObjectStore, StoreError};

// ---------------------------------------------------------------------------
// PackList wire format
// ---------------------------------------------------------------------------

/// ASCII magic at the start of every packlist node ("mkit pack list").
pub const PACKLIST_MAGIC: &[u8; 4] = b"MKPL";
/// Current packlist version. Readers reject anything else so a future
/// format change is a loud error, not a silent misparse.
pub const PACKLIST_VERSION: u8 = 1;
/// Hard cap on packs recorded in a single node — a normal push records
/// one; refuse to allocate unboundedly on a malformed blob.
pub const PACKLIST_MAX_ENTRIES: u32 = 1_000_000;

/// `[4B magic][1B version][1B has_prev][32B prev][4B count]`. The `prev`
/// bytes are always present (zeroed when `has_prev == 0`) so the layout is
/// fixed-size up to `count`.
const PACKLIST_HEADER_LEN: usize = 4 + 1 + 1 + hash::HASH_LEN + 4;

/// A single node in a branch's packlist chain.
///
/// The push path appends one node per push: `prev` points at the previous
/// node (the current packmap value before this push), and `packs` holds the
/// pack(s) this push added. The full ordered pack set for a branch is the
/// chain walked oldest-first — see `remote_dispatch::fetch_pack_chain`.
///
/// Chaining keeps each push O(1) on the wire (read a 32-byte pointer, write
/// a ~64-byte node) instead of re-uploading the whole history's list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackListNode {
    /// Previous node's key, or `None` for the first node of a branch.
    pub prev: Option<Hash>,
    /// Pack keys added by this node, in apply order.
    pub packs: Vec<Hash>,
}

/// Errors decoding a [`PackListNode`] blob.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PackListError {
    #[error("packlist is shorter than the {PACKLIST_HEADER_LEN}-byte header")]
    TooShort,
    #[error("packlist magic is not \"MKPL\"")]
    InvalidMagic,
    #[error("packlist version {0} is not supported (v1 only)")]
    UnsupportedVersion(u8),
    #[error("packlist has_prev byte {0} is not 0 or 1")]
    InvalidHasPrev(u8),
    #[error("packlist pack count {0} exceeds the {PACKLIST_MAX_ENTRIES} cap")]
    TooManyEntries(u32),
    #[error("packlist body length does not match the declared pack count")]
    LengthMismatch,
}

/// Serialise one packlist node.
///
/// # Errors
///
/// [`PackListError::TooManyEntries`] if `packs` exceeds the cap.
pub fn encode_packlist(prev: Option<Hash>, packs: &[Hash]) -> Result<Vec<u8>, PackListError> {
    let count = u32::try_from(packs.len()).map_err(|_| PackListError::TooManyEntries(u32::MAX))?;
    if count > PACKLIST_MAX_ENTRIES {
        return Err(PackListError::TooManyEntries(count));
    }
    let mut out = Vec::with_capacity(PACKLIST_HEADER_LEN + packs.len() * hash::HASH_LEN);
    out.extend_from_slice(PACKLIST_MAGIC);
    out.push(PACKLIST_VERSION);
    out.push(u8::from(prev.is_some()));
    out.extend_from_slice(&prev.unwrap_or(hash::ZERO));
    out.extend_from_slice(&count.to_le_bytes());
    for k in packs {
        out.extend_from_slice(k);
    }
    Ok(out)
}

/// Parse a packlist node blob.
///
/// # Errors
///
/// Returns the matching [`PackListError`] for a short buffer, wrong magic,
/// unknown version, a bad `has_prev` flag, an over-cap count, or a body
/// whose length does not match the declared count (which also catches
/// trailing data).
pub fn decode_packlist(bytes: &[u8]) -> Result<PackListNode, PackListError> {
    if bytes.len() < PACKLIST_HEADER_LEN {
        return Err(PackListError::TooShort);
    }
    if &bytes[..4] != PACKLIST_MAGIC.as_slice() {
        return Err(PackListError::InvalidMagic);
    }
    let version = bytes[4];
    if version != PACKLIST_VERSION {
        return Err(PackListError::UnsupportedVersion(version));
    }
    let prev = match bytes[5] {
        0 => None,
        1 => {
            let mut p = [0u8; hash::HASH_LEN];
            p.copy_from_slice(&bytes[6..6 + hash::HASH_LEN]);
            Some(p)
        }
        other => return Err(PackListError::InvalidHasPrev(other)),
    };
    let count_off = 6 + hash::HASH_LEN;
    let mut count_bytes = [0u8; 4];
    count_bytes.copy_from_slice(&bytes[count_off..count_off + 4]);
    let count = u32::from_le_bytes(count_bytes);
    if count > PACKLIST_MAX_ENTRIES {
        return Err(PackListError::TooManyEntries(count));
    }
    let count = count as usize;
    // Exact-length check doubles as a trailing-bytes guard: any extra or
    // missing byte after the declared entries is a malformed packlist.
    let expected = PACKLIST_HEADER_LEN + count * hash::HASH_LEN;
    if bytes.len() != expected {
        return Err(PackListError::LengthMismatch);
    }
    let mut packs = Vec::with_capacity(count);
    for i in 0..count {
        let start = PACKLIST_HEADER_LEN + i * hash::HASH_LEN;
        let mut h = [0u8; hash::HASH_LEN];
        h.copy_from_slice(&bytes[start..start + hash::HASH_LEN]);
        packs.push(h);
    }
    Ok(PackListNode { prev, packs })
}

// ---------------------------------------------------------------------------
// Delta base selection
// ---------------------------------------------------------------------------

/// Cap on tree-diff recursion depth when pairing chunked blobs across two
/// commits. Bounds the walk on adversarial / pathologically nested trees.
const MAX_TREE_DEPTH: usize = 64;

/// Choose, for each changed `FastCDC` chunk in `new_tip`, a base chunk from
/// `old_tip` to delta against.
///
/// The heuristic is deliberately simple (SPEC-DELTA §5 is informative —
/// any base the size-gate later accepts is fine): diff the two commits'
/// trees by path; where the same path is a [`crate::object::ChunkedBlob`] on both sides
/// with a different manifest hash, pair each new chunk against the
/// old chunk at the same index (falling back to the last old chunk). A
/// small in-place edit keeps chunk boundaries stable, so same-index
/// pairing lands the new chunk against its prior version. Identical chunks
/// (present byte-for-byte in the old manifest) are skipped — they dedup
/// for free and never need a delta.
///
/// The returned map is `new_chunk_hash -> base_chunk_hash`. Every base is
/// reachable from `old_tip`, so a remote that already holds `old_tip` holds
/// the base. The caller still gates on whether the delta actually saves
/// bytes ([`plan_pack`]).
///
/// # Errors
///
/// Propagates [`StoreError`] other than `ObjectNotFound`, which is treated
/// as "no pairing available" (a partial local history is not fatal here —
/// the worst case is that we send the chunk raw).
pub fn select_chunk_delta_bases(
    store: &ObjectStore,
    new_tip: Hash,
    old_tip: Hash,
) -> Result<HashMap<Hash, Hash>, StoreError> {
    let mut out = HashMap::new();
    let (Some(new_tree), Some(old_tree)) = (tip_tree(store, new_tip)?, tip_tree(store, old_tip)?)
    else {
        return Ok(out);
    };
    pair_trees(store, new_tree, old_tree, 0, &mut out)?;
    Ok(out)
}

/// Resolve a commit/remix tip to its root tree hash; `None` for any other
/// object kind (a tip that is not a commit has no tree to diff).
fn tip_tree(store: &ObjectStore, tip: Hash) -> Result<Option<Hash>, StoreError> {
    match store.read_object(&tip) {
        Ok(Object::Commit(c)) => Ok(Some(c.tree_hash)),
        Ok(Object::Remix(r)) => Ok(Some(r.tree_hash)),
        // A non-commit tip, or one we don't have, simply has no tree to diff.
        Ok(_) | Err(StoreError::ObjectNotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Merge-join two sorted trees by entry name, recursing into matching
/// subtrees and pairing chunks for matching chunked-blob entries.
fn pair_trees(
    store: &ObjectStore,
    new_tree: Hash,
    old_tree: Hash,
    depth: usize,
    out: &mut HashMap<Hash, Hash>,
) -> Result<(), StoreError> {
    if depth > MAX_TREE_DEPTH || new_tree == old_tree {
        return Ok(());
    }
    let (Some(Object::Tree(new_t)), Some(Object::Tree(old_t))) = (
        read_optional(store, new_tree)?,
        read_optional(store, old_tree)?,
    ) else {
        return Ok(());
    };

    // Both trees are lex-sorted by name (SPEC-OBJECTS §4); two-pointer
    // merge to find entries present under the same name on both sides.
    let (mut i, mut j) = (0usize, 0usize);
    while i < new_t.entries.len() && j < old_t.entries.len() {
        let ne = &new_t.entries[i];
        let oe = &old_t.entries[j];
        match ne.name.cmp(&oe.name) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                if ne.object_hash != oe.object_hash {
                    pair_entry(store, ne.object_hash, oe.object_hash, depth, out)?;
                }
                i += 1;
                j += 1;
            }
        }
    }
    Ok(())
}

/// Dispatch a changed same-named entry: recurse into subtrees, pair
/// chunked blobs, ignore everything else.
fn pair_entry(
    store: &ObjectStore,
    new_hash: Hash,
    old_hash: Hash,
    depth: usize,
    out: &mut HashMap<Hash, Hash>,
) -> Result<(), StoreError> {
    match (store.read_object(&new_hash), store.read_object(&old_hash)) {
        (Ok(Object::Tree(_)), Ok(Object::Tree(_))) => {
            pair_trees(store, new_hash, old_hash, depth + 1, out)
        }
        (Ok(Object::ChunkedBlob(new_cb)), Ok(Object::ChunkedBlob(old_cb))) => {
            pair_chunks(&new_cb.chunks, &old_cb.chunks, out);
            Ok(())
        }
        // A missing object or a kind mismatch (file became a chunked blob,
        // etc.) just yields no pairing for this entry.
        (Err(StoreError::ObjectNotFound(_)), _) | (_, Err(StoreError::ObjectNotFound(_))) => Ok(()),
        (Err(e), _) | (_, Err(e)) => Err(e),
        _ => Ok(()),
    }
}

/// Pair each new chunk against an old chunk by index. Skips chunks that
/// already exist byte-identically in the old manifest (those dedup) and
/// never overwrites an existing pairing, so the result is deterministic.
fn pair_chunks(new_chunks: &[Hash], old_chunks: &[Hash], out: &mut HashMap<Hash, Hash>) {
    if old_chunks.is_empty() {
        return;
    }
    let old_set: HashSet<&Hash> = old_chunks.iter().collect();
    for (j, nj) in new_chunks.iter().enumerate() {
        if old_set.contains(nj) || out.contains_key(nj) {
            continue;
        }
        // Same-index base, clamped to the last old chunk. The size-gate in
        // `plan_pack` rejects a poor pick and falls back to raw, so a loose
        // heuristic here only ever costs a wasted encode, never correctness.
        let base = old_chunks
            .get(j)
            .copied()
            .unwrap_or_else(|| old_chunks[old_chunks.len() - 1]);
        if base != *nj {
            out.insert(*nj, base);
        }
    }
}

/// Read an object, mapping a missing object to `None` so callers can treat
/// "absent" the same as "not the kind I wanted" without a hard error.
fn read_optional(store: &ObjectStore, h: Hash) -> Result<Option<Object>, StoreError> {
    match store.read_object(&h) {
        Ok(o) => Ok(Some(o)),
        Err(StoreError::ObjectNotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Pack planning
// ---------------------------------------------------------------------------

/// One delta entry in a [`PackPlan`]: a target object encoded against a
/// base the remote already holds.
#[derive(Debug, Clone)]
pub struct PlannedDelta {
    /// BLAKE3 of the reconstructed (canonical) object — its storage id.
    pub target: Hash,
    /// BLAKE3 of the base object the delta is applied against.
    pub base: Hash,
    /// SPEC-DELTA instruction stream.
    pub stream: Vec<u8>,
}

/// A deterministic plan for the single pack a push uploads for one ref.
///
/// Entries are pre-ordered for [`crate::pack::PackWriter`]: all `raw`
/// objects first (non-blobs before blobs, each group in BLAKE3 order),
/// then `deltas`. Delta bases are external — they live in `old_tip`'s
/// closure, which the remote already holds and earlier packs already
/// delivered — so no in-pack base ordering is required (SPEC-PACKFILE §4).
#[derive(Debug, Clone, Default)]
pub struct PackPlan {
    /// Objects to send verbatim, already ordered non-blobs-then-blobs.
    pub raw: Vec<Hash>,
    /// Objects to send as a delta against an already-present base.
    pub deltas: Vec<PlannedDelta>,
    /// `true` when the pack needs no externally-resolved base — i.e. this is
    /// a full-closure push (no usable `old_tip`), so the pack reconstructs
    /// the ref's whole closure on its own. The push path normally **appends**
    /// this pack to the branch's packlist chain; it uses `self_contained`
    /// only to decide whether a push may **reset** to a fresh chain when the
    /// prior chain is unreadable — a self-contained pack is the one kind that
    /// can safely escape a broken chain. (A safe re-baseline that resets a
    /// *healthy* chain to bound its depth needs the atomic head+packmap
    /// advance and is tracked as a follow-up; the resilient default is to
    /// append.)
    pub self_contained: bool,
}

impl PackPlan {
    /// Total objects the plan transfers (raw + delta).
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.raw.len() + self.deltas.len()
    }

    /// `true` when the plan carries nothing — the remote already holds the
    /// ref's whole closure.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty() && self.deltas.is_empty()
    }
}

/// Plan the pack for pushing `new_tip` to a remote whose current tip is
/// `old_tip` (`None` for a first push or a remote we cannot diff against).
///
/// Computes the send-set as `closure(new_tip) \ closure(old_tip)` — so
/// objects the remote already holds are never re-sent (this is the
/// identical-object dedup, preferred over delta) — then delta-encodes
/// changed chunks against same-path prior chunks where that actually
/// saves bytes, falling back to raw otherwise.
///
/// # Errors
///
/// Propagates [`StoreError`] from reading the local closure. A missing
/// `old_tip` closure is treated as "diff unavailable" (full-closure,
/// all-raw push) rather than an error.
pub fn plan_pack(
    store: &ObjectStore,
    new_tip: Hash,
    old_tip: Option<Hash>,
) -> Result<PackPlan, StoreError> {
    let new_set = crate::ops::reachable_objects(store, &new_tip)?;

    // What the remote already holds = the closure of its current tip, if we
    // can compute it locally. A partial local history (some referenced
    // object pruned) degrades to "send everything" rather than failing.
    let mut remote_set = BTreeSet::new();
    let mut base_map = HashMap::new();
    let mut have_old = false;
    if let Some(o) = old_tip
        && store.contains(&o)
    {
        match crate::ops::reachable_objects(store, &o) {
            Ok(s) => {
                remote_set = s;
                base_map = select_chunk_delta_bases(store, new_tip, o)?;
                have_old = true;
            }
            Err(StoreError::ObjectNotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }

    let send: BTreeSet<Hash> = new_set.difference(&remote_set).copied().collect();

    // Partition the send-set, iterating in BTreeSet (BLAKE3) order so the
    // plan — and therefore the pack bytes — is deterministic.
    let mut non_blob_raw = Vec::new();
    let mut blob_raw = Vec::new();
    let mut deltas = Vec::new();

    for h in &send {
        let bytes = store.read(h)?;
        // The object-type tag is the first prologue byte (SPEC-OBJECTS §1);
        // decode it through the canonical helper rather than re-deriving the
        // format here.
        let is_blob =
            bytes.first().and_then(|b| ObjectType::from_u8(*b).ok()) == Some(ObjectType::Blob);

        // Only blobs (FastCDC chunks) are delta candidates, and only against
        // a base the remote actually holds.
        if is_blob
            && let Some(base) = base_map.get(h)
            && remote_set.contains(base)
            && let Some(planned) = try_delta(store, *h, *base, &bytes)?
        {
            deltas.push(planned);
            continue;
        }

        if is_blob {
            blob_raw.push(*h);
        } else {
            non_blob_raw.push(*h);
        }
    }

    let mut raw = non_blob_raw;
    raw.extend(blob_raw);

    Ok(PackPlan {
        raw,
        deltas,
        self_contained: !have_old,
    })
}

/// Encode `target` against `base` and return the delta only if it is
/// strictly smaller on the wire than sending the target raw. The per-entry
/// frame (SPEC-PACKFILE §2) is identical for raw and delta, so only the
/// payloads differ: a delta payload is `base_hash (HASH_LEN) + stream`
/// (SPEC-PACKFILE §3.2) versus the raw object bytes. Compare those.
fn try_delta(
    store: &ObjectStore,
    target: Hash,
    base: Hash,
    target_bytes: &[u8],
) -> Result<Option<PlannedDelta>, StoreError> {
    let base_bytes = store.read(&base)?;
    let Ok(stream) = delta::encode(&base_bytes, target_bytes) else {
        // Over-u32 inputs can't happen here (object cap < 4 GiB), but treat
        // any encode failure as "send raw" rather than propagating.
        return Ok(None);
    };
    if hash::HASH_LEN + stream.len() < target_bytes.len() {
        Ok(Some(PlannedDelta {
            target,
            base,
            stream,
        }))
    } else {
        Ok(None)
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunker::{ChunkIterator, FastCdc};
    use crate::object::{Blob, ChunkedBlob, Commit, EntryMode, Identity, Tree, TreeEntry};
    use crate::pack::{PackReader, PackWriter};
    use crate::serialize;
    use tempfile::TempDir;

    fn store() -> (TempDir, ObjectStore) {
        let d = TempDir::new().unwrap();
        let s = ObjectStore::init(d.path()).unwrap();
        (d, s)
    }

    fn put(s: &ObjectStore, obj: &Object) -> Hash {
        s.write(&serialize::serialize(obj).unwrap()).unwrap()
    }

    /// Store `data` as `FastCDC` chunks + a `ChunkedBlob` manifest, mirroring
    /// the worktree large-file path. Returns the manifest hash.
    fn put_chunked(s: &ObjectStore, data: &[u8]) -> Hash {
        let chunks: Vec<Hash> = ChunkIterator::new(FastCdc::v1(), data)
            .map(|b| {
                put(
                    s,
                    &Object::Blob(Blob {
                        data: data[b.offset..b.offset + b.length].to_vec(),
                    }),
                )
            })
            .collect();
        put(
            s,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: data.len() as u64,
                chunk_size: 0,
                chunks,
            }),
        )
    }

    fn commit_with_file(s: &ObjectStore, file_hash: Hash, parents: Vec<Hash>, msg: &str) -> Hash {
        let tree = put(
            s,
            &Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"big.bin".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: file_hash,
                }],
            }),
        );
        put(
            s,
            &Object::Commit(Commit::new_unannotated(
                tree,
                parents,
                Identity::ed25519([7; 32]),
                [0; 32],
                msg.as_bytes().to_vec(),
                msg.len() as u64,
                [0; 64],
            )),
        )
    }

    /// A >1 MiB pseudo-random buffer (deterministic) that `FastCDC` splits
    /// into several chunks. Splitmix64 keeps it dependency-free and
    /// reproducible.
    fn big_buffer() -> Vec<u8> {
        let mut data = vec![0u8; 2 * 1024 * 1024];
        let mut state: u64 = 0x1234_5678_9abc_def0;
        for chunk in data.chunks_mut(8) {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            let bytes = z.to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&bytes[..n]);
        }
        data
    }

    #[test]
    fn packlist_node_roundtrip_with_prev() {
        let prev = [0x11u8; 32];
        let packs = vec![[1u8; 32], [2u8; 32], [0xABu8; 32]];
        let bytes = encode_packlist(Some(prev), &packs).unwrap();
        assert_eq!(&bytes[..4], PACKLIST_MAGIC);
        assert_eq!(bytes[4], PACKLIST_VERSION);
        let node = decode_packlist(&bytes).unwrap();
        assert_eq!(node.prev, Some(prev));
        assert_eq!(node.packs, packs);
    }

    #[test]
    fn packlist_node_roundtrip_first_node() {
        // First node of a branch: no predecessor, one pack.
        let bytes = encode_packlist(None, &[[7u8; 32]]).unwrap();
        let node = decode_packlist(&bytes).unwrap();
        assert_eq!(node.prev, None);
        assert_eq!(node.packs, vec![[7u8; 32]]);
    }

    #[test]
    fn packlist_rejects_bad_magic_version_haspriv_and_length() {
        let good = encode_packlist(Some([0x11u8; 32]), &[[9u8; 32]]).unwrap();

        let mut bad_magic = good.clone();
        bad_magic[0] = b'X';
        assert_eq!(
            decode_packlist(&bad_magic),
            Err(PackListError::InvalidMagic)
        );

        let mut bad_ver = good.clone();
        bad_ver[4] = 2;
        assert_eq!(
            decode_packlist(&bad_ver),
            Err(PackListError::UnsupportedVersion(2))
        );

        let mut bad_prev = good.clone();
        bad_prev[5] = 9; // has_prev must be 0 or 1
        assert_eq!(
            decode_packlist(&bad_prev),
            Err(PackListError::InvalidHasPrev(9))
        );

        // Drop a byte → declared count no longer matches the body.
        let mut short = good.clone();
        short.pop();
        assert_eq!(decode_packlist(&short), Err(PackListError::LengthMismatch));

        // Trailing byte → same guard fires.
        let mut long = good;
        long.push(0);
        assert_eq!(decode_packlist(&long), Err(PackListError::LengthMismatch));

        assert_eq!(decode_packlist(&[0u8; 3]), Err(PackListError::TooShort));
    }

    #[test]
    fn plan_first_push_is_self_contained_all_raw() {
        let (_d, s) = store();
        let file = put_chunked(&s, &big_buffer());
        let c1 = commit_with_file(&s, file, vec![], "v1");

        let plan = plan_pack(&s, c1, None).unwrap();
        assert!(plan.self_contained);
        assert!(plan.deltas.is_empty(), "no base on a first push");
        // commit + tree + manifest + every chunk must be present.
        let full = crate::ops::reachable_objects(&s, &c1).unwrap();
        assert_eq!(plan.object_count(), full.len());
    }

    #[test]
    fn plan_second_push_deltas_changed_chunk_and_skips_unchanged() {
        let (_d, s) = store();
        let v1 = big_buffer();
        let file1 = put_chunked(&s, &v1);
        let c1 = commit_with_file(&s, file1, vec![], "v1");

        // Edit a small in-place region (same length → stable boundaries).
        let mut v2 = v1.clone();
        for k in 0..16 {
            v2[900_000 + k] ^= 0xFF;
        }
        let file2 = put_chunked(&s, &v2);
        let c2 = commit_with_file(&s, file2, vec![c1], "v2");

        let plan = plan_pack(&s, c2, Some(c1)).unwrap();
        assert!(
            !plan.self_contained,
            "second push diffs against the prior tip"
        );

        // At least one changed chunk should delta-compress.
        assert!(
            !plan.deltas.is_empty(),
            "expected a delta for the edited chunk"
        );

        // The send-set must exclude every object the v1 closure already
        // holds (identical-chunk dedup), so it is far smaller than the full
        // v2 closure.
        let v2_full = crate::ops::reachable_objects(&s, &c2).unwrap();
        assert!(
            plan.object_count() < v2_full.len(),
            "unchanged chunks must not be re-sent"
        );

        // The pack must reconstruct, bit-for-bit, against a store seeded
        // with the v1 closure (what the remote/fetcher already holds).
        assert_pack_reconstructs(&s, &plan, c1, c2);
    }

    /// Build the planned pack, replay it into a fresh store pre-seeded with
    /// `old_tip`'s closure, and assert every `new_tip` object reconstructs
    /// with a matching hash.
    fn assert_pack_reconstructs(src: &ObjectStore, plan: &PackPlan, old_tip: Hash, new_tip: Hash) {
        let mut w = PackWriter::new();
        for h in &plan.raw {
            let bytes = src.read(h).unwrap();
            w.push_raw(*h, bytes).unwrap();
        }
        for d in &plan.deltas {
            w.push_delta(&d.base, &d.stream).unwrap();
        }
        let pack = w.finish().unwrap();

        // Seed the destination with what the remote already has.
        let (_d2, dst) = store();
        for h in crate::ops::reachable_objects(src, &old_tip).unwrap() {
            dst.write(&src.read(&h).unwrap()).unwrap();
        }

        PackReader::read(&pack, &dst).unwrap();

        for h in crate::ops::reachable_objects(src, &new_tip).unwrap() {
            // `dst.read` already re-verifies the object addresses to `h`
            // (merkle root for Tree/ChunkedBlob, BLAKE3 otherwise); assert
            // the dispatched id explicitly via `Object::id`.
            let got = dst.read(&h).unwrap();
            assert_eq!(
                crate::serialize::deserialize(&got).unwrap().id().unwrap(),
                h,
                "reconstructed object must address to its id"
            );
            assert_eq!(got, src.read(&h).unwrap());
        }
    }

    #[test]
    fn select_bases_pairs_only_changed_chunks() {
        let (_d, s) = store();
        let v1 = big_buffer();
        let file1 = put_chunked(&s, &v1);
        let c1 = commit_with_file(&s, file1, vec![], "v1");

        let mut v2 = v1.clone();
        v2[1_000_000] ^= 0xFF;
        let file2 = put_chunked(&s, &v2);
        let c2 = commit_with_file(&s, file2, vec![c1], "v2");

        let bases = select_chunk_delta_bases(&s, c2, c1).unwrap();
        assert!(!bases.is_empty());
        // Every paired target is a chunk that is new in v2, and every base
        // is a chunk that v1 held.
        let v1_set = crate::ops::reachable_objects(&s, &c1).unwrap();
        for (target, base) in &bases {
            assert!(!v1_set.contains(target), "target should be new");
            assert!(v1_set.contains(base), "base must be present at old tip");
        }
    }
}
