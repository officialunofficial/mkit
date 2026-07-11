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
//! reconstructed object's id (BLAKE3 of its canonical bytes, or the merkle
//! BMT root for a `Tree`/`ChunkedBlob` — see `crate::merkle`) is
//! re-verified by `PackReader` before storing.

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

/// The fixed guard header preceding the codec body: `[4B magic][1B
/// version]`. The body (`prev` pointer + pack list) is encoded with
/// `commonware-codec` and is variable-length.
const PACKLIST_HEADER_LEN: usize = 4 + 1;

/// A single node in a branch's packlist chain.
///
/// The push path appends one node per push: `prev` points at the previous
/// node (the current packmap value before this push), and `packs` holds the
/// pack(s) this push added. The full ordered pack set for a branch is the
/// chain walked oldest-first — see `remote_dispatch::fetch_pack_chain`.
///
/// Chaining keeps each push O(1) on the wire (read a 32-byte pointer, write
/// a ~64-byte node) instead of re-uploading the whole history's list.
///
/// A node's `prev` is reset to `None` (rather than linked to the prior head)
/// when a push re-baselines (#406) — proactively bounding chain depth, or
/// reactively escaping a broken chain. Either way the packs the superseded
/// chain referenced become unreachable from the new head node: they are not
/// deleted here (this module only ever writes new nodes/packs, never
/// deletes), so they linger as orphaned storage on the remote until a
/// server-side sweep reclaims them (tracked as makechain#849). A stale
/// pack lingering harmlessly is safe; nothing on the fetch side ever
/// resolves it once no live chain points to it.
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
    #[error("packlist is shorter than the {PACKLIST_HEADER_LEN}-byte magic+version header")]
    TooShort,
    #[error("packlist magic is not \"MKPL\"")]
    InvalidMagic,
    #[error("packlist version {0} is not supported (v1 only)")]
    UnsupportedVersion(u8),
    #[error("packlist pack count exceeds the {PACKLIST_MAX_ENTRIES} cap")]
    TooManyEntries(u32),
    /// The codec body (prev pointer / pack list) is malformed, truncated,
    /// or has trailing bytes.
    #[error("packlist body is malformed (bad codec payload or trailing bytes)")]
    Malformed,
}

/// Serialise one packlist node: the `MKPL`/version guard header followed by
/// the `prev`/`packs` body encoded with `commonware-codec` (idiomatic
/// `Option` + `Vec`).
///
/// # Errors
///
/// [`PackListError::TooManyEntries`] if `packs` exceeds the cap.
pub fn encode_packlist(prev: Option<Hash>, packs: &[Hash]) -> Result<Vec<u8>, PackListError> {
    use commonware_codec::Write;
    let count = u32::try_from(packs.len()).map_err(|_| PackListError::TooManyEntries(u32::MAX))?;
    if count > PACKLIST_MAX_ENTRIES {
        return Err(PackListError::TooManyEntries(count));
    }
    let mut out = Vec::new();
    out.extend_from_slice(PACKLIST_MAGIC);
    out.push(PACKLIST_VERSION);
    // Body via commonware-codec: an `Option<Hash>` then a `Vec<Hash>`
    // (length-prefixed). `Vec<u8>` is a `bytes::BufMut`.
    prev.write(&mut out);
    packs.to_vec().write(&mut out);
    Ok(out)
}

/// Parse a packlist node blob.
///
/// # Errors
///
/// Returns the matching [`PackListError`] for a short buffer, wrong magic,
/// or unknown version (the explicit guard header), or
/// [`PackListError::Malformed`] / [`PackListError::TooManyEntries`] from
/// the `commonware-codec` body (over-cap pack list, truncation, or
/// trailing bytes).
pub fn decode_packlist(bytes: &[u8]) -> Result<PackListNode, PackListError> {
    use bytes::Buf as _;
    use commonware_codec::{ReadExt, ReadRangeExt};

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
    // Body: `Option<Hash>` then a length-capped `Vec<Hash>`. `&[u8]` is a
    // `bytes::Buf`; the `RangeCfg` enforces the entry cap at decode time.
    let mut buf: &[u8] = &bytes[PACKLIST_HEADER_LEN..];
    let prev = <Option<Hash>>::read(&mut buf).map_err(|_| PackListError::Malformed)?;
    let packs = <Vec<Hash>>::read_range(&mut buf, 0..=PACKLIST_MAX_ENTRIES as usize)
        .map_err(|_| PackListError::Malformed)?;
    // Trailing bytes after the declared body are a malformed packlist.
    if buf.has_remaining() {
        return Err(PackListError::Malformed);
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
/// (SPEC-DELTA §5 is informative — any base the size-gate later accepts is
/// fine.) Diff the two commits' trees by path; where the same path is a
/// [`crate::object::ChunkedBlob`] on both sides with a different manifest
/// hash, pair each changed new chunk against a base in the old manifest —
/// by same-index when the chunk counts match (an in-place edit didn't shift
/// boundaries) or by content similarity when they differ (an insert/delete
/// did, via `pair_chunks`). Identical chunks (present byte-for-byte in the
/// old manifest) are skipped — they dedup for free and never need a delta.
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
            pair_chunks(store, &new_cb.chunks, &old_cb.chunks, out)
        }
        // A missing object or a kind mismatch (file became a chunked blob,
        // etc.) just yields no pairing for this entry.
        (Err(StoreError::ObjectNotFound(_)), _) | (_, Err(StoreError::ObjectNotFound(_))) => Ok(()),
        (Err(e), _) | (_, Err(e)) => Err(e),
        _ => Ok(()),
    }
}

/// Window size for content-similarity sketching. Matches the delta
/// encoder's match-block size, so a shared 16-byte run is a shared feature.
const FEATURE_WINDOW: usize = 16;
/// Number of min-hash "super-features" sampled per chunk. Small keeps the
/// index cheap; the delta size-gate in [`plan_pack`] is the final judge of a
/// pick, so a few features are enough signal to rank candidates.
const FEATURE_COUNT: usize = 4;

/// Pair each changed new chunk against a base chunk in the old manifest.
/// Skips chunks already present byte-identically in the old manifest (those
/// dedup for free) and never overwrites an existing pairing, so the result
/// is deterministic.
///
/// Two regimes:
///
/// * **Equal chunk counts** ⇒ `FastCDC` boundaries didn't shift (an in-place,
///   same-length edit), so same-index pairing lands the new chunk on its own
///   prior version. This is the common case and reads no chunk content.
/// * **Differing counts** ⇒ an insert/delete shifted indices, so position is
///   unreliable. We match by **content similarity**: index every old chunk's
///   min-hash super-features, then pick, for each changed new chunk, the old
///   chunk sharing the most features (deterministic tiebreak: lowest hash),
///   falling back to the clamped same-index chunk when there is no overlap.
///   This reads the changed file's chunk content (`O(file size)`), but only
///   when there actually was a shift — and it trades those local reads for a
///   much smaller upload than re-sending the shifted chunks raw.
fn pair_chunks(
    store: &ObjectStore,
    new_chunks: &[Hash],
    old_chunks: &[Hash],
    out: &mut HashMap<Hash, Hash>,
) -> Result<(), StoreError> {
    if old_chunks.is_empty() {
        return Ok(());
    }
    let old_set: HashSet<&Hash> = old_chunks.iter().collect();

    // Fast path: no boundary shift → same-index pairing, no content reads.
    if new_chunks.len() == old_chunks.len() {
        for (j, nj) in new_chunks.iter().enumerate() {
            if old_set.contains(nj) || out.contains_key(nj) {
                continue;
            }
            if old_chunks[j] != *nj {
                out.insert(*nj, old_chunks[j]);
            }
        }
        return Ok(());
    }

    // Shifted: index old chunks by their super-features once. An unreadable
    // old chunk (absent / non-blob) contributes no features and can't be a
    // base — it is simply absent from the index.
    let mut feature_index: HashMap<u64, Vec<Hash>> = HashMap::new();
    for oc in old_chunks {
        if let Some(content) = chunk_bytes(store, oc)? {
            for f in chunk_features(&content) {
                feature_index.entry(f).or_default().push(*oc);
            }
        }
    }

    for nj in new_chunks {
        if old_set.contains(nj) || out.contains_key(nj) {
            continue;
        }
        // An unreadable new chunk has no content signal — skip pairing it
        // (it's sent raw) rather than guessing a base.
        let Some(content) = chunk_bytes(store, nj)? else {
            continue;
        };
        // Count shared features per candidate old chunk.
        let mut votes: HashMap<Hash, u32> = HashMap::new();
        for f in &chunk_features(&content) {
            if let Some(cands) = feature_index.get(f) {
                for cand in cands {
                    *votes.entry(*cand).or_default() += 1;
                }
            }
        }
        // Pair ONLY on genuine content overlap: most shared features wins,
        // ties → lowest hash (deterministic, order-independent). No overlap →
        // no base; the chunk is sent raw (a dissimilar base would be rejected
        // by the size-gate anyway). No position fallback after a shift.
        if let Some((base, _)) = votes
            .into_iter()
            .filter(|(cand, _)| cand != nj)
            .max_by(|x, y| x.1.cmp(&y.1).then_with(|| y.0.cmp(&x.0)))
        {
            out.insert(*nj, base);
        }
    }
    Ok(())
}

/// Read a chunk blob's CONTENT bytes (not its serialized object form).
///
/// Returns `None` when the object is absent or not a blob — there is no
/// content to compare, so the caller skips pairing that chunk rather than
/// inventing a base. A genuine read/IO error propagates, preserving the
/// [`select_chunk_delta_bases`] contract (only `ObjectNotFound` is swallowed).
fn chunk_bytes(store: &ObjectStore, h: &Hash) -> Result<Option<Vec<u8>>, StoreError> {
    match store.read_object(h) {
        Ok(Object::Blob(b)) => Ok(Some(b.data)),
        Ok(_) | Err(StoreError::ObjectNotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Up to [`FEATURE_COUNT`] shift-resistant "super-features" for a chunk: the
/// smallest distinct `FEATURE_WINDOW`-byte FNV-1a window hashes. Two chunks
/// that share content share these min-hashes with high probability even when
/// the content is shifted, making them a cheap similarity key. Chunks shorter
/// than the window yield none (such a chunk has no similarity key, so it is
/// left unpaired and sent raw).
fn chunk_features(bytes: &[u8]) -> Vec<u64> {
    if bytes.len() < FEATURE_WINDOW {
        return Vec::new();
    }
    // Keep the K smallest DISTINCT window hashes, ascending.
    let mut best: Vec<u64> = Vec::with_capacity(FEATURE_COUNT + 1);
    for w in bytes.windows(FEATURE_WINDOW) {
        let h = fnv1a(w);
        if best.len() == FEATURE_COUNT && h >= best[FEATURE_COUNT - 1] {
            continue;
        }
        if let Err(pos) = best.binary_search(&h) {
            best.insert(pos, h);
            best.truncate(FEATURE_COUNT);
        }
    }
    best
}

/// FNV-1a 64-bit over a fixed window — same primitive the delta writer uses
/// for block matching, so a shared block surfaces as a shared feature.
fn fnv1a(block: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in block {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0001_0000_01b3);
    }
    h
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
    /// to decide whether a push may **reset** to a fresh chain, in two
    /// cases:
    ///
    /// * Reactively, when the prior chain is unreadable — a self-contained
    ///   pack is the one kind that can safely escape a broken chain.
    /// * Proactively (#406): when a *healthy* chain has simply grown past
    ///   the re-baseline depth threshold, the push side calls [`plan_pack`]
    ///   with `old_tip: None` specifically to force `self_contained: true`,
    ///   then resets the chain to bound its depth. This reuses the atomic
    ///   head+packmap advance (#408) the reactive reset already depends on
    ///   — no separate mechanism was needed once that landed.
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
        // Classify via the cheap 6-byte prologue check (`object_type`)
        // instead of a full read+verify of the object's bytes — the send-set
        // classification only needs the type tag, not the content (INV-14).
        // Bytes are read (and BLAKE3-verified) below, lazily, only for the
        // subset that are actually delta candidates.
        let is_blob = store.object_type(h)? == ObjectType::Blob;

        // Only blobs (FastCDC chunks) are delta candidates, and only against
        // a base the remote actually holds.
        if is_blob
            && let Some(base) = base_map.get(h)
            && remote_set.contains(base)
        {
            let bytes = store.read(h)?;
            if let Some(planned) = try_delta(store, *h, *base, &bytes)? {
                deltas.push(planned);
                continue;
            }
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
        let s = ObjectStore::init(&crate::layout::RepoLayout::single(d.path())).unwrap();
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
    fn packlist_rejects_bad_magic_version_body_and_length() {
        let good = encode_packlist(Some([0x11u8; 32]), &[[9u8; 32]]).unwrap();

        // Magic and version are the explicit guard header (precise errors).
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

        // Truncated codec body → Malformed.
        let mut short = good.clone();
        short.pop();
        assert_eq!(decode_packlist(&short), Err(PackListError::Malformed));

        // Trailing byte after the declared body → Malformed.
        let mut long = good;
        long.push(0);
        assert_eq!(decode_packlist(&long), Err(PackListError::Malformed));

        // Shorter than the magic+version guard header → TooShort.
        assert_eq!(decode_packlist(&[0u8; 3]), Err(PackListError::TooShort));
    }

    #[test]
    fn packlist_decode_rejects_over_cap_pack_list() {
        // A REAL over-cap body: `encode_packlist` refuses to build one,
        // so assemble the node by hand with the same codec — the guard
        // header followed by `Option<Hash>` + a `Vec<Hash>` holding
        // PACKLIST_MAX_ENTRIES + 1 entries (~32 MiB). The decode-side
        // RangeCfg must reject it as Malformed, not allocate it.
        use commonware_codec::Write as _;
        let over_cap = PACKLIST_MAX_ENTRIES as usize + 1;
        let mut node = Vec::with_capacity(PACKLIST_HEADER_LEN + 8 + 32 * over_cap);
        node.extend_from_slice(PACKLIST_MAGIC);
        node.push(PACKLIST_VERSION);
        let prev: Option<Hash> = None;
        prev.write(&mut node);
        vec![[1u8; 32]; over_cap].write(&mut node);
        assert_eq!(decode_packlist(&node), Err(PackListError::Malformed));

        // Sanity: the identical construction at exactly the cap is
        // accepted, so the failure above is the cap check itself, not
        // an artifact of the hand-rolled encoding.
        let mut at_cap = Vec::with_capacity(PACKLIST_HEADER_LEN + 8 + 32 * (over_cap - 1));
        at_cap.extend_from_slice(PACKLIST_MAGIC);
        at_cap.push(PACKLIST_VERSION);
        let prev: Option<Hash> = None;
        prev.write(&mut at_cap);
        vec![[1u8; 32]; over_cap - 1].write(&mut at_cap);
        let decoded = decode_packlist(&at_cap).expect("at-cap list must decode");
        assert_eq!(decoded.packs.len(), PACKLIST_MAX_ENTRIES as usize);
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

    // =================================================================
    // object_type() short-circuit for plan_pack's type check (#636 /
    // INV-14) — classification must use the cheap type-prologue check
    // rather than a full read+verify, while objects actually selected as
    // delta candidates still get a real, verified read.
    // =================================================================

    /// Flip a byte well past the 6-byte type prologue so the object's
    /// on-disk content no longer matches its BLAKE3 hash, while its type
    /// tag stays intact and `object_type()` still reads it correctly.
    fn corrupt_payload_byte(s: &ObjectStore, h: &Hash) {
        use std::fs::OpenOptions;
        use std::io::{Read, Seek, SeekFrom, Write};
        let path = s.path_for(h);
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.seek(SeekFrom::Start(6)).unwrap();
        let mut byte = [0u8; 1];
        f.read_exact(&mut byte).unwrap();
        f.seek(SeekFrom::Start(6)).unwrap();
        f.write_all(&[byte[0] ^ 0xFF]).unwrap();
        f.sync_all().unwrap();
    }

    #[test]
    fn plan_pack_first_push_tolerates_corrupted_raw_blob_content() {
        // First push: every blob in the send-set is `raw` (no delta base
        // exists yet), so classification never needs to read a blob's
        // content — only its type. A blob whose payload has bit-rotted
        // must therefore still plan cleanly and land in `raw`; the actual
        // pack build is where its (now-failing) integrity check belongs.
        let (_d, s) = store();
        let file = put_chunked(&s, &big_buffer());
        let c1 = commit_with_file(&s, file, vec![], "v1");

        let full = crate::ops::reachable_objects(&s, &c1).unwrap();
        let blob_hash = *full
            .iter()
            .find(|h| s.object_type(h).unwrap() == ObjectType::Blob)
            .expect("chunked big_buffer must contain at least one blob chunk");
        corrupt_payload_byte(&s, &blob_hash);

        // Sanity: a full verified read of this object now fails.
        assert!(matches!(
            s.read(&blob_hash),
            Err(StoreError::HashMismatch { .. })
        ));

        let plan = plan_pack(&s, c1, None).unwrap();
        assert!(plan.raw.contains(&blob_hash));
        assert_eq!(plan.object_count(), full.len());
    }

    #[test]
    fn plan_pack_second_push_still_verifies_delta_candidate_bytes() {
        // A blob that IS a delta candidate (paired with a base the remote
        // holds) must still get a real, verified read — the short-circuit
        // only removes the *classification* read, not the read needed to
        // actually build a delta.
        let (_d, s) = store();
        let v1 = big_buffer();
        let file1 = put_chunked(&s, &v1);
        let c1 = commit_with_file(&s, file1, vec![], "v1");

        let mut v2 = v1.clone();
        for k in 0..16 {
            v2[900_000 + k] ^= 0xFF;
        }
        let file2 = put_chunked(&s, &v2);
        let c2 = commit_with_file(&s, file2, vec![c1], "v2");

        let bases = select_chunk_delta_bases(&s, c2, c1).unwrap();
        let target = *bases.keys().next().expect("expected a paired chunk");
        corrupt_payload_byte(&s, &target);

        let err = plan_pack(&s, c2, Some(c1)).unwrap_err();
        assert!(matches!(err, StoreError::HashMismatch { .. }));
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
            w.push_raw(*h, &bytes).unwrap();
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

    /// Deterministic, feature-rich chunk content (xorshift so 16-byte window
    /// hashes are well-distributed rather than colliding on flat data).
    fn chunk_content(seed: u8, len: usize) -> Vec<u8> {
        let mut state = u64::from(seed).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut v = vec![0u8; len];
        for byte in &mut v {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = (state & 0xff) as u8;
        }
        v
    }

    fn put_blob(s: &ObjectStore, content: Vec<u8>) -> Hash {
        put(s, &Object::Blob(Blob { data: content }))
    }

    /// Build a `ChunkedBlob` from explicit chunk contents (bypassing
    /// `FastCDC`) so a test can control chunk boundaries and shifts precisely.
    fn put_chunked_from(s: &ObjectStore, chunks: &[Vec<u8>]) -> Hash {
        let total: usize = chunks.iter().map(Vec::len).sum();
        let chunk_ids: Vec<Hash> = chunks.iter().map(|c| put_blob(s, c.clone())).collect();
        put(
            s,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: total as u64,
                chunk_size: 0,
                chunks: chunk_ids,
            }),
        )
    }

    #[test]
    #[allow(clippy::many_single_char_names)] // a..e keep the chunk-shift table compact
    fn content_aware_pairing_picks_similar_base_after_a_shift() {
        let (_d, s) = store();
        let (a, b, c, d, e) = (
            chunk_content(1, 400),
            chunk_content(2, 400),
            chunk_content(3, 400),
            chunk_content(4, 400),
            chunk_content(5, 400),
        );
        let mut e_mod = e.clone();
        e_mod[200] ^= 0xFF; // a one-byte edit to E

        // Old file = [A,B,C,D,E]; new file = [B,C,D,E'] — A deleted (so every
        // surviving chunk's index shifts down by one) and E modified. Counts
        // differ, so the content-similarity path runs.
        let old_file = put_chunked_from(&s, &[a, b.clone(), c.clone(), d.clone(), e.clone()]);
        let new_file = put_chunked_from(&s, &[b, c, d.clone(), e_mod.clone()]);
        let c_old = commit_with_file(&s, old_file, vec![], "old");
        let c_new = commit_with_file(&s, new_file, vec![c_old], "new");

        let bases = select_chunk_delta_bases(&s, c_new, c_old).unwrap();

        let e_mod_id = put_blob(&s, e_mod);
        let e_id = put_blob(&s, e);
        let d_id = put_blob(&s, d);

        // E' is the only changed chunk. It sits at new index 3; the old chunk
        // at index 3 is D, so position-clamp pairing would mispair E'→D.
        // Content similarity must instead pair E'→E (its real prior version).
        assert_eq!(
            bases.get(&e_mod_id),
            Some(&e_id),
            "E' must delta against E (content match), not the wrong-index D"
        );
        assert_ne!(bases.get(&e_mod_id), Some(&d_id));
    }

    #[test]
    #[allow(clippy::many_single_char_names)] // a..d + z keep the chunk table compact
    fn shifted_pairing_skips_a_chunk_with_no_content_overlap() {
        // After a shift (differing counts), a brand-new chunk dissimilar to
        // every old chunk must NOT be paired — no position/clamp fallback.
        let (_d, s) = store();
        let (a, b, c, d) = (
            chunk_content(1, 400),
            chunk_content(2, 400),
            chunk_content(3, 400),
            chunk_content(4, 400),
        );
        let z = chunk_content(99, 400); // unrelated to a/b/c/d
        // old = [A,B,C,D]; new = [B,C,Z] — counts differ (content path), and Z
        // is new + dissimilar to every old chunk.
        let old_file = put_chunked_from(&s, &[a, b.clone(), c.clone(), d]);
        let new_file = put_chunked_from(&s, &[b, c, z.clone()]);
        let c_old = commit_with_file(&s, old_file, vec![], "old");
        let c_new = commit_with_file(&s, new_file, vec![c_old], "new");

        let bases = select_chunk_delta_bases(&s, c_new, c_old).unwrap();
        let z_id = put_blob(&s, z);
        assert!(
            !bases.contains_key(&z_id),
            "a dissimilar new chunk must be left unpaired (sent raw), not clamped to a base"
        );
    }

    #[test]
    fn equal_count_edit_still_uses_fast_index_path() {
        // Same chunk count ⇒ no shift ⇒ same-index pairing (no content reads).
        let (_d, s) = store();
        let (a, b, c) = (
            chunk_content(10, 400),
            chunk_content(11, 400),
            chunk_content(12, 400),
        );
        let mut b_mod = b.clone();
        b_mod[50] ^= 0xFF;
        let old_file = put_chunked_from(&s, &[a.clone(), b.clone(), c.clone()]);
        let new_file = put_chunked_from(&s, &[a, b_mod.clone(), c]);
        let c_old = commit_with_file(&s, old_file, vec![], "old");
        let c_new = commit_with_file(&s, new_file, vec![c_old], "new");

        let bases = select_chunk_delta_bases(&s, c_new, c_old).unwrap();
        let b_mod_id = put_blob(&s, b_mod);
        let b_id = put_blob(&s, b);
        assert_eq!(
            bases.get(&b_mod_id),
            Some(&b_id),
            "in-place edit pairs by index"
        );
    }
}

#[cfg(test)]
mod wire_conformance {
    use super::*;

    /// Conformance pin: the exact on-wire bytes of a `PackListNode`. Locks
    /// the `commonware-codec` body encoding (`MKPL` + version guard, then a
    /// codec `Option<Hash>` and a length-prefixed `Vec<Hash>`) so a
    /// commonware version bump that silently changes the encoding is caught
    /// here rather than in the field. Regenerate deliberately only on an
    /// intentional format change (and bump `PACKLIST_VERSION`).
    #[test]
    fn packlist_wire_format_is_pinned() {
        let bytes = encode_packlist(Some([0x11u8; 32]), &[[0x22u8; 32], [0x33u8; 32]]).unwrap();
        let expected = "4d4b504c0101\
                        1111111111111111111111111111111111111111111111111111111111111111\
                        02\
                        2222222222222222222222222222222222222222222222222222222222222222\
                        3333333333333333333333333333333333333333333333333333333333333333";
        assert_eq!(
            hash::to_hex_bytes(&bytes),
            expected,
            "PackListNode wire format drifted (commonware-codec change?)"
        );
        let node = decode_packlist(&bytes).unwrap();
        assert_eq!(node.prev, Some([0x11u8; 32]));
        assert_eq!(node.packs, vec![[0x22u8; 32], [0x33u8; 32]]);
    }
}
