//! Full-disclosure (closure profile) verification: prove that a served
//! object set is exactly the content a commit (or remix, or tag) id
//! commits to.
//!
//! The root id is the only trust anchor. The [`ClosureManifest`] is a
//! convenience index of pack hashes — a verifier that already has the
//! packs can call [`verify_closure_packs`] directly. Wire format and
//! verifier obligations are pinned in `docs/specs/SPEC-DISCLOSURE.md`.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::Range;

use bytes::Buf;
use commonware_codec::{EncodeSize, ReadExt, ReadRangeExt, Write};

use crate::hash::{Hash, hash};
use crate::object::{Object, ObjectType};
use crate::ops::graph::{ClosureMode, children};
use crate::pack::{self, PackEntries, PackEntry, PackWriter, pack_key};
use crate::store::{ObjectStore, StoreError};
use crate::verify::VerifyError;

/// Hard cap on the number of packs a closure manifest may list.
pub const MAX_CLOSURE_PACKS: usize = 65_536;

const MANIFEST_MAGIC: &[u8; 4] = b"MKCL";
const MANIFEST_VERSION: u8 = 1;
const MODE_SNAPSHOT: u8 = 0;
const MODE_HISTORY: u8 = 1;

/// Fan-out threshold (per available thread) for [`index_supplied_objects`]/
/// [`index_pack_entries`]. Deliberately much higher than
/// `pack::stage_raw_entries`'s `ENTRIES_PER_THREAD` (8): that fan-out's
/// per-entry work is a zstd decompression (tens of microseconds), so a
/// `std::thread::scope` spawn pays for itself almost immediately. Here
/// each entry is a small canonical-object deserialize plus one
/// BLAKE3/BMT id derivation — often under a microsecond — so thread
/// creation itself dominates below a few thousand entries. Measured via
/// `closure_verify_fanout` (`rust/benches/benches/`) on a 4-core box:
/// 64-1024 entries lost 2-4x to spawn overhead at `ENTRIES_PER_THREAD =
/// 8`; only past ~4096 entries did fan-out clearly win (~10%). This
/// value keeps every closure below that size on the plain sequential
/// path and only pays thread cost for genuinely large closures.
#[cfg(not(target_arch = "wasm32"))]
const CLOSURE_ENTRIES_PER_THREAD: usize = 1024;

/// Provides a pull-based source for canonical object bytes.
pub trait ObjectSource {
    /// Returns canonical bytes for `id`, or `Ok(None)` when it is absent.
    /// Implementations MUST NOT use their own identity decision as the
    /// verification result; the closure walker always deserializes the bytes
    /// and re-derives the object id itself.
    ///
    /// # Errors
    ///
    /// Returns a source error when the requested object cannot be fetched.
    fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, VerifyError>;
}

/// Outcome of walking a supplied object set from `root` in `mode`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureReport {
    /// The id the walk started from.
    pub root: Hash,
    /// Walk mode used.
    pub mode: ClosureMode,
    /// Objects whose id was recomputed and that were reachable from `root`.
    pub verified: usize,
    /// Referenced by a reachable object but not supplied, sorted.
    pub missing: Vec<Hash>,
    /// Bytes that failed to deserialize or whose derived id did not match
    /// the requested id, sorted by reported id. The map path keys decode
    /// failures by BLAKE3 of the supplied bytes and preserves the
    /// `missing` + `unreferenced` result for parsable bit flips; a streaming
    /// fetch-by-id path reports either failure under the requested id.
    pub corrupt: Vec<(Hash, String)>,
    /// Supplied (and successfully identified) but not reachable from
    /// `root`, sorted. A DA provider may legitimately serve a superset;
    /// this field is reported, not an error.
    pub unreferenced: Vec<Hash>,
    /// Whether the verifier could enumerate every supplied object to compute
    /// [`Self::unreferenced`]. Streaming sources set this to `false` and
    /// leave that list empty; map- and pack-backed paths set it to `true`.
    pub unreferenced_checked: bool,
}

impl ClosureReport {
    /// Complete iff nothing referenced is missing or corrupt.
    /// Unreferenced extras do not fail completeness.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.missing.is_empty() && self.corrupt.is_empty()
    }
}

/// Encoded closure plus the raw-only packs it indexes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureExport {
    /// [`ClosureManifest`] bytes.
    pub manifest: Vec<u8>,
    /// Raw-only v1 packs, in the order listed by the manifest.
    pub packs: Vec<Vec<u8>>,
}

/// Convenience index of a closure export: magic `"MKCL"`, version 1,
/// root id, mode, and the [`pack_key`] of each pack in order.
///
/// The caller supplies the trusted root to [`verify_closure_manifest`];
/// the manifest does not authenticate the objects and is not itself a
/// trust anchor. It only tells a verifier which pack hashes to expect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureManifest {
    /// Commit, remix, or tag id the closure is claimed to cover.
    pub root: Hash,
    /// Snapshot or history.
    pub mode: ClosureMode,
    /// `pack_key` of each pack, in export order. At most
    /// [`MAX_CLOSURE_PACKS`] entries.
    pub packs: Vec<Hash>,
}

impl ClosureManifest {
    /// Encode to `"MKCL" ‖ version ‖ root ‖ mode ‖ packs`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + 32 + 1 + self.packs.encode_size());
        out.extend_from_slice(MANIFEST_MAGIC);
        out.push(MANIFEST_VERSION);
        self.root.write(&mut out);
        mode_byte(self.mode).write(&mut out);
        self.packs.write(&mut out);
        out
    }

    /// Decode, rejecting unknown version/mode and trailing bytes.
    ///
    /// # Errors
    ///
    /// [`VerifyError::ClosureManifestBadMagic`],
    /// [`VerifyError::ClosureManifestUnsupportedVersion`], or
    /// [`VerifyError::ClosureManifestMalformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, VerifyError> {
        if bytes.len() < 5 || bytes[..4] != *MANIFEST_MAGIC {
            return Err(VerifyError::ClosureManifestBadMagic);
        }
        let version = bytes[4];
        if version != MANIFEST_VERSION {
            return Err(VerifyError::ClosureManifestUnsupportedVersion(version));
        }
        let mut r: &[u8] = &bytes[5..];
        let root = Hash::read(&mut r).map_err(|_| VerifyError::ClosureManifestMalformed)?;
        let mode_b = u8::read(&mut r).map_err(|_| VerifyError::ClosureManifestMalformed)?;
        let mode = match mode_b {
            MODE_SNAPSHOT => ClosureMode::Snapshot,
            MODE_HISTORY => ClosureMode::History,
            _ => return Err(VerifyError::ClosureManifestMalformed),
        };
        let packs = Vec::<Hash>::read_range(&mut r, ..=MAX_CLOSURE_PACKS)
            .map_err(|_| VerifyError::ClosureManifestMalformed)?;
        if r.has_remaining() {
            return Err(VerifyError::ClosureManifestMalformed);
        }
        Ok(Self { root, mode, packs })
    }
}

fn mode_byte(mode: ClosureMode) -> u8 {
    match mode {
        ClosureMode::Snapshot => MODE_SNAPSHOT,
        ClosureMode::History => MODE_HISTORY,
    }
}

struct MapObjectSource<'a> {
    objects: BTreeMap<Hash, &'a [u8]>,
}

impl ObjectSource for MapObjectSource<'_> {
    fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, VerifyError> {
        Ok(self.objects.get(id).map(|bytes| Cow::Borrowed(*bytes)))
    }
}

struct PackObjectSource<'a> {
    packs: Vec<&'a [u8]>,
    index: BTreeMap<Hash, (usize, Range<usize>)>,
    corrupt: Vec<(Hash, String)>,
}

impl ObjectSource for PackObjectSource<'_> {
    fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, VerifyError> {
        let Some((pack_index, range)) = self.index.get(id) else {
            return Ok(None);
        };
        Ok(Some(Cow::Borrowed(&self.packs[*pack_index][range.clone()])))
    }
}

impl ObjectSource for &ObjectStore {
    fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, VerifyError> {
        // `read_raw_for_verification` is deliberately used instead of
        // `ObjectStore::read`: the latter discards mismatching bytes, while
        // this walker must see them so it can report `corrupt` under the
        // requested id. The walker is the only identity authority here.
        match (*self).read_raw_for_verification(id) {
            Ok(bytes) => Ok(Some(Cow::Owned(bytes))),
            Err(StoreError::ObjectNotFound(_)) => Ok(None),
            Err(error) => Err(VerifyError::Store(error)),
        }
    }
}

/// What the shared walker does when a root turns out not to be a
/// commit, remix or tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootRule {
    /// Abort with [`VerifyError::ClosureRootWrongType`] (closure callers).
    Fail,
    /// Record it in [`Walk::bad_roots`] and keep walking (push verification).
    Record,
}

/// Outcome of the shared [`walk`].
#[derive(Debug, Default)]
pub(crate) struct Walk {
    /// Fetched objects whose id was re-derived and matched.
    pub(crate) verified: usize,
    /// Frontier stops: ids for which `known` held; never fetched.
    pub(crate) skipped_known: usize,
    /// Referenced (or a root) but absent from the source, sorted.
    pub(crate) missing: Vec<Hash>,
    /// Undecodable or mis-identified bytes, sorted by requested id.
    pub(crate) corrupt: Vec<(Hash, String)>,
    /// Roots that are not a commit/remix/tag ([`RootRule::Record`]), sorted.
    pub(crate) bad_roots: Vec<(Hash, ObjectType)>,
    /// Every id the walk reached, including frontier stops.
    pub(crate) visited: BTreeSet<Hash>,
}

/// The one closure BFS. Every closure and push verifier in this crate
/// walks through here, taking its edges from [`children`]`(obj, mode)`.
///
/// Starting from every id in `roots`, each id is visited at most once:
/// - `known(id)` true: a frontier stop, counted and neither fetched nor
///   descended;
/// - otherwise fetched once from `source`, deserialized and re-hashed
///   ([`crate::object::id_from_object`]); absent → `missing`, bad bytes
///   or a different derived id → `corrupt` (not descended);
/// - a root must be a commit/remix/tag (`root_rule`);
/// - `visit` sees each verified object, then its children are queued and
///   its bytes dropped.
///
/// `known` is the caller's frontier contract: it may hold only for ids
/// whose whole closure in `mode` was already verified *in the same
/// repository*. See [`crate::verify::verify_push`].
///
/// # Errors
///
/// [`VerifyError::TooManyClosureObjects`] past [`pack::MAX_ENTRIES`]
/// visited ids, [`VerifyError::ClosureRootWrongType`] under
/// [`RootRule::Fail`], a source error, or the first error `visit` returns.
pub(crate) fn walk(
    roots: &[Hash],
    mode: ClosureMode,
    source: &mut impl ObjectSource,
    mut known: impl FnMut(&Hash) -> bool,
    root_rule: RootRule,
    mut visit: impl FnMut(&Hash, &Object) -> Result<(), VerifyError>,
) -> Result<Walk, VerifyError> {
    let root_set: BTreeSet<Hash> = roots.iter().copied().collect();
    let mut out = Walk::default();
    let mut queue: VecDeque<Hash> = roots.iter().copied().collect();

    while let Some(id) = queue.pop_front() {
        if !out.visited.insert(id) {
            continue;
        }
        if out.visited.len() > pack::MAX_ENTRIES as usize {
            return Err(VerifyError::TooManyClosureObjects);
        }
        if known(&id) {
            out.skipped_known += 1;
            continue;
        }

        let Some(bytes) = source.fetch(&id)? else {
            out.missing.push(id);
            continue;
        };
        let object = match crate::serialize::deserialize(bytes.as_ref()) {
            Ok(object) => object,
            Err(error) => {
                out.corrupt.push((id, error.to_string()));
                continue;
            }
        };
        let derived = crate::object::id_from_object(&object, bytes.as_ref());
        if derived != id {
            out.corrupt.push((
                id,
                format!(
                    "object bytes hash to {}, expected {}",
                    crate::hash::to_hex(&derived),
                    crate::hash::to_hex(&id)
                ),
            ));
            continue;
        }
        if root_set.contains(&id) {
            match &object {
                Object::Commit(_) | Object::Remix(_) | Object::Tag(_) => {}
                other => match root_rule {
                    RootRule::Fail => {
                        return Err(VerifyError::ClosureRootWrongType(other.object_type()));
                    }
                    RootRule::Record => out.bad_roots.push((id, other.object_type())),
                },
            }
        }
        visit(&id, &object)?;

        let child_ids = children(&object, mode);
        out.verified += 1;
        drop(object);
        drop(bytes);
        queue.extend(child_ids);
    }

    out.missing.sort_unstable();
    out.missing.dedup();
    out.corrupt.sort_by_key(|(id, _)| *id);
    out.bad_roots.sort_by_key(|(id, _)| *id);
    Ok(out)
}

/// Single-root closure walk: [`walk`] with no frontier, no visitor and a
/// hard root-type rule.
fn walk_closure(
    root: &Hash,
    mode: ClosureMode,
    source: &mut impl ObjectSource,
) -> Result<(ClosureReport, BTreeSet<Hash>), VerifyError> {
    let walked = walk(
        std::slice::from_ref(root),
        mode,
        source,
        |_| false,
        RootRule::Fail,
        |_, _| Ok(()),
    )?;
    Ok((
        ClosureReport {
            root: *root,
            mode,
            verified: walked.verified,
            missing: walked.missing,
            corrupt: walked.corrupt,
            unreferenced: Vec::new(),
            unreferenced_checked: false,
        },
        walked.visited,
    ))
}

fn merge_corrupt(report: &mut ClosureReport, extra: Vec<(Hash, String)>) {
    // Walker corrupt is empty on these paths: the index is keyed by
    // derived id, so fetch never returns bytes that fail the id check.
    report.corrupt.extend(extra);
    report.corrupt.sort_by_key(|(id, _)| *id);
    report.corrupt.dedup_by_key(|(id, _)| *id);
}

/// Result of indexing [`verify_closure`]'s supplied object set:
/// derived-id → bytes, plus anything that failed to classify.
type SuppliedIndex<'a> = (BTreeMap<Hash, &'a [u8]>, Vec<(Hash, String)>);

/// Result of indexing [`verify_closure_packs`]'s recorded entries:
/// derived-id → `(pack_index, payload_range)`, plus anything that
/// failed to classify.
type PackIndex = (BTreeMap<Hash, (usize, Range<usize>)>, Vec<(Hash, String)>);

/// Deserialize `bytes` as a canonical object and derive its id, or
/// classify it as corrupt under the BLAKE3 of the raw bytes. Pure and
/// independent per call — the per-item step shared by every branch
/// below, and by [`walk_closure`]'s own (deliberately separate)
/// re-derivation.
fn classify_object(bytes: &[u8]) -> Result<Hash, (Hash, String)> {
    match crate::serialize::deserialize(bytes) {
        Err(e) => Err((hash(bytes), e.to_string())),
        Ok(obj) => Ok(crate::object::id_from_object(&obj, bytes)),
    }
}

/// Indexes `verify_closure`'s supplied object set by derived id: a
/// pure map over independent byte slices, same shape as
/// `pack::stage_raw_entries`'s raw-entry fan-out. Runs a plain
/// sequential loop below a small-set threshold, and fans out across a
/// scoped thread pool at or above it (native builds only — wasm32 has
/// no threads).
fn index_supplied_objects<'a>(items: &[&'a [u8]]) -> SuppliedIndex<'a> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        if threads > 1 && items.len() >= CLOSURE_ENTRIES_PER_THREAD.saturating_mul(threads) {
            return index_supplied_objects_parallel(items, threads);
        }
    }
    index_supplied_objects_sequential(items)
}

fn index_supplied_objects_sequential<'a>(items: &[&'a [u8]]) -> SuppliedIndex<'a> {
    let mut by_id = BTreeMap::new();
    let mut corrupt = Vec::new();
    for bytes in items {
        match classify_object(bytes) {
            Ok(id) => {
                by_id.insert(id, *bytes);
            }
            Err(e) => corrupt.push(e),
        }
    }
    (by_id, corrupt)
}

/// Parallel branch of [`index_supplied_objects`]: split `items` into
/// `threads` contiguous chunks and process each chunk on its own
/// scoped thread. `std::thread::scope` (not a persistent pool) is
/// deliberate — `mkit-core` stays dependency-neutral and wasm-clean
/// (see `pack::stage_raw_entries_parallel`'s doc for the same
/// reasoning) — and this call is already gated by
/// [`index_supplied_objects`]'s threshold so the per-call spawn cost is
/// only paid when there is enough work to amortize it.
#[cfg(not(target_arch = "wasm32"))]
fn index_supplied_objects_parallel<'a>(items: &[&'a [u8]], threads: usize) -> SuppliedIndex<'a> {
    let chunk_size = items.len().div_ceil(threads).max(1);
    let mut by_id = BTreeMap::new();
    let mut corrupt = Vec::new();
    std::thread::scope(|scope| {
        let handles: Vec<_> = items
            .chunks(chunk_size)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|bytes| classify_object(bytes).map(|id| (id, *bytes)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for handle in handles {
            for result in handle
                .join()
                .expect("closure object indexing worker thread panicked")
            {
                match result {
                    Ok((id, bytes)) => {
                        by_id.insert(id, bytes);
                    }
                    Err(e) => corrupt.push(e),
                }
            }
        }
    });
    (by_id, corrupt)
}

/// Indexes `verify_closure_packs`'s recorded `(pack_index,
/// payload_range)` entries by derived id — the pack-backed
/// counterpart of [`index_supplied_objects`], same threshold and
/// `std::thread::scope` shape.
fn index_pack_entries(packs: &[&[u8]], refs: &[(usize, Range<usize>)]) -> PackIndex {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        if threads > 1 && refs.len() >= CLOSURE_ENTRIES_PER_THREAD.saturating_mul(threads) {
            return index_pack_entries_parallel(packs, refs, threads);
        }
    }
    index_pack_entries_sequential(packs, refs)
}

fn index_pack_entries_sequential(packs: &[&[u8]], refs: &[(usize, Range<usize>)]) -> PackIndex {
    let mut index = BTreeMap::new();
    let mut corrupt = Vec::new();
    for (pack_index, range) in refs {
        let bytes = &packs[*pack_index][range.clone()];
        match classify_object(bytes) {
            Ok(id) => {
                index.insert(id, (*pack_index, range.clone()));
            }
            Err(e) => corrupt.push(e),
        }
    }
    (index, corrupt)
}

#[cfg(not(target_arch = "wasm32"))]
fn index_pack_entries_parallel(
    packs: &[&[u8]],
    refs: &[(usize, Range<usize>)],
    threads: usize,
) -> PackIndex {
    let chunk_size = refs.len().div_ceil(threads).max(1);
    let mut index = BTreeMap::new();
    let mut corrupt = Vec::new();
    std::thread::scope(|scope| {
        let handles: Vec<_> = refs
            .chunks(chunk_size)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|(pack_index, range)| {
                            let bytes = &packs[*pack_index][range.clone()];
                            classify_object(bytes).map(|id| (id, *pack_index, range.clone()))
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for handle in handles {
            for result in handle
                .join()
                .expect("closure pack indexing worker thread panicked")
            {
                match result {
                    Ok((id, pack_index, range)) => {
                        index.insert(id, (pack_index, range));
                    }
                    Err(e) => corrupt.push(e),
                }
            }
        }
    });
    (index, corrupt)
}

/// Walks a closure by fetching each requested id only when the BFS reaches it.
/// Bytes are deserialized, re-hashed, and discarded after their child ids are
/// extracted, so the walk retains object ids rather than the complete object
/// set. A fetch-by-id source that returns bytes whose derived id differs from
/// the requested id reports `corrupt` under the requested id; this is
/// intentionally different from the map path's legacy
/// `missing` + `unreferenced` classification for a parsable bit flip.
///
/// The root itself missing yields `missing = [root]`, `verified = 0`. The
/// root, when present and correctly identified, MUST deserialize as a
/// `Commit`, `Remix`, or `Tag`. Since a streaming source cannot enumerate
/// objects it never fetched, the returned report has an empty `unreferenced`
/// list and `unreferenced_checked = false`.
///
/// # Errors
///
/// [`VerifyError::TooManyClosureObjects`] if the walk visits more than
/// [`pack::MAX_ENTRIES`] ids; [`VerifyError::ClosureRootWrongType`] if the
/// root is present but not a commit/remix/tag; or a source error.
pub fn verify_closure_streaming(
    root: &Hash,
    mode: ClosureMode,
    source: &mut impl ObjectSource,
) -> Result<ClosureReport, VerifyError> {
    walk_closure(root, mode, source).map(|(report, _visited)| report)
}

/// Verifies a closure by reading the local [`ObjectStore`] on demand.
///
/// The source reads only ids reached by the BFS. It uses the store's raw
/// capped read so a file whose bytes no longer match its filename remains
/// available to the walker; the walker then re-derives the id and reports a
/// hash mismatch as `corrupt` under the requested id. This is the deliberate
/// store-backed counterpart to the map path, whose parsable bit-flip behavior
/// remains `missing` plus `unreferenced`.
///
/// # Errors
///
/// Returns [`VerifyError::TooManyClosureObjects`] if the walk visits more than
/// [`pack::MAX_ENTRIES`] ids, [`VerifyError::ClosureRootWrongType`] if the root
/// is not a commit/remix/tag, or [`VerifyError::Store`] for a store failure.
pub fn verify_closure_store(
    store: &ObjectStore,
    root: &Hash,
    mode: ClosureMode,
) -> Result<ClosureReport, VerifyError> {
    let mut source = store;
    verify_closure_streaming(root, mode, &mut source)
}

/// Re-hashes every supplied object and walks from `root` with
/// [`children`]`(obj, mode)`. Store-less: the caller provides the
/// object bytes. This compatibility path is implemented by the same
/// pull-based walker as [`verify_closure_streaming`], with an in-memory
/// source keyed by each successfully derived id, followed by the legacy
/// supplied-set `unreferenced` pass.
///
/// A deserialize failure is recorded as `corrupt` under the BLAKE3 of
/// those bytes. A parsable bit flip remains `missing` (the requested id)
/// plus `unreferenced` (the derived id), preserving the map path's existing
/// semantics. The root itself missing yields `missing = [root]`,
/// `verified = 0`. The root, when present, MUST deserialize as a
/// `Commit`, `Remix`, or `Tag`.
///
/// # Errors
///
/// [`VerifyError::TooManyClosureObjects`] if more than
/// [`pack::MAX_ENTRIES`] objects are supplied;
/// [`VerifyError::ClosureRootWrongType`] if the root is present but
/// not a commit/remix/tag.
pub fn verify_closure<'a>(
    root: &Hash,
    mode: ClosureMode,
    objects: impl IntoIterator<Item = &'a [u8]>,
) -> Result<ClosureReport, VerifyError> {
    // Bail as soon as the cap is exceeded rather than draining `objects`
    // first: it's a caller-supplied `IntoIterator`, so for an adversarial
    // or merely huge lazy source this keeps the old per-item fail-fast
    // bound instead of paying to produce every item before rejecting.
    let mut items: Vec<&'a [u8]> = Vec::new();
    for (supplied, bytes) in objects.into_iter().enumerate() {
        if supplied >= pack::MAX_ENTRIES as usize {
            return Err(VerifyError::TooManyClosureObjects);
        }
        items.push(bytes);
    }
    let (by_id, mut corrupt) = index_supplied_objects(&items);
    corrupt.sort_by_key(|a| a.0);

    let mut source = MapObjectSource { objects: by_id };
    let (mut report, visited) = walk_closure(root, mode, &mut source)?;
    merge_corrupt(&mut report, corrupt);
    report.unreferenced = source
        .objects
        .keys()
        .copied()
        .filter(|id| !visited.contains(id))
        .collect();
    report.unreferenced_checked = true;
    Ok(report)
}

/// Iterates each pack with [`PackEntries`]. Any delta or compressed
/// entry is a profile violation — the closure profile is raw-only so a
/// wasm verifier (no `pack-zstd`) can consume it. Raw payloads are indexed
/// by their derived ids and served as borrowed slices into the original
/// pack buffers.
///
/// # Errors
///
/// [`VerifyError::ClosureProfileViolation`] on a non-`0x00` entry;
/// [`VerifyError::Pack`] on framing errors; plus
/// [`verify_closure`]'s errors.
pub fn verify_closure_packs(
    root: &Hash,
    mode: ClosureMode,
    packs: &[&[u8]],
) -> Result<ClosureReport, VerifyError> {
    // Phase 1 (sequential, cheap): walk each pack's frames to validate
    // the raw-only profile and record every entry's `(pack_index,
    // payload_range)` in encounter order. This never decompresses —
    // `is_raw_only` (computed by `PackEntries::new`'s header scan) is
    // required before the loop even starts, so every entry this loop
    // reaches is already known to be an uncompressed `0x00` frame; the
    // `PackEntry::Delta` arm below is unreachable in practice and kept
    // only as defense in depth.
    let mut refs: Vec<(usize, Range<usize>)> = Vec::new();
    let mut supplied = 0usize;
    for (pack_index, pack) in packs.iter().enumerate() {
        let entries = PackEntries::new(pack)?;
        if !entries.is_raw_only() {
            return Err(VerifyError::ClosureProfileViolation {
                pack_index,
                entry_index: entries.first_non_raw_index().unwrap_or(0) as usize,
            });
        }
        let mut entries = entries;
        let mut entry_index = 0usize;
        while let Some(entry) = entries.next() {
            if supplied >= pack::MAX_ENTRIES as usize {
                return Err(VerifyError::TooManyClosureObjects);
            }
            supplied += 1;
            let payload_range = entries
                .last_payload_range()
                .ok_or(VerifyError::Pack(pack::PackError::UnexpectedEof))?;
            match entry? {
                PackEntry::Raw { .. } => refs.push((pack_index, payload_range)),
                PackEntry::Delta { .. } => {
                    return Err(VerifyError::ClosureProfileViolation {
                        pack_index,
                        entry_index,
                    });
                }
            }
            entry_index += 1;
        }
    }

    // Phase 2 (fanned out above a size threshold): deserialize + derive
    // the id of every recorded entry — the actual CPU-bound work
    // (canonical decode + a BLAKE3/BMT id derivation per object),
    // independent per entry since each only reads its own payload
    // range.
    let (index, mut corrupt) = index_pack_entries(packs, &refs);
    corrupt.sort_by_key(|a| a.0);
    let mut source = PackObjectSource {
        packs: packs.to_vec(),
        index,
        corrupt,
    };
    let (mut report, visited) = walk_closure(root, mode, &mut source)?;
    merge_corrupt(&mut report, source.corrupt);
    report.unreferenced = source
        .index
        .keys()
        .copied()
        .filter(|id| !visited.contains(id))
        .collect();
    report.unreferenced_checked = true;
    Ok(report)
}

/// Decode the manifest, reject it if its `root` is not `expected_root`,
/// check pack count and `pack_key` equality in order, then
/// [`verify_closure_packs`]. `mode` comes from the manifest (it only
/// widens or narrows the walk; the report carries it). The caller
/// supplies the trusted root; the manifest is a locator, never a
/// trust anchor.
///
/// # Errors
///
/// Manifest decode errors, [`VerifyError::ClosureRootMismatch`],
/// [`VerifyError::ClosurePackCountMismatch`],
/// [`VerifyError::ClosurePackKeyMismatch`], plus
/// [`verify_closure_packs`]'s errors.
pub fn verify_closure_manifest(
    expected_root: &Hash,
    manifest: &[u8],
    packs: &[&[u8]],
) -> Result<ClosureReport, VerifyError> {
    let decoded = ClosureManifest::decode(manifest)?;
    if decoded.root != *expected_root {
        return Err(VerifyError::ClosureRootMismatch {
            expected: *expected_root,
            got: decoded.root,
        });
    }
    if decoded.packs.len() != packs.len() {
        return Err(VerifyError::ClosurePackCountMismatch {
            expected: decoded.packs.len(),
            got: packs.len(),
        });
    }
    for (index, (want, got)) in decoded.packs.iter().zip(packs.iter()).enumerate() {
        if pack_key(got) != *want {
            return Err(VerifyError::ClosurePackKeyMismatch { index });
        }
    }
    verify_closure_packs(&decoded.root, decoded.mode, packs)
}

/// Walk `store` in `mode`, write raw-only packs of the reachable
/// objects in sorted id order, and return the encoded manifest plus
/// packs. Native-only (`ObjectStore`).
///
/// Packs split when the next object would exceed
/// [`pack::MAX_TOTAL_PAYLOAD`] or [`pack::MAX_ENTRIES`].
///
/// # Errors
///
/// Store errors, [`crate::pack::PackError`] from the raw-only writer, or
/// [`VerifyError::ClosureRootWrongType`] if `root` is not a
/// commit/remix/tag.
pub fn export_closure(
    store: &ObjectStore,
    root: &Hash,
    mode: ClosureMode,
) -> Result<ClosureExport, VerifyError> {
    export_closure_with_limits(
        store,
        root,
        mode,
        pack::MAX_TOTAL_PAYLOAD,
        pack::MAX_ENTRIES,
    )
}

pub(crate) fn export_closure_with_limits(
    store: &ObjectStore,
    root: &Hash,
    mode: ClosureMode,
    max_pack_payload: u64,
    max_entries: u32,
) -> Result<ClosureExport, VerifyError> {
    let obj = store.read_object(root)?;
    match &obj {
        Object::Commit(_) | Object::Remix(_) | Object::Tag(_) => {}
        other => return Err(VerifyError::ClosureRootWrongType(other.object_type())),
    }

    let hashes = match mode {
        ClosureMode::Snapshot => crate::ops::graph::reachable_snapshot(store, root)?,
        ClosureMode::History => crate::ops::graph::reachable_objects(store, root)?,
    };

    let mut packs: Vec<Vec<u8>> = Vec::new();
    let mut writer = PackWriter::new_raw_only();
    for h in &hashes {
        let bytes = store.read(h)?;
        let next_payload = writer.total_payload().saturating_add(bytes.len() as u64);
        if writer.entry_count() > 0
            && (next_payload > max_pack_payload || writer.entry_count() >= max_entries as usize)
        {
            packs.push(writer.finish()?);
            writer = PackWriter::new_raw_only();
        }
        writer.push_raw(*h, &bytes)?;
    }
    if writer.entry_count() > 0 {
        packs.push(writer.finish()?);
    }
    if packs.len() > MAX_CLOSURE_PACKS {
        return Err(VerifyError::TooManyClosureObjects);
    }

    let manifest = ClosureManifest {
        root: *root,
        mode,
        packs: packs.iter().map(|p| pack_key(p)).collect(),
    };
    Ok(ClosureExport {
        manifest: manifest.encode(),
        packs,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::fs;

    use crate::hash::ZERO;
    use crate::layout::RepoLayout;
    use crate::object::{Blob, Commit, EntryMode, Identity, Object, ObjectType, Tree, TreeEntry};
    use crate::sign::{KeyPair, sign_commit};
    use crate::worktree::store_file_object;
    use tempfile::TempDir;

    fn fixture() -> (TempDir, ObjectStore, Hash, Hash) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        let blob = store_file_object(&store, b"hello closure").unwrap();
        let tree = Tree {
            entries: vec![TreeEntry {
                name: b"f.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        };
        let tree_hash = store
            .write(&crate::serialize::serialize(&Object::Tree(tree)).unwrap())
            .unwrap();
        let kp = KeyPair::from_seed([0x11; 32]);
        let mut commit = Commit {
            tree_hash,
            parents: vec![],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"closure unit".to_vec(),
            timestamp: 1,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0u8; 64],
        };
        commit.signature = sign_commit(&commit, &kp).unwrap().0;
        let commit_id = store
            .write(&crate::serialize::serialize(&Object::Commit(commit)).unwrap())
            .unwrap();
        (dir, store, commit_id, blob)
    }

    fn two_commit_fixture() -> (TempDir, ObjectStore, Hash, Hash) {
        let (dir, store, c1, _) = fixture();
        let blob2 = store_file_object(&store, b"second commit only").unwrap();
        let tree2 = Tree {
            entries: vec![TreeEntry {
                name: b"g.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob2,
            }],
        };
        let tree2_hash = store
            .write(&crate::serialize::serialize(&Object::Tree(tree2)).unwrap())
            .unwrap();
        let kp = KeyPair::from_seed([0x11; 32]);
        let mut commit = Commit {
            tree_hash: tree2_hash,
            parents: vec![c1],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"child".to_vec(),
            timestamp: 2,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0u8; 64],
        };
        commit.signature = sign_commit(&commit, &kp).unwrap().0;
        let c2 = store
            .write(&crate::serialize::serialize(&Object::Commit(commit)).unwrap())
            .unwrap();
        (dir, store, c1, c2)
    }

    struct CountingSource {
        objects: BTreeMap<Hash, Vec<u8>>,
        missing: BTreeSet<Hash>,
        fetches: BTreeMap<Hash, usize>,
    }

    impl CountingSource {
        fn from_store(store: &ObjectStore) -> Self {
            let mut objects = BTreeMap::new();
            for id in store.iter_object_hashes().unwrap() {
                objects.insert(id, store.read(&id).unwrap());
            }
            Self {
                objects,
                missing: BTreeSet::new(),
                fetches: BTreeMap::new(),
            }
        }

        fn fetched_ids(&self) -> BTreeSet<Hash> {
            self.fetches.keys().copied().collect()
        }
    }

    impl ObjectSource for CountingSource {
        fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, VerifyError> {
            *self.fetches.entry(*id).or_default() += 1;
            if self.missing.contains(id) {
                return Ok(None);
            }
            let bytes = self
                .objects
                .get(id)
                .unwrap_or_else(|| panic!("unexpected object fetch: {}", crate::hash::to_hex(id)));
            Ok(Some(Cow::Borrowed(bytes)))
        }
    }

    #[test]
    fn export_verify_round_trip_snapshot_and_history() {
        let (_d, store, _c1, c2) = two_commit_fixture();
        for mode in [ClosureMode::Snapshot, ClosureMode::History] {
            let export = export_closure(&store, &c2, mode).unwrap();
            let packs: Vec<&[u8]> = export.packs.iter().map(Vec::as_slice).collect();
            let report = verify_closure_manifest(&c2, &export.manifest, &packs).unwrap();
            assert!(report.is_complete(), "{mode:?}: {report:?}");
            assert!(report.unreferenced.is_empty());
            assert!(report.unreferenced_checked);
            assert_eq!(report.root, c2);
            assert_eq!(report.mode, mode);
            assert!(report.verified >= 3);
        }
    }

    #[test]
    fn history_on_snapshot_reports_parent_missing() {
        let (_d, store, c1, c2) = two_commit_fixture();
        let export = export_closure(&store, &c2, ClosureMode::Snapshot).unwrap();
        let packs: Vec<&[u8]> = export.packs.iter().map(Vec::as_slice).collect();
        let report = verify_closure_packs(&c2, ClosureMode::History, &packs).unwrap();
        assert!(
            report.missing.contains(&c1),
            "parent must be missing: {report:?}"
        );
        assert!(!report.is_complete());
        assert!(report.unreferenced_checked);
    }

    #[test]
    fn snapshot_on_history_reports_parent_unreferenced() {
        let (_d, store, c1, c2) = two_commit_fixture();
        let export = export_closure(&store, &c2, ClosureMode::History).unwrap();
        let packs: Vec<&[u8]> = export.packs.iter().map(Vec::as_slice).collect();
        let report = verify_closure_packs(&c2, ClosureMode::Snapshot, &packs).unwrap();
        assert!(
            report.unreferenced.contains(&c1),
            "parent commit is history-only: {report:?}"
        );
        assert!(report.is_complete());
        assert!(report.unreferenced_checked);
    }

    #[test]
    fn streaming_fetches_each_reachable_object_once_and_only() {
        let (_d, store, c1, c2) = two_commit_fixture();
        let snapshot_expected = crate::ops::graph::reachable_snapshot(&store, &c2).unwrap();
        let mut snapshot_source = CountingSource::from_store(&store);
        let snapshot =
            verify_closure_streaming(&c2, ClosureMode::Snapshot, &mut snapshot_source).unwrap();
        assert!(snapshot.is_complete(), "{snapshot:?}");
        assert_eq!(snapshot_source.fetched_ids(), snapshot_expected);
        assert!(snapshot_source.fetches.values().all(|count| *count == 1));

        let mut history_source = CountingSource::from_store(&store);
        let history =
            verify_closure_streaming(&c2, ClosureMode::History, &mut history_source).unwrap();
        let history_expected = crate::ops::graph::reachable_objects(&store, &c2).unwrap();
        assert!(history.is_complete(), "{history:?}");
        assert_eq!(history_source.fetched_ids(), history_expected);
        assert!(history_source.fetches.values().all(|count| *count == 1));

        let parent_closure = crate::ops::graph::reachable_snapshot(&store, &c1).unwrap();
        let history_only: BTreeSet<Hash> = history_expected
            .difference(&snapshot_expected)
            .copied()
            .collect();
        assert_eq!(history_only, parent_closure);
    }

    #[test]
    fn streaming_reports_missing_and_corrupt_under_requested_id() {
        let (_d, store, root, blob) = fixture();

        let mut missing_source = CountingSource::from_store(&store);
        missing_source.missing.insert(blob);
        let missing =
            verify_closure_streaming(&root, ClosureMode::Snapshot, &mut missing_source).unwrap();
        assert!(missing.missing.contains(&blob), "{missing:?}");
        assert!(missing.corrupt.is_empty(), "{missing:?}");
        assert!(!missing.unreferenced_checked);

        let mut corrupt_source = CountingSource::from_store(&store);
        let bytes = corrupt_source.objects.get_mut(&blob).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let corrupt =
            verify_closure_streaming(&root, ClosureMode::Snapshot, &mut corrupt_source).unwrap();
        assert!(
            corrupt.corrupt.iter().any(|(id, _)| *id == blob),
            "{corrupt:?}"
        );
        assert!(!corrupt.missing.contains(&blob), "{corrupt:?}");

        let mut malformed_source = CountingSource::from_store(&store);
        malformed_source
            .objects
            .insert(blob, b"not an object".to_vec());
        let malformed =
            verify_closure_streaming(&root, ClosureMode::Snapshot, &mut malformed_source).unwrap();
        assert!(
            malformed.corrupt.iter().any(|(id, _)| *id == blob),
            "{malformed:?}"
        );
        assert!(!malformed.missing.contains(&blob), "{malformed:?}");
    }

    struct MismatchSource {
        objects: BTreeMap<Hash, Vec<u8>>,
        mismatch_id: Hash,
        mismatch_bytes: Vec<u8>,
    }

    impl ObjectSource for MismatchSource {
        fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, VerifyError> {
            if *id == self.mismatch_id {
                return Ok(Some(Cow::Borrowed(self.mismatch_bytes.as_slice())));
            }
            Ok(self.objects.get(id).map(|b| Cow::Borrowed(b.as_slice())))
        }
    }

    #[test]
    fn merge_keeps_walker_corrupt_when_source_bytes_hash_elsewhere() {
        let (_d, store, root, blob) = fixture();
        let blob_bytes = store.read(&blob).unwrap();
        let derived = crate::object::id_from_object(
            &crate::serialize::deserialize(&blob_bytes).unwrap(),
            &blob_bytes,
        );
        assert_eq!(derived, blob);

        let mut objects = BTreeMap::new();
        for id in store.iter_object_hashes().unwrap() {
            if id != blob {
                objects.insert(id, store.read(&id).unwrap());
            }
        }
        let mut source = MismatchSource {
            objects,
            mismatch_id: blob,
            mismatch_bytes: crate::serialize::serialize(&Object::Blob(Blob {
                data: b"different blob".to_vec(),
            }))
            .unwrap(),
        };
        let other_id = crate::object::id_from_object(
            &crate::serialize::deserialize(&source.mismatch_bytes).unwrap(),
            &source.mismatch_bytes,
        );
        assert_ne!(other_id, blob);

        let (mut report, _) = walk_closure(&root, ClosureMode::Snapshot, &mut source).unwrap();
        assert!(
            report.corrupt.iter().any(|(id, _)| *id == blob),
            "walker must classify the mismatch under the requested id: {report:?}"
        );

        let extra_id = hash(b"not an object");
        merge_corrupt(
            &mut report,
            vec![(extra_id, "deserialize failed".to_string())],
        );
        assert!(
            report.corrupt.iter().any(|(id, _)| *id == blob),
            "walker entry must survive the merge: {report:?}"
        );
        assert!(
            report.corrupt.iter().any(|(id, _)| *id == extra_id),
            "index-time entry must survive the merge: {report:?}"
        );
    }

    #[test]
    fn map_path_keeps_parsable_bit_flip_as_missing_and_unreferenced() {
        let (_d, store, root, blob) = fixture();
        let mut objects = Vec::new();
        let mut flipped_bytes = None;
        for id in store.iter_object_hashes().unwrap() {
            let mut bytes = store.read(&id).unwrap();
            if id == blob {
                let last = bytes.len() - 1;
                bytes[last] ^= 0x01;
                flipped_bytes = Some(bytes.clone());
            }
            objects.push(bytes);
        }
        let flipped = flipped_bytes.expect("flipped blob");
        let flipped_object = crate::serialize::deserialize(&flipped).unwrap();
        let flipped_id = crate::object::id_from_object(&flipped_object, &flipped);
        assert_ne!(flipped_id, blob);

        let report = verify_closure(
            &root,
            ClosureMode::Snapshot,
            objects.iter().map(Vec::as_slice),
        )
        .unwrap();
        assert!(report.missing.contains(&blob), "{report:?}");
        assert!(report.unreferenced.contains(&flipped_id), "{report:?}");
        assert!(report.corrupt.is_empty(), "{report:?}");
        assert!(report.unreferenced_checked);
    }

    #[test]
    fn store_streaming_reports_missing_and_corrupt_files() {
        let (_d, store, root, blob) = fixture();
        fs::remove_file(store.path_for(&blob)).unwrap();
        let missing = verify_closure_store(&store, &root, ClosureMode::Snapshot).unwrap();
        assert!(missing.missing.contains(&blob), "{missing:?}");
        assert!(!missing.unreferenced_checked);

        let (_d, store, root, blob) = fixture();
        let path = store.path_for(&blob);
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        fs::write(path, bytes).unwrap();
        let corrupt = verify_closure_store(&store, &root, ClosureMode::Snapshot).unwrap();
        assert!(
            corrupt.corrupt.iter().any(|(id, _)| *id == blob),
            "{corrupt:?}"
        );
        assert!(!corrupt.missing.contains(&blob), "{corrupt:?}");
        assert!(!corrupt.unreferenced_checked);
    }

    #[test]
    fn missing_root_is_reported() {
        let root = [0xAB; 32];
        let report = verify_closure(&root, ClosureMode::Snapshot, std::iter::empty()).unwrap();
        assert_eq!(report.missing, vec![root]);
        assert_eq!(report.verified, 0);
        assert!(!report.is_complete());
        assert!(report.unreferenced_checked);
    }

    #[test]
    fn corrupt_bytes_are_reported() {
        let (_d, store, commit_id, _) = fixture();
        let export = export_closure(&store, &commit_id, ClosureMode::Snapshot).unwrap();
        let mut objects: Vec<Vec<u8>> = Vec::new();
        for pack in &export.packs {
            for entry in PackEntries::new(pack).unwrap() {
                let PackEntry::Raw { bytes } = entry.unwrap() else {
                    panic!("raw-only");
                };
                objects.push(bytes.into_owned());
            }
        }
        objects.push(b"not an object".to_vec());
        let report = verify_closure(
            &commit_id,
            ClosureMode::Snapshot,
            objects.iter().map(Vec::as_slice),
        )
        .unwrap();
        assert!(!report.corrupt.is_empty());
        assert!(!report.is_complete());
    }

    #[test]
    fn unreferenced_extra_is_still_complete() {
        let (_d, store, commit_id, _) = fixture();
        let extra = crate::serialize::serialize(&Object::Blob(Blob {
            data: b"unrelated".to_vec(),
        }))
        .unwrap();
        let export = export_closure(&store, &commit_id, ClosureMode::Snapshot).unwrap();
        let mut objects: Vec<Vec<u8>> = Vec::new();
        for pack in &export.packs {
            for entry in PackEntries::new(pack).unwrap() {
                let PackEntry::Raw { bytes } = entry.unwrap() else {
                    panic!("raw-only");
                };
                objects.push(bytes.into_owned());
            }
        }
        objects.push(extra);
        let report = verify_closure(
            &commit_id,
            ClosureMode::Snapshot,
            objects.iter().map(Vec::as_slice),
        )
        .unwrap();
        assert!(report.is_complete());
        assert_eq!(report.unreferenced.len(), 1);
        assert!(report.unreferenced_checked);
    }

    #[test]
    fn wrong_root_type_is_typed_error() {
        let blob = crate::serialize::serialize(&Object::Blob(Blob {
            data: b"not a commit".to_vec(),
        }))
        .unwrap();
        let id =
            crate::object::id_from_object(&crate::serialize::deserialize(&blob).unwrap(), &blob);
        let err = verify_closure(&id, ClosureMode::Snapshot, std::iter::once(blob.as_slice()))
            .unwrap_err();
        assert!(matches!(
            err,
            VerifyError::ClosureRootWrongType(ObjectType::Blob)
        ));
    }

    #[test]
    fn delta_pack_is_profile_violation() {
        let base = crate::serialize::serialize(&Object::Blob(Blob {
            data: b"delta-base-xxxx".to_vec(),
        }))
        .unwrap();
        let target = crate::serialize::serialize(&Object::Blob(Blob {
            data: b"delta-target-yy".to_vec(),
        }))
        .unwrap();
        let base_hash = hash(&base);
        let stream = crate::delta::encode(&base, &target).unwrap();
        let mut w = PackWriter::new();
        w.push_raw(base_hash, &base).unwrap();
        w.push_delta(&base_hash, &stream).unwrap();
        let pack = w.finish().unwrap();
        let err = verify_closure_packs(&[0u8; 32], ClosureMode::Snapshot, &[pack.as_slice()])
            .unwrap_err();
        assert!(matches!(
            err,
            VerifyError::ClosureProfileViolation {
                pack_index: 0,
                entry_index: 1
            }
        ));
    }

    #[test]
    fn manifest_rejects_unknown_version_trailing_and_mode() {
        let m = ClosureManifest {
            root: [0u8; 32],
            mode: ClosureMode::Snapshot,
            packs: vec![],
        };
        let mut bytes = m.encode();
        bytes.push(0xFF);
        assert!(matches!(
            ClosureManifest::decode(&bytes),
            Err(VerifyError::ClosureManifestMalformed)
        ));
        let mut v2 = m.encode();
        v2[4] = 2;
        assert!(matches!(
            ClosureManifest::decode(&v2),
            Err(VerifyError::ClosureManifestUnsupportedVersion(2))
        ));
        assert!(matches!(
            ClosureManifest::decode(b"XXXX\x01"),
            Err(VerifyError::ClosureManifestBadMagic)
        ));
        let mut bad_mode = m.encode();
        // magic(4)+version(1)+root(32)+mode
        bad_mode[5 + 32] = 9;
        assert!(matches!(
            ClosureManifest::decode(&bad_mode),
            Err(VerifyError::ClosureManifestMalformed)
        ));
    }

    #[test]
    fn manifest_pack_key_mismatch() {
        let (_d, store, commit_id, _) = fixture();
        let export = export_closure(&store, &commit_id, ClosureMode::Snapshot).unwrap();
        let mut decoded = ClosureManifest::decode(&export.manifest).unwrap();
        decoded.packs[0] = [0xFF; 32];
        let bad = decoded.encode();
        let packs: Vec<&[u8]> = export.packs.iter().map(Vec::as_slice).collect();
        let err = verify_closure_manifest(&commit_id, &bad, &packs).unwrap_err();
        assert!(matches!(
            err,
            VerifyError::ClosurePackKeyMismatch { index: 0 }
        ));
    }

    #[test]
    fn manifest_root_mismatch() {
        let (_d, store, commit_id, _) = fixture();
        let export = export_closure(&store, &commit_id, ClosureMode::Snapshot).unwrap();
        let packs: Vec<&[u8]> = export.packs.iter().map(Vec::as_slice).collect();
        let other = [0x11u8; 32];
        let err = verify_closure_manifest(&other, &export.manifest, &packs).unwrap_err();
        assert!(matches!(
            err,
            VerifyError::ClosureRootMismatch { expected, got }
                if expected == other && got == commit_id
        ));
    }

    #[test]
    fn raw_only_pack_round_trips_through_pack_reader() {
        let (_d, store, commit_id, _) = fixture();
        let export = export_closure(&store, &commit_id, ClosureMode::Snapshot).unwrap();
        assert!(!export.packs.is_empty());
        for pack in &export.packs {
            assert_eq!(&pack[..4], b"MKIT");
            assert_eq!(
                u32::from_le_bytes(pack[4..8].try_into().unwrap()),
                pack::VERSION
            );
            let entries = PackEntries::new(pack).unwrap();
            assert!(entries.is_raw_only());
            let (_dir, dest) = {
                let d = TempDir::new().unwrap();
                let s = ObjectStore::init(&RepoLayout::single(d.path())).unwrap();
                (d, s)
            };
            crate::pack::PackReader::read(pack, &dest).unwrap();
        }
    }

    /// A closure with enough objects to be a meaningfully different
    /// shape from every other (tiny) fixture in this module. With
    /// `CLOSURE_ENTRIES_PER_THREAD` tuned for real fan-out wins (see
    /// its doc — only past ~4096 entries per thread), this fixture
    /// stays below the live dispatch threshold on any real machine, so
    /// these tests instead call `index_supplied_objects_sequential`/
    /// `_parallel` directly to exercise and cross-check the parallel
    /// branch's correctness regardless of threshold.
    const LARGE_FIXTURE_N: usize = 200;

    fn large_fixture() -> (TempDir, ObjectStore, Hash, usize) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        let mut entries = Vec::with_capacity(LARGE_FIXTURE_N);
        for i in 0..LARGE_FIXTURE_N {
            let blob =
                store_file_object(&store, format!("large closure blob #{i}").as_bytes()).unwrap();
            entries.push(TreeEntry {
                name: format!("f{i:04}.txt").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: blob,
            });
        }
        let tree_hash = store
            .write(&crate::serialize::serialize(&Object::Tree(Tree { entries })).unwrap())
            .unwrap();
        let kp = KeyPair::from_seed([0x22; 32]);
        let mut commit = Commit {
            tree_hash,
            parents: vec![],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"large closure fan-out fixture".to_vec(),
            timestamp: 1,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0u8; 64],
        };
        commit.signature = sign_commit(&commit, &kp).unwrap().0;
        let commit_id = store
            .write(&crate::serialize::serialize(&Object::Commit(commit)).unwrap())
            .unwrap();
        let total = store.iter_object_hashes().unwrap().len();
        (dir, store, commit_id, total)
    }

    #[test]
    fn large_object_set_parallel_path_matches_sequential_map() {
        let (_d, store, commit_id, total) = large_fixture();
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);

        let objects: Vec<Vec<u8>> = store
            .iter_object_hashes()
            .unwrap()
            .into_iter()
            .map(|id| store.read(&id).unwrap())
            .collect();

        let report = verify_closure(
            &commit_id,
            ClosureMode::Snapshot,
            objects.iter().map(Vec::as_slice),
        )
        .unwrap();
        assert!(report.is_complete(), "{report:?}");
        assert_eq!(report.verified, total);
        assert!(report.unreferenced.is_empty());

        let refs: Vec<&[u8]> = objects.iter().map(Vec::as_slice).collect();
        let (seq_by_id, mut seq_corrupt) = index_supplied_objects_sequential(&refs);
        let (par_by_id, mut par_corrupt) = index_supplied_objects_parallel(&refs, threads.max(2));
        seq_corrupt.sort_by_key(|a| a.0);
        par_corrupt.sort_by_key(|a| a.0);
        assert_eq!(seq_by_id, par_by_id);
        assert_eq!(seq_corrupt, par_corrupt);
        assert!(seq_corrupt.is_empty());
    }

    #[test]
    fn large_object_set_parallel_path_matches_sequential_packs() {
        let (_d, store, commit_id, total) = large_fixture();
        let export = export_closure(&store, &commit_id, ClosureMode::Snapshot).unwrap();
        let packs: Vec<&[u8]> = export.packs.iter().map(Vec::as_slice).collect();

        let report = verify_closure_packs(&commit_id, ClosureMode::Snapshot, &packs).unwrap();
        assert!(report.is_complete(), "{report:?}");
        assert_eq!(report.verified, total);
        assert!(report.unreferenced.is_empty());
        assert!(report.unreferenced_checked);
    }

    #[test]
    fn large_object_set_parallel_path_classifies_corrupt_entry_correctly() {
        // A bit-flipped (but still parsable) object doesn't exercise
        // `classify_object`'s error arm at all — it just derives a
        // different id — so it wouldn't touch `index_supplied_objects_*`'s
        // `corrupt` bookkeeping. Replace one entry with bytes that fail to
        // deserialize entirely instead, and call the parallel indexer
        // directly (`large_fixture`'s object count stays under the live
        // dispatch threshold — see its doc) so this actually runs the
        // parallel branch's per-chunk corrupt handling, whichever
        // thread-chunk the corrupt entry lands in.
        let (_d, store, _commit_id, total) = large_fixture();
        let mut objects: Vec<Vec<u8>> = store
            .iter_object_hashes()
            .unwrap()
            .into_iter()
            .map(|id| store.read(&id).unwrap())
            .collect();
        let corrupt_index = total / 2;
        objects[corrupt_index] = b"not an object".to_vec();
        let expected_corrupt_id = hash(&objects[corrupt_index]);

        let refs: Vec<&[u8]> = objects.iter().map(Vec::as_slice).collect();
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        let (seq_by_id, mut seq_corrupt) = index_supplied_objects_sequential(&refs);
        let (par_by_id, mut par_corrupt) = index_supplied_objects_parallel(&refs, threads.max(2));
        seq_corrupt.sort_by_key(|a| a.0);
        par_corrupt.sort_by_key(|a| a.0);

        assert_eq!(par_by_id, seq_by_id);
        assert_eq!(par_corrupt, seq_corrupt);
        assert_eq!(seq_corrupt.len(), 1, "{seq_corrupt:?}");
        assert_eq!(seq_corrupt[0].0, expected_corrupt_id);
        assert_eq!(
            seq_by_id.len(),
            total - 1,
            "the corrupt entry must not be indexed"
        );
    }
}
