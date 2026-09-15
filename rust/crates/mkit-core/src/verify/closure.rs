//! Full-disclosure (closure profile) verification: prove that a served
//! object set is exactly the content a commit (or remix, or tag) id
//! commits to.
//!
//! The root id is the only trust anchor. The [`ClosureManifest`] is a
//! convenience index of pack hashes — a verifier that already has the
//! packs can call [`verify_closure_packs`] directly. Wire format and
//! verifier obligations are pinned in `docs/specs/SPEC-DISCLOSURE.md`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use bytes::Buf;
use commonware_codec::{EncodeSize, ReadExt, ReadRangeExt, Write};

use crate::hash::{Hash, hash};
use crate::object::Object;
use crate::ops::graph::{ClosureMode, children};
use crate::pack::{self, PackEntries, PackEntry, PackWriter, pack_key};
use crate::store::ObjectStore;
use crate::verify::VerifyError;

/// Hard cap on the number of packs a closure manifest may list.
pub const MAX_CLOSURE_PACKS: usize = 65_536;

const MANIFEST_MAGIC: &[u8; 4] = b"MKCL";
const MANIFEST_VERSION: u8 = 1;
const MODE_SNAPSHOT: u8 = 0;
const MODE_HISTORY: u8 = 1;

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
    /// Supplied bytes that failed to deserialize, keyed by BLAKE3 of
    /// those bytes, sorted by id. A bit-flipped object that still
    /// deserializes is content-addressed under a *different* id and
    /// surfaces as [`Self::missing`] (the referenced id) plus
    /// [`Self::unreferenced`] (the supplied one), not here.
    pub corrupt: Vec<(Hash, String)>,
    /// Supplied (and successfully identified) but not reachable from
    /// `root`, sorted. A DA provider may legitimately serve a superset;
    /// this field is reported, not an error.
    pub unreferenced: Vec<Hash>,
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

/// Re-hash every supplied object and walk from `root` with
/// [`children`]`(obj, mode)`. Store-less: the caller provides the
/// object bytes.
///
/// A deserialize failure is recorded as `corrupt` under the BLAKE3 of
/// those bytes. The root itself missing yields `missing = [root]`,
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
    let mut supplied: Vec<&'a [u8]> = Vec::new();
    for obj in objects {
        if supplied.len() >= pack::MAX_ENTRIES as usize {
            return Err(VerifyError::TooManyClosureObjects);
        }
        supplied.push(obj);
    }

    let mut by_id: BTreeMap<Hash, Object> = BTreeMap::new();
    let mut corrupt: Vec<(Hash, String)> = Vec::new();
    for bytes in &supplied {
        match crate::serialize::deserialize(bytes) {
            Err(e) => corrupt.push((hash(bytes), e.to_string())),
            Ok(obj) => {
                let id = crate::object::id_from_object(&obj, bytes);
                by_id.insert(id, obj);
            }
        }
    }
    corrupt.sort_by_key(|a| a.0);

    if let Some(obj) = by_id.get(root) {
        match obj {
            Object::Commit(_) | Object::Remix(_) | Object::Tag(_) => {}
            other => return Err(VerifyError::ClosureRootWrongType(other.object_type())),
        }
    }

    let mut visited: BTreeSet<Hash> = BTreeSet::new();
    let mut missing: Vec<Hash> = Vec::new();
    let mut queue: VecDeque<Hash> = VecDeque::new();
    queue.push_back(*root);
    let mut verified = 0usize;

    while let Some(h) = queue.pop_front() {
        if !visited.insert(h) {
            continue;
        }
        let Some(obj) = by_id.get(&h) else {
            missing.push(h);
            continue;
        };
        verified += 1;
        for child in children(obj, mode) {
            queue.push_back(child);
        }
    }
    missing.sort_unstable();
    missing.dedup();

    let unreferenced: Vec<Hash> = by_id
        .keys()
        .copied()
        .filter(|id| !visited.contains(id))
        .collect();

    Ok(ClosureReport {
        root: *root,
        mode,
        verified,
        missing,
        corrupt,
        unreferenced,
    })
}

/// Iterate each pack with [`PackEntries`]. Any delta or compressed
/// entry is a profile violation — the closure profile is raw-only so a
/// wasm verifier (no `pack-zstd`) can consume it. Raw payloads are
/// fed to [`verify_closure`].
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
    let mut objects: Vec<Vec<u8>> = Vec::new();
    for (pack_index, pack) in packs.iter().enumerate() {
        let entries = PackEntries::new(pack)?;
        if !entries.is_raw_only() {
            return Err(VerifyError::ClosureProfileViolation {
                pack_index,
                entry_index: entries.first_non_raw_index().unwrap_or(0) as usize,
            });
        }
        for (entry_index, entry) in entries.enumerate() {
            match entry? {
                PackEntry::Raw { bytes } => objects.push(bytes.into_owned()),
                PackEntry::Delta { .. } => {
                    return Err(VerifyError::ClosureProfileViolation {
                        pack_index,
                        entry_index,
                    });
                }
            }
        }
    }
    verify_closure(root, mode, objects.iter().map(Vec::as_slice))
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

    #[test]
    fn export_verify_round_trip_snapshot_and_history() {
        let (_d, store, _c1, c2) = two_commit_fixture();
        for mode in [ClosureMode::Snapshot, ClosureMode::History] {
            let export = export_closure(&store, &c2, mode).unwrap();
            let packs: Vec<&[u8]> = export.packs.iter().map(Vec::as_slice).collect();
            let report = verify_closure_manifest(&c2, &export.manifest, &packs).unwrap();
            assert!(report.is_complete(), "{mode:?}: {report:?}");
            assert!(report.unreferenced.is_empty());
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
    }

    #[test]
    fn missing_root_is_reported() {
        let root = [0xAB; 32];
        let report = verify_closure(&root, ClosureMode::Snapshot, std::iter::empty()).unwrap();
        assert_eq!(report.missing, vec![root]);
        assert_eq!(report.verified, 0);
        assert!(!report.is_complete());
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
}
