//! Legacy pre-merkle repository export/translation (issue #713).
//!
//! [`crate::store::ObjectStore::open`] hard-rejects any repository whose
//! `.mkit/format` marker isn't `bmt-v1` (`store.rs` `IncompatibleRepoFormat`,
//! SPEC-MERKLE-OBJECTS §7) — a deliberate, permanent "no migration" policy
//! for repositories written before merkle object addressing
//! (`docs/adr/0001-merkelize-chunkedblob-and-tree.md`). This module is the
//! escape hatch that ADR calls for, not a reversal of it: it walks a
//! pre-merkle repository using the historical **flat-BLAKE3** addressing
//! rule (before merkle addressing, every object type — including `Tree`
//! and `ChunkedBlob` — was `id = BLAKE3(bytes)`; see SPEC-MERKLE-OBJECTS
//! §7) and re-emits every object reachable from its refs into a fresh
//! current-format (`bmt-v1`) store, recomputing ids under the current
//! type-dependent rule ([`crate::object::Object::id`]) bottom-up so a
//! parent object's serialized bytes reference its children's NEW ids.
//!
//! ## Re-signing
//!
//! Translating a `Tree`/`ChunkedBlob` changes its id. That changes the
//! serialized bytes of any `Commit`/`Remix`/`Tag` that references it
//! (directly or transitively), which invalidates that object's original
//! Ed25519 signature — the signing bytes cover `tree_hash` and parent
//! hashes (SPEC-SIGNING §3/§4/§4a). There is no way to reproduce the
//! original author's signature over the new bytes without their private
//! key, so every translated `Commit`/`Remix`/`Tag` is **re-signed** with
//! the caller-supplied export keypair: `signer` becomes that keypair's
//! public key, while `author`/`tagger` (an informational identity, not
//! cryptographically bound to `signer` — see [`crate::sign::verify_commit`])
//! is preserved unchanged, so original provenance metadata is not lost
//! even though the cryptographic signer changes. Callers are expected to
//! record this translation out-of-band (the CLI mints an attestation; see
//! `mkit export-legacy`).
//!
//! ## What this does NOT do
//!
//! This does not reopen the `ObjectStore::open` gate — a pre-merkle
//! repository remains permanently unreadable by the normal store path.
//! It reads the SOURCE repository directly off disk, bypassing
//! `ObjectStore::open` entirely (that verifies under the CURRENT
//! addressing rule, which would misclassify a perfectly valid legacy
//! `Tree`/`ChunkedBlob` as corrupt), and never writes to it — every write
//! lands in the caller-supplied destination store.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::hash::{self, Hash};
use crate::layout::RepoLayout;
use crate::object::{ChunkedBlob, Commit, MkitError, Object, Remix, Tag, Tree, TreeEntry};
use crate::refs::{self, Head};
use crate::serialize;
use crate::sign::{self, KeyPair};
use crate::store::{FORMAT_VALUE, MAX_TREE_DEPTH, ObjectStore, StoreError};

/// Depth cap mirroring [`crate::store::MAX_TREE_DEPTH`] — translation
/// recurses one stack frame per object-graph edge (tree entry, chunk,
/// commit parent), so this bounds a crafted or corrupt legacy repo from
/// overflowing the stack. Distinct constant (same value) so a future
/// change to one cap does not silently change the other's contract.
const MAX_TRANSLATE_DEPTH: usize = MAX_TREE_DEPTH;

/// Outcome of inspecting a source repository's `.mkit/format` marker
/// (SPEC-OBJECTS §10 / SPEC-MERKLE-OBJECTS §7), without opening the
/// store (which would reject a legacy repo before this can classify it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyFormatStatus {
    /// No `.mkit/format` marker at all. The marker was introduced
    /// alongside merkle addressing (SPEC-OBJECTS §10), so a missing
    /// marker means the repository predates it and used the original
    /// all-flat-hash scheme (SPEC-MERKLE-OBJECTS §7). Safe to translate.
    Legacy,
    /// `.mkit/format` already declares the current format — nothing to
    /// export; the repository opens normally via `ObjectStore::open`.
    AlreadyCurrent,
    /// `.mkit/format` declares some OTHER value. This exporter only
    /// understands the pre-marker all-flat-hash scheme, so an
    /// unrecognised declared format is refused rather than guessed at.
    Unknown(String),
}

/// Inspect `src_layout`'s `.mkit/format` marker.
///
/// # Errors
/// [`StoreError::NotAMkitRepository`] if `src_layout` has no `objects/`
/// directory; [`StoreError::Io`] if the format file exists but cannot be
/// read.
pub fn classify(src_layout: &RepoLayout) -> Result<LegacyFormatStatus, StoreError> {
    if !src_layout.objects_dir().is_dir() {
        return Err(StoreError::NotAMkitRepository);
    }
    match fs::read_to_string(src_layout.format_file()) {
        Ok(s) if s.trim() == FORMAT_VALUE => Ok(LegacyFormatStatus::AlreadyCurrent),
        Ok(s) => Ok(LegacyFormatStatus::Unknown(s.trim().to_owned())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(LegacyFormatStatus::Legacy),
        Err(e) => Err(StoreError::Io(e)),
    }
}

/// Errors from a legacy-repository export/translation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LegacyExportError {
    #[error(
        "{0} declares the current object-addressing format ({FORMAT_VALUE}); \
         nothing to export — open it directly"
    )]
    AlreadyCurrentFormat(String),
    #[error(
        "{0} declares object-addressing format {1:?}, which this exporter does not \
         recognize; refusing to guess how to read it (only unmarked pre-merkle \
         repositories are supported)"
    )]
    UnknownFormat(String, String),
    #[error("legacy object {0} not found under {1}")]
    ObjectNotFound(String, String),
    #[error("legacy object {0} is corrupt: on-disk bytes hash to {1}, expected {0}")]
    HashMismatch(String, String),
    #[error("decode legacy object {0}: {1}")]
    Decode(String, MkitError),
    #[error("object graph exceeds {0} levels of nesting")]
    TooDeep(usize),
    #[error("encode/sign translated object: {0}")]
    Encode(#[from] MkitError),
    #[error("refs: {0}")]
    Refs(#[from] refs::RefError),
    #[error("destination store: {0}")]
    Store(#[from] StoreError),
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

/// Destination `HEAD` outcome, mirroring the source's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadOutcome {
    /// Source `HEAD` was symbolic; destination `HEAD` points at the same
    /// branch name (already translated as part of the branch walk).
    Branch(String),
    /// Source `HEAD` was detached at `old`; destination `HEAD` is
    /// detached at the translated `new`.
    Detached { old: Hash, new: Hash },
}

/// Report of one legacy-repository translation run.
#[derive(Debug, Clone, Default)]
pub struct ExportReport {
    /// `(ref name, old commit id, new commit id)` for every `refs/heads/*`
    /// branch translated.
    pub branches: Vec<(String, Hash, Hash)>,
    /// `(tag name, old target id, new target id)` for every `refs/tags/*`
    /// tag translated.
    pub tags: Vec<(String, Hash, Hash)>,
    /// The destination `HEAD`, mirroring the source's — `None` if the
    /// source had no readable `HEAD` at all.
    pub head: Option<HeadOutcome>,
    /// Count of distinct legacy objects translated (the size of the
    /// old-id -> new-id memo table).
    pub objects_translated: usize,
}

/// Translate every ref reachable from `src_layout` (a legacy pre-merkle
/// repository — see [`classify`]) into `dst`/`dst_layout` (an already
/// `ObjectStore::init`-ed, fresh current-format repository), re-signing
/// every `Commit`/`Remix`/`Tag` whose bytes changed with `kp` (see the
/// module docs).
///
/// Read-only with respect to `src_layout`: every write lands in
/// `dst`/`dst_layout`.
///
/// # Errors
/// See [`LegacyExportError`]. Fails closed: a single corrupt/missing
/// legacy object aborts the whole run. `dst` is left however far the
/// run got — callers own the destination repo and are expected to
/// discard it on error (it is meant to be created fresh for this call).
pub fn export_legacy_repo(
    src_layout: &RepoLayout,
    dst: &ObjectStore,
    dst_layout: &RepoLayout,
    kp: &KeyPair,
) -> Result<ExportReport, LegacyExportError> {
    let root_display = || src_layout.worktree_root().display().to_string();
    match classify(src_layout)? {
        LegacyFormatStatus::Legacy => {}
        LegacyFormatStatus::AlreadyCurrent => {
            return Err(LegacyExportError::AlreadyCurrentFormat(root_display()));
        }
        LegacyFormatStatus::Unknown(found) => {
            return Err(LegacyExportError::UnknownFormat(root_display(), found));
        }
    }

    refs::init(dst_layout)?;

    let src_objects = src_layout.objects_dir();
    let mut tr = Translator {
        src_objects: &src_objects,
        dst,
        kp,
        memo: HashMap::new(),
    };

    let mut report = ExportReport::default();

    for r in refs::list_refs(src_layout)? {
        let Some(old) = r.hash else { continue };
        let new = tr.translate(old, 0)?;
        refs::write_ref(dst_layout, &r.name, &new)?;
        report.branches.push((r.name, old, new));
    }
    for r in refs::list_tags(src_layout)? {
        let Some(old) = r.hash else { continue };
        let new = tr.translate(old, 0)?;
        refs::write_tag(dst_layout, &r.name, &new)?;
        report.tags.push((r.name, old, new));
    }
    match refs::read_head(src_layout) {
        Ok(Head::Branch(name)) => {
            refs::write_head_branch(dst_layout, &name)?;
            report.head = Some(HeadOutcome::Branch(name));
        }
        Ok(Head::Detached(old)) => {
            let new = tr.translate(old, 0)?;
            refs::write_head_detached(dst_layout, &new)?;
            report.head = Some(HeadOutcome::Detached { old, new });
        }
        Err(refs::RefError::NoHead) => {}
        Err(e) => return Err(e.into()),
    }

    report.objects_translated = tr.memo.len();
    Ok(report)
}

/// One in-flight translation session: legacy source objects dir +
/// destination store + re-signing key + the old-id -> new-id memo table
/// (shared across every ref so common history is translated once).
struct Translator<'a> {
    src_objects: &'a Path,
    dst: &'a ObjectStore,
    kp: &'a KeyPair,
    memo: HashMap<Hash, Hash>,
}

impl Translator<'_> {
    /// Read `h`'s raw bytes from the legacy source and verify them under
    /// the HISTORICAL flat-BLAKE3 rule (`id = BLAKE3(bytes)` for every
    /// type — SPEC-MERKLE-OBJECTS §7). Deliberately does not go through
    /// `ObjectStore::read`, which verifies under the CURRENT
    /// merkle-aware rule and would misclassify a valid legacy
    /// `Tree`/`ChunkedBlob` as corrupt.
    fn legacy_read(&self, h: &Hash) -> Result<Vec<u8>, LegacyExportError> {
        let hex = hash::to_hex(h);
        let path: PathBuf = self.src_objects.join(&hex[..2]).join(&hex[2..]);
        let bytes = fs::read(&path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                LegacyExportError::ObjectNotFound(
                    hex.clone(),
                    self.src_objects.display().to_string(),
                )
            } else {
                LegacyExportError::Io(e)
            }
        })?;
        let actual = hash::hash(&bytes);
        if actual != *h {
            return Err(LegacyExportError::HashMismatch(hex, hash::to_hex(&actual)));
        }
        Ok(bytes)
    }

    /// Translate `old` (and, recursively, everything it references) into
    /// the destination store, returning its NEW id. Memoized so shared
    /// history (a common ancestor of two branches, a chunk shared by two
    /// files, ...) is only read/re-hashed/written once.
    fn translate(&mut self, old: Hash, depth: usize) -> Result<Hash, LegacyExportError> {
        if let Some(new) = self.memo.get(&old) {
            return Ok(*new);
        }
        if depth > MAX_TRANSLATE_DEPTH {
            return Err(LegacyExportError::TooDeep(MAX_TRANSLATE_DEPTH));
        }
        let bytes = self.legacy_read(&old)?;
        let obj = serialize::deserialize(&bytes)
            .map_err(|e| LegacyExportError::Decode(hash::to_hex(&old), e))?;

        let new = match obj {
            // Byte-hashed in both eras (never merkelized) — bytes and id
            // are unchanged, so write straight through. `Delta` is
            // pack-only and should never appear loose, but if a legacy
            // repo somehow has one on disk, it is likewise unaffected by
            // the merkle-addressing change.
            Object::Blob(_) | Object::Delta(_) => self.dst.write(&bytes)?,

            Object::ChunkedBlob(cb) => {
                let mut chunks = Vec::with_capacity(cb.chunks.len());
                for c in &cb.chunks {
                    chunks.push(self.translate(*c, depth + 1)?);
                }
                let translated = ChunkedBlob {
                    total_size: cb.total_size,
                    chunk_size: cb.chunk_size,
                    chunks,
                };
                let out = serialize::serialize(&Object::ChunkedBlob(translated))?;
                self.dst.write(&out)?
            }

            Object::Tree(t) => {
                let mut entries = Vec::with_capacity(t.entries.len());
                for e in &t.entries {
                    let new_hash = self.translate(e.object_hash, depth + 1)?;
                    entries.push(TreeEntry {
                        name: e.name.clone(),
                        mode: e.mode,
                        object_hash: new_hash,
                    });
                }
                let out = serialize::serialize(&Object::Tree(Tree { entries }))?;
                self.dst.write(&out)?
            }

            Object::Commit(c) => {
                let tree_hash = self.translate(c.tree_hash, depth + 1)?;
                let mut parents = Vec::with_capacity(c.parents.len());
                for p in &c.parents {
                    parents.push(self.translate(*p, depth + 1)?);
                }
                let mut translated = Commit {
                    tree_hash,
                    parents,
                    author: c.author.clone(),
                    signer: self.kp.public.0,
                    message: c.message.clone(),
                    timestamp: c.timestamp,
                    message_hash: c.message_hash,
                    content_digest: c.content_digest,
                    signature: [0u8; 64],
                };
                let sig = sign::sign_commit(&translated, self.kp)?;
                translated.signature = sig.0;
                let out = serialize::serialize(&Object::Commit(translated))?;
                self.dst.write(&out)?
            }

            Object::Remix(r) => {
                let tree_hash = self.translate(r.tree_hash, depth + 1)?;
                let mut parents = Vec::with_capacity(r.parents.len());
                for p in &r.parents {
                    parents.push(self.translate(*p, depth + 1)?);
                }
                let mut translated = Remix {
                    tree_hash,
                    parents,
                    // `sources` are foreign-repo pointers (SPEC-OBJECTS
                    // §6), never resolvable in our own store — left
                    // untouched, same policy as the reachable-object
                    // walk (`ops::graph::reachable_objects`).
                    sources: r.sources.clone(),
                    author: r.author.clone(),
                    signer: self.kp.public.0,
                    message: r.message.clone(),
                    timestamp: r.timestamp,
                    signature: [0u8; 64],
                };
                let sig = sign::sign_remix(&translated, self.kp)?;
                translated.signature = sig.0;
                let out = serialize::serialize(&Object::Remix(translated))?;
                self.dst.write(&out)?
            }

            Object::Tag(t) => {
                let target = self.translate(t.target, depth + 1)?;
                let mut translated = Tag {
                    target,
                    target_type: t.target_type,
                    name: t.name.clone(),
                    tagger: t.tagger.clone(),
                    signer: self.kp.public.0,
                    message: t.message.clone(),
                    timestamp: t.timestamp,
                    signature: [0u8; 64],
                };
                let sig = sign::sign_tag(&translated, self.kp)?;
                translated.signature = sig.0;
                let out = serialize::serialize(&Object::Tag(translated))?;
                self.dst.write(&out)?
            }
        };
        self.memo.insert(old, new);
        Ok(new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{EntryMode, Identity};
    use crate::sign::KeyPair;
    use tempfile::TempDir;

    /// Build a tiny legacy (pre-merkle) repository on disk: writes raw
    /// object files addressed by FLAT BLAKE3 (the historical rule for
    /// every type, including `Tree`) with NO `.mkit/format` marker, plus
    /// a `main` branch ref and symbolic `HEAD`. Uses the CURRENT
    /// `serialize`/encode functions — the byte LAYOUT never changed
    /// (SPEC-MERKLE-OBJECTS §7 / SPEC-OBJECTS §12), only the bytes->id
    /// function, so this reproduces genuine pre-#414 bytes without
    /// needing to build historical mkit binaries.
    fn build_legacy_repo(root: &Path, author_kp: &KeyPair) -> (Hash, Hash, Hash, Hash) {
        let objects = root.join(".mkit").join("objects");
        let flat_write = |bytes: &[u8]| -> Hash {
            let h = hash::hash(bytes);
            let hex = hash::to_hex(&h);
            let dir = objects.join(&hex[..2]);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(&hex[2..]), bytes).unwrap();
            h
        };

        // blob
        let blob_bytes = serialize::serialize(&Object::Blob(crate::object::Blob {
            data: b"hello legacy world".to_vec(),
        }))
        .unwrap();
        let blob_id = flat_write(&blob_bytes);

        // nested tree (subdir/) containing the blob
        let inner_tree_bytes = serialize::serialize(&Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"file.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob_id,
            }],
        }))
        .unwrap();
        let inner_tree_id = flat_write(&inner_tree_bytes);

        // root tree referencing the nested tree
        let root_tree_bytes = serialize::serialize(&Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"subdir".to_vec(),
                mode: EntryMode::Tree,
                object_hash: inner_tree_id,
            }],
        }))
        .unwrap();
        let root_tree_id = flat_write(&root_tree_bytes);

        // signed root commit (legacy-era signature — the translated
        // commit's own signature will differ from this one; the point
        // is that the LEGACY bytes on disk are a real signed commit).
        let mut commit = Commit::new_unannotated(
            root_tree_id,
            vec![],
            Identity::ed25519(author_kp.public.0),
            author_kp.public.0,
            b"legacy root commit".to_vec(),
            1_700_000_000,
            [0u8; 64],
        );
        commit.signature = sign::sign_commit(&commit, author_kp).unwrap().0;
        let commit_bytes = serialize::serialize(&Object::Commit(commit)).unwrap();
        let commit_id = flat_write(&commit_bytes);

        // refs/heads/main + HEAD -> main. No `.mkit/format` marker.
        fs::create_dir_all(root.join(".mkit/refs/heads")).unwrap();
        fs::write(
            root.join(".mkit/refs/heads/main"),
            format!("{}\n", hash::to_hex(&commit_id)),
        )
        .unwrap();
        fs::write(root.join(".mkit/HEAD"), "ref: refs/heads/main\n").unwrap();

        (blob_id, inner_tree_id, root_tree_id, commit_id)
    }

    #[test]
    fn classify_detects_missing_marker_as_legacy() {
        let dir = TempDir::new().unwrap();
        let author_kp = KeyPair::generate().unwrap();
        build_legacy_repo(dir.path(), &author_kp);
        let layout = RepoLayout::single(dir.path());
        assert_eq!(classify(&layout).unwrap(), LegacyFormatStatus::Legacy);
    }

    #[test]
    fn classify_rejects_current_format_as_already_current() {
        let dir = TempDir::new().unwrap();
        let layout = RepoLayout::single(dir.path());
        ObjectStore::init(&layout).unwrap();
        assert_eq!(
            classify(&layout).unwrap(),
            LegacyFormatStatus::AlreadyCurrent
        );
    }

    #[test]
    fn classify_rejects_unknown_marker_loudly() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join(".mkit/objects")).unwrap();
        fs::write(dir.path().join(".mkit/format"), "some-future-fmt\n").unwrap();
        let layout = RepoLayout::single(dir.path());
        assert_eq!(
            classify(&layout).unwrap(),
            LegacyFormatStatus::Unknown("some-future-fmt".to_owned())
        );
    }

    #[test]
    fn export_translates_ids_and_content_matches() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();
        let author_kp = KeyPair::generate().unwrap();
        let export_kp = KeyPair::generate().unwrap();
        let (blob_id, inner_tree_id, root_tree_id, commit_id) =
            build_legacy_repo(src_dir.path(), &author_kp);

        let src_layout = RepoLayout::single(src_dir.path());
        let dst_layout = RepoLayout::single(dst_dir.path());
        let dst = ObjectStore::init(&dst_layout).unwrap();

        let report = export_legacy_repo(&src_layout, &dst, &dst_layout, &export_kp).unwrap();

        assert_eq!(report.branches.len(), 1);
        let (name, old, new) = &report.branches[0];
        assert_eq!(name, "main");
        assert_eq!(*old, commit_id);
        assert_ne!(*new, commit_id, "commit id must change (tree re-addressed)");
        assert_eq!(report.head, Some(HeadOutcome::Branch("main".to_owned())));
        // 1 blob + 2 trees (root, subdir) + 1 commit = 4 distinct objects.
        assert_eq!(report.objects_translated, 4);

        // The new repo opens cleanly under the current format.
        let reopened = ObjectStore::open(&dst_layout).unwrap();
        let new_commit = match reopened.read_object(new).unwrap() {
            Object::Commit(c) => c,
            other => panic!("expected commit, got {other:?}"),
        };
        assert_ne!(new_commit.tree_hash, root_tree_id, "tree id must change");
        assert_eq!(new_commit.signer, export_kp.public.0);
        assert_eq!(
            new_commit.author,
            Identity::ed25519(author_kp.public.0),
            "original author identity is preserved even though signer changes"
        );
        sign::verify_commit(&new_commit).expect("re-signed commit must verify");

        let new_tree = match reopened.read_object(&new_commit.tree_hash).unwrap() {
            Object::Tree(t) => t,
            other => panic!("expected tree, got {other:?}"),
        };
        assert_eq!(new_tree.entries.len(), 1);
        assert_eq!(new_tree.entries[0].name, b"subdir");
        assert_ne!(new_tree.entries[0].object_hash, inner_tree_id);

        let new_inner_tree = match reopened
            .read_object(&new_tree.entries[0].object_hash)
            .unwrap()
        {
            Object::Tree(t) => t,
            other => panic!("expected tree, got {other:?}"),
        };
        assert_eq!(new_inner_tree.entries.len(), 1);
        assert_eq!(new_inner_tree.entries[0].name, b"file.txt");
        // Blob content-addressing is unaffected by the merkle change —
        // the blob keeps its original id.
        assert_eq!(new_inner_tree.entries[0].object_hash, blob_id);

        let new_blob = match reopened.read_object(&blob_id).unwrap() {
            Object::Blob(b) => b,
            other => panic!("expected blob, got {other:?}"),
        };
        assert_eq!(new_blob.data, b"hello legacy world");
    }

    #[test]
    fn export_refuses_already_current_format_source() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();
        let src_layout = RepoLayout::single(src_dir.path());
        ObjectStore::init(&src_layout).unwrap();
        let dst_layout = RepoLayout::single(dst_dir.path());
        let dst = ObjectStore::init(&dst_layout).unwrap();
        let kp = KeyPair::generate().unwrap();

        let err = export_legacy_repo(&src_layout, &dst, &dst_layout, &kp).unwrap_err();
        assert!(matches!(err, LegacyExportError::AlreadyCurrentFormat(_)));
    }

    #[test]
    fn export_refuses_unknown_format_source() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();
        fs::create_dir_all(src_dir.path().join(".mkit/objects")).unwrap();
        fs::write(src_dir.path().join(".mkit/format"), "bmt-v2\n").unwrap();
        let src_layout = RepoLayout::single(src_dir.path());
        let dst_layout = RepoLayout::single(dst_dir.path());
        let dst = ObjectStore::init(&dst_layout).unwrap();
        let kp = KeyPair::generate().unwrap();

        let err = export_legacy_repo(&src_layout, &dst, &dst_layout, &kp).unwrap_err();
        assert!(matches!(err, LegacyExportError::UnknownFormat(_, f) if f == "bmt-v2"));
    }

    #[test]
    fn export_detects_corrupt_legacy_object() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();
        let author_kp = KeyPair::generate().unwrap();
        let (_, _, _, commit_id) = build_legacy_repo(src_dir.path(), &author_kp);

        // Tear the commit object's on-disk bytes.
        let hex = hash::to_hex(&commit_id);
        let path = src_dir
            .path()
            .join(".mkit/objects")
            .join(&hex[..2])
            .join(&hex[2..]);
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 0xFF;
        fs::write(&path, &bytes).unwrap();

        let src_layout = RepoLayout::single(src_dir.path());
        let dst_layout = RepoLayout::single(dst_dir.path());
        let dst = ObjectStore::init(&dst_layout).unwrap();
        let kp = KeyPair::generate().unwrap();

        let err = export_legacy_repo(&src_layout, &dst, &dst_layout, &kp).unwrap_err();
        assert!(matches!(err, LegacyExportError::HashMismatch(_, _)));
    }
}
