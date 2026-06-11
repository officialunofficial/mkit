//! The git→mkit import driver (SPEC-GIT-IMPORT §3).
//!
//! Pure translation engine: reads git objects through a [`GitSource`],
//! writes serialized mkit objects through an [`ObjectSink`], signs
//! through caller-supplied callbacks (the crate stays crypto-free —
//! the CLI passes its `CommitSigner`), and records sha1→blake3 pairs
//! plus retained raw commit/tag bytes through caller-supplied hooks.
//!
//! Everything here is deterministic given *(git bytes, signing key,
//! import-spec version)*: deterministic Ed25519 means the engine can
//! be re-run idempotently and the map is a rebuildable cache under
//! the same key (SPEC-GIT-IMPORT §1.2).

use crate::error::{BridgeError, Refusal};
use crate::gitobj::Sha1Id;
use crate::gitparse::{self, ModeMapping};
use crate::gitsrc::{CatFileBatch, GitObjKind};
use mkit_core::object::{
    Blob, ChunkedBlob, Commit, Identity, Object, ObjectType, Tag, Tree, TreeEntry,
};
use mkit_core::{ChunkIterator, FastCdc, Hash};
use std::collections::HashMap;

/// SPEC-GIT-IMPORT §3.1: the normative chunking threshold.
pub const CHUNK_THRESHOLD: u64 = mkit_core::worktree::CHUNK_THRESHOLD;

/// SPEC-GIT-IMPORT §3.4: tag→tag chains beyond this depth refuse.
pub const MAX_TAG_CHAIN: usize = 16;

/// Tree nesting cap, matching mkit-core's `MAX_TREE_DEPTH` defense
/// (the importer is the most untrusted boundary in the system).
pub const MAX_TREE_DEPTH: usize = 128;

/// This implementation's import-spec version (SPEC-GIT-IMPORT §1.2).
pub const IMPORT_SPEC_VERSION: u32 = 1;

/// Where the driver reads git objects from. [`CatFileBatch`] for real
/// repositories; an in-memory map for hermetic tests/vectors.
pub trait GitSource {
    fn read_git(&mut self, id: &Sha1Id) -> Result<(GitObjKind, Vec<u8>), BridgeError>;
}

impl GitSource for CatFileBatch {
    fn read_git(&mut self, id: &Sha1Id) -> Result<(GitObjKind, Vec<u8>), BridgeError> {
        self.read(id)
    }
}

/// In-memory source for tests and golden vectors.
#[derive(Debug, Default)]
pub struct MemGitSource(pub HashMap<Sha1Id, (GitObjKind, Vec<u8>)>);

impl MemGitSource {
    /// Insert a git object body, computing its real sha1 id.
    pub fn put(&mut self, kind: GitObjKind, body: Vec<u8>) -> Sha1Id {
        let gtype = match kind {
            GitObjKind::Blob => crate::gitobj::GitType::Blob,
            GitObjKind::Tree => crate::gitobj::GitType::Tree,
            GitObjKind::Commit => crate::gitobj::GitType::Commit,
            GitObjKind::Tag => crate::gitobj::GitType::Tag,
        };
        let id = crate::gitobj::GitObject {
            gtype,
            body: body.clone(),
        }
        .id();
        self.0.insert(id, (kind, body));
        id
    }
}

impl GitSource for MemGitSource {
    fn read_git(&mut self, id: &Sha1Id) -> Result<(GitObjKind, Vec<u8>), BridgeError> {
        self.0
            .get(id)
            .cloned()
            .ok_or_else(|| BridgeError::Source("object missing from memory source".into()))
    }
}

/// Where serialized mkit objects land. Implemented for
/// [`mkit_core::ObjectStore`] (per-object fsync) and the CLI's bulk
/// writer; tests use an in-memory map.
pub trait ObjectSink {
    fn write_object(&mut self, bytes: &[u8]) -> Result<Hash, BridgeError>;

    /// The stored object's type byte, when the sink can answer (used
    /// only to disambiguate blob vs chunked-manifest tag targets).
    fn kind_of(&self, _h: &Hash) -> Option<ObjectType> {
        None
    }
}

impl ObjectSink for mkit_core::ObjectStore {
    fn write_object(&mut self, bytes: &[u8]) -> Result<Hash, BridgeError> {
        self.write(bytes)
            .map_err(|e| BridgeError::Source(format!("store write: {e}")))
    }

    fn kind_of(&self, h: &Hash) -> Option<ObjectType> {
        self.read_object(h).ok().map(|o| o.object_type())
    }
}

/// In-memory sink for tests.
#[derive(Debug, Default)]
pub struct MemSink(pub HashMap<Hash, Vec<u8>>);

impl ObjectSink for MemSink {
    fn write_object(&mut self, bytes: &[u8]) -> Result<Hash, BridgeError> {
        let h = mkit_core::hash::hash(bytes);
        self.0.insert(h, bytes.to_vec());
        Ok(h)
    }

    fn kind_of(&self, h: &Hash) -> Option<ObjectType> {
        self.0
            .get(h)
            .and_then(|b| mkit_core::deserialize(b).ok())
            .map(|o| o.object_type())
    }
}

/// Hook receiving (upstream sha1, framed raw git bytes) for retention.
/// The explicit lifetime keeps the trait object bound to the
/// borrower's scope (a bare `dyn` alias would default to `'static`).
pub type RetainRawFn<'f> = dyn FnMut(&Sha1Id, &[u8]) -> Result<(), BridgeError> + 'f;

/// Signing callbacks: given the unsigned object (zeroed signature),
/// return the 64-byte signature. The signer pubkey is supplied
/// separately so the engine can fill the `signer` field first.
pub struct ImportSigner<'a> {
    pub public: [u8; 32],
    pub sign_commit: &'a mut dyn FnMut(&Commit) -> Result<[u8; 64], BridgeError>,
    pub sign_tag: &'a mut dyn FnMut(&Tag) -> Result<[u8; 64], BridgeError>,
}

impl std::fmt::Debug for ImportSigner<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportSigner")
            .field("public", &crate::gitobj::bytes_hex(&self.public))
            .finish_non_exhaustive()
    }
}

/// Per-run options.
#[derive(Debug, Clone, Copy, Default)]
pub struct ImportOptions {
    /// Recorded state-dir direction is `fork`: historic-mode
    /// normalization must refuse instead (SPEC-GIT-IMPORT §3.3).
    pub fork_mode: bool,
}

/// Outcome of importing one ref tip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedRef {
    /// The mkit hash of the translated tip object (commit or tag).
    pub head: Hash,
    /// New (sha1, blake3) pairs discovered by this call, in
    /// dependency order — append these to the map cache.
    pub new_pairs: Vec<(Sha1Id, Hash)>,
    /// Whether any historic mode was normalized (declared-lossy warn).
    pub normalized_modes: bool,
}

/// The import engine. `map` is the sha1→blake3 cache (load it from
/// the state dir; pairs accumulate across calls).
///
/// Long unmapped parent chains should go through
/// [`Importer::import_commits`] (parents-first order, recursion depth
/// 1); [`Importer::import_ref`] recurses through unmapped parents.
pub struct Importer<'a, S: GitSource, K: ObjectSink> {
    pub source: &'a mut S,
    pub sink: &'a mut K,
    pub signer: ImportSigner<'a>,
    pub map: &'a mut HashMap<Sha1Id, Hash>,
    /// Retained-raw-bytes hook (commits + tags only); the CLI writes
    /// these sha1-addressed under the state dir (SPEC-GIT-IMPORT §5).
    pub retain_raw: &'a mut RetainRawFn<'a>,
    pub options: ImportOptions,
}

impl<S: GitSource, K: ObjectSink> std::fmt::Debug for Importer<'_, S, K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Importer").finish_non_exhaustive()
    }
}

impl<S: GitSource, K: ObjectSink> Importer<'_, S, K> {
    /// Import the closure of one upstream ref tip (commit or tag
    /// object id, parents-first commit order is derived internally
    /// for the in-memory path; CLI callers pass `rev_list` order via
    /// [`Self::import_commits`] for incremental efficiency).
    pub fn import_ref(&mut self, tip: &Sha1Id) -> Result<ImportedRef, BridgeError> {
        let mut new_pairs = Vec::new();
        let mut normalized = false;
        let head = self.object(tip, 0, 0, &mut new_pairs, &mut normalized)?;
        Ok(ImportedRef {
            head,
            new_pairs,
            normalized_modes: normalized,
        })
    }

    /// Import commits in caller-supplied parents-first order, then
    /// return the map entry for `tip`. More efficient than
    /// [`Self::import_ref`] for long histories (no deep recursion
    /// through parent links).
    pub fn import_commits(
        &mut self,
        order: &[Sha1Id],
        tip: &Sha1Id,
    ) -> Result<ImportedRef, BridgeError> {
        let mut new_pairs = Vec::new();
        let mut normalized = false;
        for id in order {
            self.object(id, 0, 0, &mut new_pairs, &mut normalized)?;
        }
        let head = self.object(tip, 0, 0, &mut new_pairs, &mut normalized)?;
        Ok(ImportedRef {
            head,
            new_pairs,
            normalized_modes: normalized,
        })
    }

    /// Translate one git object (memoized through the map).
    fn object(
        &mut self,
        id: &Sha1Id,
        tag_depth: usize,
        tree_depth: usize,
        new_pairs: &mut Vec<(Sha1Id, Hash)>,
        normalized: &mut bool,
    ) -> Result<Hash, BridgeError> {
        if let Some(h) = self.map.get(id) {
            return Ok(*h);
        }
        let (kind, body) = self.source.read_git(id)?;
        let h = match kind {
            GitObjKind::Blob => self.blob(&body, new_pairs)?,
            GitObjKind::Tree => {
                if tree_depth >= MAX_TREE_DEPTH {
                    return Err(Refusal::TreeTooDeep { object: hash20(id) }.into());
                }
                self.tree(id, &body, tree_depth, new_pairs, normalized)?
            }
            GitObjKind::Commit => self.commit(id, &body, new_pairs, normalized)?,
            GitObjKind::Tag => {
                if tag_depth >= MAX_TAG_CHAIN {
                    return Err(Refusal::TagChain { object: hash20(id) }.into());
                }
                self.tag(id, &body, tag_depth, new_pairs, normalized)?
            }
        };
        self.map.insert(*id, h);
        new_pairs.push((*id, h));
        Ok(h)
    }

    /// §3.1: verbatim ≤ threshold, pinned `FastCDC` above it.
    fn blob(
        &mut self,
        body: &[u8],
        new_pairs: &mut Vec<(Sha1Id, Hash)>,
    ) -> Result<Hash, BridgeError> {
        let _ = new_pairs; // chunk blobs are content-addressed extras, not mapped
        if body.len() as u64 <= CHUNK_THRESHOLD {
            let bytes = ser(&Object::Blob(Blob {
                data: body.to_vec(),
            }))?;
            return self.sink.write_object(&bytes);
        }
        let mut chunks = Vec::new();
        for b in ChunkIterator::new(FastCdc::v1(), body) {
            let chunk = ser(&Object::Blob(Blob {
                data: body[b.offset..b.offset + b.length].to_vec(),
            }))?;
            chunks.push(self.sink.write_object(&chunk)?);
        }
        let manifest = ser(&Object::ChunkedBlob(ChunkedBlob {
            total_size: body.len() as u64,
            chunk_size: 0,
            chunks,
        }))?;
        self.sink.write_object(&manifest)
    }

    /// §3.3: re-sort, validate names, map modes.
    fn tree(
        &mut self,
        id: &Sha1Id,
        body: &[u8],
        depth: usize,
        new_pairs: &mut Vec<(Sha1Id, Hash)>,
        normalized: &mut bool,
    ) -> Result<Hash, BridgeError> {
        let parsed =
            gitparse::parse_tree(body).map_err(|e| BridgeError::Source(format!("tree: {e}")))?;
        let mut entries = Vec::with_capacity(parsed.len());
        for e in parsed {
            let mode = match gitparse::map_mode(&e.mode) {
                ModeMapping::Canonical(m) => m,
                ModeMapping::Normalized(m) => {
                    if self.options.fork_mode {
                        return Err(Refusal::NormalizedModeInFork {
                            object: hash20(id),
                            mode: String::from_utf8_lossy(&e.mode).into_owned(),
                        }
                        .into());
                    }
                    *normalized = true;
                    m
                }
                ModeMapping::Gitlink => {
                    return Err(Refusal::Gitlink {
                        object: hash20(id),
                        path: String::from_utf8_lossy(&e.name).into_owned(),
                    }
                    .into());
                }
                ModeMapping::Unknown => {
                    return Err(Refusal::UnknownTreeMode {
                        object: hash20(id),
                        mode: String::from_utf8_lossy(&e.mode).into_owned(),
                    }
                    .into());
                }
            };
            if !TreeEntry::validate_name(&e.name) {
                return Err(Refusal::TreeEntryName {
                    object: hash20(id),
                    name: String::from_utf8_lossy(&e.name).into_owned(),
                }
                .into());
            }
            let child = self.object(&e.id, 0, depth + 1, new_pairs, normalized)?;
            entries.push(TreeEntry {
                name: e.name,
                mode,
                object_hash: child,
            });
        }
        // git order → mkit byte-lex order. Duplicate names are
        // git-representable (file `a` + dir `a` sort apart under
        // git's `name+"/"` key) but undecodable in mkit — the
        // serializer does NOT check on write, so refuse here or the
        // store gains a poisoned signed object.
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        if entries.windows(2).any(|w| w[0].name == w[1].name) {
            return Err(Refusal::DuplicateTreeEntry { object: hash20(id) }.into());
        }
        let bytes = ser(&Object::Tree(Tree { entries }))?;
        self.sink.write_object(&bytes)
    }

    /// §3.2: importer-signed commit.
    fn commit(
        &mut self,
        id: &Sha1Id,
        body: &[u8],
        new_pairs: &mut Vec<(Sha1Id, Hash)>,
        normalized: &mut bool,
    ) -> Result<Hash, BridgeError> {
        let parsed = gitparse::parse_commit(body)
            .map_err(|e| BridgeError::Source(format!("commit: {e}")))?;
        if parsed.committer.timestamp < 0 {
            return Err(Refusal::NegativeTimestamp {
                object: hash20(id),
                timestamp: parsed.committer.timestamp,
            }
            .into());
        }
        if parsed.parents.len() > 1000 {
            return Err(Refusal::TooManyParents { object: hash20(id) }.into());
        }
        if parsed.author.identity.is_empty() || parsed.author.identity.len() > 4096 {
            return Err(Refusal::AuthorPayload { object: hash20(id) }.into());
        }
        let tree = self.object(&parsed.tree, 0, 0, new_pairs, normalized)?;
        let mut parents = Vec::with_capacity(parsed.parents.len());
        for p in &parsed.parents {
            parents.push(self.object(p, 0, 0, new_pairs, normalized)?);
        }
        // Raw bytes: the full git object body (commit framing is
        // recomputable from kind+len).
        let raw = raw_git_bytes(GitObjKind::Commit, body);
        (self.retain_raw)(id, &raw)?;

        #[allow(clippy::cast_sign_loss)] // negative refused above
        let timestamp = parsed.committer.timestamp as u64;
        let mut commit = Commit {
            tree_hash: tree,
            parents,
            author: Identity::opaque(parsed.author.identity),
            signer: self.signer.public,
            message: parsed.message,
            timestamp,
            message_hash: mkit_core::hash::ZERO,
            content_digest: mkit_core::hash::hash(&raw),
            signature: [0u8; 64],
        };
        commit.signature = (self.signer.sign_commit)(&commit)?;
        let bytes = ser(&Object::Commit(commit))?;
        self.sink.write_object(&bytes)
    }

    /// §3.4: importer-signed tag.
    fn tag(
        &mut self,
        id: &Sha1Id,
        body: &[u8],
        depth: usize,
        new_pairs: &mut Vec<(Sha1Id, Hash)>,
        normalized: &mut bool,
    ) -> Result<Hash, BridgeError> {
        let parsed =
            gitparse::parse_tag(body).map_err(|e| BridgeError::Source(format!("tag: {e}")))?;
        if crate::refname::check_tag_name(&parsed.name).is_err() {
            return Err(Refusal::TagName { object: hash20(id) }.into());
        }
        let target_type = match parsed.target_type.as_slice() {
            b"commit" => ObjectType::Commit,
            b"tree" => ObjectType::Tree,
            b"blob" => ObjectType::Blob,
            b"tag" => ObjectType::Tag,
            other => {
                return Err(BridgeError::Source(format!(
                    "tag target type {:?} unknown",
                    String::from_utf8_lossy(other)
                )));
            }
        };
        let target = self.object(&parsed.object, depth + 1, 0, new_pairs, normalized)?;
        // The mkit target_type must reflect what the TRANSLATED target
        // is: a >1MiB git blob became a chunked manifest.
        let target_type = if target_type == ObjectType::Blob {
            // Chunked manifests and blobs are both `blob` on the git
            // side; the mkit tag must record the TRANSLATED type.
            match self.sink.kind_of(&target) {
                Some(ObjectType::ChunkedBlob) => ObjectType::ChunkedBlob,
                _ => ObjectType::Blob,
            }
        } else {
            target_type
        };
        let (tagger_identity, timestamp) = match parsed.tagger {
            Some(p) => {
                if p.timestamp < 0 {
                    return Err(Refusal::NegativeTimestamp {
                        object: hash20(id),
                        timestamp: p.timestamp,
                    }
                    .into());
                }
                if p.identity.is_empty() || p.identity.len() > 4096 {
                    return Err(Refusal::AuthorPayload { object: hash20(id) }.into());
                }
                #[allow(clippy::cast_sign_loss)]
                let ts = p.timestamp as u64;
                (Identity::opaque(p.identity), ts)
            }
            // Historic tagger-less tags: a pinned sentinel identity
            // and epoch 0 (deterministic; provenance retains truth).
            None => (Identity::opaque(b"(no tagger)".to_vec()), 0),
        };
        let raw = raw_git_bytes(GitObjKind::Tag, body);
        (self.retain_raw)(id, &raw)?;
        let mut tag = Tag {
            target,
            target_type,
            name: parsed.name,
            tagger: tagger_identity,
            signer: self.signer.public,
            message: parsed.message,
            timestamp,
            signature: [0u8; 64],
        };
        tag.signature = (self.signer.sign_tag)(&tag)?;
        let bytes = ser(&Object::Tag(tag))?;
        self.sink.write_object(&bytes)
    }
}

fn ser(obj: &Object) -> Result<Vec<u8>, BridgeError> {
    mkit_core::serialize(obj).map_err(|e| BridgeError::Source(format!("serialize: {e}")))
}

/// Rebuild the full `"<type> <len>\0" + body` git object bytes for
/// retention + `content_digest` (SPEC-GIT-IMPORT §5: "raw git commit
/// bytes" are the framed object bytes, matching `git cat-file`'s
/// hashed form).
fn raw_git_bytes(kind: GitObjKind, body: &[u8]) -> Vec<u8> {
    let name = match kind {
        GitObjKind::Blob => "blob",
        GitObjKind::Tree => "tree",
        GitObjKind::Commit => "commit",
        GitObjKind::Tag => "tag",
    };
    let mut out = Vec::with_capacity(name.len() + 12 + body.len());
    out.extend_from_slice(name.as_bytes());
    out.push(b' ');
    out.extend_from_slice(body.len().to_string().as_bytes());
    out.push(0);
    out.extend_from_slice(body);
    out
}

/// A `Sha1Id` widened into the 32-byte `Hash` slot Refusal uses for
/// display (zero-padded; Display prints the meaningful prefix).
fn hash20(id: &Sha1Id) -> Hash {
    let mut h = [0u8; 32];
    h[..20].copy_from_slice(id);
    h
}
