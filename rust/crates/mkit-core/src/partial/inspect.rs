//! Bounded, local facts about one canonical Snapshot object.
//!
//! A fact does not establish a complete graph, any child's type/length, or
//! permission to read the object. The source must cap its allocation before
//! passing bytes here. No input bytes or serialized proof are retained.

use crate::hash::Hash;
use crate::object::{Object, ObjectType, TreeEntry, id_from_object};
use crate::serialize::{deserialize, serialize};
use crate::sign::{verify_commit, verify_remix};

/// The role required by an authenticated incoming Snapshot edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotRole {
    /// Signed existing Commit or Remix; signer identity is not authorized here.
    BaseRoot,
    /// Signed candidate Commit; parent and author are not checked here.
    CandidateRoot,
    /// Tree reached through an authenticated Tree-mode edge.
    Tree,
    /// Blob or `ChunkedBlob` reached through a regular/executable edge.
    File,
    /// Blob reached through a symlink edge.
    Symlink,
    /// Blob reached through a manifest chunk position.
    Chunk,
}

/// Per-operation limits. These may be lower than generic object-format caps;
/// they are not selected-file limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectInspectionLimits {
    /// Maximum canonical input bytes of any object.
    pub max_object_bytes: usize,
    /// Additional byte cap when the encoded kind is Tree.
    pub max_tree_bytes: usize,
    /// Maximum declared Tree entries, checked before decoding.
    pub max_tree_entries: usize,
    /// Maximum declared `ChunkedBlob` chunk IDs, checked before decoding.
    pub max_manifest_chunks: usize,
}

/// Failure to authenticate or bound one object's stated facts.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum InspectError {
    /// A caller-lowered byte or declared-count cap was exceeded.
    #[error("object inspection limit exceeded: {0}")]
    Limit(&'static str),
    /// The bytes, canonical encoding or independently expected ID disagree.
    #[error("object is malformed, noncanonical or has the wrong ID")]
    Corrupt,
    /// The object kind does not match the incoming role or snapshot profile.
    #[error("object has the wrong type for this Snapshot edge")]
    WrongType,
    /// A Commit or Remix fails strict signature verification.
    #[error("snapshot root signature is invalid")]
    InvalidSignature,
    /// A manifest's intrinsic empty-list and total-size fields disagree.
    #[error("manifest has invalid intrinsic empty/total fields")]
    InvalidManifest,
    /// A page request is empty, overflowing or out of bounds.
    #[error("requested object page is empty, overflowing or out of bounds")]
    InvalidPage,
}

/// The authenticated kind of one object. Manifest here never means its
/// referenced chunks have been fetched or checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectedKind {
    /// Signed Commit root.
    Commit,
    /// Signed Remix root.
    Remix,
    /// Canonical Tree.
    Tree,
    /// Canonical Blob.
    Blob,
    /// Canonical `ChunkedBlob`; its referenced chunks remain unchecked.
    ChunkedBlob,
}

enum Facts {
    Root {
        tree_id: Hash,
        signer: [u8; 32],
    },
    Tree(Vec<TreeEntry>),
    Blob {
        len: usize,
    },
    Manifest {
        total_size: u64,
        chunk_size: u32,
        chunks: Vec<Hash>,
    },
}

/// Private-construction, in-memory facts from one bounded canonical object.
/// This is not a closure certificate or a deserializable authority token.
pub struct InspectedObject {
    id: Hash,
    role: Option<SnapshotRole>,
    kind: InspectedKind,
    canonical_len: usize,
    facts: Facts,
}

impl std::fmt::Debug for InspectedObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InspectedObject")
            .field("kind", &self.kind)
            .field("role", &self.role)
            .field("canonical_len", &self.canonical_len)
            .finish_non_exhaustive()
    }
}

impl InspectedObject {
    /// Derived type-aware object ID, not an authorization claim.
    #[must_use]
    pub fn id(&self) -> Hash {
        self.id
    }
    /// Incoming role checked by inspection, absent for identification only.
    /// `None` means only canonical Snapshot-kind identification was checked;
    /// no incoming role was asserted.
    /// Canonical snapshot object kind.
    #[must_use]
    pub fn role(&self) -> Option<SnapshotRole> {
        self.role
    }
    /// Length of the canonical input bytes, which are not retained.
    #[must_use]
    pub fn kind(&self) -> InspectedKind {
        self.kind
    }
    /// Signed root Tree ID and embedded signer, if this is a root.
    #[must_use]
    pub fn canonical_len(&self) -> usize {
        self.canonical_len
    }
    /// Blob content length, if this is a Blob.
    #[must_use]
    pub fn root(&self) -> Option<(Hash, [u8; 32])> {
        match self.facts {
            Facts::Root { tree_id, signer } => Some((tree_id, signer)),
            _ => None,
        }
    }
    /// Entry count, if this is a Tree.
    #[must_use]
    pub fn blob_len(&self) -> Option<usize> {
        match self.facts {
            Facts::Blob { len } => Some(len),
            _ => None,
        }
    }
    /// Intrinsic total, chunk-size field and ID count for a manifest.
    /// This does not validate referenced chunk lengths or their sum.
    #[must_use]
    pub fn tree_entries_len(&self) -> Option<usize> {
        match &self.facts {
            Facts::Tree(entries) => Some(entries.len()),
            _ => None,
        }
    }
    #[must_use]
    pub fn manifest(&self) -> Option<(u64, u32, usize)> {
        match &self.facts {
            Facts::Manifest {
                total_size,
                chunk_size,
                chunks,
            } => Some((*total_size, *chunk_size, chunks.len())),
            _ => None,
        }
    }
    /// Borrow a nonempty indexed Tree-entry page; no child vector is cloned.
    ///
    /// # Errors
    ///
    /// Returns [`InspectError::WrongType`] for a non-Tree or
    /// [`InspectError::InvalidPage`] for zero count, overflow or an
    /// out-of-bounds range.
    pub fn tree_page(&self, start: usize, count: usize) -> Result<&[TreeEntry], InspectError> {
        let Facts::Tree(entries) = &self.facts else {
            return Err(InspectError::WrongType);
        };
        page(entries, start, count)
    }
    /// Borrow a nonempty indexed manifest-chunk page; positions are preserved.
    ///
    /// # Errors
    ///
    /// Returns [`InspectError::WrongType`] for a non-manifest or
    /// [`InspectError::InvalidPage`] for zero count, overflow or an
    /// out-of-bounds range.
    pub fn chunk_page(&self, start: usize, count: usize) -> Result<&[Hash], InspectError> {
        let Facts::Manifest { chunks, .. } = &self.facts else {
            return Err(InspectError::WrongType);
        };
        page(chunks, start, count)
    }
}

fn page<T>(values: &[T], start: usize, count: usize) -> Result<&[T], InspectError> {
    let end = start.checked_add(count).ok_or(InspectError::InvalidPage)?;
    if count == 0 || end > values.len() {
        return Err(InspectError::InvalidPage);
    }
    Ok(&values[start..end])
}

/// Inspect exactly one object under its incoming role. Canonical bytes,
/// decoded object, canonical re-encoding and Merkle scratch may coexist during
/// the call; the returned fact owns only necessary fields from the decoded
/// object. This bound is not an exact process-RSS or whole-repository bound.
///
/// # Errors
///
/// Returns [`InspectError::Limit`] before decoding for caller byte/count
/// limits, [`InspectError::Corrupt`] for malformed, noncanonical or wrong-ID
/// bytes, [`InspectError::WrongType`] for the incoming role,
/// [`InspectError::InvalidSignature`] for a bad root signature, or
/// [`InspectError::InvalidManifest`] for contradictory intrinsic fields.
pub fn inspect_snapshot_object(
    expected_id: Hash,
    bytes: &[u8],
    role: SnapshotRole,
    limits: ObjectInspectionLimits,
) -> Result<InspectedObject, InspectError> {
    inspect_inner(bytes, Some(expected_id), Some(role), limits)
}

/// Identify one bounded canonical snapshot-kind payload from a checked raw
/// pack. The derived type-aware ID is a local object fact, not an incoming
/// edge, reachability, catalog-completeness or authorization claim.
///
/// # Errors
///
/// Uses the same limits, canonical, signature and intrinsic checks as
/// [`inspect_snapshot_object`], and returns [`InspectError::WrongType`] for
/// Tags, Delta or any other kind outside the snapshot-object profile.
pub fn identify_snapshot_object(
    bytes: &[u8],
    limits: ObjectInspectionLimits,
) -> Result<InspectedObject, InspectError> {
    inspect_inner(bytes, None, None, limits)
}

fn inspect_inner(
    bytes: &[u8],
    expected_id: Option<Hash>,
    role: Option<SnapshotRole>,
    limits: ObjectInspectionLimits,
) -> Result<InspectedObject, InspectError> {
    if bytes.is_empty() || bytes.len() > limits.max_object_bytes {
        return Err(InspectError::Limit("object bytes"));
    }
    preflight(bytes, limits)?;
    let object = deserialize(bytes).map_err(|_| InspectError::Corrupt)?;
    if serialize(&object).map_err(|_| InspectError::Corrupt)? != bytes {
        return Err(InspectError::Corrupt);
    }
    let id = id_from_object(&object, bytes);
    if expected_id.is_some_and(|expected| expected != id) {
        return Err(InspectError::Corrupt);
    }
    let allowed = match role {
        Some(SnapshotRole::BaseRoot) => matches!(object, Object::Commit(_) | Object::Remix(_)),
        Some(SnapshotRole::CandidateRoot) => matches!(object, Object::Commit(_)),
        Some(SnapshotRole::Tree) => matches!(object, Object::Tree(_)),
        Some(SnapshotRole::File) => matches!(object, Object::Blob(_) | Object::ChunkedBlob(_)),
        Some(SnapshotRole::Symlink | SnapshotRole::Chunk) => matches!(object, Object::Blob(_)),
        None => matches!(
            object,
            Object::Commit(_)
                | Object::Remix(_)
                | Object::Tree(_)
                | Object::Blob(_)
                | Object::ChunkedBlob(_)
        ),
    };
    if !allowed {
        return Err(InspectError::WrongType);
    }
    let canonical_len = bytes.len();
    let (kind, facts) = match object {
        Object::Commit(commit) => {
            verify_commit(&commit).map_err(|_| InspectError::InvalidSignature)?;
            (
                InspectedKind::Commit,
                Facts::Root {
                    tree_id: commit.tree_hash,
                    signer: commit.signer,
                },
            )
        }
        Object::Remix(remix) => {
            verify_remix(&remix).map_err(|_| InspectError::InvalidSignature)?;
            (
                InspectedKind::Remix,
                Facts::Root {
                    tree_id: remix.tree_hash,
                    signer: remix.signer,
                },
            )
        }
        Object::Tree(tree) => (InspectedKind::Tree, Facts::Tree(tree.entries)),
        Object::Blob(blob) => (
            InspectedKind::Blob,
            Facts::Blob {
                len: blob.data.len(),
            },
        ),
        Object::ChunkedBlob(manifest) => {
            if manifest.chunks.is_empty() != (manifest.total_size == 0) {
                return Err(InspectError::InvalidManifest);
            }
            (
                InspectedKind::ChunkedBlob,
                Facts::Manifest {
                    total_size: manifest.total_size,
                    chunk_size: manifest.chunk_size,
                    chunks: manifest.chunks,
                },
            )
        }
        _ => return Err(InspectError::WrongType),
    };
    Ok(InspectedObject {
        id,
        role,
        kind,
        canonical_len,
        facts,
    })
}

fn preflight(bytes: &[u8], limits: ObjectInspectionLimits) -> Result<(), InspectError> {
    match bytes.first().copied() {
        Some(tag) if tag == ObjectType::Tree as u8 => {
            if bytes.len() > limits.max_tree_bytes {
                return Err(InspectError::Limit("tree bytes"));
            }
            if bytes.len() < 10 {
                return Err(InspectError::Corrupt);
            }
            let count = u32::from_le_bytes(bytes[6..10].try_into().expect("four bytes")) as usize;
            if count > limits.max_tree_entries {
                return Err(InspectError::Limit("tree entries"));
            }
            if count > (bytes.len() - 10) / 38 {
                return Err(InspectError::Corrupt);
            }
        }
        Some(tag) if tag == ObjectType::ChunkedBlob as u8 => {
            if bytes.len() < 22 {
                return Err(InspectError::Corrupt);
            }
            let count = u32::from_le_bytes(bytes[18..22].try_into().expect("four bytes")) as usize;
            if count > limits.max_manifest_chunks {
                return Err(InspectError::Limit("manifest chunks"));
            }
            if count > (bytes.len() - 22) / 32 {
                return Err(InspectError::Corrupt);
            }
        }
        _ => {}
    }
    // A caller-lowered tree cap applies by encoded kind, even when the
    // incoming role is wrong. A selected-file cap does not apply here.
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::collections::BTreeMap;

    use super::super::recipient::{RecipientError, RecipientLimits};
    use super::super::recipient_graph::RecipientGraph;
    use super::*;
    use crate::object::{Blob, ChunkedBlob, Commit, Delta, Identity, Remix, Tree};
    use crate::sign::{KeyPair, sign_commit, sign_remix};
    use crate::verify::{ObjectSource, VerifyError};

    struct OracleSource(BTreeMap<Hash, Vec<u8>>);

    impl ObjectSource for OracleSource {
        fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, VerifyError> {
            Ok(self.0.get(id).map(|bytes| Cow::Borrowed(bytes.as_slice())))
        }
    }

    fn limits() -> ObjectInspectionLimits {
        ObjectInspectionLimits {
            max_object_bytes: 4096,
            max_tree_bytes: 4096,
            max_tree_entries: 2,
            max_manifest_chunks: 2,
        }
    }

    fn encoded(object: &Object) -> (Hash, Vec<u8>) {
        let bytes = serialize(object).unwrap();
        (id_from_object(object, &bytes), bytes)
    }

    #[test]
    fn identification_and_role_inspection_agree_on_type_aware_ids() {
        let blob = Object::Blob(Blob {
            data: b"payload".to_vec(),
        });
        let (blob_id, blob_bytes) = encoded(&blob);
        let found = identify_snapshot_object(&blob_bytes, limits()).unwrap();
        assert_eq!(found.id(), blob_id);
        assert_eq!(found.role(), None);
        assert_eq!(found.blob_len(), Some(7));
        assert_eq!(
            inspect_snapshot_object(blob_id, &blob_bytes, SnapshotRole::Chunk, limits())
                .unwrap()
                .role(),
            Some(SnapshotRole::Chunk)
        );
        assert!(matches!(
            inspect_snapshot_object(blob_id, &blob_bytes, SnapshotRole::Tree, limits()),
            Err(InspectError::WrongType)
        ));

        let tree = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"file".to_vec(),
                mode: crate::object::EntryMode::Blob,
                object_hash: blob_id,
            }],
        });
        let (tree_id, tree_bytes) = encoded(&tree);
        assert_ne!(
            tree_id,
            crate::hash::hash(&tree_bytes),
            "Tree uses Merkle identity"
        );
        let found = identify_snapshot_object(&tree_bytes, limits()).unwrap();
        assert_eq!(found.id(), tree_id);
        assert_eq!(found.tree_page(0, 1).unwrap()[0].object_hash, blob_id);
        assert!(matches!(
            found.tree_page(0, 0),
            Err(InspectError::InvalidPage)
        ));
        assert!(matches!(
            found.tree_page(usize::MAX, 2),
            Err(InspectError::InvalidPage)
        ));
        assert!(matches!(
            inspect_snapshot_object(
                crate::hash::hash(&tree_bytes),
                &tree_bytes,
                SnapshotRole::Tree,
                limits()
            ),
            Err(InspectError::Corrupt)
        ));

        let manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: 999,
            chunk_size: 4,
            chunks: vec![blob_id],
        });
        let (manifest_id, manifest_bytes) = encoded(&manifest);
        assert_ne!(
            manifest_id,
            crate::hash::hash(&manifest_bytes),
            "manifest uses Merkle identity"
        );
        let found = identify_snapshot_object(&manifest_bytes, limits()).unwrap();
        assert_eq!(found.id(), manifest_id);
        assert_eq!(found.manifest(), Some((999, 4, 1)));
        assert_eq!(found.chunk_page(0, 1).unwrap(), &[blob_id]);
        // Intrinsic identification deliberately does not claim the 7-byte
        // chunk satisfies a declared 999-byte file or fixed-size rule.
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn root_signature_and_predecode_caps_are_enforced() {
        let key = KeyPair::from_seed([61; 32]);
        let mut commit = Commit::new_unannotated(
            [7; 32],
            Vec::new(),
            Identity::ed25519(key.public.0),
            key.public.0,
            b"test".to_vec(),
            1,
            [0; 64],
        );
        commit.signature = sign_commit(&commit, &key).unwrap().0;
        let (id, bytes) = encoded(&Object::Commit(commit.clone()));
        assert_eq!(
            identify_snapshot_object(&bytes, limits())
                .unwrap()
                .root()
                .unwrap()
                .0,
            [7; 32]
        );
        assert_eq!(
            inspect_snapshot_object(id, &bytes, SnapshotRole::CandidateRoot, limits())
                .unwrap()
                .kind(),
            InspectedKind::Commit
        );
        let mut remix = Remix {
            tree_hash: [8; 32],
            parents: Vec::new(),
            sources: Vec::new(),
            author: Identity::ed25519(key.public.0),
            signer: key.public.0,
            message: b"remix".to_vec(),
            timestamp: 2,
            signature: [0; 64],
        };
        remix.signature = sign_remix(&remix, &key).unwrap().0;
        let (remix_id, remix_bytes) = encoded(&Object::Remix(remix));
        assert_eq!(
            inspect_snapshot_object(remix_id, &remix_bytes, SnapshotRole::BaseRoot, limits())
                .unwrap()
                .kind(),
            InspectedKind::Remix
        );
        assert!(matches!(
            inspect_snapshot_object(
                remix_id,
                &remix_bytes,
                SnapshotRole::CandidateRoot,
                limits()
            ),
            Err(InspectError::WrongType)
        ));
        commit.signature[0] ^= 1;
        let (_, tampered) = encoded(&Object::Commit(commit));
        assert!(matches!(
            identify_snapshot_object(&tampered, limits()),
            Err(InspectError::InvalidSignature)
        ));
        let mut small = limits();
        small.max_object_bytes = bytes.len() - 1;
        assert!(matches!(
            identify_snapshot_object(&bytes, small),
            Err(InspectError::Limit("object bytes"))
        ));
        let tree = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"x".to_vec(),
                mode: crate::object::EntryMode::Blob,
                object_hash: id,
            }],
        });
        let (_, tree_bytes) = encoded(&tree);
        small = limits();
        small.max_tree_entries = 0;
        assert!(matches!(
            identify_snapshot_object(&tree_bytes, small),
            Err(InspectError::Limit("tree entries"))
        ));
        small = limits();
        small.max_tree_bytes = tree_bytes.len() - 1;
        assert!(matches!(
            identify_snapshot_object(&tree_bytes, small),
            Err(InspectError::Limit("tree bytes"))
        ));
        let manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: 1,
            chunk_size: 0,
            chunks: vec![id],
        });
        let (_, manifest_bytes) = encoded(&manifest);
        small = limits();
        small.max_manifest_chunks = 0;
        assert!(matches!(
            identify_snapshot_object(&manifest_bytes, small),
            Err(InspectError::Limit("manifest chunks"))
        ));
        let empty_bad = Object::ChunkedBlob(ChunkedBlob {
            total_size: 1,
            chunk_size: 0,
            chunks: Vec::new(),
        });
        let (_, empty_bad_bytes) = encoded(&empty_bad);
        assert!(matches!(
            identify_snapshot_object(&empty_bad_bytes, limits()),
            Err(InspectError::InvalidManifest)
        ));
    }

    #[test]
    fn non_snapshot_kinds_and_malformed_counts_reject() {
        let delta = Object::Delta(Delta {
            base_hash: [3; 32],
            result_size: 0,
            instructions: Vec::new(),
        });
        let (_, bytes) = encoded(&delta);
        assert!(matches!(
            identify_snapshot_object(&bytes, limits()),
            Err(InspectError::WrongType)
        ));
        let tree = Object::Tree(Tree {
            entries: Vec::new(),
        });
        let (_, mut tree_bytes) = encoded(&tree);
        tree_bytes[6..10].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            identify_snapshot_object(&tree_bytes, limits()),
            Err(InspectError::Limit("tree entries"))
        ));
        tree_bytes[6..10].copy_from_slice(&1u32.to_le_bytes());
        let mut broad = limits();
        broad.max_tree_entries = 100;
        assert!(
            matches!(
                identify_snapshot_object(&tree_bytes, broad),
                Err(InspectError::Corrupt)
            ),
            "physically impossible count is refused before decoder allocation"
        );
        let manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: 0,
            chunk_size: 0,
            chunks: Vec::new(),
        });
        let (_, mut manifest_bytes) = encoded(&manifest);
        manifest_bytes[18..22].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            identify_snapshot_object(&manifest_bytes, limits()),
            Err(InspectError::Limit("manifest chunks"))
        ));
        manifest_bytes[18..22].copy_from_slice(&1u32.to_le_bytes());
        broad.max_manifest_chunks = 100;
        assert!(matches!(
            identify_snapshot_object(&manifest_bytes, broad),
            Err(InspectError::Corrupt)
        ));
        let mut unknown = bytes;
        unknown[0] = 0xFF;
        assert!(matches!(
            identify_snapshot_object(&unknown, limits()),
            Err(InspectError::Corrupt)
        ));
    }

    #[test]
    fn small_complete_snapshot_agrees_with_old_full_graph_oracle() {
        let mut objects = BTreeMap::new();
        let (blob_id, blob_bytes) = encoded(&Object::Blob(Blob {
            data: b"ok".to_vec(),
        }));
        objects.insert(blob_id, blob_bytes.clone());
        let (tree_id, tree_bytes) = encoded(&Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"ok".to_vec(),
                mode: crate::object::EntryMode::Blob,
                object_hash: blob_id,
            }],
        }));
        objects.insert(tree_id, tree_bytes.clone());
        let key = KeyPair::from_seed([62; 32]);
        let mut commit = Commit::new_unannotated(
            tree_id,
            Vec::new(),
            Identity::ed25519(key.public.0),
            key.public.0,
            b"oracle".to_vec(),
            3,
            [0; 64],
        );
        commit.signature = sign_commit(&commit, &key).unwrap().0;
        let (root_id, root_bytes) = encoded(&Object::Commit(commit));
        objects.insert(root_id, root_bytes.clone());
        let mut source = OracleSource(objects);
        assert!(
            RecipientGraph::new(&mut source, RecipientLimits::default())
                .validate_base(root_id)
                .is_ok()
        );
        let limits = limits();
        assert_eq!(
            inspect_snapshot_object(root_id, &root_bytes, SnapshotRole::BaseRoot, limits)
                .unwrap()
                .root()
                .unwrap()
                .0,
            tree_id
        );
        assert_eq!(
            inspect_snapshot_object(tree_id, &tree_bytes, SnapshotRole::Tree, limits)
                .unwrap()
                .tree_page(0, 1)
                .unwrap()[0]
                .object_hash,
            blob_id
        );
        assert_eq!(
            inspect_snapshot_object(blob_id, &blob_bytes, SnapshotRole::File, limits)
                .unwrap()
                .blob_len(),
            Some(2)
        );
        source.0.remove(&blob_id);
        assert!(
            matches!(RecipientGraph::new(&mut source, RecipientLimits::default()).validate_base(root_id), Err(RecipientError::Missing(id)) if id == blob_id)
        );
        // The local inspections above are still true: they never implied the
        // referenced Blob was present in a complete source.
    }
}
