//! Producer and verifier for complete selected-file materialization.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::hash::Hash;
use crate::object::{EntryMode, Object, ObjectType, Tree};
use crate::serialize::{deserialize, serialize};
use crate::sign::{verify_commit, verify_remix};
use crate::store::{ObjectSource, StoreError};

use super::{PartialError, PartialLimits, PartialPath, PartialSnapshotBundle, validate_paths};

/// Honest coverage label for a verified partial snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartialCoverage {
    /// Selected files and their complete authenticated ancestor Trees only.
    SelectedOnly,
}

/// One complete authenticated ancestor Tree.
#[derive(Debug, Clone)]
pub struct VerifiedTree {
    id: Hash,
    tree: Tree,
}

impl VerifiedTree {
    #[must_use]
    pub fn id(&self) -> &Hash {
        &self.id
    }

    #[must_use]
    pub fn tree(&self) -> &Tree {
        &self.tree
    }
}

/// One selected regular/executable file and its verified representation.
#[derive(Debug, Clone)]
pub struct SelectedFile {
    path: PartialPath,
    mode: EntryMode,
    object_id: Hash,
    content_len: u64,
    chunk_ids: Arc<[Hash]>,
}

impl SelectedFile {
    #[must_use]
    pub fn path(&self) -> &PartialPath {
        &self.path
    }

    #[must_use]
    pub fn mode(&self) -> EntryMode {
        self.mode
    }

    #[must_use]
    pub fn object_id(&self) -> &Hash {
        &self.object_id
    }

    #[must_use]
    pub fn content_len(&self) -> u64 {
        self.content_len
    }

    #[must_use]
    pub fn chunk_ids(&self) -> &[Hash] {
        &self.chunk_ids
    }
}

/// Privately constructed result of atomic partial-snapshot verification.
#[derive(Debug, Clone)]
pub struct VerifiedPartialSnapshot {
    base_id: Hash,
    base: Object,
    signer: [u8; 32],
    paths: Vec<PartialPath>,
    trees: BTreeMap<Hash, VerifiedTree>,
    files: Vec<SelectedFile>,
    objects: BTreeMap<Hash, Vec<u8>>,
}

impl VerifiedPartialSnapshot {
    #[must_use]
    pub fn base_id(&self) -> &Hash {
        &self.base_id
    }

    #[must_use]
    pub fn base_object(&self) -> &Object {
        &self.base
    }

    /// Embedded signer key. This is a signature fact, not identity trust.
    #[must_use]
    pub fn signer(&self) -> &[u8; 32] {
        &self.signer
    }

    #[must_use]
    pub fn paths(&self) -> &[PartialPath] {
        &self.paths
    }

    #[must_use]
    pub fn coverage(&self) -> PartialCoverage {
        PartialCoverage::SelectedOnly
    }

    #[must_use]
    pub fn trees(&self) -> impl ExactSizeIterator<Item = &VerifiedTree> {
        self.trees.values()
    }

    #[must_use]
    pub fn files(&self) -> &[SelectedFile] {
        &self.files
    }

    /// Canonical bytes retained for the base, Trees, selected file
    /// representations, and chunks. No unrelated/history object is retained.
    #[must_use]
    pub fn object_bytes(&self, id: &Hash) -> Option<&[u8]> {
        self.objects.get(id).map(Vec::as_slice)
    }

    #[must_use]
    pub fn objects(&self) -> impl ExactSizeIterator<Item = (&Hash, &[u8])> {
        self.objects
            .iter()
            .map(|(id, bytes)| (id, bytes.as_slice()))
    }
}

/// Build a portable selected snapshot from a caller-bounded source.
///
/// `ObjectSource::read` returns an already allocated `Vec`; source
/// implementations therefore MUST impose their own read-allocation bound. This
/// function checks every returned length immediately, before decode or copy.
pub fn build_partial_snapshot<S: ObjectSource + ?Sized>(
    source: &S,
    base_id: Hash,
    selected_paths: &[PartialPath],
    limits: &PartialLimits,
) -> Result<PartialSnapshotBundle, PartialError> {
    validate_request(selected_paths, limits)?;
    let mut objects = BTreeMap::new();
    let base_bytes = read_source(source, &base_id, limits.max_base_object_bytes)?;
    let base = decode_checked(&base_id, &base_bytes, limits, DecodeRole::Base)?;
    let root = verify_base(&base)?;
    objects.insert(base_id, base_bytes);

    let mut witness_ids = BTreeSet::new();
    let mut witness_bytes = 0usize;
    let mut visits = 0usize;
    let mut total_selected = 0usize;
    let mut tree_cache = BTreeMap::new();
    let mut representation_cache = ProducerRepresentationCache::default();
    for path in selected_paths {
        let mut tree_id = root;
        for (index, component) in path.iter().enumerate() {
            visits = visits
                .checked_add(1)
                .ok_or(PartialError::ValidationBudgetExceeded)?;
            if visits > limits.max_tree_visits {
                return Err(PartialError::ValidationBudgetExceeded);
            }
            ensure_source_object(
                source,
                &mut objects,
                tree_id,
                limits.max_tree_object_bytes,
                limits,
            )?;
            let tree_bytes = objects
                .get(&tree_id)
                .ok_or(PartialError::InsufficientWitness)?;
            if witness_ids.insert(tree_id) {
                witness_bytes = checked_add(witness_bytes, tree_bytes.len())?;
                if witness_bytes > limits.max_witness_bytes {
                    return Err(PartialError::WitnessTooLarge);
                }
            }
            if let std::collections::btree_map::Entry::Vacant(entry) = tree_cache.entry(tree_id) {
                let Object::Tree(tree) =
                    decode_checked(&tree_id, tree_bytes, limits, DecodeRole::Tree)?
                else {
                    return Err(PartialError::WrongObjectType);
                };
                entry.insert(tree);
            }
            let tree = tree_cache
                .get(&tree_id)
                .ok_or(PartialError::InsufficientWitness)?;
            let entry = tree
                .entries
                .binary_search_by(|entry| entry.name.as_slice().cmp(component))
                .ok()
                .map(|position| &tree.entries[position])
                .ok_or(PartialError::IncompleteSelection)?;
            if index + 1 != path.len() {
                if entry.mode != EntryMode::Tree {
                    return Err(PartialError::WrongObjectType);
                }
                tree_id = entry.object_hash;
                continue;
            }
            if !matches!(entry.mode, EntryMode::Blob | EntryMode::Executable) {
                return Err(PartialError::UnsupportedPartialOperation);
            }
            collect_file(
                source,
                &mut objects,
                entry.object_hash,
                &mut total_selected,
                &mut representation_cache,
                limits,
            )?;
        }
    }
    let object_vec = objects.into_iter().collect();
    let bundle = PartialSnapshotBundle::new(base_id, selected_paths.to_vec(), object_vec, limits)?;
    // Self-verify the exact inventory before returning producer output.
    let encoded = bundle.encode(limits)?;
    verify_partial_snapshot(base_id, selected_paths, &encoded, limits)?;
    Ok(bundle)
}

/// Verify a bundle against an independently supplied trust root and exact
/// selection. No host grant, owner, policy database, clock, or I/O is used.
pub fn verify_partial_snapshot(
    expected_base: Hash,
    expected_paths: &[PartialPath],
    bundle_bytes: &[u8],
    limits: &PartialLimits,
) -> Result<VerifiedPartialSnapshot, PartialError> {
    validate_request(expected_paths, limits)?;
    let bundle = PartialSnapshotBundle::decode(bundle_bytes, limits)?;
    let (base_id, paths, objects) = bundle.into_parts();
    if base_id != expected_base {
        return Err(PartialError::BaseMismatch);
    }
    if paths != expected_paths {
        return Err(PartialError::SelectionMismatch);
    }
    let objects: BTreeMap<_, _> = objects.into_iter().collect();
    verify_object_set(base_id, paths, objects, limits)
}

fn verify_object_set(
    base_id: Hash,
    paths: Vec<PartialPath>,
    objects: BTreeMap<Hash, Vec<u8>>,
    limits: &PartialLimits,
) -> Result<VerifiedPartialSnapshot, PartialError> {
    let base_bytes = objects
        .get(&base_id)
        .ok_or(PartialError::InsufficientWitness)?;
    let base = decode_checked(&base_id, base_bytes, limits, DecodeRole::Base)?;
    let root = verify_base(&base)?;
    let signer = match &base {
        Object::Commit(commit) => commit.signer,
        Object::Remix(remix) => remix.signer,
        _ => return Err(PartialError::WrongObjectType),
    };
    let mut required = BTreeSet::from([base_id]);
    let mut trees = BTreeMap::new();
    let mut files = Vec::with_capacity(paths.len());
    let mut witness_bytes = 0usize;
    let mut visits = 0usize;
    let mut total_selected = 0usize;
    let mut representation_cache = VerifierRepresentationCache::default();

    for path in &paths {
        let mut tree_id = root;
        for (index, component) in path.iter().enumerate() {
            visits = visits
                .checked_add(1)
                .ok_or(PartialError::ValidationBudgetExceeded)?;
            if visits > limits.max_tree_visits {
                return Err(PartialError::ValidationBudgetExceeded);
            }
            let tree_bytes = objects
                .get(&tree_id)
                .ok_or(PartialError::InsufficientWitness)?;
            if let std::collections::btree_map::Entry::Vacant(entry) = trees.entry(tree_id) {
                let Object::Tree(tree) =
                    decode_checked(&tree_id, tree_bytes, limits, DecodeRole::Tree)?
                else {
                    return Err(PartialError::WrongObjectType);
                };
                witness_bytes = checked_add(witness_bytes, tree_bytes.len())?;
                if witness_bytes > limits.max_witness_bytes {
                    return Err(PartialError::WitnessTooLarge);
                }
                entry.insert(VerifiedTree { id: tree_id, tree });
            }
            required.insert(tree_id);
            let tree = trees
                .get(&tree_id)
                .ok_or(PartialError::InsufficientWitness)?
                .tree();
            let entry = tree
                .entries
                .binary_search_by(|entry| entry.name.as_slice().cmp(component))
                .ok()
                .map(|position| &tree.entries[position])
                .ok_or(PartialError::IncompleteSelection)?;
            if index + 1 != path.len() {
                if entry.mode != EntryMode::Tree {
                    return Err(PartialError::WrongObjectType);
                }
                tree_id = entry.object_hash;
                continue;
            }
            if !matches!(entry.mode, EntryMode::Blob | EntryMode::Executable) {
                return Err(PartialError::UnsupportedPartialOperation);
            }
            files.push(verify_file(
                path.clone(),
                entry.mode,
                entry.object_hash,
                &objects,
                &mut required,
                &mut total_selected,
                &mut representation_cache,
                limits,
            )?);
        }
    }
    if required.len() != objects.len() || objects.keys().any(|id| !required.contains(id)) {
        return Err(PartialError::NonCanonical);
    }
    Ok(VerifiedPartialSnapshot {
        base_id,
        base,
        signer,
        paths,
        trees,
        files,
        objects,
    })
}

fn verify_file(
    path: PartialPath,
    mode: EntryMode,
    id: Hash,
    objects: &BTreeMap<Hash, Vec<u8>>,
    required: &mut BTreeSet<Hash>,
    total_selected: &mut usize,
    cache: &mut VerifierRepresentationCache,
    limits: &PartialLimits,
) -> Result<SelectedFile, PartialError> {
    let representation = if let Some(representation) = cache.files.get(&id) {
        representation.clone()
    } else {
        let bytes = objects.get(&id).ok_or(PartialError::InsufficientWitness)?;
        let object = decode_checked(&id, bytes, limits, DecodeRole::File)?;
        required.insert(id);
        let representation = match object {
            Object::Blob(blob) => VerifiedFileRepresentation {
                content_len: blob.data.len() as u64,
                chunk_ids: Arc::from([]),
            },
            Object::ChunkedBlob(manifest) => {
                validate_manifest_size(&manifest, limits)?;
                let mut sum = 0u64;
                for (index, chunk_id) in manifest.chunks.iter().enumerate() {
                    let chunk_len = if let Some(len) = cache.chunks.get(chunk_id) {
                        *len
                    } else {
                        let chunk_bytes = objects
                            .get(chunk_id)
                            .ok_or(PartialError::InsufficientWitness)?;
                        let Object::Blob(chunk) =
                            decode_checked(chunk_id, chunk_bytes, limits, DecodeRole::Chunk)?
                        else {
                            return Err(PartialError::WrongObjectType);
                        };
                        let len = chunk.data.len();
                        cache.chunks.insert(*chunk_id, len);
                        len
                    };
                    required.insert(*chunk_id);
                    validate_chunk_occurrence(&manifest, index, chunk_len)?;
                    sum = sum
                        .checked_add(chunk_len as u64)
                        .ok_or(PartialError::InvalidChunkLayout)?;
                }
                if sum != manifest.total_size {
                    return Err(PartialError::InvalidChunkLayout);
                }
                VerifiedFileRepresentation {
                    content_len: manifest.total_size,
                    chunk_ids: manifest.chunks.into(),
                }
            }
            _ => return Err(PartialError::WrongObjectType),
        };
        cache.files.insert(id, representation.clone());
        representation
    };
    let content_len_usize =
        usize::try_from(representation.content_len).map_err(|_| PartialError::WorkspaceTooLarge)?;
    if content_len_usize > limits.max_selected_file_bytes {
        return Err(PartialError::WorkspaceTooLarge);
    }
    *total_selected = checked_add(*total_selected, content_len_usize)?;
    if *total_selected > limits.max_total_selected_bytes {
        return Err(PartialError::WorkspaceTooLarge);
    }
    Ok(SelectedFile {
        path,
        mode,
        object_id: id,
        content_len: representation.content_len,
        chunk_ids: representation.chunk_ids,
    })
}

#[derive(Clone)]
struct VerifiedFileRepresentation {
    content_len: u64,
    chunk_ids: Arc<[Hash]>,
}

#[derive(Default)]
struct VerifierRepresentationCache {
    files: BTreeMap<Hash, VerifiedFileRepresentation>,
    chunks: BTreeMap<Hash, usize>,
}

#[derive(Default)]
struct ProducerRepresentationCache {
    files: BTreeMap<Hash, usize>,
    chunks: BTreeMap<Hash, usize>,
}

fn collect_file<S: ObjectSource + ?Sized>(
    source: &S,
    objects: &mut BTreeMap<Hash, Vec<u8>>,
    id: Hash,
    total_selected: &mut usize,
    cache: &mut ProducerRepresentationCache,
    limits: &PartialLimits,
) -> Result<(), PartialError> {
    if let Some(file_len) = cache.files.get(&id) {
        return add_selected(total_selected, *file_len, limits);
    }
    ensure_source_object(source, objects, id, limits.max_object_bytes, limits)?;
    let object = decode_checked(
        &id,
        objects.get(&id).ok_or(PartialError::InsufficientWitness)?,
        limits,
        DecodeRole::File,
    )?;
    let file_len = match object {
        Object::Blob(blob) => blob.data.len(),
        Object::ChunkedBlob(manifest) => {
            validate_manifest_size(&manifest, limits)?;
            let mut sum = 0u64;
            for (index, chunk_id) in manifest.chunks.iter().copied().enumerate() {
                ensure_source_object(source, objects, chunk_id, limits.max_object_bytes, limits)?;
                let chunk_len = if let Some(len) = cache.chunks.get(&chunk_id) {
                    *len
                } else {
                    let Object::Blob(chunk) = decode_checked(
                        &chunk_id,
                        objects
                            .get(&chunk_id)
                            .ok_or(PartialError::InsufficientWitness)?,
                        limits,
                        DecodeRole::Chunk,
                    )?
                    else {
                        return Err(PartialError::WrongObjectType);
                    };
                    let len = chunk.data.len();
                    cache.chunks.insert(chunk_id, len);
                    len
                };
                validate_chunk_occurrence(&manifest, index, chunk_len)?;
                sum = sum
                    .checked_add(chunk_len as u64)
                    .ok_or(PartialError::InvalidChunkLayout)?;
            }
            if sum != manifest.total_size {
                return Err(PartialError::InvalidChunkLayout);
            }
            usize::try_from(manifest.total_size).map_err(|_| PartialError::WorkspaceTooLarge)?
        }
        _ => return Err(PartialError::WrongObjectType),
    };
    cache.files.insert(id, file_len);
    add_selected(total_selected, file_len, limits)
}

fn add_selected(
    total: &mut usize,
    file_len: usize,
    limits: &PartialLimits,
) -> Result<(), PartialError> {
    if file_len > limits.max_selected_file_bytes {
        return Err(PartialError::WorkspaceTooLarge);
    }
    *total = checked_add(*total, file_len)?;
    if *total > limits.max_total_selected_bytes {
        return Err(PartialError::WorkspaceTooLarge);
    }
    Ok(())
}

fn validate_manifest_size(
    manifest: &crate::object::ChunkedBlob,
    limits: &PartialLimits,
) -> Result<(), PartialError> {
    if manifest.total_size > limits.max_selected_file_bytes as u64 {
        return Err(PartialError::WorkspaceTooLarge);
    }
    if manifest.chunks.is_empty() != (manifest.total_size == 0) {
        return Err(PartialError::InvalidChunkLayout);
    }
    Ok(())
}

fn validate_chunk_occurrence(
    manifest: &crate::object::ChunkedBlob,
    index: usize,
    actual: usize,
) -> Result<(), PartialError> {
    if manifest.chunk_size == 0 {
        return Ok(());
    }
    let fixed = manifest.chunk_size as usize;
    let final_chunk = index + 1 == manifest.chunks.len();
    if actual == 0 || (!final_chunk && actual != fixed) || (final_chunk && actual > fixed) {
        return Err(PartialError::InvalidChunkLayout);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum DecodeRole {
    Base,
    Tree,
    File,
    Chunk,
}

fn decode_checked(
    expected: &Hash,
    bytes: &[u8],
    limits: &PartialLimits,
    role: DecodeRole,
) -> Result<Object, PartialError> {
    if bytes.is_empty() || bytes.len() > limits.max_object_bytes {
        return Err(PartialError::WitnessTooLarge);
    }
    match role {
        DecodeRole::Base if bytes.len() > limits.max_base_object_bytes => {
            return Err(PartialError::WitnessTooLarge);
        }
        DecodeRole::Tree => preflight_tree(bytes, limits)?,
        DecodeRole::File => preflight_file(bytes, limits)?,
        DecodeRole::Base | DecodeRole::Chunk => {}
    }
    let object = deserialize(bytes).map_err(|_| PartialError::NonCanonical)?;
    if serialize(&object).map_err(|_| PartialError::NonCanonical)? != bytes
        || crate::object::id_from_object(&object, bytes) != *expected
    {
        return Err(PartialError::NonCanonical);
    }
    let expected_type = match role {
        DecodeRole::Base => matches!(object, Object::Commit(_) | Object::Remix(_)),
        DecodeRole::Tree => matches!(object, Object::Tree(_)),
        DecodeRole::File => matches!(object, Object::Blob(_) | Object::ChunkedBlob(_)),
        DecodeRole::Chunk => matches!(object, Object::Blob(_)),
    };
    if !expected_type {
        return Err(PartialError::WrongObjectType);
    }
    Ok(object)
}

fn preflight_tree(bytes: &[u8], limits: &PartialLimits) -> Result<(), PartialError> {
    if bytes.len() > limits.max_tree_object_bytes {
        return Err(PartialError::WitnessTooLarge);
    }
    if bytes.first() != Some(&(ObjectType::Tree as u8)) || bytes.len() < 10 {
        return Err(PartialError::WrongObjectType);
    }
    let count = u32::from_le_bytes(
        bytes[6..10]
            .try_into()
            .map_err(|_| PartialError::NonCanonical)?,
    ) as usize;
    if count > limits.max_tree_entries {
        return Err(PartialError::ValidationBudgetExceeded);
    }
    Ok(())
}

fn preflight_file(bytes: &[u8], limits: &PartialLimits) -> Result<(), PartialError> {
    match bytes.first().copied() {
        Some(tag) if tag == ObjectType::Blob as u8 => {
            if bytes.len() < 10 {
                return Err(PartialError::NonCanonical);
            }
            let len = u32::from_le_bytes(
                bytes[6..10]
                    .try_into()
                    .map_err(|_| PartialError::NonCanonical)?,
            ) as usize;
            if len > limits.max_selected_file_bytes {
                return Err(PartialError::WorkspaceTooLarge);
            }
        }
        Some(tag) if tag == ObjectType::ChunkedBlob as u8 => {
            if bytes.len() < 22 {
                return Err(PartialError::NonCanonical);
            }
            let total = u64::from_le_bytes(
                bytes[6..14]
                    .try_into()
                    .map_err(|_| PartialError::NonCanonical)?,
            );
            if total > limits.max_selected_file_bytes as u64 {
                return Err(PartialError::WorkspaceTooLarge);
            }
        }
        _ => return Err(PartialError::WrongObjectType),
    }
    Ok(())
}

fn verify_base(base: &Object) -> Result<Hash, PartialError> {
    match base {
        Object::Commit(commit) => {
            verify_commit(commit).map_err(|_| PartialError::InvalidSignature)?;
            Ok(commit.tree_hash)
        }
        Object::Remix(remix) => {
            verify_remix(remix).map_err(|_| PartialError::InvalidSignature)?;
            Ok(remix.tree_hash)
        }
        _ => Err(PartialError::WrongObjectType),
    }
}

fn ensure_source_object<S: ObjectSource + ?Sized>(
    source: &S,
    objects: &mut BTreeMap<Hash, Vec<u8>>,
    id: Hash,
    cap: usize,
    limits: &PartialLimits,
) -> Result<(), PartialError> {
    if objects.contains_key(&id) {
        return Ok(());
    }
    if objects.len() >= limits.max_objects {
        return Err(PartialError::ValidationBudgetExceeded);
    }
    let bytes = read_source(source, &id, cap.min(limits.max_object_bytes))?;
    objects.insert(id, bytes);
    Ok(())
}

fn read_source<S: ObjectSource + ?Sized>(
    source: &S,
    id: &Hash,
    cap: usize,
) -> Result<Vec<u8>, PartialError> {
    let bytes = match source.read(id) {
        Ok(bytes) => bytes,
        Err(StoreError::ObjectNotFound(_)) => return Err(PartialError::InsufficientWitness),
        Err(error) => return Err(PartialError::Source(error)),
    };
    if bytes.is_empty() || bytes.len() > cap {
        return Err(PartialError::WitnessTooLarge);
    }
    Ok(bytes)
}

fn validate_request(paths: &[PartialPath], limits: &PartialLimits) -> Result<(), PartialError> {
    if !limits.is_v1_subset() {
        return Err(PartialError::ValidationBudgetExceeded);
    }
    validate_paths(paths, limits)
}

fn checked_add(a: usize, b: usize) -> Result<usize, PartialError> {
    a.checked_add(b).ok_or(PartialError::WorkspaceTooLarge)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use commonware_codec::Write;

    use crate::hash::ZERO;
    use crate::object::{Blob, ChunkedBlob, Commit, Identity, TreeEntry};
    use crate::ops::ClosureMode;
    use crate::sign::{KeyPair, sign_commit};
    use crate::store::StoreResult;

    use super::*;

    struct CountingSource {
        objects: BTreeMap<Hash, Vec<u8>>,
        reads: RefCell<Vec<Hash>>,
    }

    impl ObjectSource for CountingSource {
        fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
            self.reads.borrow_mut().push(*id);
            self.objects
                .get(id)
                .cloned()
                .ok_or_else(|| StoreError::ObjectNotFound(crate::hash::to_hex(id)))
        }
    }

    struct Fixture {
        source: CountingSource,
        base_id: Hash,
        paths: Vec<PartialPath>,
        hidden_tree: Hash,
        hidden_blob: Hash,
        chunk: Hash,
    }

    #[allow(clippy::needless_pass_by_value)]
    fn insert(objects: &mut BTreeMap<Hash, Vec<u8>>, object: Object) -> Hash {
        let bytes = serialize(&object).unwrap();
        let id = crate::object::id_from_object(&object, &bytes);
        objects.insert(id, bytes);
        id
    }

    #[allow(clippy::too_many_lines)]
    fn fixture() -> Fixture {
        let mut objects = BTreeMap::new();
        let plain = insert(
            &mut objects,
            Object::Blob(Blob {
                data: b"plain selected bytes".to_vec(),
            }),
        );
        let chunk = insert(
            &mut objects,
            Object::Blob(Blob {
                data: b"shared chunk".to_vec(),
            }),
        );
        let chunked = insert(
            &mut objects,
            Object::ChunkedBlob(ChunkedBlob {
                total_size: 24,
                chunk_size: 0,
                chunks: vec![chunk, chunk],
            }),
        );
        let child = insert(
            &mut objects,
            Object::Tree(Tree {
                entries: vec![
                    TreeEntry {
                        name: b"a.txt".to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: plain,
                    },
                    TreeEntry {
                        name: b"b.bin".to_vec(),
                        mode: EntryMode::Executable,
                        object_hash: chunked,
                    },
                    TreeEntry {
                        name: b"c.bin".to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: chunked,
                    },
                ],
            }),
        );
        let hidden_blob = insert(
            &mut objects,
            Object::Blob(Blob {
                data: b"must not be fetched".to_vec(),
            }),
        );
        let hidden_tree = insert(
            &mut objects,
            Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"secret.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: hidden_blob,
                }],
            }),
        );
        let root = insert(
            &mut objects,
            Object::Tree(Tree {
                entries: vec![
                    TreeEntry {
                        name: b"dir".to_vec(),
                        mode: EntryMode::Tree,
                        object_hash: child,
                    },
                    TreeEntry {
                        name: b"hidden".to_vec(),
                        mode: EntryMode::Tree,
                        object_hash: hidden_tree,
                    },
                ],
            }),
        );
        let key = KeyPair::from_seed([9; 32]);
        let mut commit = Commit::new_unannotated(
            root,
            Vec::new(),
            Identity::ed25519(key.public.0),
            key.public.0,
            b"partial fixture".to_vec(),
            1_700_000_000,
            [0; 64],
        );
        commit.signature = sign_commit(&commit, &key).unwrap().0;
        let base_id = insert(&mut objects, Object::Commit(commit));
        Fixture {
            source: CountingSource {
                objects,
                reads: RefCell::new(Vec::new()),
            },
            base_id,
            paths: vec![
                vec![b"dir".to_vec(), b"a.txt".to_vec()],
                vec![b"dir".to_vec(), b"b.bin".to_vec()],
                vec![b"dir".to_vec(), b"c.bin".to_vec()],
            ],
            hidden_tree,
            hidden_blob,
            chunk,
        }
    }

    fn signed_file_bundle(
        mut objects: BTreeMap<Hash, Vec<u8>>,
        file: Object,
        names: &[&[u8]],
        limits: &PartialLimits,
    ) -> (Hash, Vec<PartialPath>, Vec<u8>) {
        let file_id = insert(&mut objects, file);
        let root = insert(
            &mut objects,
            Object::Tree(Tree {
                entries: names
                    .iter()
                    .map(|name| TreeEntry {
                        name: name.to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: file_id,
                    })
                    .collect(),
            }),
        );
        let key = KeyPair::from_seed([19; 32]);
        let mut commit = Commit::new_unannotated(
            root,
            Vec::new(),
            Identity::ed25519(key.public.0),
            key.public.0,
            b"partial layout fixture".to_vec(),
            1_700_000_001,
            [0; 64],
        );
        commit.signature = sign_commit(&commit, &key).unwrap().0;
        let base_id = insert(&mut objects, Object::Commit(commit));
        let paths: Vec<_> = names.iter().map(|name| vec![name.to_vec()]).collect();
        let bundle = PartialSnapshotBundle::new(
            base_id,
            paths.clone(),
            objects.into_iter().collect(),
            limits,
        )
        .unwrap()
        .encode(limits)
        .unwrap();
        (base_id, paths, bundle)
    }

    #[test]
    fn producer_and_verifier_retain_exact_selected_materialization() {
        let fixture = fixture();
        let limits = PartialLimits::default();
        let bundle =
            build_partial_snapshot(&fixture.source, fixture.base_id, &fixture.paths, &limits)
                .unwrap();
        let encoded = bundle.encode(&limits).unwrap();
        let verified =
            verify_partial_snapshot(fixture.base_id, &fixture.paths, &encoded, &limits).unwrap();

        assert_eq!(verified.coverage(), PartialCoverage::SelectedOnly);
        assert_eq!(verified.files().len(), 3);
        assert_eq!(verified.trees().len(), 2);
        assert_eq!(
            verified.files()[1].chunk_ids(),
            &[fixture.chunk, fixture.chunk]
        );
        assert_eq!(
            verified.files()[1].object_id(),
            verified.files()[2].object_id(),
            "distinct selected files may share one representation"
        );
        assert!(Arc::ptr_eq(
            &verified.files()[1].chunk_ids,
            &verified.files()[2].chunk_ids
        ));
        assert!(!fixture.source.reads.borrow().contains(&fixture.hidden_tree));
        assert!(!fixture.source.reads.borrow().contains(&fixture.hidden_blob));

        let report = crate::verify::verify_closure(
            &fixture.base_id,
            ClosureMode::Snapshot,
            verified.objects().map(|(_, bytes)| bytes),
        )
        .unwrap();
        assert!(
            !report.is_complete(),
            "selected coverage is not full closure"
        );
        assert!(report.missing.contains(&fixture.hidden_tree));
    }

    #[test]
    fn independent_base_selection_and_exact_inventory_are_enforced() {
        let fixture = fixture();
        let limits = PartialLimits::default();
        let bundle =
            build_partial_snapshot(&fixture.source, fixture.base_id, &fixture.paths, &limits)
                .unwrap();
        let bytes = bundle.encode(&limits).unwrap();
        assert!(matches!(
            verify_partial_snapshot([7; 32], &fixture.paths, &bytes, &limits),
            Err(PartialError::BaseMismatch)
        ));
        assert!(matches!(
            verify_partial_snapshot(
                fixture.base_id,
                &[fixture.paths[0].clone()],
                &bytes,
                &limits
            ),
            Err(PartialError::SelectionMismatch)
        ));

        let (_, paths, mut objects) = bundle.into_parts();
        let extra = fixture
            .source
            .objects
            .get(&fixture.hidden_blob)
            .unwrap()
            .clone();
        objects.push((fixture.hidden_blob, extra));
        objects.sort_by_key(|(id, _)| *id);
        let with_extra = PartialSnapshotBundle::new(fixture.base_id, paths, objects, &limits)
            .unwrap()
            .encode(&limits)
            .unwrap();
        assert!(matches!(
            verify_partial_snapshot(fixture.base_id, &fixture.paths, &with_extra, &limits),
            Err(PartialError::NonCanonical)
        ));
    }

    #[test]
    fn missing_chunk_signature_failure_and_trailing_bytes_reject_atomically() {
        let fixture = fixture();
        let limits = PartialLimits::default();
        let bundle =
            build_partial_snapshot(&fixture.source, fixture.base_id, &fixture.paths, &limits)
                .unwrap();
        let (_, paths, objects) = bundle.clone().into_parts();
        let missing = PartialSnapshotBundle::new(
            fixture.base_id,
            paths,
            objects
                .into_iter()
                .filter(|(id, _)| *id != fixture.chunk)
                .collect(),
            &limits,
        )
        .unwrap()
        .encode(&limits)
        .unwrap();
        assert!(matches!(
            verify_partial_snapshot(fixture.base_id, &fixture.paths, &missing, &limits),
            Err(PartialError::InsufficientWitness)
        ));

        let mut trailing = bundle.encode(&limits).unwrap();
        trailing.push(0);
        assert!(matches!(
            verify_partial_snapshot(fixture.base_id, &fixture.paths, &trailing, &limits),
            Err(PartialError::NonCanonical)
        ));

        let Object::Commit(mut commit) =
            deserialize(fixture.source.objects.get(&fixture.base_id).unwrap()).unwrap()
        else {
            panic!("fixture base must be a commit");
        };
        commit.signature = [0; 64];
        let bad_bytes = serialize(&Object::Commit(commit)).unwrap();
        let bad_id = crate::hash::hash(&bad_bytes);
        let (_, paths, mut objects) = bundle.into_parts();
        objects.retain(|(id, _)| *id != fixture.base_id);
        objects.push((bad_id, bad_bytes));
        objects.sort_by_key(|(id, _)| *id);
        let invalid_signature =
            PartialSnapshotBundle::new(bad_id, paths, objects, &limits).unwrap();
        assert!(matches!(
            verify_partial_snapshot(
                bad_id,
                &fixture.paths,
                &invalid_signature.encode(&limits).unwrap(),
                &limits
            ),
            Err(PartialError::InvalidSignature)
        ));
    }

    #[test]
    fn paths_and_limits_reject_before_materialization() {
        let limits = PartialLimits::default();
        for paths in [
            vec![vec![b"bad\nname".to_vec()]],
            vec![vec![b".MKIT-SCOPED".to_vec(), b"x".to_vec()]],
            vec![vec![b"b".to_vec()], vec![b"a".to_vec()]],
            vec![vec![b"a".to_vec()], vec![b"a".to_vec()]],
        ] {
            assert!(validate_paths(&paths, &limits).is_err());
        }
        let mut widened = limits;
        widened.max_bundle_bytes += 1;
        assert!(matches!(
            validate_request(&[vec![b"a".to_vec()]], &widened),
            Err(PartialError::ValidationBudgetExceeded)
        ));

        let fixture = fixture();
        assert!(matches!(
            build_partial_snapshot(
                &fixture.source,
                fixture.base_id,
                &[vec![
                    b"dir".to_vec(),
                    b"b.bin".to_vec(),
                    b"not-a-tree".to_vec()
                ]],
                &limits
            ),
            Err(PartialError::WrongObjectType)
        ));
    }

    #[test]
    fn missing_or_mutated_required_objects_and_lower_limits_reject() {
        let fixture = fixture();
        let limits = PartialLimits::default();
        let bundle =
            build_partial_snapshot(&fixture.source, fixture.base_id, &fixture.paths, &limits)
                .unwrap();
        let encoded = bundle.encode(&limits).unwrap();
        let verified =
            verify_partial_snapshot(fixture.base_id, &fixture.paths, &encoded, &limits).unwrap();
        let tree_id = *verified.trees().next().unwrap().id();
        let file_id = *verified.files()[0].object_id();
        let (_, paths, objects) = bundle.into_parts();

        for omitted in [tree_id, file_id] {
            let bytes = PartialSnapshotBundle::new(
                fixture.base_id,
                paths.clone(),
                objects
                    .iter()
                    .filter(|(id, _)| *id != omitted)
                    .cloned()
                    .collect(),
                &limits,
            )
            .unwrap()
            .encode(&limits)
            .unwrap();
            assert!(matches!(
                verify_partial_snapshot(fixture.base_id, &fixture.paths, &bytes, &limits),
                Err(PartialError::InsufficientWitness)
            ));
        }

        let mut mutated = objects.clone();
        let tree_bytes = &mut mutated.iter_mut().find(|(id, _)| *id == tree_id).unwrap().1;
        *tree_bytes.last_mut().unwrap() ^= 1;
        let bytes = PartialSnapshotBundle::new(fixture.base_id, paths, mutated, &limits)
            .unwrap()
            .encode(&limits)
            .unwrap();
        assert!(matches!(
            verify_partial_snapshot(fixture.base_id, &fixture.paths, &bytes, &limits),
            Err(PartialError::NonCanonical)
        ));

        let mut lower = limits;
        lower.max_selected_file_bytes = b"shared chunkshared chunk".len() - 1;
        assert!(matches!(
            verify_partial_snapshot(fixture.base_id, &fixture.paths, &encoded, &lower),
            Err(PartialError::WorkspaceTooLarge)
        ));
    }

    #[test]
    fn fixed_and_cdc_layouts_verify_end_to_end() {
        let limits = PartialLimits::default();
        let mut fixed_objects = BTreeMap::new();
        let first = insert(
            &mut fixed_objects,
            Object::Blob(Blob {
                data: b"abcd".to_vec(),
            }),
        );
        let last = insert(&mut fixed_objects, Object::Blob(Blob { data: vec![b'e'] }));
        let fixed = Object::ChunkedBlob(ChunkedBlob {
            total_size: 5,
            chunk_size: 4,
            chunks: vec![first, last],
        });
        let (base, paths, bytes) =
            signed_file_bundle(fixed_objects, fixed, &[b"fixed.bin"], &limits);
        let verified = verify_partial_snapshot(base, &paths, &bytes, &limits).unwrap();
        assert_eq!(verified.files()[0].content_len(), 5);

        let fixture = fixture();
        let cdc = build_partial_snapshot(&fixture.source, fixture.base_id, &fixture.paths, &limits)
            .unwrap()
            .encode(&limits)
            .unwrap();
        assert!(verify_partial_snapshot(fixture.base_id, &fixture.paths, &cdc, &limits).is_ok());
    }

    #[test]
    fn wrong_type_chunk_and_incorrect_total_reject_end_to_end() {
        let limits = PartialLimits::default();
        let mut wrong_type_objects = BTreeMap::new();
        let wrong_type = insert(
            &mut wrong_type_objects,
            Object::Tree(Tree {
                entries: Vec::new(),
            }),
        );
        let manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: 1,
            chunk_size: 0,
            chunks: vec![wrong_type],
        });
        let (base, paths, bytes) =
            signed_file_bundle(wrong_type_objects, manifest, &[b"wrong-type.bin"], &limits);
        assert!(matches!(
            verify_partial_snapshot(base, &paths, &bytes, &limits),
            Err(PartialError::WrongObjectType)
        ));

        let mut incorrect_objects = BTreeMap::new();
        let chunk = insert(
            &mut incorrect_objects,
            Object::Blob(Blob {
                data: b"abc".to_vec(),
            }),
        );
        let manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: 4,
            chunk_size: 0,
            chunks: vec![chunk],
        });
        let (base, paths, bytes) =
            signed_file_bundle(incorrect_objects, manifest, &[b"wrong-total.bin"], &limits);
        assert!(matches!(
            verify_partial_snapshot(base, &paths, &bytes, &limits),
            Err(PartialError::InvalidChunkLayout)
        ));
    }

    #[test]
    fn shared_large_manifest_is_verified_and_retained_once() {
        let limits = PartialLimits::default();
        let mut objects = BTreeMap::new();
        let one = insert(&mut objects, Object::Blob(Blob { data: vec![1] }));
        let empty = insert(&mut objects, Object::Blob(Blob { data: Vec::new() }));
        let mut chunks = Vec::with_capacity(10_000);
        chunks.push(one);
        chunks.resize(10_000, empty);
        let manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: 1,
            chunk_size: 0,
            chunks,
        });
        let (base, paths, bytes) =
            signed_file_bundle(objects, manifest, &[b"a.bin", b"b.bin"], &limits);
        let (_, _, object_pairs) = PartialSnapshotBundle::decode(&bytes, &limits)
            .unwrap()
            .into_parts();
        let source = CountingSource {
            objects: object_pairs.into_iter().collect(),
            reads: RefCell::new(Vec::new()),
        };
        let produced = build_partial_snapshot(&source, base, &paths, &limits)
            .unwrap()
            .encode(&limits)
            .unwrap();
        let verified = verify_partial_snapshot(base, &paths, &produced, &limits).unwrap();
        assert_eq!(verified.files()[0].chunk_ids().len(), 10_000);
        assert!(Arc::ptr_eq(
            &verified.files()[0].chunk_ids,
            &verified.files()[1].chunk_ids
        ));
    }

    #[test]
    fn decoder_enforces_joined_path_and_raw_count_and_size_caps() {
        let limits = PartialLimits {
            max_path_bytes: 8,
            ..PartialLimits::default()
        };
        let mut joined = Vec::from(&b"MKWB"[..]);
        joined.push(1);
        joined.extend_from_slice(&ZERO);
        1usize.write(&mut joined);
        2usize.write(&mut joined);
        b"aaaa".as_slice().write(&mut joined);
        b"bbbb".as_slice().write(&mut joined);
        assert!(matches!(
            PartialSnapshotBundle::decode(&joined, &limits),
            Err(PartialError::WorkspaceTooLarge)
        ));

        let mut count = Vec::from(&b"MKWB"[..]);
        count.push(1);
        count.extend_from_slice(&ZERO);
        (limits.max_selected_paths + 1).write(&mut count);
        assert!(matches!(
            PartialSnapshotBundle::decode(&count, &limits),
            Err(PartialError::NonCanonical)
        ));

        let aggregate_limits = PartialLimits {
            max_total_path_bytes: 7,
            ..PartialLimits::default()
        };
        let mut aggregate = Vec::from(&b"MKWB"[..]);
        aggregate.push(1);
        aggregate.extend_from_slice(&ZERO);
        2usize.write(&mut aggregate);
        for component in [b"aaaa".as_slice(), b"bbbb".as_slice()] {
            1usize.write(&mut aggregate);
            component.write(&mut aggregate);
        }
        assert!(matches!(
            PartialSnapshotBundle::decode(&aggregate, &aggregate_limits),
            Err(PartialError::WorkspaceTooLarge)
        ));

        let mut object_count = Vec::from(&b"MKWB"[..]);
        object_count.push(1);
        object_count.extend_from_slice(&ZERO);
        1usize.write(&mut object_count);
        1usize.write(&mut object_count);
        b"a".as_slice().write(&mut object_count);
        (limits.max_objects + 1).write(&mut object_count);
        assert!(matches!(
            PartialSnapshotBundle::decode(&object_count, &limits),
            Err(PartialError::NonCanonical)
        ));

        let mut object_size = Vec::from(&b"MKWB"[..]);
        object_size.push(1);
        object_size.extend_from_slice(&ZERO);
        1usize.write(&mut object_size);
        1usize.write(&mut object_size);
        b"a".as_slice().write(&mut object_size);
        1usize.write(&mut object_size);
        ZERO.write(&mut object_size);
        (limits.max_object_bytes + 1).write(&mut object_size);
        assert!(matches!(
            PartialSnapshotBundle::decode(&object_size, &limits),
            Err(PartialError::NonCanonical)
        ));

        let oversized = vec![0; limits.max_bundle_bytes + 1];
        assert!(matches!(
            PartialSnapshotBundle::decode(&oversized, &limits),
            Err(PartialError::WorkspaceTooLarge)
        ));
    }

    #[test]
    fn declared_huge_file_is_rejected_by_preflight() {
        let limits = PartialLimits::default();
        let object = Object::ChunkedBlob(ChunkedBlob {
            total_size: limits.max_selected_file_bytes as u64 + 1,
            chunk_size: 0,
            chunks: Vec::new(),
        });
        let bytes = serialize(&object).unwrap();
        let id = object.id().unwrap();
        assert!(matches!(
            decode_checked(&id, &bytes, &limits, DecodeRole::File),
            Err(PartialError::WorkspaceTooLarge)
        ));
    }

    #[test]
    fn malformed_nonminimal_length_is_noncanonical() {
        let limits = PartialLimits::default();
        let mut bytes = Vec::from(&b"MKWB"[..]);
        bytes.push(1);
        bytes.extend_from_slice(&ZERO);
        // Non-minimal varint for path count 1.
        bytes.extend_from_slice(&[0x81, 0x00]);
        assert!(matches!(
            PartialSnapshotBundle::decode(&bytes, &limits),
            Err(PartialError::NonCanonical)
        ));
    }
}
