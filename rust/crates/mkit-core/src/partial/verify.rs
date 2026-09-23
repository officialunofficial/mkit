//! Producer and verifier for complete selected-file materialization.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::hash::Hash;
use crate::object::{ChunkedBlob, EntryMode, Object, ObjectType, Tree};
use crate::serialize::{deserialize, serialize};
use crate::sign::{verify_commit, verify_remix};
use crate::store::{ObjectSource, StoreError};

use super::bundle::BundleBudget;
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
/// implementations therefore MUST impose their own per-read allocation bound.
/// This function checks every returned length immediately and charges the exact
/// encoded bundle framing before retaining it. The current returned `Vec`,
/// decoded objects, and caches are separate bounded overhead, so the bundle
/// limit is not an exact process-RSS limit.
pub fn build_partial_snapshot<S: ObjectSource + ?Sized>(
    source: &S,
    base_id: Hash,
    selected_paths: &[PartialPath],
    limits: &PartialLimits,
) -> Result<PartialSnapshotBundle, PartialError> {
    let mut builder = PartialSnapshotBuilder::new(base_id, selected_paths, limits)?;
    while let Some(request) = builder.next_request() {
        // Preserve the old source/missing/role-cap error mapping. The smaller
        // advisory max_bytes is for hosts that bound allocation before I/O.
        let bytes = read_source(source, &request.id, request.role_cap)?;
        builder = builder.supply(bytes)?;
    }
    builder.finish()
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
            Object::Blob(blob) => {
                selected_after(*total_selected, blob.data.len(), limits)?;
                VerifiedFileRepresentation {
                    content_len: blob.data.len() as u64,
                    chunk_ids: Arc::from([]),
                }
            }
            Object::ChunkedBlob(manifest) => {
                validate_manifest_size(&manifest, limits)?;
                let declared = usize::try_from(manifest.total_size)
                    .map_err(|_| PartialError::WorkspaceTooLarge)?;
                selected_after(*total_selected, declared, limits)?;
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
                    sum = add_chunk_len(sum, chunk_len, manifest.total_size)?;
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

#[derive(Debug, Default)]
struct ProducerRepresentationCache {
    files: BTreeMap<Hash, usize>,
    chunks: BTreeMap<Hash, usize>,
}

/// The one selected-only producer traversal, driven either by explicit
/// request/supply or by `build_partial_snapshot`'s synchronous source loop.
/// It owns only the selected dependency bytes it has accepted. A host must
/// bound each fetch before allocating its response `Vec`; dropping this value
/// cancels the in-memory traversal without a resumable checkpoint.
pub struct PartialSnapshotBuilder {
    base_id: Hash,
    paths: Vec<PartialPath>,
    limits: PartialLimits,
    objects: BTreeMap<Hash, Vec<u8>>,
    budget: BundleBudget,
    request: Option<PartialObjectRequest>,
    phase: ProducerPhase,
    root: Option<Hash>,
    path_index: usize,
    component_index: usize,
    tree_id: Hash,
    visits: usize,
    witness_ids: BTreeSet<Hash>,
    witness_bytes: usize,
    total_selected: usize,
    tree_cache: BTreeMap<Hash, Tree>,
    representation_cache: ProducerRepresentationCache,
}

impl std::fmt::Debug for PartialSnapshotBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartialSnapshotBuilder")
            .field("selected_paths", &self.paths.len())
            .field("retained_objects", &self.objects.len())
            .field("outstanding_request", &self.request.is_some())
            .finish_non_exhaustive()
    }
}

/// Role expected for one selected producer request. This is a type check,
/// not authorization to fetch the ID from an untrusted remote service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartialObjectRole {
    /// Signed base Commit or Remix.
    Base,
    /// Authenticated selected ancestor Tree.
    Tree,
    /// Selected Blob or `ChunkedBlob` representation.
    File,
    /// Chunk Blob named by a selected manifest.
    Chunk,
}

/// Privately constructed one-at-a-time selected dependency request.
#[derive(Debug, Clone, Copy)]
pub struct PartialObjectRequest {
    id: Hash,
    role: PartialObjectRole,
    max_bytes: usize,
    role_cap: usize,
}

impl PartialObjectRequest {
    /// Authenticated ID requested by the builder.
    #[must_use]
    pub fn id(&self) -> Hash {
        self.id
    }
    /// Required object type role for this response.
    #[must_use]
    pub fn role(&self) -> PartialObjectRole {
        self.role
    }
    /// Minimum of the role cap and remaining encoded-bundle room. Hosts
    /// should enforce this before I/O allocation. Supply retains the separate
    /// role cap so over-budget responses keep their historical error class.
    #[must_use]
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }
}

#[derive(Debug)]
enum ProducerPhase {
    Base,
    Path {
        visited: bool,
    },
    File {
        id: Hash,
    },
    Chunk {
        id: Hash,
        manifest: ChunkedBlob,
        index: usize,
        sum: u64,
        next_total: usize,
    },
    Done,
}

impl PartialSnapshotBuilder {
    /// Start from an independently pinned base and exact selected paths. No
    /// source reads or path-derived allocations happen before validation.
    ///
    /// # Errors
    ///
    /// Returns the existing request-validation [`PartialError`] for invalid
    /// V1 limits, path grammar/count/length or initial bundle framing budget.
    /// No object source is consulted until the first request is supplied.
    pub fn new(
        base_id: Hash,
        selected_paths: &[PartialPath],
        limits: &PartialLimits,
    ) -> Result<Self, PartialError> {
        validate_request(selected_paths, limits)?;
        let budget = BundleBudget::new(selected_paths, limits)?;
        let mut builder = Self {
            base_id,
            paths: selected_paths.to_vec(),
            limits: *limits,
            objects: BTreeMap::new(),
            budget,
            request: None,
            phase: ProducerPhase::Base,
            root: None,
            path_index: 0,
            component_index: 0,
            tree_id: [0; 32],
            visits: 0,
            witness_ids: BTreeSet::new(),
            witness_bytes: 0,
            total_selected: 0,
            tree_cache: BTreeMap::new(),
            representation_cache: ProducerRepresentationCache::default(),
        };
        builder.advance()?;
        Ok(builder)
    }

    /// Idempotently observe the sole outstanding request, if any.
    #[must_use]
    pub fn next_request(&self) -> Option<&PartialObjectRequest> {
        self.request.as_ref()
    }

    /// Consume exactly the requested response. Any error consumes the builder,
    /// so a caller cannot continue after a rejected response.
    /// The returned `Vec` belongs to the caller until this call; successful
    /// supply retains its bytes by authenticated ID and advances cached work.
    ///
    /// # Errors
    ///
    /// Returns [`PartialError::UnsupportedPartialOperation`] when no request
    /// remains, witness/role or workspace/bundle budget errors before decode,
    /// then the existing canonical-ID, type, signature and selected-layout
    /// errors. A rejected response destroys this builder state.
    pub fn supply(mut self, bytes: Vec<u8>) -> Result<Self, PartialError> {
        let request = self
            .request
            .take()
            .ok_or(PartialError::UnsupportedPartialOperation)?;
        if bytes.is_empty() || bytes.len() > request.role_cap {
            return Err(PartialError::WitnessTooLarge);
        }
        // Match the old producer's order: exact bundle/object budget before
        // canonical decode/re-encoding and before retention.
        self.budget.charge_object(bytes.len())?;
        if request.role == PartialObjectRole::Tree && !self.witness_ids.contains(&request.id) {
            let prospective = checked_add(self.witness_bytes, bytes.len())?;
            if prospective > self.limits.max_witness_bytes {
                return Err(PartialError::WitnessTooLarge);
            }
        }
        let role = match request.role {
            PartialObjectRole::Base => DecodeRole::Base,
            PartialObjectRole::Tree => DecodeRole::Tree,
            PartialObjectRole::File => DecodeRole::File,
            PartialObjectRole::Chunk => DecodeRole::Chunk,
        };
        let object = decode_checked(&request.id, &bytes, &self.limits, role)?;
        if request.role == PartialObjectRole::Base {
            verify_base(&object)?;
        }
        drop(object);
        self.objects.insert(request.id, bytes);
        self.advance()?;
        Ok(self)
    }

    /// Build the original ID-sorted bundle and self-verify exact inventory.
    ///
    /// # Errors
    ///
    /// Returns [`PartialError::InsufficientWitness`] while a request remains,
    /// or the existing bundle encoding/selected-verifier error if final
    /// independent inventory validation fails.
    pub fn finish(self) -> Result<PartialSnapshotBundle, PartialError> {
        if self.request.is_some() || !matches!(self.phase, ProducerPhase::Done) {
            return Err(PartialError::InsufficientWitness);
        }
        let bundle = PartialSnapshotBundle::new(
            self.base_id,
            self.paths.clone(),
            self.objects.into_iter().collect(),
            &self.limits,
        )?;
        let encoded = bundle.encode(&self.limits)?;
        verify_partial_snapshot(self.base_id, &self.paths, &encoded, &self.limits)?;
        Ok(bundle)
    }

    fn request_missing(
        &mut self,
        id: Hash,
        role: PartialObjectRole,
        cap: usize,
    ) -> Result<bool, PartialError> {
        if self.objects.contains_key(&id) {
            return Ok(false);
        }
        self.budget.ensure_object_read_possible()?;
        let role_cap = cap.min(self.limits.max_object_bytes);
        let max_bytes = self.budget.max_next_object_bytes(role_cap)?;
        self.request = Some(PartialObjectRequest {
            id,
            role,
            max_bytes,
            role_cap,
        });
        Ok(true)
    }

    fn next_path(&mut self) {
        self.path_index += 1;
        self.component_index = 0;
        if let Some(root) = self.root {
            self.tree_id = root;
        }
        self.phase = ProducerPhase::Path { visited: false };
    }

    // Keeping the five phases together makes the single outstanding-request
    // transition and terminal-error rule auditable in one place.
    #[allow(clippy::too_many_lines)]
    fn advance(&mut self) -> Result<(), PartialError> {
        while self.request.is_none() {
            let phase = std::mem::replace(&mut self.phase, ProducerPhase::Done);
            match phase {
                ProducerPhase::Base => {
                    if self.request_missing(
                        self.base_id,
                        PartialObjectRole::Base,
                        self.limits.max_base_object_bytes,
                    )? {
                        self.phase = ProducerPhase::Base;
                        break;
                    }
                    let bytes = self
                        .objects
                        .get(&self.base_id)
                        .ok_or(PartialError::InsufficientWitness)?;
                    let object =
                        decode_checked(&self.base_id, bytes, &self.limits, DecodeRole::Base)?;
                    let root = verify_base(&object)?;
                    self.root = Some(root);
                    self.tree_id = root;
                    self.phase = ProducerPhase::Path { visited: false };
                }
                ProducerPhase::Path { visited } => {
                    if self.path_index == self.paths.len() {
                        self.phase = ProducerPhase::Done;
                        break;
                    }
                    if !visited {
                        self.visits = checked_add(self.visits, 1)?;
                        if self.visits > self.limits.max_tree_visits {
                            return Err(PartialError::ValidationBudgetExceeded);
                        }
                    }
                    let tree_id = self.tree_id;
                    if self.request_missing(
                        tree_id,
                        PartialObjectRole::Tree,
                        self.limits.max_tree_object_bytes,
                    )? {
                        self.phase = ProducerPhase::Path { visited: true };
                        break;
                    }
                    let tree_bytes = self
                        .objects
                        .get(&tree_id)
                        .ok_or(PartialError::InsufficientWitness)?;
                    if self.witness_ids.insert(tree_id) {
                        self.witness_bytes = checked_add(self.witness_bytes, tree_bytes.len())?;
                        if self.witness_bytes > self.limits.max_witness_bytes {
                            return Err(PartialError::WitnessTooLarge);
                        }
                    }
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        self.tree_cache.entry(tree_id)
                    {
                        let Object::Tree(tree) =
                            decode_checked(&tree_id, tree_bytes, &self.limits, DecodeRole::Tree)?
                        else {
                            return Err(PartialError::WrongObjectType);
                        };
                        entry.insert(tree);
                    }
                    let component = &self.paths[self.path_index][self.component_index];
                    let tree = self
                        .tree_cache
                        .get(&tree_id)
                        .ok_or(PartialError::InsufficientWitness)?;
                    let entry = tree
                        .entries
                        .binary_search_by(|entry| entry.name.as_slice().cmp(component))
                        .ok()
                        .map(|position| &tree.entries[position])
                        .ok_or(PartialError::IncompleteSelection)?;
                    let child_id = entry.object_hash;
                    let mode = entry.mode;
                    if self.component_index + 1 == self.paths[self.path_index].len() {
                        if !matches!(mode, EntryMode::Blob | EntryMode::Executable) {
                            return Err(PartialError::UnsupportedPartialOperation);
                        }
                        self.phase = ProducerPhase::File { id: child_id };
                    } else {
                        if mode != EntryMode::Tree {
                            return Err(PartialError::WrongObjectType);
                        }
                        self.tree_id = child_id;
                        self.component_index += 1;
                        self.phase = ProducerPhase::Path { visited: false };
                    }
                }
                ProducerPhase::File { id } => {
                    if let Some(len) = self.representation_cache.files.get(&id) {
                        self.total_selected =
                            selected_after(self.total_selected, *len, &self.limits)?;
                        self.next_path();
                        continue;
                    }
                    if self.request_missing(
                        id,
                        PartialObjectRole::File,
                        self.limits.max_object_bytes,
                    )? {
                        self.phase = ProducerPhase::File { id };
                        break;
                    }
                    let bytes = self
                        .objects
                        .get(&id)
                        .ok_or(PartialError::InsufficientWitness)?;
                    match decode_checked(&id, bytes, &self.limits, DecodeRole::File)? {
                        Object::Blob(blob) => {
                            let len = blob.data.len();
                            self.total_selected =
                                selected_after(self.total_selected, len, &self.limits)?;
                            self.representation_cache.files.insert(id, len);
                            self.next_path();
                        }
                        Object::ChunkedBlob(manifest) => {
                            validate_manifest_size(&manifest, &self.limits)?;
                            let len = usize::try_from(manifest.total_size)
                                .map_err(|_| PartialError::WorkspaceTooLarge)?;
                            let next_total =
                                selected_after(self.total_selected, len, &self.limits)?;
                            self.phase = ProducerPhase::Chunk {
                                id,
                                manifest,
                                index: 0,
                                sum: 0,
                                next_total,
                            };
                        }
                        _ => return Err(PartialError::WrongObjectType),
                    }
                }
                ProducerPhase::Chunk {
                    id,
                    manifest,
                    index,
                    sum,
                    next_total,
                } => {
                    if index == manifest.chunks.len() {
                        if sum != manifest.total_size {
                            return Err(PartialError::InvalidChunkLayout);
                        }
                        let len = usize::try_from(manifest.total_size)
                            .map_err(|_| PartialError::WorkspaceTooLarge)?;
                        self.representation_cache.files.insert(id, len);
                        self.total_selected = next_total;
                        self.next_path();
                        continue;
                    }
                    let chunk_id = manifest.chunks[index];
                    if self.request_missing(
                        chunk_id,
                        PartialObjectRole::Chunk,
                        self.limits.max_object_bytes,
                    )? {
                        self.phase = ProducerPhase::Chunk {
                            id,
                            manifest,
                            index,
                            sum,
                            next_total,
                        };
                        break;
                    }
                    let chunk_len =
                        if let Some(len) = self.representation_cache.chunks.get(&chunk_id) {
                            *len
                        } else {
                            let bytes = self
                                .objects
                                .get(&chunk_id)
                                .ok_or(PartialError::InsufficientWitness)?;
                            let Object::Blob(chunk) =
                                decode_checked(&chunk_id, bytes, &self.limits, DecodeRole::Chunk)?
                            else {
                                return Err(PartialError::WrongObjectType);
                            };
                            let len = chunk.data.len();
                            self.representation_cache.chunks.insert(chunk_id, len);
                            len
                        };
                    validate_chunk_occurrence(&manifest, index, chunk_len)?;
                    let next_sum = add_chunk_len(sum, chunk_len, manifest.total_size)?;
                    self.phase = ProducerPhase::Chunk {
                        id,
                        manifest,
                        index: index + 1,
                        sum: next_sum,
                        next_total,
                    };
                }
                ProducerPhase::Done => {
                    self.phase = ProducerPhase::Done;
                    break;
                }
            }
        }
        Ok(())
    }
}

fn selected_after(
    total: usize,
    file_len: usize,
    limits: &PartialLimits,
) -> Result<usize, PartialError> {
    if file_len > limits.max_selected_file_bytes {
        return Err(PartialError::WorkspaceTooLarge);
    }
    let next = checked_add(total, file_len)?;
    if next > limits.max_total_selected_bytes {
        return Err(PartialError::WorkspaceTooLarge);
    }
    Ok(next)
}

pub(crate) fn add_chunk_len(
    sum: u64,
    chunk_len: usize,
    declared: u64,
) -> Result<u64, PartialError> {
    let chunk_len = u64::try_from(chunk_len).map_err(|_| PartialError::InvalidChunkLayout)?;
    let next = sum
        .checked_add(chunk_len)
        .ok_or(PartialError::InvalidChunkLayout)?;
    if next > declared {
        return Err(PartialError::InvalidChunkLayout);
    }
    Ok(next)
}

pub(crate) fn validate_manifest_size(
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

pub(crate) fn validate_chunk_occurrence(
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

pub(crate) fn preflight_tree(bytes: &[u8], limits: &PartialLimits) -> Result<(), PartialError> {
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

pub(crate) fn preflight_file(bytes: &[u8], limits: &PartialLimits) -> Result<(), PartialError> {
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

    struct GuardedSource {
        objects: BTreeMap<Hash, Vec<u8>>,
        reads: RefCell<Vec<Hash>>,
        forbidden: BTreeSet<Hash>,
    }

    impl ObjectSource for GuardedSource {
        fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
            self.reads.borrow_mut().push(*id);
            if self.forbidden.contains(id) {
                return Err(StoreError::ObjectNotFound(format!(
                    "unexpected read of {}",
                    crate::hash::to_hex(id)
                )));
            }
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
        chunked: Hash,
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
            chunked,
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

    fn signed_source(
        mut objects: BTreeMap<Hash, Vec<u8>>,
        entries: Vec<TreeEntry>,
        forbidden: BTreeSet<Hash>,
    ) -> (GuardedSource, Hash, Vec<PartialPath>) {
        let paths = entries
            .iter()
            .map(|entry| vec![entry.name.clone()])
            .collect();
        let root = insert(&mut objects, Object::Tree(Tree { entries }));
        let key = KeyPair::from_seed([23; 32]);
        let mut commit = Commit::new_unannotated(
            root,
            Vec::new(),
            Identity::ed25519(key.public.0),
            key.public.0,
            b"partial producer budget fixture".to_vec(),
            1_700_000_002,
            [0; 64],
        );
        commit.signature = sign_commit(&commit, &key).unwrap().0;
        let base_id = insert(&mut objects, Object::Commit(commit));
        (
            GuardedSource {
                objects,
                reads: RefCell::new(Vec::new()),
                forbidden,
            },
            base_id,
            paths,
        )
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

    fn parent_fixture_trace() -> Vec<Hash> {
        // Captured with the unchanged producer at b41117de in an isolated
        // parent worktree. The shared ancestor, representation and repeated
        // chunk each cause only one source read.
        [
            "71a68896c1643f940c6f9500a7cb5ff51b3258a6b410879626d617a3f367b541",
            "14a5ef0f8ffee0e421b6f1883115de47d9f3f1a0795c874c81781c5714fd37f5",
            "c69ba4e1a9839af815f4c9a661f263aa2e4d42c47c4f6870a7ebe70da246e55d",
            "714cce97dce09664e3b95b86eeaab079df222881746efb322c14a6b8ac5ae25d",
            "690963b2b54ca76b5edcb802b6acb67a963213e253f4b920cf08ebb9d0542756",
            "9c66180ef8da233105d4d5cd0913da3cbc89b1e002c71dd36cdd6649f6eae4e1",
        ]
        .iter()
        .map(|hex| crate::hash::from_hex(hex).unwrap())
        .collect()
    }

    #[test]
    fn consuming_builder_matches_selected_producer_and_fetches_only_selected_ids() {
        let fixture = fixture();
        let limits = PartialLimits::default();
        let parent_trace = parent_fixture_trace();
        let reference =
            build_partial_snapshot(&fixture.source, fixture.base_id, &fixture.paths, &limits)
                .unwrap()
                .encode(&limits)
                .unwrap();
        assert_eq!(*fixture.source.reads.borrow(), parent_trace);
        assert_eq!(reference.len(), 903, "parent producer bundle length");
        let mut builder =
            PartialSnapshotBuilder::new(fixture.base_id, &fixture.paths, &limits).unwrap();
        let mut requests = Vec::new();
        while let Some(request) = builder.next_request() {
            assert_eq!(
                builder.next_request().unwrap().id(),
                request.id(),
                "request is stable until supply"
            );
            let id = request.id();
            assert_ne!(id, fixture.hidden_tree);
            assert_ne!(id, fixture.hidden_blob);
            requests.push(id);
            let bytes = fixture.source.objects.get(&id).unwrap().clone();
            assert!(bytes.len() <= request.max_bytes());
            builder = builder.supply(bytes).unwrap();
        }
        assert_eq!(
            requests, parent_trace,
            "request order matches the captured parent producer trace"
        );
        assert!(requests.contains(&fixture.chunked));
        assert_eq!(
            requests.iter().filter(|id| **id == fixture.chunk).count(),
            1,
            "repeated chunk ID fetched once"
        );
        assert_eq!(
            builder.finish().unwrap().encode(&limits).unwrap(),
            reference
        );
    }

    #[test]
    fn parent_limit_traces_match_both_producer_drivers() {
        // Independently captured at b41117de: bundle 902 fails only after
        // the sixth read; witness 92 fails on the root Tree; base role 263
        // fails on the first read. Parent exact values: bundle 903 bytes,
        // root Tree 93 bytes, base Commit 264 bytes. When the same first
        // response exceeds both its role cap and bundle room, role wins.
        let trace = parent_fixture_trace();
        let generic = PartialLimits::default();
        for (case, limits, read_count) in [
            (
                "bundle",
                PartialLimits {
                    max_bundle_bytes: 902,
                    ..generic
                },
                6,
            ),
            (
                "witness",
                PartialLimits {
                    max_witness_bytes: 92,
                    ..generic
                },
                2,
            ),
            (
                "base role",
                PartialLimits {
                    max_base_object_bytes: 263,
                    ..generic
                },
                1,
            ),
            (
                "role before bundle",
                PartialLimits {
                    max_base_object_bytes: 263,
                    max_bundle_bytes: 200,
                    ..generic
                },
                1,
            ),
        ] {
            let fixture = self::fixture();
            let sync_error =
                build_partial_snapshot(&fixture.source, fixture.base_id, &fixture.paths, &limits)
                    .unwrap_err();
            assert_eq!(
                *fixture.source.reads.borrow(),
                trace[..read_count],
                "{case}"
            );
            assert!(
                matches!(
                    (&sync_error, case),
                    (PartialError::WorkspaceTooLarge, "bundle")
                        | (
                            PartialError::WitnessTooLarge,
                            "witness" | "base role" | "role before bundle"
                        )
                ),
                "parent sync error changed for {case}: {sync_error:?}"
            );

            let fixture = self::fixture();
            let mut builder =
                PartialSnapshotBuilder::new(fixture.base_id, &fixture.paths, &limits).unwrap();
            let mut requests = Vec::new();
            let supplied_error = loop {
                let request = builder.next_request().expect("parent trace must reject");
                let id = request.id();
                requests.push(id);
                let bytes = fixture.source.objects.get(&id).unwrap().clone();
                match builder.supply(bytes) {
                    Ok(next) => builder = next,
                    Err(error) => break error,
                }
            };
            assert_eq!(requests, trace[..read_count], "{case}");
            assert!(
                matches!(
                    (&supplied_error, case),
                    (PartialError::WorkspaceTooLarge, "bundle")
                        | (
                            PartialError::WitnessTooLarge,
                            "witness" | "base role" | "role before bundle"
                        )
                ),
                "parent request/supply error changed for {case}: {supplied_error:?}"
            );
        }
    }

    #[test]
    fn builder_rejects_wrong_supply_and_premature_finish() {
        let fixture = fixture();
        let limits = PartialLimits::default();
        let builder =
            PartialSnapshotBuilder::new(fixture.base_id, &fixture.paths, &limits).unwrap();
        assert!(matches!(
            builder.finish(),
            Err(PartialError::InsufficientWitness)
        ));
        let builder =
            PartialSnapshotBuilder::new(fixture.base_id, &fixture.paths, &limits).unwrap();
        assert_eq!(
            builder.next_request().unwrap().role(),
            PartialObjectRole::Base
        );
        let wrong = fixture.source.objects.get(&fixture.chunk).unwrap().clone();
        assert!(matches!(
            builder.supply(wrong),
            Err(PartialError::NonCanonical)
        ));
        let mut builder =
            PartialSnapshotBuilder::new(fixture.base_id, &fixture.paths, &limits).unwrap();
        while let Some(request) = builder.next_request() {
            let id = request.id();
            builder = builder
                .supply(fixture.source.objects.get(&id).unwrap().clone())
                .unwrap();
        }
        assert!(matches!(
            builder.supply(Vec::new()),
            Err(PartialError::UnsupportedPartialOperation)
        ));
    }

    #[test]
    fn builder_preserves_role_cap_before_remaining_bundle_error() {
        let fixture = fixture();
        let base_bytes = fixture
            .source
            .objects
            .get(&fixture.base_id)
            .unwrap()
            .clone();
        let Object::Commit(base) = deserialize(&base_bytes).unwrap() else {
            panic!("fixture commit")
        };
        let tree_bytes = fixture.source.objects.get(&base.tree_hash).unwrap().clone();
        let mut budget = BundleBudget::new(&fixture.paths, &PartialLimits::default()).unwrap();
        budget.charge_object(base_bytes.len()).unwrap();
        budget.charge_object(tree_bytes.len()).unwrap();
        let limits = PartialLimits {
            max_bundle_bytes: budget.encoded_bytes() - 1,
            ..PartialLimits::default()
        };
        let builder =
            PartialSnapshotBuilder::new(fixture.base_id, &fixture.paths, &limits).unwrap();
        let builder = builder.supply(base_bytes).unwrap();
        let request = builder.next_request().unwrap();
        assert_eq!(request.id(), base.tree_hash);
        assert!(
            request.max_bytes() < tree_bytes.len(),
            "remaining-byte cap is advisory to async host"
        );
        assert!(matches!(
            builder.supply(tree_bytes),
            Err(PartialError::WorkspaceTooLarge)
        ));
        assert!(matches!(
            build_partial_snapshot(&fixture.source, fixture.base_id, &fixture.paths, &limits),
            Err(PartialError::WorkspaceTooLarge)
        ));
    }

    #[test]
    fn builder_witness_bound_precedes_tree_decode() {
        let fixture = fixture();
        let base_bytes = fixture
            .source
            .objects
            .get(&fixture.base_id)
            .unwrap()
            .clone();
        let Object::Commit(base) = deserialize(&base_bytes).unwrap() else {
            panic!("fixture commit")
        };
        let mut tree_bytes = fixture.source.objects.get(&base.tree_hash).unwrap().clone();
        let limits = PartialLimits {
            max_witness_bytes: tree_bytes.len() - 1,
            ..PartialLimits::default()
        };
        let builder =
            PartialSnapshotBuilder::new(fixture.base_id, &fixture.paths, &limits).unwrap();
        let builder = builder.supply(base_bytes).unwrap();
        assert_eq!(
            builder.next_request().unwrap().role(),
            PartialObjectRole::Tree
        );
        tree_bytes[0] ^= 1;
        assert!(matches!(
            builder.supply(tree_bytes),
            Err(PartialError::WitnessTooLarge)
        ));
    }

    #[test]
    fn builder_rejects_authenticated_wrong_role_at_requested_id() {
        let mut objects = BTreeMap::new();
        let wrong = insert(
            &mut objects,
            Object::Tree(Tree {
                entries: Vec::new(),
            }),
        );
        let (source, base, paths) = signed_source(
            objects,
            vec![TreeEntry {
                name: b"file".to_vec(),
                mode: EntryMode::Blob,
                object_hash: wrong,
            }],
            BTreeSet::new(),
        );
        let limits = PartialLimits::default();
        let mut builder = PartialSnapshotBuilder::new(base, &paths, &limits).unwrap();
        while let Some(request) = builder.next_request() {
            let id = request.id();
            let role = request.role();
            let result = builder.supply(source.objects.get(&id).unwrap().clone());
            if id == wrong {
                assert_eq!(role, PartialObjectRole::File);
                assert!(matches!(result, Err(PartialError::WrongObjectType)));
                return;
            }
            builder = result.unwrap();
        }
        panic!("wrong-role file was never requested");
    }

    #[test]
    fn builder_exact_selected_and_bundle_bounds_match_sync_output() {
        let fixture = fixture();
        let generic = PartialLimits::default();
        let encoded =
            build_partial_snapshot(&fixture.source, fixture.base_id, &fixture.paths, &generic)
                .unwrap()
                .encode(&generic)
                .unwrap();
        let selected_len = b"plain selected bytes".len() + 48;
        let exact = PartialLimits {
            max_total_selected_bytes: selected_len,
            max_bundle_bytes: encoded.len(),
            ..generic
        };
        let mut builder =
            PartialSnapshotBuilder::new(fixture.base_id, &fixture.paths, &exact).unwrap();
        while let Some(request) = builder.next_request() {
            let id = request.id();
            builder = builder
                .supply(fixture.source.objects.get(&id).unwrap().clone())
                .unwrap();
        }
        assert_eq!(builder.finish().unwrap().encode(&exact).unwrap(), encoded);
        let one_less = PartialLimits {
            max_total_selected_bytes: selected_len - 1,
            ..exact
        };
        let mut builder =
            PartialSnapshotBuilder::new(fixture.base_id, &fixture.paths, &one_less).unwrap();
        loop {
            let Some(request) = builder.next_request() else {
                panic!("selected bound was not enforced")
            };
            let id = request.id();
            match builder.supply(fixture.source.objects.get(&id).unwrap().clone()) {
                Err(PartialError::WorkspaceTooLarge) => break,
                Ok(next) => builder = next,
                Err(error) => panic!("unexpected error: {error}"),
            }
        }
        let one_less = PartialLimits {
            max_bundle_bytes: encoded.len() - 1,
            ..exact
        };
        let mut builder =
            PartialSnapshotBuilder::new(fixture.base_id, &fixture.paths, &one_less).unwrap();
        loop {
            let Some(request) = builder.next_request() else {
                panic!("bundle bound was not enforced")
            };
            let id = request.id();
            match builder.supply(fixture.source.objects.get(&id).unwrap().clone()) {
                Err(PartialError::WorkspaceTooLarge) => break,
                Ok(next) => builder = next,
                Err(error) => panic!("unexpected error: {error}"),
            }
        }
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
    fn producer_stops_when_chunk_sum_exceeds_declared_total() {
        let mut objects = BTreeMap::new();
        let oversized = insert(
            &mut objects,
            Object::Blob(Blob {
                data: b"ab".to_vec(),
            }),
        );
        let sentinel = insert(&mut objects, Object::Blob(Blob { data: vec![1] }));
        let manifest = insert(
            &mut objects,
            Object::ChunkedBlob(ChunkedBlob {
                total_size: 1,
                chunk_size: 0,
                chunks: vec![oversized, sentinel],
            }),
        );
        let entries = vec![TreeEntry {
            name: b"bad.bin".to_vec(),
            mode: EntryMode::Blob,
            object_hash: manifest,
        }];
        let (source, base, paths) = signed_source(objects, entries, BTreeSet::from([sentinel]));

        assert!(matches!(
            build_partial_snapshot(&source, base, &paths, &PartialLimits::default()),
            Err(PartialError::InvalidChunkLayout)
        ));
        assert!(!source.reads.borrow().contains(&sentinel));
    }

    #[test]
    fn producer_enforces_encoded_bundle_budget_before_retaining_more_objects() {
        let mut objects = BTreeMap::new();
        let one = insert(&mut objects, Object::Blob(Blob { data: vec![1] }));
        let empty = insert(&mut objects, Object::Blob(Blob { data: Vec::new() }));
        let mut manifests = Vec::new();
        for empty_count in [8, 9, 10] {
            let mut chunks = vec![one];
            chunks.resize(empty_count + 1, empty);
            manifests.push(insert(
                &mut objects,
                Object::ChunkedBlob(ChunkedBlob {
                    total_size: 1,
                    chunk_size: 0,
                    chunks,
                }),
            ));
        }
        let entries = [b'a', b'b', b'c']
            .into_iter()
            .zip(manifests.iter().copied())
            .map(|(name, object_hash)| TreeEntry {
                name: vec![name],
                mode: EntryMode::Blob,
                object_hash,
            })
            .collect::<Vec<_>>();
        let (source, base, paths) = signed_source(objects, entries, BTreeSet::from([manifests[2]]));
        let retained = [base, manifests[0], one, empty]
            .into_iter()
            .chain(source.objects.iter().filter_map(|(id, bytes)| {
                matches!(deserialize(bytes), Ok(Object::Tree(_))).then_some(*id)
            }))
            .collect::<BTreeSet<_>>();
        let retained_objects = source
            .objects
            .iter()
            .filter(|(id, _)| retained.contains(*id))
            .map(|(id, bytes)| (*id, bytes.clone()))
            .collect();
        let exact_retained = PartialSnapshotBundle::new(
            base,
            paths.clone(),
            retained_objects,
            &PartialLimits::default(),
        )
        .unwrap()
        .encode(&PartialLimits::default())
        .unwrap()
        .len();
        let limits = PartialLimits {
            max_bundle_bytes: exact_retained + 40,
            ..PartialLimits::default()
        };

        assert!(matches!(
            build_partial_snapshot(&source, base, &paths, &limits),
            Err(PartialError::WorkspaceTooLarge)
        ));
        let reads = source.reads.borrow();
        assert!(
            reads.contains(&manifests[1]),
            "the crossing object may be read"
        );
        assert!(
            !reads.contains(&manifests[2]),
            "collection must stop after overflow"
        );
    }

    #[test]
    fn producer_checks_declared_selected_bytes_before_chunk_reads() {
        let mut objects = BTreeMap::new();
        let first = insert(&mut objects, Object::Blob(Blob { data: vec![1] }));
        let sentinel = insert(&mut objects, Object::Blob(Blob { data: vec![2] }));
        let manifest = insert(
            &mut objects,
            Object::ChunkedBlob(ChunkedBlob {
                total_size: 1,
                chunk_size: 0,
                chunks: vec![sentinel],
            }),
        );
        let entries = vec![
            TreeEntry {
                name: b"a".to_vec(),
                mode: EntryMode::Blob,
                object_hash: first,
            },
            TreeEntry {
                name: b"b".to_vec(),
                mode: EntryMode::Blob,
                object_hash: manifest,
            },
        ];
        let (source, base, paths) = signed_source(objects, entries, BTreeSet::from([sentinel]));
        let limits = PartialLimits {
            max_total_selected_bytes: 1,
            ..PartialLimits::default()
        };

        assert!(matches!(
            build_partial_snapshot(&source, base, &paths, &limits),
            Err(PartialError::WorkspaceTooLarge)
        ));
        assert!(!source.reads.borrow().contains(&sentinel));
    }

    #[test]
    fn producer_budget_is_exact_across_object_count_varint_boundary() {
        let limits = PartialLimits::default();
        let mut objects = BTreeMap::new();
        let chunks = (0u8..125)
            .map(|byte| insert(&mut objects, Object::Blob(Blob { data: vec![byte] })))
            .collect::<Vec<_>>();
        let manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: 125,
            chunk_size: 1,
            chunks,
        });
        let (base, paths, bytes) =
            signed_file_bundle(objects, manifest, &[b"boundary.bin"], &limits);
        let (_, _, object_pairs) = PartialSnapshotBundle::decode(&bytes, &limits)
            .unwrap()
            .into_parts();
        assert_eq!(object_pairs.len(), 128);

        let source = CountingSource {
            objects: object_pairs.iter().cloned().collect(),
            reads: RefCell::new(Vec::new()),
        };
        let exact = PartialLimits {
            max_bundle_bytes: bytes.len(),
            ..limits
        };
        let produced = build_partial_snapshot(&source, base, &paths, &exact).unwrap();
        assert_eq!(produced.encode(&exact).unwrap().len(), bytes.len());

        let source = CountingSource {
            objects: object_pairs.into_iter().collect(),
            reads: RefCell::new(Vec::new()),
        };
        let one_byte_short = PartialLimits {
            max_bundle_bytes: bytes.len() - 1,
            ..limits
        };
        assert!(matches!(
            build_partial_snapshot(&source, base, &paths, &one_byte_short),
            Err(PartialError::WorkspaceTooLarge)
        ));
    }

    #[test]
    fn shared_representations_charge_storage_once_and_content_per_path() {
        let initial_fixture = fixture();
        let default_bundle = build_partial_snapshot(
            &initial_fixture.source,
            initial_fixture.base_id,
            &initial_fixture.paths,
            &PartialLimits::default(),
        )
        .unwrap();
        let exact_bundle_bytes = default_bundle
            .encode(&PartialLimits::default())
            .unwrap()
            .len();
        let exact_selected_bytes = b"plain selected bytes".len() + 48;
        let exact_fixture = fixture();
        let exact = PartialLimits {
            max_bundle_bytes: exact_bundle_bytes,
            max_total_selected_bytes: exact_selected_bytes,
            ..PartialLimits::default()
        };
        let bundle = build_partial_snapshot(
            &exact_fixture.source,
            exact_fixture.base_id,
            &exact_fixture.paths,
            &exact,
        )
        .unwrap();
        assert_eq!(bundle.encode(&exact).unwrap().len(), exact_bundle_bytes);
        assert_eq!(
            exact_fixture
                .source
                .reads
                .borrow()
                .iter()
                .filter(|id| **id == exact_fixture.chunk)
                .count(),
            1
        );
        assert_eq!(
            exact_fixture
                .source
                .reads
                .borrow()
                .iter()
                .filter(|id| **id == exact_fixture.chunked)
                .count(),
            1
        );
        let verified = verify_partial_snapshot(
            exact_fixture.base_id,
            &exact_fixture.paths,
            &bundle.encode(&exact).unwrap(),
            &exact,
        )
        .unwrap();
        assert_eq!(verified.files()[1].content_len(), 24);
        assert_eq!(verified.files()[2].content_len(), 24);

        let limited_fixture = fixture();
        let too_little_selected = PartialLimits {
            max_bundle_bytes: exact_bundle_bytes,
            max_total_selected_bytes: exact_selected_bytes - 1,
            ..PartialLimits::default()
        };
        assert!(matches!(
            build_partial_snapshot(
                &limited_fixture.source,
                limited_fixture.base_id,
                &limited_fixture.paths,
                &too_little_selected
            ),
            Err(PartialError::WorkspaceTooLarge)
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
        let fixture = fixture();
        let valid =
            build_partial_snapshot(&fixture.source, fixture.base_id, &fixture.paths, &limits)
                .unwrap()
                .encode(&limits)
                .unwrap();
        assert!(PartialSnapshotBundle::decode(&valid, &limits).is_ok());
        let mut bytes = valid;
        let path_count_offset = 5 + ZERO.len();
        assert_eq!(bytes[path_count_offset], 3);
        bytes.splice(path_count_offset..=path_count_offset, [0x83, 0x00]);
        assert!(matches!(
            PartialSnapshotBundle::decode(&bytes, &limits),
            Err(PartialError::NonCanonical)
        ));
    }
}
