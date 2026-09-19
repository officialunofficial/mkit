//! Authenticated replacement overlay and ordinary commit preparation.

use std::collections::{BTreeMap, BTreeSet};

use crate::hash::{Hash, to_hex};
use crate::object::{Commit, EntryMode, Identity, Object, ObjectType, Tree};
use crate::serialize::serialize;
use crate::store::{ObjectSink, ObjectSource, StoreError, StoreResult};
use crate::worktree::{WorktreeError, content_eq, read_blob, store_file_object};

use super::collector::BoundedCollector;
use super::verify::{preflight_file, preflight_tree};
use super::{PartialError, PartialLimits, PartialPath, SelectedFile, VerifiedPartialSnapshot};

/// Complete replacement content for one existing selected file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReplacement {
    path: PartialPath,
    content: ReplacementContent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReplacementContent {
    Bytes(Vec<u8>),
    ReuseSelected(PartialPath),
}

impl FileReplacement {
    /// Replace `path` with complete caller-supplied file bytes.
    #[must_use]
    pub fn bytes(path: PartialPath, bytes: Vec<u8>) -> Self {
        Self {
            path,
            content: ReplacementContent::Bytes(bytes),
        }
    }

    /// Replace `path` with the complete verified representation selected at
    /// `source_path`. This never accepts a bare object id.
    #[must_use]
    pub fn reuse_selected(path: PartialPath, source_path: PartialPath) -> Self {
        Self {
            path,
            content: ReplacementContent::ReuseSelected(source_path),
        }
    }

    #[must_use]
    pub fn path(&self) -> &PartialPath {
        &self.path
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedChange {
    pub(crate) path: PartialPath,
    pub(crate) old_mode: EntryMode,
    pub(crate) old_id: Hash,
    pub(crate) new_id: Hash,
    pub(crate) content_len: usize,
}

/// Privately constructed, immutable result of applying an authenticated
/// replacement batch.
#[derive(Debug, Clone)]
pub struct PreparedPartialEdit {
    pub(crate) base_id: Hash,
    pub(crate) root_id: Hash,
    pub(crate) changes: Vec<PreparedChange>,
    pub(crate) produced: BTreeMap<Hash, Vec<u8>>,
    pub(crate) dependency_ids: BTreeSet<Hash>,
    #[cfg(test)]
    accounting: OverlayAccounting,
}

#[derive(Debug, Clone, Default)]
struct OverlayAccounting {
    dependency_occurrences_scanned: usize,
    reuse_comparisons: usize,
    byte_representations_loaded: usize,
}

struct DependencyInventory {
    ids: BTreeSet<Hash>,
    representations: BTreeSet<Hash>,
    accounting: OverlayAccounting,
}

impl DependencyInventory {
    fn new(limits: &PartialLimits, accounting: OverlayAccounting) -> Result<Self, PartialError> {
        if 12 + 32 > limits.max_raw_pack_bytes {
            return Err(PartialError::ValidationBudgetExceeded);
        }
        Ok(Self {
            ids: BTreeSet::new(),
            representations: BTreeSet::new(),
            accounting,
        })
    }

    fn record(
        &mut self,
        verified: &VerifiedPartialSnapshot,
        selected: &SelectedFile,
        collector: &BoundedCollector,
        limits: &PartialLimits,
    ) -> Result<(), PartialError> {
        if !self.representations.insert(*selected.object_id()) {
            return Ok(());
        }
        self.record_id(verified, *selected.object_id(), collector, limits)?;
        for chunk_id in selected.chunk_ids() {
            self.accounting.dependency_occurrences_scanned = self
                .accounting
                .dependency_occurrences_scanned
                .checked_add(1)
                .ok_or(PartialError::ValidationBudgetExceeded)?;
            self.record_id(verified, *chunk_id, collector, limits)?;
        }
        Ok(())
    }

    fn record_id(
        &mut self,
        verified: &VerifiedPartialSnapshot,
        id: Hash,
        collector: &BoundedCollector,
        limits: &PartialLimits,
    ) -> Result<(), PartialError> {
        if self.ids.contains(&id) {
            return Ok(());
        }
        let bytes = verified
            .object_bytes(&id)
            .ok_or(PartialError::InsufficientWitness)?;
        validate_output_object(bytes, limits)?;
        collector.reserve(id, bytes)?;
        self.ids.insert(id);
        Ok(())
    }
}

enum PendingContent<'a> {
    Bytes(&'a [u8]),
    Reuse(&'a SelectedFile),
}

struct PendingReplacement<'a> {
    path: &'a PartialPath,
    destination: &'a SelectedFile,
    content_len: usize,
    content: PendingContent<'a>,
}

impl PreparedPartialEdit {
    #[must_use]
    pub fn root_id(&self) -> &Hash {
        &self.root_id
    }

    #[must_use]
    pub fn changed_paths(&self) -> impl ExactSizeIterator<Item = &PartialPath> {
        self.changes.iter().map(|change| &change.path)
    }

    #[must_use]
    pub fn produced_objects(&self) -> impl ExactSizeIterator<Item = (&Hash, &[u8])> {
        self.produced
            .iter()
            .map(|(id, bytes)| (id, bytes.as_slice()))
    }
}

#[derive(Default)]
struct EditNode {
    replacement: Option<Hash>,
    children: BTreeMap<Vec<u8>, EditNode>,
}

struct SnapshotSource<'a>(&'a VerifiedPartialSnapshot);

impl ObjectSource for SnapshotSource<'_> {
    fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
        self.0
            .object_bytes(id)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| StoreError::ObjectNotFound(to_hex(id)))
    }
}

/// Atomically replace existing selected regular/executable files.
pub fn replace_files(
    verified: &VerifiedPartialSnapshot,
    replacements: &[FileReplacement],
    limits: &PartialLimits,
) -> Result<PreparedPartialEdit, PartialError> {
    if !limits.is_v1_subset()
        || replacements.is_empty()
        || replacements.len() > limits.max_changed_paths
    {
        return Err(PartialError::ValidationBudgetExceeded);
    }

    let (collector, mut changes, dependencies) =
        collect_replacements(verified, replacements, limits)?;
    changes.sort_by_key(|change| joined(&change.path));

    let mut edits = EditNode::default();
    for change in &changes {
        let mut node = &mut edits;
        for component in &change.path {
            node = node.children.entry(component.clone()).or_default();
        }
        node.replacement = Some(change.new_id);
    }

    let root = match verified.base_object() {
        Object::Commit(commit) => commit.tree_hash,
        Object::Remix(remix) => remix.tree_hash,
        _ => return Err(PartialError::WrongObjectType),
    };
    let root_id = rebuild_tree(verified, &collector, root, &edits, limits)?;
    let produced = collector.into_objects();
    let prepared = PreparedPartialEdit {
        base_id: *verified.base_id(),
        root_id,
        changes,
        produced,
        dependency_ids: dependencies.ids,
        #[cfg(test)]
        accounting: dependencies.accounting,
    };
    validate_prepared_output(verified, &prepared, limits)?;
    Ok(prepared)
}

fn collect_replacements(
    verified: &VerifiedPartialSnapshot,
    replacements: &[FileReplacement],
    limits: &PartialLimits,
) -> Result<(BoundedCollector, Vec<PreparedChange>, DependencyInventory), PartialError> {
    let files: BTreeMap<&PartialPath, &SelectedFile> = verified
        .files()
        .iter()
        .map(|file| (file.path(), file))
        .collect();
    preflight_replacements(&files, replacements, limits)?;
    let source = SnapshotSource(verified);
    let mut comparison_cache = BTreeMap::new();
    // Distinct authenticated content is bounded by the verified snapshot's
    // selected-byte total. Cache it once even when replacements differ, so
    // repeated path occurrences cannot multiply shared manifest traversal.
    let mut original_content = BTreeMap::new();
    let mut accounting = OverlayAccounting::default();
    let mut pending = Vec::new();

    for replacement in replacements {
        let destination = files
            .get(&replacement.path)
            .copied()
            .ok_or(PartialError::UnsupportedPartialOperation)?;

        let (content_len, equal, content) = match &replacement.content {
            ReplacementContent::Bytes(bytes) => {
                let original = match original_content.entry(*destination.object_id()) {
                    std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        accounting.byte_representations_loaded = accounting
                            .byte_representations_loaded
                            .checked_add(1)
                            .ok_or(PartialError::ValidationBudgetExceeded)?;
                        let content = read_blob(&source, destination.object_id()).map_err(
                            |error| match error {
                                WorktreeError::Store(error) => PartialError::Source(error),
                                _ => PartialError::InvalidChunkLayout,
                            },
                        )?;
                        entry.insert(content)
                    }
                };
                let equal = original.as_slice() == bytes.as_slice();
                (bytes.len(), equal, PendingContent::Bytes(bytes))
            }
            ReplacementContent::ReuseSelected(source_path) => {
                let selected = files
                    .get(source_path)
                    .copied()
                    .ok_or(PartialError::UnsupportedPartialOperation)?;
                let pair = ordered_pair(*destination.object_id(), *selected.object_id());
                let equal = if let Some(equal) = comparison_cache.get(&pair) {
                    *equal
                } else {
                    accounting.reuse_comparisons = accounting
                        .reuse_comparisons
                        .checked_add(1)
                        .ok_or(PartialError::ValidationBudgetExceeded)?;
                    let equal = content_eq(&source, destination.object_id(), selected.object_id())
                        .map_err(PartialError::Source)?;
                    comparison_cache.insert(pair, equal);
                    equal
                };
                (
                    usize::try_from(selected.content_len())
                        .map_err(|_| PartialError::WorkspaceTooLarge)?,
                    equal,
                    PendingContent::Reuse(selected),
                )
            }
        };
        if !equal {
            pending.push(PendingReplacement {
                path: &replacement.path,
                destination,
                content_len,
                content,
            });
        }
    }

    if pending.is_empty() {
        return Err(PartialError::NoChanges);
    }
    preflight_affected_trees(verified, &pending, limits)?;
    let collector = BoundedCollector::new(limits)?;
    let mut dependencies = DependencyInventory::new(limits, accounting)?;
    let mut changes = Vec::with_capacity(pending.len());
    for replacement in pending {
        let new_id = match replacement.content {
            PendingContent::Bytes(bytes) => store_file_object(&collector, bytes)
                .map_err(|error| map_writer_error(&collector, error))?,
            PendingContent::Reuse(selected) => {
                dependencies.record(verified, selected, &collector, limits)?;
                *selected.object_id()
            }
        };
        changes.push(PreparedChange {
            path: replacement.path.clone(),
            old_mode: replacement.destination.mode(),
            old_id: *replacement.destination.object_id(),
            new_id,
            content_len: replacement.content_len,
        });
    }

    Ok((collector, changes, dependencies))
}

fn preflight_replacements(
    files: &BTreeMap<&PartialPath, &SelectedFile>,
    replacements: &[FileReplacement],
    limits: &PartialLimits,
) -> Result<(), PartialError> {
    let mut seen = BTreeSet::new();
    let mut total = 0usize;
    for replacement in replacements {
        if !seen.insert(&replacement.path) {
            return Err(PartialError::UnsupportedPartialOperation);
        }
        let destination = files
            .get(&replacement.path)
            .copied()
            .ok_or(PartialError::UnsupportedPartialOperation)?;
        if !matches!(destination.mode(), EntryMode::Blob | EntryMode::Executable) {
            return Err(PartialError::UnsupportedPartialOperation);
        }
        let len = match &replacement.content {
            ReplacementContent::Bytes(bytes) => bytes.len(),
            ReplacementContent::ReuseSelected(source_path) => usize::try_from(
                files
                    .get(source_path)
                    .ok_or(PartialError::UnsupportedPartialOperation)?
                    .content_len(),
            )
            .map_err(|_| PartialError::WorkspaceTooLarge)?,
        };
        if len > limits.max_selected_file_bytes {
            return Err(PartialError::WorkspaceTooLarge);
        }
        total = total
            .checked_add(len)
            .ok_or(PartialError::WorkspaceTooLarge)?;
        if total > limits.max_total_selected_bytes {
            return Err(PartialError::WorkspaceTooLarge);
        }
    }
    Ok(())
}

fn preflight_affected_trees(
    verified: &VerifiedPartialSnapshot,
    replacements: &[PendingReplacement<'_>],
    limits: &PartialLimits,
) -> Result<(), PartialError> {
    let root = match verified.base_object() {
        Object::Commit(commit) => commit.tree_hash,
        Object::Remix(remix) => remix.tree_hash,
        _ => return Err(PartialError::WrongObjectType),
    };
    let trees = verified
        .trees()
        .map(|tree| (*tree.id(), tree.tree()))
        .collect::<BTreeMap<_, _>>();
    let mut checked = BTreeSet::new();
    for replacement in replacements {
        let mut tree_id = root;
        for (index, component) in replacement.path.iter().enumerate() {
            if checked.insert(tree_id) {
                validate_output_object(
                    verified
                        .object_bytes(&tree_id)
                        .ok_or(PartialError::InsufficientWitness)?,
                    limits,
                )?;
            }
            if index + 1 == replacement.path.len() {
                break;
            }
            let tree = trees
                .get(&tree_id)
                .ok_or(PartialError::InsufficientWitness)?;
            let entry = tree
                .entries
                .iter()
                .find(|entry| entry.name == *component)
                .ok_or(PartialError::IncompleteSelection)?;
            if entry.mode != EntryMode::Tree {
                return Err(PartialError::WrongObjectType);
            }
            tree_id = entry.object_hash;
        }
    }
    Ok(())
}

/// Build the ordinary unsigned one-parent Commit that a caller signs through
/// the existing signing interface.
pub fn prepare_partial_commit(
    verified: &VerifiedPartialSnapshot,
    prepared: &PreparedPartialEdit,
    author: Identity,
    signer: [u8; 32],
    message: Vec<u8>,
    timestamp: u64,
    limits: &PartialLimits,
) -> Result<Commit, PartialError> {
    if !limits.is_v1_subset() || message.len() > limits.max_commit_message_bytes {
        return Err(PartialError::ValidationBudgetExceeded);
    }
    if prepared.base_id != *verified.base_id() {
        return Err(PartialError::CommitMismatch);
    }
    validate_prepared_output(verified, prepared, limits)?;
    let commit = Commit::new_unannotated(
        prepared.root_id,
        vec![*verified.base_id()],
        author,
        signer,
        message,
        timestamp,
        [0; 64],
    );
    let bytes =
        serialize(&Object::Commit(commit.clone())).map_err(|_| PartialError::NonCanonical)?;
    if bytes.len() > limits.max_object_bytes {
        return Err(PartialError::SubmissionTooLarge);
    }
    Ok(commit)
}

fn rebuild_tree(
    verified: &VerifiedPartialSnapshot,
    collector: &BoundedCollector,
    tree_id: Hash,
    edits: &EditNode,
    limits: &PartialLimits,
) -> Result<Hash, PartialError> {
    let tree = verified
        .trees()
        .find(|tree| *tree.id() == tree_id)
        .ok_or(PartialError::InsufficientWitness)?;
    let mut rebuilt = Tree {
        entries: tree.tree().entries.clone(),
    };
    for (name, child_edit) in &edits.children {
        let entry = rebuilt
            .entries
            .iter_mut()
            .find(|entry| entry.name == *name)
            .ok_or(PartialError::IncompleteSelection)?;
        if let Some(replacement) = child_edit.replacement {
            if !child_edit.children.is_empty()
                || !matches!(entry.mode, EntryMode::Blob | EntryMode::Executable)
            {
                return Err(PartialError::UnsupportedPartialOperation);
            }
            entry.object_hash = replacement;
        } else {
            if entry.mode != EntryMode::Tree {
                return Err(PartialError::WrongObjectType);
            }
            entry.object_hash =
                rebuild_tree(verified, collector, entry.object_hash, child_edit, limits)?;
        }
    }
    let bytes = serialize(&Object::Tree(rebuilt)).map_err(|_| PartialError::NonCanonical)?;
    preflight_tree(&bytes, limits)?;
    collector
        .put(&bytes)
        .map_err(|error| collector.translate_error(error))
}

fn map_writer_error(collector: &BoundedCollector, error: WorktreeError) -> PartialError {
    match error {
        WorktreeError::Store(error) => collector.translate_error(error),
        WorktreeError::FileTooLarge(_) => PartialError::WorkspaceTooLarge,
        _ => PartialError::NonCanonical,
    }
}

fn joined(path: &PartialPath) -> Vec<u8> {
    path.iter()
        .enumerate()
        .fold(Vec::new(), |mut out, (index, component)| {
            if index != 0 {
                out.push(b'/');
            }
            out.extend_from_slice(component);
            out
        })
}

fn ordered_pair(left: Hash, right: Hash) -> (Hash, Hash) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

pub(crate) fn validate_prepared_output(
    verified: &VerifiedPartialSnapshot,
    prepared: &PreparedPartialEdit,
    limits: &PartialLimits,
) -> Result<(), PartialError> {
    if !limits.is_v1_subset() {
        return Err(PartialError::ValidationBudgetExceeded);
    }
    if prepared.base_id != *verified.base_id() {
        return Err(PartialError::CommitMismatch);
    }
    if prepared.changes.is_empty() || prepared.changes.len() > limits.max_changed_paths {
        return Err(PartialError::ValidationBudgetExceeded);
    }
    super::validate_paths(
        &prepared
            .changes
            .iter()
            .map(|change| change.path.clone())
            .collect::<Vec<_>>(),
        limits,
    )?;
    let mut total = 0usize;
    for change in &prepared.changes {
        if change.content_len > limits.max_selected_file_bytes {
            return Err(PartialError::WorkspaceTooLarge);
        }
        total = total
            .checked_add(change.content_len)
            .ok_or(PartialError::WorkspaceTooLarge)?;
        if total > limits.max_total_selected_bytes {
            return Err(PartialError::WorkspaceTooLarge);
        }
    }

    let mut inventory = BTreeMap::new();
    let mut pack_bytes = 12 + 32;
    for (id, bytes) in &prepared.produced {
        validate_output_object(bytes, limits)?;
        if let Some(existing) = inventory.get(id) {
            if *existing != bytes.as_slice() {
                return Err(PartialError::NonCanonical);
            }
        } else {
            if inventory.len() >= limits.max_update_objects {
                return Err(PartialError::ValidationBudgetExceeded);
            }
            pack_bytes = charge_raw_bytes(pack_bytes, bytes.len(), limits)?;
            inventory.insert(*id, bytes.as_slice());
        }
    }
    for id in &prepared.dependency_ids {
        let bytes = verified
            .object_bytes(id)
            .ok_or(PartialError::InsufficientWitness)?;
        validate_output_object(bytes, limits)?;
        if let Some(existing) = inventory.get(id) {
            if *existing != bytes {
                return Err(PartialError::NonCanonical);
            }
        } else {
            if inventory.len() >= limits.max_update_objects {
                return Err(PartialError::ValidationBudgetExceeded);
            }
            pack_bytes = charge_raw_bytes(pack_bytes, bytes.len(), limits)?;
            inventory.insert(*id, bytes);
        }
    }
    Ok(())
}

pub(crate) fn validate_output_object(
    bytes: &[u8],
    limits: &PartialLimits,
) -> Result<(), PartialError> {
    if bytes.len() > limits.max_object_bytes {
        return Err(PartialError::SubmissionTooLarge);
    }
    match bytes.first().copied() {
        Some(tag) if tag == ObjectType::Tree as u8 => preflight_tree(bytes, limits),
        Some(tag) if tag == ObjectType::Blob as u8 || tag == ObjectType::ChunkedBlob as u8 => {
            preflight_file(bytes, limits)
        }
        _ => Err(PartialError::WrongObjectType),
    }
}

fn charge_raw_bytes(
    current: usize,
    bytes_len: usize,
    limits: &PartialLimits,
) -> Result<usize, PartialError> {
    let next = current
        .checked_add(5)
        .and_then(|value| value.checked_add(bytes_len))
        .ok_or(PartialError::SubmissionTooLarge)?;
    if next > limits.max_raw_pack_bytes {
        return Err(PartialError::SubmissionTooLarge);
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::ZERO;
    use crate::layout::RepoLayout;
    use crate::object::{Blob, ChunkedBlob, TreeEntry, id_from_object};
    use crate::pack::{PackEntries, PackEntry, PackReader};
    use crate::sign::{KeyPair, sign_commit};
    use crate::store::ObjectStore;
    use crate::verify::verify_closure_store;
    use crate::{
        ClosureMode, build_partial_snapshot, export_partial_update, prepare_partial_commit,
        verify_partial_snapshot,
    };

    fn put(store: &ObjectStore, object: &Object) -> Hash {
        let bytes = serialize(object).unwrap();
        let id = id_from_object(object, &bytes);
        assert_eq!(store.write(&bytes).unwrap(), id);
        id
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one end-to-end resource oracle keeps fixture and assertions together
    fn dependency_retention_is_unique_across_reused_destinations() {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        let one = put(&store, &Object::Blob(Blob { data: vec![1] }));
        let empty = put(&store, &Object::Blob(Blob { data: Vec::new() }));
        let mut forward_chunks = vec![one];
        forward_chunks.resize(65, empty);
        let mut reverse_chunks = vec![empty; 64];
        reverse_chunks.push(one);
        let forward = put(
            &store,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: 1,
                chunk_size: 0,
                chunks: forward_chunks,
            }),
        );
        let reverse = put(
            &store,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: 1,
                chunk_size: 0,
                chunks: reverse_chunks,
            }),
        );
        let noop = put(
            &store,
            &Object::Blob(Blob {
                data: b"noop".to_vec(),
            }),
        );
        let names_and_ids = [
            (b"d1".as_slice(), empty),
            (b"d2".as_slice(), empty),
            (b"d3".as_slice(), empty),
            (b"noop".as_slice(), noop),
            (b"source-a".as_slice(), forward),
            (b"source-b".as_slice(), reverse),
        ];
        let root = put(
            &store,
            &Object::Tree(Tree {
                entries: names_and_ids
                    .iter()
                    .map(|(name, id)| TreeEntry {
                        name: name.to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: *id,
                    })
                    .collect(),
            }),
        );
        let key = KeyPair::from_seed([31; 32]);
        let mut commit = Commit::new_unannotated(
            root,
            Vec::new(),
            Identity::ed25519(key.public.0),
            key.public.0,
            b"metadata-heavy".to_vec(),
            1,
            [0; 64],
        );
        commit.message_hash = ZERO;
        commit.content_digest = ZERO;
        commit.signature = sign_commit(&commit, &key).unwrap().0;
        let base = put(&store, &Object::Commit(commit));
        let paths = names_and_ids
            .iter()
            .map(|(name, _)| vec![name.to_vec()])
            .collect::<Vec<_>>();
        let limits = PartialLimits::V1;
        let bundle = build_partial_snapshot(&store, base, &paths, &limits).unwrap();
        let verified =
            verify_partial_snapshot(base, &paths, &bundle.encode(&limits).unwrap(), &limits)
                .unwrap();

        let supplied = replace_files(
            &verified,
            &[
                FileReplacement::bytes(paths[0].clone(), vec![2]),
                FileReplacement::bytes(paths[1].clone(), vec![2]),
                FileReplacement::bytes(paths[2].clone(), vec![3]),
                FileReplacement::bytes(paths[4].clone(), vec![2]),
                FileReplacement::bytes(paths[5].clone(), vec![2]),
            ],
            &limits,
        )
        .unwrap();
        // Different replacement bytes must still share one authenticated load.
        assert_eq!(supplied.accounting.byte_representations_loaded, 3);
        assert_eq!(supplied.changes.len(), 5);
        assert_eq!(supplied.changes[0].new_id, supplied.changes[1].new_id);
        assert_ne!(supplied.changes[1].new_id, supplied.changes[2].new_id);

        let prepared = replace_files(
            &verified,
            &[
                FileReplacement::reuse_selected(paths[3].clone(), paths[3].clone()),
                FileReplacement::reuse_selected(paths[0].clone(), paths[4].clone()),
                FileReplacement::reuse_selected(paths[1].clone(), paths[4].clone()),
                FileReplacement::reuse_selected(paths[2].clone(), paths[5].clone()),
            ],
            &limits,
        )
        .unwrap();

        assert_eq!(prepared.changes.len(), 3);
        assert_eq!(
            prepared
                .changes
                .iter()
                .map(|change| change.content_len)
                .sum::<usize>(),
            3
        );
        assert_eq!(prepared.dependency_ids.len(), 4);
        assert!(!prepared.dependency_ids.contains(&noop));
        assert_eq!(prepared.accounting.dependency_occurrences_scanned, 130);
        assert_eq!(prepared.accounting.reuse_comparisons, 3);

        let unsigned = prepare_partial_commit(
            &verified,
            &prepared,
            Identity::opaque(b"author".to_vec()),
            key.public.0,
            b"reuse metadata-heavy representations".to_vec(),
            2,
            &limits,
        )
        .unwrap();
        let mut signed = unsigned.clone();
        signed.signature = sign_commit(&signed, &key).unwrap().0;
        let update =
            export_partial_update(&verified, &prepared, &unsigned, &signed, &limits).unwrap();
        let encoded_update = update.encode(&limits).unwrap();
        super::super::update::reset_decode_chunk_occurrences();
        assert!(super::super::update::PartialUpdate::decode(&encoded_update, &limits).is_ok());
        assert_eq!(super::super::update::decode_chunk_occurrences(), 130);
        let packed_ids = PackEntries::new(update.pack_bytes())
            .unwrap()
            .map(|entry| match entry.unwrap() {
                PackEntry::Raw { bytes } => {
                    let object = crate::deserialize(bytes.as_ref()).unwrap();
                    id_from_object(&object, bytes.as_ref())
                }
                PackEntry::Delta { .. } => unreachable!(),
            })
            .collect::<BTreeSet<_>>();
        let expected_ids = prepared
            .produced
            .keys()
            .copied()
            .chain(prepared.dependency_ids.iter().copied())
            .chain(std::iter::once(*update.candidate_id()))
            .collect::<BTreeSet<_>>();
        assert_eq!(packed_ids, expected_ids);

        let recipient_dir = tempfile::tempdir().unwrap();
        let recipient = ObjectStore::init(&RepoLayout::single(recipient_dir.path())).unwrap();
        for id in [base, root, one, empty, forward, reverse, noop] {
            recipient.write(&store.read(&id).unwrap()).unwrap();
        }
        PackReader::read(update.pack_bytes(), &recipient).unwrap();
        assert!(
            verify_closure_store(&recipient, update.candidate_id(), ClosureMode::Snapshot)
                .unwrap()
                .is_complete()
        );

        let manifest_len = store.read(&forward).unwrap().len();
        assert!(
            prepared
                .produced
                .values()
                .all(|bytes| bytes.len() < manifest_len)
        );
        assert!(serialize(&Object::Commit(signed.clone())).unwrap().len() < manifest_len);
        let stricter = PartialLimits {
            max_object_bytes: manifest_len - 1,
            ..limits
        };
        super::super::update::reset_pack_build_count();
        assert!(matches!(
            export_partial_update(&verified, &prepared, &unsigned, &signed, &stricter),
            Err(PartialError::SubmissionTooLarge)
        ));
        assert_eq!(super::super::update::pack_build_count(), 0);

        super::super::collector::reset_collected_object_count();
        let combined_count_limit = PartialLimits {
            max_update_objects: 3,
            ..limits
        };
        assert!(matches!(
            replace_files(
                &verified,
                &[
                    FileReplacement::bytes(paths[0].clone(), b"generated".to_vec()),
                    FileReplacement::reuse_selected(paths[1].clone(), paths[4].clone()),
                ],
                &combined_count_limit,
            ),
            Err(PartialError::ValidationBudgetExceeded)
        ));
        assert_eq!(super::super::collector::collected_object_count(), 1);

        super::super::collector::reset_collected_object_count();
        let combined_pack_limit = PartialLimits {
            max_raw_pack_bytes: 100,
            ..limits
        };
        assert!(matches!(
            replace_files(
                &verified,
                &[
                    FileReplacement::bytes(paths[0].clone(), b"generated".to_vec()),
                    FileReplacement::reuse_selected(paths[1].clone(), paths[4].clone()),
                ],
                &combined_pack_limit,
            ),
            Err(PartialError::SubmissionTooLarge)
        ));
        assert_eq!(super::super::collector::collected_object_count(), 1);

        super::super::collector::reset_collected_object_count();
        let tree_limit = PartialLimits {
            max_tree_entries: names_and_ids.len() - 1,
            ..limits
        };
        assert!(matches!(
            replace_files(
                &verified,
                &[FileReplacement::bytes(
                    paths[0].clone(),
                    b"generated".to_vec(),
                )],
                &tree_limit,
            ),
            Err(PartialError::ValidationBudgetExceeded)
        ));
        assert_eq!(super::super::collector::collected_object_count(), 0);

        super::super::collector::reset_collected_object_count();
        let tree_bytes_limit = PartialLimits {
            max_tree_object_bytes: store.read(&root).unwrap().len() - 1,
            ..limits
        };
        assert!(matches!(
            replace_files(
                &verified,
                &[FileReplacement::bytes(
                    paths[0].clone(),
                    b"generated".to_vec(),
                )],
                &tree_bytes_limit,
            ),
            Err(PartialError::WitnessTooLarge)
        ));
        assert_eq!(super::super::collector::collected_object_count(), 0);

        let no_op_limits = PartialLimits {
            max_tree_entries: 0,
            max_tree_object_bytes: 1,
            max_raw_pack_bytes: 1,
            max_update_objects: 0,
            ..limits
        };
        assert!(matches!(
            replace_files(
                &verified,
                &[FileReplacement::reuse_selected(
                    paths[3].clone(),
                    paths[3].clone(),
                )],
                &no_op_limits,
            ),
            Err(PartialError::NoChanges)
        ));

        let mut conflicting = prepared.clone();
        let different_bytes = conflicting.produced.values().next().unwrap().clone();
        conflicting.produced.insert(forward, different_bytes);
        assert!(matches!(
            validate_prepared_output(&verified, &conflicting, &limits),
            Err(PartialError::NonCanonical)
        ));
    }
}
