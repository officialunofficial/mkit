//! Authenticated replacement overlay and ordinary commit preparation.

use std::collections::{BTreeMap, BTreeSet};

use crate::hash::{Hash, to_hex};
use crate::object::{Commit, EntryMode, Identity, Object, Tree};
use crate::serialize::serialize;
use crate::store::{ObjectSink, ObjectSource, StoreError, StoreResult};
use crate::worktree::{WorktreeError, content_eq, content_eq_bytes, store_file_object};

use super::collector::BoundedCollector;
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
    pub(crate) dependency_ids: Vec<Hash>,
}

/// Privately constructed, immutable result of applying an authenticated
/// replacement batch.
#[derive(Debug, Clone)]
pub struct PreparedPartialEdit {
    pub(crate) base_id: Hash,
    pub(crate) root_id: Hash,
    pub(crate) changes: Vec<PreparedChange>,
    pub(crate) produced: BTreeMap<Hash, Vec<u8>>,
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

    let (collector, mut changes) = collect_replacements(verified, replacements, limits)?;
    if changes.is_empty() {
        return Err(PartialError::NoChanges);
    }
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
    let root_id = rebuild_tree(verified, &collector, root, &edits)?;
    let produced = collector.into_objects();
    Ok(PreparedPartialEdit {
        base_id: *verified.base_id(),
        root_id,
        changes,
        produced,
    })
}

fn collect_replacements(
    verified: &VerifiedPartialSnapshot,
    replacements: &[FileReplacement],
    limits: &PartialLimits,
) -> Result<(BoundedCollector, Vec<PreparedChange>), PartialError> {
    let files: BTreeMap<&PartialPath, &SelectedFile> = verified
        .files()
        .iter()
        .map(|file| (file.path(), file))
        .collect();
    preflight_replacements(&files, replacements, limits)?;
    let source = SnapshotSource(verified);
    let collector = BoundedCollector::new(limits)?;
    let mut changes = Vec::new();

    for replacement in replacements {
        let destination = files
            .get(&replacement.path)
            .copied()
            .ok_or(PartialError::UnsupportedPartialOperation)?;

        let (new_id, dependency_ids, equal) = match &replacement.content {
            ReplacementContent::Bytes(bytes) => {
                let equal = content_eq_bytes(&source, destination.object_id(), bytes)
                    .map_err(PartialError::Source)?;
                if equal {
                    (*destination.object_id(), Vec::new(), true)
                } else {
                    let id = store_file_object(&collector, bytes)
                        .map_err(|error| map_writer_error(&collector, error))?;
                    let deps = dependencies_from_collector(&collector, &id)?;
                    (id, deps, false)
                }
            }
            ReplacementContent::ReuseSelected(source_path) => {
                let selected = files
                    .get(source_path)
                    .copied()
                    .ok_or(PartialError::UnsupportedPartialOperation)?;
                let equal = content_eq(&source, destination.object_id(), selected.object_id())
                    .map_err(PartialError::Source)?;
                let mut deps = Vec::with_capacity(1 + selected.chunk_ids().len());
                deps.push(*selected.object_id());
                deps.extend_from_slice(selected.chunk_ids());
                (*selected.object_id(), deps, equal)
            }
        };
        if !equal {
            changes.push(PreparedChange {
                path: replacement.path.clone(),
                old_mode: destination.mode(),
                old_id: *destination.object_id(),
                new_id,
                dependency_ids,
            });
        }
    }

    Ok((collector, changes))
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
    let commit = Commit::new_unannotated(
        prepared.root_id,
        vec![*verified.base_id()],
        author,
        signer,
        message,
        timestamp,
        [0; 64],
    );
    serialize(&Object::Commit(commit.clone())).map_err(|_| PartialError::NonCanonical)?;
    Ok(commit)
}

fn rebuild_tree(
    verified: &VerifiedPartialSnapshot,
    collector: &BoundedCollector,
    tree_id: Hash,
    edits: &EditNode,
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
            entry.object_hash = rebuild_tree(verified, collector, entry.object_hash, child_edit)?;
        }
    }
    let bytes = serialize(&Object::Tree(rebuilt)).map_err(|_| PartialError::NonCanonical)?;
    collector
        .put(&bytes)
        .map_err(|error| collector.translate_error(error))
}

fn dependencies_from_collector(
    collector: &BoundedCollector,
    top: &Hash,
) -> Result<Vec<Hash>, PartialError> {
    let bytes = collector
        .object_bytes(top)
        .ok_or(PartialError::InsufficientWitness)?;
    let object = crate::serialize::deserialize(&bytes).map_err(|_| PartialError::NonCanonical)?;
    let mut ids = vec![*top];
    if let Object::ChunkedBlob(manifest) = object {
        ids.extend(manifest.chunks);
    }
    Ok(ids)
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
