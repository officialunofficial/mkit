//! Bounded actual-frontier and exact supplied-origin transitions for MKWU.
//!
//! Records are restorable trusted bookkeeping, never portable proof that an
//! external queue, seen ledger or inventory index is complete.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::Arc;

use crate::hash::Hash;
use crate::object::EntryMode;

use super::PartialPath;
use super::inspect::{InspectedKind, InspectedObject, SnapshotRole};
use super::staged_update::{
    ContextBinding, StagedCandidateFact, StagedUpdateError, StagedUpdateUsageV1,
    StagedValidationContext,
};

/// Maximum entries compared or chunk positions checked in one step.
pub const MAX_STAGED_PAGE: usize = 64;

/// One actual Tree-pair occurrence or continuation. The caller must bind
/// restored records to the same header, limits and fenced generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangedPairRecord {
    Visit {
        old_id: Hash,
        new_id: Hash,
        path: PartialPath,
    },
    Page {
        old_id: Hash,
        new_id: Hash,
        path: PartialPath,
        next_index: u32,
    },
}

impl ChangedPairRecord {
    #[must_use]
    pub fn old_id(&self) -> Hash {
        match self {
            Self::Visit { old_id, .. } | Self::Page { old_id, .. } => *old_id,
        }
    }
    #[must_use]
    pub fn new_id(&self) -> Hash {
        match self {
            Self::Visit { new_id, .. } | Self::Page { new_id, .. } => *new_id,
        }
    }
    #[must_use]
    pub fn path(&self) -> &PartialPath {
        match self {
            Self::Visit { path, .. } | Self::Page { path, .. } => path,
        }
    }
}

/// A declared changed-file occurrence or a manifest-page continuation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequiredFileRecord {
    Visit {
        change_index: u32,
        expected_file_id: Hash,
    },
    ManifestPage {
        change_index: u32,
        expected_file_id: Hash,
        next_index: u32,
        sum: u64,
    },
}

impl RequiredFileRecord {
    #[must_use]
    pub fn change_index(&self) -> u32 {
        match self {
            Self::Visit { change_index, .. } | Self::ManifestPage { change_index, .. } => {
                *change_index
            }
        }
    }
    #[must_use]
    pub fn expected_file_id(&self) -> Hash {
        match self {
            Self::Visit {
                expected_file_id, ..
            }
            | Self::ManifestPage {
                expected_file_id, ..
            } => *expected_file_id,
        }
    }
}

/// One required supplied object, derived from an inspected fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StagedRequiredObservation {
    id: Hash,
    role: SnapshotRole,
    canonical_len: u64,
    change_index: Option<u32>,
}

impl StagedRequiredObservation {
    #[must_use]
    pub fn id(&self) -> Hash {
        self.id
    }
    #[must_use]
    pub fn role(&self) -> SnapshotRole {
        self.role
    }
    #[must_use]
    pub fn canonical_len(&self) -> u64 {
        self.canonical_len
    }
    #[must_use]
    pub fn change_index(&self) -> Option<u32> {
        self.change_index
    }
}

/// One local changed-pair transition, not a complete diff certificate.
#[derive(Debug)]
pub struct ChangedPairStep {
    binding: Arc<ContextBinding>,
    successors: Vec<ChangedPairRecord>,
    files: Vec<RequiredFileRecord>,
    matched_indices: Vec<u32>,
    observations: Vec<StagedRequiredObservation>,
    pair_visits: u64,
    compared_entries: u64,
    origin_work: u64,
}

impl ChangedPairStep {
    #[must_use]
    pub fn successors(&self) -> &[ChangedPairRecord] {
        &self.successors
    }
    #[must_use]
    pub fn files(&self) -> &[RequiredFileRecord] {
        &self.files
    }
    #[must_use]
    pub fn matched_indices(&self) -> &[u32] {
        &self.matched_indices
    }
    #[must_use]
    pub fn observations(&self) -> &[StagedRequiredObservation] {
        &self.observations
    }
}

/// One bounded required-file transition. A Visit's reservation is charged
/// before its successor can request chunks; a completed page does not charge
/// the file bytes again.
#[derive(Debug)]
pub struct RequiredFileStep {
    binding: Arc<ContextBinding>,
    successors: Vec<RequiredFileRecord>,
    observations: Vec<StagedRequiredObservation>,
    reserve_file_bytes: Option<u64>,
    origin_work: u64,
    complete: bool,
}

impl RequiredFileStep {
    #[must_use]
    pub fn successors(&self) -> &[RequiredFileRecord] {
        &self.successors
    }
    #[must_use]
    pub fn observations(&self) -> &[StagedRequiredObservation] {
        &self.observations
    }
    #[must_use]
    pub fn complete(&self) -> bool {
        self.complete
    }
}

fn required(
    fact: &InspectedObject,
    role: SnapshotRole,
    index: Option<u32>,
) -> Result<StagedRequiredObservation, StagedUpdateError> {
    Ok(StagedRequiredObservation {
        id: fact.id(),
        role,
        canonical_len: u64::try_from(fact.canonical_len())
            .map_err(|_| StagedUpdateError::Budget)?,
        change_index: index,
    })
}

fn empty_step(context: &StagedValidationContext) -> ChangedPairStep {
    ChangedPairStep {
        binding: context.binding(),
        successors: Vec::new(),
        files: Vec::new(),
        matched_indices: Vec::new(),
        observations: Vec::new(),
        pair_visits: 0,
        compared_entries: 0,
        origin_work: 0,
    }
}

/// Bind independently inspected base/candidate roots to the canonical header
/// and derive both root Tree IDs without accepting a caller-chosen raw ID.
///
/// # Errors
/// Refuses wrong role/ID/base binding or absent root Tree facts.
pub fn start_changed_pairs(
    base_root: &InspectedObject,
    candidate: &StagedCandidateFact,
    context: &StagedValidationContext,
) -> Result<ChangedPairStep, StagedUpdateError> {
    if base_root.role() != Some(SnapshotRole::BaseRoot)
        || base_root.id() != context.header().base_id()
        || base_root.canonical_len() > context.portable().max_base_object_bytes
        || base_root.canonical_len() > context.inspection().max_object_bytes
        || candidate.object().role() != Some(SnapshotRole::CandidateRoot)
        || candidate.id() != context.header().candidate_id()
        || candidate.base_id() != context.header().base_id()
        || !candidate.matches_context(context)
    {
        return Err(StagedUpdateError::Inconsistent);
    }
    let (old_id, _) = base_root.root().ok_or(StagedUpdateError::Invalid)?;
    let (new_id, _) = candidate
        .object()
        .root()
        .ok_or(StagedUpdateError::Invalid)?;
    let mut step = empty_step(context);
    step.successors.push(ChangedPairRecord::Visit {
        old_id,
        new_id,
        path: PartialPath::new(),
    });
    step.observations.push(required(
        candidate.object(),
        SnapshotRole::CandidateRoot,
        None,
    )?);
    step.origin_work = 1;
    Ok(step)
}

fn width(value: NonZeroUsize) -> Result<usize, StagedUpdateError> {
    if value.get() > MAX_STAGED_PAGE {
        return Err(StagedUpdateError::Budget);
    }
    Ok(value.get())
}

fn valid_path(path: &PartialPath, context: &StagedValidationContext) -> bool {
    path.len() <= context.portable().max_path_depth
        && path
            .iter()
            .all(|part| !part.is_empty() && part.len() <= context.portable().max_component_bytes)
        && path
            .iter()
            .try_fold(0usize, |sum, part| sum.checked_add(part.len() + 1))
            .is_some_and(|bytes| bytes <= context.portable().max_path_bytes + 1)
}

fn declared_descendant(path: &PartialPath, name: &[u8], context: &StagedValidationContext) -> bool {
    context.header().changes().iter().any(|change| {
        change.path().starts_with(path)
            && change
                .path()
                .get(path.len())
                .is_some_and(|part| part == name)
    })
}

fn declared_leaf(
    path: &PartialPath,
    name: &[u8],
    context: &StagedValidationContext,
) -> Option<usize> {
    context.header().changes().iter().position(|change| {
        change.path().len() == path.len() + 1
            && change.path().starts_with(path)
            && change.path().last().is_some_and(|part| part == name)
    })
}

fn child_path(
    path: &PartialPath,
    name: &[u8],
    context: &StagedValidationContext,
) -> Result<PartialPath, StagedUpdateError> {
    let depth = path.len().checked_add(1).ok_or(StagedUpdateError::Budget)?;
    let bytes = path
        .iter()
        .try_fold(0usize, |sum, part| sum.checked_add(part.len() + 1))
        .and_then(|sum| sum.checked_add(name.len()))
        .ok_or(StagedUpdateError::Budget)?;
    if depth > context.portable().max_path_depth || bytes > context.portable().max_path_bytes {
        return Err(StagedUpdateError::Budget);
    }
    let mut child = path.clone();
    child.push(name.to_vec());
    Ok(child)
}

fn tree_matches(fact: &InspectedObject, id: Hash, context: &StagedValidationContext) -> bool {
    fact.id() == id
        && fact.kind() == InspectedKind::Tree
        && fact.role().is_none_or(|role| role == SnapshotRole::Tree)
        && fact.canonical_len()
            <= context
                .portable()
                .max_tree_object_bytes
                .min(context.inspection().max_tree_bytes)
                .min(context.inspection().max_object_bytes)
        && fact.tree_entries_len().is_some_and(|count| {
            count
                <= context
                    .portable()
                    .max_tree_entries
                    .min(context.inspection().max_tree_entries)
        })
}

/// Compare one actual Tree-pair occurrence or page against declared paths.
/// Each page checks at most 64 corresponding entries and preflights all
/// changed child records before cloning a path or growing successors.
///
/// # Errors
/// Refuses mismatched facts, malformed cursor, undeclared/mode/name/count
/// changes, wrong old/new leaf, or output/path bounds.
#[allow(clippy::too_many_lines)] // One auditable transition keeps preflight and emission paired.
pub fn advance_changed_pair(
    record: &ChangedPairRecord,
    old: &InspectedObject,
    new: &InspectedObject,
    context: &StagedValidationContext,
    page_width: NonZeroUsize,
) -> Result<ChangedPairStep, StagedUpdateError> {
    let width = width(page_width)?;
    if !valid_path(record.path(), context)
        || !tree_matches(old, record.old_id(), context)
        || !tree_matches(new, record.new_id(), context)
    {
        return Err(StagedUpdateError::Inconsistent);
    }
    if record.old_id() == record.new_id() {
        if !matches!(record, ChangedPairRecord::Visit { .. }) {
            return Err(StagedUpdateError::Inconsistent);
        }
        let mut step = empty_step(context);
        step.pair_visits = 1;
        return Ok(step);
    }
    let old_count = old.tree_entries_len().ok_or(StagedUpdateError::Invalid)?;
    let new_count = new.tree_entries_len().ok_or(StagedUpdateError::Invalid)?;
    if old_count != new_count {
        return Err(StagedUpdateError::Invalid);
    }
    let mut step = empty_step(context);
    match record {
        ChangedPairRecord::Visit {
            old_id,
            new_id,
            path,
        } => {
            if !context
                .header()
                .changes()
                .iter()
                .any(|change| change.path().starts_with(path))
            {
                return Err(StagedUpdateError::Invalid);
            }
            step.pair_visits = 1;
            step.origin_work = 1;
            step.observations
                .push(required(new, SnapshotRole::Tree, None)?);
            if old_count != 0 {
                step.successors.push(ChangedPairRecord::Page {
                    old_id: *old_id,
                    new_id: *new_id,
                    path: path.clone(),
                    next_index: 0,
                });
            }
        }
        ChangedPairRecord::Page {
            old_id,
            new_id,
            path,
            next_index,
        } => {
            let start = usize::try_from(*next_index).map_err(|_| StagedUpdateError::Budget)?;
            if start >= old_count {
                return Err(StagedUpdateError::Inconsistent);
            }
            let count = (old_count - start).min(width);
            let before = old.tree_page(start, count)?;
            let after = new.tree_page(start, count)?;
            // Validate the entire page and count changed successors first.
            let mut children = 0usize;
            let mut child_bytes = 0usize;
            for (left, right) in before.iter().zip(after) {
                if left.name != right.name || left.mode != right.mode {
                    return Err(StagedUpdateError::Invalid);
                }
                if left.object_hash == right.object_hash {
                    continue;
                }
                if left.mode == EntryMode::Tree {
                    if !declared_descendant(path, &left.name, context) {
                        return Err(StagedUpdateError::Invalid);
                    }
                    // Preflight path shape before any child path is cloned.
                    let depth = path.len().checked_add(1).ok_or(StagedUpdateError::Budget)?;
                    let bytes = path
                        .iter()
                        .try_fold(0usize, |sum, part| sum.checked_add(part.len() + 1))
                        .and_then(|sum| sum.checked_add(left.name.len()))
                        .ok_or(StagedUpdateError::Budget)?;
                    if depth > context.portable().max_path_depth
                        || bytes > context.portable().max_path_bytes
                    {
                        return Err(StagedUpdateError::Budget);
                    }
                } else {
                    if !matches!(left.mode, EntryMode::Blob | EntryMode::Executable) {
                        return Err(StagedUpdateError::Invalid);
                    }
                    let index = declared_leaf(path, &left.name, context)
                        .ok_or(StagedUpdateError::Invalid)?;
                    let change = &context.header().changes()[index];
                    if change.old_mode() != left.mode
                        || change.old_id() != left.object_hash
                        || change.new_id() != right.object_hash
                    {
                        return Err(StagedUpdateError::Invalid);
                    }
                }
                children = children.checked_add(1).ok_or(StagedUpdateError::Budget)?;
                child_bytes = child_bytes
                    .checked_add(left.name.len())
                    .ok_or(StagedUpdateError::Budget)?;
                if children > MAX_STAGED_PAGE
                    || child_bytes > MAX_STAGED_PAGE * context.portable().max_component_bytes
                {
                    return Err(StagedUpdateError::Budget);
                }
            }
            step.successors
                .reserve(children + usize::from(start + count < old_count));
            step.files.reserve(children);
            for (left, right) in before.iter().zip(after) {
                if left.object_hash == right.object_hash {
                    continue;
                }
                if left.mode == EntryMode::Tree {
                    step.successors.push(ChangedPairRecord::Visit {
                        old_id: left.object_hash,
                        new_id: right.object_hash,
                        path: child_path(path, &left.name, context)?,
                    });
                } else {
                    if !matches!(left.mode, EntryMode::Blob | EntryMode::Executable) {
                        return Err(StagedUpdateError::Invalid);
                    }
                    let index = declared_leaf(path, &left.name, context)
                        .ok_or(StagedUpdateError::Invalid)?;
                    let change = &context.header().changes()[index];
                    if change.old_mode() != left.mode
                        || change.old_id() != left.object_hash
                        || change.new_id() != right.object_hash
                    {
                        return Err(StagedUpdateError::Invalid);
                    }
                    let index = u32::try_from(index).map_err(|_| StagedUpdateError::Budget)?;
                    step.matched_indices.push(index);
                    step.files.push(RequiredFileRecord::Visit {
                        change_index: index,
                        expected_file_id: right.object_hash,
                    });
                }
            }
            if start + count < old_count {
                step.successors.push(ChangedPairRecord::Page {
                    old_id: *old_id,
                    new_id: *new_id,
                    path: path.clone(),
                    next_index: u32::try_from(start + count)
                        .map_err(|_| StagedUpdateError::Budget)?,
                });
            }
            step.compared_entries = u64::try_from(count).map_err(|_| StagedUpdateError::Budget)?;
        }
    }
    Ok(step)
}

fn valid_required_file(
    record: &RequiredFileRecord,
    file: &InspectedObject,
    context: &StagedValidationContext,
) -> Result<usize, StagedUpdateError> {
    let index =
        usize::try_from(record.change_index()).map_err(|_| StagedUpdateError::Inconsistent)?;
    let change = context
        .header()
        .changes()
        .get(index)
        .ok_or(StagedUpdateError::Inconsistent)?;
    if change.new_id() != record.expected_file_id()
        || file.id() != record.expected_file_id()
        || !matches!(
            file.kind(),
            InspectedKind::Blob | InspectedKind::ChunkedBlob
        )
        || file.role().is_some_and(|role| role != SnapshotRole::File)
        || file.canonical_len()
            > context
                .portable()
                .max_object_bytes
                .min(context.inspection().max_object_bytes)
        || file.manifest().is_some_and(|(_, _, count)| {
            count > context.inspection().max_manifest_chunks
                || count > file.canonical_len().saturating_sub(22) / 32
        })
        || file
            .blob_len()
            .is_some_and(|length| length > context.portable().max_selected_file_bytes)
        || file
            .manifest()
            .is_some_and(|(total, _, _)| total > context.portable().max_selected_file_bytes as u64)
    {
        return Err(StagedUpdateError::Inconsistent);
    }
    Ok(index)
}

pub(super) fn check_usage(
    usage: &StagedUpdateUsageV1,
    context: &StagedValidationContext,
) -> Result<(), StagedUpdateError> {
    let limits = context.staged();
    let walk = |usage: super::walk::SnapshotWalkUsage, bounds: super::walk::SnapshotWalkLimits| {
        usage.objects <= bounds.max_objects
            && usage.canonical_bytes <= bounds.max_canonical_bytes
            && usage.max_tree_depth <= bounds.max_tree_depth
            && usage.work <= bounds.max_work
    };
    if usage.header_bytes > limits.max_header_bytes
        || usage.update_bytes
            > limits
                .max_update_bytes
                .min(context.portable().max_update_bytes as u64)
        || usage.pack_bytes
            > limits
                .max_pack_bytes
                .min(context.portable().max_raw_pack_bytes as u64)
        || usage.inventory_entries
            > limits
                .max_inventory_entries
                .min(context.portable().max_update_objects as u64)
        || usage.inventory_payload_bytes > limits.max_inventory_payload_bytes
        || usage.inventory_work > limits.max_inventory_work
        || usage.inventory_work
            != usage
                .inventory_entries
                .checked_mul(2)
                .ok_or(StagedUpdateError::Budget)?
        || !walk(usage.base_walk, limits.base_walk)
        || !walk(usage.candidate_walk, limits.candidate_walk)
        || usage.diff_pair_visits > limits.max_diff_pair_visits
        || usage.diff_work > limits.max_diff_work
        || usage.diff_work
            != usage
                .diff_pair_visits
                .checked_add(usage.diff_compared_entries)
                .ok_or(StagedUpdateError::Budget)?
        || usage.required_unique_ids > limits.max_required_unique_ids
        || usage.required_canonical_bytes > limits.max_required_canonical_bytes
        || usage.origin_work > limits.max_origin_work
        || usage.max_changed_file_bytes_seen > context.portable().max_selected_file_bytes as u64
        || usage.changed_total_bytes > context.portable().max_total_selected_bytes as u64
        || usage.max_changed_file_bytes_seen > usage.changed_total_bytes
    {
        return Err(StagedUpdateError::Budget);
    }
    Ok(())
}

fn check_manifest_cursor(
    file: &InspectedObject,
    next_index: u32,
    sum: u64,
) -> Result<(), StagedUpdateError> {
    let (total, fixed, _) = file.manifest().ok_or(StagedUpdateError::Inconsistent)?;
    if sum > total || next_index == 0 && sum != 0 {
        return Err(StagedUpdateError::Inconsistent);
    }
    if fixed != 0
        && next_index != 0
        && sum
            != u64::from(next_index)
                .checked_mul(u64::from(fixed))
                .ok_or(StagedUpdateError::Budget)?
    {
        return Err(StagedUpdateError::Inconsistent);
    }
    Ok(())
}

/// Borrow the next exact manifest chunk IDs after validating header binding
/// and necessary cursor/usage conditions, before a child fetch.
///
/// # Errors
/// Refuses wrong change index/file ID, malformed cursor/width or exhausted
/// page. Restored prior positional work remains the caller's trusted ledger.
pub fn next_required_chunk_ids<'a>(
    record: &RequiredFileRecord,
    file: &'a InspectedObject,
    current: &StagedUpdateUsageV1,
    context: &StagedValidationContext,
    page_width: NonZeroUsize,
) -> Result<&'a [Hash], StagedUpdateError> {
    check_usage(current, context)?;
    valid_required_file(record, file, context)?;
    let RequiredFileRecord::ManifestPage {
        next_index, sum, ..
    } = record
    else {
        return Err(StagedUpdateError::Inconsistent);
    };
    check_manifest_cursor(file, *next_index, *sum)?;
    let (_, _, total) = file.manifest().ok_or(StagedUpdateError::Inconsistent)?;
    let start = usize::try_from(*next_index).map_err(|_| StagedUpdateError::Budget)?;
    if start >= total {
        return Err(StagedUpdateError::Inconsistent);
    }
    let count = (total - start).min(width(page_width)?);
    file.chunk_page(start, count).map_err(Into::into)
}

/// Advance one required-file Visit or manifest page using inspected facts.
/// A Visit reserves the declared file bytes before any chunk request.
///
/// # Errors
/// Refuses wrong header binding/facts, cursor, chunk dimensions, positional
/// sum or prospective per-file/aggregate usage.
#[allow(clippy::too_many_lines)] // Visit reservation and positional continuation share one contract.
pub fn advance_required_file(
    record: &RequiredFileRecord,
    file: &InspectedObject,
    chunks: &[InspectedObject],
    page_width: NonZeroUsize,
    current: &StagedUpdateUsageV1,
    context: &StagedValidationContext,
) -> Result<RequiredFileStep, StagedUpdateError> {
    check_usage(current, context)?;
    let index = valid_required_file(record, file, context)?;
    let width = width(page_width)?;
    let index_u32 = u32::try_from(index).map_err(|_| StagedUpdateError::Budget)?;
    match record {
        RequiredFileRecord::Visit { .. } => {
            if !chunks.is_empty() {
                return Err(StagedUpdateError::Inconsistent);
            }
            let length = match file.kind() {
                InspectedKind::Blob => {
                    u64::try_from(file.blob_len().ok_or(StagedUpdateError::Invalid)?)
                        .map_err(|_| StagedUpdateError::Budget)?
                }
                InspectedKind::ChunkedBlob => file.manifest().ok_or(StagedUpdateError::Invalid)?.0,
                _ => return Err(StagedUpdateError::Inconsistent),
            };
            if length > context.portable().max_selected_file_bytes as u64
                || current
                    .changed_total_bytes
                    .checked_add(length)
                    .ok_or(StagedUpdateError::Budget)?
                    > context.portable().max_total_selected_bytes as u64
            {
                return Err(StagedUpdateError::Budget);
            }
            let mut step = RequiredFileStep {
                binding: context.binding(),
                successors: Vec::new(),
                observations: vec![required(file, SnapshotRole::File, Some(index_u32))?],
                reserve_file_bytes: Some(length),
                origin_work: 1,
                complete: true,
            };
            if let Some((_, _, count)) = file.manifest()
                && count != 0
            {
                step.complete = false;
                step.successors.push(RequiredFileRecord::ManifestPage {
                    change_index: index_u32,
                    expected_file_id: file.id(),
                    next_index: 0,
                    sum: 0,
                });
            }
            Ok(step)
        }
        RequiredFileRecord::ManifestPage {
            change_index,
            expected_file_id,
            next_index,
            sum,
        } => {
            let ids = next_required_chunk_ids(record, file, current, context, page_width)?;
            if chunks.len() != ids.len() || chunks.len() > width {
                return Err(StagedUpdateError::Inconsistent);
            }
            let (declared, fixed, total) = file.manifest().ok_or(StagedUpdateError::Invalid)?;
            let start = usize::try_from(*next_index).map_err(|_| StagedUpdateError::Budget)?;
            let mut next_sum = *sum;
            let mut observations = Vec::with_capacity(chunks.len());
            for (offset, (id, chunk)) in ids.iter().zip(chunks).enumerate() {
                if chunk.id() != *id
                    || chunk.kind() != InspectedKind::Blob
                    || chunk.role().is_some_and(|role| role != SnapshotRole::Chunk)
                    || chunk.canonical_len()
                        > context
                            .portable()
                            .max_object_bytes
                            .min(context.inspection().max_object_bytes)
                {
                    return Err(StagedUpdateError::Inconsistent);
                }
                let length = chunk.blob_len().ok_or(StagedUpdateError::Invalid)?;
                let position = start + offset;
                if fixed != 0
                    && (length == 0
                        || position + 1 < total && length != fixed as usize
                        || position + 1 == total && length > fixed as usize)
                {
                    return Err(StagedUpdateError::ChunkLayout);
                }
                next_sum = next_sum
                    .checked_add(u64::try_from(length).map_err(|_| StagedUpdateError::Budget)?)
                    .ok_or(StagedUpdateError::Budget)?;
                if next_sum > declared {
                    return Err(StagedUpdateError::ChunkLayout);
                }
                observations.push(required(chunk, SnapshotRole::Chunk, Some(index_u32))?);
            }
            let end = start + chunks.len();
            let complete = end == total;
            if complete && next_sum != declared {
                return Err(StagedUpdateError::ChunkLayout);
            }
            let mut successors = Vec::new();
            if !complete {
                successors.push(RequiredFileRecord::ManifestPage {
                    change_index: *change_index,
                    expected_file_id: *expected_file_id,
                    next_index: u32::try_from(end).map_err(|_| StagedUpdateError::Budget)?,
                    sum: next_sum,
                });
            }
            Ok(RequiredFileStep {
                binding: context.binding(),
                successors,
                observations,
                reserve_file_bytes: None,
                origin_work: u64::try_from(chunks.len()).map_err(|_| StagedUpdateError::Budget)?,
                complete,
            })
        }
    }
}

fn charge_required(
    usage: &mut StagedUpdateUsageV1,
    observations: &[StagedRequiredObservation],
    newly_required: &[Hash],
    context: &StagedValidationContext,
) -> Result<(), StagedUpdateError> {
    if observations.len() > MAX_STAGED_PAGE || newly_required.len() > observations.len() {
        return Err(StagedUpdateError::Inconsistent);
    }
    let mut available = BTreeMap::new();
    for observation in observations {
        if let Some(previous) = available.insert(observation.id, observation.canonical_len)
            && previous != observation.canonical_len
        {
            return Err(StagedUpdateError::Inconsistent);
        }
    }
    let mut distinct = BTreeSet::new();
    for id in newly_required {
        if !distinct.insert(*id) {
            return Err(StagedUpdateError::Inconsistent);
        }
        let length = available.get(id).ok_or(StagedUpdateError::Inconsistent)?;
        usage.required_unique_ids = usage
            .required_unique_ids
            .checked_add(1)
            .ok_or(StagedUpdateError::Budget)?;
        usage.required_canonical_bytes = usage
            .required_canonical_bytes
            .checked_add(*length)
            .ok_or(StagedUpdateError::Budget)?;
    }
    if usage.required_unique_ids > context.staged().max_required_unique_ids
        || usage.required_canonical_bytes > context.staged().max_required_canonical_bytes
    {
        return Err(StagedUpdateError::Budget);
    }
    Ok(())
}

/// Atomically calculate prospective changed-pair and unique-required usage.
/// `newly_required` is a trusted external ledger decision for this step only.
///
/// # Errors
/// Refuses over-budget previous/next usage or duplicate/unobserved flags.
pub fn apply_changed_accounting(
    previous: StagedUpdateUsageV1,
    step: &ChangedPairStep,
    newly_required: &[Hash],
    context: &StagedValidationContext,
) -> Result<StagedUpdateUsageV1, StagedUpdateError> {
    if !context.binds(&step.binding) {
        return Err(StagedUpdateError::Inconsistent);
    }
    check_usage(&previous, context)?;
    let mut next = previous;
    next.diff_pair_visits = next
        .diff_pair_visits
        .checked_add(step.pair_visits)
        .ok_or(StagedUpdateError::Budget)?;
    next.diff_compared_entries = next
        .diff_compared_entries
        .checked_add(step.compared_entries)
        .ok_or(StagedUpdateError::Budget)?;
    next.diff_work = next
        .diff_pair_visits
        .checked_add(next.diff_compared_entries)
        .ok_or(StagedUpdateError::Budget)?;
    next.origin_work = next
        .origin_work
        .checked_add(step.origin_work)
        .ok_or(StagedUpdateError::Budget)?;
    charge_required(&mut next, &step.observations, newly_required, context)?;
    check_usage(&next, context)?;
    Ok(next)
}

/// Atomically calculate prospective file-reservation, positional and unique
/// required-ID usage. Completing a manifest does not charge its file twice.
///
/// # Errors
/// Refuses over-budget previous/next usage or duplicate/unobserved flags.
pub fn apply_required_accounting(
    previous: StagedUpdateUsageV1,
    step: &RequiredFileStep,
    newly_required: &[Hash],
    context: &StagedValidationContext,
) -> Result<StagedUpdateUsageV1, StagedUpdateError> {
    if !context.binds(&step.binding) {
        return Err(StagedUpdateError::Inconsistent);
    }
    check_usage(&previous, context)?;
    let mut next = previous;
    next.origin_work = next
        .origin_work
        .checked_add(step.origin_work)
        .ok_or(StagedUpdateError::Budget)?;
    if let Some(length) = step.reserve_file_bytes {
        next.max_changed_file_bytes_seen = next.max_changed_file_bytes_seen.max(length);
        next.changed_total_bytes = next
            .changed_total_bytes
            .checked_add(length)
            .ok_or(StagedUpdateError::Budget)?;
    }
    charge_required(&mut next, &step.observations, newly_required, context)?;
    check_usage(&next, context)?;
    Ok(next)
}
