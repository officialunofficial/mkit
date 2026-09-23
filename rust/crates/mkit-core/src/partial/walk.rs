//! Bounded transitions for a complete typed Snapshot walk.
//!
//! Records and seen-ID decisions are trusted recipient bookkeeping, not
//! cryptographic proofs. A host must bind persisted records to its pinned root,
//! catalog, limits, validator version and fenced job generation. These helpers
//! authenticate each supplied fact and transition; they cannot attest that a
//! host persisted every earlier transition or exhausted its external frontier.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;

use crate::hash::Hash;
use crate::object::EntryMode;

use super::inspect::{InspectedKind, InspectedObject, SnapshotRole};

/// Largest child page accepted by one transition.
pub const MAX_WALK_PAGE: usize = 64;

/// Recipient-owned work record. Construct or restore only inside trusted,
/// versioned job state; the fields do not authenticate prior traversal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SnapshotWalkRecord {
    /// Inspect one object under an incoming edge role.
    Visit {
        /// Independently pinned root or authenticated child ID.
        id: Hash,
        /// Expected incoming edge role.
        role: SnapshotRole,
        /// Number of Tree-to-Tree edges from the root Tree.
        tree_depth: u64,
    },
    /// Expand one nonempty page of an already visited Tree occurrence.
    TreePage {
        /// Authenticated Tree ID.
        id: Hash,
        /// Depth of this occurrence.
        tree_depth: u64,
        /// First unexpanded entry.
        next_index: u32,
    },
    /// Validate one page of an already visited manifest occurrence.
    ManifestPage {
        /// Authenticated `ChunkedBlob` ID.
        id: Hash,
        /// Depth of this occurrence.
        tree_depth: u64,
        /// First unchecked chunk position.
        next_index: u32,
        /// Sum of lengths checked for this occurrence so far.
        sum: u64,
    },
}

impl std::fmt::Debug for SnapshotWalkRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Visit {
                role, tree_depth, ..
            } => f
                .debug_struct("Visit")
                .field("role", role)
                .field("tree_depth", tree_depth)
                .finish_non_exhaustive(),
            Self::TreePage {
                tree_depth,
                next_index,
                ..
            } => f
                .debug_struct("TreePage")
                .field("tree_depth", tree_depth)
                .field("next_index", next_index)
                .finish_non_exhaustive(),
            Self::ManifestPage {
                tree_depth,
                next_index,
                sum,
                ..
            } => f
                .debug_struct("ManifestPage")
                .field("tree_depth", tree_depth)
                .field("next_index", next_index)
                .field("sum", sum)
                .finish_non_exhaustive(),
        }
    }
}

impl SnapshotWalkRecord {
    /// ID whose canonical bytes the next transition must inspect.
    #[must_use]
    pub fn id(&self) -> Hash {
        match self {
            Self::Visit { id, .. } | Self::TreePage { id, .. } | Self::ManifestPage { id, .. } => {
                *id
            }
        }
    }

    /// Incoming role for reinspection of this record's object.
    #[must_use]
    pub fn role(&self) -> SnapshotRole {
        match self {
            Self::Visit { role, .. } => *role,
            Self::TreePage { .. } => SnapshotRole::Tree,
            Self::ManifestPage { .. } => SnapshotRole::File,
        }
    }

    /// Tree depth carried by this trusted occurrence record.
    #[must_use]
    pub fn tree_depth(&self) -> u64 {
        match self {
            Self::Visit { tree_depth, .. }
            | Self::TreePage { tree_depth, .. }
            | Self::ManifestPage { tree_depth, .. } => *tree_depth,
        }
    }
}

/// Semantic bounds for one complete Snapshot walk. Object inspection has
/// separate caller-lowered per-object and Tree/manifest limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotWalkLimits {
    /// Maximum number of distinct reachable IDs.
    pub max_objects: u64,
    /// Maximum sum of distinct canonical object byte lengths.
    pub max_canonical_bytes: u64,
    /// Maximum Tree-to-Tree depth, with root Tree at zero.
    pub max_tree_depth: u64,
    /// Maximum old-recipient-equivalent occurrence work units.
    pub max_work: u64,
}

/// Success counters for one walk, excluding upload intake, diff and closure
/// passes of the full partial-update recipient.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotWalkUsage {
    /// Distinct reached IDs.
    pub objects: u64,
    /// Canonical bytes across distinct reached IDs.
    pub canonical_bytes: u64,
    /// Deepest reached Tree occurrence.
    pub max_tree_depth: u64,
    /// Visits plus expanded Tree edges plus two per manifest chunk position.
    pub work: u64,
}

/// Failure to make or account for one local transition. No variant means a
/// whole Snapshot or durable job has been verified.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotWalkError {
    /// The supplied root role or inspected object's role/kind is unsuitable.
    #[error("wrong Snapshot walk role or object kind")]
    WrongRole,
    /// Supplied fact ID or a positional child ID differs from the expected ID.
    #[error("Snapshot walk object ID mismatch")]
    WrongId,
    /// Trusted cursor is malformed, or page width/length cannot progress.
    #[error("invalid Snapshot walk page or cursor")]
    InvalidPage,
    /// Manifest chunk length, fixed layout or final sum is invalid.
    #[error("invalid Snapshot chunk layout")]
    InvalidChunkLayout,
    /// Checked arithmetic or a semantic walk limit was exceeded.
    #[error("Snapshot walk budget exceeded")]
    BudgetExceeded,
    /// Trusted newly-seen ledger decisions disagree with this step's facts.
    #[error("inconsistent Snapshot walk accounting input")]
    InconsistentAccounting,
}

/// One authenticated object observation for an external unique-ID ledger.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WalkObjectObservation {
    id: Hash,
    canonical_len: u64,
}

impl std::fmt::Debug for WalkObjectObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalkObjectObservation")
            .field("canonical_len", &self.canonical_len)
            .finish_non_exhaustive()
    }
}

impl WalkObjectObservation {
    /// Observed type-aware object ID.
    #[must_use]
    pub fn id(&self) -> Hash {
        self.id
    }

    /// Length of its canonical serialization.
    #[must_use]
    pub fn canonical_len(&self) -> u64 {
        self.canonical_len
    }
}

/// Bounded result of exactly one local transition; this is not a completion
/// certificate or a verified Snapshot.
pub struct SnapshotWalkStep {
    successors: Vec<SnapshotWalkRecord>,
    observations: Vec<WalkObjectObservation>,
    work_delta: u64,
    tree_depth: Option<u64>,
}

impl std::fmt::Debug for SnapshotWalkStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotWalkStep")
            .field("successor_count", &self.successors.len())
            .field("observation_count", &self.observations.len())
            .field("work_delta", &self.work_delta)
            .finish_non_exhaustive()
    }
}

impl SnapshotWalkStep {
    /// Bounded, authenticated next records. An empty slice finishes this
    /// record only; it does not establish whole-walk completion.
    #[must_use]
    pub fn successors(&self) -> &[SnapshotWalkRecord] {
        &self.successors
    }

    /// Object facts to reconcile with the trusted external seen-ID ledger.
    #[must_use]
    pub fn observations(&self) -> &[WalkObjectObservation] {
        &self.observations
    }

    /// Work units consumed by this transition, including implicit chunk visits.
    #[must_use]
    pub fn work_delta(&self) -> u64 {
        self.work_delta
    }

    /// Tree depth observed by a Tree Visit, if any.
    #[must_use]
    pub fn tree_depth(&self) -> Option<u64> {
        self.tree_depth
    }
}

/// Start with an independently supplied root. The returned record is trusted
/// bookkeeping; the subsequent Visit must still inspect and authenticate it.
///
/// # Errors
/// Returns [`SnapshotWalkError::WrongRole`] unless the role is `BaseRoot` or
/// `CandidateRoot`.
pub fn start_snapshot_walk(
    root: Hash,
    role: SnapshotRole,
) -> Result<SnapshotWalkRecord, SnapshotWalkError> {
    if !matches!(role, SnapshotRole::BaseRoot | SnapshotRole::CandidateRoot) {
        return Err(SnapshotWalkError::WrongRole);
    }
    Ok(SnapshotWalkRecord::Visit {
        id: root,
        role,
        tree_depth: 0,
    })
}

fn width(width: NonZeroUsize) -> Result<usize, SnapshotWalkError> {
    if width.get() > MAX_WALK_PAGE {
        return Err(SnapshotWalkError::InvalidPage);
    }
    Ok(width.get())
}

fn checked_page(
    index: u32,
    total: usize,
    width: usize,
) -> Result<(usize, usize), SnapshotWalkError> {
    let start = usize::try_from(index).map_err(|_| SnapshotWalkError::InvalidPage)?;
    if start >= total {
        return Err(SnapshotWalkError::InvalidPage);
    }
    let count = (total - start).min(width);
    let end = start
        .checked_add(count)
        .ok_or(SnapshotWalkError::InvalidPage)?;
    u32::try_from(end).map_err(|_| SnapshotWalkError::InvalidPage)?;
    Ok((start, count))
}

// Detect locally impossible trusted cursor metadata before a child fetch.
// This does not authenticate an arbitrary resumed cursor or its prior work.
fn check_manifest_cursor(
    parent: &InspectedObject,
    next_index: u32,
    sum: u64,
) -> Result<(), SnapshotWalkError> {
    let (total_size, fixed_size, _) = parent.manifest().ok_or(SnapshotWalkError::WrongRole)?;
    if sum > total_size || (next_index == 0 && sum != 0) {
        return Err(SnapshotWalkError::InvalidPage);
    }
    if fixed_size != 0 && next_index != 0 {
        let required = u64::from(next_index)
            .checked_mul(u64::from(fixed_size))
            .ok_or(SnapshotWalkError::InvalidPage)?;
        if sum != required {
            return Err(SnapshotWalkError::InvalidPage);
        }
    }
    Ok(())
}

fn fact_matches(fact: &InspectedObject, id: Hash, role: SnapshotRole) -> bool {
    if fact.id() != id {
        return false;
    }
    let kind_matches = match role {
        SnapshotRole::BaseRoot => {
            matches!(fact.kind(), InspectedKind::Commit | InspectedKind::Remix)
        }
        SnapshotRole::CandidateRoot => fact.kind() == InspectedKind::Commit,
        SnapshotRole::Tree => fact.kind() == InspectedKind::Tree,
        SnapshotRole::File => matches!(
            fact.kind(),
            InspectedKind::Blob | InspectedKind::ChunkedBlob
        ),
        SnapshotRole::Symlink | SnapshotRole::Chunk => fact.kind() == InspectedKind::Blob,
    };
    kind_matches && fact.role().is_none_or(|asserted| asserted == role)
}

fn observation(fact: &InspectedObject) -> Result<WalkObjectObservation, SnapshotWalkError> {
    Ok(WalkObjectObservation {
        id: fact.id(),
        canonical_len: u64::try_from(fact.canonical_len())
            .map_err(|_| SnapshotWalkError::BudgetExceeded)?,
    })
}

/// Borrow the exact next manifest IDs needed before fetching their Blob facts.
/// The same parent fact and record must be passed to `advance_snapshot_walk`.
/// An impossible initial or fixed-size prefix sum is refused before fetching;
/// this necessary check does not authenticate arbitrary persisted cursors.
///
/// # Errors
/// Rejects mismatched IDs/kinds/roles, malformed or exhausted cursors, and
/// widths above [`MAX_WALK_PAGE`].
pub fn next_manifest_ids<'a>(
    record: &SnapshotWalkRecord,
    parent: &'a InspectedObject,
    page_width: NonZeroUsize,
) -> Result<&'a [Hash], SnapshotWalkError> {
    let SnapshotWalkRecord::ManifestPage {
        id,
        next_index,
        sum,
        ..
    } = record
    else {
        return Err(SnapshotWalkError::WrongRole);
    };
    if parent.id() != *id {
        return Err(SnapshotWalkError::WrongId);
    }
    if !fact_matches(parent, *id, SnapshotRole::File) || parent.kind() != InspectedKind::ChunkedBlob
    {
        return Err(SnapshotWalkError::WrongRole);
    }
    let (_, _, total) = parent.manifest().ok_or(SnapshotWalkError::WrongRole)?;
    check_manifest_cursor(parent, *next_index, *sum)?;
    let (start, count) = checked_page(*next_index, total, width(page_width)?)?;
    parent
        .chunk_page(start, count)
        .map_err(|_| SnapshotWalkError::InvalidPage)
}

/// Advance one trusted work record using facts from the bounded object
/// inspector. For a manifest page, `chunks` must contain exactly the ordered
/// facts returned by the corresponding `next_manifest_ids` request. No input
/// or result represents whole-graph verification.
///
/// # Errors
/// Rejects mismatched facts/roles, malformed or non-progressing cursors, bad
/// chunk layouts and checked depth/work overflow. Object inspection errors
/// occur before this call and are not hidden by it.
#[allow(clippy::too_many_lines)] // One transition keeps all role/phase exits auditable.
pub fn advance_snapshot_walk(
    record: &SnapshotWalkRecord,
    parent: &InspectedObject,
    chunks: &[InspectedObject],
    page_width: NonZeroUsize,
    limits: &SnapshotWalkLimits,
) -> Result<SnapshotWalkStep, SnapshotWalkError> {
    let width = width(page_width)?;
    if parent.id() != record.id() {
        return Err(SnapshotWalkError::WrongId);
    }
    if !fact_matches(parent, record.id(), record.role()) {
        return Err(SnapshotWalkError::WrongRole);
    }
    if record.tree_depth() > limits.max_tree_depth
        || (matches!(
            record,
            SnapshotWalkRecord::Visit {
                role: SnapshotRole::BaseRoot | SnapshotRole::CandidateRoot,
                ..
            }
        ) && record.tree_depth() != 0)
    {
        return Err(SnapshotWalkError::BudgetExceeded);
    }
    if !matches!(record, SnapshotWalkRecord::ManifestPage { .. }) && !chunks.is_empty() {
        return Err(SnapshotWalkError::InvalidPage);
    }
    let mut step = SnapshotWalkStep {
        successors: Vec::new(),
        observations: Vec::new(),
        work_delta: 0,
        tree_depth: None,
    };
    match record {
        SnapshotWalkRecord::Visit {
            id,
            role,
            tree_depth,
        } => {
            step.work_delta = 1;
            step.observations.push(observation(parent)?);
            match role {
                SnapshotRole::BaseRoot | SnapshotRole::CandidateRoot => {
                    let (tree_id, _) = parent.root().ok_or(SnapshotWalkError::WrongRole)?;
                    step.successors.push(SnapshotWalkRecord::Visit {
                        id: tree_id,
                        role: SnapshotRole::Tree,
                        tree_depth: 0,
                    });
                }
                SnapshotRole::Tree => {
                    if *tree_depth > limits.max_tree_depth {
                        return Err(SnapshotWalkError::BudgetExceeded);
                    }
                    step.tree_depth = Some(*tree_depth);
                    if parent
                        .tree_entries_len()
                        .ok_or(SnapshotWalkError::WrongRole)?
                        > 0
                    {
                        step.successors.push(SnapshotWalkRecord::TreePage {
                            id: *id,
                            tree_depth: *tree_depth,
                            next_index: 0,
                        });
                    }
                }
                SnapshotRole::File if parent.kind() == InspectedKind::ChunkedBlob => {
                    let (_, _, count) = parent.manifest().ok_or(SnapshotWalkError::WrongRole)?;
                    if count > 0 {
                        step.successors.push(SnapshotWalkRecord::ManifestPage {
                            id: *id,
                            tree_depth: *tree_depth,
                            next_index: 0,
                            sum: 0,
                        });
                    }
                }
                SnapshotRole::File | SnapshotRole::Symlink | SnapshotRole::Chunk => {}
            }
        }
        SnapshotWalkRecord::TreePage {
            id,
            tree_depth,
            next_index,
        } => {
            if *tree_depth > limits.max_tree_depth {
                return Err(SnapshotWalkError::BudgetExceeded);
            }
            let total = parent
                .tree_entries_len()
                .ok_or(SnapshotWalkError::WrongRole)?;
            let (start, count) = checked_page(*next_index, total, width)?;
            for entry in parent
                .tree_page(start, count)
                .map_err(|_| SnapshotWalkError::InvalidPage)?
            {
                let (role, depth) = match entry.mode {
                    EntryMode::Tree => (
                        SnapshotRole::Tree,
                        tree_depth
                            .checked_add(1)
                            .ok_or(SnapshotWalkError::BudgetExceeded)?,
                    ),
                    EntryMode::Blob | EntryMode::Executable => (SnapshotRole::File, *tree_depth),
                    EntryMode::Symlink => (SnapshotRole::Symlink, *tree_depth),
                };
                step.successors.push(SnapshotWalkRecord::Visit {
                    id: entry.object_hash,
                    role,
                    tree_depth: depth,
                });
            }
            let next = start + count;
            if next < total {
                step.successors.push(SnapshotWalkRecord::TreePage {
                    id: *id,
                    tree_depth: *tree_depth,
                    next_index: u32::try_from(next).map_err(|_| SnapshotWalkError::InvalidPage)?,
                });
            }
            step.work_delta =
                u64::try_from(count).map_err(|_| SnapshotWalkError::BudgetExceeded)?;
        }
        SnapshotWalkRecord::ManifestPage {
            id,
            tree_depth,
            next_index,
            sum,
        } => {
            check_manifest_cursor(parent, *next_index, *sum)?;
            let (total_size, fixed_size, total) =
                parent.manifest().ok_or(SnapshotWalkError::WrongRole)?;
            let (start, count) = checked_page(*next_index, total, width)?;
            if chunks.len() != count {
                return Err(SnapshotWalkError::InvalidPage);
            }
            let ids = parent
                .chunk_page(start, count)
                .map_err(|_| SnapshotWalkError::InvalidPage)?;
            let mut next_sum = *sum;
            for (offset, (expected, chunk)) in ids.iter().zip(chunks).enumerate() {
                if chunk.id() != *expected {
                    return Err(SnapshotWalkError::WrongId);
                }
                if !fact_matches(chunk, *expected, SnapshotRole::Chunk) {
                    return Err(SnapshotWalkError::WrongRole);
                }
                let length = chunk.blob_len().ok_or(SnapshotWalkError::WrongRole)?;
                let index = start + offset;
                if fixed_size != 0 {
                    let fixed = usize::try_from(fixed_size)
                        .map_err(|_| SnapshotWalkError::BudgetExceeded)?;
                    if length == 0
                        || (index + 1 < total && length != fixed)
                        || (index + 1 == total && length > fixed)
                    {
                        return Err(SnapshotWalkError::InvalidChunkLayout);
                    }
                }
                next_sum = next_sum
                    .checked_add(
                        u64::try_from(length).map_err(|_| SnapshotWalkError::InvalidChunkLayout)?,
                    )
                    .ok_or(SnapshotWalkError::InvalidChunkLayout)?;
                if next_sum > total_size {
                    return Err(SnapshotWalkError::InvalidChunkLayout);
                }
                step.observations.push(observation(chunk)?);
            }
            let next = start + count;
            if next == total {
                if next_sum != total_size {
                    return Err(SnapshotWalkError::InvalidChunkLayout);
                }
            } else {
                step.successors.push(SnapshotWalkRecord::ManifestPage {
                    id: *id,
                    tree_depth: *tree_depth,
                    next_index: u32::try_from(next).map_err(|_| SnapshotWalkError::InvalidPage)?,
                    sum: next_sum,
                });
            }
            step.work_delta = u64::try_from(count)
                .map_err(|_| SnapshotWalkError::BudgetExceeded)?
                .checked_mul(2)
                .ok_or(SnapshotWalkError::BudgetExceeded)?;
        }
    }
    if step.successors.len() > MAX_WALK_PAGE + 1 || step.observations.len() > MAX_WALK_PAGE {
        return Err(SnapshotWalkError::InvalidPage);
    }
    Ok(step)
}

/// Apply one step's counters prospectively. `newly_seen` is the external
/// transaction's trusted unique-ID decision, not a claim from the input
/// object. The transaction must insert those IDs, reconcile previously seen
/// lengths, advance the frontier and save this result atomically.
///
/// # Errors
/// Rejects prior usage already beyond limits, too many/duplicate/unobserved
/// new IDs, inconsistent lengths for repeated observations, and any checked
/// arithmetic or semantic limit overflow. `previous` is never modified.
pub fn apply_walk_accounting(
    previous: SnapshotWalkUsage,
    step: &SnapshotWalkStep,
    newly_seen: &[Hash],
    limits: SnapshotWalkLimits,
) -> Result<SnapshotWalkUsage, SnapshotWalkError> {
    if previous.objects > limits.max_objects
        || previous.canonical_bytes > limits.max_canonical_bytes
        || previous.max_tree_depth > limits.max_tree_depth
        || previous.work > limits.max_work
    {
        return Err(SnapshotWalkError::BudgetExceeded);
    }
    // Refuse caller-controlled length before allocating even a bounded map.
    if newly_seen.len() > step.observations.len() || step.observations.len() > MAX_WALK_PAGE {
        return Err(SnapshotWalkError::InconsistentAccounting);
    }
    let mut observed = BTreeMap::new();
    for item in &step.observations {
        if observed
            .insert(item.id, item.canonical_len)
            .is_some_and(|old| old != item.canonical_len)
        {
            return Err(SnapshotWalkError::InconsistentAccounting);
        }
    }
    let mut next = previous;
    let mut listed = BTreeSet::new();
    for id in newly_seen {
        let length = *observed
            .get(id)
            .ok_or(SnapshotWalkError::InconsistentAccounting)?;
        if !listed.insert(*id) {
            return Err(SnapshotWalkError::InconsistentAccounting);
        }
        next.objects = next
            .objects
            .checked_add(1)
            .ok_or(SnapshotWalkError::BudgetExceeded)?;
        next.canonical_bytes = next
            .canonical_bytes
            .checked_add(length)
            .ok_or(SnapshotWalkError::BudgetExceeded)?;
    }
    next.work = next
        .work
        .checked_add(step.work_delta)
        .ok_or(SnapshotWalkError::BudgetExceeded)?;
    if let Some(depth) = step.tree_depth {
        next.max_tree_depth = next.max_tree_depth.max(depth);
    }
    if next.objects > limits.max_objects
        || next.canonical_bytes > limits.max_canonical_bytes
        || next.max_tree_depth > limits.max_tree_depth
        || next.work > limits.max_work
    {
        return Err(SnapshotWalkError::BudgetExceeded);
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::collections::{BTreeMap, VecDeque};

    use super::*;
    use crate::object::{
        Blob, ChunkedBlob, Commit, Identity, Object, Remix, RemixSource, Tree, TreeEntry,
        id_from_object,
    };
    use crate::partial::inspect::{ObjectInspectionLimits, inspect_snapshot_object};
    use crate::partial::recipient::{RecipientLimits, RecipientUsage};
    use crate::partial::recipient_graph::RecipientGraph;
    use crate::serialize::serialize;
    use crate::sign::{KeyPair, sign_commit, sign_remix};
    use crate::verify::{ObjectSource, VerifyError};

    fn inspection_limits() -> ObjectInspectionLimits {
        ObjectInspectionLimits {
            max_object_bytes: 16 * 1024 * 1024,
            max_tree_bytes: 16 * 1024 * 1024,
            max_tree_entries: 100_000,
            max_manifest_chunks: 100_000,
        }
    }

    fn walk_limits() -> SnapshotWalkLimits {
        SnapshotWalkLimits {
            max_objects: 100_000,
            max_canonical_bytes: 256 * 1024 * 1024,
            max_tree_depth: 128,
            max_work: 1_000_000,
        }
    }

    fn insert(objects: &mut BTreeMap<Hash, Vec<u8>>, object: &Object) -> Hash {
        let bytes = serialize(object).unwrap();
        let id = id_from_object(object, &bytes);
        objects.insert(id, bytes);
        id
    }

    fn signed_root(objects: &mut BTreeMap<Hash, Vec<u8>>, tree_id: Hash) -> Hash {
        let key = KeyPair::from_seed([73; 32]);
        let mut commit = Commit::new_unannotated(
            tree_id,
            vec![[9; 32]], // History is outside this Snapshot walk.
            Identity::ed25519(key.public.0),
            key.public.0,
            b"walk fixture".to_vec(),
            1,
            [0; 64],
        );
        commit.signature = sign_commit(&commit, &key).unwrap().0;
        insert(objects, &Object::Commit(commit))
    }

    #[derive(Clone)]
    struct MapSource(BTreeMap<Hash, Vec<u8>>);

    impl ObjectSource for MapSource {
        fn fetch(&mut self, id: &Hash) -> Result<Option<Cow<'_, [u8]>>, VerifyError> {
            Ok(self.0.get(id).map(|bytes| Cow::Borrowed(bytes.as_slice())))
        }
    }

    fn drive(
        source: &BTreeMap<Hash, Vec<u8>>,
        root: Hash,
        width: usize,
        limits: SnapshotWalkLimits,
    ) -> Result<(SnapshotWalkUsage, BTreeMap<Hash, u64>), SnapshotWalkError> {
        let width = NonZeroUsize::new(width).ok_or(SnapshotWalkError::InvalidPage)?;
        let mut pending = VecDeque::from([start_snapshot_walk(root, SnapshotRole::BaseRoot)?]);
        let mut usage = SnapshotWalkUsage::default();
        let mut seen = BTreeMap::new();
        while let Some(record) = pending.pop_front() {
            let bytes = source.get(&record.id()).ok_or(SnapshotWalkError::WrongId)?;
            let parent =
                inspect_snapshot_object(record.id(), bytes, record.role(), inspection_limits())
                    .map_err(|_| SnapshotWalkError::WrongRole)?;
            let chunks = if matches!(record, SnapshotWalkRecord::ManifestPage { .. }) {
                next_manifest_ids(&record, &parent, width)?
                    .iter()
                    .map(|id| {
                        let bytes = source.get(id).ok_or(SnapshotWalkError::WrongId)?;
                        inspect_snapshot_object(
                            *id,
                            bytes,
                            SnapshotRole::Chunk,
                            inspection_limits(),
                        )
                        .map_err(|_| SnapshotWalkError::WrongRole)
                    })
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                Vec::new()
            };
            let step = advance_snapshot_walk(&record, &parent, &chunks, width, &limits)?;
            let mut new = Vec::new();
            for item in step.observations() {
                if let Some(old) = seen.get(&item.id()) {
                    assert_eq!(*old, item.canonical_len());
                } else if !new.contains(&item.id()) {
                    new.push(item.id());
                }
            }
            let next_usage = apply_walk_accounting(usage, &step, &new, limits)?;
            for item in step.observations() {
                seen.insert(item.id(), item.canonical_len());
            }
            usage = next_usage;
            pending.extend(step.successors().iter().copied());
        }
        Ok((usage, seen))
    }

    // Protocol model only. PR10c must implement and test actual durable SQL.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ModelJob {
        pending: VecDeque<SnapshotWalkRecord>,
        usage: SnapshotWalkUsage,
        seen: BTreeMap<Hash, u64>,
        generation: u64,
    }

    impl ModelJob {
        fn new(root: Hash) -> Self {
            Self {
                pending: VecDeque::from([
                    start_snapshot_walk(root, SnapshotRole::BaseRoot).unwrap()
                ]),
                usage: SnapshotWalkUsage::default(),
                seen: BTreeMap::new(),
                generation: 1,
            }
        }

        fn commit(
            &mut self,
            record: SnapshotWalkRecord,
            step: &SnapshotWalkStep,
            enqueued: &[SnapshotWalkRecord],
            generation: u64,
        ) -> Result<(), SnapshotWalkError> {
            if generation != self.generation
                || self.pending.front() != Some(&record)
                || enqueued != step.successors()
            {
                return Err(SnapshotWalkError::InconsistentAccounting);
            }
            let mut new = Vec::new();
            for item in step.observations() {
                if let Some(old) = self.seen.get(&item.id()) {
                    if *old != item.canonical_len() {
                        return Err(SnapshotWalkError::InconsistentAccounting);
                    }
                } else if !new.contains(&item.id()) {
                    new.push(item.id());
                }
            }
            let next_usage = apply_walk_accounting(self.usage, step, &new, walk_limits())?;
            let mut next = self.clone();
            next.pending.pop_front();
            next.pending.extend(enqueued.iter().copied());
            for item in step.observations() {
                next.seen.insert(item.id(), item.canonical_len());
            }
            next.usage = next_usage;
            *self = next;
            Ok(())
        }

        fn finish(&self, catalog: &BTreeSet<Hash>) -> Result<SnapshotWalkUsage, SnapshotWalkError> {
            if !self.pending.is_empty()
                || self.seen.keys().copied().collect::<BTreeSet<_>>() != *catalog
            {
                return Err(SnapshotWalkError::InconsistentAccounting);
            }
            Ok(self.usage)
        }
    }

    fn model_step(
        objects: &BTreeMap<Hash, Vec<u8>>,
        record: SnapshotWalkRecord,
    ) -> SnapshotWalkStep {
        let width = NonZeroUsize::new(1).unwrap();
        let parent = inspect_snapshot_object(
            record.id(),
            &objects[&record.id()],
            record.role(),
            inspection_limits(),
        )
        .unwrap();
        let chunks = if matches!(record, SnapshotWalkRecord::ManifestPage { .. }) {
            next_manifest_ids(&record, &parent, width)
                .unwrap()
                .iter()
                .map(|id| {
                    inspect_snapshot_object(
                        *id,
                        &objects[id],
                        SnapshotRole::Chunk,
                        inspection_limits(),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        advance_snapshot_walk(&record, &parent, &chunks, width, &walk_limits()).unwrap()
    }

    fn old_usage(objects: &BTreeMap<Hash, Vec<u8>>, root: Hash) -> RecipientUsage {
        let mut source = MapSource(objects.clone());
        let mut graph = RecipientGraph::new(&mut source, RecipientLimits::default());
        graph.validate_base(root).unwrap();
        graph.usage()
    }

    #[test]
    fn shared_tree_and_repeated_chunks_match_old_single_walk() {
        let mut objects = BTreeMap::new();
        let chunk = insert(
            &mut objects,
            &Object::Blob(Blob {
                data: b"abc".to_vec(),
            }),
        );
        let manifest = insert(
            &mut objects,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: 6,
                chunk_size: 3,
                chunks: vec![chunk, chunk],
            }),
        );
        let leaf = insert(
            &mut objects,
            &Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"file".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: manifest,
                }],
            }),
        );
        let nested = insert(
            &mut objects,
            &Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"leaf".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: leaf,
                }],
            }),
        );
        let root_tree = insert(
            &mut objects,
            &Object::Tree(Tree {
                entries: vec![
                    TreeEntry {
                        name: b"a".to_vec(),
                        mode: EntryMode::Tree,
                        object_hash: leaf,
                    },
                    TreeEntry {
                        name: b"b".to_vec(),
                        mode: EntryMode::Tree,
                        object_hash: nested,
                    },
                    TreeEntry {
                        name: b"c".to_vec(),
                        mode: EntryMode::Symlink,
                        object_hash: chunk,
                    },
                ],
            }),
        );
        let root = signed_root(&mut objects, root_tree);
        let old = old_usage(&objects, root);
        for width in [1, 2, 64] {
            let (actual, seen) = drive(&objects, root, width, walk_limits()).unwrap();
            assert_eq!(usize::try_from(actual.objects).unwrap(), old.objects);
            assert_eq!(
                usize::try_from(actual.canonical_bytes).unwrap(),
                old.canonical_bytes
            );
            assert_eq!(
                usize::try_from(actual.max_tree_depth).unwrap(),
                old.max_tree_depth
            );
            assert_eq!(usize::try_from(actual.work).unwrap(), old.occurrences);
            assert_eq!(seen.len(), old.objects);
        }
    }

    #[test]
    fn root_roles_and_empty_objects_walk_without_history() {
        let mut objects = BTreeMap::new();
        let empty_tree = insert(
            &mut objects,
            &Object::Tree(Tree {
                entries: Vec::new(),
            }),
        );
        let empty_blob = insert(&mut objects, &Object::Blob(Blob { data: Vec::new() }));
        let empty_manifest = insert(
            &mut objects,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: 0,
                chunk_size: 0,
                chunks: Vec::new(),
            }),
        );
        let key = KeyPair::from_seed([74; 32]);
        let mut remix = Remix {
            tree_hash: empty_tree,
            parents: vec![[93; 32]],
            sources: vec![RemixSource {
                upstream_id: [94; 32],
                commit_hash: [95; 32],
            }],
            author: Identity::ed25519(key.public.0),
            signer: key.public.0,
            message: b"walk root".to_vec(),
            timestamp: 1,
            signature: [0; 64],
        };
        remix.signature = sign_remix(&remix, &key).unwrap().0;
        let remix_id = insert(&mut objects, &Object::Remix(remix));
        let (usage, reached) = drive(&objects, remix_id, 1, walk_limits()).unwrap();
        assert_eq!(usage.objects, 2); // Remix and its Tree, not parents/sources.
        assert_eq!(reached.len(), 2);
        let remix_fact = inspect_snapshot_object(
            remix_id,
            &objects[&remix_id],
            SnapshotRole::BaseRoot,
            inspection_limits(),
        )
        .unwrap();
        let candidate = start_snapshot_walk(remix_id, SnapshotRole::CandidateRoot).unwrap();
        assert_eq!(
            advance_snapshot_walk(
                &candidate,
                &remix_fact,
                &[],
                NonZeroUsize::new(1).unwrap(),
                &walk_limits()
            )
            .map(|_| ()),
            Err(SnapshotWalkError::WrongRole)
        );
        let commit_id = signed_root(&mut objects, empty_tree);
        let commit_fact = inspect_snapshot_object(
            commit_id,
            &objects[&commit_id],
            SnapshotRole::CandidateRoot,
            inspection_limits(),
        )
        .unwrap();
        let candidate = start_snapshot_walk(commit_id, SnapshotRole::CandidateRoot).unwrap();
        assert_eq!(
            advance_snapshot_walk(
                &candidate,
                &commit_fact,
                &[],
                NonZeroUsize::new(1).unwrap(),
                &walk_limits()
            )
            .unwrap()
            .successors()
            .len(),
            1
        );
        for (id, role) in [
            (empty_blob, SnapshotRole::File),
            (empty_manifest, SnapshotRole::File),
        ] {
            let fact =
                inspect_snapshot_object(id, &objects[&id], role, inspection_limits()).unwrap();
            let step = advance_snapshot_walk(
                &SnapshotWalkRecord::Visit {
                    id,
                    role,
                    tree_depth: 0,
                },
                &fact,
                &[],
                NonZeroUsize::new(1).unwrap(),
                &walk_limits(),
            )
            .unwrap();
            assert!(step.successors().is_empty());
            assert_eq!(step.work_delta(), 1);
        }
    }

    #[test]
    fn accounting_is_prospective_and_rejects_untrusted_new_id_claims() {
        let mut objects = BTreeMap::new();
        let tree = insert(
            &mut objects,
            &Object::Tree(Tree {
                entries: Vec::new(),
            }),
        );
        let root = signed_root(&mut objects, tree);
        let fact = inspect_snapshot_object(
            root,
            &objects[&root],
            SnapshotRole::BaseRoot,
            inspection_limits(),
        )
        .unwrap();
        let record = start_snapshot_walk(root, SnapshotRole::BaseRoot).unwrap();
        let step = advance_snapshot_walk(
            &record,
            &fact,
            &[],
            NonZeroUsize::new(1).unwrap(),
            &walk_limits(),
        )
        .unwrap();
        let prior = SnapshotWalkUsage::default();
        let mut one_less = walk_limits();
        one_less.max_canonical_bytes = fact.canonical_len() as u64 - 1;
        assert_eq!(
            apply_walk_accounting(prior, &step, &[root], one_less),
            Err(SnapshotWalkError::BudgetExceeded)
        );
        assert_eq!(prior, SnapshotWalkUsage::default());
        let exact = SnapshotWalkLimits {
            max_objects: 1,
            max_canonical_bytes: u64::try_from(fact.canonical_len()).unwrap(),
            max_tree_depth: 0,
            max_work: 1,
        };
        assert_eq!(
            apply_walk_accounting(prior, &step, &[root], exact).unwrap(),
            SnapshotWalkUsage {
                objects: 1,
                canonical_bytes: exact.max_canonical_bytes,
                max_tree_depth: 0,
                work: 1,
            }
        );
        let mut too_few = exact;
        too_few.max_objects = 0;
        assert_eq!(
            apply_walk_accounting(prior, &step, &[root], too_few),
            Err(SnapshotWalkError::BudgetExceeded)
        );
        too_few = exact;
        too_few.max_work = 0;
        assert_eq!(
            apply_walk_accounting(prior, &step, &[root], too_few),
            Err(SnapshotWalkError::BudgetExceeded)
        );
        assert_eq!(
            apply_walk_accounting(prior, &step, &[root, root], walk_limits()),
            Err(SnapshotWalkError::InconsistentAccounting)
        );
        assert_eq!(
            apply_walk_accounting(prior, &step, &[[99; 32]], walk_limits()),
            Err(SnapshotWalkError::InconsistentAccounting)
        );
        let mut stale = prior;
        stale.work = walk_limits().max_work + 1;
        assert_eq!(
            apply_walk_accounting(stale, &step, &[], walk_limits()),
            Err(SnapshotWalkError::BudgetExceeded)
        );
    }

    #[test]
    fn manifest_page_checks_each_repeated_position() {
        let mut objects = BTreeMap::new();
        let chunk = insert(
            &mut objects,
            &Object::Blob(Blob {
                data: b"abc".to_vec(),
            }),
        );
        let manifest = insert(
            &mut objects,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: 5,
                chunk_size: 3,
                chunks: vec![chunk, chunk],
            }),
        );
        let parent = inspect_snapshot_object(
            manifest,
            &objects[&manifest],
            SnapshotRole::File,
            inspection_limits(),
        )
        .unwrap();
        let fact = inspect_snapshot_object(
            chunk,
            &objects[&chunk],
            SnapshotRole::Chunk,
            inspection_limits(),
        )
        .unwrap();
        let record = SnapshotWalkRecord::ManifestPage {
            id: manifest,
            tree_depth: 0,
            next_index: 0,
            sum: 0,
        };
        assert_eq!(
            next_manifest_ids(&record, &parent, NonZeroUsize::new(2).unwrap()).unwrap(),
            &[chunk, chunk]
        );
        let result = advance_snapshot_walk(
            &record,
            &parent,
            &[fact],
            NonZeroUsize::new(2).unwrap(),
            &walk_limits(),
        );
        assert!(matches!(result, Err(SnapshotWalkError::InvalidPage)));
        let facts = [
            inspect_snapshot_object(
                chunk,
                &objects[&chunk],
                SnapshotRole::Chunk,
                inspection_limits(),
            )
            .unwrap(),
            inspect_snapshot_object(
                chunk,
                &objects[&chunk],
                SnapshotRole::Chunk,
                inspection_limits(),
            )
            .unwrap(),
        ];
        assert!(matches!(
            advance_snapshot_walk(
                &record,
                &parent,
                &facts,
                NonZeroUsize::new(2).unwrap(),
                &walk_limits()
            ),
            Err(SnapshotWalkError::InvalidChunkLayout)
        ));
    }

    #[test]
    fn manifest_cursor_rejects_impossible_initial_and_fixed_prefix_sums() {
        let mut objects = BTreeMap::new();
        let chunk = insert(&mut objects, &Object::Blob(Blob { data: vec![1; 3] }));
        let manifest = insert(
            &mut objects,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: 6,
                chunk_size: 3,
                chunks: vec![chunk, chunk],
            }),
        );
        let parent = inspect_snapshot_object(
            manifest,
            &objects[&manifest],
            SnapshotRole::File,
            inspection_limits(),
        )
        .unwrap();
        let fact = inspect_snapshot_object(
            chunk,
            &objects[&chunk],
            SnapshotRole::Chunk,
            inspection_limits(),
        )
        .unwrap();
        let width = NonZeroUsize::new(1).unwrap();
        for (next_index, sum) in [(0, 1), (1, 2), (1, 4)] {
            let record = SnapshotWalkRecord::ManifestPage {
                id: manifest,
                tree_depth: 0,
                next_index,
                sum,
            };
            assert_eq!(
                next_manifest_ids(&record, &parent, width),
                Err(SnapshotWalkError::InvalidPage)
            );
            assert_eq!(
                advance_snapshot_walk(
                    &record,
                    &parent,
                    std::slice::from_ref(&fact),
                    width,
                    &walk_limits()
                )
                .map(|_| ()),
                Err(SnapshotWalkError::InvalidPage)
            );
        }
    }

    #[test]
    fn manifest_positions_and_cursors_reject_bad_facts_and_layouts() {
        let mut objects = BTreeMap::new();
        let ids: Vec<_> = [0usize, 1, 2, 3, 4]
            .into_iter()
            .map(|length| {
                insert(
                    &mut objects,
                    &Object::Blob(Blob {
                        data: vec![1; length],
                    }),
                )
            })
            .collect();
        let width = NonZeroUsize::new(2).unwrap();
        let inspect = |id, role| {
            inspect_snapshot_object(id, &objects[&id], role, inspection_limits()).unwrap()
        };
        for (total, fixed, chunks, expected) in [
            (6, 3, vec![ids[3], ids[3]], Ok(())),
            (
                5,
                3,
                vec![ids[2], ids[3]],
                Err(SnapshotWalkError::InvalidChunkLayout),
            ),
            (
                7,
                3,
                vec![ids[3], ids[4]],
                Err(SnapshotWalkError::InvalidChunkLayout),
            ),
            (
                3,
                3,
                vec![ids[3], ids[0]],
                Err(SnapshotWalkError::InvalidChunkLayout),
            ),
            (
                5,
                0,
                vec![ids[2], ids[2]],
                Err(SnapshotWalkError::InvalidChunkLayout),
            ),
            (
                3,
                0,
                vec![ids[2], ids[2]],
                Err(SnapshotWalkError::InvalidChunkLayout),
            ),
        ] {
            let manifest = Object::ChunkedBlob(ChunkedBlob {
                total_size: total,
                chunk_size: fixed,
                chunks: chunks.clone(),
            });
            let bytes = serialize(&manifest).unwrap();
            let id = id_from_object(&manifest, &bytes);
            let parent =
                inspect_snapshot_object(id, &bytes, SnapshotRole::File, inspection_limits())
                    .unwrap();
            let record = SnapshotWalkRecord::ManifestPage {
                id,
                tree_depth: 0,
                next_index: 0,
                sum: 0,
            };
            let facts: Vec<_> = chunks
                .iter()
                .map(|child| inspect(*child, SnapshotRole::Chunk))
                .collect();
            assert_eq!(
                advance_snapshot_walk(&record, &parent, &facts, width, &walk_limits()).map(|_| ()),
                expected
            );
        }
        let manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: 6,
            chunk_size: 3,
            chunks: vec![ids[3], ids[3]],
        });
        let bytes = serialize(&manifest).unwrap();
        let id = id_from_object(&manifest, &bytes);
        let parent =
            inspect_snapshot_object(id, &bytes, SnapshotRole::File, inspection_limits()).unwrap();
        let record = SnapshotWalkRecord::ManifestPage {
            id,
            tree_depth: 0,
            next_index: 0,
            sum: 0,
        };
        let wrong = [
            inspect(ids[3], SnapshotRole::Chunk),
            inspect(ids[2], SnapshotRole::Chunk),
        ];
        assert_eq!(
            advance_snapshot_walk(&record, &parent, &wrong, width, &walk_limits()).map(|_| ()),
            Err(SnapshotWalkError::WrongId)
        );
        let distinct = Object::ChunkedBlob(ChunkedBlob {
            total_size: 5,
            chunk_size: 0,
            chunks: vec![ids[2], ids[3]],
        });
        let bytes = serialize(&distinct).unwrap();
        let distinct_id = id_from_object(&distinct, &bytes);
        let distinct_fact =
            inspect_snapshot_object(distinct_id, &bytes, SnapshotRole::File, inspection_limits())
                .unwrap();
        let distinct_record = SnapshotWalkRecord::ManifestPage {
            id: distinct_id,
            tree_depth: 0,
            next_index: 0,
            sum: 0,
        };
        let reordered = [
            inspect(ids[3], SnapshotRole::Chunk),
            inspect(ids[2], SnapshotRole::Chunk),
        ];
        assert_eq!(
            advance_snapshot_walk(
                &distinct_record,
                &distinct_fact,
                &reordered,
                width,
                &walk_limits()
            )
            .map(|_| ()),
            Err(SnapshotWalkError::WrongId)
        );
        let record = SnapshotWalkRecord::ManifestPage {
            id,
            tree_depth: 0,
            next_index: u32::MAX,
            sum: 0,
        };
        assert_eq!(
            next_manifest_ids(&record, &parent, width),
            Err(SnapshotWalkError::InvalidPage)
        );
        let record = SnapshotWalkRecord::ManifestPage {
            id: [99; 32],
            tree_depth: 0,
            next_index: 0,
            sum: 0,
        };
        assert_eq!(
            next_manifest_ids(&record, &parent, width),
            Err(SnapshotWalkError::WrongId)
        );
        assert_eq!(
            advance_snapshot_walk(&record, &parent, &[], width, &walk_limits()).map(|_| ()),
            Err(SnapshotWalkError::WrongId)
        );
        let wrong_role = SnapshotWalkRecord::Visit {
            id,
            role: SnapshotRole::Tree,
            tree_depth: 0,
        };
        assert_eq!(
            advance_snapshot_walk(&wrong_role, &parent, &[], width, &walk_limits()).map(|_| ()),
            Err(SnapshotWalkError::WrongRole)
        );

        let huge = Object::ChunkedBlob(ChunkedBlob {
            total_size: u64::MAX,
            chunk_size: 0,
            chunks: vec![ids[1], ids[1]],
        });
        let bytes = serialize(&huge).unwrap();
        let huge_id = id_from_object(&huge, &bytes);
        let parent =
            inspect_snapshot_object(huge_id, &bytes, SnapshotRole::File, inspection_limits())
                .unwrap();
        let record = SnapshotWalkRecord::ManifestPage {
            id: huge_id,
            tree_depth: 0,
            next_index: 1,
            sum: u64::MAX,
        };
        assert_eq!(
            advance_snapshot_walk(
                &record,
                &parent,
                &[inspect(ids[1], SnapshotRole::Chunk)],
                width,
                &walk_limits()
            )
            .map(|_| ()),
            Err(SnapshotWalkError::InvalidChunkLayout)
        );
    }

    #[test]
    fn page_and_depth_bounds_are_independent_of_full_tree_width() {
        let mut objects = BTreeMap::new();
        let blob = insert(&mut objects, &Object::Blob(Blob { data: vec![1] }));
        let entries = (0..100)
            .map(|i| TreeEntry {
                name: format!("f{i:03}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: blob,
            })
            .collect();
        let tree = insert(&mut objects, &Object::Tree(Tree { entries }));
        let parent = inspect_snapshot_object(
            tree,
            &objects[&tree],
            SnapshotRole::Tree,
            inspection_limits(),
        )
        .unwrap();
        let record = SnapshotWalkRecord::TreePage {
            id: tree,
            tree_depth: 0,
            next_index: 0,
        };
        let step = advance_snapshot_walk(
            &record,
            &parent,
            &[],
            NonZeroUsize::new(64).unwrap(),
            &walk_limits(),
        )
        .unwrap();
        assert_eq!(step.successors().len(), 65);
        assert_eq!(step.work_delta(), 64);
        assert!(matches!(
            advance_snapshot_walk(
                &record,
                &parent,
                &[],
                NonZeroUsize::new(65).unwrap(),
                &walk_limits()
            ),
            Err(SnapshotWalkError::InvalidPage)
        ));
        assert!(matches!(
            advance_snapshot_walk(
                &SnapshotWalkRecord::TreePage {
                    id: tree,
                    tree_depth: 0,
                    next_index: 100
                },
                &parent,
                &[],
                NonZeroUsize::new(1).unwrap(),
                &walk_limits()
            ),
            Err(SnapshotWalkError::InvalidPage)
        ));
        assert!(matches!(
            advance_snapshot_walk(
                &SnapshotWalkRecord::TreePage {
                    id: tree,
                    tree_depth: 129,
                    next_index: 0
                },
                &parent,
                &[],
                NonZeroUsize::new(1).unwrap(),
                &walk_limits()
            ),
            Err(SnapshotWalkError::BudgetExceeded)
        ));
        let root = signed_root(&mut objects, tree);
        let mut low = walk_limits();
        low.max_work = 201; // 1 root + 1 Tree + 100 edges + 100 Blob visits = 202.
        assert_eq!(
            drive(&objects, root, 64, low),
            Err(SnapshotWalkError::BudgetExceeded)
        );
        low.max_work = 202;
        assert!(drive(&objects, root, 1, low).is_ok());
    }

    #[test]
    fn shared_tree_at_two_actual_depths_rechecks_limit() {
        let mut objects = BTreeMap::new();
        let shared = insert(
            &mut objects,
            &Object::Tree(Tree {
                entries: Vec::new(),
            }),
        );
        let middle = insert(
            &mut objects,
            &Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"child".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: shared,
                }],
            }),
        );
        let tree = insert(
            &mut objects,
            &Object::Tree(Tree {
                entries: vec![
                    TreeEntry {
                        name: b"a".to_vec(),
                        mode: EntryMode::Tree,
                        object_hash: shared,
                    },
                    TreeEntry {
                        name: b"b".to_vec(),
                        mode: EntryMode::Tree,
                        object_hash: middle,
                    },
                ],
            }),
        );
        let root = signed_root(&mut objects, tree);
        let mut limits = walk_limits();
        limits.max_tree_depth = 1;
        assert_eq!(
            drive(&objects, root, 1, limits),
            Err(SnapshotWalkError::BudgetExceeded)
        );
        let mut source = MapSource(objects.clone());
        let old_limits = RecipientLimits {
            max_tree_depth: 1,
            ..RecipientLimits::default()
        };
        assert!(
            RecipientGraph::new(&mut source, old_limits)
                .validate_base(root)
                .is_err()
        );
        limits.max_tree_depth = 2;
        assert_eq!(
            drive(&objects, root, 2, limits).unwrap().0.max_tree_depth,
            2
        );
    }

    #[test]
    fn native_large_distinct_bytes_use_bounded_live_facts() {
        // Descriptor-only source: never retain the complete 129 MiB graph.
        const FILES: u8 = 129;
        const CONTENT: usize = 1024 * 1024;
        let mut descriptors = BTreeMap::new();
        let mut entries = Vec::new();
        let mut expected_blob_bytes = 0u64;
        for seed in 0..FILES {
            let object = Object::Blob(Blob {
                data: vec![seed; CONTENT],
            });
            let bytes = serialize(&object).unwrap();
            expected_blob_bytes += u64::try_from(bytes.len()).unwrap();
            let id = id_from_object(&object, &bytes);
            descriptors.insert(id, seed);
            entries.push(TreeEntry {
                name: format!("file-{seed:03}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: id,
            });
        }
        let mut roots = BTreeMap::new();
        let tree = insert(&mut roots, &Object::Tree(Tree { entries }));
        let root = signed_root(&mut roots, tree);
        let expected_total =
            expected_blob_bytes + roots.values().map(|bytes| bytes.len() as u64).sum::<u64>();
        assert_eq!(descriptors.len() + roots.len(), usize::from(FILES) + 2);
        assert!(roots.values().map(Vec::len).sum::<usize>() < 64 * 1024);
        let mut pending =
            VecDeque::from([start_snapshot_walk(root, SnapshotRole::BaseRoot).unwrap()]);
        let mut seen = BTreeMap::new();
        let mut usage = SnapshotWalkUsage::default();
        let mut max_live_input = 0usize;
        let mut max_fact_tree_entries = 0usize;
        let mut max_fact_name_bytes = 0usize;
        let mut max_fact_manifest_ids = 0usize;
        while let Some(record) = pending.pop_front() {
            let bytes = if let Some(bytes) = roots.get(&record.id()) {
                bytes.clone()
            } else {
                let fill_byte = descriptors[&record.id()];
                serialize(&Object::Blob(Blob {
                    data: vec![fill_byte; CONTENT],
                }))
                .unwrap()
            };
            max_live_input = max_live_input.max(bytes.len());
            let fact =
                inspect_snapshot_object(record.id(), &bytes, record.role(), inspection_limits())
                    .unwrap();
            // Measure the variable-length metadata exposed by this fact;
            // size_of_val would miss the Tree and manifest Vec allocations.
            // The caller still has transient serialize/inspect scratch, so
            // these structural counts are not an exact process-RSS claim.
            if let Some(count) = fact.tree_entries_len() {
                max_fact_tree_entries = max_fact_tree_entries.max(count);
                if count != 0 {
                    let names = fact
                        .tree_page(0, count)
                        .unwrap()
                        .iter()
                        .map(|entry| entry.name.len())
                        .sum::<usize>();
                    max_fact_name_bytes = max_fact_name_bytes.max(names);
                }
            }
            if let Some((_, _, count)) = fact.manifest() {
                max_fact_manifest_ids = max_fact_manifest_ids.max(count);
            }
            let step = advance_snapshot_walk(
                &record,
                &fact,
                &[],
                NonZeroUsize::new(64).unwrap(),
                &walk_limits(),
            )
            .unwrap();
            let new: Vec<_> = step
                .observations()
                .iter()
                .map(WalkObjectObservation::id)
                .filter(|id| !seen.contains_key(id))
                .collect();
            usage = apply_walk_accounting(usage, &step, &new, walk_limits()).unwrap();
            for item in step.observations() {
                seen.insert(item.id(), item.canonical_len());
            }
            pending.extend(step.successors().iter().copied());
        }
        assert_eq!(usage.objects, u64::from(FILES) + 2);
        assert_eq!(usage.canonical_bytes, expected_total);
        assert!(expected_total > 128 * 1024 * 1024);
        assert!(max_live_input < 2 * 1024 * 1024);
        assert_eq!(max_fact_tree_entries, usize::from(FILES));
        assert!(max_fact_name_bytes < 2 * 1024);
        assert_eq!(max_fact_manifest_ids, 0);
        assert_eq!(seen.len(), usize::from(FILES) + 2);
    }

    #[test]
    fn model_job_retries_every_task_kind_and_refuses_partial_transactions() {
        // Protocol example only: this is not evidence of SQL durability.
        let mut objects = BTreeMap::new();
        let chunk = insert(&mut objects, &Object::Blob(Blob { data: vec![7; 3] }));
        let manifest = insert(
            &mut objects,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: 6,
                chunk_size: 3,
                chunks: vec![chunk, chunk],
            }),
        );
        let shared = insert(
            &mut objects,
            &Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"file".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: manifest,
                }],
            }),
        );
        let tree = insert(
            &mut objects,
            &Object::Tree(Tree {
                entries: vec![
                    TreeEntry {
                        name: b"a".to_vec(),
                        mode: EntryMode::Tree,
                        object_hash: shared,
                    },
                    TreeEntry {
                        name: b"b".to_vec(),
                        mode: EntryMode::Tree,
                        object_hash: shared,
                    },
                ],
            }),
        );
        let root = signed_root(&mut objects, tree);
        let catalog = objects.keys().copied().collect::<BTreeSet<_>>();
        let old = old_usage(&objects, root);
        let mut baseline = ModelJob::new(root);
        while let Some(record) = baseline.pending.front().copied() {
            let step = model_step(&objects, record);
            baseline
                .commit(record, &step, step.successors(), 1)
                .unwrap();
        }
        assert_eq!(
            baseline.finish(&catalog).unwrap().objects as usize,
            old.objects
        );
        assert_eq!(baseline.usage.canonical_bytes as usize, old.canonical_bytes);
        assert_eq!(baseline.usage.max_tree_depth as usize, old.max_tree_depth);
        assert_eq!(baseline.usage.work as usize, old.occurrences);

        let mut replay = ModelJob::new(root);
        let mut interrupted = [false; 3];
        while let Some(record) = replay.pending.front().copied() {
            let kind = match record {
                SnapshotWalkRecord::Visit { .. } => 0,
                SnapshotWalkRecord::TreePage { .. } => 1,
                SnapshotWalkRecord::ManifestPage { .. } => 2,
            };
            let step = model_step(&objects, record);
            if !interrupted[kind] {
                let before = replay.clone();
                let discarded = model_step(&objects, record);
                assert_eq!(step.successors(), discarded.successors());
                assert_eq!(step.observations(), discarded.observations());
                assert_eq!(replay, before);
                interrupted[kind] = true;
            }
            let before = replay.clone();
            assert_eq!(
                replay.commit(record, &step, step.successors(), 2),
                Err(SnapshotWalkError::InconsistentAccounting)
            );
            assert_eq!(replay, before);
            if step.successors().len() > 1 {
                assert_eq!(
                    replay.commit(record, &step, &step.successors()[..1], 1),
                    Err(SnapshotWalkError::InconsistentAccounting)
                );
                assert_eq!(replay, before);
            }
            replay.commit(record, &step, step.successors(), 1).unwrap();
        }
        assert_eq!(interrupted, [true; 3]);
        assert_eq!(replay, baseline);
        assert_eq!(replay.finish(&catalog), Ok(baseline.usage));
        let mut extra = catalog.clone();
        extra.insert([255; 32]);
        assert_eq!(
            replay.finish(&extra),
            Err(SnapshotWalkError::InconsistentAccounting)
        );
        let mut missing = catalog;
        missing.remove(&chunk);
        assert_eq!(
            replay.finish(&missing),
            Err(SnapshotWalkError::InconsistentAccounting)
        );

        let mut corrupt = ModelJob::new(root);
        corrupt.seen.insert(root, u64::MAX);
        let record = corrupt.pending.front().copied().unwrap();
        let step = model_step(&objects, record);
        let before = corrupt.clone();
        assert_eq!(
            corrupt.commit(record, &step, step.successors(), 1),
            Err(SnapshotWalkError::InconsistentAccounting)
        );
        assert_eq!(corrupt, before);
    }

    #[test]
    fn cdc_zero_length_chunk_and_exact_catalog_membership() {
        let mut objects = BTreeMap::new();
        let empty = insert(&mut objects, &Object::Blob(Blob { data: Vec::new() }));
        let content = insert(
            &mut objects,
            &Object::Blob(Blob {
                data: b"x".to_vec(),
            }),
        );
        let manifest = insert(
            &mut objects,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: 1,
                chunk_size: 0,
                chunks: vec![empty, content, empty],
            }),
        );
        let tree = insert(
            &mut objects,
            &Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"file".to_vec(),
                    mode: EntryMode::Executable,
                    object_hash: manifest,
                }],
            }),
        );
        let root = signed_root(&mut objects, tree);
        let old = old_usage(&objects, root);
        let (actual, seen) = drive(&objects, root, 1, walk_limits()).unwrap();
        assert_eq!(usize::try_from(actual.work).unwrap(), old.occurrences);
        assert_eq!(seen.len(), objects.len());
        assert_eq!(
            seen.keys().copied().collect::<BTreeSet<_>>(),
            objects.keys().copied().collect()
        );
    }

    #[test]
    fn wrong_edge_kind_and_missing_dependency_reject_like_old_walk() {
        let mut objects = BTreeMap::new();
        let child_tree = insert(
            &mut objects,
            &Object::Tree(Tree {
                entries: Vec::new(),
            }),
        );
        let root_tree = insert(
            &mut objects,
            &Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"file".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: child_tree,
                }],
            }),
        );
        let root = signed_root(&mut objects, root_tree);
        assert_eq!(
            drive(&objects, root, 1, walk_limits()),
            Err(SnapshotWalkError::WrongRole)
        );
        let mut old = MapSource(objects.clone());
        assert!(
            RecipientGraph::new(&mut old, RecipientLimits::default())
                .validate_base(root)
                .is_err()
        );
        objects.remove(&child_tree);
        assert_eq!(
            drive(&objects, root, 1, walk_limits()),
            Err(SnapshotWalkError::WrongId)
        );
        let mut old = MapSource(objects);
        assert!(
            RecipientGraph::new(&mut old, RecipientLimits::default())
                .validate_base(root)
                .is_err()
        );
    }
}
