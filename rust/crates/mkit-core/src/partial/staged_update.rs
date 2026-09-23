//! Borrowed MKWU carrier facts and bounded staged-validation accounting.
//!
//! These local facts do not certify an external inventory, graph frontier,
//! persisted checkpoint, or publication decision.

use crate::hash::{Hash, hash};
use crate::object::{EntryMode, Object, ObjectType};
use crate::pack::{CheckedRawPack, RawPackError, RawPackLimits};
use crate::serialize::deserialize;
use std::sync::Arc;

use super::inspect::{
    InspectError, InspectedKind, InspectedObject, ObjectInspectionLimits, SnapshotRole,
    identify_snapshot_object, inspect_snapshot_object,
};
use super::update::{
    HeaderParseFailure, ParsedUpdateHeader, UpdateChange, parse_borrowed_header,
    parse_borrowed_header_detailed, preflight_candidate,
};
use super::verify::{preflight_file, preflight_tree};
use super::walk::{SnapshotWalkLimits, SnapshotWalkUsage};
use super::{PartialError, PartialLimits, PartialPath};

/// Named v1 resource profile for staged local transitions. It is not the old
/// recipient's shared-cache accounting profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StagedUpdateLimitsV1 {
    /// Maximum encoded MKWU prefix through the pack length, in bytes.
    pub max_header_bytes: u64,
    /// Maximum complete caller-owned MKWU carrier, in bytes.
    pub max_update_bytes: u64,
    /// Maximum embedded raw pack, including its framing, in bytes.
    pub max_pack_bytes: u64,
    /// Maximum number of supplied raw frames, regardless of reachability.
    pub max_inventory_entries: u64,
    /// Sum of canonical payload lengths across supplied raw frames, in bytes.
    pub max_inventory_payload_bytes: u64,
    /// Maximum inventory work: exactly two units per inspected frame.
    pub max_inventory_work: u64,
    /// Independent complete source-only base Snapshot U/B/D/W limits.
    pub base_walk: SnapshotWalkLimits,
    /// Independent complete candidate Snapshot U/B/D/W limits.
    pub candidate_walk: SnapshotWalkLimits,
    /// Maximum changed Tree-pair Visit occurrences, not unique Tree IDs.
    pub max_diff_pair_visits: u64,
    /// Maximum combined diff work: pair Visits plus compared Tree entries.
    pub max_diff_work: u64,
    /// Maximum deduplicated required supplied IDs.
    pub max_required_unique_ids: u64,
    /// Sum of canonical lengths for deduplicated required IDs, in bytes.
    pub max_required_canonical_bytes: u64,
    /// Candidate observation, changed Tree/file occurrences and chunk positions.
    pub max_origin_work: u64,
}

impl Default for StagedUpdateLimitsV1 {
    fn default() -> Self {
        let walk = SnapshotWalkLimits {
            max_objects: 100_000,
            max_canonical_bytes: 256 * 1024 * 1024,
            max_tree_depth: 128,
            max_work: 1_000_000,
        };
        Self {
            max_header_bytes: 128 * 1024,
            max_update_bytes: 56 * 1024 * 1024,
            max_pack_bytes: 48 * 1024 * 1024,
            max_inventory_entries: 65_536,
            max_inventory_payload_bytes: 48 * 1024 * 1024,
            max_inventory_work: 131_072,
            base_walk: walk,
            candidate_walk: walk,
            max_diff_pair_visits: 8_193,
            max_diff_work: 1_000_000,
            max_required_unique_ids: 65_536,
            max_required_canonical_bytes: 48 * 1024 * 1024,
            max_origin_work: 1_000_000,
        }
    }
}

impl StagedUpdateLimitsV1 {
    fn is_v1_subset(self) -> bool {
        let v1 = Self::default();
        let walk = |actual: SnapshotWalkLimits, ceiling: SnapshotWalkLimits| {
            actual.max_objects <= ceiling.max_objects
                && actual.max_canonical_bytes <= ceiling.max_canonical_bytes
                && actual.max_tree_depth <= ceiling.max_tree_depth
                && actual.max_work <= ceiling.max_work
        };
        self.max_header_bytes <= v1.max_header_bytes
            && self.max_update_bytes <= v1.max_update_bytes
            && self.max_pack_bytes <= v1.max_pack_bytes
            && self.max_inventory_entries <= v1.max_inventory_entries
            && self.max_inventory_payload_bytes <= v1.max_inventory_payload_bytes
            && self.max_inventory_work <= v1.max_inventory_work
            && walk(self.base_walk, v1.base_walk)
            && walk(self.candidate_walk, v1.candidate_walk)
            && self.max_diff_pair_visits <= v1.max_diff_pair_visits
            && self.max_diff_work <= v1.max_diff_work
            && self.max_required_unique_ids <= v1.max_required_unique_ids
            && self.max_required_canonical_bytes <= v1.max_required_canonical_bytes
            && self.max_origin_work <= v1.max_origin_work
    }
}

/// Checked counters for staged local transitions. Trusted callers own their
/// persistence, seen-ID decisions, exact queues and completion predicates.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StagedUpdateUsageV1 {
    /// Encoded header prefix size from the checked carrier, in bytes.
    pub header_bytes: u64,
    /// Exact complete MKWU carrier length, in bytes.
    pub update_bytes: u64,
    /// Exact embedded raw-pack length including framing, in bytes.
    pub pack_bytes: u64,
    /// Checked raw frames in strict ordinal and ID order.
    pub inventory_entries: u64,
    /// Sum of their canonical payload bytes; no deduplication by ID.
    pub inventory_payload_bytes: u64,
    /// Exactly twice `inventory_entries` after committed local steps.
    pub inventory_work: u64,
    /// Unique U/B, max depth D and occurrence W for source-only base closure.
    pub base_walk: SnapshotWalkUsage,
    /// Independent U/B/D/W for complete candidate logical closure.
    pub candidate_walk: SnapshotWalkUsage,
    /// Changed Tree-pair Visit occurrences, even for shared Tree IDs.
    pub diff_pair_visits: u64,
    /// Compared entry positions across all changed Tree pages.
    pub diff_compared_entries: u64,
    /// Exactly `diff_pair_visits + diff_compared_entries`, checked on each step.
    pub diff_work: u64,
    /// Deduplicated required supplied IDs; the caller owns the seen ledger.
    pub required_unique_ids: u64,
    /// Canonical bytes charged once for each newly required ID.
    pub required_canonical_bytes: u64,
    /// Candidate, changed Tree/file occurrences and chunk positions checked.
    pub origin_work: u64,
    /// Largest changed Blob length or manifest declared total reserved at Visit.
    pub max_changed_file_bytes_seen: u64,
    /// Sum of Visit-time reservations per changed path, including repeated IDs.
    pub changed_total_bytes: u64,
}

/// Error from one borrowed-carrier or staged local validation operation.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum StagedUpdateError {
    #[error("staged update exceeds an active limit or checked arithmetic bound")]
    Budget,
    #[error("staged update has invalid carrier framing, paths or objects")]
    Invalid,
    #[error("staged update differs from an independently expected identity")]
    WrongIdentity,
    #[error("staged update local record, fact or ledger input is inconsistent")]
    Inconsistent,
    #[error("staged update has invalid chunk layout")]
    ChunkLayout,
    #[error(transparent)]
    Partial(#[from] PartialError),
    #[error(transparent)]
    Pack(#[from] RawPackError),
    #[error(transparent)]
    Inspect(#[from] InspectError),
}

/// One declared changed file at an exact path. The old ID/mode must later
/// match an inspected base occurrence, not merely this header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedChange {
    path: PartialPath,
    old_mode: EntryMode,
    old_id: Hash,
    new_id: Hash,
}

impl StagedChange {
    #[must_use]
    pub fn path(&self) -> &PartialPath {
        &self.path
    }
    #[must_use]
    pub fn old_mode(&self) -> EntryMode {
        self.old_mode
    }
    #[must_use]
    pub fn old_id(&self) -> Hash {
        self.old_id
    }
    #[must_use]
    pub fn new_id(&self) -> Hash {
        self.new_id
    }
}

/// Private-construction canonical header facts. A prefix does not prove its
/// embedded pack or whole-carrier identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMkwuHeader {
    base_id: Hash,
    candidate_id: Hash,
    changes: Vec<StagedChange>,
    pack_hash: Hash,
    pack_len: usize,
    pack_offset: usize,
}

impl ParsedMkwuHeader {
    #[must_use]
    pub fn base_id(&self) -> Hash {
        self.base_id
    }
    #[must_use]
    pub fn candidate_id(&self) -> Hash {
        self.candidate_id
    }
    #[must_use]
    pub fn changes(&self) -> &[StagedChange] {
        &self.changes
    }
    #[must_use]
    pub fn pack_hash(&self) -> Hash {
        self.pack_hash
    }
    #[must_use]
    pub fn pack_len(&self) -> usize {
        self.pack_len
    }
    #[must_use]
    pub fn pack_offset(&self) -> usize {
        self.pack_offset
    }
}

impl From<ParsedUpdateHeader> for ParsedMkwuHeader {
    fn from(parsed: ParsedUpdateHeader) -> Self {
        Self {
            base_id: parsed.base_id,
            candidate_id: parsed.candidate_id,
            changes: parsed
                .changes
                .into_iter()
                .map(|change: UpdateChange| StagedChange {
                    path: change.path,
                    old_mode: change.old_mode,
                    old_id: change.old_id,
                    new_id: change.new_id,
                })
                .collect(),
            pack_hash: parsed.declared_pack_hash,
            pack_len: parsed.declared_pack_len,
            pack_offset: parsed.pack_offset,
        }
    }
}

/// Result of reading only a bounded MKWU prefix. `NeedMore` is not a
/// validation success and may be retried with a longer bounded prefix.
#[derive(Debug)]
pub enum HeaderPrefix {
    NeedMore,
    Parsed(ParsedMkwuHeader),
}

/// Parse canonical header grammar shared with the existing MKWU decoder.
/// This does not inspect or authenticate the remaining carrier.
///
/// # Errors
/// Refuses invalid limits, malformed complete fields or a prefix over 128 KiB.
pub fn parse_mkwu_header_prefix(
    prefix: &[u8],
    portable: &PartialLimits,
    staged: &StagedUpdateLimitsV1,
) -> Result<HeaderPrefix, StagedUpdateError> {
    if !portable.is_v1_subset() || !staged.is_v1_subset() {
        return Err(StagedUpdateError::Budget);
    }
    let cap = staged.max_header_bytes.min(128 * 1024);
    if u64::try_from(prefix.len()).map_err(|_| StagedUpdateError::Budget)? > cap {
        return Err(StagedUpdateError::Budget);
    }
    match parse_borrowed_header_detailed(
        prefix,
        portable,
        usize::try_from(cap).map_err(|_| StagedUpdateError::Budget)?,
    ) {
        Ok(parsed) => Ok(HeaderPrefix::Parsed(parsed.into())),
        Err(HeaderParseFailure::Incomplete) if prefix.len() < cap as usize => {
            Ok(HeaderPrefix::NeedMore)
        }
        Err(HeaderParseFailure::Incomplete) => Err(StagedUpdateError::Budget),
        Err(HeaderParseFailure::Invalid(error)) => Err(error.into()),
    }
}

/// Borrowed complete MKWU v1 framing/key fact. The caller keeps `bytes`
/// alive; this contains no decoded inventory and is not edit admission.
#[derive(Debug)]
pub struct CheckedMkwu<'a> {
    header: ParsedMkwuHeader,
    pack: CheckedRawPack<'a>,
    usage: StagedUpdateUsageV1,
}

impl<'a> CheckedMkwu<'a> {
    /// Check the complete independently pinned update and borrow its raw pack.
    ///
    /// # Errors
    /// Refuses active caps before hashing, wrong complete length/digest/base,
    /// malformed header/lengths and the checked raw-pack key/profile/framing.
    pub fn open(
        bytes: &'a [u8],
        expected_len: u64,
        expected_digest: Hash,
        expected_base: Hash,
        portable: PartialLimits,
        staged: StagedUpdateLimitsV1,
    ) -> Result<Self, StagedUpdateError> {
        if !portable.is_v1_subset() || !staged.is_v1_subset() {
            return Err(StagedUpdateError::Budget);
        }
        let len = u64::try_from(bytes.len()).map_err(|_| StagedUpdateError::Budget)?;
        if len
            > staged
                .max_update_bytes
                .min(portable.max_update_bytes as u64)
        {
            return Err(StagedUpdateError::Budget);
        }
        if len != expected_len || hash(bytes) != expected_digest {
            return Err(StagedUpdateError::WrongIdentity);
        }
        let parsed = parse_borrowed_header(
            bytes,
            &portable,
            usize::try_from(staged.max_header_bytes.min(128 * 1024))
                .map_err(|_| StagedUpdateError::Budget)?,
        )?;
        if parsed.base_id != expected_base {
            return Err(StagedUpdateError::WrongIdentity);
        }
        if parsed.encoded_pack_len != parsed.declared_pack_len {
            return Err(StagedUpdateError::Invalid);
        }
        let end = parsed
            .pack_offset
            .checked_add(parsed.declared_pack_len)
            .ok_or(StagedUpdateError::Budget)?;
        if end != bytes.len() {
            return Err(StagedUpdateError::Invalid);
        }
        let pack_bytes = bytes
            .get(parsed.pack_offset..end)
            .ok_or(StagedUpdateError::Invalid)?;
        let pack = CheckedRawPack::open(
            pack_bytes,
            parsed.declared_pack_hash,
            RawPackLimits {
                max_pack_bytes: portable.max_raw_pack_bytes.min(
                    usize::try_from(staged.max_pack_bytes)
                        .map_err(|_| StagedUpdateError::Budget)?,
                ),
                max_entries: u32::try_from(
                    portable.max_update_objects.min(
                        usize::try_from(staged.max_inventory_entries)
                            .map_err(|_| StagedUpdateError::Budget)?,
                    ),
                )
                .map_err(|_| StagedUpdateError::Budget)?,
                max_entry_bytes: portable.max_object_bytes,
                max_payload_bytes: staged
                    .max_inventory_payload_bytes
                    .min(staged.max_pack_bytes),
            },
        )?;
        let header: ParsedMkwuHeader = parsed.into();
        let usage = StagedUpdateUsageV1 {
            header_bytes: u64::try_from(header.pack_offset)
                .map_err(|_| StagedUpdateError::Budget)?,
            update_bytes: len,
            pack_bytes: u64::try_from(pack_bytes.len()).map_err(|_| StagedUpdateError::Budget)?,
            ..StagedUpdateUsageV1::default()
        };
        Ok(Self {
            header,
            pack,
            usage,
        })
    }

    #[must_use]
    pub fn header(&self) -> &ParsedMkwuHeader {
        &self.header
    }
    #[must_use]
    pub fn pack(&self) -> &CheckedRawPack<'a> {
        &self.pack
    }
    #[must_use]
    pub fn initial_usage(&self) -> StagedUpdateUsageV1 {
        self.usage
    }
}

/// Immutable active header and limits for local staged transitions. This
/// context alone does not prove a prior sealed carrier or durable job state.
#[derive(Debug)]
pub struct StagedValidationContext {
    binding: Arc<ContextBinding>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ContextBinding {
    header: ParsedMkwuHeader,
    portable: PartialLimits,
    staged: StagedUpdateLimitsV1,
    inspection: ObjectInspectionLimits,
}

impl StagedValidationContext {
    /// Capture active limits and a canonical header fact.
    ///
    /// # Errors
    /// Rejects limits above v1 or an incompatible staged profile.
    pub fn new(
        header: ParsedMkwuHeader,
        portable: PartialLimits,
        staged: StagedUpdateLimitsV1,
        inspection: ObjectInspectionLimits,
    ) -> Result<Self, StagedUpdateError> {
        if !portable.is_v1_subset()
            || !staged.is_v1_subset()
            || staged.max_inventory_payload_bytes > staged.max_pack_bytes
            || inspection.max_object_bytes > portable.max_object_bytes
            || inspection.max_tree_bytes > portable.max_tree_object_bytes
            || inspection.max_tree_entries > portable.max_tree_entries
            || inspection.max_manifest_chunks > 100_000
            || header.changes.len() > portable.max_changed_paths
            || header.changes.len() > portable.max_selected_paths
            || u64::try_from(header.pack_offset)
                .map_or(true, |length| length > staged.max_header_bytes)
            || header.pack_len > portable.max_raw_pack_bytes
            || u64::try_from(header.pack_len).map_or(true, |length| length > staged.max_pack_bytes)
            || header
                .pack_offset
                .checked_add(header.pack_len)
                .is_none_or(|length| {
                    length > portable.max_update_bytes
                        || u64::try_from(length)
                            .map_or(true, |length| length > staged.max_update_bytes)
                })
        {
            return Err(StagedUpdateError::Budget);
        }
        // Reject lowered shape/aggregate bounds before copying path bytes for
        // the shared canonical spelling and ordering validator.
        let mut aggregate = 0usize;
        for change in &header.changes {
            if change.path.len() > portable.max_path_depth {
                return Err(StagedUpdateError::Budget);
            }
            let mut joined = 0usize;
            for (index, component) in change.path.iter().enumerate() {
                if component.len() > portable.max_component_bytes {
                    return Err(StagedUpdateError::Budget);
                }
                joined = joined
                    .checked_add(component.len() + usize::from(index != 0))
                    .ok_or(StagedUpdateError::Budget)?;
            }
            aggregate = aggregate
                .checked_add(joined)
                .ok_or(StagedUpdateError::Budget)?;
            if joined > portable.max_path_bytes || aggregate > portable.max_total_path_bytes {
                return Err(StagedUpdateError::Budget);
            }
        }
        super::validate_paths(
            &header
                .changes
                .iter()
                .map(|change| change.path.clone())
                .collect::<Vec<_>>(),
            &portable,
        )?;
        Ok(Self {
            binding: Arc::new(ContextBinding {
                header,
                portable,
                staged,
                inspection,
            }),
        })
    }
    #[must_use]
    pub fn header(&self) -> &ParsedMkwuHeader {
        &self.binding.header
    }
    #[must_use]
    pub fn portable(&self) -> &PartialLimits {
        &self.binding.portable
    }
    #[must_use]
    pub fn staged(&self) -> &StagedUpdateLimitsV1 {
        &self.binding.staged
    }
    #[must_use]
    pub fn inspection(&self) -> ObjectInspectionLimits {
        self.binding.inspection
    }
    pub(super) fn binds(&self, binding: &Arc<ContextBinding>) -> bool {
        Arc::ptr_eq(&self.binding, binding) || self.binding == *binding
    }
    pub(super) fn binding(&self) -> Arc<ContextBinding> {
        Arc::clone(&self.binding)
    }
}

/// Canonical, portable-preflighted supplied object. Not a reachability fact.
#[derive(Debug)]
pub struct StagedInventoryFact {
    object: InspectedObject,
    portable: PartialLimits,
    inspection: ObjectInspectionLimits,
}

impl StagedInventoryFact {
    #[must_use]
    pub fn object(&self) -> &InspectedObject {
        &self.object
    }
}

/// Check one supplied raw payload under active portable MKWU rules.
///
/// # Errors
/// Refuses disallowed type, lowered object/Tree/file/Commit cap, malformed
/// canonical bytes or invalid signed Commit.
pub fn inspect_staged_inventory_object(
    bytes: &[u8],
    context: &StagedValidationContext,
) -> Result<StagedInventoryFact, StagedUpdateError> {
    if bytes.is_empty() || bytes.len() > context.portable().max_object_bytes {
        return Err(StagedUpdateError::Budget);
    }
    match bytes[0] {
        tag if tag == ObjectType::Tree as u8 => preflight_tree(bytes, context.portable())?,
        tag if tag == ObjectType::Blob as u8 || tag == ObjectType::ChunkedBlob as u8 => {
            preflight_file(bytes, context.portable())?;
        }
        tag if tag == ObjectType::Commit as u8 => preflight_candidate(bytes, context.portable())?,
        _ => return Err(StagedUpdateError::Invalid),
    }
    let object = identify_snapshot_object(bytes, context.inspection())?;
    Ok(StagedInventoryFact {
        object,
        portable: *context.portable(),
        inspection: context.inspection(),
    })
}

/// Restorable trusted inventory bookkeeping; not proof of prior frames.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StagedInventoryCursor {
    /// Next raw frame ordinal; must equal `count` in a consistent checkpoint.
    pub next_ordinal: u64,
    /// Last checked type-aware ID; the next ID must be strictly greater.
    pub previous_id: Option<Hash>,
    /// Frames already checked; the trusted caller must prove every prior frame.
    pub count: u64,
    /// Canonical payload bytes over those frames, matching the usage ledger.
    pub canonical_bytes: u64,
}

/// One local inventory observation and prospective cursor.
#[derive(Debug)]
pub struct StagedInventoryStep {
    binding: Arc<ContextBinding>,
    cursor: StagedInventoryCursor,
    id: Hash,
    kind: InspectedKind,
    canonical_len: u64,
}

impl StagedInventoryStep {
    #[must_use]
    pub fn cursor(&self) -> StagedInventoryCursor {
        self.cursor
    }
    #[must_use]
    pub fn id(&self) -> Hash {
        self.id
    }
    #[must_use]
    pub fn kind(&self) -> InspectedKind {
        self.kind
    }
    #[must_use]
    pub fn canonical_len(&self) -> u64 {
        self.canonical_len
    }
}

/// Advance one strict ordinal/ID inventory step without retaining a map.
///
/// # Errors
/// Refuses inconsistent cursor/ordering or prospective inventory bounds.
pub fn advance_staged_inventory(
    previous: &StagedInventoryCursor,
    frame_ordinal: u64,
    fact: &StagedInventoryFact,
    context: &StagedValidationContext,
) -> Result<StagedInventoryStep, StagedUpdateError> {
    if previous.next_ordinal != previous.count
        || frame_ordinal != previous.next_ordinal
        || fact.portable != *context.portable()
        || fact.inspection != context.inspection()
        || previous
            .previous_id
            .is_some_and(|id| id >= fact.object.id())
        || previous.count == 0 && previous.previous_id.is_some()
        || previous.count != 0 && previous.previous_id.is_none()
    {
        return Err(StagedUpdateError::Inconsistent);
    }
    let count = previous
        .count
        .checked_add(1)
        .ok_or(StagedUpdateError::Budget)?;
    let canonical_len =
        u64::try_from(fact.object.canonical_len()).map_err(|_| StagedUpdateError::Budget)?;
    let canonical_bytes = previous
        .canonical_bytes
        .checked_add(canonical_len)
        .ok_or(StagedUpdateError::Budget)?;
    let work = count.checked_mul(2).ok_or(StagedUpdateError::Budget)?;
    if count
        > context
            .staged()
            .max_inventory_entries
            .min(context.portable().max_update_objects as u64)
        || canonical_bytes > context.staged().max_inventory_payload_bytes
        || work > context.staged().max_inventory_work
    {
        return Err(StagedUpdateError::Budget);
    }
    Ok(StagedInventoryStep {
        binding: context.binding(),
        cursor: StagedInventoryCursor {
            next_ordinal: count,
            previous_id: Some(fact.object.id()),
            count,
            canonical_bytes,
        },
        id: fact.object.id(),
        kind: fact.object.kind(),
        canonical_len,
    })
}

/// Atomically charge one inventory observation against a prior complete
/// carrier usage. The external driver still owns exact frame iteration.
///
/// # Errors
/// Refuses inconsistent prior count/byte state or prospective active caps.
pub fn apply_inventory_accounting(
    previous: StagedUpdateUsageV1,
    step: &StagedInventoryStep,
    context: &StagedValidationContext,
) -> Result<StagedUpdateUsageV1, StagedUpdateError> {
    if !context.binds(&step.binding) {
        return Err(StagedUpdateError::Inconsistent);
    }
    super::staged_diff::check_usage(&previous, context)?;
    if previous.inventory_entries > context.staged().max_inventory_entries
        || previous.inventory_payload_bytes > context.staged().max_inventory_payload_bytes
        || previous.inventory_work > context.staged().max_inventory_work
        || previous.inventory_work
            != previous
                .inventory_entries
                .checked_mul(2)
                .ok_or(StagedUpdateError::Budget)?
    {
        return Err(StagedUpdateError::Budget);
    }
    let count = previous
        .inventory_entries
        .checked_add(1)
        .ok_or(StagedUpdateError::Budget)?;
    let bytes = previous
        .inventory_payload_bytes
        .checked_add(step.canonical_len)
        .ok_or(StagedUpdateError::Budget)?;
    let work = count.checked_mul(2).ok_or(StagedUpdateError::Budget)?;
    if step.cursor.count != count
        || step.cursor.canonical_bytes != bytes
        || step.cursor.next_ordinal != count
    {
        return Err(StagedUpdateError::Inconsistent);
    }
    if count
        > context
            .staged()
            .max_inventory_entries
            .min(context.portable().max_update_objects as u64)
        || bytes > context.staged().max_inventory_payload_bytes
        || work > context.staged().max_inventory_work
    {
        return Err(StagedUpdateError::Budget);
    }
    let next = StagedUpdateUsageV1 {
        inventory_entries: count,
        inventory_payload_bytes: bytes,
        inventory_work: work,
        ..previous
    };
    super::staged_diff::check_usage(&next, context)?;
    Ok(next)
}

/// Strictly checked candidate Commit fact for the header's base/candidate.
#[derive(Debug)]
pub struct StagedCandidateFact {
    object: InspectedObject,
    base_id: Hash,
    portable: PartialLimits,
    inspection: ObjectInspectionLimits,
}

impl StagedCandidateFact {
    #[must_use]
    pub fn object(&self) -> &InspectedObject {
        &self.object
    }
    #[must_use]
    pub fn id(&self) -> Hash {
        self.object.id()
    }
    #[must_use]
    pub fn base_id(&self) -> Hash {
        self.base_id
    }
    pub(super) fn matches_context(&self, context: &StagedValidationContext) -> bool {
        self.portable == *context.portable() && self.inspection == context.inspection()
    }
}

/// Inspect the supplied candidate and its MKWU-specific strict fields.
///
/// # Errors
/// Refuses wrong candidate ID, parent/base, annotation, message cap,
/// canonical bytes, signature or role.
pub fn inspect_staged_candidate(
    bytes: &[u8],
    context: &StagedValidationContext,
) -> Result<StagedCandidateFact, StagedUpdateError> {
    preflight_candidate(bytes, context.portable())?;
    let object = inspect_snapshot_object(
        context.header().candidate_id,
        bytes,
        SnapshotRole::CandidateRoot,
        context.inspection(),
    )?;
    let Object::Commit(commit) = deserialize(bytes).map_err(|_| StagedUpdateError::Invalid)? else {
        return Err(StagedUpdateError::Invalid);
    };
    if commit.parents.as_slice() != [context.header().base_id]
        || commit.message_hash != [0; 32]
        || commit.content_digest != [0; 32]
        || commit.message.len() > context.portable().max_commit_message_bytes
    {
        return Err(StagedUpdateError::Invalid);
    }
    Ok(StagedCandidateFact {
        object,
        base_id: context.header().base_id,
        portable: *context.portable(),
        inspection: context.inspection(),
    })
}

/// Default per-object staged inspection profile; a host may lower it.
#[must_use]
pub fn default_staged_inspection_limits() -> ObjectInspectionLimits {
    ObjectInspectionLimits {
        max_object_bytes: 16 * 1024 * 1024,
        max_tree_bytes: 16 * 1024 * 1024,
        max_tree_entries: 100_000,
        max_manifest_chunks: 100_000,
    }
}
