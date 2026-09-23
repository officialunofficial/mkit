//! Pure full-data recipient validation of an explicit partial update.

use std::collections::BTreeMap;

use crate::hash::Hash;
use crate::object::{EntryMode, id_from_object};
use crate::ops::graph::ClosureMode;
use crate::pack::{PackEntries, PackEntry};
use crate::serialize::deserialize;
use crate::verify::{ClosureReport, ObjectSource, VerifyError, verify_closure_streaming};

use super::recipient_diff::verify_diff;
use super::recipient_graph::{CachedSource, RecipientGraph};
use super::update::RecipientIntakeLimits;
use super::{PartialError, PartialLimits, PartialPath, PartialUpdate};

/// Independent full-snapshot limits. These never cap untouched files at the
/// selected-file limits of the portable MKWU profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientLimits {
    pub max_objects: usize,
    pub max_canonical_bytes: usize,
    pub max_object_bytes: usize,
    /// Root Tree has depth zero; each Tree-to-Tree edge adds one.
    pub max_tree_depth: usize,
    /// Shared across upload intake, base, result, actual diff, and closure.
    /// The intake pass reserves two units per raw inventory entry; repeated
    /// path and chunk occurrences in graph walks count again.
    pub max_occurrences: usize,
}

impl RecipientLimits {
    pub const DEFAULT: Self = Self {
        max_objects: 100_000,
        max_canonical_bytes: 256 * 1024 * 1024,
        max_object_bytes: 16 * 1024 * 1024,
        max_tree_depth: 128,
        max_occurrences: 1_000_000,
    };
}

impl Default for RecipientLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Resource use across upload intake, complete base, candidate, diff and closure.
/// Work units are traversal accounting, not an exact CPU or memory measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientUsage {
    pub objects: usize,
    pub canonical_bytes: usize,
    pub max_tree_depth: usize,
    pub occurrences: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum RecipientError {
    #[error("portable partial update is invalid: {0}")]
    Portable(#[from] PartialError),
    #[error("expected base differs from the update base")]
    BaseMismatch,
    #[error("recipient validation budget exceeded")]
    BudgetExceeded,
    #[error("snapshot object {0:?} is missing")]
    Missing(Hash),
    #[error("snapshot object {0:?} has corrupt or noncanonical bytes")]
    Corrupt(Hash),
    #[error("snapshot edge to {0:?} has the wrong object type")]
    WrongObjectType(Hash),
    #[error("snapshot root {0:?} has an invalid signature")]
    InvalidSignature(Hash),
    #[error("actual replacement-only diff does not match the manifest")]
    InvalidChange,
    #[error("chunked file occurrence has invalid length or layout")]
    InvalidChunkLayout,
    #[error("resulting snapshot closure is incomplete")]
    IncompleteClosure(ClosureReport),
    #[error("source failed: {0}")]
    Source(VerifyError),
}

/// Factual, path-specific replacement established against the complete base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReplacement {
    pub path: PartialPath,
    pub mode: EntryMode,
    pub old_id: Hash,
    pub new_id: Hash,
}

/// Private construction: only complete snapshot validation yields this value.
/// Its signer is cryptographically valid, but signer identity and publication
/// authority require an independent caller policy.
#[derive(Debug)]
pub struct VerifiedPartialUpdate {
    update: PartialUpdate,
    replacements: Vec<VerifiedReplacement>,
    closure: ClosureReport,
    usage: RecipientUsage,
}

impl VerifiedPartialUpdate {
    #[must_use]
    pub fn update(&self) -> &PartialUpdate {
        &self.update
    }
    #[must_use]
    pub fn base_id(&self) -> &Hash {
        self.update.base_id()
    }
    #[must_use]
    pub fn candidate_id(&self) -> &Hash {
        self.update.candidate_id()
    }
    #[must_use]
    pub fn replacements(&self) -> &[VerifiedReplacement] {
        &self.replacements
    }
    /// This is Snapshot completeness only. Parent History may be absent.
    #[must_use]
    pub fn snapshot_closure(&self) -> &ClosureReport {
        &self.closure
    }

    #[must_use]
    pub fn usage(&self) -> RecipientUsage {
        self.usage
    }
}

/// Validate an MKWU against an independently supplied complete base source.
/// No ref or transport effects. The source's own initial fetch allocation is
/// outside these limits; returned bytes are bounded before retention/decode.
pub fn verify_partial_update<S: ObjectSource + ?Sized>(
    expected_base: Hash,
    update_bytes: &[u8],
    source: &mut S,
    portable: &PartialLimits,
    recipient: &RecipientLimits,
) -> Result<VerifiedPartialUpdate, RecipientError> {
    let (update, intake_work) = PartialUpdate::decode_for_recipient(
        update_bytes,
        portable,
        RecipientIntakeLimits {
            objects: recipient.max_objects,
            canonical_bytes: recipient.max_canonical_bytes,
            object_bytes: recipient.max_object_bytes,
            work: recipient.max_occurrences,
        },
    )
    .map_err(|error| match error {
        PartialError::RecipientBudgetExceeded => RecipientError::BudgetExceeded,
        other => RecipientError::Portable(other),
    })?;
    if *update.base_id() != expected_base {
        return Err(RecipientError::BaseMismatch);
    }
    let mut graph = RecipientGraph::new(source, *recipient);
    graph.charge(intake_work)?;
    // Complete, source-only base traversal precedes access to the upload.
    graph.validate_base(expected_base)?;
    let uploaded = inventory(&update, recipient)?;
    graph.validate_candidate(*update.candidate_id(), &uploaded)?;
    verify_diff(
        &mut graph,
        expected_base,
        *update.candidate_id(),
        &update.changes,
    )?;
    graph.closure_work(*update.candidate_id())?;
    let closure = verify_closure_streaming(
        update.candidate_id(),
        ClosureMode::Snapshot,
        &mut CachedSource(&graph),
    )
    .map_err(RecipientError::Source)?;
    if !closure.is_complete() {
        return Err(RecipientError::IncompleteClosure(closure));
    }
    let usage = graph.usage();
    let replacements = update
        .changes
        .iter()
        .map(|change| VerifiedReplacement {
            path: change.path.clone(),
            mode: change.old_mode,
            old_id: change.old_id,
            new_id: change.new_id,
        })
        .collect();
    Ok(VerifiedPartialUpdate {
        update,
        replacements,
        closure,
        usage,
    })
}

fn inventory<'a>(
    update: &'a PartialUpdate,
    recipient: &RecipientLimits,
) -> Result<BTreeMap<Hash, &'a [u8]>, RecipientError> {
    // The MKWU decoder has already checked canonical sorted raw inventory.
    // This pass indexes it; it does not parse the MKWU wire format again.
    let mut objects = BTreeMap::new();
    let mut total_bytes = 0usize;
    let entries = PackEntries::new(update.pack_bytes())
        .map_err(|_| RecipientError::Portable(PartialError::InvalidUpdatePack))?;
    for entry in entries {
        let PackEntry::Raw { bytes } =
            entry.map_err(|_| RecipientError::Portable(PartialError::InvalidUpdatePack))?
        else {
            return Err(RecipientError::Portable(PartialError::InvalidUpdatePack));
        };
        let std::borrow::Cow::Borrowed(raw) = bytes else {
            return Err(RecipientError::Portable(PartialError::InvalidUpdatePack));
        };
        total_bytes = total_bytes
            .checked_add(raw.len())
            .ok_or(RecipientError::BudgetExceeded)?;
        if raw.len() > recipient.max_object_bytes
            || total_bytes > recipient.max_canonical_bytes
            || objects.len() >= recipient.max_objects
        {
            return Err(RecipientError::BudgetExceeded);
        }
        let object = deserialize(raw)
            .map_err(|_| RecipientError::Portable(PartialError::InvalidUpdatePack))?;
        objects.insert(id_from_object(&object, raw), raw);
    }
    Ok(objects)
}
