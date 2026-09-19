//! Durable scoped-workspace state records and transition logic.
//!
//! The wire types here (`WorkspaceStateV1`, `StageStateV1`, `PendingStateV1`,
//! `AcceptedStateV1`) are the payloads of the bounded envelopes defined in
//! `SPEC-PARTIAL-WORKSPACES` §"Local workspace state"; their byte-level
//! encode/decode lives in `local_codec.rs`. Durable state is a local
//! integrity record only — checksums detect corruption and torn writes, they
//! are not signatures, and nothing here confers permission, ownership,
//! publication authority, or signer trust.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::hash::{Hash, to_hex};
use crate::object::{Commit, EntryMode, Object, id_from_object, object_id_from_bytes};
use crate::store::{ObjectSource, StoreError, StoreResult};
use crate::worktree::read_blob;

use super::layout::{
    ACCEPTED_FILE, BUNDLES_DIR, CURRENT_FILE, Fault, GENERATIONS_DIR, MANIFEST_FILE, OBJECTS_DIR,
    PENDING_FILE, STAGE_FILE, STATE_DIR, ScopedWorkspaceLayout, UPDATES_DIR, WORKSPACE_FILE,
    bundle_file_name, update_file_name,
};
use super::local_codec::{
    CurrentPointerV1, GenerationManifestV1, MAX_ENVELOPE_BYTES, envelope_digest,
};
use super::sys::{self, DirFd, OpenMode, SysError};
use super::{
    FileReplacement, PartialError, PartialLimits, PartialPath, PartialUpdate,
    VerifiedPartialSnapshot, build_partial_snapshot, export_partial_update, replace_files,
    verify_partial_snapshot,
};

/// Errors from scoped-workspace durable state: codecs, filesystem safety,
/// bindings, and transactions.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PartialStateError {
    /// The envelope declares a version this implementation does not know.
    #[error("scoped-state envelope version {0} is unsupported")]
    UnsupportedVersion(u8),
    /// The payload is malformed, non-minimal, carries an unknown tag, or
    /// has trailing bytes.
    #[error("scoped-state encoding is not canonical: {0}")]
    NonCanonical(&'static str),
    /// The envelope checksum does not match its bytes.
    #[error("scoped-state envelope checksum mismatch")]
    ChecksumMismatch,
    /// A complete envelope exceeds the 1 MiB bound.
    #[error("scoped-state envelope exceeds the 1 MiB bound")]
    EnvelopeTooLarge,
    /// Persisted limits are not a subset of the v1 profile.
    #[error("persisted scoped-workspace limits exceed the v1 profile")]
    LimitsUnsupported,
    /// `open` was asked for a root that has no exact scoped marker.
    #[error("not a scoped workspace root: {}", .0.display())]
    NotScopedWorkspace(PathBuf),
    /// The `.mkit` marker begins like a scoped marker but is not exact.
    #[error("scoped workspace marker is malformed: {}", .0.display())]
    MarkerCorrupt(PathBuf),
    /// Recognizable scoped metadata exists without the exact root marker,
    /// or the install is torn.
    #[error("scoped workspace install is incomplete: {}", .0.display())]
    IncompleteInstall(PathBuf),
    /// Scoped authority overlaps or nests inside ordinary repository state.
    #[error("scoped workspace conflicts with repository layout: {}", .0.display())]
    LayoutConflict(PathBuf),
    /// The create destination already exists (including a lost rename race).
    #[error("scoped workspace destination already exists: {}", .0.display())]
    DestinationExists(PathBuf),
    /// The destination nests inside an existing repository or scoped
    /// workspace.
    #[error(
        "scoped workspace destination nests inside existing repository state: {}",
        .0.display()
    )]
    NestedLayout(PathBuf),
    /// A symlink, non-regular file, multi-linked file, or aliasing path
    /// occupies a position that must be a plain file or directory.
    #[error("unsafe filesystem entry {}: {reason}", .path.display())]
    UnsafeFilesystemEntry { path: PathBuf, reason: String },
    /// A referenced durable artifact (bundle/object/update/member) is absent.
    #[error("required scoped-state artifact {} is missing: {reason}", .path.display())]
    MissingArtifact { path: PathBuf, reason: String },
    /// A referenced durable artifact fails checksum, digest, or decode.
    #[error("scoped-state artifact {} is corrupt: {reason}", .path.display())]
    CorruptArtifact { path: PathBuf, reason: String },
    /// A redundant cross-record binding (workspace id, base id/revision,
    /// candidate, generation) does not match.
    #[error("scoped-state binding mismatch: {0}")]
    BindingMismatch(&'static str),
    /// The caller's expected transaction generation is stale.
    #[error("workspace generation mismatch: expected {expected}, current {actual}")]
    GenerationMismatch { expected: u64, actual: u64 },
    /// The next transaction generation cannot be represented.
    #[error("workspace transaction generation overflow")]
    GenerationOverflow,
    /// A pending operation exists (or a conflicting substitution was tried).
    #[error("a different pending operation is already recorded")]
    PendingConflict,
    /// An outcome was recorded while no pending operation exists.
    #[error("no pending operation is recorded")]
    PendingMissing,
    /// The supplied pending identity does not match the recorded operation.
    #[error("pending identity does not match the recorded operation")]
    PendingMismatch,
    /// The supplied commit/update does not reproduce the staged edit.
    #[error("candidate or update does not exactly match the staged edit")]
    CandidateMismatch,
    /// The new generation was published but its durability is unconfirmed.
    #[error("new state may be durable but the final sync failed: {0}")]
    DurabilityUncertain(#[source] io::Error),
    /// A required primitive is unavailable on this platform.
    #[error("scoped workspace operation is unsupported here: {0}")]
    UnsupportedPlatform(&'static str),
    /// The workspace lock file could not be acquired or was unsafe.
    #[error("workspace lock {} failed: {source}", .path.display())]
    LockFailed { path: PathBuf, source: io::Error },
    /// The process CSPRNG failed.
    #[error("random number generation failed")]
    RngFailure,
    /// An underlying partial-snapshot error.
    #[error(transparent)]
    Partial(#[from] PartialError),
    /// An underlying store error.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// An underlying I/O error.
    #[error("scoped workspace I/O on {}: {source}", .path.display())]
    Io { path: PathBuf, source: io::Error },
}

impl From<io::Error> for PartialStateError {
    fn from(source: io::Error) -> Self {
        Self::Io {
            path: PathBuf::new(),
            source,
        }
    }
}

/// A descriptive, non-authoritative remote publication target.
///
/// Recorded verbatim in `WorkspaceStateV1`; carrying it grants nothing and
/// authenticates nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePublicationTargetV1 {
    pub(crate) endpoint: String,
    pub(crate) repository: String,
    pub(crate) exact_ref: String,
}

impl RemotePublicationTargetV1 {
    /// Byte cap for `endpoint`.
    pub const MAX_ENDPOINT_BYTES: usize = 2048;
    /// Byte cap for `repository`.
    pub const MAX_REPOSITORY_BYTES: usize = 255;
    /// Byte cap for `exact_ref`.
    pub const MAX_REF_BYTES: usize = 1024;

    /// Validate a descriptive target: nonempty UTF-8 fields within byte caps,
    /// no Unicode control characters, and `exact_ref` must start with
    /// `refs/` and satisfy [`crate::refs::validate_ref_name`].
    pub fn new(
        endpoint: &str,
        repository: &str,
        exact_ref: &str,
    ) -> Result<Self, PartialStateError> {
        check_target_field(endpoint, Self::MAX_ENDPOINT_BYTES, "endpoint")?;
        check_target_field(repository, Self::MAX_REPOSITORY_BYTES, "repository")?;
        check_target_field(exact_ref, Self::MAX_REF_BYTES, "exact_ref")?;
        if !exact_ref.starts_with("refs/") || !crate::refs::validate_ref_name(exact_ref) {
            return Err(PartialStateError::NonCanonical("exact_ref"));
        }
        Ok(Self {
            endpoint: endpoint.to_string(),
            repository: repository.to_string(),
            exact_ref: exact_ref.to_string(),
        })
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    #[must_use]
    pub fn exact_ref(&self) -> &str {
        &self.exact_ref
    }
}

fn check_target_field(
    value: &str,
    max: usize,
    field: &'static str,
) -> Result<(), PartialStateError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(PartialStateError::NonCanonical(field));
    }
    Ok(())
}

/// One selected file's verified base binding in `MKWS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSelectionV1 {
    pub(crate) path: PartialPath,
    pub(crate) mode: EntryMode,
    pub(crate) base_file_id: Hash,
}

impl WorkspaceSelectionV1 {
    #[must_use]
    pub fn path(&self) -> &PartialPath {
        &self.path
    }

    #[must_use]
    pub fn mode(&self) -> EntryMode {
        self.mode
    }

    #[must_use]
    pub fn base_file_id(&self) -> &Hash {
        &self.base_file_id
    }
}

/// The `MKWS` workspace record: identity, counters, pinned base, selection,
/// limits, and optional descriptive target.
#[derive(Debug, Clone)]
pub struct WorkspaceStateV1 {
    pub(crate) workspace_id: Hash,
    pub(crate) transaction_generation: u64,
    pub(crate) base_revision: u64,
    pub(crate) base_id: Hash,
    pub(crate) base_bundle_digest: Hash,
    pub(crate) selection: Vec<WorkspaceSelectionV1>,
    pub(crate) limits: PartialLimits,
    pub(crate) target: Option<RemotePublicationTargetV1>,
}

impl WorkspaceStateV1 {
    #[must_use]
    pub fn workspace_id(&self) -> &Hash {
        &self.workspace_id
    }

    #[must_use]
    pub fn transaction_generation(&self) -> u64 {
        self.transaction_generation
    }

    #[must_use]
    pub fn base_revision(&self) -> u64 {
        self.base_revision
    }

    #[must_use]
    pub fn base_id(&self) -> &Hash {
        &self.base_id
    }

    /// Flat BLAKE3 of the exact `MKWB` bundle bytes under
    /// `.mkit-scoped/bundles/<hex>.mkwb`.
    #[must_use]
    pub fn base_bundle_digest(&self) -> &Hash {
        &self.base_bundle_digest
    }

    #[must_use]
    pub fn selection(&self) -> &[WorkspaceSelectionV1] {
        &self.selection
    }

    #[must_use]
    pub fn limits(&self) -> &PartialLimits {
        &self.limits
    }

    #[must_use]
    pub fn target(&self) -> Option<&RemotePublicationTargetV1> {
        self.target.as_ref()
    }
}

/// One staged file binding in `MKST`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageEntryV1 {
    pub(crate) path: PartialPath,
    pub(crate) mode: EntryMode,
    pub(crate) staged_id: Hash,
}

impl StageEntryV1 {
    #[must_use]
    pub fn path(&self) -> &PartialPath {
        &self.path
    }

    #[must_use]
    pub fn mode(&self) -> EntryMode {
        self.mode
    }

    #[must_use]
    pub fn staged_id(&self) -> &Hash {
        &self.staged_id
    }
}

/// The `MKST` stage record: the authoritative staged representation per
/// selected path plus every local object the stage requires.
#[derive(Debug, Clone)]
pub struct StageStateV1 {
    pub(crate) workspace_id: Hash,
    pub(crate) base_id: Hash,
    pub(crate) base_revision: u64,
    pub(crate) entries: Vec<StageEntryV1>,
    pub(crate) required_object_ids: Vec<Hash>,
}

impl StageStateV1 {
    #[must_use]
    pub fn workspace_id(&self) -> &Hash {
        &self.workspace_id
    }

    #[must_use]
    pub fn base_id(&self) -> &Hash {
        &self.base_id
    }

    #[must_use]
    pub fn base_revision(&self) -> u64 {
        self.base_revision
    }

    #[must_use]
    pub fn entries(&self) -> &[StageEntryV1] {
        &self.entries
    }

    /// Sorted object ids that must exist under `.mkit-scoped/objects/`.
    #[must_use]
    pub fn required_object_ids(&self) -> &[Hash] {
        &self.required_object_ids
    }
}

/// Pending-operation status persisted in `MKPN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingStatusV1 {
    /// Candidate built and update stored; not yet exported to a transport.
    Prepared,
    /// Update handed to a transport; never implies acceptance.
    Exported,
    /// The remote reported a conflict for this candidate.
    Conflict,
    /// The outcome is unknown (e.g. the export path was lost).
    Unknown,
}

/// Optional transport-side correlation pair; the two fields are always
/// recorded or absent together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingOperationV1 {
    /// Caller-assigned operation identifier.
    pub operation_id: [u8; 32],
    /// BLAKE3 fingerprint of the exact request bytes sent.
    pub request_fingerprint: [u8; 32],
}

/// The `MKPN` record: at most one active pending candidate per workspace.
#[derive(Debug, Clone)]
pub struct PendingStateV1 {
    pub(crate) workspace_id: Hash,
    pub(crate) base_id: Hash,
    pub(crate) base_revision: u64,
    pub(crate) created_generation: u64,
    pub(crate) candidate_id: Hash,
    pub(crate) update_digest: Hash,
    pub(crate) update_length: u64,
    pub(crate) status: PendingStatusV1,
    pub(crate) operation: Option<PendingOperationV1>,
}

impl PendingStateV1 {
    #[must_use]
    pub fn workspace_id(&self) -> &Hash {
        &self.workspace_id
    }

    #[must_use]
    pub fn base_id(&self) -> &Hash {
        &self.base_id
    }

    #[must_use]
    pub fn base_revision(&self) -> u64 {
        self.base_revision
    }

    #[must_use]
    pub fn created_generation(&self) -> u64 {
        self.created_generation
    }

    #[must_use]
    pub fn candidate_id(&self) -> &Hash {
        &self.candidate_id
    }

    #[must_use]
    pub fn update_digest(&self) -> &Hash {
        &self.update_digest
    }

    #[must_use]
    pub fn update_length(&self) -> u64 {
        self.update_length
    }

    #[must_use]
    pub fn status(&self) -> PendingStatusV1 {
        self.status
    }

    #[must_use]
    pub fn operation(&self) -> Option<PendingOperationV1> {
        self.operation
    }

    /// File name of the exact pending update artifact:
    /// `.mkit-scoped/updates/<lowercase update_digest hex>.mkwu`.
    #[must_use]
    pub fn update_file_name(&self) -> String {
        format!("{}.mkwu", to_hex(&self.update_digest))
    }

    /// The identity a caller uses to report this operation's outcome.
    #[must_use]
    pub fn identity(&self) -> PendingIdentityV1 {
        PendingIdentityV1 {
            workspace_id: self.workspace_id,
            base_revision: self.base_revision,
            candidate_id: self.candidate_id,
            update_digest: self.update_digest,
            operation: self.operation,
        }
    }
}

/// The `MKAC` record: context of the last accepted-candidate advancement.
#[derive(Debug, Clone)]
pub struct AcceptedStateV1 {
    pub(crate) workspace_id: Hash,
    pub(crate) prior_base_id: Hash,
    pub(crate) accepted_base_revision: u64,
    pub(crate) candidate_id: Hash,
    pub(crate) update_digest: Hash,
    pub(crate) operation: Option<PendingOperationV1>,
}

impl AcceptedStateV1 {
    #[must_use]
    pub fn workspace_id(&self) -> &Hash {
        &self.workspace_id
    }

    #[must_use]
    pub fn prior_base_id(&self) -> &Hash {
        &self.prior_base_id
    }

    #[must_use]
    pub fn accepted_base_revision(&self) -> u64 {
        self.accepted_base_revision
    }

    #[must_use]
    pub fn candidate_id(&self) -> &Hash {
        &self.candidate_id
    }

    #[must_use]
    pub fn update_digest(&self) -> &Hash {
        &self.update_digest
    }

    #[must_use]
    pub fn operation(&self) -> Option<PendingOperationV1> {
        self.operation
    }
}

/// Caller-supplied identity for [`ScopedWorkspaceLayout::record_outcome`],
/// obtained from [`PendingStateV1::identity`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingIdentityV1 {
    pub(crate) workspace_id: Hash,
    pub(crate) base_revision: u64,
    pub(crate) candidate_id: Hash,
    pub(crate) update_digest: Hash,
    pub(crate) operation: Option<PendingOperationV1>,
}

impl PendingIdentityV1 {
    #[must_use]
    pub fn workspace_id(&self) -> &Hash {
        &self.workspace_id
    }

    #[must_use]
    pub fn base_revision(&self) -> u64 {
        self.base_revision
    }

    #[must_use]
    pub fn candidate_id(&self) -> &Hash {
        &self.candidate_id
    }

    #[must_use]
    pub fn update_digest(&self) -> &Hash {
        &self.update_digest
    }

    #[must_use]
    pub fn operation(&self) -> Option<PendingOperationV1> {
        self.operation
    }
}

/// The outcome a caller asserts for the recorded pending operation.
///
/// `Accepted` is a local assertion only: no network result, receipt, or
/// authority is verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingOutcomeV1 {
    /// The candidate was prepared locally.
    Prepared,
    /// The update was exported to a transport.
    Exported,
    /// The remote reported a conflict.
    Conflict,
    /// The outcome is unknown.
    Unknown,
    /// The candidate was accepted; advances the workspace base.
    Accepted,
}

/// One coherent, `CURRENT`-selected view of a scoped workspace.
#[derive(Debug)]
pub struct ScopedWorkspaceState {
    pub(crate) workspace: WorkspaceStateV1,
    pub(crate) stage: StageStateV1,
    pub(crate) pending: Option<PendingStateV1>,
    pub(crate) accepted: Option<AcceptedStateV1>,
    pub(crate) verified: VerifiedPartialSnapshot,
    /// Verified canonical bytes for every `stage.required_object_ids` entry.
    pub(crate) local_objects: BTreeMap<Hash, Vec<u8>>,
    /// Exact bytes of the recorded pending update, when one exists.
    pub(crate) pending_update_bytes: Option<Vec<u8>>,
}

impl ScopedWorkspaceState {
    #[must_use]
    pub fn workspace(&self) -> &WorkspaceStateV1 {
        &self.workspace
    }

    #[must_use]
    pub fn stage(&self) -> &StageStateV1 {
        &self.stage
    }

    #[must_use]
    pub fn pending(&self) -> Option<&PendingStateV1> {
        self.pending.as_ref()
    }

    #[must_use]
    pub fn accepted(&self) -> Option<&AcceptedStateV1> {
        self.accepted.as_ref()
    }

    /// The verified base snapshot the stage and pending candidate build on.
    #[must_use]
    pub fn verified(&self) -> &VerifiedPartialSnapshot {
        &self.verified
    }

    /// Canonical serialized bytes of a stage-required local object, if the
    /// stage recorded it in `required_object_ids`.
    #[must_use]
    pub fn local_object(&self, id: &Hash) -> Option<&[u8]> {
        self.local_objects.get(id).map(Vec::as_slice)
    }

    /// True when every staged id equals its base id — nothing to export.
    #[must_use]
    pub fn stage_is_clean(&self) -> bool {
        stage_is_clean(&self.workspace, &self.stage)
    }
}

fn stage_is_clean(workspace: &WorkspaceStateV1, stage: &StageStateV1) -> bool {
    stage.required_object_ids.is_empty()
        && stage
            .entries
            .iter()
            .zip(&workspace.selection)
            .all(|(entry, selection)| {
                entry.path == selection.path && entry.staged_id == selection.base_file_id
            })
}

/// Object source over the verified base snapshot plus the stage's persisted
/// local objects. Reads are id-checked by callers (`read_blob` verifies the
/// manifest/chunk structure; ids are verified on load).
struct StageSource<'a> {
    verified: &'a VerifiedPartialSnapshot,
    local: &'a BTreeMap<Hash, Vec<u8>>,
}

impl ObjectSource for StageSource<'_> {
    fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
        if let Some(bytes) = self.local.get(id) {
            return Ok(bytes.clone());
        }
        self.verified
            .object_bytes(id)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| StoreError::ObjectNotFound(to_hex(id)))
    }
}

/// Union of the verified base snapshot with every raw object carried by the
/// pending update pack — the complete, fetch-free source for rebuilding the
/// accepted candidate's selected snapshot.
struct UnionSource<'a> {
    base: BTreeMap<Hash, &'a [u8]>,
}

impl UnionSource<'_> {
    fn read_vec(&self, id: &Hash) -> StoreResult<Vec<u8>> {
        self.base
            .get(id)
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| StoreError::ObjectNotFound(to_hex(id)))
    }
}

impl ObjectSource for UnionSource<'_> {
    fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
        self.read_vec(id)
    }
}

fn map_worktree(error: crate::worktree::WorktreeError) -> PartialStateError {
    match error {
        crate::worktree::WorktreeError::Store(error) => PartialStateError::Store(error),
        _ => PartialStateError::Partial(PartialError::InvalidChunkLayout),
    }
}

fn selection_map(state: &ScopedWorkspaceState) -> BTreeMap<&PartialPath, &WorkspaceSelectionV1> {
    state
        .workspace
        .selection
        .iter()
        .map(|entry| (&entry.path, entry))
        .collect()
}

fn staged_bytes(
    state: &ScopedWorkspaceState,
    staged_id: &Hash,
) -> Result<Vec<u8>, PartialStateError> {
    let source = StageSource {
        verified: &state.verified,
        local: &state.local_objects,
    };
    read_blob(&source, staged_id).map_err(map_worktree)
}

/// Verify every stage entry's persisted representation against the
/// authenticated sources — never working files. Entries equal to their
/// base id reuse the verified selected file's already checked
/// `content_len`; differing entries must resolve through the verified
/// base objects or the stage's required local objects to a canonical
/// `Blob`/`ChunkedBlob`, whose declared length is bounded by the
/// persisted limits BEFORE materialization and whose full content
/// `read_blob` then re-verifies chunk-by-chunk. A stage id outside the
/// authenticated sources, a non-file object, a bad chunk layout, or an
/// over-limit file/aggregate fails the load.
fn validate_stage_representations(
    workspace: &WorkspaceStateV1,
    stage: &StageStateV1,
    verified: &VerifiedPartialSnapshot,
    local_objects: &BTreeMap<Hash, Vec<u8>>,
) -> Result<(), PartialStateError> {
    let source = StageSource {
        verified,
        local: local_objects,
    };
    let max_file = u64::try_from(workspace.limits.max_selected_file_bytes)
        .map_err(|_| PartialStateError::NonCanonical("limits"))?;
    let max_total = u64::try_from(workspace.limits.max_total_selected_bytes)
        .map_err(|_| PartialStateError::NonCanonical("limits"))?;
    let mut total = 0u64;
    for ((entry, selection), file) in stage
        .entries
        .iter()
        .zip(&workspace.selection)
        .zip(verified.files())
    {
        let declared = if entry.staged_id == selection.base_file_id {
            file.content_len()
        } else {
            let path = PathBuf::from(STATE_DIR)
                .join(OBJECTS_DIR)
                .join(to_hex(&entry.staged_id));
            let raw = source.read(&entry.staged_id).map_err(|error| match error {
                StoreError::ObjectNotFound(_) => missing(path.clone(), "staged object"),
                other => PartialStateError::Store(other),
            })?;
            let object =
                crate::deserialize(&raw).map_err(|_| PartialStateError::CorruptArtifact {
                    path: path.clone(),
                    reason: "staged object does not decode".to_owned(),
                })?;
            let declared = match &object {
                Object::Blob(blob) => u64::try_from(blob.data.len())
                    .map_err(|_| PartialStateError::Partial(PartialError::WorkspaceTooLarge))?,
                Object::ChunkedBlob(manifest) => manifest.total_size,
                _ => {
                    return Err(PartialStateError::BindingMismatch(
                        "staged object is not file content",
                    ));
                }
            };
            if declared > max_file {
                return Err(PartialStateError::Partial(PartialError::WorkspaceTooLarge));
            }
            let content = read_blob(&source, &entry.staged_id).map_err(map_worktree)?;
            let content_len = u64::try_from(content.len())
                .map_err(|_| PartialStateError::NonCanonical("staged length"))?;
            if content_len != declared {
                return Err(PartialStateError::CorruptArtifact {
                    path,
                    reason: "staged content length disagrees with its declaration".to_owned(),
                });
            }
            declared
        };
        total = total
            .checked_add(declared)
            .ok_or(PartialStateError::Partial(PartialError::WorkspaceTooLarge))?;
        if total > max_total {
            return Err(PartialStateError::Partial(PartialError::WorkspaceTooLarge));
        }
    }
    Ok(())
}

/// Rebuild the overlay that produced the current stage: one bytes
/// replacement per staged entry that differs from base.
fn stage_replacements(
    state: &ScopedWorkspaceState,
) -> Result<Vec<FileReplacement>, PartialStateError> {
    let selection = selection_map(state);
    let mut replacements = Vec::new();
    for entry in &state.stage.entries {
        let base = selection
            .get(&entry.path)
            .ok_or(PartialStateError::BindingMismatch(
                "stage path outside selection",
            ))?;
        if entry.staged_id == base.base_file_id {
            continue;
        }
        let bytes = staged_bytes(state, &entry.staged_id)?;
        replacements.push(FileReplacement::bytes(entry.path.clone(), bytes));
    }
    Ok(replacements)
}

fn clean_stage(state: &ScopedWorkspaceState) -> StageStateV1 {
    StageStateV1 {
        workspace_id: state.workspace.workspace_id,
        base_id: state.workspace.base_id,
        base_revision: state.workspace.base_revision,
        entries: state
            .workspace
            .selection
            .iter()
            .map(|selection| StageEntryV1 {
                path: selection.path.clone(),
                mode: selection.mode,
                staged_id: selection.base_file_id,
            })
            .collect(),
        required_object_ids: Vec::new(),
    }
}

fn check_generation(
    state: &ScopedWorkspaceState,
    expected_generation: u64,
) -> Result<u64, PartialStateError> {
    let current = state.workspace.transaction_generation;
    if current != expected_generation {
        return Err(PartialStateError::GenerationMismatch {
            expected: expected_generation,
            actual: current,
        });
    }
    current
        .checked_add(1)
        .ok_or(PartialStateError::GenerationOverflow)
}

fn next_workspace(state: &ScopedWorkspaceState, generation: u64) -> WorkspaceStateV1 {
    let mut workspace = state.workspace.clone();
    workspace.transaction_generation = generation;
    workspace
}

/// Everything needed to publish one transaction generation: the new
/// member records plus every immutable artifact they reference. Artifact
/// names are always digest-derived; member names are fixed by code inside
/// a digest-named generation directory.
pub(crate) struct StatePlan {
    pub(crate) workspace: WorkspaceStateV1,
    pub(crate) stage: StageStateV1,
    pub(crate) pending: Option<PendingStateV1>,
    pub(crate) accepted: Option<AcceptedStateV1>,
    pub(crate) objects: BTreeMap<Hash, Vec<u8>>,
    pub(crate) bundles: Vec<(Hash, Vec<u8>)>,
    pub(crate) updates: Vec<(Hash, Vec<u8>)>,
}

static CURRENT_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn injected(seam: &'static str) -> PartialStateError {
    PartialStateError::Io {
        path: PathBuf::from(STATE_DIR),
        source: io::Error::other(format!("injected fault at {seam}")),
    }
}

pub(crate) fn unsafe_entry(path: PathBuf, reason: &str) -> PartialStateError {
    PartialStateError::UnsafeFilesystemEntry {
        path,
        reason: reason.to_owned(),
    }
}

fn missing(path: PathBuf, reason: &str) -> PartialStateError {
    PartialStateError::MissingArtifact {
        path,
        reason: reason.to_owned(),
    }
}

pub(crate) fn sys_err(path: PathBuf, error: SysError) -> PartialStateError {
    if error.is_symlink() {
        return unsafe_entry(path, "symlink refused by no-follow open");
    }
    match error {
        SysError::Io(source) => PartialStateError::Io { path, source },
        SysError::AlreadyExists => unsafe_entry(path, "entry exists under a different spelling"),
        SysError::Unsupported => {
            PartialStateError::UnsupportedPlatform("descriptor-anchored filesystem primitive")
        }
    }
}

/// Read one fixed-name file beneath `dir`, refusing symlinks, non-regular
/// files, multi-linked files, and anything over `cap` bytes.
fn read_member(dir: &DirFd, name: &str, cap: usize) -> Result<Vec<u8>, PartialStateError> {
    let path = PathBuf::from(STATE_DIR).join(name);
    let file = sys::open_file(dir, name.as_bytes(), OpenMode::Read).map_err(|error| {
        if error.is_not_found() {
            missing(path.clone(), "state member")
        } else {
            sys_err(path.clone(), error)
        }
    })?;
    let meta = file.metadata().map_err(|e| sys_err(path.clone(), e))?;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(unsafe_entry(
            path,
            "state member must be a regular file with exactly one link",
        ));
    }
    file.read_all(cap).map_err(|e| sys_err(path, e))
}

/// Read one digest-named artifact beneath `dir/<subdir>`.
fn read_artifact(
    dir: &DirFd,
    subdir: &str,
    name: &str,
    cap: usize,
) -> Result<Vec<u8>, PartialStateError> {
    let path = PathBuf::from(STATE_DIR).join(subdir).join(name);
    let sub = sys::open_dir(dir, subdir.as_bytes()).map_err(|error| {
        if error.is_not_found() {
            missing(path.clone(), "artifact directory")
        } else {
            sys_err(path.clone(), error)
        }
    })?;
    let file = sys::open_file(&sub, name.as_bytes(), OpenMode::Read).map_err(|error| {
        if error.is_not_found() {
            missing(path.clone(), "state artifact")
        } else {
            sys_err(path.clone(), error)
        }
    })?;
    let meta = file.metadata().map_err(|e| sys_err(path.clone(), e))?;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(unsafe_entry(
            path,
            "artifact must be a regular file with exactly one link",
        ));
    }
    file.read_all(cap).map_err(|e| sys_err(path, e))
}

/// Write `bytes` to a fixed name beneath `dir` create-new and fsynced; an
/// existing file with identical bytes is a completed retry and is left in
/// place, different bytes are corruption.
fn write_new(dir: &DirFd, name: &str, bytes: &[u8]) -> Result<(), PartialStateError> {
    let path = PathBuf::from(STATE_DIR).join(name);
    match sys::open_file(dir, name.as_bytes(), OpenMode::CreateExclusive) {
        Ok(file) => {
            file.write_all(bytes)
                .map_err(|e| sys_err(path.clone(), e))?;
            file.fsync().map_err(|e| sys_err(path, e))
        }
        Err(SysError::AlreadyExists) => {
            let existing = read_member(dir, name, bytes.len().max(MAX_ENVELOPE_BYTES))?;
            if existing != bytes {
                return Err(PartialStateError::CorruptArtifact {
                    path,
                    reason: "existing file bytes differ".to_owned(),
                });
            }
            Ok(())
        }
        Err(error) => Err(sys_err(path, error)),
    }
}

/// Persist one immutable artifact beneath `dir/<subdir>` create-new with
/// the same retry semantics as [`write_new`].
pub(crate) fn write_artifact(
    dir: &DirFd,
    subdir: &str,
    name: &str,
    bytes: &[u8],
) -> Result<(), PartialStateError> {
    let path = PathBuf::from(STATE_DIR).join(subdir).join(name);
    let sub = sys::open_dir(dir, subdir.as_bytes()).map_err(|e| sys_err(path.clone(), e))?;
    match sys::open_file(&sub, name.as_bytes(), OpenMode::CreateExclusive) {
        Ok(file) => {
            file.write_all(bytes)
                .map_err(|e| sys_err(path.clone(), e))?;
            file.fsync().map_err(|e| sys_err(path.clone(), e))?;
            sub.fsync().map_err(|e| sys_err(path, e))
        }
        Err(SysError::AlreadyExists) => {
            let existing = read_artifact(dir, subdir, name, bytes.len().max(MAX_ENVELOPE_BYTES))?;
            if existing != bytes {
                return Err(PartialStateError::CorruptArtifact {
                    path,
                    reason: "existing artifact bytes differ".to_owned(),
                });
            }
            Ok(())
        }
        Err(error) => Err(sys_err(path, error)),
    }
}

/// Publish `plan` as one transaction generation: immutable artifacts and
/// members first, the manifest, then `CURRENT` — the atomic replace of
/// `CURRENT` is the linearization point. A fault before the switch leaves
/// the old state authoritative; a fault after the switch before the final
/// directory fsync reports [`PartialStateError::DurabilityUncertain`].
#[allow(clippy::too_many_lines)] // one sequential publish pipeline; splitting mid-transaction obscures ordering
pub(crate) fn commit(
    dir: &DirFd,
    faults: &super::layout::Faults,
    plan: &StatePlan,
) -> Result<(), PartialStateError> {
    if faults.hit(Fault::BeforeData) {
        return Err(injected("data"));
    }
    for (id, bytes) in &plan.objects {
        write_artifact(dir, OBJECTS_DIR, &to_hex(id), bytes)?;
    }
    for (digest, bytes) in &plan.bundles {
        write_artifact(dir, BUNDLES_DIR, &bundle_file_name(digest), bytes)?;
    }
    for (digest, bytes) in &plan.updates {
        write_artifact(dir, UPDATES_DIR, &update_file_name(digest), bytes)?;
    }

    let workspace_bytes = plan.workspace.encode()?;
    let stage_bytes = plan.stage.encode()?;
    let pending_bytes = plan
        .pending
        .as_ref()
        .map(PendingStateV1::encode)
        .transpose()?;
    let accepted_bytes = plan
        .accepted
        .as_ref()
        .map(AcceptedStateV1::encode)
        .transpose()?;
    let manifest = GenerationManifestV1 {
        transaction_generation: plan.workspace.transaction_generation,
        workspace_digest: envelope_digest(&workspace_bytes),
        stage_digest: envelope_digest(&stage_bytes),
        pending_digest: pending_bytes.as_ref().map(|b| envelope_digest(b)),
        accepted_digest: accepted_bytes.as_ref().map(|b| envelope_digest(b)),
    };
    let manifest_bytes = manifest.encode()?;
    let manifest_digest = envelope_digest(&manifest_bytes);
    let generation_name = to_hex(&manifest_digest);

    if faults.hit(Fault::BeforeMembers) {
        return Err(injected("members"));
    }
    let generations = sys::open_dir(dir, GENERATIONS_DIR.as_bytes())
        .map_err(|e| sys_err(PathBuf::from(GENERATIONS_DIR), e))?;
    match sys::mkdir(&generations, generation_name.as_bytes(), 0o700) {
        Ok(()) | Err(SysError::AlreadyExists) => {}
        Err(error) => {
            return Err(sys_err(
                PathBuf::from(GENERATIONS_DIR).join(&generation_name),
                error,
            ));
        }
    }
    let generation = sys::open_dir(&generations, generation_name.as_bytes())
        .map_err(|e| sys_err(PathBuf::from(GENERATIONS_DIR).join(&generation_name), e))?;
    write_new(&generation, WORKSPACE_FILE, &workspace_bytes)?;
    write_new(&generation, STAGE_FILE, &stage_bytes)?;
    if let Some(bytes) = &pending_bytes {
        write_new(&generation, PENDING_FILE, bytes)?;
    }
    if let Some(bytes) = &accepted_bytes {
        write_new(&generation, ACCEPTED_FILE, bytes)?;
    }
    if faults.hit(Fault::BeforeManifest) {
        return Err(injected("manifest"));
    }
    write_new(&generation, MANIFEST_FILE, &manifest_bytes)?;
    generation
        .fsync()
        .map_err(|e| sys_err(PathBuf::from(GENERATIONS_DIR).join(&generation_name), e))?;
    generations
        .fsync()
        .map_err(|e| sys_err(PathBuf::from(GENERATIONS_DIR), e))?;

    if faults.hit(Fault::BeforeCurrentSwitch) {
        return Err(injected("current-pre-switch"));
    }
    let current = CurrentPointerV1 {
        transaction_generation: plan.workspace.transaction_generation,
        manifest_digest,
    }
    .encode()?;
    // The tmp sibling is create-new; a stale name means a leftover from a
    // crashed commit, which remove-tree cleanup does not touch — pick a
    // fresh name rather than trusting its bytes.
    let (tmp_name, tmp) = loop {
        let tmp_name = format!(
            ".CURRENT.tmp-{}-{}",
            std::process::id(),
            CURRENT_TMP_COUNTER.fetch_add(1, Ordering::Relaxed),
        );
        match sys::open_file(dir, tmp_name.as_bytes(), OpenMode::CreateExclusive) {
            Ok(file) => break (tmp_name, file),
            Err(SysError::AlreadyExists) => {}
            Err(error) => {
                return Err(sys_err(PathBuf::from(CURRENT_FILE), error));
            }
        }
    };
    tmp.write_all(&current)
        .map_err(|e| sys_err(PathBuf::from(CURRENT_FILE), e))?;
    tmp.fsync()
        .map_err(|e| sys_err(PathBuf::from(CURRENT_FILE), e))?;
    sys::rename_replace(dir, tmp_name.as_bytes(), CURRENT_FILE.as_bytes())
        .map_err(|e| sys_err(PathBuf::from(CURRENT_FILE), e))?;

    if faults.hit(Fault::AfterCurrentSwitch) {
        return Err(PartialStateError::DurabilityUncertain(io::Error::other(
            "injected fault at current-post-switch",
        )));
    }
    dir.fsync().map_err(|e| {
        PartialStateError::DurabilityUncertain(match e {
            SysError::Io(source) => source,
            _ => io::Error::other("state directory fsync"),
        })
    })?;
    if faults.hit(Fault::AfterSync) {
        return Err(PartialStateError::DurabilityUncertain(io::Error::other(
            "injected fault at post-sync",
        )));
    }
    Ok(())
}

/// Commit `plan` and reload the freshly selected state.
pub(crate) fn publish(
    layout: &ScopedWorkspaceLayout,
    plan: &StatePlan,
) -> Result<ScopedWorkspaceState, PartialStateError> {
    commit(layout.state_dir(), &layout.faults, plan)?;
    load_full(layout)
}

/// Read the raw file bytes a verified base object carries — used to
/// materialize selected working files at create time.
pub(crate) fn snapshot_file_bytes(
    snapshot: &VerifiedPartialSnapshot,
    file_id: &Hash,
) -> Result<Vec<u8>, PartialStateError> {
    struct SnapshotSource<'a>(&'a VerifiedPartialSnapshot);
    impl ObjectSource for SnapshotSource<'_> {
        fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
            self.0
                .object_bytes(id)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| StoreError::ObjectNotFound(to_hex(id)))
        }
    }
    read_blob(&SnapshotSource(snapshot), file_id).map_err(map_worktree)
}

/// Read and fully verify the `CURRENT`-selected generation: manifest and
/// member digests, every cross-record binding, the pinned bundle, every
/// required stage object, and the pending update. Readers never scan
/// generations or fall back to working files.
#[allow(clippy::too_many_lines)] // one sequential verification pipeline; each step gates the next read
pub(crate) fn load_full(
    layout: &ScopedWorkspaceLayout,
) -> Result<ScopedWorkspaceState, PartialStateError> {
    let dir = layout.state_dir();
    let current_bytes =
        read_member(dir, CURRENT_FILE, MAX_ENVELOPE_BYTES).map_err(|error| match error {
            PartialStateError::MissingArtifact { .. } => PartialStateError::IncompleteInstall(
                layout.root().join(STATE_DIR).join(CURRENT_FILE),
            ),
            other => other,
        })?;
    let current = CurrentPointerV1::decode(&current_bytes)?;
    let generation_name = to_hex(&current.manifest_digest);
    let generations = sys::open_dir(dir, GENERATIONS_DIR.as_bytes()).map_err(|error| {
        if error.is_not_found() {
            PartialStateError::IncompleteInstall(
                layout.root().join(STATE_DIR).join(GENERATIONS_DIR),
            )
        } else {
            sys_err(PathBuf::from(GENERATIONS_DIR), error)
        }
    })?;
    let generation = sys::open_dir(&generations, generation_name.as_bytes()).map_err(|error| {
        let path = PathBuf::from(GENERATIONS_DIR).join(&generation_name);
        if error.is_not_found() {
            missing(path, "CURRENT-selected generation")
        } else {
            sys_err(path, error)
        }
    })?;
    let manifest_bytes = read_member(&generation, MANIFEST_FILE, MAX_ENVELOPE_BYTES)?;
    if envelope_digest(&manifest_bytes) != current.manifest_digest {
        return Err(PartialStateError::CorruptArtifact {
            path: PathBuf::from(GENERATIONS_DIR)
                .join(&generation_name)
                .join(MANIFEST_FILE),
            reason: "manifest digest does not match CURRENT".to_owned(),
        });
    }
    let manifest = GenerationManifestV1::decode(&manifest_bytes)?;
    if manifest.transaction_generation != current.transaction_generation {
        return Err(PartialStateError::BindingMismatch(
            "manifest/CURRENT generation",
        ));
    }

    let member = |name: &str, expected: &Hash| -> Result<Vec<u8>, PartialStateError> {
        let bytes = read_member(&generation, name, MAX_ENVELOPE_BYTES)?;
        if envelope_digest(&bytes) != *expected {
            return Err(PartialStateError::CorruptArtifact {
                path: PathBuf::from(GENERATIONS_DIR)
                    .join(&generation_name)
                    .join(name),
                reason: "member digest does not match manifest".to_owned(),
            });
        }
        Ok(bytes)
    };
    let workspace = WorkspaceStateV1::decode(&member(WORKSPACE_FILE, &manifest.workspace_digest)?)?;
    if workspace.transaction_generation != manifest.transaction_generation {
        return Err(PartialStateError::BindingMismatch(
            "workspace/manifest generation",
        ));
    }
    let stage = StageStateV1::decode(&member(STAGE_FILE, &manifest.stage_digest)?)?;
    if stage.workspace_id != workspace.workspace_id
        || stage.base_id != workspace.base_id
        || stage.base_revision != workspace.base_revision
    {
        return Err(PartialStateError::BindingMismatch("stage binding"));
    }
    if stage.entries.len() != workspace.selection.len()
        || !stage
            .entries
            .iter()
            .zip(&workspace.selection)
            .all(|(entry, selection)| entry.path == selection.path && entry.mode == selection.mode)
    {
        return Err(PartialStateError::BindingMismatch(
            "stage entries do not cover the selection",
        ));
    }
    let pending = match manifest.pending_digest {
        Some(digest) => {
            let pending = PendingStateV1::decode(&member(PENDING_FILE, &digest)?)?;
            if pending.workspace_id != workspace.workspace_id
                || pending.base_id != workspace.base_id
                || pending.base_revision != workspace.base_revision
            {
                return Err(PartialStateError::BindingMismatch("pending binding"));
            }
            if pending.created_generation > workspace.transaction_generation {
                return Err(PartialStateError::BindingMismatch(
                    "pending created in a future generation",
                ));
            }
            Some(pending)
        }
        None => None,
    };
    let accepted = match manifest.accepted_digest {
        Some(digest) => {
            let accepted = AcceptedStateV1::decode(&member(ACCEPTED_FILE, &digest)?)?;
            if accepted.workspace_id != workspace.workspace_id
                || accepted.candidate_id != workspace.base_id
                || accepted.accepted_base_revision != workspace.base_revision
            {
                return Err(PartialStateError::BindingMismatch("accepted binding"));
            }
            Some(accepted)
        }
        None => None,
    };
    // A prior accepted record may legally sit beside a later distinct
    // pending operation; the SAME candidate/update may not be both
    // accepted and active.
    if let (Some(pending), Some(accepted)) = (&pending, &accepted)
        && pending.candidate_id == accepted.candidate_id
        && pending.update_digest == accepted.update_digest
    {
        return Err(PartialStateError::BindingMismatch(
            "pending duplicates the accepted outcome",
        ));
    }

    // The persisted bundle must verify against the persisted independent
    // base/selection/limits — never trust the member record alone.
    let bundle_name = bundle_file_name(&workspace.base_bundle_digest);
    let bundle_bytes = read_artifact(
        dir,
        BUNDLES_DIR,
        &bundle_name,
        workspace.limits.max_bundle_bytes,
    )?;
    if crate::hash::hash(&bundle_bytes) != workspace.base_bundle_digest {
        return Err(PartialStateError::CorruptArtifact {
            path: PathBuf::from(STATE_DIR)
                .join(BUNDLES_DIR)
                .join(&bundle_name),
            reason: "bundle digest mismatch".to_owned(),
        });
    }
    let paths: Vec<PartialPath> = workspace
        .selection
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    let verified =
        verify_partial_snapshot(workspace.base_id, &paths, &bundle_bytes, &workspace.limits)?;
    if verified.files().len() != workspace.selection.len()
        || !verified
            .files()
            .iter()
            .zip(&workspace.selection)
            .all(|(file, selection)| {
                *file.path() == selection.path
                    && file.mode() == selection.mode
                    && *file.object_id() == selection.base_file_id
            })
    {
        return Err(PartialStateError::BindingMismatch(
            "selection does not equal verified files",
        ));
    }

    // Every stage-required object must exist at its canonical path and be
    // the canonical serialization of an object whose id is the recorded
    // one — a byte-hash match alone never authenticates content.
    if stage.required_object_ids.len() > workspace.limits.max_update_objects {
        return Err(PartialStateError::NonCanonical("required object count"));
    }
    let mut local_objects = BTreeMap::new();
    for id in &stage.required_object_ids {
        let object_path = PathBuf::from(STATE_DIR).join(OBJECTS_DIR).join(to_hex(id));
        let bytes = read_artifact(
            dir,
            OBJECTS_DIR,
            &to_hex(id),
            workspace.limits.max_object_bytes,
        )?;
        let object =
            crate::deserialize(&bytes).map_err(|_| PartialStateError::CorruptArtifact {
                path: object_path.clone(),
                reason: "object does not decode".to_owned(),
            })?;
        let canonical =
            crate::serialize(&object).map_err(|_| PartialStateError::CorruptArtifact {
                path: object_path.clone(),
                reason: "object does not re-encode".to_owned(),
            })?;
        if canonical != bytes || id_from_object(&object, &bytes) != *id {
            return Err(PartialStateError::CorruptArtifact {
                path: object_path,
                reason: "object id mismatch".to_owned(),
            });
        }
        local_objects.insert(*id, bytes);
    }

    // The persisted stage ids are checksummed, not self-authenticating:
    // every staged representation must resolve and re-verify through the
    // authenticated sources before the state is handed out.
    validate_stage_representations(&workspace, &stage, &verified, &local_objects)?;

    let pending_update_bytes = match &pending {
        Some(pending) => {
            let update_name = pending.update_file_name();
            // Bound the persisted length by the active profile BEFORE any
            // artifact read or allocation.
            let max_update = u64::try_from(workspace.limits.max_update_bytes)
                .map_err(|_| PartialStateError::NonCanonical("limits"))?;
            if pending.update_length > max_update {
                return Err(PartialStateError::NonCanonical("update_length"));
            }
            let update_length = usize::try_from(pending.update_length)
                .map_err(|_| PartialStateError::NonCanonical("update_length"))?;
            let bytes = read_artifact(dir, UPDATES_DIR, &update_name, update_length)?;
            if bytes.len() != update_length || crate::hash::hash(&bytes) != pending.update_digest {
                return Err(PartialStateError::CorruptArtifact {
                    path: PathBuf::from(STATE_DIR)
                        .join(UPDATES_DIR)
                        .join(&update_name),
                    reason: "update length or digest mismatch".to_owned(),
                });
            }
            let update = PartialUpdate::decode(&bytes, &workspace.limits)?;
            if *update.base_id() != pending.base_id
                || *update.candidate_id() != pending.candidate_id
            {
                return Err(PartialStateError::BindingMismatch("pending update"));
            }
            Some(bytes)
        }
        None => None,
    };

    Ok(ScopedWorkspaceState {
        workspace,
        stage,
        pending,
        accepted,
        verified,
        local_objects,
        pending_update_bytes,
    })
}

impl ScopedWorkspaceLayout {
    /// Apply caller-supplied complete `FileReplacement`s on top of the
    /// authoritative stage. The working tree is never consulted; unrelated
    /// staged entries are preserved; restoring every path to its base bytes
    /// yields the clean stage. Refused while a pending operation exists.
    pub fn replace_stage(
        &self,
        expected_generation: u64,
        replacements: &[FileReplacement],
    ) -> Result<ScopedWorkspaceState, PartialStateError> {
        self.with_lock(|_| self.replace_stage_locked(expected_generation, replacements))
    }

    fn replace_stage_locked(
        &self,
        expected_generation: u64,
        replacements: &[FileReplacement],
    ) -> Result<ScopedWorkspaceState, PartialStateError> {
        let state = load_full(self)?;
        let next_generation = check_generation(&state, expected_generation)?;
        if state.pending.is_some() {
            return Err(PartialStateError::PendingConflict);
        }
        let limits = *state.workspace.limits();
        let selection = selection_map(&state);
        for replacement in replacements {
            selection
                .get(replacement.path())
                .ok_or(PartialError::UnsupportedPartialOperation)?;
        }
        // `reuse_selected` names a verified BASE representation, never a
        // staged one — caller replacements pass through unchanged. Only
        // unrelated staged entries are re-fed from authoritative state.
        let mut feed: Vec<FileReplacement> = replacements.to_vec();
        let mut replaced: BTreeSet<&PartialPath> = BTreeSet::new();
        for replacement in replacements {
            replaced.insert(replacement.path());
        }
        for entry in &state.stage.entries {
            let base = selection
                .get(&entry.path)
                .ok_or(PartialStateError::BindingMismatch(
                    "stage path outside selection",
                ))?;
            if entry.staged_id == base.base_file_id || replaced.contains(&entry.path) {
                continue;
            }
            let bytes = staged_bytes(&state, &entry.staged_id)?;
            feed.push(FileReplacement::bytes(entry.path.clone(), bytes));
        }
        if feed.is_empty() {
            return Ok(state);
        }
        let prepared = match replace_files(&state.verified, &feed, &limits) {
            Ok(prepared) => Some(prepared),
            Err(PartialError::NoChanges) => None,
            Err(error) => return Err(PartialStateError::Partial(error)),
        };
        let next_stage = match &prepared {
            None => clean_stage(&state),
            Some(prepared) => {
                let changes: BTreeMap<&PartialPath, Hash> = prepared
                    .changes
                    .iter()
                    .map(|change| (&change.path, change.new_id))
                    .collect();
                StageStateV1 {
                    workspace_id: state.workspace.workspace_id,
                    base_id: state.workspace.base_id,
                    base_revision: state.workspace.base_revision,
                    entries: state
                        .workspace
                        .selection
                        .iter()
                        .map(|selection| StageEntryV1 {
                            path: selection.path.clone(),
                            mode: selection.mode,
                            staged_id: changes
                                .get(&selection.path)
                                .copied()
                                .unwrap_or(selection.base_file_id),
                        })
                        .collect(),
                    required_object_ids: prepared.produced.keys().copied().collect(),
                }
            }
        };
        let objects = prepared
            .map(|prepared| prepared.produced)
            .unwrap_or_default();
        let plan = StatePlan {
            workspace: next_workspace(&state, next_generation),
            stage: next_stage,
            pending: None,
            accepted: state.accepted.clone(),
            objects,
            bundles: Vec::new(),
            updates: Vec::new(),
        };
        publish(self, &plan)
    }

    /// Record the signed candidate and its exact deterministic `MKWU`
    /// update. Rebuilds the staged overlay from verified state, requires the
    /// caller-supplied commits to reproduce it exactly, and requires the
    /// encoded update to be byte-identical to `exact_update_bytes`. At most
    /// one pending operation exists; an exact retry of the recorded one is
    /// generation-neutral.
    pub fn save_pending(
        &self,
        expected_generation: u64,
        expected_unsigned: &Commit,
        signed: &Commit,
        exact_update_bytes: &[u8],
        operation: Option<PendingOperationV1>,
    ) -> Result<ScopedWorkspaceState, PartialStateError> {
        self.with_lock(|_| {
            self.save_pending_locked(
                expected_generation,
                expected_unsigned,
                signed,
                exact_update_bytes,
                operation,
            )
        })
    }

    fn save_pending_locked(
        &self,
        expected_generation: u64,
        expected_unsigned: &Commit,
        signed: &Commit,
        exact_update_bytes: &[u8],
        operation: Option<PendingOperationV1>,
    ) -> Result<ScopedWorkspaceState, PartialStateError> {
        let state = load_full(self)?;
        // The expected generation gates EVERY save — including exact
        // retries, which re-validate but never advance the generation.
        if state.workspace.transaction_generation != expected_generation {
            return Err(PartialStateError::GenerationMismatch {
                expected: expected_generation,
                actual: state.workspace.transaction_generation,
            });
        }
        let limits = *state.workspace.limits();
        if let Some(pending) = &state.pending {
            let stored = state.pending_update_bytes.as_deref().ok_or_else(|| {
                PartialStateError::MissingArtifact {
                    path: PathBuf::from(STATE_DIR)
                        .join(UPDATES_DIR)
                        .join(pending.update_file_name()),
                    reason: "pending update".to_owned(),
                }
            })?;
            if stored != exact_update_bytes || pending.operation != operation {
                return Err(PartialStateError::PendingConflict);
            }
            // Byte-identical retry: the supplied commits must still
            // reproduce the recorded update exactly — a substituted
            // expected_unsigned/signed is a candidate mismatch, not a
            // silent success.
            let decoded = PartialUpdate::decode(exact_update_bytes, &limits)?;
            if *decoded.base_id() != state.workspace.base_id {
                return Err(PartialStateError::CandidateMismatch);
            }
            let feed = stage_replacements(&state)?;
            let prepared = replace_files(&state.verified, &feed, &limits)?;
            let update = export_partial_update(
                &state.verified,
                &prepared,
                expected_unsigned,
                signed,
                &limits,
            )
            .map_err(|_| PartialStateError::CandidateMismatch)?;
            let encoded = update.encode(&limits)?;
            if encoded != exact_update_bytes || *decoded.candidate_id() != *update.candidate_id() {
                return Err(PartialStateError::CandidateMismatch);
            }
            return Ok(state);
        }
        let next_generation = state
            .workspace
            .transaction_generation
            .checked_add(1)
            .ok_or(PartialStateError::GenerationOverflow)?;
        if stage_is_clean(&state.workspace, &state.stage) {
            return Err(PartialStateError::Partial(PartialError::NoChanges));
        }
        let decoded = PartialUpdate::decode(exact_update_bytes, &limits)?;
        if *decoded.base_id() != state.workspace.base_id {
            return Err(PartialStateError::CandidateMismatch);
        }
        let feed = stage_replacements(&state)?;
        let prepared = replace_files(&state.verified, &feed, &limits)?;
        let update = export_partial_update(
            &state.verified,
            &prepared,
            expected_unsigned,
            signed,
            &limits,
        )?;
        let encoded = update.encode(&limits)?;
        if encoded != exact_update_bytes {
            return Err(PartialStateError::CandidateMismatch);
        }
        if *decoded.candidate_id() != *update.candidate_id() {
            return Err(PartialStateError::CandidateMismatch);
        }
        let update_digest = crate::hash::hash(exact_update_bytes);
        let pending = PendingStateV1 {
            workspace_id: state.workspace.workspace_id,
            base_id: state.workspace.base_id,
            base_revision: state.workspace.base_revision,
            created_generation: next_generation,
            candidate_id: *update.candidate_id(),
            update_digest,
            update_length: u64::try_from(exact_update_bytes.len())
                .map_err(|_| PartialStateError::NonCanonical("update_length"))?,
            status: PendingStatusV1::Prepared,
            operation,
        };
        let plan = StatePlan {
            workspace: next_workspace(&state, next_generation),
            stage: state.stage.clone(),
            pending: Some(pending),
            accepted: state.accepted.clone(),
            objects: BTreeMap::new(),
            bundles: Vec::new(),
            updates: vec![(update_digest, exact_update_bytes.to_vec())],
        };
        publish(self, &plan)
    }

    /// Record the asserted outcome of the recorded pending operation.
    /// Non-accepted outcomes update only the pending status; `Accepted`
    /// rebuilds and re-verifies the candidate's selected bundle from local
    /// objects alone, advances the base, clears pending, and never touches
    /// working files.
    pub fn record_outcome(
        &self,
        expected_generation: u64,
        identity: &PendingIdentityV1,
        outcome: PendingOutcomeV1,
    ) -> Result<ScopedWorkspaceState, PartialStateError> {
        self.with_lock(|_| self.record_outcome_locked(expected_generation, identity, outcome))
    }

    fn record_outcome_locked(
        &self,
        expected_generation: u64,
        identity: &PendingIdentityV1,
        outcome: PendingOutcomeV1,
    ) -> Result<ScopedWorkspaceState, PartialStateError> {
        let state = load_full(self)?;
        if state.pending.is_none() {
            return Self::outcome_without_pending(state, identity, outcome);
        }
        let pending = state.pending.as_ref().expect("pending checked");
        if pending.identity() != *identity {
            return Err(PartialStateError::PendingMismatch);
        }
        let status = match outcome {
            PendingOutcomeV1::Prepared => Some(PendingStatusV1::Prepared),
            PendingOutcomeV1::Exported => Some(PendingStatusV1::Exported),
            PendingOutcomeV1::Conflict => Some(PendingStatusV1::Conflict),
            PendingOutcomeV1::Unknown => Some(PendingStatusV1::Unknown),
            PendingOutcomeV1::Accepted => None,
        };
        let Some(status) = status else {
            return self.accept_pending(&state, pending, expected_generation);
        };
        if pending.status == status {
            return Ok(state);
        }
        let next_generation = check_generation(&state, expected_generation)?;
        let mut pending = pending.clone();
        pending.status = status;
        let plan = StatePlan {
            workspace: next_workspace(&state, next_generation),
            stage: state.stage.clone(),
            pending: Some(pending),
            accepted: state.accepted.clone(),
            objects: BTreeMap::new(),
            bundles: Vec::new(),
            updates: Vec::new(),
        };
        publish(self, &plan)
    }

    /// Idempotent replay of a completed acceptance, or a typed refusal when
    /// no pending operation exists.
    fn outcome_without_pending(
        state: ScopedWorkspaceState,
        identity: &PendingIdentityV1,
        outcome: PendingOutcomeV1,
    ) -> Result<ScopedWorkspaceState, PartialStateError> {
        if outcome == PendingOutcomeV1::Accepted
            && let Some(accepted) = &state.accepted
        {
            let prior_revision = accepted
                .accepted_base_revision
                .checked_sub(1)
                .ok_or(PartialStateError::PendingMismatch)?;
            let matches = identity.workspace_id == accepted.workspace_id
                && identity.base_revision == prior_revision
                && identity.candidate_id == accepted.candidate_id
                && identity.update_digest == accepted.update_digest
                && identity.operation == accepted.operation;
            if matches {
                return Ok(state);
            }
        }
        Err(PartialStateError::PendingMissing)
    }

    /// Advance the base to the pending candidate. Rebuilds the candidate's
    /// selected snapshot from the verified base objects unioned with the
    /// update's raw pack — no fetch and no `ObjectStore` — then persists the
    /// new verified bundle, a clean stage, and the accepted record.
    #[allow(clippy::too_many_lines)] // union, rebuild, re-verify, and persist in one acceptance step
    fn accept_pending(
        &self,
        state: &ScopedWorkspaceState,
        pending: &PendingStateV1,
        expected_generation: u64,
    ) -> Result<ScopedWorkspaceState, PartialStateError> {
        let next_generation = check_generation(state, expected_generation)?;
        let limits = *state.workspace.limits();
        let update_bytes = state.pending_update_bytes.as_deref().ok_or_else(|| {
            PartialStateError::MissingArtifact {
                path: PathBuf::from(STATE_DIR)
                    .join(UPDATES_DIR)
                    .join(pending.update_file_name()),
                reason: "pending update".to_owned(),
            }
        })?;
        let update = PartialUpdate::decode(update_bytes, &limits)?;
        if *update.base_id() != pending.base_id || *update.candidate_id() != pending.candidate_id {
            return Err(PartialStateError::BindingMismatch("pending update binding"));
        }
        let mut union: BTreeMap<Hash, &[u8]> = BTreeMap::new();
        for (id, bytes) in state.verified.objects() {
            union.insert(*id, bytes);
        }
        let update_artifact_path = PathBuf::from(STATE_DIR)
            .join(UPDATES_DIR)
            .join(pending.update_file_name());
        let entries = crate::pack::PackEntries::new(update.pack_bytes()).map_err(|_| {
            PartialStateError::CorruptArtifact {
                path: update_artifact_path.clone(),
                reason: "pending update pack".to_owned(),
            }
        })?;
        let mut pack_objects: Vec<(Hash, Vec<u8>)> = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| PartialStateError::CorruptArtifact {
                path: update_artifact_path.clone(),
                reason: "pending update pack".to_owned(),
            })?;
            let crate::pack::PackEntry::Raw { bytes } = entry else {
                return Err(PartialStateError::CorruptArtifact {
                    path: update_artifact_path.clone(),
                    reason: "pending update pack must be raw-only".to_owned(),
                });
            };
            pack_objects.push((object_id_from_bytes(bytes.as_ref()), bytes.into_owned()));
        }
        for (id, bytes) in &pack_objects {
            union.insert(*id, bytes.as_slice());
        }
        let source = UnionSource { base: union };
        let bundle = build_partial_snapshot(
            &source,
            *update.candidate_id(),
            state.verified.paths(),
            &limits,
        )?;
        let bundle_bytes = bundle.encode(&limits)?;
        let new_verified = verify_partial_snapshot(
            *update.candidate_id(),
            state.verified.paths(),
            &bundle_bytes,
            &limits,
        )?;
        let bundle_digest = crate::hash::hash(&bundle_bytes);
        let base_revision = state
            .workspace
            .base_revision
            .checked_add(1)
            .ok_or(PartialStateError::GenerationOverflow)?;
        let workspace = WorkspaceStateV1 {
            workspace_id: state.workspace.workspace_id,
            transaction_generation: next_generation,
            base_revision,
            base_id: *update.candidate_id(),
            base_bundle_digest: bundle_digest,
            selection: new_verified
                .files()
                .iter()
                .map(|file| WorkspaceSelectionV1 {
                    path: file.path().clone(),
                    mode: file.mode(),
                    base_file_id: *file.object_id(),
                })
                .collect(),
            limits,
            target: state.workspace.target.clone(),
        };
        let next_stage = StageStateV1 {
            workspace_id: workspace.workspace_id,
            base_id: workspace.base_id,
            base_revision: workspace.base_revision,
            entries: workspace
                .selection
                .iter()
                .map(|selection| StageEntryV1 {
                    path: selection.path.clone(),
                    mode: selection.mode,
                    staged_id: selection.base_file_id,
                })
                .collect(),
            required_object_ids: Vec::new(),
        };
        let accepted = AcceptedStateV1 {
            workspace_id: workspace.workspace_id,
            prior_base_id: state.workspace.base_id,
            accepted_base_revision: base_revision,
            candidate_id: *update.candidate_id(),
            update_digest: pending.update_digest,
            operation: pending.operation,
        };
        let plan = StatePlan {
            workspace,
            stage: next_stage,
            pending: None,
            accepted: Some(accepted),
            objects: BTreeMap::new(),
            bundles: vec![(bundle_digest, bundle_bytes)],
            updates: Vec::new(),
        };
        publish(self, &plan)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::AsRawFd;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;

    use tempfile::tempdir;

    use crate::hash::to_hex;
    use crate::object::{EntryMode, Object, Tree, TreeEntry, id_from_object, object_id_from_bytes};
    use crate::partial::PartialLimits;
    use crate::partial::layout::{Fault, Faults};
    use crate::partial::overlay::FileReplacement;
    use crate::partial::verify::build_partial_snapshot;
    use crate::serialize;
    use crate::sign::{KeyPair, sign_remix};
    use crate::store::ObjectStore;
    use crate::{Identity, Remix, RepoLayout};

    use super::{
        AcceptedStateV1, CURRENT_TMP_COUNTER, PartialStateError, PendingStateV1, PendingStatusV1,
        ScopedWorkspaceLayout, StatePlan, commit,
    };

    /// One-file base remix, verified bundle, and a created workspace — the
    /// smallest fixture that exercises the full commit pipeline.
    fn fixture() -> (tempfile::TempDir, ScopedWorkspaceLayout) {
        fixture_with(PartialLimits::V1)
    }

    fn fixture_with(limits: PartialLimits) -> (tempfile::TempDir, ScopedWorkspaceLayout) {
        let repo = tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(repo.path())).unwrap();
        let blob_bytes = serialize(&Object::Blob(crate::object::Blob {
            data: b"content".to_vec(),
        }))
        .unwrap();
        let blob = store.write(&blob_bytes).unwrap();
        let tree = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"file.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        });
        let tree_bytes = serialize(&tree).unwrap();
        let tree_id = id_from_object(&tree, &tree_bytes);
        assert_eq!(store.write(&tree_bytes).unwrap(), tree_id);
        let key = KeyPair::from_seed([1; 32]);
        let mut remix = Remix {
            tree_hash: tree_id,
            parents: Vec::new(),
            sources: Vec::new(),
            author: Identity::opaque(b"author".to_vec()),
            signer: key.public.0,
            message: b"base".to_vec(),
            timestamp: 1,
            signature: [0; 64],
        };
        remix.signature = sign_remix(&remix, &key).unwrap().0;
        let remix_object = Object::Remix(remix);
        let remix_bytes = serialize(&remix_object).unwrap();
        let base_id = id_from_object(&remix_object, &remix_bytes);
        assert_eq!(store.write(&remix_bytes).unwrap(), base_id);
        let paths = vec![vec![b"file.txt".to_vec()]];
        let bundle = build_partial_snapshot(&store, base_id, &paths, &limits).unwrap();
        let dir = tempdir().unwrap();
        let layout = ScopedWorkspaceLayout::create(
            &dir.path().join("ws"),
            base_id,
            &paths,
            &bundle.encode(&limits).unwrap(),
            limits,
            None,
        )
        .unwrap();
        (dir, layout)
    }

    fn edit() -> FileReplacement {
        FileReplacement::bytes(vec![b"file.txt".to_vec()], b"edited".to_vec())
    }

    #[test]
    fn faults_before_the_current_switch_keep_the_old_generation() {
        for seam in [
            Fault::BeforeData,
            Fault::BeforeMembers,
            Fault::BeforeManifest,
            Fault::BeforeCurrentSwitch,
        ] {
            let (_dir, layout) = fixture();
            layout.faults.arm(seam);
            assert!(layout.replace_stage(0, &[edit()]).is_err());
            let state = layout.read_state().unwrap();
            assert_eq!(
                state.workspace().transaction_generation(),
                0,
                "fault at {seam:?} must leave generation 0 authoritative"
            );
            assert!(state.stage_is_clean());
        }
    }

    #[test]
    fn faults_after_the_current_switch_report_durability_uncertainty() {
        for seam in [Fault::AfterCurrentSwitch, Fault::AfterSync] {
            let (_dir, layout) = fixture();
            layout.faults.arm(seam);
            let result = layout.replace_stage(0, &[edit()]);
            assert!(
                matches!(result, Err(PartialStateError::DurabilityUncertain(_))),
                "fault at {seam:?} must surface DurabilityUncertain, got {result:?}"
            );
            // The switch already happened: a fresh open observes the new
            // complete generation — never a rollback and never a guess.
            let reopened = ScopedWorkspaceLayout::open(layout.root()).unwrap();
            let state = reopened.read_state().unwrap();
            assert_eq!(state.workspace().transaction_generation(), 1);
            assert!(!state.stage_is_clean());
        }
    }

    #[test]
    fn replaced_lock_inode_fails_closed() {
        let (_dir, layout) = fixture();
        let state_dir = layout.root().join(".mkit-scoped");
        let lock_path = state_dir.join("workspace.lock");
        let saved = state_dir.join("workspace.lock.saved");
        // Move the ORIGINAL inode aside — it stays the retained
        // descriptor's inode — and drop a replacement at the lock path.
        std::fs::rename(&lock_path, &saved).unwrap();
        std::fs::write(&lock_path, b"").unwrap();
        assert!(matches!(
            layout.replace_stage(0, &[edit()]),
            Err(PartialStateError::UnsafeFilesystemEntry { .. })
        ));
        // A failed acquisition must not leave the kernel lock held on the
        // retained descriptor: flock(LOCK_EX|LOCK_NB) on a fresh fd over
        // the same inode succeeds only if the lock was released.
        let probe = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&saved)
            .unwrap();
        // SAFETY: flock(2) on a valid fd we own; nonblocking probe only.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, 0, "a failed lock must not stay held");
        // SAFETY: releasing the probe's own lock.
        #[allow(unsafe_code)]
        unsafe {
            libc::flock(probe.as_raw_fd(), libc::LOCK_UN);
        }
        drop(probe);
        // Restore the original inode at the lock path; the workspace
        // works again — proving the failed path left nothing stranded.
        std::fs::remove_file(&lock_path).unwrap();
        std::fs::rename(&saved, &lock_path).unwrap();
        layout.replace_stage(0, &[edit()]).unwrap();
    }

    /// Occupy the next predicted CURRENT tmp names and prove a transition
    /// completes under a FRESH name — a fixed-name retry would spin or
    /// clobber a leftover.
    #[test]
    fn stale_current_tmp_names_are_skipped() {
        let (_dir, layout) = fixture();
        let state_dir = layout.root().join(".mkit-scoped");
        let mut sentinels: Vec<PathBuf> = Vec::new();
        // The counter is process-global and shared with parallel tests;
        // occupy a band so any in-flight value still collides, retrying
        // if concurrent commits raced the band while it was populated.
        for _attempt in 0..8 {
            let base = CURRENT_TMP_COUNTER.load(Ordering::Relaxed);
            for offset in 0..32u64 {
                let path = state_dir.join(format!(
                    ".CURRENT.tmp-{}-{}",
                    std::process::id(),
                    base + offset
                ));
                match std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                {
                    Ok(mut file) => {
                        file.write_all(b"stale").unwrap();
                        sentinels.push(path);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("{error}"),
                }
            }
            if CURRENT_TMP_COUNTER.load(Ordering::Relaxed) < base + 32 {
                break;
            }
            for path in sentinels.drain(..) {
                let _ = std::fs::remove_file(path);
            }
        }
        assert!(!sentinels.is_empty());
        layout.replace_stage(0, &[edit()]).unwrap();
        // No stale-name file was consumed or overwritten by the commit.
        for path in &sentinels {
            assert_eq!(std::fs::read(path).unwrap(), b"stale");
        }
        for path in &sentinels {
            let _ = std::fs::remove_file(path);
        }
    }

    /// A FIFO substituted for a stage object must fail the descriptor
    /// metadata check — never block the read open.
    #[test]
    fn fifo_state_object_is_refused_without_blocking() {
        let (_dir, layout) = fixture();
        layout.replace_stage(0, &[edit()]).unwrap();
        let state = layout.read_state().unwrap();
        let id = state.stage().required_object_ids()[0];
        let path = layout
            .root()
            .join(format!(".mkit-scoped/objects/{}", to_hex(&id)));
        std::fs::remove_file(&path).unwrap();
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: mkfifo(2) on a CString path we built inside our own
        // temp workspace.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0);
        assert!(matches!(
            layout.read_state(),
            Err(PartialStateError::UnsafeFilesystemEntry { .. })
        ));
    }

    /// Republish a crafted generation through the real `commit` path:
    /// clone the current state into a plan, bump the generation, mutate,
    /// and commit. Used to build states no honest transition produces.
    fn republish(layout: &ScopedWorkspaceLayout, mutate: impl FnOnce(&mut StatePlan)) {
        let state = layout.read_state().unwrap();
        let mut workspace = state.workspace.clone();
        workspace.transaction_generation += 1;
        let mut plan = StatePlan {
            workspace,
            stage: state.stage.clone(),
            pending: state.pending.clone(),
            accepted: state.accepted.clone(),
            objects: BTreeMap::new(),
            bundles: Vec::new(),
            updates: Vec::new(),
        };
        mutate(&mut plan);
        commit(layout.state_dir(), &Faults::new(), &plan).unwrap();
    }

    fn crafted_pending(workspace: &super::WorkspaceStateV1) -> PendingStateV1 {
        PendingStateV1 {
            workspace_id: workspace.workspace_id,
            base_id: workspace.base_id,
            base_revision: workspace.base_revision,
            created_generation: workspace.transaction_generation,
            candidate_id: [0x11; 32],
            update_digest: [0x22; 32],
            update_length: 0,
            status: PendingStatusV1::Prepared,
            operation: None,
        }
    }

    /// A stage claiming more required objects than the active limits
    /// allow must fail BEFORE any object artifact is read — the object
    /// does not exist, so `MissingArtifact` would prove the order wrong.
    #[test]
    fn required_object_count_over_active_limit_fails_before_read() {
        let limits = PartialLimits {
            max_update_objects: 0,
            ..PartialLimits::V1
        };
        let (_dir, layout) = fixture_with(limits);
        republish(&layout, |plan| {
            plan.stage.required_object_ids = vec![[0x42; 32]];
        });
        assert!(matches!(
            layout.read_state(),
            Err(PartialStateError::NonCanonical(_))
        ));
    }

    /// A persisted `update_length` over the active limit must fail BEFORE
    /// the update artifact is read — the artifact does not exist, so
    /// `MissingArtifact` would prove the order wrong.
    #[test]
    fn oversized_pending_update_length_fails_before_read() {
        let (_dir, layout) = fixture();
        republish(&layout, |plan| {
            let mut pending = crafted_pending(&plan.workspace);
            pending.update_length = u64::try_from(PartialLimits::V1.max_update_bytes).unwrap() + 1;
            plan.pending = Some(pending);
        });
        assert!(matches!(
            layout.read_state(),
            Err(PartialStateError::NonCanonical(_))
        ));
    }

    /// A pending record created after the generation it lives in is a
    /// binding violation.
    #[test]
    fn pending_created_in_a_future_generation_is_rejected() {
        let (_dir, layout) = fixture();
        republish(&layout, |plan| {
            let mut pending = crafted_pending(&plan.workspace);
            pending.created_generation = plan.workspace.transaction_generation + 1;
            plan.pending = Some(pending);
        });
        assert!(matches!(
            layout.read_state(),
            Err(PartialStateError::BindingMismatch(_))
        ));
    }

    /// The same candidate/update may not be simultaneously accepted and
    /// actively pending.
    #[test]
    fn pending_duplicating_the_accepted_outcome_is_rejected() {
        let (_dir, layout) = fixture();
        republish(&layout, |plan| {
            let mut pending = crafted_pending(&plan.workspace);
            pending.candidate_id = plan.workspace.base_id;
            pending.update_digest = [0x33; 32];
            plan.pending = Some(pending);
            plan.accepted = Some(AcceptedStateV1 {
                workspace_id: plan.workspace.workspace_id,
                prior_base_id: [0x44; 32],
                accepted_base_revision: plan.workspace.base_revision,
                candidate_id: plan.workspace.base_id,
                update_digest: [0x33; 32],
                operation: None,
            });
        });
        assert!(matches!(
            layout.read_state(),
            Err(PartialStateError::BindingMismatch(_))
        ));
    }

    /// An object artifact whose BYTES hash to the recorded id is not
    /// enough: the content must decode canonically.
    #[test]
    fn noncanonical_stage_object_bytes_are_rejected() {
        let (_dir, layout) = fixture();
        let garbage = b"\xFFnot-an-object".to_vec();
        let id = object_id_from_bytes(&garbage);
        republish(&layout, |plan| {
            plan.stage.required_object_ids = vec![id];
            plan.objects.insert(id, garbage.clone());
        });
        assert!(matches!(
            layout.read_state(),
            Err(PartialStateError::CorruptArtifact { .. })
        ));
    }

    /// A stage entry bound to a canonical TREE object — present and
    /// intact in `required_object_ids` — is still not file content.
    #[test]
    fn staged_tree_object_is_rejected() {
        let (_dir, layout) = fixture();
        let tree = Object::Tree(Tree {
            entries: Vec::new(),
        });
        let tree_bytes = serialize(&tree).unwrap();
        let tree_id = id_from_object(&tree, &tree_bytes);
        republish(&layout, |plan| {
            plan.stage.entries[0].staged_id = tree_id;
            plan.stage.required_object_ids = vec![tree_id];
            plan.objects.insert(tree_id, tree_bytes.clone());
        });
        assert!(matches!(
            layout.read_state(),
            Err(PartialStateError::BindingMismatch(_))
        ));
    }

    /// A stage entry bound to an id that is neither a verified base
    /// object nor a required local object cannot be materialized.
    #[test]
    fn staged_object_outside_authenticated_sources_is_rejected() {
        let (_dir, layout) = fixture();
        republish(&layout, |plan| {
            plan.stage.entries[0].staged_id = [0x77; 32];
        });
        assert!(matches!(
            layout.read_state(),
            Err(PartialStateError::MissingArtifact { .. })
        ));
    }

    /// The honest path: a staged Blob edit validates and the state opens.
    #[test]
    fn valid_changed_blob_stage_opens() {
        let (_dir, layout) = fixture();
        layout.replace_stage(0, &[edit()]).unwrap();
        let state = layout.read_state().unwrap();
        assert!(!state.stage_is_clean());
        assert_ne!(
            state.stage().entries()[0].staged_id(),
            state.workspace().selection()[0].base_file_id()
        );
    }

    #[test]
    fn generation_generation_dir_names_are_manifest_digests() {
        let (_dir, layout) = fixture();
        layout.replace_stage(0, &[edit()]).unwrap();
        let current = std::fs::read(layout.root().join(".mkit-scoped/CURRENT")).unwrap();
        let digest = crate::hash::Hash::try_from(&current[13..45]).unwrap();
        let gen_dir = layout
            .root()
            .join(format!(".mkit-scoped/generations/{}", to_hex(&digest)));
        let manifest = std::fs::read(gen_dir.join("manifest.bin")).unwrap();
        assert_eq!(digest, crate::hash::hash(&manifest));
        assert!(gen_dir.join("workspace.bin").is_file());
        assert!(gen_dir.join("stage.bin").is_file());
        assert!(!gen_dir.join("pending.bin").exists());
    }
}
