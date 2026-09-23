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
    FileReplacement, PartialError, PartialLimits, PartialPath, PartialUpdate, PreparedPartialEdit,
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
    /// Publication was already attempted, or the requested transition would
    /// make its result appear safely unattempted again.
    #[error("pending publication cannot make this state transition")]
    InvalidPublicationTransition,
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

    /// Exact, verified MKWU bytes loaded through CURRENT and its digest-bound
    /// artifact. Callers must not read `.mkit-scoped` paths themselves.
    #[must_use]
    pub fn pending_update_bytes(&self) -> Option<&[u8]> {
        self.pending_update_bytes.as_deref()
    }

    /// Replay the authoritative stage with its selected representation IDs.
    /// Working files are never read while preparing a commit.
    pub fn prepare_staged_edit(&self) -> Result<PreparedPartialEdit, PartialStateError> {
        if self.pending.is_some() {
            return Err(PartialStateError::PendingConflict);
        }
        if self.stage_is_clean() {
            return Err(PartialStateError::Partial(PartialError::NoChanges));
        }
        let prepared = replace_files(
            &self.verified,
            &stage_replacements(self)?,
            &self.workspace.limits,
        )?;
        check_prepared_matches_stage(self, &prepared)?;
        Ok(prepared)
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

    /// Reassemble a selected base or staged file from authenticated objects.
    pub fn selected_file_bytes(&self, id: &Hash) -> Result<Vec<u8>, PartialStateError> {
        struct SelectedSource<'a>(&'a ScopedWorkspaceState);
        impl ObjectSource for SelectedSource<'_> {
            fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
                self.0
                    .local_object(id)
                    .or_else(|| self.0.verified.object_bytes(id))
                    .map(<[u8]>::to_vec)
                    .ok_or_else(|| StoreError::ObjectNotFound(to_hex(id)))
            }
        }
        read_blob(&SelectedSource(self), id).map_err(map_worktree)
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

/// Read one staged object from the authenticated sources, bounding the
/// returned bytes by the persisted per-object limit BEFORE decode. A
/// stage id outside the verified base objects and the stage's required
/// local objects is a missing artifact, never a store fallback.
fn read_staged_object(
    source: &StageSource<'_>,
    id: &Hash,
    limits: &PartialLimits,
) -> Result<Object, PartialStateError> {
    let path = PathBuf::from(STATE_DIR).join(OBJECTS_DIR).join(to_hex(id));
    let raw = source.read(id).map_err(|error| match error {
        StoreError::ObjectNotFound(_) => missing(path.clone(), "staged object"),
        other => PartialStateError::Store(other),
    })?;
    if raw.is_empty() || raw.len() > limits.max_object_bytes {
        return Err(PartialStateError::CorruptArtifact {
            path,
            reason: "staged object exceeds the per-object bound".to_owned(),
        });
    }
    crate::deserialize(&raw).map_err(|_| PartialStateError::CorruptArtifact {
        path,
        reason: "staged object does not decode".to_owned(),
    })
}

/// The chunk byte length one manifest occurrence carries: the chunk must
/// resolve to a `Blob` through the authenticated sources, with results
/// cached per chunk id so repeated occurrences and shared chunks never
/// multiply decode work.
fn staged_chunk_len(
    source: &StageSource<'_>,
    chunk_id: &Hash,
    limits: &PartialLimits,
    cache: &mut BTreeMap<Hash, usize>,
) -> Result<usize, PartialStateError> {
    if let Some(len) = cache.get(chunk_id) {
        return Ok(*len);
    }
    let path = PathBuf::from(STATE_DIR)
        .join(OBJECTS_DIR)
        .join(to_hex(chunk_id));
    let Object::Blob(chunk) = read_staged_object(source, chunk_id, limits)? else {
        return Err(PartialStateError::CorruptArtifact {
            path,
            reason: "manifest chunk is not a Blob".to_owned(),
        });
    };
    cache.insert(*chunk_id, chunk.data.len());
    Ok(chunk.data.len())
}

/// Validate one staged representation's chunk layout and return its
/// declared content length. Manifest bounds, each occurrence's type and
/// fixed/CDC length rules, and the running sum against the declared total
/// are all enforced BEFORE any content is concatenated — the first
/// detectable overrun stops the walk rather than assembling an
/// over-declared buffer. Results are cached per representation id so
/// many stage entries sharing one representation never re-verify it.
fn staged_declared_len(
    source: &StageSource<'_>,
    staged_id: &Hash,
    limits: &PartialLimits,
    file_cache: &mut BTreeMap<Hash, u64>,
    chunk_cache: &mut BTreeMap<Hash, usize>,
) -> Result<u64, PartialStateError> {
    if let Some(declared) = file_cache.get(staged_id) {
        return Ok(*declared);
    }
    let path = PathBuf::from(STATE_DIR)
        .join(OBJECTS_DIR)
        .join(to_hex(staged_id));
    let declared = match read_staged_object(source, staged_id, limits)? {
        Object::Blob(blob) => u64::try_from(blob.data.len())
            .map_err(|_| PartialStateError::Partial(PartialError::WorkspaceTooLarge))?,
        Object::ChunkedBlob(manifest) => {
            super::verify::validate_manifest_size(&manifest, limits)?;
            let mut sum = 0u64;
            for (index, chunk_id) in manifest.chunks.iter().enumerate() {
                let chunk_len = staged_chunk_len(source, chunk_id, limits, chunk_cache)?;
                super::verify::validate_chunk_occurrence(&manifest, index, chunk_len)?;
                sum = super::verify::add_chunk_len(sum, chunk_len, manifest.total_size)?;
            }
            if sum != manifest.total_size {
                return Err(PartialStateError::CorruptArtifact {
                    path,
                    reason: "chunk lengths disagree with the declared total".to_owned(),
                });
            }
            manifest.total_size
        }
        _ => {
            return Err(PartialStateError::BindingMismatch(
                "staged object is not file content",
            ));
        }
    };
    if declared > u64::try_from(limits.max_selected_file_bytes).unwrap_or(u64::MAX) {
        return Err(PartialStateError::Partial(PartialError::WorkspaceTooLarge));
    }
    file_cache.insert(*staged_id, declared);
    Ok(declared)
}

/// Reassemble one staged representation's content as an incrementally
/// bounded materializer: each chunk occurrence is type-checked, rule-
/// checked, and charged against the declared total BEFORE its bytes are
/// appended, so the buffer can never exceed `manifest.total_size` — which
/// `validate_manifest_size` has already bounded by the per-file limit.
fn staged_content(
    source: &StageSource<'_>,
    staged_id: &Hash,
    limits: &PartialLimits,
) -> Result<Vec<u8>, PartialStateError> {
    let path = PathBuf::from(STATE_DIR)
        .join(OBJECTS_DIR)
        .join(to_hex(staged_id));
    match read_staged_object(source, staged_id, limits)? {
        Object::Blob(blob) => {
            if blob.data.len() > limits.max_selected_file_bytes {
                return Err(PartialStateError::Partial(PartialError::WorkspaceTooLarge));
            }
            Ok(blob.data)
        }
        Object::ChunkedBlob(manifest) => {
            super::verify::validate_manifest_size(&manifest, limits)?;
            let declared = usize::try_from(manifest.total_size)
                .map_err(|_| PartialStateError::Partial(PartialError::WorkspaceTooLarge))?;
            let mut out = Vec::with_capacity(declared);
            let mut sum = 0u64;
            for (index, chunk_id) in manifest.chunks.iter().enumerate() {
                let Object::Blob(chunk) = read_staged_object(source, chunk_id, limits)? else {
                    return Err(PartialStateError::CorruptArtifact {
                        path: path.clone(),
                        reason: "manifest chunk is not a Blob".to_owned(),
                    });
                };
                super::verify::validate_chunk_occurrence(&manifest, index, chunk.data.len())?;
                sum = super::verify::add_chunk_len(sum, chunk.data.len(), manifest.total_size)?;
                out.extend_from_slice(&chunk.data);
            }
            if sum != manifest.total_size {
                return Err(PartialStateError::CorruptArtifact {
                    path,
                    reason: "chunk lengths disagree with the declared total".to_owned(),
                });
            }
            Ok(out)
        }
        _ => Err(PartialStateError::BindingMismatch(
            "staged object is not file content",
        )),
    }
}

/// Verify every stage entry's persisted representation against the
/// authenticated sources — never working files. Entries equal to their
/// base id reuse the verified selected file's already checked
/// `content_len`; differing entries must resolve through the verified
/// base objects or the stage's required local objects to a `Blob`/
/// `ChunkedBlob` whose chunk layout is validated per-occurrence BEFORE
/// materialization. A stage id outside the authenticated sources, a
/// non-file object, a bad chunk layout, or an over-limit file/aggregate
/// fails the load.
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
    let max_total = u64::try_from(workspace.limits.max_total_selected_bytes)
        .map_err(|_| PartialStateError::NonCanonical("limits"))?;
    let mut file_cache = BTreeMap::new();
    let mut chunk_cache = BTreeMap::new();
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
            staged_declared_len(
                &source,
                &entry.staged_id,
                &workspace.limits,
                &mut file_cache,
                &mut chunk_cache,
            )?
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

/// The overlay feed entry that replays one persisted stage entry without
/// losing its representation: a staged id naming a verified SELECTED
/// file's representation is replayed through [`FileReplacement::reuse_selected`]
/// so the persisted id — possibly a valid alternate `ChunkedBlob` layout
/// — is retained instead of silently re-canonicalized. Any other staged
/// id is generated canonical content, where re-feeding the materialized
/// bytes reproduces the same id; those bytes come from the incrementally
/// bounded [`staged_content`], never a working file.
fn stage_feed(
    selection: &BTreeMap<&PartialPath, &WorkspaceSelectionV1>,
    verified: &VerifiedPartialSnapshot,
    local_objects: &BTreeMap<Hash, Vec<u8>>,
    limits: &PartialLimits,
    entry: &StageEntryV1,
) -> Result<Option<FileReplacement>, PartialStateError> {
    let base = selection
        .get(&entry.path)
        .ok_or(PartialStateError::BindingMismatch(
            "stage path outside selection",
        ))?;
    if entry.staged_id == base.base_file_id {
        return Ok(None);
    }
    if let Some(source_file) = verified
        .files()
        .iter()
        .find(|file| *file.object_id() == entry.staged_id)
    {
        return Ok(Some(FileReplacement::reuse_selected(
            entry.path.clone(),
            source_file.path().clone(),
        )));
    }
    let source = StageSource {
        verified,
        local: local_objects,
    };
    let bytes = staged_content(&source, &entry.staged_id, limits)?;
    Ok(Some(FileReplacement::bytes(entry.path.clone(), bytes)))
}

/// Rebuild the overlay that produced a stage: one
/// representation-preserving feed entry per staged entry that differs
/// from base. Shared by `save_pending`'s candidate reconstruction,
/// `replace_stage`'s unrelated-entry preservation, and `load_full`'s
/// required-inventory replay.
fn stage_replacements(
    state: &ScopedWorkspaceState,
) -> Result<Vec<FileReplacement>, PartialStateError> {
    let selection = selection_map(state);
    let mut replacements = Vec::new();
    for entry in &state.stage.entries {
        if let Some(feed) = stage_feed(
            &selection,
            &state.verified,
            &state.local_objects,
            &state.workspace.limits,
            entry,
        )? {
            replacements.push(feed);
        }
    }
    Ok(replacements)
}

/// The replayed overlay's changed ids must equal the authoritative
/// stage's recorded ids exactly — same paths, same `staged_id` values.
/// A candidate produced from content that merely compares equal but
/// carries a different representation id is a mismatch, not a
/// substitute.
fn check_prepared_matches_stage(
    state: &ScopedWorkspaceState,
    prepared: &PreparedPartialEdit,
) -> Result<(), PartialStateError> {
    let expected: BTreeMap<&PartialPath, &Hash> = state
        .stage
        .entries
        .iter()
        .zip(&state.workspace.selection)
        .filter(|(entry, selection)| entry.staged_id != selection.base_file_id)
        .map(|(entry, _)| (&entry.path, &entry.staged_id))
        .collect();
    if prepared.changes.len() != expected.len()
        || !prepared
            .changes
            .iter()
            .all(|change| expected.get(&change.path).copied() == Some(&change.new_id))
    {
        return Err(PartialStateError::CandidateMismatch);
    }
    Ok(())
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

/// Canonical local publication-request fingerprint (SPEC-PARTIAL-WORKSPACES
/// §18): domain, length-prefixed target fields, fixed identities, and size.
fn publication_fingerprint(
    target: &RemotePublicationTargetV1,
    pending: &PendingStateV1,
    operation_id: &[u8; 32],
) -> Hash {
    let mut request = b"mkit.scoped-publication-request.v1\0".to_vec();
    for field in [target.endpoint(), target.repository(), target.exact_ref()] {
        let length = u32::try_from(field.len()).expect("validated target field byte cap");
        request.extend_from_slice(&length.to_be_bytes());
        request.extend_from_slice(field.as_bytes());
    }
    request.extend_from_slice(&pending.base_id);
    request.extend_from_slice(&pending.candidate_id);
    request.extend_from_slice(&pending.update_digest);
    request.extend_from_slice(&pending.update_length.to_be_bytes());
    request.extend_from_slice(operation_id);
    crate::hash::hash(&request)
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

/// Open one digest-named artifact beneath `dir/<subdir>` no-follow and
/// return the validated descriptor with its length, so callers can bound
/// a read by the descriptor's own size before allocating.
fn open_artifact_file(
    dir: &DirFd,
    subdir: &str,
    name: &str,
) -> Result<(sys::File, u64), PartialStateError> {
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
    Ok((file, meta.len()))
}

/// Read one digest-named artifact beneath `dir/<subdir>`, bounded by
/// `cap` bytes.
fn read_artifact(
    dir: &DirFd,
    subdir: &str,
    name: &str,
    cap: usize,
) -> Result<Vec<u8>, PartialStateError> {
    let path = PathBuf::from(STATE_DIR).join(subdir).join(name);
    let (file, _len) = open_artifact_file(dir, subdir, name)?;
    file.read_all(cap).map_err(|e| sys_err(path, e))
}

/// Fresh-name counter for immutable-file temporaries — a stale leftover
/// collides at most once per counter value, never in a fixed-name loop.
static IMMUTABLE_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Deterministic operation trace for durability-ordering tests.
#[cfg(test)]
pub(crate) mod commit_trace {
    use std::cell::RefCell;
    use std::path::Path;

    thread_local! {
        static EVENTS: RefCell<Vec<(&'static str, String)>> =
            const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn record(kind: &'static str, path: &Path) {
        EVENTS.with(|events| {
            events.borrow_mut().push((kind, path.display().to_string()));
        });
    }

    pub(crate) fn take() -> Vec<(&'static str, String)> {
        EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()))
    }
}

/// Install `bytes` as the immutable file `name` beneath `dir`.
///
/// Content lands in a fresh private sibling temporary, is fully written
/// and fsynced, then installed under the canonical name by an atomic
/// NO-REPLACE rename; the containing directory is fsynced before
/// returning. An interrupted write can therefore never leave a torn file
/// at the canonical name — only an ignorable `.name.tmp-*` orphan.
///
/// A pre-existing file at `name` is a completed retry: it is opened
/// no-follow, metadata-checked, byte-verified, and its file + directory
/// durability is (re)established — identical page-cache bytes are not
/// proof the earlier attempt synced. Different bytes are corruption and
/// are never overwritten.
fn write_immutable(
    dir: &DirFd,
    name: &str,
    bytes: &[u8],
    display: PathBuf,
    faults: &super::layout::Faults,
) -> Result<(), PartialStateError> {
    let (tmp_name, tmp) = loop {
        let tmp_name = format!(
            ".{name}.tmp-{}-{}",
            std::process::id(),
            IMMUTABLE_TMP_COUNTER.fetch_add(1, Ordering::Relaxed),
        );
        match sys::open_file(dir, tmp_name.as_bytes(), OpenMode::CreateExclusive) {
            Ok(file) => break (tmp_name, file),
            Err(SysError::AlreadyExists) => {}
            Err(error) => return Err(sys_err(display.clone(), error)),
        }
    };
    if faults.hit(Fault::ImmutablePartialWrite) {
        // Torn write: only a prefix reaches the temporary — nothing is
        // installed at the canonical name.
        tmp.write_all(&bytes[..bytes.len() / 2])
            .map_err(|e| sys_err(display.clone(), e))?;
        return Err(injected("immutable-partial-write"));
    }
    tmp.write_all(bytes)
        .map_err(|e| sys_err(display.clone(), e))?;
    #[cfg(test)]
    commit_trace::record("temp-write", &display);
    if faults.hit(Fault::ImmutableBeforeFileSync) {
        return Err(injected("immutable-before-file-sync"));
    }
    tmp.fsync().map_err(|e| sys_err(display.clone(), e))?;
    #[cfg(test)]
    commit_trace::record("file-fsync", &display);
    match sys::rename_no_replace(dir, tmp_name.as_bytes(), dir, name.as_bytes()) {
        Ok(()) => {
            #[cfg(test)]
            commit_trace::record("install", &display);
        }
        Err(SysError::AlreadyExists) => {
            let existing = sys::open_file(dir, name.as_bytes(), OpenMode::Read)
                .map_err(|e| sys_err(display.clone(), e))?;
            let meta = existing
                .metadata()
                .map_err(|e| sys_err(display.clone(), e))?;
            if !meta.is_file() || meta.nlink() != 1 {
                return Err(unsafe_entry(
                    display,
                    "immutable file must be a regular file with exactly one link",
                ));
            }
            let stored = existing
                .read_all(bytes.len().max(MAX_ENVELOPE_BYTES))
                .map_err(|e| sys_err(display.clone(), e))?;
            if stored != bytes {
                return Err(PartialStateError::CorruptArtifact {
                    path: display,
                    reason: "existing immutable bytes differ".to_owned(),
                });
            }
            #[cfg(test)]
            commit_trace::record("reuse-verify", &display);
            existing.fsync().map_err(|e| sys_err(display.clone(), e))?;
            #[cfg(test)]
            commit_trace::record("reuse-file-fsync", &display);
        }
        Err(error) => return Err(sys_err(display, error)),
    }
    if faults.hit(Fault::ImmutableBeforeDirSync) {
        return Err(injected("immutable-before-dir-sync"));
    }
    dir.fsync().map_err(|e| sys_err(display.clone(), e))?;
    #[cfg(test)]
    commit_trace::record("dir-fsync", &display);
    Ok(())
}

/// Write `bytes` to fixed member `name` beneath the generation `dir` via
/// [`write_immutable`]'s temporary + no-replace install.
fn write_new(
    dir: &DirFd,
    name: &str,
    bytes: &[u8],
    display: PathBuf,
    faults: &super::layout::Faults,
) -> Result<(), PartialStateError> {
    write_immutable(dir, name, bytes, display, faults)
}

/// Persist one immutable artifact beneath `dir/<subdir>` with the same
/// temporary + no-replace semantics as [`write_new`].
pub(crate) fn write_artifact(
    dir: &DirFd,
    subdir: &str,
    name: &str,
    bytes: &[u8],
    faults: &super::layout::Faults,
) -> Result<(), PartialStateError> {
    let path = PathBuf::from(STATE_DIR).join(subdir).join(name);
    let sub = sys::open_dir(dir, subdir.as_bytes()).map_err(|e| sys_err(path.clone(), e))?;
    write_immutable(&sub, name, bytes, path, faults)
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
    // Encode every member and the manifest FIRST: a plan that cannot
    // produce bounded canonical envelopes must fail before any
    // persistence effect, not after artifacts are already on disk.
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
    let generation_display = PathBuf::from(STATE_DIR)
        .join(GENERATIONS_DIR)
        .join(&generation_name);

    if faults.hit(Fault::BeforeData) {
        return Err(injected("data"));
    }
    for (id, bytes) in &plan.objects {
        write_artifact(dir, OBJECTS_DIR, &to_hex(id), bytes, faults)?;
    }
    for (digest, bytes) in &plan.bundles {
        write_artifact(dir, BUNDLES_DIR, &bundle_file_name(digest), bytes, faults)?;
    }
    for (digest, bytes) in &plan.updates {
        write_artifact(dir, UPDATES_DIR, &update_file_name(digest), bytes, faults)?;
    }

    if faults.hit(Fault::BeforeMembers) {
        return Err(injected("members"));
    }
    let generations = sys::open_dir(dir, GENERATIONS_DIR.as_bytes())
        .map_err(|e| sys_err(PathBuf::from(GENERATIONS_DIR), e))?;
    match sys::mkdir(&generations, generation_name.as_bytes(), 0o700) {
        Ok(()) | Err(SysError::AlreadyExists) => {}
        Err(error) => {
            return Err(sys_err(generation_display.clone(), error));
        }
    }
    let generation = sys::open_dir(&generations, generation_name.as_bytes())
        .map_err(|e| sys_err(generation_display.clone(), e))?;
    write_new(
        &generation,
        WORKSPACE_FILE,
        &workspace_bytes,
        generation_display.join(WORKSPACE_FILE),
        faults,
    )?;
    write_new(
        &generation,
        STAGE_FILE,
        &stage_bytes,
        generation_display.join(STAGE_FILE),
        faults,
    )?;
    if let Some(bytes) = &pending_bytes {
        write_new(
            &generation,
            PENDING_FILE,
            bytes,
            generation_display.join(PENDING_FILE),
            faults,
        )?;
    }
    if let Some(bytes) = &accepted_bytes {
        write_new(
            &generation,
            ACCEPTED_FILE,
            bytes,
            generation_display.join(ACCEPTED_FILE),
            faults,
        )?;
    }
    if faults.hit(Fault::BeforeManifest) {
        return Err(injected("manifest"));
    }
    write_new(
        &generation,
        MANIFEST_FILE,
        &manifest_bytes,
        generation_display.join(MANIFEST_FILE),
        faults,
    )?;
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
    #[cfg(test)]
    commit_trace::record("current-rename", &PathBuf::from(CURRENT_FILE));

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

/// `#[cfg(test)]` instrumentation probes for bounds and ordering the
/// type system cannot express: how many caller bytes were cloned into a
/// `replace_stage` feed, and the cap each retained-object read was
/// actually given. Compiled out of non-test builds.
#[cfg(test)]
mod test_instrument {
    use std::cell::{Cell, RefCell};
    use std::path::Path;

    // Thread-local so parallel tests never observe each other's
    // instrumentation: each thread records only its own clones, caps,
    // and growth hooks.
    /// A one-shot file-growth hook keyed by object file name.
    type MutateHook = (String, fn(&Path));

    thread_local! {
        /// Total caller payload bytes cloned into a `replace_stage`
        /// feed on THIS thread — a batch rejected by borrowed preflight
        /// must leave it at zero.
        static FEED_CLONE_BYTES: Cell<usize> = const { Cell::new(0) };
        /// The cap each retained-object read in `load_full` received on
        /// THIS thread.
        static OBJECT_READ_CAPS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
        /// One-shot hook fired between a retained object's
        /// descriptor-length check and its bounded read, only for the
        /// object whose file name matches — the seam where a test can
        /// grow the backing file.
        static OBJECT_READ_MUTATE: RefCell<Option<MutateHook>> = const { RefCell::new(None) };
    }

    pub(crate) fn reset() {
        FEED_CLONE_BYTES.with(|c| c.set(0));
        OBJECT_READ_CAPS.with(|c| c.borrow_mut().clear());
        OBJECT_READ_MUTATE.with(|m| *m.borrow_mut() = None);
    }

    pub(crate) fn note_feed_clone(replacements: &[super::FileReplacement]) {
        let bytes: usize = replacements
            .iter()
            .map(super::FileReplacement::payload_len)
            .sum();
        FEED_CLONE_BYTES.with(|c| c.set(c.get() + bytes));
    }

    pub(crate) fn feed_clone_bytes() -> usize {
        FEED_CLONE_BYTES.with(Cell::get)
    }

    /// `path` is the absolute filesystem path of the retained object —
    /// the hook receives it so a test can grow the file in place.
    pub(crate) fn object_read_probe(path: &Path, cap: usize) {
        OBJECT_READ_CAPS.with(|c| c.borrow_mut().push(cap));
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
        let mutate = OBJECT_READ_MUTATE.with(|m| {
            let mut slot = m.borrow_mut();
            match slot.as_ref() {
                Some((target, _)) if Some(target) == name.as_ref() => slot.take(),
                _ => None,
            }
        });
        if let Some((_, mutate)) = mutate {
            mutate(path);
        }
    }

    pub(crate) fn read_caps() -> Vec<usize> {
        OBJECT_READ_CAPS.with(|c| c.borrow().clone())
    }

    /// Fire `hook` once, on the next retained-object read whose file
    /// name equals `object_name` on this thread.
    pub(crate) fn on_object_read(object_name: String, hook: fn(&Path)) {
        OBJECT_READ_MUTATE.with(|m| *m.borrow_mut() = Some((object_name, hook)));
    }
}

/// Commit `plan` and reload the freshly selected state.
///
/// The complete proposed next state is validated BEFORE `commit` can
/// switch `CURRENT`: bindings, selection coverage, the retained
/// inventory bound, and every staged representation must satisfy the
/// same checks `load_full` enforces on reopen. A transition that would
/// publish a state the reopen validator rejects is refused while the
/// old generation is still authoritative — `CURRENT` never selects an
/// unusable workspace. `local` is the staged-object resolution domain:
/// the stage's retained objects plus any newly produced ones.
pub(crate) fn publish(
    layout: &ScopedWorkspaceLayout,
    plan: &StatePlan,
    verified: &VerifiedPartialSnapshot,
    local: &BTreeMap<Hash, Vec<u8>>,
) -> Result<ScopedWorkspaceState, PartialStateError> {
    preflight_next(plan, verified, local)?;
    commit(layout.state_dir(), &layout.faults, plan)?;
    load_full(layout)
}

/// The retained stage inventory bound shared by pre-publication
/// preflight and reopen: the required set is the canonical object list an
/// update pack would carry, so it is held to the same raw-pack framing
/// budget (`max_raw_pack_bytes`) and object count (`max_update_objects`)
/// `validate_prepared_output` enforces on the producing side — `12 + 32`
/// header/trailer plus `charge_raw_bytes`'s `5 + len` per distinct
/// object. Every required id must resolve inside the stage's retained
/// objects and appear once; a missing, duplicated, or over-budget entry
/// is corruption, not authority.
fn check_required_inventory(
    required: &[Hash],
    limits: &PartialLimits,
    local: &BTreeMap<Hash, Vec<u8>>,
) -> Result<(), PartialStateError> {
    if required.len() > limits.max_update_objects {
        return Err(PartialStateError::NonCanonical("required object count"));
    }
    let mut pack_bytes = 12usize
        .checked_add(32)
        .ok_or(PartialStateError::Partial(PartialError::SubmissionTooLarge))?;
    let mut seen = BTreeSet::new();
    for id in required {
        if !seen.insert(*id) {
            return Err(PartialStateError::NonCanonical(
                "duplicate required object id",
            ));
        }
        let Some(bytes) = local.get(id) else {
            return Err(missing(
                PathBuf::from(STATE_DIR).join(OBJECTS_DIR).join(to_hex(id)),
                "required object",
            ));
        };
        pack_bytes = super::overlay::charge_raw_bytes(pack_bytes, bytes.len(), limits)
            .map_err(PartialStateError::Partial)?;
    }
    Ok(())
}

/// The deterministic local retained-inventory rule, shared by producer
/// persistence and reopen verification: the produced-object set of the
/// representation-preserving overlay MINUS any id whose bytes the
/// verified base snapshot already authenticates — selected-file
/// representations, their complete chunk dependency closure, base Trees,
/// and the base object itself. `stage_feed` resolves a persisted staged
/// id that equals a selected representation through `reuse_selected` —
/// without reading a retained copy — so the caller's `Bytes` versus
/// `ReuseSelected` form never changes what the stage must retain, and a
/// `Bytes` copy of a CHUNKED selected file drops its reproduced chunks
/// exactly like the manifest. A chunk a produced representation shares
/// with a selected one is already base-authenticated and stays
/// resolvable; a chunk only new content needs remains retained. This is
/// a LOCAL storage contract only: the exported MKWU update still lists
/// every changed representation and chunk.
fn retained_inventory(
    verified: &VerifiedPartialSnapshot,
    produced: &BTreeMap<Hash, Vec<u8>>,
) -> BTreeSet<Hash> {
    produced
        .keys()
        .filter(|id| verified.object_bytes(id).is_none())
        .copied()
        .collect()
}

/// Replay `stage` through the representation-preserving feed and return
/// the retained inventory it must declare — the same derivation
/// `replace_stage` applies when persisting it. A clean stage retains
/// nothing.
fn staged_inventory(
    workspace: &WorkspaceStateV1,
    stage: &StageStateV1,
    verified: &VerifiedPartialSnapshot,
    local: &BTreeMap<Hash, Vec<u8>>,
) -> Result<BTreeSet<Hash>, PartialStateError> {
    if stage_is_clean(workspace, stage) {
        return Ok(BTreeSet::new());
    }
    let selection: BTreeMap<&PartialPath, &WorkspaceSelectionV1> = workspace
        .selection
        .iter()
        .map(|entry| (&entry.path, entry))
        .collect();
    let mut feed = Vec::new();
    for entry in &stage.entries {
        if let Some(feed_entry) = stage_feed(&selection, verified, local, &workspace.limits, entry)?
        {
            feed.push(feed_entry);
        }
    }
    let prepared =
        replace_files(verified, &feed, &workspace.limits).map_err(PartialStateError::Partial)?;
    Ok(retained_inventory(verified, &prepared.produced))
}

/// The persisted required inventory must equal what the staged overlay
/// retains — not a superset padded with unrelated objects and not a
/// subset missing produced ancestor trees or staged blobs. Shared by
/// `preflight_next` and `load_full` so no reachable rejection is first
/// discovered after `CURRENT` has switched.
fn check_stage_inventory(
    workspace: &WorkspaceStateV1,
    stage: &StageStateV1,
    verified: &VerifiedPartialSnapshot,
    local: &BTreeMap<Hash, Vec<u8>>,
) -> Result<(), PartialStateError> {
    if stage
        .required_object_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        != staged_inventory(workspace, stage, verified, local)?
    {
        return Err(PartialStateError::NonCanonical(
            "required objects do not match the staged overlay",
        ));
    }
    Ok(())
}

/// The pre-publication validation every transition shares — a subset of
/// `load_full`'s checks applied to the proposed records before they can
/// become authoritative. Member/envelope digests are not re-checked: the
/// commit encodes them itself moments later.
pub(crate) fn preflight_next(
    plan: &StatePlan,
    verified: &VerifiedPartialSnapshot,
    local: &BTreeMap<Hash, Vec<u8>>,
) -> Result<(), PartialStateError> {
    let workspace = &plan.workspace;
    let stage = &plan.stage;
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
    if let Some(pending) = &plan.pending
        && (pending.workspace_id != workspace.workspace_id
            || pending.base_id != workspace.base_id
            || pending.base_revision != workspace.base_revision
            || pending.created_generation > workspace.transaction_generation)
    {
        return Err(PartialStateError::BindingMismatch("pending binding"));
    }
    if let Some(accepted) = &plan.accepted
        && (accepted.workspace_id != workspace.workspace_id
            || accepted.candidate_id != workspace.base_id
            || accepted.accepted_base_revision != workspace.base_revision)
    {
        return Err(PartialStateError::BindingMismatch("accepted binding"));
    }
    if let (Some(pending), Some(accepted)) = (&plan.pending, &plan.accepted)
        && pending.candidate_id == accepted.candidate_id
        && pending.update_digest == accepted.update_digest
    {
        return Err(PartialStateError::BindingMismatch(
            "pending duplicates the accepted outcome",
        ));
    }
    // The retained stage inventory must be internally consistent AND
    // within the raw-pack budget the producing overlay was held to —
    // before any artifact is written.
    check_required_inventory(&stage.required_object_ids, &workspace.limits, local)?;
    validate_stage_representations(workspace, stage, verified, local)?;
    // …and it must equal the deterministic replay inventory `load_full`
    // will require on reopen — an inventory mismatch is caught here,
    // while the old generation is still authoritative.
    check_stage_inventory(workspace, stage, verified, local)
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
    // one — a byte-hash match alone never authenticates content. The
    // inventory is held to the raw-pack budget the producing overlay was
    // charged against: the descriptor's own length must fit the
    // REMAINING allowance before the object is read or retained, so an
    // over-budget file is refused without an over-budget read.
    if stage.required_object_ids.len() > workspace.limits.max_update_objects {
        return Err(PartialStateError::NonCanonical("required object count"));
    }
    let mut local_objects = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut pack_bytes = 12usize
        .checked_add(32)
        .ok_or(PartialStateError::Partial(PartialError::SubmissionTooLarge))?;
    for id in &stage.required_object_ids {
        if !seen.insert(*id) {
            return Err(PartialStateError::NonCanonical(
                "duplicate required object id",
            ));
        }
        let object_path = PathBuf::from(STATE_DIR).join(OBJECTS_DIR).join(to_hex(id));
        let headroom = workspace
            .limits
            .max_raw_pack_bytes
            .checked_sub(pack_bytes + 5)
            .ok_or(PartialStateError::Partial(PartialError::SubmissionTooLarge))?;
        let (file, file_len) = open_artifact_file(dir, OBJECTS_DIR, &to_hex(id))?;
        let file_len = usize::try_from(file_len)
            .map_err(|_| PartialStateError::NonCanonical("artifact length"))?;
        // The actual read is bounded by the SAME cap the descriptor
        // length was checked against — remaining raw-pack headroom,
        // never more — so a file grown after metadata inspection still
        // cannot exceed the aggregate budget.
        let read_cap = headroom.min(workspace.limits.max_object_bytes);
        if file_len > read_cap {
            return Err(PartialStateError::Partial(PartialError::SubmissionTooLarge));
        }
        #[cfg(test)]
        test_instrument::object_read_probe(&layout.root().join(&object_path), read_cap);
        let bytes = file.read_all(read_cap).map_err(|e| match e {
            SysError::Io(e) if e.kind() == io::ErrorKind::InvalidData => {
                PartialStateError::Partial(PartialError::SubmissionTooLarge)
            }
            other => sys_err(object_path.clone(), other),
        })?;
        pack_bytes = super::overlay::charge_raw_bytes(pack_bytes, bytes.len(), &workspace.limits)
            .map_err(PartialStateError::Partial)?;
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

    // The required inventory must equal EXACTLY what the staged overlay
    // retains — the same deterministic rule `replace_stage` persists by
    // and `preflight_next` verifies. A clean stage retains nothing.
    check_stage_inventory(&workspace, &stage, &verified, &local_objects)?;

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

    #[allow(clippy::too_many_lines)] // validate-borrowed → clone → merge feed → publish is one pipeline
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
        // Bound the caller's batch on BORROWED data before any of it is
        // cloned into the feed — the same changed-path, destination,
        // duplicate, per-payload, and aggregate-byte checks
        // `replace_files` itself applies. An over-budget batch is refused
        // without ever becoming an allocation; retained staged entries
        // join the feed one bounded entry at a time from the already
        // validated persisted stage.
        if replacements.len() > limits.max_changed_paths {
            return Err(PartialStateError::Partial(
                PartialError::ValidationBudgetExceeded,
            ));
        }
        let files: BTreeMap<_, _> = state
            .verified
            .files()
            .iter()
            .map(|file| (file.path(), file))
            .collect();
        super::overlay::preflight_replacements(&files, replacements, &limits)
            .map_err(PartialStateError::Partial)?;
        // `reuse_selected` names a verified BASE representation, never a
        // staged one — caller replacements pass through unchanged.
        // Unrelated staged entries are re-fed through `stage_feed`, which
        // preserves a persisted staged id that names a verified selected
        // representation instead of silently re-canonicalizing it.
        let mut feed: Vec<FileReplacement> = {
            #[cfg(test)]
            test_instrument::note_feed_clone(replacements);
            replacements.to_vec()
        };
        let mut replaced: BTreeSet<&PartialPath> = BTreeSet::new();
        for replacement in replacements {
            replaced.insert(replacement.path());
        }
        for entry in &state.stage.entries {
            if replaced.contains(&entry.path) {
                continue;
            }
            if let Some(preserved) = stage_feed(
                &selection,
                &state.verified,
                &state.local_objects,
                &limits,
                entry,
            )? {
                feed.push(preserved);
            }
        }
        if feed.is_empty() {
            return Ok(state);
        }
        let prepared = match replace_files(&state.verified, &feed, &limits) {
            Ok(prepared) => Some(prepared),
            Err(PartialError::NoChanges) => None,
            Err(error) => return Err(PartialStateError::Partial(error)),
        };
        let (next_stage, objects) = match prepared {
            None => (clean_stage(&state), BTreeMap::new()),
            Some(prepared) => {
                let changes: BTreeMap<&PartialPath, Hash> = prepared
                    .changes
                    .iter()
                    .map(|change| (&change.path, change.new_id))
                    .collect();
                // The retained inventory is the deterministic rule
                // `staged_inventory` derives on reopen — produced objects
                // minus ids the verified base already authenticates, so
                // a `Bytes` replacement equal to a selected file's
                // representation persists exactly what its
                // `reuse_selected` equivalent would.
                let retained = retained_inventory(&state.verified, &prepared.produced);
                let objects: BTreeMap<Hash, Vec<u8>> = prepared
                    .produced
                    .into_iter()
                    .filter(|(id, _)| retained.contains(id))
                    .collect();
                (
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
                        required_object_ids: retained.into_iter().collect(),
                    },
                    objects,
                )
            }
        };
        // The staged-object resolution domain for the next stage: the
        // verified base objects plus every retained local object —
        // pre-existing required objects and this transition's produced
        // set alike.
        let mut local = state.local_objects.clone();
        local.extend(objects.iter().map(|(id, bytes)| (*id, bytes.clone())));
        let plan = StatePlan {
            workspace: next_workspace(&state, next_generation),
            stage: next_stage,
            pending: None,
            accepted: state.accepted.clone(),
            objects,
            bundles: Vec::new(),
            updates: Vec::new(),
        };
        publish(self, &plan, &state.verified, &local)
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
            check_prepared_matches_stage(&state, &prepared)?;
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
        check_prepared_matches_stage(&state, &prepared)?;
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
        publish(self, &plan, &state.verified, &state.local_objects)
    }

    /// Pin an existing offline candidate to one exact publication target and
    /// operation. This is a local transaction, before any remote effects.
    pub fn bind_pending_publication(
        &self,
        expected_generation: u64,
        identity: &PendingIdentityV1,
        target: RemotePublicationTargetV1,
        operation_id: [u8; 32],
    ) -> Result<ScopedWorkspaceState, PartialStateError> {
        self.with_lock(|_| {
            let state = load_full(self)?;
            let next_generation = check_generation(&state, expected_generation)?;
            let pending = state
                .pending
                .as_ref()
                .ok_or(PartialStateError::PendingMissing)?;
            if pending.identity() != *identity {
                return Err(PartialStateError::PendingMismatch);
            }
            if !matches!(
                pending.status,
                PendingStatusV1::Prepared | PendingStatusV1::Exported
            ) || pending.operation.is_some()
                || !target.exact_ref().starts_with("refs/heads/")
                || state
                    .workspace
                    .target
                    .as_ref()
                    .is_some_and(|old| old != &target)
            {
                return Err(PartialStateError::InvalidPublicationTransition);
            }
            let mut pending = pending.clone();
            pending.operation = Some(PendingOperationV1 {
                operation_id,
                request_fingerprint: publication_fingerprint(&target, &pending, &operation_id),
            });
            let mut workspace = next_workspace(&state, next_generation);
            workspace.target = Some(target);
            let plan = StatePlan {
                workspace,
                stage: state.stage.clone(),
                pending: Some(pending),
                accepted: state.accepted.clone(),
                objects: BTreeMap::new(),
                bundles: Vec::new(),
                updates: Vec::new(),
            };
            publish(self, &plan, &state.verified, &state.local_objects)
        })
    }

    /// Durable write-ahead barrier. Only its successful return authorizes a
    /// caller to invoke one remote publication attempt.
    pub fn begin_publication(
        &self,
        expected_generation: u64,
        identity: &PendingIdentityV1,
    ) -> Result<ScopedWorkspaceState, PartialStateError> {
        self.with_lock(|_| {
            let state = load_full(self)?;
            let next_generation = check_generation(&state, expected_generation)?;
            let pending = state
                .pending
                .as_ref()
                .ok_or(PartialStateError::PendingMissing)?;
            if pending.identity() != *identity {
                return Err(PartialStateError::PendingMismatch);
            }
            let target = state
                .workspace
                .target
                .as_ref()
                .ok_or(PartialStateError::InvalidPublicationTransition)?;
            let operation = pending
                .operation
                .ok_or(PartialStateError::InvalidPublicationTransition)?;
            if !matches!(
                pending.status,
                PendingStatusV1::Prepared | PendingStatusV1::Exported
            ) || publication_fingerprint(target, pending, &operation.operation_id)
                != operation.request_fingerprint
            {
                return Err(PartialStateError::InvalidPublicationTransition);
            }
            let mut pending = pending.clone();
            pending.status = PendingStatusV1::Unknown;
            let plan = StatePlan {
                workspace: next_workspace(&state, next_generation),
                stage: state.stage.clone(),
                pending: Some(pending),
                accepted: state.accepted.clone(),
                objects: BTreeMap::new(),
                bundles: Vec::new(),
                updates: Vec::new(),
            };
            publish(self, &plan, &state.verified, &state.local_objects)
        })
    }

    /// Explicitly release the one-pending slot. This changes no working file,
    /// stage entry or immutable historical artifact, and cannot undo a remote
    /// effect that may have occurred.
    pub fn abandon_pending(
        &self,
        expected_generation: u64,
        candidate_id: &Hash,
        acknowledge_possible_publication: bool,
    ) -> Result<ScopedWorkspaceState, PartialStateError> {
        if !acknowledge_possible_publication {
            return Err(PartialStateError::InvalidPublicationTransition);
        }
        self.with_lock(|_| {
            let state = load_full(self)?;
            let next_generation = check_generation(&state, expected_generation)?;
            let pending = state
                .pending
                .as_ref()
                .ok_or(PartialStateError::PendingMissing)?;
            if &pending.candidate_id != candidate_id {
                return Err(PartialStateError::PendingMismatch);
            }
            let plan = StatePlan {
                workspace: next_workspace(&state, next_generation),
                stage: state.stage.clone(),
                pending: None,
                accepted: state.accepted.clone(),
                objects: BTreeMap::new(),
                bundles: Vec::new(),
                updates: Vec::new(),
            };
            publish(self, &plan, &state.verified, &state.local_objects)
        })
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
        // Even equal-status calls must observe the caller's generation. An
        // idempotent response is never permission for a stale sender to act.
        let next_generation = check_generation(&state, expected_generation)?;
        if (outcome == PendingOutcomeV1::Prepared && pending.status != PendingStatusV1::Prepared)
            || (outcome == PendingOutcomeV1::Exported
                && !matches!(
                    pending.status,
                    PendingStatusV1::Prepared | PendingStatusV1::Exported
                ))
        {
            return Err(PartialStateError::InvalidPublicationTransition);
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
        publish(self, &plan, &state.verified, &state.local_objects)
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
        // The accepted stage is clean on the candidate's freshly verified
        // snapshot — no retained objects are required.
        publish(self, &plan, &new_verified, &BTreeMap::new())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::AsRawFd;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;
    use std::time::Duration;

    use tempfile::tempdir;

    use crate::hash::to_hex;
    use crate::object::{EntryMode, Object, Tree, TreeEntry, id_from_object, object_id_from_bytes};
    use crate::partial::layout::{Fault, Faults, LOCK_FILE, STATE_DIR, lock_gate};
    use crate::partial::overlay::FileReplacement;
    use crate::partial::sys::{self, OpenMode};
    use crate::partial::verify::build_partial_snapshot;
    use crate::partial::{
        PartialError, PartialLimits, PendingOutcomeV1, export_partial_update,
        prepare_partial_commit, replace_files,
    };
    use crate::serialize;
    use crate::sign::{KeyPair, sign_commit, sign_remix};
    use crate::store::ObjectStore;
    use crate::{Identity, Remix, RepoLayout};

    use super::{
        AcceptedStateV1, CURRENT_TMP_COUNTER, PartialStateError, PendingStateV1, PendingStatusV1,
        ScopedWorkspaceLayout, StatePlan, commit, test_instrument,
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

    fn offline_pending(
        layout: &ScopedWorkspaceLayout,
    ) -> (crate::object::Commit, crate::object::Commit, Vec<u8>) {
        let staged = layout.replace_stage(0, &[edit()]).unwrap();
        let prepared = staged.prepare_staged_edit().unwrap();
        let key = KeyPair::from_seed([9; 32]);
        let unsigned = prepare_partial_commit(
            staged.verified(),
            &prepared,
            Identity::ed25519(key.public.0),
            key.public.0,
            b"offline".to_vec(),
            2,
            staged.workspace().limits(),
        )
        .unwrap();
        let mut signed = unsigned.clone();
        signed.signature = sign_commit(&signed, &key).unwrap().0;
        let update = export_partial_update(
            staged.verified(),
            &prepared,
            &unsigned,
            &signed,
            staged.workspace().limits(),
        )
        .unwrap();
        let bytes = update.encode(staged.workspace().limits()).unwrap();
        layout
            .save_pending(1, &unsigned, &signed, &bytes, None)
            .unwrap();
        (unsigned, signed, bytes)
    }

    #[test]
    fn late_bind_begin_unknown_and_abandon_preserve_stage() {
        let (dir, layout) = fixture();
        let (unsigned, signed, bytes) = offline_pending(&layout);
        let state = layout.read_state().unwrap();
        assert_eq!(state.pending_update_bytes(), Some(bytes.as_slice()));
        let old_id = state.pending().unwrap().identity();
        let target = super::RemotePublicationTargetV1::new(
            "mkit+file:///tmp/recipient",
            "repo",
            "refs/heads/main",
        )
        .unwrap();
        let bound = layout
            .bind_pending_publication(2, &old_id, target.clone(), [7; 32])
            .unwrap();
        assert_eq!(bound.workspace().target(), Some(&target));
        let identity = bound.pending().unwrap().identity();
        assert!(identity.operation().is_some());
        let unknown = layout.begin_publication(3, &identity).unwrap();
        assert_eq!(
            unknown.pending().unwrap().status(),
            PendingStatusV1::Unknown
        );
        let reopened = ScopedWorkspaceLayout::open(&dir.path().join("ws")).unwrap();
        assert!(matches!(
            reopened.begin_publication(4, &identity),
            Err(PartialStateError::InvalidPublicationTransition)
        ));
        assert!(matches!(
            reopened.begin_publication(3, &identity),
            Err(PartialStateError::GenerationMismatch { .. })
        ));
        assert!(matches!(
            reopened.record_outcome(3, &identity, PendingOutcomeV1::Unknown),
            Err(PartialStateError::GenerationMismatch { .. })
        ));
        assert!(matches!(
            reopened.record_outcome(4, &identity, PendingOutcomeV1::Exported),
            Err(PartialStateError::InvalidPublicationTransition)
        ));
        assert!(matches!(
            reopened.save_pending(4, &unsigned, &signed, &bytes, None),
            Err(PartialStateError::PendingConflict)
        ));
        let abandoned = reopened
            .abandon_pending(4, &identity.candidate_id, true)
            .unwrap();
        assert!(abandoned.pending().is_none());
        assert!(!abandoned.stage_is_clean());
        assert_eq!(abandoned.workspace().base_revision(), 0);
        assert!(
            dir.path()
                .join("ws/.mkit-scoped/updates")
                .join(format!("{}.mkwu", to_hex(&identity.update_digest)))
                .exists()
        );
    }

    #[test]
    fn begin_durability_fault_never_authorizes_remote_effect() {
        let (_dir, layout) = fixture();
        offline_pending(&layout);
        let old_id = layout.read_state().unwrap().pending().unwrap().identity();
        let target = super::RemotePublicationTargetV1::new(
            "mkit+file:///tmp/recipient",
            "repo",
            "refs/heads/main",
        )
        .unwrap();
        let bound = layout
            .bind_pending_publication(2, &old_id, target, [7; 32])
            .unwrap();
        let identity = bound.pending().unwrap().identity();
        layout.faults.arm(Fault::BeforeCurrentSwitch);
        assert!(layout.begin_publication(3, &identity).is_err());
        assert_eq!(
            layout.read_state().unwrap().pending().unwrap().status(),
            PendingStatusV1::Prepared
        );
        layout.faults.arm(Fault::AfterCurrentSwitch);
        assert!(matches!(
            layout.begin_publication(3, &identity),
            Err(PartialStateError::DurabilityUncertain(_))
        ));
        // The CURRENT switch may have happened, but uncertainty blocks the
        // caller from invoking a transport. Reopen never treats it as safe.
        assert_eq!(
            layout.read_state().unwrap().pending().unwrap().status(),
            PendingStatusV1::Unknown
        );
        assert!(layout.begin_publication(4, &identity).is_err());
    }

    #[test]
    fn concurrent_begin_allows_one_effect_permission() {
        let (_dir, layout) = fixture();
        offline_pending(&layout);
        let old_id = layout.read_state().unwrap().pending().unwrap().identity();
        let target = super::RemotePublicationTargetV1::new(
            "mkit+file:///tmp/recipient",
            "repo",
            "refs/heads/main",
        )
        .unwrap();
        let bound = layout
            .bind_pending_publication(2, &old_id, target, [7; 32])
            .unwrap();
        let identity = bound.pending().unwrap().identity();
        let shared = Arc::new(layout);
        let start = Arc::new(std::sync::Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let layout = Arc::clone(&shared);
            let start = Arc::clone(&start);
            let identity = identity.clone();
            handles.push(std::thread::spawn(move || {
                start.wait();
                layout.begin_publication(3, &identity).is_ok()
            }));
        }
        start.wait();
        let permissions = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|allowed| *allowed)
            .count();
        assert_eq!(
            permissions, 1,
            "only one caller can enter a remote effect path"
        );
        assert_eq!(
            shared.read_state().unwrap().pending().unwrap().status(),
            PendingStatusV1::Unknown
        );
    }

    #[test]
    fn publication_fingerprint_matches_committed_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/golden/partial_publication/request_v1.json"
        ))
        .unwrap();
        let target = super::RemotePublicationTargetV1::new(
            vector["endpoint"].as_str().unwrap(),
            vector["repository"].as_str().unwrap(),
            vector["exact_ref"].as_str().unwrap(),
        )
        .unwrap();
        let pending = PendingStateV1 {
            workspace_id: [0; 32],
            base_id: [1; 32],
            base_revision: 0,
            created_generation: 1,
            candidate_id: [2; 32],
            update_digest: [3; 32],
            update_length: 7,
            status: PendingStatusV1::Prepared,
            operation: None,
        };
        assert_eq!(
            to_hex(&super::publication_fingerprint(&target, &pending, &[4; 32])),
            vector["fingerprint"].as_str().unwrap(),
        );
    }

    #[test]
    fn export_binds_identity_and_never_clobbers_or_downgrades_unknown() {
        let (dir, layout) = fixture();
        let (_unsigned, _signed, bytes) = offline_pending(&layout);
        let state = layout.read_state().unwrap();
        let identity = state.pending().unwrap().identity();
        let outside = tempdir().unwrap();
        let outside_real = outside.path().canonicalize().unwrap();
        let target = outside_real.join("update.mkwu");
        assert_eq!(
            layout.export_pending_to(2, &identity, &target).unwrap(),
            bytes.len()
        );
        assert_eq!(std::fs::read(&target).unwrap(), bytes);
        assert!(layout.export_pending_to(2, &identity, &target).is_err());
        assert!(
            layout
                .export_pending_to(2, &identity, &dir.path().join("ws/file.txt"))
                .is_err()
        );
        let ordinary = tempdir().unwrap();
        let _ordinary_store = ObjectStore::init(&RepoLayout::single(ordinary.path())).unwrap();
        let ordinary_real = ordinary.path().canonicalize().unwrap();
        std::fs::create_dir_all(ordinary_real.join(".mkit/refs")).unwrap();
        let metadata_output = ordinary_real.join(".mkit/refs/update.mkwu");
        assert!(
            layout
                .export_pending_to(2, &identity, &metadata_output)
                .is_err()
        );
        assert!(!metadata_output.exists());
        let alias_output = ordinary_real.join(".MKIT/refs/alias.mkwu");
        assert!(
            layout
                .export_pending_to(2, &identity, &alias_output)
                .is_err()
        );
        assert!(!ordinary_real.join(".mkit/refs/alias.mkwu").exists());
        // On normalization-insensitive filesystems this differently spelled
        // component may resolve to the same metadata directory. The export
        // guard also compares opened ancestor identities, not just spelling.
        let normalized_alias = ordinary_real.join(".m\u{212a}it/refs/normalized.mkwu");
        if normalized_alias.parent().unwrap().is_dir() {
            assert!(
                layout
                    .export_pending_to(2, &identity, &normalized_alias)
                    .is_err()
            );
            assert!(!ordinary_real.join(".mkit/refs/normalized.mkwu").exists());
        }
        let reserved_leaf = outside_real.join(".mkit");
        assert!(
            layout
                .export_pending_to(2, &identity, &reserved_leaf)
                .is_err()
        );
        assert!(!reserved_leaf.exists());
        let mixed_case_leaf = outside_real.join(".MkIt-ScOpEd");
        assert!(
            layout
                .export_pending_to(2, &identity, &mixed_case_leaf)
                .is_err()
        );
        assert!(!mixed_case_leaf.exists());
        let ordinary_worktree_output = ordinary_real.join("update.mkwu");
        assert_eq!(
            layout
                .export_pending_to(2, &identity, &ordinary_worktree_output)
                .unwrap(),
            bytes.len()
        );
        assert_eq!(std::fs::read(ordinary_worktree_output).unwrap(), bytes);
        assert_eq!(
            layout.read_state().unwrap().pending().unwrap().status(),
            PendingStatusV1::Prepared
        );
        let (other_dir, _other_layout) = fixture();
        assert!(
            layout
                .export_pending_to(2, &identity, &other_dir.path().join("ws/update.mkwu"))
                .is_err()
        );
        std::os::unix::fs::symlink(outside.path(), dir.path().join("alias")).unwrap();
        assert!(
            layout
                .export_pending_to(2, &identity, &dir.path().join("alias/other.mkwu"))
                .is_err()
        );

        let target = super::RemotePublicationTargetV1::new(
            "mkit+file:///tmp/recipient",
            "repo",
            "refs/heads/main",
        )
        .unwrap();
        let bound = layout
            .bind_pending_publication(2, &identity, target, [7; 32])
            .unwrap();
        let bound_id = bound.pending().unwrap().identity();
        layout.begin_publication(3, &bound_id).unwrap();
        // The old identity/generation cannot export a different candidate or
        // silently claim the old state. A fresh export is still exact bytes.
        assert!(matches!(
            layout.export_pending_to(2, &identity, &outside_real.join("stale.mkwu")),
            Err(PartialStateError::GenerationMismatch { .. })
        ));
        let fresh = outside_real.join("unknown.mkwu");
        assert_eq!(
            layout.export_pending_to(4, &bound_id, &fresh).unwrap(),
            bytes.len()
        );
        assert_eq!(std::fs::read(fresh).unwrap(), bytes);
        let uncertain = outside_real.join("uncertain.mkwu");
        layout.faults.arm(Fault::ExportBeforeDirSync);
        assert!(matches!(
            layout.export_pending_to(4, &bound_id, &uncertain),
            Err(PartialStateError::DurabilityUncertain(_))
        ));
        assert_eq!(std::fs::read(uncertain).unwrap(), bytes);
        assert_eq!(
            layout.read_state().unwrap().pending().unwrap().status(),
            PendingStatusV1::Unknown
        );
    }

    #[test]
    fn acceptance_sync_fault_preserves_replay_identity() {
        let (_dir, layout) = fixture();
        offline_pending(&layout);
        let old = layout.read_state().unwrap().pending().unwrap().identity();
        let target = super::RemotePublicationTargetV1::new(
            "mkit+file:///tmp/recipient",
            "repo",
            "refs/heads/main",
        )
        .unwrap();
        let bound = layout
            .bind_pending_publication(2, &old, target, [7; 32])
            .unwrap();
        let identity = bound.pending().unwrap().identity();
        layout.begin_publication(3, &identity).unwrap();
        // Simulate a definite transport success followed by an interrupted
        // local acceptance record. Only the same identity may replay.
        layout.faults.arm(Fault::AfterCurrentSwitch);
        assert!(matches!(
            layout.record_outcome(4, &identity, PendingOutcomeV1::Accepted),
            Err(PartialStateError::DurabilityUncertain(_))
        ));
        let reopened = layout.read_state().unwrap();
        assert!(reopened.pending().is_none());
        assert_eq!(reopened.workspace().base_revision(), 1);
        assert!(
            layout
                .record_outcome(5, &identity, PendingOutcomeV1::Accepted)
                .is_ok()
        );
        let mut wrong = identity;
        wrong.candidate_id = [0xff; 32];
        assert!(
            layout
                .record_outcome(5, &wrong, PendingOutcomeV1::Accepted)
                .is_err()
        );
    }

    /// Selected root files with caller-chosen base contents — the
    /// fixture the complete-stage and inventory checks need.
    fn named_fixture(
        files: &[(&[u8], &[u8])],
        limits: PartialLimits,
    ) -> (tempfile::TempDir, ScopedWorkspaceLayout) {
        let repo = tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(repo.path())).unwrap();
        let mut entries = Vec::new();
        for (name, data) in files {
            let blob_bytes = serialize(&Object::Blob(crate::object::Blob {
                data: data.to_vec(),
            }))
            .unwrap();
            let blob = store.write(&blob_bytes).unwrap();
            entries.push(TreeEntry {
                name: name.to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            });
        }
        let tree = Object::Tree(Tree { entries });
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
        let paths: Vec<Vec<Vec<u8>>> = files.iter().map(|(name, _)| vec![name.to_vec()]).collect();
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

    /// Two selected root files `a.txt`/`b.txt` with caller-chosen base
    /// contents — the fixture the complete-stage total checks need.
    fn two_file_fixture(
        a: &[u8],
        b: &[u8],
        limits: PartialLimits,
    ) -> (tempfile::TempDir, ScopedWorkspaceLayout) {
        named_fixture(&[(b"a.txt", a), (b"b.txt", b)], limits)
    }

    /// Deterministic non-constant bytes so `FastCDC` sees real boundary
    /// candidates instead of one max-sized chunk.
    fn splitmix_bytes(n: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            out.push((z & 0xFF) as u8);
        }
        out
    }

    /// Like [`named_fixture`] but stores each file through the canonical
    /// worktree writer — content above `CHUNK_THRESHOLD` becomes a real
    /// `ChunkedBlob` manifest plus chunk Blobs exactly as a checked-in
    /// file would be stored.
    fn canonical_named_fixture(
        files: &[(&[u8], &[u8])],
        limits: PartialLimits,
    ) -> (tempfile::TempDir, ScopedWorkspaceLayout) {
        let repo = tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(repo.path())).unwrap();
        let mut entries = Vec::new();
        for (name, data) in files {
            let id = crate::worktree::store_file_object(&store, data).unwrap();
            entries.push(TreeEntry {
                name: name.to_vec(),
                mode: EntryMode::Blob,
                object_hash: id,
            });
        }
        let tree = Object::Tree(Tree { entries });
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
        let paths: Vec<Vec<Vec<u8>>> = files.iter().map(|(name, _)| vec![name.to_vec()]).collect();
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

    fn current_bytes(layout: &ScopedWorkspaceLayout) -> Vec<u8> {
        std::fs::read(layout.root().join(".mkit-scoped/CURRENT")).unwrap()
    }

    fn staged_id(state: &super::ScopedWorkspaceState, path: &[u8]) -> crate::hash::Hash {
        *state
            .stage()
            .entries()
            .iter()
            .find(|entry| entry.path() == &vec![path.to_vec()])
            .unwrap()
            .staged_id()
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

    /// A panic inside the critical section must release the kernel lock:
    /// the operation descriptor is closed by unwind, so an independently
    /// opened handle proceeds instead of blocking on a stranded flock.
    #[test]
    fn panic_inside_critical_section_releases_the_operation_lock() {
        let (_dir, layout) = fixture();
        let root = layout.root().to_path_buf();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = layout.with_lock(|_| -> Result<(), PartialStateError> {
                panic!("critical section panic");
            });
        }));
        assert!(panicked.is_err());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let other = ScopedWorkspaceLayout::open(&root).unwrap();
            tx.send(other.replace_stage(0, &[edit()]).is_ok()).unwrap();
        });
        assert!(
            matches!(
                rx.recv_timeout(std::time::Duration::from_secs(10)),
                Ok(true)
            ),
            "panic inside the critical section left the workspace lock held"
        );
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

    /// An armed partial-write abort must leave only a `.tmp` orphan —
    /// never torn bytes at the canonical object name — so a retry of the
    /// SAME transition installs cleanly instead of wedging on
    /// `CorruptArtifact`.
    #[test]
    fn immutable_partial_write_fault_leaves_only_tmp_orphans() {
        let (_dir, layout) = fixture();
        let objects = layout.root().join(".mkit-scoped/objects");
        layout.faults.arm(Fault::ImmutablePartialWrite);
        assert!(layout.replace_stage(0, &[edit()]).is_err());
        let state = layout.read_state().unwrap();
        assert_eq!(state.workspace().transaction_generation(), 0);
        assert!(state.stage_is_clean());
        let orphans: Vec<_> = objects
            .read_dir()
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(
            !orphans.is_empty(),
            "the torn temporary must be retained as an orphan"
        );
        assert!(
            orphans
                .iter()
                .all(|name| name.to_string_lossy().starts_with('.')),
            "no canonical artifact name may appear from a torn write: {orphans:?}"
        );
        // Retry of the same transition succeeds and publishes gen 1.
        layout.replace_stage(0, &[edit()]).unwrap();
        assert_eq!(
            layout
                .read_state()
                .unwrap()
                .workspace()
                .transaction_generation(),
            1
        );
    }

    /// The same torn-write coverage for a generation MEMBER: a plan with
    /// no artifacts makes workspace.bin the first immutable write — the
    /// abort must leave every canonical member name untouched.
    #[test]
    fn immutable_member_partial_write_fault_retries_cleanly() {
        let (_dir, layout) = fixture();
        let state = layout.read_state().unwrap();
        let mut workspace = state.workspace.clone();
        workspace.transaction_generation += 1;
        let plan = StatePlan {
            workspace,
            stage: state.stage.clone(),
            pending: state.pending.clone(),
            accepted: state.accepted.clone(),
            objects: BTreeMap::new(),
            bundles: Vec::new(),
            updates: Vec::new(),
        };
        let faults = Faults::new();
        faults.arm(Fault::ImmutablePartialWrite);
        assert!(commit(layout.state_dir(), &faults, &plan).is_err());
        assert_eq!(
            layout
                .read_state()
                .unwrap()
                .workspace()
                .transaction_generation(),
            0
        );
        commit(layout.state_dir(), &Faults::new(), &plan).unwrap();
        assert_eq!(
            layout
                .read_state()
                .unwrap()
                .workspace()
                .transaction_generation(),
            1
        );
    }

    /// A pre-existing identical immutable file (a completed earlier
    /// attempt whose directory sync never happened) must have its file
    /// and directory durability established on retry BEFORE the new
    /// CURRENT may rely on it — identical bytes are not proof of sync.
    #[test]
    fn immutable_dir_sync_fault_retry_establishes_durability() {
        let (_dir, layout) = fixture();
        layout.faults.arm(Fault::ImmutableBeforeDirSync);
        assert!(layout.replace_stage(0, &[edit()]).is_err());
        // The rename already landed: exactly one canonical artifact
        // exists while CURRENT still selects generation 0.
        let objects = layout.root().join(".mkit-scoped/objects");
        let installed: Vec<_> = objects
            .read_dir()
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| !name.to_string_lossy().starts_with('.'))
            .collect();
        assert_eq!(
            installed.len(),
            1,
            "exactly one artifact may be installed before the dir-sync fault: {installed:?}"
        );
        assert_eq!(
            layout
                .read_state()
                .unwrap()
                .workspace()
                .transaction_generation(),
            0
        );
        super::commit_trace::take();
        layout.replace_stage(0, &[edit()]).unwrap();
        let trace = super::commit_trace::take();
        let object_path = format!(".mkit-scoped/objects/{}", installed[0].to_string_lossy());
        let position = |kind: &'static str| {
            trace
                .iter()
                .position(|(k, path)| *k == kind && *path == object_path)
                .unwrap_or_else(|| panic!("{kind} for {object_path} not in {trace:?}"))
        };
        let reuse_verify = position("reuse-verify");
        let reuse_file_fsync = position("reuse-file-fsync");
        let dir_fsync = position("dir-fsync");
        let current = trace
            .iter()
            .position(|(k, _)| *k == "current-rename")
            .expect("current rename must be traced");
        assert!(
            reuse_verify < reuse_file_fsync && reuse_file_fsync < dir_fsync && dir_fsync < current,
            "reused artifact durability must be established before CURRENT: {trace:?}"
        );
    }

    /// Abort after the temporary's full bytes are written but before its
    /// file sync: the canonical name must not exist, and the retry must
    /// run the complete write→fsync→install→dir-fsync sequence.
    #[test]
    fn immutable_file_sync_fault_retry_runs_full_sequence() {
        let (_dir, layout) = fixture();
        layout.faults.arm(Fault::ImmutableBeforeFileSync);
        assert!(layout.replace_stage(0, &[edit()]).is_err());
        let objects = layout.root().join(".mkit-scoped/objects");
        let names: Vec<_> = objects
            .read_dir()
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(
            names
                .iter()
                .all(|name| name.to_string_lossy().starts_with('.')),
            "no canonical name may appear before the rename: {names:?}"
        );
        super::commit_trace::take();
        layout.replace_stage(0, &[edit()]).unwrap();
        let trace = super::commit_trace::take();
        let object_path = ".mkit-scoped/objects/";
        let kinds: Vec<&'static str> = trace
            .iter()
            .filter(|(_, path)| path.starts_with(object_path))
            .map(|(kind, _)| *kind)
            .collect();
        assert_eq!(
            kinds[..4],
            ["temp-write", "file-fsync", "install", "dir-fsync"],
            "retry must run the complete immutable sequence: {trace:?}"
        );
    }

    /// Genuinely different bytes at a canonical artifact name remain
    /// corruption — the atomic install never overwrites or "repairs".
    #[test]
    fn conflicting_immutable_file_is_refused() {
        let (_dir, layout) = fixture();
        let blob = Object::Blob(crate::object::Blob {
            data: b"edited".to_vec(),
        });
        let id = id_from_object(&blob, &serialize(&blob).unwrap());
        let canonical = layout
            .root()
            .join(format!(".mkit-scoped/objects/{}", to_hex(&id)));
        std::fs::write(&canonical, b"poison").unwrap();
        assert!(matches!(
            layout.replace_stage(0, &[edit()]),
            Err(PartialStateError::CorruptArtifact { .. })
        ));
        // The conflicting bytes are preserved for inspection, never
        // overwritten by the transition.
        assert_eq!(std::fs::read(&canonical).unwrap(), b"poison");
    }

    /// Republish a crafted generation through the real `commit` path:
    /// clone the current state into a plan, bump the generation, mutate,
    /// and commit. Used to build states no honest transition produces.
    fn republish(layout: &ScopedWorkspaceLayout, mutate: impl FnOnce(&mut StatePlan)) {
        let state = layout.read_state().unwrap();
        republish_from(&state, layout, mutate);
    }

    /// Republish derived from a captured state — for cases where the
    /// CURRENT-selected state is intentionally no longer loadable.
    fn republish_from(
        state: &super::ScopedWorkspaceState,
        layout: &ScopedWorkspaceLayout,
        mutate: impl FnOnce(&mut StatePlan),
    ) {
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

    // -- pre-publication validation of the COMPLETE next state ----------

    /// The reviewed failure: a stage whose REPLACEMENT bytes fit but
    /// whose complete selected total exceeds the limit must be rejected
    /// before CURRENT moves — never published and then discovered
    /// unloadable.
    #[test]
    fn over_budget_complete_stage_is_rejected_before_publish() {
        let limits = PartialLimits {
            max_total_selected_bytes: 10,
            ..PartialLimits::V1
        };
        // 4 + 4 selected bytes fit; staging a 7-byte replacement would
        // make the selected total 11.
        let (_dir, layout) = two_file_fixture(b"aaaa", b"bbbb", limits);
        let before = current_bytes(&layout);
        let result = layout.replace_stage(
            0,
            &[FileReplacement::bytes(
                vec![b"a.txt".to_vec()],
                b"1234567".to_vec(),
            )],
        );
        assert!(
            matches!(
                result,
                Err(PartialStateError::Partial(PartialError::WorkspaceTooLarge))
            ),
            "expected WorkspaceTooLarge, got {result:?}"
        );
        // The failed call changed nothing: identical CURRENT bytes,
        // generation, base, clean stage, no pending — and the prior
        // state still reopens.
        assert_eq!(current_bytes(&layout), before);
        let reopened = ScopedWorkspaceLayout::open(layout.root()).unwrap();
        let state = reopened.read_state().unwrap();
        assert_eq!(state.workspace().transaction_generation(), 0);
        assert!(state.stage_is_clean());
        assert!(state.pending().is_none());
        assert!(state.accepted().is_none());
    }

    /// The boundary case: a complete stage totaling exactly
    /// `max_total_selected_bytes` must publish.
    #[test]
    fn exact_budget_complete_stage_publishes() {
        let limits = PartialLimits {
            max_total_selected_bytes: 10,
            ..PartialLimits::V1
        };
        let (_dir, layout) = two_file_fixture(b"aaaa", b"bbbb", limits);
        // 6 + 4 = 10 == the limit.
        let state = layout
            .replace_stage(
                0,
                &[FileReplacement::bytes(
                    vec![b"a.txt".to_vec()],
                    b"123456".to_vec(),
                )],
            )
            .unwrap();
        assert_eq!(state.workspace().transaction_generation(), 1);
        let reopened = ScopedWorkspaceLayout::open(layout.root()).unwrap();
        assert_eq!(
            reopened
                .read_state()
                .unwrap()
                .workspace()
                .transaction_generation(),
            1
        );
    }

    /// A rejected later stage leaves earlier unrelated staged entries —
    /// and the generation — exactly as the last good publish left them.
    #[test]
    fn rejected_second_stage_preserves_unrelated_entries() {
        let limits = PartialLimits {
            max_total_selected_bytes: 10,
            ..PartialLimits::V1
        };
        let (_dir, layout) = two_file_fixture(b"aaaa", b"bbbb", limits);
        let staged_a = layout
            .replace_stage(
                0,
                &[FileReplacement::bytes(
                    vec![b"a.txt".to_vec()],
                    b"aa".to_vec(),
                )],
            )
            .unwrap();
        let a_id = staged_id(&staged_a, b"a.txt");
        let before = current_bytes(&layout);
        // Staged total would become 2 + 9 = 11 — rejected.
        let result = layout.replace_stage(
            1,
            &[FileReplacement::bytes(
                vec![b"b.txt".to_vec()],
                b"123456789".to_vec(),
            )],
        );
        assert!(matches!(
            result,
            Err(PartialStateError::Partial(PartialError::WorkspaceTooLarge))
        ));
        assert_eq!(current_bytes(&layout), before);
        let state = layout.read_state().unwrap();
        assert_eq!(state.workspace().transaction_generation(), 1);
        assert_eq!(staged_id(&state, b"a.txt"), a_id);
        // And the in-budget retry of the second file still works.
        let state = layout
            .replace_stage(
                1,
                &[FileReplacement::bytes(
                    vec![b"b.txt".to_vec()],
                    b"12345678".to_vec(),
                )],
            )
            .unwrap();
        assert_eq!(state.workspace().transaction_generation(), 2);
        assert_eq!(staged_id(&state, b"a.txt"), a_id);
    }

    // -- staged representation validation BEFORE materialization --------

    /// Write `objects` as stage artifacts and point the stage's single
    /// entry at `staged`, retaining `required` as the inventory. This is
    /// the malformed-but-checksummed local state a hostile `.mkit-scoped`
    /// write can produce.
    fn craft_stage(
        layout: &ScopedWorkspaceLayout,
        staged: crate::hash::Hash,
        mut required: Vec<crate::hash::Hash>,
        objects: Vec<(crate::hash::Hash, Vec<u8>)>,
    ) {
        required.sort_unstable();
        republish(layout, |plan| {
            plan.stage.entries[0].staged_id = staged;
            plan.stage.required_object_ids = required;
            plan.objects = objects.into_iter().collect();
        });
    }

    fn put_object(object: &Object) -> (crate::hash::Hash, Vec<u8>) {
        let bytes = serialize(object).unwrap();
        (id_from_object(object, &bytes), bytes)
    }

    /// A `ChunkedBlob` declaring `total_size = 1` whose first occurrence
    /// already overflows must fail at occurrence zero — the SECOND chunk
    /// id does not exist at all, so any read of it (a concatenate-first
    /// validator) would surface a missing-object error instead of the
    /// layout error.
    #[test]
    fn staged_chunked_declared_total_stops_at_first_overrun() {
        let (_dir, layout) = fixture();
        let (chunk_id, chunk_bytes) = put_object(&Object::Blob(crate::object::Blob {
            data: b"1234".to_vec(),
        }));
        let manifest = Object::ChunkedBlob(crate::object::ChunkedBlob {
            total_size: 1,
            chunk_size: 0,
            chunks: vec![chunk_id, [0xEE; 32]],
        });
        let (manifest_id, manifest_bytes) = put_object(&manifest);
        craft_stage(
            &layout,
            manifest_id,
            vec![manifest_id, chunk_id],
            vec![(manifest_id, manifest_bytes), (chunk_id, chunk_bytes)],
        );
        let result = layout.read_state();
        assert!(
            matches!(
                result,
                Err(PartialStateError::Partial(PartialError::InvalidChunkLayout))
            ),
            "occurrence 0 overflows the declared total; a late validator \
             would instead fail reading the nonexistent second chunk — got {result:?}"
        );
    }

    /// A fixed-size manifest whose occurrences sum to the declared total
    /// but violate the per-occurrence fixed rule is rejected — the
    /// matching aggregate cannot launder an invalid layout.
    #[test]
    fn staged_chunked_fixed_layout_rejects_despite_matching_aggregate() {
        let (_dir, layout) = fixture();
        let (short_id, short_bytes) = put_object(&Object::Blob(crate::object::Blob {
            data: b"12".to_vec(),
        }));
        let (long_id, long_bytes) = put_object(&Object::Blob(crate::object::Blob {
            data: b"123456".to_vec(),
        }));
        // Fixed size 4: occurrence 0 is non-final with actual 2 — the
        // aggregate 2 + 6 = 8 matches the declared total exactly.
        let manifest = Object::ChunkedBlob(crate::object::ChunkedBlob {
            total_size: 8,
            chunk_size: 4,
            chunks: vec![short_id, long_id],
        });
        let (manifest_id, manifest_bytes) = put_object(&manifest);
        craft_stage(
            &layout,
            manifest_id,
            vec![manifest_id, short_id, long_id],
            vec![
                (manifest_id, manifest_bytes),
                (short_id, short_bytes),
                (long_id, long_bytes),
            ],
        );
        let result = layout.read_state();
        assert!(
            matches!(
                result,
                Err(PartialStateError::Partial(PartialError::InvalidChunkLayout))
            ),
            "got {result:?}"
        );
    }

    // -- retained-inventory accounting ----------------------------------

    /// Raw-pack cost of a stage's persisted inventory: 12-byte header +
    /// 32-byte trailer + (5-byte entry header + object bytes) per id —
    /// the same accounting `charge_raw_bytes` applies.
    fn inventory_pack_bytes(layout: &ScopedWorkspaceLayout, ids: &[crate::hash::Hash]) -> usize {
        let mut total = 12 + 32;
        for id in ids {
            let len = std::fs::metadata(
                layout
                    .root()
                    .join(format!(".mkit-scoped/objects/{}", to_hex(id))),
            )
            .unwrap()
            .len();
            total += 5 + usize::try_from(len).unwrap();
        }
        total
    }

    /// The aggregate retained-inventory budget is enforced at the
    /// descriptor-length check BEFORE the object is read: one byte under
    /// the real aggregate is `SubmissionTooLarge`, exactly at it is fine.
    #[test]
    fn required_inventory_aggregate_budget_is_exact() {
        let (_dir, layout) = fixture();
        let staged = layout.replace_stage(0, &[edit()]).unwrap();
        let ids = staged.stage().required_object_ids().to_vec();
        let exact = inventory_pack_bytes(&layout, &ids);
        republish(&layout, |plan| {
            plan.workspace.limits.max_raw_pack_bytes = exact;
        });
        layout.read_state().unwrap();
        republish(&layout, |plan| {
            plan.workspace.limits.max_raw_pack_bytes = exact - 1;
        });
        assert!(matches!(
            layout.read_state(),
            Err(PartialStateError::Partial(PartialError::SubmissionTooLarge))
        ));
    }

    /// The remaining-allowance check runs BEFORE the artifact is read:
    /// corrupting a required object's bytes (same length) still yields
    /// `SubmissionTooLarge` under the tight budget — never the read-time
    /// `CorruptArtifact` — while the headroom case reads and rejects the
    /// same corrupt bytes. The error pair proves the read never happened
    /// in the over-budget path.
    #[test]
    fn required_inventory_bound_check_precedes_read() {
        let (_dir, layout) = fixture();
        let staged = layout.replace_stage(0, &[edit()]).unwrap();
        let ids = staged.stage().required_object_ids().to_vec();
        let exact = inventory_pack_bytes(&layout, &ids);
        // Corrupt the LAST required object's bytes in place — the object
        // whose headroom check will fail under the one-under budget.
        let last = ids.last().unwrap();
        let object_path = layout
            .root()
            .join(format!(".mkit-scoped/objects/{}", to_hex(last)));
        let len = std::fs::metadata(&object_path).unwrap().len();
        std::fs::write(&object_path, vec![0xAB; usize::try_from(len).unwrap()]).unwrap();
        republish_from(&staged, &layout, |plan| {
            plan.workspace.limits.max_raw_pack_bytes = exact - 1;
        });
        assert!(
            matches!(
                layout.read_state(),
                Err(PartialStateError::Partial(PartialError::SubmissionTooLarge))
            ),
            "the pre-read headroom check must fire before the corrupt bytes are read"
        );
        republish_from(&staged, &layout, |plan| {
            plan.workspace.limits.max_raw_pack_bytes = exact;
        });
        assert!(
            matches!(
                layout.read_state(),
                Err(PartialStateError::CorruptArtifact { .. })
            ),
            "with headroom the same corrupt object IS read and rejected"
        );
    }

    /// An inventory padded with a valid but unrelated object — one the
    /// staged overlay never produced — is not required state.
    #[test]
    fn required_inventory_rejects_unrelated_extra() {
        let (_dir, layout) = fixture();
        let staged = layout.replace_stage(0, &[edit()]).unwrap();
        let mut ids = staged.stage().required_object_ids().to_vec();
        let (extra_id, extra_bytes) = put_object(&Object::Blob(crate::object::Blob {
            data: b"unrelated".to_vec(),
        }));
        ids.push(extra_id);
        ids.sort_unstable();
        republish(&layout, |plan| {
            plan.stage.required_object_ids = ids.clone();
            plan.objects.insert(extra_id, extra_bytes.clone());
        });
        assert!(matches!(
            layout.read_state(),
            Err(PartialStateError::NonCanonical(_))
        ));
    }

    /// Required inventories legitimately hold non-file objects: a staged
    /// edit retains the rebuilt ancestor TREE alongside the produced
    /// file object, and a pure reuse stage retains ONLY trees — the
    /// reused representation is a verified base object, never produced.
    /// A file-closure-only check would wrongly reject both.
    #[test]
    fn required_inventory_retains_produced_trees() {
        let inventory_objects =
            |layout: &ScopedWorkspaceLayout, state: &super::ScopedWorkspaceState| {
                state
                    .stage()
                    .required_object_ids()
                    .iter()
                    .map(|id| {
                        let bytes = std::fs::read(
                            layout
                                .root()
                                .join(format!(".mkit-scoped/objects/{}", to_hex(id))),
                        )
                        .unwrap();
                        crate::deserialize(&bytes).unwrap()
                    })
                    .collect::<Vec<Object>>()
            };
        let (_dir, layout) = two_file_fixture(b"aaaa", b"bbbb", PartialLimits::V1);
        let staged = layout
            .replace_stage(
                0,
                &[FileReplacement::bytes(
                    vec![b"a.txt".to_vec()],
                    b"new".to_vec(),
                )],
            )
            .unwrap();
        let kinds = inventory_objects(&layout, &staged);
        assert!(
            kinds.iter().any(|object| matches!(object, Object::Tree(_)))
                && kinds.iter().any(|object| matches!(object, Object::Blob(_))),
            "a staged edit retains the produced file object AND the rebuilt \
             ancestor tree: {kinds:?}"
        );
        // A stage consisting solely of a reuse produces no file object —
        // the reused representation is a verified base object — so its
        // entire inventory is produced trees, and it must still load.
        let (_dir2, layout2) = two_file_fixture(b"aaaa", b"bbbb", PartialLimits::V1);
        let reused = layout2
            .replace_stage(
                0,
                &[FileReplacement::reuse_selected(
                    vec![b"b.txt".to_vec()],
                    vec![b"a.txt".to_vec()],
                )],
            )
            .unwrap();
        let kinds = inventory_objects(&layout2, &reused);
        assert!(!kinds.is_empty(), "a real reuse still produces trees");
        assert!(
            kinds.iter().all(|object| matches!(object, Object::Tree(_))),
            "a pure reuse stage's inventory is produced trees only: {kinds:?}"
        );
        let reopened = ScopedWorkspaceLayout::open(layout2.root()).unwrap();
        reopened.read_state().unwrap();
    }

    // -- R1: normalized retained inventory --------------------------------

    /// The selected base representation id for `path`.
    fn selected_id(layout: &ScopedWorkspaceLayout, path: &[u8]) -> crate::hash::Hash {
        let state = layout.read_state().unwrap();
        *state
            .verified
            .files()
            .iter()
            .find(|file| file.path() == &vec![path.to_vec()])
            .unwrap()
            .object_id()
    }

    /// R1: a `Bytes` replacement whose content equals ANOTHER selected
    /// file's representation must persist an inventory derived by the
    /// same rule reopen verifies — otherwise `CURRENT` selects a state
    /// the loader rejects.
    #[test]
    fn bytes_copy_of_selected_content_survives_reopen_and_pending() {
        let (dir, layout) = two_file_fixture(b"aaa", b"bbb", PartialLimits::V1);
        let b_id = selected_id(&layout, b"b.txt");
        let state = layout
            .replace_stage(
                0,
                &[FileReplacement::bytes(
                    vec![b"a.txt".to_vec()],
                    b"bbb".to_vec(),
                )],
            )
            .unwrap();
        // The staged id IS b's verified representation, and the retained
        // inventory must not list it — the base already authenticates it.
        assert_eq!(staged_id(&state, b"a.txt"), b_id);
        assert!(
            !state.stage().required_object_ids().contains(&b_id),
            "the selected representation needs no retained copy: {:?}",
            state.stage().required_object_ids()
        );
        assert!(state.local_object(&b_id).is_none());
        // The CURRENT-selected state must still load after reopen.
        let reopened = ScopedWorkspaceLayout::open(&dir.path().join("ws")).unwrap();
        let reloaded = reopened.read_state().unwrap();
        assert_eq!(reloaded.workspace().transaction_generation(), 1);
        // And the stage must carry a pending candidate through accept:
        // the representation-preserving replay `reuse_selected` is the
        // exact operation the loader itself used to validate it.
        let signer = KeyPair::from_seed([9; 32]);
        let verified = reloaded.verified().clone();
        let limits = *reloaded.workspace().limits();
        let prepared = replace_files(
            &verified,
            &[FileReplacement::reuse_selected(
                vec![b"a.txt".to_vec()],
                vec![b"b.txt".to_vec()],
            )],
            &limits,
        )
        .unwrap();
        let unsigned = prepare_partial_commit(
            &verified,
            &prepared,
            Identity::opaque(b"op".to_vec()),
            signer.public.0,
            b"op".to_vec(),
            2,
            &limits,
        )
        .unwrap();
        let mut signed_commit = unsigned.clone();
        signed_commit.signature = sign_commit(&signed_commit, &signer).unwrap().0;
        let update =
            export_partial_update(&verified, &prepared, &unsigned, &signed_commit, &limits)
                .unwrap();
        let update_bytes = update.encode(&limits).unwrap();
        let pending = reopened
            .save_pending(1, &unsigned, &signed_commit, &update_bytes, None)
            .unwrap();
        let identity = pending.pending().unwrap().identity();
        reopened
            .record_outcome(2, &identity, PendingOutcomeV1::Accepted)
            .unwrap();
        let after = ScopedWorkspaceLayout::open(&dir.path().join("ws")).unwrap();
        assert!(after.read_state().unwrap().accepted().is_some());
    }

    /// Equivalent caller forms persist identical stage records: the
    /// caller's `Bytes` versus `ReuseSelected` spelling never changes the
    /// durable inventory.
    #[test]
    fn bytes_copy_and_reuse_persist_identical_stage_records() {
        let (_d1, via_bytes) = two_file_fixture(b"aaa", b"bbb", PartialLimits::V1);
        let (_d2, via_reuse) = two_file_fixture(b"aaa", b"bbb", PartialLimits::V1);
        let a_path = vec![b"a.txt".to_vec()];
        let b_path = vec![b"b.txt".to_vec()];
        let bytes_state = via_bytes
            .replace_stage(
                0,
                &[FileReplacement::bytes(a_path.clone(), b"bbb".to_vec())],
            )
            .unwrap();
        let reuse_state = via_reuse
            .replace_stage(0, &[FileReplacement::reuse_selected(a_path, b_path)])
            .unwrap();
        assert_eq!(
            bytes_state.stage().entries(),
            reuse_state.stage().entries(),
            "same staged ids for the same representation"
        );
        assert_eq!(
            bytes_state.stage().required_object_ids(),
            reuse_state.stage().required_object_ids(),
            "one inventory rule regardless of caller form"
        );
    }

    /// A mixed batch where a `Bytes` entry and a `ReuseSelected` entry
    /// resolve to the same selected representation shares the deduped
    /// inventory, and a later unrelated stage plus restart still works.
    #[test]
    fn mixed_batch_sharing_selected_id_survives_reopen_and_restaging() {
        let (dir, layout) = named_fixture(
            &[(b"a.txt", b"aaa"), (b"b.txt", b"bbb"), (b"c.txt", b"ccc")],
            PartialLimits::V1,
        );
        let b_id = selected_id(&layout, b"b.txt");
        let state = layout
            .replace_stage(
                0,
                &[
                    FileReplacement::bytes(vec![b"a.txt".to_vec()], b"bbb".to_vec()),
                    FileReplacement::reuse_selected(
                        vec![b"c.txt".to_vec()],
                        vec![b"b.txt".to_vec()],
                    ),
                ],
            )
            .unwrap();
        assert_eq!(staged_id(&state, b"a.txt"), b_id);
        assert_eq!(staged_id(&state, b"c.txt"), b_id);
        assert!(!state.stage().required_object_ids().contains(&b_id));
        let reopened = ScopedWorkspaceLayout::open(&dir.path().join("ws")).unwrap();
        // An unrelated further stage and another restart still load.
        reopened
            .replace_stage(
                1,
                &[FileReplacement::bytes(
                    vec![b"a.txt".to_vec()],
                    b"zzz".to_vec(),
                )],
            )
            .unwrap();
        let again = ScopedWorkspaceLayout::open(&dir.path().join("ws")).unwrap();
        let final_state = again.read_state().unwrap();
        assert_eq!(staged_id(&final_state, b"a.txt"), {
            let canonical = crate::object::Blob {
                data: b"zzz".to_vec(),
            };
            let bytes = serialize(&Object::Blob(canonical)).unwrap();
            id_from_object(
                &Object::Blob(crate::object::Blob {
                    data: b"zzz".to_vec(),
                }),
                &bytes,
            )
        });
        assert_eq!(staged_id(&final_state, b"c.txt"), b_id);
    }

    // -- F4: retained inventory covers the chunked dependency closure -----

    /// The chunk ids a selected file's representation declares — the
    /// base-authenticated dependency closure `retained_inventory` must
    /// dedup against, not just the manifest id.
    fn selected_chunk_ids(layout: &ScopedWorkspaceLayout, path: &[u8]) -> Vec<crate::hash::Hash> {
        let state = layout.read_state().unwrap();
        state
            .verified
            .files()
            .iter()
            .find(|file| file.path() == &vec![path.to_vec()])
            .unwrap()
            .chunk_ids()
            .to_vec()
    }

    /// F4: a `Bytes` copy of a CHUNKED selected file reproduces its
    /// manifest AND chunks in `produced`; the retained inventory must
    /// drop the whole base-authenticated closure — otherwise the
    /// replay's reuse-derived inventory mismatches and a valid
    /// replacement is refused.
    #[test]
    fn bytes_copy_of_chunked_selected_content_survives_reopen_and_pending() {
        let big = splitmix_bytes(
            usize::try_from(crate::worktree::CHUNK_THRESHOLD).unwrap() + 256 * 1024,
            0xB16,
        );
        let (dir, layout) =
            canonical_named_fixture(&[(b"a.txt", b"aaa"), (b"b.bin", &big)], PartialLimits::V1);
        // B really is a ChunkedBlob — this test must exercise the
        // chunked representation shape, not a plain Blob.
        let b_id = selected_id(&layout, b"b.bin");
        let b_chunks = selected_chunk_ids(&layout, b"b.bin");
        assert!(b_chunks.len() > 1, "B must be chunked: {b_chunks:?}");
        let b_object = layout
            .read_state()
            .unwrap()
            .verified
            .object_bytes(&b_id)
            .unwrap()
            .to_vec();
        assert!(matches!(
            crate::serialize::deserialize(&b_object),
            Ok(Object::ChunkedBlob(_))
        ));

        let state = layout
            .replace_stage(
                0,
                &[FileReplacement::bytes(vec![b"a.txt".to_vec()], big.clone())],
            )
            .expect("a byte-copy of chunked selected content is valid and must succeed");
        // A's staged id IS B's manifest id, and neither it nor any of
        // its chunks is retained — the base authenticates all of them.
        assert_eq!(staged_id(&state, b"a.txt"), b_id);
        let required = state.stage().required_object_ids();
        assert!(!required.contains(&b_id));
        for chunk in &b_chunks {
            assert!(
                !required.contains(chunk),
                "base-authenticated chunk must not be retained: {chunk:?}"
            );
        }
        // Reopen loads the CURRENT-selected state…
        let reopened = ScopedWorkspaceLayout::open(&dir.path().join("ws")).unwrap();
        let reloaded = reopened.read_state().unwrap();
        assert_eq!(reloaded.workspace().transaction_generation(), 1);
        // …and carries a pending candidate through accept.
        let signer = KeyPair::from_seed([9; 32]);
        let verified = reloaded.verified().clone();
        let limits = *reloaded.workspace().limits();
        let prepared = replace_files(
            &verified,
            &[FileReplacement::reuse_selected(
                vec![b"a.txt".to_vec()],
                vec![b"b.bin".to_vec()],
            )],
            &limits,
        )
        .unwrap();
        let unsigned = prepare_partial_commit(
            &verified,
            &prepared,
            Identity::opaque(b"op".to_vec()),
            signer.public.0,
            b"op".to_vec(),
            2,
            &limits,
        )
        .unwrap();
        let mut signed_commit = unsigned.clone();
        signed_commit.signature = sign_commit(&signed_commit, &signer).unwrap().0;
        let update =
            export_partial_update(&verified, &prepared, &unsigned, &signed_commit, &limits)
                .unwrap();
        let update_bytes = update.encode(&limits).unwrap();
        let pending = reopened
            .save_pending(1, &unsigned, &signed_commit, &update_bytes, None)
            .unwrap();
        let identity = pending.pending().unwrap().identity();
        reopened
            .record_outcome(2, &identity, PendingOutcomeV1::Accepted)
            .unwrap();
        let after = ScopedWorkspaceLayout::open(&dir.path().join("ws")).unwrap();
        assert!(after.read_state().unwrap().accepted().is_some());
    }

    /// Equivalent `Bytes` and `ReuseSelected` operations on a chunked
    /// selected representation persist identical stage ids and identical
    /// retained inventories.
    #[test]
    fn chunked_bytes_copy_and_reuse_persist_identical_stage_records() {
        let big = splitmix_bytes(
            usize::try_from(crate::worktree::CHUNK_THRESHOLD).unwrap() + 128 * 1024,
            0xC4E,
        );
        let files: &[(&[u8], &[u8])] = &[(b"a.txt", b"aaa"), (b"b.bin", &big)];
        let (_d1, via_bytes) = canonical_named_fixture(files, PartialLimits::V1);
        let (_d2, via_reuse) = canonical_named_fixture(files, PartialLimits::V1);
        let a_path = vec![b"a.txt".to_vec()];
        let b_path = vec![b"b.bin".to_vec()];
        let bytes_state = via_bytes
            .replace_stage(0, &[FileReplacement::bytes(a_path.clone(), big.clone())])
            .unwrap();
        let reuse_state = via_reuse
            .replace_stage(0, &[FileReplacement::reuse_selected(a_path, b_path)])
            .unwrap();
        assert_eq!(bytes_state.stage().entries(), reuse_state.stage().entries());
        assert_eq!(
            bytes_state.stage().required_object_ids(),
            reuse_state.stage().required_object_ids(),
            "one inventory rule regardless of caller form, chunked included"
        );
    }

    /// A mixed batch: A byte-copies chunked B while C gets genuinely new
    /// chunked content sharing a whole leading chunk with B. The shared
    /// chunk is base-authenticated (not retained); C's new chunks and
    /// manifest are retained; reopen and the exported update inventory
    /// stay complete.
    #[test]
    fn mixed_chunked_batch_shares_base_chunks_and_retains_new_ones() {
        let big = splitmix_bytes(
            usize::try_from(crate::worktree::CHUNK_THRESHOLD).unwrap() + 256 * 1024,
            0xF00D,
        );
        // C's new content shares all of B's chunks but the last (the
        // split point is a real FastCDC boundary of `big`, and CDC cuts
        // are prefix-stable so every boundary inside the shared prefix
        // is reproduced), then diverges with a tail producing genuinely
        // new chunks. The last boundary keeps C above CHUNK_THRESHOLD.
        let last_boundary = crate::chunker::ChunkIterator::new(crate::chunker::FastCdc::v1(), &big)
            .map(|b| b.offset + b.length)
            .take_while(|end| *end < big.len())
            .last()
            .expect("chunked content has interior boundaries");
        let mut c_data = big[..last_boundary].to_vec();
        c_data.extend_from_slice(&splitmix_bytes(96 * 1024, 0xCA7));
        let (dir, layout) = canonical_named_fixture(
            &[(b"a.txt", b"aaa"), (b"b.bin", &big), (b"c.bin", b"ccc")],
            PartialLimits::V1,
        );
        let b_id = selected_id(&layout, b"b.bin");
        let b_chunk_list = selected_chunk_ids(&layout, b"b.bin");
        let b_chunks: std::collections::BTreeSet<_> = b_chunk_list.iter().copied().collect();
        // B's FIRST chunk is inside the shared prefix — the same bytes
        // `store_file_object` hashed into `b.bin`'s manifest.
        let shared_chunk = b_chunk_list[0];

        let state = layout
            .replace_stage(
                0,
                &[
                    FileReplacement::bytes(vec![b"a.txt".to_vec()], big.clone()),
                    FileReplacement::bytes(vec![b"c.bin".to_vec()], c_data.clone()),
                ],
            )
            .unwrap();
        // A copies B wholesale; C's new manifest is its own id.
        assert_eq!(staged_id(&state, b"a.txt"), b_id);
        let c_id = staged_id(&state, b"c.bin");
        assert_ne!(c_id, b_id);
        let c_object = state.local_object(&c_id).unwrap().to_vec();
        let Object::ChunkedBlob(c_manifest) = crate::serialize::deserialize(&c_object).unwrap()
        else {
            panic!("C's staged representation must be a ChunkedBlob");
        };
        let c_chunks: std::collections::BTreeSet<_> = c_manifest.chunks.iter().copied().collect();
        // The shared prefix chunk is a real shared chunk.
        assert!(c_chunks.contains(&shared_chunk));
        let new_chunks: Vec<_> = c_chunks.difference(&b_chunks).copied().collect();
        assert!(!new_chunks.is_empty(), "C must contribute new chunks");
        let required = state.stage().required_object_ids();
        // Shared chunk and B's whole closure: base-authenticated, not retained.
        assert!(!required.contains(&shared_chunk));
        assert!(!required.contains(&b_id));
        // C's manifest and its genuinely new chunks: retained.
        assert!(required.contains(&c_id));
        for chunk in &new_chunks {
            assert!(
                required.contains(chunk),
                "new chunk must be retained: {chunk:?}"
            );
        }
        // Reopen loads, and the exported update carries the complete
        // changed inventory — local dedup never shrinks the MKWU.
        let reopened = ScopedWorkspaceLayout::open(&dir.path().join("ws")).unwrap();
        let reloaded = reopened.read_state().unwrap();
        let verified = reloaded.verified().clone();
        let limits = *reloaded.workspace().limits();
        let prepared = replace_files(
            &verified,
            &[
                FileReplacement::reuse_selected(vec![b"a.txt".to_vec()], vec![b"b.bin".to_vec()]),
                FileReplacement::bytes(vec![b"c.bin".to_vec()], c_data),
            ],
            &limits,
        )
        .unwrap();
        let signer = KeyPair::from_seed([3; 32]);
        let unsigned = prepare_partial_commit(
            &verified,
            &prepared,
            Identity::opaque(b"op".to_vec()),
            signer.public.0,
            b"op".to_vec(),
            2,
            &limits,
        )
        .unwrap();
        let mut signed_commit = unsigned.clone();
        signed_commit.signature = sign_commit(&signed_commit, &signer).unwrap().0;
        let update =
            export_partial_update(&verified, &prepared, &unsigned, &signed_commit, &limits)
                .unwrap();
        let pack = update.pack_bytes();
        // Every changed representation id and every chunk — shared or
        // new — must appear in the exported pack bytes.
        for id in c_chunks
            .iter()
            .chain(std::iter::once(&c_id))
            .chain(std::iter::once(&b_id))
            .chain(b_chunks.iter())
        {
            let raw = verified
                .object_bytes(id)
                .or_else(|| reloaded.local_object(id))
                .unwrap_or_else(|| panic!("export inventory must include {id:?}"))
                .to_vec();
            assert!(
                pack.windows(raw.len()).any(|w| w == raw.as_slice()),
                "exported pack must carry object {id:?}"
            );
        }
    }

    // -- R2: borrowed preflight and bounded retained reads ----------------

    /// The aggregate batch bound must reject while the caller's
    /// replacements are still borrowed — never after cloning them into
    /// the feed. `FEED_CLONE_BYTES` is the observable seam: it counts
    /// payload bytes copied into the feed, and must stay zero.
    #[test]
    fn replace_stage_rejects_over_budget_batch_before_cloning() {
        let limits = PartialLimits {
            max_selected_file_bytes: 32,
            max_total_selected_bytes: 40,
            ..PartialLimits::V1
        };
        let (_dir, layout) = two_file_fixture(b"aaa", b"bbb", limits);
        test_instrument::reset();
        let err = layout
            .replace_stage(
                0,
                &[
                    FileReplacement::bytes(vec![b"a.txt".to_vec()], vec![b'x'; 32]),
                    FileReplacement::bytes(vec![b"b.txt".to_vec()], vec![b'y'; 32]),
                ],
            )
            .unwrap_err();
        assert!(
            matches!(
                err,
                PartialStateError::Partial(PartialError::WorkspaceTooLarge)
            ),
            "got {err:?}"
        );
        assert_eq!(
            test_instrument::feed_clone_bytes(),
            0,
            "an over-budget batch must be refused before its bytes are cloned"
        );
        // Control: an exact-aggregate batch does reach the clone — the
        // counter is live, not just always zero.
        test_instrument::reset();
        layout
            .replace_stage(
                0,
                &[
                    FileReplacement::bytes(vec![b"a.txt".to_vec()], vec![b'x'; 20]),
                    FileReplacement::bytes(vec![b"b.txt".to_vec()], vec![b'y'; 20]),
                ],
            )
            .unwrap();
        assert_eq!(test_instrument::feed_clone_bytes(), 40);
    }

    /// The bounded read of a retained object must be capped by the
    /// REMAINING raw-pack headroom, not the per-object bound alone — the
    /// recorded cap is the oracle.
    #[test]
    fn retained_object_read_is_capped_by_remaining_headroom() {
        let (_dir, layout) = fixture();
        let staged = layout.replace_stage(0, &[edit()]).unwrap();
        let ids = staged.stage().required_object_ids().to_vec();
        let exact = inventory_pack_bytes(&layout, &ids);
        // Tighten the budget so the LAST required object's remaining
        // headroom falls below `max_object_bytes` — the recorded cap
        // must be that headroom, not the per-object bound.
        let last_len = usize::try_from(
            std::fs::metadata(layout.root().join(format!(
                ".mkit-scoped/objects/{}",
                to_hex(ids.last().unwrap())
            )))
            .unwrap()
            .len(),
        )
        .unwrap();
        republish_from(&staged, &layout, |plan| {
            plan.workspace.limits.max_raw_pack_bytes = exact;
        });
        test_instrument::reset();
        layout.read_state().unwrap();
        let caps = test_instrument::read_caps();
        assert_eq!(caps.len(), ids.len());
        // The last read's cap is the headroom left after the earlier
        // objects — strictly below `max_object_bytes` and equal to the
        // object's own length under the exact budget.
        assert_eq!(
            *caps.last().unwrap(),
            last_len,
            "final retained read cap must be the remaining headroom: {caps:?}"
        );
    }

    /// A retained object grown between its descriptor-length check and
    /// the bounded read must still fail closed — as a budget violation,
    /// not a mid-read corruption or an unbounded allocation.
    #[test]
    fn grown_retained_object_fails_at_bounded_read() {
        let (_dir, layout) = fixture();
        let staged = layout.replace_stage(0, &[edit()]).unwrap();
        let ids = staged.stage().required_object_ids().to_vec();
        let exact = inventory_pack_bytes(&layout, &ids);
        republish_from(&staged, &layout, |plan| {
            plan.workspace.limits.max_raw_pack_bytes = exact;
        });
        test_instrument::reset();
        // Grow the LAST required object — the one whose read cap equals
        // exactly its recorded length — AFTER its fstat. The bounded
        // read, not the metadata check, is what must catch it.
        test_instrument::on_object_read(to_hex(ids.last().unwrap()), |path| {
            let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
            file.write_all(&[0xAB; 16]).unwrap();
        });
        let result = layout.read_state();
        assert!(
            matches!(
                result,
                Err(PartialStateError::Partial(PartialError::SubmissionTooLarge))
            ),
            "grown object must fail at the bounded read: {result:?}"
        );
    }

    // -- R5/R6: deterministic lock contention and stale-waiter refusal ----

    const LOCK_TEST_TIMEOUT: Duration = Duration::from_secs(15);

    /// Drive one writer through `replace_stage` on `handle`; the result
    /// arrives on a bounded channel so a wedged lock fails the test
    /// instead of hanging it.
    fn spawn_writer(
        handle: Arc<ScopedWorkspaceLayout>,
        bytes: &'static [u8],
    ) -> mpsc::Receiver<Result<(), PartialStateError>> {
        let (done, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = handle
                .replace_stage(
                    0,
                    &[FileReplacement::bytes(
                        vec![b"file.txt".to_vec()],
                        bytes.to_vec(),
                    )],
                )
                .map(|_| ());
            let _ = done.send(result);
        });
        done_rx
    }

    /// R5: two writers racing one generation — exactly one commits, the
    /// other observes `GenerationMismatch`. Deterministic: writer A is
    /// provably inside the critical section (armed `Acquired` gate) and
    /// writer B is provably at the acquisition boundary (armed
    /// `BeforeFlock` gate) before A releases. Covered for a shared
    /// `Arc` handle and for independent handles.
    #[test]
    fn lock_serializes_competing_writers_deterministically() {
        for separate_handles in [false, true] {
            let (dir, layout) = fixture();
            let identity = layout.lock_identity();
            let first = Arc::new(layout);
            let second = if separate_handles {
                Arc::new(ScopedWorkspaceLayout::open(&dir.path().join("ws")).unwrap())
            } else {
                Arc::clone(&first)
            };
            // A enters the critical section and parks there.
            let (a_in, a_in_rx) = mpsc::channel();
            let (a_go, a_go_rx) = mpsc::channel();
            let _a_gate =
                lock_gate::arm(lock_gate::Phase::Acquired, identity, a_in, a_go_rx, false)
                    .expect("gate registration");
            let a_done = spawn_writer(Arc::clone(&first), b"writer A");
            a_in_rx
                .recv_timeout(LOCK_TEST_TIMEOUT)
                .expect("writer A never reached the critical section");
            // B opens + verifies the sentinel, then parks at flock. The
            // gate first probes B's OWN operation descriptor with a
            // nonblocking flock while A is still parked inside: the
            // attempt MUST report would-block — proof the loser
            // descriptor genuinely contends for the lock BEFORE the
            // winner is released. A probe that acquires means B's
            // descriptor already shares the locked open-file
            // description (the shared-descriptor defect: flock on the
            // same OFD is a no-op success) and nothing ever serialized
            // the writers.
            let (b_at, b_at_rx) = mpsc::channel();
            let (b_go, b_go_rx) = mpsc::channel();
            let _b_gate =
                lock_gate::arm(lock_gate::Phase::BeforeFlock, identity, b_at, b_go_rx, true)
                    .expect("gate registration");
            let b_done = spawn_writer(second, b"writer B");
            let b_observation = b_at_rx
                .recv_timeout(LOCK_TEST_TIMEOUT)
                .expect("writer B never reached the acquisition boundary");
            assert_eq!(
                b_observation.probe_acquired,
                Some(false),
                "B's own operation descriptor must fail to acquire while \
                 A holds the lock — a successful probe means the \
                 descriptor already shared the locked open-file \
                 description, so B never contended for the lock at all"
            );
            // Only now release B's acquisition attempt and A's critical
            // section: B blocks inside flock until A's descriptor
            // closes, then must observe generation 1.
            b_go.send(()).unwrap();
            a_go.send(()).unwrap();
            let a_result = a_done
                .recv_timeout(LOCK_TEST_TIMEOUT)
                .expect("writer A never finished after release");
            let b_result = b_done
                .recv_timeout(LOCK_TEST_TIMEOUT)
                .expect("writer B never finished after A released");
            assert!(
                a_result.is_ok(),
                "the writer inside the section commits: {a_result:?}"
            );
            assert!(
                matches!(
                    b_result,
                    Err(PartialStateError::GenerationMismatch {
                        expected: 0,
                        actual: 1
                    })
                ),
                "the waiting writer must observe the new generation: {b_result:?}"
            );
            // The committed state is coherent: generation 1 with A's
            // bytes staged and B's never written.
            let state = first.read_state().unwrap();
            assert_eq!(state.workspace().transaction_generation(), 1);
            assert_eq!(
                staged_id(&state, b"file.txt"),
                {
                    let object = Object::Blob(crate::object::Blob {
                        data: b"writer A".to_vec(),
                    });
                    let bytes = serialize(&object).unwrap();
                    id_from_object(&object, &bytes)
                },
                "separate_handles={separate_handles}"
            );
        }
    }

    /// R6: a writer parked at the flock boundary holds a descriptor for
    /// the CURRENT sentinel inode; if the sentinel is atomically
    /// replaced while it waits, acquisition lands on the detached old
    /// inode — the post-acquisition recheck must refuse before `f` runs.
    #[test]
    fn replaced_lock_sentinel_refuses_stale_waiter() {
        let (dir, layout) = fixture();
        let lock_path = dir.path().join("ws").join(STATE_DIR).join(LOCK_FILE);
        // An external flock holds the sentinel so the writer genuinely
        // blocks mid-acquisition.
        let state_fd = sys::open_dir_path(&dir.path().join("ws").join(STATE_DIR)).unwrap();
        let hold = sys::open_file(&state_fd, LOCK_FILE.as_bytes(), OpenMode::ReadWrite).unwrap();
        hold.lock_exclusive().unwrap();
        // Writer opens + verifies the sentinel, then parks at flock.
        let identity = layout.lock_identity();
        let (at_flock, at_flock_rx) = mpsc::channel();
        let (go, go_rx) = mpsc::channel();
        let _gate = lock_gate::arm(
            lock_gate::Phase::BeforeFlock,
            identity,
            at_flock,
            go_rx,
            false,
        )
        .expect("gate registration");
        let done = spawn_writer(Arc::new(layout), b"stale waiter");
        at_flock_rx
            .recv_timeout(LOCK_TEST_TIMEOUT)
            .expect("writer never reached the acquisition boundary");
        // Replace the sentinel while the writer is provably waiting.
        let replacement = lock_path.with_file_name("workspace.lock.replacement");
        std::fs::write(&replacement, b"replacement sentinel").unwrap();
        std::fs::rename(&replacement, &lock_path).unwrap();
        // Release the writer into flock; it still blocks on the OLD
        // inode until the external hold is dropped.
        go.send(()).unwrap();
        drop(hold);
        let result = done
            .recv_timeout(LOCK_TEST_TIMEOUT)
            .expect("stale waiter never finished");
        assert!(
            matches!(result, Err(PartialStateError::UnsafeFilesystemEntry { .. })),
            "the stale waiter must refuse on the replaced sentinel: {result:?}"
        );
        // No mutation happened: generation 0 still loads cleanly.
        let state = ScopedWorkspaceLayout::open(&dir.path().join("ws"))
            .unwrap()
            .read_state()
            .unwrap();
        assert_eq!(state.workspace().transaction_generation(), 0);
    }

    /// F2: gate registrations are keyed by `(workspace identity, phase)`
    /// — two workspaces holding `BeforeFlock` gates simultaneously must
    /// not overwrite or consume each other's registration, and a
    /// duplicate registration for an armed key is rejected. Without
    /// keying, a second `arm` replaced the first gate and dropped its
    /// channels, silently disarming the first test's synchronization.
    #[test]
    fn lock_gates_are_isolated_per_workspace_and_phase() {
        let (_dir_a, layout_a) = fixture();
        let (_dir_b, layout_b) = fixture();
        let id_a = layout_a.lock_identity();
        let id_b = layout_b.lock_identity();
        assert_ne!(id_a, id_b, "two workspaces need distinct sentinels");

        // Arm both workspaces at BeforeFlock while BOTH stay armed.
        let (a_tx, a_rx) = mpsc::channel();
        let (a_release, a_release_rx) = mpsc::channel();
        let _gate_a = lock_gate::arm(
            lock_gate::Phase::BeforeFlock,
            id_a,
            a_tx,
            a_release_rx,
            false,
        )
        .expect("workspace A gate registration");
        let (b_tx, b_rx) = mpsc::channel();
        let (b_release, b_release_rx) = mpsc::channel();
        let _gate_b = lock_gate::arm(
            lock_gate::Phase::BeforeFlock,
            id_b,
            b_tx,
            b_release_rx,
            false,
        )
        .expect("workspace B gate registration — must not evict A's");

        // A second registration for an already-armed key is rejected.
        let (dup_tx, _dup_rx) = mpsc::channel();
        let (_dup_release, dup_release_rx) = mpsc::channel();
        assert!(
            lock_gate::arm(
                lock_gate::Phase::BeforeFlock,
                id_a,
                dup_tx,
                dup_release_rx,
                false,
            )
            .is_none(),
            "a duplicate gate for an armed (identity, phase) is refused"
        );

        // A's writer fires A's gate — and only A's.
        let a_done = spawn_writer(Arc::new(layout_a), b"via A");
        a_rx.recv_timeout(LOCK_TEST_TIMEOUT)
            .expect("workspace A's gate never fired");
        a_release.send(()).unwrap();
        a_done
            .recv_timeout(LOCK_TEST_TIMEOUT)
            .expect("workspace A writer never finished")
            .unwrap();

        // B's registration survived untouched: B's writer still parks
        // on B's own gate.
        let b_done = spawn_writer(Arc::new(layout_b), b"via B");
        b_rx.recv_timeout(LOCK_TEST_TIMEOUT)
            .expect("workspace B's gate was lost to A's registration");
        b_release.send(()).unwrap();
        b_done
            .recv_timeout(LOCK_TEST_TIMEOUT)
            .expect("workspace B writer never finished")
            .unwrap();
    }
}
