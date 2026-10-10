//! Server-side repository fork (SPEC-SERVER §9.9): a durable, resumable job
//! that gives an empty destination the published membership of one source
//! branch, without a ref.
//!
//! The job lives in the destination's coordinator (`fj`). Every step is a
//! bounded slice of at most [`SLICE_CALLS`] storage calls, advanced by the
//! request that starts it and then by the kind-16 timer. Each effect is a
//! repeatable write (a put of the same value, or a holder write that only
//! raises a sequence), so a crash at any state resumes by
//! re-running the state's slice; published membership is written last and
//! the destination registration first (takedown sweeps enumerate the
//! registry).

pub mod boundary;
mod closure;
mod copy;
mod job;
mod plan;
mod publish;
mod request;
mod sets;
mod settle;

pub(crate) use crate::store::CONTENT_APPLY_WINDOW_MS as CONTENT_WINDOW;
pub use job::{ForkTimer, StartOutcome, StepReport, plan_bytes, start, start_with, step};
pub use request::ForkRequest;
pub use settle::SettleV1;
pub use settle::{ChargeV1, ReplayV1};

use crate::error::ServerError;
use crate::repo::{NamespaceKey, RepoId, RepoName};
use crate::rt::Clock;
use crate::store::{NamespaceStore, StoreError, codec::CODEC_V1, keys};
use crate::{Value, pipeline::ShardMap};
use mkit_core::hash::{Hash, hash};
use serde::{Deserialize, Serialize};

/// Most packs (packmap nodes, listed packs and external-base packs) one fork
/// copies. The job row lists them, so the bound keeps the row far under the
/// value limit.
pub const MAX_FORK_PACKS: usize = 1_024;
/// Most index rows one fork copies. Measured: 10,000 rows copy in 400 storage
/// calls (about 20 s at 50 ms per call, one slice), so the copy is not the
/// limit. The limit is the next advance: its denial proof visits every
/// dependency pack's inventory at 8 rows per two calls, and 16,384 rows keep
/// that near 4,100 calls, inside one request's 9,000.
pub const MAX_FORK_OBJECTS: u64 = 16_384;
/// Most ids in one working or cleared set row. A batch holds at most 1 MiB
/// including the job row twice (guard and new value, up to about 400 KiB each
/// at the packs/dependency bounds), so two changed sets of 8,000 ids (256 KiB
/// each) fit beside it.
pub const MAX_SET_IDS: usize = 8_000;
/// Storage calls one slice may use: the alarm allowance (1,000) minus the
/// timer's own settlement and a margin.
pub const SLICE_CALLS: u32 = 600;
/// An unfinished job (and its admission reservation) expires after this long.
pub const JOB_TTL_MS: u64 = 24 * 3_600_000;
/// Packs counted in one coordinator batch (one `RepoStorageChanged`).
pub const COUNT_BATCH_PACKS: usize = 45;
/// Index rows per destination write batch.
pub const COPY_PUTS: usize = 96;
/// Rows per source index scan.
pub const SCAN_PAGE_ROWS: u32 = 500;
/// Source index rows one fork may scan, however many it copies.
pub const MAX_SCANNED_ROWS: u64 = 262_144;
/// Most external-base object ids one pack may name, and one job may hold
/// unresolved. The ids ride in the job row.
pub const MAX_FORK_DEPS: usize = 2_048;
/// Most external-base ids one pack may name (its scan costs a quarter call each).
pub const MAX_PACK_DEPS: u64 = 1_800;
/// Whether a slice's allowance is still whole: it is at least the default
/// slice and only the job row read and the reservation check have been spent. A unit that fails for budget on a whole
/// allowance can never succeed, which is a bound of the implementation; on a
/// partly spent one it only waits for the next slice.
pub(crate) fn fresh(budget: &crate::budget::SliceBudget) -> bool {
    budget.used() <= 4
        && budget.limit() >= SLICE_CALLS
        && budget.remaining().saturating_add(4) >= SLICE_CALLS
        && !budget.ancestor_refused()
}

/// Whether `error` is a spent allowance: the slice's own marker, or any
/// failure after the budget refused a call (the denial and index layers
/// report a refused call as an ordinary storage failure).
pub(crate) fn spent(error: &ForkError, budget: &crate::budget::SliceBudget) -> bool {
    matches!(error, ForkError::Slice)
        || (matches!(error, ForkError::Unavailable(_)) && budget.refused())
}

/// The membership generation of a freshly forked destination.
pub const MEMBERSHIP_GENERATION: u64 = 0;

/// Working and cleared id sets (`fo` rows).
pub(crate) mod set {
    /// Cleared commits and trees of the inherited closure.
    pub(crate) const CLEARED: u8 = 0;
    /// Tree ids of every inherited pack (classifies commit children).
    pub(crate) const TREES: u8 = 1;
    /// Closure walk queue.
    pub(crate) const QUEUE: u8 = 2;
    /// Inherited external-base packs, a dependency of every skipped object.
    pub(crate) const BASES: u8 = 3;
    /// Chunked-blob manifests, which may be extracted.
    pub(crate) const MANIFESTS: u8 = 4;
}

/// The refusal of a pack set larger than the bytes admission charged for.
pub(crate) const OVER_ADMITTED: &str = "fork exceeds the bytes admitted; retry";

/// Why a fork step stopped. Mapped to the public answers by [`Self::error`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForkError {
    /// Anything the caller must not distinguish: absent, unreadable,
    /// unpublished, unverified, blocked or superseded source content.
    NotFound,
    /// The published tip or packmap differs from `expected_tip`.
    TipChanged,
    /// A bound of this implementation was exceeded.
    TooLarge,
    /// The destination already has refs, members or another fork.
    NotEmpty,
    /// Retryable: lag, contention or a failed backend call.
    Unavailable(&'static str),
    /// The job outlived its expiry, its reservation was settled elsewhere, or
    /// the authority it was authorized under moved.
    Expired,
    /// The destination's namespace may not be registered by a fork.
    Denied,
    /// The authority generation (`"authority"`) or grant epoch (`"epoch"`)
    /// the request was authorized under moved.
    Moved(&'static str),
    /// The admission quota refuses the fork's charge (the reason is the
    /// client-safe text of the quota decision), or the pack set outgrew the
    /// bytes admission charged for.
    Quota(&'static str),
    /// The slice's call budget ended; progress so far is kept. Never public.
    Slice,
}

impl ForkError {
    /// The public error. The messages are fixed so that refusals are
    /// byte-identical.
    #[must_use]
    pub fn error(&self) -> ServerError {
        match self {
            Self::NotFound => ServerError::not_found("source not found"),
            Self::TipChanged => ServerError::failed_precondition("source tip changed"),
            Self::TooLarge => ServerError::resource_exhausted("fork too large"),
            Self::NotEmpty => ServerError::failed_precondition("destination not empty"),
            Self::Unavailable(message) => ServerError::unavailable(*message),
            Self::Expired => ServerError::unavailable("fork expired"),
            Self::Denied => ServerError::permission_denied("namespace not registered"),
            Self::Moved("authority") => crate::authority::moved(),
            Self::Moved(_) => crate::pipeline::epoch_moved(),
            Self::Quota(reason) => ServerError::resource_exhausted(*reason),
            Self::Slice => ServerError::unavailable("fork in progress"),
        }
    }
    fn from_error(error: &ServerError) -> Self {
        match error.code() {
            crate::Code::NotFound | crate::Code::PermissionDenied => Self::NotFound,
            crate::Code::ResourceExhausted => Self::TooLarge,
            _ => Self::Unavailable("fork unavailable"),
        }
    }
}

impl From<StoreError> for ForkError {
    fn from(error: StoreError) -> Self {
        if crate::budget::is_exhausted(&error) {
            Self::Slice
        } else {
            Self::Unavailable("fork storage unavailable")
        }
    }
}

impl From<ServerError> for ForkError {
    fn from(error: ServerError) -> Self {
        Self::from_error(&error)
    }
}

/// The bounds of one fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkLimits {
    /// Most packs.
    pub max_packs: usize,
    /// Most copied index rows.
    pub max_objects: u64,
    /// Most ids in one working or cleared set.
    pub max_set_ids: usize,
}

impl Default for ForkLimits {
    fn default() -> Self {
        Self {
            max_packs: MAX_FORK_PACKS,
            max_objects: MAX_FORK_OBJECTS,
            max_set_ids: MAX_SET_IDS,
        }
    }
}

/// What one fork reads and writes.
#[derive(Clone, Copy)]
pub struct ForkEnv<'a, S> {
    /// The deployment's namespace store, reaching every partition.
    pub store: &'a S,
    /// The deployment's shard map.
    pub shards: &'a dyn ShardMap,
    /// The business clock.
    pub clock: &'a dyn Clock,
    /// Whether pack-level takedown denial is on. MUST equal
    /// `PipelineConfig::takedown_denial` of the pipeline that serves the
    /// destination: it selects the pack proof, and the publication walk
    /// honours the cleared set only under it.
    pub takedown_denial: bool,
    /// The extraction threshold; `None` when extraction is not deployed, in
    /// which case no holder rows are copied.
    pub extract_min_bytes: Option<u64>,
    /// The bounds; [`ForkLimits::default`] in production.
    pub limits: ForkLimits,
}

impl<S> core::fmt::Debug for ForkEnv<'_, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ForkEnv")
            .field("takedown_denial", &self.takedown_denial)
            .field("extract_min_bytes", &self.extract_min_bytes)
            .finish_non_exhaustive()
    }
}

impl<S> ForkEnv<'_, S> {
    pub(crate) fn now(&self) -> u64 {
        u64::try_from(self.clock.now_ms()).unwrap_or(0)
    }
}

/// A fork request: everything the binding hash covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkSpec {
    /// The source repository.
    pub source: RepoId,
    /// The source branch, `refs/heads/<name>`.
    pub source_ref: String,
    /// The tip the caller expects: a required compare-and-swap.
    pub expected_tip: Hash,
    /// The destination repository.
    pub dest: RepoId,
    /// The destination's requested visibility.
    pub dest_visibility: mkit_attest::grant::Visibility,
}

impl ForkSpec {
    pub(crate) fn visibility_name(&self) -> &'static str {
        match self.dest_visibility {
            mkit_attest::grant::Visibility::Public => "public",
            mkit_attest::grant::Visibility::Private => "private",
        }
    }
}

/// The lineage anchor of a finished fork.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkResult {
    /// The source repository identity.
    pub source: String,
    /// The forked branch.
    pub source_ref: String,
    /// The published tip that was forked.
    pub tip: Hash,
    /// The source's publication sequence at the fork.
    pub source_sequence: u64,
    /// The published packmap head.
    pub packmap: Hash,
    /// Packs the destination now holds as members.
    pub pack_count: u64,
    /// Their total bytes, counted once.
    pub pack_bytes: u64,
    /// Index rows copied.
    pub object_count: u64,
    /// Digest of the sorted pack ids.
    pub pack_set: Hash,
    /// The destination's membership generation.
    pub membership_generation: u64,
}

/// One pack of the inherited set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackRow {
    /// Pack id.
    pub id: Hash,
    /// Pack length in bytes.
    pub len: u64,
    /// Entries with an index row.
    pub objects: u64,
    /// A packmap node (MKPL) rather than a data pack.
    pub node: bool,
    /// Pulled in only as an external delta base.
    pub base: bool,
}

/// The job's state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Phase {
    /// Compute the pack set from the source's sealed inventories.
    Plan,
    /// Collect every tree id of the pack set.
    Trees,
    /// Walk the tip's commits and trees into the cleared set.
    Walk,
    /// Register the destination.
    Register,
    /// Copy index rows (and holders) of the pack set.
    Copy,
    /// Count the packs once against the destination.
    Count,
    /// Prove and publish membership.
    Publish,
    /// Finished.
    Done,
    /// Terminally refused.
    Failed,
}

/// The authority facts a request was authorized under, re-checked when the
/// destination is registered (the job may run long after the request).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceV1 {
    /// The namespace authority generation the request was authorized under.
    pub authority_generation: Option<u64>,
    /// The grant epoch the request's grant was checked against.
    pub grant_epoch: Option<u64>,
    /// Whether registering the destination may create its namespace; false
    /// where namespaces are registered by their authority.
    pub create_namespace: bool,
}

/// A terminal refusal, replayed to later callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Failure {
    /// The source cannot be forked (the uniform answer).
    NotFound,
    /// A bound of this implementation was exceeded.
    TooLarge,
    /// The source's published value moved.
    TipChanged,
    /// The destination gained refs or conflicting rows during the job.
    Changed,
    /// The job expired, its reservation was settled elsewhere, or the
    /// authority it was authorized under moved.
    Expired,
    /// Registering the destination was not permitted.
    Denied,
    /// The namespace authority generation moved.
    AuthorityMoved,
    /// The grant epoch moved.
    EpochMoved,
    /// The pack set outgrew the bytes admission charged for.
    OverAdmitted,
}

impl Failure {
    pub(crate) fn of(error: &ForkError) -> Option<Self> {
        match error {
            ForkError::NotFound => Some(Self::NotFound),
            ForkError::TooLarge => Some(Self::TooLarge),
            ForkError::TipChanged => Some(Self::TipChanged),
            ForkError::NotEmpty => Some(Self::Changed),
            ForkError::Expired => Some(Self::Expired),
            ForkError::Denied => Some(Self::Denied),
            ForkError::Moved("authority") => Some(Self::AuthorityMoved),
            ForkError::Moved(_) => Some(Self::EpochMoved),
            ForkError::Quota(_) => Some(Self::OverAdmitted),
            ForkError::Unavailable(_) | ForkError::Slice => None,
        }
    }
    /// The public error this failure replays.
    #[must_use]
    pub fn error(&self) -> ServerError {
        match self {
            Self::NotFound => ForkError::NotFound.error(),
            Self::TooLarge => ForkError::TooLarge.error(),
            Self::TipChanged => ForkError::TipChanged.error(),
            Self::Changed => ForkError::NotEmpty.error(),
            Self::Expired => ForkError::Expired.error(),
            Self::Denied => ForkError::Denied.error(),
            Self::AuthorityMoved => ForkError::Moved("authority").error(),
            Self::EpochMoved => ForkError::Moved("epoch").error(),
            Self::OverAdmitted => ForkError::Quota(OVER_ADMITTED).error(),
        }
    }
}

/// The durable job row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkJobV1 {
    /// Hash of the request this job serves.
    pub binding: Hash,
    /// Destination namespace, as stored.
    pub dest_ns: String,
    /// Destination repository name.
    pub dest_repo: String,
    /// Source namespace, as stored.
    pub source_ns: String,
    /// Source repository name.
    pub source_repo: String,
    /// Source branch.
    pub source_ref: String,
    /// The published tip.
    pub tip: Hash,
    /// The published packmap head.
    pub packmap: Hash,
    /// The source's publication sequence when the job began.
    pub source_sequence: u64,
    /// The source's membership generation when the job began.
    pub source_generation: u64,
    /// Requested destination visibility.
    pub visibility: String,
    /// Creation time.
    pub created_ms: u64,
    /// Expiry time.
    pub expires_ms: u64,
    /// Current state.
    pub phase: Phase,
    /// The pack set, packmap head first.
    pub packs: Vec<PackRow>,
    /// Phase cursor: the next pack (Plan, Trees, Count, Publish).
    pub cursor: u32,
    /// External-base object ids not yet mapped to a pack.
    pub deps: Vec<Hash>,
    /// Index partition cursor of the copy.
    pub part: u16,
    /// Resume key within the partition.
    pub after: Option<Vec<u8>>,
    /// Source index rows scanned.
    pub scanned: u64,
    /// Index rows copied.
    pub copied: u64,
    /// Terminal refusal.
    pub failure: Option<Failure>,
    /// Admission and replay settlement data, if the request carried any.
    pub settle: Option<SettleV1>,
    /// The authority facts to re-check at registration, if the request had any.
    pub fence: Option<FenceV1>,
    /// The lineage anchor once done.
    pub result: Option<ForkResult>,
}

impl ForkJobV1 {
    pub(crate) fn source(&self) -> Result<RepoId, ForkError> {
        Ok(RepoId {
            namespace: NamespaceKey::from_stored(self.source_ns.clone()),
            name: RepoName::new(self.source_repo.clone()).map_err(|_| ForkError::NotFound)?,
        })
    }
    pub(crate) fn dest(&self) -> Result<RepoId, ForkError> {
        Ok(RepoId {
            namespace: NamespaceKey::from_stored(self.dest_ns.clone()),
            name: RepoName::new(self.dest_repo.clone()).map_err(|_| ForkError::NotFound)?,
        })
    }
    pub(crate) fn pack_ids(&self) -> std::collections::BTreeSet<Hash> {
        self.packs.iter().map(|p| p.id).collect()
    }
    pub(crate) fn pack_bytes(&self) -> u64 {
        self.packs.iter().map(|p| p.len).sum()
    }
    pub(crate) fn object_total(&self) -> u64 {
        self.packs.iter().map(|p| p.objects).sum()
    }
    /// Digest of the sorted pack ids.
    pub(crate) fn pack_set(&self) -> Hash {
        let mut bytes = Vec::new();
        for id in self.pack_ids() {
            bytes.extend_from_slice(&id);
        }
        hash(&bytes)
    }
    /// Whether the job has reached a terminal state.
    #[must_use]
    pub fn finished(&self) -> bool {
        matches!(self.phase, Phase::Done | Phase::Failed)
    }
}

/// Encode a job row.
///
/// # Errors
/// [`StoreError::Invalid`] when the row exceeds the value limit.
pub fn encode_job(job: &ForkJobV1) -> Result<Value, StoreError> {
    let mut bytes = vec![CODEC_V1];
    serde_json::to_writer(&mut bytes, job)
        .map_err(|_| StoreError::Invalid("fork job encoding".into()))?;
    if bytes.len() > crate::store::MAX_VALUE_BYTES {
        return Err(StoreError::Invalid("fork job exceeds value limit".into()));
    }
    Ok(Value::new(bytes))
}

/// Decode a job row, failing closed.
///
/// # Errors
/// [`StoreError::Corrupt`] for any malformed row.
pub fn decode_job(value: &Value) -> Result<ForkJobV1, StoreError> {
    match value.as_bytes().split_first() {
        Some((&CODEC_V1, body)) => {
            serde_json::from_slice(body).map_err(|_| StoreError::Corrupt("invalid fork job".into()))
        }
        _ => Err(StoreError::Corrupt("invalid fork job version".into())),
    }
}

/// Read a destination's job row.
///
/// # Errors
/// Storage failures.
pub async fn read_job<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    dest: &RepoId,
) -> Result<Option<(ForkJobV1, Value)>, StoreError> {
    let p = shards.coordinator(&dest.namespace);
    store
        .get(&p, &keys::fork_job(&dest.name))
        .await?
        .map(|raw| Ok((decode_job(&raw)?, raw)))
        .transpose()
}

/// The hash of everything a fork request binds: two requests with the same
/// binding are the same fork.
#[must_use]
pub fn binding(spec: &ForkSpec) -> Hash {
    let mut bytes = Vec::new();
    for part in [
        spec.source.namespace.as_str().as_bytes(),
        spec.source.name.as_str().as_bytes(),
        spec.source_ref.as_bytes(),
        spec.dest.namespace.as_str().as_bytes(),
        spec.dest.name.as_str().as_bytes(),
        spec.visibility_name().as_bytes(),
    ] {
        bytes.extend_from_slice(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    bytes.extend_from_slice(&spec.expected_tip);
    hash(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::SliceBudget;

    #[test]
    fn a_whole_default_allowance_is_fresh_and_nothing_else_is() {
        assert!(fresh(&SliceBudget::new(SLICE_CALLS)));
        assert!(fresh(&SliceBudget::new(SLICE_CALLS + 100)));
        // Smaller than the default: a unit that does not fit may fit later.
        assert!(!fresh(&SliceBudget::new(SLICE_CALLS - 1)));
        // Partly spent.
        let spent = SliceBudget::new(SLICE_CALLS);
        spent.charge_many(5).unwrap();
        assert!(!fresh(&spent));
        // A whole child of a nearly spent parent is not whole.
        let parent = SliceBudget::new(100);
        let child = parent.child(SLICE_CALLS);
        assert!(!fresh(&child));
        // A refusal by an ancestor is never a bound of the unit.
        let parent = SliceBudget::new(SLICE_CALLS + 10);
        let child = parent.child(SLICE_CALLS);
        parent.charge_many(SLICE_CALLS + 10).unwrap();
        assert!(child.charge().is_err());
        assert!(!fresh(&child));
    }

    #[test]
    fn only_a_spent_allowance_hides_a_retryable_error_and_a_refusal_is_never_hidden() {
        let budget = SliceBudget::new(1);
        let storage = ForkError::Unavailable("storage");
        assert!(!spent(&storage, &budget));
        budget.charge().unwrap();
        assert!(budget.charge().is_err());
        assert!(spent(&storage, &budget));
        assert!(spent(&ForkError::Slice, &budget));
        for refusal in [
            ForkError::NotFound,
            ForkError::TooLarge,
            ForkError::TipChanged,
            ForkError::NotEmpty,
            ForkError::Expired,
        ] {
            assert!(!spent(&refusal, &budget), "{refusal:?}");
        }
    }
}
