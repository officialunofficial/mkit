//! The transport-neutral request pipeline (PRD §5.4): the unary RPCs of
//! `mkit.transport.v1` over the storage contract.
//!
//! A binding calls [`Pipeline::authenticate`] (stages 0 and 1) from its
//! interceptor, then one entry point. A signed write runs one function per
//! stage, in order: `identify` (stage 1), `replay_lookup` (the stage 0
//! lookup), `authorize` (2), `admit` (3), `pre_receive` (5) and
//! `plan_and_apply` (4 and 6, one batch). Receipts (7) and outcomes (8)
//! land in M3/M5. The streaming procedures are [`Pipeline::begin_upload`]
//! ([`UploadSession`]) and [`Pipeline::download`] ([`DownloadStream`]).
//!
//! With the `test-faults` feature, `Pipeline::with_faults` installs
//! `FaultHooks` and [`Pipeline::authenticate`] reads per-request
//! `TestDirectives`; without it none of that exists in the binary.
//!
//! Behavior equals the servers it replaces: `mkit serve --http` (`Bearer`/`Open`:
//! no replay or quota, packmap-then-head on a non-atomic store),
//! `vcs-worker` (`AuthV2`: replay ledger, per-signer quota, atomic
//! advance) and `mkit serve` over ssh (`TransportIdentity`).

mod auth;
mod download;
#[cfg(feature = "test-faults")]
mod faults;
mod gate;
mod hooks;
mod outcome;
mod plan;
mod shard;
#[cfg(test)]
mod tests;
mod upload;

use core::future::Future;
use core::time::Duration;
use std::sync::Arc;

use mkit_core::hash::{Hash, to_hex_bytes};
use mkit_core::protocol::{AdvanceOutcome, PackKey};
use mkit_core::write_auth::MAX_CLOCK_LEAD_MS;
use tracing::Instrument;

use crate::download::DOWNLOAD_CHUNK_MAX;
use crate::error::{ADMISSION_CHALLENGE_TYPE, InvalidHeader, ServerError};
use crate::op::{AuthzFacts, OpKind, Operation, Procedure, RefUpdate};
use crate::quota::{DEFAULT_WRITE_QUOTA, QuotaCharge, QuotaLimits, QuotaScope};
use crate::refs::{self, strip_listed_prefix, validate_ref_name};
use crate::replay::{ReplayDecision, StoredResult, UpdateRefResult, classify};
use crate::repo::Addressing;
use crate::rt::Clock;
use crate::storage_error::{StorageOp, describe_and_map};
use crate::store::{
    Batch, BatchOutcome, BlobStore, Key, KeyClasses, NamespaceStore, Partition, StoreError, Value,
    codec, keys, read,
};
use crate::telemetry::{Metrics, Redactor};
use crate::upload::UploadLimits;

pub use auth::{AuthMode, Authenticated, RequestMeta};
pub use download::{DownloadChunk, DownloadStream};
#[cfg(feature = "test-faults")]
pub use faults::{
    CLOCK_SKEW_HEADER, FAULT_HEADER, FailOnce, FaultHooks, FaultPoint, RUN_TIMERS_HEADER,
    TIMER_MS_HEADER, TestDirectives,
};
pub use hooks::{
    Admission, AdmissionDecision, AdmissionInput, Authorizer, Challenge, DefaultAdmission, HookSet,
    Hooks, NoOutcomes, NoPreReceive, NoReceipts, OpenAuthorizer, OutboxRow, OutcomeSink,
    PreReceive, ReceiptSigner,
};
use outcome::Outcome;
use plan::{
    MAX_REPLAN, PRUNE_LIMIT, Plan, PlanClock, Planned, Snapshot, WriteKind, WriteRequest,
    plan_write, prune_sampled,
};
pub use shard::{ShardMap, SinglePartition};
pub use upload::{UploadMode, UploadSession};

/// Call the installed fault hooks at a fault point, returning early on
/// their error. Compiled out without `test-faults`.
macro_rules! fault {
    ($pipe:expr, $point:ident, $op:expr, $a:expr) => {
        #[cfg(feature = "test-faults")]
        $pipe
            .fault($crate::pipeline::FaultPoint::$point, $op, $a)
            .await?
    };
}
pub(crate) use fault;

/// Default bound from planning a batch to its commit (00-plan P-21,
/// SPEC-WRITE-GRANTS §5.5). It MUST exceed the clock skew between the
/// planner and the storage backend (Worker isolate vs Durable Object on
/// Workers; zero natively) plus the longest synchronous span before the
/// commit, by a wide margin: a batch that misses it commits nothing.
pub const MAX_APPLY_WINDOW: Duration = Duration::from_secs(10);

// A signed write's deadline is capped at `expires_at + MAX_CLOCK_LEAD_MS`
// (see `plan_clock`). That stays below the replay prune grace, so a stalled
// duplicate can never commit after its record could have been pruned.
const _: () = assert!(MAX_CLOCK_LEAD_MS.unsigned_abs() < read::REPLAY_PRUNE_GRACE_MS);

/// Default `ListRefs` scan page.
pub const DEFAULT_LIST_PAGE_LIMIT: u32 = 1000;

/// Counter: a write failed because its partition is full (00-plan P-24).
/// Alert on any increase.
pub const METRIC_PARTITION_FULL: &str = "mkit_server_partition_full";

/// Counter: [`Pipeline::with_header`] dropped an invalid or reserved
/// header; label `reason` (`name`, `reserved`, `value`).
pub const METRIC_HEADER_DROPPED: &str = "mkit_server_error_header_dropped_total";

/// A deployment's pipeline settings. Start from [`PipelineConfig::new`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PipelineConfig {
    /// How requests map to a repository (M0: `Single`).
    pub addressing: Addressing,
    /// How requests authenticate.
    pub auth: AuthMode,
    /// Upload caps, supplied by the binding (used by M0-05b).
    pub upload_limits: UploadLimits,
    /// Largest download chunk (used by M0-05b).
    pub download_chunk_max: usize,
    /// The default write quota: `Some(DEFAULT_WRITE_QUOTA)` for auth v2
    /// deployments (`vcs-worker` parity).
    pub write_quota: Option<QuotaLimits>,
    /// `ListRefs` scan page size, at least 1.
    pub list_page_limit: u32,
    /// Commit deadline window; see [`MAX_APPLY_WINDOW`].
    pub max_apply_window: Duration,
    /// Extra header names never to log.
    pub redactor: Redactor,
}

impl PipelineConfig {
    /// Defaults for `auth`: the default write quota only for auth v2.
    #[must_use]
    pub fn new(addressing: Addressing, auth: AuthMode, upload_limits: UploadLimits) -> Self {
        let write_quota = matches!(auth, AuthMode::AuthV2(_)).then_some(DEFAULT_WRITE_QUOTA);
        Self {
            addressing,
            auth,
            upload_limits,
            download_chunk_max: DOWNLOAD_CHUNK_MAX,
            write_quota,
            list_page_limit: DEFAULT_LIST_PAGE_LIMIT,
            max_apply_window: MAX_APPLY_WINDOW,
            redactor: Redactor::default(),
        }
    }
}

/// What the pipeline offers bindings (and a future `GetServerInfo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PipelineCapabilities {
    /// `AdvanceRefs` commits head and packmap in one batch.
    pub atomic_advance: bool,
}

/// [`Pipeline::health`]: whether each store answered its probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthStatus {
    /// The blob store.
    pub blobs: bool,
    /// The metadata store.
    pub meta: bool,
}

impl HealthStatus {
    /// Both stores are healthy.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.blobs && self.meta
    }
}

/// One `ListRefs` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefEntry {
    /// The name with the requested prefix stripped (SPEC-REFS §4).
    pub name: String,
    /// The object id.
    pub id: Hash,
}

/// The request pipeline over blobs `B`, metadata `N` and hooks `H`.
pub struct Pipeline<B, N, H = Hooks> {
    blobs: B,
    meta: N,
    hooks: H,
    shards: Arc<dyn ShardMap>,
    cfg: PipelineConfig,
    clock: Arc<dyn Clock>,
    metrics: Arc<dyn Metrics>,
    #[cfg(feature = "test-faults")]
    faults: Option<Arc<dyn faults::DynFaultHooks>>,
    gate: Option<Arc<gate::WriteGate>>,
}

impl<B, N, H> core::fmt::Debug for Pipeline<B, N, H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pipeline")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

/// A fixed-message `internal` whose detail only the server logs.
fn internal(detail: &'static str) -> ServerError {
    ServerError::internal("ref store request failed", detail)
}

/// Map a storage failure to a redacted `internal` and log its detail.
fn store_error(op: StorageOp, err: StoreError) -> ServerError {
    let op = match err {
        StoreError::Corrupt(_) => StorageOp::MetaDecode,
        _ => op,
    };
    let (line, err) = describe_and_map(op, err);
    tracing::warn!(detail = %line, "storage failure");
    err
}

fn meta_error(err: StoreError) -> ServerError {
    store_error(StorageOp::MetaCall, err)
}

/// The Connect method name, e.g. `UpdateRef`: the `procedure` label.
fn method(procedure: Procedure) -> &'static str {
    let path = procedure.connect_path();
    path.rsplit('/').next().unwrap_or(path)
}

/// Stage 0 lookup's answer for a replay decision: `None` continues.
fn replay_answer(decision: ReplayDecision) -> Result<Option<StoredResult>, ServerError> {
    match decision {
        ReplayDecision::New => Ok(None),
        ReplayDecision::Return(result) => Ok(Some(result)),
        ReplayDecision::FingerprintMismatch => Err(ServerError::invalid_argument(
            "nonce reused for a different operation",
        )),
        // `Resume` is for `UploadPack` only (M0-05b); a unary write that
        // finds its record in flight waits like any other.
        ReplayDecision::RetryLater | ReplayDecision::Resume => Err(ServerError::aborted_retryable(
            "operation already in flight; retry",
        )),
    }
}

fn ms(ms: i64) -> u64 {
    u64::try_from(ms).unwrap_or(0)
}

impl<B: BlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// A pipeline over `blobs` and `meta`, routed by [`SinglePartition`].
    ///
    /// # Errors
    /// `invalid_argument` for a configuration the store cannot serve: auth
    /// v2 needs every key class and atomic multi-key batches (so
    /// `FsLayoutStore` never runs auth v2); a store without atomic batches
    /// must report an implicit layout version; a store's layout version
    /// must be this binary's; the page limit and apply window must be
    /// positive.
    pub fn new(
        blobs: B,
        meta: N,
        hooks: H,
        cfg: PipelineConfig,
        clock: Arc<dyn Clock>,
        metrics: Arc<dyn Metrics>,
    ) -> Result<Self, ServerError> {
        let caps = meta.capabilities();
        let full = caps.atomic_multi_key && caps.key_classes == KeyClasses::All;
        let refused = if matches!(cfg.auth, AuthMode::AuthV2(_)) && !full {
            "auth v2 needs every key class and atomic multi-key batches"
        } else if !caps.atomic_multi_key && caps.implicit_layout_version.is_none() {
            "a store without atomic batches must report its layout version"
        } else if caps
            .implicit_layout_version
            .is_some_and(|v| v != keys::LAYOUT_VERSION)
        {
            "the store's layout version is not this server's"
        } else if cfg.list_page_limit == 0 || cfg.max_apply_window.is_zero() {
            "list page limit and apply window must be positive"
        } else {
            ""
        };
        if !refused.is_empty() {
            return Err(ServerError::invalid_argument(refused));
        }
        Ok(Self {
            blobs,
            meta,
            hooks,
            shards: Arc::new(SinglePartition),
            cfg,
            clock,
            metrics,
            #[cfg(feature = "test-faults")]
            faults: None,
            gate: None,
        })
    }

    /// Install test fault hooks (feature `test-faults` only).
    #[cfg(feature = "test-faults")]
    #[must_use]
    pub fn with_faults(mut self, hooks: impl FaultHooks + 'static) -> Self {
        self.faults = Some(Arc::new(hooks));
        self
    }

    #[cfg(feature = "test-faults")]
    async fn fault(
        &self,
        point: FaultPoint,
        op: &Operation,
        a: &Authenticated,
    ) -> Result<(), ServerError> {
        match &self.faults {
            Some(hooks) => hooks.at_boxed(point, op, a.test_directives()).await,
            None => Ok(()),
        }
    }

    /// Route partitions with `shards` instead of [`SinglePartition`].
    #[must_use]
    pub fn with_shards(mut self, shards: Arc<dyn ShardMap>) -> Self {
        self.shards = shards;
        self
    }

    /// Run the writes to one partition one at a time in this process: each
    /// write's read-plan-apply loop waits for the partition's gate, as a
    /// Durable Object's input gate serializes them on Workers. For a
    /// single-process server over a single-writer store (native `SQLite`,
    /// which commits one batch at a time anyway): concurrent writes that
    /// share a key, such as one signer's quota window, then never exhaust
    /// the re-plan bound and fail `aborted`. Reads are not gated. Several
    /// processes on one store still race, through the optimistic loop.
    #[must_use]
    pub fn with_write_gate(mut self) -> Self {
        self.gate = Some(Arc::new(gate::WriteGate::new()));
        self
    }

    /// A second pipeline over the same stores, hooks, shard map, clock,
    /// metrics, test fault hooks and write gate, authenticating with
    /// `auth`: how one server hosts bindings with different identity
    /// sources on one root (the enc listener's `TransportIdentity` beside
    /// an HTTP listener's bearer token or auth v2) while its writes to a
    /// partition still pass one gate. Every other setting is `self`'s.
    ///
    /// # Errors
    /// As [`Self::new`] for `auth` over these stores.
    pub fn with_auth(&self, auth: AuthMode) -> Result<Self, ServerError>
    where
        B: Clone,
        N: Clone,
        H: Clone,
    {
        let mut cfg = self.cfg.clone();
        cfg.auth = auth;
        let mut sibling = Self::new(
            self.blobs.clone(),
            self.meta.clone(),
            self.hooks.clone(),
            cfg,
            Arc::clone(&self.clock),
            Arc::clone(&self.metrics),
        )?;
        sibling.shards = Arc::clone(&self.shards);
        sibling.gate.clone_from(&self.gate);
        #[cfg(feature = "test-faults")]
        sibling.faults.clone_from(&self.faults);
        Ok(sibling)
    }

    /// Stages 0a and 1: verify credentials and map the identity. Pure and
    /// synchronous; writes no state. The result is bound to
    /// `meta.procedure`. Under `test-faults` it also reads the request's
    /// test directives: the clock skew shifts business time, including the
    /// auth v2 validity window, for this request only.
    ///
    /// # Errors
    /// `unauthenticated` for missing or invalid credentials;
    /// `invalid_argument` for a malformed test directive. A rejection is
    /// recorded like any failed request (procedure, code, latency), with
    /// principal `none`: no entry point runs after it to record it.
    pub fn authenticate(&self, meta: &RequestMeta<'_>) -> Result<Authenticated, ServerError> {
        tracing::debug!(stage = "authenticate", procedure = method(meta.procedure));
        let result = self.authenticate_inner(meta);
        if let Err(err) = &result {
            self.outcome_for(meta.procedure, "none").record(Err(err));
        }
        result
    }

    fn authenticate_inner(&self, meta: &RequestMeta<'_>) -> Result<Authenticated, ServerError> {
        #[cfg(feature = "test-faults")]
        let directives = TestDirectives::from_headers(meta.header)?;
        #[cfg(feature = "test-faults")]
        let skew = directives.clock_skew_ms;
        #[cfg(not(feature = "test-faults"))]
        let skew = 0;
        let now = self.clock.now_ms().saturating_add(skew);
        let mut a = auth::authenticate(&self.cfg.auth, meta, now)?;
        a.business_skew_ms = skew;
        #[cfg(feature = "test-faults")]
        a.set_test_directives(directives);
        Ok(a)
    }

    /// Every ref of the repository under `prefix` at a path-component
    /// boundary, with the prefix and its `/` stripped (SPEC-REFS §4, see
    /// [`refs::list_scan_prefix`]), read page by page.
    ///
    /// # Errors
    /// `invalid_argument` for an invalid prefix or one over
    /// [`refs::MAX_REF_NAME_BYTES`]; the authorizer's error; `internal`
    /// for a storage failure.
    pub async fn list_refs(
        &self,
        a: &Authenticated,
        prefix: &str,
    ) -> Result<Vec<RefEntry>, ServerError> {
        let kind = OpKind::ListRefs {
            prefix: prefix.to_owned(),
        };
        self.observe(a, async {
            if prefix.trim_end_matches('/').len() > refs::MAX_REF_NAME_BYTES {
                return Err(ServerError::invalid_argument(refs::REF_NAME_TOO_LONG));
            }
            if !refs::validate_ref_prefix(prefix) {
                return Err(ServerError::invalid_argument(
                    "prefix is invalid (SPEC-REFS §3)",
                ));
            }
            let op = self.identify(a, kind)?;
            self.authorize(&op).await?;
            #[cfg(feature = "test-faults")]
            faults::run_timers(
                a.test_directives(),
                &self.meta,
                self.shards.as_ref(),
                &op.repo,
                self.clock.as_ref(),
                ms(self.clock.now_ms().saturating_add(a.business_skew_ms)),
            )
            .await?;
            let p = self.shards.ref_index(&op.repo);
            let scan = refs::list_scan_prefix(prefix);
            let (mut out, mut after) = (Vec::new(), None);
            loop {
                let limit = self.cfg.list_page_limit;
                let page =
                    read::list_refs(&self.meta, &p, &op.repo.name, &scan, after.as_ref(), limit)
                        .await
                        .map_err(meta_error)?;
                // Every scanned name starts with `scan`.
                out.extend(page.refs.into_iter().filter_map(|(name, id)| {
                    let name = strip_listed_prefix(&name, prefix)?.to_owned();
                    Some(RefEntry { name, id })
                }));
                match page.next {
                    Some(next) => after = Some(next),
                    None => return Ok(out),
                }
            }
        })
        .await
    }

    /// One ref's id, if it exists.
    ///
    /// # Errors
    /// `invalid_argument` for an invalid name; the authorizer's error;
    /// `internal` for a storage failure.
    pub async fn read_ref(
        &self,
        a: &Authenticated,
        name: &str,
    ) -> Result<Option<Hash>, ServerError> {
        let kind = OpKind::ReadRef {
            name: name.to_owned(),
        };
        self.observe(a, async {
            check_ref_name(name)?;
            let op = self.identify(a, kind)?;
            self.authorize(&op).await?;
            let p = self.shards.ref_shard(&op.repo, name);
            read::read_ref(&self.meta, &p, &op.repo.name, name)
                .await
                .map_err(meta_error)
        })
        .await
    }

    /// Compare-and-swap one ref. A conflict is a result, not an error.
    ///
    /// # Errors
    /// See the stage functions; a stored rejection comes back as its error.
    pub async fn update_ref(
        &self,
        a: &Authenticated,
        upd: RefUpdate,
    ) -> Result<UpdateRefResult, ServerError> {
        self.observe(a, async {
            check_ref_name(&upd.name)?;
            match self.write(a, OpKind::UpdateRef(upd)).await? {
                StoredResult::UpdateRef(result) => Ok(result),
                other => Err(stored_mismatch(&other)),
            }
        })
        .await
    }

    /// Advance a branch head and its packmap together: one batch on an
    /// atomic store, else packmap then head (`Transport::advance_refs`'s
    /// default order).
    ///
    /// # Errors
    /// See the stage functions; a stored rejection comes back as its error.
    pub async fn advance_refs(
        &self,
        a: &Authenticated,
        head: RefUpdate,
        packmap: RefUpdate,
    ) -> Result<AdvanceOutcome, ServerError> {
        self.observe(a, async {
            check_ref_name(&head.name)?;
            check_ref_name(&packmap.name)?;
            match self.write(a, OpKind::AdvanceRefs { head, packmap }).await? {
                StoredResult::AdvanceRefs(outcome) => Ok(outcome),
                other => Err(stored_mismatch(&other)),
            }
        })
        .await
    }

    /// Whether the pack is present (M0 membership: presence in the blob
    /// store).
    ///
    /// # Errors
    /// The authorizer's error; `internal` for a storage failure.
    pub async fn pack_exists(&self, a: &Authenticated, key: PackKey) -> Result<bool, ServerError> {
        self.observe(a, async {
            let op = self.identify(a, OpKind::PackExists { key })?;
            self.authorize(&op).await?;
            let head = self.blobs.head(&key).await;
            Ok(head
                .map_err(|e| store_error(StorageOp::BlobHead, e))?
                .is_some())
        })
        .await
    }

    /// Stages 0–3 of an `UploadPack` whose header declared `pack_id` and
    /// `total_bytes` (`None` when absent): framing, the signed `pack:`
    /// commitment, the replay lookup, authorization, admission and, for a
    /// new signed operation, the reservation. Nothing is read from the
    /// stream before it returns.
    ///
    /// # Errors
    /// The header's [`crate::upload::UploadError`]; `unauthenticated` when
    /// the header differs from the signed commitment; a stored or
    /// in-flight replay answer; a hook's error; the reservation's error.
    pub async fn begin_upload(
        &self,
        a: &Authenticated,
        pack_id: Option<&[u8]>,
        total_bytes: Option<u64>,
    ) -> Result<UploadSession<'_, B, N, H>, ServerError> {
        UploadSession::begin(self, a, pack_id, total_bytes).await
    }

    /// A pack's bytes as chunks of at most `download_chunk_max` bytes.
    ///
    /// # Errors
    /// `not_found` for a missing pack, before any chunk; the authorizer's
    /// error; `internal` for a storage failure.
    ///
    /// The request is recorded `ok` when the `last` chunk is yielded, with
    /// its error at the first failure, and as `canceled` when the stream is
    /// dropped before either.
    pub async fn download(
        &self,
        a: &Authenticated,
        key: PackKey,
    ) -> Result<DownloadStream, ServerError> {
        let mut outcome = self.outcome(a);
        let opened = async {
            let op = self.identify(a, OpKind::DownloadPack { key })?;
            self.authorize(&op).await?;
            let body = self.blobs.get(&key, None).await;
            match body.map_err(|e| store_error(StorageOp::BlobGet, e))? {
                Some(body) => Ok(body),
                None => Err(ServerError::not_found("pack not found")),
            }
        }
        .instrument(outcome.span.clone())
        .await;
        match opened {
            Ok(body) => {
                let max = self.cfg.download_chunk_max;
                Ok(DownloadStream::new(body, max, Some(outcome)))
            }
            Err(err) => {
                outcome.record(Err(&err));
                Err(err)
            }
        }
    }

    /// Probe both stores.
    pub async fn health(&self) -> HealthStatus {
        HealthStatus {
            blobs: self.blobs.probe().await.is_ok(),
            meta: self.meta.probe().await.is_ok(),
        }
    }

    /// How this pipeline authenticates (the ssh session requires
    /// `TransportIdentity`; an HTTP adapter may pre-check a bearer token
    /// before it spends resources on the request).
    #[must_use]
    pub fn auth_mode(&self) -> &AuthMode {
        &self.cfg.auth
    }

    /// The upload caps `begin_upload` applies: a binding that validates
    /// framing itself uses the same ones.
    #[cfg(feature = "ssh")]
    pub(crate) fn upload_limits(&self) -> UploadLimits {
        self.cfg.upload_limits
    }

    /// The metadata store, for the ssh tests' state checks.
    #[cfg(all(test, feature = "ssh"))]
    pub(crate) fn meta_store(&self) -> &N {
        &self.meta
    }

    /// What this pipeline offers.
    pub fn capabilities(&self) -> PipelineCapabilities {
        PipelineCapabilities {
            atomic_advance: self.meta.capabilities().atomic_multi_key,
        }
    }

    /// Add a response header to `err`, counting a dropped one in
    /// [`METRIC_HEADER_DROPPED`] (what [`ServerError::with_header`] cannot
    /// do without a metrics sink). The value is never logged.
    #[must_use]
    pub fn with_header(&self, err: ServerError, name: &str, value: &str) -> ServerError {
        match err.clone().try_with_header(name, value) {
            Ok(err) => err,
            Err(reason) => {
                let label = match reason {
                    InvalidHeader::Name => "name",
                    InvalidHeader::Reserved => "reserved",
                    InvalidHeader::Value => "value",
                };
                tracing::warn!(header = ?name, %reason, "dropped an error response header");
                self.metrics
                    .incr(METRIC_HEADER_DROPPED, &[("reason", label)], 1);
                err
            }
        }
    }

    /// The span, request metrics and outcome log around one entry point.
    async fn observe<T>(
        &self,
        a: &Authenticated,
        fut: impl Future<Output = Result<T, ServerError>>,
    ) -> Result<T, ServerError> {
        let mut outcome = self.outcome(a);
        let result = fut.instrument(outcome.span.clone()).await;
        outcome.record(result.as_ref().map(|_| ()));
        result
    }

    /// The span and recorder of one request.
    fn outcome(&self, a: &Authenticated) -> Outcome {
        self.outcome_for(a.procedure(), a.principal.kind())
    }

    /// The span and recorder of one request to `procedure` as `principal`.
    fn outcome_for(&self, procedure: Procedure, principal: &'static str) -> Outcome {
        let repo = match &self.cfg.addressing {
            Addressing::Single { repo } => repo.name.as_str(),
        };
        let procedure = method(procedure);
        let span = tracing::info_span!("mkit.server.rpc", procedure, repo, principal);
        let (metrics, clock) = (self.metrics.clone(), self.clock.clone());
        Outcome::new(span, procedure, metrics, clock, self.cfg.redactor.clone())
    }

    /// A signed or unsigned unary write, stage by stage. In steady state
    /// a signed write costs two backend calls: one `get_many` before any
    /// hook runs (the replay record and the snapshot) and one `apply`.
    async fn write(&self, a: &Authenticated, kind: OpKind) -> Result<StoredResult, ServerError> {
        let mut op = self.identify(a, kind)?;
        fault!(self, AfterAuthenticate, &op, a);
        let (kind, refs, p) = self.ref_writes(&op)?;
        let ahead = self.read_ahead(&op, &p, &refs).await?;
        if let Some(stored) = Self::replay_lookup(&op, ahead.as_ref())? {
            return Ok(stored);
        }
        op.authz = self.authorize(&op).await?;
        fault!(self, AfterAuthorize, &op, a);
        let charges = self.admit(AdmissionInput::new(&op)).await?;
        self.pre_receive(&op).await?;
        let write = (kind, refs.as_slice(), charges.as_slice());
        self.plan_and_apply(&op, a, &p, write, ahead).await
    }

    /// Stage 1: the typed operation, for the procedure `a` was
    /// authenticated for only.
    fn identify(&self, a: &Authenticated, kind: OpKind) -> Result<Operation, ServerError> {
        if a.procedure() != kind.procedure() {
            return Err(ServerError::unauthenticated(
                "credentials were checked for another procedure",
            ));
        }
        if matches!(self.cfg.auth, AuthMode::AuthV2(_))
            && kind.procedure().is_write()
            && a.auth.is_none()
        {
            return Err(ServerError::unauthenticated(
                "missing auth v2 authorization",
            ));
        }
        let repo = self.cfg.addressing.resolve(None)?.clone();
        let principal = a.principal.clone();
        Ok(Operation::new(repo, principal, a.auth.clone(), kind))
    }

    /// A unary write's ref writes in decision order (packmap first) and
    /// the ref shard they commit in, which a head and its packmap share.
    fn ref_writes(
        &self,
        op: &Operation,
    ) -> Result<(WriteKind, Vec<RefUpdate>, Partition), ServerError> {
        let (kind, refs) = match &op.kind {
            OpKind::UpdateRef(u) => (WriteKind::UpdateRef, vec![u.clone()]),
            OpKind::AdvanceRefs { head, packmap } => {
                (WriteKind::AdvanceRefs, vec![packmap.clone(), head.clone()])
            }
            _ => return Err(internal("not a unary write")),
        };
        let p = self.shards.ref_shard(&op.repo, &refs[0].name);
        if refs
            .iter()
            .any(|r| self.shards.ref_shard(&op.repo, &r.name) != p)
        {
            return Err(internal("shard map splits a head from its packmap"));
        }
        Ok((kind, refs, p))
    }

    /// One `get_many` before any hook, on an atomic store: the write's
    /// refs and layout version, and for a signed write its replay record,
    /// the grant epoch and the default quota key it will most likely be
    /// charged. Keys admission adds later are read after it.
    async fn read_ahead(
        &self,
        op: &Operation,
        p: &Partition,
        refs: &[RefUpdate],
    ) -> Result<Option<Snapshot>, ServerError> {
        let caps = self.meta.capabilities();
        if !caps.atomic_multi_key {
            return Ok(None);
        }
        let mut wanted: Vec<Key> = refs
            .iter()
            .map(|r| keys::ref_key(&op.repo.name, &r.name))
            .collect();
        if caps.implicit_layout_version.is_none() {
            wanted.push(keys::layout_version());
        }
        if let Some(auth) = &op.auth {
            wanted.push(keys::replay(&auth.replay_scope));
            wanted.push(keys::grant_epoch());
            if self.cfg.write_quota.is_some() {
                let scope = QuotaScope::for_signer(&op.repo.namespace, &auth.signer);
                wanted.push(keys::quota(&scope));
            }
        }
        let mut snap = Snapshot::default();
        self.fill(p, &mut snap, wanted).await?;
        Ok(Some(snap))
    }

    /// Read every key of `wanted` that `snap` lacks, in one `get_many`.
    async fn fill(
        &self,
        p: &Partition,
        snap: &mut Snapshot,
        mut wanted: Vec<Key>,
    ) -> Result<(), ServerError> {
        wanted.retain(|k| !snap.contains(k));
        wanted.sort();
        wanted.dedup();
        if wanted.is_empty() {
            return Ok(());
        }
        let values = self.meta.get_many(p, &wanted).await.map_err(meta_error)?;
        for (key, value) in wanted.into_iter().zip(values) {
            snap.insert(key, value);
        }
        Ok(())
    }

    /// Stage 0 lookup: a signed write's replay record, from the read-ahead
    /// and before any hook. A committed record's result is returned, an
    /// in-flight one is `aborted`; a new operation continues.
    fn replay_lookup(
        op: &Operation,
        ahead: Option<&Snapshot>,
    ) -> Result<Option<StoredResult>, ServerError> {
        let (Some(auth), Some(snap)) = (&op.auth, ahead) else {
            return Ok(None);
        };
        tracing::debug!(stage = "replay_lookup");
        let stored = snap.get(&keys::replay(&auth.replay_scope));
        let record = stored.map(codec::decode_replay_record).transpose();
        let record = record.map_err(meta_error)?;
        replay_answer(classify(record.as_ref(), &auth.fingerprint))
    }

    /// Stage 2: the facts it returns become `op.authz` before admission.
    async fn authorize(&self, op: &Operation) -> Result<AuthzFacts, ServerError> {
        tracing::debug!(stage = "authorize");
        self.hooks.authorizer().authorize(op).await
    }

    /// Stage 3. A challenge is `permission_denied` "admission required" in
    /// M0 (the 402 response lands in M3); nothing is written for it.
    async fn admit(&self, mut input: AdmissionInput<'_>) -> Result<Vec<QuotaCharge>, ServerError> {
        tracing::debug!(stage = "admission");
        input.write_quota = self.cfg.write_quota;
        match self.hooks.admission().admit(&input).await? {
            AdmissionDecision::Allow { charges, .. } => Ok(charges),
            AdmissionDecision::Challenge { .. } => {
                Err(ServerError::permission_denied("admission required"))
            }
            AdmissionDecision::Deny(err) => Err(deny_status(err)),
        }
    }

    /// Stage 5 (no pack on a unary write).
    async fn pre_receive(&self, op: &Operation) -> Result<(), ServerError> {
        tracing::debug!(stage = "pre_receive");
        self.hooks.pre_receive().check(op, None).await
    }

    /// Stages 4 and 6: plan and apply, as one batch on an atomic store or
    /// as sequential single-ref batches on a non-atomic one.
    async fn plan_and_apply(
        &self,
        op: &Operation,
        a: &Authenticated,
        p: &Partition,
        (kind, refs, charges): (WriteKind, &[RefUpdate], &[QuotaCharge]),
        ahead: Option<Snapshot>,
    ) -> Result<StoredResult, ServerError> {
        let caps = self.meta.capabilities();
        let replay = upload::replay_guard(op);
        let mut req = WriteRequest {
            repo: &op.repo.name,
            kind,
            refs,
            replay,
            charges,
            grant: op.authz.grant,
            layout_version: caps.implicit_layout_version.is_none(),
            rejection: None,
        };
        if caps.atomic_multi_key || replay.is_some() || !charges.is_empty() {
            return self.apply_atomic(op, a, p, &req, ahead).await;
        }
        // `Transport::advance_refs`'s default: packmap first, then head.
        req.kind = WriteKind::UpdateRef;
        for (i, update) in refs.iter().enumerate() {
            req.refs = core::slice::from_ref(update);
            let result = self.apply_loop(op, a, p, &req, None).await?;
            if let StoredResult::UpdateRef(UpdateRefResult::Conflict { .. }) = result {
                if kind == WriteKind::UpdateRef {
                    return Ok(result);
                }
                return Ok(StoredResult::AdvanceRefs(if i == 0 {
                    AdvanceOutcome::PackmapConflict
                } else {
                    AdvanceOutcome::HeadConflict
                }));
            }
        }
        Ok(match kind {
            WriteKind::UpdateRef => StoredResult::UpdateRef(UpdateRefResult::Committed),
            _ => StoredResult::AdvanceRefs(AdvanceOutcome::Committed),
        })
    }

    /// [`Self::apply_loop`] on a store with atomic multi-key batches, which
    /// replay records and quota need.
    async fn apply_atomic(
        &self,
        op: &Operation,
        a: &Authenticated,
        p: &Partition,
        req: &WriteRequest<'_>,
        ahead: Option<Snapshot>,
    ) -> Result<StoredResult, ServerError> {
        if !self.meta.capabilities().atomic_multi_key {
            return Err(internal("replay and quota need atomic multi-key batches"));
        }
        self.apply_loop(op, a, p, req, ahead).await
    }

    /// The bounded optimistic loop: read, plan, apply. The first attempt
    /// plans on `ahead`, reading only what it lacks. A guard another
    /// writer broke re-plans up to [`MAX_REPLAN`] times, then `aborted`; a
    /// lost prune race retries once without the prune, uncounted. A missed
    /// deadline re-plans once while the envelope is still valid at the
    /// failed commit, then `unavailable` (SPEC-WRITE-GRANTS §5.5).
    async fn apply_loop(
        &self,
        op: &Operation,
        a: &Authenticated,
        p: &Partition,
        req: &WriteRequest<'_>,
        mut ahead: Option<Snapshot>,
    ) -> Result<StoredResult, ServerError> {
        #[cfg(not(feature = "test-faults"))]
        let _ = op;
        // Held until the loop ends (see `with_write_gate`).
        let _gate = match &self.gate {
            Some(gate) => Some(gate.enter(p).await),
            None => None,
        };
        let skew_ms = a.business_skew_ms;
        let (mut replans, mut deadline_missed, mut prune_ok) = (0, false, true);
        loop {
            let clock = self.plan_clock(skew_ms, req);
            let base = ahead.take().unwrap_or_default();
            let snap = self.read_snapshot(p, req, &clock, base, prune_ok).await?;
            let plan = match plan_write(req, &snap, &clock)? {
                Planned::Done(result) => return Ok(result),
                Planned::Apply(plan) => plan,
            };
            let Plan {
                batch,
                on_commit,
                replay_index,
                epoch_index,
                prune,
                prune_from,
            } = plan;
            if req.kind != WriteKind::UploadReserve {
                fault!(self, BeforeFinalApply, op, a);
            }
            tracing::debug!(stage = "apply", replans);
            match self.meta.apply(p, batch).await {
                Ok(BatchOutcome::Committed) => {
                    #[cfg(feature = "test-faults")]
                    if let OpKind::UpdateRef(upd) = &op.kind
                        && matches!(
                            on_commit,
                            StoredResult::UpdateRef(UpdateRefResult::Committed)
                        )
                    {
                        let timer_partition = self.shards.ref_shard(&op.repo, &upd.name);
                        faults::schedule_timer(
                            a.test_directives(),
                            &self.meta,
                            &timer_partition,
                            &op.repo.name,
                            &upd.name,
                            ms(clock.business_now_ms),
                        )
                        .await?;
                    }
                    return Ok(on_commit);
                }
                Ok(BatchOutcome::DeadlinePassed { backend_now }) => {
                    tracing::info!(
                        backend_now,
                        deadline = clock.deadline(),
                        "commit deadline passed"
                    );
                    // Validity at the failed commit, on both clocks.
                    let now = self.clock.now_ms().saturating_add(skew_ms);
                    let backend = i64::try_from(backend_now).unwrap_or(i64::MAX);
                    let valid = req
                        .replay
                        .is_none_or(|r| now.max(backend) <= r.expires_at_ms);
                    if deadline_missed || !valid {
                        return Err(ServerError::unavailable("commit deadline passed; retry"));
                    }
                    deadline_missed = true;
                }
                Ok(BatchOutcome::PreconditionFailed { index, observed }) => {
                    if Some(index) == replay_index {
                        return replay_raced(req, observed.as_ref());
                    }
                    if Some(index) == epoch_index {
                        return Err(plan::epoch_moved());
                    }
                    if index >= prune_from && prune_ok {
                        prune_ok = false;
                        continue;
                    }
                    replans += 1;
                    if replans > MAX_REPLAN {
                        return Err(ServerError::aborted_retryable("write contention; retry"));
                    }
                }
                Err(StoreError::Full) => return Err(self.partition_full(p, prune).await),
                Err(e) => return Err(meta_error(e)),
            }
        }
    }

    /// The deadline uses the injected clock unshifted; business time adds
    /// the request's skew. A signed write's deadline is also capped at
    /// `expires_at + MAX_CLOCK_LEAD_MS`, below the replay prune grace.
    fn plan_clock(&self, skew_ms: i64, req: &WriteRequest<'_>) -> PlanClock {
        let now = self.clock.now_ms();
        let lead = MAX_CLOCK_LEAD_MS.unsigned_abs();
        PlanClock {
            plan_time_ms: ms(now),
            business_now_ms: now.saturating_add(skew_ms),
            max_apply_window_ms: u64::try_from(self.cfg.max_apply_window.as_millis())
                .unwrap_or(u64::MAX),
            deadline_cap: req.replay.map(|r| ms(r.expires_at_ms).saturating_add(lead)),
        }
    }

    /// Everything [`plan_write`] reads that `base` lacks, in one
    /// `get_many`. A sampled write ([`prune_sampled`]) first scans a
    /// bounded page of prune candidates, on the real clock, never the
    /// business clock.
    async fn read_snapshot(
        &self,
        p: &Partition,
        req: &WriteRequest<'_>,
        clock: &PlanClock,
        mut snap: Snapshot,
        prune: bool,
    ) -> Result<Snapshot, ServerError> {
        let now = clock.plan_time_ms;
        if prune && prune_sampled(req, now) {
            if req.replay.is_some() {
                snap.expired_replays = read::expired_replay_keys(&self.meta, p, now, PRUNE_LIMIT)
                    .await
                    .map_err(meta_error)?;
            }
            if let Some(window) = req.charges.iter().map(|c| c.limits.window_ms).max() {
                snap.stale_quotas =
                    read::stale_quota_keys(&self.meta, p, now, ms(window), PRUNE_LIMIT)
                        .await
                        .map_err(meta_error)?;
            }
        }
        let mut wanted = req.read_keys();
        wanted.extend(snap.stale_quotas.iter().map(|(_, quota)| quota.clone()));
        self.fill(p, &mut snap, wanted).await?;
        Ok(snap)
    }

    /// A full partition: count it, retry the prune alone (deletes still
    /// work) and fail closed with a retryable `unavailable`.
    async fn partition_full(&self, p: &Partition, prune: Option<Batch>) -> ServerError {
        self.metrics.incr(METRIC_PARTITION_FULL, &[], 1);
        let name = p.encode().map(|b| to_hex_bytes(&b)).unwrap_or_default();
        tracing::error!(partition = %name, "storage partition full");
        if let Some(prune) = prune
            && let Err(e) = self.meta.apply(p, prune).await
        {
            tracing::warn!(error = %e, "prune on a full partition failed");
        }
        ServerError::unavailable("storage partition full")
    }
}

/// A denial is 403, never 402: only [`ServerError::admission_challenge`],
/// with its `AdmissionChallenge` detail, answers 402
/// (SPEC-TRANSPORT-CONNECT §5).
fn deny_status(err: ServerError) -> ServerError {
    let challenge = err
        .details()
        .iter()
        .any(|d| d.type_name == ADMISSION_CHALLENGE_TYPE);
    if err.http_status() == Some(402) && !challenge {
        err.with_http_status(403)
    } else {
        err
    }
}

/// A ref name the pipeline reads or writes: at most
/// [`refs::MAX_REF_NAME_BYTES`], the SPEC-REFS §3 grammar, and under
/// `refs/` ([`refs::is_served_ref_name`], R-86), each refused by name.
fn check_ref_name(name: &str) -> Result<(), ServerError> {
    if name.len() > refs::MAX_REF_NAME_BYTES {
        Err(ServerError::invalid_argument(refs::REF_NAME_TOO_LONG))
    } else if !validate_ref_name(name) {
        Err(ServerError::invalid_argument(
            "ref name is invalid (SPEC-REFS §3)",
        ))
    } else if refs::is_served_ref_name(name) {
        Ok(())
    } else {
        Err(ServerError::invalid_argument(refs::REF_NAME_OUTSIDE_REFS))
    }
}

/// A result of another procedure: a stored rejection is its error; any
/// other kind is corruption (the fingerprint covers the procedure).
fn stored_mismatch(result: &StoredResult) -> ServerError {
    match result {
        StoredResult::Rejected(rejection) => {
            ServerError::new(rejection.code(), rejection.message().to_owned())
        }
        _ => internal("stored result is for another procedure"),
    }
}

/// The replay guard failed: another request with this nonce committed
/// first. Classify its record like stage 0 does.
fn replay_raced(
    req: &WriteRequest<'_>,
    observed: Option<&Value>,
) -> Result<StoredResult, ServerError> {
    let (Some(replay), Some(value)) = (req.replay, observed) else {
        return Err(ServerError::aborted_retryable(
            "operation already in flight; retry",
        ));
    };
    let record = codec::decode_replay_record(value).map_err(meta_error)?;
    replay_answer(classify(Some(&record), &replay.fingerprint))?
        .ok_or_else(|| ServerError::aborted_retryable("operation already in flight; retry"))
}
