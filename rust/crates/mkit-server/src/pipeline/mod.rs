//! The transport-neutral request pipeline (PRD §5.4): the unary RPCs of
//! `mkit.transport.v1` over the storage contract.
//!
//! A binding calls [`Pipeline::authenticate`] (stages 0 and 1) from its
//! interceptor, then one entry point. A signed write runs one function per
//! stage, in order: `identify` (stage 1), `replay_lookup` (the stage 0
//! lookup), `authorize` (2), `admit` (3), `pre_receive` (5) and
//! `plan_and_apply` (4 and 6, one batch). Receipts (7) and outcomes (8)
//! land in M3/M5.
//!
//! Behavior equals today's servers: `mkit serve --http` (`Bearer`/`Open`:
//! no replay or quota, packmap-then-head on a non-atomic store),
//! `vcs-worker` (`AuthV2`: replay ledger, per-signer quota, atomic
//! advance) and `mkit serve` over ssh (`TransportIdentity`).

mod auth;
mod hooks;
mod plan;
mod shard;
#[cfg(test)]
mod tests;

use core::future::Future;
use core::time::Duration;
use std::sync::Arc;

use mkit_core::hash::{Hash, to_hex_bytes};
use mkit_core::protocol::{AdvanceOutcome, PackKey};
use tracing::Instrument;

use crate::download::DOWNLOAD_CHUNK_MAX;
use crate::error::{InvalidHeader, ServerError};
use crate::op::{OpKind, Operation, Procedure, RefUpdate};
use crate::quota::{DEFAULT_WRITE_QUOTA, QuotaCharge, QuotaLimits};
use crate::refs::{self, strip_listed_prefix, validate_ref_name};
use crate::replay::{ReplayDecision, ReplayKey, StoredResult, UpdateRefResult, classify};
use crate::repo::Addressing;
use crate::rt::Clock;
use crate::storage_error::{StorageOp, describe_and_map};
use crate::store::{
    Batch, BatchOutcome, BlobStore, KeyClasses, NamespaceStore, Partition, StoreError, Value,
    codec, keys::LAYOUT_VERSION, read,
};
use crate::telemetry::{METRIC_LATENCY, METRIC_REQUESTS, Metrics, Redactor};
use crate::upload::UploadLimits;

pub use auth::{AuthMode, Authenticated, RequestMeta};
pub use hooks::{
    Admission, AdmissionDecision, AdmissionInput, Authorizer, Challenge, DefaultAdmission, HookSet,
    Hooks, NoOutcomes, NoPreReceive, NoReceipts, OpenAuthorizer, OutboxRow, OutcomeSink,
    PreReceive, ReceiptSigner,
};
use plan::{
    MAX_REPLAN, PRUNE_LIMIT, Plan, PlanClock, Planned, ReplayGuard, Snapshot, WriteKind,
    WriteRequest, plan_write,
};
pub use shard::{ShardMap, SinglePartition};

/// Default bound from planning a batch to its commit (00-plan P-21,
/// SPEC-WRITE-GRANTS §5.5). It MUST exceed the clock skew between the
/// planner and the storage backend (Worker isolate vs Durable Object on
/// Workers; zero natively) plus the longest synchronous span before the
/// commit, by a wide margin: a batch that misses it commits nothing.
pub const MAX_APPLY_WINDOW: Duration = Duration::from_secs(10);

/// Default `ListRefs` scan page.
pub const DEFAULT_LIST_PAGE_LIMIT: u32 = 1000;

/// Counter: a write failed because its partition is full (00-plan P-24).
/// Alert on any increase.
pub const METRIC_PARTITION_FULL: &str = "mkit_server_partition_full";

/// Counter: [`Pipeline::with_header`] dropped an invalid or reserved
/// header; label `reason` (`name`, `reserved`, `value`).
pub const METRIC_HEADER_DROPPED: &str = "mkit_server_error_header_dropped_total";

/// A deployment's pipeline settings.
#[derive(Debug, Clone)]
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
            .is_some_and(|v| v != LAYOUT_VERSION)
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
        })
    }

    /// Route partitions with `shards` instead of [`SinglePartition`].
    #[must_use]
    pub fn with_shards(mut self, shards: Arc<dyn ShardMap>) -> Self {
        self.shards = shards;
        self
    }

    /// Stages 0a and 1: verify credentials and map the identity. Pure and
    /// synchronous; writes no state. The result is bound to
    /// `meta.procedure`.
    ///
    /// # Errors
    /// `unauthenticated` for missing or invalid credentials.
    pub fn authenticate(&self, meta: &RequestMeta<'_>) -> Result<Authenticated, ServerError> {
        tracing::debug!(stage = "authenticate", procedure = method(meta.procedure));
        auth::authenticate(&self.cfg.auth, meta, self.clock.now_ms())
    }

    /// Every ref of the repository whose name starts with `prefix`, with
    /// `prefix` stripped, read page by page.
    ///
    /// # Errors
    /// `invalid_argument` for an invalid prefix; the authorizer's error;
    /// `internal` for a storage failure.
    pub async fn list_refs(
        &self,
        a: &Authenticated,
        prefix: &str,
    ) -> Result<Vec<RefEntry>, ServerError> {
        let kind = OpKind::ListRefs {
            prefix: prefix.to_owned(),
        };
        self.observe(a, async {
            if !refs::validate_ref_prefix(prefix) {
                return Err(ServerError::invalid_argument(
                    "prefix is invalid (SPEC-REFS §3)",
                ));
            }
            let op = self.identify(a, kind)?;
            self.authorize(&op).await?;
            let p = self.shards.ref_index(&op.repo);
            let (mut out, mut after) = (Vec::new(), None);
            loop {
                let limit = self.cfg.list_page_limit;
                let page =
                    read::list_refs(&self.meta, &p, &op.repo.name, prefix, after.as_ref(), limit)
                        .await
                        .map_err(meta_error)?;
                out.extend(page.refs.into_iter().map(|(name, id)| RefEntry {
                    name: strip_listed_prefix(&name, prefix).to_owned(),
                    id,
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

    /// Probe both stores.
    pub async fn health(&self) -> HealthStatus {
        HealthStatus {
            blobs: self.blobs.probe().await.is_ok(),
            meta: self.meta.probe().await.is_ok(),
        }
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
        let procedure = method(a.procedure());
        let repo = match &self.cfg.addressing {
            Addressing::Single { repo } => repo.name.as_str(),
        };
        let span = tracing::info_span!(
            "mkit.server.rpc",
            procedure,
            repo,
            principal = a.principal.kind()
        );
        let start = self.clock.now_ms();
        let result = fut.instrument(span.clone()).await;
        let code = result.as_ref().err().map_or("ok", |e| e.code().as_str());
        span.in_scope(|| match &result {
            Ok(_) => tracing::debug!(code, "rpc done"),
            Err(e) => {
                let headers: Vec<_> = e
                    .headers()
                    .iter()
                    .map(|(n, v)| (n.as_str(), self.cfg.redactor.loggable(n, v)))
                    .collect();
                tracing::info!(code, message = e.public_message(), ?headers, "rpc failed");
            }
        });
        self.metrics.incr(
            METRIC_REQUESTS,
            &[("procedure", procedure), ("code", code)],
            1,
        );
        let elapsed = u32::try_from(self.clock.now_ms().saturating_sub(start)).unwrap_or(u32::MAX);
        self.metrics.observe_ms(
            METRIC_LATENCY,
            &[("procedure", procedure)],
            f64::from(elapsed),
        );
        result
    }

    /// A signed or unsigned unary write, stage by stage.
    async fn write(&self, a: &Authenticated, kind: OpKind) -> Result<StoredResult, ServerError> {
        let op = self.identify(a, kind)?;
        let (kind, refs, p) = self.ref_writes(&op)?;
        if let Some(stored) = self.replay_lookup(&op, &p).await? {
            return Ok(stored);
        }
        self.authorize(&op).await?;
        let charges = self.admit(&op).await?;
        self.pre_receive(&op).await?;
        let skew = a.business_skew_ms;
        self.plan_and_apply(&op, &p, kind, &refs, &charges, skew)
            .await
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

    /// Stage 0 lookup: a signed write's replay record, before any hook.
    /// A committed record's result is returned; a new one continues.
    async fn replay_lookup(
        &self,
        op: &Operation,
        p: &Partition,
    ) -> Result<Option<StoredResult>, ServerError> {
        let Some(auth) = &op.auth else {
            return Ok(None);
        };
        tracing::debug!(stage = "replay_lookup");
        let record = read::replay_lookup(&self.meta, p, &ReplayKey(auth.replay_scope))
            .await
            .map_err(meta_error)?;
        replay_answer(classify(record.as_ref(), &auth.fingerprint))
    }

    /// Stage 2.
    async fn authorize(&self, op: &Operation) -> Result<(), ServerError> {
        tracing::debug!(stage = "authorize");
        self.hooks.authorizer().authorize(op).await.map(drop)
    }

    /// Stage 3. A challenge is `permission_denied` "admission required" in
    /// M0 (the 402 response lands in M3); nothing is written for it.
    async fn admit(&self, op: &Operation) -> Result<Vec<QuotaCharge>, ServerError> {
        tracing::debug!(stage = "admission");
        let mut input = AdmissionInput::new(op);
        input.write_quota = self.cfg.write_quota;
        match self.hooks.admission().admit(&input).await? {
            AdmissionDecision::Allow { charges, .. } => Ok(charges),
            AdmissionDecision::Challenge { .. } => {
                Err(ServerError::permission_denied("admission required"))
            }
            AdmissionDecision::Deny(err) => Err(err),
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
        p: &Partition,
        kind: WriteKind,
        refs: &[RefUpdate],
        charges: &[QuotaCharge],
        skew_ms: i64,
    ) -> Result<StoredResult, ServerError> {
        let caps = self.meta.capabilities();
        let replay = op.auth.as_ref().map(|auth| ReplayGuard {
            scope: auth.replay_scope,
            fingerprint: auth.fingerprint,
            expires_at_ms: auth.expires_at_ms,
        });
        let mut req = WriteRequest {
            repo: &op.repo.name,
            kind,
            refs,
            replay,
            charges,
            grant: op.authz.grant,
            layout_version: caps.implicit_layout_version.is_none(),
        };
        if caps.atomic_multi_key {
            return self.apply_loop(p, &req, skew_ms).await;
        }
        if replay.is_some() || !charges.is_empty() {
            return Err(internal("replay and quota need atomic multi-key batches"));
        }
        // `Transport::advance_refs`'s default: packmap first, then head.
        req.kind = WriteKind::UpdateRef;
        for (i, update) in refs.iter().enumerate() {
            req.refs = core::slice::from_ref(update);
            let result = self.apply_loop(p, &req, skew_ms).await?;
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
            WriteKind::AdvanceRefs => StoredResult::AdvanceRefs(AdvanceOutcome::Committed),
        })
    }

    /// The bounded optimistic loop: read, plan, apply. A guard another
    /// writer broke re-plans up to [`MAX_REPLAN`] times, then `aborted`. A
    /// missed deadline re-plans once while the envelope is valid, then
    /// `unavailable` (SPEC-WRITE-GRANTS §5.5).
    async fn apply_loop(
        &self,
        p: &Partition,
        req: &WriteRequest<'_>,
        skew_ms: i64,
    ) -> Result<StoredResult, ServerError> {
        let (mut replans, mut deadline_missed) = (0, false);
        loop {
            let clock = self.plan_clock(skew_ms);
            let snap = self.read_snapshot(p, req, &clock).await?;
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
                ..
            } = plan;
            tracing::debug!(stage = "apply", replans);
            match self.meta.apply(p, batch).await {
                Ok(BatchOutcome::Committed) => return Ok(on_commit),
                Ok(BatchOutcome::DeadlinePassed { backend_now }) => {
                    tracing::info!(
                        backend_now,
                        deadline = clock.deadline(),
                        "commit deadline passed"
                    );
                    let now = self.clock.now_ms().saturating_add(skew_ms);
                    let valid = req.replay.is_none_or(|r| now <= r.expires_at_ms);
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
    /// the request's skew.
    fn plan_clock(&self, skew_ms: i64) -> PlanClock {
        let now = self.clock.now_ms();
        PlanClock {
            plan_time_ms: ms(now),
            business_now_ms: now.saturating_add(skew_ms),
            max_apply_window_ms: u64::try_from(self.cfg.max_apply_window.as_millis())
                .unwrap_or(u64::MAX),
            deadline_cap: None,
        }
    }

    /// Everything [`plan_write`] reads: its keys, and for signed or charged
    /// writes a bounded page of prune candidates.
    async fn read_snapshot(
        &self,
        p: &Partition,
        req: &WriteRequest<'_>,
        clock: &PlanClock,
    ) -> Result<Snapshot, ServerError> {
        let mut snap = Snapshot::default();
        let now = ms(clock.business_now_ms);
        if req.replay.is_some() {
            snap.expired_replays = read::expired_replay_keys(&self.meta, p, now, PRUNE_LIMIT)
                .await
                .map_err(meta_error)?;
        }
        if let Some(window) = req.charges.iter().map(|c| c.limits.window_ms).max() {
            snap.stale_quotas = read::stale_quota_keys(&self.meta, p, now, ms(window), PRUNE_LIMIT)
                .await
                .map_err(meta_error)?;
        }
        let mut keys = req.read_keys();
        keys.extend(snap.stale_quotas.iter().map(|(_, quota)| quota.clone()));
        keys.sort();
        keys.dedup();
        let values = self.meta.get_many(p, &keys).await.map_err(meta_error)?;
        for (key, value) in keys.into_iter().zip(values) {
            snap.insert(key, value);
        }
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

fn check_ref_name(name: &str) -> Result<(), ServerError> {
    if validate_ref_name(name) {
        Ok(())
    } else {
        Err(ServerError::invalid_argument(
            "ref name is invalid (SPEC-REFS §3)",
        ))
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
