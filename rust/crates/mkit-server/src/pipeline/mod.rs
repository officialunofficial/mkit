//! The transport-neutral request pipeline (PRD §5.4): the unary RPCs of
//! `mkit.transport.v1` over the storage contract.
//!
//! A binding calls [`Pipeline::authenticate`] (stages 0 and 1) from its
//! interceptor, then one entry point. A signed write runs one function per
//! stage, in order: `identify` (stage 1), `replay_lookup` (the stage 0
//! lookup), `authorize` (2), `admit` (3), `pre_receive` (5) and
//! `plan_and_apply` (4 and 6, one batch). Receipts (7) and outcomes (8)
//! land in M3/M5. The streaming procedures are [`Pipeline::open_upload`]
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

mod advance;
mod auth;
mod begin;
mod coordinator;
mod download;
#[cfg(feature = "test-faults")]
mod faults;
mod gate;
mod hooks;
mod info;
mod lease;
mod list;
mod outcome;
mod parts;
mod plan;
mod revocation;
mod shard;
#[cfg(test)]
mod tests;
mod upload;

use core::future::Future;
use core::time::Duration;
use std::sync::Arc;

use mkit_core::hash::{Hash, to_hex_bytes};
use mkit_core::protocol::{AdvanceOutcome, PackKey};
use mkit_core::repo_identity::Namespace;
use mkit_core::write_auth::MAX_CLOCK_LEAD_MS;
use tracing::Instrument;

use crate::download::DOWNLOAD_CHUNK_MAX;
use crate::error::{ADMISSION_CHALLENGE_TYPE, InvalidHeader, ServerError};
use crate::op::{AuthzFacts, OpKind, Operation, Procedure, RefUpdate};
use crate::policy::{AuthorizerRole, GrantConfig, NamespacePolicy, WritePolicy, grants};
use crate::quota::{
    self, DEFAULT_WRITE_QUOTA, NamespaceCharge, NamespaceDecision, NamespaceView, QuotaCharge,
    QuotaLimits, QuotaScope, ViewStatus,
};
use crate::refs::{self, strip_listed_prefix, validate_ref_name};
use crate::replay::{BeginUploadResult, ReplayDecision, StoredResult, UpdateRefResult, classify};
use crate::repo::Addressing;
use crate::rt::Clock;
use crate::storage_error::{StorageOp, describe_and_map};
use crate::store::tickets::TicketCaps;
use crate::store::{
    Batch, BatchOutcome, Key, KeyClasses, MultipartBlobStore, NamespaceStore, Partition,
    StoreError, Value, codec, keys, read,
};
use crate::telemetry::{Metrics, Redactor};
use crate::upload::{UploadLimits, token::TicketKeys};
use begin::BeginWrite;

pub use auth::{AuthMode, Authenticated, RequestMeta};
pub use download::{DownloadChunk, DownloadStream};
#[cfg(feature = "test-faults")]
pub use faults::{
    BUMP_EPOCH_HEADER, CLOCK_SKEW_HEADER, FAULT_HEADER, FailOnce, FaultHooks, FaultPoint,
    LEASE_RECOVERED_HEADER, RUN_TIMERS_HEADER, TIMER_MS_HEADER, TestDirectives,
};
pub use hooks::{
    Admission, AdmissionDecision, AdmissionInput, Authorizer, Challenge, DefaultAdmission, HookSet,
    Hooks, NoOutcomes, NoPreReceive, NoReceipts, OpenAuthorizer, OutboxRow, OutcomeSink,
    PreReceive, ReceiptSigner,
};
pub use info::ServerInfo;
use outcome::Outcome;
pub use parts::PartUploadSession;
use plan::{
    MAX_REPLAN, PRUNE_LIMIT, Plan, PlanClock, Planned, Snapshot, WriteKind, WriteRequest,
    plan_write, prune_sampled,
};
pub use revocation::{MAX_EPOCH_STEP, RevokeBudget, RevokeProgress};
pub use shard::{D34Shards, ShardMap, SinglePartition};
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
/// Label `kind`; alert on any increase.
pub const METRIC_PARTITION_FULL: &str = "mkit_server_partition_full_total";

/// Counter: [`Pipeline::with_header`] dropped an invalid or reserved
/// header; label `reason` (`name`, `reserved`, `value`).
pub const METRIC_HEADER_DROPPED: &str = "mkit_server_error_header_dropped_total";

/// Deployment routing for repository state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Sharding {
    /// All rows of a namespace share one partition.
    #[default]
    Single,
    /// Coordinator and per-branch ref shards (D34).
    D34,
}

/// A deployment's pipeline settings. Start from [`PipelineConfig::new`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PipelineConfig {
    /// How requests map to a repository (M0: `Single`).
    pub addressing: Addressing,
    /// How metadata partitions are routed.
    pub sharding: Sharding,
    /// How requests authenticate.
    pub auth: AuthMode,
    /// Owner-signed write grant verifier for Multi/Owner deployments.
    pub grants: Option<GrantConfig>,
    /// Write authorization policy; Open for Single, Owner for Multi.
    pub write_policy: WritePolicy,
    /// Role of the authorizer hook, defaulting to an additional check.
    pub authorizer_role: AuthorizerRole,
    /// Upload caps, supplied by the binding (used by M0-05b).
    pub upload_limits: UploadLimits,
    /// Resumable upload part size: a power of two in 8–32 MiB.
    pub part_size: u64,
    /// Largest number of parts, sufficient to reach the upload byte cap.
    pub max_parts: u32,
    /// Largest requested `ListRefs` page, in 1..=10,000. The default 1000
    /// refs with at most 512-byte names fit STC §7.9's 2 MiB page bound.
    pub max_list_refs_page_size: u32,
    /// Packs smaller than this may skip `BeginUpload`; `u64::MAX` means never
    /// required. Advertised as zero with Multi addressing or admission.
    pub begin_upload_threshold_bytes: u64,
    /// Accepted deployment upload MAC keys; first key signs.
    pub ticket_keys: Option<TicketKeys>,
    /// Ticket lifetime, positive and strictly below seven days.
    pub ticket_ttl_ms: u64,
    /// Open-ticket bounds in each ref shard.
    pub ticket_caps: TicketCaps,
    /// Largest download chunk (used by M0-05b).
    pub download_chunk_max: usize,
    /// The default write quota: `Some(DEFAULT_WRITE_QUOTA)` for auth v2
    /// deployments (`vcs-worker` parity). Under D34 it counts per ref shard;
    /// Multi-addressing deployments also use it as the default namespace cap.
    pub write_quota: Option<QuotaLimits>,
    /// `ListRefs` scan page size, at least 1.
    pub list_page_limit: u32,
    /// Commit deadline window; see [`MAX_APPLY_WINDOW`].
    pub max_apply_window: Duration,
    /// Coordinator epoch lease duration, in milliseconds.
    pub epoch_lease_ms: u64,
    /// Safety margin in milliseconds. It must exceed the maximum clock skew
    /// between every pipeline instance (grant, renewal and revoke), the sweep
    /// driver, and every storage backend. The constructor cannot verify this.
    pub lease_margin_ms: u64,
    /// Minimum useful lease budget before renewing, in milliseconds.
    pub min_lease_budget_ms: u64,
    /// Extra header names never to log.
    pub redactor: Redactor,
}

impl PipelineConfig {
    /// Defaults for `auth`: the default write quota only for auth v2.
    #[must_use]
    pub fn new(addressing: Addressing, auth: AuthMode, upload_limits: UploadLimits) -> Self {
        let write_quota = matches!(auth, AuthMode::AuthV2(_)).then_some(DEFAULT_WRITE_QUOTA);
        let write_policy = match &addressing {
            Addressing::Single { .. } => WritePolicy::Open,
            Addressing::Multi(_) => WritePolicy::Owner,
        };
        Self {
            write_policy,
            authorizer_role: AuthorizerRole::Check,
            addressing,
            sharding: Sharding::Single,
            auth,
            grants: None,
            upload_limits,
            part_size: mkit_core::upload_parts::MIN_PART_SIZE,
            max_parts: 10_000,
            max_list_refs_page_size: DEFAULT_LIST_PAGE_LIMIT,
            begin_upload_threshold_bytes: u64::MAX,
            ticket_keys: None,
            ticket_ttl_ms: 86_400_000,
            ticket_caps: TicketCaps {
                per_ref: 1024,
                per_signer: 64,
            },
            download_chunk_max: DOWNLOAD_CHUNK_MAX,
            write_quota,
            list_page_limit: DEFAULT_LIST_PAGE_LIMIT,
            max_apply_window: MAX_APPLY_WINDOW,
            epoch_lease_ms: 30_000,
            lease_margin_ms: 5_000,
            min_lease_budget_ms: 1_000,
            redactor: Redactor::default(),
        }
    }

    /// The namespace policy advertised by `GetServerInfo` (STC §2.1).
    #[must_use]
    pub fn advertised_namespace_policy(&self) -> &'static str {
        match &self.addressing {
            Addressing::Single { .. } => "single-repository",
            Addressing::Multi(multi) => match &multi.namespace_policy {
                NamespacePolicy::Allowlist(_) => "allowlist",
                NamespacePolicy::Any { .. } => "any",
            },
        }
    }
}

/// What the pipeline offers bindings and `GetServerInfo`.
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
    revocation_cursors: Arc<revocation::RevokeCursors>,
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

fn validate_upload_ticket_config<H: HookSet>(
    cfg: &PipelineConfig,
    hooks: &H,
) -> Result<(), ServerError> {
    if matches!(cfg.addressing, Addressing::Multi(_))
        && matches!(cfg.auth, AuthMode::TransportIdentity)
    {
        return Err(ServerError::invalid_argument(
            "multi-repository deployments require auth v2 until transport identity carries tickets",
        ));
    }
    if cfg.begin_upload_threshold_bytes != u64::MAX
        && (!matches!(cfg.auth, AuthMode::AuthV2(_)) || cfg.ticket_keys.is_none())
    {
        return Err(ServerError::invalid_argument(
            "a ticket threshold requires auth v2 and upload ticket keys",
        ));
    }
    if !matches!(cfg.auth, AuthMode::TransportIdentity)
        && !hooks.admission().is_default()
        && (!matches!(cfg.auth, AuthMode::AuthV2(_)) || cfg.ticket_keys.is_none())
    {
        return Err(ServerError::invalid_argument(
            "admission requires auth v2 and upload ticket keys",
        ));
    }
    Ok(())
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// A pipeline over `blobs` and `meta`, routed by `cfg.sharding`.
    ///
    /// # Errors
    /// `invalid_argument` for a configuration the store cannot serve: auth
    /// v2 needs every key class and atomic multi-key batches (so
    /// `FsLayoutStore` never runs auth v2); a store without atomic batches
    /// must report an implicit layout version; a store's layout version
    /// must be this binary's; the page limit and apply window must be
    /// positive. Resumable upload and advertised page limits must be valid
    /// and the part capacity must reach the upload byte cap. Namespace/write
    /// policy combinations must be compatible;
    /// `any` requires non-default admission or its explicit unsafe override,
    /// and an authority authorizer must not be the open default.
    #[allow(clippy::too_many_lines)] // Startup rejects incompatible storage, auth and grant combinations together.
    pub fn new(
        blobs: B,
        meta: N,
        hooks: H,
        cfg: PipelineConfig,
        clock: Arc<dyn Clock>,
        metrics: Arc<dyn Metrics>,
    ) -> Result<Self, ServerError> {
        cfg.validate_server_info_limits()?;

        if cfg.max_parts > B::MAX_PARTS {
            return Err(ServerError::invalid_argument(
                "max_parts exceeds storage backend capacity",
            ));
        }

        validate_upload_ticket_config(&cfg, &hooks)?;
        if cfg.ticket_ttl_ms == 0
            || cfg.ticket_ttl_ms >= 604_800_000
            || cfg.ticket_caps.per_ref == 0
            || cfg.ticket_caps.per_signer == 0
        {
            return Err(ServerError::invalid_argument(
                "invalid upload ticket lifetime or caps",
            ));
        }
        let policy_refusal = match (&cfg.addressing, cfg.write_policy) {
            (Addressing::Multi(_), WritePolicy::Open) => {
                Some("write_policy open is single-repository only (SPEC-TRANSPORT-CONNECT §7.5)")
            }
            (Addressing::Single { .. }, WritePolicy::Owner) => {
                Some("write_policy owner needs multi-repository addressing")
            }
            (Addressing::Multi(multi), _)
                if matches!(
                    multi.namespace_policy,
                    NamespacePolicy::Any {
                        unsafe_without_admission: false
                    }
                ) && hooks.admission().is_default() =>
            {
                Some(
                    "namespace_policy any needs a non-default admission step, or the explicit unsafe override (D27)",
                )
            }
            _ => None,
        };
        if let Some(message) = policy_refusal {
            return Err(ServerError::invalid_argument(message));
        }
        if let Some(grants) = &cfg.grants {
            let AuthMode::AuthV2(auth) = &cfg.auth else {
                return Err(ServerError::invalid_argument(
                    "write grants require auth v2",
                ));
            };
            if !matches!(cfg.addressing, Addressing::Multi(_))
                || cfg.write_policy != WritePolicy::Owner
            {
                return Err(ServerError::invalid_argument(
                    "write grants require Multi addressing and owner write policy",
                ));
            }
            if grants.audience() != auth.audience() {
                return Err(ServerError::invalid_argument(
                    "write grant audience must match auth v2 audience",
                ));
            }
        }
        if cfg.authorizer_role == AuthorizerRole::Authority && hooks.authorizer().is_open() {
            return Err(ServerError::invalid_argument(
                "an authority authorizer must be a real authority source",
            ));
        }
        let caps = meta.capabilities();
        let full = caps.atomic_multi_key && caps.key_classes == KeyClasses::All;
        let refused = if matches!(cfg.auth, AuthMode::AuthV2(_)) && !full {
            "auth v2 needs every key class and atomic multi-key batches"
        } else if (cfg.sharding == Sharding::D34 || matches!(cfg.addressing, Addressing::Multi(_)))
            && !full
        {
            "sharded or multi-repository routing needs every key class and atomic multi-key batches"
        } else if !caps.atomic_multi_key && caps.implicit_layout_version.is_none() {
            "a store without atomic batches must report its layout version"
        } else if caps
            .implicit_layout_version
            .is_some_and(|v| v != keys::LAYOUT_VERSION)
        {
            "the store's layout version is not this server's"
        } else if cfg.lease_margin_ms == 0
            || cfg.epoch_lease_ms <= cfg.lease_margin_ms.saturating_add(cfg.min_lease_budget_ms)
        {
            "epoch lease must exceed its positive margin plus minimum budget"
        } else if cfg.list_page_limit == 0 || cfg.max_apply_window.is_zero() {
            "list page limit and apply window must be positive"
        } else {
            ""
        };
        if !refused.is_empty() {
            return Err(ServerError::invalid_argument(refused));
        }
        let shards: Arc<dyn ShardMap> = match cfg.sharding {
            Sharding::Single => Arc::new(SinglePartition),
            Sharding::D34 => Arc::new(D34Shards),
        };
        Ok(Self {
            blobs,
            meta,
            hooks,
            shards,
            cfg,
            clock,
            metrics,
            #[cfg(feature = "test-faults")]
            faults: None,
            gate: None,
            revocation_cursors: Arc::default(),
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

    /// Run the writes to one partition one at a time in this process: each
    /// write's read-plan-apply loop waits for the partition's gate, as a
    /// Durable Object's input gate serializes them on Workers. For a
    /// single-process server over a single-writer store (native `SQLite`,
    /// which commits one batch at a time anyway): concurrent writes that
    /// share a key, such as one signer's quota window, then never exhaust
    /// the re-plan bound and fail `aborted`. D34 lease-grant batches also
    /// take this gate after admission. Reads are not gated. Several
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
        sibling.revocation_cursors = Arc::clone(&self.revocation_cursors);
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
            self.outcome_for(meta.procedure, "none", "-")
                .record(Err(err));
        }
        result
    }

    fn authenticate_inner(&self, meta: &RequestMeta<'_>) -> Result<Authenticated, ServerError> {
        let signed = matches!(self.cfg.auth, AuthMode::AuthV2(_)) && meta.procedure.is_write();
        if matches!(self.cfg.addressing, Addressing::Multi(_))
            && !signed
            && matches!(
                meta.procedure,
                Procedure::UpdateRef
                    | Procedure::AdvanceRefs
                    | Procedure::BeginUpload
                    | Procedure::UploadPack
            )
            && (meta.header)("x-write-grant").is_some()
        {
            return Err(ServerError::unauthenticated(
                "write grant requires auth v2 authorization",
            ));
        }
        let repo = self
            .cfg
            .addressing
            .resolve((meta.header)("x-repository").as_deref(), signed)?;
        let expected_repository = match (&self.cfg.addressing, &self.cfg.auth) {
            (Addressing::Single { .. }, AuthMode::AuthV2(cfg)) => cfg.repository(),
            _ => &repo.identity,
        }
        .to_owned();
        #[cfg(feature = "test-faults")]
        let directives = TestDirectives::from_headers(meta.header)?;
        #[cfg(feature = "test-faults")]
        let skew = directives.clock_skew_ms;
        #[cfg(not(feature = "test-faults"))]
        let skew = 0;
        let now = self.clock.now_ms().saturating_add(skew);
        let mut a = auth::authenticate(&self.cfg.auth, meta, now, repo, &expected_repository)?;
        // Header adapters supply UTF-8 Strings; undecodable bytes are absent.
        a.ref_hint =
            (meta.header)("x-mkit-ref").filter(|name| name.len() <= refs::MAX_REF_NAME_BYTES);
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
    /// `not_found` for a nonexistent Multi repository;
    /// `invalid_argument` for an invalid prefix or one over
    /// [`refs::MAX_REF_NAME_BYTES`]; the authorizer's error; `unavailable`
    /// for a bucket scan failure.
    pub async fn list_refs(
        &self,
        a: &Authenticated,
        prefix: &str,
    ) -> Result<Vec<RefEntry>, ServerError> {
        let mut out = Vec::new();
        let mut token = None;
        loop {
            let page = self
                .list_refs_page(a, prefix, Some(self.cfg.list_page_limit), token.as_deref())
                .await?;
            out.extend(page.refs);
            match page.next {
                Some(next) => token = Some(next),
                None => return Ok(out),
            }
        }
    }

    /// One bounded `ListRefs` page. The token is opaque core bytes; the
    /// Connect binding encodes it as unpadded base64url.
    pub(crate) async fn list_refs_page(
        &self,
        a: &Authenticated,
        prefix: &str,
        page_size: Option<u32>,
        token: Option<&[u8]>,
    ) -> Result<list::ListPage, ServerError> {
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
            self.require_repository(&op.repo).await?;
            let scan = refs::list_scan_prefix(prefix);
            let last = token
                .map(|bytes| {
                    list::decode_token(&op.repo, &scan, bytes)
                        .ok_or_else(|| ServerError::invalid_argument("invalid page token"))
                })
                .transpose()?;
            #[cfg(feature = "test-faults")]
            {
                if a.test_directives().lease_recovered {
                    self.mark_lease_table_recovered(&op.repo.namespace).await?;
                }
                if let Some(epoch) = a.test_directives().bump_epoch {
                    self.test_bump_epoch(&op.repo.namespace, epoch).await?;
                }
            }
            let partitions = self.shards.ref_index_partitions(&op.repo);
            if partitions.len() != 1 {
                // TODO(WP-1.28b): read the eventually consistent ref-name index.
                return Err(ServerError::new(
                    crate::Code::Unimplemented,
                    "ListRefs under d34 sharding lands with WP-1.28",
                ));
            }
            let p = partitions
                .into_iter()
                .next()
                .ok_or_else(|| internal("missing ref index"))?;
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
            let requested = page_size.unwrap_or(0);
            let limit = if requested == 0 {
                self.cfg.max_list_refs_page_size
            } else {
                requested.min(self.cfg.max_list_refs_page_size)
            };
            let bucket = list::RefBucket {
                store: &self.meta,
                partition: &p,
            };
            let mut page = list::page(
                &[bucket],
                &op.repo,
                &scan,
                last.as_deref(),
                limit,
                list::MAX_RESPONSE_BYTES,
            )
            .await
            .map_err(|err| {
                tracing::warn!(detail = %err, "ref listing scan failed");
                ServerError::unavailable("ref listing unavailable")
            })?;
            for entry in &mut page.refs {
                entry.name = strip_listed_prefix(&entry.name, prefix)
                    .ok_or_else(|| ServerError::unavailable("ref listing unavailable"))?
                    .to_owned();
            }
            Ok(page)
        })
        .await
    }

    /// One ref's id, if it exists.
    ///
    /// # Errors
    /// `not_found` for a nonexistent Multi repository;
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
            self.require_repository(&op.repo).await?;
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
            if upd.new.is_none()
                && !matches!(upd.condition, mkit_core::refs::RefWriteCondition::Match(_))
            {
                return Err(ServerError::invalid_argument(
                    "delete requires MATCH and an empty new_id",
                ));
            }
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
        self.advance_refs_with_tickets(a, head, packmap, Vec::new())
            .await
    }

    /// Advance both refs while consuming the named upload tickets.
    ///
    /// # Errors
    /// Invalid ticket bindings, incomplete uploads, authorization or storage errors.
    pub async fn advance_refs_with_tickets(
        &self,
        a: &Authenticated,
        head: RefUpdate,
        packmap: RefUpdate,
        tickets: Vec<Hash>,
    ) -> Result<AdvanceOutcome, ServerError> {
        self.observe(a, async {
            check_ref_name(&head.name)?;
            check_ref_name(&packmap.name)?;
            if head.new.is_none() != packmap.new.is_none()
                || (head.new.is_none()
                    && (!matches!(head.condition, mkit_core::refs::RefWriteCondition::Match(_))
                        || !matches!(
                            packmap.condition,
                            mkit_core::refs::RefWriteCondition::Match(_)
                        )))
            {
                return Err(ServerError::invalid_argument(
                    "delete requires MATCH and an empty new_id",
                ));
            }
            if head.new.is_none() && !tickets.is_empty() {
                return Err(ServerError::invalid_argument("delete consumes no tickets"));
            }
            if tickets.len() > crate::store::outbox::MAX_TICKETS_PER_ADVANCE {
                return Err(ServerError::invalid_argument(
                    "too many tickets in one advance",
                ));
            }
            let mut distinct = std::collections::BTreeSet::new();
            if tickets.iter().any(|id| !distinct.insert(id)) {
                return Err(ServerError::invalid_argument("duplicate ticket id"));
            }
            if !tickets.is_empty() || self.cfg.sharding == Sharding::D34 {
                let head_branch = head.name.strip_prefix("refs/heads/");
                let packmap_branch = packmap
                    .name
                    .strip_prefix(mkit_core::refs::PACKMAP_REF_PREFIX);
                if head_branch.is_none() || head_branch != packmap_branch {
                    return Err(ServerError::invalid_argument(if tickets.is_empty() {
                        "AdvanceRefs pairs refs/heads/<x> with refs/mkit/packmap/<x> on this server"
                    } else {
                        "ticketed advance requires a branch head and its packmap"
                    }));
                }
            }
            match self
                .write(
                    a,
                    OpKind::AdvanceRefs {
                        head,
                        packmap,
                        tickets,
                    },
                )
                .await?
            {
                StoredResult::AdvanceRefs(outcome) => Ok(outcome),
                other => Err(stored_mismatch(&other)),
            }
        })
        .await
    }

    /// Whether the pack is present in a Single deployment's blob store.
    /// Multi deployments require repository membership before serving packs.
    ///
    /// # Errors
    /// `not_found` for a nonexistent Multi repository; the authorizer's
    /// error; `internal` for a storage failure.
    pub async fn pack_exists(&self, a: &Authenticated, key: PackKey) -> Result<bool, ServerError> {
        self.observe(a, async {
            let op = self.identify(a, OpKind::PackExists { key })?;
            self.authorize(&op).await?;
            self.require_repository(&op.repo).await?;
            if !self.pack_is_member(a, &key).await? {
                return Ok(false);
            }
            let head = self.blobs.head(&key.into()).await;
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
    /// `failed_precondition` when the advertised threshold requires a ticket;
    /// the header's [`crate::upload::UploadError`]; `unauthenticated` when
    /// the header differs from the signed commitment; a stored or
    /// in-flight replay answer; a hook's error; the reservation's error.
    pub async fn open_upload(
        &self,
        a: &Authenticated,
        pack_id: Option<&[u8]>,
        total_bytes: Option<u64>,
    ) -> Result<UploadSession<'_, B, N, H>, ServerError> {
        UploadSession::begin(self, a, pack_id, total_bytes).await
    }

    /// Open a stateless ticketed `UploadPack` stream after checking the header,
    /// signed commitment and token, before reading any body bytes.
    ///
    /// # Errors
    /// Framing, authentication, binding and blob-store failures.
    pub async fn open_ticketed_upload(
        &self,
        a: &Authenticated,
        pack_id: Option<&[u8]>,
        total_bytes: Option<u64>,
        token: &[u8],
    ) -> Result<UploadSession<'_, B, N, H>, ServerError> {
        UploadSession::begin_ticketed(self, a, pack_id, total_bytes, token).await
    }

    /// A pack's bytes as chunks of at most `download_chunk_max` bytes.
    ///
    /// # Errors
    /// `not_found` for a missing repository or non-member pack, before any chunk; the authorizer's
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
            self.require_repository(&op.repo).await?;
            if !self.pack_is_member(a, &key).await? {
                return Err(ServerError::not_found("pack not found"));
            }
            let body = self.blobs.get(&key.into(), None).await;
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
        self.outcome_for(a.procedure(), a.principal.kind(), &a.repo().identity)
    }

    /// The span and recorder of one request to `procedure` as `principal`.
    fn outcome_for(&self, procedure: Procedure, principal: &'static str, repo: &str) -> Outcome {
        let procedure = method(procedure);
        let span = tracing::info_span!("mkit.server.rpc", procedure, repo, principal);
        let (metrics, clock) = (self.metrics.clone(), self.clock.clone());
        Outcome::new(span, procedure, metrics, clock, self.cfg.redactor.clone())
    }

    /// A signed or unsigned unary write, stage by stage. In steady state
    /// a signed write costs two backend calls: one `get_many` before any
    /// hook runs (the replay record and the snapshot) and one `apply`.
    #[allow(clippy::too_many_lines)] // Stage order and multipart session cleanup share this entry point.
    async fn write(&self, a: &Authenticated, kind: OpKind) -> Result<StoredResult, ServerError> {
        let mut op = self.identify(a, kind)?;
        fault!(self, AfterAuthenticate, &op, a);
        let (kind, refs, p) = self.ref_writes(&op)?;
        let mut ahead = self.read_ahead(&op, &p, &refs, a.business_skew_ms).await?;
        if let Some(stored) = Self::replay_lookup(&op, ahead.as_ref())? {
            return Ok(stored);
        }
        let lease = if self.cfg.sharding == Sharding::D34 {
            let observed = self.observe_lease(&op, &p, ahead.as_ref()).await?;
            if let Some((window, total)) = observed.quota_seed()
                && let Some(snapshot) = ahead.as_mut()
            {
                snapshot.namespace_seed = Some((
                    window,
                    codec::encode_namespace_view(NamespaceView {
                        total,
                        pushed: crate::quota::NamespaceUsage::default(),
                        observed_at_ms: ms(self.clock.now_ms()),
                    }),
                ));
            }
            op.creation = observed.creation(&self.cfg.addressing);
            op.leased_epoch = Some(observed.epoch());
            Some(observed)
        } else {
            op.creation = self.creation_facts(&op, ahead.as_ref()).await?;
            None
        };
        if self.cfg.sharding == Sharding::Single {
            let key = keys::grant_epoch();
            if let Some(snapshot) = ahead.as_ref().filter(|snapshot| snapshot.contains(&key)) {
                op.observed_epoch = Some(
                    snapshot
                        .get(&key)
                        .map(codec::decode_u64)
                        .transpose()
                        .map_err(meta_error)?
                        .unwrap_or(0),
                );
            }
        }
        op.authz = self.authorize(&op).await?;
        fault!(self, AfterAuthorize, &op, a);
        let ticketed =
            matches!(&op.kind, OpKind::AdvanceRefs { tickets, .. } if !tickets.is_empty());
        if ticketed {
            let snap = ahead
                .as_mut()
                .ok_or_else(|| internal("ticket advance requires atomic metadata"))?;
            if let Some(stored) = self.ticket_decision(&op, a, &p, snap).await? {
                return Ok(stored);
            }
        }
        let existing = self.begin_decision(&op, a, ahead.as_mut()).await?;
        let allowance = if existing.is_some() || ticketed {
            Allowance::default()
        } else {
            let mut input = AdmissionInput::new(&op);
            if let OpKind::BeginUpload { key, bytes, .. } = &op.kind {
                input.declared_bytes = *bytes;
                input.pack_id = Some(*key);
                input.new_to_repo_bytes = Some(*bytes);
            }
            self.admit(input).await?
        };
        if !matches!(op.kind, OpKind::BeginUpload { .. }) && allowance.reservation.is_some() {
            return Err(ServerError::unimplemented(
                "admission reservations on ref writes land with WP-3.3",
            ));
        }
        let mut begin = self.begin_write(&op, a, existing, allowance.reservation)?;
        self.precheck_namespace(&p, &allowance.charges, &mut ahead, a.business_skew_ms)?;
        let mut opened_session = None;
        if let Some(BeginWrite::Open(open)) = &mut begin
            && open.spec.bytes > open.spec.part_size
        {
            let key = PackKey(open.spec.pack_id).into();
            let session = self
                .blobs
                .begin_multipart(key, open.spec.bytes, open.spec.part_size)
                .await
                .map_err(|e| {
                    if open.reserved() {
                        // TODO(WP-3.3): record Aborted via Pending when admission
                        // supplied a reservation but session creation failed.
                        tracing::warn!(error = %e, "reserved multipart session creation failed");
                        ServerError::unavailable("multipart session creation failed; retry")
                    } else {
                        store_error(StorageOp::MultipartSession, e)
                    }
                })?;
            if session.is_empty() || session.len() > u16::MAX as usize {
                if let Err(err) = self.blobs.abort(key, &session).await {
                    tracing::warn!(error = %err, "failed to abort invalid multipart session");
                }
                return Err(ServerError::internal(
                    "object storage request failed",
                    "multipart store returned an invalid session identifier",
                ));
            }
            opened_session = Some((
                key,
                session.clone(),
                crate::store::tickets::ticket_id(&open.spec.reservation_id),
            ));
            open.spec.upload_session = Some(session);
        }
        let write_result = async {
            let lease = if let Some(observed) = lease {
                let (created, lease) = {
                    // The native gate serializes same-shard lease grants too.
                    // Read observations remain pre-admission; a waiter rebuilds
                    // a stale coordinator observation within the usual three tries.
                    let _grant_gate = match (&self.gate, &observed) {
                        (Some(gate), lease::LeaseObservation::Renew(_)) => {
                            Some(gate.enter(&p).await)
                        }
                        _ => None,
                    };
                    self.admit_lease(&op, &p, observed, a.business_skew_ms)
                        .await?
                };
                op.created = created;
                op.leased_epoch = Some(lease.value.epoch);
                if lease.install {
                    fault!(self, AfterLeaseGrant, &op, a);
                }
                Some(lease)
            } else {
                op.created = self.commit_creation(&op, a.business_skew_ms).await?;
                None
            };
            self.pre_receive(&op).await?;
            let write = (kind, refs.as_slice(), allowance.charges.as_slice());
            self.plan_and_apply(&op, a, &p, write, ahead, (lease, begin.as_ref()))
                .await
        }
        .await;
        if let Some((key, session, fresh_id)) = opened_session {
            self.cleanup_opened_session(&p, &write_result, key, &session, fresh_id)
                .await;
        }
        write_result
    }

    async fn cleanup_opened_session(
        &self,
        partition: &Partition,
        result: &Result<StoredResult, ServerError>,
        key: crate::store::BlobKey,
        session: &[u8],
        fresh_id: Hash,
    ) {
        // A raced Existing ticket can have the same reservation-derived id
        // with a different session. Compare the authenticated answer.
        let committed_fresh = match result {
            Ok(StoredResult::BeginUpload(BeginUploadResult::Ticket { id, token, .. }))
                if *id == fresh_id =>
            {
                self.cfg
                    .ticket_keys
                    .as_ref()
                    .and_then(|keys| keys.verify(token, 0).ok())
                    .is_some_and(|claims| claims.upload_session == session)
            }
            _ => false,
        };
        // An apply can commit and then lose its acknowledgement. Check the
        // row before reclaiming; an unavailable or corrupt read is ambiguous.
        let stored_fresh = if result.is_err() {
            match self.meta.get(partition, &keys::ticket(&fresh_id)).await {
                Ok(Some(raw)) => codec::decode_ticket(&raw)
                    .ok()
                    .is_none_or(|ticket| ticket.upload_session.as_deref() == Some(session)),
                Ok(None) => false,
                Err(err) => {
                    tracing::warn!(error = %err, "could not confirm multipart ticket after failed write");
                    true
                }
            }
        } else {
            false
        };
        if !committed_fresh
            && !stored_fresh
            && let Err(err) = self.blobs.abort(key, session).await
        {
            tracing::warn!(error = %err, "failed to abort unused multipart session");
        }
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
        let repo = a.repo().repo.clone();
        let principal = a.principal.clone();
        let mut op = Operation::new(repo, principal, a.auth.clone(), kind);
        op.write_grant.clone_from(&a.write_grant);
        op.business_now_ms = Some(a.business_now_ms);
        Ok(op)
    }

    /// Multi reads require a repository registered in the namespace coordinator.
    async fn require_repository(&self, repo: &crate::repo::RepoId) -> Result<(), ServerError> {
        if matches!(self.cfg.addressing, Addressing::Multi(_)) {
            let p = self.shards.coordinator(&repo.namespace);
            let value = self
                .meta
                .get(&p, &keys::repo_record(&repo.name))
                .await
                .map_err(meta_error)?;
            match value {
                Some(value) => {
                    codec::decode_repo_record(&value).map_err(meta_error)?;
                }
                None => return Err(ServerError::not_found("repository not found")),
            }
        }
        Ok(())
    }

    async fn pack_is_member(&self, a: &Authenticated, key: &PackKey) -> Result<bool, ServerError> {
        if matches!(self.cfg.addressing, Addressing::Single { .. }) {
            return Ok(true);
        }
        read::is_member(
            &self.meta,
            self.shards.as_ref(),
            &a.repo().repo,
            &key.0,
            a.ref_hint.as_deref(),
        )
        .await
        .map_err(meta_error)
    }

    /// A unary write's ref writes in decision order (packmap first) and
    /// the ref shard they commit in, which a head and its packmap share.
    fn ref_writes(
        &self,
        op: &Operation,
    ) -> Result<(WriteKind, Vec<RefUpdate>, Partition), ServerError> {
        let (kind, refs) = match &op.kind {
            OpKind::UpdateRef(u) => (WriteKind::UpdateRef, vec![u.clone()]),
            OpKind::AdvanceRefs { head, packmap, .. } => {
                (WriteKind::AdvanceRefs, vec![packmap.clone(), head.clone()])
            }
            OpKind::BeginUpload { ref_name, .. } => {
                return Ok((
                    WriteKind::BeginUpload,
                    vec![],
                    self.shards.ref_shard(&op.repo, ref_name),
                ));
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
        business_skew_ms: i64,
    ) -> Result<Option<Snapshot>, ServerError> {
        let caps = self.meta.capabilities();
        if !caps.atomic_multi_key {
            return Ok(None);
        }
        let namespace_window = if matches!(self.cfg.addressing, Addressing::Multi(_))
            && self.hooks.admission().is_default()
        {
            self.cfg.write_quota.map(|limits| {
                quota::namespace_window(
                    self.clock.now_ms().saturating_add(business_skew_ms),
                    limits.window_ms,
                )
            })
        } else {
            None
        };
        let mut wanted: Vec<Key> = refs
            .iter()
            .map(|r| keys::ref_key(&op.repo.name, &r.name))
            .collect();
        if caps.implicit_layout_version.is_none() {
            wanted.push(keys::layout_version());
        }
        if matches!(self.cfg.addressing, Addressing::Multi(_)) {
            wanted.push(keys::repo_known(&op.repo.name));
        }
        if self.cfg.sharding == Sharding::D34 {
            wanted.push(keys::epoch_lease());
        }
        if let Some(auth) = &op.auth {
            wanted.push(keys::replay(&auth.replay_scope));
            if self.cfg.sharding == Sharding::Single {
                wanted.push(keys::grant_epoch());
            }
            if self.cfg.write_quota.is_some() {
                let scope = QuotaScope::for_signer(&op.repo.namespace, &auth.signer);
                wanted.push(keys::quota(&scope));
            }
            if let (Some(window), Some(limits)) = (namespace_window, self.cfg.write_quota) {
                let charge = NamespaceCharge {
                    limits,
                    window,
                    bytes: 0,
                    rollup: matches!(p, Partition::Ref { .. }),
                };
                wanted.push(quota::counter_key(charge, window));
                if charge.rollup {
                    wanted.push(keys::quota_view(window));
                }
                // Admission may run after the current window ends. Fetch the
                // next window in the same read-ahead call, before any lease.
                let next = window.saturating_add(1);
                wanted.push(quota::counter_key(charge, next));
                if charge.rollup {
                    wanted.push(keys::quota_view(next));
                }
            }
        }
        if let OpKind::BeginUpload { ref_name, key, .. } = &op.kind {
            let signer = op
                .auth
                .as_ref()
                .ok_or_else(|| internal("missing ticket signer"))?
                .signer;
            wanted.extend(begin::decision_keys(
                &op.repo.name,
                ref_name,
                &key.0,
                &signer,
            )?);
        }
        let mut snap = Snapshot::default();
        snap.namespace_window = namespace_window;
        self.fill(p, &mut snap, wanted).await?;
        Ok(Some(snap))
    }

    fn namespace_charge(
        &self,
        p: &Partition,
        charges: &[QuotaCharge],
        window: Option<u64>,
    ) -> Result<Option<NamespaceCharge>, ServerError> {
        if !matches!(self.cfg.addressing, Addressing::Multi(_))
            || !self.hooks.admission().is_default()
        {
            return Ok(None);
        }
        let Some(charge) = charges.first() else {
            return Ok(None);
        };
        let window = window.ok_or_else(|| internal("namespace quota read-ahead missing"))?;
        Ok(Some(NamespaceCharge {
            limits: charge.limits,
            window,
            bytes: charge.bytes,
            rollup: matches!(p, Partition::Ref { .. }),
        }))
    }

    /// Reject a namespace cap before a lease or multipart session is made.
    /// The planner repeats the guarded check when it commits the write.
    fn precheck_namespace(
        &self,
        p: &Partition,
        charges: &[QuotaCharge],
        ahead: &mut Option<Snapshot>,
        business_skew_ms: i64,
    ) -> Result<(), ServerError> {
        let Some(mut charge) = self.namespace_charge(
            p,
            charges,
            ahead
                .as_ref()
                .and_then(|snapshot| snapshot.namespace_window),
        )?
        else {
            return Ok(());
        };
        let now = self.clock.now_ms().saturating_add(business_skew_ms);
        let window = quota::namespace_window(now, charge.limits.window_ms);
        if window != charge.window && window != charge.window.saturating_add(1) {
            return Err(ServerError::aborted_retryable(
                "namespace quota window advanced; retry",
            ));
        }
        charge.window = window;
        let snap = ahead
            .as_mut()
            .ok_or_else(|| internal("namespace quota needs atomic reads"))?;
        let stored_view = charge
            .rollup
            .then(|| snap.get(&keys::quota_view(window)))
            .flatten();
        let seeded_view = snap
            .namespace_seed
            .as_ref()
            .filter(|(seed_window, _)| *seed_window == window)
            .map(|(_, value)| value);
        let decision = quota::check_namespace(
            snap.get(&quota::counter_key(charge, window)),
            stored_view.or(seeded_view),
            now,
            charge,
        )?;
        match decision {
            NamespaceDecision::Exhausted => {
                return Err(ServerError::resource_exhausted(
                    "namespace write op/byte quota exceeded for this window; try again later",
                ));
            }
            NamespaceDecision::Allowed {
                view: ViewStatus::Missing,
                ..
            } => self.metrics.incr(
                crate::telemetry::METRIC_NAMESPACE_QUOTA_VIEW_FALLBACK,
                &[("state", "missing")],
                1,
            ),
            NamespaceDecision::Allowed {
                view: ViewStatus::Stale,
                ..
            } => self.metrics.incr(
                crate::telemetry::METRIC_NAMESPACE_QUOTA_VIEW_FALLBACK,
                &[("state", "stale")],
                1,
            ),
            NamespaceDecision::Allowed { .. } => {}
        }
        snap.namespace_window = Some(window);
        Ok(())
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
        if !op.procedure().is_write() {
            // TODO(WP-2.9): private read authorization.
            return self.hooks.authorizer().authorize(op).await;
        }
        let Addressing::Multi(multi) = &self.cfg.addressing else {
            return self.hooks.authorizer().authorize(op).await;
        };
        let namespace = Namespace::parse(op.repo.namespace.as_str())
            .map_err(|_| internal("invalid resolved Multi namespace"))?;
        if let NamespacePolicy::Allowlist(allowed) = &multi.namespace_policy
            && !allowed.contains(&namespace)
        {
            return Err(ServerError::permission_denied("write not permitted"));
        }
        if op.write_grant.is_some()
            && matches!(namespace, Namespace::Address(_))
            && !matches!(&multi.namespace_policy, NamespacePolicy::Allowlist(_))
        {
            return Err(ServerError::permission_denied("write not permitted"));
        }
        let grant = if let Some(header) = &op.write_grant {
            let cfg = self.cfg.grants.as_ref().ok_or_else(|| {
                grants::rejected(mkit_attest::grant::GrantError::SchemeNotAdvertised)
            })?;
            let verified = cfg.verify(header.expose(), op)?;
            let observed = match self.cfg.sharding {
                Sharding::Single => op.observed_epoch,
                Sharding::D34 => op.leased_epoch,
            };
            if observed != Some(verified.epoch()) {
                return Err(plan::epoch_moved());
            }
            grants::interim_ref_gate(&verified, &op.kind)?;
            tracing::debug!(grant_id = %to_hex_bytes(verified.id()), "write grant accepted");
            Some(crate::op::GrantRef {
                id: *verified.id(),
                epoch: verified.epoch(),
            })
        } else {
            None
        };
        let owner = grant.is_none()
            && matches!(&namespace, Namespace::Ed25519(key)
            if op.principal.ed25519() == Some(key));
        if self.cfg.authorizer_role == AuthorizerRole::Check && !owner && grant.is_none() {
            return Err(ServerError::permission_denied("write not permitted"));
        }
        let facts = AuthzFacts { grant, owner };
        // Both Authorize and Admit see the established owner/grant facts (§6.2).
        let mut authorized = op.clone();
        authorized.authz = facts.clone();
        self.hooks.authorizer().authorize(&authorized).await?;
        Ok(facts)
    }

    /// Stage 3. A challenge is `permission_denied` "admission required" in
    /// M0 (the 402 response lands in M3); nothing is written for it.
    async fn admit(&self, mut input: AdmissionInput<'_>) -> Result<Allowance, ServerError> {
        tracing::debug!(stage = "admission");
        input.write_quota = self.cfg.write_quota;
        match self.hooks.admission().admit(&input).await? {
            AdmissionDecision::Allow {
                charges,
                reservation,
            } => Ok(Allowance {
                charges,
                reservation,
            }),
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
        (lease, begin): (Option<lease::LeaseWrite>, Option<&BeginWrite>),
    ) -> Result<StoredResult, ServerError> {
        let caps = self.meta.capabilities();
        let replay = upload::replay_guard(op);
        let advance = match &op.kind {
            OpKind::AdvanceRefs { head, tickets, .. } if !tickets.is_empty() => {
                Some(advance::AdvanceWrite {
                    ids: tickets,
                    signer: op
                        .auth
                        .as_ref()
                        .ok_or_else(|| {
                            ServerError::failed_precondition("invalid or expired upload ticket")
                        })?
                        .signer,
                    head_ref: &head.name,
                    repo_id: &op.repo,
                    repository: &a.repo().identity,
                    source: p,
                    shards: self.shards.as_ref(),
                })
            }
            _ => None,
        };
        let mut req = WriteRequest {
            repo: &op.repo.name,
            kind,
            refs,
            replay,
            charges,
            namespace_charge: self.namespace_charge(
                p,
                charges,
                ahead.as_ref().and_then(|s| s.namespace_window),
            )?,
            grant: op.authz.grant,
            lease,
            layout_version: caps.implicit_layout_version.is_none(),
            mark_repo_known: matches!(self.cfg.addressing, Addressing::Multi(_))
                && ahead
                    .as_ref()
                    .is_none_or(|snap| snap.get(&keys::repo_known(&op.repo.name)).is_none()),
            rejection: None,
            begin,
            advance,
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
        let mut req = req.clone();
        // Held until the loop ends (see `with_write_gate`).
        let _gate = match &self.gate {
            Some(gate) => Some(gate.enter(p).await),
            None => None,
        };
        let skew_ms = a.business_skew_ms;
        let (mut replans, mut deadline_missed, mut prune_ok) = (0, false, true);
        let mut first_attempt = true;
        loop {
            let mut clock = self.plan_clock(skew_ms, &req);
            let base = ahead.take().unwrap_or_default();
            let snap = self.read_snapshot(p, &req, &clock, base, prune_ok).await?;
            // Every retry re-reads el. Only the initial attempt uses a grant
            // already committed after admission; later attempts renew if needed.
            if req.lease.is_some() && !first_attempt {
                let observed = self.observe_lease(op, p, Some(&snap)).await?;
                let (_, renewed) = self.admit_lease(op, p, observed, skew_ms).await?;
                req.lease = Some(renewed);
                clock = self.plan_clock(skew_ms, &req);
            }
            first_attempt = false;
            let plan = match plan_write(&req, &snap, &clock)? {
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
                #[cfg(feature = "test-faults")]
                {
                    let mut attempt = op.clone();
                    attempt.leased_epoch = req.lease.map(|l| l.value.epoch);
                    fault!(self, BeforeFinalApply, &attempt, a);
                }
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
                        return replay_raced(&req, observed.as_ref());
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
            deadline_cap: match (
                req.replay.map(|r| ms(r.expires_at_ms).saturating_add(lead)),
                req.lease.map(|l| {
                    l.value
                        .expires_at_ms
                        .saturating_sub(self.cfg.lease_margin_ms)
                }),
            ) {
                (Some(replay), Some(lease)) => Some(replay.min(lease)),
                (replay, lease) => replay.or(lease),
            },
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
        if let Some(advance) = &req.advance {
            let detail = advance::detail_keys(&snap, advance)?;
            self.fill(p, &mut snap, detail).await?;
        }
        if let Some(BeginWrite::Open(open)) = req.begin {
            begin::read_indexed(&self.meta, p, &open.spec, &mut snap).await?;
            let reservation = crate::store::tickets::keys(&open.spec).reservation;
            if snap.get(&reservation).is_some()
                && let Some(replay) = req.replay
            {
                let key = keys::replay(&replay.scope);
                let value = self.meta.get(p, &key).await.map_err(meta_error)?;
                snap.insert(key, value);
            }
        }
        Ok(snap)
    }

    /// A full partition: count it, retry the prune alone (deletes still
    /// work) and fail closed with a retryable `unavailable`.
    async fn partition_full(&self, p: &Partition, prune: Option<Batch>) -> ServerError {
        self.metrics
            .incr(METRIC_PARTITION_FULL, &[("kind", p.kind())], 1);
        let name = p.encode().map(|b| to_hex_bytes(&b)).unwrap_or_default();
        tracing::error!(partition = %name, kind = p.kind(), "storage partition full");
        if let Some(prune) = prune
            && let Err(e) = self.meta.apply(p, prune).await
        {
            tracing::warn!(error = %e, "prune on a full partition failed");
        }
        ServerError::unavailable("storage partition full")
    }
}

/// The allowance stays local until the guarded apply.
#[derive(Default)]
struct Allowance {
    charges: Vec<QuotaCharge>,
    reservation: Option<String>,
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
