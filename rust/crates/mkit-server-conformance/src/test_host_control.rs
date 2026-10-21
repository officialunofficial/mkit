//! Test-only controls around an isolated reference pipeline. The wrapper is
//! deliberately outside the engine and has no production configuration path.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::response::IntoResponse;
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use mkit_core::hash::{Hash, from_hex, hash, to_hex};
use mkit_server::pipeline::{
    Admission, AdmissionDecision, AdmissionInput, Authorizer, Hooks, NoOutcomes, NoPreReceive,
    NoReceipts, Pipeline, PipelineConfig, ShardMap, SinglePartition,
};
use mkit_server::policy::AuthorizerRole;
use mkit_server::store::adapter_spi::{codec, keys};
use mkit_server::{
    Addressing, AuthzFacts, Batch, BatchOutcome, Clock, Cursor, Key, ManualClock, MemoryBlobStore,
    MemoryKv, MultiAddressing, NamespaceKey, NamespaceStore, NoopMetrics, Operation, Partition,
    RepoId, RepoName, ServerError, StoreCapabilities, StoreError, Value, Write,
};
use tokio::sync::{Notify, RwLock};
use tower::ServiceExt as _;

use crate::control::{self, Observation, ObservationQuery, Request, Response};
use crate::wire::{Feature, Profile, WireAuth};

#[path = "test_host_publication.rs"]
mod publication;
#[path = "reference_fork.rs"]
mod reference_fork;
use reference_fork::ForkBinding;

type Core = Pipeline<MemoryBlobStore, ControlStore, Hooks<TestAuthority, TestAdmission>>;

/// Controls advertised only when the host runs an indexed pipeline; otherwise
/// each is reported unsupported.
const INDEXED_CONTROLS: &[&str] = &[
    "observe.publication",
    "publication.eligibility",
    "publication.drive",
    "fixture.indexed_refs",
    "pause.before_published_clearance",
];

/// Disposable loopback reference server implementing the versioned test controls.
/// Its retained-memory restart tests process-local recovery only; kill-style
/// persistence is explicitly unsupported.
pub struct ControlledHost {
    base_url: String,
    profile: Profile,
    state: Arc<HostState>,
    listener: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for ControlledHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlledHost")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl ControlledHost {
    /// Starts an isolated opaque or indexed core Connect host. Branch-bucketed and
    /// object HTTP profiles are refused: this fixture observes one atomic domain.
    ///
    /// # Errors
    /// Returns a configuration, listener, or pipeline construction error.
    pub async fn start(profile: Profile) -> Result<Self, String> {
        Self::start_with_ref_reservation(profile, true).await
    }

    /// [`Self::start`] without `fixture.ref_reservation`: the fixture grants no
    /// separate ref reservation and does not advertise the control, mirroring
    /// a host whose admission cannot produce one.
    ///
    /// # Errors
    /// Returns a configuration, listener, or pipeline construction error.
    pub async fn start_without_ref_reservation(profile: Profile) -> Result<Self, String> {
        Self::start_with_ref_reservation(profile, false).await
    }

    async fn start_with_ref_reservation(
        mut profile: Profile,
        ref_reservation: bool,
    ) -> Result<Self, String> {
        if profile.sharding_d34
            || profile.has(Feature::HttpObjects)
            || profile.has(Feature::Takedown)
            || profile.has(Feature::Gc)
            || profile.has(Feature::AsyncInspection)
        {
            return Err("controlled host requires unsharded core Connect profile without object HTTP, takedown, GC, or async inspection".into());
        }
        if !matches!(profile.auth, WireAuth::AuthV2 { .. }) {
            return Err("controlled reservation fixture requires auth v2".into());
        }
        profile.features.insert(Feature::Tickets);
        if profile.has(Feature::IndexedMode) {
            profile.features.insert(Feature::CombinedPublication);
        }
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|e| e.to_string())?;
        let base_url = format!(
            "http://{}",
            listener.local_addr().map_err(|e| e.to_string())?
        );
        if let WireAuth::AuthV2 { audience, .. } = &mut profile.auth {
            audience.clone_from(&base_url);
        }
        let clock = Arc::new(ManualClock::new(crate::wire::sign::now_ms()));
        profile.server_clock = Some(clock.clone());
        profile.derive_features();
        let mut config = super::profile_config(&profile, &base_url)?;
        let store = ControlStore::new(clock.clone(), ref_reservation);
        let authority = configure_authority(&mut profile, &mut config)?;
        let blobs = MemoryBlobStore::default();
        let core = build_core(&store, &blobs, &clock, &config)?;
        let forks = ForkBinding::new(&store, &blobs, &clock, &config)?;
        let state = Arc::new(HostState {
            forks,
            store,
            blobs,
            clock,
            config,
            authority,
            ref_reservation,
            audience: base_url.clone(),
            core: RwLock::new(core),
            reset: Notify::new(),
        });
        let app = axum::Router::new()
            .route(control::CAPABILITIES_PATH, axum::routing::get({
                let state = state.clone();
                move || async move { axum::Json(state.capabilities()) }
            }))
            .route(control::CONTROL_PATH, axum::routing::post({
                let state = state.clone();
                move |axum::Json(request): axum::Json<Request>| {
                    let state = state.clone();
                    async move { Box::pin(state.command(request)).await }
                }
            }))
            .route("/__mkit_test/fork", axum::routing::post({
                let state = state.clone();
                move |headers: http::HeaderMap, body: bytes::Bytes| { let state = state.clone(); async move { Box::pin(state.invoke_fork(headers, body)).await } }
            }))
            .fallback({
                let state = state.clone();
                move |request: axum::extract::Request| {
                    let state = state.clone();
                    async move {
                        let repository = request.headers().get("x-repository").and_then(|v|v.to_str().ok()).unwrap_or("");
                        let core = if state.forks.handles(repository) { state.forks.core.read().await.clone() } else { state.core.read().await.clone() };
                        let response = tokio::select! {
                            biased;
                            () = state.reset.notified() => return http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
                            response = mkit_server::connect::service(core).oneshot(request) => response,
                        };
                        match response {
                            Ok(response) => response.into_response(),
                            Err(never) => match never {},
                        }
                    }
                }
            })
            .layer(super::connect_cors());
        let listener = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        profile.fresh_target = true;
        profile.features.insert(Feature::Health);
        Ok(Self {
            base_url,
            profile,
            state,
            listener,
        })
    }

    /// Canonical loopback origin and signed audience.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
    /// The host's effective wire profile.
    #[must_use]
    pub fn profile(&self) -> &Profile {
        &self.profile
    }
    /// Isolated reference metadata, for fixture construction only.
    #[must_use]
    pub fn kv(&self) -> &Arc<MemoryKv> {
        &self.state.store.inner
    }
    /// Deterministic business clock.
    #[must_use]
    pub fn clock(&self) -> &Arc<ManualClock> {
        &self.state.clock
    }
    /// Stops this host's listener.
    pub async fn shutdown(mut self) {
        self.listener.abort();
        let _ = (&mut self.listener).await;
    }
}

impl Drop for ControlledHost {
    fn drop(&mut self) {
        self.listener.abort();
    }
}

fn configure_authority(profile: &mut Profile, config: &mut PipelineConfig) -> Result<bool, String> {
    let authority = profile.has(Feature::MultiRepo) && profile.has(Feature::AuthV2);
    if authority {
        config.addressing = Addressing::Multi(MultiAddressing::new().with_namespace_policy(
            mkit_server::policy::NamespacePolicy::Any {
                unsafe_without_admission: false,
            },
        ));
        config.authorizer_role = AuthorizerRole::Authority;
        let dedicated = ed25519_dalek::SigningKey::from_bytes(&[0x59; 32]);
        let owner = ed25519_dalek::SigningKey::from_bytes(&[0x58; 32]);
        config.authority_fence = Some(
            mkit_server::authority::AuthorityFence::parse(&format!(
                "test-authority {} ed25519-{}",
                to_hex(dedicated.verifying_key().as_bytes()),
                to_hex(owner.verifying_key().as_bytes()),
            ))
            .map_err(|e| e.to_string())?,
        );
    }
    profile.features.insert(Feature::Fork);
    if authority {
        profile
            .features
            .extend([Feature::AuthorityFencing, Feature::AuthoritySetter]);
    } else {
        profile.features.remove(&Feature::AuthorityFencing);
        profile.features.remove(&Feature::AuthoritySetter);
    }
    Ok(authority)
}

fn build_core(
    store: &ControlStore,
    blobs: &MemoryBlobStore,
    clock: &Arc<ManualClock>,
    config: &PipelineConfig,
) -> Result<Arc<Core>, String> {
    let hooks = Hooks {
        authorizer: TestAuthority(store.clone()),
        admission: TestAdmission(store.clone()),
        pre_receive: NoPreReceive,
        receipts: NoReceipts,
        outcomes: NoOutcomes,
    };
    let pipeline = Pipeline::new(
        blobs.clone(),
        store.clone(),
        hooks,
        config.clone(),
        clock.clone(),
        Arc::new(NoopMetrics),
    )
    .map_err(|e| e.to_string())?;
    let pipeline = if config.indexed.is_some() {
        pipeline
            .with_publication_policy(Arc::new(publication::Eligibility(store.clone())))
            .map_err(|e| e.to_string())?
    } else {
        pipeline
    };
    Ok(Arc::new(pipeline))
}

struct HostState {
    forks: ForkBinding,
    store: ControlStore,
    blobs: MemoryBlobStore,
    clock: Arc<ManualClock>,
    config: PipelineConfig,
    authority: bool,
    ref_reservation: bool,
    audience: String,
    core: RwLock<Arc<Core>>,
    reset: Notify,
}

impl HostState {
    fn capabilities(&self) -> control::Capabilities {
        let mut controls = [
            "observe",
            "clock.pin",
            "clock.advance",
            "restart.graceful",
            "pause.before_acceptance",
            "pause.after_durable_acceptance_before_response",
            "fault.uncertain_result",
        ]
        .map(str::to_owned)
        .to_vec();
        if self.ref_reservation {
            controls.push("fixture.ref_reservation".into());
        }
        let mut unsupported = BTreeMap::from([
            (
                "restart.kill".into(),
                "in-process volatile memory cannot survive process termination".into(),
            ),
            (
                "pause.after_response".into(),
                "response acknowledgement is observed by the client before requesting restart"
                    .into(),
            ),
        ]);
        controls.extend(
            [
                "fork.fixture",
                "fork.invoke",
                "fork.observe",
                "fork.destination_gate",
                "fork.authority_fence",
                "decision.fork_acceptance",
                "decision.fork_progress",
                "decision.fork_destination_claim",
                "decision.writer_authority_ready",
                "decision.fork_source_proof",
                "fork.final_source_proof",
                "fork.source_change.moved",
                "fork.source_change.unpublished",
                "fork.source_change.visibility_revoked",
                "fork.source_change.denied",
            ]
            .map(str::to_owned),
        );
        for name in [
            "reliance.fixture",
            "reliance.observe",
            "gc.prepare_drop",
            "gc.commit_drop",
            "inspection.hide_member",
        ] {
            unsupported.insert(
                name.into(),
                "GC reliance and async inspection controls are not integrated".into(),
            );
        }
        if self.config.indexed.is_some() {
            controls.extend(INDEXED_CONTROLS.iter().map(|name| (*name).to_owned()));
        } else {
            for name in INDEXED_CONTROLS {
                unsupported.insert(
                    (*name).into(),
                    "requires indexed publication profile".into(),
                );
            }
        }
        if !self.ref_reservation {
            unsupported.insert(
                "fixture.ref_reservation".into(),
                "fixture grants no separate ref reservation".into(),
            );
        }
        if self.authority {
            controls.push("authority.bump".into());
            controls.push("authority.setter_fixture".into());
        } else {
            unsupported.insert(
                "authority.bump".into(),
                "requires Multi addressing with auth v2".into(),
            );
        }
        control::Capabilities {
            version: control::VERSION,
            controls,
            durability_profile: "volatile process-local memory retained across pipeline restart"
                .into(),
            unsupported,
        }
    }

    async fn command(&self, request: Request) -> axum::response::Response {
        match Box::pin(self.execute(request)).await {
            Ok(reply) => (http::StatusCode::OK, axum::Json(reply)).into_response(),
            Err((code, message)) => {
                (code, axum::Json(serde_json::json!({"error":message}))).into_response()
            }
        }
    }

    async fn authority_setter_fixture(&self) -> Result<Response, (http::StatusCode, String)> {
        let bad = |message: String| (http::StatusCode::BAD_REQUEST, message);
        let mut reply = Response::default();
        if !self.authority {
            return Err((
                http::StatusCode::NOT_IMPLEMENTED,
                "authority setter fixture disabled".into(),
            ));
        }
        let owner = ed25519_dalek::SigningKey::from_bytes(&[0x58; 32]);
        let namespace = format!("ed25519-{}", to_hex(owner.verifying_key().as_bytes()));
        let generation = self
            .core
            .read()
            .await
            .get_authority_generation(&namespace)
            .await
            .map_err(|e| bad(e.to_string()))?
            .checked_add(1)
            .ok_or_else(|| bad("authority overflow".into()))?;
        let now = self.clock.now_ms();
        let expiry = now
            .checked_add(60_000)
            .ok_or_else(|| bad("clock overflow".into()))?;
        let text = format!(
            "mkit-authority-generation:v1\ntest-authority\n{namespace}\n{generation}\n{}\n{now}\n{expiry}\n{}",
            self.audience,
            "61".repeat(32)
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x59; 32]);
        let signature = key.sign(&hash(text.as_bytes()));
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        reply.authority_namespace = Some(namespace);
        reply.authority_statement = Some(format!(
            "{}.{}",
            b64.encode(text.as_bytes()),
            b64.encode(signature.to_bytes())
        ));
        reply.generation = Some(generation);
        Ok(reply)
    }

    async fn execute(&self, request: Request) -> Result<Response, (http::StatusCode, String)> {
        let bad = |message: String| (http::StatusCode::BAD_REQUEST, message);
        let mut reply = Response::default();
        match request {
            Request::ObservePublication { query } => {
                self.require_publication()?;
                reply.publication_observation =
                    Some(self.observe_publication(query).await.map_err(bad)?);
            }
            Request::SetPublicationEligibility {
                repository,
                head,
                eligible,
            } => {
                self.require_publication()?;
                self.set_publication_eligibility(&repository, &head, eligible)
                    .map_err(bad)?;
            }
            Request::DrivePublication { repository, head } => {
                self.require_publication()?;
                self.drive_publication(&repository, &head)
                    .await
                    .map_err(bad)?;
            }
            Request::PackLocationFixture { .. } => {
                return Err((
                    http::StatusCode::NOT_IMPLEMENTED,
                    "pack-location fixtures are not enabled on this host".into(),
                ));
            }
            Request::PrepareReliance { .. }
            | Request::PrepareGcDrop { .. }
            | Request::CommitGcDrop { .. }
            | Request::HideMember { .. }
            | Request::ObserveReliance { .. } => {
                return Err((
                    http::StatusCode::NOT_IMPLEMENTED,
                    "GC reliance and async inspection controls are not integrated".into(),
                ));
            }
            Request::PrepareAuthoritySetter => return self.authority_setter_fixture().await,
            Request::PinClock { now_ms } => {
                self.clock.set(now_ms);
                reply.now_ms = Some(now_ms);
            }
            Request::AdvanceClock { delta_ms } => {
                reply.now_ms = Some(self.advance_clock(delta_ms).map_err(bad)?);
            }
            Request::Pause {
                step,
                repository,
                head,
                decision_class,
                occurrence,
                on_resume,
            } => {
                self.arm_pause(
                    step,
                    repository,
                    head,
                    decision_class,
                    occurrence,
                    on_resume,
                )?;
            }
            Request::PrepareFork { query } => {
                reply.fork_fixture = Some(self.prepare_fork(query).await.map_err(bad)?);
            }
            Request::ObserveFork { query } => {
                reply.fork_observation = Some(self.observe_fork(query).await.map_err(bad)?);
            }
            Request::ChangeForkSource { query, change } => {
                self.change_fork_source(query, change).await.map_err(bad)?;
            }
            Request::BarrierStatus => {
                reply.paused = self.store.barriers.paused();
            }
            Request::Resume => {
                self.store.barriers.resume();
            }
            Request::Restart { mode } => self.restart_fixture(&mode).await?,
            Request::BumpAuthority { namespace } => {
                if !self.authority {
                    return Err((
                        http::StatusCode::NOT_IMPLEMENTED,
                        "authority fencing is not enabled".into(),
                    ));
                }
                reply.generation = Some(self.bump_authority(&namespace).await.map_err(bad)?);
            }
            Request::Observe { query } => {
                reply.observation = Some(self.observe(query).await.map_err(bad)?);
            }
        }
        Ok(reply)
    }

    async fn restart_fixture(&self, mode: &str) -> Result<(), (http::StatusCode, String)> {
        if mode != "graceful" {
            return Err((
                http::StatusCode::NOT_IMPLEMENTED,
                "kill restart unsupported by retained-memory host".into(),
            ));
        }
        let bad = |message: String| (http::StatusCode::BAD_REQUEST, message);
        // Retire all issued commands at a deterministic test barrier. A
        // blocked caller is canceled by the case before restart.
        self.reset.notify_waiters();
        self.store.barriers.resume();
        *self.core.write().await =
            build_core(&self.store, &self.blobs, &self.clock, &self.config).map_err(bad)?;
        self.forks
            .restart(&self.store, &self.blobs, &self.clock)
            .await
            .map_err(bad)
    }

    fn require_publication(&self) -> Result<(), (http::StatusCode, String)> {
        if self.config.indexed.is_none() {
            return Err((
                http::StatusCode::NOT_IMPLEMENTED,
                "requires indexed publication profile".into(),
            ));
        }
        Ok(())
    }

    fn advance_clock(&self, delta_ms: u64) -> Result<i64, String> {
        let delta =
            i64::try_from(delta_ms).map_err(|_| "clock duration out of range".to_owned())?;
        let now = self
            .clock
            .now_ms()
            .checked_add(delta)
            .ok_or_else(|| "clock overflow".to_owned())?;
        self.clock.set(now);
        Ok(now)
    }

    fn repository(&self, identity: &str) -> Result<RepoId, String> {
        match &self.config.addressing {
            Addressing::Single { repo } => {
                if identity != repo.name.as_str() {
                    return Err("unexpected single repository".into());
                }
                Ok(repo.clone())
            }
            Addressing::Multi(_) => {
                let (namespace, name) = identity
                    .rsplit_once('/')
                    .ok_or("expected full repository identity")?;
                Ok(RepoId {
                    namespace: parse_namespace(namespace)?,
                    name: RepoName::new(name).map_err(|e| e.to_string())?,
                })
            }
            _ => Err("unsupported repository addressing".into()),
        }
    }

    fn arm_pause(
        &self,
        step: String,
        repository: String,
        head: String,
        decision_class: Option<String>,
        occurrence: Option<u64>,
        on_resume: Option<String>,
    ) -> Result<(), (http::StatusCode, String)> {
        let unsupported = |message: &str| (http::StatusCode::NOT_IMPLEMENTED, message.to_owned());
        if !matches!(
            step.as_str(),
            "before_acceptance"
                | "after_durable_acceptance_before_response"
                | "before_published_clearance"
        ) || decision_class.as_deref().is_some_and(|class| {
            if step == "before_published_clearance" {
                class != "published_clearance"
            } else {
                !matches!(
                    class,
                    "ref_acceptance"
                        | "fork_acceptance"
                        | "fork_progress"
                        | "fork_source_proof"
                        | "fork_destination_claim"
                        | "writer_authority_ready"
                )
            }
        }) || occurrence == Some(0)
            || step == "before_published_clearance" && occurrence.is_some_and(|n| n != 1)
            || on_resume
                .as_deref()
                .is_some_and(|action| action != "uncertain_storage_result")
        {
            return Err(unsupported(
                "unsupported protocol boundary or decision selector",
            ));
        }
        if step == "before_published_clearance" && self.config.indexed.is_none() {
            return Err(unsupported("requires indexed publication profile"));
        }
        if on_resume.is_some() && step != "after_durable_acceptance_before_response" {
            return Err((
                http::StatusCode::BAD_REQUEST,
                "uncertain result requires durable acceptance".into(),
            ));
        }
        let bad = |message: String| (http::StatusCode::BAD_REQUEST, message);
        let repo = self.repository(&repository).map_err(bad)?;
        if !mkit_server::refs::validate_ref_name(&head) {
            return Err(bad("invalid head ref".into()));
        }
        self.store
            .barriers
            .arm(
                step.clone(),
                if decision_class
                    .as_deref()
                    .is_some_and(|class| class.starts_with("fork_"))
                {
                    mkit_server::pipeline::D34Shards.coordinator(&repo.namespace)
                } else if decision_class.as_deref() == Some("writer_authority_ready") {
                    mkit_server::pipeline::D34Shards.ref_shard(&repo, &head)
                } else {
                    SinglePartition.ref_shard(&repo, &head)
                },
                if decision_class
                    .as_deref()
                    .is_some_and(|class| class.starts_with("fork_"))
                {
                    keys::fork_job(&repo.name)
                } else if step == "before_published_clearance" {
                    keys::publication(&repo.name, &head)
                } else {
                    keys::ref_key(&repo.name, &head)
                },
                on_resume.is_some(),
                decision_class.unwrap_or_else(|| "ref_acceptance".into()),
                occurrence.unwrap_or(1),
            )
            .map_err(bad)
    }

    async fn bump_authority(&self, namespace: &str) -> Result<u64, String> {
        let ns = parse_namespace(namespace)?;
        let _guard = self.store.gate.lock().await;
        let p = SinglePartition.coordinator(&ns);
        let key = keys::authority_generation();
        let raw = self
            .store
            .inner
            .get(&p, &key)
            .await
            .map_err(|e| e.to_string())?;
        let generation = raw
            .as_ref()
            .map(codec::decode_u64)
            .transpose()
            .map_err(|e| e.to_string())?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or("authority overflow")?;
        self.store
            .inner
            .apply(&p, Batch::new().put(key, codec::encode_u64(generation)))
            .await
            .map_err(|e| e.to_string())?;
        self.store
            .inner
            .apply(
                &mkit_server::pipeline::D34Shards.coordinator(&ns),
                Batch::new().put(keys::authority_generation(), codec::encode_u64(generation)),
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(generation)
    }

    async fn observe(&self, query: ObservationQuery) -> Result<Observation, String> {
        let _guard = self.store.gate.lock().await;
        self.observe_locked(query).await
    }

    async fn observe_locked(&self, query: ObservationQuery) -> Result<Observation, String> {
        if query.ticket_ids.len() + query.reservation_ids.len() + query.packs.len() > 64 {
            return Err("observation exceeds 64 identities".into());
        }
        let repo = self.repository(&query.repository)?;
        if !mkit_server::refs::validate_ref_name(&query.head) {
            return Err("invalid head ref".into());
        }
        let partition = SinglePartition.ref_shard(&repo, &query.head);
        // Every engine apply and the complete typed observation share this
        // wrapper lock. All helpers run within the same observation point.
        let reader = ObservationReader {
            host: self,
            partition,
        };
        let head = reader.ref_id(&repo.name, &query.head).await?;
        let packmap_name =
            mkit_attest::grant::head_packmap(&query.head).ok_or("expected branch head")?;
        let packmap = reader.ref_id(&repo.name, &packmap_name).await?;
        let replay = reader
            .replay(&query.repository, query.replay.as_ref())
            .await?;
        let mut reservation_ids: Vec<Option<String>> =
            query.reservation_ids.into_iter().map(Some).collect();
        let infer_reservations = reservation_ids.is_empty();
        let mut tickets = Vec::new();
        for id in &query.ticket_ids {
            let (ticket, reservation) = reader.ticket(id).await?;
            tickets.push(ticket);
            if infer_reservations {
                reservation_ids.push(reservation);
            }
        }
        if infer_reservations && let Some(identity) = &query.replay {
            reservation_ids.push(reader.operation_reservation(identity));
        }
        let reservations = reader.reservations(reservation_ids).await?;
        let memberships = reader.memberships(&repo.name, &query.packs).await?;
        let quota = reader.quota(&repo, query.quota.as_ref()).await?;
        Ok(Observation {
            head,
            packmap,
            replay,
            tickets,
            reservations,
            memberships,
            quota,
        })
    }
}

/// Reads one snapshot while the caller holds the mutation gate, including
/// every helper read and the reference fixture's terminal-creation counters.
struct ObservationReader<'a> {
    host: &'a HostState,
    partition: Partition,
}

impl ObservationReader<'_> {
    async fn read(&self, key: Key) -> Result<Option<Value>, String> {
        self.host
            .store
            .inner
            .get(&self.partition, &key)
            .await
            .map_err(|e| e.to_string())
    }

    async fn ref_id(&self, repo: &RepoName, name: &str) -> Result<Option<String>, String> {
        self.read(keys::ref_key(repo, name))
            .await?
            .as_ref()
            .map(codec::decode_ref_id)
            .transpose()
            .map(|id| id.as_ref().map(to_hex))
            .map_err(|e| e.to_string())
    }

    async fn replay(
        &self,
        repository: &str,
        identity: Option<&control::ReplayIdentity>,
    ) -> Result<Option<control::ReplayView>, String> {
        let Some(identity) = identity else {
            return Ok(None);
        };
        if identity.repository != repository {
            return Err("replay repository differs from query".into());
        }
        Ok(self
            .read(keys::replay(&replay_scope(identity)))
            .await?
            .as_ref()
            .map(codec::decode_replay_record)
            .transpose()
            .map_err(|e| e.to_string())?
            .map(|record| {
                let (state, result) = match record.state {
                    mkit_server::ReplayState::InFlight { .. } => ("in_flight", None),
                    mkit_server::ReplayState::Committed(result) => {
                        ("committed", Some(result_class(&result).into()))
                    }
                };
                control::ReplayView {
                    state: state.into(),
                    result,
                    fingerprint: Some(to_hex(&record.fingerprint)),
                }
            }))
    }

    async fn ticket(
        &self,
        id: &str,
    ) -> Result<(Option<control::TicketView>, Option<String>), String> {
        let ticket = self
            .read(keys::ticket(&parse_hash(id)?))
            .await?
            .as_ref()
            .map(codec::decode_ticket)
            .transpose()
            .map_err(|e| e.to_string())?;
        let remembered = self
            .host
            .store
            .ticket_reservations
            .lock()
            .unwrap()
            .get(id)
            .cloned();
        let reservation = ticket
            .as_ref()
            .map(|ticket| ticket.reservation_id.clone())
            .or_else(|| remembered.clone());
        let state = if ticket.is_some() {
            Some("live")
        } else if let Some(rid) = remembered {
            match self
                .read(keys::reservation(&rid).map_err(|e| e.to_string())?)
                .await?
                .as_ref()
                .map(codec::decode_reservation)
                .transpose()
                .map_err(|e| e.to_string())?
            {
                Some(codec::ReservationV1::Committed { .. }) => Some("consumed"),
                Some(codec::ReservationV1::Expired { .. }) => Some("expired"),
                _ => None,
            }
        } else {
            None
        };
        Ok((
            state.map(|state| control::TicketView {
                state: state.into(),
            }),
            reservation,
        ))
    }

    fn operation_reservation(&self, identity: &control::ReplayIdentity) -> Option<String> {
        let scope = replay_scope(identity);
        let accepted = self
            .host
            .store
            .accepted_reservations
            .lock()
            .unwrap()
            .get(&scope)
            .cloned();
        accepted.or_else(|| {
            self.host
                .store
                .operation_reservations
                .lock()
                .unwrap()
                .get(&scope)
                .cloned()
        })
    }

    async fn reservations(
        &self,
        ids: Vec<Option<String>>,
    ) -> Result<Vec<Option<control::ReservationView>>, String> {
        let mut reservations = Vec::new();
        for id in ids {
            let Some(id) = id else {
                reservations.push(None);
                continue;
            };
            let record = self
                .read(keys::reservation(&id).map_err(|e| e.to_string())?)
                .await?
                .as_ref()
                .map(codec::decode_reservation)
                .transpose()
                .map_err(|e| e.to_string())?;
            reservations.push(record.map(|record| {
                control::ReservationView {
                    state: reservation_state(&record).into(),
                    terminal_count: self
                        .host
                        .store
                        .terminal_counts
                        .lock()
                        .unwrap()
                        .get(&id)
                        .copied()
                        .unwrap_or(0),
                }
            }));
        }
        Ok(reservations)
    }

    async fn memberships(&self, repo: &RepoName, packs: &[String]) -> Result<Vec<bool>, String> {
        let mut memberships = Vec::new();
        for pack in packs {
            memberships.push(
                self.read(keys::membership(repo, &parse_hash(pack)?))
                    .await?
                    .is_some(),
            );
        }
        Ok(memberships)
    }

    async fn quota(
        &self,
        repo: &RepoId,
        query: Option<&control::QuotaQuery>,
    ) -> Result<Option<control::QuotaView>, String> {
        let Some(query) = query else {
            return Ok(None);
        };
        let scope = mkit_server::quota::QuotaScope::for_signer(
            &repo.namespace,
            &parse_hash(&query.signer)?,
        );
        Ok(self
            .read(keys::quota(&scope))
            .await?
            .as_ref()
            .map(codec::decode_quota_state)
            .transpose()
            .map_err(|e| e.to_string())?
            .filter(|state| {
                query
                    .window_start_ms
                    .is_none_or(|window| state.window_start == window)
            })
            .map(|state| control::QuotaView {
                ops: u64::from(state.ops),
                bytes: state.bytes,
            }))
    }
}

fn replay_scope(identity: &control::ReplayIdentity) -> Hash {
    hash(
        format!(
            "{}\n{}\n{}\n{}",
            identity.audience, identity.repository, identity.signer, identity.nonce
        )
        .as_bytes(),
    )
}

fn result_class(result: &mkit_server::StoredResult) -> &'static str {
    use mkit_server::{StoredResult, UpdateRefResult};
    match result {
        StoredResult::UpdateRef(UpdateRefResult::Committed) => "update_ref_committed",
        StoredResult::UpdateRef(UpdateRefResult::Conflict { .. }) => "update_ref_conflict",
        StoredResult::AdvanceRefs(mkit_core::protocol::AdvanceOutcome::Committed) => {
            "advance_committed"
        }
        StoredResult::AdvanceRefs(_) => "advance_conflict",
        StoredResult::BeginUpload(_) => "begin_upload",
        StoredResult::UploadPack => "upload_pack",
        StoredResult::RepoVisibility => "repo_visibility",
        StoredResult::Fork => "fork_committed",
        StoredResult::Rejected(_) => "rejected",
    }
}

fn parse_namespace(value: &str) -> Result<NamespaceKey, String> {
    mkit_core::repo_identity::Namespace::parse(value)
        .map(|ns| NamespaceKey::from_namespace(&ns))
        .map_err(|e| e.to_string())
}

fn parse_hash(value: &str) -> Result<Hash, String> {
    from_hex(value).map_err(|e| e.to_string())
}

fn reservation_state(record: &codec::ReservationV1) -> &'static str {
    use codec::ReservationV1;
    match record {
        ReservationV1::Pending { .. } => "pending",
        ReservationV1::Ticketed { .. } => "ticketed",
        ReservationV1::Committed { .. } => "committed",
        ReservationV1::Aborted { .. } => "aborted",
        ReservationV1::Expired { .. } => "expired",
        ReservationV1::ReadServed { .. } => "read_served",
        ReservationV1::RepoStorageChanged { .. } => "storage_changed",
    }
}

#[derive(Clone)]
struct ControlStore {
    inner: Arc<MemoryKv>,
    gate: Arc<tokio::sync::Mutex<()>>,
    barriers: Arc<Barriers>,
    terminal_counts: Arc<Mutex<BTreeMap<String, u32>>>,
    ticket_reservations: Arc<Mutex<BTreeMap<String, String>>>,
    operation_reservations: Arc<Mutex<BTreeMap<Hash, String>>>,
    accepted_reservations: Arc<Mutex<BTreeMap<Hash, String>>>,
    next_reservation: Arc<AtomicU64>,
    publication_eligibility: Arc<Mutex<BTreeMap<(Partition, Key), bool>>>,
    fork_progress: Arc<Mutex<BTreeMap<(Partition, Key), u64>>>,
    // Retained test evidence for jobs the engine discards atomically with abort.
    // The reservation row, not this remembered snapshot, establishes failure.
    discarded_forks: Arc<Mutex<BTreeMap<(Partition, Key), mkit_server::fork::ForkJobV1>>>,
    /// Whether admission grants the separate ref reservation advertised as
    /// `fixture.ref_reservation`.
    ref_reservation: bool,
}

impl ControlStore {
    fn new(clock: Arc<ManualClock>, ref_reservation: bool) -> Self {
        Self {
            inner: Arc::new(MemoryKv::with_clock(clock)),
            gate: Arc::default(),
            barriers: Arc::default(),
            terminal_counts: Arc::default(),
            ticket_reservations: Arc::default(),
            operation_reservations: Arc::default(),
            accepted_reservations: Arc::default(),
            next_reservation: Arc::default(),
            publication_eligibility: Arc::default(),
            fork_progress: Arc::default(),
            discarded_forks: Arc::default(),
            ref_reservation,
        }
    }
}

/// Terminal writes are counted only after the real guarded batch commits.
fn terminal_reservations(batch: &Batch) -> Vec<String> {
    batch
        .writes
        .iter()
        .filter_map(|write| {
            if let Write::Put(key, value) = write
                && let Some(keys::ParsedKey::Reservation(id)) = keys::parse(key)
                && let Ok(record) = codec::decode_reservation(value)
                && !matches!(
                    record,
                    codec::ReservationV1::Pending { .. } | codec::ReservationV1::Ticketed { .. }
                )
            {
                return Some(id);
            }
            None
        })
        .collect()
}

impl NamespaceStore for ControlStore {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    fn read_call_allowance(&self) -> Option<u32> {
        self.inner.read_call_allowance()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.before_fork_source_read(p, std::slice::from_ref(key))
            .await?;
        self.inner.get(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.before_fork_source_read(p, keys).await?;
        self.inner.get_many(p, keys).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<mkit_server::ScanPage, StoreError> {
        self.inner.scan(p, start, end, after, limit).await
    }
    #[allow(clippy::too_many_lines)] // Wrap each complete reference commit and its fault boundary.
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        let fork_rows: Vec<_> = batch
            .writes
            .iter()
            .filter_map(|write| {
                if let Write::Put(key, value) = write
                    && matches!(keys::parse(key), Some(keys::ParsedKey::ForkJob(_)))
                {
                    return Some((key.clone(), mkit_server::fork::decode_job(value)));
                }
                None
            })
            .collect();
        let mut fork_commits = Vec::new();
        for (key, next) in fork_rows {
            let next = next?;
            let prior = self
                .inner
                .get(p, &key)
                .await?
                .as_ref()
                .map(mkit_server::fork::decode_job)
                .transpose()?;
            if let Some(prior) = prior {
                let accepting = prior.accepted.is_none() && next.accepted.is_some();
                let preparing =
                    reference_fork::preparation(&prior) && reference_fork::preparation(&next);
                let occurrence = self
                    .fork_progress
                    .lock()
                    .unwrap()
                    .get(&(p.clone(), key.clone()))
                    .copied()
                    .unwrap_or(0)
                    + 1;
                if batch.writes.iter().any(|write| matches!(write, Write::Put(key, _) if matches!(keys::parse(key), Some(keys::ParsedKey::ForkBarrier(_))))) {
                    self.barriers.pass_decision("before_acceptance", "fork_destination_claim", 1, p, &key).await;
                }
                if accepting {
                    self.barriers
                        .pass_decision("before_acceptance", "fork_acceptance", 1, p, &key)
                        .await;
                } else if preparing {
                    self.barriers
                        .pass_decision("before_acceptance", "fork_progress", occurrence, p, &key)
                        .await;
                }
                fork_commits.push((key, preparing, accepting));
            }
        }
        if matches!(p, Partition::Ref { .. }) {
            for write in &batch.writes {
                if let Write::Put(key, value) = write
                    && matches!(keys::parse(key), Some(keys::ParsedKey::Ticket(_)))
                {
                    let ticket = codec::decode_ticket(value)?;
                    self.barriers
                        .pass_decision(
                            "before_acceptance",
                            "writer_authority_ready",
                            1,
                            p,
                            &keys::ref_key(&ticket.repo, &ticket.ref_name),
                        )
                        .await;
                }
            }
        }
        let refs: Vec<_> = batch
            .writes
            .iter()
            .filter_map(|write| {
                let key = match write {
                    Write::Put(key, _) | Write::Delete(key) | Write::Increment(key) => key,
                };
                matches!(keys::parse(key), Some(keys::ParsedKey::Ref { .. })).then_some(key.clone())
            })
            .collect();
        for key in &refs {
            self.barriers.pass("before_acceptance", p, key).await;
        }
        for key in publication::clearance_keys(self, p, &batch).await? {
            self.barriers
                .pass("before_published_clearance", p, &key)
                .await;
        }
        let guard = self.gate.lock().await;
        let terminals = terminal_reservations(&batch);
        let mut accepted_ref_reservation = None;
        if !refs.is_empty() {
            for id in &terminals {
                let key = keys::reservation(id)?;
                if let Some(raw) = self.inner.get(p, &key).await?
                    && matches!(
                        codec::decode_reservation(&raw)?,
                        codec::ReservationV1::Pending { .. }
                    )
                {
                    accepted_ref_reservation = Some(id.clone());
                }
            }
        }
        let replay_scopes: Vec<_> = batch
            .writes
            .iter()
            .filter_map(|write| {
                if let Write::Put(key, _) = write
                    && let Some(keys::ParsedKey::Replay(scope)) = keys::parse(key)
                {
                    return Some(scope);
                }
                None
            })
            .collect();
        let mut consumed = Vec::new();
        for write in &batch.writes {
            if let Write::Delete(key) = write
                && let Some(keys::ParsedKey::Ticket(id)) = keys::parse(key)
                && let Some(raw) = self.inner.get(p, key).await?
            {
                let ticket = codec::decode_ticket(&raw)?;
                consumed.push((to_hex(&id), ticket.reservation_id));
            }
        }
        let mut discarded_forks = Vec::new();
        for write in &batch.writes {
            if let Write::Delete(key) = write
                && matches!(keys::parse(key), Some(keys::ParsedKey::ForkJob(_)))
                && let Some(raw) = self.inner.get(p, key).await?
            {
                discarded_forks.push((
                    (p.clone(), key.clone()),
                    mkit_server::fork::decode_job(&raw)?,
                ));
            }
        }
        let outcome = self.inner.apply(p, batch).await?;
        if outcome == BatchOutcome::Committed {
            self.discarded_forks.lock().unwrap().extend(discarded_forks);
            for (key, preparing, _) in &fork_commits {
                if *preparing {
                    *self
                        .fork_progress
                        .lock()
                        .unwrap()
                        .entry((p.clone(), key.clone()))
                        .or_default() += 1;
                }
            }
            let mut counts = self.terminal_counts.lock().unwrap();
            for id in terminals {
                *counts.entry(id).or_default() += 1;
            }
            self.ticket_reservations.lock().unwrap().extend(consumed);
            if let Some(id) = accepted_ref_reservation {
                let mut accepted = self.accepted_reservations.lock().unwrap();
                for scope in replay_scopes {
                    accepted.insert(scope, id.clone());
                }
            }
        }
        drop(guard);
        if outcome == BatchOutcome::Committed {
            for (key, _, accepting) in &fork_commits {
                if *accepting
                    && self
                        .barriers
                        .pass_decision(
                            "after_durable_acceptance_before_response",
                            "fork_acceptance",
                            1,
                            p,
                            key,
                        )
                        .await
                {
                    return Err(StoreError::unavailable(
                        "test uncertain committed fork outcome",
                    ));
                }
            }
            for key in &refs {
                if self
                    .barriers
                    .pass("after_durable_acceptance_before_response", p, key)
                    .await
                {
                    return Err(StoreError::unavailable("test uncertain committed outcome"));
                }
            }
        }
        Ok(outcome)
    }
    async fn stats(&self, p: &Partition) -> Result<mkit_server::PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

#[derive(Default)]
struct Barriers {
    state: Mutex<Option<Barrier>>,
    resume: Notify,
}
struct Barrier {
    step: String,
    partition: Partition,
    key: Key,
    reached: bool,
    uncertain_result: bool,
    decision_class: String,
    occurrence: u64,
}

impl Barriers {
    fn arm(
        &self,
        step: String,
        partition: Partition,
        key: Key,
        uncertain_result: bool,
        decision_class: String,
        occurrence: u64,
    ) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        if state.is_some() {
            return Err("a barrier is already armed".into());
        }
        *state = Some(Barrier {
            step,
            partition,
            key,
            reached: false,
            uncertain_result,
            decision_class,
            occurrence,
        });
        Ok(())
    }
    fn paused(&self) -> bool {
        self.state
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|b| b.reached)
    }
    fn resume(&self) {
        *self.state.lock().unwrap() = None;
        self.resume.notify_waiters();
    }
    async fn pass(&self, step: &str, partition: &Partition, key: &Key) -> bool {
        self.pass_decision(step, "ref_acceptance", 1, partition, key)
            .await
    }
    async fn pass_decision(
        &self,
        step: &str,
        decision_class: &str,
        occurrence: u64,
        partition: &Partition,
        key: &Key,
    ) -> bool {
        let notified = self.resume.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let (pause, uncertain_result) = {
            let mut state = self.state.lock().unwrap();
            if let Some(barrier) = state.as_mut()
                && barrier.step == step
                && barrier.decision_class == decision_class
                && barrier.occurrence == occurrence
                && partition == &barrier.partition
                && key == &barrier.key
                && !barrier.reached
            {
                barrier.reached = true;
                (true, barrier.uncertain_result)
            } else {
                (false, false)
            }
        };
        if pause {
            notified.await;
        }
        uncertain_result
    }
}

#[derive(Clone)]
struct TestAuthority(ControlStore);
impl Authorizer for TestAuthority {
    async fn authorize(&self, op: &Operation) -> Result<AuthzFacts, ServerError> {
        let mut facts = AuthzFacts::default();
        facts.authority_generation = Some(
            self.0
                .inner
                .get(
                    &if op.repo.name.as_str().starts_with("fork-") {
                        mkit_server::pipeline::D34Shards.coordinator(&op.repo.namespace)
                    } else {
                        SinglePartition.coordinator(&op.repo.namespace)
                    },
                    &keys::authority_generation(),
                )
                .await
                .map_err(|_| ServerError::unavailable("test authority read failed"))?
                .as_ref()
                .map(codec::decode_u64)
                .transpose()
                .map_err(|_| ServerError::unavailable("test authority state corrupt"))?
                .unwrap_or(0),
        );
        if op.repo.name.as_str().starts_with("fork-source-") {
            let raw = self
                .0
                .inner
                .get(
                    &mkit_server::pipeline::D34Shards.coordinator(&op.repo.namespace),
                    &keys::repo_visibility(&op.repo.name),
                )
                .await
                .map_err(|_| ServerError::unavailable("test visibility read failed"))?;
            if raw
                .as_ref()
                .map(codec::decode_repo_visibility)
                .transpose()
                .map_err(|_| ServerError::unavailable("test visibility corrupt"))?
                .is_some_and(|v| v.visibility == codec::StoredVisibility::Private)
            {
                return Err(ServerError::permission_denied("source read revoked"));
            }
        }
        facts.caller_view = mkit_server::CallerView::Writer;
        Ok(facts)
    }
}

#[derive(Clone)]
struct TestAdmission(ControlStore);
impl Admission for TestAdmission {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        let decision = mkit_server::pipeline::DefaultAdmission.admit(input).await?;
        // The fixture's separate reservation is the ref reservation only when
        // `fixture.ref_reservation` is advertised; ticket reservations are
        // bound by `BeginUpload` admission regardless.
        let grants = self.0.ref_reservation
            || !matches!(
                input.op.kind,
                mkit_server::OpKind::UpdateRef(_) | mkit_server::OpKind::AdvanceRefs { .. }
            );
        Ok(if let (Some(auth), true) = (&input.op.auth, grants) {
            let sequence = self.0.next_reservation.fetch_add(1, Ordering::Relaxed);
            let id = format!("conformance:{}:{sequence}", to_hex(&auth.replay_scope));
            self.0
                .operation_reservations
                .lock()
                .unwrap()
                .insert(auth.replay_scope, id.clone());
            decision.with_reservation(id)
        } else {
            decision
        })
    }
}

impl ControlStore {
    async fn before_fork_source_read(
        &self,
        partition: &Partition,
        read_keys: &[Key],
    ) -> Result<(), StoreError> {
        let selected = self
            .barriers
            .state
            .lock()
            .unwrap()
            .as_ref()
            .filter(|b| b.decision_class == "fork_source_proof" && !b.reached)
            .map(|b| (b.partition.clone(), b.key.clone()));
        if let Some((target, key)) = selected
            && let Some(raw) = self.inner.get(&target, &key).await?
        {
            let job = mkit_server::fork::decode_job(&raw)?;
            // Capture checkpoints are preparation. Pause only after their
            // final durable checkpoint, before the first eligibility proof.
            let shape = serde_json::to_value(&job)
                .map_err(|_| StoreError::Corrupt("invalid control fork job".into()))?;
            let proof_ready = shape
                .get("proof")
                .and_then(|proof| proof.get("stage"))
                .and_then(serde_json::Value::as_str)
                == Some("Proving");
            if job.phase == mkit_server::fork::Phase::Accept && proof_ready && job.cursor == 0 {
                let source = RepoId {
                    namespace: parse_namespace(&job.source_ns).map_err(StoreError::unavailable)?,
                    name: RepoName::new(job.source_repo)
                        .map_err(|e| StoreError::unavailable(e.to_string()))?,
                };
                let first = job.packs.first().ok_or_else(|| {
                    StoreError::Corrupt("fork proof lacks inherited packs".into())
                })?;
                if partition
                    == &mkit_server::pipeline::D34Shards
                        .membership(&source, &mkit_server::BlobKey::pack(first.id))
                    && read_keys.contains(&keys::published_member(&source.name, &first.id))
                {
                    self.barriers
                        .pass_decision("before_acceptance", "fork_source_proof", 1, &target, &key)
                        .await;
                }
            }
        }
        Ok(())
    }
}
