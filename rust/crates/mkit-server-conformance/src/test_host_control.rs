//! Test-only controls around an isolated reference pipeline. The wrapper is
//! deliberately outside the engine and has no production configuration path.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::response::IntoResponse;
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

type Core = Pipeline<MemoryBlobStore, ControlStore, Hooks<TestAuthority, TestAdmission>>;

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
    /// Starts an isolated opaque core Connect host. Indexed, branch-bucketed, and object HTTP profiles are
    /// refused: this fixture observes one single-partition acceptance domain.
    ///
    /// # Errors
    /// Returns a configuration, listener, or pipeline construction error.
    pub async fn start(mut profile: Profile) -> Result<Self, String> {
        if profile.sharding_d34
            || profile.has(Feature::HttpObjects)
            || profile.has(Feature::IndexedMode)
            || profile.has(Feature::Takedown)
        {
            return Err("controlled host requires unsharded opaque core Connect profile".into());
        }
        if !matches!(profile.auth, WireAuth::AuthV2 { .. }) {
            return Err("controlled reservation fixture requires auth v2".into());
        }
        profile.features.insert(Feature::Tickets);
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
        let store = ControlStore::new(clock.clone());
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
        let blobs = MemoryBlobStore::default();
        let core = build_core(&store, &blobs, &clock, &config)?;
        let state = Arc::new(HostState {
            store,
            blobs,
            clock,
            config,
            authority,
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
                    async move { state.command(request).await }
                }
            }))
            .fallback({
                let state = state.clone();
                move |request: axum::extract::Request| {
                    let state = state.clone();
                    async move {
                        let core = state.core.read().await.clone();
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
    Pipeline::new(
        blobs.clone(),
        store.clone(),
        hooks,
        config.clone(),
        clock.clone(),
        Arc::new(NoopMetrics),
    )
    .map(Arc::new)
    .map_err(|e| e.to_string())
}

struct HostState {
    store: ControlStore,
    blobs: MemoryBlobStore,
    clock: Arc<ManualClock>,
    config: PipelineConfig,
    authority: bool,
    core: RwLock<Arc<Core>>,
    reset: Notify,
}

impl HostState {
    fn capabilities(&self) -> control::Capabilities {
        let mut controls = [
            "observe",
            "fixture.opaque_refs",
            "clock.pin",
            "clock.advance",
            "restart.graceful",
            "pause.before_acceptance",
            "pause.after_durable_acceptance_before_response",
            "fault.uncertain_result",
            "fixture.ref_reservation",
        ]
        .map(str::to_owned)
        .to_vec();
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
        unsupported.extend([
            ("pause.before_published_clearance".into(),"opaque fixture has no deferred publication decision".into()),
            ("fork.fixture".into(),"gated fork test binding awaits destination activation and advancing-commit fencing".into()),
            ("fork.invoke".into(),"gated fork test binding awaits destination activation and advancing-commit fencing".into()),
            ("fork.observe".into(),"gated fork test binding awaits destination activation and advancing-commit fencing".into()),
            ("fork.destination_gate".into(),"reference fork does not yet gate destination reads and writes on guarded acceptance".into()),
            ("fork.authority_fence".into(),"reference fork does not yet compare recorded authority facts at every advancing commit".into()),
            ("decision.fork_acceptance".into(),"gated fork test binding is not yet available".into()),
            ("decision.fork_progress".into(),"advancing fork authority-fence control is not yet available".into()),
        ]);
        if self.authority {
            controls.push("authority.bump".into());
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
        match self.execute(request).await {
            Ok(reply) => (http::StatusCode::OK, axum::Json(reply)).into_response(),
            Err((code, message)) => {
                (code, axum::Json(serde_json::json!({"error":message}))).into_response()
            }
        }
    }

    async fn execute(&self, request: Request) -> Result<Response, (http::StatusCode, String)> {
        let bad = |message: String| (http::StatusCode::BAD_REQUEST, message);
        let mut reply = Response::default();
        match request {
            Request::PinClock { now_ms } => {
                self.clock.set(now_ms);
                reply.now_ms = Some(now_ms);
            }
            Request::AdvanceClock { delta_ms } => {
                let delta = i64::try_from(delta_ms)
                    .map_err(|_| bad("clock duration out of range".into()))?;
                let now = self
                    .clock
                    .now_ms()
                    .checked_add(delta)
                    .ok_or_else(|| bad("clock overflow".into()))?;
                self.clock.set(now);
                reply.now_ms = Some(now);
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
            Request::PrepareFork { .. } | Request::ObserveFork { .. } => {
                return Err((http::StatusCode::NOT_IMPLEMENTED,
                    "reference fork destination gate and advancing-commit authority fence are not implemented".into()));
            }
            Request::BarrierStatus => {
                reply.paused = self.store.barriers.paused();
            }
            Request::Resume => {
                self.store.barriers.resume();
            }
            Request::Restart { mode } => {
                if mode != "graceful" {
                    return Err((
                        http::StatusCode::NOT_IMPLEMENTED,
                        "kill restart unsupported by retained-memory host".into(),
                    ));
                }
                // Retire all issued commands at a deterministic test barrier. A
                // blocked caller is canceled by the case before restart.
                self.reset.notify_waiters();
                self.store.barriers.resume();
                *self.core.write().await =
                    build_core(&self.store, &self.blobs, &self.clock, &self.config).map_err(bad)?;
            }
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
            "before_acceptance" | "after_durable_acceptance_before_response"
        ) || decision_class
            .as_deref()
            .is_some_and(|class| class != "ref_acceptance")
            || occurrence.is_some_and(|n| n != 1)
            || on_resume
                .as_deref()
                .is_some_and(|action| action != "uncertain_storage_result")
        {
            return Err(unsupported(
                "unsupported protocol boundary or decision selector",
            ));
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
                step,
                SinglePartition.ref_shard(&repo, &head),
                keys::ref_key(&repo.name, &head),
                on_resume.is_some(),
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
        Ok(generation)
    }

    async fn observe(&self, query: ObservationQuery) -> Result<Observation, String> {
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
        let guard = self.store.gate.lock().await;
        let reader = ObservationReader {
            host: self,
            partition,
            _guard: guard,
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

/// Holds the mutation gate for the complete observation, including every
/// helper's reads and the reference fixture's terminal-creation counters.
struct ObservationReader<'a> {
    host: &'a HostState,
    partition: Partition,
    _guard: tokio::sync::MutexGuard<'a, ()>,
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
        StoredResult::Fork => "fork",
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
}

impl ControlStore {
    fn new(clock: Arc<ManualClock>) -> Self {
        Self {
            inner: Arc::new(MemoryKv::with_clock(clock)),
            gate: Arc::default(),
            barriers: Arc::default(),
            terminal_counts: Arc::default(),
            ticket_reservations: Arc::default(),
            operation_reservations: Arc::default(),
            accepted_reservations: Arc::default(),
            next_reservation: Arc::default(),
        }
    }
}

impl NamespaceStore for ControlStore {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    fn read_call_allowance(&self) -> Option<u32> {
        self.inner.read_call_allowance()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(p, key).await
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
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        let refs: Vec<_> = batch
            .writes
            .iter()
            .filter_map(|write| {
                let key = match write {
                    Write::Put(key, _) | Write::Delete(key) => key,
                };
                matches!(keys::parse(key), Some(keys::ParsedKey::Ref { .. })).then_some(key.clone())
            })
            .collect();
        for key in &refs {
            self.barriers.pass("before_acceptance", p, key).await;
        }
        let guard = self.gate.lock().await;
        let terminals: Vec<_> = batch
            .writes
            .iter()
            .filter_map(|write| {
                if let Write::Put(key, value) = write
                    && let Some(keys::ParsedKey::Reservation(id)) = keys::parse(key)
                    && let Ok(record) = codec::decode_reservation(value)
                    && !matches!(
                        record,
                        codec::ReservationV1::Pending { .. }
                            | codec::ReservationV1::Ticketed { .. }
                    )
                {
                    return Some(id);
                }
                None
            })
            .collect();
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
        let outcome = self.inner.apply(p, batch).await?;
        if outcome == BatchOutcome::Committed {
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
}

impl Barriers {
    fn arm(
        &self,
        step: String,
        partition: Partition,
        key: Key,
        uncertain_result: bool,
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
        let notified = self.resume.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let (pause, uncertain_result) = {
            let mut state = self.state.lock().unwrap();
            if let Some(barrier) = state.as_mut()
                && barrier.step == step
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
                    &SinglePartition.coordinator(&op.repo.namespace),
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
        facts.caller_view = mkit_server::CallerView::Writer;
        Ok(facts)
    }
}

#[derive(Clone)]
struct TestAdmission(ControlStore);
impl Admission for TestAdmission {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        let decision = mkit_server::pipeline::DefaultAdmission.admit(input).await?;
        Ok(if let Some(auth) = &input.op.auth {
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
