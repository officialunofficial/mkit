//! Test-only loopback host for contract tests that need a real HTTP boundary
//! around the core Connect handlers.
//!
//! Enable the `test-host` feature in a debug/test dependency. The feature is
//! rejected in release builds. Each host owns isolated memory stores and a
//! manual clock; callers advance time and explicitly drain core timers.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use tokio::task::JoinHandle;

use mkit_attest::grant::{AcceptedSchemes, OwnerScheme, RelyingParty};
use mkit_server::auth_v2::AuthV2Config;
use mkit_server::pipeline::{AuthMode, HookSet, Hooks, Pipeline, PipelineConfig, Sharding};
use mkit_server::policy::NamespacePolicy;
use mkit_server::quota::QuotaLimits;
use mkit_server::store::adapter_spi::keys;
use mkit_server::timers::outcome_delivery::OutcomeDelivery;
use mkit_server::timers::ticket_expiry::TicketExpiry;
use mkit_server::timers::{RunReport, TickBudget, TimerRegistry, run_due};
use mkit_server::upload::UploadLimits;
use mkit_server::{
    Addressing, Batch, BlobKey, BlobStore, Clock, ManualClock, MemoryBlobStore, MemoryKv,
    MultiAddressing, NamespaceKey, NamespaceStore, NoopMetrics, PackSink, Partition, Redacted,
    RepoId, RepoName, Value,
};

use crate::wire::{Feature, Profile, WireAuth};

/// HTTP channel for the conformance crate's signed loopback hook stub.
///
/// It refuses non-loopback origins, disables redirects and reads at most one
/// byte beyond the response limit requested by the core hook client.
#[derive(Clone)]
pub struct LoopbackHookChannel {
    client: reqwest::Client,
    origin: String,
}

impl fmt::Debug for LoopbackHookChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoopbackHookChannel")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl LoopbackHookChannel {
    /// Creates a channel to a loopback `http` origin, such as
    /// [`crate::stubs::hook::FakeHook::origin`].
    ///
    /// # Errors
    /// Returns a fixed error if the origin is invalid or the client cannot be built.
    pub fn new(origin: &str) -> Result<Self, String> {
        let url = url::Url::parse(origin).map_err(|_| "invalid hook origin".to_owned())?;
        let loopback = match url.host() {
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            Some(url::Host::Domain(name)) => name == "localhost",
            None => false,
        };
        if url.scheme() != "http"
            || !loopback
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("hook channel requires a loopback http origin".into());
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| "hook client could not be built".to_owned())?;
        Ok(Self {
            client,
            origin: url.origin().ascii_serialization(),
        })
    }
}

impl mkit_server::hooks::HookChannel for LoopbackHookChannel {
    fn audience(&self) -> Option<&str> {
        Some(&self.origin)
    }

    async fn call(
        &self,
        request: mkit_server::hooks::HookRequest,
    ) -> Result<mkit_server::hooks::HookResponse, mkit_server::hooks::ChannelError> {
        use bytes::Bytes;
        use mkit_server::Redacted;

        let mut call = self
            .client
            .post(format!("{}{}", self.origin, request.procedure))
            .timeout(request.timeout);
        for (name, value) in &request.headers {
            call = call.header(*name, value);
        }
        let max = request.max_response_bytes;
        let mut response = call
            .body(Bytes::from_owner(request.body))
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    mkit_server::hooks::ChannelError::Timeout
                } else {
                    mkit_server::hooks::ChannelError::Transport(Redacted::new("request failed"))
                }
            })?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut body = Vec::new();
        while body.len() <= max {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    let room = (max + 1 - body.len()).min(chunk.len());
                    body.extend_from_slice(&chunk[..room]);
                }
                Ok(None) => break,
                Err(error) if error.is_timeout() => {
                    return Err(mkit_server::hooks::ChannelError::Timeout);
                }
                Err(_) => {
                    return Err(mkit_server::hooks::ChannelError::Transport(Redacted::new(
                        "response body failed",
                    )));
                }
            }
        }
        Ok(mkit_server::hooks::HookResponse::new(
            status,
            content_type,
            body,
        ))
    }
}

const REPOSITORY: &str = "default";
const TICKET_KEY: &str = "dev 1111111111111111111111111111111111111111111111111111111111111111";
// Bound even a handler that never wakes, without relying on wall-clock sleeps.
const MAX_TIMER_DRAIN_POLLS: usize = 100_000;

/// Isolated in-process Connect server with a canonical loopback origin.
///
/// Construct with [`TestHost::start`] or [`TestHost::start_with_hooks`].
/// Dropping the value aborts its listener task; prefer [`TestHost::shutdown`]
/// when a test needs to await orderly task completion.
pub struct TestHost {
    base_url: String,
    profile: Profile,
    kv: Arc<MemoryKv>,
    blobs: MemoryBlobStore,
    preserved: MemoryBlobStore,
    clock: Arc<ManualClock>,
    listener_task: Option<JoinHandle<()>>,
}

impl core::fmt::Debug for TestHost {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TestHost")
            .field("base_url", &self.base_url)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

impl TestHost {
    /// Starts a host with the default core hooks and an isolated memory store.
    ///
    /// If `profile.auth` is auth v2, its audience is replaced with the exact
    /// loopback origin allocated for this host and reflected in
    /// [`Self::profile`]. Single profiles address the default repository;
    /// profiles declaring `MultiRepo` use an allowlist derived from their
    /// conformance run id and signer seed. `sharding_d34` selects D34 routing.
    ///
    /// # Errors
    /// Returns a message if binding, profile configuration, or pipeline
    /// construction fails.
    pub async fn start(profile: Profile) -> Result<Self, String> {
        Self::start_with_hooks(profile, Hooks::new()).await
    }

    /// Starts a host with caller-provided core hooks, such as the conformance
    /// crate's scripted admission and outcome stubs.
    ///
    /// # Errors
    /// Returns a message if binding, profile configuration, or pipeline
    /// construction fails.
    pub async fn start_with_hooks<H: HookSet + 'static>(
        profile: Profile,
        hooks: H,
    ) -> Result<Self, String> {
        Self::start_with_hooks_factory(profile, move |_, _| Ok(hooks)).await
    }

    /// Starts with hooks created after the loopback origin and manual clock
    /// are allocated. This supports a signed `FakeHook` client whose request
    /// bodies bind the host's canonical origin.
    ///
    /// # Errors
    /// Returns a message if binding, hook construction, profile configuration,
    /// or pipeline construction fails.
    pub async fn start_with_hooks_factory<H, F>(
        profile: Profile,
        make_hooks: F,
    ) -> Result<Self, String>
    where
        H: HookSet + 'static,
        F: FnOnce(&str, Arc<ManualClock>) -> Result<H, String>,
    {
        Self::start_with_test_layers(profile, make_hooks, |_| {}, |app| app).await
    }

    /// Starts a host with an opt-in HTTP test layer, applied after the core
    /// routes. Contract consumers can capture wire bytes or inject response
    /// loss while retaining the host's exact origin and real core handlers.
    /// Ordinary hosts retain their streaming boundary without this layer.
    pub async fn start_with_test_layers<H, F, C, L>(
        mut profile: Profile,
        make_hooks: F,
        configure: C,
        layer: L,
    ) -> Result<Self, String>
    where
        H: HookSet + 'static,
        F: FnOnce(&str, Arc<ManualClock>) -> Result<H, String>,
        C: FnOnce(&mut PipelineConfig),
        L: FnOnce(axum::Router) -> axum::Router,
    {
        profile.derive_features();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|error| error.to_string())?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let base_url = format!("http://127.0.0.1:{}", address.port());
        let clock = Arc::new(ManualClock::new(crate::wire::sign::now_ms()));
        profile.server_clock = Some(clock.clone());
        let hooks = make_hooks(&base_url, clock.clone())?;

        if let WireAuth::AuthV2 { audience, .. } = &mut profile.auth {
            audience.clone_from(&base_url);
        }
        let mut config = profile_config(&profile, &base_url)?;
        configure(&mut config);

        profile.sign_reads = config.url_tokens.is_some();
        profile.derive_features();
        let kv = Arc::new(MemoryKv::with_clock(clock.clone()));
        let blobs = MemoryBlobStore::default();
        let preserved = MemoryBlobStore::new("preserved");
        if profile.has(Feature::MultiRepo) {
            plant_membership(&blobs, &kv, &config.addressing, config.sharding, &profile).await?;
            profile.planted_membership = true;
        }
        let pipeline = Arc::new(
            Pipeline::new(
                blobs.clone(),
                kv.clone(),
                hooks,
                config,
                clock.clone(),
                Arc::new(NoopMetrics),
            )
            .map_err(|error| error.to_string())?,
        );
        let app = mount_app(
            &profile,
            &base_url,
            clock.clone(),
            kv.clone(),
            blobs.clone(),
            preserved.clone(),
            pipeline,
        )?;
        let app = layer(app);
        let listener_task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        profile.fresh_target = true;
        profile.derive_features();
        profile.features.insert(Feature::Health);
        Ok(Self {
            base_url,
            profile,
            kv,
            blobs,
            preserved,
            clock,
            listener_task: Some(listener_task),
        })
    }

    /// Rebuild the listener and default hooks over the same metadata, blobs,
    /// origin and clock. Intended for the default-hook persistence scenarios.
    ///
    /// # Errors
    /// Listener rebinding or pipeline construction fails.
    pub async fn restart_with_default_hooks(&mut self) -> Result<(), String> {
        if let Some(task) = self.listener_task.take() {
            task.abort();
            let _ = task.await;
        }
        let address = self
            .base_url
            .strip_prefix("http://")
            .ok_or("invalid test origin")?;
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .map_err(|e| e.to_string())?;
        let pipeline = Arc::new(
            Pipeline::new(
                self.blobs.clone(),
                self.kv.clone(),
                Hooks::new(),
                profile_config(&self.profile, &self.base_url)?,
                self.clock.clone(),
                Arc::new(NoopMetrics),
            )
            .map_err(|e| e.to_string())?,
        );
        let app = mount_app(
            &self.profile,
            &self.base_url,
            self.clock.clone(),
            self.kv.clone(),
            self.blobs.clone(),
            self.preserved.clone(),
            pipeline,
        )?;
        self.listener_task = Some(tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        }));
        Ok(())
    }

    /// Returns this host's canonical loopback origin as the auth v2 audience
    /// and `WireTarget` base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Returns the wire-suite profile with this host's auth v2 audience.
    #[must_use]
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// Returns the isolated metadata store for fixture setup and assertions.
    #[must_use]
    pub fn kv(&self) -> &Arc<MemoryKv> {
        &self.kv
    }

    /// Returns the isolated pack and object store for fixture setup and assertions.
    #[must_use]
    pub fn blobs(&self) -> &MemoryBlobStore {
        &self.blobs
    }

    /// Returns the deterministic server clock. It advances only when the test
    /// calls [`ManualClock::set`] or [`ManualClock::advance`].
    #[must_use]
    pub fn clock(&self) -> &Arc<ManualClock> {
        &self.clock
    }

    /// Fires due core timers for one partition. The caller supplies the
    /// registered core handlers so each test controls exactly which durable
    /// work is drained; no background timer task or sleep is used.
    /// A pending handler is cancelled after a finite number of executor polls.
    ///
    /// # Errors
    /// Returns a store scan error or an unavailable error when a handler
    /// exhausts the poll budget. Its uncommitted timer remains queued.
    pub async fn drain_timers(
        &self,
        partition: &Partition,
        registry: &TimerRegistry<'_, MemoryKv>,
        budget: &TickBudget,
    ) -> Result<RunReport, mkit_server::StoreError> {
        let now_ms = u64::try_from(self.clock.now_ms()).unwrap_or(0);
        let mut drain = core::pin::pin!(run_due(
            self.kv.as_ref(),
            partition,
            registry,
            self.clock.as_ref(),
            now_ms,
            budget,
        ));
        for _ in 0..MAX_TIMER_DRAIN_POLLS {
            if let core::task::Poll::Ready(result) = futures::poll!(&mut drain) {
                return result;
            }
            tokio::task::yield_now().await;
        }
        Err(mkit_server::StoreError::unavailable(
            "test host timer drain exhausted its poll budget; a timer handler did not complete",
        ))
    }

    /// Fires due core timers registered by the production adapters. The
    /// delivery sink acknowledges outcomes locally, and all other handlers
    /// use this host's isolated memory stores.
    ///
    /// # Errors
    /// Returns a store scan error or an unavailable error from the bounded drain.
    pub async fn drain_core_timers(
        &self,
        partition: &Partition,
        budget: &TickBudget,
    ) -> Result<RunReport, mkit_server::StoreError> {
        self.drain_core_timers_with_outcomes(partition, budget, mkit_server::pipeline::NoOutcomes)
            .await
    }

    /// Fires the same core timer registry with the supplied outcome sink.
    /// This supports tests that need to observe signed hook outcome delivery.
    ///
    /// # Errors
    /// Returns a store scan error or an unavailable error from the bounded drain.
    pub async fn drain_core_timers_with_outcomes<O>(
        &self,
        partition: &Partition,
        budget: &TickBudget,
        outcomes: O,
    ) -> Result<RunReport, mkit_server::StoreError>
    where
        O: mkit_server::pipeline::OutcomeSink + 'static,
    {
        let target = self.kv.clone();
        let clock: Arc<dyn Clock> = self.clock.clone();
        let registry = TimerRegistry::new()
            .register(TicketExpiry {
                blobs: self.blobs.clone(),
            })
            .register(mkit_server::timers::lease_sweep::LeaseSweep::new(
                target.clone(),
            ))
            .register(mkit_server::relay::RelayHandler {
                target: target.clone(),
                hook: mkit_server::relay::NoHook,
                budget: mkit_server::relay::RelayBudget::default(),
            })
            .register(
                OutcomeDelivery::new(
                    outcomes,
                    self.base_url.clone(),
                    Arc::new(NoopMetrics),
                    Arc::new(mkit_server::ManualSleep::new()),
                )
                .with_clock(clock)
                .with_sink_timeout(core::time::Duration::from_secs(5)),
            )
            .register(mkit_server::timers::reservation_reconcile::ReservationReconcile)
            .register(
                mkit_server::timers::publication_recheck::PublicationRecheck {
                    target: target.clone(),
                },
            )
            .register(mkit_server::timers::quota_rollup::QuotaRollup {
                coordinator: target.clone(),
                metrics: NoopMetrics,
            });
        // Kind 16 (a fork job) exists only where indexed mode runs on leased
        // sharding; its handler's settings must equal the pipeline's.
        let registry = if self.profile.sharding_d34 && self.profile.has(Feature::IndexedMode) {
            registry.register(mkit_server::fork::ForkTimer {
                store: target,
                shards: Arc::new(mkit_server::pipeline::D34Shards),
                clock: self.clock.clone(),
                takedown_denial: self.profile.has(Feature::Takedown),
                extract_min_bytes: Some(
                    mkit_server::indexed::IndexedConfig::default().extract_min_bytes,
                ),
            })
        } else {
            registry
        };
        #[cfg(feature = "__test-faults")]
        let registry = registry.register(mkit_server::timers::test_kind::TestTimer);
        self.drain_timers(partition, &registry, budget).await
    }

    /// Stops and awaits the loopback listener.
    pub async fn shutdown(mut self) {
        if let Some(task) = self.listener_task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

fn mount_app<H: HookSet + 'static>(
    profile: &Profile,
    origin: &str,
    clock: Arc<ManualClock>,
    kv: Arc<MemoryKv>,
    blobs: MemoryBlobStore,
    preserved: MemoryBlobStore,
    pipeline: Arc<Pipeline<MemoryBlobStore, Arc<MemoryKv>, H>>,
) -> Result<axum::Router, String> {
    let app = axum::Router::new()
        .fallback_service(mkit_server::connect::service(pipeline.clone()))
        .layer(connect_cors());
    #[cfg(feature = "http-objects")]
    let app = app.layer(axum::middleware::from_fn(move |request, next| {
        let pipeline = pipeline.clone();
        async move { dispatch_http_objects(request, next, pipeline).await }
    }));
    #[cfg(feature = "__test-faults")]
    let app = if profile.has(Feature::TestFaults) {
        app.route(
            crate::wire::STATS_PATH,
            axum::routing::get({
                let kv = kv.clone();
                move || stats(kv.clone())
            }),
        )
    } else {
        app
    };

    let app = if profile.has(Feature::Takedown) {
        let config = crate::test_host_admin::config(origin)?;
        let routing = profile_config(profile, origin)?;
        let shards: Arc<dyn mkit_server::pipeline::ShardMap> = if profile.sharding_d34 {
            Arc::new(mkit_server::pipeline::D34Shards)
        } else {
            Arc::new(mkit_server::pipeline::SinglePartition)
        };
        let root = Partition::Namespace(NamespaceKey::deployment_default());
        let work = Arc::new(mkit_server::takedown::work::Work::new(
            kv.clone(),
            blobs,
            preserved,
            mkit_server::takedown::work::WorkConfig::new(
                root.clone(),
                shards,
                routing.addressing,
                3_600_000,
                clock.clone(),
            ),
        ));
        let engine =
            Arc::new(mkit_server::admin::Engine::new(kv, root, config).with_operations(work));
        app.route(
            mkit_server::admin::TAKEDOWN_PATH,
            axum::routing::post(crate::test_host_admin::dispatch),
        )
        .route(
            mkit_server::admin::GET_TAKEDOWN_PATH,
            axum::routing::post(crate::test_host_admin::dispatch),
        )
        .layer(axum::Extension(engine))
        .layer(axum::Extension(clock))
    } else {
        app
    };
    Ok(app)
}

fn profile_config(profile: &Profile, origin: &str) -> Result<PipelineConfig, String> {
    let auth = match &profile.auth {
        WireAuth::None => AuthMode::Open,
        WireAuth::Bearer { token } => AuthMode::Bearer {
            token: Redacted::new(token.clone()),
        },
        WireAuth::AuthV2 { repository, .. } => AuthMode::AuthV2(
            AuthV2Config::new(origin, repository.as_str()).map_err(|error| error.to_string())?,
        ),
    };

    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new(REPOSITORY).map_err(|error| error.to_string())?,
    };
    let limits = UploadLimits::new(profile.max_pack_bytes, 64);
    let addressing = if profile.has(Feature::MultiRepo) {
        Addressing::Multi(
            MultiAddressing::new()
                .with_namespace_policy(NamespacePolicy::Allowlist(multi_allowlist(profile))),
        )
    } else {
        Addressing::Single { repo }
    };
    let mut config = PipelineConfig::new(addressing, auth, limits);
    config.sharding = if profile.sharding_d34 {
        Sharding::D34
    } else {
        Sharding::Single
    };
    config.outbox_backlog_cap = profile.backlog_cap.map(|rows| {
        mkit_server::pipeline::OutboxBacklogCap::new(rows, rows.saturating_mul(16 * 1024))
    });
    if let Some(quota) = profile.quota {
        config.write_quota = Some(QuotaLimits::new(
            quota.window_ms,
            quota.max_ops,
            quota.max_bytes,
        ));
    }
    if profile.has(Feature::Tickets) {
        config.ticket_keys = Some(
            mkit_server::upload::token::TicketKeys::parse(TICKET_KEY)
                .map_err(|error| error.to_string())?,
        );
        config.ticket_caps.per_signer = profile.ticket_per_signer;
        config.ticket_caps.per_ref = profile.ticket_per_ref;
    }
    if profile.has(Feature::ShortTickets) {
        config.ticket_ttl_ms = 1_000;
    }
    configure_profile_features(profile, &mut config)?;
    Ok(config)
}

fn configure_profile_features(
    profile: &Profile,
    config: &mut PipelineConfig,
) -> Result<(), String> {
    if profile.has(Feature::Takedown) {
        if !profile.has(Feature::Admin)
            || !profile.has(Feature::HttpObjects)
            || !profile.has(Feature::SignedReads)
        {
            return Err("takedown test host requires admin, HTTP objects and signed reads".into());
        }
        config.takedown_denial = true;
        config.default_repo_visibility = mkit_server::pipeline::RepoVisibility::Private;
    }
    if profile.has(Feature::Grants) {
        let WireAuth::AuthV2 { audience, .. } = &profile.auth else {
            return Err("grant profiles require auth v2".into());
        };
        config.grants = Some(
            mkit_server::GrantConfig::new_allowing_loopback(
                audience,
                AcceptedSchemes::of(&OwnerScheme::ALL),
                vec![
                    RelyingParty::new(crate::wire::GRANT_RP_ID, [crate::wire::GRANT_RP_ORIGIN])
                        .map_err(|error| error.to_string())?,
                ],
            )
            .map_err(|error| error.to_string())?,
        );
    }
    if profile.has(Feature::SignedReads) {
        config.url_tokens = Some(
            mkit_server::url_token::UrlTokenConfig::with_ttl_ms(
                mkit_server::url_token::UrlTokenKeys::parse_key_file(&format!(
                    "active {}",
                    crate::wire::URL_TOKEN_SEED
                ))
                .map_err(|error| error.to_string())?,
                crate::wire::URL_TOKEN_TTL_MS,
            )
            .map_err(|error| error.to_string())?,
        );
    }
    if profile.has(Feature::IndexedMode) || profile.has(Feature::HttpObjects) {
        let mut indexed = mkit_server::indexed::IndexedConfig::default();
        indexed.max_pack_bytes = profile.max_pack_bytes;
        indexed.decode_budget = indexed.decode_budget.max(profile.max_pack_bytes);
        config.indexed = Some(indexed);
    }
    #[cfg(feature = "http-objects")]
    if profile.has(Feature::HttpObjects) {
        config.http_objects = Some(mkit_server::http_objects::HttpObjectsConfig::default());
    }
    Ok(())
}

fn connect_cors() -> tower_http::cors::CorsLayer {
    use http::{HeaderName, Method};
    use tower_http::cors::{Any, CorsLayer};

    let allow = mkit_server::auth_v2::CORS_ALLOW_HEADERS
        .split(',')
        .map(str::trim)
        .chain([
            "authorization",
            "payment-authorization",
            "payment-signature",
            "accept-payment",
        ])
        .filter_map(|name| HeaderName::from_bytes(name.as_bytes()).ok())
        .collect::<Vec<_>>();
    let expose = mkit_server::pipeline::ADMISSION_EXPOSE_HEADERS
        .iter()
        .filter_map(|name| HeaderName::from_bytes(name.as_bytes()).ok())
        .collect::<Vec<_>>();
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::POST, Method::GET, Method::OPTIONS])
        .allow_headers(allow)
        .expose_headers(expose)
}

#[cfg(feature = "http-objects")]
async fn dispatch_http_objects<H: HookSet + 'static>(
    request: axum::extract::Request,
    next: axum::middleware::Next,
    pipeline: Arc<Pipeline<MemoryBlobStore, Arc<MemoryKv>, H>>,
) -> axum::response::Response {
    use axum::body::Body;
    use http::{Response, StatusCode};
    use mkit_server::http_objects::mount::{HttpMountOptions, KEY_PATH, apply_cors, key_document};
    use mkit_server::http_objects::{
        HttpBody, HttpObjectRequest, HttpObjectResponse, RedactedQuery, is_http_object_path,
    };

    let path = request.uri().path().to_owned();
    let query = request.uri().query().map(str::to_owned);
    if !is_http_object_path(&path) && path != KEY_PATH {
        return next.run(request).await;
    }
    let method = request.method().as_str().to_owned();
    let origin = request
        .headers()
        .get("origin")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let head = method == "HEAD";
    let mut result = if path == KEY_PATH {
        pipeline
            .url_token_config()
            .map_or_else(HttpObjectResponse::not_found, |keys| {
                key_document(keys, &method)
            })
    } else if method == "OPTIONS" {
        HttpObjectResponse::new(204).with_header("Allow", "GET, HEAD, OPTIONS")
    } else if !matches!(method.as_str(), "GET" | "HEAD") {
        HttpObjectResponse::error(405).with_header("Allow", "GET, HEAD, OPTIONS")
    } else if mkit_server::http_objects::parse_with_mode(
        &path,
        query.as_deref(),
        mkit_server::http_objects::RepoPrefix::Required,
        pipeline.namespace_mode(),
    )
    .is_err()
    {
        HttpObjectResponse::error(400)
    } else {
        let (parts, _) = request.into_parts();
        let headers = |name: &str| {
            parts
                .headers
                .get_all(name)
                .iter()
                .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
                .collect()
        };
        let names: Vec<_> = parts.headers.keys().map(http::HeaderName::as_str).collect();
        let object_request = HttpObjectRequest {
            method: &method,
            raw_path: &path,
            raw_query: query.as_deref().map(RedactedQuery::new),
            headers: &headers,
            header_names: &names,
        };
        pipeline.serve_http_object(&object_request).await
    };
    apply_cors(&mut result, origin.as_deref(), &HttpMountOptions::default());
    let body = if head {
        Body::empty()
    } else {
        match result.body {
            HttpBody::Empty => Body::empty(),
            HttpBody::Bytes(bytes) => Body::from(bytes),
            HttpBody::Stream { stream, .. } => Body::from_stream(stream),
        }
    };
    let mut response = Response::new(body);
    *response.status_mut() =
        StatusCode::from_u16(result.status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    for (name, value) in result.headers {
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(&value),
        ) {
            response.headers_mut().append(name, value);
        }
    }
    response
}

impl Drop for TestHost {
    fn drop(&mut self) {
        if let Some(task) = self.listener_task.take() {
            task.abort();
        }
    }
}

fn multi_allowlist(profile: &Profile) -> BTreeSet<mkit_core::repo_identity::Namespace> {
    let WireAuth::AuthV2 {
        audience,
        repository,
        seed,
    } = &profile.auth
    else {
        return BTreeSet::new();
    };
    let mut allowed: BTreeSet<_> = crate::wire::CASES
        .iter()
        .filter(|case| {
            case.requires.contains(&Feature::MultiRepo)
                || case.name == "tickets.advance_ticket_bindings"
        })
        .flat_map(|case| {
            ["repository-a", "repository-b"].map(|label| {
                let label = format!("{}/{label}", case.name);
                let signer = crate::wire::sign::Signer::derive(
                    seed,
                    &profile.run_id,
                    &label,
                    audience,
                    repository,
                );
                mkit_core::repo_identity::Namespace::parse(&format!(
                    "ed25519-{}",
                    signer.public_key_hex()
                ))
                .expect("derived namespace is valid")
            })
        })
        .collect();
    // A case may address the owner repository declared by its profile.
    if let Some(namespace) = repository
        .split_once('/')
        .and_then(|(namespace, _)| mkit_core::repo_identity::Namespace::parse(namespace).ok())
    {
        allowed.insert(namespace);
    }
    if profile.has(Feature::Grants) {
        allowed.extend(crate::wire::grant_owner_namespaces());
    }
    allowed
}

async fn plant_membership(
    blobs: &MemoryBlobStore,
    meta: &MemoryKv,
    addressing: &Addressing,
    sharding: Sharding,
    profile: &Profile,
) -> Result<(), String> {
    use mkit_server::pipeline::{D34Shards, ShardMap, SinglePartition};

    let WireAuth::AuthV2 {
        audience,
        repository,
        seed,
    } = &profile.auth
    else {
        return Err("Multi repository profiles require auth v2".into());
    };
    let shards: &dyn ShardMap = match sharding {
        Sharding::D34 => &D34Shards,
        _ => &SinglePartition,
    };
    for case in [
        "repo.isolation_packs",
        "repo.membership_read_your_writes",
        "repo.malformed_membership_hint_no_op",
    ] {
        let signer = crate::wire::sign::Signer::derive(
            seed,
            &profile.run_id,
            &format!("{case}/repository-a"),
            audience,
            repository,
        );
        let identity = format!("ed25519-{}/packs", signer.public_key_hex());
        let repo = addressing
            .resolve(Some(&identity), false)
            .map_err(|error| error.to_string())?
            .repo;
        let bytes = bytes::Bytes::from(format!("conformance/{}/{case}", profile.run_id));
        let id = mkit_core::hash::hash(&bytes);
        let key = BlobKey::pack(id);
        let byte_len = u64::try_from(bytes.len()).map_err(|error| error.to_string())?;
        let mut sink = blobs
            .begin(key, byte_len)
            .await
            .map_err(|error| error.to_string())?;
        sink.write(bytes).await.map_err(|error| error.to_string())?;
        sink.commit().await.map_err(|error| error.to_string())?;
        let source = shards.ref_shard(&repo, "refs/heads/main");
        let index = shards.membership(&repo, &key);
        let ref_only = case == "repo.membership_read_your_writes";
        let mut partitions = vec![source];
        if !ref_only {
            partitions.push(index.clone());
        }
        for partition in partitions {
            let batch = if matches!(partition, Partition::RepoIndex { .. }) {
                Batch::new()
                    .put(keys::membership(&repo.name, &id), Value::default())
                    .put(keys::published_member(&repo.name, &id), Value::default())
            } else {
                Batch::new().put(keys::membership(&repo.name, &id), Value::default())
            };
            if meta
                .apply(&partition, batch)
                .await
                .map_err(|error| error.to_string())?
                != mkit_server::BatchOutcome::Committed
            {
                return Err("failed to plant Multi membership fixture".into());
            }
        }
    }
    Ok(())
}

#[cfg(feature = "__test-faults")]
async fn stats(kv: Arc<MemoryKv>) -> axum::Json<serde_json::Value> {
    let partition = Partition::Namespace(NamespaceKey::deployment_default());
    let stats = kv.stats(&partition).await.expect("memory store stats");
    axum::Json(serde_json::json!({ "bytes": stats.bytes, "keys": stats.keys }))
}
