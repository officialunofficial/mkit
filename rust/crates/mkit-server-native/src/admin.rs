//! Separate, default-off operator listener (SPEC-SERVER §16).
use crate::config::{ConfigError, MetaChoice, read_secret_file};
use axum::{Router, body::Body, extract::Request, response::Response};
use clap::Args;
use futures_util::StreamExt;
use mkit_server::pipeline::{AuthMode, PipelineConfig, Sharding};
use mkit_server::{
    NamespaceKey, NamespaceStore, Partition,
    admin::{BodyCapture, Config, Engine},
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};

/// Native operator configuration flags.
#[derive(Debug, Clone, Default, Args)]
pub struct AdminArgs {
    /// SPEC-SERVER §16.3 public operator key list; absent disables the service.
    #[arg(long, value_name = "PATH")]
    pub admin_keys_file: Option<PathBuf>,
    /// Separate operator listener (default 127.0.0.1:19191).
    #[arg(long, value_name = "ADDR")]
    pub admin_listen: Option<SocketAddr>,
    /// Restricted filesystem preservation root; enables launch takedown when indexed.
    #[arg(long, value_name = "PATH")]
    pub preservation_root: Option<PathBuf>,
    /// Explicit preservation retention; no default.
    #[arg(long, value_name = "MS")]
    pub preservation_retention_ms: Option<u64>,
    /// Owner-only receipt-and-notice Ed25519 seed file (64 hex).
    #[arg(long, value_name = "PATH")]
    pub receipt_key_file: Option<PathBuf>,
    /// Published receipt-and-notice public key list.
    #[arg(long, value_name = "PATH")]
    pub receipt_keys_file: Option<PathBuf>,
}
/// Validated operator configuration, independent of client authentication.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Separate operator address.
    pub listen: SocketAddr,
    /// Exact audience and role-bearing public keys.
    pub config: Config,
    /// Default-off verified preservation configuration.
    pub takedown: Option<TakedownSettings>,
}
/// Restricted preservation storage and required receipt key publication.
#[derive(Debug, Clone)]
pub struct TakedownSettings {
    /// User-provisioned filesystem root, disjoint from serving storage.
    pub root: PathBuf,
    /// Explicit positive preservation lifetime.
    pub retention_ms: u64,
    /// Required receipt-and-notice public key publication.
    pub publication: mkit_server::takedown::PublicationConfig,
}
fn invalid(message: impl std::fmt::Display) -> ConfigError {
    ConfigError::new(
        crate::exit::CONFIG_ERROR,
        format!("admin configuration: {message}"),
    )
}
/// Resolve the opt-in key file; durable metadata and a canonical server origin are required.
/// # Errors
/// Rejects partial configuration, unsafe key files, or unsupported metadata/auth modes.
pub fn resolve(
    args: &AdminArgs,
    pipeline: &mut PipelineConfig,
    meta: &MetaChoice,
) -> Result<Option<Settings>, ConfigError> {
    let Some(path) = &args.admin_keys_file else {
        if args.admin_listen.is_some()
            || args.preservation_root.is_some()
            || args.preservation_retention_ms.is_some()
            || args.receipt_key_file.is_some()
            || args.receipt_keys_file.is_some()
        {
            return Err(invalid("--admin-listen requires --admin-keys-file"));
        }
        return Ok(None);
    };
    if !matches!(pipeline.sharding, Sharding::Single | Sharding::D34) {
        return Err(invalid("unsupported admin sharding"));
    }
    if !matches!(meta, MetaChoice::Sqlite { .. }) {
        return Err(invalid("admin requires --meta sqlite:<PATH>"));
    }
    let AuthMode::AuthV2(auth) = &pipeline.auth else {
        return Err(invalid("admin requires --auth auth-v2 and --audience"));
    };
    let json = read_secret_file(path, "--admin-keys-file", "admin public key list")?;
    let config = Config::parse(auth.audience(), &json).map_err(invalid)?;
    if !config.enabled() {
        if args.preservation_root.is_some()
            || args.preservation_retention_ms.is_some()
            || args.receipt_key_file.is_some()
            || args.receipt_keys_file.is_some()
        {
            return Err(invalid("takedown requires nonempty admin keys"));
        }
        return Ok(None);
    }
    if pipeline.ticket_keys.as_ref().is_some_and(|tickets| {
        config
            .public_keys()
            .iter()
            .any(|key| tickets.contains_ed25519_public(key))
    }) {
        return Err(invalid("admin key repeats a ticket/MAC key"));
    }
    #[cfg(feature = "http-objects")]
    if let Some(tokens) = &pipeline.url_tokens {
        config
            .check_separation(&tokens.keys().public_keys().collect::<Vec<_>>())
            .map_err(invalid)?;
    }
    if let Some(fence) = &pipeline.authority_fence {
        config
            .check_separation(&fence.public_keys().collect::<Vec<_>>())
            .map_err(invalid)?;
    }
    pipeline.admin_keys = config.public_keys();
    let takedown = preservation_settings(args, pipeline, &config, auth.audience())?;
    pipeline.receipt_publication = takedown.as_ref().map(|s| s.publication.clone());
    if let Some(settings) = &takedown {
        pipeline
            .admin_keys
            .extend_from_slice(settings.publication.public_keys());
    }
    Ok(Some(Settings {
        listen: args
            .admin_listen
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 19191))),
        config,
        takedown,
    }))
}
/// Validate the independently provisioned preservation role and required publication.
fn preservation_settings(
    args: &AdminArgs,
    pipeline: &PipelineConfig,
    config: &Config,
    audience: &str,
) -> Result<Option<TakedownSettings>, ConfigError> {
    let settings = match &args.preservation_root {
        None => {
            if args.preservation_retention_ms.is_some()
                || args.receipt_key_file.is_some()
                || args.receipt_keys_file.is_some()
            {
                return Err(invalid("preservation settings require --preservation-root"));
            }
            None
        }
        Some(root) => {
            if audience.len() > 2048 {
                return Err(invalid("takedown origin exceeds 2048 bytes"));
            }
            if pipeline.indexed.is_none() {
                return Err(invalid("takedown requires indexed opt-in"));
            }
            let retention_ms = args
                .preservation_retention_ms
                .filter(|n| *n > 0)
                .ok_or_else(|| {
                    invalid("takedown requires explicit positive --preservation-retention-ms")
                })?;
            let seed = read_secret_file(
                args.receipt_key_file
                    .as_deref()
                    .ok_or_else(|| invalid("takedown requires --receipt-key-file"))?,
                "--receipt-key-file",
                "receipt-and-notice key",
            )?;
            let keys = std::fs::read_to_string(
                args.receipt_keys_file
                    .as_deref()
                    .ok_or_else(|| invalid("takedown requires --receipt-keys-file"))?,
            )
            .map_err(|_| invalid("cannot read receipt public key list"))?;
            let publication = mkit_server::takedown::PublicationConfig::parse(seed.trim(), &keys)
                .map_err(invalid)?;
            config
                .check_separation(publication.public_keys())
                .map_err(invalid)?;
            if pipeline.ticket_keys.as_ref().is_some_and(|keys| {
                publication
                    .public_keys()
                    .iter()
                    .any(|key| keys.contains_ed25519_public(key))
            }) {
                return Err(invalid("receipt key repeats ticket key"));
            }
            #[cfg(feature = "http-objects")]
            if pipeline.url_tokens.as_ref().is_some_and(|tokens| {
                tokens
                    .keys()
                    .public_keys()
                    .any(|key| publication.public_keys().contains(&key))
            }) {
                return Err(invalid("receipt key repeats URL-token key"));
            }
            Some(TakedownSettings {
                root: root.clone(),
                retention_ms,
                publication,
            })
        }
    };
    Ok(settings)
}
/// Stable deployment-wide audit/replay partition, inaccessible as a client namespace.
#[must_use]
pub fn partition(sharding: Sharding) -> Partition {
    match sharding {
        Sharding::Single => Partition::Namespace(NamespaceKey::deployment_default()),
        _ => Partition::Coordinator(NamespaceKey::deployment_default()),
    }
}
pub(crate) fn shards(sharding: Sharding) -> Arc<dyn mkit_server::pipeline::ShardMap> {
    match sharding {
        Sharding::Single => Arc::new(mkit_server::pipeline::SinglePartition),
        _ => Arc::new(mkit_server::pipeline::D34Shards),
    }
}
pub(crate) fn work<B: mkit_server::BlobStore, N: NamespaceStore + Clone>(
    serving: B,
    metadata: N,
    settings: &TakedownSettings,
    pipeline: &PipelineConfig,
) -> Result<
    mkit_server::takedown::work::Work<N, B, crate::Blocking<mkit_server::fs::FsBlobStore>>,
    ConfigError,
> {
    let indexed = pipeline
        .indexed
        .ok_or_else(|| invalid("preservation requires indexed limits"))?;
    Ok(mkit_server::takedown::work::Work {
        metadata,
        serving,
        preserved: crate::Blocking::new(mkit_server::fs::FsBlobStore::new(&settings.root)),
        root: partition(pipeline.sharding),
        shards: shards(pipeline.sharding),
        addressing: pipeline.addressing.clone(),
        retention_ms: settings.retention_ms,
        discovery_margin_ms: indexed.relay_lag_bound_ms,
        profile: mkit_server::takedown::acquisition::Profile::inline(
            indexed.decode_budget,
            indexed.max_delta_chain_depth,
        )
        .map_err(invalid)?,
        clock: Arc::new(mkit_server::SystemClock),
    })
}
pub(crate) fn register<B, N, S>(
    registry: mkit_server::timers::TimerRegistry<'static, S>,
    serving: B,
    metadata: N,
    settings: Option<&TakedownSettings>,
    pipeline: &PipelineConfig,
    enabled: bool,
) -> Result<mkit_server::timers::TimerRegistry<'static, S>, ConfigError>
where
    B: mkit_server::BlobStore + 'static,
    N: NamespaceStore + Clone + 'static,
    S: NamespaceStore,
{
    if enabled && let Some(settings) = settings {
        Ok(registry
            .register(work(serving, metadata.clone(), settings, pipeline)?)
            .register(mkit_server::takedown::late::LateTimer {
                acceptance: mkit_server::takedown::late_owner::LateOwner::new(
                    metadata,
                    partition(pipeline.sharding),
                ),
                max_subrequests: 700,
            }))
    } else {
        Ok(registry)
    }
}
/// Build the audit export procedure on the separate operator router.
pub fn router<S: NamespaceStore + Clone + 'static>(
    store: S,
    settings: &Settings,
    pipeline: &PipelineConfig,
) -> Router {
    let enabled = mkit_server::takedown::ACTIVATED && settings.takedown.is_some();
    let mut engine = Engine::new(
        store.clone(),
        partition(pipeline.sharding),
        settings.config.clone(),
    )
    .with_purge(pipeline.purge.is_some());
    if enabled {
        engine = engine.with_operations(Arc::new(mkit_server::takedown::Service::new(
            store,
            partition(pipeline.sharding),
            shards(pipeline.sharding),
        )));
    }
    let engine = Arc::new(engine);
    let dispatch = move |req: Request| {
        let engine = Arc::clone(&engine);
        async move {
            let headers: Vec<_> = req
                .headers()
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or_default().to_owned()))
                .collect();
            if let Err(reply) = mkit_server::admin::precheck(&headers) {
                return response(reply);
            }
            let path = req
                .uri()
                .path_and_query()
                .map_or("", |p| p.as_str())
                .to_owned();
            let mut capture = BodyCapture::default();
            let mut stream = req.into_body().into_data_stream();
            while let Some(chunk) = stream.next().await {
                let Ok(chunk) = chunk else {
                    return Response::builder()
                        .status(400)
                        .body(Body::empty())
                        .unwrap_or_default();
                };
                capture.push(&chunk);
            }
            let now = mkit_server::Clock::now_ms(&mkit_server::SystemClock);
            response(engine.handle(&path, &headers, &capture, now).await)
        }
    };
    let router = Router::new()
        .route(
            mkit_server::admin::AUDIT_PATH,
            axum::routing::post(dispatch.clone()),
        )
        .route(
            mkit_server::admin::PURGE_PATH,
            axum::routing::post(dispatch.clone()),
        );
    if enabled {
        router.route(
            mkit_server::admin::TAKEDOWN_PATH,
            axum::routing::post(dispatch),
        )
    } else {
        router
    }
}
fn response(reply: mkit_server::admin::Response) -> Response {
    Response::builder()
        .status(reply.status)
        .header("content-type", reply.content_type)
        .header("cache-control", "no-store")
        .body(Body::from(reply.body))
        .unwrap_or_default()
}

pub(crate) fn publish(router: Router, settings: Option<&Settings>) -> Router {
    let Some(settings) = settings.and_then(|a| a.takedown.as_ref()) else {
        return router;
    };
    let keys = settings.publication.key_list.clone();
    router.route(
        "/.well-known/mkit-receipt-keys.json",
        axum::routing::get(move || {
            let keys = keys.clone();
            async move {
                Response::builder()
                    .header("content-type", "application/json")
                    .header("cache-control", "public, max-age=300")
                    .header("access-control-allow-origin", "*")
                    .body(Body::from(keys))
                    .unwrap_or_default()
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_server::MemoryKv;
    use tower::ServiceExt;

    #[tokio::test]
    async fn manual_purge_is_routed_and_takedown_stays_unexposed() {
        let mut public = [0x66; 32];
        public[0] = 0x58;
        let config = Config::parse("https://server.example", &serde_json::json!({"version":1,"keys":[{"keyId":"operator","alg":"ed25519","publicKey":mkit_core::hash::to_hex(&public),"roles":["all"]}]}).to_string()).unwrap();
        let settings = Settings {
            listen: SocketAddr::from(([127, 0, 0, 1], 19191)),
            config,
            takedown: None,
        };
        let pipeline = PipelineConfig::new(
            mkit_server::Addressing::Single {
                repo: mkit_server::RepoId {
                    namespace: NamespaceKey::deployment_default(),
                    name: mkit_server::RepoName::new("repo").unwrap(),
                },
            },
            AuthMode::TransportIdentity,
            mkit_server::upload::UploadLimits {
                max_total_bytes: 1024,
                max_chunks: 1,
            },
        );
        let routes = router(
            std::sync::Arc::new(MemoryKv::default()),
            &settings,
            &pipeline,
        );
        let takedown = routes
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(mkit_server::admin::TAKEDOWN_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(takedown.status(), 404);
        let response = routes
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(mkit_server::admin::PURGE_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(response.status(), 404);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // Exercise signed acceptance, replay and disabled configuration together.
    async fn signed_native_purge_requires_configured_delivery_and_audits_disabled_result() {
        use ed25519_dalek::{Signer as _, SigningKey};
        let signer = SigningKey::from_bytes(&[71; 32]);
        let config = Config::parse("https://server.example", &serde_json::json!({"version":1,"keys":[{"keyId":"operator","alg":"ed25519","publicKey":mkit_core::hash::to_hex(signer.verifying_key().as_bytes()),"roles":["moderation"]}]}).to_string()).unwrap();
        let settings = Settings {
            listen: SocketAddr::from(([127, 0, 0, 1], 19191)),
            config,
            takedown: None,
        };
        for enabled in [false, true] {
            let mut pipeline = PipelineConfig::new(
                mkit_server::Addressing::Single {
                    repo: mkit_server::RepoId {
                        namespace: NamespaceKey::deployment_default(),
                        name: mkit_server::RepoName::new("repo").unwrap(),
                    },
                },
                AuthMode::TransportIdentity,
                mkit_server::upload::UploadLimits {
                    max_total_bytes: 1024,
                    max_chunks: 1,
                },
            );
            if enabled {
                pipeline.purge = Some(mkit_server::purge::PurgeConfig::new(
                    "https://server.example".into(),
                    true,
                    true,
                ));
            }
            let store = Arc::new(MemoryKv::default());
            let bytes = serde_json::json!({"repository":"root/repo","operationId":"native-operation","reason":"manual"}).to_string().into_bytes();
            let mut capture = BodyCapture::default();
            capture.push(&bytes);
            let now = mkit_server::Clock::now_ms(&mkit_server::SystemClock);
            let expiry = now + 60_000;
            let nonce = mkit_core::hash::to_hex(&[91; 32]);
            let digest = capture.digest();
            let canonical = format!(
                "mkit-admin:v1\noperator\nhttps://server.example\n{}\n{digest}\n{now}\n{expiry}\n{nonce}",
                mkit_server::admin::PURGE_PATH
            );
            let signature = mkit_core::hash::to_hex_bytes(
                &signer
                    .sign(&mkit_core::hash::hash(canonical.as_bytes()))
                    .to_bytes(),
            );
            let request = Request::builder()
                .method("POST")
                .uri(mkit_server::admin::PURGE_PATH)
                .header("x-mkit-admin-version", "1")
                .header("x-mkit-admin-key-id", "operator")
                .header("x-mkit-admin-audience", "https://server.example")
                .header("x-mkit-admin-created-at", now.to_string())
                .header("x-mkit-admin-expires-at", expiry.to_string())
                .header("x-mkit-admin-nonce", nonce)
                .header("x-mkit-admin-digest", digest)
                .header("x-mkit-admin-signature", signature)
                .body(Body::from(bytes))
                .unwrap();
            let response = router(store.clone(), &settings, &pipeline)
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(response.status(), if enabled { 200 } else { 400 });
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            if enabled {
                assert!(crate::admin::partition(pipeline.sharding) == partition(Sharding::Single));
                assert!(
                    mkit_server::purge::read_request(
                        &store,
                        &partition(pipeline.sharding),
                        result["purgeId"].as_str().unwrap()
                    )
                    .await
                    .unwrap()
                    .is_some()
                );
            } else {
                assert_eq!(result["code"], "failed_precondition");
                assert!(
                    store
                        .get(
                            &partition(pipeline.sharding),
                            &mkit_server::store::keys::outcome_backlog()
                        )
                        .await
                        .unwrap()
                        .is_none()
                );
            }
            let head = store
                .get(
                    &partition(pipeline.sharding),
                    &mkit_server::Key::new(b"ah\0".to_vec()),
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(head.as_bytes()).unwrap()["seq"],
                1
            );
        }
    }
    #[tokio::test]
    async fn receipt_publication_is_public_and_cacheable() {
        let public = [42; 32];
        let config = Config::parse("https://server.example", &serde_json::json!({"version":1,"keys":[{"keyId":"operator","alg":"ed25519","publicKey":mkit_core::hash::to_hex(&public),"roles":["all"]}]}).to_string()).unwrap();
        let settings = Settings {
            listen: SocketAddr::from(([127, 0, 0, 1], 19191)),
            config,
            takedown: Some(TakedownSettings {
                root: PathBuf::from("unused"),
                retention_ms: 10,
                publication: {
                    let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32])
                        .verifying_key()
                        .to_bytes();
                    let list=serde_json::json!({"version":1,"keys":[{"keyId":mkit_core::hash::to_hex(&mkit_core::hash::hash(&key)),"alg":"ed25519","publicKey":mkit_core::hash::to_hex(&key)}]}).to_string();
                    mkit_server::takedown::PublicationConfig::parse(
                        &mkit_core::hash::to_hex(&[17; 32]),
                        &list,
                    )
                    .unwrap()
                },
            }),
        };
        let response = publish(Router::new(), Some(&settings))
            .oneshot(
                Request::builder()
                    .uri("/.well-known/mkit-receipt-keys.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["cache-control"], "public, max-age=300");
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        assert_eq!(response.headers()["content-type"], "application/json");
        let absent = publish(Router::new(), None)
            .oneshot(
                Request::builder()
                    .uri("/.well-known/mkit-receipt-keys.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(absent.status(), 404);
    }

    #[test]
    fn preservation_configuration_requires_complete_distinct_keys_and_allows_any() {
        use ed25519_dalek::SigningKey;
        let temp = tempfile::tempdir().unwrap();
        let seed = [17; 32];
        let public = *SigningKey::from_bytes(&seed).verifying_key().as_bytes();
        let operator = *SigningKey::from_bytes(&[18; 32]).verifying_key().as_bytes();
        let admin_path = temp.path().join("admin.json");
        let seed_path = temp.path().join("receipt.key");
        let list_path = temp.path().join("receipt.json");
        std::fs::write(&admin_path, serde_json::json!({"version":1,"keys":[{"keyId":"op","alg":"ed25519","publicKey":mkit_core::hash::to_hex(&operator),"roles":["all"]}]}).to_string()).unwrap();
        std::fs::write(&seed_path, mkit_core::hash::to_hex(&seed)).unwrap();
        std::fs::write(&list_path,serde_json::json!({"version":1,"keys":[{"keyId":mkit_core::hash::to_hex(&mkit_core::hash::hash(&public)),"alg":"ed25519","publicKey":mkit_core::hash::to_hex(&public)}]}).to_string()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for file in [&admin_path, &seed_path] {
                std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        let mut args = AdminArgs {
            admin_keys_file: Some(admin_path),
            preservation_root: Some(temp.path().join("preserved")),
            preservation_retention_ms: Some(1000),
            receipt_key_file: Some(seed_path),
            receipt_keys_file: Some(list_path),
            ..Default::default()
        };
        let mut pipeline = PipelineConfig::new(
            mkit_server::Addressing::Single {
                repo: mkit_server::RepoId {
                    namespace: NamespaceKey::deployment_default(),
                    name: mkit_server::RepoName::new("repo").unwrap(),
                },
            },
            AuthMode::AuthV2(
                mkit_server::auth_v2::AuthV2Config::new("https://server.example", "repo").unwrap(),
            ),
            mkit_server::upload::UploadLimits {
                max_total_bytes: 1024,
                max_chunks: 1,
            },
        );
        pipeline.indexed = Some(mkit_server::indexed::IndexedConfig::default());
        let meta = MetaChoice::Sqlite {
            path: temp.path().join("metadata.sqlite"),
            capacity: mkit_server::sql::Capacity::new(64 * 1024 * 1024),
        };
        let settings = resolve(&args, &mut pipeline, &meta).unwrap().unwrap();
        assert_eq!(settings.takedown.unwrap().retention_ms, 1000);
        assert!(pipeline.admin_keys.contains(&public));
        args.preservation_retention_ms = None;
        assert!(resolve(&args, &mut pipeline, &meta).is_err());
        args.preservation_retention_ms = Some(0);
        assert!(resolve(&args, &mut pipeline, &meta).is_err());
        args.preservation_retention_ms = Some(1000);
        pipeline.addressing = mkit_server::Addressing::Multi(
            mkit_server::MultiAddressing::new().with_namespace_policy(
                mkit_server::policy::NamespacePolicy::Any {
                    unsafe_without_admission: true,
                },
            ),
        );
        let open = resolve(&args, &mut pipeline, &meta).unwrap().unwrap();
        assert_eq!(open.takedown.unwrap().retention_ms, 1000);
        args = AdminArgs::default();
        assert!(resolve(&args, &mut pipeline, &meta).unwrap().is_none());
    }

    #[tokio::test]
    async fn real_preservation_factory_is_separate_and_registration_stays_gated() {
        use mkit_server::{BlobKey, BlobStore, PackSink};
        let serving = tempfile::tempdir().unwrap();
        let preserved = tempfile::tempdir().unwrap();
        let seed = [17; 32];
        let public = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let list=serde_json::json!({"version":1,"keys":[{"keyId":mkit_core::hash::to_hex(&mkit_core::hash::hash(&public)),"alg":"ed25519","publicKey":mkit_core::hash::to_hex(&public)}]}).to_string();
        let settings = TakedownSettings {
            root: preserved.path().to_owned(),
            retention_ms: 12345,
            publication: mkit_server::takedown::PublicationConfig::parse(
                &mkit_core::hash::to_hex(&seed),
                &list,
            )
            .unwrap(),
        };
        let mut pipeline = PipelineConfig::new(
            mkit_server::Addressing::Single {
                repo: mkit_server::RepoId {
                    namespace: NamespaceKey::deployment_default(),
                    name: mkit_server::RepoName::new("repo").unwrap(),
                },
            },
            AuthMode::TransportIdentity,
            mkit_server::upload::UploadLimits {
                max_total_bytes: 1024,
                max_chunks: 1,
            },
        );
        pipeline.indexed = Some(mkit_server::indexed::IndexedConfig::default());
        let source = crate::Blocking::new(mkit_server::fs::FsBlobStore::new(serving.path()));
        let metadata = Arc::new(MemoryKv::default());
        let workflow = work(source.clone(), metadata.clone(), &settings, &pipeline).unwrap();
        let bytes = bytes::Bytes::from_static(b"restricted preserved bytes");
        let key = BlobKey::pack(mkit_core::hash::hash(&bytes));
        let mut sink = workflow
            .preserved
            .begin(key, bytes.len() as u64)
            .await
            .unwrap();
        sink.write(bytes).await.unwrap();
        sink.commit().await.unwrap();
        assert!(workflow.preserved.head(&key).await.unwrap().is_some());
        assert!(workflow.serving.head(&key).await.unwrap().is_none());
        assert_eq!(workflow.retention_ms, 12345);
        let off = register::<_, _, MemoryKv>(
            mkit_server::timers::TimerRegistry::new(),
            source.clone(),
            metadata.clone(),
            Some(&settings),
            &pipeline,
            mkit_server::takedown::ACTIVATED,
        )
        .unwrap();
        assert_eq!(format!("{off:?}"), "TimerRegistry { kinds: [] }");
        let on = register::<_, _, MemoryKv>(
            mkit_server::timers::TimerRegistry::new(),
            source,
            metadata,
            Some(&settings),
            &pipeline,
            true,
        )
        .unwrap();
        assert!(format!("{on:?}").contains("TimerKind(13)"));
        assert!(format!("{on:?}").contains("TimerKind(15)"));
    }
}
