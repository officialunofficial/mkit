//! Default-off signed operator routes on the canonical Worker paths.
use crate::adapter::ConfigError;
use mkit_server::admin::Config;
/// Operator public keys are configured only through this Worker secret.
pub const KEYS_SECRET: &str = "ADMIN_KEYS";
/// User-provisioned restricted R2 bucket, separate from serving STORAGE.
pub const PRESERVATION_BINDING: &str = "PRESERVATION";
/// Required role key seed, available only as a Worker secret.
pub const RECEIPT_SECRET: &str = "RECEIPT_NOTICE_KEY";
/// Default-off launch preservation configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TakedownSettings {
    /// Explicit positive preservation lifetime.
    pub retention_ms: u64,
    /// Required receipt-and-notice public key publication.
    pub publication: mkit_server::takedown::PublicationConfig,
}

impl TakedownSettings {
    /// Construct explicit deployment settings; fields may be adjusted before use.
    #[must_use]
    pub fn new(retention_ms: u64, publication: mkit_server::takedown::PublicationConfig) -> Self {
        Self {
            retention_ms,
            publication,
        }
    }
}
pub(crate) fn takedown(
    var: &impl Fn(&str) -> Option<String>,
    admin: Option<&Config>,
    indexed: bool,
    _addressing: &mkit_server::Addressing,
    paid: bool,
    tickets: Option<&mkit_server::upload::token::TicketKeys>,
) -> Result<Option<TakedownSettings>, ConfigError> {
    let enabled = match var("TAKEDOWN_ENABLED").as_deref() {
        None | Some("false") => false,
        Some("true") => true,
        _ => return Err(ConfigError("TAKEDOWN_ENABLED must be true or false".into())),
    };
    if !enabled {
        if ["PRESERVATION_RETENTION_MS", RECEIPT_SECRET, "RECEIPT_KEYS"]
            .iter()
            .any(|name| var(name).is_some())
        {
            return Err(ConfigError(
                "preservation settings require TAKEDOWN_ENABLED=true".into(),
            ));
        }
        return Ok(None);
    }
    let admin = admin.ok_or_else(|| ConfigError("takedown requires ADMIN_KEYS".into()))?;
    if !indexed || !paid {
        return Err(ConfigError(
            "takedown requires indexed opt-in on Workers Paid".into(),
        ));
    }
    let retention_ms = var("PRESERVATION_RETENTION_MS")
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .ok_or_else(|| {
            ConfigError("explicit positive PRESERVATION_RETENTION_MS required".into())
        })?;
    let seed = zeroize::Zeroizing::new(
        var(RECEIPT_SECRET)
            .ok_or_else(|| ConfigError("RECEIPT_NOTICE_KEY secret required".into()))?,
    );
    let list = var("RECEIPT_KEYS")
        .ok_or_else(|| ConfigError("RECEIPT_KEYS publication required".into()))?;
    let publication = mkit_server::takedown::PublicationConfig::parse(seed.trim(), &list)
        .map_err(|e| ConfigError(e.to_string()))?;
    admin
        .check_separation(publication.public_keys())
        .map_err(|e| ConfigError(e.to_string()))?;
    if tickets.is_some_and(|keys| {
        publication
            .public_keys()
            .iter()
            .any(|key| keys.contains_ed25519_public(key))
    }) {
        return Err(ConfigError("receipt key repeats ticket key".into()));
    }
    Ok(Some(TakedownSettings::new(retention_ms, publication)))
}
/// Parse keys and reject reuse of ticket/MAC and URL-token keys.
/// # Errors
/// A malformed, empty or overlapping key list.
pub fn parse(
    var: &impl Fn(&str) -> Option<String>,
    audience: &str,
    tickets: Option<&mkit_server::upload::token::TicketKeys>,
) -> Result<Option<Config>, ConfigError> {
    let Some(json) = var(KEYS_SECRET) else {
        return Ok(None);
    };
    let config =
        Config::parse(audience, &json).map_err(|_| ConfigError("ADMIN_KEYS is invalid".into()))?;
    if !config.enabled() {
        return Ok(None);
    }
    if tickets.is_some_and(|keys| {
        config
            .public_keys()
            .iter()
            .any(|key| keys.contains_ed25519_public(key))
    }) {
        return Err(ConfigError(
            "ADMIN_KEYS must differ from TICKET_KEYS".into(),
        ));
    }
    Ok(Some(config))
}
#[cfg(target_arch = "wasm32")]
type WorkerWork = mkit_server::takedown::work::Work<
    crate::ns_client::DoNamespaceStore<crate::ns_client::StubTransport>,
    crate::r2::WorkerBlobStore,
    crate::r2::WorkerBlobStore,
>;
#[cfg(target_arch = "wasm32")]
#[allow(clippy::arc_with_non_send_sync)] // Worker shares core callbacks on a single thread.
pub(crate) fn purge_config<S: mkit_server::NamespaceStore + 'static>(
    cfg: &crate::adapter::WorkerConfig,
    metadata: S,
    request: Option<&mkit_server::indexed::budget::SliceBudget>,
) -> Result<Option<mkit_server::purge::PurgeConfig>, ConfigError> {
    use std::sync::{Arc, atomic::AtomicBool};
    let Some(purge) = cfg.pipeline_config()?.purge else {
        return Ok(None);
    };
    let local = cfg.custom_purge.as_ref().map_or_else(
        || Arc::new(crate::purge::local_cache()) as Arc<dyn mkit_server::purge::LocalInvalidation>,
        |custom| custom.local.clone(),
    );
    let local = request.map_or(local.clone(), |budget| {
        Arc::new(crate::purge::RequestLocal {
            local,
            budget: budget.clone(),
            reserved: AtomicBool::new(false),
        }) as Arc<dyn mkit_server::purge::LocalInvalidation>
    });
    Ok(Some(purge.with_local(local).with_audit(Arc::new(
        mkit_server::admin::SystemAudit::new(metadata, cfg.probe_partition()),
    ))))
}
#[cfg(target_arch = "wasm32")]
pub(crate) fn work(
    env: &worker::Env,
    cfg: &crate::adapter::WorkerConfig,
    budget: &mkit_server::purge::SliceBudget,
) -> Result<WorkerWork, ConfigError> {
    build_work(env, cfg, None, Some(budget))
}
#[cfg(target_arch = "wasm32")]
fn build_work(
    env: &worker::Env,
    cfg: &crate::adapter::WorkerConfig,
    request: Option<&mkit_server::indexed::budget::SliceBudget>,
    alarm: Option<&mkit_server::purge::SliceBudget>,
) -> Result<WorkerWork, ConfigError> {
    let settings = cfg
        .takedown
        .as_ref()
        .ok_or_else(|| ConfigError("preservation disabled".into()))?;
    let indexed = cfg
        .indexed
        .as_ref()
        .ok_or_else(|| ConfigError("preservation requires indexed storage".into()))?;
    let blob = |binding, keyspace| {
        let mut bucket = crate::r2::EnvBucket::new(env.clone(), binding);
        if let Some(budget) = request {
            bucket = bucket.with_budget(budget.clone());
        }
        if let Some(budget) = alarm {
            bucket = bucket.with_alarm_budget(budget.clone());
        }
        crate::r2::R2BlobStore::new(bucket, keyspace)
    };
    let mut metadata = crate::ns_client::DoNamespaceStore::new(
        crate::ns_client::StubTransport::new(env.clone(), cfg.placement.clone()),
        cfg.probe_partition(),
    );
    if let Some(budget) = request {
        metadata = metadata.with_budget(budget.clone());
    }
    if let Some(budget) = alarm {
        metadata = metadata.with_alarm_budget(budget.clone());
    }
    let mut config = mkit_server::takedown::work::WorkConfig::new(
        cfg.probe_partition(),
        std::sync::Arc::new(mkit_server::pipeline::D34Shards),
        cfg.addressing.clone(),
        settings.retention_ms,
        std::sync::Arc::new(crate::clock::WorkerClock),
    );
    config.namespace_mode = cfg.namespace_mode;
    config.purge = purge_config(cfg, metadata.clone(), request)?;
    config.discovery_margin_ms = indexed.relay_lag_bound_ms;
    Ok(mkit_server::takedown::work::Work::new(
        metadata,
        blob(cfg.blob_binding, crate::r2::PACKS_KEYSPACE),
        blob(PRESERVATION_BINDING, "preserved"),
        config,
    ))
}
#[cfg(any(target_arch = "wasm32", test))]
fn supported_path(path: &str, cfg: &crate::adapter::WorkerConfig) -> bool {
    cfg.admin.as_ref().is_some_and(Config::enabled)
        && cfg.takedown.is_some()
        && cfg.takedown_denial
        && cfg.indexed.is_some()
        && purge_enabled(cfg)
        && path
            .strip_prefix(mkit_server::admin::PREFIX)
            .is_some_and(|operation| {
                matches!(
                    operation,
                    "Takedown"
                        | "GetTakedown"
                        | "ListTakedowns"
                        | "ReadPreserved"
                        | "SetLegalHold"
                        | "PurgeCache"
                        | "ReadAuditLog"
                )
            })
}
#[cfg(any(target_arch = "wasm32", test))]
fn purge_enabled(cfg: &crate::adapter::WorkerConfig) -> bool {
    cfg.custom_purge.is_some()
        || cfg
            .hooks
            .as_ref()
            .is_some_and(|hooks| hooks.roles.cache_purge && hooks.http.is_some())
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn serve(
    mut req: worker::Request,
    env: worker::Env,
    cfg: &crate::adapter::WorkerConfig,
    budget: &mkit_server::indexed::budget::SliceBudget,
) -> worker::Result<worker::Response> {
    use futures::StreamExt;
    use mkit_server::admin::{BodyCapture, Engine, Reply, Response};
    let Some(config) = &cfg.admin else {
        return no_store(worker::Response::error("admin disabled", 404));
    };
    let enabled = cfg.takedown.is_some() && cfg.takedown_denial;
    if !supported_path(&req.path(), cfg) {
        return no_store(worker::Response::error("admin operation unavailable", 404));
    }
    if req.method() != worker::Method::Post {
        return no_store(worker::Response::error("POST required", 405));
    }
    let headers = req.headers().entries().collect();
    let url = req.url()?;
    let path = format!(
        "{}{}",
        url.path(),
        url.query().map_or(String::new(), |q| format!("?{q}"))
    );
    let now = mkit_server::Clock::now_ms(&crate::clock::WorkerClock);
    let reply = if let Err(reply) = mkit_server::admin::precheck(&headers) {
        Reply::Unary(reply)
    } else if let Err(reply) = mkit_server::admin::precheck_envelope(config, &path, &headers, now) {
        Reply::Unary(reply)
    } else {
        let mut capture = BodyCapture::default();
        let mut stream = req.stream()?;
        match mkit_server::with_timeout(
            &crate::sleep::WorkerSleep,
            mkit_server::hooks::DEFAULT_TIMEOUT,
            async {
                while let Some(chunk) = stream.next().await {
                    capture.push(&chunk?);
                }
                Ok::<_, worker::Error>(capture)
            },
        )
        .await
        {
            Ok(Ok(capture)) => {
                let store = crate::ns_client::DoNamespaceStore::new(
                    crate::ns_client::StubTransport::new(env.clone(), cfg.placement.clone()),
                    cfg.probe_partition(),
                )
                .with_budget(budget.clone());
                let mut engine = Engine::new(
                    store.clone(),
                    cfg.probe_partition(),
                    config.clone().with_namespace_mode(cfg.namespace_mode),
                )
                .with_purge(purge_enabled(cfg));
                if enabled {
                    // Workers run on one thread; the shared core operations interface uses Arc.
                    #[allow(clippy::arc_with_non_send_sync)]
                    let operations = std::sync::Arc::new(
                        build_work(&env, cfg, Some(budget), None)
                            .map_err(|error| worker::Error::RustError(error.to_string()))?,
                    );
                    engine = engine.with_operations(operations);
                }
                #[allow(clippy::arc_with_non_send_sync)]
                let engine = std::sync::Arc::new(engine);
                let verified_at = mkit_server::Clock::now_ms(&crate::clock::WorkerClock);
                engine
                    .handle_streamed(&path, &headers, &capture, None, verified_at)
                    .await
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => Reply::Unary(Response::error(&mkit_server::ServerError::unavailable(
                "admin request body read timed out",
            ))),
        }
    };
    let response = match reply {
        Reply::Unary(Response {
            status,
            content_type,
            body,
        }) => {
            let mut response = worker::Response::from_bytes(body)?.with_status(status);
            response.headers_mut().set("content-type", &content_type)?;
            response
        }
        Reply::Stream(stream) => {
            let stream = stream.map(|result| {
                result
                    .map(|bytes| bytes.to_vec())
                    .map_err(|error| worker::Error::RustError(error.to_string()))
            });
            let mut response = worker::Response::from_stream(stream)?;
            response
                .headers_mut()
                .set("content-type", "application/connect+json")?;
            response
        }
    };
    no_store(Ok(response))
}
#[cfg(target_arch = "wasm32")]
pub(crate) fn no_store(
    response: worker::Result<worker::Response>,
) -> worker::Result<worker::Response> {
    let mut response = response?;
    response.headers_mut().set("cache-control", "no-store")?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn operator_config(public: [u8; 32]) -> Config {
        Config::parse("https://server.example", &serde_json::json!({"version":1,"keys":[{"keyId":"operator","alg":"ed25519","publicKey":mkit_core::hash::to_hex(&public),"roles":["all"]}]}).to_string()).unwrap()
    }
    struct PreservationFixture {
        vars: std::collections::BTreeMap<&'static str, String>,
        admin: Config,
        addressing: mkit_server::Addressing,
        operator: [u8; 32],
        receipt: [u8; 32],
    }
    impl PreservationFixture {
        fn new() -> Self {
            let receipt =
                mkit_server::hooks::HookSigner::new("receipt", zeroize::Zeroizing::new([17; 32]))
                    .unwrap()
                    .public_key();
            let operator =
                mkit_server::hooks::HookSigner::new("operator", zeroize::Zeroizing::new([18; 32]))
                    .unwrap()
                    .public_key();
            let list = serde_json::json!({"version":1,"keys":[{"keyId":mkit_core::hash::to_hex(&mkit_core::hash::hash(&receipt)),"alg":"ed25519","publicKey":mkit_core::hash::to_hex(&receipt)}]}).to_string();
            Self {
                vars: std::collections::BTreeMap::from([
                    ("TAKEDOWN_ENABLED", "true".to_owned()),
                    ("PRESERVATION_RETENTION_MS", "12345".to_owned()),
                    (RECEIPT_SECRET, mkit_core::hash::to_hex(&[17; 32])),
                    ("RECEIPT_KEYS", list),
                ]),
                admin: operator_config(operator),
                addressing: mkit_server::Addressing::Single {
                    repo: mkit_server::RepoId {
                        namespace: mkit_server::NamespaceKey::deployment_default(),
                        name: mkit_server::RepoName::new("repo").unwrap(),
                    },
                },
                operator,
                receipt,
            }
        }
        fn settings(
            &self,
            indexed: bool,
            paid: bool,
        ) -> Result<Option<TakedownSettings>, ConfigError> {
            takedown(
                &|key| self.vars.get(key).cloned(),
                Some(&self.admin),
                indexed,
                &self.addressing,
                paid,
                None,
            )
        }
    }
    #[test]
    fn preservation_requires_explicit_retention_and_publication() {
        let mut fixture = PreservationFixture::new();
        assert_eq!(
            fixture.settings(true, true).unwrap().unwrap().retention_ms,
            12345
        );
        for required in ["PRESERVATION_RETENTION_MS", RECEIPT_SECRET, "RECEIPT_KEYS"] {
            let removed = fixture.vars.remove(required).unwrap();
            assert!(fixture.settings(true, true).is_err(), "{required}");
            fixture.vars.insert(required, removed);
        }
        fixture.vars.insert("TAKEDOWN_ENABLED", "invalid".into());
        assert!(fixture.settings(true, true).is_err());
        fixture.vars.insert("TAKEDOWN_ENABLED", "true".into());
        fixture.vars.insert("PRESERVATION_RETENTION_MS", "0".into());
        assert!(fixture.settings(true, true).is_err());
        assert!(
            takedown(&|_| None, None, false, &fixture.addressing, false, None)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn preservation_requires_indexed_paid_and_accepts_all_namespace_policies() {
        let mut fixture = PreservationFixture::new();
        assert!(fixture.settings(false, true).is_err());
        assert!(fixture.settings(true, false).is_err());
        fixture.addressing = mkit_server::Addressing::Multi(
            mkit_server::MultiAddressing::new().with_namespace_policy(
                mkit_server::policy::NamespacePolicy::Any {
                    unsafe_without_admission: true,
                },
            ),
        );
        assert_eq!(
            fixture.settings(true, true).unwrap().unwrap().retention_ms,
            12345
        );
        fixture.addressing = mkit_server::Addressing::Multi(
            mkit_server::MultiAddressing::new().with_namespace_policy(
                mkit_server::policy::NamespacePolicy::Allowlist(
                    [mkit_core::repo_identity::Namespace::parse(&format!(
                        "ed25519-{}",
                        mkit_core::hash::to_hex(&fixture.operator)
                    ))
                    .unwrap()]
                    .into(),
                ),
            ),
        );
        assert!(fixture.settings(true, true).is_ok());
    }
    #[test]
    fn preservation_role_keys_stay_separate_after_rotation() {
        let mut fixture = PreservationFixture::new();
        fixture.admin = operator_config(fixture.receipt);
        assert!(fixture.settings(true, true).is_err());
        fixture.admin = operator_config(fixture.operator);
        let mut retired: serde_json::Value =
            serde_json::from_str(&fixture.vars["RECEIPT_KEYS"]).unwrap();
        retired["keys"].as_array_mut().unwrap().push(serde_json::json!({"keyId":mkit_core::hash::to_hex(&mkit_core::hash::hash(&fixture.operator)),"alg":"ed25519","publicKey":mkit_core::hash::to_hex(&fixture.operator),"notAfterMs":"1"}));
        fixture.vars.insert("RECEIPT_KEYS", retired.to_string());
        assert!(
            fixture.settings(true, true).is_err(),
            "retired receipt keys cannot become admin keys"
        );
    }
    #[test]
    fn lean_catalog_requires_admin_and_takedown_and_never_exposes_hold_ops() {
        let mut cfg = crate::adapter::WorkerConfig::from_vars(|name| match name {
            "AUTH_AUDIENCE" => Some("https://server.example".into()),
            "AUTH_REPOSITORY" => Some("repo".into()),
            "ADMIN_KEYS" => Some(
                serde_json::json!({"version":1,"keys":[{
                    "keyId":"operator", "alg":"ed25519", "publicKey":"11".repeat(32),
                    "roles":["audit","moderation"]
                }]})
                .to_string(),
            ),
            _ => None,
        })
        .unwrap();
        let fixture = PreservationFixture::new();
        for op in [
            "Takedown",
            "GetTakedown",
            "ListTakedowns",
            "ReadPreserved",
            "SetLegalHold",
            "PurgeCache",
            "ReadAuditLog",
        ] {
            let path = format!("{}{op}", mkit_server::admin::PREFIX);
            assert!(!supported_path(&path, &cfg), "unconfigured {op}");
            cfg.launch = Some(crate::launch::LaunchConfig::new(true));
            assert!(!supported_path(&path, &cfg), "selection alone {op}");
            cfg.takedown = fixture.settings(true, true).unwrap();
            cfg.takedown_denial = true;
            cfg.indexed = Some(mkit_server::indexed::IndexedConfig::default());
            // Built directly: HOOK_URL parsing is refused without the
            // `signed-http-hooks` feature, but the catalog gate only needs a
            // cache-purge role over the signed HTTP channel.
            cfg.hooks = Some(crate::hooks::config::HookVars {
                roles: crate::hooks::config::HookRoles {
                    authorize: false,
                    admit: false,
                    outcome: false,
                    cache_purge: true,
                    inspect: false,
                },
                timeout: crate::hooks::config::DEFAULT_TIMEOUT,
                authorizer_role: mkit_server::policy::AuthorizerRole::Check,
                http: Some(crate::hooks::config::HttpVars::new(
                    crate::hooks::fetch::Endpoint::new("https://hooks.example").unwrap(),
                    std::time::Duration::from_mins(1),
                )),
                inspect_batch_max_objects: 1,
            });
            assert!(supported_path(&path, &cfg), "configured {op}");
            cfg.takedown_denial = false;
            assert!(!supported_path(&path, &cfg), "no global denial {op}");
            cfg.takedown_denial = true;
            let admin = cfg.admin.take();
            assert!(!supported_path(&path, &cfg), "no admin {op}");
            cfg.admin = admin;
            cfg.launch = None;
            cfg.takedown = None;
        }
        assert!(!supported_path(mkit_server::admin::AUDIT_PATH, &cfg));
        assert!(!supported_path(mkit_server::admin::PURGE_PATH, &cfg));
        cfg.launch = Some(crate::launch::LaunchConfig::new(true));
        for op in [
            "Reinstate",
            "GetHold",
            "ListHolds",
            "ReleaseHold",
            "RejectHold",
        ] {
            assert!(!supported_path(
                &format!("{}{op}", mkit_server::admin::PREFIX),
                &cfg
            ));
        }
    }

    #[test]
    fn purge_activation_requires_the_signed_purge_role() {
        let mut cfg = crate::adapter::WorkerConfig::from_vars(|name| match name {
            "AUTH_AUDIENCE" => Some("https://server.example".into()),
            "AUTH_REPOSITORY" => Some("repo".into()),
            _ => None,
        })
        .unwrap();
        assert!(!purge_enabled(&cfg));
        let mut hooks = crate::hooks::config::HookVars {
            roles: crate::hooks::config::HookRoles {
                authorize: false,
                admit: false,
                outcome: true,
                cache_purge: false,
                inspect: false,
            },
            timeout: crate::hooks::config::DEFAULT_TIMEOUT,
            authorizer_role: mkit_server::policy::AuthorizerRole::Check,
            http: None,
            inspect_batch_max_objects: 10_000,
        };
        cfg.hooks = Some(hooks.clone());
        assert!(!purge_enabled(&cfg));
        hooks.roles.cache_purge = true;
        cfg.hooks = Some(hooks.clone());
        assert!(
            !purge_enabled(&cfg),
            "service binding alone cannot sign global purge"
        );
        hooks.http = Some(crate::hooks::config::HttpVars::new(
            crate::hooks::fetch::Endpoint::new("https://hooks.example").unwrap(),
            std::time::Duration::from_mins(1),
        ));
        cfg.hooks = Some(hooks);
        assert!(purge_enabled(&cfg));
    }

    #[test]
    fn keys_default_off_and_overlap_is_refused() {
        assert!(
            parse(&|_| None, "https://server.example", None)
                .unwrap()
                .is_none()
        );
        assert!(
            parse(
                &|_| Some(r#"{"version":1,"keys":[]}"#.into()),
                "https://server.example",
                None
            )
            .unwrap()
            .is_none()
        );
        let signer =
            mkit_server::hooks::HookSigner::new("fixture", zeroize::Zeroizing::new([19; 32]))
                .unwrap();
        let public = mkit_core::hash::to_hex(&signer.public_key());
        let json=serde_json::json!({"version":1,"keys":[{"keyId":"operator","alg":"ed25519","publicKey":public,"roles":["audit"]}]}).to_string();
        let tickets =
            mkit_server::upload::token::TicketKeys::new(vec![("ticket".into(), [19; 32])]).unwrap();
        assert!(
            parse(
                &|_| Some(json.clone()),
                "https://server.example",
                Some(&tickets)
            )
            .is_err()
        );
        assert!(
            parse(&|_| Some(json.clone()), "https://server.example", None)
                .unwrap()
                .unwrap()
                .enabled()
        );
    }

    #[test]
    fn configured_storage_cannot_enable_takedown_intake() {
        let fixture = PreservationFixture::new();
        let mut cfg = crate::adapter::WorkerConfig::from_vars(|name| match name {
            "AUTH_AUDIENCE" => Some("https://server.example".into()),
            "AUTH_REPOSITORY" => Some("repo".into()),
            _ => None,
        })
        .unwrap();
        cfg.takedown = fixture.settings(true, true).unwrap();
        assert!(cfg.takedown.is_some());
        assert!(!supported_path(mkit_server::admin::TAKEDOWN_PATH, &cfg));
        cfg.takedown_denial = true;
        assert!(
            cfg.validate().is_err(),
            "denial requires complete indexed configuration"
        );
    }
}
