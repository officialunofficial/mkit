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
}
/// Validated operator configuration, independent of client authentication.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Separate operator address.
    pub listen: SocketAddr,
    /// Exact audience and role-bearing public keys.
    pub config: Config,
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
        if args.admin_listen.is_some() {
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
    Ok(Some(Settings {
        listen: args
            .admin_listen
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 19191))),
        config,
    }))
}
/// Stable deployment-wide audit/replay partition, inaccessible as a client namespace.
#[must_use]
pub fn partition(sharding: Sharding) -> Partition {
    match sharding {
        Sharding::Single => Partition::Namespace(NamespaceKey::deployment_default()),
        _ => Partition::Coordinator(NamespaceKey::deployment_default()),
    }
}
/// Build the audit export procedure on the separate operator router.
pub fn router<S: NamespaceStore + Clone + 'static>(
    store: S,
    settings: &Settings,
    pipeline: &PipelineConfig,
) -> Router {
    let engine = Arc::new(Engine::new(
        store,
        partition(pipeline.sharding),
        settings.config.clone(),
    ));
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
    Router::new().route(
        mkit_server::admin::AUDIT_PATH,
        axum::routing::post(dispatch),
    )
}
fn response(reply: mkit_server::admin::Response) -> Response {
    Response::builder()
        .status(reply.status)
        .header("content-type", reply.content_type)
        .header("cache-control", "no-store")
        .body(Body::from(reply.body))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_server::MemoryKv;
    use tower::ServiceExt;

    #[tokio::test]
    async fn manual_purge_has_no_native_route() {
        let mut public = [0x66; 32];
        public[0] = 0x58;
        let config = Config::parse("https://server.example", &serde_json::json!({"version":1,"keys":[{"keyId":"operator","alg":"ed25519","publicKey":mkit_core::hash::to_hex(&public),"roles":["all"]}]}).to_string()).unwrap();
        let settings = Settings {
            listen: SocketAddr::from(([127, 0, 0, 1], 19191)),
            config,
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
        let response = router(
            std::sync::Arc::new(MemoryKv::default()),
            &settings,
            &pipeline,
        )
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(mkit_server::admin::PURGE_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), 404);
    }
}
