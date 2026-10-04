//! Local workerd regression through each supported dispatch entry point.
#![allow(clippy::arc_with_non_send_sync, clippy::result_large_err)]
use mkit_server::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig};
use mkit_server::{
    Addressing, ManualClock, MemoryBlobStore, MemoryKv, NamespaceKey, NoopMetrics, RepoId, RepoName,
};
use mkit_server_worker::adapter::{self, ConfigError, WorkerConfig};
use mkit_worker_common::adapter::{
    copy_response_headers, dispatch_oneshot, http_request_from_worker, respond_streamed,
};
use std::sync::Arc;
use std::time::Duration;
use worker::{Context, Env, Request, RequestInit, Response, Result, event};

fn config(env: &Env) -> core::result::Result<WorkerConfig, ConfigError> {
    WorkerConfig::from_env(env)
}
fn hooks(_: &Env, _: &WorkerConfig) -> core::result::Result<Hooks, ConfigError> {
    Ok(Hooks::new())
}
fn sink(
    _: &Env,
    _: &WorkerConfig,
) -> core::result::Result<mkit_server::pipeline::NoOutcomes, ConfigError> {
    Ok(mkit_server::pipeline::NoOutcomes)
}
mkit_server_worker::durable_objects!(config, sink);

#[event(fetch)]
async fn fetch(mut req: Request, env: Env, ctx: Context) -> Result<Response> {
    let path = req.path();
    let mut parts = path.splitn(3, '/');
    parts.next();
    let entry = parts.next().unwrap_or_default();
    let procedure = parts.next().unwrap_or_default();
    let mut init = RequestInit::new();
    init.with_method(req.method())
        .with_headers(req.headers().clone())
        .with_body(req.inner().body().map(Into::into));
    let request = Request::new_with_init(&format!("https://deadline.invalid/{procedure}"), &init)?;
    if entry == "direct" || entry == "default" || entry == "router" {
        let http_req =
            http_request_from_worker(&request, bytes::Bytes::from(req.bytes().await?), |_| true)?;
        let clock = Arc::new(ManualClock::new(0));
        let cfg = PipelineConfig::new(
            Addressing::Single {
                repo: RepoId {
                    namespace: NamespaceKey::deployment_default(),
                    name: RepoName::new("default").unwrap(),
                },
            },
            AuthMode::Bearer {
                token: mkit_server::Redacted::new("fixture-token"),
            },
            mkit_server::upload::UploadLimits::new(1 << 20, 64),
        );
        let pipe = Pipeline::new(
            MemoryBlobStore::default(),
            MemoryKv::with_clock(clock.clone()),
            Hooks::new(),
            cfg,
            clock,
            Arc::new(NoopMetrics),
        )
        .unwrap();
        let pipe = Arc::new(pipe);
        let mut svc = if entry == "router" {
            mkit_server::connect::ConnectService::new(mkit_server::connect::router(pipe))
        } else {
            mkit_server::connect::service(pipe)
        };
        if entry == "default" {
            svc = svc.with_deadline_policy(
                connectrpc::DeadlinePolicy::new()
                    .with_min(Duration::from_millis(1))
                    .with_max(Duration::from_secs(1))
                    .with_default_timeout(Duration::from_millis(1))
                    .with_enforce_on_streams(true)
                    .with_inter_message_timeout(Duration::from_millis(1)),
            );
            assert!(svc.deadline_policy().default_timeout().is_none());
            assert!(svc.deadline_policy().inter_message_timeout().is_none());
        }
        let response = dispatch_oneshot(svc, http_req).await;
        let headers = response.headers().clone();
        let mut out = respond_streamed(response.status().as_u16(), response.into_body())?;
        copy_response_headers(&headers, &mut out);
        return Ok(out);
    }
    let cfg = config(&env).map_err(|e| worker::Error::RustError(e.to_string()))?;
    match entry {
        "serve" => adapter::serve(request, env, &cfg).await,
        "serve_with" => adapter::serve_with(request, env, &cfg, hooks).await,
        "admin" => adapter::serve_admin_with(request, env, &cfg).await,
        "fetch" => adapter::fetch(request, env).await,
        "fetch_with_context" => adapter::fetch_with_context(request, env, ctx).await,
        "fetch_with" => adapter::fetch_with(request, env, Default::default(), hooks).await,
        _ => Response::error("unknown fixture entry", 404),
    }
}
