// SPDX-License-Identifier: MIT OR Apache-2.0
use std::sync::Arc;

use mkit_server::hooks::{HookClient, RemoteAdmission, RemoteOutcomes};
use mkit_server::pipeline::{Hooks, NoPreReceive, NoReceipts, OpenAuthorizer};
use mkit_server_worker::adapter::{self, ConfigError, WorkerConfig};
use mkit_server_worker::clock::WorkerClock;
use mkit_server_worker::hooks::binding::BindingChannel;
use mkit_server_worker::sleep::WorkerSleep;
use worker::{Context, Env, Request, RequestInit, Response, Result, event};

type EmbeddedHooks = Hooks<
    OpenAuthorizer,
    RemoteAdmission<BindingChannel>,
    NoPreReceive,
    NoReceipts,
    RemoteOutcomes<BindingChannel>,
>;

fn config(env: &Env) -> core::result::Result<WorkerConfig, ConfigError> {
    let mut cfg = WorkerConfig::from_env(env)?;
    // The host may place admin elsewhere; this example has no admin keys.
    cfg.admin_on_public_path = false;
    Ok(cfg)
}

fn client(
    env: &Env,
    cfg: &WorkerConfig,
) -> core::result::Result<Arc<HookClient<BindingChannel>>, ConfigError> {
    let channel = BindingChannel::from_env(env)?;
    // This is AUTH_AUDIENCE, never the constructed request's internal URL.
    HookClient::new(
        channel,
        &cfg.audience,
        None,
        Arc::new(WorkerClock),
        Arc::new(WorkerSleep),
    )
    .map(Arc::new)
    .map_err(|_| ConfigError("embedded hook configuration is invalid".into()))
}

fn hooks(env: &Env, cfg: &WorkerConfig) -> core::result::Result<EmbeddedHooks, ConfigError> {
    let client = client(env, cfg)?;
    Ok(Hooks {
        authorizer: OpenAuthorizer,
        admission: RemoteAdmission::new(Arc::clone(&client)),
        pre_receive: NoPreReceive,
        receipts: NoReceipts,
        outcomes: RemoteOutcomes::new(client),
    })
}

fn sink(
    env: &Env,
    cfg: &WorkerConfig,
) -> core::result::Result<RemoteOutcomes<BindingChannel>, ConfigError> {
    client(env, cfg).map(RemoteOutcomes::new)
}

mkit_server_worker::durable_objects!(config, sink);

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let path = req.path();
    let Some(procedure) = path.strip_prefix("/_uno/mkit/") else {
        return Response::error("host route not found", 404);
    };
    if procedure.is_empty() {
        return Response::error("missing embedded procedure", 404);
    }
    let cfg = config(&env).map_err(|err| worker::Error::RustError(err.to_string()))?;
    let mut init = RequestInit::new();
    init.with_method(req.method())
        .with_headers(req.headers().clone())
        // Transfer the ReadableStream; do not call bytes(), text() or clone().
        .with_body(req.inner().body().map(Into::into));
    let request = Request::new_with_init(&format!("https://embedded.invalid/{procedure}"), &init)?;
    adapter::serve_with(request, env, &cfg, hooks).await
}
