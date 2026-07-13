// SPDX-License-Identifier: MIT OR Apache-2.0
//
// wasm32-only worker glue: the auth interceptor, the RefStore Durable
// Object, the TransportService implementation, and the `#[event(fetch)]`
// adapter that bridges `worker::Request` <-> `http::Request` and drives the
// connectrpc Router. Adapted from apps/repo-worker/src/worker_impl.rs (see
// its module docs for the full request/response bridge rationale).
//
// The CORS handling, body-size cap, and worker::Request<->http::Request
// fetch-adapter skeleton are shared with apps/repo-worker via
// `mkit-worker-common` (mkit#797) — this module wires those generic pieces
// together with vcs-worker's OWN business logic (the auth interceptor, the
// RefStore DO, the TransportService/HealthServer registration, and the
// buffered response bridge — this service has no `/watch` WebSocket route
// or server-streaming RPC, unlike repo-worker's WatchRefs, so it collects
// the response body whole rather than streaming it).

use std::sync::Arc;

use connectrpc::{ConnectRpcService, Router};
use mkit_worker_common::{
    adapter::{
        copy_response_headers, dispatch_oneshot, http_request_from_worker, respond_buffered,
    },
    body_cap::{CappedBody, read_capped_body},
    cors::{cors_preflight_response, is_options_preflight, with_cors},
};
use worker::{Context, Env, Request, Response, Result, event};

pub mod auth;
pub mod health;
pub mod refstore;
pub mod service;
pub mod wire;

use auth::AuthInterceptor;
use health::HealthServer;
use service::{MAX_PACK_BYTES, TransportServer};

use crate::proto::grpc::health::v1::HealthExt;
use crate::proto::mkit::transport::v1::TransportServiceExt;

/// The RefStore Durable Object, re-exported so worker-build/wrangler find it.
pub use refstore::RefStore;

/// Reject any request body larger than this. This reference server buffers
/// whole HTTP request bodies in memory (see service.rs module docs), so the
/// cap here IS the effective pack-size ceiling for `UploadPack` — kept equal
/// to `MAX_PACK_BYTES` so the two limits can't silently drift apart.
const MAX_BODY_BYTES: usize = MAX_PACK_BYTES;

/// Headers we expose for cross-origin clients (mirrors apps/repo-worker's
/// CORS posture — this is a reference/demo deployment, not a locked-down
/// production origin).
const CORS_ALLOW_HEADERS: &str = "x-public-key, x-signature, x-digest, x-created-at, \
     idempotency-key, content-type, connect-protocol-version";
const CORS_ALLOW_METHODS: &str = "POST, GET, OPTIONS";

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    if is_options_preflight(&req) {
        return cors_preflight_response(CORS_ALLOW_HEADERS, CORS_ALLOW_METHODS);
    }

    serve_connect(req, env).await
}

fn body_too_large() -> Result<Response> {
    let payload = format!(
        "{{\"code\":\"resource_exhausted\",\"message\":\"request body exceeds {MAX_BODY_BYTES} bytes\"}}"
    );
    let mut resp = Response::error(payload, 400)?;
    let _ = resp.headers_mut().set("Content-Type", "application/json");
    Ok(resp)
}

/// Drive a ConnectRPC request through the Router-backed tower::Service. See
/// apps/repo-worker's identical function for the full request/response
/// bridge rationale (the `Full<Bytes>` body, the `SendFuture` wrapping, the
/// header copy loop) — now shared via `mkit_worker_common::adapter`.
async fn serve_connect(mut req: Request, env: Env) -> Result<Response> {
    let body = match read_capped_body(&mut req, MAX_BODY_BYTES).await? {
        CappedBody::Ok(body) => body,
        CappedBody::TooLarge => return Ok(with_cors(body_too_large()?)),
    };

    // Drop the Connect/gRPC client-deadline headers before they reach
    // `connectrpc`'s dispatcher: parsing either into a
    // `RequestContext::deadline` calls `std::time::Instant::now()`
    // (`connectrpc-0.8.1/src/response.rs`), which panics with "time not
    // implemented on this platform" on wasm32-unknown-unknown — this target
    // has no OS clock and Rust's std `Instant`/`SystemTime` have no JS-Date
    // fallback (unlike `worker::Date`, which this server already uses for
    // its own envelope freshness check in `auth.rs`). Any real ConnectRPC
    // client that asserts a per-call timeout — e.g.
    // `mkit-transport-connect::ConnectTransport`'s `with_default_timeout`
    // (#701), not just a hand-crafted request — hits this unconditionally
    // and takes the whole Worker down (`workerd` reports it as a hung
    // request, not a clean 5xx). Stripping the header here means this
    // reference server simply never enforces a client-asserted deadline
    // (`RequestContext::deadline()` sees `None`, matching the documented
    // no-`DeadlinePolicy` behavior) — an accepted trade for a wasm32 target
    // with no wall clock, not a change to the transport's write-auth
    // contract.
    let http_req = http_request_from_worker(&req, body, |k| {
        !(k.eq_ignore_ascii_case("connect-timeout-ms") || k.eq_ignore_ascii_case("grpc-timeout"))
    })?;

    // `AuthInterceptor` needs its own `Env` to address the RefStore DO for
    // the write-quota check (`enforce_write_quota`), and `HealthServer` its
    // own for the liveness probe — clone before `env` is moved into
    // `TransportServer::new`. Cheap (see `worker::Env`'s doc note on
    // apps/repo-worker's identical pattern).
    let auth_interceptor = AuthInterceptor::new(env.clone());
    let router: Router = Arc::new(TransportServer::new(env.clone())).register(Router::new());
    let router: Router = Arc::new(HealthServer::new(env)).register(router);
    let svc = ConnectRpcService::new(router).with_interceptor(auth_interceptor);

    let http_resp = dispatch_oneshot(svc, http_req).await;

    let status = http_resp.status().as_u16();
    let resp_headers = http_resp.headers().clone();

    let mut out = respond_buffered(status, http_resp.into_body()).await?;
    copy_response_headers(&resp_headers, &mut out);
    Ok(with_cors(out))
}
