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
        copy_response_headers, dispatch_oneshot, http_request_from_worker, is_deadline_header,
        respond_buffered,
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
const CORS_ALLOW_HEADERS: &str = "x-envelope-version, x-audience, x-repository, x-content-commitment, x-expires-at, x-public-key, x-signature, x-digest, x-created-at, \
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

    // See `is_deadline_header`'s doc comment: parsing `connect-timeout-ms`/
    // `grpc-timeout` calls `Instant::now()`, which panics on wasm32.
    let http_req = http_request_from_worker(&req, body, |k| !is_deadline_header(k))?;

    // Share deployment context with auth, service, and health handlers.
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
