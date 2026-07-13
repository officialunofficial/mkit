// SPDX-License-Identifier: MIT OR Apache-2.0
//
// wasm32-only worker glue: the auth interceptor, the RefStore Durable
// Object, the TransportService implementation, and the `#[event(fetch)]`
// adapter that bridges `worker::Request` <-> `http::Request` and drives the
// connectrpc Router. Adapted from apps/repo-worker/src/worker_impl.rs (see
// its module docs for the full request/response bridge rationale — this
// mirrors it almost verbatim; the only behavioral difference is the larger
// body cap, since packs are expected larger than repo-worker's small
// objects, and there is no `/watch` WebSocket route — this service has no
// streaming-fallback surface).

use std::sync::Arc;

use bytes::Bytes;
use connectrpc::{ConnectRpcService, Router};
use http_body_util::{BodyExt, Full};
use tower::ServiceExt;
use worker::send::SendFuture;
use worker::{Context, Env, Method, Request, Response, Result, event};

pub mod auth;
pub mod refstore;
pub mod service;
pub mod wire;

use auth::AuthInterceptor;
use service::{MAX_PACK_BYTES, TransportServer};

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

fn with_cors(resp: Response) -> Response {
    let mut resp = resp;
    let _ = resp.headers_mut().set("Access-Control-Allow-Origin", "*");
    resp
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    if req.method() == Method::Options {
        let headers = worker::Headers::new();
        let _ = headers.set("Access-Control-Allow-Origin", "*");
        let _ = headers.set("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS);
        let _ = headers.set("Access-Control-Allow-Methods", CORS_ALLOW_METHODS);
        let _ = headers.set("Access-Control-Max-Age", "86400");
        return Ok(Response::empty()?.with_status(204).with_headers(headers));
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
/// header copy loop).
async fn serve_connect(mut req: Request, env: Env) -> Result<Response> {
    if let Ok(Some(len)) = req.headers().get("content-length")
        && len.parse::<usize>().is_ok_and(|n| n > MAX_BODY_BYTES)
    {
        return Ok(with_cors(body_too_large()?));
    }
    let body = req.bytes().await.unwrap_or_default();
    if body.len() > MAX_BODY_BYTES {
        return Ok(with_cors(body_too_large()?));
    }

    let method = match req.method() {
        Method::Get => http::Method::GET,
        Method::Post => http::Method::POST,
        Method::Put => http::Method::PUT,
        Method::Delete => http::Method::DELETE,
        Method::Options => http::Method::OPTIONS,
        Method::Head => http::Method::HEAD,
        Method::Patch => http::Method::PATCH,
        _ => http::Method::POST,
    };
    let uri = req.url()?.to_string();

    let mut http_req = http::Request::builder()
        .method(method)
        .uri(uri)
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| worker::Error::RustError(format!("build http request: {e}")))?;

    {
        let headers = http_req.headers_mut();
        for (k, v) in req.headers().entries() {
            // Drop the Connect/gRPC client-deadline headers before they
            // reach `connectrpc`'s dispatcher: parsing either into a
            // `RequestContext::deadline` calls `std::time::Instant::now()`
            // (`connectrpc-0.8.1/src/response.rs`), which panics with
            // "time not implemented on this platform" on
            // wasm32-unknown-unknown — this target has no OS clock and
            // Rust's std `Instant`/`SystemTime` have no JS-Date fallback
            // (unlike `worker::Date`, which this server already uses for
            // its own envelope freshness check in `auth.rs`). Any real
            // ConnectRPC client that asserts a per-call timeout — e.g.
            // `mkit-transport-connect::ConnectTransport`'s
            // `with_default_timeout` (#701), not just a hand-crafted
            // request — hits this unconditionally and takes the whole
            // Worker down (`workerd` reports it as a hung request, not a
            // clean 5xx). Stripping the header here means this reference
            // server simply never enforces a client-asserted deadline
            // (`RequestContext::deadline()` sees `None`, matching the
            // documented no-`DeadlinePolicy` behavior) — an accepted
            // trade for a wasm32 target with no wall clock, not a change
            // to the transport's write-auth contract.
            if k.eq_ignore_ascii_case("connect-timeout-ms")
                || k.eq_ignore_ascii_case("grpc-timeout")
            {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                http::header::HeaderName::try_from(k.as_str()),
                http::header::HeaderValue::try_from(v.as_str()),
            ) {
                headers.insert(name, val);
            }
        }
    }

    // `AuthInterceptor` needs its own `Env` to address the RefStore DO for
    // the write-quota check (`enforce_write_quota`) — clone before `env` is
    // moved into `TransportServer::new`. Cheap (see `worker::Env`'s doc note
    // on apps/repo-worker's identical pattern).
    let auth_interceptor = AuthInterceptor::new(env.clone());
    let router: Router = Arc::new(TransportServer::new(env)).register(Router::new());
    let svc = ConnectRpcService::new(router).with_interceptor(auth_interceptor);

    let http_resp = SendFuture::new(async move {
        svc.oneshot(http_req)
            .await
            .expect("ConnectRpcService error is Infallible")
    })
    .await;

    let status = http_resp.status().as_u16();
    let resp_headers = http_resp.headers().clone();
    let collected = SendFuture::new(async move { http_resp.into_body().collect().await })
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();

    let mut out = Response::from_bytes(collected.to_vec())?.with_status(status);
    let out_headers = out.headers_mut();
    for (k, v) in resp_headers.iter() {
        if let Ok(val) = v.to_str() {
            let _ = out_headers.set(k.as_str(), val);
        }
    }
    Ok(with_cors(out))
}
