// SPDX-License-Identifier: MIT OR Apache-2.0
//
// wasm32-only worker glue: the auth interceptor, the RefStore Durable Object,
// the RepoService implementation, and the `#[event(fetch)]` adapter that
// bridges `worker::Request` <-> `http::Request` and drives the connectrpc
// Router. Gated out of host builds (the macros emit `#[wasm_bindgen]`).

use std::sync::Arc;

use bytes::Bytes;
use connectrpc::{ConnectRpcService, Router};
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full};
use tower::ServiceExt;
use worker::send::SendFuture;
use worker::{Context, Env, Method, Request, Response, Result, event};

pub mod auth;
pub mod commit_index;
pub mod health;
pub mod refstore;
pub mod service;
pub mod wire;

use auth::AuthInterceptor;
use health::HealthServer;
use service::RepoServer;

// Surface the proto extension trait + DO type to this module.
use crate::proto::grpc::health::v1::HealthExt;
use crate::proto::mkit::repo::v1::RepoServiceExt;
// Reuse the canonical room validator (same one the unary path enforces via
// `service::check_room`) so the streaming /watch route can't address a DO with
// an invalid room name.
use crate::refs::is_valid_room;

/// The RefStore Durable Object, re-exported so worker-build/wrangler find it.
pub use refstore::RefStore;

/// Reject any request body larger than this (the PutObject `bytes` payload is
/// the only large input; everything else is tiny JSON). Buffering more than
/// this is refused with `invalid_argument`.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024; // 8 MiB

/// Headers we expose for cross-origin browser clients. `x-admin-token` is
/// listed for completeness (an operator console could call PurgeRoom
/// cross-origin) even though the shipped web demo never sends it.
const CORS_ALLOW_HEADERS: &str = "x-public-key, x-signature, x-digest, x-created-at, \
     idempotency-key, x-admin-token, content-type, connect-protocol-version";
const CORS_ALLOW_METHODS: &str = "POST, GET, OPTIONS";

/// Append the permissive `Access-Control-Allow-Origin: *` header to a response.
/// Browser clients hit this worker cross-origin (the demo web app on a
/// different origin), so every response — success or error — must carry it.
fn with_cors(resp: Response) -> Response {
    let mut resp = resp;
    let _ = resp.headers_mut().set("Access-Control-Allow-Origin", "*");
    resp
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // CORS preflight: answer OPTIONS with a 204 + the allow-* headers BEFORE
    // any routing, so browsers can complete the preflight for the signed-write
    // headers (X-Public-Key, …) regardless of the eventual route.
    if req.method() == Method::Options {
        let headers = worker::Headers::new();
        let _ = headers.set("Access-Control-Allow-Origin", "*");
        let _ = headers.set("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS);
        let _ = headers.set("Access-Control-Allow-Methods", CORS_ALLOW_METHODS);
        let _ = headers.set("Access-Control-Max-Age", "86400");
        return Ok(Response::empty()?.with_status(204).with_headers(headers));
    }

    // WatchRefs streaming fallback: `GET /watch/<room>` opens a raw WebSocket
    // straight to the room's RefStore DO (see README "WatchRefs"). Everything
    // else is a ConnectRPC call routed through the Router.
    let path = req.path();
    if let Some(room) = path.strip_prefix("/watch/")
        && !room.is_empty()
    {
        // Validate the room with the SAME allow-list the unary path enforces
        // (see `service::check_room` → `is_valid_room`) BEFORE addressing a
        // DO via `id_from_name`: the room is used as the DO instance name, so
        // an unvalidated value must not reach `watch_fallback`.
        if !is_valid_room(room) {
            return Ok(with_cors(Response::error("invalid room", 400)?));
        }
        // Forward the optional `?pubkey=<hex>` so the DO can attribute live
        // presence to a key (absent → a signed-out viewer).
        let pubkey = req.url().ok().and_then(|u| {
            u.query_pairs()
                .find(|(k, _)| k == "pubkey")
                .map(|(_, v)| v.into_owned())
        });
        // Return the WebSocket upgrade Response (status 101) DIRECTLY — do
        // NOT run `with_cors` on it: CORS headers are meaningless on a 101
        // handshake, and mutating the upgrade response can drop the
        // `webSocket` it carries. CORS stays on the unary/JSON path only.
        return watch_fallback(env, room, pubkey).await;
    }

    serve_connect(req, env).await
}

/// The Connect `invalid_argument` 400 returned when a request body exceeds the cap.
fn body_too_large() -> Result<Response> {
    let payload = format!(
        "{{\"code\":\"invalid_argument\",\"message\":\"request body exceeds {MAX_BODY_BYTES} bytes\"}}"
    );
    let mut resp = Response::error(payload, 400)?;
    let _ = resp.headers_mut().set("Content-Type", "application/json");
    Ok(resp)
}

/// Drive a ConnectRPC request through the Router-backed tower::Service.
async fn serve_connect(mut req: Request, env: Env) -> Result<Response> {
    // Read raw body + method/uri/headers up front. The envelope auth
    // interceptor needs the raw body, and `Full<Bytes>` is the simplest
    // `http_body::Body<Data = Bytes>` (error = Infallible) that satisfies the
    // ConnectRpcService bound.
    // H2: cap the request body. Reject by Content-Length BEFORE buffering, so an
    // oversized POST is refused in O(1) instead of `req.bytes()` materializing the
    // whole payload in the isolate first (the only large input is PutObject
    // `bytes`). The post-buffer check below is the backstop for chunked/
    // unknown-length requests where Content-Length is absent.
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
            if let (Ok(name), Ok(val)) = (
                http::header::HeaderName::try_from(k.as_str()),
                http::header::HeaderValue::try_from(v.as_str()),
            ) {
                headers.insert(name, val);
            }
        }
    }

    // Read the admin secret BEFORE `env` moves into `RepoServer::new` below.
    // `env.secret()` is `Err` when the binding doesn't exist (never
    // configured, or a local `wrangler dev` run with no `.dev.vars` entry) —
    // that maps to `None`, which the interceptor treats as "fail every
    // PurgeRoom call closed", not "allow any token".
    let admin_token = env.secret("ADMIN_TOKEN").ok().map(|s| s.to_string());

    // Build the service fresh per request — `Env` is Send and cheap to clone;
    // the service holds no cross-request state. The interceptor needs its own
    // `Env` clone too: it addresses the room's RefStore DO directly for the
    // write-quota check (ahead of, and independent of, the handler's own DO
    // calls), and separately reaches the `WRITE_EVENTS` Analytics Engine
    // binding for accepted/rejected-write telemetry (see worker_impl/auth.rs).
    let router: Router = Arc::new(RepoServer::new(env.clone())).register(Router::new());
    let router: Router = Arc::new(HealthServer::new(env.clone())).register(router);
    // Default compression policy (gzip large responses). The wasm client now
    // re-asserts `content-encoding` from the gzip magic and decompresses, so the
    // earlier "browser strips the header → client decodes raw gzip" bug is fixed
    // at the source (see mkit-repo-client transport `is_gzip`).
    let svc =
        ConnectRpcService::new(router).with_interceptor(AuthInterceptor::new(env, admin_token));

    // The dispatch touches JS-backed (`!Send`) worker handles inside handlers;
    // wrap in SendFuture so it satisfies ConnectRpcService's `Future: Send`
    // bound (sound under single-threaded wasm).
    let http_resp = SendFuture::new(async move {
        svc.oneshot(http_req)
            .await
            .expect("ConnectRpcService error is Infallible")
    })
    .await;

    let status = http_resp.status().as_u16();
    let resp_headers = http_resp.headers().clone();

    // Stream the response body chunk-by-chunk rather than buffering it whole.
    // A unary response is a single chunk either way, but a server-streaming
    // RPC (`WatchRefs`) produces an OPEN-ENDED body — it only reaches EOF
    // when the client disconnects — so the previous `.collect()`-then-
    // `from_bytes` would block forever waiting for a terminal chunk that
    // never comes, and the client would never see a single byte. Bridging a
    // borrowed `WebSocket::events()` into a `'static + Send` `ServiceStream`
    // (see `worker_impl/service.rs::watch_refs`) is necessary but not
    // SUFFICIENT for Connect server-streaming on Workers — this half, the
    // generic HTTP adapter's response side, is the other half: it has to
    // forward each Connect envelope frame to the client as `svc.oneshot`
    // produces it, not wait for the stream to end.
    //
    // KNOWN GAP (2026-07-11): switching to `from_stream` here made the
    // bridge itself provably work under `wrangler dev` (see the `watch_refs`
    // doc comment) but did NOT get a byte of the response back to a test
    // client — `curl -N`/`fetch()` against `WatchRefs` still see zero bytes,
    // even after the bridge logged real `RefEvent`s flowing through it. Not
    // yet root-caused: could be a `wrangler dev`/miniflare-local limitation
    // for wasm-worker `ReadableStream` responses, or a remaining issue in
    // this adapter — unverified against a real deployed Worker (no deploy
    // credentials in this environment). See README "WatchRefs / streaming".
    let body_stream = http_resp.into_body().into_data_stream().map(
        |item: std::result::Result<Bytes, std::convert::Infallible>| {
            // `ConnectRpcBody`'s `Error` is `Infallible`, so `item` is always
            // `Ok`; `unwrap_or_default()` just avoids matching a variant that
            // can't exist while giving the closure a concrete `Result` type.
            Ok::<Vec<u8>, worker::Error>(item.unwrap_or_default().to_vec())
        },
    );
    let mut out = Response::from_stream(body_stream)?.with_status(status);
    let out_headers = out.headers_mut();
    for (k, v) in resp_headers.iter() {
        if let Ok(val) = v.to_str() {
            let _ = out_headers.set(k.as_str(), val);
        }
    }
    Ok(with_cors(out))
}

/// Raw-WebSocket fallback: proxy the client straight to the room DO `/watch`.
async fn watch_fallback(env: Env, room: &str, pubkey: Option<String>) -> Result<Response> {
    let room = room.to_owned();
    SendFuture::new(async move {
        let ns = env.durable_object("REFSTORE")?;
        let stub = ns.id_from_name(&room)?.get_stub()?;
        // Only forward a well-formed pubkey, and only after validating it — a
        // stray value (`&`, spaces) must not break the DO's URL query parsing.
        let url = match pubkey.as_deref().filter(|p| refstore::is_valid_pubkey(p)) {
            Some(pk) => format!("https://refstore/watch?pubkey={pk}"),
            None => "https://refstore/watch".to_string(),
        };
        let mut req = Request::new(&url, Method::Get)?;
        req.headers_mut()?.set("upgrade", "websocket")?;
        stub.fetch_with_request(req).await
    })
    .await
}
