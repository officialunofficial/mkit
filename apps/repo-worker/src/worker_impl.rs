// SPDX-License-Identifier: MIT OR Apache-2.0
//
// wasm32-only worker glue: the auth interceptor, the RefStore Durable Object,
// the RepoService implementation, and the `#[event(fetch)]` adapter that
// bridges `worker::Request` <-> `http::Request` and drives the connectrpc
// Router. Gated out of host builds (the macros emit `#[wasm_bindgen]`).
//
// The CORS handling, body-size cap, and worker::Request<->http::Request
// fetch-adapter skeleton are shared with apps/vcs-worker via
// `mkit-worker-common` (mkit#797) — this module wires those generic pieces
// together with repo-worker's OWN business logic (the auth interceptor,
// the RefStore DO, the RepoService/HealthServer registration, and the
// streamed response bridge WatchRefs needs), which stays here.

use std::sync::Arc;

use bytes::Bytes;
use connectrpc::{ConnectRpcService, Router};
use mkit_worker_common::{
    adapter::{
        copy_response_headers, dispatch_oneshot, http_request_from_worker, is_deadline_header,
        respond_streamed,
    },
    body_cap::{CappedBody, read_capped_body},
    cors::{cors_preflight_response, is_options_preflight, with_cors},
};
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
const CORS_ALLOW_HEADERS: &str = "x-envelope-version, x-audience, x-repository, x-content-commitment, x-expires-at, x-public-key, x-signature, x-digest, x-created-at, \
     idempotency-key, x-admin-token, content-type, connect-protocol-version";
const CORS_ALLOW_METHODS: &str = "POST, GET, OPTIONS";

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // CORS preflight: answer OPTIONS with a 204 + the allow-* headers BEFORE
    // any routing, so browsers can complete the preflight for the signed-write
    // headers (X-Public-Key, …) regardless of the eventual route.
    if is_options_preflight(&req) {
        return cors_preflight_response(CORS_ALLOW_HEADERS, CORS_ALLOW_METHODS);
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
    // ConnectRpcService bound. Cap it first (see `mkit_worker_common::body_cap`
    // for the Content-Length-then-post-buffer check) — the only large input is
    // PutObject `bytes`.
    let body: Bytes = match read_capped_body(&mut req, MAX_BODY_BYTES).await? {
        CappedBody::Ok(body) => body,
        CappedBody::TooLarge => return Ok(with_cors(body_too_large()?)),
    };

    // See `is_deadline_header`'s doc comment: parsing `connect-timeout-ms`/
    // `grpc-timeout` calls `Instant::now()`, which panics on wasm32.
    let http_req = http_request_from_worker(&req, body, |k| !is_deadline_header(k))?;

    // Read the admin secret BEFORE `env` moves into `RepoServer::new` below.
    // `env.secret()` is `Err` when the binding doesn't exist (never
    // configured, or a local `wrangler dev` run with no `.dev.vars` entry) —
    // that maps to `None`, which the interceptor treats as "fail every
    // PurgeRoom call closed", not "allow any token".
    let admin_token = env.secret("ADMIN_TOKEN").ok().map(|s| s.to_string());

    // Build services per request. Auth uses the configured audience and the
    // WRITE_EVENTS binding; services use storage and health bindings.
    let router: Router = Arc::new(RepoServer::new(env.clone())).register(Router::new());
    let router: Router = Arc::new(HealthServer::new(env.clone())).register(router);
    // Default compression policy (gzip large responses). The wasm client now
    // re-asserts `content-encoding` from the gzip magic and decompresses, so the
    // earlier "browser strips the header → client decodes raw gzip" bug is fixed
    // at the source (see mkit-repo-client transport `is_gzip`).
    let svc =
        ConnectRpcService::new(router).with_interceptor(AuthInterceptor::new(env, admin_token));

    // The dispatch touches JS-backed (`!Send`) worker handles inside handlers;
    // `dispatch_oneshot` wraps it in `SendFuture` so it satisfies
    // ConnectRpcService's `Future: Send` bound (sound under single-threaded
    // wasm) — see `mkit_worker_common::adapter`.
    let http_resp = dispatch_oneshot(svc, http_req).await;

    let status = http_resp.status().as_u16();
    let resp_headers = http_resp.headers().clone();

    // Stream the response body chunk-by-chunk rather than buffering it whole.
    // A unary response is a single chunk either way, but a server-streaming
    // RPC (`WatchRefs`) produces an OPEN-ENDED body — it only reaches EOF
    // when the client disconnects — so buffering-then-replying would block
    // forever waiting for a terminal chunk that never comes, and the client
    // would never see a single byte. Bridging a borrowed `WebSocket::events()`
    // into a `'static + Send` `ServiceStream` (see
    // `worker_impl/service.rs::watch_refs`) is necessary but not SUFFICIENT
    // for Connect server-streaming on Workers — this half, the generic HTTP
    // adapter's response side (`mkit_worker_common::adapter::respond_streamed`),
    // is the other half: it has to forward each Connect envelope frame to the
    // client as `svc.oneshot` produces it, not wait for the stream to end.
    //
    // RESOLVED, then re-verified under `wrangler dev` only (2026-07-11 →
    // 2026-07-12, issue #705 / PR #763). This comment used to record a
    // "KNOWN GAP" here: an earlier pass (PR #738, the #697 spike) switched
    // to `from_stream` and got the bridge itself provably working under
    // `wrangler dev`, but reported that a test client still saw zero bytes
    // back from `WatchRefs` — `curl -N`/`fetch()` receiving nothing even
    // after the bridge logged real `RefEvent`s flowing through it, not yet
    // root-caused. PR #763 re-ran that exact repro against the SAME adapter
    // logic (now living in `mkit_worker_common::adapter::respond_streamed`,
    // unmodified in behavior from the gap report) and did NOT reproduce it:
    // 20+ manual trials against a fresh local `wrangler dev` instance
    // delivered every event, every time (see the `watch_refs` doc comment in
    // `worker_impl/service.rs` and the README "WatchRefs / streaming"
    // section for the full writeup). The likely explanation for the original
    // "zero bytes" finding was a test-harness artifact (a `curl -N ...&
    // sleep; kill` pattern can lose buffered-but-unflushed bytes on
    // `SIGTERM`), not a bug in this adapter or in `wrangler dev` itself.
    // What remains UNVERIFIED is a real deployed Cloudflare Worker (an
    // actual `wrangler deploy`) — every pass so far has been local
    // `wrangler dev`/Miniflare only; see issue #803 for that outstanding
    // follow-up trial.
    let mut out = respond_streamed(status, http_resp.into_body())?;
    copy_response_headers(&resp_headers, &mut out);
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
