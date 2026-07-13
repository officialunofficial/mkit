// SPDX-License-Identifier: MIT OR Apache-2.0
//! The CF Worker fetch-adapter skeleton shared by both Workers: converting
//! a `worker::Request` into an `http::Request<Full<Bytes>>` for `tower`
//! dispatch, driving a `tower::Service` (each Worker's `ConnectRpcService`)
//! via `oneshot` wrapped in `worker::send::SendFuture`, and copying the
//! resulting `http::Response`'s status/headers back onto a
//! `worker::Response` — either streamed (server-streaming RPCs, e.g.
//! repo-worker's WatchRefs) or buffered (vcs-worker, whose body is already
//! size-capped upstream — see `body_cap`). See mkit#797.

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full};
use std::convert::Infallible;
use tower::ServiceExt;
use worker::send::SendFuture;
use worker::{Method as WorkerMethod, Request, Response, Result};

/// Map a `worker::Method` to its `http::Method` equivalent. Anything
/// exotic (`Connect`/`Trace`/`Report` — never actually sent by a Connect
/// client) falls back to `POST`, matching both Workers' original behavior.
pub fn to_http_method(method: WorkerMethod) -> http::Method {
    match method {
        WorkerMethod::Get => http::Method::GET,
        WorkerMethod::Post => http::Method::POST,
        WorkerMethod::Put => http::Method::PUT,
        WorkerMethod::Delete => http::Method::DELETE,
        WorkerMethod::Options => http::Method::OPTIONS,
        WorkerMethod::Head => http::Method::HEAD,
        WorkerMethod::Patch => http::Method::PATCH,
        _ => http::Method::POST,
    }
}

/// Header names that must never reach `connectrpc`'s dispatcher on a wasm32
/// target: parsing either into a `RequestContext::deadline` calls
/// `std::time::Instant::now()` (`connectrpc-0.8.1/src/response.rs`), which
/// panics with "time not implemented on this platform" on
/// wasm32-unknown-unknown — this target has no OS clock and Rust's std
/// `Instant`/`SystemTime` have no JS-Date fallback (unlike `worker::Date`,
/// which both Workers already use for their own envelope freshness checks).
/// Any real ConnectRPC client that asserts a per-call timeout — e.g.
/// `mkit-transport-connect::ConnectTransport`'s `with_default_timeout`
/// (#701), not just a hand-crafted request — hits this unconditionally and
/// takes the whole Worker down (`workerd` reports it as a hung request, not
/// a clean 5xx). Stripping these headers means a Worker using this
/// predicate simply never enforces a client-asserted deadline
/// (`RequestContext::deadline()` sees `None`, matching the documented
/// no-`DeadlinePolicy` behavior) — an accepted trade for a wasm32 target
/// with no wall clock, not a change to the transport's write-auth contract.
/// A single named predicate rather than each Worker hand-rolling its own
/// closure: repo-worker originally passed `|_| true` here (keeping
/// everything) while vcs-worker filtered correctly, a duplication-drift bug
/// the shared `mkit-worker-common` crate exists to prevent — see mkit#797.
pub fn is_deadline_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connect-timeout-ms") || name.eq_ignore_ascii_case("grpc-timeout")
}

/// Copy `(name, value)` header pairs onto an `http::HeaderMap`, dropping
/// any pair that isn't a valid HTTP header name/value rather than failing
/// the whole request. `keep` lets a caller filter out headers the dispatch
/// target can't handle — e.g. vcs-worker drops `connect-timeout-ms`/
/// `grpc-timeout` before they reach `connectrpc`'s dispatcher, because
/// parsing either into a deadline calls `Instant::now()`, which panics on
/// wasm32 (see vcs-worker's `worker_impl.rs` doc comment for the full
/// rationale). Pass `|_| true` to keep everything.
pub fn copy_headers_filtered(
    entries: impl IntoIterator<Item = (String, String)>,
    headers: &mut http::HeaderMap,
    mut keep: impl FnMut(&str) -> bool,
) {
    for (k, v) in entries {
        if !keep(&k) {
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

/// Build the `http::Request<Full<Bytes>>` `tower` dispatch needs, from a
/// `worker::Request`'s method/URL/headers plus an already-read (and
/// already size-capped — see `body_cap::read_capped_body`) body.
/// `keep_header` filters the header copy (see [`copy_headers_filtered`]);
/// pass `|_| true` to keep everything.
pub fn http_request_from_worker(
    req: &Request,
    body: Bytes,
    mut keep_header: impl FnMut(&str) -> bool,
) -> Result<http::Request<Full<Bytes>>> {
    let method = to_http_method(req.method());
    let uri = req.url()?.to_string();

    let mut http_req = http::Request::builder()
        .method(method)
        .uri(uri)
        .body(Full::new(body))
        .map_err(|e| worker::Error::RustError(format!("build http request: {e}")))?;

    copy_headers_filtered(
        req.headers().entries(),
        http_req.headers_mut(),
        &mut keep_header,
    );

    Ok(http_req)
}

/// Drive `svc` against `req` via `tower::ServiceExt::oneshot`, wrapped in
/// `SendFuture` so the call satisfies whatever `Send` bound the caller's
/// async context demands even though the dispatch touches JS-backed,
/// `!Send` worker handles inside RPC handlers — sound because Cloudflare
/// Workers run single-threaded wasm (see `worker::send::SendFuture`'s own
/// doc comment). `S::Error = Infallible` because neither Worker's
/// `ConnectRpcService` ever actually fails the outer `tower::Service::call`
/// — errors surface as Connect-coded HTTP responses instead.
pub async fn dispatch_oneshot<S>(svc: S, req: http::Request<Full<Bytes>>) -> S::Response
where
    S: tower::Service<http::Request<Full<Bytes>>, Error = Infallible>,
{
    SendFuture::new(async move { svc.oneshot(req).await.expect("service error is Infallible") })
        .await
}

/// Copy an `http::Response`'s headers onto a `worker::Response`'s headers,
/// skipping any value that isn't valid UTF-8 (mirrors both Workers'
/// original header-copy loop).
pub fn copy_response_headers(from: &http::HeaderMap, out: &mut Response) {
    let out_headers = out.headers_mut();
    for (k, v) in from.iter() {
        if let Ok(val) = v.to_str() {
            let _ = out_headers.set(k.as_str(), val);
        }
    }
}

/// Bridge a streamed `http_body::Body` response onto a `worker::Response`
/// chunk-by-chunk, rather than buffering it whole — required for
/// server-streaming RPCs (e.g. repo-worker's WatchRefs), which produce an
/// open-ended body that only reaches EOF when the client disconnects.
/// Buffering-then-replying would block forever waiting for a terminal
/// chunk that never comes (see repo-worker's original `serve_connect` doc
/// comment, mkit#705/#763, for the full history).
pub fn respond_streamed<B>(status: u16, body: B) -> Result<Response>
where
    B: http_body::Body<Data = Bytes, Error = Infallible> + 'static,
{
    let body_stream =
        body.into_data_stream()
            .map(|item: std::result::Result<Bytes, Infallible>| {
                // `item` is always `Ok` (the body's `Error` is `Infallible`);
                // `unwrap_or_default()` just avoids matching a variant that
                // can't exist while giving the closure a concrete `Result`.
                Ok::<Vec<u8>, worker::Error>(item.unwrap_or_default().to_vec())
            });
    Ok(Response::from_stream(body_stream)?.with_status(status))
}

/// Bridge a buffered `http_body::Body` response onto a `worker::Response`,
/// collecting it whole first. Used by Workers with no server-streaming
/// route (e.g. vcs-worker), whose response bodies are already capped
/// upstream (see `body_cap`).
pub async fn respond_buffered<B>(status: u16, body: B) -> Result<Response>
where
    B: http_body::Body<Data = Bytes, Error = Infallible>,
{
    let collected = SendFuture::new(async move { body.collect().await })
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    Ok(Response::from_bytes(collected.to_vec())?.with_status(status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::{Context, Poll};

    // `to_http_method`, `copy_headers_filtered`, and `dispatch_oneshot` are
    // pure/generic (no `worker::*` types touched), so they get real
    // host-executed coverage here. `http_request_from_worker`,
    // `copy_response_headers`, `respond_streamed`, and `respond_buffered`
    // are NOT unit-tested here: each constructs or reads a real
    // `worker::Request`/`Response`, which needs a live Workers/JS runtime
    // to execute without panicking (see lib.rs's module doc).

    #[test]
    fn maps_standard_methods() {
        assert_eq!(to_http_method(WorkerMethod::Get), http::Method::GET);
        assert_eq!(to_http_method(WorkerMethod::Post), http::Method::POST);
        assert_eq!(to_http_method(WorkerMethod::Put), http::Method::PUT);
        assert_eq!(to_http_method(WorkerMethod::Delete), http::Method::DELETE);
        assert_eq!(to_http_method(WorkerMethod::Options), http::Method::OPTIONS);
        assert_eq!(to_http_method(WorkerMethod::Head), http::Method::HEAD);
        assert_eq!(to_http_method(WorkerMethod::Patch), http::Method::PATCH);
    }

    #[test]
    fn maps_exotic_methods_to_post() {
        assert_eq!(to_http_method(WorkerMethod::Connect), http::Method::POST);
        assert_eq!(to_http_method(WorkerMethod::Trace), http::Method::POST);
        assert_eq!(to_http_method(WorkerMethod::Report), http::Method::POST);
    }

    #[test]
    fn copies_valid_headers_and_drops_invalid_ones() {
        let mut headers = http::HeaderMap::new();
        let entries = vec![
            ("x-public-key".to_string(), "abc123".to_string()),
            // A header value with a bare NUL byte is not a valid
            // `HeaderValue` — must be silently dropped, not panic the
            // whole request.
            ("x-bad".to_string(), "bad\u{0}value".to_string()),
        ];
        copy_headers_filtered(entries, &mut headers, |_| true);
        assert_eq!(headers.get("x-public-key").unwrap(), "abc123");
        assert!(headers.get("x-bad").is_none());
    }

    #[test]
    fn keep_predicate_drops_filtered_headers() {
        let mut headers = http::HeaderMap::new();
        let entries = vec![
            ("connect-timeout-ms".to_string(), "5000".to_string()),
            ("x-public-key".to_string(), "abc123".to_string()),
        ];
        copy_headers_filtered(entries, &mut headers, |k| {
            !k.eq_ignore_ascii_case("connect-timeout-ms")
        });
        assert!(headers.get("connect-timeout-ms").is_none());
        assert_eq!(headers.get("x-public-key").unwrap(), "abc123");
    }

    #[test]
    fn is_deadline_header_matches_both_names_case_insensitively() {
        assert!(is_deadline_header("connect-timeout-ms"));
        assert!(is_deadline_header("Connect-Timeout-Ms"));
        assert!(is_deadline_header("grpc-timeout"));
        assert!(is_deadline_header("GRPC-TIMEOUT"));
        assert!(!is_deadline_header("x-public-key"));
        assert!(!is_deadline_header("connect-timeout"));
    }

    #[test]
    fn is_deadline_header_strips_both_from_a_header_copy() {
        let mut headers = http::HeaderMap::new();
        let entries = vec![
            ("connect-timeout-ms".to_string(), "5000".to_string()),
            ("grpc-timeout".to_string(), "5S".to_string()),
            ("x-public-key".to_string(), "abc123".to_string()),
        ];
        copy_headers_filtered(entries, &mut headers, |k| !is_deadline_header(k));
        assert!(headers.get("connect-timeout-ms").is_none());
        assert!(headers.get("grpc-timeout").is_none());
        assert_eq!(headers.get("x-public-key").unwrap(), "abc123");
    }

    /// A minimal `tower::Service` test double standing in for
    /// `ConnectRpcService`: always ready, echoes back a canned response.
    struct Echo;

    impl tower::Service<http::Request<Full<Bytes>>> for Echo {
        type Response = http::Response<&'static str>;
        type Error = Infallible;
        type Future = std::future::Ready<std::result::Result<Self::Response, Infallible>>;

        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: http::Request<Full<Bytes>>) -> Self::Future {
            std::future::ready(Ok(http::Response::builder()
                .status(200)
                .body("ok")
                .unwrap()))
        }
    }

    #[tokio::test]
    async fn dispatch_oneshot_drives_the_service_and_returns_its_response() {
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://example.invalid/svc/Method")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = dispatch_oneshot(Echo, req).await;
        assert_eq!(resp.status(), 200);
        assert_eq!(*resp.body(), "ok");
    }
}
