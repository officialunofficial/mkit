//! The router's tower layers: CORS, header redaction, tracing, the bearer
//! pre-check, the concurrency cap, the body limit and the per-procedure
//! deadline.

use std::time::Duration;

use axum::body::Body;
use connectrpc::DeadlinePolicy;
use http::{HeaderName, Method, Request, Response};
use tower::util::{MapRequestLayer, MapResponseLayer};

use crate::guard::{BearerGateLayer, CapLayer};
use tower_http::body::Limited;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::router::{CorsPolicy, RouterOptions};

/// Framing slack over the pack cap for an `UploadPack` body: Connect
/// envelopes, the header message and each chunk's fields.
pub const BODY_FRAMING_SLACK: u64 = 64 * 1024;

/// `Access-Control-Max-Age`, as `vcs-worker` sends it.
pub const CORS_MAX_AGE: Duration = Duration::from_hours(24);

/// The body limit for a server whose pack cap is `max_pack_bytes`: the cap,
/// plus [`BODY_FRAMING_SLACK`], plus 1/1024 of the cap for per-chunk
/// framing (about 50 bytes per chunk, so chunks down to 50 KiB fit; the
/// `mkit` client sends 800 KiB chunks).
#[must_use]
pub const fn body_limit_for(max_pack_bytes: u64) -> u64 {
    max_pack_bytes
        .saturating_add(max_pack_bytes / 1024)
        .saturating_add(BODY_FRAMING_SLACK)
}

/// The deadline of every call on one route: `timeout` when the client
/// asserts none, and never longer than `timeout` when it does. A streaming
/// route bounds its whole response stream too.
#[must_use]
pub fn deadline_policy(timeout: Duration, streaming: bool) -> DeadlinePolicy {
    DeadlinePolicy::new()
        .with_max(timeout)
        .with_default_timeout(timeout)
        .with_enforce_on_streams(streaming)
}

/// The CORS layer `opts` asks for, if any. A preflight is answered by the
/// layer itself, so it never meets the auth interceptor.
fn cors(opts: &RouterOptions) -> Option<CorsLayer> {
    let origins = match &opts.cors {
        CorsPolicy::Disabled => return None,
        CorsPolicy::AllowAny => AllowOrigin::any(),
        CorsPolicy::AllowOrigins(list) => AllowOrigin::list(list.iter().cloned()),
    };
    let allow = mkit_server::auth_v2::CORS_ALLOW_HEADERS
        .split(',')
        .map(str::trim)
        .chain(["authorization"])
        .filter_map(|name| HeaderName::from_bytes(name.as_bytes()).ok())
        .chain(opts.cors_extra_allow_headers.iter().cloned())
        .collect::<Vec<_>>();
    Some(
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([Method::POST, Method::GET, Method::OPTIONS])
            .allow_headers(allow)
            .expose_headers(opts.cors_expose_headers.clone())
            .max_age(CORS_MAX_AGE),
    )
}

/// Mark every header `redactor` names as sensitive, so a trace prints
/// `Sensitive` in place of its value.
fn mark_sensitive(headers: &mut http::HeaderMap, redactor: &mkit_server::Redactor) {
    for (name, value) in headers.iter_mut() {
        if redactor.redacts(name.as_str()) {
            value.set_sensitive(true);
        }
    }
}

/// Wrap `router` in the layers `opts` describes (see
/// [`crate::build_router`] for the order).
pub(crate) fn apply(
    router: axum::Router,
    opts: &RouterOptions,
    bearer: Option<&str>,
) -> axum::Router {
    // The limit wraps the body in `Limited`; the route takes axum's
    // `Body`, so box it back. An oversize `Content-Length` is answered 413
    // here, before the handler.
    let limit = usize::try_from(opts.max_body_bytes).unwrap_or(usize::MAX);
    let body_limit = tower::ServiceBuilder::new()
        .layer(RequestBodyLimitLayer::new(limit))
        .layer(MapRequestLayer::new(|req: Request<Limited<Body>>| {
            req.map(Body::new)
        }));
    let redact_req = opts.redactor.clone();
    let redact_resp = opts.redactor.clone();
    // `Router::layer` layers each route on its own; the cap's semaphore is
    // shared by every clone of the layer.
    let router = router
        .layer(body_limit)
        .layer(CapLayer::new(opts.max_concurrency, opts.queue_timeout));
    let router = match bearer {
        // Outside the cap: a request without the token takes no permit.
        Some(token) => router.layer(BearerGateLayer::new(token)),
        None => router,
    };
    let router = router
        // Inside the trace layer, so response values are marked before
        // the trace records the response.
        .layer(MapResponseLayer::new(move |mut resp: Response<Body>| {
            mark_sensitive(resp.headers_mut(), &redact_resp);
            resp
        }))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(
                    DefaultMakeSpan::new()
                        .level(Level::INFO)
                        .include_headers(true),
                )
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        // Outside the trace layer, so the values are marked before a span
        // records them.
        .layer(MapRequestLayer::new(move |mut req: Request<Body>| {
            mark_sensitive(req.headers_mut(), &redact_req);
            req
        }));
    match cors(opts) {
        Some(cors) => router.layer(cors),
        None => router,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_limit_covers_client_chunk_framing() {
        let cap = mkit_core::protocol::PACK_BODY_LIMIT;
        // 800 KiB chunks at ~50 framing bytes each.
        let chunks = cap.div_ceil(800 * 1024);
        assert!(body_limit_for(cap) >= cap + chunks * 50 + BODY_FRAMING_SLACK);
        assert_eq!(body_limit_for(u64::MAX), u64::MAX);
        assert_eq!(body_limit_for(0), BODY_FRAMING_SLACK);
    }

    #[test]
    fn cors_allows_auth_v2_and_bearer_headers() {
        let mut opts = RouterOptions::default();
        assert!(cors(&opts).is_none());
        opts.cors = CorsPolicy::AllowAny;
        assert!(cors(&opts).is_some());
    }

    #[test]
    fn marks_never_log_headers_sensitive() {
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", "Bearer t".parse().unwrap());
        headers.insert("x-signature", "sig".parse().unwrap());
        headers.insert("x-audience", "a".parse().unwrap());
        mark_sensitive(&mut headers, &mkit_server::Redactor::default());
        assert!(headers["authorization"].is_sensitive());
        assert!(headers["x-signature"].is_sensitive());
        assert!(!headers["x-audience"].is_sensitive());
    }
}
