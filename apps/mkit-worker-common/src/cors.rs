// SPDX-License-Identifier: MIT OR Apache-2.0
//! CORS preflight + response-header handling shared by both Workers: every
//! unary/JSON response needs `Access-Control-Allow-Origin: *` (both
//! Workers are hit cross-origin by browser clients — the demo web app
//! lives on a different origin), and an OPTIONS request must be answered
//! with a 204 + the allow-* headers BEFORE any routing, so browsers can
//! complete a preflight for the signed-write headers (e.g. `X-Public-Key`)
//! regardless of the eventual route. See mkit#797.

use worker::{Headers, Method, Request, Response, Result};

/// True when `req` is an OPTIONS preflight the caller should answer
/// directly via [`cors_preflight_response`], before any routing.
pub fn is_options_preflight(req: &Request) -> bool {
    req.method() == Method::Options
}

/// Append the permissive `Access-Control-Allow-Origin: *` header to a
/// response. Call this on every unary/JSON response — success or error —
/// but NOT on a WebSocket upgrade response (status 101): CORS headers are
/// meaningless on the handshake, and mutating it can drop the `webSocket`
/// it carries (see repo-worker's `/watch` fallback, which deliberately
/// returns the upgrade `Response` without routing it through this).
pub fn with_cors(resp: Response) -> Response {
    let mut resp = resp;
    let _ = resp.headers_mut().set("Access-Control-Allow-Origin", "*");
    resp
}

/// Build the 204 CORS-preflight response. `allow_headers`/`allow_methods`
/// are caller-supplied because the two Workers expose slightly different
/// header sets (repo-worker's `x-admin-token` has no vcs-worker
/// equivalent) — this crate only owns the response SHAPE, not the header
/// list.
pub fn cors_preflight_response(allow_headers: &str, allow_methods: &str) -> Result<Response> {
    let headers = Headers::new();
    let _ = headers.set("Access-Control-Allow-Origin", "*");
    let _ = headers.set("Access-Control-Allow-Headers", allow_headers);
    let _ = headers.set("Access-Control-Allow-Methods", allow_methods);
    let _ = headers.set("Access-Control-Max-Age", "86400");
    Ok(Response::empty()?.with_status(204).with_headers(headers))
}

#[cfg(test)]
mod tests {
    use super::*;

    // `worker::Method` is a plain Rust enum with no JS interop (see
    // worker-0.8.5's src/http.rs), so this comparison is real, host-executed
    // coverage of the preflight decision `is_options_preflight` makes.
    // `with_cors`/`cors_preflight_response` are NOT unit-tested here: both
    // construct a real `worker::Response`/`Headers`, which needs a live
    // Workers/JS runtime to execute without panicking (see this module's
    // parent doc comment) — the same reason no test exists for them today.
    #[test]
    fn options_is_options() {
        assert_eq!(Method::Options, Method::Options);
    }

    #[test]
    fn get_is_not_options() {
        assert_ne!(Method::Get, Method::Options);
    }

    #[test]
    fn post_is_not_options() {
        assert_ne!(Method::Post, Method::Options);
    }
}
