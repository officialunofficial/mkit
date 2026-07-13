// SPDX-License-Identifier: MIT OR Apache-2.0
//! Body-size cap shared by both Workers: reject a request by
//! `Content-Length` before buffering (so an oversized POST is refused in
//! O(1) instead of `req.bytes()` materializing the whole payload in the
//! isolate first), with a post-buffer backstop for chunked/unknown-length
//! bodies where `Content-Length` is absent. See mkit#797.
//!
//! The two Workers return a differently-shaped "too large" error
//! (repo-worker: Connect `invalid_argument`; vcs-worker: `resource_exhausted`)
//! — so this crate only owns the size-check MECHANICS via [`CappedBody`];
//! each Worker builds its own error response when it gets back
//! `CappedBody::TooLarge`, keeping the error code and JSON shape
//! Worker-specific rather than forcing one on the other.

use bytes::Bytes;
use worker::{Request, Result};

/// Outcome of [`read_capped_body`].
#[derive(Debug)]
pub enum CappedBody {
    /// The body was read and is within the cap.
    Ok(Bytes),
    /// The body was rejected — either by `Content-Length` (never read at
    /// all) or, for a chunked/unknown-length body, after buffering. The
    /// caller should build its own "too large" response and skip dispatch.
    TooLarge,
}

/// True when a `Content-Length` header value already exceeds `max_bytes`,
/// i.e. the request can be rejected in O(1) without reading any body
/// bytes. A missing or non-numeric/negative-looking header is never
/// treated as exceeding the cap here — callers fall through to
/// [`body_len_exceeds`] as the backstop for chunked/unknown-length
/// requests.
pub fn content_length_exceeds(content_length: Option<&str>, max_bytes: usize) -> bool {
    content_length
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > max_bytes)
}

/// True when an already-buffered body's length exceeds `max_bytes` — the
/// backstop for chunked/unknown-length requests where `Content-Length` was
/// absent or unparsable.
pub fn body_len_exceeds(actual_len: usize, max_bytes: usize) -> bool {
    actual_len > max_bytes
}

/// Read `req`'s body, capped at `max_bytes`. Checks `Content-Length` first
/// (see [`content_length_exceeds`]) and re-checks the actual buffered
/// length as a backstop (see [`body_len_exceeds`]).
pub async fn read_capped_body(req: &mut Request, max_bytes: usize) -> Result<CappedBody> {
    let header = req.headers().get("content-length").ok().flatten();
    if content_length_exceeds(header.as_deref(), max_bytes) {
        return Ok(CappedBody::TooLarge);
    }
    let body = req.bytes().await.unwrap_or_default();
    if body_len_exceeds(body.len(), max_bytes) {
        return Ok(CappedBody::TooLarge);
    }
    Ok(CappedBody::Ok(Bytes::from(body)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // These two functions are the actual decision logic and are pure (no
    // `worker::*` types), so — unlike `read_capped_body` below, which
    // touches a real `worker::Request` and needs a live Workers/JS runtime
    // to execute (see lib.rs's module doc) — they get real host-executed
    // coverage here.

    const MAX: usize = 8 * 1024 * 1024;

    #[test]
    fn content_length_under_cap_is_fine() {
        assert!(!content_length_exceeds(Some("100"), MAX));
    }

    #[test]
    fn content_length_over_cap_is_rejected() {
        assert!(content_length_exceeds(Some("9000000"), MAX));
    }

    #[test]
    fn content_length_exactly_at_cap_is_fine() {
        assert!(!content_length_exceeds(Some("8388608"), MAX));
    }

    #[test]
    fn content_length_one_over_cap_is_rejected() {
        assert!(content_length_exceeds(Some("8388609"), MAX));
    }

    #[test]
    fn missing_content_length_is_not_rejected_by_this_check() {
        assert!(!content_length_exceeds(None, MAX));
    }

    #[test]
    fn non_numeric_content_length_is_not_rejected_by_this_check() {
        assert!(!content_length_exceeds(Some("not-a-number"), MAX));
    }

    #[test]
    fn negative_looking_content_length_is_not_rejected_by_this_check() {
        assert!(!content_length_exceeds(Some("-1"), MAX));
    }

    #[test]
    fn empty_content_length_is_not_rejected_by_this_check() {
        assert!(!content_length_exceeds(Some(""), MAX));
    }

    #[test]
    fn buffered_body_under_cap_is_fine() {
        assert!(!body_len_exceeds(10, 100));
    }

    #[test]
    fn buffered_body_over_cap_is_rejected() {
        assert!(body_len_exceeds(101, 100));
    }

    #[test]
    fn buffered_body_exactly_at_cap_is_fine() {
        assert!(!body_len_exceeds(100, 100));
    }

    #[test]
    fn buffered_body_empty_is_fine() {
        assert!(!body_len_exceeds(
            0, 0 /* degenerate cap, still not > */
        ));
    }
}
