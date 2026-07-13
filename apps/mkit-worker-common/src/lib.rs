// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Shared CF Worker request/response glue extracted out of
// apps/repo-worker and apps/vcs-worker's `worker_impl.rs` (mkit#797): the
// three genuinely-identical pieces both Workers duplicated near-verbatim —
// CORS preflight handling, the Content-Length body-size cap, and the
// `worker::Request` <-> `http::Request` fetch-adapter skeleton (including
// the `SendFuture`-wrapped `tower::Service` dispatch).
//
// Deliberately NOT here: the auth/quota business logic. An earlier audit
// pass assumed `auth.rs` was near-verbatim duplicated too, but direct
// comparison found the two crates' `auth.rs` have genuinely diverged —
// repo-worker's carries envelope+quota+Analytics-Engine-audit logic,
// vcs-worker's is a different signed-envelope write-auth model with its own
// quota wiring, and vcs-worker has no `hashing.rs`/`constant_time_eq` at
// all. Unifying that would mean forcing one Worker's business rules onto
// the other, not extracting shared plumbing — so each Worker keeps its own
// `auth.rs` untouched. The RPC handlers, the Router/service registration,
// and the streamed-vs-buffered choice for the response bridge also stay put
// (that choice IS the crates' one confirmed behavioral divergence — see
// mkit#797 — and picking a single strategy here would paper over it).
//
// Split into "pure" decision logic (host-testable; the `#[cfg(test)]`
// modules in each file below exercise these directly) and thin
// `worker::*`-touching glue. The glue compiles on host but its JS-backed
// calls (`Headers::new()`, `Response::from_stream`, etc.) panic without a
// real Workers/JS runtime — verified directly: constructing a
// `worker::Response` under a plain `cargo test` panics with "cannot call
// wasm-bindgen imported functions on non-wasm targets". That's the exact
// reason apps/repo-worker's and apps/vcs-worker's `worker_impl` module is
// `#[cfg(target_arch = "wasm32")]`-gated and carries zero unit tests today.
// The glue here is verified the same way theirs is: the wasm32 build, each
// Worker's own integration tests (against fakes, not real `worker::` I/O),
// and a manual `wrangler dev` pass.

pub mod adapter;
pub mod body_cap;
pub mod cors;

pub use adapter::{
    copy_response_headers, dispatch_oneshot, http_request_from_worker, respond_buffered,
    respond_streamed, to_http_method,
};
pub use body_cap::{CappedBody, body_len_exceeds, content_length_exceeds, read_capped_body};
pub use cors::{cors_preflight_response, is_options_preflight, with_cors};
