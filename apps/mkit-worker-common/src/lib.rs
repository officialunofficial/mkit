// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Shared CF Worker request/response glue extracted out of
// apps/repo-worker and apps/vcs-worker's `worker_impl.rs` (mkit#797): the
// three genuinely-identical pieces both Workers duplicated near-verbatim —
// CORS preflight handling, the Content-Length body-size cap, and the
// `worker::Request` <-> `http::Request` fetch-adapter skeleton (including
// the `SendFuture`-wrapped `tower::Service` dispatch).
//
// The replay module also shares the explicit transactionSync bridge and
// durable nonce/result ledger across repo, VCS and keys Workers. Each service
// still owns its quota policy and effects; the pure auth v2 contract lives in
// mkit-core::write_auth.
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
//
// `health` (mkit#813, deferred step 7 of mkit#797) adds the R2-HEAD half of
// the `grpc.health.v1.Health` reachability probe and the `service`-field
// match decision — see that module's doc comment for what's deliberately
// NOT here (the `impl Health` trait itself and the RefStore DO probe, both
// blocked from full sharing by real per-crate/per-Worker differences, not
// scope timidity).

pub mod adapter;
pub mod body_cap;
pub mod cors;
pub mod health;

pub use adapter::{
    copy_response_headers, dispatch_oneshot, http_request_from_worker, respond_buffered,
    respond_streamed, to_http_method,
};
pub use body_cap::{CappedBody, body_len_exceeds, content_length_exceeds, read_capped_body};
pub use cors::{cors_preflight_response, is_options_preflight, with_cors};
pub use health::{HEALTH_PROBE_KEY, r2_head_probe, service_name_matches};

/// Transactional authenticated operation replay storage.
pub mod replay;
