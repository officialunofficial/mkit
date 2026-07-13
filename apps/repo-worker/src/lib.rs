// SPDX-License-Identifier: MIT OR Apache-2.0
//
// mkit anonymous-multiplayer repo server — a Rust Cloudflare Worker
// (workers-rs) speaking ConnectRPC over `mkit.repo.v1.RepoService`.
//
// Entry point: the `#[event(fetch)]` handler converts a `worker::Request`
// into an `http::Request<Full<Bytes>>`, drives the connectrpc Router (wrapped
// in `ConnectRpcService` + the write-envelope auth interceptor) as a
// `tower::Service`, and converts the `http::Response<ConnectRpcBody>` back
// into a `worker::Response`. R2 + the RefStore Durable Object are reached from
// inside the service handlers via the (Send) `worker::Env`. See README.md.

#![allow(clippy::result_large_err)]

// Pure, target-independent modules — these carry the conformance contract and
// run under `cargo test` on the host. The `sign` dev binary depends only on
// these (+ the generated proto), so the host build never compiles the
// wasm-only worker glue below.
pub mod audit;
pub mod chat;
pub mod envelope;
pub mod hashing;
pub mod refs;
pub mod storage_error;
pub mod write_quota;

/// Generated buffa messages + ConnectRPC RepoService server stubs.
pub mod commit_log;
pub mod proto {
    connectrpc::include_generated!();
}

/// The `/watch` wire encoding — a `RoomEvent` proto-JSON payload — shared by
/// the RefStore DO (producer) and the WatchRefs Connect-streaming bridge
/// (consumer). See the module doc for why this lives outside `worker_impl`
/// (host-testable, no wasm32 target required).
pub mod room_event;

// Worker glue (R2 / Durable Object / fetch event) is wasm32-only: the
// `#[durable_object]` and `#[event(fetch)]` macros emit `#[wasm_bindgen]`
// exports that only build for the worker target.
#[cfg(target_arch = "wasm32")]
mod worker_impl;

#[cfg(target_arch = "wasm32")]
pub use worker_impl::RefStore;
