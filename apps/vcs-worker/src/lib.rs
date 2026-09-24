// SPDX-License-Identifier: MIT OR Apache-2.0
//
// mkit reference `mkit.transport.v1` server — a Rust Cloudflare Worker
// (workers-rs) speaking ConnectRPC over `mkit.transport.v1.TransportService`.
// See README.md for architecture and apps/repo-worker for the proven pattern
// this crate follows.

#![allow(clippy::result_large_err)]

// Pure, target-independent modules — these carry the conformance contract
// and run under `cargo test` on the host. Compiled on host *and* wasm.
#[cfg(feature = "managed-access")]
pub mod access_policy;
pub mod envelope;
pub mod hashing;
pub mod refs;
#[cfg(feature = "managed-access")]
pub mod snapshot_frontier;
#[cfg(feature = "managed-access")]
pub mod snapshot_wire;
pub mod storage_error;
#[cfg(feature = "managed-access")]
mod submission_errors;
#[cfg(feature = "managed-access")]
pub mod submission_frontier;
#[cfg(feature = "managed-access")]
mod submission_response;
#[cfg(feature = "managed-access")]
pub mod submission_wire;
pub mod write_quota;

/// Generated buffa messages + ConnectRPC TransportService server stubs.
pub mod proto {
    connectrpc::include_generated!();
}

// Worker glue (R2 / Durable Object / fetch event) is wasm32-only: the
// `#[durable_object]` and `#[event(fetch)]` macros emit `#[wasm_bindgen]`
// exports that only build for the worker target.
#[cfg(target_arch = "wasm32")]
mod worker_impl;

#[cfg(target_arch = "wasm32")]
pub use worker_impl::RefStore;
