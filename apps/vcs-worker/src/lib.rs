// SPDX-License-Identifier: MIT OR Apache-2.0
//
// mkit reference `mkit.transport.v1` server — a thin Cloudflare Workers
// deployment of `mkit-server-worker` (see README.md). Everything here is
// the wasm32 glue: the `#[durable_object]` and `#[event(fetch)]` macros
// emit `#[wasm_bindgen]` exports that only build for the Worker target.
// The logic lives in, and is tested with, `mkit-server` and
// `mkit-server-worker`.

#![allow(clippy::result_large_err)]

#[cfg(target_arch = "wasm32")]
mod worker_impl;

#[cfg(target_arch = "wasm32")]
pub use worker_impl::RefStore;
