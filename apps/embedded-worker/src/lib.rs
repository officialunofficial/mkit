// SPDX-License-Identifier: MIT OR Apache-2.0
//! Host routing plus programmatic hooks, with the production streaming adapter.
#![allow(clippy::result_large_err)]

#[cfg(target_arch = "wasm32")]
mod worker_impl;

#[cfg(target_arch = "wasm32")]
pub use worker_impl::{ContentIndexShard, NsCoordinator, RefShard, RefStore, RepoIndexShard};
