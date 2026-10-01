// SPDX-License-Identifier: MIT OR Apache-2.0
//! Local Uno acceptance host: public API composition, no deployed policy.
#![allow(clippy::result_large_err)]
#[cfg(target_arch = "wasm32")]
mod host;
#[cfg(target_arch = "wasm32")]
pub use host::{ContentIndexShard, NsCoordinator, RefShard, RefStore, RepoIndexShard};
