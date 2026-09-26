#![forbid(unsafe_code)]
// Cases take their harness by value so every case future is `'static`.
#![allow(clippy::needless_pass_by_value)]
//! Conformance suite for `mkit-server` storage backends (PRD §5.1, §5.3).
//!
//! [`storage`] holds generic cases for the key-level
//! [`NamespaceStore`](mkit_server::NamespaceStore) contract (its eight
//! normative rules, including the `NotAfter` commit deadline), the
//! [`BlobStore`](mkit_server::BlobStore) contract, the
//! [`ContentIndex`](mkit_server::ContentIndex) layer, cancellation and
//! crash/restart atomicity, and the portable export/import.
//!
//! **This suite is the gate for third-party backends** (PRD §5.3): SQL
//! stores, Durable Objects, and non-SQL single-writer key-value stores such
//! as qmdb alike. A backend passes iff every case that is not skipped
//! passes. A case skips only when the backend's
//! [`StoreCapabilities`](mkit_server::StoreCapabilities) exclude what it
//! tests, and before skipping it checks that the excluded operation returns
//! [`StoreError::Unsupported`](mkit_server::StoreError::Unsupported) and
//! writes nothing; or when the harness cannot build the store the case needs
//! (an injectable clock, a capacity cap, a persistent reopen), which it
//! reports with a reason.
//!
//! A backend implements [`storage::KvHarness`] (and passes any
//! `Fn() -> impl BlobStore` as a blob harness), then invokes
//! [`storage_suite!`] from its `tests/` directory. Each case becomes its
//! own `#[test]`, named `<module>::<case>`, so a failure names the case.
//! A runner that cannot use the macro iterates [`storage::kv_cases`] and
//! [`storage::blob_cases`] instead.
//!
//! ```
//! use std::sync::Arc;
//!
//! use mkit_server::{Clock, MemoryBlobStore, MemoryKv};
//! use mkit_server_conformance::storage::KvHarness;
//!
//! struct Memory;
//!
//! impl KvHarness for Memory {
//!     type Store = MemoryKv;
//!
//!     fn store(&self) -> MemoryKv {
//!         MemoryKv::default()
//!     }
//!
//!     fn store_with_clock(&self, clock: Arc<dyn Clock>) -> Option<MemoryKv> {
//!         Some(MemoryKv::with_clock(clock))
//!     }
//! }
//!
//! mkit_server_conformance::storage_suite!(memory, kv = Memory, blob = MemoryBlobStore::default);
//! # fn main() {}
//! ```

pub mod storage;

#[doc(hidden)]
pub mod __private {
    use core::future::Future;

    pub use mkit_server::BoxFuture;

    use crate::storage::{CaseResult, Outcome};

    /// Run one case to completion on a fresh multi-threaded runtime.
    ///
    /// # Panics
    /// If the case fails, with its message.
    pub fn run(name: &str, case: impl Future<Output = Outcome>) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .build()
            .expect("build a tokio runtime");
        match runtime.block_on(case) {
            Ok(CaseResult::Pass) => {}
            Ok(CaseResult::Skip(reason)) => eprintln!("{name}: skipped: {reason}"),
            Err(message) => panic!("{name} failed: {message}"),
        }
    }
}
