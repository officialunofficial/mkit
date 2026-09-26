#![forbid(unsafe_code)]
// Cases take their harness by value so every case future is `'static`.
#![allow(clippy::needless_pass_by_value)]
//! Conformance suites for `mkit-server` storage backends and for
//! `mkit.transport.v1` servers (PRD §5.1, §5.3).
//!
//! [`wire`] is the black-box wire suite: it drives any server over HTTP
//! from a base URL and a profile, and ships as the
//! `mkit-server-conformance wire` binary. The rest of this page is about
//! the storage suite.
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
//! passes and every skip is declared. A case skips only when the backend's
//! [`StoreCapabilities`](mkit_server::StoreCapabilities) exclude what it
//! tests, and before skipping it checks that the excluded operation returns
//! [`StoreError::Unsupported`](mkit_server::StoreError::Unsupported) and
//! writes nothing; or when the harness cannot build the store the case needs
//! (an injectable clock, a capacity cap, a persistent reopen), which it
//! reports with a reason. The harness declares its skips
//! ([`storage::KvHarness::expected_skips`]): an undeclared skip fails, and
//! so does a declared case that passes.
//!
//! A backend implements [`storage::KvHarness`] (and passes any
//! `Fn() -> impl BlobStore` as a blob harness), then invokes
//! [`storage_suite!`] from its `tests/` directory. Each case becomes its
//! own `#[test]`, named `<module>::<case>`, so a failure names the case.
//! A runner that cannot use the macro iterates [`storage::kv_cases`] and
//! [`storage::blob_cases`] instead, on any executor (the case futures need
//! no particular runtime), and judges each with [`storage::verdict`].
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
//!
//!     // No capacity cap and no persistent reopen: those cases skip.
//!     fn expected_skips(&self) -> &'static [&'static str] {
//!         &[
//!             "kv_full_store_rejects_writes_but_serves_reads_and_deletes",
//!             "dur_crash_restart_atomic_at_last_commit",
//!         ]
//!     }
//! }
//!
//! mkit_server_conformance::storage_suite!(memory, kv = Memory, blob = MemoryBlobStore::default);
//! # fn main() {}
//! ```

#[cfg(feature = "fake-s3")]
pub mod fake_s3;
pub mod storage;
pub mod wire;

#[doc(hidden)]
pub mod __private {
    use core::future::Future;

    pub use mkit_server::BoxFuture;

    use crate::storage::{self, CaseResult, KvHarness, Outcome};

    /// Run one case to completion on a fresh multi-threaded runtime, with
    /// its I/O and timer drivers on (a network backend, such as an S3
    /// client, needs them).
    ///
    /// # Panics
    /// If the case fails, skips without being declared, or passes though
    /// declared as a skip.
    pub fn run(name: &str, declared: &[&str], case: impl Future<Output = Outcome>) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(4)
            .build()
            .expect("build a tokio runtime");
        let outcome = runtime.block_on(case);
        if let Ok(CaseResult::Skip(reason)) = &outcome {
            eprintln!("{name}: skipped (declared): {reason}");
        }
        if let Err(message) = storage::verdict(name, declared, outcome) {
            panic!("{message}");
        }
    }

    /// The skips a kv harness declares.
    pub fn kv_skips<H: KvHarness>(harness: &H) -> &'static [&'static str] {
        harness.expected_skips()
    }

    /// Blob cases never skip.
    pub fn no_skips<H>(_harness: &H) -> &'static [&'static str] {
        &[]
    }

    /// Fail unless every skip `harness` declares names a case.
    ///
    /// # Panics
    /// On a declared name that is not a case.
    pub fn check_declared<H: KvHarness>(harness: &H) {
        if let Err(message) = storage::check_declared_skips(harness) {
            panic!("{message}");
        }
    }
}
