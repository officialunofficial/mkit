#![forbid(unsafe_code)]
// Cases take their harness by value so every case future is `'static`.
#![allow(clippy::needless_pass_by_value)]
//! Portable conformance for any implementation of the mkit protocol.
//!
//! [`wire`] is Tier 1 (ordinary HTTP); [`controlled`] is Tier 2 (versioned
//! test controls and typed atomic observations). Neither surface requires
//! reference-server types. Both run against a base URL and wire profile.
//!
//! Enable `storage-spi` for the optional reference storage adapter suite,
//! `storage_suite!` macro, and its declared-skip harness. Other server
//! implementations do not need that feature or a dependency on mkit-server.
//! `test-host` adds a debug-only reference host. The standalone test utility
//! additionally enables `reference-runner` for optimized installation.

pub mod control;
pub mod controlled;
mod controlled_fork;
mod controlled_pack_locations;
mod controlled_publication;
mod controlled_reliance;
pub mod differential;
#[cfg(feature = "storage-spi")]
mod reference_support;
pub mod runner;
#[cfg(feature = "storage-spi")]
pub mod storage;
#[cfg(feature = "stubs")]
pub mod stubs;
/// A loopback host for external contract tests. Available only with the
/// `test-host` feature and debug assertions, or the explicit standalone
/// `reference-runner` test utility feature.
#[cfg(all(
    feature = "test-host",
    any(debug_assertions, feature = "reference-runner")
))]
pub mod test_host;
pub mod wire;

#[cfg(all(
    feature = "test-host",
    not(debug_assertions),
    not(feature = "reference-runner")
))]
compile_error!(
    "optimized test-host builds require the standalone reference-runner test utility feature"
);

#[doc(hidden)]
#[cfg(feature = "storage-spi")]
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

#[cfg(feature = "test-host")]
mod test_host_admin;
