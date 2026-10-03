#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
// `worker::Error` is large; the Workers glue returns it as vcs-worker does.
#![allow(clippy::result_large_err)]
//! The Cloudflare Workers adapter of the mkit server (production server design §5.1),
//! storage half.
//!
//! - [`r2`]: [`R2BlobStore`], a content-addressed [`BlobStore`] that
//!   streams both ways. A put is spawned at `begin` and fed through a
//!   depth-1 channel; its final chunk is withheld until the BLAKE3 of every
//!   byte equals the key, so a blob becomes visible only if it verifies.
//! - [`do_sql`]: the Durable Object `SQLite` [`SqlConn`], so each Durable
//!   Object runs the same `SqlKvStore` as any other `SqlConn` host.
//! - [`ns_object`]: the Durable Object side of the key-level contract: a
//!   pure key-value store behind a JSON request, no pipeline logic.
//! - [`ns_client`]: [`DoNamespaceStore`], the Worker-side
//!   [`NamespaceStore`] that routes each [`Partition`] to its own Durable
//!   Object ([`naming`]).
//! - [`wire`]: the JSON between the two; [`clock`]: the Worker clock;
//!   [`sleep`]: the Worker sleep behind the kind-8 sink timeout.
//! - [`adapter`]: what a deployment's `#[event(fetch)]` and
//!   `#[durable_object]` call: the pipeline's Connect binding over these
//!   stores, streaming both bodies.
//! - [`hooks`]: remote hooks over a service binding (WP-3.9): `BindingChannel`,
//!   the `HOOK_ROLES` vars, and the hooks and kind-8 sink they build.
//! - [`alarm`]: pure alarm choices; `NsObject::alarm` fires due timers and
//!   sets the object's one alarm to the next partition wake.
//!
//! `NAMESPACE_LOCATION_HINT` and `NAMESPACE_JURISDICTION` apply deployment-wide,
//! defaulting to none. Jurisdiction is fixed for the deployment lifetime:
//! changing it re-maps every object name to new, empty objects.
//!
//! # Embedding (supported, 0.x)
//! `adapter::serve_with` accepts constructed streaming requests and a custom
//! `HookSet`; `adapter::fetch_with` parses the environment first. Configure the
//! same `adapter::WorkerConfig` on fetch and `embedding::NsObjectBuilder` to
//! combine snapshots, custom outcome delivery and `embedding::PurgeHooks`.
//! `durable_objects!` generates all five DO exports for these factories.
//! Host-routed operators use `adapter::serve_admin_with` with `ADMIN_KEYS`;
//! `WorkerConfig::admin_on_public_path` disables the public mount.
//! Programmatic ref rules and takedown denial are validated before serving.
//! The signed audience is the exact public origin, regardless of a constructed
//! request's URL. Dispatch shares the host isolate's resource budgets.
//! Breaking 0.x changes are called out in CHANGELOG; this unpublished crate
//! is consumed as a git dependency pinned to the release tag.
//!
//! Everything that touches a `worker` handle is compiled for `wasm32`
//! only. The logic around it is generic over small backend traits
//! ([`r2::ObjectBucket`], [`ns_client::NsTransport`]) and tested on the
//! host against simulated R2 and Durable Object backends, through the
//! `mkit-server-conformance` storage suite.
//!
//! The fetch adapter strips `connect-timeout-ms` and `grpc-timeout` before
//! Connect dispatch (`mkit_worker_common::adapter::is_deadline_header`):
//! connectrpc turns them into a deadline with `Instant::now()`, which
//! panics on wasm32.
//!
//! [`BlobStore`]: mkit_server::BlobStore
//! [`NamespaceStore`]: mkit_server::NamespaceStore
//! [`Partition`]: mkit_server::Partition
//! [`SqlConn`]: mkit_server::sql::SqlConn
//! [`R2BlobStore`]: r2::R2BlobStore
//! [`DoNamespaceStore`]: ns_client::DoNamespaceStore

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../tests/common/sqlite.rs"]
mod test_sqlite;

pub mod adapter;
pub mod admin;
pub mod alarm;
pub mod backup;
pub mod classes;
pub mod clock;
pub mod do_sql;
pub mod durable_objects;
pub mod embedding;
#[cfg(feature = "test-faults")]
pub mod faults;
pub mod hooks;
#[cfg(feature = "http-objects")]
pub mod http_mount;
pub mod launch;
pub mod naming;
pub mod ns_client;
pub mod ns_object;
pub mod purge;
pub mod r2;
pub mod scanner_retrieval;
pub mod sharding_guard;
pub mod sleep;
pub mod telemetry;
pub mod verify;
pub mod wire;

use mkit_server::StoreError;
use mkit_server::storage_error::{StorageOp, describe_and_map};

/// A backend failure: log its detail server-side (issue #794) and return
/// an `Unavailable` whose text is `op`'s fixed public message.
pub(crate) fn backend_error(op: StorageOp, detail: impl core::fmt::Display) -> StoreError {
    let (line, err) = describe_and_map(op, detail);
    log_failure(&line);
    StoreError::unavailable(err)
}

/// Write a storage-failure line to the server-side log.
pub(crate) fn log_failure(line: &str) {
    #[cfg(target_arch = "wasm32")]
    worker::console_error!("{line}");
    #[cfg(not(target_arch = "wasm32"))]
    tracing::warn!(detail = %line, "storage failure");
}

#[cfg(test)]
mod tests {
    /// Transaction-control keywords, assembled so this file never holds
    /// them.
    fn forbidden() -> Vec<String> {
        [
            ["BEG", "IN"],
            ["COM", "MIT"],
            ["ROLL", "BACK"],
            ["SAVE", "POINT"],
            ["PRAG", "MA"],
            ["VAC", "UUM"],
        ]
        .iter()
        .map(|parts| parts.concat())
        .collect()
    }

    /// The crate never issues SQL of its own that a Durable Object rejects:
    /// atomicity is `transactionSync`, every statement is `SqlKvStore`'s.
    #[test]
    fn no_transaction_control_or_pragma_in_the_crate() {
        let sources = [
            include_str!("lib.rs"),
            include_str!("adapter.rs"),
            include_str!("clock.rs"),
            include_str!("do_sql.rs"),
            include_str!("naming.rs"),
            include_str!("ns_client.rs"),
            include_str!("ns_object.rs"),
            include_str!("r2.rs"),
            include_str!("sleep.rs"),
            include_str!("wire.rs"),
            include_str!("faults.rs"),
            include_str!("hooks/binding.rs"),
            include_str!("hooks/build.rs"),
            include_str!("hooks/config.rs"),
        ];
        // Case-sensitive: prose may say "commit" or "pragma".
        for word in forbidden() {
            for source in sources {
                assert!(!source.contains(&word), "{word} in the crate");
            }
        }
    }
}

#[cfg(test)]
#[path = "../tests/fixtures/stored_v050.rs"]
mod stored_golden;
