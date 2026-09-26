#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
// `worker::Error` is large; the Workers glue returns it as vcs-worker does.
#![allow(clippy::result_large_err)]
//! The Cloudflare Workers adapter of the mkit server (PRD MKIT-29 §5.1),
//! storage half.
//!
//! - [`r2`]: [`R2BlobStore`], a content-addressed [`BlobStore`] that
//!   streams both ways. A put is spawned at `begin` and fed through a
//!   depth-1 channel; its final chunk is withheld until the BLAKE3 of every
//!   byte equals the key, so a blob becomes visible only if it verifies.
//! - [`do_sql`]: the Durable Object `SQLite` [`SqlConn`], so each Durable
//!   Object runs the same `SqlKvStore` as the native server.
//! - [`ns_object`]: the Durable Object side of the key-level contract: a
//!   pure key-value store behind a JSON request, no pipeline logic.
//! - [`ns_client`]: [`DoNamespaceStore`], the Worker-side
//!   [`NamespaceStore`] that routes each [`Partition`] to its own Durable
//!   Object ([`naming`]).
//! - [`wire`]: the JSON between the two; [`clock`]: the Worker clock.
//! - [`adapter`]: what a deployment's `#[event(fetch)]` and
//!   `#[durable_object]` call: the pipeline's Connect binding over these
//!   stores, streaming both bodies.
//! - [`alarm`]: pure alarm choices; `NsObject::alarm` fires due timers and
//!   sets the object's one alarm to the next partition wake.
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

pub mod adapter;
pub mod alarm;
pub mod clock;
pub mod do_sql;
#[cfg(feature = "test-faults")]
pub mod faults;
pub mod naming;
pub mod ns_client;
pub mod ns_object;
pub mod r2;
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
            include_str!("wire.rs"),
            include_str!("faults.rs"),
        ];
        // Case-sensitive: prose may say "commit" or "pragma".
        for word in forbidden() {
            for source in sources {
                assert!(!source.contains(&word), "{word} in the crate");
            }
        }
    }
}
