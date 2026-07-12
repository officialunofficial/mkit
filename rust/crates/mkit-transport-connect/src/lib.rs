#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
#![doc = include_str!("../README.md")]
//!
//! `mkit.transport.v1.TransportService` (SPEC-TRANSPORT-CONNECT): both
//! halves of the `mkit+https://` remote scheme live in this crate.
//!
//! - **Client** ([`ConnectTransport`]): a non-wasm ConnectRPC client
//!   implementing [`mkit_core::protocol::Transport`] itself, used by
//!   `mkit-cli`'s `remote_dispatch` for `mkit+https://` / loopback
//!   `mkit+http://`. Mandatory — always compiled.
//! - **Server** ([`router`], [`serve`], [`TransportServer`]): an
//!   axum-hosted `TransportService` implementation generic over any
//!   [`mkit_core::protocol::Transport`] backend. This is `mkit serve
//!   --http`'s implementation
//!   (`rust/crates/mkit-cli/src/commands/serve/http.rs`). Behind this
//!   crate's own `server` cargo feature (off by default; `mkit-cli`
//!   enables it via its `http-transport` feature) so a client-only
//!   consumer doesn't pay axum/hyper-server's compile cost.
//!
//! Both are generated from the same canonical
//! `<repo-root>/proto/mkit/transport/v1/transport.proto` (see `build.rs` —
//! no duplicated proto, matching `mkit-repo-client`'s pattern for
//! `mkit.repo.v1`).
//!
//! See [`docs/specs/SPEC-TRANSPORT-CONNECT.md`][spec] for the full wire
//! contract (verb mapping, CAS semantics, error-code mapping, streaming
//! design).
//!
//! [spec]: https://github.com/officialunofficial/mkit/blob/main/docs/specs/SPEC-TRANSPORT-CONNECT.md

mod client;
mod error;
mod executor;
#[cfg(feature = "server")]
mod hashutil;
#[cfg(feature = "server")]
mod pack;
#[cfg(feature = "server")]
mod refs_convert;
#[cfg(feature = "server")]
mod service;

/// Generated `mkit.transport.v1` message + Connect service types, compiled
/// directly from the canonical `<repo-root>/proto/mkit/transport/v1/transport.proto`
/// (see `build.rs` — no duplicated proto, matching `mkit-repo-client`'s
/// pattern for `mkit.repo.v1`).
pub mod proto {
    // `::connectrpc` required: the generated file declares `pub mod
    // connectrpc` inside this module, which would shadow the crate name if
    // relative.
    ::connectrpc::include_generated!();
}

pub use client::{ConnectTransport, DEFAULT_TIMEOUT, TOKEN_ENV};
#[cfg(feature = "server")]
pub use error::map_transport_error;
#[cfg(feature = "server")]
pub use service::TransportServer;

// Re-exported so integration tests (and any future in-tree reference
// server) can build request/response messages and register the generated
// `TransportService` trait without reaching into this crate's private
// `proto` module.
#[doc(hidden)]
pub mod generated {
    pub use crate::proto::mkit::transport::v1::*;
}

#[cfg(feature = "server")]
use std::future::Future;
#[cfg(feature = "server")]
use std::sync::Arc;

#[cfg(feature = "server")]
use mkit_core::protocol::Transport;
#[cfg(feature = "server")]
use proto::mkit::transport::v1::TransportServiceExt as _;

/// Build a [`connectrpc::Router`] hosting `mkit.transport.v1.TransportService`
/// over `transport`.
///
/// Combine with other `connectrpc`/axum routes via `Router::merge` before
/// calling [`connectrpc::Router::into_axum_router`], or use [`serve`] for
/// the common single-service case.
#[cfg(feature = "server")]
#[must_use]
pub fn router<T>(transport: Arc<T>) -> connectrpc::Router
where
    T: Transport + Send + Sync + 'static,
{
    Arc::new(TransportServer::new(transport)).register(connectrpc::Router::new())
}

/// Serve `mkit.transport.v1.TransportService` over `listener`, backed by
/// `transport`, until `shutdown` resolves (then drain in-flight requests
/// and return).
///
/// This is `mkit serve --http`'s implementation
/// (`rust/crates/mkit-cli/src/commands/serve/http.rs`): an axum `Router`
/// whose fallback service is the generated `TransportService` dispatcher,
/// handed to `axum::serve`. Pass `std::future::pending()` for a listener
/// that never shuts down gracefully (the caller's own signal handling, if
/// any, should race this future instead).
///
/// # Errors
///
/// Propagates any I/O error `axum::serve` returns (accept-loop failure).
#[cfg(feature = "server")]
pub async fn serve<T>(
    listener: tokio::net::TcpListener,
    transport: Arc<T>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()>
where
    T: Transport + Send + Sync + 'static,
{
    let app = router(transport).into_axum_router();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
}
