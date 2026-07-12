#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod error;
mod hashutil;
mod pack;
mod refs_convert;
mod service;

/// Generated `mkit.transport.v1` message + Connect service types, compiled
/// directly from the canonical `<repo-root>/proto/mkit/transport/v1/transport.proto`
/// (see `build.rs` — no duplicated proto, matching `mkit-repo-client`'s
/// pattern for `mkit.repo.v1`).
pub mod proto {
    ::connectrpc::include_generated!();
}

pub use error::map_transport_error;
pub use service::TransportServer;

use std::future::Future;
use std::sync::Arc;

use mkit_core::protocol::Transport;
use proto::mkit::transport::v1::TransportServiceExt as _;

/// Build a [`connectrpc::Router`] hosting `mkit.transport.v1.TransportService`
/// over `transport`.
///
/// Combine with other `connectrpc`/axum routes via `Router::merge` before
/// calling [`connectrpc::Router::into_axum_router`], or use [`serve`] for
/// the common single-service case.
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
