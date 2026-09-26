//! The `mkit.transport.v1` Connect binding (feature `connect`,
//! SPEC-TRANSPORT-CONNECT): [`service`] mounts `TransportService` and
//! `grpc.health.v1.Health` over a [`Pipeline`], behind the
//! [`AuthInterceptor`]. It is runtime-agnostic and wasm-clean (connectrpc
//! without its `server` and `zstd` features), so the native adapter serves
//! it through axum and the Workers adapter through its fetch bridge, both
//! unchanged.
//!
//! Every RPC runs pipeline stage 0 in the interceptor, which sees the exact
//! unary request bytes (the auth v2 body commitment), and hands the
//! handler an [`Authenticated`] bound to the procedure called. A handler
//! decodes its message with the shared wire helpers ([`crate::refs`],
//! [`crate::upload`]), calls one pipeline entry point inside
//! [`crate::send_wrap`] and encodes the answer. Errors cross the wire only
//! through `From<ServerError> for ConnectError`: public message, code,
//! HTTP status, response headers and typed details.
//!
//! `grpc.health.v1.Health` is not authenticated: `Check` reports whether
//! both stores answer their probe (`SERVING` or `NOT_SERVING`), for load
//! balancers and kubelet probes.
//!
//! A `connect-timeout-ms` header makes connectrpc compute a deadline with
//! `Instant::now()`, which panics on wasm32. The Workers adapter strips the
//! header before dispatch (`mkit_worker_common::adapter::is_deadline_header`);
//! this binding does not.
//!
//! An upload is read message by message and stops at the `last` chunk.
//! connectrpc 0.9.1 then drains at most 1 MiB (and, natively, 5 s) more of
//! the request body before it resets the stream (RUSTSEC-2026-0304), so a
//! client cannot hold the handler open with trailing bytes.

mod error;
mod health;
mod interceptor;
mod service;

use std::sync::Arc;

use connectrpc::{ConnectRpcService, Router};

pub use error::from_upload_error;
pub use health::ConnectHealth;
pub use interceptor::AuthInterceptor;
pub use service::ConnectTransport;

use crate::pipeline::{Authenticated, HookSet, Pipeline};
use crate::store::{BlobStore, NamespaceStore};

/// The generated `mkit.transport.v1` and `grpc.health.v1` messages and
/// service traits, vendored under `generated/` (refresh with
/// `scripts/regen-transport-proto.sh`).
// Generated code: the workspace's pedantic and Debug lints do not apply.
#[allow(missing_debug_implementations, clippy::all, clippy::pedantic)]
pub mod proto {
    // `::connectrpc`: the generated code declares its own `connectrpc`
    // module, which would shadow a relative path.
    ::connectrpc::include_generated!();
}

/// `TransportService` and `Health` over `pipeline`, without the
/// interceptor: every authenticated transport RPC then fails
/// `unauthenticated`; the M1 stub RPCs answer `unimplemented`. Mount
/// [`service`] unless another layer installs [`AuthInterceptor`].
pub fn router<B, N, H>(pipeline: Arc<Pipeline<B, N, H>>) -> Router
where
    B: BlobStore + 'static,
    N: NamespaceStore + 'static,
    H: HookSet + 'static,
{
    use proto::grpc::health::v1::HealthExt;
    use proto::mkit::transport::v1::TransportServiceExt;

    let router = Arc::new(ConnectTransport::new(pipeline.clone())).register(Router::new());
    Arc::new(ConnectHealth::new(pipeline)).register(router)
}

/// [`router`] behind [`AuthInterceptor`]: what an adapter mounts. Apply
/// deployment limits with `ConnectRpcService::with_limits`.
pub fn service<B, N, H>(pipeline: Arc<Pipeline<B, N, H>>) -> ConnectRpcService
where
    B: BlobStore + 'static,
    N: NamespaceStore + 'static,
    H: HookSet + 'static,
{
    ConnectRpcService::new(router(pipeline.clone()))
        .with_interceptor(AuthInterceptor::new(pipeline))
}

/// The pipeline as connectrpc's `Send + Sync` service objects hold it: an
/// `Arc` on native targets. On wasm32 the pipeline is `!Send` (Workers
/// handles are), so the `Arc` sits in a `SendWrapper`: Workers run
/// single-threaded, and a use on another thread panics, never undefined
/// behavior.
struct Shared<P> {
    #[cfg(not(target_arch = "wasm32"))]
    pipe: Arc<P>,
    #[cfg(target_arch = "wasm32")]
    pipe: send_wrapper::SendWrapper<Arc<P>>,
}

impl<P> Shared<P> {
    fn new(pipe: Arc<P>) -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            pipe,
            #[cfg(target_arch = "wasm32")]
            pipe: send_wrapper::SendWrapper::new(pipe),
        }
    }

    fn get(&self) -> &P {
        &self.pipe
    }

    /// An owned handle, to move into a [`crate::send_wrap`]ped future.
    fn arc(&self) -> Arc<P> {
        // On wasm32 this derefs the `SendWrapper` (its thread check).
        let pipe: &Arc<P> = &self.pipe;
        Arc::clone(pipe)
    }
}

/// The [`Authenticated`] the interceptor stored for this request.
fn authenticated(ctx: &connectrpc::RequestContext) -> Result<Authenticated, crate::ServerError> {
    ctx.extensions()
        .get::<Authenticated>()
        .cloned()
        .ok_or_else(|| crate::ServerError::unauthenticated("missing authorization"))
}
