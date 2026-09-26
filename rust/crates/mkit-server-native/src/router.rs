//! The embeddable axum router: `mkit.transport.v1` and
//! `grpc.health.v1.Health` over a [`Pipeline`], behind the production
//! tower layers.

use std::sync::Arc;
use std::time::Duration;

use http::{HeaderName, HeaderValue};
use mkit_server::pipeline::{AuthMode, HookSet, Pipeline};
use mkit_server::{BlobStore, NamespaceStore, Procedure, Redactor};

use crate::layers;

/// Who may call the server from a browser.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CorsPolicy {
    /// No CORS headers; browsers refuse cross-origin calls.
    #[default]
    Disabled,
    /// These origins only (each a canonical `scheme://host[:port]`).
    AllowOrigins(Vec<HeaderValue>),
    /// Any origin (`Access-Control-Allow-Origin: *`), as `vcs-worker`.
    AllowAny,
}

/// The router's production settings. [`RouterOptions::default`] holds the
/// `mkit-server serve` defaults.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RouterOptions {
    /// Deadline of a unary RPC (and of health), from the first request
    /// byte to the response. A client's `Connect-Timeout-Ms` may shorten
    /// it, never extend it.
    pub unary_timeout: Duration,
    /// Deadline of `UploadPack` and `DownloadPack`, covering the whole
    /// stream.
    pub stream_timeout: Duration,
    /// Requests in flight at once, counted until each response body ends
    /// (a streamed `DownloadPack` holds its slot while it streams). Keep it
    /// below tokio's blocking-pool size (512 by default): every store call
    /// runs there.
    pub max_concurrency: usize,
    /// How long a request waits for a slot before it is shed with HTTP 503
    /// and Connect `unavailable`. Zero sheds at once.
    pub queue_timeout: Duration,
    /// Largest request body on the wire; a larger `Content-Length` is
    /// refused `413` before any handler runs, and a body that grows past it
    /// fails mid-stream. See [`layers::body_limit_for`].
    pub max_body_bytes: u64,
    /// Cross-origin access.
    pub cors: CorsPolicy,
    /// Extra CORS request headers (reconciliation R-15). M0 passes none; M3
    /// (WP-3.4) adds the payment request headers.
    pub cors_extra_allow_headers: Vec<HeaderName>,
    /// Response headers exposed to browsers. M0 passes none; M3 exposes
    /// `WWW-Authenticate`, `Payment-Receipt` and `PAYMENT-*`.
    pub cors_expose_headers: Vec<HeaderName>,
    /// Headers whose values never reach a trace: [`mkit_server::NEVER_LOG`]
    /// plus the deployment's extras.
    pub redactor: Redactor,
}

impl Default for RouterOptions {
    fn default() -> Self {
        Self {
            unary_timeout: Duration::from_secs(30),
            stream_timeout: Duration::from_hours(1),
            max_concurrency: 256,
            queue_timeout: Duration::from_secs(5),
            max_body_bytes: layers::body_limit_for(mkit_core::protocol::PACK_BODY_LIMIT),
            cors: CorsPolicy::Disabled,
            cors_extra_allow_headers: Vec::new(),
            cors_expose_headers: Vec::new(),
            redactor: Redactor::default(),
        }
    }
}

/// The streaming procedures, which get [`RouterOptions::stream_timeout`].
const STREAMING: [Procedure; 2] = [Procedure::UploadPack, Procedure::DownloadPack];

/// The mkit server as an [`axum::Router`]: `mkit_server::connect::service`
/// (the `mkit.transport.v1` Connect binding and `grpc.health.v1.Health`,
/// behind `AuthInterceptor`) over `pipeline`, with the layers `opts`
/// describes. From the outside in: CORS (a preflight is answered here,
/// without auth), header redaction, tracing, the bearer pre-check (a
/// [`AuthMode::Bearer`] pipeline: a request without the token is refused
/// from its headers, before it takes a slot), the concurrency cap, the
/// body limit, then the per-procedure deadline.
///
/// Mountable in an implementer's own axum app (PRD §5.1). The Connect
/// service is the router's fallback, so either make this router the base
/// and add routes to it, or mount it as the app's fallback:
///
/// ```no_run
/// # use std::sync::Arc;
/// # use mkit_server::pipeline::{Hooks, Pipeline};
/// # use mkit_server::{MemoryBlobStore, MemoryKv};
/// # fn demo(pipeline: Arc<Pipeline<MemoryBlobStore, MemoryKv, Hooks>>) {
/// use mkit_server_native::{RouterOptions, build_router};
///
/// let mkit = build_router(pipeline, &RouterOptions::default());
/// let app: axum::Router = axum::Router::new()
///     .route("/status", axum::routing::get(|| async { "ok" }))
///     .fallback_service(mkit);
/// # let _ = app;
/// # }
/// ```
///
/// A timeout answers Connect `deadline_exceeded`. The router does not
/// terminate TLS: put a reverse proxy in front.
pub fn build_router<B, N, H>(pipeline: Arc<Pipeline<B, N, H>>, opts: &RouterOptions) -> axum::Router
where
    B: BlobStore + 'static,
    N: NamespaceStore + 'static,
    H: HookSet + 'static,
{
    let bearer = match pipeline.auth_mode() {
        AuthMode::Bearer { token } => Some(token.expose().to_owned()),
        _ => None,
    };
    let unary = mkit_server::connect::service(Arc::clone(&pipeline))
        .with_deadline_policy(layers::deadline_policy(opts.unary_timeout, false));
    let streaming = mkit_server::connect::service(pipeline)
        .with_deadline_policy(layers::deadline_policy(opts.stream_timeout, true));
    let router = STREAMING
        .iter()
        .fold(axum::Router::new(), |router, procedure| {
            router.route_service(procedure.connect_path(), streaming.clone())
        })
        .fallback_service(unary);
    layers::apply(router, opts, bearer.as_deref())
}
