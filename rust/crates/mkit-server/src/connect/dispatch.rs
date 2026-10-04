//! Pre-dispatch wasm protection; never expose the inner service for mutation.
use std::sync::Arc;
use std::task::{Context, Poll};

use connectrpc::{
    CompressionPolicy, CompressionRegistry, ConnectRpcService, DeadlinePolicy, Dispatcher,
    Interceptor, Limits, Router,
};
use tower_service::Service;

/// Connect dispatch with an explicit no-deadline policy on wasm32.
///
/// Both timeout headers are removed before connectrpc parses the request.
/// Configured deadline policies (including defaults and inter-message timers)
/// are ignored: connectrpc uses unsupported std/Tokio clocks for them. Request
/// bodies and all other headers, limits, compression and interceptors pass
/// through unchanged. On native targets this name aliases `ConnectRpcService`.
/// Hosts remain responsible for bounding work with their platform clock.
pub struct ConnectService<D = Router> {
    inner: ConnectRpcService<D>,
}

impl<D> std::fmt::Debug for ConnectService<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectService").finish_non_exhaustive()
    }
}

impl<D> Clone for ConnectService<D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<D: Dispatcher> ConnectService<D> {
    /// Mount a dispatcher with wasm-safe deadline handling.
    pub fn new(dispatcher: D) -> Self {
        Self::from_arc(Arc::new(dispatcher))
    }

    /// Mount a shared dispatcher with wasm-safe deadline handling.
    pub fn from_arc(dispatcher: Arc<D>) -> Self {
        Self {
            inner: ConnectRpcService::from_arc(dispatcher),
        }
    }

    /// Configure request and message limits.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.inner = self.inner.with_limits(limits);
        self
    }

    /// Configure compression algorithms.
    #[must_use]
    pub fn with_compression(mut self, compression: CompressionRegistry) -> Self {
        self.inner = self.inner.with_compression(compression);
        self
    }

    /// Configure response compression.
    #[must_use]
    pub fn with_compression_policy(mut self, policy: CompressionPolicy) -> Self {
        self.inner = self.inner.with_compression_policy(policy);
        self
    }

    /// Ignored on wasm32, including default and inter-message timeouts.
    /// Native targets apply connectrpc's deadline policy unchanged.
    #[must_use]
    pub fn with_deadline_policy(self, _policy: DeadlinePolicy) -> Self {
        self
    }

    /// The effective policy, always unset on wasm32.
    #[must_use]
    pub fn deadline_policy(&self) -> &DeadlinePolicy {
        self.inner.deadline_policy()
    }

    /// Append an interceptor after mkit's auth interceptor, if present.
    #[must_use]
    pub fn with_interceptor(self, interceptor: impl Interceptor) -> Self {
        self.with_interceptor_arc(Arc::new(interceptor))
    }

    /// Append a shared interceptor.
    #[must_use]
    pub fn with_interceptor_arc(mut self, interceptor: Arc<dyn Interceptor>) -> Self {
        self.inner = self.inner.with_interceptor_arc(interceptor);
        self
    }

    /// The effective request limits.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        self.inner.limits()
    }

    /// The mounted dispatcher.
    #[must_use]
    pub fn dispatcher(&self) -> &D {
        self.inner.dispatcher()
    }
}

impl<D, B> Service<http::Request<B>> for ConnectService<D>
where
    ConnectRpcService<D>: Service<http::Request<B>>,
{
    type Response = <ConnectRpcService<D> as Service<http::Request<B>>>::Response;
    type Error = <ConnectRpcService<D> as Service<http::Request<B>>>::Error;
    type Future = <ConnectRpcService<D> as Service<http::Request<B>>>::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        req.headers_mut().remove("connect-timeout-ms");
        req.headers_mut().remove("grpc-timeout");
        self.inner.call(req)
    }
}
