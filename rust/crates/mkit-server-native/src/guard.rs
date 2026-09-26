//! The router's admission layers: the concurrency cap, whose permit lives
//! as long as the response body, and the bearer pre-check that keeps
//! unauthenticated requests from taking a permit.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use bytes::Bytes;
use http::{HeaderValue, Request, Response, StatusCode, header};
use http_body::{Body as HttpBody, Frame, SizeHint};
use mkit_core::hash::hash;
use subtle::ConstantTimeEq as _;
use tokio::sync::Semaphore;
use tower::{Layer, Service, ServiceExt as _};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// A Connect error response with `status`, as JSON (the Connect unary
/// error shape; a gRPC client maps the HTTP status).
fn connect_error(status: StatusCode, code: &str, message: &str) -> Response<Body> {
    let body = format!(r#"{{"code":"{code}","message":"{message}"}}"#);
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

/// The answer when no permit frees up within the queue timeout: HTTP 503
/// with `Retry-After`, Connect code `unavailable` (503 in both the Connect
/// and gRPC mappings, so every client reads the same retryable status).
fn overloaded() -> Response<Body> {
    let mut resp = connect_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "unavailable",
        "server busy; retry",
    );
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    resp
}

/// A response body that holds `T` (a concurrency permit, a connection's
/// activity guard) until it ends or is dropped: a streamed `DownloadPack`
/// keeps its slot for as long as it streams.
pub(crate) struct HoldBody<T> {
    inner: Body,
    hold: Option<T>,
}

impl<T> HoldBody<T> {
    pub(crate) fn wrap(inner: Body, hold: T) -> Body
    where
        T: Send + Unpin + 'static,
    {
        Body::new(Self {
            inner,
            hold: Some(hold),
        })
    }
}

impl<T: Unpin> HttpBody for HoldBody<T> {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let this = &mut *self;
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        if let Poll::Ready(None) = polled {
            // Done: release before the connection finishes up.
            this.hold = None;
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Caps requests in flight across every route: a request waits at most
/// `queue_timeout` for a permit (then [`overloaded`]), and its permit is
/// released only when its response body finishes or is dropped.
#[derive(Debug, Clone)]
pub(crate) struct CapLayer {
    permits: Arc<Semaphore>,
    queue_timeout: Duration,
}

impl CapLayer {
    pub(crate) fn new(max: usize, queue_timeout: Duration) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(max)),
            queue_timeout,
        }
    }
}

impl<S> Layer<S> for CapLayer {
    type Service = Cap<S>;

    fn layer(&self, inner: S) -> Cap<S> {
        Cap {
            inner,
            layer: self.clone(),
        }
    }
}

/// See [`CapLayer`].
#[derive(Debug, Clone)]
pub(crate) struct Cap<S> {
    inner: S,
    layer: CapLayer,
}

impl<S> Service<Request<Body>> for Cap<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<Result<Response<Body>, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let inner = self.inner.clone();
        let CapLayer {
            permits,
            queue_timeout,
        } = self.layer.clone();
        Box::pin(async move {
            // A timeout, or a closed semaphore (never: the layer owns it).
            let Ok(Ok(permit)) = tokio::time::timeout(queue_timeout, permits.acquire_owned()).await
            else {
                tracing::warn!("concurrency cap: no slot within the queue timeout; shed");
                return Ok(overloaded());
            };
            let resp = inner.oneshot(req).await?;
            Ok(resp.map(|inner| HoldBody::wrap(inner, permit)))
        })
    }
}

/// The transport paths a bearer deployment guards; health stays open.
fn guarded(path: &str) -> bool {
    !path.starts_with("/grpc.health.v1.Health/")
}

/// In bearer mode, checks `Authorization: Bearer <token>` from the headers
/// alone, before the request takes a concurrency permit or has its body
/// read: an unauthenticated caller costs no slot. The pipeline's
/// interceptor checks again (defense in depth). The digests of the
/// presented and expected values are compared in constant time.
#[derive(Clone)]
pub(crate) struct BearerGateLayer {
    expected: Arc<[u8; 32]>,
}

impl std::fmt::Debug for BearerGateLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BearerGateLayer").finish_non_exhaustive()
    }
}

impl BearerGateLayer {
    pub(crate) fn new(token: &str) -> Self {
        Self {
            expected: Arc::new(hash(format!("Bearer {token}").as_bytes())),
        }
    }
}

impl<S> Layer<S> for BearerGateLayer {
    type Service = BearerGate<S>;

    fn layer(&self, inner: S) -> BearerGate<S> {
        BearerGate {
            inner,
            expected: Arc::clone(&self.expected),
        }
    }
}

/// See [`BearerGateLayer`].
#[derive(Clone)]
pub(crate) struct BearerGate<S> {
    inner: S,
    expected: Arc<[u8; 32]>,
}

impl<S> Service<Request<Body>> for BearerGate<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<Result<Response<Body>, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let presented = req
            .headers()
            .get(header::AUTHORIZATION)
            .map_or(&[][..], HeaderValue::as_bytes);
        let ok = bool::from(hash(presented).ct_eq(&*self.expected));
        if ok || !guarded(req.uri().path()) {
            let inner = self.inner.clone();
            return Box::pin(inner.oneshot(req));
        }
        Box::pin(async {
            Ok(connect_error(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "missing or invalid Authorization: Bearer <token>",
            ))
        })
    }
}
