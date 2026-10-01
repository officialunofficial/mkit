//! Conservative retry for unary RPCs on stale pooled HTTP/1 connections.
use connectrpc::{
    ConnectError,
    client::{ClientBody, ClientTransport, full_body},
};
use futures::future::BoxFuture;
use http::{Request, Response, Uri};
use http_body_util::BodyExt as _;
use hyper_util::client::legacy::{
    Client,
    connect::{Connected, Connection, HttpConnector, capture_connection},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tower_service::Service;
type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Registry = Arc<Mutex<Vec<Weak<Meter>>>>;
#[derive(Default)]
struct Meter {
    received: AtomicU64,
    responses: AtomicU64,
}
#[derive(Clone)]
struct MeterRef(Arc<Meter>);
pin_project_lite::pin_project! { struct MeterIo<T> { #[pin] inner: TokioIo<T>, meter: Arc<Meter> } }
impl<T: hyper::rt::Read + hyper::rt::Write> AsyncRead for MeterIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        let before = buf.filled().len();
        let result = this.inner.poll_read(cx, buf);
        this.meter
            .received
            .fetch_add((buf.filled().len() - before) as u64, Ordering::SeqCst);
        result
    }
}
impl<T: hyper::rt::Read + hyper::rt::Write> AsyncWrite for MeterIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write_vectored(cx, bytes)
    }
}
impl<T: Connection> Connection for MeterIo<T> {
    fn connected(&self) -> Connected {
        self.inner
            .inner()
            .connected()
            .extra(MeterRef(self.meter.clone()))
    }
}
#[derive(Clone)]
struct MeterConnector<C> {
    inner: C,
    registry: Registry,
}
impl<C> Service<Uri> for MeterConnector<C>
where
    C: Service<Uri> + Clone + Send + 'static,
    C::Response: hyper::rt::Read + hyper::rt::Write + Connection + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    C::Future: Send + 'static,
{
    type Response = TokioIo<MeterIo<C::Response>>;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, BoxError>>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }
    fn call(&mut self, uri: Uri) -> Self::Future {
        let future = self.inner.call(uri);
        let registry = self.registry.clone();
        Box::pin(async move {
            let stream =
                tokio::time::timeout(connectrpc::client::DEFAULT_ESTABLISHMENT_TIMEOUT, future)
                    .await
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "connection establishment timed out",
                        )
                    })?
                    .map_err(Into::into)?;
            let meter = Arc::new(Meter::default());
            let mut live = registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            live.retain(|entry| entry.strong_count() > 0);
            live.push(Arc::downgrade(&meter));
            drop(live);
            Ok(TokioIo::new(MeterIo {
                inner: TokioIo::new(stream),
                meter,
            }))
        })
    }
}
#[derive(Clone)]
enum Pool {
    Plain(Client<MeterConnector<HttpConnector>, ClientBody>),
    Tls(Client<MeterConnector<hyper_rustls::HttpsConnector<HttpConnector>>, ClientBody>),
}
/// Native HTTP transport that retries a replay-safe unary RPC once, on a fresh
/// connection, only when a previously used HTTP/1 socket receives zero bytes.
/// It never retries streaming RPCs, partial responses, or unsigned writes.
#[derive(Clone)]
pub struct PooledHttpClient {
    pool: Pool,
    registry: Registry,
    tls: Option<Arc<rustls::ClientConfig>>,
}
impl PooledHttpClient {
    /// Build a plaintext-only transport with the standard connect bounds.
    #[must_use]
    pub fn plaintext() -> Self {
        Self::new(None)
    }
    /// Build an HTTPS-only transport preserving the supplied TLS configuration.
    #[must_use]
    pub fn with_tls(config: Arc<rustls::ClientConfig>) -> Self {
        Self::new(Some(config))
    }
    fn new(tls: Option<Arc<rustls::ClientConfig>>) -> Self {
        let registry = Registry::default();
        let mut http = HttpConnector::new();
        http.set_nodelay(true);
        http.set_connect_timeout(Some(connectrpc::client::DEFAULT_TCP_CONNECT_TIMEOUT));
        let mut builder = Client::builder(TokioExecutor::new());
        builder.retry_canceled_requests(false);
        let pool = if let Some(config) = &tls {
            http.enforce_http(false);
            let mut config = (**config).clone();
            config.alpn_protocols.clear();
            let https = hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(config)
                .https_only()
                .enable_all_versions()
                .wrap_connector(http);
            Pool::Tls(builder.build(MeterConnector {
                inner: https,
                registry: registry.clone(),
            }))
        } else {
            Pool::Plain(builder.build(MeterConnector {
                inner: http,
                registry: registry.clone(),
            }))
        };
        Self {
            pool,
            registry,
            tls,
        }
    }
    fn snapshot(&self) -> Vec<(Arc<Meter>, u64)> {
        let mut live = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        live.retain(|entry| entry.strong_count() > 0);
        live.iter()
            .filter_map(Weak::upgrade)
            .filter(|m| m.responses.load(Ordering::SeqCst) > 0)
            .map(|m| {
                let bytes = m.received.load(Ordering::SeqCst);
                (m, bytes)
            })
            .collect()
    }
    async fn exchange(
        &self,
        mut request: Request<ClientBody>,
    ) -> Result<Response<hyper::body::Incoming>, hyper_util::client::legacy::Error> {
        let captured = capture_connection(&mut request);
        let response = match &self.pool {
            Pool::Plain(c) => c.request(request).await,
            Pool::Tls(c) => c.request(request).await,
        };
        if response.is_ok()
            && let Some(info) = captured.connection_metadata().as_ref()
        {
            let mut extras = http::Extensions::new();
            info.get_extras(&mut extras);
            if let Some(m) = extras.get::<MeterRef>() {
                m.0.responses.fetch_add(1, Ordering::SeqCst);
            }
        }
        response
    }
}
fn replay_safe(request: &Request<ClientBody>) -> bool {
    let unary = request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| matches!(h, "application/proto" | "application/json"));
    if !unary {
        return false;
    }
    let Some(method) = request
        .uri()
        .path()
        .strip_prefix("/mkit.transport.v1.TransportService/")
    else {
        return false;
    };
    match method {
        "GetServerInfo"
        | "ReadRef"
        | "ListRefs"
        | "PackExists"
        | "GetReceipt"
        | "GetGrantEpoch"
        | "GetAuthorityGeneration" => true,
        "UpdateRef" | "AdvanceRefs" | "BeginUpload" | "CompleteUpload" | "IssueObjectUrl"
        | "SetRepoVisibility" => {
            request
                .headers()
                .get("x-envelope-version")
                .is_some_and(|v| v == "2")
                && request
                    .headers()
                    .get("idempotency-key")
                    .is_some_and(|v| !v.is_empty())
                && request.headers().contains_key("x-signature")
        }
        _ => false,
    }
}
fn stale_without_bytes(
    error: &hyper_util::client::legacy::Error,
    snapshot: &[(Arc<Meter>, u64)],
) -> bool {
    let Some(info) = error.connect_info() else {
        return false;
    };
    if info.is_negotiated_h2() {
        return false;
    }
    let mut extras = http::Extensions::new();
    info.get_extras(&mut extras);
    let Some(meter) = extras.get::<MeterRef>() else {
        return false;
    };
    // Snapshots precede dispatch. Concurrent traffic can only increase this
    // counter, disabling a retry; it cannot hide partially received headers.
    if !snapshot.iter().any(|(prior, bytes)| {
        Arc::ptr_eq(prior, &meter.0) && meter.0.received.load(Ordering::SeqCst) == *bytes
    }) {
        return false;
    }
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = source {
        if let Some(e) = current.downcast_ref::<hyper::Error>()
            && (e.is_incomplete_message() || e.is_closed() || e.is_canceled())
        {
            return true;
        }
        if let Some(e) = current.downcast_ref::<io::Error>()
            && matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
            )
        {
            return true;
        }
        source = current.source();
    }
    false
}
impl ClientTransport for PooledHttpClient {
    type ResponseBody = hyper::body::Incoming;
    type Error = ConnectError;
    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, ConnectError>> {
        let client = self.clone();
        Box::pin(async move {
            if request.uri().scheme_str()
                != Some(if client.tls.is_some() {
                    "https"
                } else {
                    "http"
                })
            {
                return Err(ConnectError::invalid_argument(
                    "HTTP transport scheme does not match its configured mode",
                ));
            }
            if request
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.starts_with("application/connect+"))
            {
                // A streamed body cannot be replayed. Start its only attempt on
                // a fresh connection instead of risking a stale pooled socket.
                return Self::new(client.tls.clone())
                    .exchange(request)
                    .await
                    .map_err(|e| {
                        ConnectError::unavailable_from_transport("HTTP request failed", e)
                    });
            }
            if !replay_safe(&request) {
                return client.exchange(request).await.map_err(|e| {
                    ConnectError::unavailable_from_transport("HTTP request failed", e)
                });
            }
            let (parts, body) = request.into_parts();
            let bytes = body.collect().await?.to_bytes();
            let snapshot = client.snapshot();
            match client
                .exchange(Request::from_parts(parts.clone(), full_body(bytes.clone())))
                .await
            {
                Err(error) if stale_without_bytes(&error, &snapshot) => {
                    Self::new(client.tls.clone())
                        .exchange(Request::from_parts(parts, full_body(bytes)))
                        .await
                }
                result => result,
            }
            .map_err(|e| ConnectError::unavailable_from_transport("HTTP request failed", e))
        })
    }
}
