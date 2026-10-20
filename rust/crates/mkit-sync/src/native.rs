//! A small native HTTP channel for [`mkit_client`]: hyper over rustls on a
//! current-thread tokio runtime, gzip as the only content coding.
//!
//! The footprint is deliberate. There is no multi-thread scheduler, no HTTP/2,
//! no connect-RPC runtime and no zstd: a response may be `gzip` or identity
//! and anything else is refused, so the zstd C library is never linked by this feature (a default `pack-zstd`
//! build links it for pack decode; build without default features). The
//! `connect-native` dependency gate in CI enforces that.

mod location;

use std::io::Write as _;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, USER_AGENT};
use http::{HeaderMap, HeaderValue, Request, Response, Uri};
use http_body_util::{BodyExt as _, Full};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use mkit_client::{
    AdvertiseRequestTimeout, ChannelError, Clock, Error, FailureDiagnostic, FailureKind,
    FailureObserver, HttpTransport, RequestStream, RequestTimeout, ResponseStream,
};
use mkit_core::hash::Hash;
use rustls::{ClientConfig, RootCertStore};

use crate::client_source::Executor;

/// Default wall-clock bound on metadata requests, response body included.
pub const DEFAULT_METADATA_TIMEOUT: Duration = Duration::from_secs(30);
/// Default wall-clock bound on pack/part transfers, response body included.
pub const DEFAULT_TRANSFER_TIMEOUT: Duration = Duration::from_mins(5);

type LocationConnector = hyper_rustls::HttpsConnector<HttpConnector<location::LocationResolver>>;

type Connector = hyper_rustls::HttpsConnector<HttpConnector>;

/// Counts connection attempts. A request that fails while the count did not
/// move ran on a reused pooled connection; one that fails after it moved ran
/// on a connection opened for it (or concurrently), which is never retried.
#[derive(Clone)]
struct CountingConnector {
    inner: Connector,
    connects: Arc<AtomicU64>,
}

impl tower_service::Service<Uri> for CountingConnector {
    type Response = <Connector as tower_service::Service<Uri>>::Response;
    type Error = <Connector as tower_service::Service<Uri>>::Error;
    type Future = <Connector as tower_service::Service<Uri>>::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        self.connects.fetch_add(1, Ordering::SeqCst);
        self.inner.call(uri)
    }
}

/// Read RPCs of `mkit.transport.v1.TransportService`: signed reads (no replay
/// entry is recorded, SPEC-TRANSPORT-CONNECT "Signed reads") and the unsigned
/// server-info and grant-epoch reads. Resending one has no effect beyond the
/// answer.
const READ_PROCEDURES: [&str; 9] = [
    "ListRepos",
    "ListRefs",
    "ReadRef",
    "PackExists",
    "DownloadPack",
    "IssueObjectUrl",
    "GetReceipt",
    "GetServerInfo",
    "GetGrantEpoch",
];

/// Whether resending `request` after an unanswered attempt cannot change
/// server state. A signed read carries an `idempotency-key` like a write but
/// records no replay entry, so only the procedure decides. Writes (every
/// procedure not listed as a read) are never resent here: whether the server
/// applied them is unknown, and recovery belongs to the caller, which keeps
/// the signed identity.
fn is_resend_safe(method: &http::Method, uri: &Uri) -> bool {
    if method == http::Method::GET || method == http::Method::HEAD {
        return true;
    }
    method == http::Method::POST
        && uri
            .path()
            .strip_prefix("/mkit.transport.v1.TransportService/")
            .is_some_and(|name| READ_PROCEDURES.contains(&name))
}

/// A pooled connection the server had already closed: the response head never
/// arrived because the connection ended first.
fn is_stale_connection(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(cause) = current {
        if cause
            .downcast_ref::<hyper::Error>()
            .is_some_and(hyper::Error::is_incomplete_message)
        {
            return true;
        }
        current = cause.source();
    }
    false
}

// The receiver is owned and Send; the producer can still borrow the caller's
// pack. A single queued frame applies backpressure without spawning a task or
// requiring a 'static request source.
enum NativeBody {
    Full(Full<Bytes>),
    Stream(tokio::sync::mpsc::Receiver<Bytes>),
}
impl hyper::body::Body for NativeBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Full(body) => Pin::new(body).poll_frame(cx),
            Self::Stream(receiver) => receiver
                .poll_recv(cx)
                .map(|chunk| chunk.map(|bytes| Ok(hyper::body::Frame::data(bytes)))),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Full(body) => body.is_end_stream(),
            Self::Stream(receiver) => receiver.is_closed() && receiver.is_empty(),
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        match self {
            Self::Full(body) => body.size_hint(),
            Self::Stream(_) => hyper::body::SizeHint::default(),
        }
    }
}

/// The native [`HttpTransport`]. It owns a current-thread runtime, so it is
/// also the [`Executor`] to hand to a
/// [`ClientSource`](crate::ClientSource): the requests then run inside the
/// runtime that drives them. Do not call it from inside another tokio
/// runtime.
pub struct NativeHttp {
    // Declared first so in-flight connection tasks drop before the runtime
    // that drives them.
    client: HyperClient<CountingConnector, NativeBody>,
    location_client: HyperClient<LocationConnector, NativeBody>,
    location_tls: ClientConfig,
    allow_private_pack_locations: bool,
    connects: Arc<AtomicU64>,
    runtime: tokio::runtime::Runtime,
    metadata_timeout: Duration,
    transfer_timeout: Duration,
    allow_insecure_http: bool,
    test_pack_location_http: bool,
    default_headers: HeaderMap,
}

impl std::fmt::Debug for NativeHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeHttp")
            .field("metadata_timeout", &self.metadata_timeout)
            .field("transfer_timeout", &self.transfer_timeout)
            .finish_non_exhaustive()
    }
}

/// The TLS configuration used by default: the built-in web PKI roots, the
/// `ring` provider (installed on this config only, not process-wide), safe
/// protocol versions, no client certificate.
///
/// # Errors
/// The provider rejects the default protocol versions (not expected).
pub fn default_tls_config() -> Result<ClientConfig, std::io::Error> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}

impl NativeHttp {
    /// A transport that trusts the built-in web PKI roots.
    ///
    /// # Errors
    /// The runtime or TLS configuration cannot be built.
    pub fn new() -> Result<Self, std::io::Error> {
        Self::with_tls_config(&default_tls_config()?)
    }

    /// A transport using `tls` for RPC `https` origins. Pack-location fetches
    /// always use the built-in web PKI roots without client authentication.
    /// Cleartext `http` is refused except to loopback, unless
    /// [`allow_insecure_http`](Self::allow_insecure_http) is set.
    ///
    /// # Errors
    /// The runtime cannot be built.
    pub fn with_tls_config(tls: &ClientConfig) -> Result<Self, std::io::Error> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_nodelay(true);
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls.clone())
            .https_or_http()
            .enable_http1()
            .wrap_connector(http);
        let connects = Arc::new(AtomicU64::new(0));
        let connector = CountingConnector {
            inner: connector,
            connects: Arc::clone(&connects),
        };
        // Keep one idle connection per origin for sequential RPCs. Checkout
        // checks elapsed idle time even while this runtime is paused. Hyper
        // retries a canceled request only if it has not started writing it;
        // this preserves signed bytes and also the streaming body's receiver.
        // Failures after writing begins return to the existing host recovery,
        // except that a read answered by nothing on a reused connection is
        // resent once (`request_resending_reads`).
        let client = HyperClient::builder(TokioExecutor::new())
            .pool_max_idle_per_host(1)
            .pool_idle_timeout(Duration::from_secs(10))
            .pool_timer(TokioTimer::new())
            .retry_canceled_requests(true)
            .build(connector);
        // Location hosts use an independent TLS identity and connection pool.
        // Even a custom RPC TLS config with a client certificate must never
        // expose that certificate to a pack-location host.
        let location_tls = default_tls_config()?;
        let location_client = location_client(location_tls.clone(), false);
        Ok(Self {
            runtime,
            client,
            location_client,
            location_tls,
            allow_private_pack_locations: false,
            connects,
            metadata_timeout: DEFAULT_METADATA_TIMEOUT,
            transfer_timeout: DEFAULT_TRANSFER_TIMEOUT,
            allow_insecure_http: false,
            test_pack_location_http: false,
            default_headers: HeaderMap::new(),
        })
    }

    /// Apply host-supplied defaults to RPC requests, including discovery and
    /// unsigned owner statements. Pack-location fetches never use these headers.
    /// Explicit request headers take precedence.
    /// Configuration and credential trust remain the caller's responsibility.
    #[must_use]
    pub fn with_default_headers(mut self, headers: HeaderMap) -> Self {
        self.default_headers = headers;
        self
    }

    fn prepare_headers(&self, headers: &mut HeaderMap) -> Result<(), NativeHttpError> {
        for name in self.default_headers.keys() {
            if !headers.contains_key(name) {
                for value in self.default_headers.get_all(name) {
                    headers.append(name.clone(), value.clone());
                }
            }
        }
        request_headers(headers)
    }

    /// Allow cleartext `http` to hosts other than loopback. Off by default: a
    /// signed request and the packs it fetches would cross the network
    /// unencrypted. `https` and loopback `http` (for local development and
    /// tests) are always allowed for RPCs. Pack locations still require HTTPS.
    #[must_use]
    pub fn allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }

    /// Allow pack locations to connect to private or reserved addresses.
    /// Off by default: only public unicast destinations are allowed. This
    /// setting is controlled by the local caller, never by the remote.
    /// HTTPS, response bounds and content verification remain required.
    #[must_use]
    pub fn allow_private_pack_locations(mut self, allow: bool) -> Self {
        if self.allow_private_pack_locations != allow {
            // Replacing the pool prevents a connection permitted by an earlier
            // policy from surviving a switch back to public destinations only.
            self.location_client = location_client(self.location_tls.clone(), allow);
            self.allow_private_pack_locations = allow;
        }
        self
    }

    /// Permit loopback HTTP pack locations for local conformance fixtures.
    /// Production pack locations must use HTTPS. This does not permit HTTP
    /// to any other host and is independent of the RPC cleartext setting.
    /// Private destinations also require [`Self::allow_private_pack_locations`].
    #[doc(hidden)]
    #[must_use]
    pub fn with_test_pack_location_http(mut self, allow: bool) -> Self {
        self.test_pack_location_http = allow;
        self
    }

    /// Bound both metadata and transfer requests, response bodies included.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.metadata_timeout = timeout;
        self.transfer_timeout = timeout;
        self
    }

    /// Bound metadata requests, response body included (default: 30 seconds).
    #[must_use]
    pub fn with_metadata_timeout(mut self, timeout: Duration) -> Self {
        self.metadata_timeout = timeout;
        self
    }

    /// Bound `UploadPack`, `UploadPart`, `DownloadPack` and pack-location
    /// fetches, response body included (default: 300 seconds). Other procedures
    /// use the metadata bound.
    #[must_use]
    pub fn with_transfer_timeout(mut self, timeout: Duration) -> Self {
        self.transfer_timeout = timeout;
        self
    }

    fn request_timeout(&self, uri: &Uri) -> Duration {
        match uri.path() {
            mkit_client::procedures::UPLOAD_PACK
            | mkit_client::procedures::UPLOAD_PART
            | "/mkit.transport.v1.TransportService/DownloadPack" => self.transfer_timeout,
            _ => self.metadata_timeout,
        }
    }
}

impl Executor for NativeHttp {
    fn block_on<F: std::future::Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }
}

/// An error and its whole `source()` chain, joined: hyper-util's own `Display`
/// is only "client error (Connect)", and the reason (certificate, DNS, refused,
/// reset) lives in the sources.
fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(next) = source {
        text.push_str(": ");
        text.push_str(&next.to_string());
        source = next.source();
    }
    text
}

// Hyper's typed parsing and user-error markers are terminal. Other exchange
// failures (including an interrupted body) are explicitly transient; never
// infer either class from the diagnostic string.
fn exchange_error(context: &str, error: &(dyn std::error::Error + 'static)) -> NativeHttpError {
    let message = format!("{context}: {}", chain(error));
    let mut current = Some(error);
    while let Some(cause) = current {
        if cause
            .downcast_ref::<hyper::Error>()
            .is_some_and(|error| error.is_parse() || error.is_user())
        {
            return NativeHttpError::Exchange(message);
        }
        current = cause.source();
    }
    NativeHttpError::Connection(message)
}

/// Loopback hosts, the same set the Connect transport admits for plain HTTP.
/// `localhost` is trusted by name, as there; the resolver is not consulted.
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

enum ExchangeFailure {
    Native(NativeHttpError),
    Mapped(Error),
}
impl From<NativeHttpError> for ExchangeFailure {
    fn from(error: NativeHttpError) -> Self {
        Self::Native(error)
    }
}
impl ExchangeFailure {
    fn into_client(self) -> Error {
        match self {
            Self::Native(error) => client_error(error),
            Self::Mapped(error) => error,
        }
    }
}
struct NoDiagnostics;
impl FailureObserver for NoDiagnostics {}
struct Diagnostics<'a, D: FailureObserver + ?Sized> {
    observer: Option<&'a D>,
    procedure: &'a str,
    status: Option<http::StatusCode>,
    headers: Option<&'a HeaderMap>,
}
impl<D: FailureObserver + ?Sized> Copy for Diagnostics<'_, D> {}
impl<D: FailureObserver + ?Sized> Clone for Diagnostics<'_, D> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<D: FailureObserver + ?Sized> Diagnostics<'_, D> {
    fn diagnostic<'a>(
        &'a self,
        kind: FailureKind,
        cause: &'a str,
        body: Option<&'a [u8]>,
        limit: usize,
    ) -> FailureDiagnostic<'a> {
        let mut failure = FailureDiagnostic::new(self.procedure, kind, cause);
        failure.status = self.status;
        failure.headers = self.headers;
        failure.body = body;
        failure.limit = Some(limit);
        failure
    }
    fn failure(
        &self,
        kind: FailureKind,
        cause: &str,
        body: Option<&[u8]>,
        limit: usize,
        default: NativeHttpError,
    ) -> ExchangeFailure {
        let mapped = self
            .observer
            .and_then(|observer| observer.map_failure(&self.diagnostic(kind, cause, body, limit)));
        mapped.map_or_else(|| ExchangeFailure::Native(default), ExchangeFailure::Mapped)
    }
    fn client_failure(
        &self,
        kind: FailureKind,
        cause: &str,
        body: Option<&[u8]>,
        limit: usize,
        default: Error,
    ) -> Error {
        self.observer
            .and_then(|observer| observer.map_failure(&self.diagnostic(kind, cause, body, limit)))
            .unwrap_or(default)
    }
}

fn advertise_timeout<B>(
    request: &mut Request<B>,
    timeout: Duration,
) -> Result<(), NativeHttpError> {
    if request
        .extensions()
        .get::<AdvertiseRequestTimeout>()
        .is_some()
    {
        let millis = timeout.as_millis().min(9_999_999_999);
        request.headers_mut().insert(
            "connect-timeout-ms",
            HeaderValue::from_str(&millis.to_string()).map_err(|_| {
                NativeHttpError::Exchange("invalid request timeout header".to_owned())
            })?,
        );
    }
    Ok(())
}

/// Read at most `limit` bytes of `body`, refusing a longer one while it is
/// received.
async fn read_bounded<D: FailureObserver + ?Sized>(
    mut body: hyper::body::Incoming,
    limit: usize,
    diagnostics: Diagnostics<'_, D>,
) -> Result<Vec<u8>, ExchangeFailure> {
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| {
            diagnostics.failure(
                FailureKind::BodyIo,
                &error.to_string(),
                None,
                limit,
                exchange_error("response body", &error),
            )
        })?;
        if let Some(data) = frame.data_ref() {
            if out.len().saturating_add(data.len()) > limit {
                return Err(diagnostics.failure(
                    FailureKind::WireLimit,
                    "response exceeds the size limit",
                    None,
                    limit,
                    NativeHttpError::Exchange("response exceeds the size limit".to_owned()),
                ));
            }
            out.extend_from_slice(data);
        }
    }
    Ok(out)
}

/// Preserve a host-opted-in HTTP admission response even when its bounded
/// body cannot be read. The protocol client still validates challenge headers.
async fn read_response_body<D: FailureObserver + ?Sized>(
    body: hyper::body::Incoming,
    limit: usize,
    diagnostics: Diagnostics<'_, D>,
    profile: mkit_client::ResponseProfile,
) -> Result<Vec<u8>, ExchangeFailure> {
    match read_bounded(body, limit, diagnostics).await {
        Err(_)
            if profile.expose_error_responses
                && diagnostics.status == Some(http::StatusCode::PAYMENT_REQUIRED) =>
        {
            Ok(Vec::new())
        }
        result => result,
    }
}

/// Inflate a gzip body, refusing one that expands past `limit`.
enum GzipFailure {
    Coding(std::io::Error),
    Limit,
}
impl GzipFailure {
    fn diagnostic(&self) -> (FailureKind, String, String) {
        match self {
            Self::Coding(error) => (
                FailureKind::Coding,
                error.to_string(),
                format!("gzip response: {error}"),
            ),
            Self::Limit => (
                FailureKind::InflatedLimit,
                "response exceeds the size limit once decompressed".to_owned(),
                "response exceeds the size limit once decompressed".to_owned(),
            ),
        }
    }
}
fn gunzip_bounded(compressed: &[u8], limit: usize) -> Result<Vec<u8>, GzipFailure> {
    use std::io::Read as _;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(compressed)
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(GzipFailure::Coding)?;
    if out.len() > limit {
        return Err(GzipFailure::Limit);
    }
    Ok(out)
}

/// Native request refusal or exchange failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeHttpError {
    /// Negotiation names a coding other than gzip/identity, or is malformed.
    #[error("unsupported accept-encoding (gzip and identity only)")]
    UnsupportedAcceptEncoding,
    /// A redirect, cleartext, response-limit or response-coding refusal.
    #[error("{0}")]
    Exchange(String),
    /// An HTTP/TLS exchange or response-body I/O failure.
    #[error("{0}")]
    Connection(String),
    /// The configured per-request I/O budget ended.
    #[error("{0}")]
    Timeout(String),
}

/// Preserve every supplied value. Refuse negotiation we cannot decode,
/// including wildcards and unsupported codings even when their quality is zero.
fn request_headers(headers: &mut HeaderMap) -> Result<(), NativeHttpError> {
    for value in headers.get_all(ACCEPT_ENCODING) {
        let value = value
            .to_str()
            .map_err(|_| NativeHttpError::UnsupportedAcceptEncoding)?;
        if value.trim().is_empty() {
            continue; // Empty negotiation requests identity only.
        }
        for entry in value.split(',') {
            let mut fields = entry.trim().split(';');
            let coding = fields.next().unwrap_or_default().trim();
            if !coding.eq_ignore_ascii_case("gzip") && !coding.eq_ignore_ascii_case("identity") {
                return Err(NativeHttpError::UnsupportedAcceptEncoding);
            }
            if let Some(parameter) = fields.next() {
                let Some((name, quality)) = parameter.trim().split_once('=') else {
                    return Err(NativeHttpError::UnsupportedAcceptEncoding);
                };
                let quality = quality.trim();
                let valid_quality = match quality.split_once('.') {
                    None => matches!(quality, "0" | "1"),
                    Some((whole, fraction)) => {
                        fraction.len() <= 3
                            && fraction.bytes().all(|b| b.is_ascii_digit())
                            && (whole == "0"
                                || (whole == "1" && fraction.bytes().all(|b| b == b'0')))
                    }
                };
                if !name.trim().eq_ignore_ascii_case("q")
                    || !valid_quality
                    || fields.next().is_some()
                {
                    return Err(NativeHttpError::UnsupportedAcceptEncoding);
                }
            }
        }
    }
    headers
        .entry(ACCEPT_ENCODING)
        .or_insert(HeaderValue::from_static("gzip"));
    headers
        .entry(USER_AGENT)
        .or_insert(HeaderValue::from_static(concat!(
            "mkit-sync/",
            env!("CARGO_PKG_VERSION")
        )));
    Ok(())
}

fn decode_body<D: FailureObserver + ?Sized>(
    wire: Vec<u8>,
    headers: &HeaderMap,
    limit: usize,
    profile: mkit_client::ResponseProfile,
    diagnostics: Diagnostics<'_, D>,
) -> Result<Vec<u8>, ExchangeFailure> {
    let bytes = (|| {
        let mut codings = headers.get_all(CONTENT_ENCODING).iter();
        let coding = match (codings.next(), codings.next()) {
            (None, _) => None,
            (Some(v), None) => Some(
                v.to_str()
                    .map_err(|_| {
                        diagnostics.failure(
                            FailureKind::Coding,
                            "unreadable content-encoding",
                            Some(&wire),
                            limit,
                            NativeHttpError::Exchange("unreadable content-encoding".to_owned()),
                        )
                    })?
                    .trim()
                    .to_ascii_lowercase(),
            ),
            (Some(_), Some(_)) => {
                return Err(diagnostics.failure(
                    FailureKind::Coding,
                    "multiple content-encoding values",
                    Some(&wire),
                    limit,
                    NativeHttpError::Exchange(
                        "unsupported content-encoding (gzip only)".to_owned(),
                    ),
                ));
            }
        };
        match coding.as_deref() {
            None | Some("identity") => Ok(wire),
            Some("gzip") if wire.is_empty() && profile.allow_empty_coded_body => Ok(wire),
            Some("gzip") => match gunzip_bounded(&wire, limit) {
                Ok(bytes) => Ok(bytes),
                Err(error) => {
                    let (kind, cause, message) = error.diagnostic();
                    Err(diagnostics.failure(
                        kind,
                        &cause,
                        Some(&wire),
                        limit,
                        NativeHttpError::Exchange(message),
                    ))
                }
            },
            Some(coding) => Err(diagnostics.failure(
                FailureKind::Coding,
                coding,
                Some(&wire),
                limit,
                NativeHttpError::Exchange("unsupported content-encoding (gzip only)".to_owned()),
            )),
        }
    })();
    match bytes {
        Ok(bytes) => Ok(bytes),
        Err(_)
            if profile.expose_error_responses
                && diagnostics.status == Some(http::StatusCode::PAYMENT_REQUIRED) =>
        {
            // A diagnostic mapper may already have classified a body failure.
            // Admission takes precedence so the central client emits the typed
            // challenge and applies its existing validation bounds.
            Ok(Vec::new())
        }
        Err(ExchangeFailure::Native(_))
            if profile.expose_error_responses
                && diagnostics
                    .status
                    .is_some_and(|status| !status.is_success()) =>
        {
            // The central HTTP decoder still observes the status and admission
            // headers when an error envelope's coding is unusable.
            Ok(Vec::new())
        }
        Err(error) => Err(error),
    }
}

impl NativeHttp {
    /// One exchange. The server may close an idle keep-alive connection at the
    /// moment the next request is written to it; hyper then reports the
    /// request as written but unanswered and, having written it, does not
    /// resend. When the failing connection was reused (no connection was
    /// opened during the attempt) and `resend` holds a copy of a request that
    /// is safe to repeat, it is sent once more on a fresh connection. Anything
    /// else, including a second failure, is returned unchanged.
    async fn request_resending_reads(
        &self,
        request: Request<NativeBody>,
        resend: Option<(http::Method, Uri, HeaderMap, Bytes)>,
    ) -> Result<Response<hyper::body::Incoming>, hyper_util::client::legacy::Error> {
        let connects = self.connects.load(Ordering::SeqCst);
        match self.client.request(request).await {
            Err(error)
                if is_stale_connection(&error)
                    && self.connects.load(Ordering::SeqCst) == connects =>
            {
                let Some((method, uri, headers, body)) = resend else {
                    return Err(error);
                };
                let mut again = Request::new(NativeBody::Full(Full::new(body)));
                *again.method_mut() = method;
                *again.uri_mut() = uri;
                *again.headers_mut() = headers;
                self.client.request(again).await
            }
            other => other,
        }
    }

    /// Send one request with typed native errors. The [`HttpTransport`] adapter
    /// uses the same path, converting errors to its required string form.
    ///
    /// # Errors
    /// Unsupported request negotiation is refused before connecting. Exchange
    /// failures include TLS, redirects, response bounds and the request timeout.
    pub async fn send_typed(
        &self,
        request: Request<Vec<u8>>,
        response_limit: usize,
    ) -> Result<Response<Vec<u8>>, NativeHttpError> {
        self.send_inner::<NoDiagnostics>(request, response_limit, None)
            .await
            .map_err(|failure| match failure {
                ExchangeFailure::Native(error) => error,
                ExchangeFailure::Mapped(error) => NativeHttpError::Exchange(error.to_string()),
            })
    }

    async fn send_inner<D: FailureObserver + ?Sized>(
        &self,
        mut request: Request<Vec<u8>>,
        response_limit: usize,
        observer: Option<&D>,
    ) -> Result<Response<Vec<u8>>, ExchangeFailure> {
        let timeout = request.extensions().get::<RequestTimeout>().map_or_else(
            || self.request_timeout(request.uri()),
            |bound| self.request_timeout(request.uri()).min(bound.0),
        );
        advertise_timeout(&mut request, timeout)?;
        let procedure = request.uri().path().to_owned();
        let initial = Diagnostics {
            observer,
            procedure: &procedure,
            status: None,
            headers: None,
        };
        let profile = observer
            .map(FailureObserver::response_profile)
            .unwrap_or_default();
        let (mut parts, body) = request.into_parts();
        if parts.uri.scheme_str() == Some("http")
            && !self.allow_insecure_http
            && !parts.uri.host().is_some_and(is_loopback_host)
        {
            return Err(NativeHttpError::Exchange(
                "cleartext http to a non-loopback host refused".to_owned(),
            )
            .into());
        }
        self.prepare_headers(&mut parts.headers)?;
        let body = Bytes::from(body);
        let resend = is_resend_safe(&parts.method, &parts.uri).then(|| {
            (
                parts.method.clone(),
                parts.uri.clone(),
                parts.headers.clone(),
                body.clone(),
            )
        });
        let request = Request::from_parts(parts, NativeBody::Full(Full::new(body)));
        let exchange = async {
            let response = self
                .request_resending_reads(request, resend)
                .await
                .map_err(|error| {
                    initial.failure(
                        FailureKind::RequestIo,
                        &error.to_string(),
                        None,
                        response_limit,
                        exchange_error("request failed", &error),
                    )
                })?;
            // Redirects are never followed: a redirect would carry a signed
            // request to an origin the signature was not made for.
            if response.status().is_redirection() && !profile.expose_error_responses {
                let diagnostics = Diagnostics {
                    status: Some(response.status()),
                    headers: Some(response.headers()),
                    ..initial
                };
                return Err(diagnostics.failure(
                    FailureKind::Http,
                    "redirect refused",
                    None,
                    response_limit,
                    NativeHttpError::Exchange("redirect refused".to_owned()),
                ));
            }
            let (mut parts, body) = response.into_parts();
            let diagnostics = Diagnostics {
                status: Some(parts.status),
                headers: Some(&parts.headers),
                ..initial
            };
            let wire = read_response_body(body, response_limit, diagnostics, profile).await?;
            let bytes = decode_body(wire, &parts.headers, response_limit, profile, diagnostics)?;
            parts.headers.remove(CONTENT_ENCODING);
            parts.headers.remove(CONTENT_LENGTH);
            Ok(Response::from_parts(parts, bytes))
        };
        tokio::time::timeout(timeout, exchange).await.map_err(|_| {
            ExchangeFailure::Native(NativeHttpError::Timeout("request timed out".to_owned()))
        })?
    }
}

fn client_error(error: NativeHttpError) -> Error {
    match error {
        NativeHttpError::Connection(cause) => Error::Connection(cause),
        NativeHttpError::Timeout(_) => {
            Error::RequestTimeout("client-side deadline exceeded".to_owned())
        }
        refusal => Error::Transport(refusal.to_string()),
    }
}

struct ChunkWriter<'a, S: ResponseStream + ?Sized, D: FailureObserver + ?Sized> {
    sink: &'a mut S,
    received: usize,
    limit: usize,
    error: Option<Error>,
    diagnostics: Diagnostics<'a, D>,
}
impl<S: ResponseStream + ?Sized, D: FailureObserver + ?Sized> std::io::Write
    for ChunkWriter<'_, S, D>
{
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.received = self.received.saturating_add(bytes.len());
        let result = if self.received > self.limit {
            Err(self.diagnostics.client_failure(
                FailureKind::InflatedLimit,
                "response exceeds the size limit once decompressed",
                None,
                self.limit,
                Error::Transport("response exceeds the size limit once decompressed".to_owned()),
            ))
        } else {
            self.sink.chunk(bytes)
        };
        match result {
            Ok(()) => Ok(bytes.len()),
            Err(error) => {
                self.error = Some(error);
                Err(std::io::Error::other("response chunk refused"))
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn gzip_error<S: ResponseStream + ?Sized, D: FailureObserver + ?Sized>(
    decoder: &mut flate2::write::GzDecoder<ChunkWriter<'_, S, D>>,
    error: &std::io::Error,
) -> Error {
    decoder.get_mut().error.take().unwrap_or_else(|| {
        let writer = decoder.get_mut();
        writer.diagnostics.client_failure(
            FailureKind::Coding,
            &error.to_string(),
            None,
            writer.limit,
            Error::Transport(format!("gzip response: {error}")),
        )
    })
}

fn response_gzip<D: FailureObserver + ?Sized>(
    headers: &HeaderMap,
    diagnostics: Diagnostics<'_, D>,
    limit: usize,
) -> Result<bool, Error> {
    let mut codings = headers.get_all(CONTENT_ENCODING).iter();
    match (codings.next(), codings.next()) {
        (None, _) => Ok(false),
        (Some(value), None) => match value.to_str().map(str::trim) {
            Ok(value) if value.eq_ignore_ascii_case("identity") => Ok(false),
            Ok(value) if value.eq_ignore_ascii_case("gzip") => Ok(true),
            Err(_) => Err(diagnostics.client_failure(
                FailureKind::Coding,
                "unreadable content-encoding",
                None,
                limit,
                Error::Transport("unreadable content-encoding".to_owned()),
            )),
            _ => Err(diagnostics.client_failure(
                FailureKind::Coding,
                value.to_str().unwrap_or(""),
                None,
                limit,
                Error::Transport("unsupported content-encoding (gzip only)".to_owned()),
            )),
        },
        _ => Err(diagnostics.client_failure(
            FailureKind::Coding,
            "multiple content-encoding values",
            None,
            limit,
            Error::Transport("unsupported content-encoding (gzip only)".to_owned()),
        )),
    }
}

async fn stream_error_response<S: ResponseStream + ?Sized, D: FailureObserver + ?Sized>(
    response: Response<hyper::body::Incoming>,
    limit: usize,
    sink: &mut S,
    initial: Diagnostics<'_, D>,
    profile: mkit_client::ResponseProfile,
) -> Result<(), Error> {
    let (mut parts, body) = response.into_parts();
    let diagnostics = Diagnostics {
        status: Some(parts.status),
        headers: Some(&parts.headers),
        ..initial
    };
    let limit = profile.end_frame_limit.unwrap_or(limit).min(limit);
    let wire = read_response_body(body, limit, diagnostics, profile)
        .await
        .map_err(ExchangeFailure::into_client)?;
    let bytes = decode_body(wire, &parts.headers, limit, profile, diagnostics)
        .map_err(ExchangeFailure::into_client)?;
    parts.headers.remove(CONTENT_ENCODING);
    parts.headers.remove(CONTENT_LENGTH);
    sink.start(Response::from_parts(parts, ()))?;
    sink.chunk(&bytes)?;
    sink.finish()
}

async fn stream_response<S: ResponseStream + ?Sized, D: FailureObserver + ?Sized>(
    response: Response<hyper::body::Incoming>,
    limit: usize,
    sink: &mut S,
    initial: Diagnostics<'_, D>,
) -> Result<(), Error> {
    let profile = initial
        .observer
        .map(FailureObserver::response_profile)
        .unwrap_or_default();
    if !response.status().is_success() && profile.expose_error_responses {
        return stream_error_response(response, limit, sink, initial, profile).await;
    }
    if response.status().is_redirection() && !profile.expose_error_responses {
        return Err(Error::Transport("redirect refused".to_owned()));
    }
    let (mut parts, mut body) = response.into_parts();
    let original_headers = parts.headers.clone();
    let diagnostics = Diagnostics {
        status: Some(parts.status),
        headers: Some(&original_headers),
        ..initial
    };
    let gzip = response_gzip(&parts.headers, diagnostics, limit)?;
    parts.headers.remove(CONTENT_ENCODING);
    parts.headers.remove(CONTENT_LENGTH);
    sink.start(Response::from_parts(parts, ()))?;
    let mut wire_received = 0_usize;
    if gzip {
        let writer = ChunkWriter {
            sink,
            received: 0,
            limit,
            error: None,
            diagnostics,
        };
        let mut decoder = flate2::write::GzDecoder::new(writer);
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|error| {
                diagnostics.client_failure(
                    FailureKind::BodyIo,
                    &error.to_string(),
                    None,
                    limit,
                    client_error(exchange_error("response body", &error)),
                )
            })?;
            if let Some(bytes) = frame.data_ref() {
                wire_received = wire_received.saturating_add(bytes.len());
                if wire_received > limit {
                    return Err(diagnostics.client_failure(
                        FailureKind::WireLimit,
                        "response exceeds the size limit",
                        None,
                        limit,
                        Error::Transport("response exceeds the size limit".to_owned()),
                    ));
                }
                if let Err(error) = decoder.write_all(bytes) {
                    return Err(gzip_error(&mut decoder, &error));
                }
            }
        }
        if (wire_received > 0 || !profile.allow_empty_coded_body)
            && let Err(error) = decoder.try_finish()
        {
            return Err(gzip_error(&mut decoder, &error));
        }
        decoder.get_mut().sink.finish()
    } else {
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|error| {
                diagnostics.client_failure(
                    FailureKind::BodyIo,
                    &error.to_string(),
                    None,
                    limit,
                    client_error(exchange_error("response body", &error)),
                )
            })?;
            if let Some(bytes) = frame.data_ref() {
                wire_received = wire_received.saturating_add(bytes.len());
                if wire_received > limit {
                    return Err(diagnostics.client_failure(
                        FailureKind::WireLimit,
                        "response exceeds the size limit",
                        None,
                        limit,
                        Error::Transport("response exceeds the size limit".to_owned()),
                    ));
                }
                sink.chunk(bytes)?;
            }
        }
        sink.finish()
    }
}

impl NativeHttp {
    async fn stream_inner<
        B: RequestStream + ?Sized,
        S: ResponseStream + ?Sized,
        D: FailureObserver + ?Sized,
    >(
        &self,
        mut request: Request<()>,
        body: &mut B,
        response_limit: usize,
        sink: &mut S,
        observer: Option<&D>,
    ) -> Result<(), Error> {
        let timeout = request.extensions().get::<RequestTimeout>().map_or_else(
            || self.request_timeout(request.uri()),
            |bound| self.request_timeout(request.uri()).min(bound.0),
        );
        advertise_timeout(&mut request, timeout).map_err(client_error)?;
        let procedure = request.uri().path().to_owned();
        let diagnostics = Diagnostics {
            observer,
            procedure: &procedure,
            status: None,
            headers: None,
        };
        let (mut parts, ()) = request.into_parts();
        if parts.uri.scheme_str() == Some("http")
            && !self.allow_insecure_http
            && !parts.uri.host().is_some_and(is_loopback_host)
        {
            return Err(Error::Transport(
                "cleartext http to a non-loopback host refused".to_owned(),
            ));
        }
        self.prepare_headers(&mut parts.headers)
            .map_err(client_error)?;
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let request = Request::from_parts(parts, NativeBody::Stream(receiver));
        let produce = async move {
            while let Some(chunk) = body.next_chunk()? {
                if sender.send(Bytes::from(chunk)).await.is_err() {
                    // A response head may close the upload receiver before its
                    // error body arrives. Let that response finish before
                    // deciding whether incomplete request production failed.
                    return Ok::<_, Error>(false);
                }
            }
            Ok::<_, Error>(true)
        };
        let exchange = async {
            let response = self.client.request(request).await.map_err(|error| {
                diagnostics.client_failure(
                    FailureKind::RequestIo,
                    &error.to_string(),
                    None,
                    response_limit,
                    client_error(exchange_error("request failed", &error)),
                )
            })?;
            stream_response(response, response_limit, sink, diagnostics).await
        };
        // Drive both borrowing futures locally. An early rejection cancels the
        // producer; successful exchanges require complete request production.
        let together = async {
            use std::future::Future as _;
            let mut produce = std::pin::pin!(produce);
            let mut exchange = std::pin::pin!(exchange);
            let mut produced = None;
            let mut exchanged = false;
            std::future::poll_fn(|cx| {
                if !exchanged {
                    match exchange.as_mut().poll(cx) {
                        Poll::Ready(Ok(())) => exchanged = true,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => {}
                    }
                }
                if produced.is_none() {
                    match produce.as_mut().poll(cx) {
                        Poll::Ready(Ok(complete)) => produced = Some(complete),
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => {}
                    }
                }
                if exchanged {
                    match produced {
                        Some(true) => Poll::Ready(Ok(())),
                        Some(false) => Poll::Ready(Err(Error::Transport(
                            "request body stopped before completion".to_owned(),
                        ))),
                        None => Poll::Pending,
                    }
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        tokio::time::timeout(timeout, together)
            .await
            .map_err(|_| Error::RequestTimeout("client-side deadline exceeded".to_owned()))?
    }
}

fn location_client(
    tls: ClientConfig,
    allow_private: bool,
) -> HyperClient<LocationConnector, NativeBody> {
    let resolver = location::LocationResolver {
        inner: hyper_util::client::legacy::connect::dns::GaiResolver::new(),
        allow_private,
    };
    let mut http = HttpConnector::new_with_resolver(resolver);
    http.enforce_http(false);
    http.set_nodelay(true);
    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
    HyperClient::builder(TokioExecutor::new())
        .pool_max_idle_per_host(1)
        .pool_idle_timeout(Duration::from_secs(10))
        .pool_timer(TokioTimer::new())
        .build(connector)
}

impl HttpTransport for NativeHttp {
    fn supports_pack_locations(&self) -> bool {
        true
    }

    fn allows_test_pack_location_http(&self) -> bool {
        self.test_pack_location_http
    }

    async fn fetch_pack_location(
        &self,
        url: &str,
        response_limit: usize,
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>, String> {
        let uri: Uri = url.parse().map_err(|_| "invalid pack location URL")?;
        let authority = uri.authority().ok_or("pack location has no authority")?;
        if authority.as_str().contains('@') {
            return Err("pack location credentials refused".to_owned());
        }
        match uri.scheme_str() {
            Some("https") => {}
            Some("http")
                if self.test_pack_location_http && uri.host().is_some_and(is_loopback_host) => {}
            _ => return Err("pack location requires HTTPS".to_owned()),
        }
        // HttpConnector bypasses its resolver for literals, so apply the
        // identical address policy here before handing them to the connector.
        if !self.allow_private_pack_locations {
            let host = uri.host().ok_or("pack location has no host")?;
            if let Ok(ip) = host.trim_start_matches('[').trim_end_matches(']').parse()
                && !location::is_public(ip)
            {
                return Err("pack location destination refused".to_owned());
            }
        }
        let timeout = timeout.map_or(self.transfer_timeout, |bound| {
            bound.min(self.transfer_timeout)
        });
        if timeout.is_zero() {
            return Err("pack location deadline exceeded".to_owned());
        }
        // This is deliberately independent of the RPC request path: neither
        // default headers nor signed request headers reach the location host.
        // Hyper does not follow redirects or retain cookies.
        let request = Request::get(uri)
            .header(ACCEPT_ENCODING, "identity")
            .body(NativeBody::Full(Full::new(Bytes::new())))
            .map_err(|_| "invalid pack location request")?;
        let fetch = async {
            let response = self
                .location_client
                .request(request)
                .await
                .map_err(|_| "pack location request failed".to_owned())?;
            if response.status() != http::StatusCode::OK {
                return Err("pack location response was not OK".to_owned());
            }
            let mut codings = response.headers().get_all(CONTENT_ENCODING).iter();
            match (codings.next(), codings.next()) {
                (None, _) => {}
                (Some(coding), None)
                    if coding
                        .to_str()
                        .is_ok_and(|coding| coding.trim().eq_ignore_ascii_case("identity")) => {}
                _ => return Err("encoded pack location body refused".to_owned()),
            }
            let diagnostics = Diagnostics::<NoDiagnostics> {
                observer: None,
                procedure: "pack location",
                status: Some(response.status()),
                headers: None,
            };
            read_bounded(response.into_body(), response_limit, diagnostics)
                .await
                .map_err(|_| "pack location body failed or exceeded the size limit".to_owned())
        };
        tokio::time::timeout(timeout, fetch)
            .await
            .map_err(|_| "pack location deadline exceeded".to_owned())?
    }

    async fn send_stream<B: RequestStream + ?Sized, S: ResponseStream + ?Sized>(
        &self,
        request: Request<()>,
        body: &mut B,
        response_limit: usize,
        sink: &mut S,
    ) -> Result<(), Error> {
        self.stream_inner::<B, S, NoDiagnostics>(request, body, response_limit, sink, None)
            .await
    }
    async fn send_diagnosed<D: FailureObserver + ?Sized>(
        &self,
        request: Request<Vec<u8>>,
        response_limit: usize,
        observer: &D,
    ) -> Result<Response<Vec<u8>>, Error> {
        self.send_inner(request, response_limit, Some(observer))
            .await
            .map_err(ExchangeFailure::into_client)
    }
    async fn send_stream_diagnosed<
        B: RequestStream + ?Sized,
        S: ResponseStream + ?Sized,
        D: FailureObserver + ?Sized,
    >(
        &self,
        request: Request<()>,
        body: &mut B,
        response_limit: usize,
        sink: &mut S,
        observer: &D,
    ) -> Result<(), Error> {
        self.stream_inner(request, body, response_limit, sink, Some(observer))
            .await
    }

    async fn send_classified(
        &self,
        request: Request<Vec<u8>>,
        response_limit: usize,
    ) -> Result<Response<Vec<u8>>, ChannelError> {
        self.send_typed(request, response_limit)
            .await
            .map_err(|error| match error {
                NativeHttpError::Connection(cause) => ChannelError::Transient(cause),
                NativeHttpError::Timeout(_) => {
                    ChannelError::TimedOut("client-side deadline exceeded".to_owned())
                }
                refusal => ChannelError::Refused(refusal.to_string()),
            })
    }

    async fn send(
        &self,
        request: Request<Vec<u8>>,
        response_limit: usize,
    ) -> Result<Response<Vec<u8>>, String> {
        self.send_typed(request, response_limit)
            .await
            .map_err(|e| e.to_string())
    }
}

/// A [`Clock`] on the system time, the operating system's entropy and the
/// tokio timer. `wait` needs a tokio reactor, so run the client with
/// [`NativeHttp`] as the executor, as [`ClientSource`](crate::ClientSource) does
/// when given it; under `FuturesExecutor` it panics.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeClock;

impl Clock for NativeClock {
    /// A system clock set before 1970 reads as 0, which a server rejects as
    /// an expired request.
    fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
    }

    fn nonce(&self) -> Result<Hash, String> {
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
        Ok(nonce)
    }

    async fn wait(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_listed_reads_are_resend_safe() {
        let post = |name: &str| {
            is_resend_safe(
                &http::Method::POST,
                &format!("http://h/mkit.transport.v1.TransportService/{name}")
                    .parse()
                    .unwrap(),
            )
        };
        for name in READ_PROCEDURES {
            assert!(post(name), "{name}");
        }
        for name in [
            "UpdateRef",
            "AdvanceRefs",
            "BeginUpload",
            "UploadPart",
            "UploadPack",
            "CompleteUpload",
            "SetGrantEpoch",
            "SetRepoVisibility",
            "Unknown",
        ] {
            assert!(!post(name), "{name}");
        }
        assert!(!is_resend_safe(
            &http::Method::POST,
            &"http://h/".parse().unwrap()
        ));
        assert!(is_resend_safe(
            &http::Method::GET,
            &"http://h/x".parse().unwrap()
        ));
    }

    #[test]
    fn timeout_defaults_and_overrides_are_selected_by_exact_procedure() {
        let http = NativeHttp::new().expect("native transport");
        assert_eq!(DEFAULT_METADATA_TIMEOUT, Duration::from_secs(30));
        assert_eq!(DEFAULT_TRANSFER_TIMEOUT, Duration::from_mins(5));
        for procedure in [
            "GetServerInfo",
            "ListRefs",
            "ReadRef",
            "PackExists",
            "UpdateRef",
            "BeginUpload",
            "CompleteUpload",
            "AdvanceRefs",
        ] {
            let uri =
                format!("https://example.invalid/mkit.transport.v1.TransportService/{procedure}")
                    .parse::<Uri>()
                    .expect("uri");
            assert_eq!(http.request_timeout(&uri), DEFAULT_METADATA_TIMEOUT);
        }
        for procedure in ["DownloadPack", "UploadPack", "UploadPart"] {
            let uri =
                format!("https://example.invalid/mkit.transport.v1.TransportService/{procedure}")
                    .parse::<Uri>()
                    .expect("uri");
            assert_eq!(http.request_timeout(&uri), DEFAULT_TRANSFER_TIMEOUT);
        }
        let metadata: Uri = "https://example.invalid/other/UploadPack"
            .parse()
            .expect("uri");
        let transfer: Uri = "https://example.invalid/mkit.transport.v1.TransportService/UploadPart"
            .parse()
            .expect("uri");
        let http = http
            .with_timeout(Duration::from_secs(7))
            .with_metadata_timeout(Duration::from_secs(1));
        assert_eq!(http.request_timeout(&metadata), Duration::from_secs(1));
        assert_eq!(http.request_timeout(&transfer), Duration::from_secs(7));
        let http = http.with_transfer_timeout(Duration::from_secs(2));
        assert_eq!(http.request_timeout(&metadata), Duration::from_secs(1));
        assert_eq!(http.request_timeout(&transfer), Duration::from_secs(2));
    }

    #[test]
    fn defaults_and_compatible_negotiation_preserve_all_values() {
        let mut headers = HeaderMap::new();
        request_headers(&mut headers).expect("defaults");
        assert_eq!(headers[ACCEPT_ENCODING], "gzip");
        assert_eq!(
            headers[USER_AGENT],
            concat!("mkit-sync/", env!("CARGO_PKG_VERSION"))
        );
        for values in [
            vec![""],
            vec!["identity"],
            vec!["GZip;q=1.000", "identity;q=0"],
            vec!["gzip;q=0.5, identity;q=0.1"],
        ] {
            let mut headers = HeaderMap::new();
            for value in &values {
                headers.append(
                    ACCEPT_ENCODING,
                    HeaderValue::from_str(value).expect("header"),
                );
            }
            let original = headers.clone();
            request_headers(&mut headers).expect("compatible");
            assert_eq!(
                headers.get_all(ACCEPT_ENCODING),
                original.get_all(ACCEPT_ENCODING)
            );
        }
    }
}
