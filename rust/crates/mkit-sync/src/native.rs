//! A small native HTTP channel for [`mkit_client`]: hyper over rustls on a
//! current-thread tokio runtime, gzip as the only content coding.
//!
//! The footprint is deliberate. There is no multi-thread scheduler, no HTTP/2,
//! no connect-RPC runtime and no zstd: a response may be `gzip` or identity
//! and anything else is refused, so the zstd C library is never linked by this feature (a default `pack-zstd`
//! build links it for pack decode; build without default features). The
//! `connect-native` dependency gate in CI enforces that.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, USER_AGENT};
use http::{HeaderValue, Request, Response};
use http_body_util::{BodyExt as _, Full};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use mkit_client::{Clock, HttpTransport};
use mkit_core::hash::Hash;
use rustls::{ClientConfig, RootCertStore};

use crate::client_source::Executor;

/// Default wall-clock bound on one request, response body included.
const DEFAULT_TIMEOUT: Duration = Duration::from_mins(10);

type Connector = hyper_rustls::HttpsConnector<HttpConnector>;

/// The native [`HttpTransport`]. It owns a current-thread runtime, so it is
/// also the [`Executor`] to hand to a
/// [`ClientSource`](crate::ClientSource): the requests then run inside the
/// runtime that drives them. Do not call it from inside another tokio
/// runtime.
pub struct NativeHttp {
    // Declared first so in-flight connection tasks drop before the runtime
    // that drives them.
    client: HyperClient<Connector, Full<Bytes>>,
    runtime: tokio::runtime::Runtime,
    timeout: Duration,
    allow_insecure_http: bool,
}

impl std::fmt::Debug for NativeHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeHttp")
            .field("timeout", &self.timeout)
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

    /// A transport using `tls` for `https` origins. Cleartext `http` is
    /// refused except to loopback, unless
    /// [`allow_insecure_http`](Self::allow_insecure_http) is set.
    ///
    /// # Errors
    /// The runtime cannot be built.
    pub fn with_tls_config(tls: &ClientConfig) -> Result<Self, std::io::Error> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls.clone())
            .https_or_http()
            .enable_http1()
            .build();
        // No idle pool: connection tasks only run while a call is inside
        // `block_on`, so an idle connection the server closes between calls
        // would go unnoticed and the next signed POST could be written to a
        // dead socket. One connection per request costs little next to a pack.
        let client = HyperClient::builder(TokioExecutor::new())
            .pool_max_idle_per_host(0)
            .build(connector);
        Ok(Self {
            runtime,
            client,
            timeout: DEFAULT_TIMEOUT,
            allow_insecure_http: false,
        })
    }

    /// Allow cleartext `http` to hosts other than loopback. Off by default: a
    /// signed request and the packs it fetches would cross the network
    /// unencrypted. `https` and loopback `http` (for local development and
    /// tests) are always allowed.
    #[must_use]
    pub fn allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }

    /// Bound one request, response body included. The default is ten minutes.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
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

/// Loopback hosts, the same set the Connect transport admits for plain HTTP.
/// `localhost` is trusted by name, as there; the resolver is not consulted.
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Read at most `limit` bytes of `body`, refusing a longer one while it is
/// received.
async fn read_bounded(mut body: hyper::body::Incoming, limit: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| format!("response body: {}", chain(&e)))?;
        if let Some(data) = frame.data_ref() {
            if out.len().saturating_add(data.len()) > limit {
                return Err("response exceeds the size limit".to_owned());
            }
            out.extend_from_slice(data);
        }
    }
    Ok(out)
}

/// Inflate a gzip body, refusing one that expands past `limit`.
fn gunzip_bounded(compressed: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(compressed)
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| format!("gzip response: {e}"))?;
    if out.len() > limit {
        return Err("response exceeds the size limit once decompressed".to_owned());
    }
    Ok(out)
}

impl HttpTransport for NativeHttp {
    async fn send(
        &self,
        request: Request<Vec<u8>>,
        response_limit: usize,
    ) -> Result<Response<Vec<u8>>, String> {
        let (mut parts, body) = request.into_parts();
        if parts.uri.scheme_str() == Some("http")
            && !self.allow_insecure_http
            && !parts.uri.host().is_some_and(is_loopback_host)
        {
            return Err("cleartext http to a non-loopback host refused".to_owned());
        }
        parts
            .headers
            .insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        parts.headers.insert(
            USER_AGENT,
            HeaderValue::from_static(concat!("mkit-sync/", env!("CARGO_PKG_VERSION"))),
        );
        let request = Request::from_parts(parts, Full::new(Bytes::from(body)));
        let exchange = async {
            let response = self
                .client
                .request(request)
                .await
                .map_err(|e| format!("request failed: {}", chain(&e)))?;
            // Redirects are never followed: a redirect would carry a signed
            // request to an origin the signature was not made for.
            if response.status().is_redirection() {
                return Err("redirect refused".to_owned());
            }
            let (mut parts, body) = response.into_parts();
            let wire = read_bounded(body, response_limit).await?;
            let mut codings = parts.headers.get_all(CONTENT_ENCODING).iter();
            let coding = match (codings.next(), codings.next()) {
                (None, _) => None,
                (Some(v), None) => Some(
                    v.to_str()
                        .map_err(|_| "unreadable content-encoding".to_owned())?
                        .trim()
                        .to_ascii_lowercase(),
                ),
                (Some(_), Some(_)) => {
                    return Err("unsupported content-encoding (gzip only)".to_owned());
                }
            };
            let bytes = match coding.as_deref() {
                None | Some("identity") => wire,
                Some("gzip") => gunzip_bounded(&wire, response_limit)?,
                Some(_) => return Err("unsupported content-encoding (gzip only)".to_owned()),
            };
            parts.headers.remove(CONTENT_ENCODING);
            parts.headers.remove(CONTENT_LENGTH);
            Ok(Response::from_parts(parts, bytes))
        };
        tokio::time::timeout(self.timeout, exchange)
            .await
            .map_err(|_| "request timed out".to_owned())?
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
