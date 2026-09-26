//! [`S3BlobStore`]: the content-addressed [`BlobStore`] over an
//! S3-compatible bucket (AWS S3, R2's S3 API, `MinIO`), signed with
//! `mkit-transport-s3`'s `SigV4` code (PRD §5.1, §5.3).
//!
//! **Keys.** `<prefix/><keyspace>/<64-hex>` in one bucket, addressed
//! path-style (`<endpoint>/<bucket>/<key>`), `packs` by default: the key
//! shape vcs-worker's R2 layout uses.
//!
//! **Verify before visible: spool, verify, then one conditional `PUT`.** An
//! upload spools to an unnamed temp file (`O_TMPFILE` on Linux; elsewhere a
//! `.tmp*` file unlinked right after it is created, and
//! [`sweep_spool_dir`] clears the names a crash in between leaves) while it
//! computes BLAKE3 (the identity) and SHA-256 (the `SigV4` payload hash)
//! incrementally. Each upload reserves its declared length from a spool
//! budget ([`DEFAULT_SPOOL_MAX_BYTES`]) at `begin`, before any byte
//! arrives; with no room, `begin` is [`StoreError::Full`]. A full disk or
//! quota while spooling is `Full` too.
//! [`PackSink::commit`](mkit_server::PackSink::commit) checks the length
//! and the BLAKE3 against the key **before any request is issued**; only
//! then does it send
//! one `PUT` with `If-None-Match: *`, its body streamed back from the spool
//! file. S3 makes an object visible only once its whole body has arrived,
//! so nothing unverified is ever visible under a key, and an abort, a
//! mismatch or a dropped sink never sends a request at all.
//!
//! The cost: every upload is written to local disk once and read back once,
//! and the `PUT` starts only after the last byte arrived, so an upload's
//! latency is the client transfer plus the bucket transfer. Local disk
//! (under the spool directory, `<repo-root>/.mkit/server-spool` in the
//! binary) must hold the concurrent uploads, within the spool budget;
//! memory stays at one chunk per upload. The alternatives trade that for other
//! costs: a staging key plus a server-side copy doubles the bucket writes
//! and leaves orphans on a crash, and a multipart upload completed only
//! after verification needs parts of at least 5 MiB and an
//! abort-incomplete-multipart-upload lifecycle rule; resumable multipart
//! arrives in M1 (#1090).
//!
//! **Put-if-absent.** `412 Precondition Failed` is
//! [`CommitOutcome::AlreadyPresent`](mkit_server::CommitOutcome::AlreadyPresent).
//! A `409` (a concurrent `DELETE`), a `429`, a `5xx` or a `400 RequestTimeout` is retried from the spool, up
//! to [`PUT_ATTEMPTS`] times, with jittered exponential backoff that
//! honors `Retry-After`. Each attempt ends early if the body stops moving
//! (or the answer stops coming) for the stall timeout (60 s), and in any
//! case after [`PUT_DEADLINE_BASE`] plus the body at
//! [`PUT_MIN_BYTES_PER_SEC`]. Because a key only ever holds verified bytes,
//! a failed `PUT` whose key is then present with the right length is
//! `AlreadyPresent` too.
//! `--blob s3` expects a provider that honors `If-None-Match: *` on `PUT`
//! (AWS S3 since 2024, R2, `MinIO`). One that ignores it stays correct, since
//! a re-put rewrites identical bytes atomically; it only reports `Created`
//! where `AlreadyPresent` was due, which the contract allows.
//!
//! **Size.** One `PUT` carries at most [`MAX_SINGLE_PUT_BYTES`] (S3's 5 GiB
//! limit); the pipeline's pack cap (4 GiB by default) is below it.
//!
//! **Get.** A body is always a [`BlobBody::Stream`] over the response body,
//! re-chunked to pieces of at most [`MAX_BLOB_PIECE_BYTES`] and checked
//! against its length. A range is one `GET` with `Range`; a `206` must carry
//! the `Content-Range` asked for. A `416` is answered with the blob's length
//! from a `HEAD`, since S3 need not report it.
//!
//! **Errors.** Every backend failure is logged server-side with its HTTP
//! status and S3 error code, and surfaces as [`StoreError::Unavailable`]
//! carrying only a fixed public message (`storage_error`). Request headers
//! are never logged; the `Authorization` value is marked sensitive.
//! Credentials come from the operator's environment or a secret file
//! ([`crate::config`]); their `Debug` output is redacted.

mod put;
mod sink;

use std::fmt::{self, Write as _};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use futures_util::{Stream, StreamExt as _};
use mkit_server::storage_error::{StorageOp, describe_and_map};
use mkit_server::store::MAX_BLOB_PIECE_BYTES;
use mkit_server::{BlobBody, BlobKey, BlobMeta, BlobStore, ByteRange, Clock, Redactor, StoreError};
use mkit_transport_s3::sigv4;
pub use mkit_transport_s3::sigv4::Credentials;
use reqwest::header::{self, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, Response, StatusCode};
use url::Url;

pub use self::put::{PUT_ATTEMPTS, PUT_DEADLINE_BASE, PUT_MIN_BYTES_PER_SEC};
use self::sink::SpoolBudget;
pub use self::sink::{S3PackSink, sweep_spool_dir};
use crate::PROBE_CACHE_TTL;

/// The pack keyspace: objects are `<prefix/>packs/<hex>`.
pub const PACKS_KEYSPACE: &str = "packs";

/// The largest body one S3 `PUT` accepts (5 GiB).
pub const MAX_SINGLE_PUT_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// The default spool budget: the declared bytes of all open uploads
/// together (16 GiB).
pub const DEFAULT_SPOOL_MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// How long a `PUT` may go without its body moving, or without an answer
/// once the body is sent, before the attempt is abandoned.
pub const DEFAULT_STALL_TIMEOUT: Duration = Duration::from_mins(1);

/// How long a bucket probe may take.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// How much of an error response is read to find its S3 error code.
const ERROR_BODY_LIMIT: usize = 4096;

/// SHA-256 of the empty body, for `GET`, `HEAD` and `DELETE`.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Response headers worth a log line: the request ids a provider's support
/// asks for.
const LOGGED_RESPONSE_HEADERS: [&str; 2] = ["x-amz-request-id", "x-amz-id-2"];

/// Where an [`S3BlobStore`] keeps its blobs, and the credentials it signs
/// with. `Debug` redacts the secret key ([`Credentials`]).
#[derive(Debug, Clone)]
pub struct S3Config {
    /// The S3 API origin, `http(s)://host[:port]`, with no path, query or
    /// user info (e.g. `https://<account>.r2.cloudflarestorage.com`).
    pub endpoint: Url,
    /// The bucket.
    pub bucket: String,
    /// A key prefix: `/`-separated segments of `A-Z a-z 0-9 . _ -`.
    pub prefix: Option<String>,
    /// The signing credentials and region.
    pub credentials: Credentials,
}

impl S3Config {
    /// Check every field; the endpoint's origin as it is signed (`host`)
    /// and requested.
    ///
    /// # Errors
    /// Why the configuration cannot be used.
    pub fn validate(&self) -> Result<String, String> {
        let url = &self.endpoint;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(format!("endpoint {url}: the scheme must be http or https"));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(
                "the endpoint must not carry user info; pass credentials by environment or file"
                    .into(),
            );
        }
        if url.query().is_some() || url.fragment().is_some() || !matches!(url.path(), "" | "/") {
            return Err(format!(
                "endpoint {url}: only an origin (scheme, host, port) is allowed"
            ));
        }
        let Some(host) = url.host_str() else {
            return Err(format!("endpoint {url} names no host"));
        };
        if !valid_bucket(&self.bucket) {
            return Err(format!(
                "bucket {:?}: 3 to 63 of a-z 0-9 . -, starting and ending with a letter or digit",
                self.bucket
            ));
        }
        if let Some(prefix) = &self.prefix
            && !valid_prefix(prefix)
        {
            return Err(format!(
                "prefix {prefix:?}: /-separated segments of A-Z a-z 0-9 . _ - (not . or ..)"
            ));
        }
        let creds = &self.credentials;
        if creds.access_key_id.is_empty() || creds.secret_access_key.is_empty() {
            return Err("the access key id and secret access key must not be empty".into());
        }
        if creds.region.is_empty()
            || !creds
                .region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(format!("region {:?}: a-z 0-9 -", creds.region));
        }
        Ok(match url.port() {
            Some(port) => format!("{}://{host}:{port}", url.scheme()),
            None => format!("{}://{host}", url.scheme()),
        })
    }
}

fn valid_bucket(b: &str) -> bool {
    let edge = |c: Option<u8>| c.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    (3..=63).contains(&b.len())
        && b.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-')
        && edge(b.bytes().next())
        && edge(b.bytes().last())
}

fn valid_prefix(p: &str) -> bool {
    p.len() <= 512
        && p.split('/').all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        })
}

impl S3Config {
    /// Whether the endpoint's host is loopback (`localhost`, `127/8`,
    /// `::1`): plain `http` there never crosses a network.
    #[must_use]
    pub fn endpoint_is_loopback(&self) -> bool {
        match self.endpoint.host() {
            Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        }
    }
}

/// The last probe: when it ran and whether it passed.
type ProbeCache = Mutex<Option<(Instant, bool)>>;

/// A content-addressed [`BlobStore`] for one keyspace of an S3 bucket (see
/// the module docs). Needs a tokio runtime.
#[derive(Clone)]
pub struct S3BlobStore {
    /// `GET`, `HEAD`, `DELETE`: a read timeout from the request's start.
    client: reqwest::Client,
    /// `PUT`: no read timeout; the stall timeout and deadline bound it.
    put_client: reqwest::Client,
    /// `scheme://host[:port]`, signed as `host`.
    origin: String,
    bucket: String,
    /// `/<bucket>/<prefix/><keyspace>/`.
    object_base: String,
    credentials: Credentials,
    clock: Arc<dyn Clock>,
    spool_dir: Option<PathBuf>,
    spool: Arc<SpoolBudget>,
    stall_timeout: Duration,
    max_bytes: u64,
    probe: Arc<ProbeCache>,
}

impl fmt::Debug for S3BlobStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3BlobStore")
            .field("origin", &self.origin)
            .field("object_base", &self.object_base)
            .field("credentials", &self.credentials)
            .field("spool_dir", &self.spool_dir)
            .field("spool_max_bytes", &self.spool.max())
            .field("max_bytes", &self.max_bytes)
            .finish_non_exhaustive()
    }
}

impl S3BlobStore {
    /// The [`PACKS_KEYSPACE`] store over `cfg`, signing with `clock`'s time.
    /// Uploads spool under the system temp directory until
    /// [`Self::with_spool_dir`].
    ///
    /// # Errors
    /// [`StoreError::Invalid`] for a configuration [`S3Config::validate`]
    /// rejects; [`StoreError::Unavailable`] if the HTTP client cannot be
    /// built.
    pub fn new(cfg: S3Config, clock: Arc<dyn Clock>) -> Result<Self, StoreError> {
        Self::with_keyspace(cfg, PACKS_KEYSPACE, clock)
    }

    /// [`Self::new`] for `keyspace`, one plain key segment.
    ///
    /// # Errors
    /// As [`Self::new`], and [`StoreError::Invalid`] for a bad keyspace.
    pub fn with_keyspace(
        cfg: S3Config,
        keyspace: &'static str,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, StoreError> {
        let origin = cfg.validate().map_err(|e| StoreError::Invalid(e.into()))?;
        if keyspace.contains('/') || !valid_prefix(keyspace) {
            return Err(StoreError::Invalid(
                format!("keyspace {keyspace:?} is not one plain segment").into(),
            ));
        }
        let builder = || {
            reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                // A redirect (a wrong region) would need a new signature.
                .redirect(reqwest::redirect::Policy::none())
        };
        let client = builder()
            // reqwest's read timeout bounds the wait for the answer from the
            // request's start, then each body read: right for bodiless
            // requests, fatal for a long upload (hence `put_client`).
            .read_timeout(Duration::from_mins(1))
            .build()
            .map_err(|e| fail(StorageOp::BlobBinding, e))?;
        let put_client = builder()
            .build()
            .map_err(|e| fail(StorageOp::BlobBinding, e))?;
        let prefix = cfg.prefix.map(|p| format!("{p}/")).unwrap_or_default();
        Ok(Self {
            client,
            put_client,
            origin,
            object_base: format!("/{}/{prefix}{keyspace}/", cfg.bucket),
            bucket: cfg.bucket,
            credentials: cfg.credentials,
            clock,
            spool_dir: None,
            spool: Arc::new(SpoolBudget::new(DEFAULT_SPOOL_MAX_BYTES)),
            stall_timeout: DEFAULT_STALL_TIMEOUT,
            max_bytes: MAX_SINGLE_PUT_BYTES,
            probe: Arc::default(),
        })
    }

    /// Let the uploads in flight declare at most `max_bytes` of spool in
    /// total (default [`DEFAULT_SPOOL_MAX_BYTES`]); a `begin` that does not
    /// fit is [`StoreError::Full`] before any byte arrives.
    #[must_use]
    pub fn with_spool_max_bytes(mut self, max_bytes: u64) -> Self {
        self.spool = Arc::new(SpoolBudget::new(max_bytes));
        self
    }

    /// Abandon a `PUT` attempt after `timeout` without progress (default
    /// [`DEFAULT_STALL_TIMEOUT`]).
    #[must_use]
    pub fn with_stall_timeout(mut self, timeout: Duration) -> Self {
        self.stall_timeout = timeout;
        self
    }

    /// The spool bytes the open uploads have reserved.
    #[must_use]
    pub fn spool_reserved_bytes(&self) -> u64 {
        self.spool.reserved()
    }

    /// Spool uploads in `dir` (it must exist) rather than the system temp
    /// directory, which may be a RAM-backed tmpfs.
    #[must_use]
    pub fn with_spool_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.spool_dir = Some(dir.into());
        self
    }

    /// Cap one blob at `max_bytes` (at most [`MAX_SINGLE_PUT_BYTES`]).
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes.min(MAX_SINGLE_PUT_BYTES);
        self
    }

    /// The object key of `key`: `<prefix/><keyspace>/<hex>`.
    #[must_use]
    pub fn object_key(&self, key: &BlobKey) -> String {
        let base = &self.object_base[self.bucket.len() + 2..];
        format!("{base}{}", key.to_hex())
    }

    fn object_path(&self, key: &BlobKey) -> String {
        format!("{}{}", self.object_base, key.to_hex())
    }

    /// Send a bodiless request.
    async fn send(
        &self,
        method: Method,
        path: &str,
        headers: HeaderMap,
    ) -> Result<Response, reqwest::Error> {
        self.send_with(&self.client, method, path, EMPTY_SHA256, headers, None)
            .await
    }

    /// Send a request signed for `payload_sha256` through `client`.
    async fn send_with(
        &self,
        client: &reqwest::Client,
        method: Method,
        path: &str,
        payload_sha256: &str,
        mut headers: HeaderMap,
        body: Option<reqwest::Body>,
    ) -> Result<Response, reqwest::Error> {
        let now = self.clock.now_ms().div_euclid(1000);
        let signed = sigv4::sign_request_with_payload_hash(
            &self.credentials,
            method.as_str(),
            path,
            "",
            payload_sha256,
            &self.origin,
            now,
        );
        // Every value is ASCII the signer built, so these never fail.
        let mut authorization = HeaderValue::from_str(&signed.authorization)
            .unwrap_or_else(|_| HeaderValue::from_static("invalid"));
        authorization.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, authorization);
        for (name, value) in [
            ("x-amz-date", signed.x_amz_date),
            ("x-amz-content-sha256", signed.x_amz_content_sha256),
        ] {
            if let Ok(value) = HeaderValue::from_str(&value) {
                headers.insert(HeaderName::from_static(name), value);
            }
        }
        let mut request = client
            .request(method, format!("{}{path}", self.origin))
            .headers(headers);
        if let Some(body) = body {
            request = request.body(body);
        }
        request.send().await
    }

    /// The object's length, if present.
    async fn head_len(&self, path: &str) -> Result<Option<u64>, StoreError> {
        let resp = self
            .send(Method::HEAD, path, HeaderMap::new())
            .await
            .map_err(|e| fail(StorageOp::BlobHead, e))?;
        match resp.status() {
            StatusCode::OK => content_length(&resp)
                .map(Some)
                .ok_or_else(|| fail(StorageOp::BlobHead, "HEAD answered without Content-Length")),
            // A HEAD answer has no body, so no error code to check.
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(status_error(StorageOp::BlobHead, "HEAD", resp).await),
        }
    }
}

/// The log line and client error for a failed backend call.
fn fail(op: StorageOp, detail: impl fmt::Display) -> StoreError {
    let (line, err) = describe_and_map(op, detail);
    tracing::warn!(detail = %line, "storage failure");
    StoreError::unavailable(err)
}

/// The start of a failure line: the call, its status and the request ids,
/// each passed through the [`Redactor`].
struct Described(String);

fn describe(resp: &Response, what: &str, status: StatusCode) -> Described {
    let redactor = Redactor::default();
    let mut line = format!("{what}: HTTP {status}");
    for name in LOGGED_RESPONSE_HEADERS {
        if let Some(value) = resp.headers().get(name).and_then(|v| v.to_str().ok()) {
            let _ = write!(line, " {name}={}", redactor.loggable(name, value));
        }
    }
    Described(line)
}

impl Described {
    /// Append the response's S3 error code, read from at most
    /// [`ERROR_BODY_LIMIT`] bytes of its body.
    async fn await_code(self, resp: Response) -> String {
        match s3_error_code(resp).await {
            Some(code) => format!("{} {code}", self.0),
            None => self.0,
        }
    }
}

async fn status_error(op: StorageOp, what: &str, resp: Response) -> StoreError {
    let status = resp.status();
    fail(op, describe(&resp, what, status).await_code(resp).await)
}

/// The `<Code>` of an S3 error body, if it has a plausible one.
async fn s3_error_code(resp: Response) -> Option<String> {
    let mut body = BytesMut::new();
    let mut stream = resp.bytes_stream();
    while body.len() < ERROR_BODY_LIMIT {
        match stream.next().await {
            Some(Ok(piece)) => body.extend_from_slice(&piece),
            _ => break,
        }
    }
    let text = String::from_utf8_lossy(&body);
    let start = text.find("<Code>")? + "<Code>".len();
    let code = &text[start..start + text[start..].find("</Code>")?];
    (code.len() <= 64 && code.bytes().all(|b| b.is_ascii_alphanumeric())).then(|| code.to_owned())
}

/// A `404` from `GET` or `DELETE`: absent only for `NoSuchKey` (or no
/// error body); a missing bucket is a failure, not an absent blob.
async fn absent_or_error(op: StorageOp, what: &str, resp: Response) -> Result<(), StoreError> {
    let line = describe(&resp, what, resp.status());
    match s3_error_code(resp).await {
        None => Ok(()),
        Some(code) if code == "NoSuchKey" => Ok(()),
        Some(code) => Err(fail(op, format!("{} {code}", line.0))),
    }
}

/// The `Content-Length` header (reqwest's own accessor reads the body's
/// size hint, which is 0 for `HEAD`).
fn content_length(resp: &Response) -> Option<u64> {
    resp.headers()
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// `Content-Range: bytes <first>-<last>/<total>`.
fn content_range(resp: &Response) -> Option<(u64, u64, u64)> {
    let value = resp.headers().get(header::CONTENT_RANGE)?.to_str().ok()?;
    let (span, total) = value.strip_prefix("bytes ")?.split_once('/')?;
    let (first, last) = span.split_once('-')?;
    let (first, last, total) = (first.parse().ok()?, last.parse().ok()?, total.parse().ok()?);
    (first <= last && last < total).then_some((first, last, total))
}

/// A response body as the pieces of a [`BlobBody::Stream`] of `len` bytes.
fn stream_body(resp: Response, len: u64) -> BlobBody {
    BlobBody::Stream {
        len,
        stream: Box::pin(Pieces {
            inner: Box::pin(resp.bytes_stream()),
            remaining: len,
            rest: Bytes::new(),
            done: false,
        }),
    }
}

type ReqwestStream = Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>;

/// A response body re-chunked to pieces of at most
/// [`MAX_BLOB_PIECE_BYTES`], failing unless it is exactly `remaining`
/// bytes.
struct Pieces {
    inner: ReqwestStream,
    remaining: u64,
    rest: Bytes,
    done: bool,
}

impl Pieces {
    fn fail(&mut self, detail: impl fmt::Display) -> Poll<Option<Result<Bytes, StoreError>>> {
        self.done = true;
        Poll::Ready(Some(Err(fail(StorageOp::BlobRead, detail))))
    }
}

impl Stream for Pieces {
    type Item = Result<Bytes, StoreError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if this.done {
                return Poll::Ready(None);
            }
            if !this.rest.is_empty() {
                let n = this.rest.len().min(MAX_BLOB_PIECE_BYTES);
                return Poll::Ready(Some(Ok(this.rest.split_to(n))));
            }
            match this.inner.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(e))) => return this.fail(e),
                Poll::Ready(Some(Ok(piece))) => {
                    let n = piece.len() as u64;
                    if n > this.remaining {
                        return this.fail("object body longer than its length");
                    }
                    this.remaining -= n;
                    this.rest = piece;
                }
                Poll::Ready(None) if this.remaining > 0 => {
                    return this.fail("object body shorter than its length");
                }
                Poll::Ready(None) => this.done = true,
            }
        }
    }
}

impl BlobStore for S3BlobStore {
    type Sink = S3PackSink;

    async fn begin(&self, key: BlobKey, len: u64) -> Result<S3PackSink, StoreError> {
        if len > self.max_bytes {
            return Err(StoreError::Invalid(
                "blob exceeds the store's size cap".into(),
            ));
        }
        sink::begin(self, key, len).await
    }

    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        if range.is_some_and(|r| r.start > r.end_inclusive) {
            return Err(StoreError::Invalid("byte range start after its end".into()));
        }
        let path = self.object_path(key);
        let mut headers = HeaderMap::new();
        if let Some(r) = range {
            let value = format!("bytes={}-{}", r.start, r.end_inclusive);
            if let Ok(value) = HeaderValue::from_str(&value) {
                headers.insert(header::RANGE, value);
            }
        }
        let resp = self
            .send(Method::GET, &path, headers)
            .await
            .map_err(|e| fail(StorageOp::BlobGet, e))?;
        match (resp.status(), range) {
            (StatusCode::OK, _) => {
                let total = content_length(&resp).ok_or_else(|| {
                    fail(StorageOp::BlobGet, "GET answered without Content-Length")
                })?;
                if let Some(r) = range {
                    // A backend that ignores `Range` answers 200 with the
                    // whole blob; serve it only if that is what was asked.
                    if r.resolve(total)? != (0..total) {
                        return Err(fail(StorageOp::BlobGet, "the backend ignored a Range"));
                    }
                }
                Ok(Some(stream_body(resp, total)))
            }
            (StatusCode::PARTIAL_CONTENT, Some(r)) => {
                let (first, last, total) = content_range(&resp)
                    .ok_or_else(|| fail(StorageOp::BlobGet, "206 without a valid Content-Range"))?;
                let span = r.resolve(total)?;
                let len = span.end - span.start;
                if first != span.start
                    || last + 1 != span.end
                    || content_length(&resp).is_some_and(|n| n != len)
                {
                    return Err(fail(
                        StorageOp::BlobGet,
                        "206 for another range than requested",
                    ));
                }
                Ok(Some(stream_body(resp, len)))
            }
            (StatusCode::RANGE_NOT_SATISFIABLE, Some(r)) => {
                // S3 need not report the length: ask for it.
                let Some(len) = self.head_len(&path).await? else {
                    return Ok(None);
                };
                r.resolve(len)?;
                Err(fail(StorageOp::BlobGet, "416 for a satisfiable range"))
            }
            (StatusCode::NOT_FOUND, _) => {
                absent_or_error(StorageOp::BlobGet, "GET", resp).await?;
                Ok(None)
            }
            _ => Err(status_error(StorageOp::BlobGet, "GET", resp).await),
        }
    }

    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        Ok(self
            .head_len(&self.object_path(key))
            .await?
            .map(|len| BlobMeta { len }))
    }

    /// `HEAD` on the bucket, bounded by [`PROBE_TIMEOUT`]; a result answers
    /// every probe for [`PROBE_CACHE_TTL`] (unauthenticated health checks
    /// must not become one billed request each). No lock is held across
    /// the request: concurrent probes of an expired cache may each send
    /// one.
    async fn probe(&self) -> Result<(), StoreError> {
        let cached = *self.probe.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((at, ok)) = cached
            && at.elapsed() < PROBE_CACHE_TTL
        {
            return if ok {
                Ok(())
            } else {
                Err(StoreError::unavailable("bucket probe failed (cached)"))
            };
        }
        let path = format!("/{}", self.bucket);
        let sent = tokio::time::timeout(
            PROBE_TIMEOUT,
            self.send(Method::HEAD, &path, HeaderMap::new()),
        )
        .await;
        let result = match sent {
            Ok(Ok(resp)) if resp.status() == StatusCode::OK => Ok(()),
            Ok(Ok(resp)) => Err(status_error(StorageOp::BlobHead, "HEAD bucket", resp).await),
            Ok(Err(e)) => Err(fail(StorageOp::BlobHead, e)),
            Err(_) => Err(fail(
                StorageOp::BlobHead,
                format!("HEAD bucket: no answer within {PROBE_TIMEOUT:?}"),
            )),
        };
        *self.probe.lock().unwrap_or_else(PoisonError::into_inner) =
            Some((Instant::now(), result.is_ok()));
        result
    }

    /// A `HEAD` then a `DELETE`: S3's `DELETE` answers `204` whether or
    /// not the key existed.
    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        let path = self.object_path(key);
        if self.head_len(&path).await?.is_none() {
            return Ok(false);
        }
        let resp = self
            .send(Method::DELETE, &path, HeaderMap::new())
            .await
            .map_err(|e| fail(StorageOp::BlobPut, e))?;
        match resp.status() {
            StatusCode::NO_CONTENT | StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => {
                absent_or_error(StorageOp::BlobPut, "DELETE", resp).await?;
                Ok(false)
            }
            _ => Err(status_error(StorageOp::BlobPut, "DELETE", resp).await),
        }
    }
}
