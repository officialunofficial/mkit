//! [`S3BlobStore`]: the content-addressed [`BlobStore`] over an
//! S3-compatible bucket (AWS S3, R2's S3 API, `MinIO`), signed with
//! `mkit-transport-s3`'s `SigV4` code (PRD §5.1, §5.3).
//!
//! **Keys.** `<prefix/><keyspace>/<64-hex>` in one bucket, addressed
//! path-style (`<endpoint>/<bucket>/<key>`), `packs` by default: the key
//! shape vcs-worker's R2 layout uses.
//!
//! **Verify before visible: spool, verify, then one conditional `PUT`.** An
//! upload spools to an unnamed temp file (unlinked at creation, so neither
//! a dropped sink nor a crashed process leaves anything behind) while it
//! computes BLAKE3 (the identity) and SHA-256 (the `SigV4` payload hash)
//! incrementally. [`PackSink::commit`] checks the length and the BLAKE3
//! against the key **before any request is issued**; only then does it send
//! one `PUT` with `If-None-Match: *`, its body streamed back from the spool
//! file. S3 makes an object visible only once its whole body has arrived,
//! so nothing unverified is ever visible under a key, and an abort, a
//! mismatch or a dropped sink never sends a request at all.
//!
//! The cost: every upload is written to local disk once and read back once,
//! and the `PUT` starts only after the last byte arrived, so an upload's
//! latency is the client transfer plus the bucket transfer. Local disk
//! (under the spool directory, `<repo-root>/.mkit/server-spool` in the
//! binary) must hold the concurrent uploads, each up to the pack cap; memory
//! stays at one chunk per upload. The alternatives trade that for other
//! costs: a staging key plus a server-side copy doubles the bucket writes
//! and leaves orphans on a crash, and a multipart upload completed only
//! after verification needs parts of at least 5 MiB and an
//! abort-incomplete-multipart-upload lifecycle rule; resumable multipart
//! arrives in M1 (#1090).
//!
//! **Put-if-absent.** `412 Precondition Failed` is
//! [`CommitOutcome::AlreadyPresent`]. A `409` (a concurrent `DELETE`), a
//! `429` or a `5xx` is retried from the spool, up to [`PUT_ATTEMPTS`] times.
//! Because a key only ever holds verified bytes, a failed `PUT` whose key is
//! then present with the right length is `AlreadyPresent` too.
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

use std::fmt::{self, Write as _};
use std::fs::File;
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use futures_util::{Stream, StreamExt as _};
use mkit_core::hash::{Hasher, to_hex_bytes};
use mkit_server::storage_error::{StorageOp, describe_and_map};
use mkit_server::store::MAX_BLOB_PIECE_BYTES;
use mkit_server::{
    BlobBody, BlobKey, BlobMeta, BlobStore, ByteRange, Clock, CommitOutcome, PackSink, Redactor,
    StoreError,
};
use mkit_transport_s3::sigv4;
pub use mkit_transport_s3::sigv4::Credentials;
use reqwest::header::{self, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, Response, StatusCode};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::PROBE_CACHE_TTL;
use crate::blocking::on_pool;

/// The pack keyspace: objects are `<prefix/>packs/<hex>`.
pub const PACKS_KEYSPACE: &str = "packs";

/// The largest body one S3 `PUT` accepts (5 GiB).
pub const MAX_SINGLE_PUT_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// How many times a commit sends its `PUT` before it gives up.
pub const PUT_ATTEMPTS: u32 = 3;

/// The piece size a `PUT` body is read from the spool in.
const SPOOL_READ_BYTES: usize = 256 * 1024;

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

/// The last probe: when it ran and whether it passed.
type ProbeCache = tokio::sync::Mutex<Option<(Instant, bool)>>;

/// A content-addressed [`BlobStore`] for one keyspace of an S3 bucket (see
/// the module docs). Needs a tokio runtime.
#[derive(Clone)]
pub struct S3BlobStore {
    client: reqwest::Client,
    /// `scheme://host[:port]`, signed as `host`.
    origin: String,
    bucket: String,
    /// `/<bucket>/<prefix/><keyspace>/`.
    object_base: String,
    credentials: Credentials,
    clock: Arc<dyn Clock>,
    spool_dir: Option<PathBuf>,
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
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            // Per read, not per request: a long download keeps going.
            .read_timeout(Duration::from_mins(1))
            // A redirect (a wrong region) would need a new signature.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| fail(StorageOp::BlobBinding, e))?;
        let prefix = cfg.prefix.map(|p| format!("{p}/")).unwrap_or_default();
        Ok(Self {
            client,
            origin,
            object_base: format!("/{}/{prefix}{keyspace}/", cfg.bucket),
            bucket: cfg.bucket,
            credentials: cfg.credentials,
            clock,
            spool_dir: None,
            max_bytes: MAX_SINGLE_PUT_BYTES,
            probe: Arc::default(),
        })
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

    /// Send a request signed for `payload_sha256`.
    async fn send(
        &self,
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
        let mut request = self
            .client
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
            .send(Method::HEAD, path, EMPTY_SHA256, HeaderMap::new(), None)
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

    /// `PUT` the verified spool under `key`, if absent.
    async fn put_verified(
        &self,
        key: &BlobKey,
        spool: Arc<File>,
        len: u64,
        sha256: &str,
    ) -> Result<CommitOutcome, StoreError> {
        let path = self.object_path(key);
        let mut last = String::new();
        for attempt in 0..PUT_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(100 << (2 * attempt))).await;
            }
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
            headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            let body = reqwest::Body::wrap_stream(spool_stream(Arc::clone(&spool), len));
            match self
                .send(Method::PUT, &path, sha256, headers, Some(body))
                .await
            {
                Ok(resp) => match resp.status() {
                    StatusCode::OK => return Ok(CommitOutcome::Created),
                    StatusCode::PRECONDITION_FAILED => return Ok(CommitOutcome::AlreadyPresent),
                    s if retryable(s) => last = describe(&resp, "PUT", s).await_code(resp).await,
                    _ => return Err(status_error(StorageOp::BlobPut, "PUT", resp).await),
                },
                Err(e) => last = format!("PUT: {e}"),
            }
        }
        // A key only ever holds verified bytes: if it is present now (a
        // racing writer, or our own PUT whose answer was lost), ours are.
        if matches!(self.head_len(&path).await, Ok(Some(n)) if n == len) {
            return Ok(CommitOutcome::AlreadyPresent);
        }
        Err(fail(StorageOp::BlobPut, last))
    }
}

/// A `PUT` answer worth retrying: a concurrent-delete conflict, throttling
/// or a server fault.
fn retryable(status: StatusCode) -> bool {
    status == StatusCode::CONFLICT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
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

/// Read `buf.len()` bytes of `file` at `offset`, leaving its cursor alone
/// (a retried `PUT` must not race an abandoned one's reads).
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        let mut done = 0;
        while done < buf.len() {
            let n = std::os::windows::fs::FileExt::seek_read(
                file,
                &mut buf[done..],
                offset + done as u64,
            )?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            done += n;
        }
        Ok(())
    }
}

/// The spool's first `len` bytes, [`SPOOL_READ_BYTES`] at a time, each
/// read on the blocking pool.
fn spool_stream(
    spool: Arc<File>,
    len: u64,
) -> impl Stream<Item = Result<Bytes, StoreError>> + Send + 'static {
    futures_util::stream::unfold(0_u64, move |offset| {
        let spool = Arc::clone(&spool);
        async move {
            if offset >= len {
                return None;
            }
            let n =
                usize::try_from(len - offset).map_or(SPOOL_READ_BYTES, |r| r.min(SPOOL_READ_BYTES));
            let piece = on_pool(move || {
                let mut buf = vec![0; n];
                read_at(&spool, &mut buf, offset).map_err(|e| fail(StorageOp::FsIo, e))?;
                Ok(Bytes::from(buf))
            })
            .await;
            // After an error the stream ends: the offset jumps past `len`.
            let next = if piece.is_ok() {
                offset + n as u64
            } else {
                len
            };
            Some((piece, next))
        }
    })
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
        let dir = self.spool_dir.clone();
        let file = on_pool(move || {
            match dir {
                Some(dir) => tempfile::tempfile_in(dir),
                None => tempfile::tempfile(),
            }
            .map_err(|e| fail(StorageOp::FsIo, format!("creating an upload spool: {e}")))
        })
        .await?;
        Ok(S3PackSink {
            store: self.clone(),
            key,
            declared: len,
            written: 0,
            spool: Some(Spool {
                file,
                blake3: Hasher::new(),
                sha256: Sha256::new(),
            }),
            failed: false,
        })
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
            .send(Method::GET, &path, EMPTY_SHA256, headers, None)
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

    /// `HEAD` on the bucket, at most once per [`PROBE_CACHE_TTL`]
    /// (unauthenticated health checks must not become one billed request
    /// each).
    async fn probe(&self) -> Result<(), StoreError> {
        let mut last = self.probe.lock().await;
        if let Some((at, ok)) = *last
            && at.elapsed() < PROBE_CACHE_TTL
        {
            return if ok {
                Ok(())
            } else {
                Err(StoreError::unavailable("bucket probe failed (cached)"))
            };
        }
        let path = format!("/{}", self.bucket);
        let result = match self
            .send(Method::HEAD, &path, EMPTY_SHA256, HeaderMap::new(), None)
            .await
        {
            Ok(resp) if resp.status() == StatusCode::OK => Ok(()),
            Ok(resp) => Err(status_error(StorageOp::BlobHead, "HEAD bucket", resp).await),
            Err(e) => Err(fail(StorageOp::BlobHead, e)),
        };
        *last = Some((Instant::now(), result.is_ok()));
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
            .send(Method::DELETE, &path, EMPTY_SHA256, HeaderMap::new(), None)
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

/// An upload's spool file and its two running hashes.
struct Spool {
    /// Unnamed: it goes away with its last handle, even on a crash.
    file: File,
    blake3: Hasher,
    sha256: Sha256,
}

impl Spool {
    fn append(&mut self, chunk: &[u8]) -> io::Result<()> {
        self.file.write_all(chunk)?;
        self.blake3.update(chunk);
        self.sha256.update(chunk);
        Ok(())
    }
}

/// The upload handle of [`S3BlobStore`]: bytes go to a local spool file,
/// never to the bucket, until [`PackSink::commit`] has verified them.
/// Memory is one chunk, never the blob.
pub struct S3PackSink {
    store: S3BlobStore,
    key: BlobKey,
    declared: u64,
    written: u64,
    /// `None` once failed, or lost to a cancelled write.
    spool: Option<Spool>,
    failed: bool,
}

impl fmt::Debug for S3PackSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3PackSink")
            .field("key", &self.key.to_hex())
            .field("declared", &self.declared)
            .field("written", &self.written)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl S3PackSink {
    /// The spool file's size: the upload's bytes are on disk, not in
    /// memory. For tests.
    #[doc(hidden)]
    #[must_use]
    pub fn spooled_bytes(&self) -> Option<u64> {
        let spool = self.spool.as_ref()?;
        spool.file.metadata().ok().map(|m| m.len())
    }

    fn fail(&mut self) {
        self.failed = true;
        self.spool = None;
    }
}

fn sink_gone() -> StoreError {
    StoreError::unavailable("upload spool lost to a cancelled write")
}

impl PackSink for S3PackSink {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        if self.failed {
            return Err(StoreError::Invalid("write after a failed write".into()));
        }
        let total = self.written.checked_add(chunk.len() as u64);
        let Some(total) = total.filter(|t| *t <= self.declared) else {
            self.fail();
            return Err(StoreError::Invalid("blob is longer than declared".into()));
        };
        if chunk.is_empty() {
            return Ok(());
        }
        let Some(mut spool) = self.spool.take() else {
            self.failed = true;
            return Err(sink_gone());
        };
        // If this future is dropped mid-write, the spool goes with the
        // blocking task, and later calls fail.
        let appended = on_pool(move || {
            let result = spool.append(&chunk);
            Ok((spool, result))
        })
        .await;
        match appended {
            Ok((spool, Ok(()))) => {
                self.spool = Some(spool);
                self.written = total;
                Ok(())
            }
            Ok((_, Err(e))) => {
                self.fail();
                Err(fail(
                    StorageOp::FsIo,
                    format!("writing an upload spool: {e}"),
                ))
            }
            Err(e) => {
                self.fail();
                Err(e)
            }
        }
    }

    async fn commit(mut self) -> Result<CommitOutcome, StoreError> {
        if self.failed {
            return Err(StoreError::Invalid("commit after a failed write".into()));
        }
        if self.written != self.declared {
            return Err(StoreError::Invalid("blob length does not match".into()));
        }
        let spool = self.spool.take().ok_or_else(sink_gone)?;
        // Verify first: nothing is sent for bytes that do not match.
        if spool.blake3.finalize() != self.key.0 {
            return Err(StoreError::Invalid(
                "blob hash does not match its key".into(),
            ));
        }
        let sha256 = to_hex_bytes(&spool.sha256.finalize());
        self.store
            .put_verified(&self.key, Arc::new(spool.file), self.declared, &sha256)
            .await
    }

    /// Nothing was sent: dropping the spool discards the upload.
    async fn abort(self) {}
}
