//! [`FakeS3`]: a strict, in-memory S3 server for testing S3 blob stores in
//! normal CI, without Docker (feature `fake-s3`; a test utility, never in a
//! release binary).
//!
//! It models the S3 semantics a content-addressed store relies on, and
//! rejects what it does not model instead of accepting it silently: a
//! friendly simulation hides real bugs.
//!
//! - **Auth.** Every request must carry a valid `SigV4` `Authorization`
//!   header, which the fake verifies with its own implementation (not the
//!   store's signer, so a signing bug cannot verify itself): the credential
//!   scope (access key, region, `s3`), every `x-amz-*` header signed, the
//!   canonical request rebuilt from what arrived (method, path, query,
//!   signed header values), and `x-amz-content-sha256` checked against the
//!   body actually received. `403 InvalidAccessKeyId`,
//!   `403 SignatureDoesNotMatch`, `403 AccessDenied`,
//!   `400 AuthorizationHeaderMalformed`, `400 XAmzContentSHA256Mismatch`.
//! - **`PUT` object.** Path-style `/<bucket>/<key>`. `Content-Length` is
//!   required (`411 MissingContentLength`); `Transfer-Encoding` is not
//!   implemented (`501`); over 5 GiB is `400 EntityTooLarge`; a body that
//!   ends short is `400 IncompleteBody`. The object becomes visible only
//!   once the whole body has arrived and checked out.
//! - **Conditional `PUT`.** `If-None-Match: *` only (any other value, or
//!   `If-Match`, is `501 NotImplemented`). An existing key is
//!   `412 PreconditionFailed`, checked when the request arrives and again
//!   when its body is complete: of racing conditional writes, the first to
//!   finish wins (AWS). A `DELETE` of the key while a conditional write is
//!   in flight makes that write `409 ConditionalRequestConflict`.
//!   [`FakeS3Options::honor_if_none_match`] `false` models an older
//!   S3-compatible that ignores the header.
//! - **`GET` object.** `404 NoSuchKey`, or `404 NoSuchBucket`. A single
//!   `Range: bytes=a-b`, `a-` or `-n` is `206` with `Content-Range`; one
//!   that starts at or past the end is `416 InvalidRange`, **without**
//!   saying the length; an unparsable or multi-range header is ignored
//!   (`200`, the whole object), as RFC 9110 lets a server do.
//! - **`HEAD` object / bucket**, **`DELETE` object** (`204`, present or
//!   not).
//! - **Not modeled** (`501 NotImplemented`): any query subresource,
//!   multipart uploads included (resumable multipart arrives with M1),
//!   listing, and every other bucket operation.
//!
//! An error response carries an S3 XML error body (except for `HEAD`,
//! which has none) and an `x-amz-request-id`. Every request is recorded
//! ([`FakeS3::requests`]); faults can be injected ([`FakeS3::fail_next`]).
//! A request the fake answers early still has its body read first, so a
//! client never sees a reset instead of the answer.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt::{self, Write as _};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header};
use bytes::{Bytes, BytesMut};
use futures::StreamExt as _;
use hmac::{Hmac, KeyInit, Mac as _};
use mkit_server::Redactor;
use sha2::{Digest as _, Sha256};

/// The bucket [`FakeS3Options::default`] creates.
pub const DEFAULT_BUCKET: &str = "mkit-test";

/// S3's single-`PUT` limit.
const MAX_PUT_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// How a [`FakeS3`] is set up.
#[derive(Clone)]
pub struct FakeS3Options {
    /// The one access key it accepts.
    pub access_key_id: String,
    /// Its secret.
    pub secret_access_key: String,
    /// The region every signature must be scoped to.
    pub region: String,
    /// The buckets that exist.
    pub buckets: Vec<String>,
    /// Whether `If-None-Match: *` is enforced (`false`: ignored, as by
    /// some older S3-compatibles).
    pub honor_if_none_match: bool,
}

impl Default for FakeS3Options {
    fn default() -> Self {
        Self {
            access_key_id: "FAKEACCESSKEY0000000".to_owned(),
            secret_access_key: "fake/secret+access/key0000000000000000000".to_owned(),
            region: "auto".to_owned(),
            buckets: vec![DEFAULT_BUCKET.to_owned()],
            honor_if_none_match: true,
        }
    }
}

impl fmt::Debug for FakeS3Options {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeS3Options")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("region", &self.region)
            .field("buckets", &self.buckets)
            .field("honor_if_none_match", &self.honor_if_none_match)
            .finish()
    }
}

/// One request as the fake received and answered it.
#[derive(Clone)]
pub struct RecordedRequest {
    /// The method.
    pub method: Method,
    /// The raw path.
    pub path: String,
    /// The raw query, if any.
    pub query: Option<String>,
    /// Every header, lowercased name and value.
    pub headers: Vec<(String, String)>,
    /// Body bytes received.
    pub body_len: u64,
    /// The answer's status.
    pub status: StatusCode,
}

impl RecordedRequest {
    /// The first value of header `name` (lowercase).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Credentials never reach `Debug` output: header values pass through the
/// telemetry [`Redactor`].
impl fmt::Debug for RecordedRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redactor = Redactor::default();
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), redactor.loggable(n, v)))
            .collect();
        f.debug_struct("RecordedRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("query", &self.query)
            .field("headers", &headers)
            .field("body_len", &self.body_len)
            .field("status", &self.status)
            .finish()
    }
}

/// A queued fault: the next request matching `method` gets `status`.
struct Fault {
    method: Option<Method>,
    status: StatusCode,
}

#[derive(Default)]
struct Objects {
    buckets: HashMap<String, BTreeMap<String, Bytes>>,
    /// Per `(bucket, key)`: how many `DELETE`s it has seen.
    deletes: HashMap<(String, String), u64>,
    requests: Vec<RecordedRequest>,
    faults: VecDeque<Fault>,
    next_request_id: u64,
}

struct Shared {
    opts: FakeS3Options,
    objects: Mutex<Objects>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Objects> {
        self.objects.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A running fake S3 server on `127.0.0.1`, on its own thread and runtime,
/// so it works from sync and async tests alike. Dropping it stops it.
pub struct FakeS3 {
    addr: SocketAddr,
    shared: Arc<Shared>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl fmt::Debug for FakeS3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeS3")
            .field("addr", &self.addr)
            .field("opts", &self.shared.opts)
            .finish_non_exhaustive()
    }
}

impl FakeS3 {
    /// Start with [`FakeS3Options::default`].
    ///
    /// # Panics
    /// If the loopback listener or the server thread cannot start.
    #[must_use]
    pub fn start() -> Self {
        Self::start_with(FakeS3Options::default())
    }

    /// Start with `opts`.
    ///
    /// # Panics
    /// If the loopback listener or the server thread cannot start.
    #[must_use]
    pub fn start_with(opts: FakeS3Options) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
        listener
            .set_nonblocking(true)
            .expect("a non-blocking listener");
        let addr = listener.local_addr().expect("the listener's address");
        let mut objects = Objects::default();
        for bucket in &opts.buckets {
            objects.buckets.insert(bucket.clone(), BTreeMap::new());
        }
        let shared = Arc::new(Shared {
            opts,
            objects: Mutex::new(objects),
        });
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let state = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("fake-s3".to_owned())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("the fake S3 runtime");
                runtime.block_on(async move {
                    let listener =
                        tokio::net::TcpListener::from_std(listener).expect("a tokio listener");
                    let app = axum::Router::new().fallback(handle).with_state(state);
                    tokio::select! {
                        _ = axum::serve(listener, app).into_future() => {}
                        _ = stopped => {}
                    }
                });
                // Idle keep-alive connections die with the runtime.
                runtime.shutdown_background();
            })
            .expect("spawn the fake S3 thread");
        Self {
            addr,
            shared,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    /// `http://127.0.0.1:<port>`.
    #[must_use]
    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// How it was set up (its credentials, region and buckets).
    #[must_use]
    pub fn options(&self) -> &FakeS3Options {
        &self.shared.opts
    }

    /// Every request so far, oldest first.
    #[must_use]
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.shared.lock().requests.clone()
    }

    /// Forget the recorded requests.
    pub fn clear_requests(&self) {
        self.shared.lock().requests.clear();
    }

    /// The bytes stored under `key` in `bucket`.
    #[must_use]
    pub fn object(&self, bucket: &str, key: &str) -> Option<Bytes> {
        self.shared.lock().buckets.get(bucket)?.get(key).cloned()
    }

    /// Every key in `bucket`, in order.
    #[must_use]
    pub fn keys(&self, bucket: &str) -> Vec<String> {
        self.shared
            .lock()
            .buckets
            .get(bucket)
            .map(|b| b.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Store `bytes` under `key` directly, as another writer would.
    pub fn insert_object(&self, bucket: &str, key: &str, bytes: Bytes) {
        self.shared
            .lock()
            .buckets
            .entry(bucket.to_owned())
            .or_default()
            .insert(key.to_owned(), bytes);
    }

    /// Answer the next request whose method is `method` (any, for `None`)
    /// with `status` and a matching S3 error code, after reading its body.
    /// Queued faults fire in order.
    pub fn fail_next(&self, method: Option<Method>, status: StatusCode) {
        self.shared
            .lock()
            .faults
            .push_back(Fault { method, status });
    }
}

impl Drop for FakeS3 {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// An S3 error answer.
struct S3Error {
    status: StatusCode,
    code: &'static str,
    message: String,
}

fn err(status: StatusCode, code: &'static str, message: impl Into<String>) -> S3Error {
    S3Error {
        status,
        code,
        message: message.into(),
    }
}

fn not_implemented(what: &str) -> S3Error {
    err(
        StatusCode::NOT_IMPLEMENTED,
        "NotImplemented",
        format!("the fake S3 does not model {what}"),
    )
}

/// The S3 code a fault status carries.
fn fault_code(status: StatusCode) -> &'static str {
    match status.as_u16() {
        409 => "ConditionalRequestConflict",
        429 | 503 => "SlowDown",
        403 => "AccessDenied",
        _ => "InternalError",
    }
}

/// What a request resolved to, before it is recorded.
struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Answer {
    fn ok(status: StatusCode) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        }
    }

    fn error(e: &S3Error, path: &str, request_id: &str, head: bool) -> Self {
        let mut answer = Self::ok(e.status);
        if !head {
            answer.headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/xml"),
            );
            answer.body = Bytes::from(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{}</Code>\
                 <Message>{}</Message><Resource>{path}</Resource>\
                 <RequestId>{request_id}</RequestId></Error>",
                e.code, e.message
            ));
        }
        answer
    }
}

async fn handle(State(shared): State<Arc<Shared>>, request: Request<Body>) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path().to_owned();
    let query = parts.uri.query().map(str::to_owned);
    let (request_id, fault) = {
        let mut objects = shared.lock();
        objects.next_request_id += 1;
        let at = objects
            .faults
            .iter()
            .position(|f| f.method.as_ref().is_none_or(|m| *m == parts.method));
        let fault = at.and_then(|i| objects.faults.remove(i));
        (format!("{:016X}", objects.next_request_id), fault)
    };
    let mut received = 0;
    let head = parts.method == Method::HEAD;
    let result = match fault {
        Some(fault) => {
            received = drain(body).await;
            Err(err(
                fault.status,
                fault_code(fault.status),
                "injected fault",
            ))
        }
        None => {
            serve(
                &shared,
                &parts,
                &path,
                query.as_deref(),
                body,
                &mut received,
            )
            .await
        }
    };
    let mut answer = match result {
        Ok(answer) => answer,
        Err(e) => Answer::error(&e, &path, &request_id, head),
    };
    if let Ok(id) = HeaderValue::from_str(&request_id) {
        answer.headers.insert("x-amz-request-id", id);
    }
    shared.lock().requests.push(RecordedRequest {
        method: parts.method.clone(),
        path,
        query,
        headers: parts
            .headers
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_owned(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body_len: received,
        status: answer.status,
    });
    let mut response = Response::new(Body::from(answer.body));
    *response.status_mut() = answer.status;
    *response.headers_mut() = answer.headers;
    response
}

/// Read and discard a body; the bytes read.
async fn drain(body: Body) -> u64 {
    let mut stream = body.into_data_stream();
    let mut n = 0;
    while let Some(Ok(piece)) = stream.next().await {
        n += piece.len() as u64;
    }
    n
}

/// The body, if it is exactly `len` bytes; `received` counts what arrived.
async fn read_exact(body: Body, len: u64, received: &mut u64) -> Result<Bytes, S3Error> {
    let incomplete = || {
        err(
            StatusCode::BAD_REQUEST,
            "IncompleteBody",
            "the body does not match Content-Length",
        )
    };
    let mut stream = body.into_data_stream();
    let mut out = BytesMut::with_capacity(usize::try_from(len.min(64 << 20)).unwrap_or(0));
    while let Some(piece) = stream.next().await {
        let piece = piece.map_err(|_| incomplete())?;
        *received += piece.len() as u64;
        out.extend_from_slice(&piece);
    }
    if out.len() as u64 != len {
        return Err(incomplete());
    }
    Ok(out.freeze())
}

async fn serve(
    shared: &Shared,
    parts: &axum::http::request::Parts,
    path: &str,
    query: Option<&str>,
    body: Body,
    received: &mut u64,
) -> Result<Answer, S3Error> {
    let opts = &shared.opts;
    // An early answer still reads the body first (see the module docs).
    if let Err(e) = verify_sigv4(opts, parts, path, query.unwrap_or("")) {
        *received = drain(body).await;
        return Err(e);
    }
    let (bucket, key) = match path.strip_prefix('/').and_then(|p| p.split_once('/')) {
        Some((bucket, key)) => (bucket, key),
        None => (path.trim_start_matches('/'), ""),
    };
    if bucket.is_empty() {
        *received = drain(body).await;
        return Err(not_implemented("service-level operations"));
    }
    if query.is_some_and(|q| !q.is_empty()) {
        *received = drain(body).await;
        return Err(not_implemented(
            "query subresources (multipart, listing, ...)",
        ));
    }
    if !shared.lock().buckets.contains_key(bucket) {
        *received = drain(body).await;
        return Err(err(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "the bucket does not exist",
        ));
    }
    if key.is_empty() {
        *received = drain(body).await;
        return if parts.method == Method::HEAD {
            Ok(Answer::ok(StatusCode::OK))
        } else {
            Err(not_implemented("bucket operations other than HEAD"))
        };
    }
    let (bucket, key) = (bucket.to_owned(), key.to_owned());
    match parts.method {
        Method::PUT => put(shared, &parts.headers, bucket, key, body, received).await,
        Method::GET | Method::HEAD => {
            *received = drain(body).await;
            get(
                shared,
                &parts.headers,
                &bucket,
                &key,
                parts.method == Method::HEAD,
            )
        }
        Method::DELETE => {
            *received = drain(body).await;
            let mut objects = shared.lock();
            if let Some(b) = objects.buckets.get_mut(&bucket) {
                b.remove(&key);
            }
            *objects.deletes.entry((bucket, key)).or_default() += 1;
            Ok(Answer::ok(StatusCode::NO_CONTENT))
        }
        _ => {
            *received = drain(body).await;
            Err(err(
                StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "method not allowed",
            ))
        }
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

async fn put(
    shared: &Shared,
    headers: &HeaderMap,
    bucket: String,
    key: String,
    body: Body,
    received: &mut u64,
) -> Result<Answer, S3Error> {
    let checked = (|| {
        if headers.contains_key(header::TRANSFER_ENCODING) {
            return Err(not_implemented("Transfer-Encoding"));
        }
        let len: u64 = header_str(headers, "content-length")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| {
                err(
                    StatusCode::LENGTH_REQUIRED,
                    "MissingContentLength",
                    "you must provide the Content-Length HTTP header",
                )
            })?;
        if len > MAX_PUT_BYTES {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "EntityTooLarge",
                "your proposed upload exceeds the maximum allowed size",
            ));
        }
        if headers.contains_key(header::IF_MATCH) {
            return Err(not_implemented("If-Match"));
        }
        let conditional = match header_str(headers, "if-none-match") {
            None => false,
            Some("*") => shared.opts.honor_if_none_match,
            Some(_) => return Err(not_implemented("If-None-Match other than *")),
        };
        Ok((len, conditional))
    })();
    let (len, conditional) = match checked {
        Ok(checked) => checked,
        Err(e) => {
            *received = drain(body).await;
            return Err(e);
        }
    };
    let present = |objects: &Objects| {
        objects
            .buckets
            .get(&bucket)
            .is_some_and(|b| b.contains_key(&key))
    };
    let slot = (bucket.clone(), key.clone());
    let (exists, deletes_before) = {
        let objects = shared.lock();
        let deletes = objects.deletes.get(&slot).copied().unwrap_or(0);
        (present(&objects), deletes)
    };
    if conditional && exists {
        *received = drain(body).await;
        return Err(precondition_failed());
    }
    let bytes = read_exact(body, len, received).await?;
    match header_str(headers, "x-amz-content-sha256") {
        Some("UNSIGNED-PAYLOAD") => {}
        Some(claimed) if claimed == hex(&Sha256::digest(&bytes)) => {}
        _ => {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "XAmzContentSHA256Mismatch",
                "the provided x-amz-content-sha256 does not match what was computed",
            ));
        }
    }
    let mut objects = shared.lock();
    if conditional {
        if present(&objects) {
            return Err(precondition_failed());
        }
        if objects.deletes.get(&slot).copied().unwrap_or(0) != deletes_before {
            return Err(err(
                StatusCode::CONFLICT,
                "ConditionalRequestConflict",
                "a conflicting operation occurred; retry",
            ));
        }
    }
    let etag = format!("\"{}\"", &hex(&Sha256::digest(&bytes))[..32]);
    objects
        .buckets
        .entry(bucket)
        .or_default()
        .insert(key, bytes);
    let mut answer = Answer::ok(StatusCode::OK);
    if let Ok(etag) = HeaderValue::from_str(&etag) {
        answer.headers.insert(header::ETAG, etag);
    }
    Ok(answer)
}

fn precondition_failed() -> S3Error {
    err(
        StatusCode::PRECONDITION_FAILED,
        "PreconditionFailed",
        "at least one of the pre-conditions you specified did not hold",
    )
}

/// What a `Range` header asks of a `len`-byte object.
#[derive(Debug, PartialEq, Eq)]
enum RangeAsk {
    /// No usable range: the whole object.
    Whole,
    /// Bytes `start..=end`.
    Span(u64, u64),
    /// Starts at or past the end.
    Unsatisfiable,
}

fn parse_range(value: &str, len: u64) -> RangeAsk {
    let Some(spec) = value.strip_prefix("bytes=") else {
        return RangeAsk::Whole;
    };
    if spec.contains(',') {
        return RangeAsk::Whole;
    }
    let Some((first, last)) = spec.split_once('-') else {
        return RangeAsk::Whole;
    };
    if first.is_empty() {
        return match last.parse::<u64>() {
            Ok(0) => RangeAsk::Unsatisfiable,
            Ok(_) if len == 0 => RangeAsk::Unsatisfiable,
            Ok(n) => RangeAsk::Span(len.saturating_sub(n), len - 1),
            Err(_) => RangeAsk::Whole,
        };
    }
    let Ok(start) = first.parse::<u64>() else {
        return RangeAsk::Whole;
    };
    let end = if last.is_empty() {
        u64::MAX
    } else {
        match last.parse::<u64>() {
            Ok(end) if end >= start => end,
            _ => return RangeAsk::Whole,
        }
    };
    if start >= len {
        return RangeAsk::Unsatisfiable;
    }
    RangeAsk::Span(start, end.min(len - 1))
}

fn get(
    shared: &Shared,
    headers: &HeaderMap,
    bucket: &str,
    key: &str,
    head: bool,
) -> Result<Answer, S3Error> {
    let Some(object) = shared
        .lock()
        .buckets
        .get(bucket)
        .and_then(|b| b.get(key).cloned())
    else {
        return Err(err(
            StatusCode::NOT_FOUND,
            "NoSuchKey",
            "the specified key does not exist",
        ));
    };
    let len = object.len() as u64;
    let ask = match header_str(headers, "range") {
        Some(range) if !head => parse_range(range, len),
        _ => RangeAsk::Whole,
    };
    let mut answer = Answer::ok(StatusCode::OK);
    answer
        .headers
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    answer.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    let (start, end) = match ask {
        RangeAsk::Unsatisfiable => {
            return Err(err(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "InvalidRange",
                "the requested range is not satisfiable",
            ));
        }
        RangeAsk::Whole => (0, len),
        RangeAsk::Span(first, last) => {
            answer.status = StatusCode::PARTIAL_CONTENT;
            let range = format!("bytes {first}-{last}/{len}");
            if let Ok(range) = HeaderValue::from_str(&range) {
                answer.headers.insert(header::CONTENT_RANGE, range);
            }
            (first, last + 1)
        }
    };
    answer
        .headers
        .insert(header::CONTENT_LENGTH, HeaderValue::from(end - start));
    if !head {
        let (start, end) = (
            usize::try_from(start).unwrap_or(usize::MAX),
            usize::try_from(end).unwrap_or(usize::MAX),
        );
        answer.body = object.slice(start..end);
    }
    Ok(answer)
}

// ---------------------------------------------------------------------------
// SigV4 verification, written independently of `mkit-transport-s3::sigv4`.
// ---------------------------------------------------------------------------

type HmacSha256 = Hmac<Sha256>;

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    out
}

fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn percent_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let digit = |at: usize| bytes.get(at).and_then(|b| char::from(*b).to_digit(16));
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let (Some(hi), Some(lo)) = (digit(i + 1), digit(i + 2))
        {
            out.push(u8::try_from(hi * 16 + lo).unwrap_or(0));
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn uri_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The canonical query string S3 re-derives from a raw query.
fn canonical_query(raw: &str) -> String {
    let mut pairs: Vec<(String, String)> = raw
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (
                uri_encode(&percent_decode(k)),
                uri_encode(&percent_decode(v)),
            )
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn malformed(why: &str) -> S3Error {
    err(
        StatusCode::BAD_REQUEST,
        "AuthorizationHeaderMalformed",
        why.to_owned(),
    )
}

fn mismatch() -> S3Error {
    err(
        StatusCode::FORBIDDEN,
        "SignatureDoesNotMatch",
        "the request signature we calculated does not match the signature you provided",
    )
}

/// The `Credential`, `SignedHeaders` and `Signature` of an
/// `Authorization: AWS4-HMAC-SHA256 ...` value.
fn parse_authorization(auth: &str) -> Result<(&str, &str, &str), S3Error> {
    let fields = auth
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .ok_or_else(|| malformed("not AWS4-HMAC-SHA256"))?;
    let mut credential = None;
    let mut signed = None;
    let mut signature = None;
    for field in fields.split(',').map(str::trim) {
        if let Some(v) = field.strip_prefix("Credential=") {
            credential = Some(v);
        } else if let Some(v) = field.strip_prefix("SignedHeaders=") {
            signed = Some(v);
        } else if let Some(v) = field.strip_prefix("Signature=") {
            signature = Some(v);
        } else {
            return Err(malformed("unknown Authorization field"));
        }
    }
    match (credential, signed, signature) {
        (Some(c), Some(h), Some(s)) => Ok((c, h, s)),
        _ => Err(malformed("Authorization lacks a field")),
    }
}

/// The canonical header block for the signed `names`: sorted, lowercase,
/// including `host`, and covering every `x-amz-*` header present.
fn canonical_headers(headers: &HeaderMap, names: &[&str]) -> Result<String, S3Error> {
    let sorted = names.windows(2).all(|w| w[0] < w[1]);
    if !sorted
        || !names.contains(&"host")
        || names
            .iter()
            .any(|n| n.bytes().any(|b| b.is_ascii_uppercase()))
    {
        return Err(malformed(
            "SignedHeaders must be sorted, lowercase and include host",
        ));
    }
    if headers
        .keys()
        .any(|n| n.as_str().starts_with("x-amz-") && !names.contains(&n.as_str()))
    {
        return Err(err(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "there were headers present in the request which were not signed",
        ));
    }
    let mut block = String::new();
    for name in names {
        let values: Vec<String> = headers
            .get_all(*name)
            .iter()
            .map(|v| String::from_utf8_lossy(v.as_bytes()).trim().to_owned())
            .collect();
        if values.is_empty() {
            return Err(mismatch());
        }
        let _ = writeln!(block, "{name}:{}", values.join(","));
    }
    Ok(block)
}

fn verify_sigv4(
    opts: &FakeS3Options,
    parts: &axum::http::request::Parts,
    path: &str,
    query: &str,
) -> Result<(), S3Error> {
    let headers = &parts.headers;
    let Some(auth) = header_str(headers, "authorization") else {
        return Err(err(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "anonymous access is denied",
        ));
    };
    let (credential, signed, signature) = parse_authorization(auth)?;
    let scope: Vec<&str> = credential.split('/').collect();
    let [akid, date, region, service, terminator] = scope[..] else {
        return Err(malformed("bad credential scope"));
    };
    if akid != opts.access_key_id {
        return Err(err(
            StatusCode::FORBIDDEN,
            "InvalidAccessKeyId",
            "the access key id does not exist in our records",
        ));
    }
    if region != opts.region || service != "s3" || terminator != "aws4_request" {
        return Err(malformed(
            "wrong region, service or terminator in the scope",
        ));
    }
    let amz_date = header_str(headers, "x-amz-date")
        .filter(|d| d.len() == 16 && d.starts_with(date) && date.len() == 8)
        .ok_or_else(|| {
            err(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                "bad or missing x-amz-date",
            )
        })?;
    let payload = header_str(headers, "x-amz-content-sha256").ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "missing required header for this request: x-amz-content-sha256",
        )
    })?;
    if payload != "UNSIGNED-PAYLOAD"
        && !(payload.len() == 64 && payload.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "x-amz-content-sha256 must be UNSIGNED-PAYLOAD or a SHA-256 hex digest",
        ));
    }
    let names: Vec<&str> = signed.split(';').collect();
    let canonical_headers = canonical_headers(headers, &names)?;
    let canonical_request = format!(
        "{}\n{path}\n{}\n{canonical_headers}\n{signed}\n{payload}",
        parts.method,
        canonical_query(query)
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{date}/{region}/s3/aws4_request\n{}",
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );
    let mut key = hmac(
        format!("AWS4{}", opts.secret_access_key).as_bytes(),
        date.as_bytes(),
    );
    for part in [region, "s3", "aws4_request"] {
        key = hmac(&key, part.as_bytes());
    }
    if hex(&hmac(&key, string_to_sign.as_bytes())) != signature {
        return Err(mismatch());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_parse_like_s3() {
        assert_eq!(parse_range("bytes=0-0", 10), RangeAsk::Span(0, 0));
        assert_eq!(parse_range("bytes=8-100", 10), RangeAsk::Span(8, 9));
        assert_eq!(parse_range("bytes=3-", 10), RangeAsk::Span(3, 9));
        assert_eq!(parse_range("bytes=-4", 10), RangeAsk::Span(6, 9));
        assert_eq!(parse_range("bytes=-40", 10), RangeAsk::Span(0, 9));
        assert_eq!(parse_range("bytes=10-12", 10), RangeAsk::Unsatisfiable);
        assert_eq!(parse_range("bytes=0-0", 0), RangeAsk::Unsatisfiable);
        assert_eq!(parse_range("bytes=-0", 10), RangeAsk::Unsatisfiable);
        for ignored in [
            "bytes=5-4",
            "bytes=0-1,3-4",
            "items=0-1",
            "bytes=x-1",
            "bytes=1",
        ] {
            assert_eq!(parse_range(ignored, 10), RangeAsk::Whole, "{ignored}");
        }
    }

    #[test]
    fn canonical_query_reencodes_and_sorts() {
        assert_eq!(canonical_query(""), "");
        assert_eq!(
            canonical_query("prefix=a/b&list-type=2"),
            "list-type=2&prefix=a%2Fb"
        );
        assert_eq!(canonical_query("uploads"), "uploads=");
        assert_eq!(canonical_query("k=a%2fb%20c"), "k=a%2Fb%20c");
    }

    #[test]
    fn recorded_request_debug_redacts_credentials() {
        let request = RecordedRequest {
            method: Method::GET,
            path: "/b/k".to_owned(),
            query: None,
            headers: vec![
                (
                    "authorization".to_owned(),
                    "AWS4-HMAC-SHA256 secretsig".to_owned(),
                ),
                ("range".to_owned(), "bytes=0-1".to_owned()),
            ],
            body_len: 0,
            status: StatusCode::OK,
        };
        let shown = format!("{request:?}");
        assert!(!shown.contains("secretsig"), "{shown}");
        assert!(shown.contains("bytes=0-1"), "{shown}");
        let opts = format!("{:?}", FakeS3Options::default());
        assert!(!opts.contains("fake/secret"), "{opts}");
    }
}
