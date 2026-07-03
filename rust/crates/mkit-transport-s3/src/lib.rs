#![doc = include_str!("../README.md")]
//!
//! mkit S3 / Cloudflare R2 transport.
//!
//! Implements the 7-verb [`Transport`] trait on top of a reqwest
//! blocking client with our own SigV4 signer (see [`sigv4`]). Designed
//! for Cloudflare R2 — AWS S3 also works, but CAS semantics only match
//! the R2 behaviour of returning the body MD5 as the `ETag` on `PUT`.
//!
//! URL shape: `mkit+s3://<endpoint>/<bucket>[/prefix]` — credentials are
//! pulled from the `MKIT_R2_ACCESS_KEY_ID` / `MKIT_R2_SECRET_ACCESS_KEY`
//! environment at `connect` time. An unset pair does not fail
//! construction; the first signed call surfaces
//! [`TransportError::AccessDenied`].
//!
//! Retry policy mirrors SPEC-TRANSPORT §7 via
//! [`mkit_core::protocol::BackoffIterator`]: 5xx and HTTP 429 retry up to
//! 5 attempts; `412 Precondition Failed` NEVER retries so CAS writes
//! can't silently turn into duplicate PUTs.

// This crate contains zero `unsafe` — enforce that it stays that way.
#![forbid(unsafe_code)]
// Narrative-heavy module docs fight `doc_markdown`; the
// `duration_suboptimal_units` lint insists on `from_mins(1)` for our 60s
// HTTP timeout which obscures intent (we mean seconds, not minutes).
#![allow(clippy::doc_markdown, clippy::duration_suboptimal_units)]

pub mod sigv4;

use std::env;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use md5::{Digest as _, Md5};
use mkit_core::hash::{Hash, to_hex};
use mkit_core::protocol::{
    BackoffIterator, PackKey, Transport, TransportError, TransportResult, is_retryable,
};
use mkit_core::refs::{Ref, RefWriteCondition, validate_ref_name, validate_ref_prefix};
use reqwest::Method;
use reqwest::blocking::{Client, Response};

use crate::sigv4::{Credentials, SignedRequest, sign_request};

/// Per SPEC-TRANSPORT §6.4, a single PUT is capped at 5 GiB; anything
/// larger requires multipart upload (deferred).
pub const S3_SINGLE_PUT_MAX: u64 = 5 * 1024 * 1024 * 1024;

// Body-size cap for a pack download. Canonical value lives in mkit-core.
use mkit_core::protocol::{PACK_BODY_LIMIT, PACK_BODY_LIMIT_USIZE};
/// Body-size cap for a ref body (64 hex + newline + slack).
const REF_BODY_LIMIT: usize = 256;
/// Cap for list XML / small responses (16 MiB).
const REF_LIST_BODY_LIMIT: usize = 16 * 1024 * 1024;

/// HTTP `PUT`-return body cap when we don't care about the response.
const SMALL_RESPONSE_LIMIT: usize = 4 * 1024;

/// Environment variable names for credentials.
pub const ENV_ACCESS_KEY: &str = "MKIT_R2_ACCESS_KEY_ID";
pub const ENV_SECRET_KEY: &str = "MKIT_R2_SECRET_ACCESS_KEY";

// ---------------------------------------------------------------------------
// Connect / construction
// ---------------------------------------------------------------------------

/// The transport implementation. Clone-safe — the underlying reqwest
/// client is cheap to share across threads.
pub struct S3Transport {
    endpoint: String,
    bucket: String,
    prefix: Option<String>,
    creds: Credentials,
    client: Client,
    /// Test-only clock override so unit tests are deterministic.
    clock: Clock,
    /// Test-only sleep override so retry tests don't block the suite.
    sleeper: Sleeper,
    /// Backoff ladder constructor — swapped in tests to tighten delays.
    backoff: fn() -> BackoffIterator,
}

impl std::fmt::Debug for S3Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Transport")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("region", &self.creds.region)
            .finish_non_exhaustive()
    }
}

type Clock = fn() -> i64;
type Sleeper = fn(Duration);

fn default_clock() -> i64 {
    // Pre-1970 wall clock collapses to `0`, which the signer accepts
    // (maps to 1970-01-01). `as i64` can only wrap past year 2262 — we
    // explicitly accept that far-future saturation.
    #[allow(clippy::cast_possible_wrap)]
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => 0,
    }
}

fn default_sleeper(d: Duration) {
    thread::sleep(d);
}

impl S3Transport {
    /// Parse a `mkit+s3://<endpoint>/<bucket>[/prefix]` URL and build a
    /// transport. Credentials come from the environment (see
    /// [`ENV_ACCESS_KEY`] / [`ENV_SECRET_KEY`]); if either is unset the
    /// credentials default to empty strings and the first signed call
    /// returns [`TransportError::AccessDenied`].
    ///
    /// The endpoint is the host component in the URL; we rebuild it as
    /// `https://<host>` because R2 only speaks HTTPS.
    pub fn connect(url: &str) -> Result<Self, TransportError> {
        let parsed = parse_s3_url(url)?;
        let endpoint = format!("https://{}", parsed.host);
        let bucket = parsed.bucket;
        let prefix = parsed.prefix;
        let access_key_id = env::var(ENV_ACCESS_KEY).unwrap_or_default();
        let secret_access_key = env::var(ENV_SECRET_KEY).unwrap_or_default();
        let region = env::var("MKIT_R2_REGION").unwrap_or_else(|_| "auto".into());

        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|_| TransportError::ConnectionFailed)?;

        Ok(Self {
            endpoint,
            bucket,
            prefix,
            creds: Credentials {
                access_key_id,
                secret_access_key,
                region,
            },
            client,
            clock: default_clock,
            sleeper: default_sleeper,
            backoff: BackoffIterator::new,
        })
    }

    /// Construct a transport directly against an endpoint URL, for tests
    /// (mockito hands us a plain `http://127.0.0.1:PORT` base). The path
    /// component of `endpoint` MUST be empty — only scheme+host\[:port\].
    #[doc(hidden)]
    pub fn with_parts(
        endpoint: impl Into<String>,
        bucket: impl Into<String>,
        prefix: Option<String>,
        creds: Credentials,
    ) -> Result<Self, TransportError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|_| TransportError::ConnectionFailed)?;
        Ok(Self {
            endpoint: endpoint.into(),
            bucket: bucket.into(),
            prefix: normalize_s3_prefix(prefix)?,
            creds,
            client,
            clock: default_clock,
            sleeper: default_sleeper,
            backoff: BackoffIterator::new,
        })
    }

    /// Test-only: expose the resolved credentials so integration tests
    /// outside this crate can assert that [`Self::connect`] actually
    /// read [`ENV_ACCESS_KEY`] / [`ENV_SECRET_KEY`] / `MKIT_R2_REGION`,
    /// rather than merely asserting the constant names. Not exposed via
    /// `Debug` (deliberately, to avoid leaking secrets into logs).
    #[doc(hidden)]
    #[must_use]
    pub fn credentials_for_test(&self) -> (&str, &str, &str) {
        (
            &self.creds.access_key_id,
            &self.creds.secret_access_key,
            &self.creds.region,
        )
    }

    /// Test-only: install a fake clock. The clock returns Unix seconds.
    #[doc(hidden)]
    pub fn set_clock(&mut self, clock: Clock) {
        self.clock = clock;
    }

    /// Test-only: install a fake sleeper so backoff doesn't block the
    /// test suite.
    #[doc(hidden)]
    pub fn set_sleeper(&mut self, sleeper: Sleeper) {
        self.sleeper = sleeper;
    }

    /// Test-only: install a tighter backoff ladder.
    #[doc(hidden)]
    pub fn set_backoff(&mut self, backoff: fn() -> BackoffIterator) {
        self.backoff = backoff;
    }

    // -- Path / key builders --

    /// Build the S3 object key for a pack: `packs/<64-char hex digest>`.
    #[must_use]
    pub fn pack_object_key(digest: &Hash) -> String {
        format!("packs/{}", to_hex(digest))
    }

    /// Build the S3 object key for the shard manifest of a pack:
    /// `packs/<64-char hex digest>/shards.manifest`. Mirrors the HTTP
    /// transport's URL shape.
    #[must_use]
    pub fn shard_manifest_object_key(digest: &Hash) -> String {
        format!("packs/{}/shards.manifest", to_hex(digest))
    }

    /// Build the S3 object key for one shard of a pack:
    /// `packs/<64-char hex digest>/shards/<index>`. Mirrors the HTTP
    /// transport's URL shape.
    #[must_use]
    pub fn shard_object_key(digest: &Hash, index: u16) -> String {
        format!("packs/{}/shards/{}", to_hex(digest), index)
    }

    /// Build the repository namespace key. Without a URL prefix this is
    /// the canonical repository-relative key; with a prefix it is
    /// `<prefix>/<canonical-key>`.
    fn effective_key(&self, key: &str) -> String {
        match self.prefix.as_deref() {
            Some(prefix) if key.is_empty() => format!("{prefix}/"),
            Some(prefix) => format!("{prefix}/{key}"),
            None => key.to_owned(),
        }
    }

    /// Build the S3 path `/<bucket>/<effective-key>` that the signer will
    /// sign and the client will request.
    fn build_path(&self, key: &str) -> String {
        if key.is_empty() {
            return format!("/{}", self.bucket);
        }
        format!("/{}/{}", self.bucket, self.effective_key(key))
    }

    /// Build a ListObjectsV2 prefix under the URL namespace. Listing is
    /// sent to bucket root (`key = ""`) and scoped only through this query.
    fn effective_list_prefix(&self, prefix: &str) -> String {
        match self.prefix.as_deref() {
            Some(namespace) if prefix.is_empty() => format!("{namespace}/"),
            Some(namespace) => format!("{namespace}/{prefix}"),
            None => prefix.to_owned(),
        }
    }

    fn strip_effective_prefix<'a>(&self, key: &'a str) -> Option<&'a str> {
        let Some(namespace) = self.prefix.as_deref() else {
            return Some(key);
        };
        key.strip_prefix(namespace)?.strip_prefix('/')
    }

    /// Build the canonical query string for `ListObjectsV2` scoped to a
    /// prefix. `prefix` MAY be empty to list every key.
    ///
    /// The query is URI-encoded and key-sorted via
    /// [`sigv4::canonical_query_string`] so the bytes signed match what
    /// real AWS S3 re-derives server-side (a raw `/` in the prefix would
    /// otherwise yield `403 SignatureDoesNotMatch`; R2 is lenient).
    #[must_use]
    pub fn build_list_query(prefix: &str) -> String {
        sigv4::canonical_query_string(&[("list-type", "2"), ("prefix", prefix)])
    }

    /// Build the canonical `ListObjectsV2` query string for the next page
    /// of a truncated listing, carrying the `continuation-token` returned
    /// by the previous page. Same encoding/sorting rules as
    /// [`Self::build_list_query`].
    #[must_use]
    pub fn build_list_query_continued(prefix: &str, continuation_token: &str) -> String {
        sigv4::canonical_query_string(&[
            ("continuation-token", continuation_token),
            ("list-type", "2"),
            ("prefix", prefix),
        ])
    }

    // -- HTTP core --

    /// Make a signed HTTP request with exponential-backoff retry on
    /// 5xx / 429 / connection failures. 4xx other than 429 returns
    /// immediately.
    fn http_request(
        &self,
        method: &Method,
        key: &str,
        query: &str,
        payload: Option<&[u8]>,
        extra_headers: &[(&'static str, String)],
        body_limit: Option<usize>,
    ) -> TransportResult<HttpResponse> {
        let mut iter = (self.backoff)();
        loop {
            match self.http_request_once(method, key, query, payload, extra_headers, body_limit) {
                Ok(resp) => {
                    let status = resp.status;
                    // Retry on 5xx / 429.
                    if is_retryable(&TransportError::ServerError { status })
                        && let Some(d) = iter.next()
                    {
                        (self.sleeper)(d);
                        continue;
                    }
                    return Ok(resp);
                }
                Err(TransportError::ConnectionFailed) => {
                    if let Some(d) = iter.next() {
                        (self.sleeper)(d);
                        continue;
                    }
                    return Err(TransportError::ConnectionFailed);
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn http_request_once(
        &self,
        method: &Method,
        key: &str,
        query: &str,
        payload: Option<&[u8]>,
        extra_headers: &[(&'static str, String)],
        body_limit: Option<usize>,
    ) -> TransportResult<HttpResponse> {
        let path = self.build_path(key);
        let method_str = method_to_str(method);
        let ts = (self.clock)();
        let payload_bytes: &[u8] = payload.unwrap_or(&[]);

        let signed: SignedRequest = sign_request(
            &self.creds,
            method_str,
            &path,
            query,
            payload_bytes,
            &self.endpoint,
            ts,
        );

        let url = if query.is_empty() {
            format!("{}{}", self.endpoint, path)
        } else {
            format!("{}{}?{}", self.endpoint, path, query)
        };

        let mut builder = self
            .client
            .request(method.clone(), &url)
            .header("Authorization", signed.authorization)
            .header("x-amz-date", signed.x_amz_date)
            .header("x-amz-content-sha256", signed.x_amz_content_sha256);
        for (name, value) in extra_headers {
            builder = builder.header(*name, value);
        }
        if let Some(bytes) = payload {
            builder = builder
                .header("Content-Length", bytes.len().to_string())
                .body(bytes.to_vec());
        }

        let resp = builder
            .send()
            .map_err(|_| TransportError::ConnectionFailed)?;
        extract_response(resp, body_limit, method == Method::HEAD)
    }
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn extract_response(
    resp: Response,
    body_limit: Option<usize>,
    is_head: bool,
) -> TransportResult<HttpResponse> {
    let status = resp.status().as_u16();
    let body = if is_head {
        Vec::new()
    } else if let Some(limit) = body_limit {
        // Pull into memory with an upper bound — reqwest's `bytes()` is
        // unbounded, so we cap manually.
        let all = resp.bytes().map_err(|_| TransportError::ConnectionFailed)?;
        if all.len() > limit {
            // Non-retryable: re-fetching the same oversized object would
            // just exceed the cap again. (Previously mapped to a 507,
            // which `is_retryable` treats as a retryable 5xx, so the
            // backoff loop would have retried the doomed fetch.)
            return Err(TransportError::PayloadTooLarge(all.len()));
        }
        all.to_vec()
    } else {
        // Body not needed (e.g. `HEAD` response already has no body, or
        // the status is retryable and the caller discards).
        Vec::new()
    };
    Ok(HttpResponse { status, body })
}

fn method_to_str(m: &Method) -> &'static str {
    match *m {
        Method::PUT => "PUT",
        Method::HEAD => "HEAD",
        Method::DELETE => "DELETE",
        Method::POST => "POST",
        // Default to "GET" for GET (and any unrecognised method) — the S3
        // transport only issues the five verbs above so any other value
        // here indicates a bug, but we prefer a safe default to a panic.
        _ => "GET",
    }
}

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ParsedS3Url {
    host: String,
    bucket: String,
    prefix: Option<String>,
}

/// Accept `mkit+s3://<host>/<bucket>[/prefix]` and return host/bucket/prefix.
/// The host component stays intact so we can rebuild the HTTPS endpoint.
fn parse_s3_url(url: &str) -> Result<ParsedS3Url, TransportError> {
    let rest = url
        .strip_prefix("mkit+s3://")
        .ok_or_else(|| TransportError::InvalidRef(format!("not an mkit+s3 URL: {url}")))?;
    let Some((host, tail)) = rest.split_once('/') else {
        return Err(TransportError::InvalidRef(
            "mkit+s3 URL missing bucket".into(),
        ));
    };
    if host.is_empty() {
        return Err(TransportError::InvalidRef("mkit+s3 URL empty host".into()));
    }
    let (bucket, raw_prefix) = match tail.split_once('/') {
        Some((b, p)) if !p.is_empty() => (b, Some(p.to_owned())),
        Some((b, _)) => (b, None),
        None => (tail, None),
    };
    if bucket.is_empty() {
        return Err(TransportError::InvalidRef(
            "mkit+s3 URL empty bucket".into(),
        ));
    }
    Ok(ParsedS3Url {
        host: host.to_owned(),
        bucket: bucket.to_owned(),
        prefix: normalize_s3_prefix(raw_prefix)?,
    })
}

fn normalize_s3_prefix(prefix: Option<String>) -> Result<Option<String>, TransportError> {
    let Some(prefix) = prefix else {
        return Ok(None);
    };
    if prefix.is_empty()
        || prefix.starts_with('/')
        || prefix.ends_with('/')
        || prefix.contains("//")
        || prefix.contains('\\')
    {
        return Err(TransportError::InvalidRef(format!(
            "invalid S3 prefix: {prefix}"
        )));
    }
    for segment in prefix.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(TransportError::InvalidRef(format!(
                "invalid S3 prefix: {prefix}"
            )));
        }
        if !segment.bytes().all(is_safe_s3_prefix_byte) {
            return Err(TransportError::InvalidRef(format!(
                "invalid S3 prefix: {prefix}"
            )));
        }
    }
    Ok(Some(prefix))
}

fn is_safe_s3_prefix_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
}

// ---------------------------------------------------------------------------
// MD5 of wire-format ref — ETag for CAS on R2
// ---------------------------------------------------------------------------

/// Format a hash as the on-the-wire ref body: 64 hex chars + LF.
fn format_ref_wire(h: &Hash) -> Vec<u8> {
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(to_hex(h).as_bytes());
    out.push(b'\n');
    out
}

/// Wrap `value` in double quotes to produce the `"<md5>"` ETag R2 returns.
fn quoted_md5(wire: &[u8]) -> String {
    let mut h = Md5::new();
    h.update(wire);
    let digest = h.finalize();
    format!("\"{}\"", hex::encode(digest))
}

// ---------------------------------------------------------------------------
// Transport impl
// ---------------------------------------------------------------------------

impl Transport for S3Transport {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        if bytes.len() as u64 > S3_SINGLE_PUT_MAX || bytes.len() as u64 > PACK_BODY_LIMIT {
            return Err(TransportError::ServerError { status: 413 });
        }
        let object_key = Self::pack_object_key(key.as_bytes());
        let resp = self.http_request(
            &Method::PUT,
            &object_key,
            "",
            Some(bytes),
            &[],
            Some(SMALL_RESPONSE_LIMIT),
        )?;
        match resp.status {
            200 | 201 => Ok(()),
            403 | 401 => Err(TransportError::AccessDenied),
            s => Err(TransportError::ServerError { status: s }),
        }
    }

    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        // Shard-aware path: when the pack-shards feature is on, try
        // the manifest first. `Ok(None)` means the manifest is
        // missing (producer never sharded this pack), so we fall
        // through to the monolithic GET below. Any other error
        // propagates as-is.
        #[cfg(feature = "pack-shards")]
        if let Some(bytes) = self.download_pack_via_shards(key)? {
            return Ok(bytes);
        }

        let object_key = Self::pack_object_key(key.as_bytes());
        let resp = self.http_request(
            &Method::GET,
            &object_key,
            "",
            None,
            &[],
            Some(PACK_BODY_LIMIT_USIZE),
        )?;
        match resp.status {
            200 => Ok(resp.body),
            404 => Err(TransportError::PackNotFound),
            403 | 401 => Err(TransportError::AccessDenied),
            s => Err(TransportError::ServerError { status: s }),
        }
    }

    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        let object_key = Self::pack_object_key(key.as_bytes());
        let resp = self.http_request(&Method::HEAD, &object_key, "", None, &[], None)?;
        match resp.status {
            200 => Ok(true),
            404 => Ok(false),
            403 | 401 => Err(TransportError::AccessDenied),
            s => Err(TransportError::ServerError { status: s }),
        }
    }

    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.to_owned()));
        }
        let wire = format_ref_wire(hash);
        let mut extra: Vec<(&'static str, String)> = Vec::new();
        match condition {
            RefWriteCondition::Any => {}
            RefWriteCondition::Missing => {
                extra.push(("If-None-Match", "*".into()));
            }
            RefWriteCondition::Match(expected) => {
                let expected_wire = format_ref_wire(&expected);
                extra.push(("If-Match", quoted_md5(&expected_wire)));
            }
        }
        let resp = self.http_request(
            &Method::PUT,
            name,
            "",
            Some(&wire),
            &extra,
            Some(SMALL_RESPONSE_LIMIT),
        )?;
        match resp.status {
            200 | 201 => Ok(()),
            409 | 412 => Err(TransportError::RefConflict),
            403 | 401 => Err(TransportError::AccessDenied),
            s => Err(TransportError::ServerError { status: s }),
        }
    }

    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.to_owned()));
        }
        let resp = self.http_request(&Method::GET, name, "", None, &[], Some(REF_BODY_LIMIT))?;
        match resp.status {
            200 => parse_ref_body(&resp.body).map(Some),
            404 => Ok(None),
            403 | 401 => Err(TransportError::AccessDenied),
            s => Err(TransportError::ServerError { status: s }),
        }
    }

    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        if !validate_ref_prefix(prefix) {
            return Err(TransportError::InvalidRef(prefix.to_owned()));
        }
        let query_prefix = self.effective_list_prefix(prefix);

        // Trim a trailing '/' so suffix extraction below matches the
        // canonical memory/file transports: `list_refs("refs/heads")`
        // and `list_refs("refs/heads/")` both yield `"main"`, never
        // `"/main"` (which `validate_ref_name` would reject, silently
        // dropping the ref).
        let prefix_trimmed = prefix.trim_end_matches('/');

        // Paginate: ListObjectsV2 caps each page at 1000 keys and signals
        // more via IsTruncated + NextContinuationToken. Without this loop
        // a namespace with >1000 ref objects returns a silently truncated
        // ref list, corrupting fetch/sync decisions.
        let mut keys: Vec<String> = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let query = match continuation.as_deref() {
                Some(token) => Self::build_list_query_continued(&query_prefix, token),
                None => Self::build_list_query(&query_prefix),
            };
            let resp = self.http_request(
                &Method::GET,
                "",
                &query,
                None,
                &[],
                Some(REF_LIST_BODY_LIMIT),
            )?;
            match resp.status {
                200 => {}
                403 | 401 => return Err(TransportError::AccessDenied),
                s => return Err(TransportError::ServerError { status: s }),
            }
            let page = parse_list_page(&resp.body);
            keys.extend(page.keys);
            match page.next_continuation_token {
                Some(token) => continuation = Some(token),
                None => break,
            }
        }

        let mut out: Vec<Ref> = Vec::new();
        for key in keys {
            let Some(repo_key) = self.strip_effective_prefix(&key) else {
                continue;
            };
            if !validate_ref_name(repo_key) {
                continue;
            }
            // Resolve each key to its hash via a second GET. This is an
            // inherent O(N) round-trip cost of the object-per-ref layout
            // (the hash lives only in the object body, so ListObjectsV2
            // cannot return it). Ref counts are normally small (branches
            // + tags), so the cost is bounded in practice. Propagate a
            // transport error (post-retry) rather than skipping the ref —
            // silently dropping a ref would reintroduce the short-listing
            // bug that the pagination above exists to prevent.
            let ref_resp =
                self.http_request(&Method::GET, repo_key, "", None, &[], Some(REF_BODY_LIMIT))?;
            if ref_resp.status != 200 {
                continue;
            }
            let Ok(h) = parse_ref_body(&ref_resp.body) else {
                continue;
            };
            // Strip the (trimmed) prefix and the separating '/' so the
            // returned name is suffix-only per the Transport contract.
            let suffix = if prefix_trimmed.is_empty() {
                repo_key
            } else if let Some(after) = repo_key.strip_prefix(prefix_trimmed) {
                after.strip_prefix('/').unwrap_or(after)
            } else {
                repo_key
            };
            if !validate_ref_name(suffix) {
                continue;
            }
            out.push(Ref {
                name: suffix.to_owned(),
                hash: Some(h),
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}

fn parse_ref_body(body: &[u8]) -> TransportResult<Hash> {
    // Ref wire format is 64 hex chars + optional trailing whitespace.
    let s = std::str::from_utf8(body).map_err(|_| TransportError::InvalidResponse)?;
    let trimmed = s.trim_end_matches(['\n', '\r', ' ', '\t']);
    if trimmed.len() != 64 {
        return Err(TransportError::InvalidResponse);
    }
    mkit_core::hash::from_hex(trimmed).map_err(|_| TransportError::InvalidResponse)
}

/// One parsed page of a `ListObjectsV2` response: the keys it contained
/// plus the pagination cursor needed to fetch the next page.
struct ListPage {
    keys: Vec<String>,
    /// `Some(token)` when `<IsTruncated>true</IsTruncated>` and a
    /// `<NextContinuationToken>` is present — feed it back as the
    /// `continuation-token` query parameter to fetch the next page.
    next_continuation_token: Option<String>,
}

/// Extract every `<Key>...</Key>` value from a ListBucketResult body.
/// No XML validation, no entity decoding (S3 never URL-encodes keys in
/// the XML).
fn extract_keys(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < s.len() {
        let Some(start) = s[cursor..].find("<Key>") else {
            break;
        };
        let abs_start = cursor + start + "<Key>".len();
        let Some(end) = s[abs_start..].find("</Key>") else {
            break;
        };
        let abs_end = abs_start + end;
        out.push(s[abs_start..abs_end].to_owned());
        cursor = abs_end + "</Key>".len();
    }
    out
}

/// Extract the text content of the first `<tag>...</tag>` element.
fn extract_element(s: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = s.find(&open)? + open.len();
    let end = s[start..].find(&close)? + start;
    Some(s[start..end].to_owned())
}

/// Parse a full `ListObjectsV2` XML body into keys + pagination cursor.
///
/// AWS S3 and Cloudflare R2 cap a single `ListObjectsV2` response at
/// 1000 keys and signal more pages via
/// `<IsTruncated>true</IsTruncated>` plus a `<NextContinuationToken>`.
/// Ignoring those would silently truncate the ref list — see
/// [`S3Transport::list_refs`], which loops on the returned token.
fn parse_list_page(xml: &[u8]) -> ListPage {
    let Ok(s) = std::str::from_utf8(xml) else {
        return ListPage {
            keys: Vec::new(),
            next_continuation_token: None,
        };
    };
    let keys = extract_keys(s);
    let truncated = extract_element(s, "IsTruncated").as_deref() == Some("true");
    let next_continuation_token = if truncated {
        // Only honor a non-empty token; an empty/missing one ends the
        // loop rather than re-requesting page 0 forever.
        extract_element(s, "NextContinuationToken").filter(|t| !t.is_empty())
    } else {
        None
    };
    ListPage {
        keys,
        next_continuation_token,
    }
}

// ---------------------------------------------------------------------------
// Sparse-checkout fetch (issue #158). Feature-gated behind
// `sparse-checkout`.
//
// Wire contract additions (SPEC-TRANSPORT §6.6):
//
// - Object key: `sparse/<tree-hash-hex>/<filter-hash-hex>`. A server
//   that wants to offer sparse delivery pre-builds the manifest under
//   that key. Clients GET it; the response body IS the
//   `application/x-mkit-sparse` envelope.
// - The `?sparse=<filter-hash-hex>` query is a no-op on S3 (the
//   content-addressed key already encodes it) — we accept it for URL
//   parity with the HTTP transport but ignore it.
// - 404 → no precomputed sparse for that (tree, filter) pair. Maps to
//   `PackNotFound` so retries are terminated.
// ---------------------------------------------------------------------------

#[cfg(feature = "sparse-checkout")]
mod sparse_fetch {
    use super::{
        Hash, Method, PACK_BODY_LIMIT_USIZE, S3Transport, TransportError, TransportResult, to_hex,
    };
    use mkit_core::sparse::{
        SPARSE_WIRE_MAX_BYTES, SparseResponse, decode_sparse_response, hash_filter,
    };
    use std::path::PathBuf;

    impl S3Transport {
        /// Build the S3 object key for a sparse delivery:
        /// `sparse/<tree-hex>/<filter-hex>`.
        #[must_use]
        pub fn sparse_object_key(tree_hash: &Hash, filter_hash: &Hash) -> String {
            format!("sparse/{}/{}", to_hex(tree_hash), to_hex(filter_hash))
        }

        /// Fetch the precomputed sparse delivery for `(tree_hash,
        /// filter)`. The S3 transport does NOT compute manifests; it
        /// assumes a server has pre-built them under the canonical
        /// key.
        ///
        /// As with the HTTP transport, this function does NOT verify
        /// the manifest — the caller MUST run
        /// [`mkit_core::sparse::verify_sparse`] on the result before
        /// trusting any delivered entries.
        ///
        /// # Errors
        ///
        /// - [`TransportError::PackNotFound`] — no precomputed sparse
        ///   for the addressed `(tree, filter)` pair.
        /// - [`TransportError::AccessDenied`] — credentials rejected.
        /// - [`TransportError::InvalidResponse`] — wire envelope
        ///   decode failed.
        /// - [`TransportError::PayloadTooLarge`] — response body
        ///   exceeded `SPARSE_WIRE_MAX_BYTES`.
        pub fn fetch_sparse_tree(
            &self,
            tree_hash: &Hash,
            filter: &[PathBuf],
        ) -> TransportResult<SparseResponse> {
            let filter_hash = hash_filter(filter);
            let key = Self::sparse_object_key(tree_hash, &filter_hash);
            // Cap body size at the wire-format max — far smaller than
            // the pack-body limit. PACK_BODY_LIMIT_USIZE is the
            // existing transport-side ceiling, used here for parity
            // when SPARSE_WIRE_MAX_BYTES would otherwise allow a
            // non-pack body larger than any pack we'd accept.
            let cap = SPARSE_WIRE_MAX_BYTES.min(PACK_BODY_LIMIT_USIZE);
            let resp = self.http_request_pub(&Method::GET, &key, "", None, &[], Some(cap))?;
            match resp.status_pub() {
                200 => decode_sparse_response(resp.body_pub())
                    .map_err(|_| TransportError::InvalidResponse),
                404 => Err(TransportError::PackNotFound),
                403 | 401 => Err(TransportError::AccessDenied),
                s => Err(TransportError::ServerError { status: s }),
            }
        }
    }
}

// Crate-private bridge so the sparse-fetch module can poke through
// `http_request` without the transport file losing its tightly-scoped
// `pub(crate)` surface.
#[cfg(feature = "sparse-checkout")]
impl S3Transport {
    pub(crate) fn http_request_pub(
        &self,
        method: &Method,
        key: &str,
        query: &str,
        payload: Option<&[u8]>,
        extra_headers: &[(&'static str, String)],
        body_limit: Option<usize>,
    ) -> TransportResult<HttpResponse> {
        self.http_request(method, key, query, payload, extra_headers, body_limit)
    }
}

#[cfg(feature = "sparse-checkout")]
impl HttpResponse {
    pub(crate) fn status_pub(&self) -> u16 {
        self.status
    }
    pub(crate) fn body_pub(&self) -> &[u8] {
        &self.body
    }
}

// ---------------------------------------------------------------------------
// Pack-Shards client (feature-gated)
// ---------------------------------------------------------------------------

/// Per-request timeout for a single shard GET.
///
/// Bounds a stalled straggler so a detached worker can never pin a
/// thread for the process lifetime. See the HTTP transport's
/// `SHARD_REQUEST_TIMEOUT` for the matching rationale.
#[cfg(feature = "pack-shards")]
const SHARD_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Fetch a single shard, retrying transient failures through the
/// supplied backoff ladder.
///
/// Retries ONLY on `ConnectionFailed` / 429 / 5xx (per `is_retryable`).
/// `AccessDenied` (401/403), `PackNotFound` (404), and `PayloadTooLarge`
/// are terminal and return immediately. The shard object key is built
/// from the EFFECTIVE PREFIX inside [`fetch_one_shard`], preserving
/// #180's namespace isolation across retries.
#[cfg(feature = "pack-shards")]
#[allow(clippy::too_many_arguments)]
fn fetch_one_shard_with_retry(
    client: &Client,
    endpoint: &str,
    bucket: &str,
    prefix: Option<&str>,
    creds: &Credentials,
    digest: &Hash,
    index: u16,
    clock: fn() -> i64,
    backoff: fn() -> BackoffIterator,
    sleeper: fn(Duration),
) -> TransportResult<Vec<u8>> {
    let mut ladder = backoff();
    loop {
        let ts = clock();
        let err = match fetch_one_shard(client, endpoint, bucket, prefix, creds, digest, index, ts)
        {
            Ok(bytes) => return Ok(bytes),
            Err(e) => e,
        };
        if is_retryable(&err)
            && let Some(delay) = ladder.next()
        {
            sleeper(delay);
            continue;
        }
        return Err(err);
    }
}

#[cfg(feature = "pack-shards")]
fn fetch_one_shard(
    client: &Client,
    endpoint: &str,
    bucket: &str,
    prefix: Option<&str>,
    creds: &Credentials,
    digest: &Hash,
    index: u16,
    ts: i64,
) -> TransportResult<Vec<u8>> {
    let canonical_key = S3Transport::shard_object_key(digest, index);
    let object_key = prefix.map_or_else(
        || canonical_key.clone(),
        |namespace| format!("{namespace}/{canonical_key}"),
    );
    let path = if bucket.is_empty() {
        format!("/{object_key}")
    } else {
        format!("/{bucket}/{object_key}")
    };
    let signed = sign_request(creds, "GET", &path, "", &[], endpoint, ts);
    let url = format!("{endpoint}{path}");
    let resp = client
        .request(Method::GET, &url)
        .timeout(SHARD_REQUEST_TIMEOUT)
        .header("Authorization", signed.authorization)
        .header("x-amz-date", signed.x_amz_date)
        .header("x-amz-content-sha256", signed.x_amz_content_sha256)
        .send()
        .map_err(|_| TransportError::ConnectionFailed)?;
    let status = resp.status().as_u16();
    match status {
        200 => {
            let bytes = resp.bytes().map_err(|_| TransportError::ConnectionFailed)?;
            if bytes.len() > PACK_BODY_LIMIT_USIZE {
                return Err(TransportError::PayloadTooLarge(bytes.len()));
            }
            Ok(bytes.to_vec())
        }
        404 => Err(TransportError::PackNotFound),
        401 | 403 => Err(TransportError::AccessDenied),
        s => Err(TransportError::ServerError { status: s }),
    }
}

#[cfg(feature = "pack-shards")]
impl S3Transport {
    fn download_pack_via_shards(&self, key: &PackKey) -> TransportResult<Option<Vec<u8>>> {
        use mkit_core::pack_shard::{
            MANIFEST_MAX_BYTES, Shard, decode_manifest, decode_pack_from_shards,
        };
        use std::sync::mpsc;

        let manifest_key = Self::shard_manifest_object_key(key.as_bytes());
        let manifest_resp = self.http_request(
            &Method::GET,
            &manifest_key,
            "",
            None,
            &[],
            Some(MANIFEST_MAX_BYTES),
        )?;
        match manifest_resp.status {
            200 => {}
            // 404 is the only legitimate "no shards published" signal —
            // the producer never wrote a manifest, so the client must
            // fall through to the monolithic GET. Every other status,
            // including a malformed-body 200, propagates so the caller
            // sees the bug rather than silently downgrading. This
            // mirrors HTTP's `download_pack_via_shards` posture — see
            // `mkit-transport-http`'s comment on `X-Pack-Shards`.
            404 => return Ok(None),
            403 | 401 => return Err(TransportError::AccessDenied),
            s => return Err(TransportError::ServerError { status: s }),
        }
        let manifest =
            decode_manifest(&manifest_resp.body).map_err(|_| TransportError::InvalidResponse)?;

        let total = manifest.config.total_shards();
        let minimum = manifest.config.minimum_shards.get();
        let max_failures = manifest.config.extra_shards.get();

        if total > 256 {
            return Err(TransportError::InvalidResponse);
        }
        let total_u16: u16 = u16::try_from(total).unwrap_or(u16::MAX);

        let (tx, rx) = mpsc::channel::<(u16, TransportResult<Vec<u8>>)>();
        let digest: Hash = *key.as_bytes();
        // Workers are *detached* (never joined): once quorum or the
        // failure threshold is reached the collection loop stops waiting
        // so a slow straggler cannot block the download. Each shard GET
        // carries SHARD_REQUEST_TIMEOUT so detached workers terminate.
        let clock = self.clock;
        let backoff = self.backoff;
        let sleeper = self.sleeper;
        for i in 0..total_u16 {
            let tx = tx.clone();
            let endpoint = self.endpoint.clone();
            let bucket = self.bucket.clone();
            let prefix = self.prefix.clone();
            let creds = self.creds.clone();
            let client = self.client.clone();
            std::thread::spawn(move || {
                let result = fetch_one_shard_with_retry(
                    &client,
                    &endpoint,
                    &bucket,
                    prefix.as_deref(),
                    &creds,
                    &digest,
                    i,
                    clock,
                    backoff,
                    sleeper,
                );
                let _ = tx.send((i, result));
            });
        }
        drop(tx);

        let mut shards: Vec<Shard> = Vec::with_capacity(minimum as usize);
        let mut failures: u16 = 0;
        for (index, res) in &rx {
            if let Ok(bytes) = res {
                shards.push(Shard { index, bytes });
                if shards.len() >= minimum as usize {
                    break;
                }
            } else {
                failures += 1;
                if failures > max_failures {
                    break;
                }
            }
        }
        // Detached workers are not joined; stragglers are bounded by
        // SHARD_REQUEST_TIMEOUT.

        if shards.len() < minimum as usize {
            return Err(TransportError::PackNotFound);
        }

        let pack = decode_pack_from_shards(&shards, &manifest)
            .map_err(|_| TransportError::InvalidResponse)?;
        Ok(Some(pack))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_object_key_shape() {
        let digest = [0xABu8; 32];
        let key = S3Transport::pack_object_key(&digest);
        assert!(key.starts_with("packs/"));
        assert_eq!(key.len(), "packs/".len() + 64);
    }

    #[test]
    fn list_query_format() {
        // `/` MUST be percent-encoded as `%2F` and keys sorted, so the
        // signed query matches what real AWS S3 re-derives server-side.
        assert_eq!(
            S3Transport::build_list_query("refs/heads/"),
            "list-type=2&prefix=refs%2Fheads%2F"
        );
        assert_eq!(S3Transport::build_list_query(""), "list-type=2&prefix=");
    }

    #[test]
    fn list_query_continued_format() {
        // Canonical sort puts `continuation-token` before `list-type`.
        assert_eq!(
            S3Transport::build_list_query_continued("refs/heads/", "TOKEN123"),
            "continuation-token=TOKEN123&list-type=2&prefix=refs%2Fheads%2F"
        );
    }

    #[test]
    fn list_page_reports_continuation_when_truncated() {
        let xml = br"<ListBucketResult>
            <IsTruncated>true</IsTruncated>
            <Contents><Key>refs/heads/a</Key></Contents>
            <NextContinuationToken>NEXT</NextContinuationToken>
        </ListBucketResult>";
        let page = parse_list_page(xml);
        assert_eq!(page.keys, vec!["refs/heads/a".to_owned()]);
        assert_eq!(page.next_continuation_token.as_deref(), Some("NEXT"));
    }

    #[test]
    fn list_page_no_continuation_when_not_truncated() {
        let xml = br"<ListBucketResult>
            <IsTruncated>false</IsTruncated>
            <Contents><Key>refs/heads/a</Key></Contents>
        </ListBucketResult>";
        let page = parse_list_page(xml);
        assert_eq!(page.keys, vec!["refs/heads/a".to_owned()]);
        assert!(page.next_continuation_token.is_none());
    }

    #[test]
    fn list_page_truncated_but_empty_token_terminates() {
        // Defensive: IsTruncated=true with a missing/empty token must
        // not loop forever.
        let xml = br"<ListBucketResult>
            <IsTruncated>true</IsTruncated>
            <Contents><Key>refs/heads/a</Key></Contents>
        </ListBucketResult>";
        let page = parse_list_page(xml);
        assert!(page.next_continuation_token.is_none());
    }

    #[test]
    fn url_parse_ok_no_prefix() {
        let p = parse_s3_url("mkit+s3://abc.r2.cloudflarestorage.com/bucket").unwrap();
        assert_eq!(p.host, "abc.r2.cloudflarestorage.com");
        assert_eq!(p.bucket, "bucket");
        assert!(p.prefix.is_none());
    }

    #[test]
    fn url_parse_ok_with_prefix() {
        let p = parse_s3_url("mkit+s3://host.example/bucket/project-a").unwrap();
        assert_eq!(p.prefix.as_deref(), Some("project-a"));
    }

    #[test]
    fn url_parse_ok_with_nested_safe_prefix() {
        let p = parse_s3_url("mkit+s3://host.example/bucket/team_1/project.a-2").unwrap();
        assert_eq!(p.prefix.as_deref(), Some("team_1/project.a-2"));
    }

    #[test]
    fn url_parse_rejects_prefix_url_metacharacters() {
        for prefix in [
            "project?x=1",
            "project#frag",
            "project&x=1",
            "project x",
            "project%2Fother",
            "project+other",
        ] {
            let url = format!("mkit+s3://host.example/bucket/{prefix}");
            assert!(
                matches!(parse_s3_url(&url), Err(TransportError::InvalidRef(_))),
                "prefix should be rejected: {prefix}"
            );
        }
    }

    #[test]
    fn url_parse_rejects_non_mkit_scheme() {
        assert!(matches!(
            parse_s3_url("s3://bucket"),
            Err(TransportError::InvalidRef(_))
        ));
    }

    #[test]
    fn url_parse_rejects_empty_bucket() {
        assert!(matches!(
            parse_s3_url("mkit+s3://host.example"),
            Err(TransportError::InvalidRef(_))
        ));
    }

    #[test]
    fn list_xml_extracts_keys() {
        let xml = "<ListBucketResult><Contents><Key>refs/heads/main</Key></Contents><Contents><Key>refs/tags/v1</Key></Contents></ListBucketResult>";
        assert_eq!(
            extract_keys(xml),
            vec!["refs/heads/main".to_owned(), "refs/tags/v1".to_owned()]
        );
    }

    #[test]
    fn list_xml_empty() {
        assert!(extract_keys("<ListBucketResult></ListBucketResult>").is_empty());
    }

    #[test]
    fn format_ref_wire_is_65_bytes() {
        let h = [0x11u8; 32];
        let w = format_ref_wire(&h);
        assert_eq!(w.len(), 65);
        assert_eq!(w[64], b'\n');
    }

    #[test]
    fn quoted_md5_has_surrounding_quotes() {
        let got = quoted_md5(b"hello");
        assert!(got.starts_with('"') && got.ends_with('"'));
        // 32 hex + 2 quotes.
        assert_eq!(got.len(), 34);
    }

    #[test]
    fn parse_ref_body_accepts_trailing_newline() {
        let mut body = Vec::new();
        body.extend_from_slice(b"0101010101010101010101010101010101010101010101010101010101010101");
        body.push(b'\n');
        let h = parse_ref_body(&body).unwrap();
        assert_eq!(h[0], 0x01);
    }

    #[test]
    fn parse_ref_body_rejects_short() {
        assert!(parse_ref_body(b"deadbeef").is_err());
    }

    #[test]
    fn connect_rejects_bad_url() {
        assert!(S3Transport::connect("not-a-url").is_err());
    }
}
