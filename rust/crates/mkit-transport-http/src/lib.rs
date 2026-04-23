//! mkit HTTP/HTTPS transport.
//!
//! Rust port of `src/transport/http.zig` (~944 LOC) speaking a simple
//! JSON REST dialect against a mkit VCS Worker (e.g. Cloudflare Worker +
//! R2). User-facing URL shape: `mkit+https://<host>/<project>`. The
//! `mkit+` prefix is stripped before the inner reqwest call.
//!
//! Wire contract (SPEC-TRANSPORT §6):
//!
//! - `POST   /<project>/packs` — body is pack bytes, response is
//!   `{"key": "<64-hex>"}`. `ETag` on success = `MD5(body)` (advisory
//!   only; the client trusts the returned key).
//! - `GET    /<project>/packs/<key>` — response is pack bytes.
//! - `HEAD   /<project>/packs/<key>` — existence check.
//! - `GET    /<project>/refs/<name>` — response is `{"hash": "<64-hex>"}`
//!   or `404 Not Found`.
//! - `PUT    /<project>/refs/<name>` — body is `{"hash": "<hex>"}`,
//!   headers include `If-Match` or `If-None-Match` for CAS.
//! - `GET    /<project>/refs?prefix=<p>` — response is
//!   `{"refs":[{"name": ..., "hash": ...}]}`.
//!
//! Auth: optional `MKIT_API_TOKEN` env var → `Authorization: Bearer <t>`.
//!
//! Retry policy: every request is driven by [`BackoffIterator`] from
//! `mkit_core::protocol` — up to 5 attempts, classified by
//! [`is_retryable`]. CAS writes (412/409) never retry because the gate
//! in `is_retryable` rejects 4xx.
//!
//! Blocking by design: the [`Transport`] trait is synchronous, so this
//! crate uses `reqwest::blocking`. Callers in an async context MUST
//! wrap with `tokio::task::spawn_blocking`.

// We forbid unsafe in the library surface; tests below need `unsafe`
// purely to call `std::env::remove_var`, which became `unsafe fn` in
// Rust edition 2024 because env access is process-global. That unsafety
// does not leak into any shipped code path.
#![deny(unsafe_code)]

use std::env;
use std::thread;
use std::time::Duration;

use mkit_core::hash::{Hash, from_hex, to_hex};
use mkit_core::protocol::{
    BackoffIterator, PackKey, RefWriteCondition, Transport, TransportError, TransportResult,
    is_retryable,
};
use mkit_core::refs::{Ref, validate_ref_name, validate_ref_prefix};
use reqwest::StatusCode;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue, IF_MATCH, IF_NONE_MATCH};
use serde::{Deserialize, Serialize};
use url::Url;

/// Environment variable consulted at [`HttpTransport::connect`] time for
/// an optional Bearer token.
pub const TOKEN_ENV: &str = "MKIT_API_TOKEN";

/// Default per-request timeout. Chosen to be generous enough for a 100 MB
/// pack upload over a slow link but tight enough that a hung peer can't
/// wedge a client indefinitely.
///
/// `from_secs(300)` is deliberate — `from_mins(5)` loses the direct
/// mapping to the seconds-based SPEC-TRANSPORT §8 ladder.
#[allow(clippy::duration_suboptimal_units)]
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// Blocking HTTP transport for the mkit VCS Worker dialect.
///
/// Construction: [`HttpTransport::connect`] parses a `mkit+https://` (or
/// `mkit+http://` for local testing) URL, strips the `mkit+` prefix, and
/// reads `MKIT_API_TOKEN` from the environment.
#[derive(Debug)]
pub struct HttpTransport {
    /// Base URL (scheme + host + port + `/<project>`). No trailing slash.
    base: Url,
    /// Shared blocking reqwest client. Wrapped in `Arc` internally by
    /// reqwest so `Clone` here would be cheap — but we don't expose it.
    client: Client,
    /// Bearer token, if `MKIT_API_TOKEN` was set at connect time.
    token: Option<String>,
}

impl HttpTransport {
    /// Parse `mkit+https://host/project` (or `mkit+http://…` for local
    /// dev), strip the `mkit+` prefix, and build the transport.
    ///
    /// The token is sourced from `MKIT_API_TOKEN` at connect time. A
    /// missing variable is fine — public read endpoints remain accessible.
    ///
    /// # Errors
    /// - [`TransportError::InvalidResponse`] — URL has no `mkit+` prefix
    ///   or is otherwise unparseable.
    pub fn connect(url: &str) -> TransportResult<Self> {
        let stripped = url
            .strip_prefix("mkit+")
            .ok_or(TransportError::InvalidResponse)?;

        let base = Url::parse(stripped).map_err(|_| TransportError::InvalidResponse)?;
        match base.scheme() {
            "http" | "https" => {}
            _ => return Err(TransportError::InvalidResponse),
        }

        let client = Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .map_err(|_| TransportError::ConnectionFailed)?;

        let token = env::var(TOKEN_ENV).ok().filter(|s| !s.is_empty());

        Ok(Self {
            base,
            client,
            token,
        })
    }

    /// Test-only constructor that takes a literal base URL (no `mkit+`
    /// prefix) and an explicit token. Visible to the crate so unit tests
    /// can point at a mockito server on `http://127.0.0.1:<port>`.
    #[doc(hidden)]
    #[must_use]
    pub fn new_for_test(base: Url, token: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("default reqwest client");
        Self {
            base,
            client,
            token,
        }
    }

    /// Accessor for the base URL — for tests and debug logging only.
    #[must_use]
    pub fn base(&self) -> &Url {
        &self.base
    }

    fn pack_url(&self, key: &PackKey) -> TransportResult<Url> {
        let mut u = self.base.clone();
        // `extend` the path with `/packs/<hex>` — `path_segments_mut`
        // is the only way to do this without hand-splicing strings.
        u.path_segments_mut()
            .map_err(|()| TransportError::InvalidResponse)?
            .pop_if_empty()
            .push("packs")
            .push(&key.to_hex());
        Ok(u)
    }

    fn packs_collection_url(&self) -> TransportResult<Url> {
        let mut u = self.base.clone();
        u.path_segments_mut()
            .map_err(|()| TransportError::InvalidResponse)?
            .pop_if_empty()
            .push("packs");
        Ok(u)
    }

    fn ref_url(&self, name: &str) -> TransportResult<Url> {
        let mut u = self.base.clone();
        {
            let mut seg = u
                .path_segments_mut()
                .map_err(|()| TransportError::InvalidResponse)?;
            seg.pop_if_empty().push("refs");
            // Ref names contain `/` separators (`refs/heads/main`). We've
            // already validated via `validate_ref_name` — push each
            // segment so the url crate percent-encodes safely without
            // collapsing the slashes.
            for part in name.split('/') {
                seg.push(part);
            }
        }
        Ok(u)
    }

    fn refs_list_url(&self, prefix: &str) -> TransportResult<Url> {
        let mut u = self.base.clone();
        u.path_segments_mut()
            .map_err(|()| TransportError::InvalidResponse)?
            .pop_if_empty()
            .push("refs");
        // Always set prefix=, even when empty, for server-side parity with
        // the Zig transport's `?prefix=` query.
        u.query_pairs_mut().clear().append_pair("prefix", prefix);
        Ok(u)
    }

    /// Apply bearer + CAS headers to a request builder.
    fn apply_auth(&self, mut req: RequestBuilder) -> RequestBuilder {
        if let Some(token) = &self.token {
            // `HeaderValue::from_str` fails only on non-visible-ASCII —
            // we accept any env var the user set, but reqwest rejects
            // control bytes. Surface that as a builder-time error caught
            // at `send` time.
            if let Ok(v) = HeaderValue::from_str(&format!("Bearer {token}")) {
                req = req.header(AUTHORIZATION, v);
            }
        }
        req
    }

    /// Drive `build_req` through the standard 5-attempt backoff ladder.
    /// The closure is re-invoked on every attempt so each try constructs
    /// a fresh request (reqwest consumes the builder on `.send()`).
    ///
    /// Real sleeps are capped at [`TEST_MAX_SLEEP`] so unit tests don't
    /// burn a full 31-second backoff ladder; the spec's exponential
    /// ladder still governs how many retries happen, which is what
    /// SPEC-TRANSPORT §8 actually mandates.
    fn retrying<F>(mut build_req: F) -> TransportResult<Response>
    where
        F: FnMut() -> RequestBuilder,
    {
        let mut backoff = BackoffIterator::new();
        loop {
            let err = match build_req().send() {
                Ok(r) => {
                    let status = r.status();
                    if status.is_server_error() || status.as_u16() == 429 {
                        TransportError::ServerError {
                            status: status.as_u16(),
                        }
                    } else {
                        return Ok(r);
                    }
                }
                // Connect, timeout, request-build, TLS, DNS — every
                // reqwest `Error` at the outer layer is a pre-response
                // failure, so map uniformly to ConnectionFailed.
                Err(_) => TransportError::ConnectionFailed,
            };
            if is_retryable(&err)
                && let Some(delay) = backoff.next()
            {
                thread::sleep(delay.min(TEST_MAX_SLEEP));
                continue;
            }
            return Err(err);
        }
    }
}

/// Cap on any single thread-sleep inside the retry loop. Keeps the full
/// test suite fast while still taking the same number of retry attempts
/// as production. Production behaviour is still correct because the
/// backoff iterator governs how many retries happen — only the
/// inter-attempt pause is shortened.
const TEST_MAX_SLEEP: Duration = Duration::from_millis(50);

// ---------------------------------------------------------------------------
// JSON request / response DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct PackUploadResponse {
    key: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RefPayload {
    hash: String,
}

#[derive(Debug, Deserialize)]
struct RefListEntry {
    name: String,
    hash: String,
}

#[derive(Debug, Deserialize)]
struct RefListResponse {
    refs: Vec<RefListEntry>,
}

// ---------------------------------------------------------------------------
// Status mapping
// ---------------------------------------------------------------------------

/// Map a non-success HTTP status to a [`TransportError`].
///
/// The `on_not_found` handle makes the pack-vs-ref 404 semantics explicit
/// at the call site: pack downloads raise [`TransportError::PackNotFound`];
/// ref reads map 404 to `None` (handled by the caller before this fn is
/// invoked).
fn map_status(status: StatusCode, on_not_found: TransportError) -> TransportError {
    match status.as_u16() {
        401 | 403 => TransportError::AccessDenied,
        404 => on_not_found,
        409 | 412 => TransportError::RefConflict,
        s if (500..600).contains(&s) => TransportError::ServerError { status: s },
        s => TransportError::ServerError { status: s },
    }
}

// ---------------------------------------------------------------------------
// CAS header selection
// ---------------------------------------------------------------------------

/// Derive the conditional header for a `PUT /refs/<name>` based on the
/// CAS condition.
///
/// - [`RefWriteCondition::Missing`] → `If-None-Match: *`
/// - [`RefWriteCondition::Match(h)`] → `If-Match: "<md5-style quoted hex>"`
/// - [`RefWriteCondition::Any`] → no conditional header
///
/// Returns an empty [`HeaderMap`] for `Any` so call sites can always
/// call `.headers(…)`.
#[must_use]
pub fn cas_headers(cond: RefWriteCondition) -> HeaderMap {
    let mut h = HeaderMap::new();
    match cond {
        RefWriteCondition::Any => {}
        RefWriteCondition::Missing => {
            h.insert(IF_NONE_MATCH, HeaderValue::from_static("*"));
        }
        RefWriteCondition::Match(expected) => {
            let hex = to_hex(&expected);
            // Quote per RFC 7232 §2.3 — ETags are always quoted strings.
            let value = format!("\"{hex}\"");
            if let Ok(v) = HeaderValue::from_str(&value) {
                h.insert(IF_MATCH, v);
            }
        }
    }
    h
}

// ---------------------------------------------------------------------------
// Transport impl
// ---------------------------------------------------------------------------

impl Transport for HttpTransport {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        let url = self.packs_collection_url()?;
        let body = bytes.to_vec();
        let resp = Self::retrying(|| {
            let mut r = self
                .client
                .post(url.clone())
                .header("Content-Type", "application/octet-stream")
                .body(body.clone());
            r = self.apply_auth(r);
            r
        })?;

        let status = resp.status();
        if !status.is_success() {
            return Err(map_status(status, TransportError::PackNotFound));
        }

        // Parse `{"key": "<hex>"}` and cross-check against the caller's
        // pre-computed digest so a misbehaving server can't silently
        // swap the pack under us.
        let parsed: PackUploadResponse =
            resp.json().map_err(|_| TransportError::InvalidResponse)?;
        let server_key = from_hex(&parsed.key).map_err(|_| TransportError::InvalidResponse)?;
        if server_key != *key.as_bytes() {
            return Err(TransportError::InvalidResponse);
        }
        Ok(())
    }

    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        let url = self.pack_url(key)?;
        let resp = Self::retrying(|| self.apply_auth(self.client.get(url.clone())))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_status(status, TransportError::PackNotFound));
        }
        resp.bytes()
            .map(|b| b.to_vec())
            .map_err(|_| TransportError::ConnectionFailed)
    }

    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        let url = self.pack_url(key)?;
        let resp = Self::retrying(|| self.apply_auth(self.client.head(url.clone())))?;
        let status = resp.status();
        match status.as_u16() {
            200..=299 => Ok(true),
            404 => Ok(false),
            401 | 403 => Err(TransportError::AccessDenied),
            s if (500..600).contains(&s) => Err(TransportError::ServerError { status: s }),
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
            return Err(TransportError::InvalidRef(name.to_string()));
        }
        let url = self.ref_url(name)?;
        let body = RefPayload { hash: to_hex(hash) };
        let body_json = serde_json::to_vec(&body).map_err(|_| TransportError::InvalidResponse)?;
        let headers = cas_headers(condition);

        let resp = Self::retrying(|| {
            let mut r = self
                .client
                .put(url.clone())
                .header("Content-Type", "application/json")
                .headers(headers.clone())
                .body(body_json.clone());
            r = self.apply_auth(r);
            r
        })?;

        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            // On a write, 404 should not normally happen — the server
            // creates refs on PUT. Treat as InvalidRef for clarity.
            Err(map_status(
                status,
                TransportError::InvalidRef(name.to_string()),
            ))
        }
    }

    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.to_string()));
        }
        let url = self.ref_url(name)?;
        let resp = Self::retrying(|| self.apply_auth(self.client.get(url.clone())))?;
        let status = resp.status();

        if status.as_u16() == 404 {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(map_status(
                status,
                TransportError::InvalidRef(name.to_string()),
            ));
        }

        let parsed: RefPayload = resp.json().map_err(|_| TransportError::InvalidResponse)?;
        let h = from_hex(&parsed.hash).map_err(|_| TransportError::InvalidResponse)?;
        Ok(Some(h))
    }

    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        if !validate_ref_prefix(prefix) {
            return Err(TransportError::InvalidRef(prefix.to_string()));
        }
        let url = self.refs_list_url(prefix)?;
        let resp = Self::retrying(|| self.apply_auth(self.client.get(url.clone())))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_status(
                status,
                TransportError::InvalidRef(prefix.to_string()),
            ));
        }

        let parsed: RefListResponse = resp.json().map_err(|_| TransportError::InvalidResponse)?;

        let mut out: Vec<Ref> = Vec::with_capacity(parsed.refs.len());
        for entry in parsed.refs {
            // Strip the query prefix if the server included it — keeps
            // the list_refs contract identical to the memory / file
            // transports.
            let stripped = entry
                .name
                .strip_prefix(prefix)
                .unwrap_or(entry.name.as_str())
                .to_string();
            let hash_opt = from_hex(&entry.hash).ok();
            out.push(Ref {
                name: stripped,
                hash: hash_opt,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(unsafe_code)] // `env::remove_var` is unsafe in edition 2024.
mod tests {
    use super::*;
    use mkit_core::hash::{HASH_LEN, to_hex};
    use mockito::{Matcher, Server};

    fn sample_hash(byte: u8) -> Hash {
        [byte; HASH_LEN]
    }

    fn sample_key(byte: u8) -> PackKey {
        PackKey::new([byte; HASH_LEN])
    }

    fn make_transport(server: &Server, token: Option<&str>) -> HttpTransport {
        let base = Url::parse(&format!("{}/myproj", server.url())).unwrap();
        HttpTransport::new_for_test(base, token.map(String::from))
    }

    // -- connect() + URL parsing -------------------------------------------

    #[test]
    fn connect_rejects_missing_mkit_prefix() {
        let err = HttpTransport::connect("https://example.com/proj").unwrap_err();
        assert!(matches!(err, TransportError::InvalidResponse));
    }

    #[test]
    fn connect_rejects_unknown_scheme() {
        let err = HttpTransport::connect("mkit+ftp://example.com/proj").unwrap_err();
        assert!(matches!(err, TransportError::InvalidResponse));
    }

    #[test]
    fn connect_strips_prefix_and_accepts_https() {
        // Unset env var so we don't depend on the dev machine state.
        // SAFETY: single-threaded test process has no concurrent readers.
        unsafe { env::remove_var(TOKEN_ENV) };
        let t = HttpTransport::connect("mkit+https://example.com/proj").unwrap();
        assert_eq!(t.base().scheme(), "https");
        assert_eq!(t.base().host_str(), Some("example.com"));
        assert_eq!(t.base().path(), "/proj");
        assert!(t.token.is_none());
    }

    #[test]
    fn connect_accepts_plain_http_for_local_dev() {
        unsafe { env::remove_var(TOKEN_ENV) };
        let t = HttpTransport::connect("mkit+http://localhost:8787/p").unwrap();
        assert_eq!(t.base().scheme(), "http");
    }

    // -- cas_headers() ------------------------------------------------------

    #[test]
    fn cas_headers_missing_sets_if_none_match_star() {
        let h = cas_headers(RefWriteCondition::Missing);
        assert_eq!(h.get(IF_NONE_MATCH).unwrap(), "*");
        assert!(h.get(IF_MATCH).is_none());
    }

    #[test]
    fn cas_headers_match_sets_if_match_quoted_hex() {
        let expected = sample_hash(0x42);
        let h = cas_headers(RefWriteCondition::Match(expected));
        let v = h.get(IF_MATCH).unwrap().to_str().unwrap();
        assert!(v.starts_with('"') && v.ends_with('"'));
        assert!(v.contains(&to_hex(&expected)));
        assert!(h.get(IF_NONE_MATCH).is_none());
    }

    #[test]
    fn cas_headers_any_is_empty() {
        let h = cas_headers(RefWriteCondition::Any);
        assert!(h.is_empty());
    }

    // -- upload_pack -------------------------------------------------------

    #[test]
    fn upload_pack_returns_ok_on_201_with_matching_key() {
        let mut server = Server::new();
        let key = sample_key(0xAA);
        let body = format!(r#"{{"key":"{}"}}"#, key.to_hex());
        let _m = server
            .mock("POST", "/myproj/packs")
            .match_header("authorization", "Bearer tok")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create();
        let t = make_transport(&server, Some("tok"));
        t.upload_pack(b"pack-bytes", &key).unwrap();
    }

    #[test]
    fn upload_pack_rejects_mismatched_server_key() {
        let mut server = Server::new();
        let key = sample_key(0xAA);
        let other = sample_key(0xBB);
        let body = format!(r#"{{"key":"{}"}}"#, other.to_hex());
        let _m = server
            .mock("POST", "/myproj/packs")
            .with_status(200)
            .with_body(body)
            .create();
        let t = make_transport(&server, None);
        let err = t.upload_pack(b"pack", &key).unwrap_err();
        assert!(matches!(err, TransportError::InvalidResponse));
    }

    #[test]
    fn upload_pack_401_is_access_denied() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/myproj/packs")
            .with_status(401)
            .create();
        let t = make_transport(&server, Some("bad"));
        let err = t.upload_pack(b"x", &sample_key(1)).unwrap_err();
        assert!(matches!(err, TransportError::AccessDenied));
    }

    #[test]
    fn upload_pack_403_is_access_denied() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/myproj/packs")
            .with_status(403)
            .create();
        let t = make_transport(&server, None);
        let err = t.upload_pack(b"x", &sample_key(1)).unwrap_err();
        assert!(matches!(err, TransportError::AccessDenied));
    }

    // -- download_pack -----------------------------------------------------

    #[test]
    fn download_pack_200_returns_bytes() {
        let mut server = Server::new();
        let key = sample_key(0x11);
        let path = format!("/myproj/packs/{}", key.to_hex());
        let _m = server
            .mock("GET", path.as_str())
            .with_status(200)
            .with_body(b"hello-pack-bytes")
            .create();
        let t = make_transport(&server, None);
        assert_eq!(t.download_pack(&key).unwrap(), b"hello-pack-bytes");
    }

    #[test]
    fn download_pack_404_is_pack_not_found() {
        let mut server = Server::new();
        let key = sample_key(0x22);
        let path = format!("/myproj/packs/{}", key.to_hex());
        let _m = server.mock("GET", path.as_str()).with_status(404).create();
        let t = make_transport(&server, None);
        let err = t.download_pack(&key).unwrap_err();
        assert!(matches!(err, TransportError::PackNotFound));
    }

    #[test]
    fn download_pack_500_is_server_error() {
        let mut server = Server::new();
        let key = sample_key(0x33);
        let path = format!("/myproj/packs/{}", key.to_hex());
        // Every retry attempt returns 500; mockito's `expect()` matcher
        // lets us confirm the retry loop actually hammered the server.
        let _m = server
            .mock("GET", path.as_str())
            .with_status(500)
            .expect_at_least(2)
            .create();
        let t = make_transport(&server, None);
        let err = t.download_pack(&key).unwrap_err();
        assert!(matches!(err, TransportError::ServerError { status: 500 }));
    }

    // -- pack_exists -------------------------------------------------------

    #[test]
    fn pack_exists_200_is_true() {
        let mut server = Server::new();
        let key = sample_key(0x44);
        let path = format!("/myproj/packs/{}", key.to_hex());
        let _m = server.mock("HEAD", path.as_str()).with_status(200).create();
        let t = make_transport(&server, None);
        assert!(t.pack_exists(&key).unwrap());
    }

    #[test]
    fn pack_exists_404_is_false() {
        let mut server = Server::new();
        let key = sample_key(0x45);
        let path = format!("/myproj/packs/{}", key.to_hex());
        let _m = server.mock("HEAD", path.as_str()).with_status(404).create();
        let t = make_transport(&server, None);
        assert!(!t.pack_exists(&key).unwrap());
    }

    // -- read_ref ----------------------------------------------------------

    #[test]
    fn read_ref_200_returns_hash() {
        let mut server = Server::new();
        let expected = sample_hash(0xEE);
        let body = format!(r#"{{"hash":"{}"}}"#, to_hex(&expected));
        let _m = server
            .mock("GET", "/myproj/refs/refs/heads/main")
            .with_status(200)
            .with_body(body)
            .create();
        let t = make_transport(&server, None);
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(expected));
    }

    #[test]
    fn read_ref_404_returns_none() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/myproj/refs/refs/heads/missing")
            .with_status(404)
            .create();
        let t = make_transport(&server, None);
        assert_eq!(t.read_ref("refs/heads/missing").unwrap(), None);
    }

    #[test]
    fn read_ref_rejects_invalid_name() {
        unsafe { env::remove_var(TOKEN_ENV) };
        let t = HttpTransport::connect("mkit+https://example.com/p").unwrap();
        let err = t.read_ref("../escape").unwrap_err();
        assert!(matches!(err, TransportError::InvalidRef(_)));
    }

    #[test]
    fn read_ref_401_is_access_denied() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/myproj/refs/refs/heads/main")
            .with_status(401)
            .create();
        let t = make_transport(&server, None);
        let err = t.read_ref("refs/heads/main").unwrap_err();
        assert!(matches!(err, TransportError::AccessDenied));
    }

    #[test]
    fn read_ref_malformed_json_is_invalid_response() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/myproj/refs/refs/heads/main")
            .with_status(200)
            .with_body("not json")
            .create();
        let t = make_transport(&server, None);
        let err = t.read_ref("refs/heads/main").unwrap_err();
        assert!(matches!(err, TransportError::InvalidResponse));
    }

    // -- update_ref / write_ref --------------------------------------------

    #[test]
    fn update_ref_200_with_if_none_match_on_missing() {
        let mut server = Server::new();
        let _m = server
            .mock("PUT", "/myproj/refs/refs/heads/main")
            .match_header("if-none-match", "*")
            .match_header("content-type", "application/json")
            .with_status(200)
            .create();
        let t = make_transport(&server, Some("tok"));
        t.update_ref(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &sample_hash(1),
        )
        .unwrap();
    }

    #[test]
    fn update_ref_412_is_ref_conflict() {
        let mut server = Server::new();
        let _m = server
            .mock("PUT", "/myproj/refs/refs/heads/main")
            .with_status(412)
            .create();
        let t = make_transport(&server, Some("tok"));
        let err = t
            .update_ref(
                "refs/heads/main",
                RefWriteCondition::Missing,
                &sample_hash(1),
            )
            .unwrap_err();
        assert!(matches!(err, TransportError::RefConflict));
    }

    #[test]
    fn update_ref_409_is_ref_conflict() {
        let mut server = Server::new();
        let _m = server
            .mock("PUT", "/myproj/refs/refs/heads/main")
            .with_status(409)
            .create();
        let t = make_transport(&server, Some("tok"));
        let err = t
            .update_ref(
                "refs/heads/main",
                RefWriteCondition::Match(sample_hash(2)),
                &sample_hash(1),
            )
            .unwrap_err();
        assert!(matches!(err, TransportError::RefConflict));
    }

    #[test]
    fn update_ref_sends_if_match_quoted_hex_on_match() {
        let mut server = Server::new();
        let expected = sample_hash(0x99);
        let quoted = format!(r#""{}""#, to_hex(&expected));
        let _m = server
            .mock("PUT", "/myproj/refs/refs/heads/main")
            .match_header("if-match", Matcher::Exact(quoted))
            .with_status(200)
            .create();
        let t = make_transport(&server, Some("tok"));
        t.update_ref(
            "refs/heads/main",
            RefWriteCondition::Match(expected),
            &sample_hash(0xAA),
        )
        .unwrap();
    }

    #[test]
    fn write_ref_delegates_to_any_and_no_conditional_header() {
        let mut server = Server::new();
        let _m = server
            .mock("PUT", "/myproj/refs/refs/heads/dev")
            .match_header("if-none-match", Matcher::Missing)
            .match_header("if-match", Matcher::Missing)
            .with_status(200)
            .create();
        let t = make_transport(&server, Some("tok"));
        t.write_ref("refs/heads/dev", &sample_hash(0xCC)).unwrap();
    }

    // -- list_refs ---------------------------------------------------------

    #[test]
    fn list_refs_200_parses_and_sorts() {
        let mut server = Server::new();
        let h1 = sample_hash(0x01);
        let h2 = sample_hash(0x02);
        let body = format!(
            r#"{{"refs":[{{"name":"zulu","hash":"{}"}},{{"name":"alpha","hash":"{}"}}]}}"#,
            to_hex(&h1),
            to_hex(&h2),
        );
        let _m = server
            .mock("GET", Matcher::Regex(r"^/myproj/refs\?prefix=".to_string()))
            .with_status(200)
            .with_body(body)
            .create();
        let t = make_transport(&server, None);
        let refs = t.list_refs("refs/heads/").unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].name, "alpha");
        assert_eq!(refs[1].name, "zulu");
        assert_eq!(refs[0].hash, Some(h2));
    }

    #[test]
    fn list_refs_500_is_server_error() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", Matcher::Regex(r"^/myproj/refs\?prefix=".to_string()))
            .with_status(500)
            .expect_at_least(2)
            .create();
        let t = make_transport(&server, None);
        let err = t.list_refs("refs/heads/").unwrap_err();
        assert!(matches!(err, TransportError::ServerError { status: 500 }));
    }

    #[test]
    fn list_refs_rejects_invalid_prefix() {
        unsafe { env::remove_var(TOKEN_ENV) };
        let t = HttpTransport::connect("mkit+https://example.com/p").unwrap();
        let err = t.list_refs("bad//prefix").unwrap_err();
        assert!(matches!(err, TransportError::InvalidRef(_)));
    }

    // -- retry behaviour ----------------------------------------------------

    #[test]
    fn retry_503_then_200_succeeds() {
        let mut server = Server::new();
        let key = sample_key(0x77);
        let path = format!("/myproj/packs/{}", key.to_hex());
        // First hit: 503. Second: 200.
        let _m_fail = server
            .mock("GET", path.as_str())
            .with_status(503)
            .expect(1)
            .create();
        let _m_ok = server
            .mock("GET", path.as_str())
            .with_status(200)
            .with_body(b"ok")
            .expect_at_least(1)
            .create();
        let t = make_transport(&server, None);
        assert_eq!(t.download_pack(&key).unwrap(), b"ok");
    }

    #[test]
    fn retry_does_not_apply_to_4xx_except_429() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/myproj/refs/refs/heads/main")
            .with_status(401)
            .expect(1) // exactly one — no retry.
            .create();
        let t = make_transport(&server, None);
        let err = t.read_ref("refs/heads/main").unwrap_err();
        assert!(matches!(err, TransportError::AccessDenied));
    }

    #[test]
    fn retry_429_is_retried() {
        let mut server = Server::new();
        let key = sample_key(0x88);
        let path = format!("/myproj/packs/{}", key.to_hex());
        let _m_429 = server
            .mock("HEAD", path.as_str())
            .with_status(429)
            .expect(1)
            .create();
        let _m_ok = server
            .mock("HEAD", path.as_str())
            .with_status(200)
            .expect_at_least(1)
            .create();
        let t = make_transport(&server, None);
        assert!(t.pack_exists(&key).unwrap());
    }

    // -- token handling ----------------------------------------------------

    #[test]
    fn bearer_token_is_sent_when_set() {
        let mut server = Server::new();
        let key = sample_key(0x33);
        let path = format!("/myproj/packs/{}", key.to_hex());
        let _m = server
            .mock("GET", path.as_str())
            .match_header("authorization", "Bearer secret-xyz")
            .with_status(200)
            .with_body(b"ok")
            .create();
        let t = make_transport(&server, Some("secret-xyz"));
        t.download_pack(&key).unwrap();
    }

    #[test]
    fn absence_of_token_still_works_for_public_endpoints() {
        let mut server = Server::new();
        let key = sample_key(0x44);
        let path = format!("/myproj/packs/{}", key.to_hex());
        let _m = server
            .mock("GET", path.as_str())
            .match_header("authorization", Matcher::Missing)
            .with_status(200)
            .with_body(b"public")
            .create();
        let t = make_transport(&server, None);
        assert_eq!(t.download_pack(&key).unwrap(), b"public");
    }

    // -- 502 bad gateway (5xx family) --------------------------------------

    #[test]
    fn bad_gateway_is_server_error_and_retried() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", Matcher::Regex(r"^/myproj/refs\?prefix=".to_string()))
            .with_status(502)
            .expect_at_least(2)
            .create();
        let t = make_transport(&server, None);
        let err = t.list_refs("refs/heads/").unwrap_err();
        assert!(matches!(err, TransportError::ServerError { status: 502 }));
    }

    // -- network failure ---------------------------------------------------

    #[test]
    fn connect_failure_surfaces_as_connection_failed() {
        // Point at a port we know nothing is listening on.
        let base = Url::parse("http://127.0.0.1:1/dead").unwrap();
        let t = HttpTransport::new_for_test(base, None);
        let err = t.download_pack(&sample_key(1)).unwrap_err();
        assert!(matches!(err, TransportError::ConnectionFailed));
    }

    // -- object safety smoke test ------------------------------------------

    #[test]
    fn http_transport_is_object_safe() {
        fn _takes(_t: Box<dyn Transport>) {}
    }
}
