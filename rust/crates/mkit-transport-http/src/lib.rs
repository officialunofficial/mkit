//! mkit HTTP/HTTPS transport.
//!
//! Speaks a simple JSON REST dialect against a mkit VCS Worker (e.g.
//! Cloudflare Worker + R2). User-facing URL shape:
//! `mkit+https://<host>/<project>`. The `mkit+` prefix is stripped
//! before the inner reqwest call.
//!
//! Wire contract (SPEC-TRANSPORT §5.1):
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
use std::io::Read;
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
use std::net::{Ipv4Addr, Ipv6Addr};
use url::{Host, Url};

/// Environment variable consulted at [`HttpTransport::connect`] time for
/// an optional Bearer token.
pub const TOKEN_ENV: &str = "MKIT_API_TOKEN";

/// Default per-request timeout. Chosen to be generous enough for a 100 MB
/// pack upload over a slow link but tight enough that a hung peer can't
/// wedge a client indefinitely.
///
/// `from_secs(300)` is deliberate — `from_mins(5)` loses the direct
/// mapping to the seconds-based SPEC-TRANSPORT §7 ladder.
#[allow(clippy::duration_suboptimal_units)]
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

// Pack-body limit lives canonically in mkit-core; re-exported so
// existing `http::PACK_BODY_LIMIT` / `http::PACK_BODY_LIMIT_USIZE`
// call sites keep working.
pub use mkit_core::protocol::{PACK_BODY_LIMIT, PACK_BODY_LIMIT_USIZE};

/// HTTP request header advertising client willingness to receive a
/// pack as `N+K` Reed-Solomon shards. Value is `"<N>+<K>"`. Per
/// SPEC-PACK-SHARDS §5, sent by the client on `download_pack` when the
/// `pack-shards` feature is enabled.
pub const ACCEPT_PACK_SHARDS_HEADER: &str = "accept-pack-shards";

/// HTTP response header set by the server to acknowledge that the
/// pack is being served as shards. Value is `"<N>+<K>"` matching the
/// manifest's `config`. When this header is present the response body
/// is informational only — the client fetches the manifest and shards
/// from the predictable sub-paths instead.
pub const X_PACK_SHARDS_HEADER: &str = "x-pack-shards";

/// Validate that `url` uses either `https://` (always allowed) or plain
/// `http://` pointing at a loopback host (`127.0.0.1`, `::1`, or
/// `localhost`). Any other combination is refused with
/// [`TransportError::InsecureScheme`].
///
/// # Errors
/// - [`TransportError::InsecureScheme`] if `url.scheme()` is `http` and
///   the host is not a recognised loopback literal.
/// - [`TransportError::InvalidResponse`] if the scheme is neither
///   `http` nor `https`.
pub fn validate_http_scheme(url: &Url) -> TransportResult<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            // Accept `127.0.0.1`, `::1`, and `localhost` (case-insensitive)
            // and nothing else. We match on the parsed `Host` to avoid
            // spelling-dependent checks on `host_str()` (which returns
            // `[::1]` for bracketed IPv6 literals on some url versions).
            let ok = match url.host() {
                Some(Host::Ipv4(ip)) => ip == Ipv4Addr::LOCALHOST,
                Some(Host::Ipv6(ip)) => ip == Ipv6Addr::LOCALHOST,
                Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
                None => false,
            };
            if ok {
                Ok(())
            } else {
                Err(TransportError::InsecureScheme)
            }
        }
        _ => Err(TransportError::InvalidResponse),
    }
}

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
        validate_http_scheme(&base)?;

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

    /// URL for the shard manifest of a pack:
    /// `<base>/packs/<lower-hex(pack_hash)>/shards.manifest`.
    #[cfg(feature = "pack-shards")]
    fn manifest_url(&self, key: &PackKey) -> TransportResult<Url> {
        let mut u = self.base.clone();
        u.path_segments_mut()
            .map_err(|()| TransportError::InvalidResponse)?
            .pop_if_empty()
            .push("packs")
            .push(&key.to_hex())
            .push("shards.manifest");
        Ok(u)
    }

    /// URL for one shard of a pack:
    /// `<base>/packs/<lower-hex(pack_hash)>/shards/<index>`.
    #[cfg(feature = "pack-shards")]
    fn shard_url(&self, key: &PackKey, index: u16) -> TransportResult<Url> {
        let mut u = self.base.clone();
        u.path_segments_mut()
            .map_err(|()| TransportError::InvalidResponse)?
            .pop_if_empty()
            .push("packs")
            .push(&key.to_hex())
            .push("shards")
            .push(&index.to_string());
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
        // Always set `prefix=`, even when empty, so the Worker can
        // distinguish "list all refs" from a missing query parameter.
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

    /// Stream a reqwest blocking response body into a `Vec<u8>` with a
    /// running cap at [`PACK_BODY_LIMIT_USIZE`]. Shared by the
    /// monolithic-pack and shard-body paths.
    fn read_body_capped(resp: Response) -> TransportResult<Vec<u8>> {
        let mut reader = resp;
        let cap = PACK_BODY_LIMIT_USIZE;
        let mut buf = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            let n = reader
                .read(&mut chunk)
                .map_err(|_| TransportError::ConnectionFailed)?;
            if n == 0 {
                break;
            }
            if buf.len().saturating_add(n) > cap {
                return Err(TransportError::PayloadTooLarge(buf.len() + n));
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        Ok(buf)
    }

    /// Issue a pack GET that explicitly does *not* advertise
    /// `Accept-Pack-Shards`, so the server is forced to reply
    /// monolithically. Used as a fallback when the shard flow fails
    /// mid-handshake.
    #[cfg(feature = "pack-shards")]
    fn download_pack_monolithic(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        let url = self.pack_url(key)?;
        let resp = Self::retrying(|| self.apply_auth(self.client.get(url.clone())))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_status(status, TransportError::PackNotFound));
        }
        if let Some(len) = resp.content_length()
            && len > PACK_BODY_LIMIT
        {
            return Err(TransportError::PayloadTooLarge(
                usize::try_from(len).unwrap_or(usize::MAX),
            ));
        }
        Self::read_body_capped(resp)
    }

    /// Drive `build_req` through the standard 5-attempt backoff ladder.
    /// The closure is re-invoked on every attempt so each try constructs
    /// a fresh request (reqwest consumes the builder on `.send()`).
    ///
    /// Real sleeps are capped at [`TEST_MAX_SLEEP`] so unit tests don't
    /// burn a full 31-second backoff ladder; the spec's exponential
    /// ladder still governs how many retries happen, which is what
    /// SPEC-TRANSPORT §7 actually mandates.
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
        let resp = Self::retrying(|| {
            #[allow(unused_mut)]
            let mut r = self.apply_auth(self.client.get(url.clone()));
            // Opportunistically advertise willingness to accept the
            // pack as N+K shards. Servers that don't speak the shard
            // dialect ignore the header and return the pack as-is;
            // shard-aware servers may respond with `X-Pack-Shards`
            // and we'll switch to the parallel-fetch path below.
            #[cfg(feature = "pack-shards")]
            {
                let advert = pack_shards::accept_pack_shards_advertise();
                r = r.header(ACCEPT_PACK_SHARDS_HEADER, advert);
            }
            r
        })?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_status(status, TransportError::PackNotFound));
        }

        // Shard path: server advertises `X-Pack-Shards`. We discard
        // the monolithic body (if any) and fetch the manifest +
        // shards in parallel. Fall through to the body path on any
        // shard-flow error so a flaky shard server doesn't break
        // downloads outright — the monolithic body is the fallback.
        #[cfg(feature = "pack-shards")]
        if let Some(advert) = resp.headers().get(X_PACK_SHARDS_HEADER).cloned() {
            // Drain the body before issuing more requests so connection
            // reuse stays sane.
            drop(resp);
            if let Ok(spec) = advert.to_str()
                && let Ok((_n, _k)) = pack_shards::parse_n_plus_k(spec)
            {
                return self.download_pack_via_shards(key);
            }
            // Malformed `X-Pack-Shards` header — server bug. Re-issue
            // the request without the Accept-Pack-Shards header so we
            // get a clean monolithic response.
            return self.download_pack_monolithic(key);
        }

        // Pre-check: if the server advertises a Content-Length greater
        // than our cap, refuse immediately without buffering any body.
        // A missing Content-Length falls through to the streaming
        // counter below.
        if let Some(len) = resp.content_length()
            && len > PACK_BODY_LIMIT
        {
            return Err(TransportError::PayloadTooLarge(
                usize::try_from(len).unwrap_or(usize::MAX),
            ));
        }

        Self::read_body_capped(resp)
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
// Sparse-checkout fetch (issue #158, Phase 2). Feature-gated behind
// `sparse-checkout` so the binary cost of the upstream
// `commonware-storage` chain is only paid when the consumer opts in.
//
// Wire contract additions (SPEC-TRANSPORT §5.6):
//
// - `POST /<project>/trees/<tree-hash-hex>/sparse?sparse=<filter-hash-hex>`
//   * Request body: JSON `{ "filter": ["<utf8 path>", ...] }`.
//     The `?sparse=<filter-hash>` query MUST equal
//     `BLAKE3` of the canonicalised filter (see SPEC-SPARSE-CHECKOUT §2.3).
//     The server uses the query to short-circuit a precomputed manifest
//     cache; the body filter is canonical input for cache misses.
//   * Response body: opaque `application/x-mkit-sparse` bytes —
//     [`mkit_core::sparse::decode_sparse_response`] decodes it into a
//     `SparseResponse`. The verifier holds the trust boundary; this
//     transport layer only enforces transport-level size caps.
//   * 404 → tree not found on server; surfaces as `PackNotFound`
//     (no dedicated `TreeNotFound` variant — the existing taxonomy
//     covers "the addressed object is missing").
//   * 409 → server-side disagreement about the filter hash. Maps to
//     `RefConflict` so retry policy treats it as terminal.
// ---------------------------------------------------------------------------

#[cfg(feature = "sparse-checkout")]
mod sparse_fetch {
    use super::{
        Hash, HttpTransport, RequestBuilder, TransportError, TransportResult, map_status, to_hex,
    };
    use mkit_core::sparse::{
        SPARSE_WIRE_MAX_BYTES, SparseResponse, decode_sparse_response, hash_filter,
    };
    use serde::Serialize;
    use std::path::PathBuf;
    use url::Url;

    #[derive(Debug, Serialize)]
    struct SparseRequestBody<'a> {
        filter: Vec<&'a str>,
    }

    impl HttpTransport {
        fn sparse_tree_url(&self, tree_hash: &Hash, filter_hash: &Hash) -> TransportResult<Url> {
            let mut u = self.base().clone();
            u.path_segments_mut()
                .map_err(|()| TransportError::InvalidResponse)?
                .pop_if_empty()
                .push("trees")
                .push(&to_hex(tree_hash))
                .push("sparse");
            u.query_pairs_mut()
                .clear()
                .append_pair("sparse", &to_hex(filter_hash));
            Ok(u)
        }

        pub fn fetch_sparse_tree(
            &self,
            tree_hash: &Hash,
            filter: &[PathBuf],
        ) -> TransportResult<SparseResponse> {
            let filter_hash = hash_filter(filter);
            let url = self.sparse_tree_url(tree_hash, &filter_hash)?;
            let filter_strs: Vec<&str> = filter.iter().filter_map(|p| p.to_str()).collect();
            let body = SparseRequestBody {
                filter: filter_strs,
            };
            let body_json =
                serde_json::to_vec(&body).map_err(|_| TransportError::InvalidResponse)?;

            let resp = HttpTransport::retrying(|| -> RequestBuilder {
                let mut r = self
                    .client()
                    .post(url.clone())
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/x-mkit-sparse")
                    .body(body_json.clone());
                r = self.apply_auth_pub(r);
                r
            })?;

            let status = resp.status();
            if !status.is_success() {
                return Err(map_status(status, TransportError::PackNotFound));
            }
            if let Some(len) = resp.content_length()
                && len > SPARSE_WIRE_MAX_BYTES as u64
            {
                return Err(TransportError::PayloadTooLarge(
                    usize::try_from(len).unwrap_or(usize::MAX),
                ));
            }
            let body_bytes = resp.bytes().map_err(|_| TransportError::ConnectionFailed)?;
            if body_bytes.len() > SPARSE_WIRE_MAX_BYTES {
                return Err(TransportError::PayloadTooLarge(body_bytes.len()));
            }
            decode_sparse_response(&body_bytes).map_err(|_| TransportError::InvalidResponse)
        }
    }
}

// ---------------------------------------------------------------------------
// Pack-Shards client (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "pack-shards")]
mod pack_shards {
    //! Client-side support for SPEC-PACK-SHARDS §5.

    use mkit_core::pack_shard::default_config;

    pub(crate) fn accept_pack_shards_advertise() -> String {
        let c = default_config();
        format!("{}+{}", c.minimum_shards.get(), c.extra_shards.get())
    }

    pub(crate) fn parse_n_plus_k(s: &str) -> Result<(u16, u16), ()> {
        let (n, k) = s.split_once('+').ok_or(())?;
        let n: u16 = n.trim().parse().map_err(|_| ())?;
        let k: u16 = k.trim().parse().map_err(|_| ())?;
        if n == 0 || k == 0 {
            return Err(());
        }
        Ok((n, k))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_advert_round_trip() {
            assert_eq!(parse_n_plus_k("16+4"), Ok((16, 4)));
            assert_eq!(parse_n_plus_k(" 16 + 4 "), Ok((16, 4)));
        }

        #[test]
        fn parse_advert_rejects_bad() {
            assert!(parse_n_plus_k("0+4").is_err());
            assert!(parse_n_plus_k("16+0").is_err());
            assert!(parse_n_plus_k("16-4").is_err());
            assert!(parse_n_plus_k("abc").is_err());
        }

        #[test]
        fn advertise_matches_default_config() {
            let v = accept_pack_shards_advertise();
            assert_eq!(v, "16+4");
        }
    }
}

// Helper accessors used by the sparse-fetch module. Crate-private —
// other consumers should keep going through the trait surface.
#[cfg(feature = "sparse-checkout")]
impl HttpTransport {
    fn client(&self) -> &Client {
        &self.client
    }
    fn apply_auth_pub(&self, req: RequestBuilder) -> RequestBuilder {
        self.apply_auth(req)
    }
}

#[cfg(feature = "pack-shards")]
impl HttpTransport {
    /// Shard-mode download: fetch the manifest, then fetch shards in
    /// parallel via std threads. Returns the reconstructed pack.
    fn download_pack_via_shards(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        use mkit_core::pack_shard::{
            MANIFEST_MAX_BYTES, Shard, decode_manifest, decode_pack_from_shards,
        };
        use std::sync::mpsc;

        let manifest_url = self.manifest_url(key)?;
        let resp = Self::retrying(|| self.apply_auth(self.client.get(manifest_url.clone())))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_status(status, TransportError::PackNotFound));
        }
        if let Some(len) = resp.content_length()
            && len > MANIFEST_MAX_BYTES as u64
        {
            return Err(TransportError::PayloadTooLarge(
                usize::try_from(len).unwrap_or(usize::MAX),
            ));
        }
        let body = Self::read_body_capped(resp)?;
        if body.len() > MANIFEST_MAX_BYTES {
            return Err(TransportError::PayloadTooLarge(body.len()));
        }
        let manifest = decode_manifest(&body).map_err(|_| TransportError::InvalidResponse)?;

        let total = manifest.config.total_shards();
        let minimum = manifest.config.minimum_shards.get();

        // Anti-DoS: cap the parallel fan-out at the v0 ceiling.
        if total > 256 {
            return Err(TransportError::InvalidResponse);
        }

        let (tx, rx) = mpsc::channel::<(u16, TransportResult<Vec<u8>>)>();
        let mut handles = Vec::with_capacity(total as usize);
        let total_u16: u16 = u16::try_from(total).unwrap_or(u16::MAX);
        for i in 0..total_u16 {
            let tx = tx.clone();
            let url = self.shard_url(key, i)?;
            let client = self.client.clone();
            let token = self.token.clone();
            handles.push(std::thread::spawn(move || {
                let mut req = client.get(url);
                if let Some(t) = &token
                    && let Ok(v) = HeaderValue::from_str(&format!("Bearer {t}"))
                {
                    req = req.header(AUTHORIZATION, v);
                }
                let result: TransportResult<Vec<u8>> = match req.send() {
                    Ok(resp) => {
                        let status = resp.status();
                        if status.is_success() {
                            HttpTransport::read_body_capped(resp)
                        } else {
                            Err(map_status(status, TransportError::PackNotFound))
                        }
                    }
                    Err(_) => Err(TransportError::ConnectionFailed),
                };
                let _ = tx.send((i, result));
            }));
        }
        drop(tx);

        let mut shards: Vec<Shard> = Vec::with_capacity(minimum as usize);
        let mut failures: u16 = 0;
        let max_failures = manifest.config.extra_shards.get();
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

        for h in handles {
            let _ = h.join();
        }

        if shards.len() < minimum as usize {
            return Err(TransportError::PackNotFound);
        }

        decode_pack_from_shards(&shards, &manifest).map_err(|_| TransportError::InvalidResponse)
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

    // ----------------------------------------------------------------------
    // E9: http:// restricted to loopback, download_pack body cap
    // ----------------------------------------------------------------------

    #[test]
    fn connect_rejects_http_non_loopback_as_insecure() {
        unsafe { env::remove_var(TOKEN_ENV) };
        let err = HttpTransport::connect("mkit+http://example.com/proj")
            .expect_err("non-loopback http must be refused");
        assert!(
            matches!(err, TransportError::InsecureScheme),
            "expected InsecureScheme, got {err:?}"
        );
    }

    #[test]
    fn connect_accepts_http_on_loopback_ipv4() {
        unsafe { env::remove_var(TOKEN_ENV) };
        let t = HttpTransport::connect("mkit+http://127.0.0.1:1234/p").unwrap();
        assert_eq!(t.base().scheme(), "http");
        assert_eq!(t.base().host_str(), Some("127.0.0.1"));
    }

    #[test]
    fn connect_accepts_http_on_loopback_ipv6() {
        unsafe { env::remove_var(TOKEN_ENV) };
        let t = HttpTransport::connect("mkit+http://[::1]:1234/p").unwrap();
        assert_eq!(t.base().scheme(), "http");
    }

    #[test]
    fn connect_accepts_http_on_localhost_name() {
        unsafe { env::remove_var(TOKEN_ENV) };
        let t = HttpTransport::connect("mkit+http://localhost:8787/p").unwrap();
        assert_eq!(t.base().scheme(), "http");
    }

    #[test]
    fn validate_http_scheme_helper_behaves() {
        // Direct helper test: https is always OK, http only on loopback.
        let https = Url::parse("https://example.com/").unwrap();
        assert!(validate_http_scheme(&https).is_ok());

        let http_pub = Url::parse("http://example.com/").unwrap();
        assert!(matches!(
            validate_http_scheme(&http_pub),
            Err(TransportError::InsecureScheme)
        ));

        for ok in [
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://localhost/",
            "http://LOCALHOST/",
        ] {
            let u = Url::parse(ok).unwrap();
            assert!(validate_http_scheme(&u).is_ok(), "{ok} should be allowed");
        }
    }

    #[test]
    fn pack_body_limit_is_4_gib() {
        // Matches the s3 transport's existing cap, documenting that the
        // two transports agree on the same upper bound for a single
        // pack download.
        assert_eq!(PACK_BODY_LIMIT, 4 * 1024 * 1024 * 1024);
    }

    // ----------------------------------------------------------------------
    // Pack-Shards client (feature-gated) — wire tests via mockito.
    //
    // The server publishes:
    //   - GET /packs/<hex>            → 200 with `X-Pack-Shards: 16+4`
    //                                   header and empty body
    //   - GET /packs/<hex>/shards.manifest → 200 with encoded ShardSet
    //   - GET /packs/<hex>/shards/<i> → 200 with shard bytes
    //
    // and the client reconstructs the original pack.
    // ----------------------------------------------------------------------

    #[cfg(feature = "pack-shards")]
    mod shard_tests {
        use super::*;
        use mkit_core::pack_shard::{default_config, encode_manifest, encode_pack_to_shards};

        /// Deterministic synthetic pack large enough for the shard
        /// encoder to accept (the commonware backend wants > a few
        /// hundred bytes for the default `(16, 4)` config to be
        /// useful).
        fn synthetic_pack(bytes: usize) -> Vec<u8> {
            let mut x: u64 = 0xC0DE_BEEF_F00D_BABE;
            let mut out = Vec::with_capacity(bytes);
            while out.len() < bytes {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                out.extend_from_slice(&x.to_le_bytes());
            }
            out.truncate(bytes);
            out
        }

        fn key_for(pack: &[u8]) -> PackKey {
            PackKey::new(mkit_core::hash::hash(pack))
        }

        /// Publish a sharded pack at the given mockito server. Returns
        /// the pack bytes, key, and a `Vec` of all mock handles (so
        /// the caller drops them at the end of the test).
        fn publish_sharded(
            server: &mut mockito::Server,
            pack_size: usize,
            drop_indices: &[u16],
        ) -> (Vec<u8>, PackKey, Vec<mockito::Mock>) {
            let pack = synthetic_pack(pack_size);
            let key = key_for(&pack);
            let (shards, manifest) = encode_pack_to_shards(&pack, default_config()).unwrap();
            let manifest_bytes = encode_manifest(&manifest).unwrap();

            let mut mocks = Vec::new();
            // Pack URL — 200 with X-Pack-Shards header to signal shard mode.
            let pack_path = format!("/myproj/packs/{}", key.to_hex());
            mocks.push(
                server
                    .mock("GET", pack_path.as_str())
                    .with_status(200)
                    .with_header(X_PACK_SHARDS_HEADER, "16+4")
                    .with_body("")
                    .expect_at_least(1)
                    .create(),
            );
            // Manifest.
            let manifest_path = format!("/myproj/packs/{}/shards.manifest", key.to_hex());
            mocks.push(
                server
                    .mock("GET", manifest_path.as_str())
                    .with_status(200)
                    .with_body(manifest_bytes)
                    .create(),
            );
            // Shards — drop the requested indices (404).
            for shard in &shards {
                let path = format!("/myproj/packs/{}/shards/{}", key.to_hex(), shard.index);
                if drop_indices.contains(&shard.index) {
                    mocks.push(server.mock("GET", path.as_str()).with_status(404).create());
                } else {
                    mocks.push(
                        server
                            .mock("GET", path.as_str())
                            .with_status(200)
                            .with_body(shard.bytes.clone())
                            .create(),
                    );
                }
            }
            (pack, key, mocks)
        }

        #[test]
        fn shard_download_reconstructs_pack_with_all_shards_available() {
            let mut server = mockito::Server::new();
            let (pack, key, _mocks) = publish_sharded(&mut server, 64 * 1024, &[]);
            let t = make_transport(&server, None);
            let got = t.download_pack(&key).unwrap();
            assert_eq!(got, pack);
        }

        #[test]
        fn shard_download_reconstructs_pack_when_k_shards_404() {
            // Drop the 4 extra shards — exactly `minimum_shards` remain.
            let mut server = mockito::Server::new();
            let dropped = [16u16, 17, 18, 19];
            let (pack, key, _mocks) = publish_sharded(&mut server, 64 * 1024, &dropped);
            let t = make_transport(&server, None);
            let got = t.download_pack(&key).unwrap();
            assert_eq!(got, pack);
        }

        #[test]
        fn shard_download_fails_when_more_than_k_shards_404() {
            // Drop 5 shards (one more than K). Reconstruction MUST fail.
            let mut server = mockito::Server::new();
            let dropped = [0u16, 1, 2, 3, 4];
            let (_pack, key, _mocks) = publish_sharded(&mut server, 64 * 1024, &dropped);
            let t = make_transport(&server, None);
            let err = t.download_pack(&key).unwrap_err();
            assert!(
                matches!(err, TransportError::PackNotFound),
                "expected PackNotFound, got {err:?}"
            );
        }

        #[test]
        fn monolithic_fallback_when_server_omits_x_pack_shards() {
            // Server doesn't speak Pack-Shards — the response body IS
            // the pack and the client must accept it.
            let mut server = mockito::Server::new();
            let body = b"mono-pack-bytes".to_vec();
            let key = PackKey::new([0xAA; HASH_LEN]);
            let path = format!("/myproj/packs/{}", key.to_hex());
            let _m = server
                .mock("GET", path.as_str())
                .with_status(200)
                .with_body(body.clone())
                .create();
            let t = make_transport(&server, None);
            assert_eq!(t.download_pack(&key).unwrap(), body);
        }

        #[test]
        fn shard_advertise_value_is_default_config() {
            assert_eq!(pack_shards::accept_pack_shards_advertise(), "16+4");
        }
    }

    /// Regression: a normal-sized body that arrives with an accurate
    /// content-length smaller than `PACK_BODY_LIMIT` must still return
    /// the full bytes. This exercises the streaming copy path.
    #[test]
    fn download_pack_under_limit_still_returns_body() {
        let mut server = Server::new();
        let key = sample_key(0x78);
        let path = format!("/myproj/packs/{}", key.to_hex());
        let body: Vec<u8> = (0..4096u32).map(|i| (i & 0xFF) as u8).collect();
        let _m = server
            .mock("GET", path.as_str())
            .with_status(200)
            .with_body(body.clone())
            .create();
        let t = make_transport(&server, None);
        assert_eq!(t.download_pack(&key).unwrap(), body);
    }
}
