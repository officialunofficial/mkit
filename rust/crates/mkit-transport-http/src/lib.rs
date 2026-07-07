#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
#![doc = include_str!("../README.md")]
//!
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

use mkit_core::hash::{Hash, from_hex};
use mkit_core::protocol::{
    AdvanceOutcome, BackoffIterator, PackKey, RefWriteCondition, Transport, TransportError,
    TransportResult, is_retryable,
};
use mkit_core::refs::Ref;
use reqwest::StatusCode;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde::Deserialize;
use std::net::{Ipv4Addr, Ipv6Addr};
use url::{Host, Url};

mod ref_ops;

// `cas_headers` lives in `ref_ops` (mkit #423 review) — its only
// non-test caller is `update_ref_impl` there, alongside its sibling
// `cond_to_json`. Re-exported here so the crate's public API surface
// (`mkit_transport_http::cas_headers`) is unchanged.
pub use ref_ops::cas_headers;

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

/// Per-request timeout for a single shard GET.
///
/// Shards are small (a pack is split into `N+K` Reed-Solomon pieces),
/// so a generous-but-bounded timeout keeps a stalled straggler from
/// pinning a detached worker thread forever. Once `minimum_shards` have
/// arrived the collection loop stops waiting and drops the remaining
/// handles; this timeout guarantees those detached workers terminate on
/// their own instead of leaking for the process lifetime.
#[cfg(feature = "pack-shards")]
const SHARD_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

// Pack-body limit lives canonically in mkit-core; re-exported so
// existing `http::PACK_BODY_LIMIT` / `http::PACK_BODY_LIMIT_USIZE`
// call sites keep working.
pub use mkit_core::protocol::{PACK_BODY_LIMIT, PACK_BODY_LIMIT_USIZE};

/// Cap for a single control-plane ref/upload JSON body (`read_ref`,
/// `upload_pack` response). These responses are tiny — a 64-hex hash
/// plus minimal JSON framing — so a few KiB is generous. Mirrors the S3
/// transport's `REF_BODY_LIMIT` intent; an attacker-controlled or
/// MITM'd endpoint must not be able to OOM us with a multi-GB body.
const CONTROL_BODY_LIMIT: usize = 4 * 1024;

/// Cap for a `list_refs` JSON body. Larger than a single ref but still
/// bounded so a hostile remote can't return an unbounded list. Mirrors
/// the S3 transport's `REF_LIST_BODY_LIMIT` (16 MiB).
const REF_LIST_BODY_LIMIT: usize = 16 * 1024 * 1024;

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

/// Maximum number of HTTP redirects we follow before giving up.
const MAX_REDIRECTS: usize = 5;

/// Explicit reqwest redirect policy (#223): follow up to
/// [`MAX_REDIRECTS`] hops, but REFUSE any redirect that downgrades the
/// scheme (`https` → `http`). A downgrade would silently move
/// authenticated traffic (the `MKIT_API_TOKEN` bearer) onto a plaintext
/// channel, so we stop with an error rather than relying on reqwest's
/// permissive defaults.
fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        // Refuse https -> http downgrade. (http -> https upgrade and
        // same-scheme redirects are allowed.)
        if let Some(prev) = attempt.previous().last()
            && prev.scheme() == "https"
            && attempt.url().scheme() != "https"
        {
            return attempt.error("refusing redirect that downgrades https to a weaker scheme");
        }
        attempt.follow()
    })
}

/// Blocking HTTP transport for the mkit VCS Worker dialect.
///
/// Construction: [`HttpTransport::connect`] parses a `mkit+https://` (or
/// `mkit+http://` for local testing) URL, strips the `mkit+` prefix, and
/// reads `MKIT_API_TOKEN` from the environment.
pub struct HttpTransport {
    /// Base URL (scheme + host + port + `/<project>`). No trailing slash.
    base: Url,
    /// Shared blocking reqwest client. Wrapped in `Arc` internally by
    /// reqwest so `Clone` here would be cheap — but we don't expose it.
    client: Client,
    /// Bearer token, if `MKIT_API_TOKEN` was set at connect time.
    token: Option<String>,
    /// Retry-delay ladder factory. Production uses the spec ladder;
    /// tests inject a shorter ladder so retry assertions stay fast.
    backoff: fn() -> BackoffIterator,
    /// Sleep hook between retry attempts. Production sleeps for the
    /// full delay; tests inject a no-op or recorder.
    sleep: fn(Duration),
}

// Manual redacting `Debug` (mirrors `S3Transport`): the `token` field is
// the `MKIT_API_TOKEN` bearer secret and MUST NOT leak through `{:?}` /
// `dbg!` / `tracing` of this struct or any struct embedding it. We only
// reveal *whether* a token is present, never its value.
impl std::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransport")
            .field("base", &self.base)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
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
            .redirect(redirect_policy())
            .build()
            .map_err(|_| TransportError::ConnectionFailed)?;

        let token = env::var(TOKEN_ENV).ok().filter(|s| !s.is_empty());

        Ok(Self {
            base,
            client,
            token,
            backoff: BackoffIterator::new,
            sleep: thread::sleep,
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
            .redirect(redirect_policy())
            .build()
            .expect("default reqwest client");
        Self {
            base,
            client,
            token,
            backoff: test_backoff,
            sleep: no_sleep,
        }
    }

    /// Test-only constructor with explicit retry hooks.
    #[cfg(test)]
    #[must_use]
    fn new_for_test_with_retry(
        base: Url,
        token: Option<String>,
        backoff: fn() -> BackoffIterator,
        sleep: fn(Duration),
    ) -> Self {
        let mut transport = Self::new_for_test(base, token);
        transport.backoff = backoff;
        transport.sleep = sleep;
        transport
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
        Self::read_body_capped_to(resp, PACK_BODY_LIMIT_USIZE)
    }

    /// Stream a reqwest blocking response body into a `Vec<u8>` with a
    /// running cap of `cap` bytes. The cap is enforced as the body is
    /// read (never trusting `Content-Length`), so a hostile remote that
    /// omits or lies about the header still can't OOM us — we stop and
    /// return [`TransportError::PayloadTooLarge`] the moment the cap is
    /// crossed.
    fn read_body_capped_to(resp: Response, cap: usize) -> TransportResult<Vec<u8>> {
        let mut reader = resp;
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

    /// Read a small control-plane JSON response under `cap` (never trusting
    /// `Content-Length`) and deserialize it. The single bounded path every
    /// ref read/write goes through, so no control body is ever parsed
    /// unbounded.
    fn parse_json_body<T: serde::de::DeserializeOwned>(
        resp: Response,
        cap: usize,
    ) -> TransportResult<T> {
        let body = Self::read_body_capped_to(resp, cap)?;
        serde_json::from_slice(&body).map_err(|_| TransportError::InvalidResponse)
    }

    /// Issue a pack GET that explicitly does *not* advertise
    /// `Accept-Pack-Shards`, so the server is forced to reply
    /// monolithically. Used as a fallback when the shard flow fails
    /// mid-handshake.
    #[cfg(feature = "pack-shards")]
    fn download_pack_monolithic(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        let url = self.pack_url(key)?;
        let resp = self.retrying(|| self.apply_auth(self.client.get(url.clone())))?;
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
    /// Production sleeps for the full spec delay. Tests use
    /// [`HttpTransport::new_for_test`] or `new_for_test_with_retry` to
    /// inject short/no-op sleeps without changing shipped behavior.
    fn retrying<F>(&self, mut build_req: F) -> TransportResult<Response>
    where
        F: FnMut() -> RequestBuilder,
    {
        let mut backoff = (self.backoff)();
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
                (self.sleep)(delay);
                continue;
            }
            return Err(err);
        }
    }
}

fn test_backoff() -> BackoffIterator {
    BackoffIterator::with(Duration::from_millis(1), Duration::from_millis(1), 5)
}

fn no_sleep(_delay: Duration) {}

// ---------------------------------------------------------------------------
// JSON request / response DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct PackUploadResponse {
    key: String,
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
        s => TransportError::ServerError { status: s },
    }
}

// ---------------------------------------------------------------------------
// Transport impl
// ---------------------------------------------------------------------------

impl Transport for HttpTransport {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        let url = self.packs_collection_url()?;
        let body = bytes.to_vec();
        let resp = self.retrying(|| {
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
        // swap the pack under us. Routed through `parse_json_body` (the
        // same single bounded path every ref read/write uses) so a
        // hostile/compromised remote can't OOM us with an unbounded
        // response body.
        let parsed: PackUploadResponse = Self::parse_json_body(resp, CONTROL_BODY_LIMIT)?;
        let server_key = from_hex(&parsed.key).map_err(|_| TransportError::InvalidResponse)?;
        if server_key != *key.as_bytes() {
            return Err(TransportError::InvalidResponse);
        }
        Ok(())
    }

    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        let url = self.pack_url(key)?;
        let resp = self.retrying(|| {
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
        // shards in parallel. On any shard-flow error we propagate
        // it — we deliberately do NOT silently fall back to the
        // monolithic body. The server advertised `X-Pack-Shards`,
        // we trust that signal, and a failure in the shard path is
        // a server-side bug (or attacker-controlled tampering) we
        // surface rather than silently downgrade. The only fall-
        // through is when `X-Pack-Shards` is itself malformed, which
        // we treat as "no advertisement" and re-issue cleanly.
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
        let resp = self.retrying(|| self.apply_auth(self.client.head(url.clone())))?;
        let status = resp.status();
        match status.as_u16() {
            200..=299 => Ok(true),
            404 => Ok(false),
            401 | 403 => Err(TransportError::AccessDenied),
            s => Err(TransportError::ServerError { status: s }),
        }
    }

    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        self.update_ref_impl(name, condition, hash)
    }

    /// See the `ref_ops` module (mkit #423) for the shared ref-endpoint
    /// invariants this delegates to.
    fn advance_refs(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
    ) -> TransportResult<AdvanceOutcome> {
        self.advance_refs_impl(
            head_ref,
            head_condition,
            head_value,
            packmap_ref,
            packmap_condition,
            packmap_value,
        )
    }

    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        self.read_ref_impl(name)
    }

    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        self.list_refs_impl(prefix)
    }

    /// The `/refs/advance` endpoint (mkit #408, see `advance_refs` above)
    /// commits the head + packmap write in one server-side transaction —
    /// but ONLY when both CAS conditions are expressible on it (i.e. neither
    /// is `Any` — see `cond_to_json`). This flag reports the transport's
    /// *capability*; it is NOT a per-call guarantee.
    ///
    /// # Per-call `Any` fallback caveat (mkit #521)
    ///
    /// `advance_refs_impl` degrades to the NON-atomic ordered two-PUT path
    /// (`advance_refs_ordered`: packmap PUT then head PUT) whenever EITHER
    /// condition is `Any`, because `Any` has no representation on the atomic
    /// endpoint. A force push (`PushLease::Force`) produces an `Any` head
    /// condition and therefore lands on the ordered path even though this
    /// method returns `true`.
    ///
    /// The ordered path is safe for an APPENDING packmap write (a crash /
    /// lost head PUT leaves the packmap a superset — still reconstructable),
    /// but NOT for a re-baseline RESET (`prev = None`, not a superset): a
    /// committed reset packmap plus a lost head PUT strands the head at the
    /// old divergent tip whose closure the reset can no longer rebuild. So a
    /// caller MUST NOT request a reset when the head condition is `Any` —
    /// `remote_dispatch::push_branch`'s re-baseline gate additionally
    /// requires the head condition to be CAS-conditioned (not `Any`) on top
    /// of this flag, precisely so force pushes take the safe append path.
    fn supports_atomic_advance(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Sparse-checkout fetch (issue #158). Feature-gated behind
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
    use super::{Hash, HttpTransport, RequestBuilder, TransportError, TransportResult, map_status};
    use mkit_core::hash::to_hex;
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

            let resp = self.retrying(|| -> RequestBuilder {
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
            // Cheap pre-check: if the server advertises an honest
            // oversized Content-Length, refuse before reading. But do
            // NOT trust the header — the running-cap reader below enforces
            // the bound even when the header is missing or lies.
            if let Some(len) = resp.content_length()
                && len > SPARSE_WIRE_MAX_BYTES as u64
            {
                return Err(TransportError::PayloadTooLarge(
                    usize::try_from(len).unwrap_or(usize::MAX),
                ));
            }
            let body_bytes = HttpTransport::read_body_capped_to_pub(resp, SPARSE_WIRE_MAX_BYTES)?;
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
    fn read_body_capped_to_pub(resp: Response, cap: usize) -> TransportResult<Vec<u8>> {
        Self::read_body_capped_to(resp, cap)
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
        let resp = self.retrying(|| self.apply_auth(self.client.get(manifest_url.clone())))?;
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
        let total_u16: u16 = u16::try_from(total).unwrap_or(u16::MAX);
        // Workers are intentionally *detached* (we never join them).
        // Once quorum or the failure threshold is reached the collection
        // loop below stops waiting; a slow straggler must not be able to
        // block the download by holding a join. The per-request
        // SHARD_REQUEST_TIMEOUT guarantees each detached worker
        // terminates on its own instead of leaking.
        let backoff = self.backoff;
        let sleep = self.sleep;
        for i in 0..total_u16 {
            let tx = tx.clone();
            let url = self.shard_url(key, i)?;
            let client = self.client.clone();
            let token = self.token.clone();
            std::thread::spawn(move || {
                let result =
                    fetch_shard_with_retry(&client, &url, token.as_deref(), backoff, sleep);
                let _ = tx.send((i, result));
            });
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
        // Deliberately do not join the spawned workers: stragglers are
        // dropped, not awaited. They are bounded by SHARD_REQUEST_TIMEOUT.

        if shards.len() < minimum as usize {
            return Err(TransportError::PackNotFound);
        }

        decode_pack_from_shards(&shards, &manifest).map_err(|_| TransportError::InvalidResponse)
    }
}

/// Fetch a single shard via an idempotent GET, retrying transient
/// failures through the supplied backoff ladder.
///
/// Retries ONLY on `ConnectionFailed` / 429 / 5xx (the same classes
/// `is_retryable` gates). Terminal classes — 401/403 (`AccessDenied`),
/// 404 (`PackNotFound`), and body-size caps (`PayloadTooLarge`) — return
/// immediately without retrying. Each attempt carries a bounded
/// per-request timeout so a stalled peer can never wedge the worker.
#[cfg(feature = "pack-shards")]
fn fetch_shard_with_retry(
    client: &Client,
    url: &Url,
    token: Option<&str>,
    backoff: fn() -> BackoffIterator,
    sleep: fn(Duration),
) -> TransportResult<Vec<u8>> {
    let mut ladder = backoff();
    loop {
        let mut req = client.get(url.clone()).timeout(SHARD_REQUEST_TIMEOUT);
        if let Some(t) = token
            && let Ok(v) = HeaderValue::from_str(&format!("Bearer {t}"))
        {
            req = req.header(AUTHORIZATION, v);
        }
        let err = match req.send() {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    // Body-decode / size-cap failures are terminal — never retried.
                    return HttpTransport::read_body_capped(resp);
                }
                map_status(status, TransportError::PackNotFound)
            }
            Err(_) => TransportError::ConnectionFailed,
        };
        if is_retryable(&err)
            && let Some(delay) = ladder.next()
        {
            sleep(delay);
            continue;
        }
        return Err(err);
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
    use reqwest::header::{IF_MATCH, IF_NONE_MATCH};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    static RECORDED_SLEEP_COUNT: AtomicUsize = AtomicUsize::new(0);
    static RECORDED_SLEEP_MILLIS: AtomicU64 = AtomicU64::new(0);

    /// Shared with `ref_ops::tests` — kept `pub(crate)` since the ref
    /// verbs' tests moved out of this module (mkit #423).
    pub(crate) fn sample_hash(byte: u8) -> Hash {
        [byte; HASH_LEN]
    }

    fn sample_key(byte: u8) -> PackKey {
        PackKey::new([byte; HASH_LEN])
    }

    /// Shared with `ref_ops::tests` — kept `pub(crate)` since the ref
    /// verbs' tests moved out of this module (mkit #423).
    pub(crate) fn make_transport(server: &Server, token: Option<&str>) -> HttpTransport {
        let base = Url::parse(&format!("{}/myproj", server.url())).unwrap();
        HttpTransport::new_for_test(base, token.map(String::from))
    }

    fn one_retry_backoff() -> BackoffIterator {
        BackoffIterator::with(Duration::from_millis(7), Duration::from_millis(7), 1)
    }

    fn record_sleep(delay: Duration) {
        RECORDED_SLEEP_COUNT.fetch_add(1, Ordering::SeqCst);
        RECORDED_SLEEP_MILLIS.store(
            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
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

    // Ref-protocol tests (advance_refs / read_ref / update_ref / list_refs)
    // moved to `ref_ops::tests` (mkit #423).

    #[test]
    fn upload_pack_oversized_response_is_payload_too_large() {
        let mut server = Server::new();
        let key = sample_key(0x55);
        let huge = vec![b'a'; CONTROL_BODY_LIMIT + 1];
        let _m = server
            .mock("POST", "/myproj/packs")
            .with_status(201)
            .with_body(huge)
            .create();
        let t = make_transport(&server, None);
        assert!(matches!(
            t.upload_pack(b"pack", &key),
            Err(TransportError::PayloadTooLarge(_))
        ));
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
    fn retry_uses_injected_backoff_and_sleeper() {
        RECORDED_SLEEP_COUNT.store(0, Ordering::SeqCst);
        RECORDED_SLEEP_MILLIS.store(0, Ordering::SeqCst);

        let mut server = Server::new();
        let key = sample_key(0x79);
        let path = format!("/myproj/packs/{}", key.to_hex());
        let _m_fail = server
            .mock("GET", path.as_str())
            .with_status(503)
            .expect(1)
            .create();
        let _m_ok = server
            .mock("GET", path.as_str())
            .with_status(200)
            .with_body(b"ok")
            .expect(1)
            .create();
        let base = Url::parse(&format!("{}/myproj", server.url())).unwrap();
        let t = HttpTransport::new_for_test_with_retry(base, None, one_retry_backoff, record_sleep);

        assert_eq!(t.download_pack(&key).unwrap(), b"ok");
        assert_eq!(RECORDED_SLEEP_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(RECORDED_SLEEP_MILLIS.load(Ordering::SeqCst), 7);
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

    #[test]
    fn debug_redacts_bearer_token() {
        let base = Url::parse("http://127.0.0.1:1/myproj").unwrap();
        let t = HttpTransport::new_for_test(base, Some("super-secret-token".into()));
        let dbg = format!("{t:?}");
        assert!(
            !dbg.contains("super-secret-token"),
            "Debug leaked bearer token: {dbg}"
        );
        assert!(dbg.contains("<redacted>"), "Debug missing redaction: {dbg}");
    }

    #[test]
    fn debug_shows_absent_token_as_none() {
        let base = Url::parse("http://127.0.0.1:1/myproj").unwrap();
        let t = HttpTransport::new_for_test(base, None);
        let dbg = format!("{t:?}");
        assert!(dbg.contains("None"), "Debug should show token: None: {dbg}");
        assert!(!dbg.contains("<redacted>"));
    }

    #[test]
    fn redirect_loop_is_bounded_not_followed_forever() {
        // A server that 301-redirects to itself must not cause an
        // unbounded redirect chase: the explicit redirect policy caps the
        // hop count, so the request fails (mapped to ConnectionFailed
        // after retries) instead of hanging. Asserts the policy is wired.
        let mut server = Server::new();
        let loc = format!("{}/myproj/refs/refs/heads/main", server.url());
        let _m = server
            .mock("GET", "/myproj/refs/refs/heads/main")
            .with_status(301)
            .with_header("location", loc.as_str())
            .create();
        let t = make_transport(&server, None);
        let err = t.read_ref("refs/heads/main").unwrap_err();
        // Either a connection-level error (redirect policy aborted the
        // send) or a non-success status mapped through; never a hang.
        assert!(
            matches!(
                err,
                TransportError::ConnectionFailed | TransportError::InvalidRef(_)
            ),
            "unexpected error for bounded redirect loop: {err:?}"
        );
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
        fn shard_download_propagates_undecodable_manifest_never_falls_back() {
            // Server advertises X-Pack-Shards, but the manifest body it
            // serves is garbage. SPEC-PACK-SHARDS §5: a present-but-
            // undecodable manifest MUST propagate as an error, never
            // silently downgrade to the monolithic body (which in this
            // test would otherwise be the distinguishable "real" pack).
            let mut server = mockito::Server::new();
            let pack = synthetic_pack(64 * 1024);
            let key = key_for(&pack);
            let pack_path = format!("/myproj/packs/{}", key.to_hex());
            let _pack_mock = server
                .mock("GET", pack_path.as_str())
                .with_status(200)
                .with_header(X_PACK_SHARDS_HEADER, "16+4")
                .with_body("")
                .create();
            let manifest_path = format!("/myproj/packs/{}/shards.manifest", key.to_hex());
            let _manifest_mock = server
                .mock("GET", manifest_path.as_str())
                .with_status(200)
                .with_body(b"not-a-manifest")
                .create();
            let t = make_transport(&server, None);
            let err = t.download_pack(&key).unwrap_err();
            assert!(
                matches!(err, TransportError::InvalidResponse),
                "expected InvalidResponse, got {err:?}"
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

        fn make_transport_with_retry(
            server: &mockito::Server,
            backoff: fn() -> BackoffIterator,
            sleep: fn(Duration),
        ) -> HttpTransport {
            let base = Url::parse(&format!("{}/myproj", server.url())).unwrap();
            HttpTransport::new_for_test_with_retry(base, None, backoff, sleep)
        }

        fn three_attempt_backoff() -> BackoffIterator {
            BackoffIterator::with(Duration::from_millis(1), Duration::from_millis(1), 3)
        }

        fn five_attempt_backoff() -> BackoffIterator {
            BackoffIterator::with(Duration::from_millis(1), Duration::from_millis(1), 5)
        }

        /// A shard that returns 503 twice then 200 is retried on the
        /// idempotent GET and ultimately succeeds. Asserts the mock saw
        /// all three attempts.
        #[test]
        fn shard_get_retries_on_5xx_then_succeeds() {
            let mut server = mockito::Server::new();
            let pack = synthetic_pack(64 * 1024);
            let key = key_for(&pack);
            let (shards, manifest) = encode_pack_to_shards(&pack, default_config()).unwrap();
            let manifest_bytes = encode_manifest(&manifest).unwrap();

            let pack_path = format!("/myproj/packs/{}", key.to_hex());
            let _pm = server
                .mock("GET", pack_path.as_str())
                .with_status(200)
                .with_header(X_PACK_SHARDS_HEADER, "16+4")
                .with_body("")
                .expect_at_least(1)
                .create();
            let manifest_path = format!("/myproj/packs/{}/shards.manifest", key.to_hex());
            let _mm = server
                .mock("GET", manifest_path.as_str())
                .with_status(200)
                .with_body(manifest_bytes)
                .create();

            // Shard 0: 503 twice then 200. The two 503s plus the final
            // 200 require a 3-attempt ladder.
            let flaky_path = format!("/myproj/packs/{}/shards/0", key.to_hex());
            let flaky_5xx = server
                .mock("GET", flaky_path.as_str())
                .with_status(503)
                .expect(2)
                .create();
            let flaky_ok = server
                .mock("GET", flaky_path.as_str())
                .with_status(200)
                .with_body(shards[0].bytes.clone())
                .expect(1)
                .create();

            // Remaining shards always 200.
            let mut others = Vec::new();
            for shard in shards.iter().skip(1) {
                let path = format!("/myproj/packs/{}/shards/{}", key.to_hex(), shard.index);
                others.push(
                    server
                        .mock("GET", path.as_str())
                        .with_status(200)
                        .with_body(shard.bytes.clone())
                        .create(),
                );
            }

            let t = make_transport_with_retry(&server, three_attempt_backoff, no_sleep);
            let got = t.download_pack(&key).unwrap();
            assert_eq!(got, pack);
            flaky_5xx.assert();
            flaky_ok.assert();
        }

        /// A shard returning 403 is NOT retried — the worker reports the
        /// terminal error immediately (asserted via `expect(1)`).
        #[test]
        fn shard_get_does_not_retry_on_403() {
            let mut server = mockito::Server::new();
            let pack = synthetic_pack(64 * 1024);
            let key = key_for(&pack);
            let (shards, manifest) = encode_pack_to_shards(&pack, default_config()).unwrap();
            let manifest_bytes = encode_manifest(&manifest).unwrap();

            let pack_path = format!("/myproj/packs/{}", key.to_hex());
            let _pm = server
                .mock("GET", pack_path.as_str())
                .with_status(200)
                .with_header(X_PACK_SHARDS_HEADER, "16+4")
                .with_body("")
                .expect_at_least(1)
                .create();
            let manifest_path = format!("/myproj/packs/{}/shards.manifest", key.to_hex());
            let _mm = server
                .mock("GET", manifest_path.as_str())
                .with_status(200)
                .with_body(manifest_bytes)
                .create();

            // Shard 0: 403, must be hit exactly once (no retry).
            let denied_path = format!("/myproj/packs/{}/shards/0", key.to_hex());
            let denied = server
                .mock("GET", denied_path.as_str())
                .with_status(403)
                .expect(1)
                .create();
            // Remaining 19 shards all 200 — quorum (16) is reachable
            // without shard 0, so the overall download still succeeds.
            let mut others = Vec::new();
            for shard in shards.iter().skip(1) {
                let path = format!("/myproj/packs/{}/shards/{}", key.to_hex(), shard.index);
                others.push(
                    server
                        .mock("GET", path.as_str())
                        .with_status(200)
                        .with_body(shard.bytes.clone())
                        .create(),
                );
            }

            let t = make_transport_with_retry(&server, five_attempt_backoff, no_sleep);
            let got = t.download_pack(&key).unwrap();
            assert_eq!(got, pack);
            denied.assert();
        }

        /// Straggler bound: one shard never responds (mockito has no
        /// mock for it, so the request fails fast as `ConnectionFailed`),
        /// yet quorum is reached from the other shards and the download
        /// returns without waiting on the straggler's worker — the
        /// detached worker is never joined.
        #[test]
        fn shard_download_does_not_block_on_straggler_after_quorum() {
            // Drop exactly K shards (the extras). The remaining `minimum`
            // shards form quorum; the collection loop must return as soon
            // as quorum is met without joining the (failed) stragglers.
            let mut server = mockito::Server::new();
            let dropped = [16u16, 17, 18, 19];
            let (pack, key, _mocks) = publish_sharded(&mut server, 64 * 1024, &dropped);
            let t = make_transport(&server, None);
            let got = t.download_pack(&key).unwrap();
            assert_eq!(got, pack);
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
