//! Runtime-agnostic HTTP object serving (SPEC-HTTP-OBJECTS; WP-4.12, R-169).
//!
//! [`crate::pipeline::Pipeline::serve_http_object`] takes the raw escaped
//! path, query and headers of a GET, HEAD or OPTIONS request and returns a
//! complete [`HttpObjectResponse`]: no `http` crate, no runtime. A binding
//! (WP-4.16) mounts it, adds CORS and streams the body.
//!
//! The `http-objects` feature is off by default. Native embedders and the
//! Paid Workers launch can opt in through their adapter features and
//! mount configuration. The handler requires indexed mode and
//! `PipelineConfig::http_objects`.
//!
//! The pieces: [`route`] is the §2 parser, [`range`] the conditional and
//! byte-range rules, `resolve` published resolution and the byte source
//! (extracted objects held by this repository, else its own pack entry),
//! [`reach`] the reachability proof, `body` the length-enforcing body, and
//! [`seams`] the hooks for admission (4.13), proofs (4.14b), tokens (4.15),
//! mounting (4.16) and takedown (5.9a).

mod body;
pub(crate) mod content_headers;
pub mod mount;
mod paid;
pub(crate) mod proof;
pub mod range;
pub mod reach;
pub(crate) mod resolve;
pub mod route;
pub mod seams;

pub use body::{EndHook, HttpBody, exact as exact_body, with_hook as body_with_hook};
pub use paid::HttpReadRuntime;
pub(crate) use paid::ReadFinalizer;
pub use reach::{Reachability, TtlReachability};
pub use route::{BadUrl, ParsedUrl, Query, RepoPrefix, Target, is_http_object_path, parse};
pub use seams::{
    AdmitDecision, AdmitRequest, Admitted, HttpAdmission, HttpSeams, NoAdmission, NoTakedown,
    NoTokens, PreparedProof, ProofServer, ProofSource, TakedownGate, TakedownVerdict, TokenGate,
    UnsupportedProofs,
};

/// Header lookup safe to retain across a native response future.
#[cfg(not(target_arch = "wasm32"))]
pub type HttpHeaderValues<'a> = dyn Fn(&str) -> Vec<String> + Sync + 'a;
/// Workers run request futures on one thread.
#[cfg(target_arch = "wasm32")]
pub type HttpHeaderValues<'a> = dyn Fn(&str) -> Vec<String> + 'a;
use crate::{Code, ServerError};

/// Counter: ref enumeration or a reachability walk hit its row, page or
/// decode budget
/// and answered the uniform 404.
pub const METRIC_HTTP_REACH_CAPPED: &str = "mkit_server_http_reach_capped_total";
/// Counter: an object without an extracted copy exceeded
/// `max_inline_object_bytes` and answered 503.
pub const METRIC_HTTP_INLINE_CAPPED: &str = "mkit_server_http_inline_capped_total";

/// Default [`HttpObjectsConfig::max_inline_object_bytes`]: 64 MiB.
pub const DEFAULT_MAX_INLINE_OBJECT_BYTES: u64 = 64 << 20;

/// Limits of opt-in HTTP object serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpObjectsConfig {
    /// Most objects one reachability walk decides, and most ref rows scanned
    /// (including excluded refs and shard prefetch). Enumeration also has a
    /// page budget of this limit divided by the configured page size, rounded
    /// up. Exhaustion is 404 and [`METRIC_HTTP_REACH_CAPPED`].
    pub max_walk_objects: usize,
    /// Run the Admission hook for GET and HEAD at step 11. Default off.
    pub admit_reads: bool,
    /// Opt-in public ref redirects after all earlier checks; disabled with admission.
    pub redirect_public_refs: bool,
    /// Maximum paid transmission time from reservation creation.
    pub read_deadline: core::time::Duration,
    /// Time reserved for completion persistence before abandonment (default 60 s).
    pub read_reconcile_grace: core::time::Duration,
    /// How long a reachability proof is trusted, in milliseconds: a rewind
    /// or ref deletion is visible within it (§4 `reachability_lag`).
    pub reachability_lag_ms: u64,
    /// Most rows of the positive reachability cache.
    pub reach_cache_entries: usize,
    /// Largest object served from its pack entry rather than an extracted
    /// copy, at least `extract_min_bytes + 10`. Larger is 503.
    pub max_inline_object_bytes: u64,
    /// Decode bytes one request may spend on resolution and the reachability
    /// walk; at least `max_inline_object_bytes`. The inline byte source has
    /// its own `max_inline_object_bytes` allowance on top.
    pub http_decode_budget: u64,
    /// Maximum requested proof range content (checked before encoded size).
    pub max_proof_content_bytes: u64,
    /// Maximum encoded proof, at most SPEC-DISCLOSURE's 64 MiB cap.
    pub max_proof_bundle_bytes: u64,
}

impl Default for HttpObjectsConfig {
    fn default() -> Self {
        Self {
            max_walk_objects: 50_000,
            admit_reads: false,
            redirect_public_refs: false,
            read_deadline: core::time::Duration::from_mins(5),
            read_reconcile_grace: core::time::Duration::from_mins(1),
            reachability_lag_ms: 60_000,
            reach_cache_entries: 65_536,
            max_inline_object_bytes: DEFAULT_MAX_INLINE_OBJECT_BYTES,
            http_decode_budget: 256 << 20,
            max_proof_content_bytes: 8 << 20,
            max_proof_bundle_bytes: 64 << 20,
        }
    }
}

impl HttpObjectsConfig {
    /// Check the limits against the indexed configuration they run under.
    ///
    /// # Errors
    /// `invalid_argument` for a zero limit, an inline cap below
    /// `extract_min_bytes + 10`, or a decode budget below the inline cap.
    pub fn validate(&self, extract_min_bytes: u64) -> Result<(), ServerError> {
        if self.max_proof_content_bytes == 0
            || self.max_proof_bundle_bytes == 0
            || self.max_proof_bundle_bytes > 64 << 20
            || self.read_deadline.is_zero()
            || self.read_reconcile_grace.is_zero()
            || self.max_walk_objects == 0
            || self.reachability_lag_ms == 0
            || self.reach_cache_entries == 0
            || self.max_inline_object_bytes < extract_min_bytes.saturating_add(10)
            || self.http_decode_budget < self.max_inline_object_bytes
        {
            return Err(ServerError::invalid_argument("invalid HTTP object limits"));
        }
        Ok(())
    }
}

/// An escaped query whose contents are available only to the URL parser.
/// Debug and Display always redact it, including when formatted on its own.
#[derive(Clone, Copy)]
pub struct RedactedQuery<'a>(&'a str);

impl<'a> RedactedQuery<'a> {
    /// Wrap the query exactly as received, without the leading `?`.
    #[must_use]
    pub fn new(query: &'a str) -> Self {
        Self(query)
    }
}

impl core::fmt::Debug for RedactedQuery<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[redacted]")
    }
}

impl core::fmt::Display for RedactedQuery<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[redacted]")
    }
}

/// One request as a binding presents it. `raw_path` and `raw_query` are
/// exactly as received (still escaped, no leading `?`): framework decoding
/// must not reinterpret delimiters (§2). Neither is ever logged.
pub struct HttpObjectRequest<'a> {
    /// `GET`, `HEAD`, `OPTIONS` or anything else (405).
    pub method: &'a str,
    /// The escaped path.
    pub raw_path: &'a str,
    /// The escaped query, without the `?`. A trailing `?` with nothing after
    /// it is `Some(RedactedQuery::new(""))`, which is a 400 (§2); a mount
    /// that drops it must not present it as `None`.
    pub raw_query: Option<RedactedQuery<'a>>,
    /// Multi-value header lookup by lowercase name.
    pub headers: &'a HttpHeaderValues<'a>,
    /// Header names as received by the adapter, including repeated fields.
    /// Credential forwarding preserves this spelling; values stay in `headers`.
    pub header_names: &'a [&'a str],
}

impl core::fmt::Debug for HttpObjectRequest<'_> {
    /// Never shows the path, query or headers.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HttpObjectRequest")
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

/// A complete response. Header names are static; values never carry request
/// text verbatim. Filenames are derived and fully percent-encoded outside
/// RFC 5987 attr-char, with a sanitized ASCII fallback, preventing injection.
#[derive(Debug)]
pub struct HttpObjectResponse {
    /// The status code.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(&'static str, String)>,
    /// The body; empty for HEAD on every status.
    pub body: HttpBody,
}

/// Sent on every response, errors included (§5.3).
const SECURITY_HEADERS: [(&str, &str); 3] = [
    ("X-Content-Type-Options", "nosniff"),
    ("Content-Security-Policy", "sandbox; default-src 'none'"),
    ("Referrer-Policy", "no-referrer"),
];

/// The one body of every 404, so no miss can be told from another.
const NOT_FOUND_BODY: &[u8] = b"not found";

impl HttpObjectResponse {
    /// A response with the security headers and no body.
    #[must_use]
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: SECURITY_HEADERS
                .iter()
                .map(|(name, value)| (*name, (*value).to_owned()))
                .collect(),
            body: HttpBody::Empty,
        }
    }

    /// `self` with one more header.
    #[must_use]
    pub fn with_header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    /// An error response: `no-store` (§3), no body.
    #[must_use]
    pub fn error(status: u16) -> Self {
        Self::new(status).with_header("Cache-Control", "no-store")
    }

    /// The uniform 404, byte-identical for every miss (§3).
    #[must_use]
    pub fn not_found() -> Self {
        let mut response = Self::error(404)
            .with_header("Content-Type", "text/plain; charset=utf-8")
            .with_header("Content-Length", NOT_FOUND_BODY.len().to_string());
        response.body = HttpBody::Bytes(bytes::Bytes::from_static(NOT_FOUND_BODY));
        response
    }

    /// The first header named `name`, ignoring ASCII case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The Cache-Control of a successful public response (§5.3); `private`
/// replaces `public` when Admission ran.
pub(crate) fn cache_control(ref_path: bool, private: bool) -> &'static str {
    match (ref_path, private) {
        (false, false) => "public, max-age=31536000, immutable",
        (false, true) => "private, max-age=31536000, immutable",
        (true, false) => "public, no-cache",
        (true, true) => "private, no-cache",
    }
}

/// How a failed request maps to a response.
#[derive(Debug)]
pub(crate) enum Fail {
    /// The uniform 404.
    NotFound,
    /// 403.
    Forbidden,
    /// Unsupported selector, bounds, overflow or proof cap: 416.
    ProofRange,
    /// 503: a store, hook or invariant failure. Fails closed.
    Unavailable,
}

impl Fail {
    /// Map an authorization or hook error (§3 step 6): `not_found` and a
    /// private repository are 404, a denial (including `unauthenticated` on a
    /// public read, which §3 only lets be 403) is 403, everything else is 503.
    pub(crate) fn from_server_error(error: &ServerError) -> Self {
        match error.code() {
            Code::NotFound => Self::NotFound,
            Code::PermissionDenied | Code::Unauthenticated => Self::Forbidden,
            _ => Self::Unavailable,
        }
    }

    /// The code to record in request metrics.
    pub(crate) fn code(&self) -> Code {
        match self {
            Self::NotFound => Code::NotFound,
            Self::ProofRange => Code::OutOfRange,
            Self::Forbidden => Code::PermissionDenied,
            Self::Unavailable => Code::Unavailable,
        }
    }

    pub(crate) fn into_response(self) -> HttpObjectResponse {
        match self {
            Self::NotFound => HttpObjectResponse::not_found(),
            Self::ProofRange => HttpObjectResponse::error(416),
            Self::Forbidden => HttpObjectResponse::error(403),
            Self::Unavailable => HttpObjectResponse::error(503),
        }
    }
}

impl From<resolve::Miss> for Fail {
    fn from(miss: resolve::Miss) -> Self {
        match miss {
            resolve::Miss::NotFound => Self::NotFound,
            resolve::Miss::Capped | resolve::Miss::Unavailable => Self::Unavailable,
        }
    }
}
