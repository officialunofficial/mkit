//! Host policy seams: an operation-scoped signer and a pre-dispatch observer.
//!
//! The client keeps no policy. For every signed request it runs, in order:
//!
//! 1. **observer** ([`Observer::before_dispatch`], writes only), which may veto
//!    and may return extra headers for this attempt;
//! 2. **signer** ([`Signer::sign_operation`]), which sees the structured
//!    operation it signs and may refuse;
//! 3. **deadline check**: a signed window that has already ended is never sent;
//! 4. **dispatch**.
//!
//! A veto or refusal stops the call before any later step, so nothing is signed
//! after a veto and nothing is sent after either. Both seams see the same
//! [`Attempt`]. A retry that builds a new envelope runs steps 1-4 again with a
//! new attempt.

use crate::connect::Error;
use http::{HeaderMap, HeaderName, HeaderValue};
use mkit_core::{hash::Hash, refs::RefWriteCondition, write_auth::ContentCommitment};

/// Full procedure names of the `mkit.transport.v1` write RPCs.
pub mod procedures {
    macro_rules! procedure {
        ($name:ident, $method:literal) => {
            #[doc = concat!("`", $method, "`.")]
            pub const $name: &str = concat!("/mkit.transport.v1.TransportService/", $method);
        };
    }
    procedure!(BEGIN_UPLOAD, "BeginUpload");
    procedure!(UPLOAD_PACK, "UploadPack");
    procedure!(UPLOAD_PART, "UploadPart");
    procedure!(COMPLETE_UPLOAD, "CompleteUpload");
    procedure!(ADVANCE_REFS, "AdvanceRefs");
    procedure!(UPDATE_REF, "UpdateRef");
}

/// One signed envelope: the nonce and window the signature covers, and which
/// try of the call this is.
///
/// `number` counts the envelopes built by one operation in this process, from
/// 1. The seams run each time an envelope is built, so a caller who replays a
/// persisted [`Identity`](crate::Identity) (for example after a restart) runs
/// them again with the same nonce and number 1: a host keys its per-attempt
/// record on `nonce` and replaces it. Re-sending already signed bytes (a
/// pending-verification poll inside `Push::run_with`, a transport retry) does
/// not build an envelope and does not call the seams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Attempt {
    pub number: u32,
    pub nonce: Hash,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

impl Attempt {
    /// For a host's own tests of its seams.
    #[must_use]
    pub fn new(number: u32, nonce: Hash, created_at_ms: i64, expires_at_ms: i64) -> Self {
        Self {
            number,
            nonce,
            created_at_ms,
            expires_at_ms,
        }
    }
}

/// What a [`Signer`](crate::Signer) is asked to sign, next to the domain
/// separated digest. Covers every auth v2 envelope: unary (`body:`), whole-pack
/// (`pack:`) and part (`part:`) commitments.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct SigningRequest<'a> {
    /// Full procedure, for example [`procedures::UPDATE_REF`].
    pub procedure: &'a str,
    /// Canonical origin the signature is bound to.
    pub audience: &'a str,
    pub repository: &'a str,
    pub commitment: ContentCommitment,
    /// Validity window and nonce; `attempt.number` is the try.
    pub attempt: Attempt,
}

impl<'a> SigningRequest<'a> {
    /// For a host's own tests of its signer.
    #[must_use]
    pub fn new(
        procedure: &'a str,
        audience: &'a str,
        repository: &'a str,
        commitment: ContentCommitment,
        attempt: Attempt,
    ) -> Self {
        Self {
            procedure,
            audience,
            repository,
            commitment,
            attempt,
        }
    }
}

/// Why a signer did not sign.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
    /// Policy refused this operation. Becomes [`Error::SignerRefused`].
    #[error("refused: {0}")]
    Refused(String),
    /// The signer could not run (key unavailable, device error). Becomes
    /// [`Error::Signing`].
    #[error("signing failed: {0}")]
    Failed(String),
}
impl From<String> for SignError {
    fn from(error: String) -> Self {
        Self::Failed(error)
    }
}
impl SignError {
    pub(crate) fn into_error(self) -> Error {
        match self {
            Self::Refused(reason) => Error::SignerRefused(reason),
            Self::Failed(reason) => Error::Signing(reason),
        }
    }
}

/// An observer's refusal of a write. Becomes [`Error::Vetoed`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("vetoed: {0}")]
pub struct Veto(String);
impl Veto {
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.0
    }
}

/// How a ref is written.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefTarget {
    /// Set the ref to this object id.
    Set(Hash),
    /// Delete the ref.
    Delete,
    /// Copy the published branch pair of `source` to the destination
    /// (`AdvanceRefs` with `source_ref`). The new value is the source's. The
    /// request names only the destination head, but the server also writes its
    /// packmap twin, whose name the client does not know: a policy keyed on ref
    /// names must treat this move as covering both.
    CopyFrom {
        source: String,
        expected_tip: Option<Hash>,
    },
}

/// One ref move a request carries: name, precondition and new value.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RefMove {
    pub name: String,
    pub old: RefWriteCondition,
    pub new: RefTarget,
}
impl RefMove {
    #[must_use]
    pub fn new(name: impl Into<String>, old: RefWriteCondition, new: RefTarget) -> Self {
        Self {
            name: name.into(),
            old,
            new,
        }
    }
}

/// A write about to be dispatched. Fields not meaningful for a procedure are
/// empty. Build one with [`WriteIntent::new`] to sign a custom envelope.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct WriteIntent<'a> {
    /// Full procedure, for example [`procedures::ADVANCE_REFS`].
    pub procedure: &'a str,
    /// The exact ref moves the request carries (`UpdateRef`, `AdvanceRefs`).
    pub ref_moves: &'a [RefMove],
    /// The ref a `BeginUpload` reserves for.
    pub target_ref: Option<&'a str>,
    /// The pack being reserved or uploaded.
    pub pack_id: Option<Hash>,
    /// Pack bytes (`BeginUpload`, `UploadPack`) or part bytes (`UploadPart`).
    pub bytes: Option<u64>,
    /// Tickets: the one an `UploadPack` (when ticketed), `UploadPart` or
    /// `CompleteUpload` uses, or those an
    /// `AdvanceRefs` consumes. A per-RPC `upload_pack` or `complete_upload`
    /// takes only the opaque token, so it reports none; a whole push does.
    pub ticket_ids: &'a [Hash],
    /// Whether this request carries or consumes an upload ticket, even when
    /// the caller knows only its opaque token.
    pub ticketed: bool,
    pub part_index: Option<u32>,
    /// Ids of the objects the pack introduces, on every RPC of its upload
    /// (`BeginUpload`, `UploadPack`, `UploadPart`, `CompleteUpload`) in a whole
    /// push. `Some` only when the caller knows
    /// all of them: a whole push whose entries are all raw objects. A delta
    /// entry's id is not known without applying it, so a pack holding one
    /// reports `None`, and so does every per-RPC upload.
    pub new_objects: Option<&'a [Hash]>,
}
impl<'a> WriteIntent<'a> {
    #[must_use]
    pub fn new(procedure: &'a str) -> Self {
        Self {
            procedure,
            ref_moves: &[],
            target_ref: None,
            pack_id: None,
            bytes: None,
            ticket_ids: &[],
            ticketed: false,
            part_index: None,
            new_objects: None,
        }
    }
    /// The RPC name without its service prefix.
    #[must_use]
    pub fn method(&self) -> &'a str {
        self.procedure.rsplit('/').next().unwrap_or(self.procedure)
    }
    #[must_use]
    pub fn with_ref_moves(mut self, moves: &'a [RefMove]) -> Self {
        self.ref_moves = moves;
        self
    }
    #[must_use]
    pub fn with_target_ref(mut self, target: &'a str) -> Self {
        self.target_ref = Some(target);
        self
    }
    #[must_use]
    pub fn with_pack(mut self, id: Hash, bytes: u64) -> Self {
        self.pack_id = Some(id);
        self.bytes = Some(bytes);
        self
    }
    #[must_use]
    pub fn with_tickets(mut self, ids: &'a [Hash]) -> Self {
        self.ticket_ids = ids;
        self
    }
    /// Mark a request that carries or consumes ticket credentials.
    #[must_use]
    pub fn with_ticketed(mut self, ticketed: bool) -> Self {
        self.ticketed = ticketed;
        self
    }
    #[must_use]
    pub fn with_part(mut self, index: u32, bytes: u64) -> Self {
        self.part_index = Some(index);
        self.bytes = Some(bytes);
        self
    }
    #[must_use]
    pub fn with_new_objects(mut self, ids: Option<&'a [Hash]>) -> Self {
        self.new_objects = ids;
        self
    }
}

/// Extra request headers for one attempt, not signed. A header that is not
/// reserved replaces a transport default of the same name (for example
/// `accept-encoding`), so choose names accordingly. Names are checked
/// against the hard-reserved list of SPEC-TRANSPORT-CONNECT section 5.1 before
/// anything is signed.
#[derive(Clone, Debug, Default)]
pub struct AttemptHeaders(Vec<(String, String)>);
impl AttemptHeaders {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Add a header, for example `traceparent` or a request id.
    #[must_use]
    pub fn with(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.0.push((name.into(), value.into()));
        self
    }

    pub(crate) fn validate(self) -> Result<HeaderMap, Error> {
        let mut map = HeaderMap::new();
        for (name, value) in self.0 {
            let parsed = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| Error::Invalid("attempt header name"))?;
            if is_reserved_header(parsed.as_str()) {
                return Err(Error::ReservedHeader(parsed.to_string()));
            }
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::Invalid("attempt header value"))?;
            if map.insert(parsed, value).is_some() {
                return Err(Error::Invalid("duplicate attempt header"));
            }
        }
        Ok(map)
    }
}

const RESERVED_EXACT: &[&str] = &[
    "x-public-key",
    "x-signature",
    "x-digest",
    "x-created-at",
    "x-expires-at",
    "x-envelope-version",
    "x-audience",
    "x-repository",
    "x-content-commitment",
    "x-write-grant",
    "host",
    "transfer-encoding",
    "cookie",
    "idempotency-key",
    "authorization",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
];
const RESERVED_PREFIX: &[&str] = &["x-mkit-", "x-forwarded-", "content-", "connect-", "proxy-"];

/// Hard-reserved request headers (SPEC-TRANSPORT-CONNECT section 5.1): the
/// auth v2 envelope, `X-Mkit-*`, `X-Forwarded-*`, framing and hop-by-hop
/// headers. `Authorization` is refused as well, because the client cannot know
/// whether its transport already sends one.
#[must_use]
pub fn is_reserved_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    RESERVED_EXACT.contains(&name.as_str())
        || RESERVED_PREFIX
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

/// Host policy for identity-bearing writes. The default does nothing.
#[allow(async_fn_in_trait)]
pub trait Observer {
    /// Called once per signed or explicitly clocked unsigned write attempt,
    /// before signing or dispatch. `Err` vetoes the write: nothing is signed or
    /// sent. `Ok` may add headers for this attempt.
    ///
    /// # Errors
    /// A [`Veto`] stops the call with [`Error::Vetoed`].
    async fn before_dispatch(
        &self,
        intent: &WriteIntent<'_>,
        attempt: &Attempt,
    ) -> Result<AttemptHeaders, Veto> {
        let _ = (intent, attempt);
        Ok(AttemptHeaders::default())
    }
}

/// The observer of a client that has none.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoObserver;
impl Observer for NoObserver {}

/// A signed request whose host-owned credentials are selected before signing.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct RequestContext<'a> {
    /// The operation and signed validity window.
    pub signing: SigningRequest<'a>,
    /// Present for writes; absent for signed reads.
    pub intent: Option<WriteIntent<'a>>,
    /// The public key that will sign this request.
    pub public_key: [u8; 32],
}

/// An unsigned request, with no signing identity or public key.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct UnsignedRequestContext<'a> {
    pub procedure: &'a str,
    pub audience: &'a str,
    pub repository: &'a str,
    pub intent: Option<WriteIntent<'a>>,
}

/// Optional response acceptance and framing bounds selected by the host.
/// Defaults preserve the client's strict response checks and existing limits.
// Independent acceptance options, rather than mutually exclusive states.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ResponseProfile {
    /// Omit the `ListRefs` page-size field when the caller selects zero.
    pub omit_zero_page_size: bool,
    /// Drop read hints that fail the canonical ref-name grammar.
    pub ignore_invalid_ref_hints: bool,
    /// Defer the final downloaded-byte hash check to the caller. Frame order,
    /// chunk identity, offsets, declared size and resource limits still apply.
    /// Hosts using this option must verify bytes before storing or trusting them.
    pub skip_download_hash_verification: bool,
    /// Accept every successful HTTP status rather than only 200.
    pub allow_other_success_status: bool,
    /// Accept an omitted response content type.
    pub allow_missing_content_type: bool,
    /// Accept content types beginning with the requested media type.
    pub allow_content_type_prefix: bool,
    /// Default absent error fields and normalize unknown codes by HTTP status.
    pub allow_incomplete_error_fields: bool,
    /// Accept a zero-byte coded HTTP body without requiring a coding envelope.
    pub allow_empty_coded_body: bool,
    /// Interpret omitted ReadRef/PackExists presence fields as false.
    pub missing_presence_is_false: bool,
    /// Expose bounded HTTP error bodies instead of refusing redirects locally.
    /// Redirects are never followed.
    pub expose_error_responses: bool,
    /// Optional Connect data-frame cap, clamped to the response budget.
    pub frame_limit: Option<usize>,
    /// Optional end-frame and HTTP error-body cap, clamped to the response budget.
    pub end_frame_limit: Option<usize>,
}

/// The stage that observed a response or channel failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailureKind {
    Http,
    Headers,
    Decode,
    DecodeResourceLimit,
    Channel,
    RequestIo,
    BodyIo,
    Coding,
    WireLimit,
    InflatedLimit,
}

/// Borrowed, bounded evidence captured before a failure is simplified. Treat
/// bodies, headers and diagnostic causes as untrusted and potentially sensitive.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct FailureDiagnostic<'a> {
    pub procedure: &'a str,
    pub kind: FailureKind,
    pub status: Option<http::StatusCode>,
    pub headers: Option<&'a HeaderMap>,
    pub body: Option<&'a [u8]>,
    /// Client-parsed error envelope, when the response supplied a valid one.
    pub parsed_error: Option<&'a crate::RemoteError>,
    pub cause: &'a str,
    pub limit: Option<usize>,
}

impl<'a> FailureDiagnostic<'a> {
    #[must_use]
    pub fn new(procedure: &'a str, kind: FailureKind, cause: &'a str) -> Self {
        Self {
            procedure,
            kind,
            status: None,
            headers: None,
            body: None,
            parsed_error: None,
            cause,
            limit: None,
        }
    }
}

impl std::fmt::Debug for FailureDiagnostic<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FailureDiagnostic")
            .field("procedure", &self.procedure)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("limit", &self.limit)
            .field("body_len", &self.body.map(<[u8]>::len))
            .finish_non_exhaustive()
    }
}

/// Host-owned failure classification and response acceptance. Mapping a failure
/// does not retry the request; scheduling remains with the caller.
pub trait FailureObserver {
    /// Return an alternate error, or preserve the client's default failure.
    fn map_failure(&self, _failure: &FailureDiagnostic<'_>) -> Option<Error> {
        None
    }
    /// Select explicit response compatibility for this exchange.
    fn response_profile(&self) -> ResponseProfile {
        ResponseProfile::default()
    }
}

/// The policy type of a client with no configured request policy.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoRequestPolicy;
impl RequestPolicy for NoRequestPolicy {
    fn headers(&self, _: &RequestContext<'_>) -> Result<RequestHeaders, Veto> {
        Ok(RequestHeaders::new())
    }
}

/// Host-owned credential selection, consulted for every signed envelope.
///
/// The host selects grants and validated admission headers here. Challenge
/// recovery, helper execution, trust and grant verification remain in the host.
/// This synchronous callback must not run a blocking admission helper.
pub trait RequestPolicy {
    /// Select a bounded response budget for this procedure. The default keeps
    /// the primitive's caller-supplied limit unchanged.
    fn response_limit(&self, _procedure: &str, default: usize) -> usize {
        default
    }
    fn response_profile(&self, _procedure: &str) -> ResponseProfile {
        ResponseProfile::default()
    }
    fn map_failure(&self, _failure: &FailureDiagnostic<'_>) -> Option<Error> {
        None
    }
    /// Ask a native channel to advertise its actual, locally clamped I/O budget.
    fn advertise_request_timeout(&self, _procedure: &str) -> bool {
        false
    }

    /// Optionally shorten the channel's per-request I/O budget. This local
    /// extension changes no headers or authenticated bytes. Hosts can clamp a
    /// request to the remaining ticket or operation deadline. For a negotiated
    /// pack location, the budget covers the opted-in request, external fetch
    /// and any streaming fallback together.
    fn request_timeout(&self, _procedure: &str) -> Option<std::time::Duration> {
        None
    }

    /// Select headers before the signer runs. A refusal prevents dispatch.
    ///
    /// # Errors
    /// Returns a refusal when host policy disallows the request.
    fn headers(&self, request: &RequestContext<'_>) -> Result<RequestHeaders, Veto>;

    /// Observe headers from a successful HTTP response. The host may record
    /// bounded admission receipts here; response decoding still follows.
    fn after_response(&self, _request: &RequestContext<'_>, _headers: &HeaderMap) {}

    /// Select credentials for an unsigned RPC. Discovery bypasses this seam.
    /// Unsigned writes require the client's explicit host opt-in.
    ///
    /// # Errors
    /// Returns a refusal when host policy disallows the request.
    fn unsigned_headers(
        &self,
        _request: &UnsignedRequestContext<'_>,
    ) -> Result<RequestHeaders, Veto> {
        Ok(RequestHeaders::new())
    }

    /// Observe a successful unsigned RPC response, before protobuf decoding.
    fn after_unsigned_response(&self, _request: &UnsignedRequestContext<'_>, _headers: &HeaderMap) {
    }
}

/// Per-request credentials and ordinary extra headers from a host policy.
///
/// Only the dedicated setters allow a write grant or authorization value.
/// The host must prevent authorization from replacing a transport credential
/// and validate its admission helper's allowlist before supplying these values.
#[derive(Clone, Default)]
pub struct RequestHeaders {
    extra: AttemptHeaders,
    write_grant: Option<String>,
    authorization: Option<String>,
}
impl std::fmt::Debug for RequestHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestHeaders")
            .field("has_write_grant", &self.write_grant.is_some())
            .field("has_authorization", &self.authorization.is_some())
            .finish_non_exhaustive()
    }
}
impl RequestHeaders {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an ordinary header, subject to the observer's reserved-header rules.
    #[must_use]
    pub fn with(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra = self.extra.with(name, value);
        self
    }

    /// Attach the opaque grant selected and checked by the host.
    #[must_use]
    pub fn with_write_grant(mut self, value: impl Into<String>) -> Self {
        self.write_grant = Some(value.into());
        self
    }

    /// Attach admission authorization after the host has checked that no
    /// transport authorization is already carried.
    #[must_use]
    pub fn with_authorization(mut self, value: impl Into<String>) -> Self {
        self.authorization = Some(value.into());
        self
    }

    pub(crate) fn validate(self) -> Result<HeaderMap, Error> {
        let mut headers = self.extra.validate()?;
        for (name, value) in [
            ("x-write-grant", self.write_grant),
            ("authorization", self.authorization),
        ] {
            if let Some(value) = value {
                let mut value = HeaderValue::from_str(&value)
                    .map_err(|_| Error::Invalid("request credential value"))?;
                value.set_sensitive(true);
                headers.insert(name, value);
            }
        }
        Ok(headers)
    }
}
