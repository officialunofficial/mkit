//! Transport-neutral server errors.
//!
//! A [`ServerError`] carries a [`Code`], a public message that is safe to
//! send to any client, and optionally a [`Redacted`] detail for server-side
//! logs only. Bindings map [`Code`] onto Connect or ssh error codes. Backend
//! failures go through [`ServerError::internal`], which fixes the public
//! message so SDK or storage text never reaches a client (issue #794).

use std::borrow::Cow;
use std::fmt;

use crate::telemetry::{REDACTED_VALUE, is_never_echo, is_never_log};

/// Fully qualified proto name of the admission challenge detail
/// (SPEC-TRANSPORT-CONNECT §5.1).
pub const ADMISSION_CHALLENGE_TYPE: &str = "mkit.transport.v1.AdmissionChallenge";

/// Error category: the 16 Connect codes, one-to-one.
///
/// A missed `NotAfter` commit deadline, a full shard, outbox backpressure
/// and pending verification are [`Code::Unavailable`], never
/// [`Code::ResourceExhausted`] (SPEC-TRANSPORT-CONNECT §5): nothing
/// commits and a retry with the same nonce is safe. Admission challenges
/// and denials are [`Code::PermissionDenied`], never `ResourceExhausted`,
/// because clients retry that code on a backoff ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Code {
    /// The caller canceled the request.
    Canceled,
    /// No more specific category applies.
    Unknown,
    /// Malformed request: bad ref name, noncanonical field, wrong framing.
    InvalidArgument,
    /// The request ran past its deadline.
    DeadlineExceeded,
    /// The named ref, pack or repository does not exist (or is private).
    NotFound,
    /// The entity the caller tried to create already exists.
    AlreadyExists,
    /// Authenticated, but not allowed; also every admission challenge
    /// (HTTP 402) and denial.
    PermissionDenied,
    /// A client-attributable size or rate cap, such as an oversized pack
    /// or a spent per-signer quota. Never a server-side capacity limit:
    /// those are [`Code::Unavailable`].
    ResourceExhausted,
    /// A compare-and-swap precondition or upload ticket did not hold.
    FailedPrecondition,
    /// The same operation is in flight; the client may retry unchanged.
    Aborted,
    /// A value outside its valid range.
    OutOfRange,
    /// The deployment does not support this procedure.
    Unimplemented,
    /// A server-side failure.
    Internal,
    /// Temporarily unable to commit: backend outage, missed `NotAfter`
    /// deadline, full shard, outbox backpressure or pending verification.
    /// Retrying with the same nonce is safe.
    Unavailable,
    /// Unrecoverable data loss or corruption.
    DataLoss,
    /// Missing or invalid credentials.
    Unauthenticated,
}

impl Code {
    /// The Connect protocol's canonical name, e.g. `invalid_argument`. Also
    /// the `code` label value for [`crate::METRIC_REQUESTS`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Canceled => "canceled",
            Self::Unknown => "unknown",
            Self::InvalidArgument => "invalid_argument",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::NotFound => "not_found",
            Self::AlreadyExists => "already_exists",
            Self::PermissionDenied => "permission_denied",
            Self::ResourceExhausted => "resource_exhausted",
            Self::FailedPrecondition => "failed_precondition",
            Self::Aborted => "aborted",
            Self::OutOfRange => "out_of_range",
            Self::Unimplemented => "unimplemented",
            Self::Internal => "internal",
            Self::Unavailable => "unavailable",
            Self::DataLoss => "data_loss",
            Self::Unauthenticated => "unauthenticated",
        }
    }

    /// Whether a client retries this code on its backoff ladder:
    /// `unavailable`, `resource_exhausted` and `aborted` (SPEC-TRANSPORT §7,
    /// SPEC-TRANSPORT-CONNECT §5).
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::Unavailable | Self::ResourceExhausted | Self::Aborted
        )
    }
}

/// A typed error detail (Connect `ErrorDetail`): the fully qualified proto
/// message name and its encoded bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorDetail {
    /// Fully qualified proto type name, e.g. [`ADMISSION_CHALLENGE_TYPE`].
    pub type_name: String,
    /// The encoded message.
    pub value: bytes::Bytes,
}

/// A string that never prints its contents through [`fmt::Debug`] or
/// [`fmt::Display`]. Only [`Redacted::expose`] reads it, and only the
/// server-side logging sink should call that.
#[derive(Clone, PartialEq, Eq)]
pub struct Redacted(String);

impl Redacted {
    /// Wrap `value`.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The wrapped text, for the server-side log sink only.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Redacted({} bytes)", self.0.len())
    }
}

impl fmt::Display for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_VALUE)
    }
}

/// Why a response header was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidHeader {
    /// The name is not an RFC 9110 token.
    #[error("header name is not an HTTP token")]
    Name,
    /// The name is a request credential ([`crate::NEVER_ECHO`]) or a
    /// framing, hop-by-hop or cookie header the binding owns.
    #[error("header name is reserved")]
    Reserved,
    /// The value holds a control character other than horizontal tab.
    #[error("header value contains a control character")]
    Value,
}

/// Response headers the Connect binding or the HTTP stack owns, compared
/// ignoring ASCII case: framing, hop-by-hop (RFC 9110 §7.6.1) and cookies.
const RESERVED_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-connection",
    "set-cookie",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Reserved response-header name prefixes: `Content-*` framing and the
/// Connect protocol's own `Connect-*` headers.
const RESERVED_RESPONSE_PREFIXES: &[&str] = &["content-", "connect-"];

/// A transport-neutral server error. `Display` shows the public message
/// only. `Debug` shows the log detail as [`Redacted`] and replaces the
/// value of every [`crate::NEVER_LOG`] header with a placeholder; a sink
/// that knows deployment-configured names logs headers through
/// [`crate::Redactor`] instead.
#[derive(Clone, thiserror::Error)]
#[error("{public}")]
pub struct ServerError {
    code: Code,
    public: Cow<'static, str>,
    detail: Option<Redacted>,
    http_status: Option<u16>,
    headers: Vec<(String, String)>,
    details: Vec<ErrorDetail>,
}

impl fmt::Debug for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Headers<'a>(&'a [(String, String)]);
        impl fmt::Debug for Headers<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list()
                    .entries(self.0.iter().map(|(name, value)| {
                        let shown = if is_never_log(name) {
                            REDACTED_VALUE
                        } else {
                            value
                        };
                        (name, shown)
                    }))
                    .finish()
            }
        }
        f.debug_struct("ServerError")
            .field("code", &self.code)
            .field("public", &self.public)
            .field("detail", &self.detail)
            .field("http_status", &self.http_status)
            .field("headers", &Headers(&self.headers))
            .field("details", &self.details)
            .finish()
    }
}

impl ServerError {
    /// An error with `code` and a client-safe `public` message.
    #[must_use]
    pub fn new(code: Code, public: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code,
            public: public.into(),
            detail: None,
            http_status: None,
            headers: Vec::new(),
            details: Vec::new(),
        }
    }

    /// [`Code::InvalidArgument`].
    #[must_use]
    pub fn invalid_argument(public: impl Into<Cow<'static, str>>) -> Self {
        Self::new(Code::InvalidArgument, public)
    }

    /// [`Code::Unauthenticated`].
    #[must_use]
    pub fn unauthenticated(public: impl Into<Cow<'static, str>>) -> Self {
        Self::new(Code::Unauthenticated, public)
    }

    /// [`Code::PermissionDenied`], with its default HTTP status (403).
    #[must_use]
    pub fn permission_denied(public: impl Into<Cow<'static, str>>) -> Self {
        Self::new(Code::PermissionDenied, public)
    }

    /// An admission challenge (SPEC-TRANSPORT-CONNECT §5.1):
    /// [`Code::PermissionDenied`] with HTTP status 402 and exactly one
    /// [`ADMISSION_CHALLENGE_TYPE`] detail. `challenge` is the encoded
    /// `AdmissionChallenge` message. Challenge headers such as
    /// `WWW-Authenticate` are added with [`Self::with_header`].
    #[must_use]
    pub fn admission_challenge(challenge: bytes::Bytes) -> Self {
        Self::new(Code::PermissionDenied, "admission required")
            .with_http_status(402)
            .with_detail(ErrorDetail {
                type_name: ADMISSION_CHALLENGE_TYPE.to_owned(),
                value: challenge,
            })
    }

    /// [`Code::NotFound`].
    #[must_use]
    pub fn not_found(public: impl Into<Cow<'static, str>>) -> Self {
        Self::new(Code::NotFound, public)
    }

    /// [`Code::FailedPrecondition`].
    #[must_use]
    pub fn failed_precondition(public: impl Into<Cow<'static, str>>) -> Self {
        Self::new(Code::FailedPrecondition, public)
    }

    /// [`Code::ResourceExhausted`]: a client-attributable cap only (see
    /// [`Code`]).
    #[must_use]
    pub fn resource_exhausted(public: impl Into<Cow<'static, str>>) -> Self {
        Self::new(Code::ResourceExhausted, public)
    }

    /// [`Code::Aborted`]: the same operation is in flight and the client may
    /// retry it unchanged (PRD §5.4 stage 0, `in_flight` replay records).
    #[must_use]
    pub fn aborted_retryable(public: impl Into<Cow<'static, str>>) -> Self {
        Self::new(Code::Aborted, public)
    }

    /// [`Code::Unavailable`].
    #[must_use]
    pub fn unavailable(public: impl Into<Cow<'static, str>>) -> Self {
        Self::new(Code::Unavailable, public)
    }

    /// [`Code::Unimplemented`].
    #[must_use]
    pub fn unimplemented(public: impl Into<Cow<'static, str>>) -> Self {
        Self::new(Code::Unimplemented, public)
    }

    /// A backend failure: a fixed public message, with `detail` kept only
    /// for server-side logs (issue #794).
    #[must_use]
    pub fn internal(public: &'static str, detail: impl fmt::Display) -> Self {
        Self {
            detail: Some(Redacted(detail.to_string())),
            ..Self::new(Code::Internal, public)
        }
    }

    /// Set the HTTP status the Connect binding answers with. Only error
    /// statuses (`400..=599`) are accepted, and 402 only on
    /// [`Code::PermissionDenied`] (use [`Self::admission_challenge`]). Any
    /// other value fails a debug assertion and is ignored.
    #[must_use]
    pub fn with_http_status(mut self, status: u16) -> Self {
        let allowed = status_allowed(self.code, status);
        debug_assert!(
            allowed,
            "HTTP status {status} is not an error status, or is 402 on {:?}",
            self.code
        );
        if allowed {
            self.http_status = Some(status);
        }
        self
    }

    /// Add a response header from dynamic input, e.g. a value an admission
    /// helper produced.
    ///
    /// # Errors
    /// [`InvalidHeader`] if the name is not an HTTP token, is reserved
    /// (a request credential, framing, hop-by-hop or cookie header), or the
    /// value holds a control character. `self` is dropped on error.
    pub fn try_with_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, InvalidHeader> {
        let (name, value) = (name.into(), value.into());
        check_header(&name, &value)?;
        self.headers.push((name, value));
        Ok(self)
    }

    /// Add a response header, e.g. `WWW-Authenticate`. An invalid or
    /// reserved header is dropped with a warning, so a credential or a
    /// framing header can never be echoed. A reserved *name* is a
    /// programming error and also fails a debug assertion; a malformed
    /// value never panics. Use [`Self::try_with_header`] to handle the
    /// failure instead.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let (name, value) = (name.into(), value.into());
        match check_header(&name, &value) {
            Ok(()) => self.headers.push((name, value)),
            Err(reason) => {
                // Never log the value: it may be the credential being dropped.
                tracing::warn!(header = ?name, %reason, "dropped an error response header");
                debug_assert!(
                    reason != InvalidHeader::Reserved,
                    "error response header {name:?} is reserved"
                );
            }
        }
        self
    }

    /// Attach a typed error detail. An error carries at most one
    /// [`ADMISSION_CHALLENGE_TYPE`] detail (checked in debug builds).
    #[must_use]
    pub fn with_detail(mut self, detail: ErrorDetail) -> Self {
        debug_assert!(
            detail.type_name != ADMISSION_CHALLENGE_TYPE
                || !self
                    .details
                    .iter()
                    .any(|d| d.type_name == ADMISSION_CHALLENGE_TYPE),
            "an error carries exactly one AdmissionChallenge detail"
        );
        self.details.push(detail);
        self
    }

    /// The error category.
    #[must_use]
    pub fn code(&self) -> Code {
        self.code
    }

    /// The client-safe message.
    #[must_use]
    pub fn public_message(&self) -> &str {
        &self.public
    }

    /// The server-side detail, for the log sink only.
    #[must_use]
    pub fn log_detail(&self) -> Option<&str> {
        self.detail.as_ref().map(Redacted::expose)
    }

    /// The HTTP status override, if any.
    #[must_use]
    pub fn http_status(&self) -> Option<u16> {
        self.http_status
    }

    /// Response headers, in insertion order. Values may include receipts
    /// ([`crate::NEVER_LOG`]); log them through [`crate::Redactor`].
    #[must_use]
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// Typed error details, in insertion order.
    #[must_use]
    pub fn details(&self) -> &[ErrorDetail] {
        &self.details
    }
}

/// Whether `status` may be set on an error with `code`: an error status
/// (`400..=599`), and 402 only for [`Code::PermissionDenied`]
/// (SPEC-TRANSPORT-CONNECT §5).
fn status_allowed(code: Code, status: u16) -> bool {
    (400..=599).contains(&status) && (status != 402 || code == Code::PermissionDenied)
}

/// Whether a response header may be attached to an error: the name is an
/// RFC 9110 token that is neither a request credential nor reserved, and
/// the value holds no control character other than horizontal tab.
fn check_header(name: &str, value: &str) -> Result<(), InvalidHeader> {
    let token_char = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
    if name.is_empty() || !name.bytes().all(token_char) {
        return Err(InvalidHeader::Name);
    }
    let reserved_prefix = RESERVED_RESPONSE_PREFIXES.iter().any(|prefix| {
        name.len() >= prefix.len()
            && name.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
    });
    if is_never_echo(name)
        || reserved_prefix
        || RESERVED_RESPONSE_HEADERS
            .iter()
            .any(|reserved| reserved.eq_ignore_ascii_case(name))
    {
        return Err(InvalidHeader::Reserved);
    }
    if !value.bytes().all(|b| b == b'\t' || !b.is_ascii_control()) {
        return Err(InvalidHeader::Value);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "r2 put failed: bucket=prod-packs key=packs/abc token=s3cr3t";

    #[test]
    fn internal_error_never_displays_detail() {
        let e = ServerError::internal("storage failure", SECRET);
        assert_eq!(e.code(), Code::Internal);
        assert_eq!(e.public_message(), "storage failure");
        assert_eq!(e.log_detail(), Some(SECRET));
        let display = format!("{e}");
        let debug = format!("{e:?}");
        let alternate = format!("{e:#?}");
        for rendered in [&display, &debug, &alternate] {
            assert!(!rendered.contains("s3cr3t"), "{rendered}");
            assert!(!rendered.contains("prod-packs"), "{rendered}");
        }
        assert_eq!(display, "storage failure");
    }

    #[test]
    fn redacted_prints_only_its_length() {
        let r = Redacted::new("hunter2");
        assert_eq!(format!("{r:?}"), "Redacted(7 bytes)");
        assert!(!format!("{r}").contains("hunter2"));
        assert_eq!(r.expose(), "hunter2");
    }

    #[test]
    fn constructors_set_code_and_message() {
        let cases = [
            (ServerError::invalid_argument("a"), Code::InvalidArgument),
            (ServerError::unauthenticated("a"), Code::Unauthenticated),
            (ServerError::permission_denied("a"), Code::PermissionDenied),
            (ServerError::not_found("a"), Code::NotFound),
            (
                ServerError::failed_precondition("a"),
                Code::FailedPrecondition,
            ),
            (
                ServerError::resource_exhausted("a"),
                Code::ResourceExhausted,
            ),
            (ServerError::aborted_retryable("a"), Code::Aborted),
            (ServerError::unavailable("a"), Code::Unavailable),
            (ServerError::unimplemented("a"), Code::Unimplemented),
            (
                ServerError::new(Code::DeadlineExceeded, String::from("a")),
                Code::DeadlineExceeded,
            ),
        ];
        for (e, code) in cases {
            assert_eq!(e.code(), code);
            assert_eq!(e.public_message(), "a");
            assert_eq!(e.log_detail(), None);
            assert_eq!(e.http_status(), None);
            assert!(e.headers().is_empty() && e.details().is_empty());
        }
    }

    const ALL_CODES: [(Code, &str); 16] = [
        (Code::Canceled, "canceled"),
        (Code::Unknown, "unknown"),
        (Code::InvalidArgument, "invalid_argument"),
        (Code::DeadlineExceeded, "deadline_exceeded"),
        (Code::NotFound, "not_found"),
        (Code::AlreadyExists, "already_exists"),
        (Code::PermissionDenied, "permission_denied"),
        (Code::ResourceExhausted, "resource_exhausted"),
        (Code::FailedPrecondition, "failed_precondition"),
        (Code::Aborted, "aborted"),
        (Code::OutOfRange, "out_of_range"),
        (Code::Unimplemented, "unimplemented"),
        (Code::Internal, "internal"),
        (Code::Unavailable, "unavailable"),
        (Code::DataLoss, "data_loss"),
        (Code::Unauthenticated, "unauthenticated"),
    ];

    #[test]
    fn code_names_match_connect() {
        for (code, name) in ALL_CODES {
            assert_eq!(code.as_str(), name);
        }
    }

    #[test]
    fn only_unavailable_exhausted_and_aborted_are_retryable() {
        let retryable: Vec<_> = ALL_CODES
            .iter()
            .filter(|(c, _)| c.is_retryable())
            .map(|(c, _)| *c)
            .collect();
        assert_eq!(
            retryable,
            [Code::ResourceExhausted, Code::Aborted, Code::Unavailable]
        );
    }

    #[test]
    fn admission_challenge_is_permission_denied_402_with_one_detail() {
        let challenge = bytes::Bytes::from_static(b"\x0a\x03abc");
        let e = ServerError::admission_challenge(challenge.clone())
            .with_header("WWW-Authenticate", "Payment x");
        assert_eq!(e.code(), Code::PermissionDenied);
        assert!(!e.code().is_retryable());
        assert_eq!(e.http_status(), Some(402));
        assert_eq!(
            e.details(),
            &[ErrorDetail {
                type_name: ADMISSION_CHALLENGE_TYPE.to_owned(),
                value: challenge,
            }]
        );
        assert_eq!(
            e.headers(),
            &[("WWW-Authenticate".to_owned(), "Payment x".to_owned())]
        );
        assert_eq!(format!("{e}"), "admission required");
    }

    #[test]
    fn response_shaping_roundtrips() {
        let detail = ErrorDetail {
            type_name: "mkit.transport.v1.PendingVerification".into(),
            value: bytes::Bytes::from_static(b"\x08\x05"),
        };
        let e = ServerError::unavailable("pending verification")
            .with_http_status(503)
            .with_header("Retry-After", "5")
            .with_detail(detail.clone());
        assert_eq!(e.http_status(), Some(503));
        assert_eq!(e.headers(), &[("Retry-After".to_owned(), "5".to_owned())]);
        assert_eq!(e.details(), std::slice::from_ref(&detail));
    }

    #[test]
    fn status_rule_accepts_only_error_statuses_and_402_on_permission_denied() {
        for status in [0, 99, 100, 200, 302, 399, 600, u16::MAX] {
            assert!(!status_allowed(Code::Unavailable, status), "{status}");
        }
        for status in [400, 403, 429, 499, 500, 503, 599] {
            assert!(status_allowed(Code::Unavailable, status), "{status}");
        }
        assert!(status_allowed(Code::PermissionDenied, 402));
        assert!(!status_allowed(Code::ResourceExhausted, 402));
        assert!(!status_allowed(Code::Unavailable, 402));
    }

    #[test]
    fn receipts_pass_through_but_debug_redacts_them() {
        let e = ServerError::admission_challenge(bytes::Bytes::new())
            .with_header("Payment-Receipt", "rcpt-s3cr3t")
            .with_header("PAYMENT-RESPONSE", "resp-s3cr3t")
            .with_header("WWW-Authenticate", "Payment realm=x");
        assert_eq!(e.headers().len(), 3);
        let debug = format!("{e:?}");
        assert!(!debug.contains("s3cr3t"), "{debug}");
        assert!(debug.contains("Payment-Receipt"), "{debug}");
        assert!(debug.contains("Payment realm=x"), "{debug}");
    }

    #[test]
    fn try_with_header_reports_why() {
        let base = || ServerError::unavailable("down");
        for (name, value, why) in [
            ("", "v", InvalidHeader::Name),
            ("Bad Name", "v", InvalidHeader::Name),
            ("X-Colon:", "v", InvalidHeader::Name),
            ("X-Split\r\nSet-Cookie", "v", InvalidHeader::Name),
            ("Authorization", "Bearer x", InvalidHeader::Reserved),
            ("PROXY-AUTHORIZATION", "x", InvalidHeader::Reserved),
            ("cookie", "a=b", InvalidHeader::Reserved),
            ("Payment-Authorization", "x", InvalidHeader::Reserved),
            ("payment-signature", "x", InvalidHeader::Reserved),
            ("Set-Cookie", "a=b", InvalidHeader::Reserved),
            ("Content-Type", "text/html", InvalidHeader::Reserved),
            ("content-length", "0", InvalidHeader::Reserved),
            ("Connect-Protocol-Version", "1", InvalidHeader::Reserved),
            ("Transfer-Encoding", "chunked", InvalidHeader::Reserved),
            ("Connection", "close", InvalidHeader::Reserved),
            ("Host", "evil", InvalidHeader::Reserved),
            ("Keep-Alive", "x", InvalidHeader::Reserved),
            ("TE", "trailers", InvalidHeader::Reserved),
            ("Trailer", "x", InvalidHeader::Reserved),
            ("Upgrade", "h2c", InvalidHeader::Reserved),
            ("X-Ok", "line\r\nSet-Cookie: a=b", InvalidHeader::Value),
            ("X-Ok", "nul\0byte", InvalidHeader::Value),
            ("X-Ok", "del\u{7f}", InvalidHeader::Value),
        ] {
            assert_eq!(
                base().try_with_header(name, value).unwrap_err(),
                why,
                "{name:?}: {value:?}"
            );
        }
        let ok = base()
            .try_with_header("x-mkit-trace!#$%&'*+.^_`|~", "tab\tand space ok")
            .unwrap()
            .try_with_header("Payment-Receipt", "r")
            .unwrap()
            .try_with_header("Contentious", "not a Content-* header")
            .unwrap();
        assert_eq!(ok.headers().len(), 3);
    }

    #[test]
    fn with_header_drops_malformed_input_without_panicking() {
        let e = ServerError::unavailable("down")
            .with_header("Bad Name", "v")
            .with_header("X-Ok", "line\r\nSet-Cookie: a=b")
            .with_header("Retry-After", "5");
        assert_eq!(e.headers(), &[("Retry-After".to_owned(), "5".to_owned())]);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "reserved")]
    fn with_header_reserved_name_fails_debug_assertion() {
        let _ = ServerError::unavailable("down").with_header("Authorization", "Bearer x");
    }
}
