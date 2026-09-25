//! Transport-neutral server errors.
//!
//! A [`ServerError`] carries a [`Code`], a public message that is safe to
//! send to any client, and optionally a [`Redacted`] detail for server-side
//! logs only. Bindings map [`Code`] onto Connect or ssh error codes. Backend
//! failures go through [`ServerError::internal`], which fixes the public
//! message so SDK or storage text never reaches a client (issue #794).

use std::borrow::Cow;
use std::fmt;

use crate::telemetry::is_sensitive_header;

/// Error category, one-to-one with the Connect codes the bindings emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Code {
    /// Malformed request: bad ref name, noncanonical field, wrong framing.
    InvalidArgument,
    /// Missing or invalid credentials.
    Unauthenticated,
    /// Authenticated, but not allowed.
    PermissionDenied,
    /// The named ref or pack does not exist.
    NotFound,
    /// A compare-and-swap precondition did not hold.
    FailedPrecondition,
    /// A quota or size limit was hit.
    ResourceExhausted,
    /// A conflicting operation is in flight; the client may retry.
    Aborted,
    /// The backend is temporarily unavailable.
    Unavailable,
    /// The deployment does not support this procedure.
    Unimplemented,
    /// The request ran past its deadline.
    DeadlineExceeded,
    /// A server-side failure.
    Internal,
    /// No more specific category applies.
    Unknown,
}

impl Code {
    /// The Connect protocol's canonical name, e.g. `invalid_argument`. Also
    /// the `code` label value for [`crate::METRIC_REQUESTS`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid_argument",
            Self::Unauthenticated => "unauthenticated",
            Self::PermissionDenied => "permission_denied",
            Self::NotFound => "not_found",
            Self::FailedPrecondition => "failed_precondition",
            Self::ResourceExhausted => "resource_exhausted",
            Self::Aborted => "aborted",
            Self::Unavailable => "unavailable",
            Self::Unimplemented => "unimplemented",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Internal => "internal",
            Self::Unknown => "unknown",
        }
    }
}

/// A typed error detail (Connect `ErrorDetail`): the fully qualified proto
/// message name and its encoded bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorDetail {
    /// Fully qualified proto type name, e.g. `mkit.transport.v1.AdmissionChallenge`.
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
        f.write_str("[redacted]")
    }
}

/// A transport-neutral server error. `Display` shows the public message
/// only; the log detail is [`Redacted`].
#[derive(Debug, Clone, thiserror::Error)]
#[error("{public}")]
pub struct ServerError {
    code: Code,
    public: Cow<'static, str>,
    detail: Option<Redacted>,
    http_status: Option<u16>,
    headers: Vec<(String, String)>,
    details: Vec<ErrorDetail>,
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

    /// [`Code::PermissionDenied`].
    #[must_use]
    pub fn permission_denied(public: impl Into<Cow<'static, str>>) -> Self {
        Self::new(Code::PermissionDenied, public)
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

    /// [`Code::ResourceExhausted`].
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

    /// Set the HTTP status the Connect binding answers with, e.g. 402 for
    /// an admission challenge. A value outside `100..=599` is ignored (and
    /// fails a debug assertion).
    #[must_use]
    pub fn with_http_status(mut self, status: u16) -> Self {
        let valid = (100..=599).contains(&status);
        debug_assert!(valid, "invalid HTTP status {status}");
        if valid {
            self.http_status = Some(status);
        }
        self
    }

    /// Add a response header, e.g. `WWW-Authenticate`. The name must be an
    /// HTTP token and the value free of control characters; a header in
    /// [`crate::SENSITIVE_HEADERS`] is never echoed, so credentials can't
    /// leak through an error. A rejected header is dropped (and fails a
    /// debug assertion).
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let (name, value) = (name.into(), value.into());
        let allowed = header_allowed(&name, &value);
        if allowed {
            self.headers.push((name, value));
        } else {
            // Never log the value: it may be the credential being dropped.
            tracing::warn!(header = ?name, "dropped a sensitive or malformed error header");
        }
        debug_assert!(allowed, "error header is sensitive or malformed");
        self
    }

    /// Attach a typed error detail.
    #[must_use]
    pub fn with_detail(mut self, detail: ErrorDetail) -> Self {
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

    /// Response headers, in insertion order.
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

/// Whether a response header may be attached to an error: the name is an
/// RFC 9110 token that is not in [`crate::SENSITIVE_HEADERS`], and the value
/// holds no control characters other than horizontal tab.
fn header_allowed(name: &str, value: &str) -> bool {
    let token_char = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
    !name.is_empty()
        && name.bytes().all(token_char)
        && !is_sensitive_header(name)
        && value.bytes().all(|b| b == b'\t' || !b.is_ascii_control())
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

    #[test]
    fn code_names_match_connect() {
        assert_eq!(Code::InvalidArgument.as_str(), "invalid_argument");
        assert_eq!(Code::Unauthenticated.as_str(), "unauthenticated");
        assert_eq!(Code::PermissionDenied.as_str(), "permission_denied");
        assert_eq!(Code::NotFound.as_str(), "not_found");
        assert_eq!(Code::FailedPrecondition.as_str(), "failed_precondition");
        assert_eq!(Code::ResourceExhausted.as_str(), "resource_exhausted");
        assert_eq!(Code::Aborted.as_str(), "aborted");
        assert_eq!(Code::Unavailable.as_str(), "unavailable");
        assert_eq!(Code::Unimplemented.as_str(), "unimplemented");
        assert_eq!(Code::DeadlineExceeded.as_str(), "deadline_exceeded");
        assert_eq!(Code::Internal.as_str(), "internal");
        assert_eq!(Code::Unknown.as_str(), "unknown");
    }

    /// Runs `f` and returns its result, or `None` if it panicked. Rejected
    /// headers and statuses fail a debug assertion and are dropped in
    /// release, so the tests accept either outcome but never an echo.
    fn dropped_or_panicked(f: impl FnOnce() -> ServerError) -> Option<ServerError> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).ok()
    }

    #[test]
    fn response_shaping_roundtrips() {
        let detail = ErrorDetail {
            type_name: "mkit.transport.v1.AdmissionChallenge".into(),
            value: bytes::Bytes::from_static(b"\x0a\x03abc"),
        };
        let e = ServerError::new(Code::ResourceExhausted, "payment required")
            .with_http_status(402)
            .with_header("WWW-Authenticate", "Payment x")
            .with_detail(detail.clone());
        assert_eq!(e.http_status(), Some(402));
        assert_eq!(
            e.headers(),
            &[("WWW-Authenticate".to_owned(), "Payment x".to_owned())]
        );
        assert_eq!(e.details(), std::slice::from_ref(&detail));
        assert_eq!(format!("{e}"), "payment required");

        for name in ["Authorization", "cookie", "Payment-Receipt"] {
            if let Some(shaped) =
                dropped_or_panicked(|| e.clone().with_header(name, "Bearer s3cr3t"))
            {
                assert_eq!(shaped.headers(), e.headers(), "{name} must be dropped");
            }
        }
    }

    #[test]
    fn malformed_headers_and_statuses_are_dropped() {
        let base = ServerError::unavailable("down");
        for (name, value) in [
            ("", "v"),
            ("Bad Name", "v"),
            ("X-Split\r\nSet-Cookie", "v"),
            ("X-Ok", "line\r\nSet-Cookie: a=b"),
            ("X-Ok", "nul\0byte"),
        ] {
            if let Some(shaped) = dropped_or_panicked(|| base.clone().with_header(name, value)) {
                assert!(shaped.headers().is_empty(), "{name:?}: {value:?}");
            }
        }
        for status in [0, 99, 600, u16::MAX] {
            if let Some(shaped) = dropped_or_panicked(|| base.clone().with_http_status(status)) {
                assert_eq!(shaped.http_status(), None, "{status}");
            }
        }
        let ok = base.with_header("Retry-After", "5").with_http_status(503);
        assert_eq!(ok.headers().len(), 1);
        assert_eq!(ok.http_status(), Some(503));
    }

    /// The acceptance rule itself, checked without tripping the debug
    /// assertion, so debug-profile CI covers the drop decision too.
    #[test]
    fn header_acceptance_rule() {
        assert!(header_allowed("WWW-Authenticate", "Payment x"));
        assert!(header_allowed(
            "x-mkit-trace!#$%&'*+.^_`|~",
            "tab\tand space ok"
        ));
        assert!(!header_allowed("Authorization", "Bearer x"));
        assert!(!header_allowed("PROXY-AUTHORIZATION", "x"));
        assert!(!header_allowed("", "v"));
        assert!(!header_allowed("Bad Name", "v"));
        assert!(!header_allowed("X-Colon:", "v"));
        assert!(!header_allowed("X-Ok", "a\rb"));
        assert!(!header_allowed("X-Ok", "a\nb"));
        assert!(!header_allowed("X-Ok", "del\u{7f}"));
    }
}
