//! Backend-neutral failures returned by a remote source.

use mkit_core::protocol::{AdmissionRequired, TransportError};
use std::time::Duration;

/// Host scheduling classification. No class causes the library to retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Terminal for this operation; repeating it unchanged cannot be assumed safe.
    Refusal,
    /// An explicitly classified connection, overload, or temporary server failure.
    Transient,
    /// The host must wait for visibility, verification, or perform admission.
    Resumable,
}

/// A raw Connect detail, retained without interpretation or decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteDetail {
    pub type_url: String,
    pub value: Option<String>,
}

/// Remote failure evidence. Headers retain repeated values and raw bytes.
/// Treat messages, details, and headers as untrusted; headers may be sensitive.
#[derive(Debug, Clone)]
pub struct RemoteFailure {
    pub code: String,
    pub message: String,
    pub details: Vec<RemoteDetail>,
    /// Actual HTTP status, independent of the Connect code.
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
}

/// A source failure with enough information for host policy.
///
/// The ordinary transport variants retain their existing display text. A raw
/// channel string is a refusal because it may describe a deterministic failure.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("pack not found on remote")]
    PackNotFound,
    #[error("access denied by remote")]
    AccessDenied,
    #[error("admission configuration: {0}")]
    AdmissionConfiguration(String),
    #[error("HTTPS trust configuration: {0}")]
    TlsConfiguration(String),
    #[error("admission helper failed: {0}")]
    AdmissionHelperFailed(String),
    #[error("remote error: {0}")]
    RemoteError(String),
    #[error("ref CAS precondition failed")]
    RefConflict,
    #[error("invalid ref name: {0}")]
    InvalidRef(String),
    #[error("connection to remote failed")]
    ConnectionFailed,
    #[error("server error (status {status})")]
    ServerError { status: u16 },
    #[error("invalid response from remote")]
    InvalidResponse,
    #[error("protocol error")]
    ProtocolError,
    #[error("payload too large: {0} bytes")]
    PayloadTooLarge(usize),
    #[error("insecure scheme: plain http:// is allowed only for loopback hosts")]
    InsecureScheme,
    #[error("{challenges}")]
    PaymentRequired { challenges: Box<AdmissionRequired> },
    #[error("remote error: verification pending, retry after {retry_after:?}")]
    PendingVerification { retry_after: Duration },
    #[error("remote error: repository membership not yet visible")]
    MembershipNotVisible,
    #[error("remote error: retry after {ms} ms")]
    RetryAfter { ms: u64 },
    #[error("remote error: signing: {0}")]
    Signing(String),
    #[error("remote error: signer refused: {0}")]
    SignerRefused(String),
    #[error("remote error: write vetoed: {0}")]
    Vetoed(String),
    #[error("remote error: reserved request header `{0}`")]
    ReservedHeader(String),
    #[error("remote error: signed request expired before dispatch")]
    EnvelopeExpired,
    #[error("remote error: push deadline expired")]
    Deadline,
    /// Raw Connect evidence survives even for absence and authorization failures.
    #[error("{}", remote_display(.0))]
    Remote(Box<RemoteFailure>),
}

fn remote_display(remote: &RemoteFailure) -> String {
    match remote.code.as_str() {
        "not_found" => "pack not found on remote".to_owned(),
        "unauthenticated" | "permission_denied" => "access denied by remote".to_owned(),
        _ => format!("remote error: {}", remote.message),
    }
}

impl SourceError {
    /// Classify by typed evidence, never by human-readable messages.
    #[must_use]
    pub fn class(&self) -> FailureClass {
        match self {
            Self::PendingVerification { .. }
            | Self::MembershipNotVisible
            | Self::RetryAfter { .. } => FailureClass::Resumable,
            Self::PaymentRequired { challenges } if challenges.reason.is_none() => {
                FailureClass::Resumable
            }
            Self::ConnectionFailed => FailureClass::Transient,
            Self::ServerError { status } if *status >= 500 || *status == 429 => {
                FailureClass::Transient
            }
            Self::Remote(remote)
                if matches!(
                    remote.code.as_str(),
                    "unavailable" | "aborted" | "resource_exhausted"
                ) =>
            {
                FailureClass::Transient
            }
            _ => FailureClass::Refusal,
        }
    }

    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::PackNotFound)
            || matches!(self, Self::Remote(remote) if remote.code == "not_found")
    }

    #[must_use]
    pub fn is_invalid_response(&self) -> bool {
        matches!(self, Self::InvalidResponse)
    }
}

impl From<TransportError> for SourceError {
    fn from(error: TransportError) -> Self {
        match error {
            TransportError::PackNotFound => Self::PackNotFound,
            TransportError::AccessDenied => Self::AccessDenied,
            TransportError::AdmissionConfiguration(value) => Self::AdmissionConfiguration(value),
            TransportError::TlsConfiguration(value) => Self::TlsConfiguration(value),
            TransportError::AdmissionHelperFailed(value) => Self::AdmissionHelperFailed(value),
            TransportError::RemoteError(value) => Self::RemoteError(value),
            TransportError::RefConflict => Self::RefConflict,
            TransportError::InvalidRef(value) => Self::InvalidRef(value),
            TransportError::ConnectionFailed => Self::ConnectionFailed,
            TransportError::ServerError { status } => Self::ServerError { status },
            TransportError::InvalidResponse => Self::InvalidResponse,
            TransportError::ProtocolError => Self::ProtocolError,
            TransportError::PayloadTooLarge(value) => Self::PayloadTooLarge(value),
            TransportError::InsecureScheme => Self::InsecureScheme,
            TransportError::AdmissionRequired(challenges) => Self::PaymentRequired { challenges },
            TransportError::PendingVerification { retry_after } => {
                Self::PendingVerification { retry_after }
            }
            TransportError::MembershipNotVisible => Self::MembershipNotVisible,
            TransportError::RetryAfter { ms } => Self::RetryAfter { ms },
            // Future, unclassified transport errors remain terminal.
            other => Self::RemoteError(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_admission_does_not_request_host_resumption() {
        let required = AdmissionRequired::new(Vec::new(), "pay".into(), Vec::new(), Vec::new())
            .with_reason("helper failed");
        let expected = required.to_string();
        let error = SourceError::from(TransportError::AdmissionRequired(Box::new(required)));
        assert_eq!(error.class(), FailureClass::Refusal);
        assert_eq!(error.to_string(), expected);
        let SourceError::PaymentRequired { challenges } = error else {
            panic!("admission lost its structure")
        };
        assert_eq!(challenges.reason, Some("helper failed"));
    }
}
