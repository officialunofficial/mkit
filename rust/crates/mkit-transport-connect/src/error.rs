//! Connect-code -> [`TransportError`] mapping (SPEC-TRANSPORT-CONNECT §5),
//! the client-side direction.
//!
//! The mapping table lives in `docs/specs/SPEC-TRANSPORT-CONNECT.md`. This
//! module implements the client-side (Connect code -> `TransportError`)
//! direction — the inverse of the server's table (`mkit-server`'s Connect
//! binding), with [`TransportError::RemoteError`] as the fallback arm for any
//! code the table does not otherwise list.
//!
//! One wrinkle the spec calls out explicitly: `invalid_argument` is raised
//! by two different RPC families for two different reasons — a bad ref name
//! (`ListRefs`/`ReadRef`/`UpdateRef`/`AdvanceRefs`) maps to
//! [`TransportError::InvalidRef`], while a malformed `UploadPack` stream
//! (missing header, out-of-order chunk, byte-count mismatch) maps to
//! [`TransportError::ProtocolError`]. The Connect code alone can't
//! disambiguate, so callers pass an [`ErrorContext`] naming which family
//! they called.
//!
//! A second wrinkle: `connectrpc`'s own client collapses a genuine
//! transport-level failure (DNS, TCP connect, TLS handshake — anything with
//! no [`ConnectError`] in its `source()` chain) into `unavailable`
//! (internally, via a private `map_transport_send_error` helper), the
//! same code a server uses for a real backend-overload response. This
//! module can't tell the two apart either, so both surface as
//! [`TransportError::ServerError`] with a representative status (503) —
//! not [`TransportError::ConnectionFailed`]. This is intentional, not a
//! gap: [`mkit_core::protocol::is_retryable`] treats `ServerError { status:
//! 503 }` exactly like `ConnectionFailed` (both retryable), so retry
//! behavior is identical either way.

use base64::Engine as _;
use buffa::Message as _;
use connectrpc::{ConnectError, ErrorCode};
use mkit_core::protocol::TransportError;

use crate::proto::mkit::transport::v1::PendingVerification;

/// Recognise only a typed `AdvanceRefs` unavailable response. Malformed
/// details deliberately fall back to the ordinary retry ladder.
pub(crate) fn pending_verification_delay(err: &ConnectError) -> Option<std::time::Duration> {
    if err.code != ErrorCode::Unavailable {
        return None;
    }
    let detail = err.details.iter().find(|detail| {
        detail
            .type_url
            .strip_prefix("type.googleapis.com/")
            .unwrap_or(&detail.type_url)
            == "mkit.transport.v1.PendingVerification"
    })?;
    let value = detail.value.as_deref().unwrap_or("");
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(value))
        .ok()?;
    let pending = PendingVerification::decode_from_slice(&bytes).ok()?;
    Some(std::time::Duration::from_millis(u64::from(
        pending.retry_after_ms.unwrap_or(0).clamp(1_000, 60_000),
    )))
}

/// Which RPC family raised the error — needed to disambiguate
/// `invalid_argument` (see module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorContext {
    /// `ListRefs` / `ReadRef` / `UpdateRef` / `AdvanceRefs` / `PackExists` /
    /// `DownloadPack` — RPCs whose `invalid_argument` means "bad ref name or
    /// digest".
    Ref,
    /// `UploadPack` — `invalid_argument` here means "malformed
    /// client-stream protocol" (SPEC-TRANSPORT-CONNECT §6.1).
    Upload,
}

/// Representative HTTP-style status used for
/// [`TransportError::ServerError`] when the Connect code is `unavailable`
/// (5xx-equivalent) but no more specific status is available.
const UNAVAILABLE_STATUS: u16 = 503;

/// Representative status for `resource_exhausted` (429-equivalent).
const RESOURCE_EXHAUSTED_STATUS: u16 = 429;

/// Map a [`ConnectError`] to a [`TransportError`] per
/// SPEC-TRANSPORT-CONNECT §5's inverse mapping.
pub(crate) fn map_connect_error(err: ConnectError, ctx: ErrorContext) -> TransportError {
    let message = || err.message.clone().unwrap_or_default();
    match err.code {
        ErrorCode::NotFound => TransportError::PackNotFound,
        ErrorCode::PermissionDenied | ErrorCode::Unauthenticated => TransportError::AccessDenied,
        ErrorCode::FailedPrecondition => TransportError::RefConflict,
        ErrorCode::InvalidArgument => match ctx {
            ErrorContext::Ref => TransportError::InvalidRef(message()),
            ErrorContext::Upload => TransportError::ProtocolError,
        },
        ErrorCode::ResourceExhausted => TransportError::ServerError {
            status: RESOURCE_EXHAUSTED_STATUS,
        },
        ErrorCode::Unavailable | ErrorCode::Aborted => TransportError::ServerError {
            status: UNAVAILABLE_STATUS,
        },
        _ => TransportError::RemoteError(message()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_error(value: Option<String>) -> ConnectError {
        ConnectError::unavailable("verification pending").with_detail(connectrpc::ErrorDetail {
            type_url: "mkit.transport.v1.PendingVerification".to_owned(),
            value,
            debug: None,
        })
    }

    #[test]
    fn pending_delay_clamps_all_boundaries() {
        for (value, expected) in [
            (None, 1_000),
            (Some(0), 1_000),
            (Some(500), 1_000),
            (Some(5_000), 5_000),
            (Some(120_000), 60_000),
            (Some(u32::MAX), 60_000),
        ] {
            let bytes = buffa::Message::encode_to_vec(&PendingVerification {
                retry_after_ms: value,
                ..Default::default()
            });
            let error = pending_error(Some(
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes),
            ));
            assert_eq!(
                pending_verification_delay(&error),
                Some(std::time::Duration::from_millis(expected))
            );
        }
        assert_eq!(
            pending_verification_delay(&pending_error(None)),
            Some(std::time::Duration::from_millis(1_000))
        );
    }

    #[test]
    fn golden_pending_error_decodes_to_five_seconds() {
        let json = include_str!("../../../tests/golden/transport/pending-verification-error.json");
        let error: ConnectError = serde_json::from_str(json).unwrap();
        assert_eq!(
            pending_verification_delay(&error),
            Some(std::time::Duration::from_secs(5))
        );
    }

    #[test]
    fn malformed_and_other_code_details_are_plain_errors() {
        let mut malformed = pending_error(Some("%%%".to_owned()));
        assert_eq!(pending_verification_delay(&malformed), None);
        malformed.code = ErrorCode::Aborted;
        assert_eq!(pending_verification_delay(&malformed), None);
        let mut other_type = pending_error(None);
        other_type.details[0].type_url = "mkit.transport.v1.SomethingElse".to_owned();
        assert_eq!(pending_verification_delay(&other_type), None);
        let mut prefixed = pending_error(None);
        prefixed.details[0].type_url = PendingVerification::TYPE_URL.to_owned();
        assert!(pending_verification_delay(&prefixed).is_some());
    }

    #[test]
    fn aborted_is_retryable() {
        let err = map_connect_error(
            ConnectError::new(ErrorCode::Aborted, "in flight"),
            ErrorContext::Ref,
        );
        assert!(matches!(err, TransportError::ServerError { status: 503 }));
        assert!(mkit_core::protocol::is_retryable(&err));
    }
}
