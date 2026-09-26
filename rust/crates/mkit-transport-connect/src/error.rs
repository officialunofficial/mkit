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

use connectrpc::{ConnectError, ErrorCode};
use mkit_core::protocol::TransportError;

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
        ErrorCode::Unavailable => TransportError::ServerError {
            status: UNAVAILABLE_STATUS,
        },
        _ => TransportError::RemoteError(message()),
    }
}
