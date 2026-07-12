//! `TransportError` <-> Connect [`ErrorCode`] mapping, per
//! SPEC-TRANSPORT-CONNECT §5.
//!
//! The mapping is total: every [`TransportError`] variant maps onto exactly
//! one Connect code. A handful of variants are documented in the spec as
//! "not server-raised" (client-observed transport failures like
//! `ConnectionFailed`/`InvalidResponse`, or a client-side scheme concern
//! like `InsecureScheme`) — this server never constructs them, but the
//! match stays exhaustive so a future variant added to `TransportError`
//! fails to compile here instead of silently falling through unmapped;
//! those arms fall back to `unknown`, the same "catch-all" default
//! `RemoteError` already uses.

use connectrpc::ConnectError;
use mkit_core::protocol::TransportError;

/// Map a [`TransportError`] returned by the wrapped [`Transport`] backend
/// onto the Connect error the client sees, per SPEC-TRANSPORT-CONNECT §5's
/// table.
///
/// [`Transport`]: mkit_core::protocol::Transport
#[cfg(feature = "server")]
#[must_use]
pub fn map_transport_error(err: TransportError) -> ConnectError {
    match err {
        TransportError::PackNotFound => ConnectError::not_found(err.to_string()),
        TransportError::AccessDenied => ConnectError::permission_denied(err.to_string()),
        TransportError::RefConflict => ConnectError::failed_precondition(err.to_string()),
        TransportError::InvalidRef(_) => ConnectError::invalid_argument(err.to_string()),
        TransportError::ProtocolError => ConnectError::invalid_argument(err.to_string()),
        TransportError::PayloadTooLarge(_) => ConnectError::resource_exhausted(err.to_string()),
        TransportError::ServerError { status } => {
            if status >= 500 || status == 429 {
                ConnectError::unavailable(err.to_string())
            } else {
                ConnectError::unknown(err.to_string())
            }
        }
        TransportError::ConnectionFailed
        | TransportError::InvalidResponse
        | TransportError::InsecureScheme
        | TransportError::RemoteError(_) => ConnectError::unknown(err.to_string()),
    }
}

// Connect-code <-> [`TransportError`] mapping (SPEC-TRANSPORT-CONNECT §5),
// client-side direction.
//
// The mapping table lives in `docs/specs/SPEC-TRANSPORT-CONNECT.md`. This
// section implements the client-side (Connect code -> `TransportError`)
// direction — the mechanical inverse of the server-side table above, with
// [`TransportError::RemoteError`] as the fallback arm for any code the
// table does not otherwise list.
//
// One wrinkle the spec calls out explicitly: `invalid_argument` is raised
// by two different RPC families for two different reasons — a bad ref name
// (`ListRefs`/`ReadRef`/`UpdateRef`/`AdvanceRefs`) maps to
// [`TransportError::InvalidRef`], while a malformed `UploadPack` stream
// (missing header, out-of-order chunk, byte-count mismatch) maps to
// [`TransportError::ProtocolError`]. The Connect code alone can't
// disambiguate, so callers pass an [`ErrorContext`] naming which family
// they called.
//
// A second wrinkle: `connectrpc`'s own client collapses a genuine
// transport-level failure (DNS, TCP connect, TLS handshake — anything with
// no [`ConnectError`] in its `source()` chain) into `unavailable`
// (internally, via a private `map_transport_send_error` helper), the
// same code a server uses for a real backend-overload response. This
// module can't tell the two apart either, so both surface as
// [`TransportError::ServerError`] with a representative status (503) —
// not [`TransportError::ConnectionFailed`]. This is intentional, not a
// gap: [`mkit_core::protocol::is_retryable`] treats `ServerError { status:
// 503 }` exactly like `ConnectionFailed` (both retryable), so retry
// behavior is identical either way.

use connectrpc::ErrorCode;

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
