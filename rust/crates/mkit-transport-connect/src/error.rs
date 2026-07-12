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
