//! Small helpers shared by [`crate::service`] and [`crate::pack`] for
//! converting between the wire's `bytes` fields (32-byte BLAKE3 digests)
//! and [`mkit_core::hash::Hash`].

use connectrpc::ConnectError;
use mkit_core::hash::Hash;

/// Parse a 32-byte digest out of a wire `bytes` field.
///
/// # Errors
///
/// Returns `invalid_argument` if `bytes` is not exactly 32 bytes.
pub(crate) fn hash_from_slice(bytes: &[u8]) -> Result<Hash, ConnectError> {
    <Hash>::try_from(bytes).map_err(|_| {
        ConnectError::invalid_argument(format!(
            "expected a 32-byte digest, got {} bytes",
            bytes.len()
        ))
    })
}
