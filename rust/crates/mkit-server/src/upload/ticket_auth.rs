//! Stateless authentication shared by single-pack and multipart uploads.

use super::token::{TicketClaims, TicketKeys};
use crate::error::ServerError;

/// Verify a ticket token on the business clock and bind it to the caller.
/// Checks audience, repository and signer only; callers check pack/bytes/part fields.
pub(crate) fn verify_ticket(
    keys: &TicketKeys,
    token: &[u8],
    now_ms: u64,
    audience: &str,
    repository: &str,
    signer: &[u8; 32],
) -> Result<TicketClaims, ServerError> {
    let claims = keys.verify(token, now_ms)?;
    claims.check_principal(audience, repository, signer)?;
    Ok(claims)
}
