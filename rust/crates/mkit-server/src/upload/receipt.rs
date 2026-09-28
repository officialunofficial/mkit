//! Server-authenticated multipart receipts (STC §7.6, R-104).

use mkit_core::hash::Hash;
use subtle::ConstantTimeEq;

use super::token::TicketKeys;
use crate::error::ServerError;

const VERSION: u8 = 1;
const MAX_TAG: usize = 128;

/// Fields authenticated by a part receipt. The backend tag is opaque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PartReceipt {
    /// Ticket that authorized the part.
    pub ticket_id: Hash,
    /// Zero-based part index.
    pub index: u32,
    /// Non-root BLAKE3 subtree chaining value.
    pub subtree: Hash,
    /// Part byte length.
    pub len: u64,
    /// Backend part identifier.
    pub tag: Vec<u8>,
}

/// Authenticate a successfully committed part with the active key.
pub(crate) fn mint(
    keys: &TicketKeys,
    ticket_id: &Hash,
    index: u32,
    subtree: &Hash,
    len: u64,
    tag: &[u8],
) -> Result<Vec<u8>, ServerError> {
    if tag.len() > MAX_TAG {
        return Err(ServerError::internal(
            "upload part tag exceeds receipt limit",
            tag.len(),
        ));
    }
    let (id, key) = keys.receipt_signing_key();
    let mut out = Vec::with_capacity(2 + id.len() + 32 + 4 + 32 + 8 + 2 + tag.len() + 32);
    out.extend_from_slice(&[VERSION, id.len() as u8]); // validated key id <= 32
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(ticket_id);
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(subtree);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&(tag.len() as u16).to_be_bytes());
    out.extend_from_slice(tag);
    let mac = blake3::keyed_hash(&key, &out);
    out.extend_from_slice(mac.as_bytes());
    Ok(out)
}

/// Verify a receipt under any accepted key, rejecting all malformed bytes
/// with one public error. MAC verification precedes field interpretation.
pub(crate) fn verify(keys: &TicketKeys, bytes: &[u8]) -> Result<PartReceipt, ServerError> {
    let invalid = || ServerError::invalid_argument("invalid upload part receipt");
    let mac_at = bytes.len().checked_sub(32).ok_or_else(invalid)?;
    let (message, mac) = bytes.split_at(mac_at);
    if message.first() != Some(&VERSION) {
        return Err(invalid());
    }
    let id_len = usize::from(*message.get(1).ok_or_else(invalid)?);
    let id = message.get(2..2 + id_len).ok_or_else(invalid)?;
    let key = keys.receipt_verification_key(id).ok_or_else(invalid)?;
    let expected = blake3::keyed_hash(&key, message);
    if !bool::from(expected.as_bytes().as_slice().ct_eq(mac)) {
        return Err(invalid());
    }
    let mut reader = Reader(&message[2 + id_len..]);
    let ticket_id = reader.array()?;
    let index = u32::from_be_bytes(reader.array()?);
    let subtree = reader.array()?;
    let len = u64::from_be_bytes(reader.array()?);
    let tag_len = usize::from(u16::from_be_bytes(reader.array()?));
    if tag_len > MAX_TAG {
        return Err(invalid());
    }
    let tag = reader.take(tag_len)?.to_vec();
    if !reader.0.is_empty() {
        return Err(invalid());
    }
    Ok(PartReceipt {
        ticket_id,
        index,
        subtree,
        len,
        tag,
    })
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], ServerError> {
        let value = self
            .0
            .get(..len)
            .ok_or_else(|| ServerError::invalid_argument("invalid upload part receipt"))?;
        self.0 = &self.0[len..];
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ServerError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ServerError::invalid_argument("invalid upload part receipt"))
    }
}

#[cfg(test)]
#[path = "receipt_tests.rs"]
mod tests;
