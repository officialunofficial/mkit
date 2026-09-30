use core::time::Duration;
use mkit_core::hash::{Hash, from_hex, to_hex, to_hex_bytes};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::{MARGIN_MS, MAX_LIFETIME_MS, MAX_REQUEST_BYTES, PATH, RetrievalConfig};
use crate::ServerError;

const DOMAIN: &[u8] = b"mkit-scanner-retrieval:v1\n";

/// Raw pack assignment from existing, verified upload-ticket metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackGrant {
    /// Raw pack commitment.
    pub id: Hash,
    /// Exact stored byte count.
    pub length: u64,
    /// Every upload ticket bound to this pack, in request order.
    pub tickets: Vec<Hash>,
}

/// Repository and ticket bindings retained in an authenticated capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    /// Internal namespace routing key.
    pub namespace: String,
    /// Internal repository name.
    pub repo_name: String,
    /// Exact wire repository identity.
    pub repository: String,
    /// Ticket ref; selects the strongly consistent ref shard.
    pub ref_name: String,
    /// Writer that owns the tickets, independent of the scanner signer.
    pub signer: Hash,
    /// Exact ordered raw added pack ids, lengths and bound tickets.
    pub packs: Vec<PackGrant>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Claims {
    pub audience: String,
    pub inspection_id: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub nonce: Hash,
    pub assignment: Assignment,
}

fn mac(secret: &Hash, bytes: &[u8]) -> Hash {
    let mut hash = blake3::Hasher::new_keyed(secret);
    hash.update(DOMAIN);
    hash.update(bytes);
    *hash.finalize().as_bytes()
}

fn decode_hex(text: &str) -> Result<Vec<u8>, ServerError> {
    if !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(super::service::missing());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            Ok((digit(pair[0]) << 4) | digit(pair[1]))
        })
        .collect()
}

impl RetrievalConfig {
    /// Mint a fresh capability for one Inspect attempt. Its stable inspection
    /// id survives retry; the nonce and capability are always freshly minted.
    ///
    /// # Errors
    /// Invalid assignment/timeout, unavailable randomness or encoding.
    pub fn mint(
        &self,
        audience: &str,
        inspection_id: &str,
        assignment: &Assignment,
        timeout: Duration,
        now_ms: u64,
    ) -> Result<mkit_rpc::hooks::InspectRetrieval, ServerError> {
        let timeout_ms =
            u64::try_from(timeout.as_millis()).map_err(|_| super::service::missing())?;
        if timeout_ms == 0
            || timeout_ms > MAX_LIFETIME_MS - MARGIN_MS
            || inspection_id.is_empty()
            || !valid_assignment(assignment)
        {
            return Err(super::service::missing());
        }
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce)
            .map_err(|_| ServerError::unavailable("retrieval unavailable"))?;
        let expires_at_ms = now_ms
            .checked_add(timeout_ms + MARGIN_MS)
            .ok_or_else(super::service::missing)?;
        let claims = Claims {
            audience: audience.to_owned(),
            inspection_id: inspection_id.to_owned(),
            issued_at_ms: now_ms,
            expires_at_ms,
            nonce,
            assignment: assignment.clone(),
        };
        let bytes = serde_json::to_vec(&claims).map_err(|_| super::service::missing())?;
        let key = self.keys.first().ok_or_else(super::service::missing)?;
        let capability = format!(
            "r1.{}.{}.{}",
            key.id,
            to_hex_bytes(&bytes),
            to_hex(&mac(&key.secret, &bytes))
        );
        // Leave room for request JSON, the pack id and range fields.
        if capability.len() > MAX_REQUEST_BYTES - 256 {
            return Err(super::service::missing());
        }
        Ok(mkit_rpc::hooks::InspectRetrieval {
            endpoint_path: Some(PATH.to_owned()),
            capability: Some(capability),
            expires_at_ms: Some(expires_at_ms),
            packs: assignment
                .packs
                .iter()
                .map(|p| mkit_rpc::hooks::InspectPack {
                    id: Some(p.id.to_vec()),
                    length: Some(p.length),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
    }

    pub(crate) fn verify(
        &self,
        token: &str,
        audience: &str,
        now: u64,
    ) -> Result<Claims, ServerError> {
        if token.len() > MAX_REQUEST_BYTES - 256 {
            return Err(super::service::missing());
        }
        let rest = token
            .strip_prefix("r1.")
            .ok_or_else(super::service::missing)?;
        let (prefix, tag) = rest.rsplit_once('.').ok_or_else(super::service::missing)?;
        let (id, body) = prefix
            .rsplit_once('.')
            .ok_or_else(super::service::missing)?;
        let key = self
            .keys
            .iter()
            .find(|key| {
                key.id == id
                    && key
                        .retired_at_ms
                        .is_none_or(|at| now < at.saturating_add(MAX_LIFETIME_MS))
            })
            .ok_or_else(super::service::missing)?;
        let bytes = decode_hex(body)?;
        let tag_text = tag;
        let tag = from_hex(tag).map_err(|_| super::service::missing())?;
        if to_hex(&tag) != tag_text || !bool::from(mac(&key.secret, &bytes).ct_eq(&tag)) {
            return Err(super::service::missing());
        }
        let claims: Claims =
            serde_json::from_slice(&bytes).map_err(|_| super::service::missing())?;
        if claims.audience != audience
            || claims.inspection_id.is_empty()
            || now < claims.issued_at_ms
            || now >= claims.expires_at_ms
            || claims
                .expires_at_ms
                .checked_sub(claims.issued_at_ms)
                .is_none_or(|ttl| ttl == 0 || ttl > MAX_LIFETIME_MS)
            || !valid_assignment(&claims.assignment)
        {
            return Err(super::service::missing());
        }
        Ok(claims)
    }
}

fn valid_assignment(a: &Assignment) -> bool {
    // Seven consumed tickets is the existing advance contract. Packs without
    // file entries are still raw additions and remain in the assignment.
    a.packs.len() <= 7
        && a.packs
            .iter()
            .all(|p| p.length > 0 && !p.tickets.is_empty())
        && a.packs.iter().map(|p| p.tickets.len()).sum::<usize>() <= 7
        && a.packs
            .iter()
            .enumerate()
            .all(|(i, p)| !a.packs[..i].iter().any(|old| old.id == p.id))
        && crate::refs::validate_ref_name(&a.ref_name)
}
