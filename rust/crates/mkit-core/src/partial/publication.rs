//! Explicit raw-pack upload and append-only conditional ref publication.

use crate::hash::{Hash, hash};
use crate::protocol::{
    AdvanceOutcome, PackKey, RefWriteCondition, SingleAttemptAdvance, TransportError,
};
use crate::refs::validate_ref_name;
use crate::transfer::encode_packlist;

use super::{PartialError, PartialLimits, PartialUpdate};

/// In-memory exchange metadata. It is neither an authorization credential nor
/// a receipt, and has no wire codec. A future adapter must bind these fields
/// to its authenticated request and independently establish repository identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialExchangeContext {
    pub repository: String,
    pub exact_ref: String,
    pub operation_id: [u8; 32],
    pub expected_base: Hash,
    pub update_digest: Hash,
    pub update_length: u64,
}

impl PartialExchangeContext {
    /// Bind the exact MKWU carrier bytes without re-encoding them.
    #[must_use]
    pub fn bind(
        repository: &str,
        exact_ref: &str,
        operation_id: [u8; 32],
        expected_base: Hash,
        update_bytes: &[u8],
    ) -> Self {
        Self {
            repository: repository.to_owned(),
            exact_ref: exact_ref.to_owned(),
            operation_id,
            expected_base,
            update_digest: hash(update_bytes),
            update_length: update_bytes.len() as u64,
        }
    }

    fn validate(&self, bytes: &[u8], update: &PartialUpdate) -> Result<String, PublicationError> {
        if self.repository.is_empty()
            || self.repository.len() > 255
            || self.repository.chars().any(char::is_control)
            || self.exact_ref.len() > 1024
            || !validate_ref_name(&self.exact_ref)
            || self.update_length != bytes.len() as u64
            || self.update_digest != hash(bytes)
            || self.expected_base != *update.base_id()
        {
            return Err(PublicationError::InvalidContext);
        }
        let branch = self
            .exact_ref
            .strip_prefix("refs/heads/")
            .ok_or(PublicationError::InvalidContext)?;
        if !validate_ref_name(branch) {
            return Err(PublicationError::InvalidContext);
        }
        let packmap = format!("refs/mkit/packmap/{branch}");
        if packmap.len() > 1024 || !validate_ref_name(&packmap) {
            return Err(PublicationError::InvalidContext);
        }
        Ok(packmap)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PublicationError {
    #[error("portable update invalid: {0}")]
    Portable(#[from] PartialError),
    #[error("exchange context does not bind the exact update, base, repository, and branch")]
    InvalidContext,
    #[error("packlist encoding failed")]
    Packlist,
}

/// The transport call's factual result. Only `Published` reports a known
/// successful head CAS; `PublicationUnknown` retains uncertainty even if a
/// later read happens to show the candidate as today's head.
#[derive(Debug)]
pub enum PublicationOutcome {
    Published,
    HeadConflict,
    PackmapBusy,
    UnsupportedRecipient,
    Denied(TransportError),
    PrepublicationFailure(TransportError),
    PublicationUnknown(TransportError),
}

/// Upload the exact MKWU raw pack and append one packmap node before moving
/// the expected head. This never uses a complete `ObjectStore`, fetches packs,
/// or plans closure differences. The recipient transport does not perform
/// full-data admission through this generic API.
///
/// Only transports with a truthful one-attempt mutation contract qualify.
/// This is separate from `supports_atomic_advance()` and from `DurableResults`.
pub fn publish_explicit_update<T: SingleAttemptAdvance>(
    transport: &T,
    update_bytes: &[u8],
    portable: &PartialLimits,
    context: &PartialExchangeContext,
) -> Result<PublicationOutcome, PublicationError> {
    let update = PartialUpdate::decode(update_bytes, portable)?;
    let packmap_ref = context.validate(update_bytes, &update)?;
    match transport.read_ref(&context.exact_ref) {
        Ok(Some(current)) if current == context.expected_base => {}
        Ok(_) => return Ok(PublicationOutcome::HeadConflict),
        Err(TransportError::AccessDenied) => {
            return Ok(PublicationOutcome::Denied(TransportError::AccessDenied));
        }
        Err(error) => return Ok(PublicationOutcome::PrepublicationFailure(error)),
    }
    // An existing recipient-owned chain is required. A partial publisher
    // cannot seed the retained base or old history from its selected witness.
    let mut prior = match transport.read_ref(&packmap_ref) {
        Ok(Some(value)) => value,
        Ok(None) => return Ok(PublicationOutcome::UnsupportedRecipient),
        Err(TransportError::AccessDenied) => {
            return Ok(PublicationOutcome::Denied(TransportError::AccessDenied));
        }
        Err(error) => return Ok(PublicationOutcome::PrepublicationFailure(error)),
    };
    let pack_key = PackKey::from_hash(*update.pack_hash());
    match transport.upload_pack(update.pack_bytes(), &pack_key) {
        Ok(()) => {}
        Err(TransportError::AccessDenied) => {
            return Ok(PublicationOutcome::Denied(TransportError::AccessDenied));
        }
        Err(error) => return Ok(PublicationOutcome::PrepublicationFailure(error)),
    }
    // Initial attempt plus at most three retries on an explicit packmap CAS
    // conflict. Every retry extends the newly observed head, never resets it.
    for attempt in 0..=3 {
        let node = encode_packlist(Some(prior), &[*update.pack_hash()])
            .map_err(|_| PublicationError::Packlist)?;
        let node_id = hash(&node);
        match transport.upload_blob(&node, &PackKey::from_hash(node_id)) {
            Ok(()) => {}
            Err(TransportError::AccessDenied) => {
                return Ok(PublicationOutcome::Denied(TransportError::AccessDenied));
            }
            Err(error) => return Ok(PublicationOutcome::PrepublicationFailure(error)),
        }
        match transport.advance_refs_once(
            &context.exact_ref,
            RefWriteCondition::Match(context.expected_base),
            update.candidate_id(),
            &packmap_ref,
            RefWriteCondition::Match(prior),
            &node_id,
        ) {
            Ok(AdvanceOutcome::Committed) => return Ok(PublicationOutcome::Published),
            Ok(AdvanceOutcome::HeadConflict) => return Ok(PublicationOutcome::HeadConflict),
            Ok(AdvanceOutcome::PackmapConflict) if attempt < 3 => {
                prior = match transport.read_ref(&packmap_ref) {
                    Ok(Some(value)) => value,
                    Ok(None) => return Ok(PublicationOutcome::UnsupportedRecipient),
                    Err(TransportError::AccessDenied) => {
                        return Ok(PublicationOutcome::Denied(TransportError::AccessDenied));
                    }
                    Err(error) => return Ok(PublicationOutcome::PrepublicationFailure(error)),
                };
            }
            Ok(AdvanceOutcome::PackmapConflict) => return Ok(PublicationOutcome::PackmapBusy),
            Err(error) => return Ok(PublicationOutcome::PublicationUnknown(error)),
        }
    }
    unreachable!("bounded attempt loop returns on its final iteration")
}
