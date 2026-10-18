//! Pure ticketed-advance and reservation-settlement decisions.
//!
//! A ticketed advance consumes upload tickets and settles their reservations in
//! the same atomic unit as its ref changes (SPEC-SERVER §6.3, §9.3).
//! [`decide_ticketed_advance`] composes the ref decision with ticket,
//! upload-proof, verification, storage, and pending-reservation facts.
//! [`decide_ticket_cleanup`] is the separate defensive abort for a lost ticket
//! pack: it settles only ticket and reservation rows, never a ref.
//! [`decide_reservation_settlement`] is the standalone settlement a host uses
//! for post-failure aborts and reconciliation.
//!
//! No physical key, codec, routing, or transaction callback enters this module.

mod decide;
#[cfg(test)]
mod tests;

pub use decide::{decide_reservation_settlement, decide_ticket_cleanup, decide_ticketed_advance};

use super::{
    Observed, PermanentRefusal, ReservationFact, ReservationId, StorageFact, TicketId,
    ref_write::RefWriteRequest,
};

/// Most upload tickets one advance consumes (SPEC-SERVER §9.3).
pub const MAX_TICKETS_PER_ADVANCE: usize = 7;

/// Exact upload-blob proof the host acquired for one claimed ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UploadProof {
    /// Upload marker and pack blob both present.
    Ready,
    /// Upload marker absent; the upload never completed.
    MarkerMissing,
    /// Marker present but the pack blob absent; the ticket is defensively
    /// aborted by [`decide_ticket_cleanup`].
    PackMissing,
}

/// One ticket the request consumes, in request order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketClaim {
    /// Claimed ticket identity: the reservation-derived id the host supplied.
    pub ticket: TicketId,
    /// Acquired upload proof.
    pub proof: UploadProof,
    /// Whether the pack already counts toward the repository's stored bytes:
    /// its counter marker when counting inline, its membership otherwise.
    /// This advisory observation selects only the outcome's
    /// `new_to_repository` field; it is deliberately unguarded, matching the
    /// reference planner.
    pub counted: bool,
}

/// Batch content-verification result already decided by the host.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerificationVerdict {
    /// Content verification satisfied.
    Satisfied,
    /// Verification remains scheduled; the operation waits and retries.
    Pending,
    /// Verification refused the batch, including a proof arriving too late.
    /// An exact inline pending binding produces its guarded abort obligation;
    /// the host applies that settlement separately without terminal replay.
    Refused(PermanentRefusal),
}

/// Stored-bytes counting disposition of the consuming partition (§6.5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StorageAccounting {
    /// This deployment keeps no stored-bytes counter.
    Disabled,
    /// The counter lives in another partition; fresh markers relay there and
    /// this batch changes no counter state.
    Relay,
    /// The counter is in this batch's partition; fresh packs count inline.
    Inline {
        /// Exact observed repository counter.
        observed: Observed<StorageFact>,
        /// Outcome id of the counter change (`rs:`-derived by the host).
        outcome: ReservationId,
        /// Plan instant recorded on the counter-change outcome.
        occurred_ms: u64,
    },
}

/// Original admission reservation the write settles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingBinding {
    /// Admission reservation identity.
    pub reservation: ReservationId,
    /// Exact admission-written observation the write must still see.
    /// Always `Present` of `ReservationFact::Pending`.
    pub expected: Observed<ReservationFact>,
    /// Plan instant recorded on its terminal row.
    pub occurred_ms: u64,
}

/// Bounded ticketed-advance decision input.
///
/// `write.kind` is `RefWriteKind::Advance` over the canonical
/// `refs/mkit/packmap/<x>`/`refs/heads/<x>` pair whenever `tickets` is
/// non-empty; the wire admits no other ticketed shape (SPEC-TRANSPORT-CONNECT
/// §4). Unticketed pairs keep the ref decision's admitted shapes.
#[derive(Debug, Clone)]
pub struct TicketedAdvanceRequest<'a> {
    /// Embedded ref decision input. Tickets require its `operation` for
    /// durable outcomes and its `signer` for ticket binding.
    pub write: RefWriteRequest<'a>,
    /// Claimed tickets in request order; empty consumes nothing.
    pub tickets: &'a [TicketClaim],
    /// Content-verification verdict for the assembled batch.
    pub verification: VerificationVerdict,
    /// This partition's stored-bytes counting disposition.
    pub storage: StorageAccounting,
    /// Original admission reservation pending settlement.
    pub pending: Option<PendingBinding>,
    /// Trusted authority generation under authorization, when fenced; every
    /// consumed ticket must have been issued under it.
    pub authority_generation: Option<u64>,
}
