//! Semantic atomic effect groups, with no physical routing.
use super::facts::{
    OperationId, PublicationFact, RefName, ReplayFact, ReplayScope, ReservationFact, ReservationId,
    TerminalResult, TicketFact, TicketId,
};
use crate::evidence::{PackSource, RepositoryId};
use mkit_core::hash::Hash;
/// Semantic ref mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefEffect {
    /// Validated served name.
    pub name: RefName,
    /// New target; None deletes.
    pub target: Option<Hash>,
}
/// Repository membership addition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipEffect {
    /// Destination repository.
    pub repository: RepositoryId,
    /// Verified consumed pack.
    pub pack: PackSource,
}
/// Semantic ticket state replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketTransition {
    /// Exact ticket.
    pub id: TicketId,
    /// Next state; None consumes.
    pub next: Option<TicketFact>,
}
/// Semantic reservation settlement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationOutcome {
    /// Exact reservation.
    pub id: ReservationId,
    /// Exact next state.
    pub next: ReservationFact,
}
/// Atomic replay record replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayTransition {
    /// Authenticated replay scope.
    pub scope: ReplayScope,
    /// Exact record.
    pub next: ReplayFact,
}
/// Semantic publication transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationEffect {
    /// Exact repository.
    pub repository: RepositoryId,
    /// Complete next state.
    pub next: PublicationFact,
}
/// Semantic accounting charge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountingEffect {
    /// Logical charge scope.
    pub scope: Hash,
    /// Byte charge.
    pub bytes: u64,
    /// Operation charge.
    pub operations: u64,
}
/// Logical durable operation outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableOutcome {
    /// Authenticated operation.
    pub operation: OperationId,
    /// Exact terminal result.
    pub result: TerminalResult,
}
/// Semantic effects; no physical keys, routing, or write batches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptanceEffects {
    /// Ref creations, advances, or deletions.
    pub refs: Vec<RefEffect>,
    /// Membership additions.
    pub membership: Vec<MembershipEffect>,
    /// Ticket transitions.
    pub tickets: Vec<TicketTransition>,
    /// Reservation settlement.
    pub reservations: Vec<ReservationOutcome>,
    /// Replay replacement.
    pub replay: Option<ReplayTransition>,
    /// Publication transitions.
    pub publication: Vec<PublicationEffect>,
    /// Accounting charges.
    pub accounting: Vec<AccountingEffect>,
    /// Durable outcomes.
    pub outcomes: Vec<DurableOutcome>,
}
