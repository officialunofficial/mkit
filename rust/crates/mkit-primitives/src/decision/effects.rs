//! Semantic atomic effect groups, with no physical routing.
use super::facts::{
    OperationId, PublicationFact, RefName, ReplayFact, ReplayScope, ReservationFact, ReservationId,
    ReservationTerminal, TicketFact, TicketId,
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
    /// Exact terminal settlement shared with the durable outcome obligation.
    pub terminal: ReservationTerminal,
}
/// Nonterminal reservation transition, such as binding an upload ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationTransition {
    /// Exact reservation identity.
    pub id: ReservationId,
    /// Next observed lifecycle state; terminal settlement uses `ReservationOutcome`.
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
/// Semantic stored-bytes counter replacement (SPEC-SERVER §6.5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageEffect {
    /// Exact repository counter.
    pub repository: RepositoryId,
    /// Absolute next counter state.
    pub next: super::facts::StorageFact,
}
/// Logical durable operation outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableOutcome {
    /// Authenticated operation.
    pub operation: OperationId,
    /// Delivery idempotency key; each consumed ticket has its own reservation.
    pub reservation: ReservationId,
    /// Exact reservation terminal payload; never a client replay result.
    pub terminal: ReservationTerminal,
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
    /// Terminal reservation settlement, matching its durable outcome by ID/payload.
    pub reservations: Vec<ReservationOutcome>,
    /// Nonterminal reservation transitions; no durable terminal delivery implied.
    pub reservation_transitions: Vec<ReservationTransition>,
    /// Replay replacement.
    pub replay: Option<ReplayTransition>,
    /// Publication transitions.
    pub publication: Vec<PublicationEffect>,
    /// Accounting charges.
    pub accounting: Vec<AccountingEffect>,
    /// Stored-bytes counter replacements.
    pub storage: Vec<StorageEffect>,
    /// Durable outcomes.
    pub outcomes: Vec<DurableOutcome>,
}
