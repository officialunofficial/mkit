//! Typed observations, semantic effects, and atomic guard requirements.
//!
//! Unacquired facts are absent from a snapshot, never `Observed::Absent`.
//! The host compares every atomic guard and commits every effect together.
//! Source fences are separate pre-apply checks on each destination attempt.

mod effects;
mod facts;
mod guards;

pub use effects::{
    AcceptanceEffects, AccountingEffect, DurableOutcome, MembershipEffect, PublicationEffect,
    RefEffect, ReplayTransition, ReservationOutcome, ReservationTransition, TicketTransition,
};
pub use facts::{
    AccountingFact, AdmissionFact, AuthorityFact, AuthorityMode, DenialFact, GrantFact,
    LifecycleFact, LifecycleState, MembershipObservation, NamespaceId, Observed, OperationId,
    PermanentCode, PermanentRefusal, PolicyFact, PresenceDelta, PublicationFact, RefFact, RefName,
    RefValue, ReplayFact, ReplayScope, ReplayState, ReservationAbortReason, ReservationAccounting,
    ReservationFact, ReservationId, ReservationTerminal, ReservationTerminalKind, Snapshot,
    TerminalResult, TicketFact, TicketId,
};
pub use guards::{GuardKind, RequiredGuard, RequiredSourceFence};

/// Transient decision outcome; never durable replay.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryReason {
    /// Required input unavailable.
    Unavailable,
    /// Facts changed; reacquire and redecide.
    ChangedFacts,
    /// Nonresumable operation remains in flight.
    InFlight,
}
/// Pure write classification; effects require all guards to commit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteDecision {
    /// Apply all effects atomically.
    Apply(AcceptanceEffects),
    /// Guard and record an exact conflict.
    Conflict {
        /// Exact observed values.
        current: Vec<RefValue>,
        /// Exact optional terminal result.
        replay: Option<TerminalResult>,
        /// Optional reservation settlement.
        reservation: Option<ReservationOutcome>,
    },
    /// Guard and record a permanent refusal.
    Reject {
        /// Permanent refusal class.
        refusal: PermanentRefusal,
        /// Optional durable rejection.
        terminal: Option<TerminalResult>,
        /// Optional reservation settlement.
        reservation: Option<ReservationOutcome>,
    },
    /// Return exact prior result after current envelope checks.
    ReturnRecorded(TerminalResult),
    /// Retry without recording a terminal result.
    Retry(RetryReason),
}
/// Semantic decision class.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecisionClass {
    /// Apply.
    Apply,
    /// Conflict.
    Conflict,
    /// Reject.
    Reject,
    /// `ReturnRecorded`.
    ReturnRecorded,
    /// Retry.
    Retry,
}
/// Privately constructed decision and complete atomic requirements.
///
/// Only a host comparison of all guards followed by one atomic effect commit
/// accepts an operation. A guard failure requires fresh facts and redecision.
/// Collections are bounded and contradiction-checked by the owning decision
/// function; callers cannot manufacture this wrapper.
///
/// ```compile_fail
/// use mkit_primitives::decision::Guarded;
/// let forged = Guarded { decision: (), required: vec![], source_fences: vec![] };
/// ```
#[derive(Debug)]
#[must_use]
pub struct Guarded<D> {
    decision: D,
    required: Vec<RequiredGuard>,
    source_fences: Vec<RequiredSourceFence>,
}
impl<D> Guarded<D> {
    /// Decision whose effects may only be applied with all requirements.
    #[must_use]
    pub const fn decision(&self) -> &D {
        &self.decision
    }
    /// Every required atomic comparison, including authoritative absence.
    #[must_use]
    pub fn required_guards(&self) -> &[RequiredGuard] {
        &self.required
    }
    /// Separate pre-apply fences; these are not destination atomic guards.
    #[must_use]
    pub fn source_fences(&self) -> &[RequiredSourceFence] {
        &self.source_fences
    }
}
