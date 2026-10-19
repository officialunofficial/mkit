//! Typed observations, semantic effects, and atomic guard requirements.
//!
//! Unacquired facts are absent from a snapshot, never `Observed::Absent`.
//! The host compares every atomic guard and commits every effect together.
//! Source fences are separate pre-apply checks on each destination attempt.
//!
//! # Frozen surface
//!
//! Every step, decision, outcome, refusal and guard-kind enum is
//! `#[non_exhaustive]`, so a host matches with a wildcard arm and makes that arm
//! fail closed. Every fact, request and limit struct a host builds is
//! `#[non_exhaustive]` with a constructor and public fields to assign.
//!
//! ```compile_fail,E0004
//! use mkit_primitives::decision::ClearanceDecision;
//! fn published(decision: &ClearanceDecision) -> bool {
//!     match decision {
//!         ClearanceDecision::AdvancePrefix { .. } => true,
//!         ClearanceDecision::Retain { .. } => false,
//!     }
//! }
//! ```
//!
//! ```compile_fail,E0639
//! use mkit_primitives::{decision::Snapshot, evidence::RepositoryId};
//! let _ = Snapshot { repository: RepositoryId([0; 32]), refs: vec![], replay: None,
//!     tickets: vec![], reservations: vec![], authority: None, grant: None,
//!     lifecycle: None, members: vec![], denial: None, policy: None,
//!     admission: None, accounting: None, storage: None, publication: None,
//!     basis: vec![] };
//! ```
//!
//! ```
//! use mkit_primitives::{decision::{ClearanceDecision, Snapshot}, evidence::RepositoryId};
//! let mut snapshot = Snapshot::new(RepositoryId([0; 32]));
//! snapshot.refs.clear();
//! let published = |decision: &ClearanceDecision| match decision {
//!     ClearanceDecision::AdvancePrefix { .. } => true,
//!     // An unknown future decision must not publish.
//!     _ => false,
//! };
//! assert!(!published(&ClearanceDecision::Retain { published_prefix: 0 }));
//! ```

mod basis;
mod clearance;
pub(crate) mod commit;
mod effects;
#[cfg(test)]
pub(crate) mod fact_harness;
mod facts;
mod guards;
pub mod ref_write;
pub mod ticketed;

pub use basis::{
    AcceptanceBasis, BASIS_DIGEST_DOMAIN, BasisCfg, HostAttestation, MAX_BASIS_DEPENDENCIES,
};
pub use clearance::{
    ClearanceAdvance, ClearanceDecision, ClearanceFacts, ClearanceLifecycle, ClearanceLimits,
    ClearanceMoment, ClearanceState, CombinedAcceptance, DependencyWitness, PriorPublication,
    decide_accept_and_clear, decide_clearance,
};

pub use effects::{
    AcceptanceEffects, AccountingEffect, DurableOutcome, MembershipEffect, PublicationEffect,
    RefEffect, ReplayTransition, ReservationOutcome, ReservationTransition, StorageEffect,
    TicketTransition,
};
pub use facts::{
    AccountingFact, AdmissionFact, AuthorityFact, AuthorityMode, DenialFact, GrantFact,
    LifecycleFact, LifecycleState, MembershipObservation, NamespaceId, Observed, OperationId,
    PermanentCode, PermanentRefusal, PolicyFact, PresenceDelta, PublicationFact, RefFact, RefName,
    RefValue, ReplayFact, ReplayScope, ReplayState, ReservationAbortReason, ReservationAccounting,
    ReservationFact, ReservationId, ReservationOp, ReservationTerminal, ReservationTerminalKind,
    Snapshot, StorageFact, TerminalResult, TicketFact, TicketId,
};
pub use guards::{GuardKind, GuardRow, PublishedSourceFence, RequiredGuard, RequiredSourceFence};

/// Transient decision outcome; never durable replay.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryReason {
    /// Required input unavailable.
    Unavailable,
    /// Facts changed; reacquire and redecide.
    ChangedFacts,
    /// The ref changed after custom admission observed it: the admitted target
    /// or prior presence no longer matches. A ticketed settlement maps this to
    /// a ref conflict; no terminal result is stored.
    AdmittedRefChanged,
    /// A required member is not yet visible in the repository. Retryable inside
    /// the membership window; never a stored result.
    MembershipNotVisible,
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
/// let forged = Guarded { repository: mkit_primitives::evidence::RepositoryId([0; 32]),
///     decision: (), required: vec![], source_fences: vec![] };
/// ```
#[derive(Debug)]
#[must_use]
pub struct Guarded<D> {
    repository: crate::evidence::RepositoryId,
    decision: D,
    required: Vec<RequiredGuard>,
    source_fences: Vec<RequiredSourceFence>,
}
/// The owned parts of a [`Guarded`] decision, for a host that lowers them.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
pub struct Lowering<D> {
    /// Exact destination scope.
    pub repository: crate::evidence::RepositoryId,
    /// Decision whose effects may only be applied with all requirements.
    pub decision: D,
    /// Every required atomic comparison.
    pub required: Vec<RequiredGuard>,
    /// Separate pre-apply fences.
    pub source_fences: Vec<RequiredSourceFence>,
}
impl<D> Guarded<D> {
    /// Assemble a decision of another decision family with its owned guards.
    ///
    /// The caller derives the guards from distinct rows, so no two guards can
    /// share an identity; tests of each family assert it.
    pub(crate) fn from_parts(
        repository: crate::evidence::RepositoryId,
        decision: D,
        required: Vec<RequiredGuard>,
        source_fences: Vec<RequiredSourceFence>,
    ) -> Self {
        Self {
            repository,
            decision,
            required,
            source_fences,
        }
    }
    /// Consume the decision into its owned parts, so effects cannot be taken
    /// without the guards that travel with them.
    pub fn into_lowering(self) -> Lowering<D> {
        Lowering {
            repository: self.repository,
            decision: self.decision,
            required: self.required,
            source_fences: self.source_fences,
        }
    }
    /// Exact destination scope, including decisions with no mutable ref guard.
    #[must_use]
    pub const fn repository(&self) -> crate::evidence::RepositoryId {
        self.repository
    }
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

/// Reference comparison of a decision's guards against the live guards a host
/// derives from its current facts (each facts type offers a `guards` method).
///
/// A guard holds when the live view yields exactly it; `ValidThrough` holds
/// while `now_ms` is within the bound. A live view that contradicts itself
/// holds nothing. This acquires and commits nothing: a real adapter performs
/// the comparison inside its transaction.
#[must_use]
pub fn guards_hold<D>(guarded: &Guarded<D>, live: &[RequiredGuard], now_ms: u64) -> bool {
    live.iter().enumerate().all(|(i, guard)| {
        live[..i]
            .iter()
            .all(|other| ref_write::compatible(other, guard))
    }) && guarded.required_guards().iter().all(|guard| match guard {
        RequiredGuard::ValidThrough { instant_ms } => now_ms <= *instant_ms,
        _ => live.contains(guard),
    })
}
