//! Exact atomic guards and the separate source pre-apply fence.
use super::facts::{
    AccountingFact, AdmissionFact, AuthorityFact, DenialFact, GrantFact, LifecycleFact,
    NamespaceId, Observed, OperationId, PolicyFact, PublicationFact, RefName, ReplayFact,
    ReplayScope, ReservationFact, ReservationId, StorageFact, TicketFact, TicketId,
};
use crate::evidence::{MemberFact, RepositoryId};
use mkit_core::hash::Hash;
/// Atomic comparison category. Kind-level completeness is weaker than the
/// exact guard check: `MembershipWitness` is a `Membership` kind, `DenialVersion`
/// a `Denial` kind and `DependencyPublication` a `Publication` kind, so hosts
/// must lower the exact guards, not only the kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GuardKind {
    /// Exact observed ref value.
    RefValue,
    /// Observed presence without unnecessary value equality.
    RefPresence,
    /// Exact replay record.
    Replay,
    /// Exact ticket.
    Ticket,
    /// Exact reservation.
    Reservation,
    /// Original authority generation and mode.
    Authority,
    /// Exact grant epoch.
    Grant,
    /// Repository incarnation and lifecycle.
    Repository,
    /// Exact member and supplier witness.
    Membership,
    /// Exact applicable denial and inspection facts.
    Denial,
    /// Exact policy.
    Policy,
    /// Exact original admission.
    Admission,
    /// Exact charge window and counters.
    Accounting,
    /// Exact stored-bytes counter.
    Storage,
    /// Exact publication state.
    Publication,
    /// Absolute business validity bound.
    ValidThrough,
    /// Frozen acceptance record or root digest the host must still hold.
    Binding,
}
/// Every mutable fact used to choose a result or effect.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequiredGuard {
    /// Exact observed ref value.
    RefValue {
        /// Exact destination.
        repository: RepositoryId,
        /// Validated name.
        name: RefName,
        /// Exact observation.
        expected: Observed<Hash>,
    },
    /// Observed presence without unnecessary value equality.
    RefPresence {
        /// Exact destination.
        repository: RepositoryId,
        /// Validated name.
        name: RefName,
        /// Required presence only.
        present: bool,
    },
    /// Compare exact replay fact.
    Replay {
        /// Exact logical scope.
        scope: ReplayScope,
        /// Exact required observation, including authoritative absence.
        expected: Observed<ReplayFact>,
    },
    /// Compare exact ticket fact.
    Ticket {
        /// Exact logical scope.
        id: TicketId,
        /// Exact required observation, including authoritative absence.
        expected: Observed<TicketFact>,
    },
    /// Compare exact reservation fact.
    Reservation {
        /// Exact logical scope.
        id: ReservationId,
        /// Exact required observation, including authoritative absence.
        expected: Observed<ReservationFact>,
    },
    /// Compare exact authority fact.
    Authority {
        /// Exact logical scope.
        namespace: NamespaceId,
        /// Exact required observation, including authoritative absence.
        expected: Observed<AuthorityFact>,
    },
    /// Compare exact grant fact.
    Grant {
        /// Exact logical scope.
        namespace: NamespaceId,
        /// Exact required observation, including authoritative absence.
        expected: Observed<GrantFact>,
    },
    /// Compare exact repository fact.
    Repository {
        /// Exact logical scope.
        id: RepositoryId,
        /// Exact required observation, including authoritative absence.
        expected: Observed<LifecycleFact>,
    },
    /// Compare exact membership fact.
    Membership {
        /// Exact logical scope.
        repository: RepositoryId,
        /// Exact object key, including authoritative absence.
        object: Hash,
        /// Exact required observation, including authoritative absence.
        expected: Observed<MemberFact>,
    },
    /// Compare exact denial fact.
    Denial {
        /// Exact logical scope.
        repository: RepositoryId,
        /// Exact required observation, including authoritative absence.
        expected: Observed<DenialFact>,
    },
    /// Compare exact policy fact.
    Policy {
        /// Exact logical scope.
        repository: RepositoryId,
        /// Exact required observation, including authoritative absence.
        expected: Observed<PolicyFact>,
    },
    /// Compare exact admission fact.
    Admission {
        /// Exact logical scope.
        operation: OperationId,
        /// Exact required observation, including authoritative absence.
        expected: Observed<AdmissionFact>,
    },
    /// Compare exact accounting fact.
    Accounting {
        /// Exact logical scope.
        repository: RepositoryId,
        /// Exact required observation, including authoritative absence.
        expected: Observed<AccountingFact>,
    },
    /// Compare exact stored-bytes counter.
    Storage {
        /// Exact logical scope.
        repository: RepositoryId,
        /// Exact required observation, including authoritative absence.
        expected: Observed<StorageFact>,
    },
    /// Compare exact publication fact.
    Publication {
        /// Exact logical scope.
        repository: RepositoryId,
        /// Exact required observation, including authoritative absence.
        expected: Observed<PublicationFact>,
    },
    /// Compare the explicit validity bound.
    ValidThrough {
        /// Absolute business instant.
        instant_ms: u64,
    },
    /// Compare one repository-scoped membership witness atomically: the
    /// incarnation and the removal version must both still match exactly.
    MembershipWitness {
        /// Exact logical scope.
        repository: RepositoryId,
        /// Membership incarnation.
        generation: u64,
        /// Removal version.
        removal_version: u64,
    },
    /// Compare the one global denial version exactly (not per object).
    DenialVersion {
        /// Exact global denial version.
        version: u64,
    },
    /// Compare a dependency supplier's publication standing: still published
    /// and unheld as observed, or still unpublished or held as observed.
    DependencyPublication {
        /// Exact logical scope.
        repository: RepositoryId,
        /// Relied-on object the supplier provides.
        object: Hash,
        /// Supplier pack the dependency relies on.
        supplier: Hash,
        /// Whether the supplier was published.
        published: bool,
        /// Whether the supplier was held.
        held: bool,
    },
    /// The frozen root the acceptance relied on: the evidence digest, or the
    /// pack's object-set root together with the closure root.
    Binding {
        /// Exact binding digest.
        digest: Hash,
    },
}
/// Explicit pre-apply published-source exception; repeat before every destination attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredSourceFence {
    /// Source repository.
    pub repository: RepositoryId,
    /// Source ref.
    pub name: RefName,
    /// Complete captured source pair and publication equality.
    pub publication: Observed<PublicationFact>,
    /// Current source-read authorization.
    pub read_authority: Observed<AuthorityFact>,
}
