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
    /// A fork construction, progress, activation or completion row.
    Fork,
    /// A published-clearance row: the prior publication, the advance, a
    /// retained suffix advance or a dependency witness.
    Clearance,
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
    /// Compare one fork or clearance row by its observation revision and the
    /// primitive's commitment to the fact value.
    ///
    /// The revision is the host's row token; the commitment covers every field
    /// the decision read, so a value that moved without a revision change still
    /// fails the comparison. A host that stores only revisions compares them; a
    /// host that holds the typed fact recomputes the commitment with the
    /// fact's `commitment` method. For a revision-only observation the
    /// commitment is the revision itself.
    Row {
        /// Exact destination (or, for clearance, publication) scope.
        repository: RepositoryId,
        /// Which row.
        row: GuardRow,
        /// Exact observation: the commitment, or authoritative absence.
        expected: Observed<Hash>,
    },
}
/// A fork or clearance row compared by [`RequiredGuard::Row`]. Rows with a
/// typed fact of their own (authority, grant, lifecycle) use the typed guards.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GuardRow {
    /// The exact signed request an acceptance decided.
    ForkRequest,
    /// The durable job: plan, original attempt, lifetime and state.
    ForkJob,
    /// Authoritative destination emptiness.
    ForkEmptiness,
    /// Name registration and visibility declaration.
    ForkName,
    /// Create and write permission.
    ForkPermission,
    /// Admission and its charge.
    ForkAdmission,
    /// The applied quota debit.
    ForkQuota,
    /// The request reservation.
    ForkReservation,
    /// The request replay slot.
    ForkReplay,
    /// The destination apply attempt and acceptance point.
    ForkApply,
    /// Durable progress of an advancing commit.
    ForkProgress,
    /// Authority observed when the job was recorded.
    ForkRecordedAuthority,
    /// Current authority observation.
    ForkAuthority,
    /// Grant epoch observed when the job was recorded.
    ForkRecordedEpoch,
    /// Current grant epoch observation.
    ForkEpoch,
    /// The recorded pending reservation protecting the construction.
    ForkReservationRecorded(super::ReservationId),
    /// The current observation of that reservation.
    ForkReservationCurrent(super::ReservationId),
    /// The lifecycle protection profile of an activation or completion.
    ForkLifecycleProfile,
    /// The retained accepted result, expected result and inherited inventory.
    ForkAccepted,
    /// One inherited membership unit and its live and published witnesses.
    ForkUnit(Hash),
    /// The destination clearance proof for one pack.
    ForkProof(Hash),
    /// The destination denial observation behind that proof.
    ForkDenial(Hash),
    /// The proposed completion cursor, inventory digest and barrier owner.
    ForkCompletion,
    /// The prior publication identity.
    ClearancePrior,
    /// The advance under decision and the moment it is decided at.
    ClearanceChanged(u64),
    /// A retained suffix advance, by sequence.
    ClearanceSuffix(u64),
    /// A dependency or supplier membership witness, by object.
    ClearanceWitness(Hash),
    /// The lifecycle profile of a clearance.
    ClearanceLifecycleProfile,
}
impl GuardRow {
    /// Category of this row.
    #[must_use]
    pub const fn kind(&self) -> GuardKind {
        match self {
            Self::ClearancePrior
            | Self::ClearanceChanged(_)
            | Self::ClearanceSuffix(_)
            | Self::ClearanceWitness(_)
            | Self::ClearanceLifecycleProfile => GuardKind::Clearance,
            _ => GuardKind::Fork,
        }
    }
}
/// Explicit pre-apply published-source exception; repeat before every destination attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedSourceFence {
    /// Source repository.
    pub repository: RepositoryId,
    /// Source ref.
    pub name: RefName,
    /// Complete captured source pair and publication equality.
    pub publication: Observed<PublicationFact>,
    /// Current source-read authorization.
    pub read_authority: Observed<AuthorityFact>,
}
/// A separate pre-apply source check. It is never a destination atomic
/// comparison: repeat it before every destination attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequiredSourceFence {
    /// A published ref pair and the current read authorization.
    Published(Box<PublishedSourceFence>),
    /// The complete final source proof of a fork acceptance.
    Fork(Box<crate::fork::FinalForkSourceProof>),
}
