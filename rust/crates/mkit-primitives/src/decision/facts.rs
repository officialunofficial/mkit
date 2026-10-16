//! Authoritative semantic observations, independent of physical storage.
use crate::evidence::{MemberFact, PackSource, RepositoryId, Revision};
use mkit_core::hash::Hash;

/// Logical namespace identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceId(pub [u8; 32]);
/// Logical operation identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationId(pub [u8; 32]);
/// Logical upload ticket identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketId(pub [u8; 32]);
/// Logical reservation identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationId(pub [u8; 32]);
/// Authenticated replay scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayScope(pub Hash);
/// Validated served ref name; the decision owner validates incoming values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefName(pub String);
/// Authoritative observation; unacquired facts use an outer Option.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Observed<T> {
    /// Authoritative absence at an exact revision.
    Absent(Revision),
    /// Exact present fact.
    Present {
        /// Exact observed value.
        value: T,
        /// Logical observation revision.
        revision: Revision,
    },
}
/// Exact ref value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefFact {
    /// Validated served name.
    pub name: RefName,
    /// Current target.
    pub target: Hash,
}
/// Namespace authorization mode.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthorityMode {
    /// Self-certifying namespace.
    SelfCertifying,
    /// Authority-managed namespace.
    Authority,
}
/// Commit-fenced authority observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityFact {
    /// Authorization mode.
    pub mode: AuthorityMode,
    /// Original authorization generation.
    pub generation: Revision,
    /// Generation can be fenced atomically.
    pub ready: bool,
}
/// Scoped authorization grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantFact {
    /// Exact grant identity.
    pub grant: Hash,
    /// Commit-fenced namespace grant epoch.
    pub epoch: Revision,
    /// Presence constraint when authorization depends on it.
    pub presence: Option<bool>,
}
/// Repository lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LifecycleState {
    /// Available repository.
    Active,
    /// Deletion in progress.
    Deleting,
    /// Deleted repository.
    Deleted,
}
/// Repository incarnation and lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleFact {
    /// Repository incarnation.
    pub incarnation: Revision,
    /// Exact lifecycle state.
    pub state: LifecycleState,
}
/// Complete captured publication state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationFact {
    /// Publication generation.
    pub generation: Revision,
    /// Publication sequence.
    pub sequence: u64,
    /// Contiguous cleared prefix.
    pub published_prefix: u64,
    /// Deletion boundary.
    pub deletion_boundary: u64,
    /// Complete published head component.
    pub head: Option<Hash>,
    /// Complete published packmap component.
    pub packmap: Option<Hash>,
}
/// Applicable denial and inspection observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenialFact {
    /// Exact denied object set.
    pub objects: Vec<Hash>,
    /// Exact denied supplier set.
    pub packs: Vec<Hash>,
    /// Exact inspection-held supplier set.
    pub held: Vec<Hash>,
}
/// Applicable ref policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFact {
    /// Intersected allowed signer set.
    pub allowed_signers: Vec<[u8; 32]>,
    /// Ancestry restriction.
    pub fast_forward: bool,
    /// Exact policy revision.
    pub revision: Revision,
}
/// Presence change committed by admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceDelta {
    /// Served ref name.
    pub name: RefName,
    /// Observed presence.
    pub before: bool,
    /// Proposed presence.
    pub after: bool,
}
/// Admission bound to exact proposed effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionFact {
    /// Authenticated operation.
    pub operation: OperationId,
    /// Exact semantic-effect commitment.
    pub effects: Hash,
    /// Every admitted presence change.
    pub presence: Vec<PresenceDelta>,
    /// Applicable reservation.
    pub reservation: Option<ReservationId>,
}
/// Exact charge-window counters and ceilings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountingFact {
    /// Logical accounting scope.
    pub scope: Hash,
    /// Accounting window identity.
    pub window: Revision,
    /// Current charged bytes.
    pub bytes: u64,
    /// Exact byte ceiling.
    pub byte_limit: u64,
    /// Current charged operation count.
    pub operations: u64,
    /// Exact operation ceiling.
    pub operation_limit: u64,
}
/// Exact upload ticket binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketFact {
    /// Destination repository.
    pub repository: RepositoryId,
    /// Destination ref.
    pub name: RefName,
    /// Authenticated operation signer.
    pub signer: [u8; 32],
    /// Bound pack ID, length, and immutable version.
    pub pack: PackSource,
    /// Upload part geometry.
    pub part_bytes: u64,
    /// Creation instant.
    pub created_ms: u64,
    /// Expiry instant.
    pub expires_ms: u64,
    /// Bound reservation.
    pub reservation: ReservationId,
    /// Original authorization generation.
    pub authority: Revision,
    /// Exact upload incarnation or authoritative absence.
    pub upload: Observed<Revision>,
}
/// Only terminal refusal classes permitted for durable replay.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PermanentCode {
    /// `InvalidArgument`.
    InvalidArgument,
    /// `NotFound`.
    NotFound,
    /// `AlreadyExists`.
    AlreadyExists,
    /// `PermissionDenied`.
    PermissionDenied,
    /// `FailedPrecondition`.
    FailedPrecondition,
    /// `OutOfRange`.
    OutOfRange,
    /// Unimplemented.
    Unimplemented,
}
/// Normalized ref response component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefValue {
    /// Served name.
    pub name: RefName,
    /// Exact result value or authoritative absence.
    pub value: Option<Hash>,
}
/// Durable terminal result; retryable or pending results are unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TerminalResult {
    /// Exact accepted ref response.
    Applied(Vec<RefValue>),
    /// Exact conflict ref response.
    Conflict(Vec<RefValue>),
    /// Permanent refusal.
    Rejected(PermanentCode),
}
/// Durable replay state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReplayState {
    /// Reserved operation.
    InFlight {
        /// Whether the supported operation may resume.
        resumable: bool,
    },
    /// Exact terminal result.
    Committed(TerminalResult),
}
/// Replay record bound to authenticated fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayFact {
    /// Signing digest.
    pub fingerprint: Hash,
    /// Recorded envelope expiry.
    pub expires_ms: u64,
    /// Exact replay state.
    pub state: ReplayState,
}
/// Reservation lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReservationFact {
    /// Pending exact operation.
    Pending {
        /// Exact destination.
        repository: RepositoryId,
        /// Authenticated operation.
        operation: OperationId,
        /// Creation instant.
        created_ms: u64,
        /// Expiry instant.
        expires_ms: u64,
    },
    /// Bound to a ticket.
    Ticketed(TicketId),
    /// Settled by a durable accepted result.
    Committed(TerminalResult),
    /// Permanently aborted.
    Aborted(PermanentCode),
}
/// Acquired facts for a pure decision; all unacquired categories stay None.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Destination repository.
    pub repository: RepositoryId,
    /// Acquired ref observations only.
    pub refs: Vec<(RefName, Observed<Hash>)>,
    /// Acquired replay record.
    pub replay: Option<Observed<ReplayFact>>,
    /// Acquired ticket records.
    pub tickets: Vec<(TicketId, Observed<TicketFact>)>,
    /// Acquired reservations.
    pub reservations: Vec<(ReservationId, Observed<ReservationFact>)>,
    /// Commit-fenced authority.
    pub authority: Option<Observed<AuthorityFact>>,
    /// Applicable grant.
    pub grant: Option<Observed<GrantFact>>,
    /// Repository lifecycle.
    pub lifecycle: Option<Observed<LifecycleFact>>,
    /// Exact repository-scoped members.
    pub members: Vec<Observed<MemberFact>>,
    /// Applicable denial and inspection facts.
    pub denial: Option<Observed<DenialFact>>,
    /// Applicable policy.
    pub policy: Option<Observed<PolicyFact>>,
    /// Original admission.
    pub admission: Option<Observed<AdmissionFact>>,
    /// Accounting snapshot.
    pub accounting: Option<Observed<AccountingFact>>,
    /// Complete publication observation.
    pub publication: Option<Observed<PublicationFact>>,
}
