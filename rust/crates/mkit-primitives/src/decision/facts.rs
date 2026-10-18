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
    /// Namespace this observation belongs to; a guard compares it with its scope key.
    pub namespace: NamespaceId,
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
    /// Namespace this observation belongs to; a guard compares it with its scope key.
    pub namespace: NamespaceId,
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
    /// Reservation-derived ticket identity; the row's own key.
    pub ticket: TicketId,
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
    /// Authority generation the ticket was issued under; `None` means fencing is disabled.
    /// It is compared with the generation of the guarded authority observation.
    pub authority_generation: Option<Revision>,
    /// Backend upload-session incarnation, when one was allocated.
    pub upload_session: Option<Vec<u8>>,
}
/// Exact repository stored-bytes counter (SPEC-SERVER §6.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageFact {
    /// Absolute stored pack bytes.
    pub stored_bytes: u64,
    /// Monotonic counter version.
    pub version: u64,
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
/// Exact replayable refusal, with no challenge or transient details.
///
/// The owning decision path must charge and bound `public_message` with
/// `DecisionLimits::public_message_bytes` before producing a guarded result.
/// It preserves the exact public message; it never truncates or regenerates it.
/// This skeleton has no decision entry point accepting untrusted records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermanentRefusal {
    /// Only a permanent replayable transport class.
    pub code: PermanentCode,
    /// Exact original public refusal message, bounded by the decision budget.
    pub public_message: String,
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
    Rejected(PermanentRefusal),
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
    /// Authenticated replay scope this record belongs to; a guard compares it with its scope key.
    pub scope: ReplayScope,
    /// Signing digest.
    pub fingerprint: Hash,
    /// Recorded envelope expiry.
    pub expires_ms: u64,
    /// Exact replay state.
    pub state: ReplayState,
}
/// Stable semantic reservation abort reasons, separate from replay codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReservationAbortReason {
    /// Policy or pre-apply refusal without a more specific reason.
    Unspecified,
    /// A guarded ref expectation failed; tickets remain usable.
    RefConflict,
    /// Original authorization epoch changed.
    EpochMismatch,
    /// A required ticket pack is missing.
    PackMissing,
    /// A concurrent request won the exact replay reservation.
    ReplayRace,
    /// An internal failure prevented the apply.
    Internal,
    /// Reconciliation found an abandoned pending reservation.
    Abandoned,
}
/// Accounting observations carried by a committed reservation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservationAccounting {
    /// Stored bytes attributed to the operation.
    pub bytes_stored: u64,
    /// Pack bytes observed as new to this repository, not an accounting authority.
    pub new_to_repository: u64,
    /// Bytes new to the backing store.
    pub new_to_store: u64,
}
/// Reservation terminal payload, independent of client replay responses.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReservationTerminalKind {
    /// Committed reservation with its exact ref changes and accounting facts.
    Committed {
        /// Ref changes; `None` values denote deletion.
        refs: Vec<RefValue>,
        /// Exact byte observations.
        accounting: ReservationAccounting,
    },
    /// Aborted reservation, including transient pre-apply failure reasons.
    Aborted {
        /// Stable settlement reason.
        reason: ReservationAbortReason,
        /// Safe detail, at most 512 UTF-8 bytes under the server specification;
        /// the owning decision path enforces this before guarded construction.
        detail: String,
    },
    /// An unconsumed ticket expired.
    Expired,
    /// A repository's stored-bytes counter changed; `reservation` names the
    /// counter-change outcome id, never a request reservation (§6.5.1).
    StorageChanged {
        /// Absolute stored-bytes total after the change.
        stored_bytes: u64,
        /// Monotonic counter version after the change.
        version: u64,
    },
}
/// Exact terminal reservation state shared by settlement and durable delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationTerminal {
    /// Repository bound to the original reservation.
    pub repository: RepositoryId,
    /// Explicit business-clock occurrence instant.
    pub occurred_ms: u64,
    /// Exact terminal payload, never a client replay result.
    pub kind: ReservationTerminalKind,
}
/// Reservation lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReservationFact {
    /// Pending admission reservation.
    Pending {
        /// Exact destination.
        repository: RepositoryId,
        /// Creation instant.
        created_ms: u64,
        /// Earliest safe reconciliation instant.
        reconcile_ms: u64,
        /// Write or read admission semantics.
        op: ReservationOp,
    },
    /// Bound to a ticket, without terminal settlement or outcome delivery.
    Ticketed(TicketId),
    /// Terminal state with exact settlement payload.
    Terminal(ReservationTerminal),
}

/// Write or read admission semantics of a pending reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReservationOp {
    /// A directly admitted write or `BeginUpload`.
    Write,
    /// An admitted read.
    Read,
}
/// Keyed repository membership observation, including authoritative absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipObservation {
    /// Exact object key, retained even when the observation is absent.
    pub object: Hash,
    /// Exact present member or authoritative absence revision.
    /// The decision owner checks present object/repository equality with keys.
    pub observed: Observed<MemberFact>,
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
    pub members: Vec<MembershipObservation>,
    /// Applicable denial and inspection facts.
    pub denial: Option<Observed<DenialFact>>,
    /// Applicable policy.
    pub policy: Option<Observed<PolicyFact>>,
    /// Original admission.
    pub admission: Option<Observed<AdmissionFact>>,
    /// Accounting snapshot.
    pub accounting: Option<Observed<AccountingFact>>,
    /// Stored-bytes counter for the destination repository.
    pub storage: Option<Observed<StorageFact>>,
    /// Complete publication observation.
    pub publication: Option<Observed<PublicationFact>>,
}
