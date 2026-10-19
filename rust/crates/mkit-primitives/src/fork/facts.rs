//! Trusted logical observations. None of these types has a wire encoding.
use super::{ForkPlan, ForkRefusal};
use crate::{
    decision::{
        AuthorityFact, GrantFact, LifecycleFact, Observed, OperationId, PublicationFact, RefName,
        ReplayScope, ReservationId,
    },
    evidence::{RepositoryId, Revision},
};
use mkit_core::hash::Hash;

/// Repository visibility in the authorization observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForkVisibility {
    /// Public repository.
    Public,
    /// Private repository.
    Private,
}

/// Exact source visibility and principal-specific read authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SourceAccess {
    /// Authenticated principal whose read permission was observed.
    pub principal: Hash,
    /// Source visibility authorized for the destination operation.
    pub visibility: ForkVisibility,
    /// Revision covering visibility changes.
    pub visibility_revision: Revision,
    /// Revision covering this principal's read authorization.
    pub authorization_revision: Revision,
}

impl SourceAccess {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(
        principal: Hash,
        visibility: ForkVisibility,
        visibility_revision: Revision,
        authorization_revision: Revision,
    ) -> Self {
        Self {
            principal,
            visibility,
            visibility_revision,
            authorization_revision,
        }
    }
}

/// Admitted semantic binding, independent of a signed retry's identity.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForkBinding {
    /// Source repository.
    pub source: RepositoryId,
    /// Source repository incarnation.
    pub source_incarnation: Revision,
    /// Source branch.
    pub branch: RefName,
    /// Complete captured publication, including generation and deletion boundary.
    pub publication: PublicationFact,
    /// Source authorization and visibility used for admission.
    pub source_access: SourceAccess,
    /// Destination repository.
    pub destination: RepositoryId,
    /// New destination membership generation.
    pub destination_generation: Revision,
    /// Requested visibility.
    pub destination_visibility: ForkVisibility,
}

impl ForkBinding {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        source: RepositoryId,
        source_incarnation: Revision,
        branch: RefName,
        publication: PublicationFact,
        source_access: SourceAccess,
        destination: RepositoryId,
        destination_generation: Revision,
        destination_visibility: ForkVisibility,
    ) -> Self {
        Self {
            source,
            source_incarnation,
            branch,
            publication,
            source_access,
            destination,
            destination_generation,
            destination_visibility,
        }
    }
}

/// Original authorization and signed request identity of one admitted attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForkAttempt {
    /// Exact operation identity.
    pub operation: OperationId,
    /// Exact external reservation, or no reservation for default admission.
    pub reservation: Option<ReservationId>,
    /// Authenticated replay scope.
    pub replay: ReplayScope,
    /// Signed request fingerprint.
    pub fingerprint: Hash,
    /// Signed envelope expiry metadata. The host validates ingress; this does
    /// not shorten the independent durable job or reservation lifetime.
    pub expires_ms: u64,
    /// Recorded authority mode and generation.
    pub authority: AuthorityFact,
    /// Recorded grant, if authorization relies on one.
    pub grant: Option<GrantFact>,
    /// Whether every advancing commit supports atomic authority fencing.
    pub authority_fencing: bool,
}

impl ForkAttempt {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        operation: OperationId,
        reservation: Option<ReservationId>,
        replay: ReplayScope,
        fingerprint: Hash,
        expires_ms: u64,
        authority: AuthorityFact,
        grant: Option<GrantFact>,
        authority_fencing: bool,
    ) -> Self {
        Self {
            operation,
            reservation,
            replay,
            fingerprint,
            expires_ms,
            authority,
            grant,
            authority_fencing,
        }
    }
}

/// Complete immutable terminal response, including the admitted source branch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForkResult {
    /// Source branch.
    pub branch: RefName,
    /// Source repository.
    pub source: RepositoryId,
    /// Source publication sequence.
    pub source_sequence: u64,
    /// Source tip.
    pub tip: Hash,
    /// Source packmap head.
    pub packmap: Hash,
    /// Exact inherited pack count.
    pub packs: u64,
    /// Exact inherited bytes.
    pub bytes: u64,
    /// Copied index-entry count.
    pub index_entries: u64,
    /// BLAKE3 of sorted pack IDs, matching the reference result.
    pub pack_digest: Hash,
    /// Destination membership generation.
    pub destination_generation: Revision,
}

impl ForkResult {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        branch: RefName,
        source: RepositoryId,
        source_sequence: u64,
        tip: Hash,
        packmap: Hash,
        packs: u64,
        bytes: u64,
        index_entries: u64,
        pack_digest: Hash,
        destination_generation: Revision,
    ) -> Self {
        Self {
            branch,
            source,
            source_sequence,
            tip,
            packmap,
            packs,
            bytes,
            index_entries,
            pack_digest,
            destination_generation,
        }
    }
}

/// Saved fork terminal result; retries cannot change it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForkTerminal {
    /// Accepted construction; visibility still requires published clearance.
    Accepted(Box<ForkResult>),
    /// Retained permanent failure.
    Refused(ForkRefusal),
}

/// Durable stage or terminal state of the exact job binding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForkJobState {
    /// Construction is not yet accepted.
    Staged {
        /// Number of complete, non-visible staged pack effects.
        packs: u64,
        /// Revision covering all staged effects, including phantom additions.
        revision: Revision,
        /// Logical ordering point of the last staged membership effect.
        last_effect: u64,
    },
    /// Acceptance atomically saved the terminal result and outcome responsibility.
    Terminal(ForkTerminal),
}

/// Exact durable job. A restored plan must be sealed again from trusted facts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForkJob<'a> {
    /// Exact immutable admitted plan.
    pub plan: &'a ForkPlan,
    /// Original admitted request and settlement identity.
    pub attempt: ForkAttempt,
    /// Durable job lifetime; never extended by a retry.
    pub expires_ms: u64,
    /// Exact preparation or saved terminal state.
    pub state: ForkJobState,
}

impl<'a> ForkJob<'a> {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(
        plan: &'a ForkPlan,
        attempt: ForkAttempt,
        expires_ms: u64,
        state: ForkJobState,
    ) -> Self {
        Self {
            plan,
            attempt,
            expires_ms,
            state,
        }
    }
}

/// Authoritative emptiness observation covering refs and every membership row.
///
/// Its enclosing observation revision MUST change on any addition, including an
/// addition outside the rows or page the host happened to read. A page of absent
/// rows is not this fact. Staged rows belong only to the recorded construction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForkEmptiness {
    /// All destination refs.
    pub refs: u64,
    /// All reader-visible destination members.
    pub visible_members: u64,
    /// All staged destination members.
    pub staged_members: u64,
    /// BLAKE3 over all sorted staged pack IDs, computed from the complete set.
    pub staged_pack_digest: Hash,
    /// Owner of every staged member; None means no staged members.
    pub staged_owner: Option<OperationId>,
    /// Whether the destination permits ordinary writes.
    pub writes_enabled: bool,
}

impl ForkEmptiness {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(
        refs: u64,
        visible_members: u64,
        staged_members: u64,
        staged_pack_digest: Hash,
        staged_owner: Option<OperationId>,
        writes_enabled: bool,
    ) -> Self {
        Self {
            refs,
            visible_members,
            staged_members,
            staged_pack_digest,
            staged_owner,
            writes_enabled,
        }
    }
}

/// Exact name registration and any prior visibility declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForkName {
    /// Registered construction owner, or no registered repository.
    pub registered_by: Option<OperationId>,
    /// Prior owner declaration, if any.
    pub declared_visibility: Option<ForkVisibility>,
}

impl ForkName {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(
        registered_by: Option<OperationId>,
        declared_visibility: Option<ForkVisibility>,
    ) -> Self {
        Self {
            registered_by,
            declared_visibility,
        }
    }
}

/// Create/write permission for this request, bound to consistent source visibility.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForkPermission {
    /// Authenticated operation.
    pub operation: OperationId,
    /// Exact admitted source authorization and visibility.
    pub source_access: SourceAccess,
    /// Exact requested destination visibility.
    pub destination_visibility: ForkVisibility,
    /// Permission to create the destination.
    pub create: bool,
    /// Permission to write the destination.
    pub write: bool,
}

impl ForkPermission {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(
        operation: OperationId,
        source_access: SourceAccess,
        destination_visibility: ForkVisibility,
        create: bool,
        write: bool,
    ) -> Self {
        Self {
            operation,
            source_access,
            destination_visibility,
            create,
            write,
        }
    }
}

/// Exact admitted byte charge, already debited when construction was admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForkAdmission<'a> {
    /// Exact immutable plan admitted, including its full pack set.
    pub plan: &'a ForkPlan,
    /// Operation that owns this admission.
    pub operation: OperationId,
    /// Exact external reservation, if admission granted one.
    pub reservation: Option<ReservationId>,
    /// Exact inherited-byte charge supplied to admission.
    pub declared_bytes: u64,
    /// Admission's exact new-to-repository byte count.
    pub new_to_repo_bytes: u64,
    /// Identity of the already applied quota debit, or no applicable debit.
    pub charge: Option<Revision>,
}

impl<'a> ForkAdmission<'a> {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(
        plan: &'a ForkPlan,
        operation: OperationId,
        reservation: Option<ReservationId>,
        declared_bytes: u64,
        new_to_repo_bytes: u64,
        charge: Option<Revision>,
    ) -> Self {
        Self {
            plan,
            operation,
            reservation,
            declared_bytes,
            new_to_repo_bytes,
            charge,
        }
    }
}

/// Authoritative receipt for the admission debit and applicable quota window.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForkQuota {
    /// Operation owning the debit.
    pub operation: OperationId,
    /// Identity of the debit, not a request to debit again.
    pub charge: Revision,
    /// Exact bytes debited.
    pub bytes: u64,
    /// Counter including this debit.
    pub used_bytes: u64,
    /// Applicable byte limit.
    pub byte_limit: u64,
    /// Counter including this operation.
    pub used_operations: u64,
    /// Applicable operation limit.
    pub operation_limit: u64,
}

impl ForkQuota {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(
        operation: OperationId,
        charge: Revision,
        bytes: u64,
        used_bytes: u64,
        byte_limit: u64,
        used_operations: u64,
        operation_limit: u64,
    ) -> Self {
        Self {
            operation,
            charge,
            bytes,
            used_bytes,
            byte_limit,
            used_operations,
            operation_limit,
        }
    }
}

/// Reservation state. Terminal settlement belongs to acceptance, not activation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForkReservation {
    /// Exact pending, protected admission.
    Pending {
        /// Owning operation.
        operation: OperationId,
        /// Exact destination.
        destination: RepositoryId,
        /// Original protected deadline.
        expires_ms: u64,
    },
    /// Already settled; never construct or settle again.
    Settled(ForkTerminal),
    /// A separately granted joining reservation already terminated as a replay race.
    ReplayRace {
        /// Exact original construction owner; a foreign owner refuses replay.
        owner: OperationId,
    },
}

/// Replay state for the authenticated request scope and fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForkReplay {
    /// Bound pending replay slot.
    InFlight {
        /// Exact owning operation.
        operation: OperationId,
        /// Signed request fingerprint.
        fingerprint: Hash,
    },
    /// Exact saved result.
    Recorded {
        /// Signed request fingerprint.
        fingerprint: Hash,
        /// Saved result; no source revalidation may change this result.
        result: ForkTerminal,
    },
}

/// Destination-side facts compared atomically with all acceptance effects.
///
/// Outer None means unacquired; `Observed::Absent` means authoritative absence.
/// Every observation is scoped by `repository` and the exact job/request IDs.
/// The host guards this entire fixed-shape snapshot, including its revisions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForkFacts<'a> {
    /// Exact destination repository.
    pub repository: RepositoryId,
    /// Identity scoping the request-specific observations below.
    pub request: &'a ForkAttempt,
    /// Unique destination apply attempt, changed before every new source fence.
    pub apply_attempt: Revision,
    /// Proposed acceptance ordering point on the host's logical timeline.
    pub acceptance_point: u64,
    /// Durable job observation.
    pub job: Option<Observed<ForkJob<'a>>>,
    /// Authoritative emptiness, not a sampled absence.
    pub emptiness: Option<Observed<ForkEmptiness>>,
    /// Registration and declaration observation.
    pub name: Option<Observed<ForkName>>,
    /// Destination lifecycle or authoritative absence before creation.
    pub lifecycle: Option<Observed<LifecycleFact>>,
    /// Request-specific create/write permission.
    pub permission: Option<Observed<ForkPermission>>,
    /// Current commit-fenced authority mode and generation.
    pub authority: Option<Observed<AuthorityFact>>,
    /// Current grant or authoritative absence.
    pub grant: Option<Observed<GrantFact>>,
    /// Exact admission for the request's reservation.
    pub admission: Option<Observed<ForkAdmission<'a>>>,
    /// Exact already applied admission quota debit.
    pub quota: Option<Observed<ForkQuota>>,
    /// Request reservation, scoped by the supplied attempt.
    pub reservation: Option<Observed<ForkReservation>>,
    /// Request replay slot, scoped by the supplied attempt.
    pub replay: Option<Observed<ForkReplay>>,
}

impl<'a> ForkFacts<'a> {
    /// Facts with no acquired observation: every `Option` is unacquired, which
    /// is never absence. Assign the public fields the host acquired. The struct
    /// is `#[non_exhaustive]`.
    #[must_use]
    pub const fn new(
        repository: RepositoryId,
        request: &'a ForkAttempt,
        apply_attempt: Revision,
        acceptance_point: u64,
    ) -> Self {
        Self {
            repository,
            request,
            apply_attempt,
            acceptance_point,
            job: None,
            emptiness: None,
            name: None,
            lifecycle: None,
            permission: None,
            authority: None,
            grant: None,
            admission: None,
            quota: None,
            reservation: None,
            replay: None,
        }
    }
}

/// Independent source membership checks at the final proof boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForkPackEligibility {
    /// Whether source membership is live.
    pub live: bool,
    /// Whether this pack is published and cleared.
    pub cleared: bool,
    /// Whether an inspection or lifecycle hold prevents reading it.
    pub held: bool,
}

impl ForkPackEligibility {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(live: bool, cleared: bool, held: bool) -> Self {
        Self {
            live,
            cleared,
            held,
        }
    }
}

/// Final proof for one inherited whole pack at the source fence.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForkPackProof {
    /// Exact source-scoped pack identity.
    pub pack: Hash,
    /// Source membership incarnation.
    pub incarnation: Revision,
    /// Source publication membership generation.
    pub generation: Revision,
    /// Live membership revision.
    pub membership: Revision,
    /// Exact immutable descriptor commitment.
    pub descriptor: Hash,
    /// Descriptor/supersession observation revision.
    pub descriptor_revision: Revision,
    /// Current denial observation revision.
    pub denial_revision: Revision,
    /// Complete source membership, clearance, and hold eligibility.
    pub eligibility: ForkPackEligibility,
    /// Whether the pack is currently denied.
    pub denied: bool,
    /// Whether its descriptor has been superseded.
    pub superseded: bool,
}

impl ForkPackProof {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        pack: Hash,
        incarnation: Revision,
        generation: Revision,
        membership: Revision,
        descriptor: Hash,
        descriptor_revision: Revision,
        denial_revision: Revision,
        eligibility: ForkPackEligibility,
        denied: bool,
        superseded: bool,
    ) -> Self {
        Self {
            pack,
            incarnation,
            generation,
            membership,
            descriptor,
            descriptor_revision,
            denial_revision,
            eligibility,
            denied,
            superseded,
        }
    }
}

/// Separate source pre-acceptance fence; never a cross-owner atomic CAS.
///
/// The host obtains this proof after the final staged membership effect and
/// before this destination attempt commits. It checks every pack at this one
/// fence. Source changes ordered after the proof do not invalidate acceptance.
/// Reacquire the proof before each retried destination apply attempt. Logical
/// points and revisions are trusted host observations, not physical timestamps.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FinalForkSourceProof {
    /// Exact destination attempt, preventing stale proof reuse after CAS loss.
    pub apply_attempt: Revision,
    /// Complete staged-effects revision observed by the proof.
    pub staged_revision: Revision,
    /// Logical ordering point of this proof.
    pub proof_point: u64,
    /// Exact source repository.
    pub repository: RepositoryId,
    /// Exact source branch.
    pub branch: RefName,
    /// Exact source repository incarnation and active lifecycle.
    pub lifecycle: Observed<LifecycleFact>,
    /// Complete source publication observation.
    pub publication: Observed<PublicationFact>,
    /// Current principal-specific source authorization and visibility.
    pub access: Observed<SourceAccess>,
    /// False for unreadable, unpublished, or otherwise hidden sources.
    pub readable: bool,
    /// Sorted complete proofs for every inherited pack, including suppliers.
    pub packs: Vec<ForkPackProof>,
}

impl FinalForkSourceProof {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        apply_attempt: Revision,
        staged_revision: Revision,
        proof_point: u64,
        repository: RepositoryId,
        branch: RefName,
        lifecycle: Observed<LifecycleFact>,
        publication: Observed<PublicationFact>,
        access: Observed<SourceAccess>,
        readable: bool,
        packs: Vec<ForkPackProof>,
    ) -> Self {
        Self {
            apply_attempt,
            staged_revision,
            proof_point,
            repository,
            branch,
            lifecycle,
            publication,
            access,
            readable,
            packs,
        }
    }
}
