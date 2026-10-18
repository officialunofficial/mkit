//! Source-independent construction progress and accepted published clearance.
//!
//! These decisions consume trusted logical snapshots; they acquire no facts.
//! Revisions may commit exact authoritative rows, including absence. The host
//! scopes them to the actual job and compares every returned guard atomically.
//! A destination denial proof is trusted evidence of completed acquisition,
//! not a boolean permission invented by this module. Its provenance, denial
//! coverage, and any physical authority permit remain host duties. Lifecycle
//! protection is explicit: managed profiles supply acquired lifecycle facts.
//! Current source state is deliberately absent: acceptance fixed the result.

use super::{ForkRefusal, ForkResult, ForkWithheld};
use crate::decision::{LifecycleFact, LifecycleState, Observed};
use crate::error::{BoundedDetail, Failure, FailureCode, Location};
use crate::evidence::{RepositoryId, Revision};
use mkit_core::hash::{Hash, Hasher};

/// Logical construction stage, independent of a driver's physical phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkAdvancePhase {
    /// Preparation, including the final acceptance proof.
    Preparing,
    /// Terminal success recorded; published clearance remains pending.
    Accepted,
    /// Clearance finished; no further advancing effect is authorized.
    Complete,
    /// Terminal refusal; destination remains inert.
    Failed,
}
/// Exact expected durable checkpoint. Its revision covers the original job row,
/// including omitted driver cursor data; proposed progress is separate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkProgress {
    /// Logical phase.
    pub phase: ForkAdvancePhase,
    /// Next unit recorded by this durable checkpoint.
    pub cursor: u64,
    /// Subunit recorded by this durable checkpoint.
    pub part: u16,
    /// Exact job revision, including immutable binding and all progress fields.
    pub revision: Revision,
}
/// Acquired authoritative observation. Missing acquisition cannot be represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkObservation {
    /// Authoritative absence; the host must guard absence at the effect boundary.
    Absent,
    /// Exact present logical row commitment.
    Present(Revision),
}
/// An enabled grant-epoch fence; inner absence is an authoritative observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkEpochFence {
    /// Recorded epoch observation.
    pub recorded: ForkObservation,
    /// Current epoch observation.
    pub current: ForkObservation,
}
/// Exact original reservation protection before acceptance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkReservationFence {
    /// Exact original reservation identity; never a joining request's reservation.
    pub reservation: crate::decision::ReservationId,
    /// Recorded pending reservation revision.
    pub expected: Revision,
    /// Current pending reservation revision, or authoritative absence.
    pub current: ForkObservation,
}
/// Fixed-shape snapshot needed by every advancing coordinator commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkAdvanceFacts {
    /// Original immutable operation binding.
    pub binding: Hash,
    /// Exact destination scope.
    pub destination: RepositoryId,
    /// Exact durable progress.
    pub progress: ForkProgress,
    /// Original authority observation, including absence.
    pub recorded_authority: ForkObservation,
    /// Current authority observation, including absence.
    pub authority: ForkObservation,
    /// Enabled epoch fence; None means authorization did not depend on a grant.
    pub grant_epoch: Option<ForkEpochFence>,
    /// Original admission protection; absent for default admission.
    pub reservation: Option<ForkReservationFence>,
    /// Inclusive construction eligibility bound at phase start.
    /// This is not a commit deadline. Accepted clearance ignores this bound.
    pub construction_expires_ms: u64,
}
/// Fine-grained host mapping preserves authority-before-epoch precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkAdvanceRefusal {
    /// Authority changed from the recorded observation.
    AuthorityMoved,
    /// Grant epoch changed from the recorded observation.
    EpochMoved,
    /// Original construction lifetime elapsed.
    Expired,
    /// Exact original pending reservation is no longer present.
    ReservationSettled,
}
impl ForkAdvanceRefusal {
    /// Stable refusal category; host mappings retain authority and epoch detail.
    #[must_use]
    pub const fn code(self) -> FailureCode {
        match self {
            Self::AuthorityMoved | Self::EpochMoved => FailureCode::ForkPermissionDenied,
            Self::Expired => FailureCode::ForkExpired,
            Self::ReservationSettled => FailureCode::ForkReservationSettled,
        }
    }
}
/// Progress permission; no variant creates or settles a terminal outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkAdvanceDecision {
    /// One advancing commit may proceed under all guards.
    Advance,
    /// Terminal state; no advancement is permitted.
    Terminal,
    /// Before acceptance this may terminate; after acceptance it only defers clearance.
    Refuse(ForkAdvanceRefusal),
}
/// Private permission bound to the complete borrowed snapshot.
#[derive(Debug)]
#[must_use]
pub struct GuardedForkAdvance<'a> {
    decision: ForkAdvanceDecision,
    facts: &'a ForkAdvanceFacts,
    evaluated_at_ms: u64,
}
impl<'a> GuardedForkAdvance<'a> {
    /// Decision requiring every returned comparison.
    #[must_use]
    pub const fn decision(&self) -> ForkAdvanceDecision {
        self.decision
    }
    /// Exact guards to lower into the coordinator atomic unit.
    #[must_use]
    pub const fn required_guards(&self) -> &'a ForkAdvanceFacts {
        self.facts
    }
    /// Host-supplied phase-start time used to evaluate construction eligibility.
    /// It is not a deadline to lower into a later commit.
    #[must_use]
    pub const fn evaluated_at_ms(&self) -> u64 {
        self.evaluated_at_ms
    }
    /// Compare exact acquired facts at the host's atomic boundary.
    /// Construction eligibility was sampled at phase start; independently
    /// required reservation, authority, and physical apply fences still apply.
    #[must_use]
    pub fn matches(&self, current: &ForkAdvanceFacts) -> bool {
        self.facts == current
    }
}
/// Compare already acquired authority observations before any progress work.
/// The epoch is compared only where original authorization depended on it.
#[must_use]
pub fn decide_fork_authority(
    recorded: ForkObservation,
    current: ForkObservation,
    epoch: Option<&ForkEpochFence>,
) -> Option<ForkAdvanceRefusal> {
    if recorded != current {
        Some(ForkAdvanceRefusal::AuthorityMoved)
    } else if epoch.is_some_and(|e| e.recorded != e.current) {
        Some(ForkAdvanceRefusal::EpochMoved)
    } else {
        None
    }
}
/// Decide an advancing coordinator commit from exact already acquired facts.
/// `now_ms` is the sampled phase-start time. Construction expiry controls
/// eligibility to start that phase, not the later commit time. The host retains
/// its independently required commit deadlines and exact acquired-fact guards.
/// Terminal jobs return before fence checks, matching immutable replay semantics.
#[must_use = "compare every required guard before advancing"]
pub fn decide_fork_advance(facts: &ForkAdvanceFacts, now_ms: u64) -> GuardedForkAdvance<'_> {
    let phase = facts.progress.phase;
    let decision = if matches!(phase, ForkAdvancePhase::Complete | ForkAdvancePhase::Failed) {
        ForkAdvanceDecision::Terminal
    } else if let Some(reason) = decide_fork_authority(
        facts.recorded_authority,
        facts.authority,
        facts.grant_epoch.as_ref(),
    ) {
        ForkAdvanceDecision::Refuse(reason)
    } else if phase == ForkAdvancePhase::Preparing && now_ms > facts.construction_expires_ms {
        ForkAdvanceDecision::Refuse(ForkAdvanceRefusal::Expired)
    } else if phase == ForkAdvancePhase::Preparing
        && facts
            .reservation
            .as_ref()
            .is_some_and(|r| r.current != ForkObservation::Present(r.expected))
    {
        ForkAdvanceDecision::Refuse(ForkAdvanceRefusal::ReservationSettled)
    } else {
        ForkAdvanceDecision::Advance
    };
    GuardedForkAdvance {
        decision,
        facts,
        evaluated_at_ms: now_ms,
    }
}
/// Exact semantic membership witness. No storage encoding is specified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkWitness {
    /// Destination membership generation.
    pub generation: Revision,
    /// Initial publication sequence.
    pub sequence: u64,
    /// Published membership flag.
    pub published: bool,
    /// Hold flag; a foreign held witness is never replaced.
    pub held: bool,
    /// Inherited packmap head boundary flag.
    pub boundary: bool,
}
/// Distinguishes the first read from the read after a failed absent-row CAS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkPairContext {
    /// Ordinary initial observation.
    Initial,
    /// Re-read after another actor defeated the absent-row comparison.
    AfterGuardLoss,
}
/// One exact inherited membership unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkMembershipUnit {
    /// Pack in the immutable accepted inventory.
    pub pack: Hash,
    /// Exact job revision committing the immutable accepted inventory and pack identity.
    pub inherited_revision: Revision,
    /// Required exact witness.
    pub expected: ForkWitness,
    /// Current live witness.
    pub live: Option<ForkWitness>,
    /// Current published witness.
    pub published: Option<ForkWitness>,
    /// Why this pair was acquired.
    pub context: ForkPairContext,
}
/// Destination lifecycle profile and exact managed protection.
/// Profiles without lifecycle transitions declare that limitation explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForkLifecycleProtection {
    /// Host profile offers no repository lifecycle transitions.
    NotOffered,
    /// Host profile offers lifecycle transitions and must fence exact current facts.
    Managed {
        /// Repository incarnation bound to this construction.
        expected_incarnation: Revision,
        /// Acquired lifecycle and revision; None means acquisition unavailable.
        current: Option<Observed<LifecycleFact>>,
    },
}
fn lifecycle_available(protection: &ForkLifecycleProtection) -> Result<bool, Failure> {
    match protection {
        ForkLifecycleProtection::NotOffered => Ok(true),
        ForkLifecycleProtection::Managed {
            expected_incarnation,
            current,
        } => {
            match current
                .as_ref()
                .ok_or_else(|| fail(FailureCode::UnavailableInput))?
            {
                Observed::Present { value, .. } => Ok(value.incarnation == *expected_incarnation
                    && value.state == LifecycleState::Active),
                Observed::Absent(_) => Ok(false),
            }
        }
    }
}
/// Trusted completed destination denial acquisition.
///
/// The host attests current denial eligibility for this precise
/// unit, including descriptor/seal/dependency checks required by its profile.
/// This evidence is source-independent, must be renewed after its deadline,
/// and must be discharged by the host's actual publication proof/fence protocol.
/// Comparing these fields alone does not verify acquisition provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkClearanceProof {
    /// Exact destination.
    pub destination: RepositoryId,
    /// Exact operation binding.
    pub binding: Hash,
    /// Job revision for which acquisition was performed.
    pub progress_revision: Revision,
    /// Exact inherited pack.
    pub pack: Hash,
    /// Host logical application attempt, binding the proof to its fence protocol.
    pub apply_attempt: Revision,
    /// Last inclusive application time of this proof.
    pub valid_through_ms: u64,
}
/// Borrowed fixed-shape activation facts; no complete graph is reconstructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkActivationFacts<'a> {
    /// Explicit lifecycle profile and any exact acquired managed facts.
    pub lifecycle: ForkLifecycleProtection,
    /// Exact current progress and authority comparisons.
    pub advance: &'a ForkAdvanceFacts,
    /// Result recomputed from the immutable retained job fields.
    pub expected_result: &'a ForkResult,
    /// Saved terminal acceptance result, or authoritative absence.
    pub accepted_result: Option<&'a ForkResult>,
    /// Complete sorted unique pack IDs retained by immutable acceptance.
    pub inherited_packs: &'a [Hash],
    /// One inherited membership unit.
    pub unit: &'a ForkMembershipUnit,
    /// Acquired current destination proof; None means not acquired.
    pub proof: Option<&'a ForkClearanceProof>,
}
/// Explicit work and string ceilings for both borrowed result comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkActivationLimits {
    /// Maximum number of retained inherited packs.
    pub packs: u64,
    /// Maximum bytes of each retained branch name.
    pub branch_bytes: u64,
    /// Comparison budget, charged for both branch names and fixed facts.
    pub work: u64,
}
/// Membership activation permission. No variant changes terminal acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkActivationDecision {
    /// Install both absent rows atomically with exact absence guards.
    Install,
    /// Both witnesses already match exactly; repeat no effects.
    Replay,
    /// Partial identical pair after a guard loss; retry without replacing rows.
    RetryPartial,
    /// Current authority prevents advancement; retain accepted result.
    Defer(ForkAdvanceRefusal),
    /// A destination fact withholds visibility; the accepted result is unchanged.
    Withhold(ForkWithheld),
    /// Exact binding, terminal state, or foreign witness prevents activation.
    Refuse(ForkRefusal),
}
/// Private activation permission with the entire snapshot and proof fence.
#[derive(Debug)]
#[must_use]
pub struct GuardedForkActivation<'a> {
    decision: ForkActivationDecision,
    facts: &'a ForkActivationFacts<'a>,
    valid_through_ms: u64,
}
impl<'a> GuardedForkActivation<'a> {
    /// Membership-only decision requiring all guards and host proof duties.
    #[must_use]
    pub const fn decision(&self) -> ForkActivationDecision {
        self.decision
    }
    /// Exact borrowed facts to compare at the effect boundary.
    #[must_use]
    pub const fn required_guards(&self) -> &'a ForkActivationFacts<'a> {
        self.facts
    }
    /// Inclusive proof deadline.
    #[must_use]
    pub const fn valid_through_ms(&self) -> u64 {
        self.valid_through_ms
    }
    /// Exact comparison. Does not implement the host's proof protocol.
    #[must_use]
    pub fn matches(&self, current: &ForkActivationFacts<'_>, now_ms: u64) -> bool {
        self.facts == current && now_ms <= self.valid_through_ms
    }
}
fn fail(code: FailureCode) -> Failure {
    Failure {
        code,
        location: Location::default(),
        detail: BoundedDetail::None,
    }
}
fn check_activation_inventory(facts: &ForkActivationFacts<'_>) -> Result<(), Failure> {
    if facts.inherited_packs.windows(2).any(|p| p[0] >= p[1]) {
        return Err(fail(FailureCode::InvalidResponse));
    }
    let mut digest = Hasher::new();
    for pack in facts.inherited_packs {
        digest.update(pack);
    }
    if facts.unit.inherited_revision != facts.advance.progress.revision
        || facts.inherited_packs.len() as u64 != facts.expected_result.packs
        || digest.finalize() != facts.expected_result.pack_digest
        || facts
            .inherited_packs
            .binary_search(&facts.unit.pack)
            .is_err()
    {
        return Err(fail(FailureCode::InvalidResponse));
    }
    Ok(())
}
/// Decide one membership installation after terminal acceptance.
/// The selected pack must belong to accepted inventory. Serial or wave
/// scheduling and installing the packmap head last remain host obligations.
///
/// # Errors
/// Bounded comparisons fail with `ResourceLimit`; missing acquired proof is
/// `UnavailableInput`; mismatched proof scope is `InvalidResponse`. Proof
/// expiration or missing managed lifecycle acquisition is retryable
/// `UnavailableInput`. These errors create no effects.
pub fn decide_fork_activation<'a>(
    facts: &'a ForkActivationFacts<'a>,
    now_ms: u64,
    limits: ForkActivationLimits,
) -> Result<GuardedForkActivation<'a>, Failure> {
    check_result_bounds(facts.expected_result, facts.accepted_result, limits)?;
    let count = facts.inherited_packs.len() as u64;
    let work = count
        .checked_mul(33)
        .and_then(|n| n.checked_add(facts.expected_result.branch.0.len() as u64))
        .and_then(|n| n.checked_add(facts.accepted_result.map_or(0, |r| r.branch.0.len() as u64)))
        .and_then(|n| n.checked_add(64));
    if count > limits.packs || work.is_none_or(|n| n > limits.work) {
        return Err(fail(FailureCode::ResourceLimit));
    }
    let early = if facts.advance.progress.phase != ForkAdvancePhase::Accepted
        || facts.accepted_result != Some(facts.expected_result)
    {
        Some(ForkActivationDecision::Refuse(ForkRefusal::BindingMismatch))
    } else if let ForkAdvanceDecision::Refuse(reason) =
        decide_fork_advance(facts.advance, now_ms).decision()
    {
        Some(ForkActivationDecision::Defer(reason))
    } else {
        None
    };
    if let Some(decision) = early {
        return Ok(GuardedForkActivation {
            decision,
            facts,
            valid_through_ms: u64::MAX,
        });
    }
    if !lifecycle_available(&facts.lifecycle)? {
        return Ok(GuardedForkActivation {
            decision: ForkActivationDecision::Withhold(ForkWithheld::LifecycleUnavailable),
            facts,
            valid_through_ms: u64::MAX,
        });
    }
    check_activation_inventory(facts)?;
    let proof = facts
        .proof
        .ok_or_else(|| fail(FailureCode::UnavailableInput))?;
    if proof.destination != facts.advance.destination
        || proof.binding != facts.advance.binding
        || proof.progress_revision != facts.advance.progress.revision
        || proof.pack != facts.unit.pack
    {
        return Err(fail(FailureCode::InvalidResponse));
    }
    if now_ms > proof.valid_through_ms {
        return Err(fail(FailureCode::UnavailableInput));
    }
    let unit = facts.unit;
    let decision = if unit.expected.generation != facts.expected_result.destination_generation
        || unit.expected.sequence != 0
        || !unit.expected.published
        || unit.expected.held
        || unit.expected.boundary != (unit.pack == facts.expected_result.packmap)
    {
        return Err(fail(FailureCode::InvalidResponse));
    } else if unit.live == Some(unit.expected) && unit.published == Some(unit.expected) {
        ForkActivationDecision::Replay
    } else if unit.live.is_none() && unit.published.is_none() {
        if unit.context == ForkPairContext::Initial {
            ForkActivationDecision::Install
        } else {
            ForkActivationDecision::RetryPartial
        }
    } else if unit.context == ForkPairContext::AfterGuardLoss
        && unit.live.is_none_or(|w| w == unit.expected)
        && unit.published.is_none_or(|w| w == unit.expected)
    {
        ForkActivationDecision::RetryPartial
    } else {
        ForkActivationDecision::Refuse(ForkRefusal::DestinationNotEmpty)
    };
    Ok(GuardedForkActivation {
        decision,
        facts,
        valid_through_ms: proof.valid_through_ms,
    })
}

/// Final coordinator clearance facts after all membership write/check units.
/// No new membership is written by this decision, so it needs no new pack proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkCompletionFacts<'a> {
    /// Explicit lifecycle profile and any exact acquired managed facts.
    pub lifecycle: ForkLifecycleProtection,
    /// Exact job and current authority observations.
    pub advance: &'a ForkAdvanceFacts,
    /// Result recomputed from retained immutable job fields.
    pub expected_result: &'a ForkResult,
    /// Saved terminal acceptance result.
    pub accepted_result: Option<&'a ForkResult>,
    /// Proposed next cursor after completed membership write/check units.
    /// This may advance beyond the exact durable checkpoint in `advance`.
    pub completed_cursor: u64,
    /// Proposed subunit; completion requires no remaining half-unit.
    pub completed_part: u16,
    /// Count of inherited packs whose write and subsequent check completed.
    pub completed_packs: u64,
    /// Digest of that complete retained inherited inventory.
    pub completed_digest: Hash,
    /// Required exact barrier owner to compare atomically, not an acquired row.
    pub expected_barrier_owner: Hash,
}
/// Final coordinator action; never creates or settles a terminal outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkCompletionDecision {
    /// Record clearance completion and remove only the exactly owned barrier.
    Complete,
    /// Already complete; repeat no effects.
    Replay,
    /// Authority movement withholds completion without changing acceptance.
    Defer(ForkAdvanceRefusal),
    /// A destination fact withholds completion without changing acceptance.
    Withhold(ForkWithheld),
    /// Exact acceptance, progress, or barrier ownership did not match.
    Refuse(ForkRefusal),
}
/// Private permission to finish the published clearance under exact guards.
#[derive(Debug)]
#[must_use]
pub struct GuardedForkCompletion<'a> {
    decision: ForkCompletionDecision,
    facts: &'a ForkCompletionFacts<'a>,
}
impl<'a> GuardedForkCompletion<'a> {
    /// Coordinator-only completion decision.
    #[must_use]
    pub const fn decision(&self) -> ForkCompletionDecision {
        self.decision
    }
    /// Exact complete snapshot to compare atomically.
    #[must_use]
    pub const fn required_guards(&self) -> &'a ForkCompletionFacts<'a> {
        self.facts
    }
    /// Reference comparison; never substitutes for the host's atomic unit.
    #[must_use]
    pub fn matches(&self, current: &ForkCompletionFacts<'_>) -> bool {
        self.facts == current
    }
}
fn check_result_bounds(
    expected: &ForkResult,
    accepted: Option<&ForkResult>,
    limits: ForkActivationLimits,
) -> Result<(), Failure> {
    let expected_len = expected.branch.0.len() as u64;
    let accepted_len = accepted.map_or(0, |r| r.branch.0.len() as u64);
    if expected_len > limits.branch_bytes
        || accepted_len > limits.branch_bytes
        || expected_len
            .checked_add(accepted_len)
            .and_then(|n| n.checked_add(64))
            .is_none_or(|n| n > limits.work)
    {
        return Err(fail(FailureCode::ResourceLimit));
    }
    Ok(())
}
/// Finish clearance only after the exact accepted inventory completed.
///
/// # Errors
/// `ResourceLimit` when result comparisons exceed explicit ceilings;
/// `UnavailableInput` when required managed lifecycle acquisition is missing.
pub fn decide_fork_completion<'a>(
    facts: &'a ForkCompletionFacts<'a>,
    limits: ForkActivationLimits,
) -> Result<GuardedForkCompletion<'a>, Failure> {
    check_result_bounds(facts.expected_result, facts.accepted_result, limits)?;
    let phase = facts.advance.progress.phase;
    let decision = if facts.accepted_result != Some(facts.expected_result) {
        ForkCompletionDecision::Refuse(ForkRefusal::BindingMismatch)
    } else if phase == ForkAdvancePhase::Complete {
        ForkCompletionDecision::Replay
    } else if phase != ForkAdvancePhase::Accepted
        || facts.completed_packs != facts.expected_result.packs
        || facts.completed_digest != facts.expected_result.pack_digest
        || facts.completed_cursor != facts.completed_packs
        || facts.completed_part != 0
        || facts.advance.progress.cursor > facts.completed_cursor
    {
        ForkCompletionDecision::Refuse(ForkRefusal::BindingMismatch)
    } else if let Some(reason) = decide_fork_authority(
        facts.advance.recorded_authority,
        facts.advance.authority,
        facts.advance.grant_epoch.as_ref(),
    ) {
        ForkCompletionDecision::Defer(reason)
    } else if facts.expected_barrier_owner != facts.advance.binding {
        ForkCompletionDecision::Refuse(ForkRefusal::BindingMismatch)
    } else if !lifecycle_available(&facts.lifecycle)? {
        ForkCompletionDecision::Withhold(ForkWithheld::LifecycleUnavailable)
    } else {
        ForkCompletionDecision::Complete
    };
    Ok(GuardedForkCompletion { decision, facts })
}
