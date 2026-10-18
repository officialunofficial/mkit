//! Guarded fork acceptance under SPEC-SERVER §9.9.
//!
//! Acceptance saves terminal success, replay, and outcome responsibility and
//! settles the exact reservation in one atomic unit. It grants no reader-visible
//! membership and enables no destination writes. Activation is published
//! clearance; it must never repeat settlement or replace the saved result.
//!
//! Inventories and observations come from a trusted host. The primitive validates
//! their composition, not their provenance. A final source fence is ordered after
//! all staged effects and before acceptance; later source movement is concurrent.
//! All destination facts, including phantom-safe emptiness, compare atomically.
//!
//! ```
//! use mkit_primitives::fork::{ForkLimits, ForkVisibility};
//! let limits = ForkLimits { packs: 8, edges: 16, branch_bytes: 128,
//!     index_entries: 128, inherited_bytes: 4096, work: 4096 };
//! assert_eq!(limits.packs, 8);
//! assert_ne!(ForkVisibility::Public, ForkVisibility::Private);
//! // Seal full inventories, acquire destination facts and a final source proof,
//! // then call decide_fork_acceptance. Commit only after all guards compare.
//! ```

mod advance;
pub use advance::*;

mod facts;
mod plan;
pub use facts::*;
pub use plan::{ForkInventory, ForkLimits, ForkPlan};

use crate::{
    decision::{LifecycleState, Observed},
    error::{BoundedDetail, Failure, FailureCode, Location},
};

/// Stable semantic refusal, separate from acquisition or malformed-fact failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForkRefusal {
    /// Uniform missing-source answer, including source changes after admission.
    SourceNotFound,
    /// A foreign registration, ref, staged member, or visible member exists.
    DestinationNotEmpty,
    /// Recorded authority or grant no longer authorizes acceptance.
    PermissionDenied,
    /// A name declaration differs from the requested visibility.
    VisibilityMismatch,
    /// The reservation was externally settled or is no longer protected.
    ReservationSettled,
    /// The durable job or reservation protection expired.
    Expired,
    /// Exact admitted charge or applicable quota no longer permits the plan.
    QuotaExceeded,
    /// A durable job or replay belongs to another admitted binding.
    BindingMismatch,
}
impl ForkRefusal {
    /// Stable machine-readable registry code.
    #[must_use]
    pub const fn code(self) -> FailureCode {
        match self {
            Self::SourceNotFound => FailureCode::ForkSourceNotFound,
            Self::DestinationNotEmpty => FailureCode::ForkDestinationNotEmpty,
            Self::PermissionDenied => FailureCode::ForkPermissionDenied,
            Self::VisibilityMismatch => FailureCode::ForkVisibilityMismatch,
            Self::ReservationSettled => FailureCode::ForkReservationSettled,
            Self::Expired => FailureCode::ForkExpired,
            Self::QuotaExceeded => FailureCode::ForkQuotaExceeded,
            Self::BindingMismatch => FailureCode::ForkBindingMismatch,
        }
    }
}

/// Why accepted clearance is withheld without changing the saved result.
///
/// Acceptance already recorded the terminal result; the destination stays
/// invisible and the host redrives clearance once the fact clears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForkWithheld {
    /// Destination lifecycle is not active at the bound incarnation.
    LifecycleUnavailable,
}
impl ForkWithheld {
    /// Stable machine-readable registry code.
    #[must_use]
    pub const fn code(self) -> FailureCode {
        match self {
            Self::LifecycleUnavailable => FailureCode::ForkLifecycleUnavailable,
        }
    }
}

/// Settlement of a separately admitted joining reservation as a replay race.
/// It never releases the original job's reservation or debits quota again.
#[derive(Debug)]
#[must_use]
pub struct ForkReplayRace<'a> {
    /// Exact joining request and its independently guarded pending reservation.
    pub joining: &'a ForkAttempt,
}

/// One atomic acceptance unit; construction of this value is private.
///
/// The host records the accepted plan, terminal response, saved replay response,
/// and terminal outcome responsibility together, and settles `attempt`'s exact
/// pending reservation when admission granted one. An applicable admission debit
/// is already charged. This unit adds
/// no ref or visible member and never enables writes. The terminal response includes the
/// complete admitted branch and publication identity.
#[derive(Debug)]
#[must_use]
pub struct AcceptFork<'a> {
    plan: &'a ForkPlan,
    attempt: &'a ForkAttempt,
}
impl<'a> AcceptFork<'a> {
    /// Exact immutable plan recorded at acceptance.
    #[must_use = "the accepted plan is part of the atomic unit"]
    pub const fn plan(&self) -> &'a ForkPlan {
        self.plan
    }
    /// Original reservation, replay identity, and outcome owner to settle once.
    #[must_use]
    pub const fn attempt(&self) -> &'a ForkAttempt {
        self.attempt
    }
    /// Exact terminal response to record with both replay and outcome.
    #[must_use]
    pub const fn result(&self) -> &ForkResult {
        &self.plan.result
    }
}

/// Bounded semantic decision; every variant requires its returned atomic guards.
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum ForkDecision<'a> {
    /// Atomically accept and settle the construction, without publishing it.
    AcceptFork(AcceptFork<'a>),
    /// Join the identical durable construction, with no repeated quota charge.
    /// This authorizes no construction progress. Reacquire the original owner
    /// facts and decide an advancing commit separately before any progress.
    JoinIdentical {
        /// Original durable construction owner.
        owner: &'a ForkAttempt,
        /// Separately granted joining reservation terminates as a replay race.
        replay_race: Option<ForkReplayRace<'a>>,
    },
    /// Exact saved result; no source proof, construction, charge, or new outcome.
    ReturnRecorded {
        /// Original immutable terminal result.
        result: &'a ForkTerminal,
        /// A fresh joining admission, if supplied, settles only its own reservation.
        replay_race: Option<ForkReplayRace<'a>>,
    },
    /// Guarded refusal. The host must not activate or publish the construction.
    Refuse(ForkRefusal),
}

/// Complete destination comparisons plus the separate source ordering fence.
///
/// Requirements borrow the bounded typed snapshot. The sealed plan owns the
/// bounded result branch. Compare every acquired observation and its revision
/// in one atomic unit with all effects. Never implement emptiness as sampled row CAS.
/// `apply_attempt` and `acceptance_point` bind that unit to this source fence.
/// Guard loss requires fresh facts, a new attempt identity, and a new source
/// proof. Source facts are intentionally absent from destination atomic CAS.
#[derive(Debug)]
#[must_use]
pub struct GuardedFork<'a> {
    decision: ForkDecision<'a>,
    expected: &'a ForkFacts<'a>,
    valid_through_ms: Option<u64>,
    source_fence: Option<&'a FinalForkSourceProof>,
}
impl<'a> GuardedFork<'a> {
    /// Decision that requires every returned comparison and fence.
    #[must_use = "apply the decision only with all returned guards"]
    pub const fn decision(&self) -> &ForkDecision<'a> {
        &self.decision
    }
    /// Exact destination facts and revisions required at the atomic boundary.
    #[must_use]
    pub const fn required_guards(&self) -> &'a ForkFacts<'a> {
        self.expected
    }
    /// Business expiry, inclusive; independent of physical scheduling deadlines.
    #[must_use]
    pub const fn valid_through_ms(&self) -> Option<u64> {
        self.valid_through_ms
    }
    /// Final source proof requirement, separate from destination atomic guards.
    #[must_use]
    pub const fn source_fence(&self) -> Option<&'a FinalForkSourceProof> {
        self.source_fence
    }
    /// Pure reference comparison for host adapters and mutation tests.
    ///
    /// This does not commit or acquire facts. The host must scope observations by
    /// the exact plan, request, and repository and perform this comparison inside
    /// its atomic commit. Missing observations cannot satisfy acquired guards.
    #[must_use]
    pub fn matches(&self, current: &ForkFacts<'_>, now_ms: u64) -> bool {
        self.expected == current && self.valid_through_ms.is_none_or(|expiry| now_ms <= expiry)
    }
}

/// Decide fork acceptance over a sealed bounded plan and exact supplied facts.
///
/// The host validates the current signed envelope at ingress, including its
/// authentication requirements, before calling this entry point. Completed
/// replay does not repeat the completed operation's authority/grant checks.
/// The host has already authorized the initial source read and expected-tip
/// comparison before admission. At this stage every source change has the
/// uniform missing-source class. Source facts are frozen at the final fence;
/// later source movement must not invalidate this decision or a saved result.
///
/// A partial original construction returns `JoinIdentical`. A separately
/// admitted identical join also returns `JoinIdentical` and settles only the
/// joining reservation as a replay race. Only the original owner can accept.
///
/// # Errors
/// `UnavailableInput` for unacquired required facts; `InvalidResponse` for
/// contradictory, wrongly scoped, or malformed facts; `ResourceLimit` for
/// explicit plan, proof, or work bounds. Requested authority fencing that cannot
/// yet be compared atomically is retryable `UnavailableInput`, like a ref write's
/// retry. Errors create no effects or terminal result.
pub fn decide_fork_acceptance<'a>(
    plan: &'a ForkPlan,
    request: &'a ForkAttempt,
    facts: &'a ForkFacts<'a>,
    source: Option<&'a FinalForkSourceProof>,
    now_ms: u64,
    limits: ForkLimits,
) -> Result<GuardedFork<'a>, Failure> {
    check_bounds(plan, facts, source, limits)?;
    let (decision, valid_through_ms, source_fence) =
        match classify(plan, request, facts, source, now_ms) {
            Ok(parts) => parts,
            Err(CheckError::Refuse(reason)) => (ForkDecision::Refuse(reason), None, None),
            Err(CheckError::Facts(error)) => return Err(error),
        };
    Ok(GuardedFork {
        decision,
        expected: facts,
        valid_through_ms,
        source_fence,
    })
}

type DecisionParts<'a> = (
    ForkDecision<'a>,
    Option<u64>,
    Option<&'a FinalForkSourceProof>,
);
type Check<T> = Result<T, CheckError>;
enum CheckError {
    Facts(Failure),
    Refuse(ForkRefusal),
}
impl From<Failure> for CheckError {
    fn from(error: Failure) -> Self {
        Self::Facts(error)
    }
}
impl From<ForkRefusal> for CheckError {
    fn from(reason: ForkRefusal) -> Self {
        Self::Refuse(reason)
    }
}

fn classify<'a>(
    plan: &'a ForkPlan,
    request: &'a ForkAttempt,
    facts: &'a ForkFacts<'a>,
    source: Option<&'a FinalForkSourceProof>,
    now_ms: u64,
) -> Check<DecisionParts<'a>> {
    if facts.repository != plan.binding.destination || facts.request != request {
        return Err(invalid().into());
    }
    let job = present(facts.job.as_ref())?;
    if job.plan != plan {
        return Err(ForkRefusal::BindingMismatch.into());
    }
    let same_owner = request.operation == job.attempt.operation;
    if (same_owner && request != &job.attempt)
        || (!same_owner
            && ((request.reservation.is_some() && request.reservation == job.attempt.reservation)
                || request.replay == job.attempt.replay))
    {
        return Err(ForkRefusal::BindingMismatch.into());
    }
    if let ForkJobState::Terminal(ForkTerminal::Accepted(saved)) = &job.state
        && saved.as_ref() != &plan.result
    {
        return Err(invalid().into());
    }
    if let Some(decision) = recorded(request, facts, job, same_owner)? {
        return Ok((decision, None, None));
    }
    let (expiry, already_joined) = protection(request, facts, job, same_owner, now_ms)?;
    let replay_race =
        (!same_owner && !already_joined).then_some(ForkReplayRace { joining: request });
    if let ForkJobState::Terminal(result) = &job.state {
        return Ok((
            ForkDecision::ReturnRecorded {
                result,
                replay_race,
            },
            Some(expiry),
            None,
        ));
    }
    let authority = present(facts.authority.as_ref())?;
    if request.authority_fencing && !authority.ready {
        return Err(failure(FailureCode::UnavailableInput).into());
    }
    if authority != &request.authority || !grant_matches(facts.grant.as_ref(), request)? {
        return Err(ForkRefusal::PermissionDenied.into());
    }
    if !already_joined {
        check_admission(plan, request, facts)?;
    }
    if job.attempt.authority_fencing
        && (authority != &job.attempt.authority
            || !grant_matches(facts.grant.as_ref(), &job.attempt)?)
    {
        return Err(ForkRefusal::PermissionDenied.into());
    }
    let (staged, stage_revision, last_effect) = construction(plan, request, facts, job)?;
    if !same_owner || staged != plan.packs.len() as u64 {
        return Ok((
            ForkDecision::JoinIdentical {
                owner: &job.attempt,
                replay_race,
            },
            Some(expiry),
            None,
        ));
    }
    let source = source.ok_or_else(|| failure(FailureCode::UnavailableInput))?;
    if source.apply_attempt != facts.apply_attempt
        || source.staged_revision != stage_revision
        || source.proof_point <= last_effect
        || source.proof_point >= facts.acceptance_point
    {
        return Err(invalid().into());
    }
    let decision = if source_matches(plan, source)? {
        ForkDecision::AcceptFork(AcceptFork {
            plan,
            attempt: request,
        })
    } else {
        ForkDecision::Refuse(ForkRefusal::SourceNotFound)
    };
    Ok((decision, Some(expiry), Some(source)))
}

fn recorded<'a>(
    request: &ForkAttempt,
    facts: &'a ForkFacts<'a>,
    job: &'a ForkJob<'a>,
    same_owner: bool,
) -> Check<Option<ForkDecision<'a>>> {
    if let Observed::Present { value, .. } = acquired(facts.replay.as_ref())? {
        match value {
            ForkReplay::InFlight {
                operation,
                fingerprint,
            } if operation == &request.operation && fingerprint == &request.fingerprint => {}
            ForkReplay::Recorded {
                fingerprint,
                result,
            } if fingerprint == &request.fingerprint => {
                if !matches!(&job.state, ForkJobState::Terminal(saved) if saved == result) {
                    return Err(invalid().into());
                }
                if settled_for(
                    acquired(facts.reservation.as_ref())?,
                    job,
                    result,
                    same_owner,
                ) {
                    return Ok(Some(ForkDecision::ReturnRecorded {
                        result,
                        replay_race: None,
                    }));
                }
                if same_owner {
                    return Err(invalid().into());
                }
                // A fresh exact pending joining reservation still needs its
                // replay-race settlement; protection validates it below.
            }
            _ => return Err(ForkRefusal::BindingMismatch.into()),
        }
    }
    if let ForkJobState::Terminal(result) = &job.state {
        let reservation = acquired(facts.reservation.as_ref())?;
        if settled_for(reservation, job, result, same_owner) {
            return Ok(Some(ForkDecision::ReturnRecorded {
                result,
                replay_race: None,
            }));
        }
        if same_owner {
            return Err(invalid().into());
        }
    }
    Ok(None)
}

fn settled_for(
    reservation: &Observed<ForkReservation>,
    job: &ForkJob<'_>,
    result: &ForkTerminal,
    same_owner: bool,
) -> bool {
    match reservation {
        Observed::Absent(_) => true,
        Observed::Present {
            value: ForkReservation::Settled(saved),
            ..
        } => saved == result,
        Observed::Present {
            value: ForkReservation::ReplayRace { owner },
            ..
        } => !same_owner && owner == &job.attempt.operation,
        _ => false,
    }
}

fn protection(
    request: &ForkAttempt,
    facts: &ForkFacts<'_>,
    job: &ForkJob<'_>,
    same_owner: bool,
    now_ms: u64,
) -> Check<(u64, bool)> {
    let (reservation_expiry, already_joined) = match (
        request.reservation.as_ref(),
        acquired(facts.reservation.as_ref())?,
    ) {
        (None, Observed::Absent(_)) => (job.expires_ms, !same_owner),
        (
            Some(_),
            Observed::Present {
                value:
                    ForkReservation::Pending {
                        operation,
                        destination,
                        expires_ms,
                    },
                ..
            },
        ) if operation == &request.operation && destination == &facts.repository => {
            (*expires_ms, false)
        }
        (
            Some(_),
            Observed::Present {
                value: ForkReservation::ReplayRace { owner },
                ..
            },
        ) if !same_owner && owner == &job.attempt.operation => (job.expires_ms, true),
        (
            Some(_),
            Observed::Absent(_)
            | Observed::Present {
                value: ForkReservation::Settled(_) | ForkReservation::ReplayRace { .. },
                ..
            },
        ) => return Err(ForkRefusal::ReservationSettled.into()),
        _ => return Err(invalid().into()),
    };
    let expiry = if matches!(job.state, ForkJobState::Terminal(_)) {
        reservation_expiry
    } else {
        reservation_expiry.min(job.expires_ms)
    };
    if now_ms > expiry {
        return Err(ForkRefusal::Expired.into());
    }
    Ok((expiry, already_joined))
}

fn check_admission(plan: &ForkPlan, request: &ForkAttempt, facts: &ForkFacts<'_>) -> Check<()> {
    let admission = present(facts.admission.as_ref())?;
    if admission.plan != plan
        || admission.operation != request.operation
        || admission.reservation != request.reservation
    {
        return Err(invalid().into());
    }
    if admission.declared_bytes != plan.result.bytes
        || admission.new_to_repo_bytes != plan.result.bytes
    {
        return Err(ForkRefusal::QuotaExceeded.into());
    }
    match (admission.charge, acquired(facts.quota.as_ref())?) {
        (None, Observed::Absent(_)) => {}
        (Some(charge), Observed::Present { value: quota, .. }) => {
            if quota.operation != request.operation || quota.charge != charge {
                return Err(invalid().into());
            }
            if quota.bytes != plan.result.bytes
                || quota.used_bytes < quota.bytes
                || quota.used_bytes > quota.byte_limit
                || quota.used_operations == 0
                || quota.used_operations > quota.operation_limit
            {
                return Err(ForkRefusal::QuotaExceeded.into());
            }
        }
        _ => return Err(invalid().into()),
    }

    Ok(())
}

fn construction(
    plan: &ForkPlan,
    request: &ForkAttempt,
    facts: &ForkFacts<'_>,
    job: &ForkJob<'_>,
) -> Check<(u64, crate::evidence::Revision, u64)> {
    let permission = present(facts.permission.as_ref())?;
    if permission.operation != request.operation
        || permission.source_access != plan.binding.source_access
        || permission.destination_visibility != plan.binding.destination_visibility
    {
        return Err(invalid().into());
    }
    if !permission.create || !permission.write {
        return Err(ForkRefusal::PermissionDenied.into());
    }
    match acquired(facts.lifecycle.as_ref())? {
        Observed::Absent(_) => {}
        Observed::Present { value, .. }
            if value.state == LifecycleState::Active
                && value.incarnation == plan.binding.destination_generation => {}
        _ => return Err(ForkRefusal::DestinationNotEmpty.into()),
    }
    if let Observed::Present { value: name, .. } = acquired(facts.name.as_ref())? {
        if name
            .registered_by
            .as_ref()
            .is_some_and(|owner| owner != &job.attempt.operation)
        {
            return Err(ForkRefusal::DestinationNotEmpty.into());
        }
        if name
            .declared_visibility
            .is_some_and(|v| v != plan.binding.destination_visibility)
        {
            return Err(ForkRefusal::VisibilityMismatch.into());
        }
    }
    let empty = present(facts.emptiness.as_ref())?;
    let ForkJobState::Staged {
        packs,
        revision,
        last_effect,
    } = &job.state
    else {
        return Err(invalid().into());
    };
    if empty.refs != 0
        || empty.visible_members != 0
        || empty.writes_enabled
        || empty.staged_members != *packs
        || (*packs > 0 && empty.staged_owner.as_ref() != Some(&job.attempt.operation))
        || (*packs == 0 && empty.staged_owner.is_some())
    {
        return Err(ForkRefusal::DestinationNotEmpty.into());
    }
    if *packs > plan.packs.len() as u64
        || (*packs == plan.packs.len() as u64
            && empty.staged_pack_digest != plan.result.pack_digest)
    {
        return Err(invalid().into());
    }
    Ok((*packs, *revision, *last_effect))
}

fn source_matches(plan: &ForkPlan, proof: &FinalForkSourceProof) -> Result<bool, Failure> {
    if proof.packs.len() != plan.packs.len()
        || proof.packs.windows(2).any(|p| p[0].pack >= p[1].pack)
    {
        return Err(invalid());
    }
    let binding = &plan.binding;
    if proof.repository != binding.source || proof.branch != binding.branch {
        return Err(invalid());
    }
    let Observed::Present {
        value: lifecycle, ..
    } = &proof.lifecycle
    else {
        return Ok(false);
    };
    let Observed::Present {
        value: publication, ..
    } = &proof.publication
    else {
        return Ok(false);
    };
    let Observed::Present { value: access, .. } = &proof.access else {
        return Ok(false);
    };
    if !proof.readable
        || lifecycle.incarnation != binding.source_incarnation
        || lifecycle.state != LifecycleState::Active
        || publication != &binding.publication
        || access != &binding.source_access
    {
        return Ok(false);
    }
    for (inventory, pack) in plan.packs.iter().zip(&proof.packs) {
        if pack.pack != inventory.pack {
            return Err(invalid());
        }
        if pack.incarnation != binding.source_incarnation
            || pack.generation != publication.generation
            || pack.descriptor != inventory.descriptor
            || !pack.eligibility.live
            || !pack.eligibility.cleared
            || pack.eligibility.held
            || pack.denied
            || pack.superseded
        {
            return Ok(false);
        }
    }
    Ok(true)
}
fn acquired<T>(fact: Option<&Observed<T>>) -> Result<&Observed<T>, Failure> {
    fact.ok_or_else(|| failure(FailureCode::UnavailableInput))
}
fn present<T>(fact: Option<&Observed<T>>) -> Result<&T, Failure> {
    match acquired(fact)? {
        Observed::Present { value, .. } => Ok(value),
        _ => Err(invalid()),
    }
}
fn grant_matches(
    fact: Option<&Observed<crate::decision::GrantFact>>,
    attempt: &ForkAttempt,
) -> Result<bool, Failure> {
    Ok(match (acquired(fact)?, &attempt.grant) {
        (Observed::Absent(_), None) => true,
        (Observed::Present { value, .. }, Some(expected)) => value == expected,
        _ => false,
    })
}
fn check_bounds(
    plan: &ForkPlan,
    facts: &ForkFacts<'_>,
    source: Option<&FinalForkSourceProof>,
    limits: ForkLimits,
) -> Result<(), Failure> {
    let mut work = limits.work;
    charge(&mut work, 512)?;
    bound_plan(plan, limits, &mut work)?;
    if let Some(Observed::Present { value, .. }) = &facts.job {
        bound_plan(value.plan, limits, &mut work)?;
        if let ForkJobState::Terminal(result) = &value.state {
            bound_terminal(result, limits, &mut work)?;
        }
    }
    if let Some(Observed::Present { value, .. }) = &facts.admission {
        bound_plan(value.plan, limits, &mut work)?;
    }
    if let Some(Observed::Present {
        value: ForkReservation::Settled(result),
        ..
    }) = &facts.reservation
    {
        bound_terminal(result, limits, &mut work)?;
    }
    if let Some(Observed::Present {
        value: ForkReplay::Recorded { result, .. },
        ..
    }) = &facts.replay
    {
        bound_terminal(result, limits, &mut work)?;
    }
    if let Some(source) = source {
        if source.packs.len() as u64 > u64::from(limits.packs)
            || source.branch.0.len() as u64 > u64::from(limits.branch_bytes)
        {
            return Err(resource());
        }
        charge(
            &mut work,
            (source.packs.len() as u64)
                .checked_mul(32)
                .ok_or_else(resource)?,
        )?;
        charge(
            &mut work,
            (source.branch.0.len() as u64)
                .checked_mul(8)
                .ok_or_else(resource)?,
        )?;
    }
    Ok(())
}
fn bound_plan(plan: &ForkPlan, limits: ForkLimits, work: &mut u64) -> Result<(), Failure> {
    if !plan.within(limits) {
        return Err(resource());
    }
    charge(
        work,
        (plan.packs.len() as u64)
            .checked_mul(32)
            .ok_or_else(resource)?,
    )?;
    charge(work, plan.edges.checked_mul(8).ok_or_else(resource)?)?;
    // The plan owns both its binding branch and its result branch.
    charge(
        work,
        (plan.binding.branch.0.len() as u64)
            .checked_mul(16)
            .ok_or_else(resource)?,
    )
}
fn bound_terminal(
    result: &ForkTerminal,
    limits: ForkLimits,
    work: &mut u64,
) -> Result<(), Failure> {
    if let ForkTerminal::Accepted(result) = result {
        if result.branch.0.len() as u64 > u64::from(limits.branch_bytes) {
            return Err(resource());
        }
        charge(
            work,
            (result.branch.0.len() as u64)
                .checked_mul(8)
                .ok_or_else(resource)?,
        )?;
    }
    Ok(())
}
fn charge(work: &mut u64, amount: u64) -> Result<(), Failure> {
    *work = work.checked_sub(amount).ok_or_else(resource)?;
    Ok(())
}
fn valid_branch(name: &str) -> bool {
    mkit_core::refs::validate_ref_name(name)
}
fn failure(code: FailureCode) -> Failure {
    Failure {
        code,
        location: Location::default(),
        detail: BoundedDetail::None,
    }
}
fn invalid() -> Failure {
    failure(FailureCode::InvalidResponse)
}
fn resource() -> Failure {
    failure(FailureCode::ResourceLimit)
}
