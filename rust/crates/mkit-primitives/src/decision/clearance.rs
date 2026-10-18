//! Published clearance over a prior publication identity.
//!
//! The host supplies the retained suffix, the changed advance, and any
//! dependency witnesses. This module does not walk objects, read storage, or
//! emit an acceptance terminal outcome, ticket consumption, or reservation
//! settlement. A resulting-pair proof is consumed only as the dependency and
//! supplier sets the host already sealed. Ticketed acceptance stays a separate
//! decision; combining clearance with it must not call that settlement again.

use mkit_core::hash::Hash;

use super::ref_write::RefDecisionLimits;
use super::ticketed::{TicketedAdvanceRequest, decide_ticketed_advance};
use super::{
    Guarded, LifecycleFact, LifecycleState, Observed, OperationId, Snapshot, WriteDecision,
};
use crate::closure::pair::PairCoverage;
use crate::error::{BoundedDetail, Failure, FailureCode, Location};
use crate::evidence::{RepositoryId, Revision};

/// Lifecycle profile. A profile without transitions says so; it does not invent an active fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearanceLifecycle {
    /// This profile has no repository lifecycle transitions.
    NotOffered,
    /// Exact acquired lifecycle. `None` means acquisition failed.
    Managed {
        /// Incarnation bound to the publication generation.
        expected_incarnation: Revision,
        /// Acquired fact, or unavailable acquisition.
        current: Option<Observed<LifecycleFact>>,
    },
}

/// Clearance state from the publication rules. The host supplies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearanceState {
    /// Inspection or a dependency is still outstanding.
    Pending,
    /// Obligations and dependencies permit publication.
    Cleared,
    /// A flag withholds publication until release or re-inspection.
    Held,
    /// A rejection waits for takedown completion.
    Hit,
    /// Takedown and the remaining obligations are complete.
    Resolved,
}

impl ClearanceState {
    /// Whether this state may advance the published prefix.
    #[must_use]
    pub const fn publishable(self) -> bool {
        matches!(self, Self::Cleared | Self::Resolved)
    }
}

/// When the host is applying the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearanceMoment {
    /// The advance is not stored yet. Eligibility can withhold publication.
    Acceptance,
    /// A retained advance is being re-evaluated. A publishable claim must hold.
    Recheck,
}

/// One retained or candidate advance reduced to the facts clearance compares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearanceAdvance<'a> {
    /// Never-reused sequence.
    pub sequence: u64,
    /// Repository membership generation.
    pub generation: u64,
    /// Originating operation. Correlation only; not a terminal result.
    pub operation: OperationId,
    /// Head component. Absent for a component this advance does not publish.
    pub head: Option<Hash>,
    /// Packmap component. Absent for a non-branch or a partial component.
    pub packmap: Option<Hash>,
    /// Host-supplied state. Recheck refuses a publishable claim the facts reject.
    pub state: ClearanceState,
    /// Packs this advance adds. They satisfy its own dependencies only.
    pub additions: &'a [Hash],
    /// Dependencies own additions may satisfy.
    pub dependencies: &'a [Hash],
    /// External suppliers own additions must not satisfy.
    pub external_suppliers: &'a [Hash],
    /// Obligation states. An empty slice is no inspection obligation.
    pub obligations: &'a [ClearanceState],
    /// Verdict or waiver revisions, one per obligation, in the same order.
    pub obligation_revisions: &'a [Revision],
    /// Takedown of a hit is complete. Ignored unless the state is resolved.
    pub takedown_complete: bool,
    /// A flagged id occurs in the inspected set or the packs.
    pub flagged: bool,
    /// Exact row observation. Acceptance uses the prepared-fact revision.
    pub revision: Revision,
}

impl<'a> ClearanceAdvance<'a> {
    /// Take the dependency and external-supplier sets from an established
    /// resulting-pair coverage. The coverage must belong to `repository` and cover
    /// exactly this advance's head and packmap, or the sets are not this advance's.
    ///
    /// # Errors
    ///
    /// `InvalidResponse` when the repository or the covered pair differs.
    pub fn with_pair(
        mut self,
        repository: RepositoryId,
        coverage: &'a PairCoverage,
    ) -> Result<Self, Failure> {
        let pair = coverage.pair();
        if coverage.repository() != repository
            || pair.head != self.head
            || pair.packmap != self.packmap
        {
            return Err(invalid());
        }
        self.dependencies = coverage.dependencies();
        self.external_suppliers = coverage.external_suppliers();
        Ok(self)
    }
}

/// Prior publication identity. The published value is not part of the binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorPublication {
    /// Membership generation.
    pub generation: u64,
    /// Last accepted sequence.
    pub sequence: u64,
    /// Largest contiguous published prefix.
    pub published_prefix: u64,
    /// Deletion boundary. Later verdicts must not resurrect an older value.
    pub deletion_boundary: u64,
    /// Published head component.
    pub head: Option<Hash>,
    /// Published packmap component.
    pub packmap: Option<Hash>,
    /// Exact publication-row observation.
    pub revision: Revision,
}

/// Published-membership witness. Absence is `present: false`, not a missing entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyWitness {
    /// Pack identity.
    pub object: Hash,
    /// Authoritative row was present.
    pub present: bool,
    /// Present row is in published membership.
    pub published: bool,
    /// Present row is held.
    pub held: bool,
    /// Present row generation.
    pub generation: u64,
    /// Exact observation.
    pub revision: Revision,
}

/// Host-supplied clearance snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearanceFacts<'a> {
    /// Destination repository. Guard scope only.
    pub repository: RepositoryId,
    /// Acceptance or recheck.
    pub moment: ClearanceMoment,
    /// Prior identity, before this acceptance appends a sequence.
    pub prior: PriorPublication,
    /// Advance under decision. At acceptance its sequence is `prior.sequence + 1`.
    pub changed: ClearanceAdvance<'a>,
    /// State before this decision. Recheck uses it to reject `Hit` to `Cleared`.
    pub previous_state: ClearanceState,
    /// Ordered suffix `published_prefix + 1 ..= sequence`, with `changed` substituted.
    /// Empty at acceptance; the candidate is not retained yet.
    pub suffix: &'a [ClearanceAdvance<'a>],
    /// Witnesses for dependencies that are not own additions, and every supplier.
    pub witnesses: &'a [DependencyWitness],
    /// Lifecycle profile. `NotOffered` is an explicit reference limitation.
    pub lifecycle: ClearanceLifecycle,
    /// This unit is a deletion. It publishes the boundary without inspection.
    pub deleted: bool,
}

/// Finite host ceilings. They are not protocol constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClearanceLimits {
    /// Outstanding advances in one prefix walk.
    pub max_advances: u64,
    /// Dependencies, suppliers, additions, or obligations on one advance.
    pub max_items: usize,
    /// Charged comparisons.
    pub max_work: u64,
}

impl ClearanceLimits {
    /// Reference ceilings: 64 outstanding advances and 4,096 items.
    #[must_use]
    pub const fn reference() -> Self {
        Self {
            max_advances: 64,
            max_items: 4096,
            max_work: 65_536,
        }
    }
}

/// Clearance outcome. No variant settles a reservation or records a terminal result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearanceDecision {
    /// Move the published prefix. Head and packmap move together.
    AdvancePrefix {
        /// New contiguous prefix.
        published_prefix: u64,
        /// Published head after the move.
        head: Option<Hash>,
        /// Published packmap after the move.
        packmap: Option<Hash>,
        /// Deletion boundary after the unit.
        deletion_boundary: u64,
    },
    /// Record or retain the advance without moving the published pointer.
    Retain {
        /// Unchanged contiguous prefix.
        published_prefix: u64,
    },
}

/// Permission to apply the decision only while every supplied fact still matches.
#[derive(Debug)]
#[must_use]
pub struct GuardedClearance<'a> {
    decision: ClearanceDecision,
    facts: &'a ClearanceFacts<'a>,
}

impl GuardedClearance<'_> {
    /// Decision. It does not consume tickets or settle a reservation.
    #[must_use]
    pub const fn decision(&self) -> &ClearanceDecision {
        &self.decision
    }

    /// Compare the exact snapshot before apply. A mismatch requires a new decision.
    #[must_use]
    pub fn matches(&self, current: &ClearanceFacts<'_>) -> bool {
        self.facts == current
    }
}

/// Decide published clearance from facts the host already acquired.
///
/// # Errors
///
/// Returns a typed failure for malformed, unbounded, or contradictory facts.
/// An unsatisfied dependency at acceptance withholds the prefix; it is not an error.
#[must_use = "compare every supplied fact before publishing"]
pub fn decide_clearance<'a>(
    facts: &'a ClearanceFacts<'a>,
    limits: &ClearanceLimits,
) -> Result<GuardedClearance<'a>, Failure> {
    validate(facts, limits)?;
    let decision = if facts.deleted {
        deletion(facts)?
    } else if facts.moment == ClearanceMoment::Acceptance {
        acceptance(facts)?
    } else {
        recheck(facts)?
    };
    Ok(GuardedClearance { decision, facts })
}

/// Acceptance and clearance decided as one unit.
#[derive(Debug)]
#[must_use]
pub struct CombinedAcceptance<'a> {
    acceptance: Guarded<WriteDecision>,
    clearance: Option<GuardedClearance<'a>>,
}

impl<'a> CombinedAcceptance<'a> {
    /// The acceptance decision, unchanged. It alone owns ticket consumption, the
    /// terminal result, and reservation settlement.
    pub const fn acceptance(&self) -> &Guarded<WriteDecision> {
        &self.acceptance
    }

    /// Clearance riding in the same unit. `None` unless acceptance applies; a
    /// replay, conflict, refusal, or retry never publishes.
    #[must_use]
    pub const fn clearance(&self) -> Option<&GuardedClearance<'a>> {
        self.clearance.as_ref()
    }
}

/// Decide acceptance, then clearance with no intervening operation.
///
/// The acceptance decision is exactly [`decide_ticketed_advance`]'s, so its
/// guards and settlement are unchanged. Clearance is decided only when
/// acceptance applies, over the same repository and operation, and every
/// clearance condition is evaluated as for separate clearance. A not-yet-eligible
/// advance yields `Retain`: the host accepts now and clears later.
///
/// # Errors
///
/// Acceptance failures pass through. `InvalidResponse` when the clearance facts
/// are not an acceptance-moment, non-deletion view of the same repository and
/// operation; clearance failures pass through.
#[must_use = "compare every supplied fact before applying"]
pub fn decide_accept_and_clear<'a>(
    request: &TicketedAdvanceRequest<'_>,
    snapshot: &Snapshot,
    ref_limits: RefDecisionLimits,
    facts: &'a ClearanceFacts<'a>,
    limits: &ClearanceLimits,
) -> Result<CombinedAcceptance<'a>, Failure> {
    let write = &request.write;
    if facts.moment != ClearanceMoment::Acceptance
        || facts.deleted
        || facts.repository != write.repository
        || write.operation.as_ref() != Some(&facts.changed.operation)
    {
        return Err(invalid());
    }
    let acceptance = decide_ticketed_advance(request, snapshot, ref_limits)?;
    let clearance = if matches!(acceptance.decision(), WriteDecision::Apply(_)) {
        Some(decide_clearance(facts, limits)?)
    } else {
        None
    };
    Ok(CombinedAcceptance {
        acceptance,
        clearance,
    })
}

fn deletion(facts: &ClearanceFacts<'_>) -> Result<ClearanceDecision, Failure> {
    let sequence = facts.prior.sequence.checked_add(1).ok_or_else(resource)?;
    if facts.changed.sequence != sequence {
        return Err(invalid());
    }
    Ok(ClearanceDecision::AdvancePrefix {
        published_prefix: sequence,
        head: facts.changed.head.and(facts.prior.head),
        packmap: facts.changed.packmap.and(facts.prior.packmap),
        deletion_boundary: sequence,
    })
}

fn acceptance(facts: &ClearanceFacts<'_>) -> Result<ClearanceDecision, Failure> {
    let sequence = facts.prior.sequence.checked_add(1).ok_or_else(resource)?;
    if facts.changed.sequence != sequence || facts.changed.generation != facts.prior.generation {
        return Err(invalid());
    }
    if !facts.changed.state.publishable() || !eligible(&facts.changed, facts)? {
        return Ok(retain(facts));
    }
    if facts.prior.published_prefix.saturating_add(1) == sequence {
        return Ok(ClearanceDecision::AdvancePrefix {
            published_prefix: sequence,
            head: facts.changed.head,
            packmap: facts.changed.packmap,
            deletion_boundary: facts.prior.deletion_boundary,
        });
    }
    Ok(retain(facts))
}

fn recheck(facts: &ClearanceFacts<'_>) -> Result<ClearanceDecision, Failure> {
    if facts.previous_state == ClearanceState::Hit && facts.changed.state == ClearanceState::Cleared
    {
        return Err(invalid());
    }
    if facts.changed.generation != facts.prior.generation {
        return Err(invalid());
    }
    if facts.changed.state.publishable() && !eligible(&facts.changed, facts)? {
        return Err(invalid());
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(facts.suffix.len())
        .map_err(|_| resource())?;
    for record in facts.suffix {
        let publishable = if record.sequence == facts.changed.sequence {
            facts.changed.state.publishable() && eligible(&facts.changed, facts)?
        } else {
            record.state.publishable()
        };
        records.push(PrefixStep {
            sequence: record.sequence,
            publishable,
            head: record.head,
            packmap: record.packmap,
        });
    }
    let (prefix, head, packmap) = contiguous_prefix(
        facts.prior.published_prefix,
        facts.prior.head,
        facts.prior.packmap,
        &records,
    );
    if prefix == facts.prior.published_prefix {
        return Ok(retain(facts));
    }
    Ok(ClearanceDecision::AdvancePrefix {
        published_prefix: prefix,
        head,
        packmap,
        deletion_boundary: facts.prior.deletion_boundary,
    })
}

/// One already-reduced suffix step.
struct PrefixStep {
    sequence: u64,
    publishable: bool,
    head: Option<Hash>,
    packmap: Option<Hash>,
}

/// Largest contiguous publishable prefix. Stops at the first withheld advance.
fn contiguous_prefix(
    mut prefix: u64,
    mut head: Option<Hash>,
    mut packmap: Option<Hash>,
    records: &[PrefixStep],
) -> (u64, Option<Hash>, Option<Hash>) {
    for record in records {
        if !record.publishable {
            break;
        }
        prefix = record.sequence;
        head = record.head;
        packmap = record.packmap;
    }
    (prefix, head, packmap)
}

fn retain(facts: &ClearanceFacts<'_>) -> ClearanceDecision {
    ClearanceDecision::Retain {
        published_prefix: facts.prior.published_prefix,
    }
}

fn eligible(advance: &ClearanceAdvance<'_>, facts: &ClearanceFacts<'_>) -> Result<bool, Failure> {
    if advance.flagged || !obligations_publishable(advance) {
        return Ok(false);
    }
    if advance.state == ClearanceState::Resolved && !advance.takedown_complete {
        return Ok(false);
    }
    if !lifecycle_allows(&facts.lifecycle)? {
        return Ok(false);
    }
    if !dependencies_visible(advance, facts.witnesses) {
        return Ok(false);
    }
    Ok(suppliers_visible(advance, facts.witnesses))
}

fn obligations_publishable(advance: &ClearanceAdvance<'_>) -> bool {
    advance.obligations.iter().all(|state| state.publishable())
}

fn lifecycle_allows(protection: &ClearanceLifecycle) -> Result<bool, Failure> {
    match protection {
        ClearanceLifecycle::NotOffered => Ok(true),
        ClearanceLifecycle::Managed { current, .. } => match current {
            None => Err(unavailable()),
            Some(Observed::Absent(_)) => Ok(false),
            Some(Observed::Present { value, .. }) => Ok(value.state == LifecycleState::Active),
        },
    }
}

fn dependencies_visible(advance: &ClearanceAdvance<'_>, witnesses: &[DependencyWitness]) -> bool {
    advance.dependencies.iter().all(|id| {
        advance.additions.contains(id) || witness_published(witnesses, id, advance.generation)
    })
}

fn suppliers_visible(advance: &ClearanceAdvance<'_>, witnesses: &[DependencyWitness]) -> bool {
    advance
        .external_suppliers
        .iter()
        .all(|id| witness_published(witnesses, id, advance.generation))
}

fn witness_published(witnesses: &[DependencyWitness], id: &Hash, generation: u64) -> bool {
    witnesses.iter().any(|witness| {
        witness.object == *id
            && witness.present
            && witness.published
            && !witness.held
            && witness.generation == generation
    })
}

fn validate(facts: &ClearanceFacts<'_>, limits: &ClearanceLimits) -> Result<(), Failure> {
    let prior = &facts.prior;
    if prior.published_prefix > prior.sequence || prior.deletion_boundary > prior.sequence {
        return Err(invalid());
    }
    if prior.sequence - prior.published_prefix > limits.max_advances {
        return Err(resource());
    }
    bound_advance(&facts.changed, limits)?;
    if facts.moment == ClearanceMoment::Recheck {
        expect_suffix(facts, limits)?;
    } else if !facts.suffix.is_empty() {
        return Err(invalid());
    }
    if facts.witnesses.len() > limits.max_items {
        return Err(resource());
    }
    let mut work = limits.max_work;
    charge(
        &mut work,
        facts.suffix.len() as u64
            + facts.witnesses.len() as u64
            + facts.changed.dependencies.len() as u64
            + facts.changed.external_suppliers.len() as u64,
    )?;
    if facts.changed.obligation_revisions.len() != facts.changed.obligations.len() {
        return Err(invalid());
    }
    let _ = work;
    Ok(())
}

fn expect_suffix(facts: &ClearanceFacts<'_>, limits: &ClearanceLimits) -> Result<(), Failure> {
    let expected = facts
        .prior
        .sequence
        .checked_sub(facts.prior.published_prefix)
        .ok_or_else(invalid)?;
    if facts.suffix.len() as u64 != expected || facts.suffix.len() as u64 > limits.max_advances {
        return Err(invalid());
    }
    let mut previous = facts.prior.published_prefix;
    let mut saw_changed = false;
    for record in facts.suffix {
        bound_advance(record, limits)?;
        if record.sequence != previous.checked_add(1).ok_or_else(resource)? {
            return Err(invalid());
        }
        if record.generation != facts.prior.generation {
            return Err(invalid());
        }
        if record.sequence == facts.changed.sequence {
            if record.revision != facts.changed.revision {
                return Err(invalid());
            }
            saw_changed = true;
        }
        previous = record.sequence;
    }
    if !saw_changed {
        return Err(invalid());
    }
    Ok(())
}

fn bound_advance(advance: &ClearanceAdvance<'_>, limits: &ClearanceLimits) -> Result<(), Failure> {
    if advance.additions.len() > limits.max_items
        || advance.dependencies.len() > limits.max_items
        || advance.external_suppliers.len() > limits.max_items
        || advance.obligations.len() > limits.max_items
    {
        return Err(resource());
    }
    Ok(())
}

fn charge(work: &mut u64, amount: u64) -> Result<(), Failure> {
    *work = work.checked_sub(amount).ok_or_else(resource)?;
    Ok(())
}

fn invalid() -> Failure {
    Failure {
        code: FailureCode::InvalidResponse,
        location: Location::default(),
        detail: BoundedDetail::None,
    }
}

fn unavailable() -> Failure {
    Failure {
        code: FailureCode::UnavailableInput,
        location: Location::default(),
        detail: BoundedDetail::None,
    }
}

fn resource() -> Failure {
    Failure {
        code: FailureCode::ResourceLimit,
        location: Location::default(),
        detail: BoundedDetail::None,
    }
}
