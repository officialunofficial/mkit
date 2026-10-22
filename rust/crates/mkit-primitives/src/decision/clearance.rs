//! Published clearance over a prior publication identity.
//!
//! The host supplies the retained suffix, the changed advance, and any
//! dependency witnesses. This module does not walk objects, read storage, or
//! emit an acceptance terminal outcome, ticket consumption, or reservation
//! settlement. A resulting-pair proof is consumed only as the dependency and
//! supplier sets the host already sealed. Ticketed acceptance stays a separate
//! decision; combining clearance with it must not call that settlement again.

use mkit_core::hash::Hash;

use super::commit::Commit;
use super::ref_write::RefDecisionLimits;
use super::ticketed::{TicketedAdvanceRequest, decide_ticketed_advance};
use super::{
    GuardRow, Guarded, LifecycleFact, LifecycleState, Observed, OperationId, RequiredGuard,
    Snapshot, WriteDecision,
};
use crate::closure::pair::PairCoverage;
use crate::error::{BoundedDetail, Failure, FailureCode, Location};
use crate::evidence::{RepositoryId, Revision};

/// Lifecycle profile. A profile without transitions says so; it does not invent an active fact.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
pub enum ClearanceMoment {
    /// The advance is not stored yet. Eligibility can withhold publication.
    Acceptance,
    /// A retained advance is being re-evaluated. A publishable claim must hold.
    Recheck,
}

/// One retained or candidate advance reduced to the facts clearance compares.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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

impl ClearanceAdvance<'_> {
    /// An advance with no head, packmap, additions, dependencies, suppliers
    /// or obligations, and no flag. Assign the public fields that apply. The
    /// struct is `#[non_exhaustive]`.
    #[must_use]
    pub const fn new(
        sequence: u64,
        generation: u64,
        operation: OperationId,
        state: ClearanceState,
        revision: Revision,
    ) -> Self {
        Self {
            sequence,
            generation,
            operation,
            head: None,
            packmap: None,
            state,
            additions: &[],
            dependencies: &[],
            external_suppliers: &[],
            obligations: &[],
            obligation_revisions: &[],
            takedown_complete: false,
            flagged: false,
            revision,
        }
    }
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
#[non_exhaustive]
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

impl PriorPublication {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(
        generation: u64,
        sequence: u64,
        published_prefix: u64,
        deletion_boundary: u64,
        head: Option<Hash>,
        packmap: Option<Hash>,
        revision: Revision,
    ) -> Self {
        Self {
            generation,
            sequence,
            published_prefix,
            deletion_boundary,
            head,
            packmap,
            revision,
        }
    }
}

/// Published-membership witness. Absence is `present: false`, not a missing entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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

impl DependencyWitness {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(
        object: Hash,
        present: bool,
        published: bool,
        held: bool,
        generation: u64,
        revision: Revision,
    ) -> Self {
        Self {
            object,
            present,
            published,
            held,
            generation,
            revision,
        }
    }
}

/// Host-supplied clearance snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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

impl<'a> ClearanceFacts<'a> {
    /// Facts with no retained suffix, no witnesses, no lifecycle protection
    /// and no deletion. `previous_state` is explicit: it decides whether a
    /// retained `Hit` may become `Cleared`. Assign the public fields that apply. The struct is `#[non_exhaustive]`.
    #[must_use]
    pub const fn new(
        repository: RepositoryId,
        moment: ClearanceMoment,
        prior: PriorPublication,
        changed: ClearanceAdvance<'a>,
        previous_state: ClearanceState,
    ) -> Self {
        Self {
            repository,
            moment,
            prior,
            previous_state,
            changed,
            suffix: &[],
            witnesses: &[],
            lifecycle: ClearanceLifecycle::NotOffered,
            deleted: false,
        }
    }
}

fn state_tag(state: ClearanceState) -> u8 {
    match state {
        ClearanceState::Pending => 0,
        ClearanceState::Cleared => 1,
        ClearanceState::Held => 2,
        ClearanceState::Hit => 3,
        ClearanceState::Resolved => 4,
    }
}

impl ClearanceAdvance<'_> {
    /// Commitment to every field of the advance, including its row revision.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        let mut c = Commit::new("clearance-advance");
        c.u64(self.sequence)
            .u64(self.generation)
            .hash(&self.operation.0)
            .opt_hash(self.head.as_ref())
            .opt_hash(self.packmap.as_ref())
            .u8(state_tag(self.state))
            .hashes(self.additions)
            .hashes(self.dependencies)
            .hashes(self.external_suppliers)
            .u64(self.obligations.len() as u64);
        for state in self.obligations {
            c.u8(state_tag(*state));
        }
        c.u64(self.obligation_revisions.len() as u64);
        for revision in self.obligation_revisions {
            c.revision(revision);
        }
        c.bool(self.takedown_complete)
            .bool(self.flagged)
            .revision(&self.revision);
        c.finish()
    }
}

impl PriorPublication {
    /// Commitment to the prior publication identity.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        let mut c = Commit::new("clearance-prior");
        c.u64(self.generation)
            .u64(self.sequence)
            .u64(self.published_prefix)
            .u64(self.deletion_boundary)
            .opt_hash(self.head.as_ref())
            .opt_hash(self.packmap.as_ref());
        c.finish()
    }
}

impl DependencyWitness {
    /// Commitment to the witnessed standing of one pack.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        let mut c = Commit::new("clearance-witness");
        c.hash(&self.object)
            .bool(self.present)
            .bool(self.published)
            .bool(self.held)
            .u64(self.generation);
        c.finish()
    }
}

impl ClearanceFacts<'_> {
    /// The guards these facts yield: the prior publication row, the changed
    /// advance with the moment it is decided at, every suffix advance, every
    /// dependency witness, and the lifecycle observation of a managed profile.
    ///
    /// A host that re-acquires the facts at its atomic boundary derives the
    /// live guards with this method and compares them with `guards_hold`.
    #[must_use]
    pub fn guards(&self) -> Vec<RequiredGuard> {
        let repository = self.repository;
        let row = |row, value, revision| RequiredGuard::Row {
            repository,
            row,
            expected: Observed::Present { value, revision },
        };
        let mut out = vec![
            row(
                GuardRow::ClearancePrior,
                self.prior.commitment(),
                self.prior.revision,
            ),
            {
                let mut c = Commit::new("clearance-changed");
                c.hash(&self.changed.commitment())
                    .u8(match self.moment {
                        ClearanceMoment::Acceptance => 0,
                        ClearanceMoment::Recheck => 1,
                    })
                    .u8(state_tag(self.previous_state))
                    .bool(self.deleted);
                row(
                    GuardRow::ClearanceChanged(self.changed.sequence),
                    c.finish(),
                    self.changed.revision,
                )
            },
        ];
        for advance in self.suffix {
            out.push(row(
                GuardRow::ClearanceSuffix(advance.sequence),
                advance.commitment(),
                advance.revision,
            ));
        }
        // A dependency or supplier with no witness is decided as unsatisfied, so
        // its absence is guarded too: a witness that appears later moves the
        // decision and must fail the comparison.
        let needed = self
            .changed
            .dependencies
            .iter()
            .filter(|id| !self.changed.additions.contains(id))
            .chain(self.changed.external_suppliers);
        // The absence row carries the all-zero sentinel revision: it names "no
        // witness supplied", not a storage absence token.
        // Sets keep this O(n log n); `validate` charges the same items.
        let witnessed: std::collections::BTreeSet<Hash> =
            self.witnesses.iter().map(|w| w.object).collect();
        let mut guarded_absent = std::collections::BTreeSet::new();
        for object in needed {
            if !witnessed.contains(object) && guarded_absent.insert(*object) {
                out.push(RequiredGuard::Row {
                    repository,
                    row: GuardRow::ClearanceWitness(*object),
                    expected: Observed::Absent(Revision([0; 32])),
                });
            }
        }
        for witness in self.witnesses {
            out.push(row(
                GuardRow::ClearanceWitness(witness.object),
                witness.commitment(),
                witness.revision,
            ));
        }
        let mut c = Commit::new("clearance-lifecycle-profile");
        match &self.lifecycle {
            ClearanceLifecycle::NotOffered => {
                c.u8(0);
            }
            ClearanceLifecycle::Managed {
                expected_incarnation,
                current,
            } => {
                c.u8(1)
                    .revision(expected_incarnation)
                    .bool(current.is_some());
                if let Some(expected) = current {
                    out.push(RequiredGuard::Repository {
                        id: repository,
                        expected: expected.clone(),
                    });
                }
            }
        }
        out.push(row(
            GuardRow::ClearanceLifecycleProfile,
            c.finish(),
            Revision([0; 32]),
        ));
        out
    }
}

/// Finite host ceilings. They are not protocol constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClearanceLimits {
    /// Outstanding advances in one prefix walk.
    pub max_advances: u64,
    /// Dependencies, suppliers, additions, or obligations on one advance.
    pub max_items: usize,
    /// Charged comparisons.
    pub max_work: u64,
}

impl ClearanceLimits {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(max_advances: u64, max_items: usize, max_work: u64) -> Self {
        Self {
            max_advances,
            max_items,
            max_work,
        }
    }
}

impl ClearanceLimits {
    /// Reference ceilings: 64 outstanding advances, 4,096 items, and enough work
    /// for 4,096 dependencies against 4,096 additions plus 4,096 witnesses.
    #[must_use]
    pub const fn reference() -> Self {
        Self {
            max_advances: 64,
            max_items: 4096,
            max_work: 1 << 26,
        }
    }
}

/// Clearance outcome. No variant settles a reservation or records a terminal result.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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

/// Decide published clearance from facts the host already acquired.
///
/// The returned [`Guarded`] owns the typed guards of [`ClearanceFacts::guards`]:
/// the prior publication, the advance, every retained suffix advance and every
/// dependency witness, each by revision and commitment, plus the lifecycle
/// observation when the profile is managed.
///
/// # Errors
///
/// Returns a typed failure for malformed, unbounded, or contradictory facts.
/// An unsatisfied dependency at acceptance withholds the prefix; it is not an error.
#[must_use = "compare every supplied fact before publishing"]
pub fn decide_clearance<'a>(
    facts: &'a ClearanceFacts<'a>,
    limits: &ClearanceLimits,
) -> Result<Guarded<ClearanceDecision>, Failure> {
    validate(facts, limits)?;
    let decision = if facts.deleted {
        deletion(facts)?
    } else if facts.moment == ClearanceMoment::Acceptance {
        acceptance(facts)?
    } else {
        recheck(facts)?
    };
    Ok(Guarded::from_parts(
        facts.repository,
        decision,
        facts.guards(),
        Vec::new(),
    ))
}

/// Acceptance and clearance decided as one unit.
#[derive(Debug)]
#[must_use]
pub struct CombinedAcceptance {
    acceptance: Guarded<WriteDecision>,
    clearance: Option<Guarded<ClearanceDecision>>,
}

impl CombinedAcceptance {
    /// The acceptance decision, unchanged. It alone owns ticket consumption, the
    /// terminal result, and reservation settlement.
    #[must_use]
    pub const fn acceptance(&self) -> &Guarded<WriteDecision> {
        &self.acceptance
    }

    /// Clearance riding in the same unit. `None` unless acceptance applies; a
    /// replay, conflict, refusal, or retry never publishes.
    #[must_use]
    pub const fn clearance(&self) -> Option<&Guarded<ClearanceDecision>> {
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
/// Acceptance failures pass through. The binding runs first, so an unbound or
/// unobserved publication refuses even where acceptance would replay or conflict.
/// `InvalidResponse` when the clearance facts
/// are not an acceptance-moment, non-deletion view of the same repository and
/// operation; clearance failures pass through.
#[must_use = "compare every supplied fact before applying"]
pub fn decide_accept_and_clear(
    request: &TicketedAdvanceRequest<'_>,
    snapshot: &Snapshot,
    ref_limits: RefDecisionLimits,
    facts: &ClearanceFacts<'_>,
    limits: &ClearanceLimits,
) -> Result<CombinedAcceptance, Failure> {
    let write = &request.write;
    if facts.moment != ClearanceMoment::Acceptance
        || facts.deleted
        || facts.repository != write.repository
        || write.operation.as_ref() != Some(&facts.changed.operation)
    {
        return Err(invalid());
    }
    bind_acceptance(request, snapshot, facts)?;
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

/// The clearance advance must be the write being accepted: the canonical
/// packmap/head pair, and the publication state the acceptance snapshot guards.
fn bind_acceptance(
    request: &TicketedAdvanceRequest<'_>,
    snapshot: &Snapshot,
    facts: &ClearanceFacts<'_>,
) -> Result<(), Failure> {
    let [packmap, head] = request.write.changes else {
        return Err(invalid());
    };
    let Some(observed) = &snapshot.publication else {
        return Err(unavailable());
    };
    let prior = &facts.prior;
    let publication_matches = match observed {
        Observed::Present { value, revision } => {
            *revision == prior.revision
                && value.sequence == prior.sequence
                && value.published_prefix == prior.published_prefix
                && value.deletion_boundary == prior.deletion_boundary
                && value.head == prior.head
                && value.packmap == prior.packmap
        }
        // No publication row yet: the prior identity must be the empty one.
        Observed::Absent(revision) => {
            *revision == prior.revision
                && prior.sequence == 0
                && prior.published_prefix == 0
                && prior.deletion_boundary == 0
                && prior.head.is_none()
                && prior.packmap.is_none()
        }
    };
    if facts.changed.packmap != packmap.target
        || facts.changed.head != head.target
        || !publication_matches
    {
        return Err(invalid());
    }
    Ok(())
}

fn deletion(facts: &ClearanceFacts<'_>) -> Result<ClearanceDecision, Failure> {
    let sequence = facts.prior.sequence.checked_add(1).ok_or_else(resource)?;
    if facts.changed.sequence != sequence {
        return Err(invalid());
    }
    Ok(ClearanceDecision::AdvancePrefix {
        published_prefix: sequence,
        // A deletion carries no component of its own: it keeps a prior value only
        // where the deletion advance also names that component.
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
            // Only the changed record gets dependency and lifecycle checks; the
            // host retained the others under them. Cheap local facts still apply.
            record.state.publishable()
                && !record.flagged
                && obligations_publishable(record)
                && (record.state != ClearanceState::Resolved || record.takedown_complete)
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
    if !lifecycle_allows(&facts.lifecycle, facts.moment)? {
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

fn lifecycle_allows(
    protection: &ClearanceLifecycle,
    moment: ClearanceMoment,
) -> Result<bool, Failure> {
    match protection {
        ClearanceLifecycle::NotOffered => Ok(true),
        ClearanceLifecycle::Managed {
            expected_incarnation,
            current,
        } => match current {
            None => Err(unavailable()),
            Some(Observed::Absent(_)) => Ok(false),
            Some(Observed::Present { value, .. }) => {
                if value.incarnation != *expected_incarnation {
                    // A retained claim bound to another incarnation is contradictory.
                    return if moment == ClearanceMoment::Recheck {
                        Err(invalid())
                    } else {
                        Ok(false)
                    };
                }
                Ok(value.state == LifecycleState::Active)
            }
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
    // One witness per object: a conflicting second entry must not be able to
    // satisfy a dependency another entry denies.
    let mut seen = std::collections::BTreeSet::new();
    if !facts.witnesses.iter().all(|w| seen.insert(w.object)) {
        return Err(invalid());
    }
    let changed = &facts.changed;
    let lookups = (changed.dependencies.len() as u64)
        .saturating_mul(changed.additions.len() as u64 + facts.witnesses.len() as u64)
        .saturating_add(
            (changed.external_suppliers.len() as u64).saturating_mul(facts.witnesses.len() as u64),
        );
    let mut work = limits.max_work;
    charge(
        &mut work,
        lookups
            .saturating_add(facts.suffix.len() as u64)
            .saturating_add(facts.witnesses.len() as u64)
            // Deriving the guards: ordered-set build and probes over every
            // dependency, supplier and witness, about three comparisons each.
            .saturating_add(
                (changed.dependencies.len() as u64)
                    .saturating_add(changed.external_suppliers.len() as u64)
                    .saturating_add(facts.witnesses.len() as u64)
                    .saturating_mul(3),
            ),
    )?;
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
    if advance.obligation_revisions.len() != advance.obligations.len() {
        return Err(invalid());
    }
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
