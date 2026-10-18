//! Published-clearance decisions. No case emits a terminal outcome or settlement.

use mkit_core::hash::Hash;
use mkit_primitives::decision::{
    ClearanceAdvance, ClearanceDecision, ClearanceFacts, ClearanceLifecycle, ClearanceLimits,
    ClearanceMoment, ClearanceState, DependencyWitness, Observed, OperationId, PriorPublication,
    decide_clearance,
};
use mkit_primitives::error::FailureCode;
use mkit_primitives::evidence::{RepositoryId, Revision};

fn byte(n: u64) -> u8 {
    u8::try_from(n).unwrap_or(0)
}

fn id(byte: u8) -> Hash {
    let mut raw = [0; 32];
    raw[0] = byte;
    raw
}

fn rev(byte: u8) -> Revision {
    Revision([byte; 32])
}

fn advance<'a>(
    sequence: u64,
    state: ClearanceState,
    additions: &'a [Hash],
    dependencies: &'a [Hash],
    suppliers: &'a [Hash],
) -> ClearanceAdvance<'a> {
    ClearanceAdvance {
        sequence,
        generation: 1,
        operation: OperationId([byte(sequence); 32]),
        head: Some(id(byte(sequence))),
        packmap: Some(id(byte(sequence + 10))),
        state,
        additions,
        dependencies,
        external_suppliers: suppliers,
        obligations: &[],
        obligation_revisions: &[],
        takedown_complete: false,
        flagged: false,
        revision: rev(byte(sequence)),
    }
}

fn prior(published: u64, sequence: u64) -> PriorPublication {
    PriorPublication {
        generation: 1,
        sequence,
        published_prefix: published,
        deletion_boundary: 0,
        head: Some(id(byte(published))),
        packmap: Some(id(byte(published + 10))),
        revision: rev(9),
    }
}

fn facts<'a>(
    moment: ClearanceMoment,
    prior: PriorPublication,
    changed: ClearanceAdvance<'a>,
    suffix: &'a [ClearanceAdvance<'a>],
    witnesses: &'a [DependencyWitness],
) -> ClearanceFacts<'a> {
    ClearanceFacts {
        repository: RepositoryId([1; 32]),
        moment,
        prior,
        previous_state: changed.state,
        changed,
        suffix,
        witnesses,
        lifecycle: ClearanceLifecycle::NotOffered,
        deleted: false,
    }
}

fn witness(object: Hash, published: bool) -> DependencyWitness {
    DependencyWitness {
        object,
        present: true,
        published,
        held: false,
        generation: 1,
        revision: rev(4),
    }
}

#[test]
fn contiguous_cleared_prefix_advances_and_stops_at_pending() {
    let packs = [id(1), id(2), id(3)];
    let first = advance(1, ClearanceState::Cleared, &packs[..1], &packs[..1], &[]);
    let second = advance(2, ClearanceState::Pending, &packs[1..2], &packs[1..2], &[]);
    let third = advance(3, ClearanceState::Cleared, &packs[2..], &packs[2..], &[]);
    let suffix = [first.clone(), second.clone(), third.clone()];
    let input = facts(ClearanceMoment::Recheck, prior(0, 3), second, &suffix, &[]);
    let decided = decide_clearance(&input, &ClearanceLimits::reference()).unwrap();
    assert_eq!(
        decided.decision(),
        &ClearanceDecision::AdvancePrefix {
            published_prefix: 1,
            head: Some(id(1)),
            packmap: Some(id(11)),
            deletion_boundary: 0,
        }
    );
    assert!(decided.matches(&input));
}

#[test]
fn out_of_order_clearance_does_not_skip_an_earlier_pending_advance() {
    let pack = [id(2)];
    let pending = advance(1, ClearanceState::Pending, &[], &[], &[]);
    let cleared = advance(2, ClearanceState::Cleared, &pack, &pack, &[]);
    let suffix = [pending, cleared.clone()];
    let input = facts(ClearanceMoment::Recheck, prior(0, 2), cleared, &suffix, &[]);
    let decided = decide_clearance(&input, &ClearanceLimits::reference()).unwrap();
    assert_eq!(
        decided.decision(),
        &ClearanceDecision::Retain {
            published_prefix: 0
        }
    );
}

#[test]
fn own_additions_do_not_satisfy_an_external_supplier() {
    let pack = [id(7)];
    let mut changed = advance(1, ClearanceState::Cleared, &pack, &pack, &pack);
    changed.external_suppliers = &pack;
    let input = facts(ClearanceMoment::Acceptance, prior(0, 0), changed, &[], &[]);
    let decided = decide_clearance(&input, &ClearanceLimits::reference()).unwrap();
    assert!(matches!(
        decided.decision(),
        ClearanceDecision::Retain { .. }
    ));

    let published = [witness(id(7), true)];
    let mut changed = advance(1, ClearanceState::Cleared, &pack, &pack, &pack);
    changed.external_suppliers = &pack;
    let input = facts(
        ClearanceMoment::Acceptance,
        prior(0, 0),
        changed,
        &[],
        &published,
    );
    assert!(matches!(
        decide_clearance(&input, &ClearanceLimits::reference())
            .unwrap()
            .decision(),
        ClearanceDecision::AdvancePrefix {
            published_prefix: 1,
            ..
        }
    ));
}

#[test]
fn deletion_publishes_the_boundary_without_resurrecting_a_missing_component() {
    let mut changed = advance(4, ClearanceState::Pending, &[], &[], &[]);
    changed.head = Some(id(4));
    changed.packmap = None;
    let mut input = facts(ClearanceMoment::Acceptance, prior(3, 3), changed, &[], &[]);
    input.deleted = true;
    input.prior.head = Some(id(3));
    input.prior.packmap = Some(id(13));
    let decided = decide_clearance(&input, &ClearanceLimits::reference()).unwrap();
    assert_eq!(
        decided.decision(),
        &ClearanceDecision::AdvancePrefix {
            published_prefix: 4,
            head: Some(id(3)),
            packmap: None,
            deletion_boundary: 4,
        }
    );
}

#[test]
fn hit_cannot_become_cleared_and_resolved_requires_takedown() {
    let pack = [id(1)];
    let mut changed = advance(1, ClearanceState::Cleared, &pack, &pack, &[]);
    let suffix = [changed.clone()];
    let mut input = facts(
        ClearanceMoment::Recheck,
        prior(0, 1),
        changed.clone(),
        &suffix,
        &[],
    );
    input.previous_state = ClearanceState::Hit;
    assert_eq!(
        decide_clearance(&input, &ClearanceLimits::reference())
            .unwrap_err()
            .code,
        FailureCode::InvalidResponse
    );

    changed.state = ClearanceState::Resolved;
    changed.takedown_complete = false;
    let suffix = [changed.clone()];
    let input = facts(ClearanceMoment::Recheck, prior(0, 1), changed, &suffix, &[]);
    assert_eq!(
        decide_clearance(&input, &ClearanceLimits::reference())
            .unwrap_err()
            .code,
        FailureCode::InvalidResponse
    );
}

#[test]
fn flagged_advance_and_held_supplier_withhold_publication() {
    let pack = [id(5)];
    let mut changed = advance(1, ClearanceState::Cleared, &pack, &pack, &[]);
    changed.flagged = true;
    let input = facts(ClearanceMoment::Acceptance, prior(0, 0), changed, &[], &[]);
    assert!(matches!(
        decide_clearance(&input, &ClearanceLimits::reference())
            .unwrap()
            .decision(),
        ClearanceDecision::Retain { .. }
    ));

    let changed = advance(1, ClearanceState::Cleared, &[], &pack, &[]);
    let mut held = witness(id(5), true);
    held.held = true;
    let witnesses = [held];
    let input = facts(
        ClearanceMoment::Acceptance,
        prior(0, 0),
        changed,
        &[],
        &witnesses,
    );
    assert!(matches!(
        decide_clearance(&input, &ClearanceLimits::reference())
            .unwrap()
            .decision(),
        ClearanceDecision::Retain { .. }
    ));
}

#[test]
fn combined_acceptance_moves_only_the_next_eligible_prefix() {
    let pack = [id(1)];
    let changed = advance(2, ClearanceState::Cleared, &pack, &pack, &[]);
    let input = facts(ClearanceMoment::Acceptance, prior(0, 1), changed, &[], &[]);
    assert!(matches!(
        decide_clearance(&input, &ClearanceLimits::reference())
            .unwrap()
            .decision(),
        ClearanceDecision::Retain {
            published_prefix: 0
        }
    ));
}

#[test]
fn mutated_snapshot_does_not_match_and_managed_lifecycle_fails_closed() {
    let pack = [id(1)];
    let changed = advance(1, ClearanceState::Cleared, &pack, &pack, &[]);
    let input = facts(ClearanceMoment::Acceptance, prior(0, 0), changed, &[], &[]);
    let decided = decide_clearance(&input, &ClearanceLimits::reference()).unwrap();
    let mut moved = input.clone();
    moved.prior.revision = rev(8);
    assert!(!decided.matches(&moved));

    let mut managed = input.clone();
    managed.lifecycle = ClearanceLifecycle::Managed {
        expected_incarnation: rev(1),
        current: None,
    };
    assert_eq!(
        decide_clearance(&managed, &ClearanceLimits::reference())
            .unwrap_err()
            .code,
        FailureCode::UnavailableInput
    );
    managed.lifecycle = ClearanceLifecycle::Managed {
        expected_incarnation: rev(1),
        current: Some(Observed::Present {
            value: mkit_primitives::decision::LifecycleFact {
                incarnation: rev(1),
                state: mkit_primitives::decision::LifecycleState::Deleted,
            },
            revision: rev(2),
        }),
    };
    assert!(matches!(
        decide_clearance(&managed, &ClearanceLimits::reference())
            .unwrap()
            .decision(),
        ClearanceDecision::Retain { .. }
    ));
}

#[test]
fn hostile_suffix_and_item_counts_refuse_before_publication() {
    let pack = [id(1)];
    let changed = advance(2, ClearanceState::Cleared, &pack, &pack, &[]);
    let gap = [changed.clone()];
    let input = facts(ClearanceMoment::Recheck, prior(0, 2), changed, &gap, &[]);
    assert_eq!(
        decide_clearance(&input, &ClearanceLimits::reference())
            .unwrap_err()
            .code,
        FailureCode::InvalidResponse
    );

    let huge = vec![id(9); 5];
    let changed = advance(1, ClearanceState::Cleared, &huge, &huge, &[]);
    let input = facts(ClearanceMoment::Acceptance, prior(0, 0), changed, &[], &[]);
    let limits = ClearanceLimits {
        max_advances: 64,
        max_items: 2,
        max_work: 100,
    };
    assert_eq!(
        decide_clearance(&input, &limits).unwrap_err().code,
        FailureCode::ResourceLimit
    );
}

#[test]
fn seeded_hostile_facts_are_deterministic_and_never_settle() {
    let mut first = Vec::new();
    let mut second = Vec::new();
    for byte in 0..32 {
        first.push(hostile(byte));
        second.push(hostile(byte));
    }
    assert_eq!(first, second);
    assert!(first.iter().any(|decision| matches!(
        decision,
        Ok(ClearanceDecision::Retain { .. }) | Err(FailureCode::InvalidResponse)
    )));
}

fn hostile(byte: u8) -> Result<ClearanceDecision, FailureCode> {
    let pack = [id(byte)];
    let mut changed = advance(1, ClearanceState::Cleared, &pack, &pack, &[]);
    changed.flagged = byte.is_multiple_of(2);
    changed.generation = u64::from(byte % 3);
    let mut input = facts(ClearanceMoment::Acceptance, prior(0, 0), changed, &[], &[]);
    if byte.is_multiple_of(5) {
        input.deleted = true;
        input.changed.sequence = 0;
    }
    decide_clearance(&input, &ClearanceLimits::reference())
        .map(|guard| guard.decision().clone())
        .map_err(|error| error.code)
}

#[test]
fn conflicting_witnesses_and_foreign_incarnation_fail_closed() {
    let pack = [id(1)];
    let supplier = [id(5)];
    let changed = advance(1, ClearanceState::Cleared, &pack, &pack, &supplier);
    let witnesses = [witness(id(5), true), witness(id(5), false)];
    let input = facts(
        ClearanceMoment::Acceptance,
        prior(0, 0),
        changed.clone(),
        &[],
        &witnesses,
    );
    assert_eq!(
        decide_clearance(&input, &ClearanceLimits::reference())
            .unwrap_err()
            .code,
        FailureCode::InvalidResponse
    );

    let witnesses = [witness(id(5), true)];
    let mut managed = facts(
        ClearanceMoment::Acceptance,
        prior(0, 0),
        changed,
        &[],
        &witnesses,
    );
    managed.lifecycle = ClearanceLifecycle::Managed {
        expected_incarnation: rev(1),
        current: Some(Observed::Present {
            value: mkit_primitives::decision::LifecycleFact {
                incarnation: rev(2),
                state: mkit_primitives::decision::LifecycleState::Active,
            },
            revision: rev(2),
        }),
    };
    assert!(matches!(
        decide_clearance(&managed, &ClearanceLimits::reference())
            .unwrap()
            .decision(),
        ClearanceDecision::Retain { .. }
    ));
}

#[test]
fn lookup_work_is_charged_and_flagged_suffix_records_withhold() {
    let many: Vec<Hash> = (0..=255).map(id).collect();
    let changed = advance(1, ClearanceState::Cleared, &many, &many, &[]);
    let input = facts(ClearanceMoment::Acceptance, prior(0, 0), changed, &[], &[]);
    let tight = ClearanceLimits {
        max_work: 1000,
        ..ClearanceLimits::reference()
    };
    assert_eq!(
        decide_clearance(&input, &tight).unwrap_err().code,
        FailureCode::ResourceLimit
    );

    let mut flagged = advance(1, ClearanceState::Cleared, &[], &[], &[]);
    flagged.flagged = true;
    let next = advance(2, ClearanceState::Cleared, &[], &[], &[]);
    let suffix = [flagged, next.clone()];
    let input = facts(ClearanceMoment::Recheck, prior(0, 2), next, &suffix, &[]);
    assert!(matches!(
        decide_clearance(&input, &ClearanceLimits::reference())
            .unwrap()
            .decision(),
        ClearanceDecision::Retain {
            published_prefix: 0
        }
    ));
}

#[test]
fn large_valid_dependency_sets_fit_the_reference_work_ceiling() {
    let many: Vec<Hash> = (0..2048u16)
        .map(|n| {
            let mut raw = [0; 32];
            raw[..2].copy_from_slice(&n.to_be_bytes());
            raw
        })
        .collect();
    let changed = advance(1, ClearanceState::Cleared, &many, &many, &[]);
    let input = facts(ClearanceMoment::Acceptance, prior(0, 0), changed, &[], &[]);
    assert!(decide_clearance(&input, &ClearanceLimits::reference()).is_ok());
}
