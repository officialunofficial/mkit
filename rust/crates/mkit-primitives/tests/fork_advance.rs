use mkit_core::hash::Hasher;
use mkit_primitives::decision::{LifecycleState, Observed, RefName, guards_hold};
use mkit_primitives::error::FailureCode;
use mkit_primitives::evidence::{RepositoryId, Revision};
use mkit_primitives::fork::*;

fn rev(n: u8) -> Revision {
    Revision([n; 32])
}
fn progress() -> ForkAdvanceFacts {
    {
        let mut v = ForkAdvanceFacts::new(
            [1; 32],
            RepositoryId([2; 32]),
            ForkProgress::new(ForkAdvancePhase::Preparing, 0, 0, rev(3)),
            100,
        );
        v.recorded_authority = ForkObservation::Absent;
        v.authority = ForkObservation::Absent;
        v.grant_epoch = Some(ForkEpochFence::new(
            ForkObservation::Present(rev(4)),
            ForkObservation::Present(rev(4)),
        ));
        v.reservation = Some(ForkReservationFence::new(
            mkit_primitives::decision::ReservationId([5; 32]),
            rev(5),
            ForkObservation::Present(rev(5)),
        ));
        v
    }
}
fn result() -> ForkResult {
    let mut digest = Hasher::new();
    digest.update(&[7; 32]);
    digest.update(&[8; 32]);
    ForkResult::new(
        RefName("main".into()),
        RepositoryId([6; 32]),
        9,
        [10; 32],
        [8; 32],
        2,
        42,
        3,
        digest.finalize(),
        rev(1),
    )
}
fn unit() -> ForkMembershipUnit {
    ForkMembershipUnit::new(
        [7; 32],
        rev(3),
        ForkWitness::new(rev(1), 0, true, false, false),
        None,
        None,
        ForkPairContext::Initial,
    )
}
fn proof() -> ForkClearanceProof {
    ForkClearanceProof::new(
        RepositoryId([2; 32]),
        [1; 32],
        rev(3),
        [7; 32],
        rev(12),
        200,
        rev(13),
    )
}
fn limits() -> ForkActivationLimits {
    ForkActivationLimits::new(2, 4, 200)
}
const PACKS: [[u8; 32]; 2] = [[7; 32], [8; 32]];
fn facts<'a>(
    advance: &'a ForkAdvanceFacts,
    result: &'a ForkResult,
    unit: &'a ForkMembershipUnit,
    proof: &'a ForkClearanceProof,
) -> ForkActivationFacts<'a> {
    {
        let mut v = ForkActivationFacts::new(advance, result, &PACKS, unit);
        v.lifecycle = ForkLifecycleProtection::NotOffered;
        v.accepted_result = Some(result);
        v.proof = Some(proof);
        v
    }
}

#[test]
fn advance_guards_every_fixed_shape_field_and_samples_construction_expiry() {
    let original = progress();
    let guard = decide_fork_advance(&original, 100);
    assert_eq!(*guard.decision(), ForkAdvanceDecision::Advance);
    assert!(guards_hold(&guard, &original.guards(), 0));
    // Starting at the inclusive boundary is eligible; a new phase after it
    // refuses. The original decision does not invent a later commit deadline.
    assert_eq!(
        *decide_fork_advance(&original, 101).decision(),
        ForkAdvanceDecision::Refuse(ForkAdvanceRefusal::Expired)
    );
    let mutations: Vec<ForkAdvanceFacts> = (0..13)
        .map(|n| {
            let mut f = original.clone();
            match n {
                0 => f.binding[0] ^= 1,
                1 => f.destination.0[0] ^= 1,
                2 => f.progress.phase = ForkAdvancePhase::Accepted,
                3 => f.progress.cursor += 1,
                4 => f.progress.part += 1,
                5 => f.progress.revision = rev(99),
                6 => f.recorded_authority = ForkObservation::Present(rev(99)),
                7 => f.authority = ForkObservation::Present(rev(99)),
                8 => f.grant_epoch.as_mut().unwrap().recorded = ForkObservation::Absent,
                9 => f.grant_epoch.as_mut().unwrap().current = ForkObservation::Absent,
                10 => f.reservation.as_mut().unwrap().current = ForkObservation::Absent,
                11 => f.construction_expires_ms += 1,
                _ => f.reservation.as_mut().unwrap().reservation.0[0] ^= 1,
            }
            f
        })
        .collect();
    for changed in mutations {
        assert!(!guards_hold(&guard, &changed.guards(), 0));
    }
    let mut changed = original.clone();
    changed.reservation.as_mut().unwrap().expected = rev(99);
    assert!(!guards_hold(&guard, &changed.guards(), 0));
    changed = original.clone();
    changed.grant_epoch = None;
    assert!(!guards_hold(&guard, &changed.guards(), 0));
    changed = original.clone();
    changed.reservation = None;
    assert!(!guards_hold(&guard, &changed.guards(), 0));
}
#[test]
fn authority_precedes_epoch_and_reservation_and_terminal_replay_never_advances() {
    let mut f = progress();
    f.authority = ForkObservation::Present(rev(9));
    f.grant_epoch.as_mut().unwrap().current = ForkObservation::Absent;
    f.reservation.as_mut().unwrap().current = ForkObservation::Absent;
    assert_eq!(
        *decide_fork_advance(&f, 101).decision(),
        ForkAdvanceDecision::Refuse(ForkAdvanceRefusal::AuthorityMoved)
    );
    f.authority = f.recorded_authority;
    assert_eq!(
        *decide_fork_advance(&f, 101).decision(),
        ForkAdvanceDecision::Refuse(ForkAdvanceRefusal::EpochMoved)
    );
    f.grant_epoch = None;
    assert_eq!(
        *decide_fork_advance(&f, 101).decision(),
        ForkAdvanceDecision::Refuse(ForkAdvanceRefusal::Expired)
    );
    assert_eq!(
        *decide_fork_advance(&f, 100).decision(),
        ForkAdvanceDecision::Refuse(ForkAdvanceRefusal::ReservationSettled)
    );
    for phase in [ForkAdvancePhase::Complete, ForkAdvancePhase::Failed] {
        f.progress.phase = phase;
        assert_eq!(
            *decide_fork_advance(&f, 101).decision(),
            ForkAdvanceDecision::Terminal
        );
    }
}
#[test]
fn accepted_clearance_outlives_expiry_and_reservation_pruning() {
    let mut f = progress();
    f.progress.phase = ForkAdvancePhase::Accepted;
    f.reservation.as_mut().unwrap().current = ForkObservation::Absent;
    let guard = decide_fork_advance(&f, u64::MAX);
    assert_eq!(*guard.decision(), ForkAdvanceDecision::Advance);
    assert!(guards_hold(&guard, &f.guards(), 0));
    f.reservation = None;
    assert_eq!(
        *decide_fork_advance(&f, u64::MAX).decision(),
        ForkAdvanceDecision::Advance
    );
    f.authority = ForkObservation::Present(rev(9));
    assert_eq!(
        *decide_fork_advance(&f, u64::MAX).decision(),
        ForkAdvanceDecision::Refuse(ForkAdvanceRefusal::AuthorityMoved)
    );
}
#[test]
fn exact_witness_pair_is_idempotent_and_foreign_rows_are_never_replaced() {
    let mut advance = progress();
    advance.progress.phase = ForkAdvancePhase::Accepted;
    let result = result();
    let proof = proof();
    let mut unit = unit();
    assert_eq!(
        *decide_fork_activation(&facts(&advance, &result, &unit, &proof), 200, limits())
            .unwrap()
            .decision(),
        ForkActivationDecision::Install
    );
    unit.live = Some(unit.expected);
    unit.published = Some(unit.expected);
    assert_eq!(
        *decide_fork_activation(&facts(&advance, &result, &unit, &proof), 200, limits())
            .unwrap()
            .decision(),
        ForkActivationDecision::Replay
    );
    for field in 0..5 {
        let mut foreign = unit.expected;
        match field {
            0 => foreign.generation = rev(9),
            1 => foreign.sequence = 1,
            2 => foreign.published = false,
            3 => foreign.held = true,
            _ => foreign.boundary = true,
        }
        for live in [true, false] {
            let mut changed = unit.clone();
            if live {
                changed.live = Some(foreign);
            } else {
                changed.published = Some(foreign);
            }
            assert_eq!(
                *decide_fork_activation(&facts(&advance, &result, &changed, &proof), 200, limits())
                    .unwrap()
                    .decision(),
                ForkActivationDecision::Refuse(ForkRefusal::DestinationNotEmpty)
            );
        }
    }
}
#[test]
fn partial_pair_error_precedence_distinguishes_guard_loss() {
    let mut advance = progress();
    advance.progress.phase = ForkAdvancePhase::Accepted;
    let result = result();
    let proof = proof();
    for live in [true, false] {
        let mut unit = unit();
        if live {
            unit.live = Some(unit.expected);
        } else {
            unit.published = Some(unit.expected);
        }
        assert_eq!(
            *decide_fork_activation(&facts(&advance, &result, &unit, &proof), 0, limits())
                .unwrap()
                .decision(),
            ForkActivationDecision::Refuse(ForkRefusal::DestinationNotEmpty)
        );
        unit.context = ForkPairContext::AfterGuardLoss;
        assert_eq!(
            *decide_fork_activation(&facts(&advance, &result, &unit, &proof), 0, limits())
                .unwrap()
                .decision(),
            ForkActivationDecision::RetryPartial
        );
    }
}
#[test]
fn missing_expired_wrongly_scoped_and_mutated_proofs_fail_closed() {
    let mut advance = progress();
    advance.progress.phase = ForkAdvancePhase::Accepted;
    let result = result();
    let proof = proof();
    let unit = unit();
    let original = facts(&advance, &result, &unit, &proof);
    let guard = decide_fork_activation(&original, 200, limits()).unwrap();
    assert!(guards_hold(&guard, &original.guards(), 200));
    assert!(!guards_hold(&guard, &original.guards(), 201));
    let mut missing = original.clone();
    missing.proof = None;
    assert_eq!(
        decide_fork_activation(&missing, 0, limits())
            .unwrap_err()
            .code,
        FailureCode::UnavailableInput
    );
    assert_eq!(
        decide_fork_activation(&original, 201, limits())
            .unwrap_err()
            .code,
        FailureCode::UnavailableInput
    );
    for field in 0..7 {
        let mut changed = proof.clone();
        match field {
            0 => changed.destination.0[0] ^= 1,
            1 => changed.binding[0] ^= 1,
            2 => changed.progress_revision = rev(99),
            3 => changed.pack[0] ^= 1,
            4 => changed.apply_attempt = rev(99),
            5 => changed.denial_revision = rev(99),
            _ => changed.valid_through_ms += 1,
        }
        let altered = facts(&advance, &result, &unit, &changed);
        assert!(!guards_hold(&guard, &altered.guards(), 200));
        if field < 4 {
            assert_eq!(
                decide_fork_activation(&altered, 0, limits())
                    .unwrap_err()
                    .code,
                FailureCode::InvalidResponse
            );
        }
    }
}
#[test]
fn malicious_inventory_result_and_witness_facts_cannot_authorize_membership() {
    let mut advance = progress();
    advance.progress.phase = ForkAdvancePhase::Accepted;
    let result = result();
    let proof = proof();
    let unit = unit();
    for ids in [
        &[[7; 32], [7; 32]][..],
        &[[8; 32], [7; 32]][..],
        &[[7; 32]][..],
        &[[6; 32], [8; 32]][..],
    ] {
        let mut f = facts(&advance, &result, &unit, &proof);
        f.inherited_packs = ids;
        assert_eq!(
            decide_fork_activation(&f, 0, limits()).unwrap_err().code,
            FailureCode::InvalidResponse
        );
    }
    for field in 0..5 {
        let mut changed = unit.clone();
        match field {
            0 => changed.expected.generation = rev(99),
            1 => changed.expected.sequence = 1,
            2 => changed.expected.published = false,
            3 => changed.expected.held = true,
            _ => changed.expected.boundary = true,
        }
        assert_eq!(
            decide_fork_activation(&facts(&advance, &result, &changed, &proof), 0, limits())
                .unwrap_err()
                .code,
            FailureCode::InvalidResponse
        );
    }
    let mut changed = result.clone();
    changed.source_sequence += 1;
    let mut f = facts(&advance, &result, &unit, &proof);
    f.accepted_result = Some(&changed);
    assert_eq!(
        *decide_fork_activation(&f, 0, limits()).unwrap().decision(),
        ForkActivationDecision::Refuse(ForkRefusal::BindingMismatch)
    );
    f.accepted_result = None;
    assert_eq!(
        *decide_fork_activation(&f, 0, limits()).unwrap().decision(),
        ForkActivationDecision::Refuse(ForkRefusal::BindingMismatch)
    );
}
#[test]
fn activation_bounds_precede_unavailable_acquisition_and_comparisons() {
    let advance = progress();
    let result = result();
    let unit = unit();
    let proof = proof();
    let mut f = facts(&advance, &result, &unit, &proof);
    f.proof = None;
    for limit in [
        {
            let mut v = limits();
            v.packs = 1;
            v
        },
        {
            let mut v = limits();
            v.branch_bytes = 3;
            v
        },
        {
            let mut v = limits();
            v.work = 1;
            v
        },
    ] {
        assert_eq!(
            decide_fork_activation(&f, 0, limit).unwrap_err().code,
            FailureCode::ResourceLimit
        );
    }
}
#[test]
fn completion_requires_exact_inventory_progress_barrier_and_never_settles() {
    let mut advance = progress();
    advance.progress.phase = ForkAdvancePhase::Accepted;
    let result = result();
    let original = {
        let mut v = ForkCompletionFacts::new(
            &advance,
            &result,
            2,
            0,
            2,
            result.pack_digest,
            advance.binding,
        );
        v.lifecycle = ForkLifecycleProtection::NotOffered;
        v.accepted_result = Some(&result);
        v
    };
    let guard = decide_fork_completion(&original, limits()).unwrap();
    assert_eq!(*guard.decision(), ForkCompletionDecision::Complete);
    assert!(guards_hold(&guard, &original.guards(), 0));
    for field in 0..6 {
        let mut changed = original.clone();
        match field {
            0 => changed.completed_packs -= 1,
            1 => changed.completed_digest[0] ^= 1,
            2 => changed.expected_barrier_owner[0] ^= 1,
            3 => changed.accepted_result = None,
            4 => changed.completed_cursor -= 1,
            _ => changed.completed_part = 1,
        }
        assert!(!guards_hold(&guard, &changed.guards(), 0));
        assert_eq!(
            *decide_fork_completion(&changed, limits())
                .unwrap()
                .decision(),
            ForkCompletionDecision::Refuse(ForkRefusal::BindingMismatch)
        );
    }
    let mut moved_checkpoint = advance.clone();
    moved_checkpoint.progress.cursor = 1;
    moved_checkpoint.progress.part = 1;
    moved_checkpoint.progress.revision = rev(99);
    let moved = {
        let mut v = original.clone();
        v.advance = &moved_checkpoint;
        v
    };
    assert!(!guards_hold(&guard, &moved.guards(), 0));
    // A new checkpoint can still complete units finished before this commit.
    assert_eq!(
        *decide_fork_completion(&moved, limits()).unwrap().decision(),
        ForkCompletionDecision::Complete
    );
    moved_checkpoint.progress.cursor = 3;
    let backwards = {
        let mut v = original.clone();
        v.advance = &moved_checkpoint;
        v
    };
    assert_eq!(
        *decide_fork_completion(&backwards, limits())
            .unwrap()
            .decision(),
        ForkCompletionDecision::Refuse(ForkRefusal::BindingMismatch)
    );
    let mut done = advance.clone();
    done.progress.phase = ForkAdvancePhase::Complete;
    let replay = {
        let mut v = original;
        v.lifecycle = ForkLifecycleProtection::NotOffered;
        v.advance = &done;
        v
    };
    assert_eq!(
        *decide_fork_completion(&replay, limits())
            .unwrap()
            .decision(),
        ForkCompletionDecision::Replay
    );
}

#[test]
fn every_saved_result_component_is_immutable_at_activation() {
    let mut advance = progress();
    advance.progress.phase = ForkAdvancePhase::Accepted;
    let result = result();
    let unit = unit();
    let proof = proof();
    for field in 0..10 {
        let mut changed = result.clone();
        match field {
            0 => changed.branch.0 = "next".into(),
            1 => changed.source.0[0] ^= 1,
            2 => changed.source_sequence += 1,
            3 => changed.tip[0] ^= 1,
            4 => changed.packmap[0] ^= 1,
            5 => changed.packs += 1,
            6 => changed.bytes += 1,
            7 => changed.index_entries += 1,
            8 => changed.pack_digest[0] ^= 1,
            _ => changed.destination_generation = rev(99),
        }
        let mut f = facts(&advance, &result, &unit, &proof);
        f.accepted_result = Some(&changed);
        assert_eq!(
            *decide_fork_activation(&f, 0, limits()).unwrap().decision(),
            ForkActivationDecision::Refuse(ForkRefusal::BindingMismatch)
        );
    }
}

#[test]
fn accepted_refusal_and_terminal_failure_need_no_invented_clearance_proof() {
    let mut advance = progress();
    advance.progress.phase = ForkAdvancePhase::Accepted;
    let result = result();
    let unit = unit();
    let proof = proof();
    let mut f = facts(&advance, &result, &unit, &proof);
    f.proof = None;
    f.accepted_result = None;
    assert_eq!(
        *decide_fork_activation(&f, 0, limits()).unwrap().decision(),
        ForkActivationDecision::Refuse(ForkRefusal::BindingMismatch)
    );
    advance.authority = ForkObservation::Present(rev(99));
    let mut f = facts(&advance, &result, &unit, &proof);
    f.proof = None;
    assert_eq!(
        *decide_fork_activation(&f, 0, limits()).unwrap().decision(),
        ForkActivationDecision::Defer(ForkAdvanceRefusal::AuthorityMoved)
    );
    advance.progress.phase = ForkAdvancePhase::Failed;
    let mut f = facts(&advance, &result, &unit, &proof);
    f.proof = None;
    assert_eq!(
        *decide_fork_activation(&f, 0, limits()).unwrap().decision(),
        ForkActivationDecision::Refuse(ForkRefusal::BindingMismatch)
    );
}

/// Shared bounded activation fuzz replay.
#[path = "support/fork_advance.rs"]
pub mod fuzz_support;

#[test]
fn hostile_progress_and_activation_seed_replay_is_bounded() {
    fuzz_support::fuzz_fork_advance(&[]);
    for seed in 0_u8..=255 {
        let mut bytes = [0; 96];
        for (offset, byte) in (0_u8..).zip(bytes.iter_mut()) {
            *byte = seed.wrapping_mul(31).wrapping_add(offset);
        }
        fuzz_support::fuzz_fork_advance(&bytes);
        fuzz_support::fuzz_fork_advance(&bytes[..usize::from(seed) % bytes.len()]);
    }
    fuzz_support::fuzz_fork_advance(&vec![255; fuzz_support::MAX_INPUT_BYTES]);
    fuzz_support::fuzz_fork_advance(&vec![255; fuzz_support::MAX_INPUT_BYTES + 1]);
}

fn managed_lifecycle(state: mkit_primitives::decision::LifecycleState) -> ForkLifecycleProtection {
    ForkLifecycleProtection::Managed {
        expected_incarnation: rev(1),
        current: Some(mkit_primitives::decision::Observed::Present {
            value: mkit_primitives::decision::LifecycleFact::new(rev(1), state),
            revision: rev(20),
        }),
    }
}

#[test]
fn managed_lifecycle_requires_acquisition_active_incarnation_and_exact_revision() {
    assert_eq!(
        ForkWithheld::LifecycleUnavailable.code().as_str(),
        "ForkLifecycleUnavailable"
    );
    let mut advance = progress();
    advance.progress.phase = ForkAdvancePhase::Accepted;
    let result = result();
    let unit = unit();
    let proof = proof();
    let mut original = facts(&advance, &result, &unit, &proof);
    original.lifecycle = managed_lifecycle(LifecycleState::Active);
    let guard = decide_fork_activation(&original, 0, limits()).unwrap();
    assert_eq!(*guard.decision(), ForkActivationDecision::Install);
    for change in 0..7 {
        let mut changed = original.clone();
        let ForkLifecycleProtection::Managed {
            expected_incarnation,
            current,
        } = &mut changed.lifecycle
        else {
            unreachable!()
        };
        match change {
            0 => *current = None,
            1 => *current = Some(Observed::Absent(rev(20))),
            2 => *expected_incarnation = rev(99),
            _ => {
                let Some(Observed::Present { value, revision }) = current else {
                    unreachable!()
                };
                match change {
                    3 => value.state = LifecycleState::Deleting,
                    4 => value.state = LifecycleState::Deleted,
                    5 => *revision = rev(99),
                    _ => value.incarnation = rev(99),
                }
            }
        }
        assert!(!guards_hold(&guard, &changed.guards(), 0));
        let decision = decide_fork_activation(&changed, 0, limits());
        if change == 0 {
            assert_eq!(decision.unwrap_err().code, FailureCode::UnavailableInput);
        } else if change == 5 {
            assert_eq!(
                *decision.unwrap().decision(),
                ForkActivationDecision::Install
            );
        } else {
            assert_eq!(
                *decision.unwrap().decision(),
                ForkActivationDecision::Withhold(ForkWithheld::LifecycleUnavailable)
            );
        }
        assert_eq!(changed.accepted_result, Some(&result));
    }
}

#[test]
fn managed_lifecycle_withholds_completion_but_never_changes_completed_replay() {
    let mut advance = progress();
    advance.progress.phase = ForkAdvancePhase::Accepted;
    let result = result();
    let original = {
        let mut v = ForkCompletionFacts::new(
            &advance,
            &result,
            2,
            0,
            2,
            result.pack_digest,
            advance.binding,
        );
        v.lifecycle = managed_lifecycle(LifecycleState::Active);
        v.accepted_result = Some(&result);
        v
    };
    let guard = decide_fork_completion(&original, limits()).unwrap();
    assert_eq!(*guard.decision(), ForkCompletionDecision::Complete);
    for current in [
        None,
        Some(Observed::Absent(rev(20))),
        Some(Observed::Present {
            value: mkit_primitives::decision::LifecycleFact::new(rev(1), LifecycleState::Deleted),
            revision: rev(20),
        }),
    ] {
        let changed = {
            let mut v = original.clone();
            v.lifecycle = ForkLifecycleProtection::Managed {
                expected_incarnation: rev(1),
                current: current.clone(),
            };
            v
        };
        assert!(!guards_hold(&guard, &changed.guards(), 0));
        let decision = decide_fork_completion(&changed, limits());
        if current.is_none() {
            assert_eq!(decision.unwrap_err().code, FailureCode::UnavailableInput);
        } else {
            assert_eq!(
                *decision.unwrap().decision(),
                ForkCompletionDecision::Withhold(ForkWithheld::LifecycleUnavailable)
            );
        }
        let mut completed = advance.clone();
        completed.progress.phase = ForkAdvancePhase::Complete;
        let replay = {
            let mut v = changed;
            v.advance = &completed;
            v
        };
        assert_eq!(
            *decide_fork_completion(&replay, limits())
                .unwrap()
                .decision(),
            ForkCompletionDecision::Replay
        );
        assert_eq!(replay.accepted_result, Some(&result));
    }
}

/// Rows of the fact-to-class table in SPEC-SERVER §3.1 for the fork decisions.
/// The acceptance rows (`authority_unfenceable`, `authority_generation`,
/// `destination_deleting`) are pinned by `fixtures/fork/acceptance.txt`.
#[test]
fn fact_class_table_rows_for_fork_decisions() {
    // Authority or grant movement is one permission class at every stage.
    assert_eq!(
        ForkRefusal::PermissionDenied.code(),
        ForkAdvanceRefusal::AuthorityMoved.code()
    );
    assert_eq!(
        ForkAdvanceRefusal::EpochMoved.code(),
        ForkAdvanceRefusal::AuthorityMoved.code()
    );
    // After acceptance a destination lifecycle fact only withholds clearance,
    // under its own stable code; it is never a refusal of the saved result.
    assert_eq!(
        ForkWithheld::LifecycleUnavailable.code(),
        FailureCode::ForkLifecycleUnavailable
    );
    let mut advance = progress();
    advance.progress.phase = ForkAdvancePhase::Accepted;
    let result = result();
    let unit = unit();
    let proof = proof();
    let mut facts = facts(&advance, &result, &unit, &proof);
    for state in [LifecycleState::Deleting, LifecycleState::Deleted] {
        facts.lifecycle = managed_lifecycle(state);
        assert_eq!(
            *decide_fork_activation(&facts, 0, limits())
                .unwrap()
                .decision(),
            ForkActivationDecision::Withhold(ForkWithheld::LifecycleUnavailable)
        );
    }
    // An unacquired lifecycle is retryable input, as for a ref write.
    facts.lifecycle = ForkLifecycleProtection::Managed {
        expected_incarnation: rev(1),
        current: None,
    };
    assert_eq!(
        decide_fork_activation(&facts, 0, limits())
            .unwrap_err()
            .code,
        FailureCode::UnavailableInput
    );
}
