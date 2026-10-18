//! Semantic fixtures, atomic mutation checks, and bounded hostile-fact replay.
#[path = "support/fork.rs"]
pub mod harness;
use harness::{
    LIMITS, REV, attempt, binding, facts, fuzz_fork_acceptance, inventories, mutate_guard,
    observed, proof,
};
use mkit_primitives::{
    decision::{
        AuthorityMode, GrantFact, Guarded, LifecycleFact, LifecycleState, NamespaceId, Observed,
        OperationId, RequiredGuard, guards_hold,
    },
    error::FailureCode,
    evidence::{RepositoryId, Revision},
    fork::{
        FinalForkSourceProof, ForkDecision, ForkJobState, ForkPlan, ForkRefusal, ForkReplay,
        ForkReservation, ForkTerminal, ForkVisibility, decide_fork_acceptance, fork_source_proof,
    },
};

fn plan() -> ForkPlan {
    ForkPlan::seal(binding(), inventories(), LIMITS).expect("valid deterministic fixture")
}
fn value<T>(fact: &mut Option<Observed<T>>) -> &mut T {
    match fact {
        Some(Observed::Present { value, .. }) => value,
        _ => panic!("fixture must be present"),
    }
}
fn outcome(result: Result<Guarded<ForkDecision<'_>>, mkit_primitives::error::Failure>) -> String {
    match result {
        Err(failure) => failure.code.as_str().into(),
        Ok(guarded) => match guarded.decision() {
            ForkDecision::AcceptFork(_) => "AcceptFork".into(),
            ForkDecision::JoinIdentical { .. } => "JoinIdentical".into(),
            ForkDecision::ReturnRecorded { .. } => "ReturnRecorded".into(),
            ForkDecision::Refuse(refusal) => refusal.code().as_str().into(),
            _ => panic!("new decision needs a fixture"),
        },
    }
}

#[test]
fn semantic_fixtures_pin_decisions_and_stable_codes() {
    for line in include_str!("../fixtures/fork/acceptance.txt").lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (case, expected) = line.split_once('|').expect("valid deterministic fixture");
        let p = plan();
        let mut request = attempt(1);
        if matches!(case, "no_reservation" | "no_reservation_no_charge") {
            request.reservation = None;
        }
        let mut f = facts(&p, &request);
        let mut s = proof(&p);
        let mut now = 1;
        let mut source = true;
        match case {
            "accept" | "no_reservation" => {}
            "no_charge" | "no_reservation_no_charge" => {
                value(&mut f.admission).charge = None;
                f.quota = Some(Observed::Absent(REV));
            }
            "partial" => {
                if let ForkJobState::Staged { packs, .. } = &mut value(&mut f.job).state {
                    *packs = 2;
                }
                value(&mut f.emptiness).staged_members = 2;
            }
            "missing_source_proof" => source = false,
            "phantom_member" => value(&mut f.emptiness).visible_members = 1,
            "phantom_ref" => value(&mut f.emptiness).refs = 1,
            "premature_writes" => value(&mut f.emptiness).writes_enabled = true,
            "foreign_staged_owner" => {
                value(&mut f.emptiness).staged_owner = Some(OperationId([9; 32]));
            }
            "foreign_registration" => value(&mut f.name).registered_by = Some(OperationId([9; 32])),
            "visibility_declaration" => {
                value(&mut f.name).declared_visibility = Some(ForkVisibility::Public);
            }
            "create_permission" => value(&mut f.permission).create = false,
            "write_permission" => value(&mut f.permission).write = false,
            "authority_mode" => value(&mut f.authority).mode = AuthorityMode::SelfCertifying,
            "authority_generation" => value(&mut f.authority).generation = Revision([9; 32]),
            "authority_unfenceable" => value(&mut f.authority).ready = false,
            "unexpected_grant" => {
                f.grant = observed(GrantFact {
                    namespace: NamespaceId([7; 32]),
                    grant: [9; 32],
                    epoch: REV,
                    presence: None,
                });
            }
            "settled_reservation" => {
                f.reservation = observed(ForkReservation::Settled(ForkTerminal::Refused(
                    ForkRefusal::Expired,
                )));
            }
            "wrong_reservation" => {
                value(&mut f.admission)
                    .reservation
                    .as_mut()
                    .expect("reserved fixture")
                    .0 = [9; 32];
            }
            "admission_charge" => value(&mut f.admission).declared_bytes -= 1,
            "admission_new_bytes" => value(&mut f.admission).new_to_repo_bytes -= 1,
            "quota_receipt" => value(&mut f.quota).charge = Revision([9; 32]),
            "quota_bytes" => value(&mut f.quota).bytes -= 1,
            "quota_limit" => value(&mut f.quota).byte_limit -= 1,
            "quota_operations" => value(&mut f.quota).operation_limit = 0,
            "job_expiry" => now = 91,
            "request_expiry" => now = 100,
            "wrong_replay" => {
                f.replay = observed(ForkReplay::InFlight {
                    operation: request.operation.clone(),
                    fingerprint: [9; 32],
                });
            }
            "destination_deleting" => {
                f.lifecycle = observed(LifecycleFact {
                    incarnation: p.binding().destination_generation,
                    state: LifecycleState::Deleting,
                });
            }
            "unacquired_emptiness" => f.emptiness = None,
            "unacquired_authority" => f.authority = None,
            "unacquired_grant" => f.grant = None,
            "unacquired_admission" => f.admission = None,
            "unacquired_quota" => f.quota = None,
            "unacquired_reservation" => f.reservation = None,
            _ => assert!(
                mutate_source(case, &mut s),
                "unimplemented semantic fixture: {case}"
            ),
        }
        let result = decide_fork_acceptance(&p, &request, &f, source.then_some(&s), now, LIMITS);
        assert_eq!(outcome(result), expected, "{case}");
    }
}

#[test]
fn every_atomic_guard_and_expiry_rejects_mutation() {
    let p = plan();
    let request = attempt(1);
    let f = facts(&p, &request);
    let s = proof(&p);
    let guarded = decide_fork_acceptance(&p, &request, &f, Some(&s), 1, LIMITS)
        .expect("valid deterministic fixture");
    assert!(guards_hold(&guarded, &f.guards(), 1));
    let names = [
        "job",
        "phantom-safe emptiness",
        "name",
        "lifecycle",
        "permission",
        "authority",
        "grant",
        "admission",
        "quota",
        "reservation",
        "replay",
        "attempt",
        "acceptance point",
        "repository",
    ];
    for (index, name) in names.iter().enumerate() {
        let mut changed = f.clone();
        assert!(mutate_guard(&mut changed, index));
        assert!(
            !guards_hold(&guarded, &changed.guards(), 1),
            "missing atomic guard: {name}"
        );
    }
    assert!(guards_hold(&guarded, &f.guards(), 90));
    assert!(!guards_hold(&guarded, &f.guards(), 91));
    assert!(
        guarded
            .required_guards()
            .contains(&RequiredGuard::ValidThrough { instant_ms: 90 })
    );
}

#[test]
fn phantom_additions_cannot_hide_behind_previously_absent_rows() {
    let p = plan();
    let request = attempt(1);
    let f = facts(&p, &request);
    let s = proof(&p);
    let guarded = decide_fork_acceptance(&p, &request, &f, Some(&s), 1, LIMITS)
        .expect("valid deterministic fixture");
    // The sampled rows remain absent, but a new row changes the authoritative
    // all-members revision. Comparing absent sampled rows alone would miss it.
    let mut phantom = f.clone();
    if let Some(Observed::Present { revision, .. }) = &mut phantom.emptiness {
        *revision = Revision([2; 32]);
    }
    assert!(!guards_hold(&guarded, &phantom.guards(), 1));
    value(&mut phantom.emptiness).visible_members = 1;
    assert_eq!(
        outcome(decide_fork_acceptance(
            &p,
            &request,
            &phantom,
            Some(&s),
            1,
            LIMITS
        )),
        "ForkDestinationNotEmpty"
    );
}

#[test]
fn every_inherited_pack_including_transitive_suppliers_requires_live_full_proof() {
    let p = plan();
    let request = attempt(1);
    let f = facts(&p, &request);
    for index in 0..3 {
        for mutation in 0..9 {
            let mut s = proof(&p);
            let pack = &mut s.packs[index];
            match mutation {
                0 => pack.eligibility.live = false,
                1 => pack.eligibility.cleared = false,
                2 => pack.eligibility.held = true,
                3 => pack.denied = true,
                4 => pack.superseded = true,
                5 => pack.incarnation = Revision([9; 32]),
                6 => pack.generation = Revision([9; 32]),
                7 => pack.descriptor = [9; 32],
                8 => pack.pack = [9; 32],
                _ => unreachable!(),
            }
            let result = outcome(decide_fork_acceptance(
                &p,
                &request,
                &f,
                Some(&s),
                1,
                LIMITS,
            ));
            assert!(
                result == "ForkSourceNotFound" || result == "InvalidResponse",
                "pack {index} mutation {mutation}: {result}"
            );
        }
    }
}

#[test]
fn terminal_acceptance_is_once_only_and_replay_survives_later_source_loss() {
    let p = plan();
    let request = attempt(1);
    let mut f = facts(&p, &request);
    let s = proof(&p);
    let result;
    {
        let guarded = decide_fork_acceptance(&p, &request, &f, Some(&s), 1, LIMITS)
            .expect("valid deterministic fixture");
        let ForkDecision::AcceptFork(effects) = guarded.decision() else {
            panic!("expected acceptance")
        };
        assert_eq!(effects.plan(), &p);
        assert_eq!(effects.attempt(), &request);
        assert_eq!(effects.result().bytes, 300);
        assert_eq!(effects.result().index_entries, 30);
        assert_eq!(
            effects.result().pack_digest,
            mkit_core::hash::hash(&[[1; 32], [2; 32], [3; 32]].concat())
        );
        assert_eq!(value(&mut f.clone().emptiness).visible_members, 0);
        assert!(!value(&mut f.clone().emptiness).writes_enabled);
        assert_eq!(fork_source_proof(&guarded), Some(&s));
        result = ForkTerminal::Accepted(Box::new(effects.result().clone()));
    }
    // A reference atomic lowering: one accepted record, one saved replay, one
    // reservation settlement and one terminal outcome responsibility.
    value(&mut f.job).state = ForkJobState::Terminal(result.clone());
    f.replay = observed(ForkReplay::Recorded {
        fingerprint: request.fingerprint,
        result: result.clone(),
    });
    f.reservation = observed(ForkReservation::Settled(result.clone()));
    let quota = f.quota.clone();
    for _ in 0..3 {
        let replay = decide_fork_acceptance(&p, &request, &f, None, 2, LIMITS)
            .expect("valid deterministic fixture");
        assert!(
            matches!(replay.decision(), ForkDecision::ReturnRecorded { result: saved, replay_race: None } if **saved == result)
        );
        assert!(fork_source_proof(&replay).is_none());
        assert_eq!(f.quota, quota);
    }
    // Outcome acknowledgement may remove the reservation. It cannot cause a
    // second outcome or make a saved result depend on present source access.
    f.reservation = Some(Observed::Absent(Revision([3; 32])));
    assert_eq!(
        outcome(decide_fork_acceptance(&p, &request, &f, None, 2, LIMITS)),
        "ReturnRecorded"
    );
}

#[test]
fn joining_reservation_is_exact_and_never_settles_original_attempt() {
    let p = plan();
    let original = attempt(1);
    let joining = attempt(2);
    let original_facts = facts(&p, &original);
    let mut joined = facts(&p, &joining);
    joined.job = original_facts.job.clone();
    joined.emptiness = original_facts.emptiness.clone();
    let join = decide_fork_acceptance(&p, &joining, &joined, None, 1, LIMITS)
        .expect("valid deterministic fixture");
    let ForkDecision::JoinIdentical {
        owner,
        replay_race: Some(race),
    } = join.decision()
    else {
        panic!("expected join")
    };
    assert_eq!(*owner, &original);
    assert_eq!(race.joining, &joining);
    assert_ne!(race.joining.reservation, owner.reservation);
    let mut changed = joined.clone();
    changed.reservation = observed(ForkReservation::Settled(ForkTerminal::Refused(
        ForkRefusal::Expired,
    )));
    assert!(!guards_hold(&join, &changed.guards(), 1));
}

#[test]
fn malicious_and_bounded_plans_never_seal_incomplete_success() {
    for mutation in 0..8 {
        let mut b = binding();
        let mut packs = inventories();
        let mut limits = LIMITS;
        match mutation {
            0 => {
                packs.pop();
            }
            1 => packs[1].dependencies.push([3; 32]),
            2 => packs[2].pack = [2; 32],
            3 => packs[1].dependencies.clear(), // disconnected supplier
            4 => packs[2].bytes = u64::MAX,
            5 => b.source = b.destination,
            6 => limits.work = 1,
            7 => b.publication.head = None,
            _ => unreachable!(),
        }
        assert!(
            ForkPlan::seal(b, packs, limits).is_err(),
            "mutation {mutation}"
        );
    }
    let mut exact = LIMITS;
    let accepted =
        ForkPlan::seal(binding(), inventories(), exact).expect("valid deterministic fixture");
    assert_eq!(accepted.bytes(), exact.inherited_bytes);
    exact.inherited_bytes -= 1;
    assert_eq!(
        ForkPlan::seal(binding(), inventories(), exact)
            .expect_err("fixture must be refused")
            .code,
        FailureCode::ResourceLimit
    );
    for limit in 0..4 {
        let mut limits = LIMITS;
        match limit {
            0 => limits.packs = 2,
            1 => limits.edges = 1,
            2 => limits.index_entries = 29,
            3 => limits.branch_bytes = 14,
            _ => unreachable!(),
        }
        assert_eq!(
            ForkPlan::seal(binding(), inventories(), limits)
                .expect_err("fixture must be refused")
                .code,
            FailureCode::ResourceLimit
        );
    }
}

#[test]
fn original_grant_epoch_is_not_replaced_by_newer_permission() {
    let p = plan();
    let mut request = attempt(1);
    request.grant = Some(GrantFact {
        namespace: NamespaceId([7; 32]),
        grant: [8; 32],
        epoch: REV,
        presence: None,
    });
    let mut f = facts(&p, &request);
    let s = proof(&p);
    f.grant = observed(request.grant.clone().expect("valid deterministic fixture"));
    assert_eq!(
        outcome(decide_fork_acceptance(
            &p,
            &request,
            &f,
            Some(&s),
            1,
            LIMITS
        )),
        "AcceptFork"
    );
    value(&mut f.grant).epoch = Revision([9; 32]);
    assert_eq!(
        outcome(decide_fork_acceptance(
            &p,
            &request,
            &f,
            Some(&s),
            1,
            LIMITS
        )),
        "ForkPermissionDenied"
    );
}

#[test]
fn terminal_job_recovers_after_replay_pruning_without_reopening_settlement() {
    let p = plan();
    let request = attempt(1);
    let mut f = facts(&p, &request);
    let s = proof(&p);
    let result = {
        let guarded = decide_fork_acceptance(&p, &request, &f, Some(&s), 1, LIMITS)
            .expect("valid deterministic fixture");
        let ForkDecision::AcceptFork(effects) = guarded.decision() else {
            panic!("expected acceptance")
        };
        ForkTerminal::Accepted(Box::new(effects.result().clone()))
    };
    value(&mut f.job).state = ForkJobState::Terminal(result.clone());
    f.replay = Some(Observed::Absent(Revision([3; 32])));
    f.reservation = Some(Observed::Absent(Revision([4; 32])));
    f.permission = None;
    f.quota = None;
    f.admission = None;
    assert_eq!(
        outcome(decide_fork_acceptance(
            &p, &request, &f, None, 1_000, LIMITS
        )),
        "ReturnRecorded"
    );
    // A pending original reservation contradicts the atomically saved terminal
    // responsibility, even if a forged replay row claims success.
    f.reservation = observed(ForkReservation::Pending {
        operation: request.operation.clone(),
        destination: p.binding().destination,
        expires_ms: 90,
    });
    assert_eq!(
        outcome(decide_fork_acceptance(&p, &request, &f, None, 1, LIMITS)),
        "InvalidResponse"
    );
    f.reservation = observed(ForkReservation::Settled(result));
    if let ForkJobState::Terminal(ForkTerminal::Accepted(result)) = &mut value(&mut f.job).state {
        result.bytes += 1;
    }
    assert_eq!(
        outcome(decide_fork_acceptance(&p, &request, &f, None, 1, LIMITS)),
        "InvalidResponse"
    );
}

#[test]
fn repeated_join_is_idempotent_after_its_exact_replay_race_settlement() {
    let p = plan();
    let original = attempt(1);
    let joining = attempt(2);
    let original_facts = facts(&p, &original);
    let mut joined = facts(&p, &joining);
    joined.job = original_facts.job.clone();
    joined.emptiness = original_facts.emptiness.clone();
    joined.reservation = observed(ForkReservation::ReplayRace {
        owner: original.operation.clone(),
    });
    joined.quota = None;
    joined.admission = None;
    let replay = decide_fork_acceptance(&p, &joining, &joined, None, 1, LIMITS)
        .expect("valid deterministic fixture");
    assert!(matches!(
        replay.decision(),
        ForkDecision::JoinIdentical {
            replay_race: None,
            ..
        }
    ));
    joined.reservation = observed(ForkReservation::ReplayRace {
        owner: OperationId([9; 32]),
    });
    assert_eq!(
        outcome(decide_fork_acceptance(
            &p, &joining, &joined, None, 1, LIMITS
        )),
        "ForkReservationSettled"
    );
}

#[test]
fn admitted_job_preserves_ingress_expiry_and_authoritative_replay_absence() {
    let p = plan();
    let mut request = attempt(1);
    request.expires_ms = 0; // Ingress was valid before this durable work resumes.
    let mut f = facts(&p, &request);
    let s = proof(&p);
    f.replay = Some(Observed::Absent(REV));
    assert_eq!(
        outcome(decide_fork_acceptance(
            &p,
            &request,
            &f,
            Some(&s),
            1,
            LIMITS
        )),
        "AcceptFork"
    );
    f.replay = None;
    assert_eq!(
        outcome(decide_fork_acceptance(
            &p,
            &request,
            &f,
            Some(&s),
            1,
            LIMITS
        )),
        "UnavailableInput"
    );
}

#[test]
fn source_movement_after_the_final_proof_is_not_a_destination_atomic_guard() {
    let p = plan();
    let request = attempt(1);
    let f = facts(&p, &request);
    let captured = proof(&p);
    let guarded = decide_fork_acceptance(&p, &request, &f, Some(&captured), 1, LIMITS)
        .expect("valid deterministic fixture");
    let mut later_source = captured.clone();
    later_source.proof_point = 13;
    later_source.readable = false;
    later_source.packs[2].denied = true;
    assert!(guards_hold(&guarded, &f.guards(), 2));
    assert_eq!(fork_source_proof(&guarded), Some(&captured));
    assert_ne!(fork_source_proof(&guarded), Some(&later_source));
}

#[test]
fn later_pending_source_advances_do_not_make_the_published_pair_unforkable() {
    let mut b = binding();
    b.publication.sequence = 2;
    let p = ForkPlan::seal(b, inventories(), LIMITS).expect("valid deterministic fixture");
    let request = attempt(1);
    let f = facts(&p, &request);
    let s = proof(&p);
    assert_eq!(
        outcome(decide_fork_acceptance(
            &p,
            &request,
            &f,
            Some(&s),
            1,
            LIMITS
        )),
        "AcceptFork"
    );
}

#[test]
fn full_staging_digest_and_admission_plan_cannot_be_substituted() {
    let p = plan();
    let request = attempt(1);
    let mut f = facts(&p, &request);
    let s = proof(&p);
    value(&mut f.emptiness).staged_pack_digest = [9; 32];
    assert_eq!(
        outcome(decide_fork_acceptance(
            &p,
            &request,
            &f,
            Some(&s),
            1,
            LIMITS
        )),
        "InvalidResponse"
    );
    let mut other_binding = binding();
    other_binding.publication.head = Some([9; 32]);
    let other =
        ForkPlan::seal(other_binding, inventories(), LIMITS).expect("valid deterministic fixture");
    f = facts(&p, &request);
    value(&mut f.admission).plan = &other;
    assert_eq!(
        outcome(decide_fork_acceptance(
            &p,
            &request,
            &f,
            Some(&s),
            1,
            LIMITS
        )),
        "InvalidResponse"
    );
    f = facts(&p, &request);
    value(&mut f.job).plan = &other;
    assert_eq!(
        outcome(decide_fork_acceptance(
            &p,
            &request,
            &f,
            Some(&s),
            1,
            LIMITS
        )),
        "ForkBindingMismatch"
    );
}

#[test]
fn review_terminal_replay_precedes_advancement_authority_and_grant_checks() {
    let p = plan();
    let request = attempt(1);
    for terminal in [
        ForkTerminal::Accepted(Box::new(p.result().clone())),
        ForkTerminal::Refused(ForkRefusal::SourceNotFound),
    ] {
        for pruned in [false, true] {
            let mut f = facts(&p, &request);
            value(&mut f.job).state = ForkJobState::Terminal(terminal.clone());
            f.replay = if pruned {
                Some(Observed::Absent(REV))
            } else {
                observed(ForkReplay::Recorded {
                    fingerprint: request.fingerprint,
                    result: terminal.clone(),
                })
            };
            f.reservation = if pruned {
                Some(Observed::Absent(REV))
            } else {
                observed(ForkReservation::Settled(terminal.clone()))
            };
            value(&mut f.authority).generation = Revision([9; 32]);
            value(&mut f.authority).ready = false;
            f.grant = observed(GrantFact {
                namespace: NamespaceId([7; 32]),
                grant: [9; 32],
                epoch: Revision([9; 32]),
                presence: None,
            });
            assert_eq!(
                outcome(decide_fork_acceptance(
                    &p, &request, &f, None, 1_000, LIMITS
                )),
                "ReturnRecorded"
            );
            f.authority = None;
            f.grant = None;
            assert_eq!(
                outcome(decide_fork_acceptance(
                    &p, &request, &f, None, 1_000, LIMITS
                )),
                "ReturnRecorded"
            );
        }
    }
}

#[test]
fn review_cached_result_settles_only_the_fresh_joining_reservation_once() {
    let p = plan();
    let original = attempt(1);
    let joining = attempt(2);
    let mut f = facts(&p, &joining);
    value(&mut f.job).attempt = original.clone();
    let result = ForkTerminal::Accepted(Box::new(p.result().clone()));
    value(&mut f.job).state = ForkJobState::Terminal(result.clone());
    f.replay = observed(ForkReplay::Recorded {
        fingerprint: joining.fingerprint,
        result,
    });
    let guarded =
        decide_fork_acceptance(&p, &joining, &f, None, 1, LIMITS).expect("valid cached join");
    let ForkDecision::ReturnRecorded {
        replay_race: Some(race),
        ..
    } = guarded.decision()
    else {
        panic!("joining settlement required")
    };
    assert_eq!(race.joining.reservation, joining.reservation);
    assert_ne!(race.joining.reservation, original.reservation);
    f.reservation = observed(ForkReservation::ReplayRace {
        owner: original.operation,
    });
    let replay =
        decide_fork_acceptance(&p, &joining, &f, None, 1, LIMITS).expect("settled join replay");
    assert!(matches!(
        replay.decision(),
        ForkDecision::ReturnRecorded {
            replay_race: None,
            ..
        }
    ));
}

#[test]
fn review_every_retained_terminal_branch_is_bounded_before_guarding_a_refusal() {
    let p = plan();
    let request = attempt(1);
    for target in 0..3 {
        let mut f = facts(&p, &request);
        let mut result = p.result().clone();
        result.branch.0 = "x".repeat(LIMITS.branch_bytes as usize + 1);
        let terminal = ForkTerminal::Accepted(Box::new(result));
        match target {
            0 => f.reservation = observed(ForkReservation::Settled(terminal)),
            1 => {
                f.replay = observed(ForkReplay::Recorded {
                    fingerprint: request.fingerprint,
                    result: terminal,
                });
            }
            2 => value(&mut f.job).state = ForkJobState::Terminal(terminal),
            _ => unreachable!(),
        }
        assert_eq!(
            outcome(decide_fork_acceptance(&p, &request, &f, None, 1, LIMITS)),
            "ResourceLimit"
        );
    }
}

#[test]
fn default_and_charge_free_admissions_accept_join_and_replay_without_fabricated_facts() {
    let p = plan();
    for reserved in [false, true] {
        for charged in [false, true] {
            let mut original = attempt(1);
            if !reserved {
                original.reservation = None;
            }
            let mut f = facts(&p, &original);
            if !reserved {
                f.reservation = Some(Observed::Absent(REV));
            }
            if !charged {
                value(&mut f.admission).charge = None;
                f.quota = Some(Observed::Absent(REV));
            }
            let source = proof(&p);
            let accepted = decide_fork_acceptance(&p, &original, &f, Some(&source), 1, LIMITS)
                .expect("optional admission");
            assert!(
                matches!(accepted.decision(), ForkDecision::AcceptFork(effects) if effects.attempt().reservation.is_some() == reserved)
            );
            assert_eq!(
                outcome(decide_fork_acceptance(
                    &p,
                    &original,
                    &f,
                    Some(&source),
                    91,
                    LIMITS
                )),
                "ForkExpired"
            );
            let mut joining = attempt(2);
            if !reserved {
                joining.reservation = None;
            }
            let mut join = facts(&p, &joining);
            join.job = f.job.clone();
            join.emptiness = f.emptiness.clone();
            if !reserved {
                join.reservation = Some(Observed::Absent(REV));
            }
            if !charged {
                value(&mut join.admission).charge = None;
                join.quota = Some(Observed::Absent(REV));
            }
            let pending = decide_fork_acceptance(&p, &joining, &join, None, 1, LIMITS)
                .expect("optional joining admission");
            assert!(
                matches!(pending.decision(), ForkDecision::JoinIdentical { replay_race, .. } if replay_race.is_some() == reserved)
            );
            let result = ForkTerminal::Accepted(Box::new(p.result().clone()));
            value(&mut join.job).state = ForkJobState::Terminal(result.clone());
            join.replay = observed(ForkReplay::Recorded {
                fingerprint: joining.fingerprint,
                result,
            });
            let terminal = decide_fork_acceptance(&p, &joining, &join, None, 1, LIMITS)
                .expect("optional cached join");
            assert!(
                matches!(terminal.decision(), ForkDecision::ReturnRecorded { replay_race, .. } if replay_race.is_some() == reserved)
            );
        }
    }
}

#[test]
fn absent_reservation_and_quota_are_distinct_from_missing_or_contradictory_facts() {
    let p = plan();
    let mut request = attempt(1);
    request.reservation = None;
    let mut f = facts(&p, &request);
    let source = proof(&p);
    f.reservation = Some(Observed::Absent(REV));
    value(&mut f.admission).charge = None;
    f.quota = Some(Observed::Absent(REV));
    f.reservation = None;
    assert_eq!(
        outcome(decide_fork_acceptance(
            &p,
            &request,
            &f,
            Some(&source),
            1,
            LIMITS
        )),
        "UnavailableInput"
    );
    f.reservation = Some(Observed::Absent(REV));
    f.quota = None;
    assert_eq!(
        outcome(decide_fork_acceptance(
            &p,
            &request,
            &f,
            Some(&source),
            1,
            LIMITS
        )),
        "UnavailableInput"
    );
    f.quota = Some(Observed::Absent(REV));
    value(&mut f.admission).charge = Some(REV);
    assert_eq!(
        outcome(decide_fork_acceptance(
            &p,
            &request,
            &f,
            Some(&source),
            1,
            LIMITS
        )),
        "InvalidResponse"
    );
}

#[test]
fn stable_and_seeded_hostile_fact_fuzz_replay() {
    fuzz_fork_acceptance(&[]);
    for seed in [
        &[0, 1, 1, 0][..],
        &[0, 1, 1, 1],
        &[0, 1, 0, 1],
        &[0, 1, 0, 0, 1],
    ] {
        fuzz_fork_acceptance(seed);
    }
    for len in [1, 2, 8, 32, 64, 256] {
        fuzz_fork_acceptance(&vec![0; len]);
        fuzz_fork_acceptance(&vec![255; len]);
    }
    let mut state = 0x6a09_e667_f3bc_c909_u64;
    for _ in 0..256 {
        let mut data = [0_u8; 32];
        for byte in &mut data {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state.to_le_bytes()[0];
        }
        fuzz_fork_acceptance(&data);
    }
}

fn mutate_source(case: &str, s: &mut FinalForkSourceProof) -> bool {
    match case {
        "source_not_readable" => s.readable = false,
        "source_generation" => {
            if let Observed::Present { value, .. } = &mut s.publication {
                value.generation = Revision([9; 32]);
            }
        }
        "source_tip" => {
            if let Observed::Present { value, .. } = &mut s.publication {
                value.head = Some([9; 32]);
            }
        }
        "source_packmap" => {
            if let Observed::Present { value, .. } = &mut s.publication {
                value.packmap = Some([9; 32]);
            }
        }
        "source_sequence" => {
            if let Observed::Present { value, .. } = &mut s.publication {
                value.sequence += 1;
            }
        }
        "source_deletion" => {
            if let Observed::Present { value, .. } = &mut s.publication {
                value.deletion_boundary += 1;
            }
        }
        "source_incarnation" => {
            if let Observed::Present { value, .. } = &mut s.lifecycle {
                value.incarnation = Revision([9; 32]);
            }
        }
        "source_visibility" => {
            if let Observed::Present { value, .. } = &mut s.access {
                value.visibility_revision = Revision([9; 32]);
            }
        }
        "source_authorization" => {
            if let Observed::Present { value, .. } = &mut s.access {
                value.authorization_revision = Revision([9; 32]);
            }
        }
        "proof_before_staging" => s.proof_point = 9,
        "proof_at_last_effect" => s.proof_point = 10,
        "proof_at_acceptance" => s.proof_point = 12,
        "proof_wrong_attempt" => s.apply_attempt = Revision([9; 32]),
        "proof_wrong_stage" => s.staged_revision = Revision([9; 32]),
        "duplicate_proof_pack" => s.packs[1] = s.packs[0].clone(),
        "missing_supplier" => {
            s.packs.pop();
        }
        "oversized_proof" => s.packs.push(s.packs[0].clone()),
        "wrong_source" => s.repository = RepositoryId([9; 32]),
        _ => return false,
    }
    true
}
