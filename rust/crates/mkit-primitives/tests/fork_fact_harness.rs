//! Fact-mutation harness for fork acceptance, progress, activation, completion
//! and published clearance.
//!
//! For every acquired fact it builds every single-field variant and redecides.
//! Two properties must hold for each variant:
//! 1. whenever the redecision differs from the original, the original decision's
//!    guards no longer hold against the live guards of the variant (an unguarded
//!    dependency would show up as a changed decision with every guard intact);
//! 2. the variant's guards differ from the original's at all, so a field the
//!    commitments forgot is found even before a decision depends on it.
//!
//! Each family is also checked to be free of contradictory guards.
#![allow(
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::type_complexity,
    clippy::semicolon_if_nothing_returned,
    clippy::match_wildcard_for_single_variants
)]
#[path = "support/fork.rs"]
pub mod harness;
#[path = "support/fork_advance.rs"]
pub mod host_facts;

use harness::{LIMITS, REV, attempt, binding, facts, inventories, observed, proof};
use mkit_core::hash::Hash;
use mkit_primitives::{
    decision::{
        AuthorityFact, AuthorityMode, ClearanceAdvance, ClearanceFacts, ClearanceLifecycle,
        ClearanceLimits, ClearanceMoment, ClearanceState, DependencyWitness, GrantFact, Guarded,
        LifecycleFact, LifecycleState, NamespaceId, Observed, OperationId, PriorPublication,
        ReplayScope, RequiredGuard, ReservationId, decide_clearance, guards_hold,
    },
    error::Failure,
    evidence::{RepositoryId, Revision},
    fork::{
        FinalForkSourceProof, ForkActivationFacts, ForkAdmission, ForkAdvanceFacts,
        ForkAdvancePhase, ForkCompletionFacts, ForkEmptiness, ForkEpochFence, ForkFacts, ForkJob,
        ForkJobState, ForkLifecycleProtection, ForkName, ForkObservation, ForkPairContext,
        ForkPermission, ForkPlan, ForkQuota, ForkRefusal, ForkReplay, ForkReservation, ForkResult,
        ForkTerminal, ForkVisibility, decide_fork_acceptance, decide_fork_activation,
        decide_fork_advance, decide_fork_completion, fork_source_proof,
    },
};

fn rev(n: u8) -> Revision {
    Revision([n; 32])
}
fn flip(mut h: Hash) -> Hash {
    h[0] ^= 0xa5;
    h
}

type Mutation<'m, F> = (&'static str, Box<dyn Fn(&mut F) + 'm>);
macro_rules! m {
    ($name:expr, $f:expr) => {
        ($name, Box::new($f) as Box<dyn Fn(&mut _) + '_>)
    };
}

fn render<D: std::fmt::Debug>(result: &Result<Guarded<D>, Failure>) -> String {
    match result {
        Ok(guarded) => format!("{:?}", guarded.decision()),
        Err(error) => format!("{error:?}"),
    }
}

/// Run the two properties over every mutation. `decide` re-decides a variant;
/// `live` derives its guards; `now` is the decision time.
fn exhaust<F: Clone + PartialEq, D: std::fmt::Debug>(
    label: &str,
    base: &F,
    mutations: &[Mutation<'_, F>],
    now: u64,
    decide: impl Fn(&F) -> Result<Guarded<D>, Failure>,
    live: impl Fn(&F) -> Vec<RequiredGuard>,
) {
    let original = decide(base);
    let original_text = render(&original);
    let original_live = live(base);
    for (i, a) in original_live.iter().enumerate() {
        for b in &original_live[..i] {
            let same = match (a, b) {
                (
                    RequiredGuard::Row {
                        repository: ra,
                        row: xa,
                        ..
                    },
                    RequiredGuard::Row {
                        repository: rb,
                        row: xb,
                        ..
                    },
                ) => ra == rb && xa == xb,
                (RequiredGuard::Row { .. }, _) | (_, RequiredGuard::Row { .. }) => false,
                _ => std::mem::discriminant(a) == std::mem::discriminant(b),
            };
            assert!(!same, "{label}: two guards share one identity: {a:?} {b:?}");
        }
    }
    if let Ok(guarded) = &original {
        assert!(
            guards_hold(guarded, &original_live, now),
            "{label}: own guards must hold"
        );
    }
    let mut changed_decision = 0;
    let mut skipped = 0usize;
    for (name, mutate) in mutations {
        let mut variant = base.clone();
        mutate(&mut variant);
        if variant == *base {
            // The scenario already holds this value; nothing moved.
            skipped += 1;
            continue;
        }
        let variant_live = live(&variant);
        assert_ne!(
            variant_live, original_live,
            "{label}/{name}: a field change left every guard intact"
        );
        let text = render(&decide(&variant));
        if text != original_text {
            changed_decision += 1;
            if let Ok(guarded) = &original {
                assert!(
                    !guards_hold(guarded, &variant_live, now),
                    "{label}/{name}: the decision changed ({original_text} -> {text}) \
                     but every guard still holds"
                );
            }
        }
    }
    assert!(
        skipped * 4 <= mutations.len(),
        "{label}: too many mutations were no-ops in this scenario ({skipped})"
    );
    assert!(
        changed_decision > 0,
        "{label}: the harness must find mutations that move the decision"
    );
}

fn obs<T>(fact: &mut Option<Observed<T>>, edit: impl FnOnce(&mut T)) {
    if let Some(Observed::Present { value, .. }) = fact {
        edit(value);
    }
}
fn bump<T>(fact: &mut Option<Observed<T>>) {
    if let Some(Observed::Present { revision, .. } | Observed::Absent(revision)) = fact {
        revision.0[0] ^= 0xa5;
    }
}

fn acceptance_mutations<'a>(
    other: &'a ForkPlan,
    request: &'a mkit_primitives::fork::ForkAttempt,
) -> Vec<Mutation<'a, ForkFacts<'a>>> {
    vec![
        m!("repository", |f: &mut ForkFacts<'a>| f.repository =
            RepositoryId([99; 32])),
        m!("apply_attempt", |f: &mut ForkFacts<'a>| f.apply_attempt =
            rev(99)),
        m!("acceptance_point", |f: &mut ForkFacts<'a>| f
            .acceptance_point +=
            1),
        m!("request", move |f: &mut ForkFacts<'a>| f.request = request),
        m!("job.rev", |f: &mut ForkFacts<'a>| bump(&mut f.job)),
        m!("job.absent", |f: &mut ForkFacts<'a>| f.job =
            Some(Observed::Absent(REV))),
        m!("job.plan", move |f: &mut ForkFacts<'a>| obs(
            &mut f.job,
            |j: &mut ForkJob<'a>| j.plan = other
        )),
        m!("job.attempt.operation", |f: &mut ForkFacts<'a>| obs(
            &mut f.job,
            |j| j.attempt.operation.0[0] ^= 1
        )),
        m!("job.attempt.reservation", |f: &mut ForkFacts<'a>| obs(
            &mut f.job,
            |j| j.attempt.reservation = None
        )),
        m!("job.attempt.replay", |f: &mut ForkFacts<'a>| obs(
            &mut f.job,
            |j| j.attempt.replay = ReplayScope([98; 32])
        )),
        m!("job.attempt.fingerprint", |f: &mut ForkFacts<'a>| obs(
            &mut f.job,
            |j| j.attempt.fingerprint[0] ^= 1
        )),
        m!("job.attempt.expires", |f: &mut ForkFacts<'a>| obs(
            &mut f.job,
            |j| j.attempt.expires_ms += 1
        )),
        m!("job.attempt.authority", |f: &mut ForkFacts<'a>| obs(
            &mut f.job,
            |j| j.attempt.authority.generation = rev(98)
        )),
        m!("job.attempt.grant", |f: &mut ForkFacts<'a>| obs(
            &mut f.job,
            |j| j.attempt.grant = Some(GrantFact::new(NamespaceId([7; 32]), [3; 32], rev(1), None))
        )),
        m!("job.attempt.fencing", |f: &mut ForkFacts<'a>| obs(
            &mut f.job,
            |j| j.attempt.authority_fencing = false
        )),
        m!("job.expires", |f: &mut ForkFacts<'a>| obs(
            &mut f.job,
            |j| j.expires_ms += 1
        )),
        m!("job.state.packs", |f: &mut ForkFacts<'a>| obs(
            &mut f.job,
            |j| {
                j.state = ForkJobState::Staged {
                    packs: 2,
                    revision: REV,
                    last_effect: 10,
                }
            }
        )),
        m!("job.state.revision", |f: &mut ForkFacts<'a>| obs(
            &mut f.job,
            |j| {
                j.state = ForkJobState::Staged {
                    packs: 3,
                    revision: rev(98),
                    last_effect: 10,
                }
            }
        )),
        m!("job.state.last_effect", |f: &mut ForkFacts<'a>| obs(
            &mut f.job,
            |j| {
                j.state = ForkJobState::Staged {
                    packs: 3,
                    revision: REV,
                    last_effect: 11,
                }
            }
        )),
        m!("job.state.refused", |f: &mut ForkFacts<'a>| obs(
            &mut f.job,
            |j| { j.state = ForkJobState::Terminal(ForkTerminal::Refused(ForkRefusal::Expired)) }
        )),
        m!("emptiness.rev", |f: &mut ForkFacts<'a>| bump(
            &mut f.emptiness
        )),
        m!("emptiness.absent", |f: &mut ForkFacts<'a>| f.emptiness =
            Some(Observed::Absent(REV))),
        m!("emptiness.refs", |f: &mut ForkFacts<'a>| obs(
            &mut f.emptiness,
            |e: &mut ForkEmptiness| e.refs += 1
        )),
        m!("emptiness.visible", |f: &mut ForkFacts<'a>| obs(
            &mut f.emptiness,
            |e| e.visible_members += 1
        )),
        m!("emptiness.staged", |f: &mut ForkFacts<'a>| obs(
            &mut f.emptiness,
            |e| e.staged_members += 1
        )),
        m!("emptiness.digest", |f: &mut ForkFacts<'a>| obs(
            &mut f.emptiness,
            |e| e.staged_pack_digest = flip(e.staged_pack_digest)
        )),
        m!("emptiness.owner", |f: &mut ForkFacts<'a>| obs(
            &mut f.emptiness,
            |e| e.staged_owner = None
        )),
        m!("emptiness.writes", |f: &mut ForkFacts<'a>| obs(
            &mut f.emptiness,
            |e| e.writes_enabled = true
        )),
        m!("name.rev", |f: &mut ForkFacts<'a>| bump(&mut f.name)),
        m!("name.absent", |f: &mut ForkFacts<'a>| f.name =
            Some(Observed::Absent(REV))),
        m!("name.registered_by", |f: &mut ForkFacts<'a>| obs(
            &mut f.name,
            |n: &mut ForkName| n.registered_by = Some(OperationId([77; 32]))
        )),
        m!("name.visibility", |f: &mut ForkFacts<'a>| obs(
            &mut f.name,
            |n| n.declared_visibility = Some(ForkVisibility::Public)
        )),
        m!("name.visibility_none", |f: &mut ForkFacts<'a>| obs(
            &mut f.name,
            |n| n.declared_visibility = None
        )),
        m!("lifecycle.rev", |f: &mut ForkFacts<'a>| bump(
            &mut f.lifecycle
        )),
        m!("lifecycle.present", |f: &mut ForkFacts<'a>| f.lifecycle =
            Some(Observed::Present {
                value: LifecycleFact::new(Revision([2; 32]), LifecycleState::Active),
                revision: REV
            })),
        m!("lifecycle.deleting", |f: &mut ForkFacts<'a>| f.lifecycle =
            Some(Observed::Present {
                value: LifecycleFact::new(Revision([2; 32]), LifecycleState::Deleting),
                revision: REV
            })),
        m!("permission.rev", |f: &mut ForkFacts<'a>| bump(
            &mut f.permission
        )),
        m!("permission.absent", |f: &mut ForkFacts<'a>| f.permission =
            Some(Observed::Absent(REV))),
        m!("permission.operation", |f: &mut ForkFacts<'a>| obs(
            &mut f.permission,
            |p: &mut ForkPermission| p.operation.0[0] ^= 1
        )),
        m!("permission.principal", |f: &mut ForkFacts<'a>| obs(
            &mut f.permission,
            |p| p.source_access.principal[0] ^= 1
        )),
        m!("permission.source_visibility", |f: &mut ForkFacts<'a>| obs(
            &mut f.permission,
            |p| p.source_access.visibility = ForkVisibility::Public
        )),
        m!("permission.visibility_rev", |f: &mut ForkFacts<'a>| obs(
            &mut f.permission,
            |p| p.source_access.visibility_revision = rev(98)
        )),
        m!("permission.authorization_rev", |f: &mut ForkFacts<'a>| obs(
            &mut f.permission,
            |p| p.source_access.authorization_revision = rev(98)
        )),
        m!("permission.destination_visibility", |f: &mut ForkFacts<
            'a,
        >| obs(
            &mut f.permission,
            |p| p.destination_visibility = ForkVisibility::Public
        )),
        m!("permission.create", |f: &mut ForkFacts<'a>| obs(
            &mut f.permission,
            |p| p.create = false
        )),
        m!("permission.write", |f: &mut ForkFacts<'a>| obs(
            &mut f.permission,
            |p| p.write = false
        )),
        m!("authority.rev", |f: &mut ForkFacts<'a>| bump(
            &mut f.authority
        )),
        m!("authority.absent", |f: &mut ForkFacts<'a>| f.authority =
            Some(Observed::Absent(REV))),
        m!("authority.namespace", |f: &mut ForkFacts<'a>| obs(
            &mut f.authority,
            |a: &mut AuthorityFact| a.namespace.0[0] ^= 1
        )),
        m!("authority.mode", |f: &mut ForkFacts<'a>| obs(
            &mut f.authority,
            |a| a.mode = AuthorityMode::SelfCertifying
        )),
        m!("authority.generation", |f: &mut ForkFacts<'a>| obs(
            &mut f.authority,
            |a| a.generation = rev(98)
        )),
        m!("authority.ready", |f: &mut ForkFacts<'a>| obs(
            &mut f.authority,
            |a| a.ready = false
        )),
        m!("grant.rev", |f: &mut ForkFacts<'a>| bump(&mut f.grant)),
        m!("grant.present", |f: &mut ForkFacts<'a>| f.grant =
            Some(Observed::Present {
                value: GrantFact::new(NamespaceId([7; 32]), [3; 32], rev(1), None),
                revision: REV
            })),
        m!("admission.rev", |f: &mut ForkFacts<'a>| bump(
            &mut f.admission
        )),
        m!("admission.absent", |f: &mut ForkFacts<'a>| f.admission =
            Some(Observed::Absent(REV))),
        m!("admission.plan", move |f: &mut ForkFacts<'a>| obs(
            &mut f.admission,
            |a: &mut ForkAdmission<'a>| a.plan = other
        )),
        m!("admission.operation", |f: &mut ForkFacts<'a>| obs(
            &mut f.admission,
            |a| a.operation.0[0] ^= 1
        )),
        m!("admission.reservation", |f: &mut ForkFacts<'a>| obs(
            &mut f.admission,
            |a| a.reservation = None
        )),
        m!("admission.declared", |f: &mut ForkFacts<'a>| obs(
            &mut f.admission,
            |a| a.declared_bytes += 1
        )),
        m!("admission.new_to_repo", |f: &mut ForkFacts<'a>| obs(
            &mut f.admission,
            |a| a.new_to_repo_bytes += 1
        )),
        m!("admission.charge", |f: &mut ForkFacts<'a>| obs(
            &mut f.admission,
            |a| a.charge = None
        )),
        m!("quota.rev", |f: &mut ForkFacts<'a>| bump(&mut f.quota)),
        m!("quota.absent", |f: &mut ForkFacts<'a>| f.quota =
            Some(Observed::Absent(REV))),
        m!("quota.operation", |f: &mut ForkFacts<'a>| obs(
            &mut f.quota,
            |q: &mut ForkQuota| q.operation.0[0] ^= 1
        )),
        m!("quota.charge", |f: &mut ForkFacts<'a>| obs(
            &mut f.quota,
            |q| q.charge = rev(98)
        )),
        m!("quota.bytes", |f: &mut ForkFacts<'a>| obs(
            &mut f.quota,
            |q| q.bytes += 1
        )),
        m!("quota.used_bytes", |f: &mut ForkFacts<'a>| obs(
            &mut f.quota,
            |q| q.used_bytes += 1
        )),
        m!("quota.byte_limit", |f: &mut ForkFacts<'a>| obs(
            &mut f.quota,
            |q| q.byte_limit += 1
        )),
        m!("quota.used_operations", |f: &mut ForkFacts<'a>| obs(
            &mut f.quota,
            |q| q.used_operations += 1
        )),
        m!("quota.operation_limit", |f: &mut ForkFacts<'a>| obs(
            &mut f.quota,
            |q| q.operation_limit += 1
        )),
        m!("reservation.rev", |f: &mut ForkFacts<'a>| bump(
            &mut f.reservation
        )),
        m!("reservation.absent", |f: &mut ForkFacts<'a>| f
            .reservation =
            Some(Observed::Absent(REV))),
        m!("reservation.operation", |f: &mut ForkFacts<'a>| obs(
            &mut f.reservation,
            |r: &mut ForkReservation| {
                if let ForkReservation::Pending { operation, .. } = r {
                    operation.0[0] ^= 1;
                }
            }
        )),
        m!("reservation.destination", |f: &mut ForkFacts<'a>| obs(
            &mut f.reservation,
            |r| {
                if let ForkReservation::Pending { destination, .. } = r {
                    destination.0[0] ^= 1;
                }
            }
        )),
        m!("reservation.expires", |f: &mut ForkFacts<'a>| obs(
            &mut f.reservation,
            |r| {
                if let ForkReservation::Pending { expires_ms, .. } = r {
                    *expires_ms += 1;
                }
            }
        )),
        m!("reservation.race", |f: &mut ForkFacts<'a>| obs(
            &mut f.reservation,
            |r| *r = ForkReservation::ReplayRace {
                owner: OperationId([1; 32])
            }
        )),
        m!("replay.rev", |f: &mut ForkFacts<'a>| bump(&mut f.replay)),
        m!("replay.absent", |f: &mut ForkFacts<'a>| f.replay =
            Some(Observed::Absent(REV))),
        m!("replay.operation", |f: &mut ForkFacts<'a>| obs(
            &mut f.replay,
            |r: &mut ForkReplay| {
                if let ForkReplay::InFlight { operation, .. } = r {
                    operation.0[0] ^= 1;
                }
            }
        )),
        m!("replay.fingerprint", |f: &mut ForkFacts<'a>| obs(
            &mut f.replay,
            |r| {
                if let ForkReplay::InFlight { fingerprint, .. } = r {
                    fingerprint[0] ^= 1;
                }
            }
        )),
        m!("replay.recorded", |f: &mut ForkFacts<'a>| obs(
            &mut f.replay,
            |r| *r = ForkReplay::Recorded {
                fingerprint: [1; 32],
                result: ForkTerminal::Refused(ForkRefusal::Expired)
            }
        )),
    ]
}

fn other_plan() -> ForkPlan {
    let mut changed = binding();
    changed.destination_visibility = ForkVisibility::Public;
    ForkPlan::seal(changed, inventories(), LIMITS).expect("valid alternative plan")
}

fn accept_decide<'a>(
    plan: &'a ForkPlan,
    request: &'a mkit_primitives::fork::ForkAttempt,
    source: &'a FinalForkSourceProof,
    now: u64,
) -> impl Fn(&ForkFacts<'a>) -> Result<Guarded<mkit_primitives::fork::ForkDecision<'a>>, Failure> {
    move |f| {
        // The decision borrows its facts for the plan's lifetime only through
        // the plan and request, so a cloned variant outlives the call.
        let f: &'a ForkFacts<'a> = Box::leak(Box::new(f.clone()));
        decide_fork_acceptance(plan, request, f, Some(source), now, LIMITS)
    }
}

#[test]
fn fork_acceptance_guards_every_acquired_fact() {
    let plan = ForkPlan::seal(binding(), inventories(), LIMITS).expect("valid plan");
    let other = other_plan();
    let request = attempt(1);
    let other_request = attempt(2);
    let source = proof(&plan);
    let base = facts(&plan, &request);
    let mutations = acceptance_mutations(&other, &other_request);
    exhaust(
        "accept",
        &base,
        &mutations,
        1,
        accept_decide(&plan, &request, &source, 1),
        ForkFacts::guards,
    );
}

#[test]
fn fork_saved_result_replay_guards_every_acquired_fact() {
    let plan = ForkPlan::seal(binding(), inventories(), LIMITS).expect("valid plan");
    let other = other_plan();
    let request = attempt(1);
    let other_request = attempt(2);
    let source = proof(&plan);
    let mut base = facts(&plan, &request);
    let saved = ForkTerminal::Accepted(Box::new(plan.result().clone()));
    obs(&mut base.job, |j| {
        j.state = ForkJobState::Terminal(saved.clone())
    });
    base.replay = observed(ForkReplay::Recorded {
        fingerprint: request.fingerprint,
        result: saved.clone(),
    });
    base.reservation = observed(ForkReservation::Settled(saved));
    let mutations = acceptance_mutations(&other, &other_request);
    exhaust(
        "replay",
        &base,
        &mutations,
        1,
        accept_decide(&plan, &request, &source, 1),
        ForkFacts::guards,
    );
}

#[test]
fn fork_joining_attempt_guards_every_acquired_fact() {
    let plan = ForkPlan::seal(binding(), inventories(), LIMITS).expect("valid plan");
    let other = other_plan();
    let owner = attempt(1);
    let joiner = attempt(2);
    let other_request = attempt(3);
    let source = proof(&plan);
    let mut base = facts(&plan, &joiner);
    obs(&mut base.job, |j| j.attempt = owner.clone());
    base.replay = Some(Observed::Absent(REV));
    obs(&mut base.admission, |a| {
        a.operation = joiner.operation.clone();
        a.reservation = joiner.reservation.clone();
    });
    obs(&mut base.quota, |q| q.operation = joiner.operation.clone());
    obs(&mut base.permission, |p| {
        p.operation = joiner.operation.clone()
    });
    let mutations = acceptance_mutations(&other, &other_request);
    exhaust(
        "join",
        &base,
        &mutations,
        1,
        accept_decide(&plan, &joiner, &source, 1),
        ForkFacts::guards,
    );
}

#[test]
fn the_final_source_proof_is_the_pre_apply_fence_and_every_proof_field_moves_it() {
    let plan = ForkPlan::seal(binding(), inventories(), LIMITS).expect("valid plan");
    let request = attempt(1);
    let facts = facts(&plan, &request);
    let source = proof(&plan);
    let guarded = decide_fork_acceptance(&plan, &request, &facts, Some(&source), 1, LIMITS)
        .expect("accepting fixture");
    assert_eq!(fork_source_proof(&guarded), Some(&source));
    let edits: Vec<(&str, Box<dyn Fn(&mut FinalForkSourceProof)>)> = vec![
        ("readable", Box::new(|p| p.readable = false)),
        ("branch", Box::new(|p| p.branch.0.push('x'))),
        (
            "lifecycle",
            Box::new(|p| p.lifecycle = Observed::Absent(REV)),
        ),
        (
            "publication",
            Box::new(|p| p.publication = Observed::Absent(REV)),
        ),
        ("access", Box::new(|p| p.access = Observed::Absent(REV))),
        ("pack.denied", Box::new(|p| p.packs[0].denied = true)),
        (
            "pack.held",
            Box::new(|p| p.packs[1].eligibility.held = true),
        ),
        (
            "pack.live",
            Box::new(|p| p.packs[2].eligibility.live = false),
        ),
        (
            "pack.superseded",
            Box::new(|p| p.packs[0].superseded = true),
        ),
        (
            "pack.descriptor",
            Box::new(|p| p.packs[0].descriptor[0] ^= 1),
        ),
        ("proof_point", Box::new(|p| p.proof_point += 1)),
        ("apply_attempt", Box::new(|p| p.apply_attempt = rev(98))),
        ("staged_revision", Box::new(|p| p.staged_revision = rev(98))),
    ];
    let mut moved = 0;
    for (name, edit) in edits {
        let mut variant = source.clone();
        edit(&mut variant);
        assert_ne!(
            fork_source_proof(&guarded),
            Some(&variant),
            "{name}: the fence is the exact proof"
        );
        let redecided = decide_fork_acceptance(&plan, &request, &facts, Some(&variant), 1, LIMITS);
        let differs = match &redecided {
            Ok(g) => format!("{:?}", g.decision()) != format!("{:?}", guarded.decision()),
            Err(_) => true,
        };
        moved += usize::from(differs);
    }
    assert!(moved > 0, "some proof fields must move the decision");
    // A saved-result replay never reaches the fence.
    let none = decide_fork_acceptance(&plan, &request, &facts, None, 1, LIMITS);
    assert!(none.is_err(), "acceptance needs the final proof");
}

fn advance_mutations() -> Vec<Mutation<'static, ForkAdvanceFacts>> {
    vec![
        m!("binding", |f: &mut ForkAdvanceFacts| f.binding[0] ^= 1),
        m!("destination", |f: &mut ForkAdvanceFacts| f.destination.0
            [0] ^= 1),
        m!("phase.toggled", |f: &mut ForkAdvanceFacts| f
            .progress
            .phase =
            if f.progress.phase == ForkAdvancePhase::Accepted {
                ForkAdvancePhase::Preparing
            } else {
                ForkAdvancePhase::Accepted
            }),
        m!("phase.complete", |f: &mut ForkAdvanceFacts| f
            .progress
            .phase =
            ForkAdvancePhase::Complete),
        m!("phase.failed", |f: &mut ForkAdvanceFacts| f
            .progress
            .phase =
            ForkAdvancePhase::Failed),
        m!("cursor", |f: &mut ForkAdvanceFacts| f.progress.cursor += 1),
        m!("part", |f: &mut ForkAdvanceFacts| f.progress.part += 1),
        m!("revision", |f: &mut ForkAdvanceFacts| f.progress.revision =
            rev(98)),
        m!("recorded_authority", |f: &mut ForkAdvanceFacts| f
            .recorded_authority =
            ForkObservation::Present(rev(98))),
        m!("authority", |f: &mut ForkAdvanceFacts| f.authority =
            ForkObservation::Present(rev(98))),
        m!("epoch.recorded", |f: &mut ForkAdvanceFacts| {
            if let Some(e) = f.grant_epoch.as_mut() {
                e.recorded = ForkObservation::Absent;
            }
        }),
        m!("epoch.current", |f: &mut ForkAdvanceFacts| {
            if let Some(e) = f.grant_epoch.as_mut() {
                e.current = ForkObservation::Absent;
            }
        }),
        m!("epoch.removed", |f: &mut ForkAdvanceFacts| f.grant_epoch =
            None),
        m!("epoch.added", |f: &mut ForkAdvanceFacts| f.grant_epoch =
            Some(ForkEpochFence::new(
                ForkObservation::Absent,
                ForkObservation::Absent
            ))),
        m!("reservation.id", |f: &mut ForkAdvanceFacts| {
            if let Some(r) = f.reservation.as_mut() {
                r.reservation = ReservationId([97; 32]);
            }
        }),
        m!("reservation.expected", |f: &mut ForkAdvanceFacts| {
            if let Some(r) = f.reservation.as_mut() {
                r.expected = rev(98);
            }
        }),
        m!("reservation.current", |f: &mut ForkAdvanceFacts| {
            if let Some(r) = f.reservation.as_mut() {
                r.current = ForkObservation::Absent;
            }
        }),
        m!("reservation.removed", |f: &mut ForkAdvanceFacts| f
            .reservation =
            None),
        m!("expires", |f: &mut ForkAdvanceFacts| f
            .construction_expires_ms +=
            1),
        m!("expires.earlier", |f: &mut ForkAdvanceFacts| f
            .construction_expires_ms =
            10),
    ]
}

fn preparing() -> ForkAdvanceFacts {
    let mut f = host_facts::advance();
    f.progress.phase = ForkAdvancePhase::Preparing;
    f
}

#[test]
fn fork_advance_guards_every_fact_and_bounds_the_construction_lifetime() {
    let base = preparing();
    exhaust(
        "advance",
        &base,
        &advance_mutations(),
        50,
        |f| Ok(decide_fork_advance(f, 50)),
        ForkAdvanceFacts::guards,
    );
    // The construction expiry rides with the decision as a validity guard, so a
    // commit ordered after it fails the comparison.
    let guarded = decide_fork_advance(&base, 50);
    assert!(
        guarded
            .required_guards()
            .contains(&RequiredGuard::ValidThrough { instant_ms: 100 })
    );
    assert!(guards_hold(&guarded, &base.guards(), 100));
    assert!(!guards_hold(&guarded, &base.guards(), 101));
    // An accepted phase ignores the bound.
    let accepted = host_facts::advance();
    let guarded = decide_fork_advance(&accepted, 5_000);
    assert!(
        !guarded
            .required_guards()
            .iter()
            .any(|g| matches!(g, RequiredGuard::ValidThrough { .. }))
    );
}

/// Owned activation inputs, so a variant can edit any borrowed fact.
#[derive(Clone, PartialEq)]
struct Activation {
    lifecycle: ForkLifecycleProtection,
    advance: ForkAdvanceFacts,
    expected: ForkResult,
    accepted: Option<ForkResult>,
    packs: Vec<Hash>,
    unit: mkit_primitives::fork::ForkMembershipUnit,
    proof: Option<mkit_primitives::fork::ForkClearanceProof>,
}
impl Activation {
    fn new() -> Self {
        let result = host_facts::result();
        Self {
            lifecycle: ForkLifecycleProtection::NotOffered,
            advance: host_facts::advance(),
            expected: result.clone(),
            accepted: Some(result),
            packs: host_facts::PACKS.to_vec(),
            unit: host_facts::unit(),
            proof: Some(host_facts::proof()),
        }
    }
    fn facts(&self) -> ForkActivationFacts<'_> {
        {
            let mut v =
                ForkActivationFacts::new(&self.advance, &self.expected, &self.packs, &self.unit);
            v.lifecycle = self.lifecycle.clone();
            v.accepted_result = self.accepted.as_ref();
            v.proof = self.proof.as_ref();
            v
        }
    }
}

fn managed(current: Option<Observed<LifecycleFact>>) -> ForkLifecycleProtection {
    ForkLifecycleProtection::Managed {
        expected_incarnation: rev(1),
        current,
    }
}
fn active() -> Observed<LifecycleFact> {
    Observed::Present {
        value: LifecycleFact::new(rev(1), LifecycleState::Active),
        revision: rev(2),
    }
}

fn result_mutations<S: 'static>(
    expected: impl Fn(&mut S) -> &mut ForkResult + Copy + 'static,
) -> Vec<Mutation<'static, S>> {
    vec![
        m!("result.branch", move |s: &mut S| expected(s)
            .branch
            .0
            .push('x')),
        m!("result.source", move |s: &mut S| expected(s).source.0[0] ^=
            1),
        m!("result.sequence", move |s: &mut S| expected(s)
            .source_sequence +=
            1),
        m!("result.tip", move |s: &mut S| expected(s).tip[0] ^= 1),
        m!("result.packmap", move |s: &mut S| expected(s).packmap[0] ^=
            1),
        m!("result.packs", move |s: &mut S| expected(s).packs += 1),
        m!("result.bytes", move |s: &mut S| expected(s).bytes += 1),
        m!("result.entries", move |s: &mut S| expected(s)
            .index_entries += 1),
        m!("result.digest", move |s: &mut S| expected(s).pack_digest
            [0] ^= 1),
        m!("result.generation", move |s: &mut S| expected(s)
            .destination_generation =
            rev(98)),
    ]
}

fn activation_mutations() -> Vec<Mutation<'static, Activation>> {
    let mut out: Vec<Mutation<'static, Activation>> = vec![
        m!("lifecycle.managed_none", |s: &mut Activation| s.lifecycle =
            managed(None)),
        m!("lifecycle.managed_active", |s: &mut Activation| s
            .lifecycle =
            managed(Some(active()))),
        m!("accepted.none", |s: &mut Activation| s.accepted = None),
        m!("packs.extra", |s: &mut Activation| s.packs.push([200; 32])),
        m!("packs.changed", |s: &mut Activation| s.packs[0][0] ^= 1),
        m!("unit.pack", |s: &mut Activation| s.unit.pack = [8; 32]),
        m!("unit.inherited_revision", |s: &mut Activation| s
            .unit
            .inherited_revision =
            rev(98)),
        m!("unit.expected.generation", |s: &mut Activation| s
            .unit
            .expected
            .generation =
            rev(98)),
        m!("unit.expected.sequence", |s: &mut Activation| s
            .unit
            .expected
            .sequence =
            1),
        m!("unit.expected.published", |s: &mut Activation| s
            .unit
            .expected
            .published =
            false),
        m!("unit.expected.held", |s: &mut Activation| s
            .unit
            .expected
            .held = true),
        m!("unit.expected.boundary", |s: &mut Activation| s
            .unit
            .expected
            .boundary =
            true),
        m!("unit.live", |s: &mut Activation| s.unit.live =
            Some(s.unit.expected)),
        m!("unit.published", |s: &mut Activation| s.unit.published =
            Some(s.unit.expected)),
        m!("unit.context", |s: &mut Activation| s.unit.context =
            ForkPairContext::AfterGuardLoss),
        m!("proof.none", |s: &mut Activation| s.proof = None),
        m!("proof.destination", |s: &mut Activation| {
            if let Some(p) = s.proof.as_mut() {
                p.destination.0[0] ^= 1;
            }
        }),
        m!("proof.binding", |s: &mut Activation| {
            if let Some(p) = s.proof.as_mut() {
                p.binding[0] ^= 1;
            }
        }),
        m!("proof.progress_revision", |s: &mut Activation| {
            if let Some(p) = s.proof.as_mut() {
                p.progress_revision = rev(98);
            }
        }),
        m!("proof.pack", |s: &mut Activation| {
            if let Some(p) = s.proof.as_mut() {
                p.pack[0] ^= 1;
            }
        }),
        m!("proof.apply_attempt", |s: &mut Activation| {
            if let Some(p) = s.proof.as_mut() {
                p.apply_attempt = rev(98);
            }
        }),
        m!("proof.valid_through", |s: &mut Activation| {
            if let Some(p) = s.proof.as_mut() {
                p.valid_through_ms += 1;
            }
        }),
        m!("proof.denial_revision", |s: &mut Activation| {
            if let Some(p) = s.proof.as_mut() {
                p.denial_revision = rev(98);
            }
        }),
    ];
    for (name, edit) in advance_mutations() {
        out.push((
            Box::leak(format!("advance.{name}").into_boxed_str()),
            Box::new(move |s: &mut Activation| edit(&mut s.advance)),
        ));
    }
    for (name, edit) in result_mutations(|s: &mut Activation| &mut s.expected) {
        out.push((
            Box::leak(format!("expected.{name}").into_boxed_str()),
            Box::new(move |s: &mut Activation| edit(s)),
        ));
    }
    out.push(m!("accepted.branch", |s: &mut Activation| {
        if let Some(r) = s.accepted.as_mut() {
            r.branch.0.push('x');
        }
    }));
    out
}

#[test]
fn fork_activation_guards_every_fact_including_the_denial_revision() {
    let base = Activation::new();
    exhaust(
        "activation",
        &base,
        &activation_mutations(),
        150,
        |s| {
            let s: &'static Activation = Box::leak(Box::new(s.clone()));
            let facts: &'static ForkActivationFacts<'static> = Box::leak(Box::new(s.facts()));
            decide_fork_activation(facts, 150, host_facts::LIMITS)
        },
        |s| s.facts().guards(),
    );
    // The proof deadline is a validity bound; the denial revision is a row.
    let facts = base.facts();
    let guarded = decide_fork_activation(&facts, 150, host_facts::LIMITS).expect("installs");
    assert!(
        guarded
            .required_guards()
            .contains(&RequiredGuard::ValidThrough { instant_ms: 200 })
    );
    assert!(guards_hold(&guarded, &facts.guards(), 200));
    assert!(!guards_hold(&guarded, &facts.guards(), 201));
    let mut denied = base.clone();
    if let Some(p) = denied.proof.as_mut() {
        p.denial_revision = rev(98);
    }
    assert!(!guards_hold(&guarded, &denied.facts().guards(), 150));
    // A managed profile compares the lifecycle observation too.
    let mut with_lifecycle = base.clone();
    with_lifecycle.lifecycle = managed(Some(active()));
    let facts = with_lifecycle.facts();
    let guarded = decide_fork_activation(&facts, 150, host_facts::LIMITS).expect("installs");
    assert!(
        guarded
            .required_guards()
            .iter()
            .any(|g| matches!(g, RequiredGuard::Repository { .. }))
    );
}

#[derive(Clone, PartialEq)]
struct Completion {
    lifecycle: ForkLifecycleProtection,
    advance: ForkAdvanceFacts,
    expected: ForkResult,
    accepted: Option<ForkResult>,
    cursor: u64,
    part: u16,
    packs: u64,
    digest: Hash,
    owner: Hash,
}
impl Completion {
    fn new() -> Self {
        let result = host_facts::result();
        let advance = host_facts::advance();
        Self {
            lifecycle: ForkLifecycleProtection::NotOffered,
            owner: advance.binding,
            advance,
            digest: result.pack_digest,
            expected: result.clone(),
            accepted: Some(result),
            cursor: 2,
            part: 0,
            packs: 2,
        }
    }
    fn facts(&self) -> ForkCompletionFacts<'_> {
        {
            let mut v = ForkCompletionFacts::new(
                &self.advance,
                &self.expected,
                self.cursor,
                self.part,
                self.packs,
                self.digest,
                self.owner,
            );
            v.lifecycle = self.lifecycle.clone();
            v.accepted_result = self.accepted.as_ref();
            v
        }
    }
}

#[test]
fn fork_completion_guards_every_fact() {
    let base = Completion::new();
    let mut mutations: Vec<Mutation<'static, Completion>> = vec![
        m!("lifecycle.managed_none", |s: &mut Completion| s.lifecycle =
            managed(None)),
        m!("lifecycle.managed_active", |s: &mut Completion| s
            .lifecycle =
            managed(Some(active()))),
        m!("accepted.none", |s: &mut Completion| s.accepted = None),
        m!("cursor", |s: &mut Completion| s.cursor += 1),
        m!("part", |s: &mut Completion| s.part += 1),
        m!("packs", |s: &mut Completion| s.packs += 1),
        m!("digest", |s: &mut Completion| s.digest[0] ^= 1),
        m!("owner", |s: &mut Completion| s.owner[0] ^= 1),
    ];
    for (name, edit) in advance_mutations() {
        mutations.push((
            Box::leak(format!("advance.{name}").into_boxed_str()),
            Box::new(move |s: &mut Completion| edit(&mut s.advance)),
        ));
    }
    for (name, edit) in result_mutations(|s: &mut Completion| &mut s.expected) {
        mutations.push((
            Box::leak(format!("expected.{name}").into_boxed_str()),
            Box::new(move |s: &mut Completion| edit(s)),
        ));
    }
    exhaust(
        "completion",
        &base,
        &mutations,
        0,
        |s| {
            let s: &'static Completion = Box::leak(Box::new(s.clone()));
            let facts: &'static ForkCompletionFacts<'static> = Box::leak(Box::new(s.facts()));
            decide_fork_completion(facts, host_facts::LIMITS)
        },
        |s| s.facts().guards(),
    );
}

// ---- published clearance ----

static PACKS: [Hash; 3] = [[1; 32], [2; 32], [3; 32]];
static ALTERNATE: [Hash; 1] = [[9; 32]];

fn adv(sequence: u64, state: ClearanceState) -> ClearanceAdvance<'static> {
    {
        let mut v = ClearanceAdvance::new(
            sequence,
            1,
            OperationId([sequence as u8; 32]),
            state,
            rev(sequence as u8),
        );
        v.head = Some([sequence as u8; 32]);
        v.packmap = Some([sequence as u8 + 10; 32]);
        v.additions = &PACKS[..1];
        v.dependencies = &PACKS[..2];
        v.external_suppliers = &PACKS[2..];
        v.obligations = &[];
        v.obligation_revisions = &[];
        v.takedown_complete = false;
        v.flagged = false;
        v
    }
}
fn witness(object: Hash) -> DependencyWitness {
    DependencyWitness::new(object, true, true, false, 1, rev(4))
}
fn clearance_base(moment: ClearanceMoment) -> ClearanceFacts<'static> {
    {
        let mut v = ClearanceFacts::new(
            RepositoryId([1; 32]),
            moment,
            PriorPublication::new(1, 1, 1, 0, Some([1; 32]), Some([11; 32]), rev(9)),
            adv(2, ClearanceState::Cleared),
            ClearanceState::Pending,
        );
        v.suffix = &[];
        v.witnesses = Box::leak(Box::new([witness(PACKS[1]), witness(PACKS[2])]));
        v.lifecycle = ClearanceLifecycle::NotOffered;
        v.deleted = false;
        v
    }
}

fn advance_edits() -> Vec<Mutation<'static, ClearanceFacts<'static>>> {
    static ONE_STATE: [ClearanceState; 1] = [ClearanceState::Cleared];
    static ONE_REVISION: [Revision; 1] = [Revision([5; 32])];
    vec![
        m!("sequence", move |f: &mut ClearanceFacts<'static>| f
            .changed
            .sequence +=
            1),
        m!("generation", move |f: &mut ClearanceFacts<'static>| f
            .changed
            .generation =
            2),
        m!("operation", move |f: &mut ClearanceFacts<'static>| f
            .changed
            .operation
            .0[0] ^=
            1),
        m!("head", move |f: &mut ClearanceFacts<'static>| f
            .changed
            .head =
            None),
        m!("packmap", move |f: &mut ClearanceFacts<'static>| f
            .changed
            .packmap =
            None),
        m!("state", move |f: &mut ClearanceFacts<'static>| f
            .changed
            .state =
            ClearanceState::Held),
        m!("additions", move |f: &mut ClearanceFacts<'static>| f
            .changed
            .additions =
            &ALTERNATE),
        m!("dependencies", move |f: &mut ClearanceFacts<'static>| f
            .changed
            .dependencies =
            &ALTERNATE),
        m!("suppliers", move |f: &mut ClearanceFacts<'static>| f
            .changed
            .external_suppliers =
            &ALTERNATE),
        m!("obligations", move |f: &mut ClearanceFacts<'static>| f
            .changed
            .obligations =
            &ONE_STATE),
        m!("obligation_revisions", move |f: &mut ClearanceFacts<
            'static,
        >| f
            .changed
            .obligation_revisions =
            &ONE_REVISION),
        m!("takedown", move |f: &mut ClearanceFacts<'static>| f
            .changed
            .takedown_complete =
            true),
        m!("flagged", move |f: &mut ClearanceFacts<'static>| f
            .changed
            .flagged =
            true),
        m!("revision", move |f: &mut ClearanceFacts<'static>| f
            .changed
            .revision =
            rev(98)),
    ]
}

fn clearance_mutations(moment: ClearanceMoment) -> Vec<Mutation<'static, ClearanceFacts<'static>>> {
    let mut out: Vec<Mutation<'static, ClearanceFacts<'static>>> = vec![
        m!("repository", |f: &mut ClearanceFacts<'static>| f
            .repository =
            RepositoryId([98; 32])),
        m!(
            "moment",
            move |f: &mut ClearanceFacts<'static>| f.moment = match moment {
                ClearanceMoment::Acceptance => ClearanceMoment::Recheck,
                _ => ClearanceMoment::Acceptance,
            }
        ),
        m!("prior.generation", |f: &mut ClearanceFacts<'static>| f
            .prior
            .generation =
            2),
        m!("prior.sequence", |f: &mut ClearanceFacts<'static>| f
            .prior
            .sequence +=
            1),
        m!("prior.prefix", |f: &mut ClearanceFacts<'static>| f
            .prior
            .published_prefix =
            0),
        m!("prior.boundary", |f: &mut ClearanceFacts<'static>| f
            .prior
            .deletion_boundary =
            1),
        m!("prior.head", |f: &mut ClearanceFacts<'static>| f
            .prior
            .head =
            None),
        m!("prior.packmap", |f: &mut ClearanceFacts<'static>| f
            .prior
            .packmap =
            None),
        m!("prior.revision", |f: &mut ClearanceFacts<'static>| f
            .prior
            .revision =
            rev(98)),
        m!("previous_state", |f: &mut ClearanceFacts<'static>| f
            .previous_state =
            ClearanceState::Hit),
        m!("deleted", |f: &mut ClearanceFacts<'static>| f.deleted =
            true),
        m!("witness.removed", |f: &mut ClearanceFacts<'static>| f
            .witnesses =
            &f.witnesses[1..]),
        m!("witness.unpublished", |f: &mut ClearanceFacts<'static>| {
            let mut w = f.witnesses.to_vec();
            w[0].published = false;
            f.witnesses = Box::leak(w.into_boxed_slice());
        }),
        m!("witness.held", |f: &mut ClearanceFacts<'static>| {
            let mut w = f.witnesses.to_vec();
            w[1].held = true;
            f.witnesses = Box::leak(w.into_boxed_slice());
        }),
        m!("witness.present", |f: &mut ClearanceFacts<'static>| {
            let mut w = f.witnesses.to_vec();
            w[0].present = false;
            f.witnesses = Box::leak(w.into_boxed_slice());
        }),
        m!("witness.generation", |f: &mut ClearanceFacts<'static>| {
            let mut w = f.witnesses.to_vec();
            w[0].generation = 2;
            f.witnesses = Box::leak(w.into_boxed_slice());
        }),
        m!("witness.revision", |f: &mut ClearanceFacts<'static>| {
            let mut w = f.witnesses.to_vec();
            w[0].revision = rev(98);
            f.witnesses = Box::leak(w.into_boxed_slice());
        }),
        m!("witness.object", |f: &mut ClearanceFacts<'static>| {
            let mut w = f.witnesses.to_vec();
            w[0].object[0] ^= 1;
            f.witnesses = Box::leak(w.into_boxed_slice());
        }),
        m!("lifecycle.managed_none", |f: &mut ClearanceFacts<
            'static,
        >| f.lifecycle =
            ClearanceLifecycle::Managed {
                expected_incarnation: rev(1),
                current: None
            }),
        m!("lifecycle.managed_active", |f: &mut ClearanceFacts<
            'static,
        >| f.lifecycle =
            ClearanceLifecycle::Managed {
                expected_incarnation: rev(1),
                current: Some(active())
            }),
    ];
    for (name, edit) in advance_edits() {
        out.push((Box::leak(format!("changed.{name}").into_boxed_str()), edit));
    }
    out
}

fn clearance_decide(
    now_unused: u64,
) -> impl Fn(
    &ClearanceFacts<'static>,
) -> Result<Guarded<mkit_primitives::decision::ClearanceDecision>, Failure> {
    let _ = now_unused;
    |f| {
        let f: &'static ClearanceFacts<'static> = Box::leak(Box::new(f.clone()));
        decide_clearance(f, &ClearanceLimits::reference())
    }
}

#[test]
fn clearance_at_acceptance_guards_every_fact() {
    let mut base = clearance_base(ClearanceMoment::Acceptance);
    base.previous_state = ClearanceState::Cleared;
    exhaust(
        "clearance/acceptance",
        &base,
        &clearance_mutations(ClearanceMoment::Acceptance),
        0,
        clearance_decide(0),
        ClearanceFacts::guards,
    );
}

#[test]
fn clearance_recheck_guards_every_retained_suffix_fact() {
    let mut base = clearance_base(ClearanceMoment::Recheck);
    base.prior.sequence = 3;
    base.prior.published_prefix = 1;
    base.prior.head = Some([1; 32]);
    base.prior.packmap = Some([11; 32]);
    let suffix: &'static [ClearanceAdvance<'static>] = Box::leak(Box::new([
        adv(2, ClearanceState::Cleared),
        adv(3, ClearanceState::Pending),
    ]));
    base.suffix = suffix;
    base.changed = adv(2, ClearanceState::Cleared);
    base.previous_state = ClearanceState::Cleared;
    let mut mutations = clearance_mutations(ClearanceMoment::Recheck);
    for (name, edit) in advance_edits() {
        mutations.push((
            Box::leak(format!("suffix.{name}").into_boxed_str()),
            Box::new(move |f: &mut ClearanceFacts<'static>| {
                let mut probe = f.clone();
                probe.changed = f.suffix.last().cloned().expect("suffix");
                edit(&mut probe);
                let mut retained = f.suffix.to_vec();
                *retained.last_mut().expect("suffix") = probe.changed;
                f.suffix = Box::leak(retained.into_boxed_slice());
            }),
        ));
    }
    exhaust(
        "clearance/recheck",
        &base,
        &mutations,
        0,
        clearance_decide(0),
        ClearanceFacts::guards,
    );
}

#[test]
fn clearance_guards_include_every_witness_row_and_the_absence_of_a_missing_one() {
    let base = clearance_base(ClearanceMoment::Acceptance);
    let guards = base.guards();
    let rows = guards
        .iter()
        .filter(|g| {
            matches!(
                g,
                RequiredGuard::Row {
                    row: mkit_primitives::decision::GuardRow::ClearanceWitness(_),
                    ..
                }
            )
        })
        .count();
    assert_eq!(rows, 2);
    let mut missing = base.clone();
    missing.witnesses = &missing.witnesses[1..];
    let absent = missing
        .guards()
        .into_iter()
        .filter(|g| {
            matches!(
                g,
                RequiredGuard::Row {
                    expected: Observed::Absent(_),
                    row: mkit_primitives::decision::GuardRow::ClearanceWitness(_),
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        absent, 1,
        "a dependency with no witness is guarded as absent"
    );
}
