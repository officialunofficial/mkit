//! Fork acceptance: where the reference server differs from the portable
//! decision (SPEC-SERVER 3.1). Each test runs the server path and the portable
//! `decide_fork_acceptance` (or advance decision) on the same input and asserts
//! the documented difference.
#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use mkit_primitives::{
    decision::{
        AuthorityFact, AuthorityMode, GrantFact, LifecycleFact, NamespaceId, Observed, OperationId,
        PublicationFact, RefName, ReplayScope, ReservationId,
    },
    evidence::{RepositoryId, Revision},
    fork::{
        FinalForkSourceProof, ForkAdmission, ForkAdvanceFacts, ForkAdvancePhase,
        ForkAdvanceRefusal, ForkAttempt, ForkBinding, ForkDecision, ForkEmptiness, ForkFacts,
        ForkInventory, ForkJob, ForkJobState, ForkLimits, ForkName, ForkObservation,
        ForkPackEligibility, ForkPackProof, ForkPermission, ForkPlan, ForkProgress, ForkQuota,
        ForkRefusal, ForkReplay, ForkReservation, ForkReservationFence, ForkVisibility,
        SourceAccess, decide_fork_acceptance, decide_fork_advance,
    },
};

use super::{FenceRowsV1, FenceV1, ForkEnv, ForkError, ForkJobV1, Phase, SourceAccessV1};
use crate::store::Value;

const REV: Revision = Revision([1; 32]);
const LIMITS: fn() -> ForkLimits = || ForkLimits::new(3, 4, 128, 30, 300, 4096);

fn seen<T>(value: T) -> Observed<T> {
    Observed::Present {
        value,
        revision: REV,
    }
}
#[allow(clippy::unnecessary_wraps)]
fn present<T>(value: T) -> Option<Observed<T>> {
    Some(seen(value))
}

fn plan() -> ForkPlan {
    let packs = vec![
        ForkInventory::new([1; 32], [11; 32], 100, 10, vec![[2; 32]]),
        ForkInventory::new([2; 32], [12; 32], 100, 10, vec![[3; 32]]),
        ForkInventory::new([3; 32], [13; 32], 100, 10, vec![]),
    ];
    let access = SourceAccess::new([21; 32], ForkVisibility::Private, REV, REV);
    let binding = ForkBinding::new(
        RepositoryId([1; 32]),
        REV,
        RefName("refs/heads/main".into()),
        PublicationFact::new(REV, 1, 1, 0, Some([10; 32]), Some([1; 32])),
        access,
        RepositoryId([2; 32]),
        Revision([2; 32]),
        ForkVisibility::Private,
    );
    ForkPlan::seal(binding, packs, LIMITS()).unwrap()
}

fn attempt() -> ForkAttempt {
    ForkAttempt::new(
        OperationId([1; 32]),
        Some(ReservationId([1; 32])),
        ReplayScope([1; 32]),
        [1; 32],
        100,
        AuthorityFact::new(NamespaceId([7; 32]), AuthorityMode::Authority, REV, true),
        Some(GrantFact::new(NamespaceId([7; 32]), [3; 32], REV, None)),
        true,
    )
}

fn proof(plan: &ForkPlan) -> FinalForkSourceProof {
    let b = plan.binding();
    FinalForkSourceProof::new(
        REV,
        REV,
        11,
        b.source,
        b.branch.clone(),
        seen(LifecycleFact::new(
            b.source_incarnation,
            mkit_primitives::decision::LifecycleState::Active,
        )),
        seen(b.publication.clone()),
        seen(b.source_access.clone()),
        true,
        plan.packs()
            .iter()
            .map(|p| {
                ForkPackProof::new(
                    p.pack,
                    b.source_incarnation,
                    b.publication.generation,
                    REV,
                    p.descriptor,
                    REV,
                    REV,
                    ForkPackEligibility::new(true, true, false),
                    false,
                    false,
                )
            })
            .collect(),
    )
}

fn facts<'a>(plan: &'a ForkPlan, request: &'a ForkAttempt) -> ForkFacts<'a> {
    let mut f = ForkFacts::new(plan.binding().destination, request, REV, 12);
    f.job = present(ForkJob::new(
        plan,
        request.clone(),
        90,
        ForkJobState::Staged {
            packs: 3,
            revision: REV,
            last_effect: 10,
        },
    ));
    f.emptiness = present(ForkEmptiness::new(
        0,
        0,
        3,
        plan.pack_digest(),
        Some(request.operation.clone()),
        false,
    ));
    f.name = present(ForkName::new(None, Some(ForkVisibility::Private)));
    f.lifecycle = Some(Observed::Absent(REV));
    f.permission = present(ForkPermission::new(
        request.operation.clone(),
        plan.binding().source_access.clone(),
        ForkVisibility::Private,
        true,
        true,
    ));
    f.authority = present(request.authority.clone());
    f.grant = present(request.grant.clone().unwrap());
    f.admission = present(ForkAdmission::new(
        plan,
        request.operation.clone(),
        request.reservation.clone(),
        300,
        300,
        Some(REV),
    ));
    f.quota = present(ForkQuota::new(
        request.operation.clone(),
        REV,
        300,
        300,
        300,
        1,
        1,
    ));
    f.reservation = present(ForkReservation::Pending {
        operation: request.operation.clone(),
        destination: plan.binding().destination,
        expires_ms: 90,
    });
    f.replay = present(ForkReplay::InFlight {
        operation: request.operation.clone(),
        fingerprint: request.fingerprint,
    });
    f
}

fn refusal_of(
    plan: &ForkPlan,
    request: &ForkAttempt,
    facts: &ForkFacts<'_>,
) -> Option<ForkRefusal> {
    let source = proof(plan);
    let guarded = decide_fork_acceptance(plan, request, facts, Some(&source), 1, LIMITS()).unwrap();
    match guarded.decision() {
        ForkDecision::Refuse(reason) => Some(*reason),
        _ => None,
    }
}

#[test]
fn the_fixture_is_accepted_by_the_portable_decision() {
    let (plan, request) = (plan(), attempt());
    let f = facts(&plan, &request);
    assert_eq!(refusal_of(&plan, &request, &f), None);
}

/// Same input: the resolved pack set is smaller than the admitted charge.
/// The server's charge is an upper bound; the portable decision needs equality.
#[test]
fn a_larger_admission_charge_is_covered_by_the_server_and_refused_by_the_primitive() {
    let (plan, request) = (plan(), attempt());
    let (bytes, declared) = (plan.bytes(), plan.bytes() + 1);
    assert!(!super::exceeds_admission(bytes, declared));
    let mut f = facts(&plan, &request);
    if let Some(Observed::Present { value, .. }) = f.admission.as_mut() {
        value.declared_bytes = declared;
        value.new_to_repo_bytes = declared;
    }
    assert_eq!(
        refusal_of(&plan, &request, &f),
        Some(ForkRefusal::QuotaExceeded)
    );
    // A set larger than the charge is refused by both.
    assert!(super::exceeds_admission(bytes, bytes - 1));
}

fn job_with_fence() -> ForkJobV1 {
    ForkJobV1 {
        binding: [1; 32],
        dest_ns: crate::NamespaceKey::deployment_default().as_str().into(),
        dest_repo: "destination".into(),
        source_ns: crate::NamespaceKey::deployment_default().as_str().into(),
        source_repo: "source".into(),
        source_ref: "refs/heads/main".into(),
        tip: [2; 32],
        packmap: [3; 32],
        source_sequence: 1,
        source_generation: 0,
        visibility: "private".into(),
        created_ms: 0,
        expires_ms: 100_000,
        phase: Phase::Accept,
        packs: Vec::new(),
        cursor: 0,
        deps: Vec::new(),
        part: 0,
        lanes: Vec::new(),
        after: None,
        scanned: 0,
        copied: 0,
        failure: None,
        settle: None,
        fence: Some(FenceV1 {
            authority_generation: Some(1),
            grant_epoch: Some(1),
            create_namespace: false,
        }),
        fence_rows: FenceRowsV1::default(),
        source_access: SourceAccessV1::default(),
        proof: super::proof::ProofV1::default(),
        accepted: None,
        result: None,
    }
}

/// Same movement, two answers: the portable decision has one permission class,
/// the server replays the authority and epoch movements as distinct errors.
#[test]
fn authority_and_epoch_movement_are_one_portable_class_and_two_server_answers() {
    let (plan, request) = (plan(), attempt());
    // Portable: authority moved, then grant epoch moved.
    let mut moved_authority = facts(&plan, &request);
    if let Some(Observed::Present { value, .. }) = moved_authority.authority.as_mut() {
        value.generation = Revision([9; 32]);
    }
    let mut moved_epoch = facts(&plan, &request);
    if let Some(Observed::Present { value, .. }) = moved_epoch.grant.as_mut() {
        value.epoch = Revision([9; 32]);
    }
    for moved in [&moved_authority, &moved_epoch] {
        assert_eq!(
            refusal_of(&plan, &request, moved),
            Some(ForkRefusal::PermissionDenied)
        );
    }
    // Server: the same two movements, observed as stored rows.
    let job = job_with_fence();
    let recorded = FenceRowsV1 {
        authority: Some(b"a1".to_vec()),
        epoch: Some(b"e1".to_vec()),
    };
    let row = |bytes: &[u8]| Some(Value::new(bytes.to_vec()));
    assert_eq!(
        super::decision::authority(&recorded, &job, &[row(b"a2"), row(b"e1")]),
        Err(ForkError::Moved("authority"))
    );
    assert_eq!(
        super::decision::authority(&recorded, &job, &[row(b"a1"), row(b"e2")]),
        Err(ForkError::Moved("epoch"))
    );
    assert_ne!(
        ForkError::Moved("authority").error().public_message(),
        ForkError::Moved("epoch").error().public_message()
    );
}

/// Same input: the original reservation is gone before acceptance. The
/// portable decision names it; the server's progress decision ends the job as
/// expired.
#[test]
fn a_settled_reservation_is_its_own_portable_refusal_and_expired_on_the_server() {
    let (plan, request) = (plan(), attempt());
    let mut f = facts(&plan, &request);
    f.reservation = Some(Observed::Absent(REV));
    assert_eq!(
        refusal_of(&plan, &request, &f),
        Some(ForkRefusal::ReservationSettled)
    );
    let mut advance = ForkAdvanceFacts::new(
        [1; 32],
        RepositoryId([2; 32]),
        ForkProgress::new(ForkAdvancePhase::Preparing, 0, 0, REV),
        1_000,
    );
    advance.reservation = Some(ForkReservationFence::new(
        ReservationId([1; 32]),
        REV,
        ForkObservation::Absent,
    ));
    // Portable advance names the same cause with its own code...
    assert_eq!(
        *decide_fork_advance(&advance, 5).decision(),
        mkit_primitives::fork::ForkAdvanceDecision::Refuse(ForkAdvanceRefusal::ReservationSettled)
    );
    // ...and the server answers `Expired`, as it does for a lapsed lifetime.
    let server = super::decision::progress(&advance, 5);
    assert_eq!(server, Err(ForkError::Expired));
    let mut lapsed = advance.clone();
    lapsed.reservation = None;
    assert_eq!(
        super::decision::progress(&lapsed, 5_000),
        Err(ForkError::Expired)
    );
}

/// Same input: the destination already exists with another visibility. The
/// portable decision reports a visibility mismatch; the server refuses any
/// registered destination as not empty, before visibility is compared.
#[test]
fn a_registered_destination_of_another_visibility_is_a_mismatch_portably_and_not_empty_here() {
    use crate::MemoryKv;
    use crate::fork::ForkLimits as ServerLimits;
    use crate::pipeline::D34Shards;
    use crate::rt::ManualClock;
    use crate::store::{Batch, NamespaceStore, keys};
    use futures_executor::block_on;

    let (plan, request) = (plan(), attempt());
    let mut f = facts(&plan, &request);
    if let Some(Observed::Present { value, .. }) = f.name.as_mut() {
        value.declared_visibility = Some(ForkVisibility::Public);
    }
    assert_eq!(
        refusal_of(&plan, &request, &f),
        Some(ForkRefusal::VisibilityMismatch)
    );

    let store = MemoryKv::default();
    let clock = ManualClock::new(0);
    let dest = crate::RepoId {
        namespace: crate::NamespaceKey::deployment_default(),
        name: crate::RepoName::new("destination").unwrap(),
    };
    let env = ForkEnv {
        store: &store,
        shards: &D34Shards,
        clock: &clock,
        takedown_denial: true,
        extract_min_bytes: None,
        limits: ServerLimits::default(),
        publication_policy: None,
    };
    let partition = env.shards.coordinator(&dest.namespace);
    block_on(async {
        // Unregistered: the server accepts the destination.
        assert_eq!(super::job::require_unregistered(&env, &dest).await, Ok(()));
        // Registered with any visibility: not empty.
        store
            .apply(
                &partition,
                Batch::new().put(keys::repo_record(&dest.name), Value::new(vec![1])),
            )
            .await
            .unwrap();
        assert_eq!(
            super::job::require_unregistered(&env, &dest).await,
            Err(ForkError::NotEmpty)
        );
    });
}
