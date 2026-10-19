//! Bounded fork decision fuzz body and deterministic supplied-fact builders.
use mkit_primitives::{
    decision::{
        AuthorityFact, AuthorityMode, LifecycleFact, LifecycleState, NamespaceId, Observed,
        OperationId, PublicationFact, RefName, ReplayScope, ReservationId, guards_hold,
    },
    evidence::{RepositoryId, Revision},
    fork::{
        FinalForkSourceProof, ForkAdmission, ForkAttempt, ForkBinding, ForkDecision, ForkEmptiness,
        ForkFacts, ForkInventory, ForkJob, ForkJobState, ForkLimits, ForkName, ForkPackEligibility,
        ForkPackProof, ForkPermission, ForkPlan, ForkQuota, ForkReplay, ForkReservation,
        ForkVisibility, SourceAccess, decide_fork_acceptance,
    },
};

/// Fixed logical revision used by the deterministic replay corpus.
pub const REV: Revision = Revision([1; 32]);
/// Finite bounds for the three-pack test graph.
pub const LIMITS: ForkLimits = ForkLimits::new(3, 4, 128, 30, 300, 4096);

/// Trusted present observation with a fixed revision.
pub fn observed<T>(value: T) -> Option<Observed<T>> {
    Some(Observed::Present {
        value,
        revision: REV,
    })
}
/// Minimal full inventory graph: packmap, listed pack, transitive base supplier.
#[must_use]
pub fn inventories() -> Vec<ForkInventory> {
    vec![
        ForkInventory::new([1; 32], [11; 32], 100, 10, vec![[2; 32]]),
        ForkInventory::new([2; 32], [12; 32], 100, 10, vec![[3; 32]]),
        ForkInventory::new([3; 32], [13; 32], 100, 10, vec![]),
    ]
}
/// Exact deterministic source/destination publication binding.
#[must_use]
pub fn binding() -> ForkBinding {
    ForkBinding::new(
        RepositoryId([1; 32]),
        REV,
        RefName("refs/heads/main".into()),
        PublicationFact::new(REV, 1, 1, 0, Some([10; 32]), Some([1; 32])),
        SourceAccess::new([21; 32], ForkVisibility::Private, REV, REV),
        RepositoryId([2; 32]),
        Revision([2; 32]),
        ForkVisibility::Private,
    )
}
/// Fixed request with explicit authority fencing and grant-independent permission.
#[must_use]
pub fn attempt(id: u8) -> ForkAttempt {
    ForkAttempt::new(
        OperationId([id; 32]),
        Some(ReservationId([id; 32])),
        ReplayScope([id; 32]),
        [id; 32],
        100,
        AuthorityFact::new(NamespaceId([7; 32]), AuthorityMode::Authority, REV, true),
        None,
        true,
    )
}
/// Fully staged destination with no reader-visible membership or writes.
#[must_use]
pub fn facts<'a>(plan: &'a ForkPlan, request: &'a ForkAttempt) -> ForkFacts<'a> {
    {
        let mut v = ForkFacts::new(plan.binding().destination, request, REV, 12);
        v.job = observed(ForkJob::new(
            plan,
            request.clone(),
            90,
            ForkJobState::Staged {
                packs: 3,
                revision: REV,
                last_effect: 10,
            },
        ));
        v.emptiness = observed(ForkEmptiness::new(
            0,
            0,
            3,
            plan.pack_digest(),
            Some(request.operation.clone()),
            false,
        ));
        v.name = observed(ForkName::new(None, Some(ForkVisibility::Private)));
        v.lifecycle = Some(Observed::Absent(REV));
        v.permission = observed(ForkPermission::new(
            request.operation.clone(),
            plan.binding().source_access.clone(),
            ForkVisibility::Private,
            true,
            true,
        ));
        v.authority = observed(request.authority.clone());
        v.grant = Some(Observed::Absent(REV));
        v.admission = observed(ForkAdmission::new(
            plan,
            request.operation.clone(),
            request.reservation.clone(),
            300,
            300,
            Some(REV),
        ));
        v.quota = observed(ForkQuota::new(
            request.operation.clone(),
            REV,
            300,
            300,
            300,
            1,
            1,
        ));
        v.reservation = if request.reservation.is_some() {
            observed(ForkReservation::Pending {
                operation: request.operation.clone(),
                destination: plan.binding().destination,
                expires_ms: 90,
            })
        } else {
            Some(Observed::Absent(REV))
        };
        v.replay = observed(ForkReplay::InFlight {
            operation: request.operation.clone(),
            fingerprint: request.fingerprint,
        });
        v
    }
}
/// Final whole-source proof at point eleven, after staging and before acceptance.
#[must_use]
pub fn proof(plan: &ForkPlan) -> FinalForkSourceProof {
    let binding = plan.binding();
    FinalForkSourceProof::new(
        REV,
        REV,
        11,
        binding.source,
        binding.branch.clone(),
        Observed::Present {
            value: LifecycleFact::new(binding.source_incarnation, LifecycleState::Active),
            revision: REV,
        },
        Observed::Present {
            value: binding.publication.clone(),
            revision: REV,
        },
        Observed::Present {
            value: binding.source_access.clone(),
            revision: REV,
        },
        true,
        plan.packs()
            .iter()
            .map(|pack| {
                ForkPackProof::new(
                    pack.pack,
                    binding.source_incarnation,
                    binding.publication.generation,
                    REV,
                    pack.descriptor,
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

/// Mutate every destination observation revision, including authoritative absence.
/// Returns false after the finite mutation inventory is exhausted.
pub fn mutate_guard(f: &mut ForkFacts<'_>, index: usize) -> bool {
    fn revision<T>(fact: &mut Option<Observed<T>>) {
        if let Some(Observed::Present { revision, .. } | Observed::Absent(revision)) = fact {
            *revision = Revision([99; 32]);
        }
    }
    match index {
        0 => revision(&mut f.job),
        1 => revision(&mut f.emptiness),
        2 => revision(&mut f.name),
        3 => revision(&mut f.lifecycle),
        4 => revision(&mut f.permission),
        5 => revision(&mut f.authority),
        6 => revision(&mut f.grant),
        7 => revision(&mut f.admission),
        8 => revision(&mut f.quota),
        9 => revision(&mut f.reservation),
        10 => revision(&mut f.replay),
        11 => f.apply_attempt = Revision([99; 32]),
        12 => f.acceptance_point += 1,
        13 => f.repository = RepositoryId([99; 32]),
        _ => return false,
    }
    true
}

/// Exercise hostile plan and decision facts with fixed finite limits.
/// No input can create more than four packs or dependency edges per inventory.
///
/// # Panics
/// Asserts determinism and that accepted decisions contain no denied, held,
/// superseded, or non-live supplier. A panic is a reproducible fuzz finding.
pub fn fuzz_fork_acceptance(data: &[u8]) {
    if data.len() > 65_536 {
        return;
    }
    let mut packs = inventories();
    let mut binding = binding();
    let first = data.first().copied().unwrap_or(0);
    if first & 1 != 0 {
        packs[1].dependencies.push([255; 32]);
    }
    if first & 2 != 0 {
        packs[2].bytes = u64::MAX;
    }
    if first & 4 != 0 {
        packs.swap(0, 1);
    }
    if first & 8 != 0 {
        binding.publication.deletion_boundary = u64::MAX;
    }
    let sealed = ForkPlan::seal(binding, packs, LIMITS);
    if let Ok(plan) = sealed {
        let mut request = attempt(1);
        if data.get(2).is_some_and(|byte| byte & 1 != 0) {
            request.reservation = None;
        }
        let mut facts = facts(&plan, &request);
        if data.get(3).is_some_and(|byte| byte & 1 != 0) {
            if let Some(Observed::Present { value, .. }) = &mut facts.admission {
                value.charge = None;
            }
            facts.quota = Some(Observed::Absent(REV));
        }
        if data.get(4).is_some_and(|byte| byte & 1 != 0) {
            let mut result = plan.result().clone();
            result.branch.0 = "x".repeat(LIMITS.branch_bytes as usize + 1);
            facts.reservation = observed(ForkReservation::Settled(
                mkit_primitives::fork::ForkTerminal::Accepted(Box::new(result)),
            ));
        }
        let mut proof = proof(&plan);
        for (i, byte) in data.iter().take(32).enumerate() {
            let _ = mutate_guard(&mut facts, usize::from(*byte) % 16);
            let p = &mut proof.packs[i % 3];
            p.eligibility.live &= byte & 16 == 0;
            p.denied |= byte & 32 != 0;
            p.eligibility.held |= byte & 64 != 0;
            p.superseded |= byte & 128 != 0;
        }
        let now = u64::from(data.get(1).copied().unwrap_or(1));
        let a = decide_fork_acceptance(&plan, &request, &facts, Some(&proof), now, LIMITS);
        let b = decide_fork_acceptance(&plan, &request, &facts, Some(&proof), now, LIMITS);
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
        if let Ok(guarded) = a
            && matches!(guarded.decision(), ForkDecision::AcceptFork(_))
        {
            assert!(
                proof.packs.iter().all(|p| p.eligibility.live
                    && !p.denied
                    && !p.eligibility.held
                    && !p.superseded)
            );
            assert!(guards_hold(&guarded, &facts.guards(), now));
            assert!(now <= 90);
        }
    }
}
