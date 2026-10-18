//! Bounded fork decision fuzz body and deterministic supplied-fact builders.
use mkit_primitives::{
    decision::{
        AuthorityFact, AuthorityMode, LifecycleFact, LifecycleState, NamespaceId, Observed,
        OperationId, PublicationFact, RefName, ReplayScope, ReservationId,
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
pub const LIMITS: ForkLimits = ForkLimits {
    packs: 3,
    edges: 4,
    branch_bytes: 128,
    index_entries: 30,
    inherited_bytes: 300,
    work: 4096,
};

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
        ForkInventory {
            pack: [1; 32],
            descriptor: [11; 32],
            bytes: 100,
            index_entries: 10,
            dependencies: vec![[2; 32]],
        },
        ForkInventory {
            pack: [2; 32],
            descriptor: [12; 32],
            bytes: 100,
            index_entries: 10,
            dependencies: vec![[3; 32]],
        },
        ForkInventory {
            pack: [3; 32],
            descriptor: [13; 32],
            bytes: 100,
            index_entries: 10,
            dependencies: vec![],
        },
    ]
}
/// Exact deterministic source/destination publication binding.
#[must_use]
pub fn binding() -> ForkBinding {
    ForkBinding {
        source: RepositoryId([1; 32]),
        source_incarnation: REV,
        branch: RefName("refs/heads/main".into()),
        publication: PublicationFact {
            generation: REV,
            sequence: 1,
            published_prefix: 1,
            deletion_boundary: 0,
            head: Some([10; 32]),
            packmap: Some([1; 32]),
        },
        source_access: SourceAccess {
            principal: [21; 32],
            visibility: ForkVisibility::Private,
            visibility_revision: REV,
            authorization_revision: REV,
        },
        destination: RepositoryId([2; 32]),
        destination_generation: Revision([2; 32]),
        destination_visibility: ForkVisibility::Private,
    }
}
/// Fixed request with explicit authority fencing and grant-independent permission.
#[must_use]
pub fn attempt(id: u8) -> ForkAttempt {
    ForkAttempt {
        operation: OperationId([id; 32]),
        reservation: Some(ReservationId([id; 32])),
        replay: ReplayScope([id; 32]),
        fingerprint: [id; 32],
        expires_ms: 100,
        authority: AuthorityFact {
            namespace: NamespaceId([7; 32]),
            mode: AuthorityMode::Authority,
            generation: REV,
            ready: true,
        },
        grant: None,
        authority_fencing: true,
    }
}
/// Fully staged destination with no reader-visible membership or writes.
#[must_use]
pub fn facts<'a>(plan: &'a ForkPlan, request: &'a ForkAttempt) -> ForkFacts<'a> {
    ForkFacts {
        repository: plan.binding().destination,
        request,
        apply_attempt: REV,
        acceptance_point: 12,
        job: observed(ForkJob {
            plan,
            attempt: request.clone(),
            expires_ms: 90,
            state: ForkJobState::Staged {
                packs: 3,
                revision: REV,
                last_effect: 10,
            },
        }),
        emptiness: observed(ForkEmptiness {
            refs: 0,
            visible_members: 0,
            staged_members: 3,
            staged_pack_digest: plan.pack_digest(),
            staged_owner: Some(request.operation.clone()),
            writes_enabled: false,
        }),
        name: observed(ForkName {
            registered_by: None,
            declared_visibility: Some(ForkVisibility::Private),
        }),
        lifecycle: Some(Observed::Absent(REV)),
        permission: observed(ForkPermission {
            operation: request.operation.clone(),
            source_access: plan.binding().source_access.clone(),
            destination_visibility: ForkVisibility::Private,
            create: true,
            write: true,
        }),
        authority: observed(request.authority.clone()),
        grant: Some(Observed::Absent(REV)),
        admission: observed(ForkAdmission {
            plan,
            operation: request.operation.clone(),
            reservation: request.reservation.clone(),
            declared_bytes: 300,
            new_to_repo_bytes: 300,
            charge: Some(REV),
        }),
        quota: observed(ForkQuota {
            operation: request.operation.clone(),
            charge: REV,
            bytes: 300,
            used_bytes: 300,
            byte_limit: 300,
            used_operations: 1,
            operation_limit: 1,
        }),
        reservation: if request.reservation.is_some() {
            observed(ForkReservation::Pending {
                operation: request.operation.clone(),
                destination: plan.binding().destination,
                expires_ms: 90,
            })
        } else {
            Some(Observed::Absent(REV))
        },
        replay: observed(ForkReplay::InFlight {
            operation: request.operation.clone(),
            fingerprint: request.fingerprint,
        }),
    }
}
/// Final whole-source proof at point eleven, after staging and before acceptance.
#[must_use]
pub fn proof(plan: &ForkPlan) -> FinalForkSourceProof {
    let binding = plan.binding();
    FinalForkSourceProof {
        apply_attempt: REV,
        staged_revision: REV,
        proof_point: 11,
        repository: binding.source,
        branch: binding.branch.clone(),
        lifecycle: Observed::Present {
            value: LifecycleFact {
                incarnation: binding.source_incarnation,
                state: LifecycleState::Active,
            },
            revision: REV,
        },
        publication: Observed::Present {
            value: binding.publication.clone(),
            revision: REV,
        },
        access: Observed::Present {
            value: binding.source_access.clone(),
            revision: REV,
        },
        readable: true,
        packs: plan
            .packs()
            .iter()
            .map(|pack| ForkPackProof {
                pack: pack.pack,
                incarnation: binding.source_incarnation,
                generation: binding.publication.generation,
                membership: REV,
                descriptor: pack.descriptor,
                descriptor_revision: REV,
                denial_revision: REV,
                eligibility: ForkPackEligibility {
                    live: true,
                    cleared: true,
                    held: false,
                },
                denied: false,
                superseded: false,
            })
            .collect(),
    }
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
            assert!(guarded.matches(&facts, now));
            assert!(now <= 90);
        }
    }
}
