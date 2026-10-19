use super::*;
use crate::decision::ref_write::decide_ref_write;

fn plain(
    bases: &[AcceptanceBasis],
    packs: &[PackSource],
    snap: &Snapshot,
    limits: RefDecisionLimits,
) -> Result<decision::Guarded<WriteDecision>, crate::error::Failure> {
    let changes = pair();
    let req = write(&changes);
    decide_ref_write(&req, snap, limits)?.with_acceptance_basis(bases, packs, limits)
}

#[test]
fn plain_and_ticketed_paths_seal_identical_basis_guards() {
    let basis = AcceptanceBasis::attested_by_host(attestation());
    let snap = live(&snapshot(&pair(), &[0x42]), &basis);
    let ticketed = decide_with(&basis, &snap).unwrap();
    let plain = plain(std::slice::from_ref(&basis), &[], &snap, limits()).unwrap();
    assert!(matches!(plain.decision(), WriteDecision::Apply(_)));
    let basis_guards = |decision: &decision::Guarded<WriteDecision>| {
        decision
            .required_guards()
            .iter()
            .filter(|guard| basis.guards().contains(guard))
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(basis_guards(&plain), basis.guards());
    assert_eq!(basis_guards(&plain), basis_guards(&ticketed));
    assert!(guards_match(&plain, &snap, NOW));
    assert!(check_guard_completeness(&plain, plain.required_guards()).is_ok());
}

#[test]
fn plain_basis_fact_mutations_fail_the_guard_check() {
    let original = attestation();
    let basis = AcceptanceBasis::attested_by_host(original.clone());
    let snap = live(&snapshot(&pair(), &[]), &basis);
    let guarded = plain(std::slice::from_ref(&basis), &[], &snap, limits()).unwrap();
    for (name, moved) in crate::decision::fact_harness::mutations(&snap) {
        assert!(!guards_match(&guarded, &moved, NOW), "snapshot {name}");
    }
    let variants = basis_mutations(&original);
    assert!(variants.len() >= 20);
    for (name, mutated) in variants {
        let next = AcceptanceBasis::attested_by_host(mutated);
        if name.ends_with("added") {
            continue; // New facts do not invalidate an existing dependency.
        }
        let moved = live(&snapshot(&pair(), &[]), &next);
        assert!(!guards_match(&guarded, &moved, NOW), "{name}");
    }
    for guard in basis.guards() {
        let mut lowered = guarded.required_guards().to_vec();
        lowered.retain(|other| other != guard);
        assert_eq!(
            check_guard_completeness(&guarded, &lowered)
                .unwrap_err()
                .code,
            FailureCode::InvalidResponse,
            "{guard:?}"
        );
    }
    // Altered, wrong-scope and contradictory extra lowered witness guards
    // are handled by the same checker as ticketed decisions.
    for replacement in [
        RequiredGuard::MembershipWitness {
            repository: REPO,
            generation: 99,
            removal_version: 4,
        },
        RequiredGuard::MembershipWitness {
            repository: RepositoryId([9; 32]),
            generation: 3,
            removal_version: 4,
        },
    ] {
        let mut lowered = guarded.required_guards().to_vec();
        lowered.retain(|g| !matches!(g, RequiredGuard::MembershipWitness { .. }));
        lowered.push(replacement);
        assert!(check_guard_completeness(&guarded, &lowered).is_err());
    }
    let mut lowered = guarded.required_guards().to_vec();
    lowered.push(RequiredGuard::DenialVersion { version: 99 });
    assert!(check_guard_completeness(&guarded, &lowered).is_err());
}

#[test]
fn plain_basis_coverage_uses_exact_pack_identity_and_length() {
    let pack = ticket_fact(0x42).pack;
    let basis = AcceptanceBasis::attested_by_host(HostAttestation {
        packs: vec![pack],
        ..attestation()
    });
    let snap = snapshot(&pair(), &[]);
    let covering = std::slice::from_ref(&basis);
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../fixtures/decision/plain-basis.json"
    ))
    .unwrap();
    for row in fixture.as_array().unwrap() {
        let unrestricted = [AcceptanceBasis::attested_by_host(attestation())];
        let (selected, pack) = match row["case"].as_str().unwrap() {
            "covered" => (covering, pack),
            "wrong-id" => (
                covering,
                PackSource {
                    id: [99; 32],
                    ..pack
                },
            ),
            "wrong-length" => (
                covering,
                PackSource {
                    len: pack.len + 1,
                    ..pack
                },
            ),
            "no-basis" => (&[][..], pack),
            "unrestricted" => (&unrestricted[..], pack),
            other => panic!("unknown fixture {other}"),
        };
        let result = plain(selected, &[pack], &snap, limits());
        let actual = match result {
            Ok(guarded) => {
                assert!(matches!(guarded.decision(), WriteDecision::Apply(_)));
                "apply"
            }
            Err(error) => {
                assert_eq!(error.code, FailureCode::InvalidResponse);
                "InvalidResponse"
            }
        };
        assert_eq!(actual, row["expected"].as_str().unwrap(), "{row}");
    }
    let other = ticket_fact(0x43).pack;
    let second = AcceptanceBasis::attested_by_host(HostAttestation {
        packs: vec![other],
        ..attestation()
    });
    assert!(plain(&[basis, second], &[pack, other], &snap, limits()).is_ok());
}

#[test]
fn plain_basis_deduplicates_and_rejects_contradictions() {
    let basis = AcceptanceBasis::attested_by_host(attestation());
    let snap = snapshot(&pair(), &[]);
    let once = plain(std::slice::from_ref(&basis), &[], &snap, limits()).unwrap();
    let twice = plain(&[basis.clone(), basis.clone()], &[], &snap, limits()).unwrap();
    assert_eq!(once.required_guards(), twice.required_guards());
    let mut changed = attestation();
    changed.denial_version = Some(10);
    let contradictory = AcceptanceBasis::attested_by_host(changed);
    assert_eq!(
        plain(&[basis, contradictory], &[], &snap, limits())
            .unwrap_err()
            .code,
        FailureCode::InvalidResponse
    );
    let contradictory = AcceptanceBasis::attested_by_host(HostAttestation {
        dependencies: vec![
            member(),
            MemberFact {
                revision: Revision([99; 32]),
                ..member()
            },
        ],
        ..attestation()
    });
    assert_eq!(
        plain(&[contradictory], &[], &snap, limits())
            .unwrap_err()
            .code,
        FailureCode::InvalidResponse
    );
}

#[test]
fn plain_basis_rejects_repository_mismatch_and_exhausted_limits() {
    let snap = snapshot(&pair(), &[]);
    let wrong = AcceptanceBasis::attested_by_host(HostAttestation {
        repository: RepositoryId([9; 32]),
        ..attestation()
    });
    assert_eq!(
        plain(&[wrong], &[], &snap, limits()).unwrap_err().code,
        FailureCode::InvalidResponse
    );
    let bases = [AcceptanceBasis::attested_by_host(attestation())];
    for bound in [
        RefDecisionLimits {
            facts: 0,
            ..limits()
        },
        RefDecisionLimits {
            guards: 0,
            ..limits()
        },
        RefDecisionLimits {
            bytes: 0,
            ..limits()
        },
        RefDecisionLimits {
            work: 0,
            ..limits()
        },
    ] {
        let changes = pair();
        let decision = decide_ref_write(&write(&changes), &snap, limits()).unwrap();
        assert_eq!(
            decision
                .with_acceptance_basis(&bases, &[], bound)
                .unwrap_err()
                .code,
            FailureCode::ResourceLimit
        );
    }
}

#[test]
fn empty_attachment_preserves_single_pair_and_deletion_decisions() {
    let changes = pair();
    for kind in [
        RefWriteKind::Update,
        RefWriteKind::Advance,
        RefWriteKind::Delete,
        RefWriteKind::DeletePair,
    ] {
        let paired = matches!(kind, RefWriteKind::Advance | RefWriteKind::DeletePair);
        let deleting = matches!(kind, RefWriteKind::Delete | RefWriteKind::DeletePair);
        let mut changes = changes[..if paired { 2 } else { 1 }].to_vec();
        if deleting {
            for change in &mut changes {
                change.target = None;
            }
        }
        let mut request = write(&changes);
        request.kind = kind;
        let snap = snapshot(&pair(), &[]);
        let original = decide_ref_write(&request, &snap, limits()).unwrap();
        let expected = format!("{original:?}");
        let attached = original
            .with_acceptance_basis(&[], &[], RefDecisionLimits::new(0, 0, 0, 0, 0))
            .unwrap();
        assert_eq!(format!("{attached:?}"), expected);
        if !deleting {
            let basis = AcceptanceBasis::attested_by_host(attestation());
            let attached = attached
                .with_acceptance_basis(&[basis], &[], limits())
                .unwrap();
            assert!(matches!(attached.decision(), WriteDecision::Apply(_)));
        }
    }
}
