use super::*;
use crate::decision::*;
use crate::error::FailureCode;
use mkit_core::refs::RefWriteCondition::{Any, Match, Missing};

const REPO: RepositoryId = RepositoryId([1; 32]);
const REV: Revision = Revision([2; 32]);
const OLD: Hash = [3; 32];
const NEW: Hash = [4; 32];
const SIGNER: Hash = [5; 32];

fn name() -> RefName {
    RefName("refs/heads/main".into())
}
fn present<T>(value: T) -> Observed<T> {
    Observed::Present {
        value,
        revision: REV,
    }
}
fn snapshot() -> Snapshot {
    Snapshot {
        repository: REPO,
        refs: vec![(name(), present(OLD))],
        replay: None,
        tickets: vec![],
        reservations: vec![],
        authority: None,
        grant: None,
        lifecycle: None,
        members: vec![],
        denial: None,
        policy: None,
        admission: None,
        accounting: None,
        publication: None,
        storage: None,
    }
}
fn limits() -> RefDecisionLimits {
    RefDecisionLimits {
        facts: 256,
        guards: 64,
        bytes: 65_536,
        work: 100_000,
        public_message_bytes: 512,
    }
}
fn request(changes: &[RefChange]) -> RefWriteRequest<'_> {
    RefWriteRequest {
        repository: REPO,
        operation: Some(OperationId([6; 32])),
        kind: RefWriteKind::Update,
        changes,
        admitted: &[],
        presence: None,
        signer: Some(SIGNER),
        replay: None,
        ancestry: &[],
        now_ms: 100,
        required: RefRequirements {
            authority: None,
            grant: None,
            incarnation: None,
            policy: None,
            admission: None,
            members: &[],
            indexed_head: false,
            membership_window: MembershipWindow::Elapsed,
            denial: false,
            publication: false,
            source: None,
            valid_through_ms: None,
        },
    }
}
fn change(condition: RefWriteCondition) -> RefChange {
    RefChange {
        name: name(),
        condition,
        target: Some(NEW),
    }
}
fn policy(snapshot: &mut Snapshot, fast_forward: bool) {
    snapshot.policy = Some(present(PolicyFact {
        allowed_signers: vec![SIGNER],
        fast_forward,
        revision: REV,
    }));
}
fn is_apply(decision: &Guarded<WriteDecision>) -> bool {
    matches!(decision.decision(), WriteDecision::Apply(_))
}

#[test]
fn cas_matrix_matches_independent_reference_and_keeps_any_unconditional() {
    for condition in [Any, Missing, Match(OLD)] {
        for current in [None, Some(OLD), Some(NEW)] {
            let changes = [change(condition)];
            let req = request(&changes);
            let mut snap = snapshot();
            snap.refs[0].1 = current.map_or(Observed::Absent(REV), present);
            let decision = decide_ref_write(&req, &snap, limits()).unwrap();
            let expected = match condition {
                Any => true,
                Missing => current.is_none(),
                Match(want) => current == Some(want),
            };
            assert_eq!(is_apply(&decision), expected, "{condition:?} {current:?}");
            assert_eq!(decision.required_guards().is_empty(), condition == Any);
            assert!(guards_match(&decision, &snap, 100));
            let mut raced = snap.clone();
            raced.refs[0].1 = present([99; 32]);
            assert_eq!(guards_match(&decision, &raced, 100), condition == Any);
        }
    }
}

#[test]
fn pair_conflict_precedence_and_examined_prefix_are_frozen() {
    for packmap_matches in [false, true] {
        for head_matches in [false, true] {
            let changes = [
                RefChange {
                    name: RefName("refs/mkit/packmap/main".into()),
                    condition: Match(OLD),
                    target: Some(NEW),
                },
                change(Match(OLD)),
            ];
            let mut req = request(&changes);
            req.kind = RefWriteKind::Advance;
            let mut snap = snapshot();
            snap.refs = changes
                .iter()
                .zip([packmap_matches, head_matches])
                .map(|(change, yes)| (change.name.clone(), present(if yes { OLD } else { NEW })))
                .collect();
            let guarded = decide_ref_write(&req, &snap, limits()).unwrap();
            match guarded.decision() {
                WriteDecision::Apply(effects) => {
                    assert!(packmap_matches && head_matches);
                    assert_eq!(effects.refs.len(), 2);
                }
                WriteDecision::Conflict { current, .. } => {
                    assert_eq!(current.len(), 1);
                    assert_eq!(
                        guarded.required_guards().len(),
                        if packmap_matches { 2 } else { 1 }
                    );
                }
                other => panic!("unexpected {other:?}"),
            }
        }
    }
}

#[test]
fn deletion_shape_and_fast_forward_deletion_refusal() {
    for condition in [Any, Missing, Match(OLD)] {
        let changes = [RefChange {
            name: name(),
            condition,
            target: None,
        }];
        let mut req = request(&changes);
        req.kind = RefWriteKind::Delete;
        let snap = snapshot();
        let result = decide_ref_write(&req, &snap, limits());
        if condition != Match(OLD) {
            assert_eq!(result.unwrap_err().code, FailureCode::InvalidRefRequest);
            continue;
        }
        assert!(is_apply(&result.unwrap()));
        req.required.policy = Some(PolicyRequirement {
            signer_restricted: true,
            grant_fast_forward: false,
        });
        let mut snap = snap;
        policy(&mut snap, true);
        let denied = decide_ref_write(&req, &snap, limits()).unwrap();
        assert!(
            matches!(denied.decision(), WriteDecision::Reject { refusal, .. }
            if refusal.public_message == "non-fast-forward update not allowed on this ref")
        );
        assert!(
            denied
                .required_guards()
                .iter()
                .any(|guard| matches!(guard, RequiredGuard::Policy { .. }))
        );
    }
}

#[test]
fn signer_matrix_and_policy_refusal_observation_are_guarded() {
    for signer in [None, Some(SIGNER), Some(OLD)] {
        for signers in [vec![], vec![SIGNER], vec![OLD, SIGNER]] {
            let changes = [change(Any)];
            let mut req = request(&changes);
            req.signer = signer;
            req.required.policy = Some(PolicyRequirement {
                signer_restricted: true,
                grant_fast_forward: false,
            });
            let mut snap = snapshot();
            policy(&mut snap, false);
            if let Some(Observed::Present { value, .. }) = &mut snap.policy {
                value.allowed_signers = signers.clone();
            }
            let decision = decide_ref_write(&req, &snap, limits()).unwrap();
            assert_eq!(
                is_apply(&decision),
                signer.is_some_and(|key| signers.contains(&key))
            );
            let mut raced = snap.clone();
            raced.policy = Some(Observed::Absent(Revision([99; 32])));
            assert!(!guards_match(&decision, &raced, 100));
        }
    }
}

#[test]
fn fast_forward_any_guards_value_while_missing_and_match_use_their_own_basis() {
    for condition in [Any, Missing, Match(OLD)] {
        for result in [
            AncestryResult::Descendant,
            AncestryResult::Denied,
            AncestryResult::MembershipLag,
        ] {
            let changes = [change(condition)];
            let mut req = request(&changes);
            req.required.policy = Some(PolicyRequirement {
                signer_restricted: true,
                grant_fast_forward: false,
            });
            let proof = [AncestryFact {
                repository: REPO,
                name: name(),
                from: OLD,
                to: NEW,
                result,
            }];
            req.ancestry = &proof;
            let mut snap = snapshot();
            policy(&mut snap, true);
            let decision = decide_ref_write(&req, &snap, limits()).unwrap();
            if condition == Missing {
                assert!(matches!(
                    decision.decision(),
                    WriteDecision::Conflict { .. }
                ));
            } else {
                assert_eq!(is_apply(&decision), result == AncestryResult::Descendant);
                if result == AncestryResult::MembershipLag {
                    assert!(matches!(
                        decision.decision(),
                        WriteDecision::Retry(RetryReason::Unavailable)
                    ));
                }
            }
            if condition == Any {
                assert!(
                    decision
                        .required_guards()
                        .iter()
                        .any(|guard| matches!(guard, RequiredGuard::RefValue { .. }))
                );
            }
        }
    }
    // MATCH ancestry is about the immutable expected tip even if CAS will fail.
    let changes = [change(Match(OLD))];
    let mut req = request(&changes);
    req.required.policy = Some(PolicyRequirement {
        signer_restricted: false,
        grant_fast_forward: false,
    });
    let proof = [AncestryFact {
        repository: REPO,
        name: name(),
        from: OLD,
        to: NEW,
        result: AncestryResult::Descendant,
    }];
    req.ancestry = &proof;
    let mut snap = snapshot();
    snap.refs[0].1 = present(NEW);
    policy(&mut snap, true);
    assert!(matches!(
        decide_ref_write(&req, &snap, limits()).unwrap().decision(),
        WriteDecision::Conflict { .. }
    ));
}

#[test]
fn admission_any_fences_presence_without_value_equality() {
    let changes = [change(Any)];
    let admitted = [AdmittedRef {
        name: name(),
        target: Some(NEW),
        prior_present: true,
    }];
    let mut req = request(&changes);
    req.admitted = &admitted;
    req.required.admission = Some(AdmissionBinding { effects: [8; 32] });
    let mut snap = snapshot();
    snap.admission = Some(present(AdmissionFact {
        operation: req.operation.clone().unwrap(),
        effects: [8; 32],
        presence: vec![PresenceDelta {
            name: name(),
            before: true,
            after: true,
        }],
        reservation: None,
    }));
    let guarded = decide_ref_write(&req, &snap, limits()).unwrap();
    assert!(is_apply(&guarded));
    let mut raced = snap.clone();
    raced.refs[0].1 = present(NEW);
    assert!(guards_match(&guarded, &raced, 100));
    raced.refs[0].1 = Observed::Absent(REV);
    assert!(!guards_match(&guarded, &raced, 100));
    assert!(matches!(
        decide_ref_write(&req, &raced, limits()).unwrap().decision(),
        WriteDecision::Retry(RetryReason::ChangedFacts)
    ));
}

#[test]
fn authority_grant_and_lifecycle_matrix_keep_original_binding() {
    let changes = [change(Any)];
    let mut req = request(&changes);
    req.required.authority = Some(AuthorityBinding {
        namespace: NamespaceId([7; 32]),
        mode: AuthorityMode::Authority,
        generation: REV,
    });
    req.presence = Some((name(), true));
    req.required.grant = Some(GrantBinding {
        namespace: NamespaceId([7; 32]),
        grant: [8; 32],
        epoch: REV,
    });
    req.required.incarnation = Some(REV);
    let mut snap = snapshot();
    snap.authority = Some(present(AuthorityFact {
        mode: AuthorityMode::Authority,
        generation: REV,
        ready: true,
    }));
    snap.grant = Some(present(GrantFact {
        grant: [8; 32],
        epoch: REV,
        presence: Some(true),
    }));
    snap.lifecycle = Some(present(LifecycleFact {
        incarnation: REV,
        state: LifecycleState::Active,
    }));
    let guarded = decide_ref_write(&req, &snap, limits()).unwrap();
    assert!(is_apply(&guarded));
    for category in 0..3 {
        let mut raced = snap.clone();
        match category {
            0 => {
                if let Some(Observed::Present { value, .. }) = &mut raced.authority {
                    value.generation = Revision([99; 32]);
                }
            }
            1 => {
                if let Some(Observed::Present { value, .. }) = &mut raced.grant {
                    value.epoch = Revision([99; 32]);
                }
            }
            _ => {
                if let Some(Observed::Present { value, .. }) = &mut raced.lifecycle {
                    value.state = LifecycleState::Deleting;
                }
            }
        }
        assert!(!guards_match(&guarded, &raced, 100));
        let next = decide_ref_write(&req, &raced, limits()).unwrap();
        if category == 2 {
            assert_eq!(
                next.decision(),
                &WriteDecision::Retry(RetryReason::ChangedFacts)
            );
        } else {
            assert!(matches!(next.decision(), WriteDecision::Reject { .. }));
        }
    }
}

#[test]
fn completed_replay_precedes_unacquired_new_authority_and_inflight_never_stores() {
    let changes = [change(Missing)];
    let mut req = request(&changes);
    req.replay = Some(RefReplay {
        scope: ReplayScope([8; 32]),
        fingerprint: [9; 32],
        expires_ms: 20,
    });
    req.required.authority = Some(AuthorityBinding {
        namespace: NamespaceId([7; 32]),
        mode: AuthorityMode::Authority,
        generation: REV,
    });
    let mut snap = snapshot();
    let saved = TerminalResult::Applied(vec![RefValue {
        name: name(),
        value: Some(NEW),
    }]);
    snap.replay = Some(present(ReplayFact {
        fingerprint: [9; 32],
        expires_ms: 20,
        state: ReplayState::Committed(saved.clone()),
    }));
    let guarded = decide_ref_write(&req, &snap, limits()).unwrap();
    assert_eq!(guarded.decision(), &WriteDecision::ReturnRecorded(saved));
    assert_eq!(guarded.required_guards().len(), 1);
    if let Some(Observed::Present { value, .. }) = &mut snap.replay {
        value.state = ReplayState::InFlight { resumable: false };
    }
    assert!(matches!(
        decide_ref_write(&req, &snap, limits()).unwrap().decision(),
        WriteDecision::Retry(RetryReason::InFlight)
    ));
}

#[test]
fn completeness_catches_each_same_kind_key_and_kind_omission() {
    let changes = [
        RefChange {
            name: RefName("refs/mkit/packmap/main".into()),
            condition: Match(OLD),
            target: Some(NEW),
        },
        change(Match(OLD)),
    ];
    let mut req = request(&changes);
    req.kind = RefWriteKind::Advance;
    let mut snap = snapshot();
    snap.refs.insert(0, (changes[0].name.clone(), present(OLD)));
    let guarded = decide_ref_write(&req, &snap, limits()).unwrap();
    assert_eq!(guarded.required_guards().len(), 2);
    for missing in 0..guarded.required_guards().len() {
        let mut incomplete = guarded.required_guards().to_vec();
        incomplete.remove(missing);
        assert_eq!(
            check_guard_completeness(&guarded, &incomplete)
                .unwrap_err()
                .code,
            FailureCode::InvalidResponse
        );
    }
    check_guard_completeness(&guarded, guarded.required_guards()).unwrap();
    assert_eq!(
        required_guard_kinds(&DecisionClass::Apply, &guarded).unwrap(),
        vec![GuardKind::RefValue]
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Each intrinsic kind needs its own effect and assertion.
fn effect_guard_kinds_reports_each_intrinsic_effect_and_its_omission() {
    use crate::decision::ReservationFact;
    use crate::evidence::{PackSource, SourceBinding};
    type Add = fn(&mut AcceptanceEffects);
    let base = AcceptanceEffects {
        refs: vec![RefEffect {
            name: name(),
            target: Some(NEW),
        }],
        membership: vec![],
        tickets: vec![],
        reservations: vec![],
        reservation_transitions: vec![],
        replay: None,
        publication: vec![],
        accounting: vec![],
        storage: vec![],
        outcomes: vec![],
    };
    let mut effects = base.clone();
    // An unguarded unconditional write needs no intrinsic kind; each other
    // effect group contributes exactly its own category.
    assert!(
        effect_guard_kinds(&DecisionClass::Apply, &effects)
            .unwrap()
            .is_empty()
    );
    let additions: [(GuardKind, Add); 6] = [
        (GuardKind::Membership, |effects| {
            effects.membership.push(MembershipEffect {
                repository: REPO,
                pack: PackSource {
                    id: NEW,
                    len: 1,
                    binding: SourceBinding([7; 32]),
                },
            });
        }),
        (GuardKind::Ticket, |effects| {
            effects.tickets.push(TicketTransition {
                id: crate::decision::TicketId([8; 32]),
                next: None,
            });
        }),
        (GuardKind::Reservation, |effects| {
            effects.reservation_transitions.push(ReservationTransition {
                id: crate::decision::ReservationId([9; 32]),
                next: ReservationFact::Pending {
                    repository: REPO,
                    created_ms: 0,
                    reconcile_ms: 1,
                    op: crate::decision::ReservationOp::Write,
                },
            });
        }),
        (GuardKind::Replay, |effects| {
            effects.replay = Some(ReplayTransition {
                scope: crate::decision::ReplayScope(NEW),
                next: ReplayFact {
                    fingerprint: SIGNER,
                    expires_ms: 1,
                    state: ReplayState::InFlight { resumable: false },
                },
            });
        }),
        (GuardKind::Publication, |effects| {
            effects.publication.push(PublicationEffect {
                repository: REPO,
                next: PublicationFact {
                    generation: REV,
                    sequence: 0,
                    published_prefix: 0,
                    deletion_boundary: 0,
                    head: None,
                    packmap: None,
                },
            });
        }),
        (GuardKind::Accounting, |effects| {
            effects.accounting.push(AccountingEffect {
                scope: NEW,
                bytes: 1,
                operations: 1,
            });
        }),
    ];
    for (kind, add) in additions {
        let mut composed = effects.clone();
        add(&mut composed);
        let kinds = effect_guard_kinds(&DecisionClass::Apply, &composed).unwrap();
        assert!(kinds.contains(&kind), "missing intrinsic kind {kind:?}");
        // Omitting the effect must omit its kind: embedders under SPEC-SERVER
        // §10.4 compose only effects, so the rule observes the effect itself.
        assert!(
            !effect_guard_kinds(&DecisionClass::Apply, &base)
                .unwrap()
                .contains(&kind)
        );
        let mut repeated = composed.clone();
        add(&mut repeated);
        assert_eq!(
            effect_guard_kinds(&DecisionClass::Apply, &repeated)
                .unwrap()
                .iter()
                .filter(|k| **k == kind)
                .count(),
            1
        );
        effects = composed;
    }
    // A non-Apply class carrying mutations is an inconsistent composition.
    assert_eq!(
        effect_guard_kinds(&DecisionClass::Conflict, &effects)
            .unwrap_err()
            .code,
        FailureCode::InvalidResponse
    );
}

#[test]
fn unacquired_duplicate_contradictory_and_cap_plus_one_inputs_fail_closed() {
    let changes = [change(Match(OLD))];
    let req = request(&changes);
    let snap = snapshot();
    let mut missing = snap.clone();
    missing.refs.clear();
    assert_eq!(
        decide_ref_write(&req, &missing, limits()).unwrap_err().code,
        FailureCode::UnavailableInput
    );
    let mut duplicate = snap.clone();
    duplicate.refs.push((name(), present(NEW)));
    assert_eq!(
        decide_ref_write(&req, &duplicate, limits())
            .unwrap_err()
            .code,
        FailureCode::InvalidResponse
    );
    for limited in [
        RefDecisionLimits {
            facts: 1,
            ..limits()
        },
        RefDecisionLimits {
            guards: 0,
            ..limits()
        },
        RefDecisionLimits {
            bytes: 1,
            ..limits()
        },
        RefDecisionLimits {
            work: 1,
            ..limits()
        },
    ] {
        assert_eq!(
            decide_ref_write(&req, &snap, limited).unwrap_err().code,
            FailureCode::ResourceLimit
        );
    }
    let mut other = snap;
    other.repository = RepositoryId([99; 32]);
    assert_eq!(
        decide_ref_write(&req, &other, limits()).unwrap_err().code,
        FailureCode::InvalidResponse
    );
}

#[test]
#[allow(clippy::too_many_lines)] // One complete snapshot supports every independent mutation.
fn every_applicable_guard_has_an_exact_mutation_and_omission_case() {
    use crate::evidence::{MemberFact, PackSource, SourceBinding};
    use mkit_core::object::ObjectType;
    let changes = [change(Match(OLD))];
    let admitted = [AdmittedRef {
        name: name(),
        target: Some(NEW),
        prior_present: true,
    }];
    let proof = [AncestryFact {
        repository: REPO,
        name: name(),
        from: OLD,
        to: NEW,
        result: AncestryResult::Descendant,
    }];
    let members = [NEW];
    let mut req = request(&changes);
    req.ancestry = &proof;
    req.replay = Some(RefReplay {
        scope: ReplayScope([8; 32]),
        fingerprint: [9; 32],
        expires_ms: 1_000,
    });
    req.required.authority = Some(AuthorityBinding {
        namespace: NamespaceId([7; 32]),
        mode: AuthorityMode::Authority,
        generation: REV,
    });
    req.presence = Some((name(), true));
    req.required.grant = Some(GrantBinding {
        namespace: NamespaceId([7; 32]),
        grant: [8; 32],
        epoch: REV,
    });
    req.required.incarnation = Some(REV);
    req.required.policy = Some(PolicyRequirement {
        signer_restricted: true,
        grant_fast_forward: false,
    });
    req.admitted = &admitted;
    req.required.admission = Some(AdmissionBinding { effects: [8; 32] });
    req.required.members = &members;
    req.required.indexed_head = true;
    req.required.denial = true;
    req.required.publication = true;
    req.required.valid_through_ms = Some(100);
    let mut snap = snapshot();
    snap.replay = Some(Observed::Absent(REV));
    snap.authority = Some(present(AuthorityFact {
        mode: AuthorityMode::Authority,
        generation: REV,
        ready: true,
    }));
    snap.grant = Some(present(GrantFact {
        grant: [8; 32],
        epoch: REV,
        presence: Some(true),
    }));
    snap.lifecycle = Some(present(LifecycleFact {
        incarnation: REV,
        state: LifecycleState::Active,
    }));
    policy(&mut snap, true);
    snap.admission = Some(present(AdmissionFact {
        operation: req.operation.clone().unwrap(),
        effects: [8; 32],
        presence: vec![PresenceDelta {
            name: name(),
            before: true,
            after: true,
        }],
        reservation: None,
    }));
    snap.members.push(MembershipObservation {
        object: NEW,
        observed: present(MemberFact {
            repository: REPO,
            incarnation: REV,
            object: NEW,
            kind: ObjectType::Commit,
            canonical_len: 32,
            supplier: PackSource {
                id: [10; 32],
                len: 100,
                binding: SourceBinding([11; 32]),
            },
            canonical_binding: SourceBinding([12; 32]),
            revision: REV,
            delta_depth: 0,
            published: true,
            held: false,
        }),
    });
    snap.denial = Some(present(DenialFact {
        objects: vec![],
        packs: vec![],
        held: vec![],
    }));
    snap.publication = Some(present(PublicationFact {
        generation: REV,
        sequence: 4,
        published_prefix: 3,
        deletion_boundary: 0,
        head: Some(OLD),
        packmap: Some([13; 32]),
    }));
    let guarded = decide_ref_write(&req, &snap, limits()).unwrap();
    assert!(is_apply(&guarded));
    assert!(guards_match(&guarded, &snap, 100));
    assert_eq!(guarded.required_guards().len(), 12);
    let kinds = required_guard_kinds(&DecisionClass::Apply, &guarded).unwrap();
    assert_eq!(kinds.len(), 12);
    for (i, guard) in guarded.required_guards().iter().enumerate() {
        let mut raced = snap.clone();
        let mut now = 100;
        match guard {
            RequiredGuard::RefValue { .. } => raced.refs[0].1 = present(NEW),
            RequiredGuard::RefPresence { .. } => raced.refs[0].1 = Observed::Absent(REV),
            RequiredGuard::Replay { .. } => raced.replay = None,
            RequiredGuard::Authority { .. } => raced.authority = None,
            RequiredGuard::Grant { .. } => raced.grant = None,
            RequiredGuard::Repository { .. } => raced.lifecycle = None,
            RequiredGuard::Membership { .. } => raced.members[0].observed = Observed::Absent(REV),
            RequiredGuard::Denial { .. } => raced.denial = None,
            RequiredGuard::Policy { .. } => raced.policy = None,
            RequiredGuard::Admission { .. } => raced.admission = None,
            RequiredGuard::Publication { .. } => raced.publication = None,
            RequiredGuard::ValidThrough { .. } => now = 101,
            other => panic!("unexpected guard {other:?}"),
        }
        assert!(!guards_match(&guarded, &raced, now), "{guard:?}");
        let mut omitted = guarded.required_guards().to_vec();
        omitted.remove(i);
        assert!(
            check_guard_completeness(&guarded, &omitted).is_err(),
            "{guard:?}"
        );
        let kind = guard_kind(guard);
        assert!(kinds.contains(&kind));
        let without_kind: Vec<_> = guarded
            .required_guards()
            .iter()
            .filter(|candidate| guard_kind(candidate) != kind)
            .cloned()
            .collect();
        assert!(
            check_guard_completeness(&guarded, &without_kind).is_err(),
            "{kind:?}"
        );
    }
    let mut wrong_repository = snap;
    wrong_repository.repository = RepositoryId([99; 32]);
    assert!(!guards_match(&guarded, &wrong_repository, 100));
}

#[test]
fn unknown_guard_category_or_requirements_version_is_unsupported() {
    assert_eq!(
        validate_guard_kind(Some(GuardKind::RefValue), GUARD_REQUIREMENTS_VERSION).unwrap(),
        GuardKind::RefValue
    );
    assert_eq!(
        validate_guard_kind(None, GUARD_REQUIREMENTS_VERSION)
            .unwrap_err()
            .code,
        FailureCode::UnsupportedCapability
    );
    for version in [0, GUARD_REQUIREMENTS_VERSION + 1, u32::MAX] {
        assert_eq!(
            validate_guard_kind(Some(GuardKind::RefValue), version)
                .unwrap_err()
                .code,
            FailureCode::UnsupportedCapability
        );
    }
}

#[test]
fn semantic_cas_fixture_is_executable() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("../../../fixtures/decision/cas.json")).unwrap();
    for row in rows.as_array().unwrap() {
        let condition = match row["condition"].as_str().unwrap() {
            "any" => Any,
            "missing" => Missing,
            "match" => Match(OLD),
            other => panic!("unknown fixture condition {other}"),
        };
        let changes = [change(condition)];
        let mut snap = snapshot();
        snap.refs[0].1 = match row["current"].as_str().unwrap() {
            "absent" => Observed::Absent(REV),
            "old" => present(OLD),
            "new" => present(NEW),
            other => panic!("unknown fixture value {other}"),
        };
        let guarded = decide_ref_write(&request(&changes), &snap, limits()).unwrap();
        assert_eq!(is_apply(&guarded), row["decision"] == "apply");
        assert_eq!(
            !guarded.required_guards().is_empty(),
            row["guard"].as_bool().unwrap()
        );
    }
}

#[test]
fn missing_head_uses_original_lag_window_and_reference_code() {
    let changes = [change(Any)];
    let mut req = request(&changes);
    req.required.indexed_head = true;
    req.replay = Some(RefReplay {
        scope: ReplayScope([8; 32]),
        fingerprint: [9; 32],
        expires_ms: 200,
    });
    let mut snap = snapshot();
    snap.replay = Some(Observed::Absent(REV));
    snap.members.push(MembershipObservation {
        object: NEW,
        observed: Observed::Absent(REV),
    });
    req.required.membership_window = MembershipWindow::WithinLag;
    let retry = decide_ref_write(&req, &snap, limits()).unwrap();
    assert_eq!(
        retry.decision(),
        &WriteDecision::Retry(RetryReason::Unavailable)
    );
    req.required.membership_window = MembershipWindow::Elapsed;
    let denied = decide_ref_write(&req, &snap, limits()).unwrap();
    assert!(
        matches!(denied.decision(), WriteDecision::Reject { refusal, terminal: Some(_), .. }
        if refusal.code == PermanentCode::InvalidArgument && refusal.public_message == "open closure")
    );
}

#[test]
fn conflict_after_any_never_records_an_unguarded_prefix_value() {
    let changes = [
        RefChange {
            name: RefName("refs/mkit/packmap/main".into()),
            condition: Any,
            target: Some(NEW),
        },
        change(Match(OLD)),
    ];
    let mut req = request(&changes);
    req.kind = RefWriteKind::Advance;
    req.replay = Some(RefReplay {
        scope: ReplayScope([8; 32]),
        fingerprint: [9; 32],
        expires_ms: 200,
    });
    let mut snap = snapshot();
    snap.replay = Some(Observed::Absent(REV));
    snap.refs = vec![
        (changes[0].name.clone(), present(OLD)),
        (name(), present(NEW)),
    ];
    let result = decide_ref_write(&req, &snap, limits()).unwrap();
    let WriteDecision::Conflict {
        current,
        replay: Some(TerminalResult::Conflict(saved)),
        ..
    } = result.decision()
    else {
        panic!("expected durable conflict")
    };
    assert_eq!(current, saved);
    assert_eq!(
        current,
        &[RefValue {
            name: name(),
            value: Some(NEW)
        }]
    );
    snap.refs[0].1 = present([99; 32]);
    assert!(guards_match(&result, &snap, 100));
}

#[test]
fn source_fence_is_complete_separate_and_not_required_for_saved_replay() {
    let changes = [
        RefChange {
            name: RefName("refs/mkit/packmap/main".into()),
            condition: Missing,
            target: Some(OLD),
        },
        change(Missing),
    ];
    let source = RequiredSourceFence {
        repository: REPO,
        name: RefName("refs/heads/source".into()),
        read_authority: present(AuthorityFact {
            mode: AuthorityMode::Authority,
            generation: REV,
            ready: true,
        }),
        publication: present(PublicationFact {
            generation: REV,
            sequence: 2,
            published_prefix: 2,
            deletion_boundary: 0,
            head: Some(NEW),
            packmap: Some(OLD),
        }),
    };
    let mut req = request(&changes);
    req.kind = RefWriteKind::Advance;
    req.required.source = Some(&source);
    let mut snap = snapshot();
    snap.refs = changes
        .iter()
        .map(|change| (change.name.clone(), Observed::Absent(REV)))
        .collect();
    let guarded = decide_ref_write(&req, &snap, limits()).unwrap();
    assert_eq!(guarded.source_fences(), std::slice::from_ref(&source));
    assert_eq!(guarded.required_guards().len(), 2);
    for field in 0..6 {
        let mut raced = source.clone();
        match field {
            0 => raced.repository = RepositoryId([99; 32]),
            1 => raced.name = name(),
            2 => raced.read_authority = Observed::Absent(REV),
            _ => {
                if let Observed::Present { value, .. } = &mut raced.publication {
                    match field {
                        3 => value.generation = Revision([99; 32]),
                        4 => value.sequence += 1,
                        _ => value.deletion_boundary += 1,
                    }
                }
            }
        }
        assert_ne!(guarded.source_fences(), &[raced]);
    }
    let mut impossible = source.clone();
    if let Observed::Present { value, .. } = &mut impossible.publication {
        value.published_prefix = 3;
    }
    req.required.source = Some(&impossible);
    assert_eq!(
        decide_ref_write(&req, &snap, limits()).unwrap_err().code,
        FailureCode::InvalidResponse
    );
    req.replay = Some(RefReplay {
        scope: ReplayScope([8; 32]),
        fingerprint: [9; 32],
        expires_ms: 200,
    });
    snap.replay = Some(present(ReplayFact {
        fingerprint: [9; 32],
        expires_ms: 200,
        state: ReplayState::Committed(TerminalResult::Applied(vec![])),
    }));
    let saved = decide_ref_write(&req, &snap, limits()).unwrap();
    assert!(matches!(saved.decision(), WriteDecision::ReturnRecorded(_)));
    assert!(saved.source_fences().is_empty());
}

#[test]
fn variable_length_fact_comparisons_are_in_the_work_budget() {
    let changes = [change(Any)];
    let mut snap = snapshot();
    for byte in [b'a', b'b', b'c', b'd'] {
        let mut text = "refs/heads/".to_owned();
        text.push_str(&"z".repeat(1000));
        text.push(char::from(byte));
        snap.refs.push((RefName(text), Observed::Absent(REV)));
    }
    let mut cap = limits();
    cap.work = 10_000;
    assert_eq!(
        decide_ref_write(&request(&changes), &snap, cap)
            .unwrap_err()
            .code,
        FailureCode::ResourceLimit
    );
}

#[test]
fn semantic_failure_codes_are_fixture_backed() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("../../../fixtures/decision/failures.json")).unwrap();
    for row in rows.as_array().unwrap() {
        let mut changes = [change(Any)];
        let mut snap = snapshot();
        let mut cap = limits();
        let case = row["case"].as_str().unwrap();
        if case == "unknown-guard-version" {
            let failure =
                validate_guard_kind(Some(GuardKind::RefValue), GUARD_REQUIREMENTS_VERSION + 1)
                    .unwrap_err();
            assert_eq!(failure.code.as_str(), row["code"].as_str().unwrap());
            continue;
        }
        match case {
            "invalid-name" => changes[0].name = RefName("invalid".into()),
            "delete-any" => changes[0].target = None,
            "missing-observation" => snap.refs.clear(),
            "duplicate-observation" => snap.refs.push(snap.refs[0].clone()),
            "zero-facts" => cap.facts = 0,
            other => panic!("unknown semantic fixture {other}"),
        }
        let mut req = request(&changes);
        if case == "delete-any" {
            req.kind = RefWriteKind::Delete;
        }
        let failure = decide_ref_write(&req, &snap, cap).unwrap_err();
        assert_eq!(failure.code.as_str(), row["code"].as_str().unwrap());
    }
}

#[test]
fn authority_mode_readiness_and_grant_epoch_have_stable_precedence() {
    for original in [AuthorityMode::SelfCertifying, AuthorityMode::Authority] {
        for current in [AuthorityMode::SelfCertifying, AuthorityMode::Authority] {
            for ready in [false, true] {
                for generation_matches in [false, true] {
                    for epoch_matches in [false, true] {
                        let changes = [change(Any)];
                        let mut req = request(&changes);
                        req.required.authority = Some(AuthorityBinding {
                            namespace: NamespaceId([7; 32]),
                            mode: original.clone(),
                            generation: REV,
                        });
                        req.required.grant = Some(GrantBinding {
                            namespace: NamespaceId([7; 32]),
                            grant: [8; 32],
                            epoch: REV,
                        });
                        let mut snap = snapshot();
                        snap.grant = Some(present(GrantFact {
                            grant: [8; 32],
                            epoch: if epoch_matches {
                                REV
                            } else {
                                Revision([99; 32])
                            },
                            presence: None,
                        }));
                        snap.authority = Some(present(AuthorityFact {
                            mode: current.clone(),
                            generation: if generation_matches {
                                REV
                            } else {
                                Revision([99; 32])
                            },
                            ready,
                        }));
                        let result = decide_ref_write(&req, &snap, limits()).unwrap();
                        if !epoch_matches {
                            assert!(
                                matches!(result.decision(), WriteDecision::Reject { refusal, terminal: None, .. } if refusal.public_message == "write grant epoch changed; re-authorize")
                            );
                            assert!(
                                !result
                                    .required_guards()
                                    .iter()
                                    .any(|guard| matches!(guard, RequiredGuard::Authority { .. }))
                            );
                        } else if !ready {
                            assert_eq!(
                                result.decision(),
                                &WriteDecision::Retry(RetryReason::Unavailable)
                            );
                        } else if generation_matches && original == current {
                            assert!(is_apply(&result));
                        } else {
                            assert!(
                                matches!(result.decision(), WriteDecision::Reject { refusal, terminal: None, .. } if refusal.public_message == "namespace authority generation changed")
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn contradictory_member_views_fail_the_mutation_comparator() {
    let changes = [change(Any)];
    let mut req = request(&changes);
    req.required.indexed_head = true;
    req.required.membership_window = MembershipWindow::WithinLag;
    let mut snap = snapshot();
    snap.members.push(MembershipObservation {
        object: NEW,
        observed: Observed::Absent(REV),
    });
    let guarded = decide_ref_write(&req, &snap, limits()).unwrap();
    assert!(guards_match(&guarded, &snap, 100));
    snap.members.push(snap.members[0].clone());
    assert!(!guards_match(&guarded, &snap, 100));
    assert_eq!(
        decide_ref_write(&req, &snap, limits()).unwrap_err().code,
        FailureCode::InvalidResponse
    );
}
