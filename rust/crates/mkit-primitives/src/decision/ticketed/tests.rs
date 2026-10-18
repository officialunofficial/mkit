use super::*;
use crate::decision::ref_write::{
    AuthorityBinding, MembershipWindow, RefChange, RefDecisionLimits, RefRequirements,
    RefWriteKind, RefWriteRequest, check_guard_completeness, effect_guard_kinds, guard_kind,
    guards_match,
};
use crate::decision::{
    self, AuthorityFact, AuthorityMode, DecisionClass, GuardKind, NamespaceId, Observed,
    OperationId, PermanentCode, RefName, RefValue, ReplayFact, ReplayScope, ReplayState,
    RequiredGuard, ReservationAbortReason, ReservationFact, ReservationId, ReservationOp,
    ReservationTerminal, ReservationTerminalKind, RetryReason, Snapshot, StorageEffect,
    StorageFact, TerminalResult, TicketFact, TicketId, TicketTransition, WriteDecision,
};
use crate::error::FailureCode;
use crate::evidence::{PackSource, RepositoryId, Revision, SourceBinding};
use mkit_core::hash::Hash;
use mkit_core::refs::RefWriteCondition::Match;

const REPO: RepositoryId = RepositoryId([1; 32]);
const REV: Revision = Revision([2; 32]);
const OLD: Hash = [3; 32];
const NEW: Hash = [4; 32];
const SIGNER: Hash = [5; 32];
const NOW: u64 = 500;

fn head() -> RefName {
    RefName("refs/heads/main".into())
}
fn packmap() -> RefName {
    RefName("refs/mkit/packmap/main".into())
}
fn present<T>(value: T) -> Observed<T> {
    Observed::Present {
        value,
        revision: REV,
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
fn pair() -> [RefChange; 2] {
    [
        RefChange {
            name: packmap(),
            condition: Match(OLD),
            target: Some(NEW),
        },
        RefChange {
            name: head(),
            condition: Match(OLD),
            target: Some(NEW),
        },
    ]
}
fn ticket_fact(byte: u8) -> TicketFact {
    TicketFact {
        ticket: TicketId([byte; 32]),
        repository: REPO,
        name: head(),
        signer: SIGNER,
        pack: PackSource {
            id: [0x50 + byte; 32],
            len: 1000 + u64::from(byte),
            binding: SourceBinding([0; 32]),
        },
        part_bytes: 1024,
        created_ms: 10,
        expires_ms: 1_000,
        reservation: ReservationId([byte | 0x80; 32]),
        authority_generation: None,
        upload_session: None,
    }
}
fn claim(byte: u8, proof: UploadProof) -> TicketClaim {
    TicketClaim {
        ticket: TicketId([byte; 32]),
        proof,
        counted: false,
    }
}
fn reservation(byte: u8) -> (ReservationId, Observed<ReservationFact>) {
    (
        ReservationId([byte | 0x80; 32]),
        present(ReservationFact::Ticketed(TicketId([byte; 32]))),
    )
}
fn write(changes: &[RefChange]) -> RefWriteRequest<'_> {
    RefWriteRequest {
        repository: REPO,
        operation: Some(OperationId([6; 32])),
        kind: RefWriteKind::Advance,
        changes,
        admitted: &[],
        presence: None,
        signer: Some(SIGNER),
        replay: None,
        ancestry: &[],
        now_ms: NOW,
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
fn snapshot(changes: &[RefChange], ticket_bytes: &[u8]) -> Snapshot {
    Snapshot {
        repository: REPO,
        refs: changes
            .iter()
            .map(|change| (change.name.clone(), present(OLD)))
            .collect(),
        replay: None,
        tickets: ticket_bytes
            .iter()
            .map(|&byte| (TicketId([byte; 32]), present(ticket_fact(byte))))
            .collect(),
        reservations: ticket_bytes.iter().map(|&byte| reservation(byte)).collect(),
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
fn request<'a>(changes: &'a [RefChange], claims: &'a [TicketClaim]) -> TicketedAdvanceRequest<'a> {
    TicketedAdvanceRequest {
        write: write(changes),
        tickets: claims,
        verification: VerificationVerdict::Satisfied,
        storage: StorageAccounting::Disabled,
        pending: None,
    }
}
fn pending_binding(byte: u8) -> PendingBinding {
    PendingBinding {
        reservation: ReservationId([byte; 32]),
        expected: present(ReservationFact::Pending {
            repository: REPO,
            created_ms: 5,
            reconcile_ms: 9_000,
            op: ReservationOp::Write,
        }),
        occurred_ms: NOW,
    }
}

#[test]
fn applies_with_consumption_outcomes_storage_and_pending() {
    let changes = pair();
    let claims = [
        claim(0x10, UploadProof::Ready),
        claim(0x11, UploadProof::Ready),
    ];
    let mut req = request(&changes, &claims);
    req.pending = Some(pending_binding(0x70));
    req.storage = StorageAccounting::Inline {
        observed: present(StorageFact {
            stored_bytes: 400,
            version: 7,
        }),
        outcome: ReservationId([0x71; 32]),
        occurred_ms: NOW,
    };
    let mut snap = snapshot(&changes, &[0x10, 0x11]);
    snap.storage = req.storage.clone().into_observed();
    snap.reservations.push((
        ReservationId([0x70; 32]),
        pending_binding(0x70).expected.clone(),
    ));
    snap.reservations
        .push((ReservationId([0x71; 32]), Observed::Absent(REV)));
    let guarded = decide_ticketed_advance(&req, &snap, limits()).unwrap();
    let WriteDecision::Apply(effects) = guarded.decision() else {
        panic!("expected apply: {:?}", guarded.decision());
    };
    assert_eq!(effects.refs.len(), 2);
    assert_eq!(
        effects.tickets,
        vec![
            TicketTransition {
                id: TicketId([0x10; 32]),
                next: None
            },
            TicketTransition {
                id: TicketId([0x11; 32]),
                next: None
            },
        ]
    );
    // Two ticket settlements, the storage counter's terminal row, then the
    // pending one — the storage change is settled at its `rs` outcome id too.
    assert_eq!(effects.reservations.len(), 4);
    for outcome in &effects.reservations[..2] {
        match &outcome.terminal.kind {
            ReservationTerminalKind::Committed { refs, accounting } => {
                assert_eq!(refs.len(), 2);
                assert!(accounting.new_to_repository > 0);
            }
            other => panic!("expected committed ticket outcome: {other:?}"),
        }
    }
    assert!(matches!(
        effects.reservations[2].terminal.kind,
        ReservationTerminalKind::StorageChanged { .. }
    ));
    assert_eq!(effects.reservations[2].id, ReservationId([0x71; 32]));
    assert_eq!(effects.outcomes.len(), 4);
    let storage = effects
        .outcomes
        .iter()
        .find(|o| {
            matches!(
                o.terminal.kind,
                ReservationTerminalKind::StorageChanged { .. }
            )
        })
        .expect("storage outcome");
    assert_eq!(
        storage.reservation,
        ReservationId([0x71; 32]),
        "storage outcome id"
    );
    assert_eq!(
        effects.storage,
        vec![StorageEffect {
            repository: REPO,
            next: StorageFact {
                stored_bytes: 400 + ticket_fact(0x10).pack.len + ticket_fact(0x11).pack.len,
                version: 8,
            },
        }]
    );
    let pending = effects.reservations.last().unwrap();
    assert_eq!(pending.id, ReservationId([0x70; 32]));
    assert!(matches!(
        pending.terminal.kind,
        ReservationTerminalKind::Committed { .. }
    ));
    let kinds: Vec<_> = guarded.required_guards().iter().map(guard_kind).collect();
    for kind in [
        GuardKind::RefValue,
        GuardKind::Ticket,
        GuardKind::Reservation,
        GuardKind::Storage,
    ] {
        assert!(kinds.contains(&kind), "missing {kind:?}");
    }
    assert!(guards_match(&guarded, &snap, NOW));
}

#[test]
fn ticket_failures_refuse_in_request_order() {
    let changes = pair();
    // A row-invalid ticket at index 0 refuses before a missing pack at 1.
    let claims = [
        claim(0x20, UploadProof::Ready),
        claim(0x21, UploadProof::PackMissing),
    ];
    let req = request(&changes, &claims);
    let mut snap = snapshot(&changes, &[0x20, 0x21]);
    snap.tickets[0].1 = Observed::Absent(REV);
    let guarded = decide_ticketed_advance(&req, &snap, limits()).unwrap();
    match guarded.decision() {
        WriteDecision::Reject { refusal, .. } => {
            assert_eq!(refusal.code, PermanentCode::FailedPrecondition);
            assert_eq!(refusal.public_message, "invalid or expired upload ticket");
        }
        other => panic!("expected reject: {other:?}"),
    }
    // A missing pack at index 0 refuses "upload not complete" even though a
    // later row is invalid.
    let claims = [
        claim(0x20, UploadProof::PackMissing),
        claim(0x21, UploadProof::Ready),
    ];
    let req = request(&changes, &claims);
    let mut snap = snapshot(&changes, &[0x20, 0x21]);
    snap.tickets[1].1 = Observed::Absent(REV);
    let guarded = decide_ticketed_advance(&req, &snap, limits()).unwrap();
    match guarded.decision() {
        WriteDecision::Reject { refusal, .. } => {
            assert_eq!(refusal.public_message, "upload not complete for ticket");
        }
        other => panic!("expected reject: {other:?}"),
    }
}

#[test]
fn ticket_binding_expiry_and_signer_are_checked() {
    let changes = pair();
    let claims = [claim(0x30, UploadProof::Ready)];
    let req = request(&changes, &claims);
    let invalid = || {
        (
            PermanentCode::FailedPrecondition,
            "invalid or expired upload ticket",
        )
    };
    for (mutate, expected) in [
        (
            (|fact: &mut TicketFact| fact.repository = RepositoryId([9; 32]))
                as fn(&mut TicketFact),
            invalid(),
        ),
        (
            |fact| fact.name = RefName("refs/heads/other".into()),
            invalid(),
        ),
        (|fact| fact.expires_ms = NOW, invalid()),
        (
            |fact| fact.signer = [9; 32],
            (
                PermanentCode::PermissionDenied,
                "upload ticket binding mismatch",
            ),
        ),
    ] {
        let mut snap = snapshot(&changes, &[0x30]);
        let Observed::Present { value: fact, .. } = &mut snap.tickets[0].1 else {
            unreachable!()
        };
        mutate(fact);
        let guarded = decide_ticketed_advance(&req, &snap, limits()).unwrap();
        let WriteDecision::Reject { refusal, .. } = guarded.decision() else {
            panic!("expected reject: {:?}", guarded.decision());
        };
        assert_eq!(refusal.code, expected.0);
        assert_eq!(refusal.public_message, expected.1);
    }
}

#[test]
fn replay_and_pending_gate_the_decision() {
    let changes = pair();
    let claims = [claim(0x40, UploadProof::Ready)];
    let scope = ReplayScope([7; 32]);
    for pending in [false, true] {
        let mut req = request(&changes, &claims);
        req.write.replay = Some(crate::decision::ref_write::RefReplay {
            scope: scope.clone(),
            fingerprint: [8; 32],
            expires_ms: 9_000,
        });
        if pending {
            req.pending = Some(pending_binding(0x72));
        }
        let mut snap = snapshot(&changes, &[0x40]);
        snap.replay = Some(present(ReplayFact {
            scope: scope.clone(),
            fingerprint: [8; 32],
            expires_ms: 9_000,
            state: ReplayState::Committed(TerminalResult::Applied(vec![])),
        }));
        if pending {
            snap.reservations
                .push((ReservationId([0x72; 32]), pending_binding(0x72).expected));
        }
        let guarded = decide_ticketed_advance(&req, &snap, limits()).unwrap();
        if pending {
            assert!(matches!(
                guarded.decision(),
                WriteDecision::Retry(RetryReason::InFlight)
            ));
        } else {
            assert!(matches!(
                guarded.decision(),
                WriteDecision::ReturnRecorded(TerminalResult::Applied(_))
            ));
        }
    }
    // A pending reservation observed in a different state retries.
    let mut req = request(&changes, &claims);
    req.pending = Some(pending_binding(0x72));
    let mut snap = snapshot(&changes, &[0x40]);
    snap.reservations.push((
        ReservationId([0x72; 32]),
        present(ReservationFact::Ticketed(TicketId([0x40; 32]))),
    ));
    let guarded = decide_ticketed_advance(&req, &snap, limits()).unwrap();
    assert!(matches!(
        guarded.decision(),
        WriteDecision::Retry(RetryReason::Unavailable)
    ));
}

#[test]
fn conflict_aborts_the_pending_reservation() {
    let changes = pair();
    let claims = [claim(0x41, UploadProof::Ready)];
    let mut req = request(&changes, &claims);
    req.pending = Some(pending_binding(0x73));
    let mut snap = snapshot(&changes, &[0x41]);
    snap.refs[1].1 = present([99; 32]);
    snap.reservations
        .push((ReservationId([0x73; 32]), pending_binding(0x73).expected));
    let guarded = decide_ticketed_advance(&req, &snap, limits()).unwrap();
    match guarded.decision() {
        WriteDecision::Conflict {
            reservation: Some(outcome),
            ..
        } => {
            assert_eq!(outcome.id, ReservationId([0x73; 32]));
            assert!(matches!(
                outcome.terminal.kind,
                ReservationTerminalKind::Aborted {
                    reason: ReservationAbortReason::RefConflict,
                    ..
                }
            ));
        }
        other => panic!("expected conflict: {other:?}"),
    }
    // The conflict commits a recorded answer on the ticket rows it examined, so
    // those rows are guarded, but consumption never reaches the conflict path.
    assert!(
        guarded
            .required_guards()
            .iter()
            .any(|g| matches!(g, RequiredGuard::Ticket { .. }))
    );
    assert!(matches!(guarded.decision(), WriteDecision::Conflict { .. }));
}

#[test]
fn verification_verdicts_gate_and_fences_refuse() {
    let changes = pair();
    let claims = [claim(0x42, UploadProof::Ready)];
    let mut req = request(&changes, &claims);
    req.verification = VerificationVerdict::Pending;
    let snap = snapshot(&changes, &[0x42]);
    assert!(matches!(
        decide_ticketed_advance(&req, &snap, limits())
            .unwrap()
            .decision(),
        WriteDecision::Retry(RetryReason::Unavailable)
    ));
    req.verification = VerificationVerdict::Refused(decision::PermanentRefusal {
        code: PermanentCode::InvalidArgument,
        public_message: "refused".into(),
    });
    assert!(matches!(
        decide_ticketed_advance(&req, &snap, limits())
            .unwrap()
            .decision(),
        WriteDecision::Reject { refusal, .. } if refusal.code == PermanentCode::InvalidArgument
    ));
    // A ticket issued under a superseded authority generation refuses, and the
    // guarded authority observation is what the generation is compared with.
    req.verification = VerificationVerdict::Satisfied;
    let generation = Revision([7; 32]);
    req.write.required.authority = Some(AuthorityBinding {
        namespace: NamespaceId([7; 32]),
        mode: AuthorityMode::Authority,
        generation,
    });
    let mut snap = snapshot(&changes, &[0x42]);
    snap.authority = Some(present(AuthorityFact {
        namespace: NamespaceId([7; 32]),
        mode: AuthorityMode::Authority,
        generation,
        ready: true,
    }));
    let stale = decide_ticketed_advance(&req, &snap, limits()).unwrap();
    assert!(matches!(
        stale.decision(),
        WriteDecision::Reject { refusal, .. } if refusal.code == PermanentCode::PermissionDenied
    ));
    assert!(
        stale
            .required_guards()
            .iter()
            .any(|guard| matches!(guard, RequiredGuard::Authority { .. }))
    );
    // A matching generation applies.
    let Observed::Present { value: fact, .. } = &mut snap.tickets[0].1 else {
        unreachable!()
    };
    fact.authority_generation = Some(generation);
    let applied = decide_ticketed_advance(&req, &snap, limits()).unwrap();
    assert!(matches!(applied.decision(), WriteDecision::Apply(_)));
    // A moved authority observation refuses before any ticket is consumed.
    let Some(Observed::Present { value, .. }) = &mut snap.authority else {
        unreachable!()
    };
    value.generation = Revision([8; 32]);
    assert!(matches!(
        decide_ticketed_advance(&req, &snap, limits())
            .unwrap()
            .decision(),
        WriteDecision::Reject { refusal, .. } if refusal.code == PermanentCode::PermissionDenied
    ));
}

#[test]
fn wire_rejected_shapes_are_typed_refusals() {
    let changes = pair();
    // More than seven tickets.
    let claims: Vec<_> = (0..8).map(|i| claim(i, UploadProof::Ready)).collect();
    let req = request(&changes, &claims);
    let snap = snapshot(&changes, &(0..8).collect::<Vec<_>>());
    assert_eq!(
        decide_ticketed_advance(&req, &snap, limits())
            .unwrap_err()
            .code,
        FailureCode::InvalidRefRequest
    );
    // A repeated ticket id.
    let claims = [
        claim(0x50, UploadProof::Ready),
        claim(0x50, UploadProof::Ready),
    ];
    let req = request(&changes, &claims);
    let snap = snapshot(&changes, &[0x50]);
    assert_eq!(
        decide_ticketed_advance(&req, &snap, limits())
            .unwrap_err()
            .code,
        FailureCode::InvalidRefRequest
    );
    // A noncanonical pair with tickets.
    let mut other = pair();
    other[0].name = RefName("refs/heads/left".into());
    let claims = [claim(0x51, UploadProof::Ready)];
    let req = request(&other, &claims);
    let snap = snapshot(&other, &[0x51]);
    assert_eq!(
        decide_ticketed_advance(&req, &snap, limits())
            .unwrap_err()
            .code,
        FailureCode::InvalidRefRequest
    );
}

#[test]
fn cleanup_aborts_only_lost_tickets_before_the_first_failure() {
    let changes = pair();
    // t0: valid row, pack missing → lost. t1: invalid row (boundary).
    // t2: valid row, pack missing but past the boundary → retained.
    let claims = [
        claim(0x60, UploadProof::PackMissing),
        claim(0x61, UploadProof::Ready),
        claim(0x62, UploadProof::PackMissing),
    ];
    let req = request(&changes, &claims);
    let mut snap = snapshot(&changes, &[0x60, 0x61, 0x62]);
    snap.tickets[1].1 = Observed::Absent(REV);
    let guarded = decide_ticket_cleanup(
        &req,
        "ticket pack missing after upload",
        NOW,
        &snap,
        limits(),
    )
    .unwrap();
    let WriteDecision::Apply(effects) = guarded.decision() else {
        panic!("expected apply: {:?}", guarded.decision());
    };
    assert_eq!(
        effects.tickets,
        vec![TicketTransition {
            id: TicketId([0x60; 32]),
            next: None
        }]
    );
    assert_eq!(effects.reservations.len(), 1);
    assert!(matches!(
        effects.reservations[0].terminal.kind,
        ReservationTerminalKind::Aborted {
            reason: ReservationAbortReason::PackMissing,
            ..
        }
    ));
    assert_eq!(effects.outcomes.len(), 1);
    assert!(guards_match(&guarded, &snap, NOW));
    // No failure anywhere: the host never decides cleanup.
    let claims = [claim(0x60, UploadProof::Ready)];
    let req = request(&changes, &claims);
    let snap = snapshot(&changes, &[0x60]);
    assert_eq!(
        decide_ticket_cleanup(&req, "x", NOW, &snap, limits())
            .unwrap_err()
            .code,
        FailureCode::InvalidResponse
    );
}

#[test]
fn reservation_settlement_is_guarded_and_idempotent() {
    let operation = OperationId([6; 32]);
    let id = ReservationId([0x80; 32]);
    let expected = pending_binding(0x80).expected;
    let terminal = ReservationTerminal {
        repository: REPO,
        occurred_ms: NOW,
        kind: ReservationTerminalKind::Committed {
            refs: vec![RefValue {
                name: head(),
                value: Some(NEW),
            }],
            accounting: decision::ReservationAccounting {
                bytes_stored: 0,
                new_to_repository: 0,
                new_to_store: 0,
            },
        },
    };
    let mut snap = snapshot(&[], &[]);
    snap.reservations.push((id.clone(), expected.clone()));
    let guarded =
        decide_reservation_settlement(REPO, &operation, &id, &expected, &terminal, &snap, limits())
            .unwrap();
    let WriteDecision::Apply(effects) = guarded.decision() else {
        panic!("expected apply");
    };
    assert_eq!(effects.reservations.len(), 1);
    assert_eq!(effects.outcomes.len(), 1);
    // A raced settlement leaves the observed terminal and applies nothing.
    snap.reservations[0].1 = present(ReservationFact::Terminal(terminal.clone()));
    let guarded =
        decide_reservation_settlement(REPO, &operation, &id, &expected, &terminal, &snap, limits())
            .unwrap();
    let WriteDecision::Apply(effects) = guarded.decision() else {
        panic!("expected apply");
    };
    assert!(effects.reservations.is_empty() && effects.outcomes.is_empty());
    // Illegal transitions refuse.
    let expired = ReservationTerminal {
        repository: REPO,
        occurred_ms: NOW,
        kind: ReservationTerminalKind::Expired,
    };
    assert_eq!(
        decide_reservation_settlement(REPO, &operation, &id, &expected, &expired, &snap, limits())
            .unwrap_err()
            .code,
        FailureCode::InvalidResponse
    );
    // A direct abort may create a terminal without a prior row; the host
    // still acquires the (absent) observation first.
    let other = ReservationId([0x81; 32]);
    snap.reservations
        .push((other.clone(), Observed::Absent(REV)));
    let aborted = ReservationTerminal {
        repository: REPO,
        occurred_ms: NOW,
        kind: ReservationTerminalKind::Aborted {
            reason: ReservationAbortReason::Abandoned,
            detail: "abandoned".into(),
        },
    };
    let guarded = decide_reservation_settlement(
        REPO,
        &operation,
        &other,
        &Observed::Absent(REV),
        &aborted,
        &snap,
        limits(),
    )
    .unwrap();
    assert!(matches!(
        guarded.decision(),
        WriteDecision::Apply(effects) if effects.reservations.len() == 1
    ));
}

#[test]
fn effect_guard_kinds_cover_storage() {
    let mut effects = decision::AcceptanceEffects {
        refs: vec![],
        membership: vec![],
        tickets: vec![],
        reservations: vec![],
        reservation_transitions: vec![],
        replay: None,
        publication: vec![],
        accounting: vec![],
        storage: vec![StorageEffect {
            repository: REPO,
            next: StorageFact {
                stored_bytes: 1,
                version: 1,
            },
        }],
        outcomes: vec![],
    };
    assert_eq!(
        effect_guard_kinds(&DecisionClass::Apply, &effects).unwrap(),
        vec![GuardKind::Storage]
    );
    effects.storage.clear();
    assert!(
        effect_guard_kinds(&DecisionClass::Apply, &effects)
            .unwrap()
            .is_empty()
    );
}

trait IntoObserved {
    fn into_observed(self) -> Option<Observed<StorageFact>>;
}
impl IntoObserved for StorageAccounting {
    fn into_observed(self) -> Option<Observed<StorageFact>> {
        match self {
            StorageAccounting::Inline { observed, .. } => Some(observed),
            _ => None,
        }
    }
}

#[test]
fn failed_inline_proof_aborts_only_the_exact_pending_reservation() {
    let changes = pair();
    let claims = [claim(0x42, UploadProof::Ready)];
    let mut req = request(&changes, &claims);
    let pending = pending_binding(9);
    req.pending = Some(pending.clone());
    req.verification = VerificationVerdict::Refused(decision::PermanentRefusal {
        code: PermanentCode::InvalidArgument,
        public_message: "invalid pack".into(),
    });
    let mut snap = snapshot(&changes, &[0x42]);
    snap.reservations
        .push((pending.reservation.clone(), pending.expected.clone()));
    let decided = decide_ticketed_advance(&req, &snap, limits()).unwrap();
    let WriteDecision::Reject {
        terminal,
        reservation: Some(abort),
        ..
    } = decided.decision()
    else {
        panic!("missing inline abort: {:?}", decided.decision());
    };
    assert!(terminal.is_none());
    assert_eq!(abort.id, pending.reservation);
    assert!(
        matches!(&abort.terminal.kind, ReservationTerminalKind::Aborted {
        reason: ReservationAbortReason::Internal, detail
    } if detail.is_empty())
    );
    assert!(guards_match(&decided, &snap, NOW));
    snap.reservations.last_mut().unwrap().1 = Observed::Absent(REV);
    assert!(!guards_match(&decided, &snap, NOW));
    assert!(matches!(
        decide_ticketed_advance(&req, &snap, limits())
            .unwrap()
            .decision(),
        WriteDecision::Retry(_)
    ));
}

#[test]
fn cleanup_claims_and_settlement_outputs_obey_limits() {
    let changes = pair();
    let claims = vec![claim(0x42, UploadProof::PackMissing); 8];
    let snap = snapshot(&changes, &[0x42]);
    let req = request(&changes, &claims);
    assert!(decide_ticket_cleanup(&req, "missing", NOW, &snap, limits()).is_err());
    let req = request(&changes, &claims[..2]);
    assert!(decide_ticket_cleanup(&req, "missing", NOW, &snap, limits()).is_err());
    let (id, expected) = reservation(0x42);
    let terminal = ReservationTerminal {
        repository: REPO,
        occurred_ms: NOW,
        kind: ReservationTerminalKind::Aborted {
            reason: ReservationAbortReason::Internal,
            detail: String::new(),
        },
    };
    let mut zero = limits();
    zero.guards = 0;
    assert!(
        decide_reservation_settlement(
            REPO,
            &OperationId([6; 32]),
            &id,
            &expected,
            &terminal,
            &snap,
            zero
        )
        .is_err()
    );
    let mut ambiguous = snap.clone();
    ambiguous
        .reservations
        .push((id.clone(), Observed::Absent(REV)));
    assert!(
        decide_reservation_settlement(
            REPO,
            &OperationId([6; 32]),
            &id,
            &expected,
            &terminal,
            &ambiguous,
            limits()
        )
        .is_err()
    );
    let mut oversized = terminal;
    oversized.kind = ReservationTerminalKind::Committed {
        refs: vec![RefValue {
            name: RefName("x".repeat(65_537)),
            value: Some(NEW),
        }],
        accounting: decision::ReservationAccounting {
            bytes_stored: 0,
            new_to_repository: 0,
            new_to_store: 0,
        },
    };
    assert!(
        decide_reservation_settlement(
            REPO,
            &OperationId([6; 32]),
            &id,
            &expected,
            &oversized,
            &snap,
            limits()
        )
        .is_err()
    );
}

#[test]
fn upload_session_bytes_are_charged_before_deciding() {
    let changes = pair();
    let claims = [claim(0x42, UploadProof::Ready)];
    let req = request(&changes, &claims);
    let mut snap = snapshot(&changes, &[0x42]);
    let Observed::Present { value, .. } = &mut snap.tickets[0].1 else {
        unreachable!()
    };
    value.upload_session = Some(vec![0; 16]);
    let mut bounded = limits();
    bounded.work = 10_000_000;
    bounded.bytes = (2 * changes
        .iter()
        .map(|change| change.name.0.len())
        .sum::<usize>()
        + 32
        + head().0.len()
        + 16) as u64;
    assert!(decide_ticketed_advance(&req, &snap, bounded).is_ok());
    let Observed::Present { value, .. } = &mut snap.tickets[0].1 else {
        unreachable!()
    };
    value.upload_session.as_mut().unwrap().push(0);
    assert_eq!(
        decide_ticketed_advance(&req, &snap, bounded)
            .unwrap_err()
            .code,
        FailureCode::ResourceLimit
    );
    let Observed::Present { value, .. } = &mut snap.tickets[0].1 else {
        unreachable!()
    };
    value.upload_session = Some(vec![0; 65_537]);
    assert_eq!(
        decide_ticketed_advance(&req, &snap, limits())
            .unwrap_err()
            .code,
        FailureCode::ResourceLimit
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn ticketed_semantic_fixtures_pin_terminal_identity_and_replay() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("../../../fixtures/decision/ticketed.json")).unwrap();
    for row in rows.as_array().unwrap() {
        let case = row["case"].as_str().unwrap();
        let changes = pair();
        let claims = [claim(
            0x42,
            if case == "cleanup" {
                UploadProof::PackMissing
            } else {
                UploadProof::Ready
            },
        )];
        let mut req = request(&changes, &claims);
        let mut snap = snapshot(&changes, &[0x42]);
        if case == "replay" {
            req.write.replay = Some(decision::ref_write::RefReplay {
                scope: ReplayScope([8; 32]),
                fingerprint: [9; 32],
                expires_ms: 10_000,
            });
            snap.replay = Some(present(ReplayFact {
                scope: ReplayScope([8; 32]),
                fingerprint: [9; 32],
                expires_ms: 10_000,
                state: ReplayState::Committed(TerminalResult::Applied(vec![])),
            }));
            snap.tickets.clear();
        } else if case.starts_with("proof-") {
            let pending = pending_binding(9);
            snap.reservations
                .push((pending.reservation.clone(), pending.expected.clone()));
            req.pending = Some(pending);
            req.verification = VerificationVerdict::Refused(decision::PermanentRefusal {
                code: if case == "proof-late" {
                    PermanentCode::FailedPrecondition
                } else {
                    PermanentCode::InvalidArgument
                },
                public_message: if case == "proof-late" {
                    "proof arrived too late"
                } else {
                    "invalid pack"
                }
                .into(),
            });
        } else if case == "pending" {
            req.verification = VerificationVerdict::Pending;
        }
        let decided = match case {
            "cleanup" => decide_ticket_cleanup(&req, "pack missing", NOW, &snap, limits()).unwrap(),
            "settle" => {
                let (id, expected) = reservation(0x42);
                let terminal = ReservationTerminal {
                    repository: REPO,
                    occurred_ms: NOW,
                    kind: ReservationTerminalKind::Aborted {
                        reason: ReservationAbortReason::Internal,
                        detail: String::new(),
                    },
                };
                decide_reservation_settlement(
                    REPO,
                    &OperationId([6; 32]),
                    &id,
                    &expected,
                    &terminal,
                    &snap,
                    limits(),
                )
                .unwrap()
            }
            _ => decide_ticketed_advance(&req, &snap, limits()).unwrap(),
        };
        assert!(guards_match(&decided, &snap, NOW));
        let (kind, tickets, settlements, outcomes) = match decided.decision() {
            WriteDecision::Apply(effects) => {
                assert!(
                    effects
                        .outcomes
                        .iter()
                        .all(|outcome| outcome.operation == OperationId([6; 32])
                            && outcome.reservation == ReservationId([0xc2; 32]))
                );
                for settlement in &effects.reservations {
                    assert_eq!(settlement.id, ReservationId([0xc2; 32]));
                    assert_eq!(settlement.terminal.repository, REPO);
                    if let ReservationTerminalKind::Aborted { reason, .. } =
                        &settlement.terminal.kind
                    {
                        assert_eq!(format!("{reason:?}"), row["reason"].as_str().unwrap());
                    } else if let ReservationTerminalKind::Committed { refs, accounting } =
                        &settlement.terminal.kind
                    {
                        assert_eq!(
                            refs,
                            &vec![
                                RefValue {
                                    name: packmap(),
                                    value: Some(NEW)
                                },
                                RefValue {
                                    name: head(),
                                    value: Some(NEW)
                                }
                            ]
                        );
                        assert_eq!(accounting.bytes_stored, 1066);
                    }
                }
                (
                    "apply",
                    effects.tickets.len(),
                    effects.reservations.len(),
                    effects.outcomes.len(),
                )
            }
            WriteDecision::Reject {
                terminal,
                reservation: Some(outcome),
                ..
            } => {
                assert!(terminal.is_none());
                assert_eq!(outcome.id, ReservationId([9; 32]));
                assert_eq!(outcome.terminal.occurred_ms, NOW);
                let ReservationTerminalKind::Aborted { reason, detail } = &outcome.terminal.kind
                else {
                    panic!("missing abort")
                };
                assert_eq!(format!("{reason:?}"), row["reason"].as_str().unwrap());
                assert_eq!(
                    detail,
                    if case == "proof-late" {
                        "proof arrived too late"
                    } else {
                        ""
                    }
                );
                ("reject", 0, 1, 1)
            }
            WriteDecision::ReturnRecorded(value) => {
                assert_eq!(value, &TerminalResult::Applied(vec![]));
                ("recorded", 0, 0, 0)
            }
            WriteDecision::Retry(_) => ("retry", 0, 0, 0),
            other => panic!("unexpected fixture decision: {other:?}"),
        };
        assert_eq!(kind, row["decision"].as_str().unwrap());
        assert_eq!(tickets as u64, row["tickets"].as_u64().unwrap());
        assert_eq!(settlements as u64, row["settlements"].as_u64().unwrap());
        assert_eq!(outcomes as u64, row["outcomes"].as_u64().unwrap());
    }
}

mod combined {
    use super::*;
    use crate::decision::{
        ClearanceAdvance, ClearanceDecision, ClearanceFacts, ClearanceLifecycle, ClearanceLimits,
        ClearanceMoment, ClearanceState, PriorPublication, decide_accept_and_clear,
    };

    fn advance(state: ClearanceState, operation: OperationId) -> ClearanceAdvance<'static> {
        ClearanceAdvance {
            sequence: 1,
            generation: 1,
            operation,
            head: Some(NEW),
            packmap: Some(NEW),
            state,
            additions: &[],
            dependencies: &[],
            external_suppliers: &[],
            obligations: &[],
            obligation_revisions: &[],
            takedown_complete: false,
            flagged: false,
            revision: REV,
        }
    }

    fn facts(changed: ClearanceAdvance<'static>) -> ClearanceFacts<'static> {
        ClearanceFacts {
            repository: REPO,
            moment: ClearanceMoment::Acceptance,
            prior: PriorPublication {
                generation: 1,
                sequence: 0,
                published_prefix: 0,
                deletion_boundary: 0,
                head: None,
                packmap: None,
                revision: REV,
            },
            previous_state: changed.state,
            changed,
            suffix: &[],
            witnesses: &[],
            lifecycle: ClearanceLifecycle::NotOffered,
            deleted: false,
        }
    }

    fn with_publication(mut snap: Snapshot) -> Snapshot {
        snap.publication = Some(Observed::Absent(REV));
        snap
    }

    #[test]
    fn clearance_must_bind_to_the_accepted_write_and_publication() {
        let changes = pair();
        let claims = [claim(0x10, UploadProof::Ready)];
        let req = request(&changes, &claims);
        let snap = with_publication(snapshot(&changes, &[0x10]));
        let good = || facts(advance(ClearanceState::Cleared, OperationId([6; 32])));
        let mut head = good();
        head.changed.head = Some([9; 32]);
        let mut packmap = good();
        packmap.changed.packmap = None;
        let mut moved = good();
        moved.prior.sequence = 3;
        let mut stale = good();
        stale.prior.revision = Revision([0x55; 32]);
        for input in [head, packmap, moved, stale] {
            let err = decide_accept_and_clear(
                &req,
                &snap,
                limits(),
                &input,
                &ClearanceLimits::reference(),
            )
            .unwrap_err();
            assert_eq!(err.code, FailureCode::InvalidResponse);
        }
        let err = decide_accept_and_clear(
            &req,
            &snapshot(&changes, &[0x10]),
            limits(),
            &good(),
            &ClearanceLimits::reference(),
        )
        .unwrap_err();
        assert_eq!(err.code, FailureCode::UnavailableInput);
    }

    #[test]
    fn clearance_rides_apply_and_leaves_acceptance_unchanged() {
        let changes = pair();
        let claims = [claim(0x10, UploadProof::Ready)];
        let mut req = request(&changes, &claims);
        req.pending = Some(pending_binding(0x70));
        let mut snap = with_publication(snapshot(&changes, &[0x10]));
        snap.reservations.push((
            ReservationId([0x70; 32]),
            pending_binding(0x70).expected.clone(),
        ));
        let alone = decide_ticketed_advance(&req, &snap, limits()).unwrap();
        let input = facts(advance(ClearanceState::Cleared, OperationId([6; 32])));
        let both =
            decide_accept_and_clear(&req, &snap, limits(), &input, &ClearanceLimits::reference())
                .unwrap();
        assert_eq!(
            format!("{:?}", both.acceptance().decision()),
            format!("{:?}", alone.decision())
        );
        assert_eq!(both.acceptance().required_guards(), alone.required_guards());
        assert!(matches!(
            both.clearance().unwrap().decision(),
            ClearanceDecision::AdvancePrefix {
                published_prefix: 1,
                ..
            }
        ));
    }

    #[test]
    fn ineligible_advance_accepts_and_retains() {
        let changes = pair();
        let claims = [claim(0x10, UploadProof::Ready)];
        let req = request(&changes, &claims);
        let snap = with_publication(snapshot(&changes, &[0x10]));
        let input = facts(advance(ClearanceState::Pending, OperationId([6; 32])));
        let both =
            decide_accept_and_clear(&req, &snap, limits(), &input, &ClearanceLimits::reference())
                .unwrap();
        assert!(matches!(
            both.acceptance().decision(),
            WriteDecision::Apply(_)
        ));
        assert!(matches!(
            both.clearance().unwrap().decision(),
            ClearanceDecision::Retain {
                published_prefix: 0
            }
        ));
    }

    #[test]
    fn non_apply_acceptance_never_clears() {
        let changes = pair();
        let claims = [claim(0x10, UploadProof::MarkerMissing)];
        let req = request(&changes, &claims);
        let snap = with_publication(snapshot(&changes, &[0x10]));
        let input = facts(advance(ClearanceState::Cleared, OperationId([6; 32])));
        let both =
            decide_accept_and_clear(&req, &snap, limits(), &input, &ClearanceLimits::reference())
                .unwrap();
        assert!(!matches!(
            both.acceptance().decision(),
            WriteDecision::Apply(_)
        ));
        assert!(both.clearance().is_none());
    }

    #[test]
    fn mismatched_scope_moment_or_deletion_is_refused() {
        let changes = pair();
        let claims = [claim(0x10, UploadProof::Ready)];
        let req = request(&changes, &claims);
        let snap = with_publication(snapshot(&changes, &[0x10]));
        let good = || facts(advance(ClearanceState::Cleared, OperationId([6; 32])));
        let mut other_op = good();
        other_op.changed.operation = OperationId([9; 32]);
        let mut other_repo = good();
        other_repo.repository = RepositoryId([9; 32]);
        let mut recheck = good();
        recheck.moment = ClearanceMoment::Recheck;
        let mut deleted = good();
        deleted.deleted = true;
        for input in [other_op, other_repo, recheck, deleted] {
            let err = decide_accept_and_clear(
                &req,
                &snap,
                limits(),
                &input,
                &ClearanceLimits::reference(),
            )
            .unwrap_err();
            assert_eq!(err.code, FailureCode::InvalidResponse);
        }
    }
}

/// One owned ticketed-advance scenario: two tickets, inline storage counting,
/// an admission reservation, a replay record and an authority binding.
struct Scenario {
    changes: [RefChange; 2],
    claims: Vec<TicketClaim>,
    snap: Snapshot,
    verification: VerificationVerdict,
    bound: Option<AuthorityBinding>,
}
type Tweak = fn(&mut Scenario);
const GENERATION: Revision = Revision([7; 32]);
const STORAGE_OUTCOME: ReservationId = ReservationId([0x71; 32]);
impl Scenario {
    fn new() -> Self {
        let changes = pair();
        let mut snap = snapshot(&changes, &[0x10, 0x11]);
        for (_, observed) in &mut snap.tickets {
            if let Observed::Present { value, .. } = observed {
                value.authority_generation = Some(GENERATION);
            }
        }
        snap.storage = Some(present(StorageFact {
            stored_bytes: 400,
            version: 7,
        }));
        snap.reservations
            .push((ReservationId([0x70; 32]), pending_binding(0x70).expected));
        snap.reservations
            .push((STORAGE_OUTCOME, Observed::Absent(REV)));
        snap.replay = Some(Observed::Absent(REV));
        snap.authority = Some(present(AuthorityFact {
            namespace: NamespaceId([7; 32]),
            mode: AuthorityMode::Authority,
            generation: GENERATION,
            ready: true,
        }));
        Self {
            changes,
            claims: vec![
                claim(0x10, UploadProof::Ready),
                claim(0x11, UploadProof::Ready),
            ],
            snap,
            verification: VerificationVerdict::Satisfied,
            bound: Some(AuthorityBinding {
                namespace: NamespaceId([7; 32]),
                mode: AuthorityMode::Authority,
                generation: GENERATION,
            }),
        }
    }
    fn request(&self) -> TicketedAdvanceRequest<'_> {
        let mut req = request(&self.changes, &self.claims);
        req.write.replay = Some(decision::ref_write::RefReplay {
            scope: ReplayScope([8; 32]),
            fingerprint: [9; 32],
            expires_ms: 9_000,
        });
        req.write.required.authority.clone_from(&self.bound);
        req.pending = Some(pending_binding(0x70));
        req.verification = self.verification.clone();
        req.storage = StorageAccounting::Inline {
            observed: self.snap.storage.clone().unwrap(),
            outcome: STORAGE_OUTCOME,
            occurred_ms: NOW,
        };
        req
    }
    fn ticket(&mut self, index: usize) -> &mut TicketFact {
        match &mut self.snap.tickets[index].1 {
            Observed::Present { value, .. } => value,
            Observed::Absent(_) => unreachable!(),
        }
    }
}

#[test]
fn fact_mutation_finds_no_unguarded_ticketed_dependency() {
    let scenarios: Vec<(&str, Tweak)> = vec![
        ("apply", |_| {}),
        ("all counted", |s| {
            for claim in &mut s.claims {
                claim.counted = true;
            }
        }),
        ("expired ticket", |s| s.ticket(0).expires_ms = NOW),
        ("signer mismatch", |s| s.ticket(1).signer = [9; 32]),
        ("missing second ticket", |s| {
            s.snap.tickets[1].1 = Observed::Absent(REV);
        }),
        ("incomplete upload", |s| {
            s.claims[1].proof = UploadProof::MarkerMissing;
        }),
        ("epoch moved ticket", |s| {
            s.ticket(1).authority_generation = Some(Revision([1; 32]));
        }),
        ("authority moved", |s| {
            if let Some(Observed::Present { value, .. }) = &mut s.snap.authority {
                value.generation = Revision([1; 32]);
            }
        }),
        ("ref conflict", |s| {
            s.snap.refs[1].1 = present([99; 32]);
        }),
        ("pending changed", |s| {
            s.snap.reservations[2].1 = Observed::Absent(REV);
        }),
        ("verification refused", |s| {
            s.verification = VerificationVerdict::Refused(decision::PermanentRefusal {
                code: PermanentCode::FailedPrecondition,
                public_message: "proof arrived too late".into(),
            });
        }),
        ("verification pending", |s| {
            s.verification = VerificationVerdict::Pending;
        }),
        ("recorded replay", |s| {
            s.snap.replay = Some(present(ReplayFact {
                scope: ReplayScope([8; 32]),
                fingerprint: [9; 32],
                expires_ms: 9_000,
                state: ReplayState::Committed(TerminalResult::Applied(vec![])),
            }));
        }),
    ];
    let mut exercised = 0;
    for (label, tweak) in scenarios {
        let mut scenario = Scenario::new();
        tweak(&mut scenario);
        let req = scenario.request();
        exercised += crate::decision::fact_harness::assert_guards_cover(
            label,
            &scenario.snap,
            NOW,
            |snap| decide_ticketed_advance(&req, snap, limits()),
        );
    }
    assert!(exercised > 100, "scenarios must exercise many mutations");
}

#[test]
fn counted_claims_are_covered_by_the_exact_counter_row() {
    // A pack's marker appears only in a batch that also moves the counter, so
    // flipping one claim's `counted` is the same event as a counter change.
    for all_counted in [false, true] {
        let mut scenario = Scenario::new();
        for claim in &mut scenario.claims {
            claim.counted = all_counted;
        }
        let req = scenario.request();
        let original = decide_ticketed_advance(&req, &scenario.snap, limits()).unwrap();
        assert!(
            original
                .required_guards()
                .iter()
                .any(|guard| matches!(guard, RequiredGuard::Storage { .. })),
            "the counter row guards `counted` even when no bytes are added"
        );
        let mut flipped = Scenario::new();
        for claim in &mut flipped.claims {
            claim.counted = !all_counted;
        }
        if let Some(Observed::Present { value, .. }) = &mut flipped.snap.storage {
            value.version += 1;
        }
        let req = flipped.request();
        // The flipped world carries its own counter observation.
        if let Ok(redecided) = decide_ticketed_advance(&req, &flipped.snap, limits()) {
            assert_ne!(redecided.decision(), original.decision());
        }
        assert!(!guards_match(&original, &flipped.snap, NOW));
    }
}

#[test]
fn an_unsatisfiable_counter_outcome_is_an_error_not_an_apply() {
    let mut scenario = Scenario::new();
    scenario.snap.reservations[3].1 = present(ReservationFact::Terminal(ReservationTerminal {
        repository: REPO,
        occurred_ms: 1,
        kind: ReservationTerminalKind::Expired,
    }));
    let req = scenario.request();
    assert_eq!(
        decide_ticketed_advance(&req, &scenario.snap, limits())
            .unwrap_err()
            .code,
        FailureCode::InvalidResponse
    );
}

#[test]
fn recorded_refusal_and_conflict_guard_every_examined_ticket_row() {
    // A conflict records its answer; the rows it examined must not move.
    let mut conflict = Scenario::new();
    conflict.snap.refs[1].1 = present([99; 32]);
    let req = conflict.request();
    let guarded = decide_ticketed_advance(&req, &conflict.snap, limits()).unwrap();
    assert!(matches!(guarded.decision(), WriteDecision::Conflict { .. }));
    let tickets = guarded
        .required_guards()
        .iter()
        .filter(|guard| matches!(guard, RequiredGuard::Ticket { .. }))
        .count();
    assert_eq!(tickets, 2);
    // A refusal at the second ticket guards both rows read, not the rest.
    let mut refused = Scenario::new();
    refused.ticket(1).signer = [9; 32];
    let req = refused.request();
    let guarded = decide_ticketed_advance(&req, &refused.snap, limits()).unwrap();
    assert!(matches!(guarded.decision(), WriteDecision::Reject { .. }));
    assert_eq!(
        guarded
            .required_guards()
            .iter()
            .filter(|guard| matches!(guard, RequiredGuard::Ticket { .. }))
            .count(),
        2
    );
}

#[test]
fn apply_adds_each_consumed_pack_to_membership_once() {
    let mut scenario = Scenario::new();
    let shared = scenario.ticket(0).pack;
    scenario.ticket(1).pack = shared;
    let req = scenario.request();
    let guarded = decide_ticketed_advance(&req, &scenario.snap, limits()).unwrap();
    let WriteDecision::Apply(effects) = guarded.decision() else {
        panic!("expected apply: {:?}", guarded.decision());
    };
    assert_eq!(
        effects.membership,
        vec![decision::MembershipEffect {
            repository: REPO,
            pack: shared,
        }]
    );
    // The sealed decision needs no membership guard for its own additions.
    check_guard_completeness(&guarded, guarded.required_guards()).unwrap();
    let mut distinct = Scenario::new();
    let req = distinct.request();
    let guarded = decide_ticketed_advance(&req, &distinct.snap, limits()).unwrap();
    let WriteDecision::Apply(effects) = guarded.decision() else {
        panic!("expected apply");
    };
    assert_eq!(effects.membership.len(), 2);
    distinct.claims.truncate(0);
}

#[test]
fn cleanup_requires_the_exact_ticketed_reservation() {
    let changes = pair();
    let claims = [claim(0x60, UploadProof::PackMissing)];
    let req = request(&changes, &claims);
    let snap = snapshot(&changes, &[0x60]);
    let guarded = decide_ticket_cleanup(&req, "lost", NOW, &snap, limits()).unwrap();
    assert!(
        matches!(guarded.decision(), WriteDecision::Apply(effects) if effects.tickets.len() == 1)
    );
    for state in [
        Observed::Absent(REV),
        present(ReservationFact::Ticketed(TicketId([0x99; 32]))),
        present(ReservationFact::Terminal(ReservationTerminal {
            repository: REPO,
            occurred_ms: 1,
            kind: ReservationTerminalKind::Expired,
        })),
        pending_binding(0x60).expected,
    ] {
        let mut snap = snapshot(&changes, &[0x60]);
        snap.reservations[0].1 = state;
        assert_eq!(
            decide_ticket_cleanup(&req, "lost", NOW, &snap, limits())
                .unwrap_err()
                .code,
            FailureCode::InvalidResponse,
            "a second terminal outcome must never be written"
        );
    }
}

#[test]
fn cleanup_guards_every_row_that_fixes_the_first_failure() {
    use crate::decision::fact_harness::assert_guards_cover;
    let changes = pair();
    let claims = [
        claim(0x60, UploadProof::PackMissing),
        claim(0x61, UploadProof::Ready),
        claim(0x62, UploadProof::PackMissing),
    ];
    let req = request(&changes, &claims);
    let mut snap = snapshot(&changes, &[0x60, 0x61, 0x62]);
    snap.tickets[1].1 = Observed::Absent(REV);
    let flipped = assert_guards_cover("cleanup", &snap, NOW, |snap| {
        decide_ticket_cleanup(&req, "lost", NOW, snap, limits())
    });
    assert!(flipped > 0);
}

#[test]
fn settlement_of_a_ticketed_reservation_closes_or_fences_its_ticket() {
    use crate::decision::fact_harness::assert_guards_cover;
    let operation = OperationId([6; 32]);
    let (id, expected) = reservation(0x42);
    let terminal = |kind| ReservationTerminal {
        repository: REPO,
        occurred_ms: NOW,
        kind,
    };
    for kind in [
        ReservationTerminalKind::Expired,
        ReservationTerminalKind::Aborted {
            reason: ReservationAbortReason::Internal,
            detail: String::new(),
        },
    ] {
        let terminal = terminal(kind);
        let snap = snapshot(&[], &[0x42]);
        let decide = |snap: &Snapshot| {
            decide_reservation_settlement(
                REPO,
                &operation,
                &id,
                &expected,
                &terminal,
                snap,
                limits(),
            )
        };
        let guarded = decide(&snap).unwrap();
        let WriteDecision::Apply(effects) = guarded.decision() else {
            panic!("expected apply");
        };
        assert_eq!(
            effects.tickets,
            vec![TicketTransition {
                id: TicketId([0x42; 32]),
                next: None
            }]
        );
        assert_eq!(effects.reservations.len(), 1);
        assert!(assert_guards_cover("settlement", &snap, NOW, decide) > 0);
        // A ticket row already gone is fenced by its observed absence.
        let mut gone = snapshot(&[], &[0x42]);
        gone.tickets[0].1 = Observed::Absent(REV);
        let fenced = decide(&gone).unwrap();
        let WriteDecision::Apply(effects) = fenced.decision() else {
            panic!("expected apply");
        };
        assert!(effects.tickets.is_empty() && effects.reservations.len() == 1);
        assert!(!guards_match(&fenced, &snap, NOW));
    }
    // The ticket must belong to the reservation being settled.
    let mut mismatched = snapshot(&[], &[0x42]);
    if let Observed::Present { value, .. } = &mut mismatched.tickets[0].1 {
        value.reservation = ReservationId([1; 32]);
    }
    assert_eq!(
        decide_reservation_settlement(
            REPO,
            &operation,
            &id,
            &expected,
            &terminal(ReservationTerminalKind::Expired),
            &mismatched,
            limits()
        )
        .unwrap_err()
        .code,
        FailureCode::InvalidResponse
    );
}
