use super::*;
use crate::decision::ref_write::{
    MembershipWindow, RefChange, RefDecisionLimits, RefRequirements, RefWriteKind, RefWriteRequest,
    effect_guard_kinds, guard_kind, guards_match,
};
use crate::decision::{
    self, DecisionClass, GuardKind, Observed, OperationId, PermanentCode, RefName, RefValue,
    ReplayFact, ReplayScope, ReplayState, RequiredGuard, ReservationAbortReason, ReservationFact,
    ReservationId, ReservationOp, ReservationTerminal, ReservationTerminalKind, RetryReason,
    Snapshot, StorageEffect, StorageFact, TerminalResult, TicketFact, TicketId, TicketTransition,
    WriteDecision,
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
        authority_generation: None,
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
    // Ticket consumption never reaches the conflict path.
    assert!(
        guarded
            .required_guards()
            .iter()
            .all(|g| !matches!(g, RequiredGuard::Ticket { .. }))
    );
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
    // A ticket issued under a superseded authority generation refuses.
    req.verification = VerificationVerdict::Satisfied;
    req.authority_generation = Some(7);
    assert!(matches!(
        decide_ticketed_advance(&req, &snap, limits())
            .unwrap()
            .decision(),
        WriteDecision::Reject { refusal, .. } if refusal.code == PermanentCode::PermissionDenied
    ));
    // A matching generation applies.
    let mut snap = snapshot(&changes, &[0x42]);
    let Observed::Present { value: fact, .. } = &mut snap.tickets[0].1 else {
        unreachable!()
    };
    fact.authority_generation = Some(7);
    assert!(matches!(
        decide_ticketed_advance(&req, &snap, limits())
            .unwrap()
            .decision(),
        WriteDecision::Apply(_)
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
