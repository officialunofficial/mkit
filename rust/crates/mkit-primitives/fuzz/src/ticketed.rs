//! Bounded ticket, replay, cleanup and settlement transition plans.
use mkit_primitives::decision::ref_write::{
    MembershipWindow, RefChange, RefDecisionLimits, RefRequirements, RefWriteKind, RefWriteRequest,
    guards_match,
};
use mkit_primitives::decision::ticketed::{
    PendingBinding, StorageAccounting, TicketClaim, TicketedAdvanceRequest, UploadProof,
    VerificationVerdict, decide_reservation_settlement, decide_ticket_cleanup,
    decide_ticketed_advance,
};
use mkit_primitives::decision::{
    self, AcceptanceBasis, HostAttestation, Observed, OperationId, PermanentCode, RefName,
    ReplayFact, ReplayScope, ReplayState, ReservationAbortReason, ReservationFact, ReservationId,
    ReservationOp, ReservationTerminal, ReservationTerminalKind, Snapshot, TerminalResult,
    TicketFact, TicketId, WriteDecision,
};

use mkit_core::hash::Hash;
use mkit_core::refs::RefWriteCondition::Match;
use mkit_primitives::evidence::acceptance::MembershipWitness;
use mkit_primitives::evidence::{PackSource, RepositoryId, Revision, SourceBinding};

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
    RefDecisionLimits::new(256, 64, 65_536, 100_000, 512)
}
fn pair() -> [RefChange; 2] {
    [
        RefChange::new(packmap(), Match(OLD), Some(NEW)),
        RefChange::new(head(), Match(OLD), Some(NEW)),
    ]
}
fn ticket_fact(byte: u8) -> TicketFact {
    TicketFact::new(
        TicketId([byte; 32]),
        REPO,
        head(),
        SIGNER,
        PackSource {
            id: [0x50 + byte; 32],
            len: 1000 + u64::from(byte),
            binding: SourceBinding([0; 32]),
        },
        1024,
        10,
        1_000,
        ReservationId([byte | 0x80; 32]),
        None,
        None,
    )
}
fn claim(byte: u8, proof: UploadProof) -> TicketClaim {
    TicketClaim::new(TicketId([byte; 32]), proof, false)
}
fn reservation(byte: u8) -> (ReservationId, Observed<ReservationFact>) {
    (
        ReservationId([byte | 0x80; 32]),
        present(ReservationFact::Ticketed(TicketId([byte; 32]))),
    )
}
fn write(changes: &[RefChange]) -> RefWriteRequest<'_> {
    {
        let mut v = RefWriteRequest::new(
            REPO,
            RefWriteKind::Advance,
            changes,
            {
                let mut v = RefRequirements::new(MembershipWindow::Elapsed);
                v.authority = None;
                v.grant = None;
                v.incarnation = None;
                v.policy = None;
                v.admission = None;
                v.members = &[];
                v.indexed_head = false;
                v.denial = false;
                v.publication = false;
                v.source = None;
                v.valid_through_ms = None;
                v
            },
            NOW,
        );
        v.operation = Some(OperationId([6; 32]));
        v.admitted = &[];
        v.presence = None;
        v.signer = Some(SIGNER);
        v.replay = None;
        v.ancestry = &[];
        v
    }
}
fn snapshot(changes: &[RefChange], ticket_bytes: &[u8]) -> Snapshot {
    {
        let mut v = Snapshot::new(REPO);
        v.refs = changes
            .iter()
            .map(|change| (change.name.clone(), present(OLD)))
            .collect();
        v.replay = None;
        v.tickets = ticket_bytes
            .iter()
            .map(|&byte| (TicketId([byte; 32]), present(ticket_fact(byte))))
            .collect();
        v.reservations = ticket_bytes.iter().map(|&byte| reservation(byte)).collect();
        v.authority = None;
        v.grant = None;
        v.lifecycle = None;
        v.members = vec![];
        v.denial = None;
        v.policy = None;
        v.admission = None;
        v.accounting = None;
        v.storage = None;
        v.publication = None;
        v.basis = vec![];
        v
    }
}
fn request<'a>(
    changes: &'a [RefChange],
    claims: &'a [TicketClaim],
    basis: &'a [AcceptanceBasis],
) -> TicketedAdvanceRequest<'a> {
    TicketedAdvanceRequest::new(
        write(changes),
        claims,
        VerificationVerdict::Verified(basis),
        StorageAccounting::Disabled,
        None,
    )
}
fn pending_binding(byte: u8) -> PendingBinding {
    PendingBinding::new(
        ReservationId([byte; 32]),
        present(ReservationFact::Pending {
            repository: REPO,
            created_ms: 5,
            reconcile_ms: 9_000,
            op: ReservationOp::Write,
        }),
        NOW,
    )
}

/// Replay one fixed-size transition plan through all three ticketed entry points.
///
/// # Panics
/// Panics on nondeterminism, missing guards, unbounded effects, or duplicate settlement.
#[allow(clippy::too_many_lines)]
pub fn check(data: &[u8]) {
    if data.len() > super::MAX_INPUT_BYTES {
        return;
    }
    let byte = |i| data.get(i).copied().unwrap_or(0);
    let changes = pair();
    let claims = [claim(
        0x42,
        match byte(0) % 3 {
            0 => UploadProof::Ready,
            1 => UploadProof::MarkerMissing,
            _ => UploadProof::PackMissing,
        },
    )];
    // The host-attested basis carries only the fields the plan provides.
    let mut attestation = HostAttestation::new(REPO, Vec::new());
    attestation.root = (byte(5) & 1 != 0).then_some([byte(5); 32]);
    attestation.membership = (byte(6) & 1 != 0).then_some(MembershipWitness {
        generation: u64::from(byte(6)),
        removal_version: u64::from(byte(7)),
    });
    attestation.denial_version = (byte(8) & 1 != 0).then_some(u64::from(byte(8)));
    let basis = AcceptanceBasis::attested_by_host(attestation);
    let mut req = request(&changes, &claims, std::slice::from_ref(&basis));
    let mut snap = snapshot(&changes, &[0x42]);
    snap.basis = basis.guards().to_vec();
    if byte(1) & 1 != 0 {
        snap.refs[0].1 = present(NEW);
    }
    if byte(2) & 1 != 0 {
        let pending = pending_binding(9);
        snap.reservations
            .push((pending.reservation.clone(), pending.expected.clone()));
        req.pending = Some(pending);
    }
    req.verification = match byte(3) % 3 {
        0 => VerificationVerdict::Verified(std::slice::from_ref(&basis)),
        1 => VerificationVerdict::Pending,
        _ => VerificationVerdict::Refused(decision::PermanentRefusal::new(
            PermanentCode::InvalidArgument,
            "invalid pack".into(),
        )),
    };
    if byte(4) % 3 != 0 {
        req.write.replay = Some(decision::ref_write::RefReplay::new(
            ReplayScope([8; 32]),
            [9; 32],
            10_000,
        ));
        snap.replay = Some(present(ReplayFact::new(
            ReplayScope([8; 32]),
            [9; 32],
            10_000,
            if byte(4) % 3 == 1 {
                ReplayState::Committed(TerminalResult::Applied(vec![]))
            } else {
                ReplayState::InFlight { resumable: false }
            },
        )));
    }
    let first = decide_ticketed_advance(&req, &snap, limits())
        .expect("bounded model observation must exist");
    same(
        &first,
        &decide_ticketed_advance(&req, &snap, limits())
            .expect("bounded model observation must exist"),
    );
    assert!(guards_match(&first, &snap, NOW));
    assert!(first.required_guards().len() <= limits().guards as usize);
    if let WriteDecision::Apply(effects) = first.decision() {
        assert!(
            effects.tickets.len() <= 1
                && effects.reservations.len() <= 2
                && effects.outcomes.len() <= 2
        );
    }
    for guard in first.required_guards() {
        let mut mutated = snap.clone();
        match guard {
            decision::RequiredGuard::Ticket { id, .. } => {
                mutated
                    .tickets
                    .iter_mut()
                    .find(|(key, _)| key == id)
                    .expect("bounded model observation must exist")
                    .1 = Observed::Absent(REV);
            }
            decision::RequiredGuard::Reservation { id, .. } => {
                mutated
                    .reservations
                    .iter_mut()
                    .find(|(key, _)| key == id)
                    .expect("bounded model observation must exist")
                    .1 = Observed::Absent(REV);
            }
            decision::RequiredGuard::RefValue { name, .. } => {
                mutated
                    .refs
                    .iter_mut()
                    .find(|(key, _)| key == name)
                    .expect("bounded model observation must exist")
                    .1 = Observed::Absent(REV);
            }
            decision::RequiredGuard::Replay { .. } => mutated.replay = Some(Observed::Absent(REV)),
            _ => continue,
        }
        assert!(!guards_match(&first, &mutated, NOW));
    }
    let cleanup = decide_ticket_cleanup(&req, "pack missing", NOW, &snap, limits());
    let repeated_cleanup = decide_ticket_cleanup(&req, "pack missing", NOW, &snap, limits());
    match (&cleanup, &repeated_cleanup) {
        (Ok(first), Ok(second)) => same(first, second),
        (Err(first), Err(second)) => assert_eq!(first.code, second.code),
        _ => panic!("cleanup mutated on repetition"),
    }
    if let Ok(cleanup) = cleanup {
        assert!(guards_match(&cleanup, &snap, NOW));
        let WriteDecision::Apply(effects) = cleanup.decision() else {
            panic!("cleanup must apply")
        };
        assert!(effects.refs.is_empty() && effects.replay.is_none());
        assert!(effects.tickets.len() <= 1 && effects.outcomes.len() <= 1);
    }
    let (id, expected) = reservation(0x42);
    let terminal = ReservationTerminal::new(
        REPO,
        NOW,
        ReservationTerminalKind::Aborted {
            reason: ReservationAbortReason::Internal,
            detail: String::new(),
        },
    );
    let settled = decide_reservation_settlement(
        REPO,
        &OperationId([6; 32]),
        &id,
        &expected,
        &terminal,
        &snap,
        limits(),
    )
    .expect("bounded model observation must exist");
    same(
        &settled,
        &decide_reservation_settlement(
            REPO,
            &OperationId([6; 32]),
            &id,
            &expected,
            &terminal,
            &snap,
            limits(),
        )
        .expect("bounded model observation must exist"),
    );
    assert!(guards_match(&settled, &snap, NOW));
    snap.reservations[0].1 = present(ReservationFact::Terminal(terminal.clone()));
    let repeated = decide_reservation_settlement(
        REPO,
        &OperationId([6; 32]),
        &id,
        &expected,
        &terminal,
        &snap,
        limits(),
    )
    .expect("bounded model observation must exist");
    let WriteDecision::Apply(effects) = repeated.decision() else {
        panic!("settlement must apply")
    };
    assert!(effects.reservations.is_empty() && effects.outcomes.is_empty());
}

fn same(first: &decision::Guarded<WriteDecision>, second: &decision::Guarded<WriteDecision>) {
    assert_eq!(first.decision(), second.decision());
    assert_eq!(first.required_guards(), second.required_guards());
    assert_eq!(first.source_fences(), second.source_fences());
}

#[cfg(test)]
mod tests {
    #[test]
    fn ticketed_transition_seed_replay() {
        for seed in 0_u16..1024 {
            let mut state = u32::from(seed) + 1;
            let mut data = [0; 8];
            for byte in &mut data {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (state >> 24) as u8;
            }
            super::check(&data);
        }
    }
}
