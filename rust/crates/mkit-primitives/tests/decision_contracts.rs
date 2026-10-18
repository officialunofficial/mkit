//! Information-preservation regressions for shared semantic contracts.
use mkit_primitives::{
    decision::{
        DurableOutcome, MembershipObservation, Observed, OperationId, PermanentCode,
        PermanentRefusal, RequiredGuard, ReservationAbortReason, ReservationId,
        ReservationTerminal, ReservationTerminalKind, TerminalResult,
    },
    evidence::{RepositoryId, Revision},
};

#[test]
fn two_absent_members_at_one_revision_remain_distinct() {
    let repository = RepositoryId([1; 32]);
    let revision = Revision([2; 32]);
    let first = MembershipObservation::new([3; 32], Observed::Absent(revision));
    let second = MembershipObservation::new([4; 32], Observed::Absent(revision));
    assert_ne!(first, second);
    let first_guard = RequiredGuard::Membership {
        repository,
        object: first.object,
        expected: first.observed,
    };
    let second_guard = RequiredGuard::Membership {
        repository,
        object: second.object,
        expected: second.observed,
    };
    assert_ne!(first_guard, second_guard);
}

#[test]
fn replay_retains_distinct_messages_under_the_same_public_code() {
    let first = TerminalResult::Rejected(PermanentRefusal::new(
        PermanentCode::PermissionDenied,
        "signer is not allowed".into(),
    ));
    let second = TerminalResult::Rejected(PermanentRefusal::new(
        PermanentCode::PermissionDenied,
        "update is not a fast-forward".into(),
    ));
    assert_ne!(first, second);
    if let TerminalResult::Rejected(refusal) = first {
        assert_eq!(refusal.public_message, "signer is not allowed");
    } else {
        panic!("permanent refusal changed classification");
    }
}

#[test]
fn ref_conflict_outcomes_keep_each_reservations_delivery_key() {
    let terminal = ReservationTerminal::new(
        RepositoryId([1; 32]),
        100,
        ReservationTerminalKind::Aborted {
            reason: ReservationAbortReason::RefConflict,
            detail: String::new(),
        },
    );
    let first = DurableOutcome {
        operation: OperationId([2; 32]),
        reservation: ReservationId([3; 32]),
        terminal: terminal.clone(),
    };
    let second = DurableOutcome {
        operation: OperationId([2; 32]),
        reservation: ReservationId([4; 32]),
        terminal,
    };
    assert_ne!(first, second);
    assert_eq!(first.terminal, second.terminal);
}
