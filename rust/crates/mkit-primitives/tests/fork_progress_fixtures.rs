use mkit_primitives::{
    evidence::{RepositoryId, Revision},
    fork::*,
};

#[test]
fn portable_progress_cases_pin_decisions_and_precedence() {
    let token = ForkObservation::Present(Revision([1; 32]));
    for line in include_str!("../fixtures/fork/progress.txt")
        .lines()
        .filter(|s| !s.starts_with('#'))
    {
        let parts: Vec<_> = line.split_whitespace().collect();
        let [phase, authority, epoch, reservation, now, expected] = parts.as_slice() else {
            panic!("invalid fixture: {line}")
        };
        let facts = ForkAdvanceFacts {
            binding: [2; 32],
            destination: RepositoryId([3; 32]),
            progress: ForkProgress {
                phase: match *phase {
                    "preparing" => ForkAdvancePhase::Preparing,
                    "accepted" => ForkAdvancePhase::Accepted,
                    "complete" => ForkAdvancePhase::Complete,
                    "failed" => ForkAdvancePhase::Failed,
                    _ => panic!("unknown phase"),
                },
                cursor: 0,
                part: 0,
                revision: Revision([4; 32]),
            },
            recorded_authority: token,
            authority: if *authority == "same" {
                token
            } else {
                ForkObservation::Absent
            },
            grant_epoch: Some(ForkEpochFence {
                recorded: token,
                current: if *epoch == "same" {
                    token
                } else {
                    ForkObservation::Absent
                },
            }),
            reservation: Some(ForkReservationFence {
                reservation: mkit_primitives::decision::ReservationId([5; 32]),
                expected: Revision([1; 32]),
                current: if *reservation == "same" {
                    token
                } else {
                    ForkObservation::Absent
                },
            }),
            construction_expires_ms: 100,
        };
        let decision = *decide_fork_advance(&facts, now.parse().expect("fixture time")).decision();
        let expected_decision = match *expected {
            "Advance" => ForkAdvanceDecision::Advance,
            "Terminal" => ForkAdvanceDecision::Terminal,
            "AuthorityMoved" => ForkAdvanceDecision::Refuse(ForkAdvanceRefusal::AuthorityMoved),
            "EpochMoved" => ForkAdvanceDecision::Refuse(ForkAdvanceRefusal::EpochMoved),
            "ReservationSettled" => {
                ForkAdvanceDecision::Refuse(ForkAdvanceRefusal::ReservationSettled)
            }
            "Expired" => ForkAdvanceDecision::Refuse(ForkAdvanceRefusal::Expired),
            _ => panic!("unknown expected decision"),
        };
        assert_eq!(decision, expected_decision, "{line}");
    }
}
