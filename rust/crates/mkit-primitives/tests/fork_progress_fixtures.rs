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
        let facts = {
            let mut v = ForkAdvanceFacts::new(
                [2; 32],
                RepositoryId([3; 32]),
                ForkProgress::new(
                    match *phase {
                        "preparing" => ForkAdvancePhase::Preparing,
                        "accepted" => ForkAdvancePhase::Accepted,
                        "complete" => ForkAdvancePhase::Complete,
                        "failed" => ForkAdvancePhase::Failed,
                        _ => panic!("unknown phase"),
                    },
                    0,
                    0,
                    Revision([4; 32]),
                ),
                100,
            );
            v.recorded_authority = token;
            v.authority = if *authority == "same" {
                token
            } else {
                ForkObservation::Absent
            };
            v.grant_epoch = Some(ForkEpochFence::new(
                token,
                if *epoch == "same" {
                    token
                } else {
                    ForkObservation::Absent
                },
            ));
            v.reservation = Some(ForkReservationFence::new(
                mkit_primitives::decision::ReservationId([5; 32]),
                Revision([1; 32]),
                if *reservation == "same" {
                    token
                } else {
                    ForkObservation::Absent
                },
            ));
            v
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
