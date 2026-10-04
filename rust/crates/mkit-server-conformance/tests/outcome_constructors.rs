//! External embedders can build every delivery payload without stored codecs.
#![allow(clippy::unwrap_used)]

use mkit_server::pipeline::{Outcome, OutcomeKind};
use mkit_server::store::{AbortReason, PendingOp, ReservationV1, StoredProcedure};

#[test]
fn public_constructors_cover_every_sink_visible_variant() {
    let repo = "root/repo".to_owned();
    let cases = [
        (
            ReservationV1::committed(
                repo.clone(),
                100,
                10,
                9,
                8,
                vec![],
                StoredProcedure::UpdateRef,
            ),
            OutcomeKind::committed(10, 9, 8, vec![]),
        ),
        (
            ReservationV1::aborted(
                repo.clone(),
                100,
                AbortReason::Unspecified,
                "denied".into(),
                StoredProcedure::UpdateRef,
            ),
            OutcomeKind::aborted(AbortReason::Unspecified, "denied".into()),
        ),
        (
            ReservationV1::expired(repo.clone(), 100),
            OutcomeKind::expired(),
        ),
        (
            ReservationV1::read_served(
                repo.clone(),
                100,
                [7; 32],
                6,
                StoredProcedure::HttpGetObject,
            ),
            OutcomeKind::read_served([7; 32], 6),
        ),
        (
            ReservationV1::repo_storage_changed(repo.clone(), 100, 10, 2),
            OutcomeKind::repo_storage_changed(10, 2),
        ),
    ];
    for (row, kind) in cases {
        let mapped =
            Outcome::from_reservation("id".into(), "https://example.test".into(), row).unwrap();
        let mut built = Outcome::new(
            "id".into(),
            "https://example.test".into(),
            repo.clone(),
            100,
            kind,
        );
        built.procedure = mapped.procedure;
        built.visibility = mapped.visibility;
        assert_eq!(built, mapped);
    }
    for row in [
        ReservationV1::pending(repo, 0, 100, PendingOp::Write, StoredProcedure::UpdateRef),
        ReservationV1::ticketed([3; 32]),
    ] {
        assert!(
            Outcome::from_reservation("id".into(), "https://example.test".into(), row).is_err()
        );
    }
}
