use super::*;
use crate::indexed::budget::{Budgeted, SliceBudget};

#[test]
fn successor_wake_reservation_skips_insufficient_capacity_without_charge() {
    let (fx, _, _, _) = history(2, 0, 1, false);
    in_view(&fx, false, |reader| {
        let calls = SliceBudget::new(1);
        let session = SliceBudget::new(100);
        let capped = AtomicBool::new(false);
        let admission = crate::store::read_io::ReadIo::new();
        let meta = Budgeted::new(&fx.pipe.meta, &calls)
            .with_session(&session)
            .flagging(&capped)
            .with_io(&admission);
        let before = fx.pipe.meta.calls();
        assert!(reader.reserve_successor_wake(&meta).is_none());
        assert_eq!((calls.used(), session.used()), (0, 0));
        assert!(!calls.refused() && !session.refused());
        assert!(!capped.load(Ordering::SeqCst));
        assert_eq!(fx.pipe.meta.calls(), before);
    });
}

#[test]
fn successor_wake_log_reserves_exactly_two_reads_per_consumed_parent() {
    for denial in [false, true] {
        let (fx, commits, _, _) = history(11, 0, 1, denial);
        for writer in [false, true] {
            in_view(&fx, writer, |reader| {
                let mut before = Vec::new();
                let mut pages = Vec::new();
                for mode in [HistoryMode::AllParents, HistoryMode::FirstParent] {
                    let inherited = SliceBudget::new(8_500);
                    *fx.pipe.meta.request_budget.lock().unwrap() = Some(inherited.clone());
                    let mut session = ReaderSession::default();
                    let count = fx.pipe.meta.calls();
                    let seen = fx.pipe.meta.seen().len();
                    let page = block_on(reader.walk_history_in(
                        &mut session,
                        HEAD,
                        None,
                        10,
                        HistoryOptions {
                            mode,
                            ..HistoryOptions::default()
                        },
                    ))
                    .unwrap()
                    .unwrap();
                    let calls = fx.pipe.meta.calls() - count;
                    assert_eq!(inherited.used(), calls);
                    assert!(!inherited.refused());
                    if mode == HistoryMode::FirstParent {
                        let keys = &fx.pipe.meta.seen()[seen..];
                        for parent in commits.iter().rev().skip(1).take(9) {
                            let key = crate::store::keys::object_index_range(
                                &fx.repo_id("room").name,
                                &id(parent),
                            )
                            .0;
                            assert_eq!(keys.iter().filter(|seen| **seen == key).count(), 1);
                        }
                    }
                    before.push((calls, session.io.calls.used()));
                    pages.push(page);
                    *fx.pipe.meta.request_budget.lock().unwrap() = None;
                }
                assert_eq!(pages[0], pages[1]);
                assert_eq!(before[1].0, before[0].0 + 18);
                assert_eq!(before[1].1, before[0].1 + 18);
            });
        }
    }
}

#[test]
fn successor_wake_tight_walk_preserves_uniform_absence_and_owner_error() {
    let (fx, _, _, _) = history(2, 0, 1, false);
    for writer in [false, true] {
        in_view(&fx, writer, |reader| {
            let mut results = Vec::new();
            for mode in [HistoryMode::AllParents, HistoryMode::FirstParent] {
                let mut session =
                    ReaderSession::new(ReadLimits::new(1, u64::MAX, u64::MAX, u64::MAX));
                results.push(
                    block_on(reader.walk_history_in(
                        &mut session,
                        HEAD,
                        None,
                        2,
                        HistoryOptions {
                            mode,
                            ..HistoryOptions::default()
                        },
                    ))
                    .map_err(|error| error.code()),
                );
            }
            assert_eq!(results[0], results[1]);
            if writer {
                assert_eq!(results[1], Err(Code::ResourceExhausted));
            } else {
                assert_eq!(results[1], Ok(None));
            }
        });
    }
}

#[test]
fn successor_wake_preserves_denied_absent_unauthorized_and_mixed_results() {
    for case in ["denied", "absent", "unauthorized", "mixed"] {
        for writer in [false, true] {
            let (fx, commits, _, _) = history(3, 0, 1, true);
            in_view(&fx, writer, |reader| {
                if matches!(case, "denied" | "mixed") {
                    block_on(
                        crate::store::ContentIndex::new(crate::store::BorrowedStore(
                            fx.pipe.meta.inner.as_ref(),
                        ))
                        .block(
                            &id(&commits[1]),
                            &crate::store::BlockEntry::new("stopped parent", T0 as u64),
                            T0 as u64,
                        ),
                    )
                    .unwrap();
                }
                let repo = fx.repo_id("room");
                if matches!(case, "absent" | "mixed") {
                    block_on(fx.pipe.meta.inner.apply(
                        &fx.pipe.shards.ref_shard(&repo, HEAD),
                        Batch::new().delete(keys::ref_key(&repo.name, HEAD)),
                    ))
                    .unwrap();
                }
                if case == "unauthorized" {
                    block_on(fx.pipe.meta.inner.apply(
                        &fx.pipe.shards.coordinator(&repo.namespace),
                        Batch::new().put(
                            keys::repo_visibility(&repo.name),
                            codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
                                visibility: codec::StoredVisibility::Private,
                                last_created_ms: 0,
                                last_statement_id: None,
                                changed_ms: 0,
                            }),
                        ),
                    ))
                    .unwrap();
                }
                let mut results = Vec::new();
                for mode in [HistoryMode::AllParents, HistoryMode::FirstParent] {
                    results.push(
                        block_on(reader.walk_history_in(
                            &mut ReaderSession::default(),
                            HEAD,
                            None,
                            3,
                            HistoryOptions {
                                mode,
                                ..HistoryOptions::default()
                            },
                        ))
                        .map_err(|error| error.code()),
                    );
                }
                assert_eq!(results[0], results[1], "{case}, writer={writer}");
            });
        }
    }
}

#[test]
fn successor_wake_read_faults_neither_flag_exhaustion_nor_change_results() {
    let baseline = {
        let (fx, _, _, _) = history(3, 0, 1, true);
        first_parent_walk(&fx)
    };
    assert!(matches!(baseline, Ok(Some(_))));
    let (fx, commits, _, _) = history(3, 0, 1, true);
    let parent = id(&commits[1]);
    let armed = [
        crate::store::keys::object_index_range(&fx.repo_id("room").name, &parent).0,
        crate::store::keys::block(&parent),
    ];
    fx.pipe.meta.fail_once_keys.lock().unwrap().extend(armed);
    assert_eq!(first_parent_walk(&fx), baseline);
    assert!(
        fx.pipe.meta.fail_once_keys.lock().unwrap().is_empty(),
        "both speculative reads were dispatched and failed"
    );
}

fn first_parent_walk(fx: &Fx) -> Result<Option<Vec<Hash>>, Code> {
    let mut walked = None;
    in_view(fx, false, |reader| {
        walked = Some(
            block_on(reader.walk_history_in(
                &mut ReaderSession::default(),
                HEAD,
                None,
                3,
                HistoryOptions {
                    mode: HistoryMode::FirstParent,
                    ..HistoryOptions::default()
                },
            ))
            .map(|page| page.map(|page| page.commits.iter().map(|commit| commit.id).collect()))
            .map_err(|error| error.code()),
        );
    });
    walked.unwrap()
}
