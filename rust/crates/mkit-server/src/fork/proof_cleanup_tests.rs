//! Reclamation survives replacement drivers without changing fork decisions.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::fork::{Failure, ForkTimer, Phase};
use crate::pipeline::{D34Shards, ShardMap};
use crate::rt::ManualClock;
use crate::store::{BorrowedStore, codec};
use crate::timers::registry::{TimerHandler, kinds};
use crate::timers::{DueTimer, Fired, TimerCtx};
use crate::{MemoryFault, MemoryKv};
use futures_executor::block_on;
use std::sync::Arc;

fn environment<'a>(store: &'a MemoryKv, clock: &'a ManualClock) -> ForkEnv<'a, MemoryKv> {
    ForkEnv {
        store,
        shards: &D34Shards,
        clock,
        takedown_denial: true,
        extract_min_bytes: None,
        limits: crate::fork::ForkLimits::default(),
        publication_policy: None,
    }
}

async fn seed(store: &MemoryKv, phase: Phase, accepted: bool) -> ForkJobV1 {
    let mut job = super::evidence_tests::job();
    job.phase = phase;
    let destination = job.dest().unwrap();
    let coordinator = D34Shards.coordinator(&destination.namespace);
    let mut batch = Batch::new();
    for _ in 0..35 {
        append(
            &mut job,
            &mut batch,
            &Partition::ContentShard(0),
            &[keys::denial_directory_revision()],
            vec![None],
        )
        .unwrap();
    }
    if accepted {
        job.accepted = Some(crate::fork::accept::result(&job).unwrap());
    }
    if phase == Phase::Done {
        job.result.clone_from(&job.accepted);
    }
    if phase == Phase::Failed {
        job.failure = Some(Failure::AuthorityMoved);
    }
    let raw = crate::fork::encode_job(&job).unwrap();
    batch = batch.put(keys::fork_job(&destination.name), raw).put(
        keys::fork_barrier(&destination.name),
        Value::new(job.binding.to_vec()),
    );
    // Accepted Publish must stay pending even after authority has moved. The
    // cleanup batch deliberately compares only its exact immutable receipt row.
    if phase == Phase::Publish {
        batch = batch.put(keys::authority_generation(), codec::encode_u64(1));
    }
    assert_eq!(
        store.apply(&coordinator, batch).await.unwrap(),
        BatchOutcome::Committed
    );
    job
}

async fn evidence_left(store: &MemoryKv, job: &ForkJobV1) -> usize {
    let destination = job.dest().unwrap();
    let (start, end) = keys::fork_proof_evidence_range(&destination.name);
    store
        .scan(
            &D34Shards.coordinator(&destination.namespace),
            &start,
            &end,
            None,
            100,
        )
        .await
        .unwrap()
        .entries
        .len()
}

async fn fire(store: &MemoryKv, clock: Arc<ManualClock>, job: &ForkJobV1) -> Fired {
    let destination = job.dest().unwrap();
    let coordinator = D34Shards.coordinator(&destination.namespace);
    let timer = ForkTimer {
        store: BorrowedStore(store),
        shards: Arc::new(D34Shards),
        clock,
        takedown_denial: true,
        extract_min_bytes: None,
        publication_policy: None,
    };
    timer
        .fire(
            &TimerCtx {
                store,
                partition: &coordinator,
                now_ms: 0,
                continuation_deadline_ms: None,
            },
            &DueTimer {
                due_at_ms: 0,
                kind: kinds::FORK,
                reference: keys::fork_job(&destination.name).as_bytes().to_vec().into(),
                value: Value::default(),
            },
        )
        .await
        .unwrap()
}

#[test]
fn timer_reclaims_multiple_pages_for_done_failed_and_authority_blocked_activation() {
    block_on(async {
        for phase in [Phase::Done, Phase::Failed, Phase::Publish] {
            let clock = Arc::new(ManualClock::new(0));
            let store = MemoryKv::with_clock(clock.clone());
            let job = seed(&store, phase, phase != Phase::Failed).await;
            let destination = job.dest().unwrap();
            let coordinator = D34Shards.coordinator(&destination.namespace);
            let raw = store
                .get(&coordinator, &keys::fork_job(&destination.name))
                .await
                .unwrap();
            assert!(matches!(
                fire(&store, clock.clone(), &job).await,
                Fired::Reschedule { .. }
            ));
            assert_eq!(evidence_left(&store, &job).await, 19);
            // Every invocation constructs a replacement handler; no local cursor
            // remembers which page was durably deleted.
            assert!(matches!(
                fire(&store, clock.clone(), &job).await,
                Fired::Reschedule { .. }
            ));
            assert_eq!(evidence_left(&store, &job).await, 3);
            let outcome = fire(&store, clock, &job).await;
            assert_eq!(evidence_left(&store, &job).await, 0);
            if phase == Phase::Publish {
                assert!(matches!(outcome, Fired::Reschedule { .. }));
            } else if phase == Phase::Done {
                // The synthetic barrier is retained deliberately, but there
                // are no permits to release; metadata cleanup cannot clear it.
                assert!(matches!(outcome, Fired::Done(_)));
            } else {
                assert!(matches!(outcome, Fired::Done(_)));
            }
            assert_eq!(
                store
                    .get(&coordinator, &keys::fork_job(&destination.name))
                    .await
                    .unwrap(),
                raw
            );
            assert!(
                store
                    .get(&coordinator, &keys::fork_barrier(&destination.name))
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    });
}

#[test]
fn uncertain_cleanup_commit_and_stale_capture_cannot_resurrect_evidence() {
    block_on(async {
        let clock = Arc::new(ManualClock::new(0));
        let store = MemoryKv::with_clock(clock.clone());
        let mut old = super::evidence_tests::job();
        let mut capture = Batch::new();
        append(
            &mut old,
            &mut capture,
            &Partition::ContentShard(0),
            &[keys::denial_directory_revision()],
            vec![None],
        )
        .unwrap();
        let destination = old.dest().unwrap();
        let coordinator = D34Shards.coordinator(&destination.namespace);
        let stale_raw = crate::fork::encode_job(&old).unwrap();
        let stale = capture
            .require(Precondition::Equals(
                keys::fork_job(&destination.name),
                stale_raw.clone(),
            ))
            .put(keys::fork_job(&destination.name), stale_raw);
        let job = seed(&store, Phase::Done, true).await;
        let store = store.with_fault(MemoryFault::ApplyAfterCommit);
        assert!(
            cleanup(
                &environment(&store, &clock),
                &destination,
                &SliceBudget::new(600)
            )
            .await
            .is_err()
        );
        assert_eq!(
            evidence_left(&store, &job).await,
            19,
            "lost reply still deleted its page"
        );
        assert!(matches!(
            store.apply(&coordinator, stale).await.unwrap(),
            BatchOutcome::PreconditionFailed { .. }
        ));
        assert_eq!(evidence_left(&store, &job).await, 19);
        assert!(
            !cleanup(
                &environment(&store, &clock),
                &destination,
                &SliceBudget::new(600)
            )
            .await
            .unwrap()
        );
        assert!(
            cleanup(
                &environment(&store, &clock),
                &destination,
                &SliceBudget::new(600)
            )
            .await
            .unwrap()
        );
        assert_eq!(evidence_left(&store, &job).await, 0);
    });
}

#[test]
fn malformed_cleanup_evidence_is_retained_and_unaccepted_work_is_untouched() {
    block_on(async {
        let clock = Arc::new(ManualClock::new(0));
        let store = MemoryKv::with_clock(clock.clone());
        let mut job = seed(&store, Phase::Accept, false).await;
        let destination = job.dest().unwrap();
        let coordinator = D34Shards.coordinator(&destination.namespace);
        assert!(
            !cleanup(
                &environment(&store, &clock),
                &destination,
                &SliceBudget::new(600)
            )
            .await
            .unwrap()
        );
        assert_eq!(evidence_left(&store, &job).await, 35);
        job.phase = Phase::Failed;
        let bad = encode(&Evidence {
            binding: [9; 32],
            ordinal: 0,
            partition: Partition::ContentShard(0).encode().unwrap().to_vec(),
            observations: vec![Observation {
                key: keys::denial_directory_revision().as_bytes().to_vec(),
                value: None,
            }],
        })
        .unwrap();
        store
            .apply(
                &coordinator,
                Batch::new()
                    .put(
                        keys::fork_job(&destination.name),
                        crate::fork::encode_job(&job).unwrap(),
                    )
                    .put(keys::fork_proof_evidence(&destination.name, 0), bad),
            )
            .await
            .unwrap();
        assert!(
            cleanup(
                &environment(&store, &clock),
                &destination,
                &SliceBudget::new(600)
            )
            .await
            .is_err()
        );
        assert_eq!(evidence_left(&store, &job).await, 35);
    });
}

#[test]
fn cleanup_obeys_the_existing_call_allowance() {
    block_on(async {
        let clock = Arc::new(ManualClock::new(0));
        let store = MemoryKv::with_clock(clock.clone());
        let job = seed(&store, Phase::Failed, false).await;
        let budget = SliceBudget::new(2);
        assert!(
            !cleanup(&environment(&store, &clock), &job.dest().unwrap(), &budget)
                .await
                .unwrap()
        );
        assert_eq!(budget.used(), 0);
        let budget = SliceBudget::new(3);
        assert!(
            !cleanup(&environment(&store, &clock), &job.dest().unwrap(), &budget)
                .await
                .unwrap()
        );
        assert_eq!(budget.used(), 3);
        assert_eq!(evidence_left(&store, &job).await, 19);
    });
}

#[test]
fn first_acceptance_or_failure_in_a_tick_also_starts_cleanup() {
    block_on(async {
        for accept in [false, true] {
            let clock = Arc::new(ManualClock::new(1));
            let store = MemoryKv::with_clock(clock.clone());
            let mut job = seed(&store, Phase::Accept, false).await;
            if accept {
                // The certificate is already durable. The absent sealed
                // inventory stops subsequent activation, retaining acceptance.
                job.proof.stage = Stage::Complete;
            } else {
                job.expires_ms = 0;
            }
            let destination = job.dest().unwrap();
            let coordinator = D34Shards.coordinator(&destination.namespace);
            store
                .apply(
                    &coordinator,
                    Batch::new().put(
                        keys::fork_job(&destination.name),
                        crate::fork::encode_job(&job).unwrap(),
                    ),
                )
                .await
                .unwrap();
            assert!(matches!(
                fire(&store, clock, &job).await,
                Fired::Reschedule { .. }
            ));
            assert_eq!(evidence_left(&store, &job).await, 19);
            let saved = crate::fork::decode_job(
                &store
                    .get(&coordinator, &keys::fork_job(&destination.name))
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            if accept {
                assert!(saved.accepted.is_some());
                assert_eq!(saved.phase, Phase::Publish);
            } else {
                assert_eq!(saved.phase, Phase::Failed);
            }
        }
    });
}

#[test]
fn cleanup_respects_backend_reserved_operations() {
    block_on(async {
        let clock = Arc::new(ManualClock::new(0));
        let store = MemoryKv::with_clock(clock.clone());
        let job = seed(&store, Phase::Done, true).await;
        let mut caps = store.capabilities();
        caps.reserved_batch_ops = 70;
        let store = store.with_capabilities(caps);
        let destination = job.dest().unwrap();
        for remaining in [22, 9, 0] {
            let complete = cleanup(
                &environment(&store, &clock),
                &destination,
                &SliceBudget::new(600),
            )
            .await
            .unwrap();
            assert_eq!(evidence_left(&store, &job).await, remaining);
            assert_eq!(complete, remaining == 0);
        }
    });
}

#[test]
fn cleanup_shrinks_its_prefix_to_fit_evidence_value_guards() {
    block_on(async {
        let clock = Arc::new(ManualClock::new(0));
        let store = MemoryKv::with_clock(clock.clone());
        let mut job = super::evidence_tests::job();
        job.phase = Phase::Done;
        job.accepted = Some(crate::fork::accept::result(&job).unwrap());
        job.result.clone_from(&job.accepted);
        let destination = job.dest().unwrap();
        let coordinator = D34Shards.coordinator(&destination.namespace);
        for _ in 0..8 {
            let mut batch = Batch::new();
            append(
                &mut job,
                &mut batch,
                &Partition::ContentShard(0),
                &[keys::denial_directory_revision()],
                vec![Some(Value::new(vec![b'x'; 60_000]))],
            )
            .unwrap();
            assert_eq!(
                store.apply(&coordinator, batch).await.unwrap(),
                BatchOutcome::Committed
            );
        }
        store
            .apply(
                &coordinator,
                Batch::new().put(
                    keys::fork_job(&destination.name),
                    crate::fork::encode_job(&job).unwrap(),
                ),
            )
            .await
            .unwrap();
        assert!(
            !cleanup(
                &environment(&store, &clock),
                &destination,
                &SliceBudget::new(600)
            )
            .await
            .unwrap()
        );
        let remaining = evidence_left(&store, &job).await;
        assert!(
            remaining > 0 && remaining < 8,
            "a fitting prefix must commit"
        );
        let saved = crate::fork::decode_job(
            &store
                .get(&coordinator, &keys::fork_job(&destination.name))
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            saved.proof.evidence, 8,
            "partial prefix is not complete cleanup"
        );
        assert!(
            cleanup(
                &environment(&store, &clock),
                &destination,
                &SliceBudget::new(600)
            )
            .await
            .unwrap()
        );
        assert_eq!(evidence_left(&store, &job).await, 0);
    });
}

#[test]
fn done_and_write_barrier_clearance_wait_for_transient_evidence_cleanup() {
    block_on(async {
        let clock = Arc::new(ManualClock::new(0));
        let store = MemoryKv::with_clock(clock.clone());
        let mut job = seed(&store, Phase::Publish, true).await;
        // Every membership activation unit is already durably finished; this
        // driver owns only the remaining cleanup and terminal clearance.
        job.cursor = u32::try_from(job.packs.len()).unwrap();
        let destination = job.dest().unwrap();
        let coordinator = D34Shards.coordinator(&destination.namespace);
        store
            .apply(
                &coordinator,
                Batch::new().delete(keys::authority_generation()).put(
                    keys::fork_job(&destination.name),
                    crate::fork::encode_job(&job).unwrap(),
                ),
            )
            .await
            .unwrap();
        for expected in [19, 3] {
            let report = crate::fork::step(
                &environment(&store, &clock),
                &destination,
                &SliceBudget::new(44),
            )
            .await
            .unwrap();
            assert_eq!(report.job.phase, Phase::Publish);
            assert_eq!(evidence_left(&store, &job).await, expected);
            assert!(
                store
                    .get(&coordinator, &keys::fork_barrier(&destination.name))
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        let report = crate::fork::step(
            &environment(&store, &clock),
            &destination,
            &SliceBudget::new(44),
        )
        .await
        .unwrap();
        assert_eq!(report.job.phase, Phase::Done);
        assert_eq!(report.job.result, job.accepted);
        assert!(
            store
                .get(&coordinator, &keys::fork_barrier(&destination.name))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(evidence_left(&store, &job).await, 0);
    });
}
