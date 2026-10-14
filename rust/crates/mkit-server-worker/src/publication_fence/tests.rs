use super::*;
use crate::sql::SqlKvStore;
use crate::test_sqlite::RusqliteConn;
use futures::executor::block_on;
use mkit_server::ManualClock;
use mkit_server::pipeline::{D34Shards, ShardMap};
use mkit_server::store::adapter_spi::publication_fence::SourceStatus;
use mkit_server::store::adapter_spi::{codec, keys};
use mkit_server::telemetry::NoopMetrics;
use mkit_server::timers::registry::kinds;
use mkit_server::{Cursor, Key, PartitionStats, ScanPage, StoreCapabilities, Value};
use mkit_server::{NamespaceKey, Precondition, RepoName};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("writer").expect("valid fixture repository"),
    }
}
fn generation() -> Generation {
    Generation {
        incarnation: [42; 32],
        number: 1,
    }
}
fn source() -> Partition {
    D34Shards.ref_shard(&repo(), "refs/heads/main")
}
fn publication() -> Batch {
    Batch::new()
        .require(Precondition::Absent(keys::outbox_sequence()))
        .put(keys::outbox_sequence(), codec::encode_u64(1))
        .put(
            keys::published_ref(&repo().name, "refs/heads/main"),
            codec::encode_ref_id(&[1; 32]),
        )
        .put(
            keys::relay(1),
            codec::encode_relay(&codec::RelayV1 {
                at_ms: 1_000,
                target: D34Shards.ref_index(&repo(), "refs/heads/main"),
                puts: vec![(
                    keys::published_index(&repo().name, "refs/heads/main"),
                    codec::encode_ref_id(&[1; 32]),
                )],
                deletes: Vec::new(),
            })
            .expect("valid paired publication relay"),
        )
}
async fn fixture() -> SqlKvStore<RusqliteConn> {
    let store = SqlKvStore::open(RusqliteConn::open_in_memory().expect("open fixture connection"))
        .expect("open fixture store");
    PublicationFence::new(&repo())
        .initialize(&store, generation())
        .await
        .expect("initialize fixture authority");
    store
}

#[test]
fn writer_commits_the_exact_publication_and_keeps_relay_pending() {
    block_on(async {
        let store = fixture().await;
        let writer = PublicationWriter::new(&repo(), generation());
        assert_eq!(
            writer
                .apply(&store, &source(), publication(), 2_000)
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        let fence = PublicationFence::new(&repo());
        let row = fence
            .latest_intent(&store, &source())
            .await
            .unwrap()
            .unwrap();
        assert!(!row.complete());
        assert_eq!(
            fence
                .source_marker(&store, &source())
                .await
                .unwrap()
                .unwrap()
                .status(),
            SourceStatus::Committed
        );
        assert!(fence.stable(&store).await.unwrap().is_none());
        assert!(
            store
                .get(&source(), &keys::relay(1))
                .await
                .unwrap()
                .is_some()
        );
        // Enrolled sources can no longer bypass the writer.
        assert!(
            store
                .apply(
                    &source(),
                    Batch::new().put(
                        keys::published_ref(&repo().name, "refs/heads/main"),
                        codec::encode_ref_id(&[9; 32])
                    )
                )
                .await
                .is_err()
        );
    });
}

#[test]
fn writer_preserves_original_guard_failure_without_invalidating() {
    block_on(async {
        let store = fixture().await;
        store
            .apply(
                &source(),
                Batch::new().put(keys::outbox_sequence(), codec::encode_u64(9)),
            )
            .await
            .unwrap();
        let expected = BatchOutcome::PreconditionFailed {
            index: 0,
            observed: Some(codec::encode_u64(9)),
        };
        assert_eq!(
            PublicationWriter::new(&repo(), generation())
                .apply(&store, &source(), publication(), 2_000)
                .await
                .unwrap(),
            expected
        );
        assert!(
            PublicationFence::new(&repo())
                .latest_intent(&store, &source())
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[derive(Clone, Copy)]
enum Fault {
    LostCommitReply,
    BeforeCommit,
    OriginalGuardRace,
}
struct FaultStore {
    inner: SqlKvStore<RusqliteConn>,
    fault: Fault,
    fired: AtomicBool,
}
impl NamespaceStore for FaultStore {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(p, key).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        let publishes = batch.writes.iter().any(|write| matches!(write, mkit_server::Write::Put(key,_) if matches!(keys::parse(key),Some(keys::ParsedKey::PublishedRef{..}))));
        let inject = publishes && !self.fired.swap(true, Ordering::SeqCst);
        if inject {
            match self.fault {
                Fault::BeforeCommit => {
                    return Err(StoreError::unavailable("injected before commit"));
                }
                Fault::OriginalGuardRace => {
                    self.inner
                        .apply(
                            p,
                            Batch::new().put(keys::outbox_sequence(), codec::encode_u64(9)),
                        )
                        .await?;
                }
                Fault::LostCommitReply => {}
            }
        }
        let outcome = self.inner.apply(p, batch).await?;
        if inject && matches!(self.fault, Fault::LostCommitReply) {
            return Err(StoreError::unavailable("injected lost commit reply"));
        }
        Ok(outcome)
    }
}

#[test]
fn writer_resolves_a_lost_commit_reply_from_the_durable_terminal_marker() {
    block_on(async {
        let store = FaultStore {
            inner: fixture().await,
            fault: Fault::LostCommitReply,
            fired: AtomicBool::new(false),
        };
        assert_eq!(
            PublicationWriter::new(&repo(), generation())
                .apply(&store, &source(), publication(), 2_000)
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        assert!(
            store
                .get(
                    &source(),
                    &keys::published_ref(&repo().name, "refs/heads/main")
                )
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            PublicationFence::new(&repo())
                .source_marker(&store, &source())
                .await
                .unwrap()
                .unwrap()
                .status(),
            SourceStatus::Committed
        );
    });
}

#[test]
fn writer_irreversibly_aborts_an_uncommitted_ambiguous_failure() {
    block_on(async {
        let store = FaultStore {
            inner: fixture().await,
            fault: Fault::BeforeCommit,
            fired: AtomicBool::new(false),
        };
        assert!(
            PublicationWriter::new(&repo(), generation())
                .apply(&store, &source(), publication(), 2_000)
                .await
                .is_err()
        );
        let fence = PublicationFence::new(&repo());
        let row = fence
            .latest_intent(&store, &source())
            .await
            .unwrap()
            .unwrap();
        assert!(row.complete());
        assert_eq!(
            fence
                .source_marker(&store, &source())
                .await
                .unwrap()
                .unwrap()
                .status(),
            SourceStatus::Aborted
        );
        assert!(
            store
                .get(
                    &source(),
                    &keys::published_ref(&repo().name, "refs/heads/main")
                )
                .await
                .unwrap()
                .is_none()
        );
        let mut late = publication();
        PublicationFence::source_commit_fragment(row.intent(), &mut late).unwrap();
        assert!(matches!(
            store.apply(&source(), late).await.unwrap(),
            BatchOutcome::PreconditionFailed { index: 1, .. }
        ));
    });
}

#[test]
fn writer_preserves_a_domain_guard_race_after_proven_abort() {
    block_on(async {
        let store = FaultStore {
            inner: fixture().await,
            fault: Fault::OriginalGuardRace,
            fired: AtomicBool::new(false),
        };
        assert_eq!(
            PublicationWriter::new(&repo(), generation())
                .apply(&store, &source(), publication(), 2_000)
                .await
                .unwrap(),
            BatchOutcome::PreconditionFailed {
                index: 0,
                observed: Some(codec::encode_u64(9))
            }
        );
        assert_eq!(
            PublicationFence::new(&repo())
                .source_marker(&store, &source())
                .await
                .unwrap()
                .unwrap()
                .status(),
            SourceStatus::Aborted
        );
    });
}

#[test]
fn recovery_cancels_a_crash_before_arm_and_fences_the_delayed_writer() {
    block_on(async {
        let store = fixture().await;
        let fence = PublicationFence::new(&repo());
        let plan = publication_batch(&source(), &publication())
            .unwrap()
            .unwrap();
        let intent = fence
            .begin(
                &store,
                &source(),
                1,
                plan.digest,
                plan.targets
                    .iter()
                    .map(|(p, n)| Target::new(p, *n).unwrap())
                    .collect(),
            )
            .await
            .unwrap();
        let writer = PublicationWriter::new(&repo(), generation());
        writer.recover(&store, &source()).await.unwrap();
        assert!(
            fence
                .latest_intent(&store, &source())
                .await
                .unwrap()
                .unwrap()
                .complete()
        );
        fence.arm(&store, &intent).await.unwrap_err();
        let mut late = publication();
        PublicationFence::source_commit_fragment(&intent, &mut late).unwrap();
        assert!(matches!(
            store.apply(&source(), late).await.unwrap(),
            BatchOutcome::PreconditionFailed { index: 1, .. }
        ));
        assert_eq!(
            writer
                .apply(&store, &source(), publication(), 2_000)
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        assert_eq!(
            fence
                .latest_intent(&store, &source())
                .await
                .unwrap()
                .unwrap()
                .intent()
                .attempt(),
            2
        );
    });
}

#[test]
fn recovery_never_replays_a_committed_publication_with_pending_relays() {
    block_on(async {
        let store = fixture().await;
        let writer = PublicationWriter::new(&repo(), generation());
        writer
            .apply(&store, &source(), publication(), 2_000)
            .await
            .unwrap();
        assert!(writer.recover(&store, &source()).await.is_err());
        let fence = PublicationFence::new(&repo());
        assert!(
            !fence
                .latest_intent(&store, &source())
                .await
                .unwrap()
                .unwrap()
                .complete()
        );
        assert_eq!(
            codec::decode_u64(
                &store
                    .get(&source(), &keys::outbox_sequence())
                    .await
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            1
        );
    });
}

#[test]
fn writer_refuses_a_changed_external_generation_before_publication() {
    block_on(async {
        let store = fixture().await;
        let changed = Generation {
            incarnation: [43; 32],
            number: 1,
        };
        PublicationFence::new(&repo())
            .rotate(&store, changed)
            .await
            .unwrap();
        assert!(
            PublicationWriter::new(&repo(), generation())
                .apply(&store, &source(), publication(), 2_000)
                .await
                .is_err()
        );
        assert!(
            store
                .get(
                    &source(),
                    &keys::published_ref(&repo().name, "refs/heads/main")
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            PublicationFence::new(&repo())
                .latest_intent(&store, &source())
                .await
                .unwrap()
                .is_none()
        );
    });
}

struct PublishOnAlarm;
impl<S: NamespaceStore> mkit_server::timers::TimerHandler<S> for PublishOnAlarm {
    fn kind(&self) -> mkit_server::timers::TimerKind {
        mkit_server::timers::TimerKind::new(0xF0)
    }
    fn fire<'a>(
        &'a self,
        _: &'a mkit_server::timers::TimerCtx<'a, S>,
        _: &'a mkit_server::timers::DueTimer,
    ) -> BoxFuture<'a, Result<mkit_server::timers::Fired, StoreError>> {
        Box::pin(async {
            Ok(mkit_server::timers::Fired::Done(publication().put(
                keys::timer(1_000, kinds::RELAY.get(), b""),
                Value::default(),
            )))
        })
    }
}

async fn empty_sealed_authority(
    clock: std::sync::Arc<mkit_server::ManualClock>,
) -> (
    std::sync::Arc<mkit_server::MemoryKv>,
    mkit_server::store::adapter_spi::publication_fence::StableToken,
) {
    let remote = std::sync::Arc::new(mkit_server::MemoryKv::with_clock(clock));
    let fence = PublicationFence::new(&repo());
    fence
        .initialize(remote.as_ref(), generation())
        .await
        .expect("initialize empty fixture authority");
    // Controlled empty fixture has no legacy writer or queued relay.
    let ready = fence
        .bootstrap_ready_batch(remote.as_ref())
        .await
        .expect("prepare empty bootstrap cut");
    remote
        .apply(&Partition::Coordinator(repo().namespace), ready)
        .await
        .expect("write bootstrap cut");
    let receipt = fence
        .verify_bootstrap(remote.as_ref())
        .await
        .expect("verify actual readiness");
    fence
        .seal(remote.as_ref(), &receipt)
        .await
        .expect("seal empty fixture");
    let token = fence
        .stable(remote.as_ref())
        .await
        .expect("read stable authority")
        .expect("fixture is sealed");
    (remote, token)
}

#[test]
fn pressure_store_routes_authority_remotely_and_completes_real_relay_alarm() {
    use crate::{alarm::run_physical_alarm, classes::ShardClass, ns_object::PressureStore};
    use mkit_server::relay::{NoHook, RelayBudget, RelayHandler};
    use mkit_server::timers::{TickBudget, TimerRegistry, registry::kinds};
    block_on(async {
        for publish_from_alarm in [false, true] {
            let clock = Arc::new(ManualClock::new(1_000));
            let (remote, before) = empty_sealed_authority(clock.clone()).await;
            let fence = PublicationFence::new(&repo());
            let conn = RusqliteConn::open_in_memory().unwrap();
            let local = SqlKvStore::open(conn.clone()).unwrap();
            let store = PressureStore::new(
                local,
                ShardClass::RefShard,
                clock.clone(),
                Arc::new(NoopMetrics),
            )
            .with_publication_store(remote.clone(), generation());
            let batch = publication().put(
                keys::timer(1_000, kinds::RELAY.get(), b""),
                Value::default(),
            );
            if publish_from_alarm {
                store
                    .apply(
                        &source(),
                        Batch::new().put(keys::timer(1_000, 0xF0, b"publish"), Value::default()),
                    )
                    .await
                    .unwrap();
                let registry = TimerRegistry::new().register(PublishOnAlarm);
                let report = run_physical_alarm(
                    &store,
                    &registry,
                    clock.as_ref(),
                    1_000,
                    TickBudget::default(),
                    &mut None,
                )
                .await
                .unwrap();
                assert_eq!(report.committed, 1);
            } else {
                assert_eq!(
                    store.apply(&source(), batch).await.unwrap(),
                    BatchOutcome::Committed
                );
            }
            assert!(fence.stable(remote.as_ref()).await.unwrap().is_none());
            // The source marker is local; coordinator authority did not leak into
            // the source object's SQLite or vice versa.
            assert!(
                fence
                    .source_marker(remote.as_ref(), &source())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                fence
                    .generation(&SqlKvStore::open(conn).unwrap())
                    .await
                    .is_err()
            );
            let registry = TimerRegistry::new().register(RelayHandler {
                target: remote.clone(),
                hook: NoHook,
                budget: RelayBudget::default(),
            });
            let report = run_physical_alarm(
                &store,
                &registry,
                clock.as_ref(),
                1_000,
                TickBudget::default(),
                &mut None,
            )
            .await
            .unwrap();
            assert!(report.committed > 0);
            assert!(
                store
                    .get(&source(), &keys::relay(1))
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                remote
                    .get(
                        &D34Shards.ref_index(&repo(), "refs/heads/main"),
                        &keys::published_index(&repo().name, "refs/heads/main")
                    )
                    .await
                    .unwrap(),
                Some(codec::encode_ref_id(&[1; 32]))
            );
            let after = fence.stable(remote.as_ref()).await.unwrap().unwrap();
            assert_eq!(before.generation, after.generation);
            assert!(after.revision > before.revision);
        }
    });
}

#[test]
fn physical_coordinator_alarm_recovers_crash_before_local_arm() {
    use crate::{alarm::run_physical_alarm, classes::ShardClass, ns_object::PressureStore};
    use mkit_server::telemetry::NoopMetrics;
    use mkit_server::timers::{TickBudget, TimerRegistry};
    use mkit_server::{ManualClock, MemoryKv};
    use std::sync::Arc;
    block_on(async {
        let clock = Arc::new(ManualClock::new(2_000));
        let remote = Arc::new(MemoryKv::with_clock(clock.clone()));
        let store = PressureStore::new(
            SqlKvStore::open(RusqliteConn::open_in_memory().unwrap()).unwrap(),
            ShardClass::NsCoordinator,
            clock.clone(),
            Arc::new(NoopMetrics),
        );
        let fence = PublicationFence::new(&repo());
        fence.initialize(&store, generation()).await.unwrap();
        let plan = publication_batch(&source(), &publication())
            .unwrap()
            .unwrap();
        let intent = fence
            .begin_with_recovery(
                &store,
                &source(),
                1,
                plan.digest,
                plan.targets
                    .iter()
                    .map(|(p, n)| Target::new(p, *n).unwrap())
                    .collect(),
                2_000,
            )
            .await
            .unwrap();
        let registry = TimerRegistry::new().register(RecoveryHandler {
            remote: remote.clone(),
            generation: generation(),
        });
        let report = run_physical_alarm(
            &store,
            &registry,
            clock.as_ref(),
            2_000,
            TickBudget::default(),
            &mut None,
        )
        .await
        .unwrap();
        assert_eq!(report.committed, 1);
        assert!(
            fence
                .latest_intent(&store, &source())
                .await
                .unwrap()
                .unwrap()
                .complete()
        );
        assert_eq!(
            fence
                .source_marker(remote.as_ref(), &source())
                .await
                .unwrap()
                .unwrap()
                .status(),
            SourceStatus::Aborted
        );
        assert!(
            remote
                .get(
                    &source(),
                    &keys::published_ref(&repo().name, "refs/heads/main")
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.timer_window(None, 64).unwrap().is_empty());
        let mut late = publication();
        PublicationFence::source_commit_fragment(&intent, &mut late).unwrap();
        assert!(matches!(
            remote.apply(&source(), late).await.unwrap(),
            BatchOutcome::PreconditionFailed { index: 1, .. }
        ));
    });
}

#[test]
fn stale_physical_recovery_wake_cannot_abort_a_newer_armed_attempt() {
    use crate::{alarm::run_physical_alarm, classes::ShardClass, ns_object::PressureStore};
    use mkit_server::telemetry::NoopMetrics;
    use mkit_server::timers::{TickBudget, TimerRegistry};
    use mkit_server::{ManualClock, MemoryKv};
    use std::sync::Arc;
    block_on(async {
        let clock = Arc::new(ManualClock::new(2_000));
        let remote = Arc::new(MemoryKv::with_clock(clock.clone()));
        let store = PressureStore::new(
            SqlKvStore::open(RusqliteConn::open_in_memory().unwrap()).unwrap(),
            ShardClass::NsCoordinator,
            clock.clone(),
            Arc::new(NoopMetrics),
        );
        let routed = RoutedStore {
            local: &store,
            remote: &remote,
            partition: &Partition::Coordinator(repo().namespace),
        };
        let fence = PublicationFence::new(&repo());
        fence.initialize(&routed, generation()).await.unwrap();
        let plan = publication_batch(&source(), &publication())
            .unwrap()
            .unwrap();
        let targets = plan
            .targets
            .iter()
            .map(|(p, n)| Target::new(p, *n).unwrap())
            .collect::<Vec<_>>();
        let old = fence
            .begin_with_recovery(&routed, &source(), 1, plan.digest, targets.clone(), 2_000)
            .await
            .unwrap();
        fence.arm(&routed, &old).await.unwrap();
        let mut abort = Batch::new();
        PublicationFence::source_abort_fragment(&old, &mut abort).unwrap();
        routed.apply(&source(), abort).await.unwrap();
        fence.reconcile_delivered(&routed, &old).await.unwrap();
        let current = fence
            .begin_with_recovery(&routed, &source(), 2, plan.digest, targets, 3_000)
            .await
            .unwrap();
        fence.arm(&routed, &current).await.unwrap();
        let registry = TimerRegistry::new().register(RecoveryHandler {
            remote: remote.clone(),
            generation: generation(),
        });
        let report = run_physical_alarm(
            &store,
            &registry,
            clock.as_ref(),
            2_000,
            TickBudget::default(),
            &mut None,
        )
        .await
        .unwrap();
        assert_eq!(report.committed, 1);
        assert_eq!(
            fence
                .source_marker(&routed, &source())
                .await
                .unwrap()
                .unwrap()
                .status(),
            SourceStatus::Armed
        );
        let mut commit = publication();
        PublicationFence::source_commit_fragment(&current, &mut commit).unwrap();
        assert_eq!(
            routed.apply(&source(), commit).await.unwrap(),
            BatchOutcome::Committed
        );
    });
}
