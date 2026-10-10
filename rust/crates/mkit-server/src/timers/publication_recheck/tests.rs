use super::*;
use crate::repo::RepoName;
use crate::rt::ManualClock;
use crate::store::publication::{Obligation, Pair};
use crate::store::{BatchOutcome, Cursor, PartitionStats, ScanPage, StoreCapabilities, Value};
use crate::timers::{RunReport, TickBudget, TimerRegistry, run_due};
use crate::{MemoryKv, NamespaceKey};
use futures_executor::block_on;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

const NAME: &str = "refs/heads/main";
const WHOLE_ALARM_CALLS: u32 = 1_000;

#[derive(Clone)]
struct CountedTarget {
    kv: Arc<MemoryKv>,
    calls: Arc<AtomicU32>,
    reads: Arc<Mutex<Vec<Partition>>>,
    pages: Arc<Mutex<Vec<Vec<Key>>>>,
    race: Arc<Mutex<Option<(Partition, Batch)>>>,
}

impl CountedTarget {
    fn new(kv: Arc<MemoryKv>) -> Self {
        Self {
            kv,
            calls: Arc::default(),
            reads: Arc::default(),
            pages: Arc::default(),
            race: Arc::default(),
        }
    }

    fn reset(&self) {
        self.calls.store(0, Ordering::SeqCst);
        self.reads.lock().unwrap().clear();
        self.pages.lock().unwrap().clear();
    }

    fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl NamespaceStore for CountedTarget {
    fn capabilities(&self) -> StoreCapabilities {
        self.kv.capabilities()
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.kv.get(p, key).await
    }

    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        let calls = self.calls.fetch_add(1, Ordering::SeqCst);
        if calls >= WHOLE_ALARM_CALLS {
            return Err(StoreError::unavailable(
                "whole-alarm routed call allowance exhausted",
            ));
        }
        self.reads.lock().unwrap().push(p.clone());
        self.pages.lock().unwrap().push(keys.to_vec());
        let race = self.race.lock().unwrap().take();
        if let Some((partition, batch)) = race {
            assert_eq!(
                self.kv.apply(&partition, batch).await?,
                BatchOutcome::Committed
            );
        }
        self.kv.get_many(p, keys).await
    }

    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.kv.scan(p, start, end, after, limit).await
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.kv.apply(p, batch).await
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.kv.stats(p).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.kv.probe().await
    }
}

struct Fixture {
    kv: Arc<MemoryKv>,
    clock: Arc<ManualClock>,
    target: CountedTarget,
    repo: RepoId,
    source: Partition,
    dependencies: Vec<[u8; 32]>,
}

impl Fixture {
    async fn new(count: u16) -> Self {
        let clock = Arc::new(ManualClock::new(0));
        let kv = Arc::new(MemoryKv::with_clock(clock.clone()));
        let repo = RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new("resumable").unwrap(),
        };
        let source = D34Shards.ref_shard(&repo, NAME);
        // D34 routes a repository's index over sixteen shards by the top four
        // bits of the pack id. Spread the packs evenly over all sixteen, so
        // a position is one key and every eight positions of a shard are one
        // routed page. Pack order is then shard-major, which is also the order
        // the recheck walks its dependencies in.
        let mut dependencies = (0..count)
            .map(|n| {
                let mut pack = [0; 32];
                pack[0] = u8::try_from(n & 15).unwrap() << 4;
                pack[1] = u8::try_from(n >> 4).unwrap();
                pack[31] = 1;
                pack
            })
            .collect::<Vec<_>>();
        dependencies.sort_unstable();
        let packmap = mkit_core::transfer::encode_packlist(None, &dependencies).unwrap();
        assert_eq!(
            mkit_core::transfer::decode_packlist(&packmap)
                .unwrap()
                .packs,
            dependencies
        );
        let packmap_id = mkit_core::hash::hash(&packmap);
        let advance = Advance {
            sequence: 1,
            generation: 0,
            value: Pair {
                head: Some([253; 32]),
                packmap: Some(packmap_id),
            },
            additions: vec![packmap_id],
            dependencies: dependencies.clone(),
            external_bases: vec![],
            obligations: vec![],
            state: Clearance::Pending,
            operation: [255; 32],
        };
        let mut outbox = OutboxBuilder::new(None, None).unwrap();
        let mut batch = Batch::new();
        publication::append(
            &repo,
            NAME,
            &source,
            &D34Shards,
            None,
            advance,
            false,
            &mut batch.preconditions,
            &mut batch.writes,
            &mut outbox,
        )
        .unwrap();
        outbox.relay_at(0);
        outbox
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .unwrap();
        assert_eq!(
            kv.apply(&source, batch).await.unwrap(),
            BatchOutcome::Committed
        );
        let target = CountedTarget::new(kv.clone());
        Self {
            kv,
            clock,
            target,
            repo,
            source,
            dependencies,
        }
    }

    async fn witness(&self, position: usize, generation: u64, visible: bool) {
        let pack = self.dependencies[position];
        let partition = D34Shards.membership(&self.repo, &BlobKey::pack(pack));
        let key = keys::published_member(&self.repo.name, &pack);
        let witness = Witness {
            generation,
            sequence: 1,
            published: visible,
            held: false,
            boundary: false,
        };
        assert_eq!(
            self.kv
                .apply(&partition, Batch::new().put(key, witness.encode()))
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
    }

    async fn populate(&self, generation: u64) {
        for position in 0..self.dependencies.len() {
            self.witness(position, generation, true).await;
        }
    }

    async fn remove_witness(&self, position: usize) {
        let pack = self.dependencies[position];
        let partition = D34Shards.membership(&self.repo, &BlobKey::pack(pack));
        let key = keys::published_member(&self.repo.name, &pack);
        assert_eq!(
            self.kv
                .apply(&partition, Batch::new().delete(key))
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
    }

    fn advance_key(&self) -> Key {
        keys::advance(&self.repo.name, NAME, 1)
    }

    async fn advance(&self) -> Advance {
        Advance::decode(
            &self
                .kv
                .get(&self.source, &self.advance_key())
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    }

    async fn published(&self) -> u64 {
        publication::read(&self.kv, &self.source, &self.repo.name, NAME)
            .await
            .unwrap()
            .published
    }

    async fn timer(&self) -> (Key, Value) {
        let (start, end) = keys::class_range(keys::TAG_TIMER);
        let entries = self
            .kv
            .scan(&self.source, &start, &end, None, 64)
            .await
            .unwrap()
            .entries;
        entries
            .into_iter()
            .find(|(key, _)| {
                matches!(
                    keys::parse(key),
                    Some(keys::ParsedKey::Timer { kind: 12, .. })
                )
            })
            .unwrap()
    }

    async fn fire(&self, at: u64) -> RunReport {
        self.clock.set(i64::try_from(at).unwrap());
        self.target.reset();
        // Reconstruct the handler for every fire. Only the durable timer row
        // can preserve progress between these simulated adapter restarts.
        let registry = TimerRegistry::new().register(PublicationRecheck {
            target: self.target.clone(),
        });
        run_due(
            &self.kv,
            &self.source,
            &registry,
            self.clock.as_ref(),
            at,
            &TickBudget::default(),
        )
        .await
        .unwrap()
    }
}

#[test]
fn late_witness_resumes_at_the_blocked_page_instead_of_restarting() {
    block_on(async {
        let fixture = Fixture::new(2_560).await;
        fixture.populate(0).await;
        fixture.remove_witness(1_100).await;
        assert_eq!(fixture.fire(0).await.fired, 1);
        assert_eq!(fixture.target.calls(), MAX_RECHECK_CALLS);
        assert_eq!(fixture.fire(5_000).await.fired, 1);
        // Positions 1,024..=1,103 are ten routed pages; the tenth holds the gap.
        assert_eq!(fixture.target.calls(), 10);
        assert_eq!(fixture.published().await, 0);
        let blocked = fixture.timer().await;
        assert_eq!(fixture.fire(10_000).await.fired, 1);
        assert_eq!(fixture.target.calls(), 1);
        assert_eq!(
            fixture.timer().await.1,
            blocked.1,
            "an absent witness cannot waive work"
        );
        fixture.witness(1_100, 0, true).await;
        assert_eq!(fixture.fire(15_000).await.fired, 1);
        assert_eq!(fixture.target.calls(), MAX_RECHECK_CALLS);
        assert_eq!(fixture.fire(20_000).await.fired, 1);
        // 183 pages remain from position 1,100; 128 were read in the fire before.
        assert_eq!(fixture.target.calls(), 55);
        assert_eq!(fixture.published().await, 1);
    });
}

#[test]
fn restart_mid_recheck_reads_the_next_witness_from_the_durable_timer() {
    block_on(async {
        let fixture = Fixture::new(2_560).await;
        fixture.populate(0).await;
        assert_eq!(fixture.fire(0).await.fired, 1);
        let (key, value) = fixture.timer().await;
        assert!(!value.as_bytes().is_empty(), "progress must be durable");
        assert_eq!(fixture.target.calls(), MAX_RECHECK_CALLS);
        // fire() creates an entirely new handler/registry each time.
        assert_eq!(fixture.fire(5_000).await.fired, 1);
        assert_eq!(fixture.target.calls(), MAX_RECHECK_CALLS);
        assert_eq!(
            fixture.target.reads.lock().unwrap().first(),
            Some(&D34Shards.membership(&fixture.repo, &BlobKey::pack(fixture.dependencies[1_024])))
        );
        assert!(
            fixture
                .kv
                .get(&fixture.source, &key)
                .await
                .unwrap()
                .is_none()
        );
        assert_ne!(fixture.timer().await.1, value);
        assert_eq!(fixture.fire(10_000).await.fired, 1);
        assert_eq!(fixture.target.calls(), 64);
        assert_eq!(fixture.published().await, 1);
    });
}

#[test]
fn generation_change_invalidates_already_checked_witnesses() {
    block_on(async {
        let fixture = Fixture::new(2_560).await;
        fixture.populate(0).await;
        assert_eq!(fixture.fire(0).await.fired, 1);
        assert_eq!(fixture.target.calls(), MAX_RECHECK_CALLS);
        let mut advance = fixture.advance().await;
        advance.generation = 1;
        let mut state = publication::read(&fixture.kv, &fixture.source, &fixture.repo.name, NAME)
            .await
            .unwrap();
        state.generation = 1;
        assert_eq!(
            fixture
                .kv
                .apply(
                    &fixture.source,
                    Batch::new()
                        .put(fixture.advance_key(), advance.encode().unwrap())
                        .put(
                            keys::publication(&fixture.repo.name, NAME),
                            state.encode().unwrap()
                        )
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        fixture.populate(1).await;
        fixture.witness(0, 0, true).await;
        assert_eq!(fixture.fire(5_000).await.fired, 1);
        assert_eq!(
            fixture.target.calls(),
            1,
            "stale generation cursor skipped the first witness"
        );
        assert_eq!(fixture.published().await, 0);
        fixture.witness(0, 1, true).await;
        for fire in 2..5 {
            assert_eq!(fixture.fire(fire * publication::RECHECK_MS).await.fired, 1);
            assert!(fixture.target.calls() <= MAX_RECHECK_CALLS);
        }
        assert_eq!(fixture.published().await, 1);
    });
}

#[test]
fn dependency_change_invalidates_the_cursor_before_an_earlier_missing_witness() {
    block_on(async {
        let fixture = Fixture::new(2_560).await;
        fixture.populate(0).await;
        assert_eq!(fixture.fire(0).await.fired, 1);
        let mut advance = fixture.advance().await;
        let mut earlier = fixture.dependencies[0];
        earlier[31] = 0;
        advance.external_bases.push(earlier);
        assert_eq!(
            fixture
                .kv
                .apply(
                    &fixture.source,
                    Batch::new().put(fixture.advance_key(), advance.encode().unwrap())
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        assert_eq!(fixture.fire(5_000).await.fired, 1);
        assert_eq!(fixture.target.calls(), 1);
        assert_eq!(
            fixture.published().await,
            0,
            "new external delta witness was skipped"
        );
    });
}

#[test]
fn replaced_obligation_invalidates_the_cursor_and_pending_obligations_never_waive_work() {
    block_on(async {
        let fixture = Fixture::new(2_560).await;
        fixture.populate(0).await;
        assert_eq!(fixture.fire(0).await.fired, 1);
        let mut advance = fixture.advance().await;
        advance.obligations.push(Obligation {
            id: [11; 32],
            state: Clearance::Pending,
        });
        assert_eq!(
            fixture
                .kv
                .apply(
                    &fixture.source,
                    Batch::new().put(fixture.advance_key(), advance.encode().unwrap())
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        assert_eq!(fixture.fire(5_000).await.fired, 1);
        assert_eq!(fixture.target.calls(), 0);
        assert_eq!(fixture.published().await, 0);
        // A new cleared identity permits checking again, but cannot inherit
        // the 128 witnesses checked for the prior obligation configuration.
        advance.obligations[0] = Obligation {
            id: [12; 32],
            state: Clearance::Cleared,
        };
        assert_eq!(
            fixture
                .kv
                .apply(
                    &fixture.source,
                    Batch::new().put(fixture.advance_key(), advance.encode().unwrap())
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        fixture.witness(0, 0, false).await;
        assert_eq!(fixture.fire(10_000).await.fired, 1);
        assert_eq!(fixture.target.calls(), 1);
        assert_eq!(fixture.published().await, 0);
    });
}

#[test]
fn checkpoint_cas_rejects_concurrent_obligation_and_generation_changes() {
    block_on(async {
        for generation_change in [false, true] {
            let fixture = Fixture::new(2_560).await;
            fixture.populate(0).await;
            let before = fixture.timer().await;
            let change = if generation_change {
                let mut state =
                    publication::read(&fixture.kv, &fixture.source, &fixture.repo.name, NAME)
                        .await
                        .unwrap();
                state.generation = 1;
                Batch::new().put(
                    keys::publication(&fixture.repo.name, NAME),
                    state.encode().unwrap(),
                )
            } else {
                let mut advance = fixture.advance().await;
                advance.obligations.push(Obligation {
                    id: [3; 32],
                    state: Clearance::Pending,
                });
                Batch::new().put(fixture.advance_key(), advance.encode().unwrap())
            };
            *fixture.target.race.lock().unwrap() = Some((fixture.source.clone(), change));
            let report = fixture.fire(0).await;
            assert_eq!((report.raced, report.fired, report.failed), (1, 0, 0));
            assert_eq!(fixture.target.calls(), MAX_RECHECK_CALLS);
            assert_eq!(
                fixture.timer().await,
                (
                    keys::timer_retry(5_000, 12, fixture.advance_key().as_bytes(), 0, 1),
                    before.1
                ),
                "CAS race must retain the old cursor while backing off the timer"
            );
            assert_eq!(fixture.published().await, 0);
            assert_eq!(fixture.fire(5_000).await.fired, 1);
            assert_eq!(fixture.target.calls(), 0);
            assert_eq!(fixture.published().await, 0);
        }
    });
}

#[test]
fn completion_cas_cannot_publish_after_a_concurrent_obligation_change() {
    block_on(async {
        let fixture = Fixture::new(1).await;
        fixture.populate(0).await;
        let before = fixture.timer().await;
        let mut advance = fixture.advance().await;
        advance.obligations.push(Obligation {
            id: [7; 32],
            state: Clearance::Pending,
        });
        *fixture.target.race.lock().unwrap() = Some((
            fixture.source.clone(),
            Batch::new().put(fixture.advance_key(), advance.encode().unwrap()),
        ));
        let report = fixture.fire(0).await;
        assert_eq!((report.raced, report.fired, report.failed), (1, 0, 0));
        assert_eq!(fixture.target.calls(), 1);
        assert_eq!(
            fixture.timer().await,
            (
                keys::timer_retry(5_000, 12, fixture.advance_key().as_bytes(), 0, 1),
                before.1
            )
        );
        assert_eq!(fixture.published().await, 0);
    });
}

#[test]
fn valid_d34_packmap_at_its_maximum_completes_across_bounded_fires() {
    block_on(async {
        let fixture = Fixture::new(4_096).await;
        fixture.populate(0).await;
        // Exercise 4,096 packs plus 2,048 external bases over the sixteen
        // shards: 384 keys, or 48 pages, per shard. The audit's 8,192-ID structural maximum
        // exceeds the existing 512 KiB advance codec limit.
        let mut advance = fixture.advance().await;
        for prefix in 0..256 {
            let mut batch = Batch::new();
            for suffix in 2..=9 {
                let mut pack = fixture.dependencies[prefix * 16];
                pack[31] = suffix;
                advance.external_bases.push(pack);
                batch = batch.put(
                    keys::published_member(&fixture.repo.name, &pack),
                    Witness {
                        generation: 0,
                        sequence: 1,
                        published: true,
                        held: false,
                        boundary: false,
                    }
                    .encode(),
                );
            }
            let partition = D34Shards.membership(
                &fixture.repo,
                &BlobKey::pack(fixture.dependencies[prefix * 16]),
            );
            fixture.kv.apply(&partition, batch).await.unwrap();
        }
        fixture
            .kv
            .apply(
                &fixture.source,
                Batch::new().put(fixture.advance_key(), advance.encode().unwrap()),
            )
            .await
            .unwrap();
        let mut total_calls = 0;
        for fire in 0..40 {
            let report = fixture.fire(fire * publication::RECHECK_MS).await;
            assert_eq!(
                report.failed, 0,
                "timer stalled at alarm allowance on fire {fire}"
            );
            assert_eq!(report.fired, 1);
            assert!(fixture.target.calls() <= WHOLE_ALARM_CALLS);
            assert!(fixture.target.calls() <= MAX_RECHECK_CALLS);
            total_calls += fixture.target.calls();
            if fixture.published().await == 1 {
                assert!(fire > 0, "more than one bounded fire is needed");
                assert_eq!(fire, 5, "768 calls need exactly 6 bounded fires");
                assert_eq!(total_calls, 768, "already-checked witnesses were reread");
                return;
            }
        }
        panic!("valid retained publication never completed");
    });
}

#[test]
fn shared_whole_alarm_allowance_checkpoints_before_exceeding_the_remaining_share() {
    block_on(async {
        let fixture = Fixture::new(1_280).await;
        fixture.populate(0).await;
        let shared = crate::purge::SliceBudget::new(WHOLE_ALARM_CALLS);
        let mut total_calls = 0;
        for (fire, remaining) in [0, 37, 37, 37, 37, 12].into_iter().enumerate() {
            fixture.clock.set(i64::try_from(fire).unwrap() * 5_000);
            fixture.target.reset();
            shared.reset();
            assert!(shared.charge_operations(WHOLE_ALARM_CALLS - remaining));
            let registry = TimerRegistry::new().register(
                PublicationRecheck::new(fixture.target.clone()).with_alarm_budget(shared.clone()),
            );
            let report = run_due(
                &fixture.kv,
                &fixture.source,
                &registry,
                fixture.clock.as_ref(),
                u64::try_from(fire).unwrap() * publication::RECHECK_MS,
                &TickBudget::default(),
            )
            .await
            .unwrap();
            assert_eq!((report.fired, report.failed), (1, 0));
            assert_eq!(fixture.target.calls(), remaining);
            assert_eq!(
                shared.used(),
                WHOLE_ALARM_CALLS,
                "each routed call must reserve exactly one unit"
            );
            total_calls += fixture.target.calls();
            assert_eq!(fixture.published().await, u64::from(fire == 5));
        }
        assert_eq!(total_calls, 160);
    });
}

#[test]
fn malformed_cursor_is_retained_without_routed_reads_or_publication() {
    block_on(async {
        let fixture = Fixture::new(1).await;
        fixture.populate(0).await;
        let (key, _) = fixture.timer().await;
        let invalid = Value::new(b"invalid checkpoint".to_vec());
        assert_eq!(
            fixture
                .kv
                .apply(
                    &fixture.source,
                    Batch::new().put(key.clone(), invalid.clone())
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        let report = fixture.fire(0).await;
        assert_eq!((report.failed, report.fired), (1, 0));
        assert_eq!(fixture.target.calls(), 0);
        let (retained, payload) = fixture.timer().await;
        assert_eq!(payload, invalid);
        assert_ne!(retained, key);
        assert_eq!(keys::timer_retry_state(&retained), Some((0, 1)));
        assert_eq!(report.next_wake_ms, Some(crate::timers::RETRY_BACKOFF_MS));
        assert!(
            matches!(keys::parse(&retained), Some(keys::ParsedKey::Timer {
            due_at_ms, kind: 12, ..
        }) if due_at_ms == crate::timers::RETRY_BACKOFF_MS)
        );
        assert_eq!(fixture.published().await, 0);
    });
}

#[test]
fn missing_witness_inside_one_routed_page_resumes_at_that_witness() {
    block_on(async {
        let mut fixture = Fixture::new(8).await;
        for (position, pack) in fixture.dependencies.iter_mut().enumerate() {
            pack[0] = 0;
            pack[1] = 0;
            pack[31] = u8::try_from(position + 1).unwrap();
        }
        let mut advance = fixture.advance().await;
        advance.dependencies.clone_from(&fixture.dependencies);
        let packmap = mkit_core::transfer::encode_packlist(None, &fixture.dependencies).unwrap();
        let packmap_id = mkit_core::hash::hash(&packmap);
        advance.value.packmap = Some(packmap_id);
        advance.additions = vec![packmap_id];
        assert_eq!(
            fixture
                .kv
                .apply(
                    &fixture.source,
                    Batch::new().put(fixture.advance_key(), advance.encode().unwrap())
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        fixture.populate(0).await;
        fixture.remove_witness(3).await;
        assert_eq!(fixture.fire(0).await.fired, 1);
        assert_eq!(fixture.target.calls(), 1);
        assert_eq!(fixture.published().await, 0);
        fixture.witness(3, 0, true).await;
        assert_eq!(fixture.fire(5_000).await.fired, 1);
        assert_eq!(fixture.target.calls(), 1);
        let expected = fixture.dependencies[3..]
            .iter()
            .map(|pack| keys::published_member(&fixture.repo.name, pack))
            .collect::<Vec<_>>();
        assert_eq!(*fixture.target.pages.lock().unwrap(), vec![expected]);
        assert_eq!(fixture.published().await, 1);
    });
}

#[test]
fn matching_binding_cannot_skip_beyond_the_actual_dependency_set() {
    block_on(async {
        let fixture = Fixture::new(2_560).await;
        fixture.populate(0).await;
        fixture.fire(0).await;
        let (key, raw) = fixture.timer().await;
        let mut progress = Progress::decode(&raw).unwrap();
        progress.position = 2_561;
        let invalid = progress.encode();
        fixture
            .kv
            .apply(
                &fixture.source,
                Batch::new().put(key.clone(), invalid.clone()),
            )
            .await
            .unwrap();
        let report = fixture.fire(publication::RECHECK_MS).await;
        assert_eq!((report.failed, report.fired), (1, 0));
        assert_eq!(fixture.target.calls(), 0);
        let (retained, payload) = fixture.timer().await;
        assert_eq!(payload, invalid);
        assert_ne!(retained, key);
        assert_eq!(
            keys::timer_retry_state(&retained),
            Some((publication::RECHECK_MS, 1))
        );
        let next = publication::RECHECK_MS + crate::timers::RETRY_BACKOFF_MS;
        assert_eq!(report.next_wake_ms, Some(next));
        assert!(
            matches!(keys::parse(&retained), Some(keys::ParsedKey::Timer {
            due_at_ms, kind: 12, ..
        }) if due_at_ms == next)
        );
        assert_eq!(fixture.published().await, 0);
    });
}

#[test]
fn single_partition_rechecks_mutable_membership_instead_of_caching_a_prior_pass() {
    block_on(async {
        let fixture = Fixture::new(2).await;
        let source = SinglePartition.ref_shard(&fixture.repo, NAME);
        let advance = fixture.advance().await;
        let state = Publication {
            sequence: 1,
            ..Publication::default()
        };
        fixture
            .kv
            .apply(
                &source,
                Batch::new()
                    .put(fixture.advance_key(), advance.encode().unwrap())
                    .put(
                        keys::publication(&fixture.repo.name, NAME),
                        state.encode().unwrap(),
                    )
                    .put(
                        keys::timer(0, 12, fixture.advance_key().as_bytes()),
                        initial_value(),
                    ),
            )
            .await
            .unwrap();
        let registry =
            TimerRegistry::new().register(PublicationRecheck::new(fixture.target.clone()));
        for step in 0..3 {
            let mut batch = Batch::new();
            for (index, pack) in fixture.dependencies.iter().enumerate() {
                let published = match step {
                    0 => index == 0,
                    1 => index == 1,
                    _ => true,
                };
                batch = batch.put(
                    keys::membership(&fixture.repo.name, pack),
                    Witness {
                        generation: 0,
                        sequence: 1,
                        published,
                        held: false,
                        boundary: false,
                    }
                    .encode(),
                );
            }
            fixture.kv.apply(&source, batch).await.unwrap();
            let report = run_due(
                &fixture.kv,
                &source,
                &registry,
                fixture.clock.as_ref(),
                step * publication::RECHECK_MS,
                &TickBudget::default(),
            )
            .await
            .unwrap();
            assert_eq!((report.fired, report.failed), (1, 0));
            assert_eq!(
                publication::read(&fixture.kv, &source, &fixture.repo.name, NAME)
                    .await
                    .unwrap()
                    .published,
                u64::from(step == 2)
            );
            assert_eq!(fixture.target.calls(), 0, "Single SQL witnesses are local");
        }
    });
}
