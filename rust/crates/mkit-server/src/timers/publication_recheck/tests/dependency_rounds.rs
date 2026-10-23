use super::*;
use crate::store::{ReadCredits, ReadReservation};

struct ReservedReads {
    inner: CountedTarget,
    remaining: AtomicU32,
    charged: AtomicU32,
    refused: std::sync::atomic::AtomicBool,
    credits: ReadCredits,
    active: AtomicU32,
    maximum: AtomicU32,
    faults: BTreeMap<Partition, &'static str>,
}

impl ReservedReads {
    fn new(inner: CountedTarget, budget: u32) -> Self {
        Self {
            inner,
            remaining: AtomicU32::new(budget),
            charged: AtomicU32::new(0),
            refused: std::sync::atomic::AtomicBool::new(false),
            credits: ReadCredits::default(),
            active: AtomicU32::new(0),
            maximum: AtomicU32::new(0),
            faults: BTreeMap::new(),
        }
    }
}

impl NamespaceStore for ReservedReads {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    fn read_call_allowance(&self) -> Option<u32> {
        Some(self.remaining.load(Ordering::SeqCst))
    }
    fn reserve_read_calls(&self, calls: u32) -> Result<Option<ReadReservation>, StoreError> {
        self.remaining
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(calls)
            })
            .map_err(|_| {
                self.refused.store(true, Ordering::SeqCst);
                StoreError::unavailable("read budget exhausted")
            })?;
        self.charged.fetch_add(calls, Ordering::SeqCst);
        Ok(Some(self.credits.prepay(calls)))
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        assert!(self.credits.paid(), "read dispatched without reservation");
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum.fetch_max(active, Ordering::SeqCst);
        let mut yielded = false;
        futures::future::poll_fn(|cx| {
            if yielded {
                std::task::Poll::Ready(())
            } else {
                yielded = true;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        })
        .await;
        let rows = self.inner.get_many(p, keys).await;
        self.active.fetch_sub(1, Ordering::SeqCst);
        let rows = rows?;
        if let Some(reason) = self.faults.get(p) {
            return Err(StoreError::Corrupt((*reason).into()));
        }
        Ok(rows)
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
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

#[test]
fn dependency_waves_reserve_exact_calls_and_preserve_first_missing_or_error() {
    block_on(async {
        for missing_first in [false, true] {
            let fixture = Fixture::new(16).await;
            fixture.populate(0).await;
            let advance = fixture.advance().await;
            let groups = dependency_groups(&fixture.source, &D34Shards, &fixture.repo, &advance);
            let partitions = groups.keys().cloned().collect::<Vec<_>>();
            let mut target = ReservedReads::new(fixture.target.clone(), 16);
            target.faults.insert(partitions[1].clone(), "later error");
            if missing_first {
                fixture.remove_witness(0).await;
            } else {
                target.faults.insert(partitions[0].clone(), "first error");
            }
            let result = dependencies(
                &fixture.kv,
                &target,
                &fixture.source,
                &D34Shards,
                &fixture.repo,
                &advance,
            )
            .await;
            if missing_first {
                assert!(!result.unwrap());
            } else {
                assert!(
                    matches!(result, Err(StoreError::Corrupt(reason)) if reason == "first error")
                );
            }
            assert_eq!(target.inner.calls(), 6);
            assert_eq!(target.charged.load(Ordering::SeqCst), 6);
            assert_eq!(target.maximum.load(Ordering::SeqCst), 6);
            assert_eq!(target.active.load(Ordering::SeqCst), 0);
            assert_eq!(*target.inner.reads.lock().unwrap(), partitions[..6]);
        }
    });
}

#[test]
fn dependency_tight_budget_falls_back_before_missing_witness_or_later_exhaustion() {
    block_on(async {
        for missing in [false, true] {
            let fixture = Fixture::new(16).await;
            fixture.populate(0).await;
            if missing {
                fixture.remove_witness(0).await;
            }
            let target = ReservedReads::new(fixture.target.clone(), 1);
            let result = dependencies(
                &fixture.kv,
                &target,
                &fixture.source,
                &D34Shards,
                &fixture.repo,
                &fixture.advance().await,
            )
            .await;
            if missing {
                assert!(!result.unwrap());
            } else {
                assert!(matches!(result, Err(StoreError::Unavailable(_))));
            }
            assert_eq!(target.inner.calls(), 1);
            assert_eq!(target.charged.load(Ordering::SeqCst), 1);
            assert_eq!(target.maximum.load(Ordering::SeqCst), 1);
            assert_eq!(target.refused.load(Ordering::SeqCst), !missing);
        }
    });
}

#[test]
fn dependency_local_pages_preserve_row_absence_and_corruption_order() {
    block_on(async {
        for missing_first in [false, true] {
            let fixture = Fixture::new(16).await;
            let source = SinglePartition.ref_shard(&fixture.repo, NAME);
            let advance = fixture.advance().await;
            let groups = dependency_groups(&source, &SinglePartition, &fixture.repo, &advance);
            let keys = &groups[&source];
            // Two local pages: corrupt later row/page must not outrank absence.
            fixture
                .kv
                .apply(
                    &source,
                    Batch::new().put(
                        keys[usize::from(missing_first)].clone(),
                        Value::new(b"bad witness".to_vec()),
                    ),
                )
                .await
                .unwrap();
            let local = ReservedReads::new(fixture.target.clone(), 2);
            let target = ReservedReads::new(CountedTarget::new(fixture.kv.clone()), 0);
            let result = dependencies(
                &local,
                &target,
                &source,
                &SinglePartition,
                &fixture.repo,
                &advance,
            )
            .await;
            if missing_first {
                assert!(!result.unwrap());
            } else {
                assert!(matches!(result, Err(StoreError::Corrupt(_))));
            }
            assert_eq!(local.inner.calls(), 2);
            assert_eq!(local.charged.load(Ordering::SeqCst), 2);
            assert_eq!(target.inner.calls(), 0);
        }
    });
}
