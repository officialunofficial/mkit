use super::*;
use crate::store::{
    BatchOutcome, Cursor, Partition, PartitionStats, ScanPage, StoreCapabilities, content_shard,
};
use crate::{Batch, ManualClock, MemoryKv};
use futures_executor::block_on;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct ReadProbe {
    inner: MemoryKv,
    scalar: AtomicUsize,
    batches: Mutex<Vec<(Partition, Vec<Key>)>>,
    failure: Option<usize>,
    short: bool,
}

impl ReadProbe {
    fn new() -> Self {
        Self {
            inner: MemoryKv::with_clock(Arc::new(ManualClock::new(0))),
            ..Self::default()
        }
    }
}

impl NamespaceStore for ReadProbe {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.scalar.fetch_add(1, Ordering::SeqCst);
        self.inner.get(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        let call = {
            let mut batches = self.batches.lock().unwrap();
            batches.push((p.clone(), keys.to_vec()));
            batches.len()
        };
        if self.failure == Some(call) {
            return Err(StoreError::unavailable("batch probe failure"));
        }
        if self.short {
            return Ok(Vec::new());
        }
        self.inner.get_many(p, keys).await
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
fn denial_probe_uses_one_batch_and_one_budget_unit() {
    let store = ReadProbe::new();
    let id = [7; 32];
    let budget = SliceBudget::new(1);
    assert!(!block_on(denied(&Budgeted::new(&store, &budget), &id)).unwrap());
    assert_eq!(budget.used(), 1);
    assert_eq!(store.scalar.load(Ordering::SeqCst), 0);
    assert_eq!(
        *store.batches.lock().unwrap(),
        vec![(content_shard(&id), vec![keys::block(&id), action_key(&id)])]
    );
}

#[test]
fn borrowed_batch_preserves_order_duplicates_missing_and_empty() {
    block_on(async {
        let store = ReadProbe::new();
        let p = content_shard(&[7; 32]);
        let a = Key::new(&b"a"[..]);
        let b = Key::new(&b"b"[..]);
        let missing = Key::new(&b"missing"[..]);
        let av = Value::new(&b"first"[..]);
        let bv = Value::new(&b"second"[..]);
        store
            .inner
            .apply(
                &p,
                Batch::new()
                    .put(a.clone(), av.clone())
                    .put(b.clone(), bv.clone()),
            )
            .await
            .unwrap();
        let keys = vec![b, missing, a.clone(), a];
        let borrowed = BorrowedStore(&store);
        assert_eq!(
            borrowed.get_many(&p, &keys).await.unwrap(),
            vec![Some(bv), None, Some(av.clone()), Some(av)]
        );
        assert!(borrowed.get_many(&p, &[]).await.unwrap().is_empty());
        assert_eq!(
            *store.batches.lock().unwrap(),
            vec![(p.clone(), keys), (p, vec![])]
        );
        assert_eq!(store.scalar.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn borrowed_batch_propagates_backend_error_and_denial_fails_closed() {
    for short in [false, true] {
        let store = ReadProbe {
            failure: (!short).then_some(1),
            short,
            ..ReadProbe::new()
        };
        let result = block_on(ContentIndex::new(BorrowedStore(&store)).blocked(&[7; 32]));
        if short {
            assert!(
                matches!(result, Err(StoreError::Corrupt(message)) if message == "short denial read")
            );
        } else {
            assert!(
                matches!(result, Err(StoreError::Unavailable(error)) if error.to_string() == "batch probe failure")
            );
        }
        let store = ReadProbe {
            failure: (!short).then_some(1),
            short,
            ..ReadProbe::new()
        };
        let error = block_on(denied(&store, &[7; 32])).unwrap_err();
        assert_eq!(error.code(), crate::Code::Unavailable);
        assert_eq!(error.public_message(), "object storage request failed");
        assert_eq!(store.scalar.load(Ordering::SeqCst), 0);
    }
}

#[cfg(feature = "http-objects")]
#[test]
fn member_check_uses_two_batches_and_preserves_fail_closed() {
    use crate::indexed::resolve::member_dependencies_clear;
    use crate::pipeline::D34Shards;
    use crate::store::index::{IndexValue, LocatedObject};
    use crate::{NamespaceKey, NoopMetrics, RepoName};

    block_on(async {
        let id = [7; 32];
        let pack = [8; 32];
        let repo = RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new("repo").unwrap(),
        };
        let located = LocatedObject {
            pack,
            value: IndexValue {
                frame_offset: 1,
                frame_length: 1,
                wire_type: 0,
                decoded_size: 1,
                chain_depth: 0,
                delta_base: None,
            },
        };
        for (failure, blocked) in [
            (None, None),
            (Some(1), None),
            (Some(2), None),
            (None, Some(id)),
            (None, Some(pack)),
        ] {
            let store = ReadProbe {
                failure,
                ..ReadProbe::new()
            };
            if let Some(blocked) = blocked {
                store
                    .inner
                    .apply(
                        &content_shard(&blocked),
                        Batch::new().put(
                            keys::block(&blocked),
                            crate::store::codec::encode_block_entry(&BlockEntry::new("blocked", 1)),
                        ),
                    )
                    .await
                    .unwrap();
            }
            let budget = SliceBudget::new(2);
            let result = member_dependencies_clear(
                &Budgeted::new(&store, &budget),
                &D34Shards,
                &repo,
                id,
                located,
                1,
                &NoopMetrics,
                Caps::Reader,
            )
            .await;
            if failure.is_some() {
                assert_eq!(result.unwrap_err().code(), crate::Code::Unavailable);
            } else {
                assert_eq!(result.unwrap(), blocked.is_none());
            }
            let calls = failure.unwrap_or(if blocked == Some(id) { 1 } else { 2 });
            assert_eq!(budget.used(), u32::try_from(calls).unwrap());
            assert_eq!(store.scalar.load(Ordering::SeqCst), 0);
            let expected = [id, pack]
                .into_iter()
                .take(calls)
                .map(|id| (content_shard(&id), vec![keys::block(&id), action_key(&id)]))
                .collect::<Vec<_>>();
            assert_eq!(*store.batches.lock().unwrap(), expected);
        }
    });
}
