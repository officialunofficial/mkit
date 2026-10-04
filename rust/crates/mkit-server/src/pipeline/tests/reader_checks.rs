use super::*;
use crate::indexed::budget::{Budgeted, SliceBudget};
use crate::store::read_io::{ROWS, ReadIo};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

#[derive(Default)]
struct Backend {
    rows: Mutex<BTreeMap<Key, Value>>,
    faults: Mutex<std::collections::BTreeSet<Partition>>,
    batches: Mutex<Vec<Vec<Key>>>,
    active: AtomicUsize,
    peak: AtomicUsize,
    short: AtomicBool,
}
struct Active<'a>(&'a AtomicUsize);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl NamespaceStore for Backend {
    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities::full()
    }
    async fn get(&self, _: &Partition, _: &Key) -> Result<Option<Value>, StoreError> {
        panic!("guard reads must be batched")
    }
    async fn get_many(&self, p: &Partition, keys: &[Key]) -> Result<Reply, StoreError> {
        self.batches.lock().unwrap().push(keys.to_vec());
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        let _active = Active(&self.active);
        tokio::time::sleep(Duration::from_millis(30)).await;
        if self.faults.lock().unwrap().contains(p) {
            return Err(StoreError::unavailable("injected partition fault"));
        }
        let rows = self.rows.lock().unwrap();
        let mut reply: Reply = keys.iter().map(|key| rows.get(key).cloned()).collect();
        if self.short.load(Ordering::SeqCst) {
            reply.pop();
        }
        Ok(reply)
    }
    async fn scan(
        &self,
        _: &Partition,
        _: &Key,
        _: &Key,
        _: Option<&Cursor>,
        _: u32,
    ) -> Result<ScanPage, StoreError> {
        unreachable!()
    }
    async fn apply(&self, _: &Partition, _: Batch) -> Result<BatchOutcome, StoreError> {
        unreachable!()
    }
    async fn stats(&self, _: &Partition) -> Result<PartitionStats, StoreError> {
        unreachable!()
    }
    async fn probe(&self) -> Result<(), StoreError> {
        Ok(())
    }
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap()
}
fn ids(count: u16) -> Vec<Hash> {
    (0..count)
        .map(|n| {
            let mut id = [0; 32];
            id[..2].copy_from_slice(&(n * 16).to_be_bytes());
            id
        })
        .collect()
}
fn block(backend: &Backend, id: &Hash) {
    backend.rows.lock().unwrap().insert(
        crate::store::keys::block(id),
        crate::store::codec::encode_block_entry(&crate::store::BlockEntry::new("test", 0)),
    );
}

#[test]
fn guard_waves_share_six_call_admission_and_reserve_before_dispatch() {
    runtime().block_on(async {
        let backend = Backend::default();
        let budget = SliceBudget::new(13);
        let io = ReadIo::new();
        let store = Budgeted::new(&backend, &budget).with_io(&io);
        let checks = Checks::new(&store);
        let ids = ids(13);
        let start = tokio::time::Instant::now();
        checks.prefetch(&ids).await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_millis(90));
        assert_eq!(backend.peak.load(Ordering::SeqCst), 6);
        assert_eq!(budget.used(), 13);
        for id in &ids {
            assert!(!crate::takedown::denial::denied(&checks, id).await.unwrap());
        }
        assert_eq!(backend.batches.lock().unwrap().len(), 13);

        let limited = Backend::default();
        let budget = SliceBudget::new(5);
        let io = ReadIo::new();
        let store = Budgeted::new(&limited, &budget).with_io(&io);
        assert!(Checks::new(&store).prefetch(&ids).await.is_err());
        assert!(limited.batches.lock().unwrap().is_empty());
    });
}

#[test]
fn guard_groups_deduplicate_and_keep_pair_order() {
    runtime().block_on(async {
        let backend = Backend::default();
        let a = [1; 32];
        let mut b = a;
        b[31] = 2;
        block(&backend, &b);
        let checks = Checks::new(&backend);
        checks.prefetch(&[b, a, b, a]).await.unwrap();
        assert!(!crate::takedown::denial::denied(&checks, &a).await.unwrap());
        assert!(crate::takedown::denial::denied(&checks, &b).await.unwrap());
        assert_eq!(
            backend.batches.lock().unwrap().as_slice(),
            &[vec![
                crate::store::keys::block(&a),
                crate::takedown::denial::action_key(&a),
                crate::store::keys::block(&b),
                crate::takedown::denial::action_key(&b),
            ]]
        );
    });
}

#[test]
fn final_guard_phase_observes_changed_targets_and_packs() {
    runtime().block_on(async {
        for changed in ids(2) {
            let backend = Backend::default();
            let checks = Checks::new(&backend);
            checks.prefetch(&ids(2)).await.unwrap();
            block(&backend, &changed);
            checks.reset();
            checks.prefetch(&ids(2)).await.unwrap();
            assert!(
                crate::takedown::denial::denied(&checks, &changed)
                    .await
                    .unwrap()
            );
            assert_eq!(backend.batches.lock().unwrap().len(), 4);
        }
    });
}

#[test]
fn failed_pack_guard_remains_lazy_and_short_replies_fail_closed() {
    runtime().block_on(async {
        let backend = Backend::default();
        let ids = ids(2);
        block(&backend, &ids[0]);
        backend
            .faults
            .lock()
            .unwrap()
            .insert(crate::store::content_shard(&ids[1]));
        let checks = Checks::new(&backend);
        checks.prefetch(&ids).await.unwrap();
        assert!(
            crate::takedown::denial::denied(&checks, &ids[0])
                .await
                .unwrap()
        );
        assert!(
            crate::takedown::denial::denied(&checks, &ids[1])
                .await
                .is_err()
        );
        assert_eq!(backend.batches.lock().unwrap().len(), 2);
        backend.faults.lock().unwrap().clear();
        checks.reset();
        backend.short.store(true, Ordering::SeqCst);
        checks.prefetch(&ids).await.unwrap();
        assert!(
            crate::takedown::denial::denied(&checks, &ids[0])
                .await
                .is_err()
        );
        assert_eq!(backend.batches.lock().unwrap().len(), 4);
    });
}

#[test]
fn cancelled_guard_wave_releases_shared_allowances_without_refunding_calls() {
    runtime().block_on(async {
        let backend = Backend::default();
        let budget = SliceBudget::new(6);
        let io = ReadIo::new();
        let store = Budgeted::new(&backend, &budget).with_io(&io);
        let checks = Checks::new(&store);
        assert!(
            tokio::time::timeout(Duration::from_millis(1), checks.prefetch(&ids(6)))
                .await
                .is_err()
        );
        assert_eq!(budget.used(), 6);
        assert_eq!(backend.active.load(Ordering::SeqCst), 0);
        assert!(
            checks
                .cache
                .lock()
                .unwrap()
                .slots
                .values()
                .all(|s| s.try_lock().unwrap().is_none())
        );
        drop(io.acquire(ROWS, 0).await.unwrap());
        let leases = futures::future::join_all((0..6).map(|_| io.acquire(0, 0))).await;
        assert!(leases.iter().all(Result::is_ok));
    });
}

#[test]
fn prefetched_guard_rows_and_retained_bytes_are_bounded() {
    runtime().block_on(async {
        let backend = Backend::default();
        let ids = ids(u16::try_from(MAX_CHECKS + 12).unwrap());
        let value = Value::new(vec![0; crate::store::MAX_VALUE_BYTES]);
        for id in &ids {
            backend
                .rows
                .lock()
                .unwrap()
                .insert(crate::store::keys::block(id), value.clone());
            backend
                .rows
                .lock()
                .unwrap()
                .insert(crate::takedown::denial::action_key(id), value.clone());
        }
        let checks = Checks::new(&backend);
        checks.prefetch(&ids).await.unwrap();
        let cache = checks.cache.lock().unwrap();
        assert_eq!(cache.slots.len(), MAX_CHECKS);
        assert!(cache.bytes <= MAX_BYTES);
        assert!(
            backend
                .batches
                .lock()
                .unwrap()
                .iter()
                .all(|keys| keys.len() <= 32)
        );
    });
}
