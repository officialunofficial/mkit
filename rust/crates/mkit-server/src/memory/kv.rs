//! `MemoryKv`: the reference [`NamespaceStore`].

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Bound;
use std::sync::{Arc, Mutex};

use super::{MemoryFault, lock, take_fault};
use crate::rt::Clock;
use crate::store::{
    Batch, BatchOutcome, Cursor, Key, NamespaceStore, Partition, PartitionStats, Precondition,
    ScanPage, StoreCapabilities, StoreError, Value, Write,
};

type Rows = BTreeMap<Key, Value>;

/// An in-memory [`NamespaceStore`] over a `BTreeMap` per partition.
///
/// `apply` validates the batch, then, under one lock and with no await,
/// reads the injected clock once, checks every precondition, builds the
/// new partition and swaps it in. A panic can therefore never leave a
/// half-written partition, and a poisoned lock is recovered.
pub struct MemoryKv {
    partitions: Mutex<BTreeMap<Partition, Rows>>,
    clock: Arc<dyn Clock>,
    caps: StoreCapabilities,
    capacity: Option<u64>,
    fault: Mutex<Option<MemoryFault>>,
}

impl fmt::Debug for MemoryKv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryKv")
            .field("caps", &self.caps)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

/// Full capabilities and the host clock.
#[cfg(not(target_arch = "wasm32"))]
impl Default for MemoryKv {
    fn default() -> Self {
        Self::with_clock(Arc::new(crate::rt::SystemClock))
    }
}

impl MemoryKv {
    /// A store with full capabilities whose `NotAfter` clock is `clock`.
    #[must_use]
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            partitions: Mutex::default(),
            clock,
            caps: StoreCapabilities::full(),
            capacity: None,
            fault: Mutex::default(),
        }
    }

    /// A store with reduced capabilities and the host clock.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn new(caps: StoreCapabilities) -> Self {
        Self::default().with_capabilities(caps)
    }

    /// Report and enforce `caps`.
    #[must_use]
    pub fn with_capabilities(mut self, caps: StoreCapabilities) -> Self {
        self.caps = caps;
        self
    }

    /// Arm a one-shot [`MemoryFault`].
    #[must_use]
    pub fn with_fault(self, fault: MemoryFault) -> Self {
        *lock(&self.fault) = Some(fault);
        self
    }

    /// Cap each partition at `bytes` (keys plus values): a batch with a put
    /// that would exceed it fails with [`StoreError::Full`]; reads and
    /// delete-only batches keep working.
    #[must_use]
    pub fn with_capacity_limit(mut self, bytes: u64) -> Self {
        self.capacity = Some(bytes);
        self
    }
}

fn size(rows: &Rows) -> u64 {
    rows.iter()
        .map(|(k, v)| (k.as_bytes().len() + v.as_bytes().len()) as u64)
        .sum()
}

/// Check precondition `index` against `rows` at `now`; the failure outcome
/// if it does not hold.
fn check(rows: &Rows, index: usize, pre: &Precondition, now: u64) -> Option<BatchOutcome> {
    let (holds, observed) = match pre {
        Precondition::Absent(k) => (!rows.contains_key(k), rows.get(k).cloned()),
        Precondition::Present(k) => (rows.contains_key(k), None),
        Precondition::Equals(k, v) => (rows.get(k) == Some(v), rows.get(k).cloned()),
        Precondition::NotAfter(deadline) => {
            return (now > *deadline).then_some(BatchOutcome::DeadlinePassed { backend_now: now });
        }
    };
    (!holds).then_some(BatchOutcome::PreconditionFailed { index, observed })
}

impl NamespaceStore for MemoryKv {
    fn capabilities(&self) -> StoreCapabilities {
        self.caps
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        Ok(lock(&self.partitions)
            .get(p)
            .and_then(|rows| rows.get(key))
            .cloned())
    }

    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        if limit == 0 {
            return Err(StoreError::Invalid("scan limit must be at least 1".into()));
        }
        let lower = match after.map(|c| Key::new(c.clone().into_bytes())) {
            None => Bound::Included(start.clone()),
            // Every cursor this range returns is one of its keys.
            Some(cursor) if *start <= cursor && cursor < *end => Bound::Excluded(cursor),
            Some(_) => {
                return Err(StoreError::Invalid(
                    "scan cursor outside the scanned range".into(),
                ));
            }
        };
        let empty = match &lower {
            Bound::Included(k) | Bound::Excluded(k) => k >= end,
            Bound::Unbounded => false,
        };
        let partitions = lock(&self.partitions);
        let (Some(rows), false) = (partitions.get(p), empty) else {
            return Ok(ScanPage::default());
        };
        let want = usize::try_from(limit).unwrap_or(usize::MAX);
        let mut entries: Vec<_> = rows
            .range((lower, Bound::Excluded(end.clone())))
            .take(want.saturating_add(1))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let next = (entries.len() > want).then(|| {
            entries.truncate(want);
            Cursor::new(entries[want - 1].0.clone().into_bytes())
        });
        Ok(ScanPage { entries, next })
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        batch.validate(&self.caps)?;
        take_fault(&self.fault, MemoryFault::ApplyBefore)?;
        let mut partitions = lock(&self.partitions);
        // Rule 8: the store's clock, read once inside the check-and-write.
        // A reading before the epoch fails every deadline (fail closed).
        let now = u64::try_from(self.clock.now_ms()).unwrap_or(u64::MAX);
        let empty = Rows::new();
        let rows = partitions.get(p).unwrap_or(&empty);
        for (index, pre) in batch.preconditions.iter().enumerate() {
            if let Some(failed) = check(rows, index, pre, now) {
                return Ok(failed);
            }
        }
        let adds = batch.has_put();
        let mut next = rows.clone();
        for write in batch.writes {
            match write {
                Write::Put(k, v) => next.insert(k, v),
                Write::Delete(k) => next.remove(&k),
            };
        }
        if adds && self.capacity.is_some_and(|cap| size(&next) > cap) {
            return Err(StoreError::Full);
        }
        partitions.insert(p.clone(), next);
        drop(partitions);
        take_fault(&self.fault, MemoryFault::ApplyAfterCommit)?;
        Ok(BatchOutcome::Committed)
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        let partitions = lock(&self.partitions);
        let rows = partitions.get(p);
        Ok(PartitionStats {
            bytes: rows.map_or(0, size),
            keys: Some(rows.map_or(0, |r| r.len() as u64)),
        })
    }

    async fn probe(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use futures_executor::block_on;

    use super::*;
    use crate::repo::{NamespaceKey, RepoName};
    use crate::rt::ManualClock;
    use crate::store::{
        KeyClasses, MAX_BATCH_BYTES, MAX_BATCH_OPS, MAX_KEY_BYTES, MAX_VALUE_BYTES, keys,
    };
    use BatchOutcome::Committed;
    use Precondition::{Absent, Equals, NotAfter, Present};

    fn ns() -> Partition {
        Partition::Namespace(NamespaceKey::deployment_default())
    }

    fn k(s: &str) -> Key {
        Key::new(s.as_bytes().to_vec())
    }

    fn v(s: &str) -> Value {
        Value::new(s.as_bytes().to_vec())
    }

    fn apply(kv: &MemoryKv, batch: Batch) -> Result<BatchOutcome, StoreError> {
        block_on(kv.apply(&ns(), batch))
    }

    fn ok(kv: &MemoryKv, batch: Batch) -> BatchOutcome {
        apply(kv, batch).unwrap()
    }

    fn failed(index: usize, observed: Option<Value>) -> BatchOutcome {
        BatchOutcome::PreconditionFailed { index, observed }
    }

    fn get(kv: &MemoryKv, key: &Key) -> Option<Value> {
        block_on(kv.get(&ns(), key)).unwrap()
    }

    fn ab(kv: &MemoryKv) -> (Option<Value>, Option<Value>) {
        (get(kv, &k("a")), get(kv, &k("b")))
    }

    #[test]
    fn apply_all_or_nothing_reports_first_failing_precondition_and_observed_value() {
        let kv = MemoryKv::default();
        assert_eq!(ok(&kv, Batch::new().put(k("a"), v("1"))), Committed);
        let batch = |preconditions: Vec<Precondition>| Batch {
            preconditions,
            writes: vec![Write::Put(k("b"), v("2")), Write::Delete(k("a"))],
        };
        let cases = [
            (vec![Absent(k("a"))], failed(0, Some(v("1")))),
            (vec![Present(k("z"))], failed(0, None)),
            (vec![Equals(k("z"), v("1"))], failed(0, None)),
            (
                vec![Present(k("a")), Equals(k("a"), v("9")), Absent(k("a"))],
                failed(1, Some(v("1"))),
            ),
        ];
        for (pres, outcome) in cases {
            assert_eq!(ok(&kv, batch(pres)), outcome);
            assert_eq!(ab(&kv), (Some(v("1")), None));
        }
        let pres = vec![Equals(k("a"), v("1")), Absent(k("b"))];
        assert_eq!(ok(&kv, batch(pres)), Committed);
        assert_eq!(ab(&kv), (None, Some(v("2"))));
        assert!(block_on(kv.has(&ns(), &k("b"))).unwrap());
        let other = Partition::ContentShard(0);
        assert_eq!(block_on(kv.get(&other, &k("b"))).unwrap(), None);
    }

    #[test]
    fn apply_rejects_oversize_key_and_value_writing_nothing() {
        let kv = MemoryKv::default();
        let long_key = Key::new(vec![b'k'; MAX_KEY_BYTES + 1]);
        let long_value = Value::new(vec![0; MAX_VALUE_BYTES + 1]);
        let a = || Batch::new().put(k("a"), v("1"));
        for batch in [
            a().put(long_key.clone(), v("1")),
            a().require(Absent(long_key)),
            a().put(k("b"), long_value.clone()),
            a().require(Equals(k("b"), long_value)),
        ] {
            assert!(matches!(apply(&kv, batch), Err(StoreError::Invalid(_))));
        }
        assert_eq!(ab(&kv), (None, None));
        let max_key = Key::new(vec![1; MAX_KEY_BYTES]);
        let max = Batch::new().put(max_key, Value::new(vec![0; MAX_VALUE_BYTES]));
        assert_eq!(ok(&kv, max), Committed);
    }

    #[test]
    fn apply_rejects_batches_over_the_op_and_byte_caps() {
        let kv = MemoryKv::default();
        let puts = |n: usize, len: usize| {
            (0..n).fold(Batch::new(), |b, i| {
                b.put(Key::new(i.to_be_bytes().to_vec()), Value::new(vec![0; len]))
            })
        };
        assert_eq!(ok(&kv, puts(MAX_BATCH_OPS, 1)), Committed);
        let too_many = puts(MAX_BATCH_OPS, 1).require(Absent(k("z")));
        assert!(matches!(apply(&kv, too_many), Err(StoreError::Invalid(_))));
        // Each value fits, the sum does not.
        let too_big = puts(MAX_BATCH_BYTES / MAX_VALUE_BYTES + 1, MAX_VALUE_BYTES);
        assert!(matches!(apply(&kv, too_big), Err(StoreError::Invalid(_))));
    }

    #[test]
    fn not_after_uses_store_clock_at_apply() {
        let clock = Arc::new(ManualClock::new(1_000));
        let kv = MemoryKv::with_clock(clock.clone());
        // Built at 1000, applied after the store clock passed the deadline:
        // NotAfter fails first, even though the Equals after it would too.
        let late = Batch::new()
            .require(NotAfter(1_500))
            .require(Equals(k("x"), v("never")))
            .put(k("a"), v("1"));
        clock.set(1_501);
        let passed = BatchOutcome::DeadlinePassed { backend_now: 1_501 };
        assert_eq!(ok(&kv, late), passed);
        assert_eq!(ab(&kv), (None, None));
        clock.set(1_500);
        let at_deadline = Batch::new().require(NotAfter(1_500)).put(k("a"), v("1"));
        assert_eq!(ok(&kv, at_deadline), Committed);
        // A clock before 1970 fails closed: no deadline is met.
        clock.set(-5);
        let never = Batch::new()
            .require(NotAfter(u64::MAX - 1))
            .put(k("b"), v("1"));
        let invalid = BatchOutcome::DeadlinePassed {
            backend_now: u64::MAX,
        };
        assert_eq!(ok(&kv, never), invalid);
        assert_eq!(get(&kv, &k("b")), None);
    }

    #[test]
    fn not_after_accepted_by_refs_only_non_atomic_store() {
        let clock = Arc::new(ManualClock::new(10));
        let caps = StoreCapabilities::refs_only();
        let kv = MemoryKv::with_clock(clock).with_capabilities(caps);
        assert_eq!(kv.capabilities().key_classes, KeyClasses::RefsOnly);
        assert_eq!(kv.capabilities().implicit_layout_version, Some(1));
        let repo = RepoName::new("r").unwrap();
        let main = keys::ref_key(&repo, "refs/heads/main");
        let dev = keys::ref_key(&repo, "refs/heads/dev");
        let one = Batch::new()
            .require(NotAfter(10))
            .require(Absent(main.clone()))
            .put(main.clone(), v("id"));
        assert_eq!(ok(&kv, one), Committed);
        for bad in [
            Batch::new()
                .put(main.clone(), v("1"))
                .put(dev.clone(), v("2")),
            Batch::new()
                .require(Absent(dev.clone()))
                .put(main.clone(), v("1")),
            Batch::new().put(keys::layout_version(), v("1")),
            Batch::new().require(Absent(keys::grant_epoch())),
        ] {
            assert!(matches!(apply(&kv, bad), Err(StoreError::Unsupported(_))));
        }
        assert_eq!((get(&kv, &main), get(&kv, &dev)), (Some(v("id")), None));
    }

    #[test]
    fn capacity_limit_returns_full_but_reads_and_deletes_work() {
        let kv = MemoryKv::default().with_capacity_limit(4);
        assert_eq!(ok(&kv, Batch::new().put(k("a"), v("12"))), Committed);
        let b = || Batch::new().put(k("b"), v("1"));
        assert!(matches!(apply(&kv, b()), Err(StoreError::Full)));
        assert_eq!(ab(&kv), (Some(v("12")), None));
        // Rule 7: pruning retried as a delete-only batch, preconditions
        // included, succeeds on a full store.
        let prune = Batch::new()
            .require(Equals(k("a"), v("12")))
            .require(Absent(k("b")))
            .delete(k("a"));
        assert_eq!(ok(&kv, prune), Committed);
        assert_eq!(block_on(kv.stats(&ns())).unwrap().bytes, 0);
        assert_eq!(ok(&kv, b()), Committed);
        assert_eq!(block_on(kv.stats(&ns())).unwrap().keys, Some(1));
    }

    #[test]
    fn scan_orders_by_bytes_and_cursor_resumes_strictly_after() {
        let kv = MemoryKv::default();
        let keys = [&b"a"[..], b"a\0", b"ab", b"a\xff", b"b", b"c"].map(|b| Key::new(b.to_vec()));
        let batch = keys
            .iter()
            .rev()
            .fold(Batch::new(), |b, key| b.put(key.clone(), v("x")));
        assert_eq!(ok(&kv, batch), Committed);
        let scan = |start: &str, after: Option<&Cursor>, limit| {
            block_on(kv.scan(&ns(), &k(start), &k("c"), after, limit))
        };
        let names = |page: &ScanPage| page.entries.iter().map(|e| e.0.clone()).collect::<Vec<_>>();
        let first = scan("a", None, 2).unwrap();
        assert_eq!(names(&first), keys[..2]);
        let rest = scan("a", first.next.as_ref(), 10).unwrap();
        assert_eq!((names(&rest), rest.next), (keys[2..5].to_vec(), None));
        // An exact-fit page has no cursor; an inverted range is empty.
        assert_eq!(scan("a", None, 5).unwrap().next, None);
        assert_eq!(scan("d", None, 1).unwrap(), ScanPage::default());
        // A cursor outside the range is rejected, not silently restarted.
        let foreign = Cursor::new(&b"0"[..]);
        assert!(matches!(
            scan("a", Some(&foreign), 1),
            Err(StoreError::Invalid(_))
        ));
        assert!(matches!(scan("a", None, 0), Err(StoreError::Invalid(_))));
    }

    #[test]
    fn get_many_preserves_order() {
        let kv = MemoryKv::default();
        let batch = Batch::new().put(k("a"), v("1")).put(k("b"), v("2"));
        assert_eq!(ok(&kv, batch), Committed);
        let got = block_on(kv.get_many(&ns(), &[k("b"), k("z"), k("a")])).unwrap();
        assert_eq!(got, vec![Some(v("2")), None, Some(v("1"))]);
    }

    #[test]
    fn dropped_apply_future_leaves_store_consistent() {
        let kv = MemoryKv::default();
        let p = ns();
        let batch = || Batch::new().put(k("a"), v("1")).put(k("b"), v("2"));
        // Dropped before its first poll: fully before.
        drop(kv.apply(&p, batch()));
        assert_eq!(ab(&kv), (None, None));
        // The check-and-write never yields: one poll completes it, fully after.
        let mut fut = pin!(kv.apply(&p, batch()));
        let poll = fut.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        assert!(matches!(poll, Poll::Ready(Ok(Committed))));
        assert_eq!(ab(&kv), (Some(v("1")), Some(v("2"))));
    }

    #[test]
    fn poisoned_lock_recovers() {
        let kv = Arc::new(MemoryKv::default());
        assert_eq!(ok(&kv, Batch::new().put(k("a"), v("1"))), Committed);
        let held = kv.clone();
        let panicked = std::thread::spawn(move || {
            let _guard = held.partitions.lock().unwrap();
            panic!("poison the store lock");
        })
        .join();
        assert!(panicked.is_err() && kv.partitions.is_poisoned());
        assert_eq!(ok(&kv, Batch::new().put(k("b"), v("2"))), Committed);
        assert_eq!(ab(&kv), (Some(v("1")), Some(v("2"))));
    }

    #[test]
    fn injected_faults_fire_once() {
        let a = || Batch::new().put(k("a"), v("1"));
        let kv = MemoryKv::default().with_fault(MemoryFault::ApplyBefore);
        assert!(matches!(apply(&kv, a()), Err(StoreError::Unavailable(_))));
        assert_eq!(ab(&kv), (None, None));
        assert_eq!(ok(&kv, a()), Committed);
        let kv = MemoryKv::default().with_fault(MemoryFault::ApplyAfterCommit);
        assert!(matches!(apply(&kv, a()), Err(StoreError::Unavailable(_))));
        assert_eq!(ab(&kv), (Some(v("1")), None));
    }
}
