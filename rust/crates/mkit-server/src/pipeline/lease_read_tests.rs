use super::*;
use crate::NamespaceKey;
use crate::pipeline::D34Shards;
use crate::rt::ManualClock;
use crate::store::{
    Cursor, PartitionStats, ReadCredits, ReadReservation, ScanPage, StoreCapabilities,
};
use futures_executor::block_on;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

struct LeaseReads {
    scan_corrupt: bool,
    scan_unavailable: bool,
    rows_invalid: bool,
    remaining: AtomicU32,
    charged: AtomicU32,
    calls: AtomicU32,
    refused: AtomicBool,
    credits: ReadCredits,
    active: AtomicU32,
    maximum: AtomicU32,
}
impl LeaseReads {
    fn new(budget: u32) -> Self {
        Self {
            scan_corrupt: false,
            scan_unavailable: false,
            rows_invalid: false,
            remaining: AtomicU32::new(budget),
            charged: AtomicU32::new(0),
            calls: AtomicU32::new(0),
            refused: AtomicBool::new(false),
            credits: ReadCredits::default(),
            active: AtomicU32::new(0),
            maximum: AtomicU32::new(0),
        }
    }
    async fn dispatched(&self) {
        assert!(
            self.credits.paid(),
            "lease read dispatched without reservation"
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
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
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}
impl NamespaceStore for LeaseReads {
    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities::full()
    }
    fn read_call_allowance(&self) -> Option<u32> {
        Some(self.remaining.load(Ordering::SeqCst))
    }
    fn reserve_read_calls(&self, calls: u32) -> Result<Option<ReadReservation>, StoreError> {
        if self
            .remaining
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(calls)
            })
            .is_err()
        {
            self.refused.store(true, Ordering::SeqCst);
            return Err(StoreError::unavailable("read budget exhausted"));
        }
        self.charged.fetch_add(calls, Ordering::SeqCst);
        Ok(Some(self.credits.prepay(calls)))
    }
    async fn get(&self, _: &Partition, _: &crate::store::Key) -> Result<Option<Value>, StoreError> {
        unreachable!()
    }
    async fn get_many(
        &self,
        _: &Partition,
        keys: &[crate::store::Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.dispatched().await;
        if self.rows_invalid {
            return Ok(Vec::new());
        }
        Ok(vec![None; keys.len()])
    }
    async fn scan(
        &self,
        _: &Partition,
        _: &crate::store::Key,
        _: &crate::store::Key,
        _: Option<&Cursor>,
        _: u32,
    ) -> Result<ScanPage, StoreError> {
        self.dispatched().await;
        if self.scan_unavailable {
            return Err(StoreError::unavailable("watermark failure"));
        }
        if self.scan_corrupt {
            return Err(StoreError::Corrupt("watermark corruption".into()));
        }
        Ok(ScanPage {
            entries: vec![],
            next: None,
        })
    }
    async fn apply(&self, _: &Partition, _: Batch) -> Result<BatchOutcome, StoreError> {
        unreachable!()
    }
    async fn stats(&self, _: &Partition) -> Result<PartitionStats, StoreError> {
        unreachable!()
    }
    async fn probe(&self) -> Result<(), StoreError> {
        unreachable!()
    }
}

async fn read(store: &LeaseReads) -> Result<CoordinatorLease, ServerError> {
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("lease-reads").unwrap(),
    };
    let partition = D34Shards.ref_shard(&repo, "refs/heads/main");
    read_lease_rows(
        store,
        store,
        &D34Shards,
        &ManualClock::new(123),
        &repo,
        &partition,
        None,
        None,
        false,
    )
    .await
}

#[test]
fn joined_lease_watermark_precedes_coordinator_error_and_corruption_reports_zero() {
    block_on(async {
        let mut store = LeaseReads::new(2);
        store.scan_unavailable = true;
        store.rows_invalid = true;
        let error = read(&store).await.err().unwrap();
        assert_eq!(
            error.code(),
            meta_error(StoreError::unavailable("watermark failure")).code()
        );
        assert_eq!(
            error.public_message(),
            meta_error(StoreError::unavailable("watermark failure")).public_message()
        );
        assert_eq!(store.calls.load(Ordering::SeqCst), 2);
        assert_eq!(store.charged.load(Ordering::SeqCst), 2);
        assert_eq!(store.maximum.load(Ordering::SeqCst), 2);

        let mut store = LeaseReads::new(2);
        store.scan_corrupt = true;
        let read = read(&store).await.unwrap();
        assert_eq!(read.relay_watermark_ms, 0);
        assert!(read.namespace.is_none());
        assert!(read.repo.is_none());
        assert_eq!(store.calls.load(Ordering::SeqCst), 2);
        assert_eq!(store.charged.load(Ordering::SeqCst), 2);
        assert_eq!(store.maximum.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn tight_lease_budget_preserves_watermark_failure_without_coordinator_refusal() {
    block_on(async {
        let mut store = LeaseReads::new(1);
        store.scan_unavailable = true;
        store.rows_invalid = true;
        let error = read(&store).await.err().unwrap();
        assert_eq!(
            error.code(),
            meta_error(StoreError::unavailable("watermark failure")).code()
        );
        assert_eq!(
            error.public_message(),
            meta_error(StoreError::unavailable("watermark failure")).public_message()
        );
        assert_eq!(store.calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.charged.load(Ordering::SeqCst), 1);
        assert_eq!(store.maximum.load(Ordering::SeqCst), 1);
        assert!(!store.refused.load(Ordering::SeqCst));
    });
}
