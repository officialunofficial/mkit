//! Bounded denial reads with input-order failure precedence.
use crate::{ServerError, store::NamespaceStore};
use mkit_core::hash::Hash;

// Decode denial admission follows staging, so match its batch cap.
const DENIAL_WAVE_WIDTH: usize = crate::takedown::inventory::STAGE_BATCH_ENTRIES;

/// Checks `ids` in waves of at most sixteen concurrent reads,
/// one `require_clear` call per id. Every response of a wave is awaited, then
/// the first failure in input order is returned and later waves are skipped.
/// Callers must await this helper serially: the width bound is per call.
pub(crate) async fn require_clear_many<S: NamespaceStore>(
    store: &S,
    mut ids: impl Iterator<Item = Hash> + crate::MaybeSend,
) -> Result<(), ServerError> {
    loop {
        let wave: Vec<_> = ids.by_ref().take(DENIAL_WAVE_WIDTH).collect();
        if wave.is_empty() {
            return Ok(());
        }
        // Ordinary mutation stores retain dispatch-time charging, so a later
        // budget failure cannot mask an earlier object's denial. Admitted
        // readers use their existing all-or-nothing wave reservation policy.
        let reservation = if store.reader_admission() {
            store
                .reserve_read_calls(u32::try_from(wave.len()).expect("bounded denial wave"))
                .map_err(|_| super::unavailable())?
        } else {
            None
        };
        // Await every response before selecting the first error in input order.
        // Short-circuiting on completion order would change Blocked precedence.
        let replies = crate::store::ReadReservation::scope(
            &[reservation],
            futures::future::join_all(
                wave.iter()
                    .map(|id| crate::takedown::denial::require_clear(store, id)),
            ),
        )
        .await;
        for reply in replies {
            reply?;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::MemoryKv;
    use crate::indexed::budget::{Budgeted, SliceBudget};
    use crate::store::{
        Batch, BatchOutcome, Cursor, Key, Partition, PartitionStats, ScanPage, StoreCapabilities,
        StoreError, Value, keys,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[derive(Default)]
    struct Delayed {
        inner: MemoryKv,
        calls: AtomicUsize,
        active: AtomicUsize,
        peak: AtomicUsize,
        blocked: Option<Hash>,
        unavailable: Option<Hash>,
    }
    impl NamespaceStore for Delayed {
        fn capabilities(&self) -> StoreCapabilities {
            self.inner.capabilities()
        }
        async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
            self.inner.get(p, key).await
        }
        async fn get_many(
            &self,
            _: &Partition,
            requested: &[Key],
        ) -> Result<Vec<Option<Value>>, StoreError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            // Earlier failures deliberately complete later than later failures.
            let delay = if requested[0] == keys::block(&[0; 32])
                || requested[0] == keys::block(&[16; 32])
            {
                620
            } else {
                310
            };
            tokio::time::sleep(Duration::from_millis(delay)).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            if self
                .unavailable
                .is_some_and(|id| requested[0] == keys::block(&id))
            {
                return Err(StoreError::unavailable("injected denial read failure"));
            }
            if self
                .blocked
                .is_some_and(|id| requested[0] == keys::block(&id))
            {
                return Ok(vec![
                    Some(crate::store::codec::encode_block_entry(
                        &crate::store::BlockEntry::new("late block", 1),
                    )),
                    None,
                ]);
            }
            Ok(vec![None, None])
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
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn denial_waves_bound_latency_and_charge_one_call_per_object() {
        let store = Delayed::default();
        let budget = SliceBudget::new(400);
        let remote = Budgeted::new(&store, &budget);
        let ids: Vec<Hash> = (1_u16..=333)
            .map(|n| {
                let mut id = [1; 32];
                id[..2].copy_from_slice(&n.to_be_bytes());
                id
            })
            .collect();
        let started = tokio::time::Instant::now();
        require_clear_many(&remote, ids.iter().copied())
            .await
            .unwrap();
        assert_eq!(store.calls.load(Ordering::SeqCst), 333);
        assert_eq!(budget.used(), 333);
        let width = DENIAL_WAVE_WIDTH;
        assert_eq!(width, 16);
        assert_eq!(crate::store::read_io::PARALLELISM, 6);
        assert_eq!(store.peak.load(Ordering::SeqCst), width);
        assert_eq!(
            started.elapsed(),
            Duration::from_millis(333_usize.div_ceil(width) as u64 * 310)
        );
        // The actual staging cap adds a partial wave at every batch boundary.
        let started = tokio::time::Instant::now();
        let budget = SliceBudget::new(400);
        let remote = Budgeted::new(&store, &budget);
        let cap = crate::takedown::inventory::STAGE_BATCH_ENTRIES;
        for batch in ids.chunks(cap) {
            require_clear_many(&remote, batch.iter().copied())
                .await
                .unwrap();
        }
        let rounds: usize = ids
            .chunks(cap)
            .map(|batch| batch.len().div_ceil(width))
            .sum();
        assert_eq!(rounds, 21);
        assert_eq!(
            started.elapsed(),
            Duration::from_millis(rounds as u64 * 310)
        );
        assert_eq!(budget.used(), 333);
    }

    #[tokio::test(start_paused = true)]
    async fn denial_waves_preserve_first_failure_in_batch_order() {
        for admitted in [false, true] {
            for (blocked, unavailable, expected, calls) in [
                (Some([0; 32]), None, crate::Code::PermissionDenied, 16),
                (None, Some([0; 32]), crate::Code::Unavailable, 16),
                (
                    Some([0; 32]),
                    Some([1; 32]),
                    crate::Code::PermissionDenied,
                    16,
                ),
                (Some([1; 32]), Some([0; 32]), crate::Code::Unavailable, 16),
                (
                    Some([16; 32]),
                    Some([17; 32]),
                    crate::Code::PermissionDenied,
                    32,
                ),
                (Some([17; 32]), Some([16; 32]), crate::Code::Unavailable, 32),
            ] {
                let store = Delayed {
                    blocked,
                    unavailable,
                    ..Delayed::default()
                };
                let budget = SliceBudget::new(40);
                let inherited = SliceBudget::new(40);
                let inner = Budgeted::new(&store, &inherited);
                let io = crate::store::read_io::ReadIo::new();
                let remote = Budgeted::new(&inner, &budget);
                let remote = if admitted {
                    remote.with_io(&io)
                } else {
                    remote
                };
                let ids: Vec<_> = (0..33).map(|n| [n; 32]).collect();
                let error = require_clear_many(&remote, ids.iter().copied())
                    .await
                    .unwrap_err();
                assert_eq!(error.code(), expected);
                assert_eq!(store.calls.load(Ordering::SeqCst), calls);
                assert_eq!(inherited.used() as usize, calls);
                assert_eq!(budget.used() as usize, store.calls.load(Ordering::SeqCst));
                assert_eq!(store.active.load(Ordering::SeqCst), 0);
                assert_eq!(
                    store.peak.load(Ordering::SeqCst),
                    if admitted { 6 } else { 16 }
                );
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn denial_waves_keep_first_block_when_later_calls_exhaust_budget() {
        let store = Delayed {
            blocked: Some([0; 32]),
            ..Delayed::default()
        };
        let budget = SliceBudget::new(1);
        let remote = Budgeted::new(&store, &budget);
        let error = require_clear_many(&remote, (0..16).map(|n| [n; 32]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), crate::Code::PermissionDenied);
        assert_eq!(store.calls.load(Ordering::SeqCst), 1);
        assert_eq!(budget.used(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn denial_waves_issue_at_most_fifteen_reads_after_failure() {
        for failed in [0_u8, 15, 16, 31] {
            let store = Delayed {
                blocked: Some([failed; 32]),
                ..Delayed::default()
            };
            let budget = SliceBudget::new(64);
            let remote = Budgeted::new(&store, &budget);
            let error = require_clear_many(&remote, (0..49).map(|n| [n; 32]))
                .await
                .unwrap_err();
            assert_eq!(error.code(), crate::Code::PermissionDenied);
            let calls = store.calls.load(Ordering::SeqCst);
            assert_eq!(calls, (usize::from(failed) + 1).div_ceil(16) * 16);
            let extra = calls - usize::from(failed) - 1;
            assert!(extra <= 15);
            if failed == 0 {
                assert_eq!(extra, 15);
            }
            assert_eq!(budget.used() as usize, calls);
            assert_eq!(store.active.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn denial_wave_reservation_failure_dispatches_no_reads() {
        let store = Delayed::default();
        let budget = SliceBudget::new(15);
        let io = crate::store::read_io::ReadIo::new();
        let remote = Budgeted::new(&store, &budget).with_io(&io);
        let error = require_clear_many(&remote, [[1; 32]; 16].into_iter())
            .await
            .unwrap_err();
        assert_eq!(error.code(), crate::Code::Unavailable);
        assert_eq!(store.calls.load(Ordering::SeqCst), 0);
        assert_eq!(error.public_message(), "object storage request failed");
    }
}
