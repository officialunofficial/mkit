//! Process-wide bounds for parallel shard delivery. A buffer retains its byte
//! reservation while queued, collected and decoded, including after another
//! download has started. Detached stragglers therefore cannot multiply the
//! memory ceiling with pack-chain length.

use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use crate::protocol::{PACK_BODY_LIMIT_USIZE, PackKey, TransportError, TransportResult};

use super::{Sequential, Shard, ShardSet, decode_shard_iter, default_parallel_strategy_for_len};

/// Encoded input buffers across all HTTP/S3 shard downloads. The extra MiB
/// covers proof/framing overhead on a pack at the whole-body ceiling.
pub const MAX_BUFFERED_SHARD_BYTES: usize = PACK_BODY_LIMIT_USIZE.saturating_add(1024 * 1024);
/// Bounds OS workers across overlapping downloads, including stragglers.
pub const MAX_SHARD_WORKERS: usize = 32;
const READ_BYTES: usize = 16 * 1024;

#[derive(Debug)]
struct Budget {
    used: AtomicUsize,
    limit: usize,
}

impl Budget {
    fn reserve(&self, bytes: usize) -> TransportResult<()> {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|&next| next <= self.limit)
            })
            .map(|_| ())
            .map_err(|_| TransportError::PayloadTooLarge(self.limit.saturating_add(1)))
    }
}

#[derive(Debug)]
struct Reservation {
    budget: Arc<Budget>,
    bytes: usize,
}

impl Reservation {
    fn grow_to(&mut self, capacity: usize) -> TransportResult<()> {
        if capacity > self.bytes {
            self.budget.reserve(capacity - self.bytes)?;
            self.bytes = capacity;
        }
        Ok(())
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// Cancels readers when their collecting request returns or fails.
#[derive(Debug, Default)]
pub struct DownloadGroup {
    cancelled: Arc<AtomicBool>,
}

impl DownloadGroup {
    /// A token that may be sent to a detached worker.
    #[must_use]
    pub fn token(&self) -> Cancellation {
        Cancellation(Arc::clone(&self.cancelled))
    }

    /// Stop straggler reads/retries without awaiting them. A read already
    /// blocked on the network remains bounded by the transport's timeout.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

impl Drop for DownloadGroup {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Shared cancellation state, without ownership of the collecting request.
#[derive(Debug, Clone)]
pub struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
    /// # Errors
    /// Returns a terminal error when the caller has stopped collecting.
    pub fn check(&self) -> TransportResult<()> {
        if self.0.load(Ordering::Acquire) {
            return Err(TransportError::ProtocolError);
        }
        Ok(())
    }
}

/// One downloaded input with its live-byte reservation. Moving it through a
/// channel does not release the reservation; dropping it does.
#[derive(Debug)]
pub struct DownloadedShard {
    shard: Shard,
    _reservation: Reservation,
}

impl DownloadedShard {
    /// Read without trusting Content-Length, checking the body and aggregate
    /// capacity limits before growing the owned buffer.
    ///
    /// # Errors
    /// Returns a terminal limit/cancellation error, or `ConnectionFailed` for
    /// a failed body read. All partial reservations are released on failure.
    pub fn read(index: u16, reader: impl Read, cancel: &Cancellation) -> TransportResult<Self> {
        static BUDGET: OnceLock<Arc<Budget>> = OnceLock::new();
        let budget = BUDGET.get_or_init(|| {
            Arc::new(Budget {
                used: AtomicUsize::new(0),
                limit: MAX_BUFFERED_SHARD_BYTES,
            })
        });
        Self::read_with_budget(index, reader, cancel, Arc::clone(budget))
    }

    fn read_with_budget(
        index: u16,
        mut reader: impl Read,
        cancel: &Cancellation,
        budget: Arc<Budget>,
    ) -> TransportResult<Self> {
        let mut reservation = Reservation { budget, bytes: 0 };
        let mut bytes = Vec::new();
        let mut chunk = [0u8; READ_BYTES];
        loop {
            cancel.check()?;
            let n = reader
                .read(&mut chunk)
                .map_err(|_| TransportError::ConnectionFailed)?;
            if n == 0 {
                break;
            }
            let next = bytes
                .len()
                .checked_add(n)
                .filter(|&n| n <= PACK_BODY_LIMIT_USIZE)
                .ok_or(TransportError::PayloadTooLarge(
                    PACK_BODY_LIMIT_USIZE.saturating_add(1),
                ))?;
            if next > bytes.capacity() {
                reservation.grow_to(next)?;
                bytes
                    .try_reserve_exact(next - bytes.len())
                    .map_err(|_| TransportError::PayloadTooLarge(next))?;
                reservation.grow_to(bytes.capacity())?;
            }
            bytes.extend_from_slice(&chunk[..n]);
        }
        Ok(Self {
            shard: Shard { index, bytes },
            _reservation: reservation,
        })
    }
}

/// Decode without cloning downloaded payloads or releasing their reservations.
/// The decoder's temporary/output buffers are bounded by the selected inputs
/// and the pack format's u32 length, independently of pack-chain length.
///
/// # Errors
/// Invalid shards, manifests or requested identity return `InvalidResponse`.
pub fn decode_downloaded_pack(
    shards: &[DownloadedShard],
    manifest: &ShardSet,
    key: &PackKey,
) -> TransportResult<Vec<u8>> {
    if manifest.pack_hash != *key.as_bytes() {
        return Err(TransportError::InvalidResponse);
    }
    let size_hint = shards.iter().map(|shard| shard.shard.bytes.len()).sum();
    let pack = match default_parallel_strategy_for_len(size_hint) {
        Some(strategy) => {
            decode_shard_iter(shards.iter().map(|shard| &shard.shard), manifest, &strategy)
        }
        None => decode_shard_iter(
            shards.iter().map(|shard| &shard.shard),
            manifest,
            &Sequential,
        ),
    }
    .map_err(|_| TransportError::InvalidResponse)?;
    key.verify_bytes(&pack)?;
    Ok(pack)
}

fn workers() -> &'static (Mutex<usize>, Condvar) {
    static WORKERS: OnceLock<(Mutex<usize>, Condvar)> = OnceLock::new();
    WORKERS.get_or_init(|| (Mutex::new(0), Condvar::new()))
}

/// A process-wide worker reservation, held through body reads and retries.
#[derive(Debug)]
pub struct WorkerSlot;

impl WorkerSlot {
    /// Wait for a bounded worker slot before spawning an OS thread.
    ///
    /// # Errors
    /// A poisoned worker-state lock is a `ConnectionFailed` error.
    pub fn acquire() -> TransportResult<Self> {
        let (lock, ready) = workers();
        let mut active = lock.lock().map_err(|_| TransportError::ConnectionFailed)?;
        while *active >= MAX_SHARD_WORKERS {
            active = ready
                .wait(active)
                .map_err(|_| TransportError::ConnectionFailed)?;
        }
        *active += 1;
        Ok(Self)
    }
}

impl Drop for WorkerSlot {
    fn drop(&mut self) {
        let (lock, ready) = workers();
        let mut active = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *active -= 1;
        ready.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_budget_follows_live_buffers_and_releases_on_drop() {
        let budget = Arc::new(Budget {
            used: AtomicUsize::new(0),
            limit: 96,
        });
        let group = DownloadGroup::default();
        let first =
            DownloadedShard::read_with_budget(0, &[0; 64][..], &group.token(), Arc::clone(&budget))
                .unwrap();
        assert!(matches!(
            DownloadedShard::read_with_budget(1, &[1; 64][..], &group.token(), Arc::clone(&budget)),
            Err(TransportError::PayloadTooLarge(_))
        ));
        assert_eq!(budget.used.load(Ordering::Acquire), 64);
        drop(first);
        let second =
            DownloadedShard::read_with_budget(1, &[1; 64][..], &group.token(), Arc::clone(&budget))
                .unwrap();
        drop(second);
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn cancellation_stops_before_reading() {
        struct MustNotRead;
        impl Read for MustNotRead {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("cancelled request read the body");
            }
        }
        let group = DownloadGroup::default();
        let token = group.token();
        drop(group);
        assert!(matches!(
            DownloadedShard::read(0, MustNotRead, &token),
            Err(TransportError::ProtocolError)
        ));
    }
}
