//! One operation's admission envelope, shared by metadata and blob readers.
use super::{MAX_KEY_BYTES, MAX_VALUE_BYTES, StoreError};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(crate) const PARALLELISM: usize = 6;
pub(crate) fn parallelism() -> usize {
    #[cfg(test)]
    {
        super::read_probe::concurrency(PARALLELISM)
    }
    #[cfg(not(test))]
    {
        PARALLELISM
    }
}
pub(crate) const ROWS: usize = 1_000;
// Preserve the original index scanner's worst-case transient row allowance.
// These are admission ceilings, not a recommendation to retain large replies.
const BYTE_UNIT: usize = 1024;
const BYTE_UNITS: usize = ROWS * (MAX_KEY_BYTES + MAX_VALUE_BYTES) / BYTE_UNIT;

tokio::task_local! { static ACTIVE_CREDITS: Vec<Arc<Credit>>; }

#[derive(Debug)]
struct Credit {
    owner: Arc<()>,
    active: AtomicBool,
    left: AtomicU32,
    encoded: AtomicU64,
}
/// Calls prepaid before a bounded read wave. Unused calls stay charged on
/// error/cancellation; dropping the guard prevents reuse of their credit.
#[doc(hidden)]
#[derive(Debug)]
pub struct ReadReservation {
    credit: Arc<Credit>,
    inherited: Option<Box<ReadReservation>>,
}
impl ReadReservation {
    /// Activate only these waves and their inherited ledgers while polling
    /// `future`. Unrelated tasks and cancelled waves cannot borrow their credit.
    #[doc(hidden)]
    pub async fn scope<T>(reservations: &[Option<Self>], future: impl Future<Output = T>) -> T {
        let mut credits = Vec::new();
        for reservation in reservations.iter().flatten() {
            let mut current = Some(reservation);
            while let Some(reservation) = current {
                credits.push(reservation.credit.clone());
                current = reservation.inherited.as_deref();
            }
        }
        ACTIVE_CREDITS.scope(credits, future).await
    }
    /// Keep every underlying ledger reservation alive for the same wave.
    #[doc(hidden)]
    #[must_use]
    pub fn with_inherited(mut self, inherited: Option<Self>) -> Self {
        self.inherited = inherited.map(Box::new);
        self
    }
}
impl Drop for ReadReservation {
    fn drop(&mut self) {
        self.credit.active.store(false, Ordering::SeqCst);
    }
}
/// Wave credits for a store's inherited call ledger. Reservations never refund
/// charges; credits only suppress the corresponding dispatch-time double charge.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct ReadCredits {
    identity: Arc<()>,
}
impl ReadCredits {
    #[must_use]
    pub fn prepay(&self, count: u32) -> ReadReservation {
        ReadReservation {
            credit: Arc::new(Credit {
                owner: self.identity.clone(),
                active: AtomicBool::new(true),
                left: AtomicU32::new(count),
                encoded: AtomicU64::new(0),
            }),
            inherited: None,
        }
    }
    #[must_use]
    pub fn paid(&self) -> bool {
        self.consume(|c| {
            c.left
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
        })
    }
    fn consume(&self, debit: impl Fn(&Credit) -> bool) -> bool {
        ACTIVE_CREDITS
            .try_with(|credits| {
                credits.iter().any(|c| {
                    Arc::ptr_eq(&self.identity, &c.owner)
                        && c.active.load(Ordering::SeqCst)
                        && debit(c)
                })
            })
            .unwrap_or(false)
    }
}
#[derive(Debug)]
pub(crate) struct ReadIo {
    calls: Arc<Semaphore>,
    rows: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
    credits: ReadCredits,
}
impl ReadIo {
    #[cfg_attr(not(feature = "http-objects"), allow(dead_code))]
    pub(crate) fn new() -> Self {
        Self {
            calls: Arc::new(Semaphore::new(parallelism())),
            rows: Arc::new(Semaphore::new(ROWS)),
            bytes: Arc::new(Semaphore::new(BYTE_UNITS)),
            credits: ReadCredits::default(),
        }
    }
    pub(crate) fn prepay(&self, count: u32) -> ReadReservation {
        self.credits.prepay(count)
    }
    pub(crate) fn prepay_bytes(&self, bytes: u64) -> Result<ReadReservation, StoreError> {
        if bytes > (BYTE_UNITS * BYTE_UNIT) as u64 {
            return Err(StoreError::unavailable("read I/O allowance exceeded"));
        }
        let reservation = self.prepay(0);
        reservation.credit.encoded.store(bytes, Ordering::SeqCst);
        Ok(reservation)
    }
    pub(crate) fn paid_bytes(&self, bytes: u64) -> bool {
        self.credits.consume(|c| {
            c.encoded
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(bytes))
                .is_ok()
        })
    }

    pub(crate) fn paid(&self) -> bool {
        self.credits.paid()
    }
    pub(crate) async fn acquire(&self, rows: usize, bytes: u64) -> Result<ReadLease, StoreError> {
        let units = usize::try_from(bytes)
            .unwrap_or(usize::MAX)
            .div_ceil(BYTE_UNIT);
        if rows > ROWS || units > BYTE_UNITS {
            return Err(StoreError::unavailable("read I/O allowance exceeded"));
        }
        let row = self
            .rows
            .clone()
            .acquire_many_owned(u32::try_from(rows).unwrap_or(u32::MAX))
            .await
            .map_err(|_| closed())?;
        let byte = self
            .bytes
            .clone()
            .acquire_many_owned(u32::try_from(units).unwrap_or(u32::MAX))
            .await
            .map_err(|_| closed())?;
        let call = self
            .calls
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| closed())?;
        Ok(ReadLease {
            _row: row,
            _byte: byte,
            _call: call,
        })
    }
}
fn closed() -> StoreError {
    StoreError::unavailable("read I/O admission closed")
}
pub(crate) struct ReadLease {
    _row: OwnedSemaphorePermit,
    _byte: OwnedSemaphorePermit,
    _call: OwnedSemaphorePermit,
}

impl ReadLease {
    pub(crate) fn hold(self, body: super::BlobBody) -> super::BlobBody {
        use futures::StreamExt as _;
        let (len, stream): (_, crate::rt::BoxStream<'static, _>) = match body {
            super::BlobBody::Bytes(bytes) => (
                bytes.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(bytes) })),
            ),
            super::BlobBody::Stream { len, stream } => (len, stream),
        };
        super::BlobBody::Stream {
            len,
            stream: Box::pin(futures::stream::unfold(
                (stream, self),
                |(mut stream, lease)| async move {
                    stream.next().await.map(|chunk| (chunk, (stream, lease)))
                },
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt as _;

    #[test]
    fn whole_raw_wave_fits_shared_byte_allowance_before_reservation() {
        let io = ReadIo::new();
        let maximum = (BYTE_UNITS * BYTE_UNIT) as u64;
        assert!(io.prepay_bytes(maximum + 1).is_err());
        assert!(!io.paid_bytes(1));
        let reservation = io.prepay_bytes(maximum).unwrap();
        futures::executor::block_on(ReadReservation::scope(&[Some(reservation)], async {
            assert!(io.paid_bytes(maximum));
            assert!(!io.paid_bytes(1));
        }));
    }

    #[test]
    fn cancelled_byte_scope_cannot_borrow_another_waves_allowance() {
        let io = ReadIo::new();
        let a = [Some(io.prepay_bytes(100).unwrap())];
        let b = [Some(io.prepay_bytes(200).unwrap())];
        assert!(!io.paid_bytes(1));
        let cancelled = ReadReservation::scope(&b, async {
            assert!(io.paid_bytes(20));
            futures::future::pending::<()>().await;
        });
        assert!(cancelled.now_or_never().is_none());
        drop(b);
        futures::executor::block_on(ReadReservation::scope(&a, async {
            assert!(io.paid_bytes(100));
            assert!(!io.paid_bytes(1));
        }));
        assert!(!io.paid_bytes(1));
    }

    #[test]
    fn rows_and_blob_bytes_share_one_in_flight_envelope() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let io = ReadIo::new();
            let maximum = (BYTE_UNITS * BYTE_UNIT) as u64;
            let rows = io.acquire(ROWS, maximum).await.unwrap();
            assert!(io.acquire(1, 0).now_or_never().is_none());
            assert!(io.acquire(0, 1).now_or_never().is_none());
            assert!(io.acquire(ROWS + 1, 0).await.is_err());
            assert!(io.acquire(0, maximum + 1).await.is_err());
            drop(rows);
            let bytes = io.acquire(0, maximum).await.unwrap();
            assert!(io.acquire(1, 1).now_or_never().is_none());
            drop(bytes);
            assert!(io.acquire(ROWS, maximum).await.is_ok());
        });
    }
}
