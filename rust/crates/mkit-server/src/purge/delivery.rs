use super::{Request, guard};
use crate::store::{codec, keys};
use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};
use crate::{
    Batch, BoxFuture, MaybeSend, MaybeSync, NamespaceStore, Precondition, StoreError, Value,
};
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

/// One combined operation budget for enumeration, invalidation and delivery.
#[derive(Debug, Clone)]
pub struct SliceBudget {
    used: Arc<AtomicU32>,
    limit: u32,
}
impl SliceBudget {
    /// Share the limit between all partition heads in a Worker alarm.
    #[must_use]
    pub fn new(limit: u32) -> Self {
        Self {
            used: Arc::new(AtomicU32::new(0)),
            limit,
        }
    }
    /// Reset once at alarm entry, never once per head or per purge.
    pub fn reset(&self) {
        self.used.store(0, Ordering::SeqCst);
    }
    /// Reserve before an operation. Exhaustion produces a durable checkpoint.
    #[must_use]
    pub fn charge(&self, operations: u32) -> bool {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(operations)
                    .filter(|total| *total <= self.limit)
            })
            .is_ok()
    }
    /// Consumed operations, for tests and metrics.
    #[must_use]
    pub fn used(&self) -> u32 {
        self.used.load(Ordering::SeqCst)
    }
}
/// Global sink. Acknowledgement means every matching variant was purged.
pub trait PurgeSink: MaybeSend + MaybeSync {
    /// Deliver unchanged body/id; the transport signs each attempt afresh.
    fn deliver<'a>(&'a self, request: &'a Request) -> BoxFuture<'a, Result<(), StoreError>>;
}
/// Checkpointed local cache invalidation, including namespace enumeration.
pub trait LocalInvalidation: MaybeSend + MaybeSync {
    /// Charge enumeration and deletes before doing them. `None` means complete;
    /// `Some(cursor)` resumes at the next operation in another alarm.
    fn invalidate<'a>(
        &'a self,
        request: &'a Request,
        cursor: u32,
        budget: &'a SliceBudget,
    ) -> BoxFuture<'a, Result<Option<u32>, StoreError>>;
}
/// Deployments with no persistent local serving cache.
#[derive(Debug, Clone, Copy)]
pub struct NoLocalCache;
impl LocalInvalidation for NoLocalCache {
    fn invalidate<'a>(
        &'a self,
        _: &'a Request,
        _: u32,
        _: &'a SliceBudget,
    ) -> BoxFuture<'a, Result<Option<u32>, StoreError>> {
        Box::pin(async { Ok(None) })
    }
}
#[derive(Debug, Default, Serialize, Deserialize)]
struct Progress {
    cursor: u32,
    local_done: bool,
    attempt: u32,
}
/// Kind-11 retries immutable work until local and global acknowledgement.
pub struct PurgeDelivery {
    local: Arc<dyn LocalInvalidation>,
    sink: Option<Arc<dyn PurgeSink>>,
    budget: SliceBudget,
}
impl core::fmt::Debug for PurgeDelivery {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PurgeDelivery")
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}
impl PurgeDelivery {
    /// Use the same shared budget for every purge timer in an alarm.
    #[must_use]
    pub fn new(
        local: Arc<dyn LocalInvalidation>,
        sink: Option<Arc<dyn PurgeSink>>,
        budget: SliceBudget,
    ) -> Self {
        Self {
            local,
            sink,
            budget,
        }
    }
    fn resume(now: u64, progress: &Progress, failed: bool) -> Result<Fired, StoreError> {
        let delay = if failed {
            1000u64
                .saturating_mul(1u64 << progress.attempt.min(10))
                .min(900_000)
        } else {
            1
        };
        Ok(Fired::Reschedule {
            due_at_ms: now.saturating_add(delay),
            value: Value::new(
                serde_json::to_vec(progress)
                    .map_err(|_| StoreError::Corrupt("invalid purge progress".into()))?,
            ),
            batch: Batch::new(),
        })
    }
}
impl<S: NamespaceStore> TimerHandler<S> for PurgeDelivery {
    fn kind(&self) -> TimerKind {
        kinds::CACHE_PURGE
    }
    fn max_per_tick(&self) -> Option<u32> {
        Some(1)
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            let id = core::str::from_utf8(&timer.reference)
                .map_err(|_| StoreError::Corrupt("invalid purge timer id".into()))?;
            let key = keys::cache_purge(id)?;
            let Some(value) = ctx.store.get(ctx.partition, &key).await? else {
                return Ok(Fired::Done(Batch::new().require(Precondition::Absent(key))));
            };
            let request: Request = serde_json::from_slice(value.as_bytes())
                .map_err(|_| StoreError::Corrupt("invalid purge work".into()))?;
            request.validate()?;
            if request.purge_id != id {
                return Err(StoreError::Corrupt("purge id mismatch".into()));
            }
            let mut progress: Progress = if timer.value.as_bytes().is_empty() {
                Progress::default()
            } else {
                serde_json::from_slice(timer.value.as_bytes())
                    .map_err(|_| StoreError::Corrupt("invalid purge progress".into()))?
            };
            if !progress.local_done {
                match self
                    .local
                    .invalidate(&request, progress.cursor, &self.budget)
                    .await
                {
                    Ok(None) => progress.local_done = true,
                    Ok(Some(cursor)) => {
                        progress.cursor = cursor;
                        return Self::resume(ctx.now_ms, &progress, false);
                    }
                    Err(_) => {
                        progress.attempt = progress.attempt.saturating_add(1);
                        return Self::resume(ctx.now_ms, &progress, true);
                    }
                }
            }
            if let Some(sink) = &self.sink {
                if !self.budget.charge(1) {
                    return Self::resume(ctx.now_ms, &progress, false);
                }
                if sink.deliver(&request).await.is_err() {
                    progress.attempt = progress.attempt.saturating_add(1);
                    return Self::resume(ctx.now_ms, &progress, true);
                }
            }
            // Read the fresh combined count after every await. The guarded
            // subtraction cannot drop concurrently accepted purge/outcome work.
            let prior = ctx
                .store
                .get(ctx.partition, &keys::outcome_backlog())
                .await?;
            let mut backlog = prior
                .as_ref()
                .map(codec::decode_backlog)
                .transpose()?
                .unwrap_or_default();
            let size = u64::try_from(key.as_bytes().len() + value.as_bytes().len())
                .map_err(|_| StoreError::Corrupt("purge size overflow".into()))?;
            backlog.rows = backlog
                .rows
                .checked_sub(1)
                .ok_or_else(|| StoreError::Corrupt("purge backlog underflow".into()))?;
            backlog.bytes = backlog
                .bytes
                .checked_sub(size)
                .ok_or_else(|| StoreError::Corrupt("purge backlog underflow".into()))?;
            let mut batch = Batch::new()
                .require(Precondition::Equals(key.clone(), value))
                .require(guard(keys::outcome_backlog(), prior.as_ref()))
                .delete(key);
            batch = if backlog.rows == 0 {
                batch.delete(keys::outcome_backlog())
            } else {
                batch.put(keys::outcome_backlog(), codec::encode_backlog(&backlog))
            };
            Ok(Fired::Done(batch))
        })
    }
}
