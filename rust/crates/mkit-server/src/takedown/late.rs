//! Transfer the actual late-holder request to an audited owning workflow.
use crate::indexed::budget::SliceBudget;
use crate::relay::ContentTakedownV1;
use crate::store::{Batch, Precondition, StoreError, content_shard, keys};
use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};
use crate::{BoxFuture, MaybeSend, MaybeSync, NamespaceStore};

/// Durable acceptance, never a completion marker. Success means the exact
/// request has an idempotent owning takedown workflow, system audit and retained
/// timer-15 responsibility. Register only with a real audited takedown owner;
/// this module does not provide or register that production workflow.
pub trait LateAcceptance: MaybeSend + MaybeSync {
    /// Persist responsibility before the producer request can be removed.
    fn accept<'a, S: NamespaceStore>(
        &'a self,
        local: &'a S,
        partition: &'a crate::Partition,
        request: &'a ContentTakedownV1,
        now_ms: u64,
        budget: &'a SliceBudget,
    ) -> BoxFuture<'a, Result<(), StoreError>>;
}

/// Timer 13 keeps the producer's exact request until its owner accepts it.
#[derive(Debug)]
pub struct LateTimer<A> {
    /// Durable owner; implementations must satisfy [`LateAcceptance`].
    pub acceptance: A,
    /// Shared allowance for request reads and all acceptance phases.
    pub max_subrequests: u32,
}
fn bad() -> StoreError {
    StoreError::Corrupt("invalid late-holder takedown request".into())
}
impl<S: NamespaceStore, A: LateAcceptance> TimerHandler<S> for LateTimer<A> {
    fn kind(&self) -> TimerKind {
        kinds::CONTENT_TAKEDOWN_REQUEST
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
            if timer.kind != kinds::CONTENT_TAKEDOWN_REQUEST {
                return Err(bad());
            }
            let (object, tail) = timer.reference.split_first_chunk::<32>().ok_or_else(bad)?;
            let intent = tail.try_into().map_err(|_| bad())?;
            if content_shard(object) != *ctx.partition {
                return Err(bad());
            }
            // Retain four calls for the driver's guarded completion/retry work.
            let budget = SliceBudget::new(self.max_subrequests.saturating_sub(4));
            budget.charge()?;
            let key = keys::content_takedown(object, &intent);
            let raw = ctx.store.get(ctx.partition, &key).await?.ok_or_else(bad)?;
            let mut request = ContentTakedownV1::decode(&raw)?;
            if request.identity.object != *object
                || request.identity.intent != intent
                || request.queued_at_ms > ctx.now_ms
            {
                return Err(bad());
            }
            let batch = Batch::new()
                .require(Precondition::Equals(key.clone(), raw))
                .require(Precondition::NotAfter(
                    ctx.now_ms
                        .saturating_add(crate::store::CONTENT_APPLY_WINDOW_MS),
                ));
            if request.ready_at_ms.is_none() {
                request.ready_at_ms = Some(ctx.now_ms);
                return Ok(Fired::Reschedule {
                    due_at_ms: ctx.now_ms.saturating_add(1),
                    value: timer.value.clone(),
                    batch: batch.put(key, request.encode()?),
                });
            }
            if request
                .ready_at_ms
                .is_some_and(|ready| ready < request.queued_at_ms || ready > ctx.now_ms)
            {
                return Err(bad());
            }
            self.acceptance
                .accept(ctx.store, ctx.partition, &request, ctx.now_ms, &budget)
                .await?;
            Ok(Fired::Done(batch.delete(key)))
        })
    }
}

#[cfg(test)]
#[path = "late_tests.rs"]
mod tests;
