//! Reconcile a pending write or read after its safe abandonment deadline.

use crate::rt::BoxFuture;
use crate::store::codec::{self, AbortReason, ReservationV1};
use crate::store::outbox::{OutboxBuilder, Terminal};
use crate::store::{Batch, NamespaceStore, StoreError, keys};
use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};

/// Kind-9 pending reservation reconciler.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReservationReconcile;

impl<S: NamespaceStore> TimerHandler<S> for ReservationReconcile {
    fn kind(&self) -> TimerKind {
        kinds::RESERVATION_RECONCILE
    }

    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            let rid = core::str::from_utf8(&timer.reference)
                .map_err(|_| StoreError::Corrupt("invalid reconcile reservation id".into()))?;
            let key = keys::reservation(rid)?;
            let Some(prior) = ctx.store.get(ctx.partition, &key).await? else {
                return Ok(Fired::Done(Batch::new()));
            };
            let ReservationV1::Pending {
                repository,
                reconcile_at_ms,
                ..
            } = codec::decode_reservation(&prior)?
            else {
                return Ok(Fired::Done(Batch::new()));
            };
            if ctx.now_ms < reconcile_at_ms {
                return Ok(Fired::Reschedule {
                    due_at_ms: reconcile_at_ms,
                    value: timer.value.clone(),
                    batch: Batch::new(),
                });
            }
            let keys = [keys::outbox_sequence(), keys::outcome_backlog()];
            let values = ctx.store.get_many(ctx.partition, &keys).await?;
            let mut outbox = OutboxBuilder::new(
                values.first().and_then(Option::as_ref),
                values.get(1).and_then(Option::as_ref),
            )?;
            outbox.outcome(
                rid,
                &prior,
                Terminal::new(ReservationV1::Aborted {
                    repository,
                    occurred_at_ms: ctx.now_ms,
                    reason: AbortReason::Abandoned,
                    detail: String::new(),
                })?,
            );
            let mut batch = Batch::new();
            outbox.try_finish(&mut batch.preconditions, &mut batch.writes)?;
            Ok(Fired::Done(batch))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryKv;
    use crate::repo::NamespaceKey;
    use crate::rt::ManualClock;
    use crate::store::codec::PendingOp;
    use crate::store::outbox::OutboxBuilder;
    use crate::store::{BatchOutcome, Partition, Precondition, Value};
    use crate::timers::{TickBudget, TimerRegistry, run_due};
    use std::sync::Arc;

    #[tokio::test]
    async fn crash_after_pending_reconciles_and_blocks_late_apply() {
        for (rid, op, reconcile_at) in [
            ("write", PendingOp::Write, 41_000),
            ("read", PendingOp::Read, 70_000),
        ] {
            let clock = Arc::new(ManualClock::new(0));
            let store = MemoryKv::with_clock(clock.clone());
            let partition = Partition::Namespace(NamespaceKey::deployment_default());
            let pending = ReservationV1::Pending {
                repository: "repo".into(),
                created_at_ms: 0,
                reconcile_at_ms: reconcile_at,
                op,
            };
            let prior = codec::encode_reservation(&pending);
            let mut builder = OutboxBuilder::new(None, None).unwrap();
            builder.pending(rid, None, &pending);
            let mut batch = Batch::new();
            builder
                .try_finish(&mut batch.preconditions, &mut batch.writes)
                .unwrap();
            assert_eq!(
                store.apply(&partition, batch).await.unwrap(),
                BatchOutcome::Committed
            );
            let registry = TimerRegistry::new().register(ReservationReconcile);
            assert_eq!(
                run_due(
                    &store,
                    &partition,
                    &registry,
                    clock.as_ref(),
                    reconcile_at - 1,
                    &TickBudget::default()
                )
                .await
                .unwrap()
                .fired,
                0
            );
            clock.set(i64::try_from(reconcile_at).unwrap());
            assert_eq!(
                run_due(
                    &store,
                    &partition,
                    &registry,
                    clock.as_ref(),
                    reconcile_at,
                    &TickBudget::default()
                )
                .await
                .unwrap()
                .fired,
                1
            );
            let key = keys::reservation(rid).unwrap();
            let value = store.get(&partition, &key).await.unwrap().unwrap();
            assert!(matches!(
                codec::decode_reservation(&value).unwrap(),
                ReservationV1::Aborted {
                    reason: AbortReason::Abandoned,
                    ..
                }
            ));
            let late = Batch::new()
                .require(Precondition::Equals(key, prior))
                .put(keys::outcome_backlog(), Value::default());
            assert!(matches!(
                store.apply(&partition, late).await.unwrap(),
                BatchOutcome::PreconditionFailed { .. }
            ));
            assert_eq!(
                codec::decode_backlog(
                    &store
                        .get(&partition, &keys::outcome_backlog())
                        .await
                        .unwrap()
                        .unwrap()
                )
                .unwrap()
                .rows,
                1
            );
        }
    }
}
