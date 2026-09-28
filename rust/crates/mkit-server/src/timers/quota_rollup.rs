//! Reconcile each ref shard's cumulative fixed-window quota into its
//! coordinator. The coordinator apply precedes the local view write; a crash
//! between them is safe because `qc` stores the last applied cumulative count.

use super::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};
use crate::quota::{NamespaceUsage, NamespaceView, QUOTA_ROLLUP_MS};
use crate::rt::BoxFuture;
use crate::store::{
    Batch, BatchOutcome, NamespaceStore, Partition, Precondition, StoreError, Value, codec, keys,
};

const MAX_AGGREGATE_REPLANS: usize = 8;
const CLOCK_GRACE_MS: u64 = mkit_core::write_auth::MAX_CLOCK_LEAD_MS.unsigned_abs();

/// A source-side kind-5 handler with a client for the namespace coordinator.
#[derive(Debug)]
pub struct QuotaRollup<T> {
    /// Store client capable of reaching the coordinator partition.
    pub coordinator: T,
}

fn guard(key: crate::store::Key, value: Option<&Value>) -> Precondition {
    match value {
        Some(value) => Precondition::Equals(key, value.clone()),
        None => Precondition::Absent(key),
    }
}

/// Prune a bounded page from an older-window range. Batches have per-key
/// deletes, so this is the portable equivalent of a range delete.
async fn prune_older<S: NamespaceStore>(
    store: &S,
    partition: &Partition,
    tag: &str,
    window: u64,
    mut batch: Batch,
) -> Result<Batch, StoreError> {
    if window == 0 {
        return Ok(batch);
    }
    let (start, end) = keys::quota_namespace_before(tag, window);
    let page = store.scan(partition, &start, &end, None, 8).await?;
    for (key, value) in page.entries {
        batch = batch
            .require(Precondition::Equals(key.clone(), value))
            .delete(key);
    }
    Ok(batch)
}

async fn aggregate<T: NamespaceStore>(
    target: &T,
    coordinator: &Partition,
    source: &Partition,
    window: u64,
    local: NamespaceUsage,
) -> Result<NamespaceUsage, StoreError> {
    let source_key = keys::quota_contribution(window, source)?;
    let total_key = keys::quota_total(window);
    for _ in 0..MAX_AGGREGATE_REPLANS {
        let values = target
            .get_many(coordinator, &[source_key.clone(), total_key.clone()])
            .await?;
        let old_value = values.first().and_then(Option::as_ref);
        let total_value = values.get(1).and_then(Option::as_ref);
        let old = old_value
            .map(codec::decode_namespace_usage)
            .transpose()?
            .unwrap_or_default();
        let total = total_value
            .map(codec::decode_namespace_usage)
            .transpose()?
            .unwrap_or_default();
        let delta = local
            .delta_from(old)
            .ok_or_else(|| StoreError::Corrupt("namespace contribution decreased".into()))?;
        if delta == NamespaceUsage::default() {
            return Ok(total);
        }
        let next = total
            .checked_add(delta)
            .ok_or_else(|| StoreError::Corrupt("namespace total overflow".into()))?;
        let batch = Batch::new()
            .require(guard(source_key.clone(), old_value))
            .require(guard(total_key.clone(), total_value))
            .put(source_key.clone(), codec::encode_namespace_usage(local))
            .put(total_key.clone(), codec::encode_namespace_usage(next));
        match target.apply(coordinator, batch).await? {
            BatchOutcome::Committed => return Ok(next),
            BatchOutcome::PreconditionFailed { .. } => {}
            BatchOutcome::DeadlinePassed { .. } => unreachable!("no timer deadline"),
        }
    }
    Err(StoreError::Invalid("namespace aggregate contention".into()))
}

/// Delete this source's old contribution. The last source also deletes the
/// obsolete aggregate. A crash before local cleanup safely re-adds and
/// removes the cumulative contribution on the next fire.
async fn prune_coordinator<T: NamespaceStore>(
    target: &T,
    coordinator: &Partition,
    source: &Partition,
    window: u64,
) -> Result<(), StoreError> {
    let source_key = keys::quota_contribution(window, source)?;
    let total_key = keys::quota_total(window);
    let source_value = target.get(coordinator, &source_key).await?;
    let (start, end) = keys::quota_namespace_window(keys::TAG_QUOTA_CONTRIBUTION, window);
    let page = target.scan(coordinator, &start, &end, None, 2).await?;
    let only_source = page.next.is_none() && page.entries.iter().all(|(key, _)| *key == source_key);
    let total_value = if only_source {
        target.get(coordinator, &total_key).await?
    } else {
        None
    };
    let mut batch = Batch::new()
        .require(guard(source_key.clone(), source_value.as_ref()))
        .delete(source_key);
    if only_source {
        batch = batch
            .require(guard(total_key.clone(), total_value.as_ref()))
            .delete(total_key);
    }
    batch = prune_older(
        target,
        coordinator,
        keys::TAG_QUOTA_CONTRIBUTION,
        window,
        batch,
    )
    .await?;
    batch = prune_older(target, coordinator, keys::TAG_QUOTA_TOTAL, window, batch).await?;
    match target.apply(coordinator, batch).await? {
        BatchOutcome::Committed => Ok(()),
        BatchOutcome::PreconditionFailed { .. } => {
            Err(StoreError::Invalid("namespace prune contention".into()))
        }
        BatchOutcome::DeadlinePassed { .. } => unreachable!("no timer deadline"),
    }
}

async fn fire_exact<S: NamespaceStore>(
    ctx: &TimerCtx<'_, S>,
    timer: &DueTimer,
    window: u64,
    end: u64,
    expired: bool,
) -> Result<Fired, StoreError> {
    let key = keys::quota_total(window);
    let value = ctx.store.get(ctx.partition, &key).await?;
    if expired {
        let batch = Batch::new()
            .require(guard(key.clone(), value.as_ref()))
            .delete(key);
        let batch = prune_older(
            ctx.store,
            ctx.partition,
            keys::TAG_QUOTA_TOTAL,
            window,
            batch,
        )
        .await?;
        let batch = prune_older(
            ctx.store,
            ctx.partition,
            keys::TAG_QUOTA_CONTRIBUTION,
            window,
            batch,
        )
        .await?;
        Ok(Fired::Done(batch))
    } else {
        Ok(Fired::Reschedule {
            due_at_ms: end
                .saturating_add(CLOCK_GRACE_MS)
                .max(timer.due_at_ms.saturating_add(1)),
            value: timer.value.clone(),
            batch: Batch::new().require(guard(key, value.as_ref())),
        })
    }
}

impl<S: NamespaceStore, T: NamespaceStore> TimerHandler<S> for QuotaRollup<T> {
    fn kind(&self) -> TimerKind {
        kinds::QUOTA_ROLLUP
    }

    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            let Ok(reference) = <[u8; 8]>::try_from(timer.reference.as_ref()) else {
                tracing::warn!("discarding malformed quota timer reference");
                return Ok(Fired::Done(Batch::new()));
            };
            let window = u64::from_be_bytes(reference);
            let window_ms = codec::decode_u64(&timer.value)?;
            if window_ms == 0 {
                return Err(StoreError::Corrupt("zero quota window".into()));
            }
            let end = window.saturating_add(1).saturating_mul(window_ms);
            let expired = ctx.now_ms >= end.saturating_add(CLOCK_GRACE_MS);
            match ctx.partition {
                Partition::Ref { ns, .. } => {
                    let key = keys::quota_shard(window);
                    let Some(value) = ctx.store.get(ctx.partition, &key).await? else {
                        return Ok(Fired::Done(Batch::new().delete(keys::quota_view(window))));
                    };
                    let local = codec::decode_namespace_usage(&value)?;
                    let coordinator = Partition::Coordinator(ns.clone());
                    let total = aggregate(
                        &self.coordinator,
                        &coordinator,
                        ctx.partition,
                        window,
                        local,
                    )
                    .await?;
                    let local_batch =
                        Batch::new().require(Precondition::Equals(key.clone(), value));
                    if expired {
                        prune_coordinator(&self.coordinator, &coordinator, ctx.partition, window)
                            .await?;
                        let batch = local_batch.delete(key).delete(keys::quota_view(window));
                        let batch = prune_older(
                            ctx.store,
                            ctx.partition,
                            keys::TAG_QUOTA_SHARD,
                            window,
                            batch,
                        )
                        .await?;
                        let batch = prune_older(
                            ctx.store,
                            ctx.partition,
                            keys::TAG_QUOTA_VIEW,
                            window,
                            batch,
                        )
                        .await?;
                        Ok(Fired::Done(batch))
                    } else {
                        let view = NamespaceView {
                            total,
                            pushed: local,
                            observed_at_ms: ctx.now_ms,
                        };
                        Ok(Fired::Reschedule {
                            due_at_ms: ctx
                                .now_ms
                                .saturating_add(QUOTA_ROLLUP_MS)
                                .max(timer.due_at_ms.saturating_add(1)),
                            value: timer.value.clone(),
                            batch: local_batch
                                .put(keys::quota_view(window), codec::encode_namespace_view(view)),
                        })
                    }
                }
                Partition::Coordinator(_) | Partition::Namespace(_) => {
                    fire_exact(ctx, timer, window, end, expired).await
                }
                _ => Ok(Fired::Retry),
            }
        })
    }
}

#[cfg(all(test, feature = "memory"))]
mod tests {
    use super::*;
    use crate::MemoryKv;
    use crate::repo::{NamespaceKey, RepoName};
    use crate::rt::ManualClock;
    use crate::timers::{TickBudget, TimerRegistry, run_due};
    use bytes::Bytes;
    use std::sync::Arc;

    const WINDOW_MS: u64 = 600_000;

    fn source(i: usize) -> Partition {
        Partition::Ref {
            ns: NamespaceKey::deployment_default(),
            repo: RepoName::new("room").expect("valid test repository"),
            shard_ref: format!("refs/heads/b{i}"),
        }
    }

    fn coordinator() -> Partition {
        Partition::Coordinator(NamespaceKey::deployment_default())
    }

    fn timer(due: u64, window: u64) -> (crate::store::Key, DueTimer) {
        let reference = Bytes::copy_from_slice(&window.to_be_bytes());
        let value = codec::encode_u64(WINDOW_MS);
        (
            keys::timer(due, kinds::QUOTA_ROLLUP.get(), &reference),
            DueTimer {
                due_at_ms: due,
                kind: kinds::QUOTA_ROLLUP,
                reference,
                value,
            },
        )
    }

    async fn usage(store: &MemoryKv, p: &Partition, key: crate::store::Key) -> NamespaceUsage {
        store
            .get(p, &key)
            .await
            .expect("read usage")
            .as_ref()
            .map(codec::decode_namespace_usage)
            .transpose()
            .expect("decode usage")
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn converges_across_shards_and_refire_after_coordinator_crash_is_idempotent() {
        let clock = Arc::new(ManualClock::new(60_000));
        let local = MemoryKv::with_clock(clock.clone());
        let handler = QuotaRollup {
            coordinator: MemoryKv::with_clock(clock.clone()),
        };
        let (_, fired) = timer(60_000, 0);
        for i in 0..4 {
            let (key, _) = timer(60_000, 0);
            local
                .apply(
                    &source(i),
                    Batch::new()
                        .put(
                            keys::quota_shard(0),
                            codec::encode_namespace_usage(NamespaceUsage {
                                ops: (i + 1) as u64,
                                bytes: i as u64,
                            }),
                        )
                        .put(key, codec::encode_u64(WINDOW_MS)),
                )
                .await
                .unwrap();
        }
        // Simulate a crash after target apply but before the returned local
        // view/timer batch. The same fire sees qc and adds zero delta.
        let first_source = source(0);
        let ctx = TimerCtx {
            store: &local,
            partition: &first_source,
            now_ms: 60_000,
        };
        let first = handler.fire(&ctx, &fired).await.unwrap();
        assert!(matches!(first, Fired::Reschedule { .. }));
        assert_eq!(
            usage(&handler.coordinator, &coordinator(), keys::quota_total(0))
                .await
                .ops,
            1
        );
        let again = handler.fire(&ctx, &fired).await.unwrap();
        assert!(matches!(again, Fired::Reschedule { .. }));
        assert_eq!(
            usage(&handler.coordinator, &coordinator(), keys::quota_total(0))
                .await
                .ops,
            1
        );

        for i in 0..4 {
            let partition = source(i);
            let ctx = TimerCtx {
                store: &local,
                partition: &partition,
                now_ms: 60_000,
            };
            assert!(matches!(
                handler.fire(&ctx, &fired).await.unwrap(),
                Fired::Reschedule { .. }
            ));
        }
        assert_eq!(
            usage(&handler.coordinator, &coordinator(), keys::quota_total(0)).await,
            NamespaceUsage { ops: 10, bytes: 6 }
        );
        for i in 0..4 {
            let partition = source(i);
            let ctx = TimerCtx {
                store: &local,
                partition: &partition,
                now_ms: 60_000,
            };
            let Fired::Reschedule { batch, .. } = handler.fire(&ctx, &fired).await.unwrap() else {
                panic!("must reschedule")
            };
            let view_value = batch
                .writes
                .iter()
                .find_map(|write| match write {
                    crate::store::Write::Put(key, value) if *key == keys::quota_view(0) => {
                        Some(value)
                    }
                    _ => None,
                })
                .unwrap();
            let view = codec::decode_namespace_view(view_value).unwrap();
            assert_eq!(view.total.ops, 10);
            assert_eq!(view.pushed.ops, (i + 1) as u64);
        }
    }

    #[tokio::test]
    async fn ended_window_prunes_both_partitions_and_leaves_no_timer() {
        let clock = Arc::new(ManualClock::new(60_000));
        let local = MemoryKv::with_clock(clock.clone());
        let handler = QuotaRollup {
            coordinator: MemoryKv::with_clock(clock.clone()),
        };
        let shard = source(0);
        let (timer_key, _) = timer(60_000, 0);
        local
            .apply(
                &shard,
                Batch::new()
                    .put(
                        keys::quota_shard(0),
                        codec::encode_namespace_usage(NamespaceUsage { ops: 3, bytes: 12 }),
                    )
                    .put(timer_key, codec::encode_u64(WINDOW_MS)),
            )
            .await
            .unwrap();
        let registry = TimerRegistry::new().register(handler);
        let first = run_due(
            &local,
            &shard,
            &registry,
            clock.as_ref(),
            60_000,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(first.fired, 1);
        assert!(
            local
                .get(&shard, &keys::quota_view(0))
                .await
                .unwrap()
                .is_some()
        );
        let before = local.stats(&shard).await.unwrap().keys.unwrap();
        clock.set(700_000);
        let last = run_due(
            &local,
            &shard,
            &registry,
            clock.as_ref(),
            700_000,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(last.fired, 1);
        assert_eq!(last.next_wake_ms, None);
        assert_eq!(local.stats(&shard).await.unwrap().keys, Some(0));
        assert!(before >= 3);
    }

    #[tokio::test]
    async fn final_fire_removes_old_coordinator_rows() {
        let clock = Arc::new(ManualClock::new(700_000));
        let local = MemoryKv::with_clock(clock.clone());
        let handler = QuotaRollup {
            coordinator: MemoryKv::with_clock(clock),
        };
        let shard = source(0);
        let (_, fired) = timer(60_000, 0);
        local
            .apply(
                &shard,
                Batch::new().put(
                    keys::quota_shard(0),
                    codec::encode_namespace_usage(NamespaceUsage { ops: 2, bytes: 0 }),
                ),
            )
            .await
            .unwrap();
        let ctx = TimerCtx {
            store: &local,
            partition: &shard,
            now_ms: 700_000,
        };
        let Fired::Done(_) = handler.fire(&ctx, &fired).await.unwrap() else {
            panic!("ended window must stop")
        };
        assert_eq!(
            handler
                .coordinator
                .stats(&coordinator())
                .await
                .unwrap()
                .keys,
            Some(0)
        );
    }

    #[tokio::test]
    async fn coordinator_direct_charge_remains_in_the_aggregate() {
        let clock = Arc::new(ManualClock::new(60_000));
        let local = MemoryKv::with_clock(clock.clone());
        let handler = QuotaRollup {
            coordinator: MemoryKv::with_clock(clock),
        };
        let shard = source(0);
        local
            .apply(
                &shard,
                Batch::new().put(
                    keys::quota_shard(0),
                    codec::encode_namespace_usage(NamespaceUsage { ops: 2, bytes: 0 }),
                ),
            )
            .await
            .unwrap();
        handler
            .coordinator
            .apply(
                &coordinator(),
                Batch::new().put(
                    keys::quota_total(0),
                    codec::encode_namespace_usage(NamespaceUsage { ops: 1, bytes: 9 }),
                ),
            )
            .await
            .unwrap();
        let (_, fired) = timer(60_000, 0);
        let ctx = TimerCtx {
            store: &local,
            partition: &shard,
            now_ms: 60_000,
        };
        assert!(matches!(
            handler.fire(&ctx, &fired).await.unwrap(),
            Fired::Reschedule { .. }
        ));
        assert_eq!(
            usage(&handler.coordinator, &coordinator(), keys::quota_total(0)).await,
            NamespaceUsage { ops: 3, bytes: 9 }
        );
    }

    #[tokio::test]
    async fn exact_partition_timer_stops_after_window_end() {
        let clock = Arc::new(ManualClock::new(700_000));
        let store = MemoryKv::with_clock(clock.clone());
        let registry = TimerRegistry::new().register(QuotaRollup {
            coordinator: MemoryKv::with_clock(clock.clone()),
        });
        for partition in [
            Partition::Namespace(NamespaceKey::deployment_default()),
            coordinator(),
        ] {
            let (key, _) = timer(630_000, 0);
            store
                .apply(
                    &partition,
                    Batch::new()
                        .put(
                            keys::quota_total(0),
                            codec::encode_namespace_usage(NamespaceUsage { ops: 1, bytes: 0 }),
                        )
                        .put(key, codec::encode_u64(WINDOW_MS)),
                )
                .await
                .unwrap();
            let report = run_due(
                &store,
                &partition,
                &registry,
                clock.as_ref(),
                700_000,
                &TickBudget::default(),
            )
            .await
            .unwrap();
            assert_eq!(report.fired, 1);
            assert_eq!(report.next_wake_ms, None);
            assert_eq!(store.stats(&partition).await.unwrap().keys, Some(0));
        }
    }
}
