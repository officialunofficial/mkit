//! Reconcile each ref shard's cumulative fixed-window quota into its
//! coordinator. The coordinator apply precedes the local view write; a crash
//! between them is safe because `qc` stores the last applied cumulative count.

use super::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};
use crate::quota::{NamespaceUsage, NamespaceView, QUOTA_ROLLUP_MS};
use crate::rt::BoxFuture;
use crate::store::{
    Batch, BatchOutcome, NamespaceStore, Partition, Precondition, StoreError, Value, codec, keys,
};
use crate::telemetry::{
    METRIC_NAMESPACE_QUOTA_REBASE, METRIC_NAMESPACE_QUOTA_ROLLUP_ERROR, Metrics, NoopMetrics,
};

const MAX_AGGREGATE_REPLANS: usize = 8;
const CLOCK_GRACE_MS: u64 = mkit_core::write_auth::MAX_CLOCK_LEAD_MS.unsigned_abs();

/// A source-side kind-5 handler with a client for the namespace coordinator.
#[derive(Debug)]
pub struct QuotaRollup<T, M = NoopMetrics> {
    /// Store client capable of reaching the coordinator partition.
    pub coordinator: T,
    /// Metrics sink shared with the serving adapter.
    pub metrics: M,
}

fn rollup_error<M: Metrics>(metrics: &M, error: &StoreError) {
    let reason = match error {
        StoreError::Corrupt(_) => "corrupt",
        StoreError::Invalid(_) => "contention",
        _ => "storage",
    };
    tracing::error!(%error, reason, "namespace quota rollup failed");
    metrics.incr(
        METRIC_NAMESPACE_QUOTA_ROLLUP_ERROR,
        &[("reason", reason)],
        1,
    );
}

fn guard(key: crate::store::Key, value: Option<&Value>) -> Precondition {
    match value {
        Some(value) => Precondition::Equals(key, value.clone()),
        None => Precondition::Absent(key),
    }
}

/// Drain an older-window range in guarded batches of at most eight keys.
/// The timer remains present until the caller commits its final batch, so a
/// crash or a raced page can resume without retaining stale windows.
async fn prune_older<S: NamespaceStore>(
    store: &S,
    partition: &Partition,
    tag: &str,
    window: u64,
) -> Result<(), StoreError> {
    if window == 0 {
        return Ok(());
    }
    let (start, end) = keys::quota_namespace_before(tag, window);
    let mut races = 0;
    loop {
        let page = store.scan(partition, &start, &end, None, 8).await?;
        if page.entries.is_empty() {
            return Ok(());
        }
        let mut batch = Batch::new();
        for (key, value) in page.entries {
            batch = batch
                .require(Precondition::Equals(key.clone(), value))
                .delete(key);
        }
        debug_assert!(
            batch.preconditions.len() + batch.writes.len() <= crate::store::MAX_BATCH_OPS
        );
        match store.apply(partition, batch).await? {
            BatchOutcome::Committed => races = 0,
            BatchOutcome::PreconditionFailed { .. } if races < 8 => races += 1,
            BatchOutcome::PreconditionFailed { .. } => {
                return Err(StoreError::Invalid("namespace prune contention".into()));
            }
            BatchOutcome::DeadlinePassed { .. } => {
                return Err(StoreError::Invalid(
                    "namespace prune had no deadline".into(),
                ));
            }
        }
    }
}

async fn aggregate<T: NamespaceStore, M: Metrics>(
    target: &T,
    metrics: &M,
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
        if local == old {
            return Ok(total);
        }
        let rebased = local.delta_from(old).is_none();
        let removed = NamespaceUsage {
            ops: old.ops.saturating_sub(local.ops),
            bytes: old.bytes.saturating_sub(local.bytes),
        };
        let added = NamespaceUsage {
            ops: local.ops.saturating_sub(old.ops),
            bytes: local.bytes.saturating_sub(old.bytes),
        };
        let next = NamespaceUsage {
            ops: total.ops.saturating_sub(removed.ops),
            bytes: total.bytes.saturating_sub(removed.bytes),
        }
        .checked_add(added)
        .ok_or_else(|| StoreError::Corrupt("namespace total overflow".into()))?;
        let batch = Batch::new()
            .require(guard(source_key.clone(), old_value))
            .require(guard(total_key.clone(), total_value))
            .put(source_key.clone(), codec::encode_namespace_usage(local))
            .put(total_key.clone(), codec::encode_namespace_usage(next));
        match target.apply(coordinator, batch).await? {
            BatchOutcome::Committed => {
                if rebased {
                    tracing::warn!(
                        window,
                        "namespace quota contribution decreased; re-baselined"
                    );
                    metrics.incr(METRIC_NAMESPACE_QUOTA_REBASE, &[], 1);
                }
                return Ok(next);
            }
            BatchOutcome::PreconditionFailed { .. } => {}
            BatchOutcome::DeadlinePassed { .. } => {
                return Err(StoreError::Invalid(
                    "namespace aggregate had no deadline".into(),
                ));
            }
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
    prune_older(target, coordinator, keys::TAG_QUOTA_CONTRIBUTION, window).await?;
    prune_older(target, coordinator, keys::TAG_QUOTA_TOTAL, window).await?;
    match target.apply(coordinator, batch).await? {
        BatchOutcome::Committed => Ok(()),
        BatchOutcome::PreconditionFailed { .. } => {
            Err(StoreError::Invalid("namespace prune contention".into()))
        }
        BatchOutcome::DeadlinePassed { .. } => Err(StoreError::Invalid(
            "namespace prune had no deadline".into(),
        )),
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
        prune_older(ctx.store, ctx.partition, keys::TAG_QUOTA_TOTAL, window).await?;
        prune_older(
            ctx.store,
            ctx.partition,
            keys::TAG_QUOTA_CONTRIBUTION,
            window,
        )
        .await?;
        Ok(Fired::Done(batch))
    } else {
        Ok(Fired::Reschedule {
            due_at_ms: end
                .saturating_add(CLOCK_GRACE_MS)
                .max(timer.due_at_ms.saturating_add(1)),
            value: timer.value.clone(),
            batch: Batch::new(),
        })
    }
}

impl<S: NamespaceStore, T: NamespaceStore, M: Metrics> TimerHandler<S> for QuotaRollup<T, M> {
    fn kind(&self) -> TimerKind {
        kinds::QUOTA_ROLLUP
    }

    #[allow(clippy::too_many_lines)] // One fire must finish coordinator cleanup before its local timer batch.
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
                    let coordinator = Partition::Coordinator(ns.clone());
                    let backoff = || Fired::Reschedule {
                        due_at_ms: ctx
                            .now_ms
                            .saturating_add(QUOTA_ROLLUP_MS)
                            .max(timer.due_at_ms.saturating_add(1)),
                        value: timer.value.clone(),
                        batch: Batch::new(),
                    };
                    let Some(value) = ctx.store.get(ctx.partition, &key).await? else {
                        if expired {
                            if let Err(error) = prune_coordinator(
                                &self.coordinator,
                                &coordinator,
                                ctx.partition,
                                window,
                            )
                            .await
                            {
                                rollup_error(&self.metrics, &error);
                                return Ok(backoff());
                            }
                            prune_older(ctx.store, ctx.partition, keys::TAG_QUOTA_SHARD, window)
                                .await?;
                            prune_older(ctx.store, ctx.partition, keys::TAG_QUOTA_VIEW, window)
                                .await?;
                        }
                        return Ok(Fired::Done(Batch::new().delete(keys::quota_view(window))));
                    };
                    let local = codec::decode_namespace_usage(&value)?;
                    let aggregated = aggregate(
                        &self.coordinator,
                        &self.metrics,
                        &coordinator,
                        ctx.partition,
                        window,
                        local,
                    )
                    .await;
                    if expired {
                        if let Err(error) = aggregated {
                            rollup_error(&self.metrics, &error);
                        }
                        if let Err(error) = prune_coordinator(
                            &self.coordinator,
                            &coordinator,
                            ctx.partition,
                            window,
                        )
                        .await
                        {
                            rollup_error(&self.metrics, &error);
                            return Ok(backoff());
                        }
                        prune_older(ctx.store, ctx.partition, keys::TAG_QUOTA_SHARD, window)
                            .await?;
                        prune_older(ctx.store, ctx.partition, keys::TAG_QUOTA_VIEW, window).await?;
                        let batch = Batch::new()
                            .require(Precondition::Equals(key.clone(), value))
                            .delete(key)
                            .delete(keys::quota_view(window));
                        Ok(Fired::Done(batch))
                    } else {
                        let total = match aggregated {
                            Ok(total) => total,
                            Err(error) => {
                                rollup_error(&self.metrics, &error);
                                return Ok(backoff());
                            }
                        };
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
                            batch: Batch::new()
                                .put(keys::quota_view(window), codec::encode_namespace_view(view)),
                        })
                    }
                }
                Partition::Coordinator(_) | Partition::Namespace(_) => {
                    fire_exact(ctx, timer, window, end, expired).await
                }
                _ => {
                    tracing::warn!(partition = ?ctx.partition, "discarding quota timer on unexpected partition");
                    Ok(Fired::Done(Batch::new()))
                }
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    const WINDOW_MS: u64 = 600_000;

    #[derive(Debug, Default, Clone)]
    struct CountMetrics(Arc<Mutex<Vec<(&'static str, String)>>>);

    impl Metrics for CountMetrics {
        fn incr(&self, name: &'static str, labels: &[(&'static str, &str)], _by: u64) {
            self.0.lock().expect("metrics lock").push((
                name,
                labels
                    .iter()
                    .find(|(key, _)| *key == "reason")
                    .map_or(String::new(), |(_, value)| (*value).to_owned()),
            ));
        }

        fn observe_ms(&self, _: &'static str, _: &[(&'static str, &str)], _: f64) {}
    }

    #[derive(Debug, Clone)]
    struct SharedStore {
        inner: Arc<MemoryKv>,
        batches: Arc<Mutex<Vec<(Partition, usize)>>>,
        contend: Arc<AtomicBool>,
    }

    impl SharedStore {
        fn new(clock: Arc<ManualClock>) -> Self {
            Self {
                inner: Arc::new(MemoryKv::with_clock(clock)),
                batches: Arc::new(Mutex::new(Vec::new())),
                contend: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl NamespaceStore for SharedStore {
        fn capabilities(&self) -> crate::store::StoreCapabilities {
            self.inner.capabilities()
        }

        async fn get(
            &self,
            p: &Partition,
            key: &crate::store::Key,
        ) -> Result<Option<Value>, StoreError> {
            self.inner.get(p, key).await
        }

        async fn get_many(
            &self,
            p: &Partition,
            keys: &[crate::store::Key],
        ) -> Result<Vec<Option<Value>>, StoreError> {
            self.inner.get_many(p, keys).await
        }

        async fn scan(
            &self,
            p: &Partition,
            start: &crate::store::Key,
            end: &crate::store::Key,
            after: Option<&crate::store::Cursor>,
            limit: u32,
        ) -> Result<crate::store::ScanPage, StoreError> {
            self.inner.scan(p, start, end, after, limit).await
        }

        async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
            self.batches
                .lock()
                .expect("batch log lock")
                .push((p.clone(), batch.preconditions.len() + batch.writes.len()));
            if self.contend.load(Ordering::SeqCst) {
                return Ok(BatchOutcome::PreconditionFailed {
                    index: 0,
                    observed: None,
                });
            }
            self.inner.apply(p, batch).await
        }

        async fn stats(&self, p: &Partition) -> Result<crate::store::PartitionStats, StoreError> {
            self.inner.stats(p).await
        }

        async fn probe(&self) -> Result<(), StoreError> {
            self.inner.probe().await
        }
    }

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

    async fn usage<S: NamespaceStore>(
        store: &S,
        p: &Partition,
        key: crate::store::Key,
    ) -> NamespaceUsage {
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
            metrics: NoopMetrics,
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
        let Fired::Reschedule { batch, .. } = first else {
            panic!("must reschedule")
        };
        assert!(
            batch.preconditions.is_empty(),
            "view refresh does not guard qs"
        );
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
            metrics: NoopMetrics,
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
            metrics: NoopMetrics,
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
            metrics: NoopMetrics,
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
    async fn decreased_contribution_rebaselines_then_prunes_after_idle() {
        let window = 2;
        let first_due = window * WINDOW_MS + QUOTA_ROLLUP_MS;
        let clock = Arc::new(ManualClock::new(first_due.cast_signed()));
        let local = SharedStore::new(clock.clone());
        let coordinator_store = SharedStore::new(clock.clone());
        let metrics = CountMetrics::default();
        let shard = source(0);
        let old = NamespaceUsage { ops: 5, bytes: 10 };
        let restored = NamespaceUsage { ops: 2, bytes: 12 };
        let (timer_key, _) = timer(first_due, window);
        local
            .apply(
                &shard,
                Batch::new()
                    .put(
                        keys::quota_shard(window),
                        codec::encode_namespace_usage(restored),
                    )
                    .put(timer_key, codec::encode_u64(WINDOW_MS)),
            )
            .await
            .unwrap();
        coordinator_store
            .apply(
                &coordinator(),
                Batch::new()
                    .put(
                        keys::quota_contribution(window, &shard).unwrap(),
                        codec::encode_namespace_usage(old),
                    )
                    .put(
                        keys::quota_total(window),
                        codec::encode_namespace_usage(old),
                    ),
            )
            .await
            .unwrap();
        let registry = TimerRegistry::new().register(QuotaRollup {
            coordinator: coordinator_store.clone(),
            metrics: metrics.clone(),
        });
        let first = run_due(
            &local,
            &shard,
            &registry,
            clock.as_ref(),
            first_due,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(first.fired, 1);
        assert_eq!(
            usage(
                &coordinator_store,
                &coordinator(),
                keys::quota_total(window)
            )
            .await,
            restored
        );
        assert_eq!(
            usage(
                &coordinator_store,
                &coordinator(),
                keys::quota_contribution(window, &shard).unwrap()
            )
            .await,
            restored
        );
        assert_eq!(
            metrics.0.lock().unwrap().as_slice(),
            &[(METRIC_NAMESPACE_QUOTA_REBASE, String::new())]
        );
        let expired = (window + 1) * WINDOW_MS + CLOCK_GRACE_MS + 1;
        clock.set(expired.cast_signed());
        let last = run_due(
            &local,
            &shard,
            &registry,
            clock.as_ref(),
            expired,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(last.fired, 1);
        assert_eq!(last.next_wake_ms, None);
        assert_eq!(local.stats(&shard).await.unwrap().keys, Some(0));
        assert_eq!(
            coordinator_store.stats(&coordinator()).await.unwrap().keys,
            Some(0)
        );
    }

    #[tokio::test]
    async fn expired_window_drains_more_than_eight_older_rows_per_class() {
        let window = 12;
        let due = (window + 1) * WINDOW_MS + CLOCK_GRACE_MS + 1;
        let clock = Arc::new(ManualClock::new(due.cast_signed()));
        let local = SharedStore::new(clock.clone());
        let coordinator_store = SharedStore::new(clock.clone());
        let shard = source(0);
        let one = codec::encode_namespace_usage(NamespaceUsage { ops: 1, bytes: 0 });
        let view = codec::encode_namespace_view(NamespaceView {
            total: NamespaceUsage { ops: 1, bytes: 0 },
            pushed: NamespaceUsage::default(),
            observed_at_ms: due,
        });
        let mut local_rows = Batch::new().put(keys::quota_shard(window), one.clone());
        let mut coordinator_rows = Batch::new();
        for old in 0..window {
            local_rows = local_rows
                .put(keys::quota_shard(old), one.clone())
                .put(keys::quota_view(old), view.clone());
            coordinator_rows = coordinator_rows
                .put(keys::quota_contribution(old, &shard).unwrap(), one.clone())
                .put(keys::quota_total(old), one.clone());
        }
        let (timer_key, _) = timer(due, window);
        local_rows = local_rows.put(timer_key, codec::encode_u64(WINDOW_MS));
        assert_eq!(
            local.apply(&shard, local_rows).await.unwrap(),
            BatchOutcome::Committed
        );
        assert_eq!(
            coordinator_store
                .apply(&coordinator(), coordinator_rows)
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        let registry = TimerRegistry::new().register(QuotaRollup {
            coordinator: coordinator_store.clone(),
            metrics: NoopMetrics,
        });
        let report = run_due(
            &local,
            &shard,
            &registry,
            clock.as_ref(),
            due,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        let coord = coordinator();
        for (store, partition) in [(&local, &shard), (&coordinator_store, &coord)] {
            assert!(
                store
                    .batches
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|(p, ops)| { p == partition && *ops <= crate::store::MAX_BATCH_OPS })
            );
        }
        assert_eq!(report.fired, 1);
        assert_eq!(report.failed, 0);
        assert_eq!(report.next_wake_ms, None);
        assert_eq!(local.stats(&shard).await.unwrap().keys, Some(0));
        assert_eq!(
            coordinator_store.stats(&coordinator()).await.unwrap().keys,
            Some(0)
        );
    }

    #[tokio::test]
    async fn corrupt_coordinator_row_backs_off_for_a_full_period() {
        let clock = Arc::new(ManualClock::new(QUOTA_ROLLUP_MS.cast_signed()));
        let local = SharedStore::new(clock.clone());
        let coordinator_store = SharedStore::new(clock.clone());
        let metrics = CountMetrics::default();
        let shard = source(0);
        let (timer_key, _) = timer(QUOTA_ROLLUP_MS, 0);
        local
            .apply(
                &shard,
                Batch::new()
                    .put(
                        keys::quota_shard(0),
                        codec::encode_namespace_usage(NamespaceUsage { ops: 1, bytes: 0 }),
                    )
                    .put(timer_key, codec::encode_u64(WINDOW_MS)),
            )
            .await
            .unwrap();
        coordinator_store
            .apply(
                &coordinator(),
                Batch::new().put(keys::quota_total(0), Value::new(vec![1])),
            )
            .await
            .unwrap();
        let registry = TimerRegistry::new().register(QuotaRollup {
            coordinator: coordinator_store.clone(),
            metrics: metrics.clone(),
        });
        let report = run_due(
            &local,
            &shard,
            &registry,
            clock.as_ref(),
            QUOTA_ROLLUP_MS,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.fired, 1);
        assert_eq!(report.next_wake_ms, Some(2 * QUOTA_ROLLUP_MS));
        assert_eq!(
            metrics.0.lock().unwrap().as_slice(),
            &[(METRIC_NAMESPACE_QUOTA_ROLLUP_ERROR, "corrupt".to_owned())]
        );
        let expired = WINDOW_MS + CLOCK_GRACE_MS + 1;
        clock.set(expired.cast_signed());
        let final_fire = run_due(
            &local,
            &shard,
            &registry,
            clock.as_ref(),
            expired,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(final_fire.fired, 1);
        assert_eq!(final_fire.next_wake_ms, None);
        assert_eq!(local.stats(&shard).await.unwrap().keys, Some(0));
        assert_eq!(
            coordinator_store.stats(&coordinator()).await.unwrap().keys,
            Some(0)
        );
    }

    #[tokio::test]
    async fn exhausted_aggregate_replans_log_and_back_off() {
        let clock = Arc::new(ManualClock::new(QUOTA_ROLLUP_MS.cast_signed()));
        let local = MemoryKv::with_clock(clock.clone());
        let coordinator_store = SharedStore::new(clock);
        coordinator_store.contend.store(true, Ordering::SeqCst);
        let metrics = CountMetrics::default();
        let shard = source(0);
        local
            .apply(
                &shard,
                Batch::new().put(
                    keys::quota_shard(0),
                    codec::encode_namespace_usage(NamespaceUsage { ops: 1, bytes: 0 }),
                ),
            )
            .await
            .unwrap();
        let handler = QuotaRollup {
            coordinator: coordinator_store.clone(),
            metrics: metrics.clone(),
        };
        let (_, fired) = timer(QUOTA_ROLLUP_MS, 0);
        let ctx = TimerCtx {
            store: &local,
            partition: &shard,
            now_ms: QUOTA_ROLLUP_MS,
        };
        let Fired::Reschedule { due_at_ms, .. } = handler.fire(&ctx, &fired).await.unwrap() else {
            panic!("aggregate contention must back off")
        };
        assert_eq!(due_at_ms, 2 * QUOTA_ROLLUP_MS);
        assert_eq!(
            coordinator_store.batches.lock().unwrap().len(),
            MAX_AGGREGATE_REPLANS
        );
        assert_eq!(
            metrics.0.lock().unwrap().as_slice(),
            &[(METRIC_NAMESPACE_QUOTA_ROLLUP_ERROR, "contention".to_owned())]
        );
    }

    #[tokio::test]
    async fn exact_partition_timer_stops_after_window_end() {
        let clock = Arc::new(ManualClock::new(700_000));
        let store = MemoryKv::with_clock(clock.clone());
        let registry = TimerRegistry::new().register(QuotaRollup {
            coordinator: MemoryKv::with_clock(clock.clone()),
            metrics: NoopMetrics,
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
