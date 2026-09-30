//! Expired epoch-lease table cleanup, confined to the coordinator partition.

use bytes::Bytes;
use std::sync::Arc;

use super::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};
use crate::relay::{RELAY_LAG_BOUND_MS, source_relay_state};
use crate::repo::RepoName;
use crate::rt::BoxFuture;
use crate::store::{Batch, NamespaceStore, Partition, Precondition, StoreError, codec, keys};
use crate::telemetry::{METRIC_RELAY_LEASE_LAG, Metrics, NoopMetrics};

/// Reference shared by the lease grant's timer and its sweep handler.
#[must_use]
pub fn lease_reference(repo: &RepoName, shard_ref: &str) -> Bytes {
    Bytes::from([repo.as_str().as_bytes(), b"\0", shard_ref.as_bytes()].concat())
}

fn discard_malformed_reference(reason: &str) -> Fired {
    tracing::warn!(
        reason,
        "discarding malformed epoch-lease sweep timer reference"
    );
    Fired::Done(Batch::new())
}

/// Deletes a coordinator lease-table row only once its actual expiry passes
/// and its source outbox is empty.
/// Malformed references are warned about and drained without touching lease rows.
pub struct LeaseSweep<T> {
    /// Client for reading ref shards. Absence keeps expired rows.
    pub source: Option<T>,
    metrics: Arc<dyn Metrics>,
}

impl<T: core::fmt::Debug> core::fmt::Debug for LeaseSweep<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LeaseSweep")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl<T> LeaseSweep<T> {
    /// Use a source store to inspect ref-shard outboxes at expiry.
    pub fn new(source: T) -> Self {
        Self::optional(Some(source))
    }

    /// Retain rows when the shard client is unavailable.
    pub fn optional(source: Option<T>) -> Self {
        Self {
            source,
            metrics: Arc::new(NoopMetrics),
        }
    }

    /// Attach the deployment's metrics sink for overdue kept rows.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<dyn Metrics>) -> Self {
        self.metrics = metrics;
        self
    }
}

impl<S: NamespaceStore, T: NamespaceStore> TimerHandler<S> for LeaseSweep<T> {
    fn kind(&self) -> TimerKind {
        kinds::LEASE_SWEEP
    }

    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            if !matches!(ctx.partition, Partition::Coordinator(_)) {
                return Ok(Fired::Retry);
            }
            let Some(sep) = timer.reference.iter().position(|&byte| byte == 0) else {
                return Ok(discard_malformed_reference("missing separator"));
            };
            let (Ok(repo), Ok(shard_ref)) = (
                core::str::from_utf8(&timer.reference[..sep]),
                core::str::from_utf8(&timer.reference[sep + 1..]),
            ) else {
                return Ok(discard_malformed_reference("invalid UTF-8"));
            };
            let Ok(repo) = RepoName::new(repo) else {
                return Ok(discard_malformed_reference("invalid repository name"));
            };
            if !crate::refs::validate_ref_name(shard_ref) {
                return Ok(discard_malformed_reference("invalid shard ref"));
            }
            let key = keys::leased_shard(&repo, shard_ref);
            let Some(value) = ctx.store.get(ctx.partition, &key).await? else {
                return Ok(Fired::Done(Batch::new()));
            };
            let lease = codec::decode_leased_shard(&value)?;
            if timer.due_at_ms != lease.sweep_due_ms {
                // A renewed row owns another timer. Drain only this stale one.
                return Ok(Fired::Done(Batch::new()));
            }
            let batch = Batch::new().require(Precondition::Equals(key.clone(), value));
            if ctx.now_ms >= lease.expires_at_ms {
                let Some(source) = self.source.as_ref() else {
                    return Ok(Fired::Retry);
                };
                let Partition::Coordinator(ns) = ctx.partition else {
                    return Ok(Fired::Retry);
                };
                let shard = Partition::Ref {
                    ns: ns.clone(),
                    repo,
                    shard_ref: shard_ref.into(),
                };
                let (reported, empty) = source_relay_state(source, &shard, ctx.now_ms).await?;
                if empty {
                    Ok(Fired::Done(batch.delete(key)))
                } else {
                    let kept_age_ms = ctx.now_ms.saturating_sub(lease.expires_at_ms);
                    if kept_age_ms > RELAY_LAG_BOUND_MS {
                        tracing::warn!(shard = ?shard, kept_age_ms, "relay backlog kept lease row beyond lag bound");
                        self.metrics.incr(METRIC_RELAY_LEASE_LAG, &[], 1);
                    }
                    let due = ctx
                        .now_ms
                        .saturating_add(10_000)
                        .max(timer.due_at_ms.saturating_add(1));
                    let mut updated = lease;
                    updated.relay_watermark_ms = updated.relay_watermark_ms.max(reported);
                    updated.sweep_due_ms = due;
                    Ok(Fired::Reschedule {
                        due_at_ms: due,
                        value: timer.value.clone(),
                        batch: batch.put(key, codec::encode_leased_shard(&updated)),
                    })
                }
            } else {
                let mut updated = lease;
                updated.sweep_due_ms = lease.expires_at_ms;
                Ok(Fired::Reschedule {
                    due_at_ms: lease.expires_at_ms,
                    value: timer.value.clone(),
                    batch: batch.put(key, codec::encode_leased_shard(&updated)),
                })
            }
        })
    }
}

#[cfg(all(test, feature = "memory"))]
mod tests {
    use super::*;
    use crate::store::{BatchOutcome, Value};
    use crate::store::{Cursor, Key, PartitionStats, ScanPage, StoreCapabilities};
    use crate::timers::{TickBudget, TimerRegistry, run_due};
    use crate::{ManualClock, MemoryKv, NamespaceKey};
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    #[derive(Default)]
    struct CountMetrics(AtomicU64);

    impl Metrics for CountMetrics {
        fn incr(&self, name: &'static str, _: &[(&'static str, &str)], by: u64) {
            if name == METRIC_RELAY_LEASE_LAG {
                self.0.fetch_add(by, Ordering::SeqCst);
            }
        }
        fn observe_ms(&self, _: &'static str, _: &[(&'static str, &str)], _: f64) {}
    }

    fn partition() -> Partition {
        Partition::Coordinator(NamespaceKey::deployment_default())
    }

    fn repo() -> RepoName {
        RepoName::new("room").expect("valid test repository")
    }

    fn lease_key() -> crate::store::Key {
        keys::leased_shard(&repo(), "refs/heads/main")
    }

    fn timer_key(due: u64) -> crate::store::Key {
        keys::timer(
            due,
            kinds::LEASE_SWEEP.get(),
            &lease_reference(&repo(), "refs/heads/main"),
        )
    }

    fn lease(expires_at_ms: u64) -> codec::LeasedShard {
        codec::LeasedShard {
            epoch: 3,
            expires_at_ms,
            acked_epoch: 2,
            relay_watermark_ms: 0,
            sweep_due_ms: expires_at_ms,
        }
    }

    #[tokio::test]
    async fn malformed_references_are_drained_without_deleting_lease_rows() {
        let malformed: &[&[u8]] = &[
            b"roomrefs/heads/main",
            b"\xff\0refs/heads/main",
            b"room\0refs/heads/\xff",
            b"\0refs/heads/main",
            b"has space\0refs/heads/main",
            b"room\0refs/heads/..",
            b"room\0refs/heads/main\0extra",
        ];
        for reference in malformed {
            let clock = Arc::new(ManualClock::new(100));
            let store = MemoryKv::with_clock(clock.clone());
            let partition = partition();
            let timer = keys::timer(100, kinds::LEASE_SWEEP.get(), reference);
            let live_lease = codec::encode_leased_shard(&lease(1_000));
            store
                .apply(
                    &partition,
                    Batch::new()
                        .put(lease_key(), live_lease.clone())
                        .put(timer.clone(), Value::default()),
                )
                .await
                .unwrap();
            let report = run_due(
                &store,
                &partition,
                &TimerRegistry::new().register(LeaseSweep::new(MemoryKv::default())),
                clock.as_ref(),
                100,
                &TickBudget::default(),
            )
            .await
            .unwrap();
            assert_eq!(report.fired, 1, "malformed reference: {reference:?}");
            assert_eq!(report.failed, 0, "malformed reference: {reference:?}");
            assert!(store.get(&partition, &timer).await.unwrap().is_none());
            assert_eq!(
                store.get(&partition, &lease_key()).await.unwrap(),
                Some(live_lease),
            );
        }
    }

    #[tokio::test]
    async fn expiry_deletes_row_and_timer_atomically() {
        let clock = Arc::new(ManualClock::new(100));
        let store = MemoryKv::with_clock(clock.clone());
        store
            .apply(
                &partition(),
                Batch::new()
                    .put(lease_key(), codec::encode_leased_shard(&lease(100)))
                    .put(timer_key(100), Value::default()),
            )
            .await
            .unwrap();
        let registry = TimerRegistry::new().register(LeaseSweep::new(MemoryKv::default()));
        let report = run_due(
            &store,
            &partition(),
            &registry,
            clock.as_ref(),
            100,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.fired, 1);
        assert!(
            store
                .get(&partition(), &lease_key())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get(&partition(), &timer_key(100))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn overdue_kept_row_emits_lag_metric() {
        let clock = Arc::new(ManualClock::new(60_102));
        let coordinator = MemoryKv::with_clock(clock.clone());
        let source = MemoryKv::with_clock(clock.clone());
        let shard = Partition::Ref {
            ns: NamespaceKey::deployment_default(),
            repo: repo(),
            shard_ref: "refs/heads/main".into(),
        };
        source
            .apply(
                &shard,
                Batch::new().put(
                    keys::relay(1),
                    codec::encode_relay(&codec::RelayV1 {
                        publication_era: false,
                        at_ms: 50,
                        target: partition(),
                        puts: vec![(Key::new(&b"x\0"[..]), Value::default())],
                        deletes: Vec::new(),
                    })
                    .unwrap(),
                ),
            )
            .await
            .unwrap();
        coordinator
            .apply(
                &partition(),
                Batch::new()
                    .put(lease_key(), codec::encode_leased_shard(&lease(100)))
                    .put(timer_key(100), Value::default()),
            )
            .await
            .unwrap();
        let metrics = Arc::new(CountMetrics::default());
        let registry =
            TimerRegistry::new().register(LeaseSweep::new(source).with_metrics(metrics.clone()));
        let report = run_due(
            &coordinator,
            &partition(),
            &registry,
            clock.as_ref(),
            60_102,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.fired, 1);
        assert_eq!(metrics.0.load(Ordering::SeqCst), 1);
        assert!(
            coordinator
                .get(&partition(), &lease_key())
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn renewal_race_prevents_deletion_and_early_timer_moves_to_expiry() {
        let store = MemoryKv::default();
        let old_value = codec::encode_leased_shard(&lease(100));
        store
            .apply(&partition(), Batch::new().put(lease_key(), old_value))
            .await
            .unwrap();
        let timer = DueTimer {
            due_at_ms: 100,
            kind: kinds::LEASE_SWEEP,
            reference: lease_reference(&repo(), "refs/heads/main"),
            value: Value::default(),
        };
        let ctx = TimerCtx {
            store: &store,
            partition: &partition(),
            now_ms: 100,
        };
        let Fired::Done(batch) = LeaseSweep::new(MemoryKv::default())
            .fire(&ctx, &timer)
            .await
            .unwrap()
        else {
            panic!("expired lease must produce a deletion");
        };
        let new_value = codec::encode_leased_shard(&lease(200));
        store
            .apply(
                &partition(),
                Batch::new().put(lease_key(), new_value.clone()),
            )
            .await
            .unwrap();
        assert!(matches!(
            store.apply(&partition(), batch).await.unwrap(),
            BatchOutcome::PreconditionFailed { .. }
        ));
        let Fired::Done(_) = LeaseSweep::new(MemoryKv::default())
            .fire(&ctx, &timer)
            .await
            .unwrap()
        else {
            panic!("stale timer must be drained");
        };
        assert_eq!(
            store.get(&partition(), &lease_key()).await.unwrap(),
            Some(new_value)
        );
    }

    struct UnreachableSource;
    impl NamespaceStore for UnreachableSource {
        fn capabilities(&self) -> StoreCapabilities {
            StoreCapabilities::full()
        }
        async fn get(&self, _: &Partition, _: &Key) -> Result<Option<Value>, StoreError> {
            unreachable!()
        }
        async fn scan(
            &self,
            _: &Partition,
            _: &Key,
            _: &Key,
            _: Option<&Cursor>,
            _: u32,
        ) -> Result<ScanPage, StoreError> {
            Err(StoreError::unavailable(std::io::Error::other(
                "source unreachable",
            )))
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

    #[tokio::test]
    async fn missing_unreachable_and_corrupt_sources_hold_expired_row() {
        let coordinator = MemoryKv::default();
        let row = codec::encode_leased_shard(&lease(100));
        coordinator
            .apply(&partition(), Batch::new().put(lease_key(), row.clone()))
            .await
            .unwrap();
        let timer = DueTimer {
            due_at_ms: 100,
            kind: kinds::LEASE_SWEEP,
            reference: lease_reference(&repo(), "refs/heads/main"),
            value: Value::default(),
        };
        let ctx = TimerCtx {
            store: &coordinator,
            partition: &partition(),
            now_ms: 100,
        };
        assert!(matches!(
            LeaseSweep::<MemoryKv>::optional(None)
                .fire(&ctx, &timer)
                .await
                .unwrap(),
            Fired::Retry
        ));
        assert!(
            LeaseSweep::new(UnreachableSource)
                .fire(&ctx, &timer)
                .await
                .is_err()
        );
        let source = MemoryKv::default();
        let source_partition = Partition::Ref {
            ns: NamespaceKey::deployment_default(),
            repo: repo(),
            shard_ref: "refs/heads/main".into(),
        };
        source
            .apply(
                &source_partition,
                Batch::new().put(keys::relay(1), Value::new(&b"bad"[..])),
            )
            .await
            .unwrap();
        assert!(LeaseSweep::new(source).fire(&ctx, &timer).await.is_err());
        assert_eq!(
            coordinator.get(&partition(), &lease_key()).await.unwrap(),
            Some(row)
        );
    }
}
