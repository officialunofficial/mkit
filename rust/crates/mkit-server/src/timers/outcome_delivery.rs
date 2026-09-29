//! Bounded, at-least-once terminal outcome delivery.

use std::sync::Arc;

use crate::pipeline::{Outcome, OutcomeSink};
use crate::rt::BoxFuture;
use crate::store::codec;
use crate::store::outbox::{guard, plan_ack};
use crate::store::{Batch, Cursor, NamespaceStore, StoreError, Value, keys};
use crate::telemetry::Metrics;
use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};

const MAX_DELIVERY_ROWS: usize = 16;
// The scan cursor names the last examined row. Scanning past the delivery
// budget would strand the unexamined suffix until a full rotation.
const SCAN_ROWS: u32 = 16;
const MAX_CURSOR_BYTES: usize = 4_096;
const MAX_BACKOFF_MS: u64 = 900_000;

/// Kind-8 delivery driver. The sink deduplicates by reservation id.
pub struct OutcomeDelivery<O> {
    /// Deployment sink.
    pub sink: O,
    /// Canonical mkit server origin.
    pub audience: String,
    /// Rows/bytes gauges and synthetic-row counter.
    pub metrics: Arc<dyn Metrics>,
}

impl<O> core::fmt::Debug for OutcomeDelivery<O> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OutcomeDelivery")
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

impl<O: OutcomeSink, S: NamespaceStore> TimerHandler<S> for OutcomeDelivery<O> {
    fn kind(&self) -> TimerKind {
        kinds::OUTCOME_DELIVERY
    }

    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(self.deliver(ctx, timer))
    }
}

fn decode_timer(value: &Value) -> Result<(u32, Option<Cursor>), StoreError> {
    if value.as_bytes().is_empty() {
        return Ok((0, None));
    }
    let bytes = value.as_bytes();
    if bytes.len() < 6 {
        return Err(StoreError::Corrupt("bad outcome timer cursor".into()));
    }
    let attempt = u32::from_be_bytes(
        bytes[..4]
            .try_into()
            .map_err(|_| StoreError::Corrupt("bad outcome timer attempt".into()))?,
    );
    let length = u16::from_be_bytes(
        bytes[4..6]
            .try_into()
            .map_err(|_| StoreError::Corrupt("bad outcome timer length".into()))?,
    ) as usize;
    if length > MAX_CURSOR_BYTES || bytes.len() != 6 + length {
        return Err(StoreError::Corrupt("bad outcome timer cursor".into()));
    }
    Ok((
        attempt,
        (length > 0).then(|| Cursor::new(bytes[6..].to_vec())),
    ))
}

fn encode_timer(attempt: u32, cursor: Option<&Cursor>) -> Result<Value, StoreError> {
    let bytes = cursor.map_or(&[][..], Cursor::as_bytes);
    if bytes.len() > MAX_CURSOR_BYTES {
        return Err(StoreError::Corrupt("outcome scan cursor too large".into()));
    }
    let mut value = Vec::with_capacity(6 + bytes.len());
    value.extend_from_slice(&attempt.to_be_bytes());
    let length = u16::try_from(bytes.len())
        .map_err(|_| StoreError::Corrupt("outcome scan cursor too large".into()))?;
    value.extend_from_slice(&length.to_be_bytes());
    value.extend_from_slice(bytes);
    Ok(Value::new(value))
}

fn backoff(partition: &crate::store::Partition, attempt: u32) -> Result<u64, StoreError> {
    let base = 1_000u64
        .saturating_mul(1u64 << attempt.min(20))
        .min(MAX_BACKOFF_MS);
    let mut seed = partition.encode()?.to_vec();
    seed.extend_from_slice(&attempt.to_be_bytes());
    let hash = blake3::hash(&seed);
    let jitter =
        u64::from(u16::from_be_bytes([hash.as_bytes()[0], hash.as_bytes()[1]])) % (base / 5 + 1);
    Ok(base.saturating_add(jitter).min(MAX_BACKOFF_MS))
}

impl<O: OutcomeSink> OutcomeDelivery<O> {
    #[allow(clippy::cast_precision_loss, clippy::too_many_lines)] // Metrics approximate large counters; one fire plans one guarded delivery batch.
    async fn deliver<S: NamespaceStore>(
        &self,
        ctx: &TimerCtx<'_, S>,
        timer: &DueTimer,
    ) -> Result<Fired, StoreError> {
        let oc_key = keys::outcome_backlog();
        let oc = ctx.store.get(ctx.partition, &oc_key).await?;
        let backlog = oc
            .as_ref()
            .map(codec::decode_backlog)
            .transpose()?
            .unwrap_or_default();
        let labels_rows = [("shard_kind", ctx.partition.kind()), ("unit", "rows")];
        let labels_bytes = [("shard_kind", ctx.partition.kind()), ("unit", "bytes")];
        self.metrics.gauge(
            "mkit_server_outbox_backlog",
            &labels_rows,
            backlog.rows as f64,
        );
        self.metrics.gauge(
            "mkit_server_outbox_backlog",
            &labels_bytes,
            backlog.bytes as f64,
        );
        if backlog.rows == 0 {
            return Ok(Fired::Done(
                Batch::new().require(guard(oc_key, oc.as_ref())),
            ));
        }
        let (attempt, cursor) = decode_timer(&timer.value)?;
        let (start, end) = keys::class_range(keys::TAG_OUTCOME_PENDING);
        let mut page = ctx
            .store
            .scan(ctx.partition, &start, &end, cursor.as_ref(), SCAN_ROWS)
            .await?;
        if page.entries.is_empty() && cursor.is_some() && page.next.is_none() {
            page = ctx
                .store
                .scan(ctx.partition, &start, &end, None, SCAN_ROWS)
                .await?;
        }
        let mut batch = Batch::new();
        let mut delivered = 0u64;
        let mut sink_retry_ms = 0u64;
        // Acknowledged rows are planned after the sink loop, against a fresh
        // `oc`, so slow sink awaits sit outside the read-modify-write window.
        let mut acked: Vec<(String, Value, u64)> = Vec::new();
        for (key, _) in page.entries.iter().take(MAX_DELIVERY_ROWS) {
            let Some(keys::ParsedKey::OutcomePending {
                seq,
                reservation_id: rid,
            }) = keys::parse(key)
            else {
                tracing::warn!("invalid outcome index row; retaining");
                continue;
            };
            let Some(value) = ctx
                .store
                .get(ctx.partition, &keys::reservation(&rid)?)
                .await?
            else {
                tracing::warn!("missing terminal outcome row; retaining index");
                continue;
            };
            let record = match codec::decode_reservation(&value) {
                Ok(record) => record,
                Err(err) => {
                    tracing::warn!(error = %err, "undecodable terminal outcome; retaining");
                    continue;
                }
            };
            let outcome =
                match Outcome::from_reservation(rid.clone(), self.audience.clone(), record) {
                    Ok(outcome) => outcome,
                    Err(reason) => {
                        tracing::warn!(reason, "indexed outcome cannot be delivered; retaining");
                        continue;
                    }
                };
            let acknowledged = if rid.starts_with("s:") {
                self.metrics
                    .incr("mkit_server_synthetic_outcomes_acked", &[], 1);
                true
            } else {
                match self.sink.deliver(&outcome).await {
                    Ok(()) => true,
                    Err(err) => {
                        sink_retry_ms = sink_retry_ms.max(err.retry_after.map_or(0, |hint| {
                            u64::try_from(hint.as_millis()).unwrap_or(u64::MAX)
                        }));
                        tracing::warn!(reason = %err.reason, "outcome delivery failed");
                        false
                    }
                }
            };
            if acknowledged {
                acked.push((rid, value, seq));
            }
        }
        let fresh_oc = if acked.is_empty() {
            None
        } else {
            ctx.store.get(ctx.partition, &oc_key).await?
        };
        for (rid, value, seq) in &acked {
            match plan_ack(
                rid,
                value,
                *seq,
                fresh_oc.as_ref(),
                &mut batch.preconditions,
                &mut batch.writes,
            ) {
                Ok(()) => delivered += 1,
                Err(err) => {
                    tracing::warn!(error = %err, "outcome acknowledgment not planned; retaining");
                }
            }
        }
        if delivered == backlog.rows {
            return Ok(Fired::Done(batch));
        }
        let next_attempt = if delivered > 0 {
            0
        } else {
            attempt.saturating_add(1)
        };
        let delay = if delivered > 0 {
            0
        } else {
            backoff(ctx.partition, attempt)?
                .max(sink_retry_ms)
                .min(MAX_BACKOFF_MS)
        };
        let due_at_ms = ctx
            .now_ms
            .saturating_add(delay)
            .max(timer.due_at_ms.saturating_add(1));
        Ok(Fired::Reschedule {
            due_at_ms,
            value: encode_timer(next_attempt, page.next.as_ref())?,
            batch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryKv;
    use crate::pipeline::{DeliveryError, OutcomeKind};
    use crate::repo::NamespaceKey;
    use crate::rt::ManualClock;
    use crate::store::codec::{Backlog, ReservationV1};
    use crate::store::outbox::{OutboxBuilder, Terminal};
    use crate::store::{BatchOutcome, Partition, Write};
    use crate::telemetry::NoopMetrics;
    use crate::timers::{TickBudget, TimerRegistry, run_due};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Capture {
        seen: Mutex<Vec<Outcome>>,
        fail: bool,
    }
    impl OutcomeSink for Capture {
        async fn deliver(&self, outcome: &Outcome) -> Result<(), DeliveryError> {
            self.seen.lock().unwrap().push(outcome.clone());
            if self.fail {
                Err(DeliveryError::new("secret sink failure", None))
            } else {
                Ok(())
            }
        }
    }

    fn partition() -> Partition {
        Partition::Namespace(NamespaceKey::deployment_default())
    }

    async fn seed(store: &MemoryKv, ids: &[&str]) {
        let p = partition();
        let prior = codec::encode_reservation(&ReservationV1::Ticketed { ticket_id: [7; 32] });
        let mut initial = Batch::new();
        for rid in ids {
            initial
                .writes
                .push(Write::Put(keys::reservation(rid).unwrap(), prior.clone()));
        }
        assert_eq!(
            store.apply(&p, initial).await.unwrap(),
            BatchOutcome::Committed
        );
        let mut outbox = OutboxBuilder::new(None, None).unwrap();
        for rid in ids {
            outbox.outcome(
                rid,
                &prior,
                Terminal::new(ReservationV1::Committed {
                    repository: "repo".into(),
                    occurred_at_ms: 100,
                    bytes_stored: 1,
                    new_to_repo: 1,
                    new_to_store: 1,
                    refs: vec![],
                })
                .unwrap(),
            );
        }
        let mut batch = Batch::new();
        outbox
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .unwrap();
        assert_eq!(batch.writes.iter().filter(|write| matches!(write, Write::Put(key, _) if matches!(keys::parse(key), Some(keys::ParsedKey::Timer { kind: 8, .. })))).count(), 1);
        assert_eq!(
            store.apply(&p, batch).await.unwrap(),
            BatchOutcome::Committed
        );
    }

    async fn fire(
        store: &MemoryKv,
        clock: &ManualClock,
        sink: Arc<Capture>,
        now: u64,
    ) -> crate::timers::RunReport {
        let registry = TimerRegistry::new().register(OutcomeDelivery {
            sink,
            audience: "https://example.test".into(),
            metrics: Arc::new(NoopMetrics),
        });
        run_due(
            store,
            &partition(),
            &registry,
            clock,
            now,
            &TickBudget::default(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn delivers_in_sequence_and_acks_synthetic_locally() {
        let clock = Arc::new(ManualClock::new(100));
        let store = MemoryKv::with_clock(clock.clone());
        seed(&store, &["one", "s:local", "three"]).await;
        let sink = Arc::new(Capture::default());
        let report = fire(&store, &clock, sink.clone(), 100).await;
        assert_eq!(report.fired, 1);
        let seen = sink.seen.lock().unwrap().clone();
        assert_eq!(
            seen.iter()
                .map(|outcome| outcome.reservation_id.as_str())
                .collect::<Vec<_>>(),
            ["one", "three"]
        );
        assert!(
            seen.iter()
                .all(|outcome| matches!(outcome.kind, OutcomeKind::Committed { .. }))
        );
        assert_eq!(
            store
                .get(&partition(), &keys::outcome_backlog())
                .await
                .unwrap(),
            None
        );
        for rid in ["one", "s:local", "three"] {
            assert_eq!(
                store
                    .get(&partition(), &keys::reservation(rid).unwrap())
                    .await
                    .unwrap(),
                None
            );
        }
    }

    #[tokio::test]
    async fn sink_error_and_poison_row_retry_without_deletion() {
        let clock = Arc::new(ManualClock::new(100));
        let store = MemoryKv::with_clock(clock.clone());
        seed(&store, &["poison", "behind"]).await;
        let poison = keys::reservation("poison").unwrap();
        assert_eq!(
            store
                .apply(
                    &partition(),
                    Batch::new().put(poison.clone(), Value::new(b"bad".to_vec()))
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        let sink = Arc::new(Capture::default());
        let report = fire(&store, &clock, sink.clone(), 100).await;
        assert_eq!(report.fired, 1);
        assert_eq!(sink.seen.lock().unwrap()[0].reservation_id, "behind");
        assert_eq!(
            codec::decode_backlog(
                &store
                    .get(&partition(), &keys::outcome_backlog())
                    .await
                    .unwrap()
                    .unwrap()
            )
            .unwrap()
            .rows,
            1
        );
        assert!(store.get(&partition(), &poison).await.unwrap().is_some());

        let failing = Arc::new(Capture {
            fail: true,
            ..Capture::default()
        });
        let second = MemoryKv::with_clock(clock.clone());
        seed(&second, &["retry"]).await;
        let report = fire(&second, &clock, failing.clone(), 100).await;
        assert_eq!(report.fired, 1);
        assert_eq!(
            codec::decode_backlog(
                &second
                    .get(&partition(), &keys::outcome_backlog())
                    .await
                    .unwrap()
                    .unwrap()
            )
            .unwrap()
            .rows,
            1
        );
        let (start, end) = keys::class_range(keys::TAG_TIMER);
        let page = second
            .scan(&partition(), &start, &end, None, 10)
            .await
            .unwrap();
        let due = page
            .entries
            .iter()
            .find_map(|(key, _)| match keys::parse(key) {
                Some(keys::ParsedKey::Timer {
                    kind: 8, due_at_ms, ..
                }) => Some(due_at_ms),
                _ => None,
            })
            .unwrap();
        assert!(due >= 1_100);
        let first = failing.seen.lock().unwrap()[0].clone();
        clock.set(i64::try_from(due).unwrap());
        assert_eq!(fire(&second, &clock, failing.clone(), due).await.fired, 1);
        assert_eq!(first, failing.seen.lock().unwrap()[1]);
        assert_eq!(first.reservation_id, "retry");
        assert!(matches!(
            codec::decode_backlog(
                &second
                    .get(&partition(), &keys::outcome_backlog())
                    .await
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            Backlog { rows: 1, .. }
        ));
    }
}
