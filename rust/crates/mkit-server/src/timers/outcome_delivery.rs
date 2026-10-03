//! Bounded, at-least-once terminal outcome delivery.

use std::sync::Arc;
use std::time::Duration;

use crate::pipeline::{Outcome, OutcomeSink};
use crate::rt::{BoxFuture, Clock, Sleep, with_timeout};
use crate::store::codec;
use crate::store::outbox::{guard, plan_ack};
use crate::store::{Batch, Cursor, NamespaceStore, StoreError, Value, keys};
use crate::telemetry::Metrics;
use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};

/// Default rows examined per fire.
pub const DEFAULT_MAX_ROWS: usize = 16;
/// Default bound on one sink call.
pub const DEFAULT_SINK_TIMEOUT: Duration = Duration::from_secs(5);
// Acknowledgments can cost four operations per row, plus timer completion or
// reschedule and the shared backlog guard/write. At 23 rows the worst case is
// 4 * 23 + 2 + 4 = 98 operations, below the shared 100-op transaction cap.
const MAX_ROWS_CEILING: usize = 23;
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
    /// Timer for the per-call sink bound.
    pub sleep: Arc<dyn Sleep>,
    /// Bound on one sink call; a timeout is a [`DeliveryError`](crate::pipeline::DeliveryError).
    pub sink_timeout: Duration,
    /// Rows examined (and so sink calls attempted) per fire, at least 1.
    pub max_rows: usize,
    /// Wall clock for the per-fire bound; without one a fire is bounded only
    /// by `max_rows` and `sink_timeout`.
    pub clock: Option<Arc<dyn Clock>>,
    /// Wall-clock bound on one fire; `None` means twice `sink_timeout`. Once
    /// exceeded the fire makes no further sink call and reschedules now, so a
    /// slow-but-successful sink cannot hold a driver.
    pub fire_budget: Option<Duration>,
}

impl<O> OutcomeDelivery<O> {
    /// A driver with the default 5 s sink timeout and 16 rows per fire.
    #[must_use]
    pub fn new(
        sink: O,
        audience: String,
        metrics: Arc<dyn Metrics>,
        sleep: Arc<dyn Sleep>,
    ) -> Self {
        Self {
            sink,
            audience,
            metrics,
            sleep,
            sink_timeout: DEFAULT_SINK_TIMEOUT,
            max_rows: DEFAULT_MAX_ROWS,
            clock: None,
            fire_budget: None,
        }
    }

    /// Bound each fire's wall-clock time (default twice the sink timeout).
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Override the per-fire wall-clock bound; needs [`Self::with_clock`].
    #[must_use]
    pub fn with_fire_budget(mut self, budget: Duration) -> Self {
        self.fire_budget = Some(budget);
        self
    }

    /// Override the per-call sink timeout.
    #[must_use]
    pub fn with_sink_timeout(mut self, timeout: Duration) -> Self {
        self.sink_timeout = timeout;
        self
    }

    /// Override the rows per fire (clamped to 1..=23 to fit atomic acknowledgments).
    #[must_use]
    pub fn with_max_rows(mut self, rows: usize) -> Self {
        self.max_rows = rows.clamp(1, MAX_ROWS_CEILING);
        self
    }
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
                Batch::new()
                    .require(guard(oc_key.clone(), oc.as_ref()))
                    .delete(oc_key),
            ));
        }
        let (attempt, cursor) = decode_timer(&timer.value)?;
        let (start, end) = keys::class_range(keys::TAG_OUTCOME_PENDING);
        // The scan cursor names the last examined row. Scanning past the
        // delivery budget would strand the unexamined suffix until a full
        // rotation, so the scan page is the budget.
        let max_rows = self.max_rows.clamp(1, MAX_ROWS_CEILING);
        let scan_rows = u32::try_from(max_rows).unwrap_or(u32::MAX);
        let mut after = cursor.as_ref();
        let mut page = ctx
            .store
            .scan(ctx.partition, &start, &end, after, scan_rows)
            .await?;
        if page.entries.is_empty() && after.is_some() && page.next.is_none() {
            after = None;
            page = ctx
                .store
                .scan(ctx.partition, &start, &end, after, scan_rows)
                .await?;
        }
        let mut batch = Batch::new();
        let mut delivered = 0u64;
        let mut sink_retry_ms = 0u64;
        // Index in `page` of the row whose delivery failed or timed out.
        let mut stopped_at: Option<usize> = None;
        // Index of the first row not tried because the fire's wall-clock
        // budget ran out.
        let mut cut_at: Option<usize> = None;
        let started_ms = self.clock.as_ref().map(|clock| clock.now_ms());
        let budget_ms = i64::try_from(
            self.fire_budget
                .unwrap_or_else(|| self.sink_timeout.saturating_mul(2))
                .as_millis(),
        )
        .unwrap_or(i64::MAX);
        // Acknowledged rows are planned after the sink loop, against a fresh
        // `oc`, so slow sink awaits sit outside the read-modify-write window.
        let mut acked: Vec<(String, Value, u64)> = Vec::new();
        for (index, (key, _)) in page.entries.iter().enumerate().take(max_rows) {
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
                if let (Some(clock), Some(started)) = (&self.clock, started_ms)
                    && clock.now_ms().saturating_sub(started) >= budget_ms
                {
                    cut_at = Some(index);
                    break;
                }
                match with_timeout(&*self.sleep, self.sink_timeout, self.sink.deliver(&outcome))
                    .await
                {
                    Ok(Ok(())) => true,
                    Ok(Err(err)) => {
                        sink_retry_ms = sink_retry_ms.max(err.retry_after.map_or(0, |hint| {
                            u64::try_from(hint.as_millis()).unwrap_or(u64::MAX)
                        }));
                        tracing::warn!(reason = %err.reason, "outcome delivery failed");
                        stopped_at = Some(index);
                        false
                    }
                    Err(_) => {
                        tracing::warn!("outcome delivery timed out");
                        stopped_at = Some(index);
                        false
                    }
                }
            };
            if acknowledged {
                acked.push((rid, value, seq));
            }
            // A failing or hung sink is not asked again in this fire.
            if stopped_at.is_some() {
                break;
            }
        }
        let fresh_oc = if acked.is_empty() {
            oc.clone()
        } else {
            ctx.store.get(ctx.partition, &oc_key).await?
        };
        let fresh_backlog = fresh_oc
            .as_ref()
            .map(codec::decode_backlog)
            .transpose()?
            .unwrap_or_default();
        // Completion and acknowledgments must share a snapshot. A later append
        // fails this guard, retaining the timer for the next fire to re-plan.
        batch.preconditions.push(guard(oc_key, fresh_oc.as_ref()));
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
        if delivered == fresh_backlog.rows {
            return Ok(Fired::Done(batch));
        }
        // The next fire resumes just after the failed row. Resuming after the
        // page instead would, when the page reached the end of the range, wrap
        // to the head and retry the same failing row first forever, starving
        // every row behind it. The page's cursor is opaque, so ask the store
        // for the one after the failed row.
        let resume = match (stopped_at, cut_at) {
            (Some(index), _) => {
                let limit = u32::try_from(index + 1).unwrap_or(u32::MAX);
                ctx.store
                    .scan(ctx.partition, &start, &end, after, limit)
                    .await?
                    .next
            }
            // Resume at the first untried row: after the one before it.
            (None, Some(index)) if index > 0 => {
                let limit = u32::try_from(index).unwrap_or(u32::MAX);
                ctx.store
                    .scan(ctx.partition, &start, &end, after, limit)
                    .await?
                    .next
            }
            (None, _) => page.next,
        };
        // Only a failed or hung sink call backs off. A page that delivered
        // nothing because every row was junk or synthetic is not a sink fault.
        let next_attempt = if delivered > 0 {
            0
        } else if stopped_at.is_some() {
            attempt.saturating_add(1)
        } else {
            attempt
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
            value: encode_timer(next_attempt, resume.as_ref())?,
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
    use crate::rt::{ManualClock, ManualSleep};
    use crate::store::codec::{Backlog, ReservationV1};
    use crate::store::outbox::{OutboxBuilder, Terminal};
    use crate::store::{BatchOutcome, Key, Partition, Precondition, Write};
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
                    procedure: None,
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
        sink: Arc<impl OutcomeSink>,
        now: u64,
    ) -> crate::timers::RunReport {
        let registry = TimerRegistry::new().register(OutcomeDelivery::new(
            sink,
            "https://example.test".into(),
            Arc::new(NoopMetrics),
            Arc::new(ManualSleep::new()),
        ));
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

    // A second terminal outcome arrives inside the first sink await.
    struct AppendDuringAck(Arc<MemoryKv>);
    impl OutcomeSink for AppendDuringAck {
        async fn deliver(&self, outcome: &Outcome) -> Result<(), DeliveryError> {
            assert_eq!(outcome.reservation_id, "first");
            let prior = codec::encode_reservation(&ReservationV1::Ticketed { ticket_id: [8; 32] });
            let p = partition();
            let os = self.0.get(&p, &keys::outbox_sequence()).await.unwrap();
            let oc = self.0.get(&p, &keys::outcome_backlog()).await.unwrap();
            let mut outbox = OutboxBuilder::new(os.as_ref(), oc.as_ref()).unwrap();
            self.0
                .apply(
                    &p,
                    Batch::new().put(keys::reservation("second").unwrap(), prior.clone()),
                )
                .await
                .unwrap();
            outbox.outcome(
                "second",
                &prior,
                Terminal::new(ReservationV1::Aborted {
                    repository: "repo".into(),
                    occurred_at_ms: 100,
                    reason: codec::AbortReason::RefConflict,
                    detail: String::new(),
                    procedure: None,
                })
                .unwrap(),
            );
            let mut batch = Batch::new();
            outbox
                .try_finish(&mut batch.preconditions, &mut batch.writes)
                .unwrap();
            assert_eq!(
                self.0.apply(&p, batch).await.unwrap(),
                BatchOutcome::Committed
            );
            Ok(())
        }
    }

    #[tokio::test]
    async fn append_during_ack_keeps_a_timer_and_delivers_on_the_next_fire() {
        let clock = Arc::new(ManualClock::new(100));
        let store = Arc::new(MemoryKv::with_clock(clock.clone()));
        seed(&store, &["first"]).await;
        let report = fire(
            &store,
            &clock,
            Arc::new(AppendDuringAck(store.clone())),
            100,
        )
        .await;
        assert_eq!(report.fired, 1);
        assert_eq!(backlog_rows(&store).await, 1);
        let (start, end) = keys::class_range(keys::TAG_TIMER);
        let timers = store
            .scan(&partition(), &start, &end, None, 10)
            .await
            .unwrap();
        assert_eq!(timers.entries.len(), 1, "one delivery timer remains");
        let (start, end) = keys::class_range(keys::TAG_OUTCOME_PENDING);
        let pending = store
            .scan(&partition(), &start, &end, None, 10)
            .await
            .unwrap();
        assert_eq!(pending.entries.len(), 1);
        let due = timer_due(&store).await;
        assert!(due <= 101, "remaining outcome is due now");
        clock.set(i64::try_from(due).unwrap());
        let sink = Arc::new(Capture::default());
        assert_eq!(fire(&store, &clock, sink.clone(), due).await.fired, 1);
        assert_eq!(sink.seen.lock().unwrap()[0].reservation_id, "second");
        assert!(matches!(
            sink.seen.lock().unwrap()[0].kind,
            OutcomeKind::Aborted { .. }
        ));
        assert_eq!(backlog_rows(&store).await, 0);
        assert!(
            store
                .scan(&partition(), &start, &end, None, 10)
                .await
                .unwrap()
                .entries
                .is_empty()
        );
    }

    async fn planned_delivery(store: &MemoryKv, sink: Arc<Capture>) -> (Key, Value, Fired) {
        let (start, end) = keys::class_range(keys::TAG_TIMER);
        let (key, value) = store
            .scan(&partition(), &start, &end, None, 10)
            .await
            .unwrap()
            .entries[0]
            .clone();
        let Some(keys::ParsedKey::Timer {
            due_at_ms,
            kind,
            reference,
        }) = keys::parse(&key)
        else {
            panic!("delivery timer");
        };
        let timer = DueTimer {
            due_at_ms,
            kind: crate::timers::TimerKind::new(kind),
            reference,
            value: value.clone(),
        };
        let delivery = OutcomeDelivery::new(
            sink,
            "https://example.test".into(),
            Arc::new(NoopMetrics),
            Arc::new(ManualSleep::new()),
        );
        let fired = delivery
            .fire(
                &TimerCtx {
                    store,
                    partition: &partition(),
                    now_ms: 100,
                },
                &timer,
            )
            .await
            .unwrap();
        (key, value, fired)
    }

    #[tokio::test]
    async fn append_after_fresh_read_fails_the_guard_and_replans_delivery() {
        let clock = Arc::new(ManualClock::new(100));
        let store = Arc::new(MemoryKv::with_clock(clock.clone()));
        seed(&store, &["first"]).await;
        let sink = Arc::new(Capture::default());
        let prior_oc = store
            .get(&partition(), &keys::outcome_backlog())
            .await
            .unwrap()
            .unwrap();
        let (key, value, fired) = planned_delivery(&store, sink.clone()).await;
        let Fired::Done(batch) = fired else {
            panic!("original row acknowledged");
        };
        assert!(
            batch
                .preconditions
                .contains(&Precondition::Equals(keys::outcome_backlog(), prior_oc))
        );
        // Append after the handler's fresh read and before applying its Done.
        let first = sink.seen.lock().unwrap()[0].clone();
        AppendDuringAck(store.clone())
            .deliver(&first)
            .await
            .unwrap();
        let batch = batch
            .require(Precondition::Equals(key.clone(), value))
            .delete(key.clone());
        assert!(matches!(
            store.apply(&partition(), batch).await.unwrap(),
            BatchOutcome::PreconditionFailed { .. }
        ));
        assert_eq!(backlog_rows(&store).await, 2);
        assert!(store.get(&partition(), &key).await.unwrap().is_some());
        assert_eq!(fire(&store, &clock, sink.clone(), 100).await.fired, 1);
        assert_eq!(backlog_rows(&store).await, 0);
        assert!(store.get(&partition(), &key).await.unwrap().is_none());
        let seen = sink.seen.lock().unwrap();
        assert_eq!(
            seen.iter().filter(|o| o.reservation_id == "first").count(),
            2
        );
        assert_eq!(
            seen.iter().filter(|o| o.reservation_id == "second").count(),
            1
        );
    }

    #[tokio::test]
    async fn no_acknowledgments_guard_the_initial_backlog() {
        let store = MemoryKv::with_clock(Arc::new(ManualClock::new(100)));
        seed(&store, &["first"]).await;
        let prior = store
            .get(&partition(), &keys::outcome_backlog())
            .await
            .unwrap()
            .unwrap();
        let sink = Arc::new(Capture {
            fail: true,
            ..Capture::default()
        });
        let (_, _, fired) = planned_delivery(&store, sink).await;
        let Fired::Reschedule { batch, .. } = fired else {
            panic!("failed sink retries");
        };
        assert!(
            batch
                .preconditions
                .contains(&Precondition::Equals(keys::outcome_backlog(), prior))
        );
        assert!(batch.writes.is_empty());
    }

    #[tokio::test]
    async fn all_acknowledgments_return_done_with_an_empty_backlog() {
        let store = MemoryKv::with_clock(Arc::new(ManualClock::new(100)));
        seed(&store, &["first", "second"]).await;
        let sink = Arc::new(Capture::default());
        let (key, value, fired) = planned_delivery(&store, sink.clone()).await;
        let Fired::Done(batch) = fired else {
            panic!("all rows acknowledged");
        };
        assert_eq!(
            store
                .apply(
                    &partition(),
                    batch
                        .require(Precondition::Equals(key.clone(), value))
                        .delete(key.clone())
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        assert_eq!(sink.seen.lock().unwrap().len(), 2);
        assert_eq!(backlog_rows(&store).await, 0);
        assert!(store.get(&partition(), &key).await.unwrap().is_none());
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

    /// A sink that never answers.
    struct Hang(Mutex<u32>);
    impl OutcomeSink for Hang {
        async fn deliver(&self, _: &Outcome) -> Result<(), DeliveryError> {
            *self.0.lock().unwrap() += 1;
            futures::future::pending().await
        }
    }

    async fn backlog_rows(store: &MemoryKv) -> u64 {
        store
            .get(&partition(), &keys::outcome_backlog())
            .await
            .unwrap()
            .map_or(0, |v| codec::decode_backlog(&v).unwrap().rows)
    }

    async fn timer_due(store: &MemoryKv) -> u64 {
        let (start, end) = keys::class_range(keys::TAG_TIMER);
        let page = store
            .scan(&partition(), &start, &end, None, 10)
            .await
            .unwrap();
        page.entries
            .iter()
            .find_map(|(key, _)| match keys::parse(key) {
                Some(keys::ParsedKey::Timer {
                    kind: 8, due_at_ms, ..
                }) => Some(due_at_ms),
                _ => None,
            })
            .unwrap()
    }

    /// A sink that succeeds, but only after the clock advances by `step_ms`.
    struct Slow {
        clock: Arc<ManualClock>,
        step_ms: i64,
        seen: Mutex<Vec<String>>,
    }
    impl OutcomeSink for Slow {
        async fn deliver(&self, outcome: &Outcome) -> Result<(), DeliveryError> {
            self.seen
                .lock()
                .unwrap()
                .push(outcome.reservation_id.clone());
            self.clock.set(self.clock.now_ms() + self.step_ms);
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_slow_but_successful_sink_is_cut_at_the_fire_budget() {
        let clock = Arc::new(ManualClock::new(100));
        let store = MemoryKv::with_clock(clock.clone());
        seed(&store, &["a", "b", "c", "d"]).await;
        let sink = Arc::new(Slow {
            clock: clock.clone(),
            step_ms: 400,
            seen: Mutex::new(Vec::new()),
        });
        // Budget 2 x 250 ms: two 400 ms calls exhaust it.
        let delivery = OutcomeDelivery::new(
            sink.clone(),
            "https://example.test".into(),
            Arc::new(NoopMetrics),
            Arc::new(ManualSleep::new()),
        )
        .with_sink_timeout(Duration::from_millis(250))
        .with_clock(clock.clone());
        fire_with(&store, &clock, delivery, 100).await;
        assert_eq!(*sink.seen.lock().unwrap(), ["a", "b"]);
        assert_eq!(backlog_rows(&store).await, 2);
        // Rescheduled now (not backed off), resuming at the untried rows.
        let due = timer_due(&store).await;
        assert!(due <= 101, "due {due}");
        clock.set(i64::try_from(due).unwrap());
        let delivery = OutcomeDelivery::new(
            sink.clone(),
            "https://example.test".into(),
            Arc::new(NoopMetrics),
            Arc::new(ManualSleep::new()),
        );
        fire_with(&store, &clock, delivery, due).await;
        assert_eq!(*sink.seen.lock().unwrap(), ["a", "b", "c", "d"]);
        assert_eq!(backlog_rows(&store).await, 0);
    }

    #[tokio::test]
    async fn an_undeliverable_page_does_not_raise_the_backoff() {
        let clock = Arc::new(ManualClock::new(100));
        let store = MemoryKv::with_clock(clock.clone());
        seed(&store, &["poison"]).await;
        store
            .apply(
                &partition(),
                Batch::new().put(
                    keys::reservation("poison").unwrap(),
                    Value::new(b"bad".to_vec()),
                ),
            )
            .await
            .unwrap();
        let sink = Arc::new(Capture::default());
        let mut now = 100u64;
        let mut dues = Vec::new();
        for _ in 0..3 {
            clock.set(i64::try_from(now).unwrap());
            fire(&store, &clock, sink.clone(), now).await;
            let due = timer_due(&store).await;
            dues.push(due - now);
            now = due;
        }
        assert!(sink.seen.lock().unwrap().is_empty());
        // No sink call failed, so the delay stays at the first backoff step.
        assert!(dues.iter().all(|gap| *gap <= 1_200), "{dues:?}");
    }

    async fn fire_with(
        store: &MemoryKv,
        clock: &ManualClock,
        delivery: OutcomeDelivery<Arc<impl OutcomeSink>>,
        now: u64,
    ) {
        let registry = TimerRegistry::new().register(delivery);
        run_due(
            store,
            &partition(),
            &registry,
            clock,
            now,
            &TickBudget::default(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_hanging_sink_is_cut_at_the_timeout_and_stops_the_fire() {
        let clock = Arc::new(ManualClock::new(100));
        let store = MemoryKv::with_clock(clock.clone());
        seed(&store, &["a", "b", "c"]).await;
        let sink = Arc::new(Hang(Mutex::new(0)));
        let sleeper = ManualSleep::elapsed();
        let delivery = OutcomeDelivery::new(
            sink.clone(),
            "https://example.test".into(),
            Arc::new(NoopMetrics),
            Arc::new(sleeper.clone()),
        )
        .with_sink_timeout(Duration::from_millis(250));
        fire_with(&store, &clock, delivery, 100).await;
        // One call, cut by the 250 ms timer; the other rows are not tried.
        assert_eq!(*sink.0.lock().unwrap(), 1);
        assert_eq!(sleeper.requested(), [Duration::from_millis(250)]);
        assert_eq!(backlog_rows(&store).await, 3);
        // Backed off: the retry is later than now.
        assert!(timer_due(&store).await >= 1_100);
    }

    #[tokio::test]
    async fn first_failure_stops_the_fire_and_no_row_is_lost() {
        let clock = Arc::new(ManualClock::new(100));
        let store = MemoryKv::with_clock(clock.clone());
        seed(&store, &["a", "b", "c"]).await;
        let failing = Arc::new(Capture {
            fail: true,
            ..Capture::default()
        });
        fire(&store, &clock, failing.clone(), 100).await;
        assert_eq!(failing.seen.lock().unwrap().len(), 1);
        assert_eq!(backlog_rows(&store).await, 3);
        // Backed off: the retry is later than now.
        assert!(timer_due(&store).await >= 1_100);
        // A healthy sink later delivers every row.
        let ok = Arc::new(Capture::default());
        let (start, end) = keys::class_range(keys::TAG_TIMER);
        let page = store
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
        clock.set(i64::try_from(due).unwrap());
        // The fire resumes after the failed row `a`, so `b` and `c` go first;
        // `a` follows once the cursor wraps.
        fire(&store, &clock, ok.clone(), due).await;
        assert_eq!(ok.seen.lock().unwrap().len(), 2);
        assert_eq!(backlog_rows(&store).await, 1);
        let (start, end) = keys::class_range(keys::TAG_TIMER);
        let page = store
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
        clock.set(i64::try_from(due).unwrap());
        fire(&store, &clock, ok.clone(), due).await;
        assert_eq!(ok.seen.lock().unwrap().len(), 3);
        assert_eq!(backlog_rows(&store).await, 0);
    }

    /// A sink that rejects one reservation id and takes the rest.
    struct Picky(Mutex<Vec<String>>);
    impl OutcomeSink for Picky {
        async fn deliver(&self, outcome: &Outcome) -> Result<(), DeliveryError> {
            if outcome.reservation_id == "b" {
                return Err(DeliveryError::new("rejected", None));
            }
            self.0.lock().unwrap().push(outcome.reservation_id.clone());
            Ok(())
        }
    }

    /// A row the sink keeps refusing does not starve the rows behind it: the
    /// fire stops at it, and the next fire resumes after it rather than
    /// retrying it first again.
    #[tokio::test]
    async fn a_refused_row_does_not_starve_the_rows_behind_it() {
        let clock = Arc::new(ManualClock::new(100));
        let store = MemoryKv::with_clock(clock.clone());
        seed(&store, &["a", "b", "c", "d"]).await;
        let sink = Arc::new(Picky(Mutex::new(Vec::new())));
        let mut now = 100u64;
        for _ in 0..3 {
            fire_with(
                &store,
                &clock,
                OutcomeDelivery::new(
                    sink.clone(),
                    "https://example.test".into(),
                    Arc::new(NoopMetrics),
                    Arc::new(ManualSleep::new()),
                ),
                now,
            )
            .await;
            now += 1_000_000;
            clock.set(i64::try_from(now).unwrap());
        }
        assert_eq!(*sink.0.lock().unwrap(), ["a", "c", "d"]);
        assert_eq!(backlog_rows(&store).await, 1, "only b remains");
    }

    #[tokio::test]
    async fn max_rows_bounds_one_fire_and_the_cursor_rotates() {
        let clock = Arc::new(ManualClock::new(100));
        let store = MemoryKv::with_clock(clock.clone());
        seed(&store, &["a", "b", "c", "d", "e"]).await;
        let sink = Arc::new(Capture::default());
        let mk = |sink: Arc<Capture>| {
            OutcomeDelivery::new(
                sink,
                "https://example.test".into(),
                Arc::new(NoopMetrics),
                Arc::new(ManualSleep::new()),
            )
            .with_max_rows(2)
        };
        fire_with(&store, &clock, mk(sink.clone()), 100).await;
        assert_eq!(sink.seen.lock().unwrap().len(), 2);
        assert_eq!(backlog_rows(&store).await, 3);
        clock.set(101);
        fire_with(&store, &clock, mk(sink.clone()), 101).await;
        clock.set(102);
        fire_with(&store, &clock, mk(sink.clone()), 102).await;
        assert_eq!(sink.seen.lock().unwrap().len(), 5);
        assert_eq!(backlog_rows(&store).await, 0);
    }

    #[tokio::test]
    async fn configured_max_rows_24_or_25_drains_without_exceeding_atomic_batch_limit() {
        for configured in [24, 25] {
            let clock = Arc::new(ManualClock::new(100));
            let store = MemoryKv::with_clock(clock.clone());
            let ids: Vec<_> = (0..25).map(|i| format!("row-{i}")).collect();
            let ids: Vec<_> = ids.iter().map(String::as_str).collect();
            seed(&store, &ids).await;
            let sink = Arc::new(Capture::default());
            for tick in 0..3 {
                let now = 100 + tick * 1_000_000;
                clock.set(i64::try_from(now).unwrap());
                fire_with(
                    &store,
                    &clock,
                    OutcomeDelivery::new(
                        sink.clone(),
                        "https://example.test".into(),
                        Arc::new(NoopMetrics),
                        Arc::new(ManualSleep::new()),
                    )
                    .with_max_rows(configured),
                    now,
                )
                .await;
            }
            assert_eq!(
                sink.seen.lock().unwrap().len(),
                25,
                "configured row bound {configured}"
            );
            assert_eq!(
                backlog_rows(&store).await,
                0,
                "configured row bound {configured}"
            );
        }
    }

    #[cfg(feature = "remote-hooks")]
    async fn rows(store: &MemoryKv) -> u64 {
        codec::decode_backlog(
            &store
                .get(&partition(), &keys::outcome_backlog())
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap()
        .rows
    }

    /// A remote sink that cannot reach its hook leaves the row queued, and each
    /// retry is signed afresh (new nonce and validity window).
    #[cfg(feature = "remote-hooks")]
    #[tokio::test]
    async fn a_failing_remote_hook_keeps_the_row_and_each_retry_is_signed_afresh() {
        use crate::hooks::HookClient;
        use crate::hooks::RemoteOutcomes;
        use crate::hooks::tests::{MockChannel, Step, channel_of, signer};
        use crate::rt::{Clock, ManualSleep};

        let clock = Arc::new(ManualClock::new(100));
        let store = MemoryKv::with_clock(clock.clone());
        seed(&store, &["retry"]).await;
        // The client shares the test clock, so a retry's window moves.
        let hook = Arc::new(
            HookClient::new(
                MockChannel::new(Step::Fail(crate::hooks::ChannelError::Timeout)),
                "https://example.test",
                Some(signer()),
                clock.clone() as Arc<dyn Clock>,
                Arc::new(ManualSleep::new()),
            )
            .unwrap(),
        );
        let sink = Arc::new(RemoteOutcomes::new(hook.clone()));
        assert_eq!(fire(&store, &clock, sink.clone(), 100).await.fired, 1);
        assert_eq!(rows(&store).await, 1);
        let (start, end) = keys::class_range(keys::TAG_TIMER);
        let page = store
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
        clock.set(i64::try_from(due).unwrap());
        assert_eq!(fire(&store, &clock, sink, due).await.fired, 1);
        assert_eq!(rows(&store).await, 1);

        let seen = channel_of(&hook).seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        let header = |i: usize, name: &str| {
            seen[i]
                .headers
                .iter()
                .find(|(n, _)| *n == name)
                .unwrap()
                .1
                .clone()
        };
        assert_ne!(
            header(0, "X-Mkit-Hook-Nonce"),
            header(1, "X-Mkit-Hook-Nonce")
        );
        assert_ne!(
            header(0, "X-Mkit-Hook-Created-At"),
            header(1, "X-Mkit-Hook-Created-At")
        );
        assert_eq!(seen[0].body, seen[1].body);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::too_many_lines)]
mod stored_v050_tests {
    crate::stored_golden::tests!(timers_outcome_delivery);
}
