//! Rediscover a small verification outbox after its durable checkpoint.

use super::{PartitionRun, TickState, TimerCtx, TimerRegistry, process_row, registry, time_prefix};
use crate::rt::Clock;
use crate::store::{NamespaceStore, StoreError, codec, keys};

const MAX_ROWS: u32 = 3;
const MAX_BYTES: usize = 16 * 1024;
const MAX_EFFECTS: usize = 12;
const TIMER_ROWS: u32 = 16;

pub(super) async fn deliver<S: NamespaceStore>(
    ctx: &TimerCtx<'_, S>,
    registry: &TimerRegistry<'_, S>,
    state: &mut TickState,
    run: &mut PartitionRun,
    clock: &dyn Clock,
) -> bool {
    match try_deliver(ctx, registry, state, run, clock).await {
        Ok(committed) => committed,
        Err(error) => {
            // The enqueue's durable relay kick and verification recovery poll
            // already exist. Optional discovery must not undo that checkpoint.
            tracing::warn!(%error, "inline verification relay discovery skipped");
            false
        }
    }
}

async fn try_deliver<S: NamespaceStore>(
    ctx: &TimerCtx<'_, S>,
    registry: &TimerRegistry<'_, S>,
    state: &mut TickState,
    run: &mut PartitionRun,
    clock: &dyn Clock,
) -> Result<bool, StoreError> {
    if registry.get(registry::kinds::RELAY).is_none()
        || state.work_exhausted(clock)
        || state.remaining_scanned() < MAX_ROWS + 2
    {
        return Ok(false);
    }
    let (start, end) = keys::class_range(keys::TAG_RELAY);
    let page = ctx
        .store
        .scan(ctx.partition, &start, &end, None, MAX_ROWS + 1)
        .await?;
    let rows = u32::try_from(page.entries.len()).unwrap_or(MAX_ROWS + 1);
    let _ = state.charge_scan(rows + 1);
    if page.entries.is_empty() || rows > MAX_ROWS || page.next.is_some() {
        return Ok(false);
    }
    let mut bytes = 0_usize;
    let mut effects = 0_usize;
    for (key, value) in page.entries {
        if !matches!(keys::parse(&key), Some(keys::ParsedKey::Relay(_))) {
            return Ok(false);
        }
        bytes = bytes.saturating_add(key.as_bytes().len() + value.as_bytes().len());
        if bytes > MAX_BYTES {
            return Ok(false);
        }
        let row = codec::decode_relay(&value)?;
        effects = effects.saturating_add(row.puts.len() + row.deletes.len());
        if effects > MAX_EFFECTS {
            return Ok(false);
        }
    }
    if state.work_exhausted(clock) || state.remaining_scanned() < 2 {
        return Ok(false);
    }
    // The emit's kick may be beyond the original tick's time range, or
    // behind its scan cursor. Refresh business time only for this bounded
    // discovery; ordinary timer traversal keeps its original snapshot.
    let now_ms = u64::try_from(clock.now_ms())
        .unwrap_or(ctx.now_ms)
        .max(ctx.now_ms);
    let (start, class_end) = keys::class_range(keys::TAG_TIMER);
    let end = now_ms.checked_add(1).map_or(class_end, time_prefix);
    let limit = TIMER_ROWS.min(state.remaining_scanned() - 1);
    let page = ctx
        .store
        .scan(ctx.partition, &start, &end, None, limit)
        .await?;
    let rows = u32::try_from(page.entries.len()).unwrap_or(limit);
    let _ = state.charge_scan(rows + 1);
    let Some((key, value)) = page.entries.into_iter().find(|(key, _)| {
        matches!(keys::parse(key), Some(keys::ParsedKey::Timer { kind, reference, .. })
            if kind == registry::kinds::RELAY.get() && reference.is_empty())
            && keys::timer_retry_state(key).is_some_and(|(_, attempt)| attempt == 0)
    }) else {
        return Ok(false);
    };
    if state.work_exhausted(clock) {
        return Ok(false);
    }
    run.report.scanned += 1;
    let before = run.report.fired;
    process_row(
        &TimerCtx {
            store: ctx.store,
            partition: ctx.partition,
            now_ms,
            continuation_deadline_ms: ctx.continuation_deadline_ms,
        },
        registry,
        key,
        value,
        state,
        run,
        clock,
    )
    .await;
    Ok(run.report.fired > before)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryKv;
    use crate::indexed::checkpoint::{Phase, VerifyJobV1, encode_job};
    use crate::relay::{NoHook, RelayBudget, RelayHandler};
    use crate::store::{Batch, BatchOutcome, Key, Partition, Precondition, Value};
    use crate::timers::{DueTimer, Fired, TickBudget, TimerHandler, run_due};
    use crate::{BoxFuture, ManualClock, NamespaceKey, RepoName};
    use std::sync::Arc;

    struct Emit {
        clock: Arc<ManualClock>,
        entries: u64,
        rows: u64,
        retry: bool,
    }

    fn source() -> Partition {
        Partition::Namespace(NamespaceKey::deployment_default())
    }

    fn target() -> Partition {
        Partition::Coordinator(NamespaceKey::deployment_default())
    }

    fn job_key() -> Key {
        keys::verify_job(&RepoName::new("sample").unwrap(), &[1; 32])
    }

    fn initial_job() -> VerifyJobV1 {
        let mut job = VerifyJobV1::new([2; 32], 100, 512, 3);
        job.phase = Phase::EmitIndex;
        job.kind = crate::indexed::checkpoint::Kind::Pack;
        job
    }

    impl<S: NamespaceStore> TimerHandler<S> for Emit {
        fn kind(&self) -> crate::timers::TimerKind {
            registry::kinds::VERIFY
        }

        fn fire<'a>(
            &'a self,
            _ctx: &'a TimerCtx<'a, S>,
            timer: &'a DueTimer,
        ) -> BoxFuture<'a, Result<Fired, StoreError>> {
            Box::pin(async move {
                self.clock.set(200);
                let mut job = initial_job();
                job.entries = self.entries;
                job.in_pack_bytes = 36;
                job.phase = Phase::AwaitDelivery;
                job.last_relay_seq = Some(self.rows);
                let kick = if self.retry {
                    keys::timer_retry(200, registry::kinds::RELAY.get(), b"", 100, 1)
                } else {
                    keys::timer(200, registry::kinds::RELAY.get(), b"")
                };
                let mut batch = Batch::new()
                    .require(Precondition::Equals(job_key(), encode_job(&initial_job())))
                    .put(job_key(), encode_job(&job))
                    .put(keys::outbox_sequence(), codec::encode_u64(self.rows))
                    .put(kick, Value::default());
                for seq in 1..=self.rows {
                    batch = batch.put(
                        keys::relay(seq),
                        codec::encode_relay(&codec::RelayV1 {
                            at_ms: 200,
                            target: target(),
                            puts: vec![(
                                Key::new(vec![b'i', u8::try_from(seq).unwrap()]),
                                Value::new(vec![1]),
                            )],
                            deletes: Vec::new(),
                        })?,
                    );
                }
                Ok(Fired::Reschedule {
                    due_at_ms: 500,
                    value: timer.value.clone(),
                    batch,
                })
            })
        }
    }

    async fn setup(
        entries: u64,
        rows: u64,
        retry: bool,
    ) -> (
        Arc<MemoryKv>,
        Arc<ManualClock>,
        TimerRegistry<'static, Arc<MemoryKv>>,
    ) {
        let clock = Arc::new(ManualClock::new(100));
        let store = Arc::new(MemoryKv::with_clock(clock.clone()));
        assert_eq!(
            store
                .apply(
                    &source(),
                    Batch::new().put(job_key(), encode_job(&initial_job())).put(
                        keys::timer(100, registry::kinds::VERIFY.get(), b"fixture"),
                        Value::default()
                    )
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        let registry = TimerRegistry::new()
            .register(Emit {
                clock: clock.clone(),
                entries,
                rows,
                retry,
            })
            .register(RelayHandler {
                target: store.clone(),
                hook: NoHook,
                budget: RelayBudget::default(),
            });
        (store, clock, registry)
    }

    #[tokio::test]
    async fn tiny_checkpoint_rediscovers_new_relay_kick_beyond_tick_snapshot() {
        let (store, clock, registry) = setup(3, 3, false).await;
        let report = run_due(
            &store,
            &source(),
            &registry,
            clock.as_ref(),
            100,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.fired, 2);
        assert_eq!(report.next_wake_ms, Some(100), "one prompt follow-up wake");
        assert!(
            store
                .get(&source(), &keys::relay(1))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .get(&target(), &keys::relay_high_water(&source()).unwrap())
                .await
                .unwrap(),
            Some(codec::encode_u64(3))
        );
        assert!(
            store
                .get(
                    &source(),
                    &keys::timer(500, registry::kinds::VERIFY.get(), b"fixture")
                )
                .await
                .unwrap()
                .is_some()
        );
        let recovery = run_due(
            &store,
            &source(),
            &registry,
            clock.as_ref(),
            200,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            recovery.next_wake_ms,
            Some(500),
            "missed nudge retains recovery poll"
        );
        assert_eq!(
            store
                .get(&target(), &keys::relay_high_water(&source()).unwrap())
                .await
                .unwrap(),
            Some(codec::encode_u64(3))
        );
    }

    #[tokio::test]
    async fn restart_after_checkpoint_keeps_delivery_durable() {
        let (store, clock, registry) = setup(3, 3, false).await;
        let report = run_due(
            &store,
            &source(),
            &registry,
            clock.as_ref(),
            100,
            &TickBudget::new(1, 32, 512, 10_000),
        )
        .await
        .unwrap();
        assert_eq!(report.fired, 1);
        assert!(
            store
                .get(&source(), &keys::relay(1))
                .await
                .unwrap()
                .is_some()
        );
        let report = run_due(
            &store,
            &source(),
            &registry,
            clock.as_ref(),
            200,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.fired, 1);
        assert!(
            store
                .get(&source(), &keys::relay(1))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn inline_delivery_preserves_large_jobs_backlogs_and_retry_backoff() {
        for (entries, rows, retry) in [(4, 1, false), (3, 4, false), (3, 1, true)] {
            let (store, clock, registry) = setup(entries, rows, retry).await;
            let report = run_due(
                &store,
                &source(),
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
                    .get(&source(), &keys::relay(1))
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    }

    #[tokio::test]
    async fn inline_discovery_respects_scan_and_elapsed_limits() {
        for budget in [
            TickBudget::new(128, 32, 4, 10_000),
            TickBudget::new(128, 32, 512, 100),
        ] {
            let (store, clock, registry) = setup(3, 1, false).await;
            let mut state = TickState::new(clock.as_ref(), budget);
            let report = crate::timers::run_due_with_state(
                &store,
                &source(),
                &registry,
                clock.as_ref(),
                100,
                &mut state,
            )
            .await
            .unwrap();
            assert_eq!(report.fired, 1);
            assert!(state.examined <= budget.max_scanned);
            assert_eq!(state.attempted_for(registry::kinds::RELAY), 0);
            assert!(
                store
                    .get(&source(), &keys::relay(1))
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    }
    #[tokio::test]
    async fn inline_delivery_does_not_refresh_the_relay_kind_allowance() {
        let (store, clock, registry) = setup(3, 1, false).await;
        run_due(
            &store,
            &source(),
            &registry,
            clock.as_ref(),
            100,
            &TickBudget::new(1, 1, 512, 10_000),
        )
        .await
        .unwrap();
        let mut state = TickState::new(clock.as_ref(), TickBudget::new(128, 1, 512, 10_000));
        assert!(state.claim_attempt(registry::kinds::RELAY, None));
        let mut run = PartitionRun::new();
        deliver(
            &TimerCtx {
                store: &store,
                partition: &source(),
                now_ms: 200,
                continuation_deadline_ms: None,
            },
            &registry,
            &mut state,
            &mut run,
            clock.as_ref(),
        )
        .await;
        assert_eq!(state.attempted_for(registry::kinds::RELAY), 1);
        assert_eq!(run.report.deferred, 1);
        assert!(
            store
                .get(&source(), &keys::relay(1))
                .await
                .unwrap()
                .is_some()
        );
    }
    #[tokio::test]
    async fn inline_discovery_rejects_expensive_small_row_counts() {
        for large_value in [false, true] {
            let (store, clock, registry) = setup(3, 1, false).await;
            run_due(
                &store,
                &source(),
                &registry,
                clock.as_ref(),
                100,
                &TickBudget::new(1, 32, 512, 10_000),
            )
            .await
            .unwrap();
            let puts = if large_value {
                vec![(Key::new(vec![b'i']), Value::new(vec![1; MAX_BYTES]))]
            } else {
                (0..=MAX_EFFECTS)
                    .map(|index| {
                        (
                            Key::new(vec![b'i', u8::try_from(index).unwrap()]),
                            Value::new(vec![1]),
                        )
                    })
                    .collect()
            };
            store
                .apply(
                    &source(),
                    Batch::new().put(
                        keys::relay(1),
                        codec::encode_relay(&codec::RelayV1 {
                            at_ms: 200,
                            target: target(),
                            puts,
                            deletes: Vec::new(),
                        })
                        .unwrap(),
                    ),
                )
                .await
                .unwrap();
            let mut state = TickState::new(clock.as_ref(), TickBudget::default());
            let mut run = PartitionRun::new();
            deliver(
                &TimerCtx {
                    store: &store,
                    partition: &source(),
                    now_ms: 200,
                    continuation_deadline_ms: None,
                },
                &registry,
                &mut state,
                &mut run,
                clock.as_ref(),
            )
            .await;
            assert_eq!(state.attempted_for(registry::kinds::RELAY), 0);
            assert!(
                store
                    .get(&source(), &keys::relay(1))
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    }
    #[tokio::test]
    async fn failed_checkpoint_does_not_start_optional_delivery() {
        let (store, clock, registry) = setup(3, 1, false).await;
        let mut changed = initial_job();
        changed.entries = 1;
        store
            .apply(
                &source(),
                Batch::new()
                    .put(job_key(), encode_job(&changed))
                    .put(keys::outbox_sequence(), codec::encode_u64(1))
                    .put(
                        keys::timer(200, registry::kinds::RELAY.get(), b""),
                        Value::default(),
                    )
                    .put(
                        keys::relay(1),
                        codec::encode_relay(&codec::RelayV1 {
                            at_ms: 200,
                            target: target(),
                            puts: vec![(Key::new(vec![b'i']), Value::new(vec![1]))],
                            deletes: Vec::new(),
                        })
                        .unwrap(),
                    ),
            )
            .await
            .unwrap();
        let report = run_due(
            &store,
            &source(),
            &registry,
            clock.as_ref(),
            100,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.raced, 1);
        assert_eq!(report.fired, 0);
        assert!(
            store
                .get(&source(), &keys::relay(1))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .get(&target(), &keys::relay_high_water(&source()).unwrap())
                .await
                .unwrap()
                .is_none()
        );
        run_due(
            &store,
            &source(),
            &registry,
            clock.as_ref(),
            200,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert!(
            store
                .get(&source(), &keys::relay(1))
                .await
                .unwrap()
                .is_none()
        );
    }
}
