//! Real physical `SQLite` alarms keep their limits across heads and cold starts.
#![allow(clippy::unwrap_used)]

use super::*;
use futures::executor::block_on;
use mkit_server::sql::SqlKvStore;
use mkit_server::timers::{DueTimer, Fired, TimerCtx, TimerHandler};
use mkit_server::{
    Batch, BoxFuture, Key, ManualClock, NamespaceKey, NamespaceStore, Partition, Precondition,
    RepoName, Value,
};
use mkit_server_native::RusqliteConn;
use std::sync::{Arc, Mutex};

type Store = PressureStore<RusqliteConn>;

fn store(clock: &Arc<ManualClock>) -> Store {
    PressureStore::new(
        SqlKvStore::open(
            RusqliteConn::open_in_memory()
                .unwrap()
                .with_clock(clock.clone()),
        )
        .unwrap(),
        crate::classes::ShardClass::RefShard,
        clock.clone(),
        Arc::new(mkit_server::NoopMetrics),
    )
}

fn partition(index: u32) -> Partition {
    Partition::Ref {
        ns: NamespaceKey::deployment_default(),
        repo: RepoName::new("alarm").unwrap(),
        shard_ref: format!("refs/heads/{index:04}"),
    }
}

fn seed(store: &Store, index: u32, kind: u8) {
    block_on(store.apply(
        &partition(index),
        Batch::new().put(
            keys::timer(1000, kind, &index.to_be_bytes()),
            Value::default(),
        ),
    ))
    .unwrap();
}

struct Handler {
    kind: u8,
    fail: bool,
    repeat_first: bool,
    fail_guard: bool,
    advance_clock: Option<Arc<ManualClock>>,
    calls: Arc<Mutex<Vec<u32>>>,
}

impl TimerHandler<Store> for Handler {
    fn kind(&self) -> TimerKind {
        TimerKind::new(self.kind)
    }
    fn max_per_tick(&self) -> Option<u32> {
        Some(128)
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, Store>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            let index = u32::from_be_bytes(timer.reference.as_ref().try_into().unwrap());
            self.calls.lock().unwrap().push(index);
            if let Some(clock) = &self.advance_clock {
                clock.set(1010);
            }
            if self.fail {
                return Err(StoreError::Invalid("fixture handler failure".into()));
            }
            if self.repeat_first && index == 0 {
                let mut changed = timer.value.as_bytes().to_vec();
                changed.push(1);
                ctx.store
                    .apply(
                        ctx.partition,
                        Batch::new().put(
                            keys::timer(timer.due_at_ms, self.kind, &timer.reference),
                            Value::new(changed),
                        ),
                    )
                    .await?;
            }
            if self.fail_guard || self.repeat_first && index == 0 {
                return Ok(Fired::Done(Batch::new().require(Precondition::Present(
                    Key::new(b"never-present".to_vec()),
                ))));
            }
            Ok(Fired::Done(Batch::new()))
        })
    }
}

fn handler(kind: u8, fail: bool, repeat_first: bool) -> (Handler, Arc<Mutex<Vec<u32>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    (
        Handler {
            kind,
            fail,
            repeat_first,
            fail_guard: false,
            advance_clock: None,
            calls: calls.clone(),
        },
        calls,
    )
}

#[test]
fn two_hundred_heads_share_scan_commit_and_kind_attempt_bounds() {
    let clock = Arc::new(ManualClock::new(1000));
    let store = store(&clock);
    for index in 0..200 {
        seed(&store, index, if index % 2 == 0 { 240 } else { 241 });
    }
    let (first, first_calls) = handler(240, false, false);
    let (second, second_calls) = handler(241, false, false);
    let registry = TimerRegistry::new().register(first).register(second);
    let budget = TickBudget::new(17, 32, 256, 10_000);
    let report = block_on(run_physical_alarm(
        &store,
        &registry,
        clock.as_ref(),
        1000,
        budget,
        &mut None,
    ))
    .unwrap();
    assert_eq!(report.committed, 17);
    assert!(report.examined <= budget.max_scanned);
    assert!(report.raw_rows <= report.examined);
    assert!(report.partition_heads <= 17);
    for (kind, calls) in [(240, first_calls), (241, second_calls)] {
        assert!(report.attempted_for(TimerKind::new(kind)) <= budget.max_per_kind);
        assert_eq!(
            usize::try_from(report.attempted_for(TimerKind::new(kind))).unwrap(),
            calls.lock().unwrap().len()
        );
    }
    assert_eq!(report.next_wake_ms, Some(1000));
}

#[test]
fn failed_handlers_cannot_refresh_their_kind_allowance_per_head() {
    let clock = Arc::new(ManualClock::new(1000));
    let store = store(&clock);
    for index in 0..200 {
        seed(&store, index, 240);
    }
    let (failed, calls) = handler(240, true, false);
    let registry = TimerRegistry::new().register(failed);
    let budget = TickBudget::new(128, 5, 256, 10_000);
    let report = block_on(run_physical_alarm(
        &store,
        &registry,
        clock.as_ref(),
        1000,
        budget,
        &mut None,
    ))
    .unwrap();
    assert_eq!(report.attempted, 5);
    assert_eq!(report.attempted_for(TimerKind::new(240)), 5);
    assert_eq!(calls.lock().unwrap().len(), 5);
    assert_eq!(report.committed, 5); // Retry movements also consume commits.
    assert!(report.examined <= budget.max_scanned);
    assert_eq!(report.next_wake_ms, Some(1000));
}

#[test]
fn unknown_and_failed_prefixes_move_durably_across_repeated_cold_alarms() {
    for failure_mode in 0..3 {
        let clock = Arc::new(ManualClock::new(1002));
        let store = store(&clock);
        let prefix_kind = if failure_mode > 0 { 240 } else { 239 };
        for index in 0..80 {
            block_on(store.apply(
                &partition(index),
                Batch::new().put(
                    keys::timer(1000, prefix_kind, &index.to_be_bytes()),
                    Value::new(b"retained payload".to_vec()),
                ),
            ))
            .unwrap();
        }
        let later_key = keys::timer(1001, 241, &200_u32.to_be_bytes());
        block_on(store.apply(
            &partition(200),
            Batch::new().put(later_key.clone(), Value::default()),
        ))
        .unwrap();
        let (later, calls) = handler(241, false, false);
        let mut registry = TimerRegistry::new().register(later);
        if failure_mode > 0 {
            let mut prefix = handler(240, failure_mode == 1, false).0;
            prefix.fail_guard = failure_mode == 2;
            registry = registry.register(prefix);
        }
        for _cold_alarm in 0..8 {
            // Eviction deliberately discards every volatile enumeration cursor.
            let report = block_on(run_physical_alarm(
                &store,
                &registry,
                clock.as_ref(),
                1002,
                TickBudget::new(16, 16, 256, 10_000),
                &mut None,
            ))
            .unwrap();
            assert!(report.examined <= 256);
            assert!(report.committed <= 16);
            if !calls.lock().unwrap().is_empty() {
                break;
            }
            assert_eq!(report.next_wake_ms, Some(1002));
        }
        assert_eq!(
            *calls.lock().unwrap(),
            vec![200],
            "failure mode: {failure_mode}"
        );
        assert!(
            block_on(store.get(&partition(200), &later_key))
                .unwrap()
                .is_none()
        );
        let mut after = None;
        let mut retained = 0;
        loop {
            let rows = store.timer_window(after.as_ref(), 64).unwrap();
            if rows.is_empty() {
                break;
            }
            for row in &rows {
                assert_eq!(keys::timer_retry_state(&row.key), Some((1000, 1)));
                assert!(
                    matches!(keys::parse(&row.key), Some(keys::ParsedKey::Timer { due_at_ms, kind, .. }) if due_at_ms > 1002 && kind == prefix_kind)
                );
                assert_eq!(
                    block_on(store.get(&row.partition, &row.key)).unwrap(),
                    Some(Value::new(b"retained payload".to_vec()))
                );
                retained += 1;
            }
            after = rows.last().cloned();
        }
        assert_eq!(retained, 80);
    }
}

#[test]
fn warm_rotation_reaches_later_heads_behind_a_repeating_earliest_timer() {
    let clock = Arc::new(ManualClock::new(1000));
    let store = store(&clock);
    for index in 0..200 {
        seed(&store, index, 240);
    }
    let (repeating, calls) = handler(240, false, true);
    let registry = TimerRegistry::new().register(repeating);
    let budget = TickBudget::new(128, 1, 256, 10_000);
    let mut cursor = None;
    for _warm_alarm in 0..4 {
        let report = block_on(run_physical_alarm(
            &store,
            &registry,
            clock.as_ref(),
            1000,
            budget,
            &mut cursor,
        ))
        .unwrap();
        assert_eq!(report.attempted, 1);
        assert!(report.examined <= budget.max_scanned);
        assert_eq!(report.next_wake_ms, Some(1000));
    }
    let calls = calls.lock().unwrap();
    assert_eq!(calls[0], 0);
    assert!(calls.iter().any(|index| *index > 64));
    assert!(
        block_on(store.get(&partition(0), &keys::timer(1000, 240, &0_u32.to_be_bytes())))
            .unwrap()
            .is_some()
    );
}

#[test]
fn elapsed_allowance_stops_all_later_heads_without_a_final_sql_probe() {
    let clock = Arc::new(ManualClock::new(1000));
    let store = store(&clock);
    for index in 0..200 {
        seed(&store, index, 240);
    }
    let (mut advancing, calls) = handler(240, false, false);
    advancing.advance_clock = Some(clock.clone());
    let registry = TimerRegistry::new().register(advancing);
    let report = block_on(run_physical_alarm(
        &store,
        &registry,
        clock.as_ref(),
        1000,
        TickBudget::new(128, 32, 512, 10),
        &mut None,
    ))
    .unwrap();
    assert_eq!((report.attempted, report.committed), (1, 1));
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert_eq!(report.raw_rows, TIMER_WINDOW_ROWS);
    assert_eq!(report.partition_heads, 1);
    assert_eq!(report.next_wake_ms, Some(1000));
    assert_eq!(clock.now_ms(), 1010);
}

#[test]
fn retry_destination_collision_retains_payloads_and_uses_partition_backoff() {
    let clock = Arc::new(ManualClock::new(100));
    let store = store(&clock);
    let original = keys::timer(1, 240, &1_u32.to_be_bytes());
    let destination = keys::timer_retry(5100, 240, &1_u32.to_be_bytes(), 1, 1);
    block_on(
        store.apply(
            &partition(1),
            Batch::new()
                .put(original.clone(), Value::new(b"original payload".to_vec()))
                .put(
                    destination.clone(),
                    Value::new(b"different payload".to_vec()),
                ),
        ),
    )
    .unwrap();
    let (failed, calls) = handler(240, true, false);
    let registry = TimerRegistry::new().register(failed);
    let report = block_on(run_physical_alarm(
        &store,
        &registry,
        clock.as_ref(),
        100,
        TickBudget::default(),
        &mut None,
    ))
    .unwrap();
    assert_eq!((report.attempted, report.committed), (1, 0));
    assert_eq!(*calls.lock().unwrap(), vec![1]);
    assert_eq!(report.next_wake_ms, Some(5100));
    assert_eq!(
        store.timer_window(None, TIMER_WINDOW_ROWS).unwrap().len(),
        2
    );
    for (key, payload) in [
        (original, b"original payload".as_slice()),
        (destination, b"different payload".as_slice()),
    ] {
        assert_eq!(
            block_on(store.get(&partition(1), &key)).unwrap(),
            Some(Value::new(payload.to_vec()))
        );
    }
}

struct InsertEarlierThenRetry;

impl TimerHandler<Store> for InsertEarlierThenRetry {
    fn kind(&self) -> TimerKind {
        TimerKind::new(240)
    }

    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, Store>,
        _timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            ctx.store
                .apply(
                    ctx.partition,
                    Batch::new().put(
                        keys::timer(0, 240, &2_u32.to_be_bytes()),
                        Value::new(b"new earlier payload".to_vec()),
                    ),
                )
                .await?;
            Ok(Fired::Retry)
        })
    }
}

#[test]
fn newly_inserted_earlier_head_keeps_an_immediate_wake_after_retry_collision() {
    let clock = Arc::new(ManualClock::new(100));
    let store = store(&clock);
    let original = keys::timer(1, 240, &1_u32.to_be_bytes());
    let destination = keys::timer_retry(5100, 240, &1_u32.to_be_bytes(), 1, 1);
    let inserted = keys::timer(0, 240, &2_u32.to_be_bytes());
    block_on(
        store.apply(
            &partition(1),
            Batch::new()
                .put(original.clone(), Value::new(b"original payload".to_vec()))
                .put(
                    destination.clone(),
                    Value::new(b"different payload".to_vec()),
                ),
        ),
    )
    .unwrap();
    let registry = TimerRegistry::new().register(InsertEarlierThenRetry);
    let report = block_on(run_physical_alarm(
        &store,
        &registry,
        clock.as_ref(),
        100,
        TickBudget::default(),
        &mut None,
    ))
    .unwrap();
    assert_eq!((report.attempted, report.committed), (1, 0));
    assert_eq!(report.next_wake_ms, Some(100));
    assert_eq!(
        store.timer_window(None, TIMER_WINDOW_ROWS).unwrap().len(),
        3
    );
    for (key, payload) in [
        (original, b"original payload".as_slice()),
        (destination, b"different payload".as_slice()),
        (inserted, b"new earlier payload".as_slice()),
    ] {
        assert_eq!(
            block_on(store.get(&partition(1), &key)).unwrap(),
            Some(Value::new(payload.to_vec()))
        );
    }
}
