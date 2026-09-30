//! Host-testable choices for a Durable Object's single alarm.

pub use mkit_server::timers::earliest_timer_put;

use mkit_server::sql::{SqlConn, TimerCursor};
use mkit_server::store::keys;
use mkit_server::timers::{TickBudget, TickState, TimerKind, TimerRegistry, run_due_with_state};
use mkit_server::{Clock, StoreError};
use std::collections::HashSet;

use crate::ns_object::PressureStore;

/// At most this many raw timer keys reside in one enumeration window.
pub const TIMER_WINDOW_ROWS: u32 = 64;

/// Aggregate work over every logical partition in one physical alarm.
#[derive(Debug)]
pub struct PhysicalRunReport {
    /// Charged reads, including raw enumeration and the reserved earliest probe.
    pub examined: u32,
    /// Successfully committed timer batches across all dispatched partitions.
    pub committed: u32,
    /// Handler invocations, including failures and lost races.
    pub attempted: u32,
    /// Raw index rows returned by enumeration, including the earliest probe.
    pub raw_rows: u32,
    /// Distinct partitions dispatched during this alarm.
    pub partition_heads: u32,
    /// The earliest remaining physical timer, clamped to business time.
    pub next_wake_ms: Option<u64>,
    per_kind: [u32; 256],
}

impl PhysicalRunReport {
    /// Handler invocations claimed by this kind in the physical alarm.
    #[must_use]
    pub fn attempted_for(&self, kind: TimerKind) -> u32 {
        self.per_kind[usize::from(kind.get())]
    }
}

/// Rotate bounded raw windows with one shared allowance across every head.
///
/// The final earliest-row probe reserves one scan slot up front, even when it
/// finds no row. Elapsed/commit exhaustion skips that SQL probe and conservatively
/// wakes immediately. The cursor is volatile and advances only through visited
/// rows; durable retries provide progress after a cold start.
/// A complete pass with no committed progress may honor the partition drivers'
/// backoff wakes when guarded retry moves leave an overdue row in place.
///
/// # Errors
/// SQL enumeration failures or partition-local scan failures.
pub async fn run_physical_alarm<C: SqlConn>(
    store: &PressureStore<C>,
    registry: &TimerRegistry<'_, PressureStore<C>>,
    clock: &dyn Clock,
    now_ms: u64,
    budget: TickBudget,
    cursor: &mut Option<TimerCursor>,
) -> Result<PhysicalRunReport, StoreError> {
    let mut state = TickState::new(clock, budget);
    if !state.charge_scan(1) {
        return Err(StoreError::Invalid(
            "physical alarm requires a positive scan allowance".into(),
        ));
    }
    let mut partitions = HashSet::new();
    let from_beginning = cursor.is_none();
    let mut traversal_complete = false;
    let mut partition_stopped = false;
    let mut fallback_wake = None;
    let mut raw_rows = 0;
    let mut partition_heads = 0;
    'windows: while !state.exhausted(clock) {
        let limit = TIMER_WINDOW_ROWS.min(state.remaining_scanned());
        let rows = store.timer_window(cursor.as_ref(), limit)?;
        let count = u32::try_from(rows.len()).unwrap_or(u32::MAX);
        let charged = state.charge_scan(count);
        debug_assert!(charged, "the SQL window is limited by the scan allowance");
        raw_rows += count;
        if rows.is_empty() {
            *cursor = None;
            traversal_complete = true;
            break;
        }
        for row in rows {
            if state.work_exhausted(clock) {
                break 'windows;
            }
            let due = match keys::parse(&row.key) {
                Some(keys::ParsedKey::Timer { due_at_ms, .. }) => {
                    if due_at_ms > now_ms {
                        fallback_wake =
                            Some(fallback_wake.map_or(due_at_ms, |wake: u64| wake.min(due_at_ms)));
                    }
                    due_at_ms <= now_ms
                }
                _ => true,
            };
            if due && partitions.insert(row.partition.clone()) {
                if state.exhausted(clock) {
                    break 'windows;
                }
                let report =
                    run_due_with_state(store, &row.partition, registry, clock, now_ms, &mut state)
                        .await?;
                partition_stopped |= report.stopped_on_budget;
                if let Some(next) = report.next_wake_ms {
                    fallback_wake = Some(fallback_wake.map_or(next, |wake| wake.min(next)));
                }
                partition_heads += 1;
            }
            *cursor = Some(row);
        }
    }
    let next_wake_ms = if state.work_exhausted(clock) {
        Some(now_ms)
    } else {
        let earliest = store.timer_window(None, 1)?;
        raw_rows += u32::try_from(earliest.len()).unwrap_or(1);
        earliest.first().map(|row| match keys::parse(&row.key) {
            Some(keys::ParsedKey::Timer { due_at_ms, .. }) => {
                if due_at_ms <= now_ms
                    && from_beginning
                    && traversal_complete
                    && state.committed == 0
                    && !partition_stopped
                    && !state.exhausted(clock)
                    && partitions.contains(&row.partition)
                    && fallback_wake.is_some_and(|wake| wake > now_ms)
                {
                    fallback_wake.unwrap_or(now_ms)
                } else {
                    due_at_ms.max(now_ms)
                }
            }
            _ => now_ms,
        })
    };
    Ok(PhysicalRunReport {
        examined: state.examined,
        committed: state.committed,
        attempted: state.attempted,
        raw_rows,
        partition_heads,
        next_wake_ms,
        per_kind: std::array::from_fn(|kind| {
            state.attempted_for(TimerKind::new(u8::try_from(kind).unwrap_or(0)))
        }),
    })
}

/// Move the alarm earlier after a committed timer Put, clamping to now.
#[must_use]
pub fn alarm_after_put(current: Option<i64>, earliest: u64, now_ms: u64) -> Option<i64> {
    let next = alarm_time(earliest.max(now_ms));
    if current.is_none_or(|current| next < current) {
        Some(next)
    } else {
        None
    }
}

/// The action after a tick has examined the stored timer heads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmAction {
    /// Set an absolute Unix epoch millisecond timestamp.
    Set(i64),
    /// No timer remains: remove the alarm.
    Delete,
}

/// Set the next wake, clamping to now, or delete an empty schedule.
#[must_use]
pub fn alarm_after_tick(next_wake: Option<u64>, now_ms: u64) -> AlarmAction {
    match next_wake {
        Some(next) => AlarmAction::Set(alarm_time(next.max(now_ms))),
        None => AlarmAction::Delete,
    }
}

/// Retain an alarm installed while the tick awaited another handler.
#[must_use]
pub fn alarm_after_tick_with_current(
    current: Option<i64>,
    next_wake: Option<u64>,
    now_ms: u64,
) -> AlarmAction {
    match (current, alarm_after_tick(next_wake, now_ms)) {
        (Some(current), AlarmAction::Set(next)) => AlarmAction::Set(current.min(next)),
        (Some(current), AlarmAction::Delete) => AlarmAction::Set(current),
        (None, action) => action,
    }
}

/// A timer put committed while an alarm tick awaited a handler must wake a
/// fresh tick. Otherwise use the stored head and currently armed alarm.
#[must_use]
pub fn alarm_after_tick_with_dirty(
    current: Option<i64>,
    next_wake: Option<u64>,
    now_ms: u64,
    dirty: bool,
) -> AlarmAction {
    if dirty {
        AlarmAction::Set(alarm_time(now_ms))
    } else {
        alarm_after_tick_with_current(current, next_wake, now_ms)
    }
}

/// The latest instant a JavaScript `Date` can hold, Unix ms.
const MAX_DATE_MS: i64 = 8_640_000_000_000_000;

fn alarm_time(time: u64) -> i64 {
    i64::try_from(time).unwrap_or(MAX_DATE_MS).min(MAX_DATE_MS)
}

#[cfg(test)]
mod tests {
    use mkit_server::{Batch, Value, store::keys};

    use super::*;

    #[test]
    fn tick_preserves_alarms_installed_by_interleaved_applies() {
        let schedules = [None, Some(10), Some(200), Some(u64::MAX)];
        let cases = [
            (
                None,
                [
                    AlarmAction::Delete,
                    AlarmAction::Set(100),
                    AlarmAction::Set(200),
                    AlarmAction::Set(MAX_DATE_MS),
                ],
            ),
            (Some(50), [AlarmAction::Set(50); 4]),
            (Some(100), [AlarmAction::Set(100); 4]),
            (
                Some(150),
                [
                    AlarmAction::Set(150),
                    AlarmAction::Set(100),
                    AlarmAction::Set(150),
                    AlarmAction::Set(150),
                ],
            ),
            (
                Some(300),
                [
                    AlarmAction::Set(300),
                    AlarmAction::Set(100),
                    AlarmAction::Set(200),
                    AlarmAction::Set(300),
                ],
            ),
        ];
        for (current, expected) in cases {
            for (next, expected) in schedules.into_iter().zip(expected) {
                assert_eq!(alarm_after_tick_with_current(current, next, 100), expected);
            }
        }
    }

    #[test]
    fn dirty_tick_wakes_now_and_clean_empty_tick_deletes() {
        assert_eq!(
            alarm_after_tick_with_dirty(Some(500), None, 100, true),
            AlarmAction::Set(100)
        );
        assert_eq!(
            alarm_after_tick_with_dirty(None, None, 100, false),
            AlarmAction::Delete
        );
    }

    #[test]
    fn only_timer_puts_lower_the_alarm() {
        let batch = Batch::new()
            .put(keys::timer(900, 1, b"later"), Value::new(Vec::new()))
            .delete(keys::timer(100, 1, b"deleted"))
            .put(keys::timer(500, 2, b"earlier"), Value::new(Vec::new()));
        assert_eq!(earliest_timer_put(&batch), Some(500));
        assert_eq!(earliest_timer_put(&Batch::new()), None);
        assert_eq!(alarm_after_put(None, 500, 100), Some(500));
        assert_eq!(alarm_after_put(Some(900), 500, 100), Some(500));
        assert_eq!(alarm_after_put(Some(500), 500, 100), None);
        assert_eq!(alarm_after_put(Some(400), 500, 100), None);
    }

    #[test]
    fn past_timers_are_set_at_now_and_empty_ticks_delete() {
        assert_eq!(alarm_after_put(None, 10, 100), Some(100));
        assert_eq!(alarm_after_tick(Some(10), 100), AlarmAction::Set(100));
        assert_eq!(alarm_after_tick(Some(200), 100), AlarmAction::Set(200));
        assert_eq!(alarm_after_tick(None, 100), AlarmAction::Delete);
        assert_eq!(
            alarm_after_tick(Some(u64::MAX), 100),
            AlarmAction::Set(MAX_DATE_MS)
        );
        assert_eq!(
            alarm_after_tick(Some(9_000_000_000_000_000), 100),
            AlarmAction::Set(MAX_DATE_MS)
        );
    }
}

#[cfg(test)]
#[path = "alarm_bounds.rs"]
mod alarm_bounds;
