//! Host-testable choices for a Durable Object's single alarm.

pub use mkit_server::timers::earliest_timer_put;

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

/// Set the next wake strictly after now, or delete an empty schedule.
/// Reusing the active alarm timestamp can strand a workerd alarm chain.
#[must_use]
pub fn alarm_after_tick(next_wake: Option<u64>, now_ms: u64) -> AlarmAction {
    match next_wake {
        Some(next) => AlarmAction::Set(alarm_time(next.max(now_ms.saturating_add(1)))),
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
    let earliest = alarm_time(now_ms.saturating_add(1));
    match (current, alarm_after_tick(next_wake, now_ms)) {
        (Some(current), AlarmAction::Set(next)) => {
            AlarmAction::Set(current.min(next).max(earliest))
        }
        (Some(current), AlarmAction::Delete) => AlarmAction::Set(current.max(earliest)),
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
        alarm_after_tick(Some(now_ms), now_ms)
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
    fn continuation_advances_a_frozen_alarm_clock() {
        // workerd can retain a rearmed timestamp equal to the active alarm
        // without scheduling a successor (cloudflare/workerd#6866).
        for current in [None, Some(99), Some(100)] {
            for dirty in [false, true] {
                assert_eq!(
                    alarm_after_tick_with_dirty(current, Some(100), 100, dirty),
                    AlarmAction::Set(101),
                );
            }
        }
        assert_eq!(alarm_after_tick(Some(90), 100), AlarmAction::Set(101));
        assert_eq!(
            alarm_after_tick_with_current(Some(90), None, 100),
            AlarmAction::Set(101),
        );
        assert_eq!(
            alarm_after_tick_with_current(Some(200), Some(300), 100),
            AlarmAction::Set(200),
        );
    }

    #[test]
    fn tick_preserves_alarms_installed_by_interleaved_applies() {
        let schedules = [None, Some(10), Some(200), Some(u64::MAX)];
        let cases = [
            (
                None,
                [
                    AlarmAction::Delete,
                    AlarmAction::Set(101),
                    AlarmAction::Set(200),
                    AlarmAction::Set(MAX_DATE_MS),
                ],
            ),
            (Some(50), [AlarmAction::Set(101); 4]),
            (Some(100), [AlarmAction::Set(101); 4]),
            (
                Some(150),
                [
                    AlarmAction::Set(150),
                    AlarmAction::Set(101),
                    AlarmAction::Set(150),
                    AlarmAction::Set(150),
                ],
            ),
            (
                Some(300),
                [
                    AlarmAction::Set(300),
                    AlarmAction::Set(101),
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
            AlarmAction::Set(101)
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
        assert_eq!(alarm_after_tick(Some(10), 100), AlarmAction::Set(101));
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
