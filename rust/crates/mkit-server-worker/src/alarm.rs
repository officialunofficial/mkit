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

/// Set the next wake, clamping to now, or delete an empty schedule.
#[must_use]
pub fn alarm_after_tick(next_wake: Option<u64>, now_ms: u64) -> AlarmAction {
    match next_wake {
        Some(next) => AlarmAction::Set(alarm_time(next.max(now_ms))),
        None => AlarmAction::Delete,
    }
}

fn alarm_time(time: u64) -> i64 {
    i64::try_from(time).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use mkit_server::{Batch, Value, store::keys};

    use super::*;

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
            AlarmAction::Set(i64::MAX)
        );
    }
}
