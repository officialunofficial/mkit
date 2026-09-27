//! Alert on physical bytes against the put soft limit. No storage I/O or
//! wall clock is hidden here: callers supply measurements and time.

/// Gauge of physical bytes, labelled by partition kind (or `database`).
pub const METRIC_PARTITION_BYTES: &str = "mkit_server_partition_bytes";
/// Minimum time between alerts of the same level, even after re-entry.
pub const ALERT_INTERVAL_MS: u64 = 10 * 60 * 1000;

/// Storage-pressure severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureLevel {
    /// At least 70% of the physical soft limit, clearing at 65%.
    Warn,
    /// At least 90% of the physical soft limit, clearing at 85%.
    Critical,
}

impl PressureLevel {
    /// Structured log label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::Critical => "critical",
        }
    }
}

/// Per-instance state. Clearing a level preserves its last emission time:
/// bouncing around a threshold cannot bypass the ten-minute limit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PressureState {
    active: [bool; 2],
    last_emitted: [Option<u64>; 2],
}

/// Pure pressure transition with an injected clock. Emits only the highest
/// active severity; hysteresis keeps it active until five points below its
/// threshold. Clock rollback cannot bypass the limiter. A zero soft limit
/// means no writable capacity and is reported as 100%.
#[must_use]
pub fn observe(
    mut state: PressureState,
    bytes: u64,
    limit_bytes: u64,
    now_ms: u64,
) -> (PressureState, Vec<PressureLevel>) {
    // Integer cross-products preserve exact boundaries even above 2^53.
    let used = u128::from(bytes) * 100;
    for (i, threshold) in [70_u128, 90].into_iter().enumerate() {
        if limit_bytes == 0 || used >= u128::from(limit_bytes) * threshold {
            state.active[i] = true;
        } else if used <= u128::from(limit_bytes) * (threshold - 5) {
            state.active[i] = false;
        }
    }
    let highest = if state.active[1] {
        Some((1, PressureLevel::Critical))
    } else if state.active[0] {
        Some((0, PressureLevel::Warn))
    } else {
        None
    };
    let mut emitted = Vec::new();
    if let Some((i, level)) = highest
        && state.last_emitted[i].is_none_or(|last| now_ms.saturating_sub(last) >= ALERT_INTERVAL_MS)
    {
        state.last_emitted[i] = Some(now_ms);
        emitted.push(level);
    }
    (state, emitted)
}

/// Percentage for display only; the decision uses integer cross-products.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn percentage(bytes: u64, limit_bytes: u64) -> f64 {
    if limit_bytes == 0 {
        100.0
    } else {
        bytes as f64 / limit_bytes as f64 * 100.0
    }
}

/// Emit the same structured fields on both runtimes. Critical pressure is
/// an error event; warning pressure is a warn event.
pub fn emit(level: PressureLevel, kind: &str, bytes: u64, limit_bytes: u64) {
    let pct = percentage(bytes, limit_bytes);
    match level {
        PressureLevel::Warn => tracing::warn!(
            event = "storage_pressure",
            level = level.label(),
            kind,
            bytes,
            limit_bytes,
            pct
        ),
        PressureLevel::Critical => tracing::error!(
            event = "storage_pressure",
            level = level.label(),
            kind,
            bytes,
            limit_bytes,
            pct
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_and_highest_severity() {
        for (bytes, expected) in [
            (69, vec![]),
            (70, vec![PressureLevel::Warn]),
            (89, vec![PressureLevel::Warn]),
            (90, vec![PressureLevel::Critical]),
            (120, vec![PressureLevel::Critical]),
        ] {
            assert_eq!(observe(PressureState::default(), bytes, 100, 0).1, expected);
        }
        assert_eq!(
            observe(PressureState::default(), 0, 0, 0).1,
            vec![PressureLevel::Critical]
        );
        assert_eq!(
            observe(PressureState::default(), u64::MAX, u64::MAX, 0).1,
            vec![PressureLevel::Critical]
        );
    }

    #[test]
    fn hysteresis_clears_at_five_points() {
        let (warn, _) = observe(PressureState::default(), 70, 100, 0);
        assert_eq!(
            observe(warn, 66, 100, ALERT_INTERVAL_MS).1,
            vec![PressureLevel::Warn]
        );
        assert!(observe(warn, 65, 100, ALERT_INTERVAL_MS).1.is_empty());
        let (critical, _) = observe(PressureState::default(), 90, 100, 0);
        assert_eq!(
            observe(critical, 86, 100, ALERT_INTERVAL_MS).1,
            vec![PressureLevel::Critical]
        );
        assert_eq!(
            observe(critical, 85, 100, ALERT_INTERVAL_MS).1,
            vec![PressureLevel::Warn]
        );
    }

    #[test]
    fn rate_limit_survives_clear_reentry_and_clock_rollback() {
        let (state, _) = observe(PressureState::default(), 70, 100, 100);
        let (cleared, _) = observe(state, 0, 100, 101);
        for at in [0, 102, ALERT_INTERVAL_MS + 99] {
            assert!(observe(cleared, 70, 100, at).1.is_empty());
        }
        assert_eq!(
            observe(cleared, 70, 100, ALERT_INTERVAL_MS + 100).1,
            vec![PressureLevel::Warn]
        );
        // Critical has its own clock, independent of an earlier warning.
        assert_eq!(
            observe(state, 90, 100, 101).1,
            vec![PressureLevel::Critical]
        );
    }
}
