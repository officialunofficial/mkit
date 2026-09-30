//! One timer allowance shared by every logical partition in a physical tick.

use super::{TickBudget, TimerKind};
use crate::rt::Clock;

/// Physical-tick counters. Fetching a page reserves its rows before processing
/// them, so an exhausted scan allowance does not discard an already read page.
#[derive(Debug)]
pub struct TickState {
    budget: TickBudget,
    start: i64,
    /// Rows fetched, including unknown, deferred and lookahead rows.
    pub examined: u32,
    /// Successfully committed timer batches.
    pub committed: u32,
    /// Claimed handler invocations, including failures and races.
    pub attempted: u32,
    per_kind: [u32; 256],
}

impl TickState {
    /// Begin one physical tick. Reuse this state for all its logical partitions.
    #[must_use]
    pub fn new(clock: &dyn Clock, budget: TickBudget) -> Self {
        Self {
            budget,
            start: clock.now_ms(),
            examined: 0,
            committed: 0,
            attempted: 0,
            per_kind: [0; 256],
        }
    }

    /// Rows that another page may fetch.
    #[must_use]
    pub fn remaining_scanned(&self) -> u32 {
        self.budget.max_scanned.saturating_sub(self.examined)
    }

    /// Whether another page or partition must wait for a later physical tick.
    #[must_use]
    pub fn exhausted(&self, clock: &dyn Clock) -> bool {
        self.remaining_scanned() == 0 || self.work_exhausted(clock)
    }

    /// Whether processing must stop, including inside an already reserved page.
    /// The scan allowance is excluded because those rows were charged on fetch.
    #[must_use]
    pub fn work_exhausted(&self, clock: &dyn Clock) -> bool {
        let elapsed = u64::try_from(clock.now_ms().saturating_sub(self.start)).unwrap_or(0);
        self.committed >= self.budget.max_fired || elapsed >= self.budget.max_elapsed_ms
    }

    /// Reserve exactly the number of fetched rows. An oversized charge changes
    /// no counters; the caller must limit its query to the remaining allowance.
    #[must_use]
    pub fn charge_scan(&mut self, rows: u32) -> bool {
        if rows > self.remaining_scanned() {
            return false;
        }
        self.examined += rows;
        true
    }

    /// Claim one handler invocation before it runs. A handler can lower its
    /// kind's allowance, but cannot enlarge the shared physical-tick ceiling.
    #[must_use]
    pub fn claim_attempt(&mut self, kind: TimerKind, handler_cap: Option<u32>) -> bool {
        let cap = handler_cap
            .unwrap_or(self.budget.max_per_kind)
            .max(1)
            .min(self.budget.max_per_kind);
        let count = &mut self.per_kind[usize::from(kind.get())];
        if *count >= cap {
            return false;
        }
        *count += 1;
        self.attempted = self.attempted.saturating_add(1);
        true
    }

    /// Record one successful guarded commit.
    pub fn committed(&mut self) {
        self.committed = self.committed.saturating_add(1);
    }

    /// Invocations already claimed by this kind, for verification and reporting.
    #[must_use]
    pub fn attempted_for(&self, kind: TimerKind) -> u32 {
        self.per_kind[usize::from(kind.get())]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rt::ManualClock;

    #[test]
    fn frozen_clock_partitions_share_scans_and_failed_attempts() {
        let clock = ManualClock::new(100);
        let mut state = TickState::new(&clock, TickBudget::default());
        let kind = TimerKind::new(12);
        let mut attempts = 0;
        for _partition in 0..16 {
            assert!(state.charge_scan(32));
            for _row in 0..32 {
                // A failed handler still consumes its invocation. No commit
                // is recorded, so failures cannot refresh the kind allowance.
                attempts += u32::from(state.claim_attempt(kind, Some(128)));
            }
        }
        assert_eq!(
            (attempts, state.attempted, state.attempted_for(kind)),
            (32, 32, 32)
        );
        assert_eq!((state.examined, state.committed), (512, 0));
        assert!(state.exhausted(&clock));
        assert!(!state.work_exhausted(&clock));
        assert!(!state.charge_scan(1));
        assert_eq!(state.examined, 512);
        // Rows in the last reserved page may still invoke another kind.
        assert!(state.claim_attempt(TimerKind::new(8), None));
    }

    #[test]
    fn handler_cap_can_lower_but_cannot_raise_the_shared_kind_limit() {
        let clock = ManualClock::new(0);
        let mut state = TickState::new(&clock, TickBudget::new(128, 3, 512, 10_000));
        let limited = TimerKind::new(1);
        assert!(state.claim_attempt(limited, Some(0)));
        assert!(!state.claim_attempt(limited, Some(0)));
        let default = TimerKind::new(2);
        let raised = TimerKind::new(3);
        for _ in 0..3 {
            assert!(state.claim_attempt(default, None));
            assert!(state.claim_attempt(raised, Some(u32::MAX)));
        }
        assert!(!state.claim_attempt(default, None));
        assert!(!state.claim_attempt(raised, Some(u32::MAX)));
        assert_eq!(state.attempted, 7);
    }

    #[test]
    fn final_reserved_page_can_finish_until_the_commit_ceiling() {
        let clock = ManualClock::new(0);
        let mut state = TickState::new(&clock, TickBudget::new(2, 32, 3, 100));
        assert!(!state.charge_scan(4));
        assert_eq!(state.examined, 0);
        assert!(state.charge_scan(3));
        assert!(state.exhausted(&clock));
        assert!(!state.work_exhausted(&clock));
        state.committed();
        assert!(!state.work_exhausted(&clock));
        state.committed();
        assert!(state.work_exhausted(&clock));
        assert_eq!(state.committed, 2);
    }

    #[test]
    fn clock_deadline_is_shared_and_stops_at_the_exact_boundary() {
        let clock = ManualClock::new(100);
        let state = TickState::new(&clock, TickBudget::new(128, 32, 512, 10));
        clock.set(99);
        assert!(!state.work_exhausted(&clock));
        clock.set(109);
        assert!(!state.exhausted(&clock));
        clock.set(110);
        assert!(state.work_exhausted(&clock));
        assert!(state.exhausted(&clock));
        assert_eq!(state.remaining_scanned(), 512);
    }
}
