//! Optional compatibility helpers for reference-server test fixtures.

impl crate::wire::TestClock for mkit_server::ManualClock {
    fn now_ms(&self) -> i64 {
        mkit_server::Clock::now_ms(self)
    }
    fn advance(&self, delta_ms: i64) {
        mkit_server::ManualClock::advance(self, delta_ms);
    }
}
