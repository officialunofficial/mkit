//! The Worker's [`Clock`](mkit_server::Clock): `Date.now()`.
//!
//! Workers freeze `Date.now()` during synchronous execution and advance it
//! with I/O, so a reading is the time of the last I/O event. The pipeline
//! uses it for validity windows; `NotAfter` deadlines are checked by the
//! Durable Object against its own `Date.now()` (`do_sql`), never this one.

/// `Date.now()` of the running isolate, in Unix epoch milliseconds.
#[derive(Debug, Default, Clone, Copy)]
pub struct WorkerClock;

#[cfg(target_arch = "wasm32")]
impl mkit_server::Clock for WorkerClock {
    fn now_ms(&self) -> i64 {
        i64::try_from(worker::Date::now().as_millis()).unwrap_or(i64::MAX)
    }
}
