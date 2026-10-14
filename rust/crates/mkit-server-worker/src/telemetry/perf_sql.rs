//! Bounded SQL accounting for a sampled, synchronous storage dispatch.
//!
//! Durations include SQL execution, cursor stepping and row materialization,
//! including the JavaScript value bridge. They exclude request/reply wire
//! encoding and decoding. Workers clocks may remain frozen during synchronous
//! execution: a zero duration is not evidence that SQL took no CPU time.

use std::sync::{Arc, Mutex};

use crate::sql::{Row, SqlConn, SqlError, SqlValue, TxFn};
use mkit_server::StoreError;
use serde::Serialize;

/// Numeric-only SQL totals for one sampled storage dispatch.
#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct SqlTimings {
    /// Query execution, stepping and materialization wall time in milliseconds.
    pub sql_query_ms: f64,
    /// Non-query execution and cursor draining wall time in milliseconds.
    pub sql_exec_ms: f64,
    /// Queries attempted, including failed queries.
    pub query_statements: u64,
    /// Non-query statements attempted, including failed statements.
    pub exec_statements: u64,
    /// Rows materialized by successful queries.
    pub query_rows: u64,
}

/// Constant-space accounting shared by all clones of a connection.
///
/// A scope must surround one synchronous dispatch, with no await between
/// `begin` and `take`. Concurrent native callers should use separate collectors.
#[derive(Debug, Clone, Default)]
pub struct SqlCollector(Arc<Mutex<Option<SqlTimings>>>);

impl SqlCollector {
    /// Reset the scope, enabling timers only for a sampled dispatch.
    pub fn begin(&self, sampled: bool) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = sampled.then(SqlTimings::default);
    }

    /// End the scope and return its numeric totals; unsampled scopes are empty.
    #[must_use]
    pub fn take(&self) -> SqlTimings {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .unwrap_or_default()
    }

    /// Start a timer only when the enclosing dispatch is sampled.
    #[must_use]
    pub fn timer(&self) -> Option<SqlTimer> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|_| SqlTimer::now())
    }

    /// Record one completed call. No SQL text, parameters or result values
    /// can enter the collector.
    pub fn record(&self, timer: Option<SqlTimer>, query: bool, rows: usize) {
        let Some(timer) = timer else { return };
        let elapsed_ms = timer.elapsed_ms();
        if let Some(totals) = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            if query {
                totals.query_statements = totals.query_statements.saturating_add(1);
                totals.query_rows = totals.query_rows.saturating_add(rows as u64);
                totals.sql_query_ms += elapsed_ms;
            } else {
                totals.exec_statements = totals.exec_statements.saturating_add(1);
                totals.sql_exec_ms += elapsed_ms;
            }
        }
    }
}

/// Platform timer, intentionally wall time rather than CPU time.
#[derive(Debug)]
pub struct SqlTimer {
    #[cfg(not(target_arch = "wasm32"))]
    start: std::time::Instant,
    #[cfg(target_arch = "wasm32")]
    start: u64,
}

impl SqlTimer {
    fn now() -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            start: std::time::Instant::now(),
            #[cfg(target_arch = "wasm32")]
            start: worker::Date::now().as_millis(),
        }
    }

    fn elapsed_ms(self) -> f64 {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.start.elapsed().as_secs_f64() * 1000.0
        }
        #[cfg(target_arch = "wasm32")]
        {
            #[allow(clippy::cast_precision_loss)]
            {
                worker::Date::now().as_millis().saturating_sub(self.start) as f64
            }
        }
    }
}

/// Generic connection wrapper for native SQL profiling with the same counters.
/// All statements, parameters, transactions and returned rows are forwarded.
#[derive(Debug, Clone)]
pub struct TimedSqlConn<C> {
    inner: C,
    collector: SqlCollector,
}

impl<C> TimedSqlConn<C> {
    /// Wrap a connection without enabling collection.
    #[must_use]
    pub fn new(inner: C) -> Self {
        Self {
            inner,
            collector: SqlCollector::default(),
        }
    }

    /// Reset and optionally enable collection for one synchronous dispatch.
    pub fn begin_perf(&self, sampled: bool) {
        self.collector.begin(sampled);
    }

    /// End collection and return totals shared by this connection's clones.
    #[must_use]
    pub fn take_perf(&self) -> SqlTimings {
        self.collector.take()
    }
}

impl<C: SqlConn> SqlConn for TimedSqlConn<C> {
    fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError> {
        let timer = self.collector.timer();
        let result = self.inner.exec(sql, params);
        self.collector.record(timer, false, 0);
        result
    }

    fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>, SqlError> {
        let timer = self.collector.timer();
        let result = self.inner.query(sql, params);
        self.collector
            .record(timer, true, result.as_ref().map_or(0, Vec::len));
        result
    }

    fn transaction<T: 'static>(&self, f: TxFn<Self, T>) -> Result<T, SqlError> {
        let collector = self.collector.clone();
        self.inner
            .transaction(Box::new(move |inner| f(Self { inner, collector })))
    }

    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
    fn size_bytes(&self) -> Result<u64, SqlError> {
        self.inner.size_bytes()
    }
    fn set_size_limit(&self, bytes: u64) -> Result<(), SqlError> {
        self.inner.set_size_limit(bytes)
    }
    fn backup_to(&self, dest: &str) -> Result<(), StoreError> {
        self.inner.backup_to(dest)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::test_sqlite::RusqliteConn;

    #[test]
    fn sql_scopes_preserve_rows_transactions_and_errors_without_values() {
        let conn = TimedSqlConn::new(
            RusqliteConn::open_in_memory().expect("SQL profiling fixture operation"),
        );
        conn.exec("CREATE TABLE profile (value TEXT)", &[])
            .expect("SQL profiling fixture operation");
        conn.begin_perf(true);
        conn.transaction(Box::new(|tx| {
            tx.exec(
                "INSERT INTO profile VALUES (?)",
                &[SqlValue::Text("private-credential".into())],
            )?;
            Ok(())
        }))
        .expect("SQL profiling fixture operation");
        let rows = conn
            .clone()
            .query("SELECT value FROM profile", &[])
            .expect("SQL profiling fixture operation");
        assert_eq!(
            rows,
            vec![vec![SqlValue::Text("private-credential".into())]]
        );
        assert!(conn.query("SELECT private_key FROM missing", &[]).is_err());
        let stats = conn.take_perf();
        assert_eq!(stats.exec_statements, 1);
        assert_eq!(stats.query_statements, 2);
        assert_eq!(stats.query_rows, 1);
        assert!(stats.sql_query_ms >= 0.0);
        let json = serde_json::to_string(&stats).expect("SQL profiling fixture operation");
        for private in [
            "private-credential",
            "private_key",
            "missing",
            "SELECT",
            "INSERT",
        ] {
            assert!(!json.contains(private));
        }
        assert_eq!(conn.take_perf(), SqlTimings::default());
        conn.begin_perf(false);
        assert_eq!(
            conn.query("SELECT value FROM profile", &[])
                .expect("SQL profiling fixture operation"),
            rows
        );
        assert_eq!(conn.take_perf(), SqlTimings::default());
    }

    #[test]
    fn failed_transactions_keep_rollback_behavior_and_count_attempts() {
        let conn = TimedSqlConn::new(
            RusqliteConn::open_in_memory().expect("SQL profiling fixture operation"),
        );
        conn.exec("CREATE TABLE profile (value INTEGER)", &[])
            .expect("SQL profiling fixture operation");
        conn.begin_perf(true);
        let result = conn.transaction(Box::new(|tx| {
            tx.exec("INSERT INTO profile VALUES (1)", &[])?;
            tx.exec("INSERT INTO missing VALUES (1)", &[])
        }));
        assert!(result.is_err());
        assert!(
            conn.query("SELECT value FROM profile", &[])
                .expect("SQL profiling fixture operation")
                .is_empty()
        );
        let stats = conn.take_perf();
        assert_eq!(stats.exec_statements, 2);
        assert_eq!(stats.query_statements, 1);
        assert_eq!(stats.query_rows, 0);
    }

    fn scan(conn: &impl SqlConn) -> Vec<Vec<Row>> {
        let mut pages = Vec::new();
        for bucket in 0..8 {
            for start in (0..100).step_by(16) {
                pages.push(conn.query("SELECT ordinal, value FROM profile WHERE bucket = ? AND ordinal >= ? ORDER BY ordinal LIMIT 16", &[
                    SqlValue::Integer(bucket), SqlValue::Integer(start),
                ]).expect("SQL profiling fixture operation"));
            }
        }
        pages
    }

    #[test]
    fn heavy_scan_profile_preserves_page_rows_and_bounds_summary_bytes() {
        let inner = RusqliteConn::open_in_memory().expect("SQL profiling fixture operation");
        inner.exec("CREATE TABLE profile (bucket INTEGER, ordinal INTEGER, value BLOB, PRIMARY KEY(bucket, ordinal)) WITHOUT ROWID", &[]).expect("SQL profiling fixture operation");
        inner
            .transaction(Box::new(|tx| {
                for bucket in 0..8 {
                    for ordinal in 0..100 {
                        tx.exec(
                            "INSERT INTO profile VALUES (?, ?, ?)",
                            &[
                                SqlValue::Integer(bucket),
                                SqlValue::Integer(ordinal),
                                SqlValue::Blob(vec![42; 240]),
                            ],
                        )?;
                    }
                }
                Ok(())
            }))
            .expect("SQL profiling fixture operation");
        let timed = TimedSqlConn::new(inner.clone());
        let reference = scan(&inner);
        for sampled in [false, true] {
            timed.begin_perf(sampled);
            assert_eq!(scan(&timed), reference);
            let stats = timed.take_perf();
            if sampled {
                assert_eq!(stats.query_statements, 56);
                assert_eq!(stats.query_rows, 800);
                assert_eq!(stats.exec_statements, 0);
                assert!(stats.sql_query_ms > 0.0);
                assert!(
                    serde_json::to_string(&stats)
                        .expect("SQL profiling fixture operation")
                        .len()
                        < 256
                );
            } else {
                assert_eq!(stats, SqlTimings::default());
            }
        }
    }
}
