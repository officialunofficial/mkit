//! Database-wide physical storage pressure, sampled every sixty seconds.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use mkit_server::sql::{Capacity, SqlConn};
use mkit_server::telemetry::pressure::{METRIC_PARTITION_BYTES, PressureState, emit, observe};
use mkit_server::{Clock, Metrics, StoreError, SystemClock};
use tokio::task::JoinHandle;
use tracing::instrument::WithSubscriber as _;

use crate::{RusqliteConn, Shutdown, blocking, telemetry::MetricsBridge};

const PERIOD: Duration = Duration::from_mins(1);

/// A monitor over the server's `SQLite` connection and physical soft limit.
/// Filesystem metadata does not create one.
pub struct PressureMonitor {
    conn: RusqliteConn,
    capacity: Capacity,
    metrics: Arc<dyn Metrics>,
}

impl fmt::Debug for PressureMonitor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PressureMonitor")
            .field("conn", &self.conn)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl PressureMonitor {
    /// Prepare a monitor; no query runs until [`Self::start`].
    #[must_use]
    pub fn new(conn: RusqliteConn, capacity: Capacity) -> Self {
        Self {
            conn,
            capacity,
            metrics: Arc::new(MetricsBridge),
        }
    }

    /// Start on the current runtime. Await the returned task during drain.
    ///
    /// # Panics
    /// Outside a Tokio runtime.
    #[must_use]
    pub fn start(self, shutdown: Shutdown) -> JoinHandle<()> {
        tokio::spawn(self.drive(shutdown, PERIOD).with_current_subscriber())
    }

    #[allow(clippy::cast_precision_loss)]
    async fn drive(self, shutdown: Shutdown, period: Duration) {
        let mut state = PressureState::default();
        let mut ticks = tokio::time::interval(period);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                () = shutdown.wait() => return,
                _ = ticks.tick() => {},
            }
            let conn = self.conn.clone();
            let bytes =
                blocking::on_pool(move || conn.size_bytes().map_err(StoreError::from)).await;
            if shutdown.is_triggered() {
                return;
            }
            let bytes = match bytes {
                Ok(bytes) => bytes,
                Err(error) => {
                    tracing::warn!(event = "storage_pressure_read_failed", kind = "database", %error);
                    continue;
                }
            };
            self.metrics.gauge(
                METRIC_PARTITION_BYTES,
                &[("kind", "database")],
                bytes as f64,
            );
            let now_ms = u64::try_from(SystemClock.now_ms()).unwrap_or(u64::MAX);
            let (next, alerts) = observe(state, bytes, self.capacity.soft_limit(), now_ms);
            state = next;
            for level in alerts {
                emit(level, "database", bytes, self.capacity.soft_limit());
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::cast_precision_loss)]
mod tests {
    use std::io::{self, Write};
    use std::sync::Mutex;

    use clap::Parser;
    use mkit_server::sql::{DEFAULT_PAGE_SIZE, SqlValue, reserve_floor};
    use tokio::sync::Notify;

    use super::*;

    #[derive(Debug, Parser)]
    struct Serve {
        #[command(flatten)]
        args: crate::config::ServeArgs,
    }

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct Gauges {
        values: Mutex<Vec<f64>>,
        changed: Notify,
    }

    impl Metrics for Gauges {
        fn incr(&self, _: &'static str, _: &[(&'static str, &str)], _: u64) {}
        fn observe_ms(&self, _: &'static str, _: &[(&'static str, &str)], _: f64) {}
        fn gauge(&self, name: &'static str, labels: &[(&'static str, &str)], value: f64) {
            assert_eq!(name, METRIC_PARTITION_BYTES);
            assert_eq!(labels, &[("kind", "database")]);
            self.values.lock().unwrap().push(value);
            self.changed.notify_one();
        }
    }

    #[tokio::test]
    async fn physical_size_emits_warn_and_critical_and_stops_on_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let conn = RusqliteConn::open(dir.path().join("pressure.sqlite3")).unwrap();
        conn.exec("CREATE TABLE data (value BLOB)", &[]).unwrap();
        let initial_bytes = conn.size_bytes().unwrap();
        // The configured cap includes the reserve, leaving a small soft
        // limit that places the existing physical pages above 70%.
        std::fs::create_dir(dir.path().join(".mkit")).unwrap();
        let cap = (reserve_floor(DEFAULT_PAGE_SIZE) + initial_bytes * 4 / 3).to_string();
        let meta = format!("sqlite:{}", dir.path().join("pressure.sqlite3").display());
        let args = Serve::try_parse_from([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            dir.path().to_str().unwrap(),
            "--meta",
            &meta,
            "--sqlite-max-bytes",
            &cap,
            "--unsafe-allow-any-peer",
        ])
        .unwrap()
        .args;
        let cfg = crate::config::resolve(&args, &|_| None).unwrap();
        let crate::config::MetaChoice::Sqlite { capacity, .. } = cfg.meta else {
            panic!("expected SQLite metadata")
        };
        let metrics = Arc::new(Gauges::default());
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let shutdown = Shutdown::new();
        let monitor = PressureMonitor {
            conn: conn.clone(),
            capacity,
            metrics: metrics.clone(),
        };
        let task = tokio::spawn(
            monitor
                .drive(shutdown.clone(), Duration::from_millis(10))
                .with_subscriber(subscriber),
        );
        tokio::time::timeout(Duration::from_secs(3), metrics.changed.notified())
            .await
            .unwrap();
        assert_eq!(
            metrics.values.lock().unwrap()[0].to_bits(),
            (initial_bytes as f64).to_bits(),
        );
        conn.exec(
            "INSERT INTO data VALUES (?1)",
            &[SqlValue::Blob(vec![0; 16 * 1024])],
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
                if text.contains("\"level\":\"critical\"") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        shutdown.trigger();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        let count = metrics.values.lock().unwrap().len();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(metrics.values.lock().unwrap().len(), count);
        let lines = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        let events: Vec<serde_json::Value> = lines
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        for level in ["warn", "critical"] {
            let event = events
                .iter()
                .find(|event| event["fields"]["level"] == level)
                .unwrap();
            assert_eq!(event["fields"]["event"], "storage_pressure");
            assert_eq!(event["fields"]["kind"], "database");
            assert_eq!(event["fields"]["limit_bytes"], capacity.soft_limit());
            assert!(event["fields"]["bytes"].as_u64().unwrap() >= initial_bytes);
        }
    }
}
