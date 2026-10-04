//! Worker console telemetry. Counters and gauges are never sampled;
//! latency observations emit on the first and then every hundredth call, across request-created
//! default sinks in one isolate. Each emitted line is one JSON object.

/// Physical Durable Object storage pressure and alert bookkeeping.
pub mod pressure;

use std::sync::atomic::{AtomicUsize, Ordering};

use mkit_server::Metrics;
use serde_json::{Map, Value, json};

/// Console channel for a structured line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Informational events and metrics.
    Log,
    /// Warning and error events.
    Error,
}

/// Injectable destination for a complete JSON line.
pub trait LineSink: Send + Sync {
    /// Emit exactly one line on the selected console channel.
    fn write(&self, channel: Channel, line: &str);
}

/// Workers' console. Host builds use an injected sink to inspect output.
#[derive(Debug, Default)]
pub struct ConsoleSink;

impl LineSink for ConsoleSink {
    fn write(&self, channel: Channel, line: &str) {
        #[cfg(target_arch = "wasm32")]
        match channel {
            Channel::Log => worker::console_log!("{line}"),
            Channel::Error => worker::console_error!("{line}"),
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = (channel, line);
    }
}

static ISOLATE_OBSERVATIONS: AtomicUsize = AtomicUsize::new(0);

/// A metrics sink that emits `metric`, `labels`, and `value` as JSON.
#[derive(Debug)]
pub struct ConsoleMetrics<S = ConsoleSink> {
    sink: S,
    observations: Option<AtomicUsize>,
}

impl Default for ConsoleMetrics {
    fn default() -> Self {
        Self {
            sink: ConsoleSink,
            observations: None,
        }
    }
}

impl<S: LineSink> ConsoleMetrics<S> {
    /// Use an injected sink and a fresh deterministic sampler. Observation
    /// 1, 101, 201, and so on are emitted; counters and gauges always emit.
    #[must_use]
    pub fn with_sink(sink: S) -> Self {
        Self {
            sink,
            observations: Some(AtomicUsize::new(0)),
        }
    }

    fn emit(&self, name: &'static str, labels: &[(&'static str, &str)], value: &Value) {
        let labels: Map<String, Value> = labels
            .iter()
            .map(|(key, value)| ((*key).to_owned(), Value::from(*value)))
            .collect();
        self.sink.write(
            Channel::Log,
            &json!({"metric": name, "labels": labels, "value": value}).to_string(),
        );
    }
}

impl<S: LineSink> Metrics for ConsoleMetrics<S> {
    fn incr(&self, name: &'static str, labels: &[(&'static str, &str)], by: u64) {
        self.emit(name, labels, &Value::from(by));
    }

    fn observe_ms(&self, name: &'static str, labels: &[(&'static str, &str)], ms: f64) {
        let observations = self.observations.as_ref().unwrap_or(&ISOLATE_OBSERVATIONS);
        // Keep the counter bounded so wraparound cannot change the cadence.
        let previous = observations
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(if n == 99 { 0 } else { n + 1 })
            })
            .unwrap_or_else(|n| n);
        // Emit on calls 1, 101, 201, ... so short-lived isolates still report.
        if previous == 0 {
            self.emit(name, labels, &Value::from(ms));
        }
    }

    fn gauge(&self, name: &'static str, labels: &[(&'static str, &str)], value: f64) {
        self.emit(name, labels, &Value::from(value));
    }
}

#[cfg(any(target_arch = "wasm32", test))]
mod events {
    use tracing::field::{Field, Visit};
    use tracing::{Event, Level, Metadata, Subscriber};
    use tracing_subscriber::layer::Context;
    use tracing_subscriber::{Layer, Registry, prelude::*};

    use super::{Channel, LineSink, Map, Value};

    #[derive(Debug)]
    struct ConsoleLayer<S>(S);

    impl<S: LineSink + 'static, T: Subscriber> Layer<T> for ConsoleLayer<S> {
        fn enabled(&self, metadata: &Metadata<'_>, _context: Context<'_, T>) -> bool {
            *metadata.level() <= Level::INFO
        }

        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::INFO)
        }

        fn on_event(&self, event: &Event<'_>, _context: Context<'_, T>) {
            let metadata = event.metadata();
            let mut fields = Fields(Map::new());
            fields.0.insert(
                "level".into(),
                Value::from(metadata.level().as_str().to_ascii_lowercase()),
            );
            fields
                .0
                .insert("target".into(), Value::from(metadata.target()));
            event.record(&mut fields);
            let channel = if *metadata.level() <= Level::WARN {
                Channel::Error
            } else {
                Channel::Log
            };
            self.0.write(channel, &Value::Object(fields.0).to_string());
        }
    }

    struct Fields(Map<String, Value>);

    impl Visit for Fields {
        fn record_u64(&mut self, field: &Field, value: u64) {
            self.0.insert(field.name().into(), value.into());
        }

        fn record_i64(&mut self, field: &Field, value: i64) {
            self.0.insert(field.name().into(), value.into());
        }

        fn record_f64(&mut self, field: &Field, value: f64) {
            self.0.insert(field.name().into(), value.into());
        }

        fn record_bool(&mut self, field: &Field, value: bool) {
            self.0.insert(field.name().into(), value.into());
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().into(), value.into());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn core::fmt::Debug) {
            self.0
                .insert(field.name().into(), format!("{value:?}").into());
        }
    }

    pub(super) fn subscriber(sink: impl LineSink + 'static) -> impl Subscriber {
        Registry::default().with(ConsoleLayer(sink))
    }
}

/// Install the informational-and-above console subscriber once per isolate.
#[cfg(target_arch = "wasm32")]
pub fn install() {
    thread_local! {
        static INSTALLED: std::cell::OnceCell<()> = const { std::cell::OnceCell::new() };
    }
    INSTALLED.with(|installed| {
        installed.get_or_init(|| {
            if let Err(error) = tracing::subscriber::set_global_default(events::subscriber(ConsoleSink)) {
                ConsoleSink.write(
                    Channel::Error,
                    &json!({"event": "telemetry_install_failed", "level": "error", "message": error.to_string()}).to_string(),
                );
            }
        });
    });
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct Capture(Arc<Mutex<Vec<(Channel, Value)>>>);

    impl LineSink for Capture {
        fn write(&self, channel: Channel, line: &str) {
            self.0
                .lock()
                .unwrap()
                .push((channel, serde_json::from_str(line).unwrap()));
        }
    }

    #[test]
    fn metrics_preserve_counter_values_and_labels_and_never_sample_gauges() {
        let sink = Capture::default();
        let metrics = ConsoleMetrics::with_sink(sink.clone());
        metrics.incr("counter", &[("kind", "namespace")], u64::MAX);
        metrics.gauge("bytes", &[("kind", "ref")], 90.5);
        let lines = sink.0.lock().unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            (
                Channel::Log,
                json!({"metric":"counter", "labels":{"kind":"namespace"}, "value":u64::MAX})
            )
        );
        assert_eq!(
            lines[1],
            (
                Channel::Log,
                json!({"metric":"bytes", "labels":{"kind":"ref"}, "value":90.5})
            )
        );
    }

    #[test]
    fn observations_emit_exactly_every_hundredth_call() {
        let sink = Capture::default();
        let metrics = ConsoleMetrics::with_sink(sink.clone());
        for observation in 1..=299 {
            metrics.observe_ms(
                "latency",
                &[("procedure", "UpdateRef")],
                f64::from(observation),
            );
        }
        let lines = sink.0.lock().unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines[0].1,
            json!({"metric":"latency", "labels":{"procedure":"UpdateRef"}, "value":1.0})
        );
        assert_eq!(lines[1].1["value"], 101.0);
        assert_eq!(lines[2].1["value"], 201.0);
    }

    #[test]
    fn default_sampler_survives_new_request_sinks() {
        let sink = Capture::default();
        for observation in 1..=100 {
            let defaults = ConsoleMetrics::default();
            let metrics = ConsoleMetrics {
                sink: sink.clone(),
                observations: defaults.observations,
            };
            metrics.observe_ms("latency", &[], f64::from(observation));
        }
        assert_eq!(sink.0.lock().unwrap().len(), 1);
    }

    #[test]
    fn subscriber_routes_levels_and_preserves_typed_fields() {
        let sink = Capture::default();
        tracing::subscriber::with_default(events::subscriber(sink.clone()), || {
            tracing::trace!("discard trace");
            tracing::debug!("discard debug");
            let outer = tracing::info_span!("outer");
            let inner = tracing::info_span!("inner");
            assert_ne!(outer.id(), inner.id());
            let _entered = outer.enter();
            tracing::info!(
                count = u64::MAX,
                signed = -3_i64,
                pct = 70.5_f64,
                ready = true,
                kind = "ref",
                "typed event"
            );
            tracing::warn!(event = "storage_pressure", "warn event");
            tracing::error!("error event");
        });
        let lines = sink.0.lock().unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].0, Channel::Log);
        assert_eq!(lines[0].1["level"], "info");
        assert_eq!(lines[0].1["count"], u64::MAX);
        assert_eq!(lines[0].1["signed"], -3);
        assert_eq!(lines[0].1["pct"], 70.5);
        assert_eq!(lines[0].1["ready"], true);
        assert_eq!(lines[0].1["kind"], "ref");
        assert_eq!(lines[0].1["message"], "typed event");
        assert_eq!(lines[1].0, Channel::Error);
        assert_eq!(lines[1].1["level"], "warn");
        assert_eq!(lines[1].1["event"], "storage_pressure");
        assert_eq!(lines[2].0, Channel::Error);
        assert_eq!(lines[2].1["level"], "error");
    }

    #[test]
    fn physical_alarm_logs_timestamp_and_dispatched_source() {
        use mkit_server::store::adapter_spi::keys;
        use mkit_server::{Batch, ManualClock, NamespaceKey, NamespaceStore, Partition, Value};
        use std::sync::Arc;
        let clock = Arc::new(ManualClock::new(1_000));
        let source = Partition::Namespace(NamespaceKey::deployment_default());
        let store = crate::ns_object::PressureStore::new(
            crate::sql::SqlKvStore::open(
                crate::test_sqlite::RusqliteConn::open_in_memory()
                    .unwrap()
                    .with_clock(clock.clone()),
            )
            .unwrap(),
            crate::classes::ShardClass::RefShard,
            clock.clone(),
            Arc::new(mkit_server::NoopMetrics),
        );
        futures::executor::block_on(store.apply(
            &source,
            Batch::new().put(keys::timer(1_000, 240, b"alarm"), Value::default()),
        ))
        .unwrap();
        let sink = Capture::default();
        tracing::subscriber::with_default(events::subscriber(sink.clone()), || {
            crate::alarm::observe_alarm(1_000);
            futures::executor::block_on(crate::alarm::run_physical_alarm(
                &store,
                &mkit_server::timers::TimerRegistry::new(),
                clock.as_ref(),
                1_000,
                mkit_server::timers::TickBudget::default(),
                &mut None,
            ))
            .unwrap();
        });
        let lines = sink.0.lock().unwrap();
        let entry = lines
            .iter()
            .position(|(_, event)| event["event"] == "verification_physical_alarm")
            .unwrap();
        let dispatch = lines
            .iter()
            .position(|(_, event)| event["event"] == "verification_alarm_partition")
            .unwrap();
        assert!(entry < dispatch);
        assert_eq!(lines[entry].1["now_ms"], 1_000);
        assert_eq!(lines[dispatch].1["now_ms"], 1_000);
        assert_eq!(lines[dispatch].1["source"], format!("{source:?}"));
    }

    #[test]
    fn pressure_alerts_preserve_console_output_across_module_moves() {
        let sink = Capture::default();
        tracing::subscriber::with_default(events::subscriber(sink.clone()), || {
            pressure::emit(pressure::PressureLevel::Warn, "ref", 70, 100);
            pressure::emit(pressure::PressureLevel::Critical, "ref", 90, 100);
        });
        let lines = sink.0.lock().unwrap();
        assert_eq!(lines.len(), 2);
        for ((channel, event), (level, bytes, pct)) in lines
            .iter()
            .zip([("warn", 70_u64, 70.0_f64), ("critical", 90_u64, 90.0_f64)])
        {
            assert_eq!(*channel, Channel::Error);
            assert_eq!(
                *event,
                json!({
                    "target": "mkit_server::telemetry::pressure",
                    "event": "storage_pressure",
                    "level": level,
                    "kind": "ref",
                    "bytes": bytes,
                    "limit_bytes": 100,
                    "pct": pct,
                })
            );
        }
    }
}
