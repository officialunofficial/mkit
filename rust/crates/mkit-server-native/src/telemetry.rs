//! Logging and metrics for the native server: a `tracing-subscriber` setup
//! and [`MetricsBridge`], which feeds `mkit_server`'s [`Metrics`] into the
//! `metrics` facade. No exporter ships (planner default Q20): an embedder
//! installs its own `metrics` recorder, and without one the calls are
//! no-ops.
//!
//! Credentials never reach a log: the router marks every header the
//! deployment's [`mkit_server::Redactor`] names (`NEVER_LOG` and its
//! extras) as sensitive before the trace layer records it, so a span shows
//! `Sensitive` in place of the value.

use mkit_server::Metrics;
use tracing_subscriber::EnvFilter;

use crate::config::LogFormat;

/// The filter used when `RUST_LOG` is unset.
pub const DEFAULT_FILTER: &str = "info";

/// Install the global subscriber: `format` lines on stderr, filtered by
/// `filter` (an `EnvFilter` directive such as `info,tower_http=debug`).
///
/// # Errors
/// An invalid `filter`, or a subscriber already installed.
pub fn init_tracing(format: LogFormat, filter: &str) -> Result<(), String> {
    let filter = EnvFilter::try_new(filter).map_err(|e| format!("log filter: {e}"))?;
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    match format {
        LogFormat::Text => builder.try_init(),
        LogFormat::Json => builder.json().try_init(),
    }
    .map_err(|e| format!("log setup: {e}"))
}

/// [`Metrics`] over the `metrics` crate's macros: counters and histograms
/// under the names `mkit_server` reports (`mkit_server_requests_total`,
/// ...), labels as given.
#[derive(Debug, Default, Clone, Copy)]
pub struct MetricsBridge;

fn labels(labels: &[(&'static str, &str)]) -> Vec<metrics::Label> {
    labels
        .iter()
        .map(|(k, v)| metrics::Label::new(*k, (*v).to_owned()))
        .collect()
}

impl Metrics for MetricsBridge {
    fn incr(&self, name: &'static str, l: &[(&'static str, &str)], by: u64) {
        metrics::counter!(name, labels(l)).increment(by);
    }

    fn observe_ms(&self, name: &'static str, l: &[(&'static str, &str)], ms: f64) {
        metrics::histogram!(name, labels(l)).record(ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_without_a_recorder_is_a_no_op() {
        let sink: &dyn Metrics = &MetricsBridge;
        sink.incr(mkit_server::METRIC_REQUESTS, &[("procedure", "ReadRef")], 1);
        sink.observe_ms(
            mkit_server::METRIC_LATENCY,
            &[("procedure", "ReadRef")],
            2.0,
        );
    }

    #[test]
    fn rejects_a_bad_filter() {
        assert!(init_tracing(LogFormat::Text, "=[").is_err());
    }
}
