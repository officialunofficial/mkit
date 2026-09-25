//! Metrics facade and logging hygiene (PRD §8 M0: tracing, metrics,
//! redaction).
//!
//! [`Metrics`] is a plain trait rather than a dependency on the `metrics`
//! crate, so the core stays backend-free on wasm32; the native binary
//! bridges it to the `metrics` facade (planner default Q20).

use crate::rt::{MaybeSend, MaybeSync};

/// Counter: requests handled. Labels: `procedure`, `code`.
pub const METRIC_REQUESTS: &str = "mkit_server_requests_total";
/// Histogram: request latency in milliseconds. Labels: `procedure`.
pub const METRIC_LATENCY: &str = "mkit_server_request_duration_ms";
/// Counter: accepted upload bytes.
pub const METRIC_UPLOAD_BYTES: &str = "mkit_server_upload_bytes_total";

/// Header names whose values are credentials and must never be logged or
/// echoed back in a response. Compare with [`is_sensitive_header`], which
/// ignores ASCII case.
pub const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "proxy-authorization",
    "payment-authorization",
    "payment-signature",
    "payment-receipt",
    "payment-response",
];

/// Whether `name` is one of [`SENSITIVE_HEADERS`], ignoring ASCII case.
#[must_use]
pub fn is_sensitive_header(name: &str) -> bool {
    SENSITIVE_HEADERS
        .iter()
        .any(|sensitive| sensitive.eq_ignore_ascii_case(name))
}

/// Metrics sink. Label values are borrowed so a hot path allocates nothing.
pub trait Metrics: MaybeSend + MaybeSync {
    /// Add `by` to the counter `name`.
    fn incr(&self, name: &'static str, labels: &[(&'static str, &str)], by: u64);
    /// Record one observation, in milliseconds, in the histogram `name`.
    fn observe_ms(&self, name: &'static str, labels: &[(&'static str, &str)], ms: f64);
}

/// A [`Metrics`] sink that discards everything.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopMetrics;

impl Metrics for NoopMetrics {
    fn incr(&self, _name: &'static str, _labels: &[(&'static str, &str)], _by: u64) {}
    fn observe_ms(&self, _name: &'static str, _labels: &[(&'static str, &str)], _ms: f64) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_headers_case_insensitive() {
        for name in SENSITIVE_HEADERS {
            assert!(is_sensitive_header(name), "{name}");
            assert!(is_sensitive_header(&name.to_ascii_uppercase()), "{name}");
        }
        assert!(is_sensitive_header("Authorization"));
        assert!(is_sensitive_header("Payment-Signature"));
        assert!(!is_sensitive_header("WWW-Authenticate"));
        assert!(!is_sensitive_header("authorization-hint"));
        assert!(!is_sensitive_header(""));
    }

    #[test]
    fn noop_metrics_is_object_safe() {
        let sink: &dyn Metrics = &NoopMetrics;
        sink.incr(
            METRIC_REQUESTS,
            &[("procedure", "UpdateRef"), ("code", "ok")],
            1,
        );
        sink.observe_ms(METRIC_LATENCY, &[("procedure", "UpdateRef")], 1.5);
    }
}
