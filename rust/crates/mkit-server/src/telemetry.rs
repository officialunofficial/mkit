//! Metrics facade and logging hygiene (PRD §8 M0: tracing, metrics,
//! redaction).
//!
//! [`Metrics`] is a plain trait rather than a dependency on the `metrics`
//! crate, so the core stays backend-free on wasm32; the native binary
//! bridges it to the `metrics` facade (planner default Q20).
//!
//! Two header lists govern credentials (SPEC-TRANSPORT-CONNECT §5.1):
//! [`NEVER_ECHO`] names request credentials a response never carries, and
//! [`NEVER_LOG`] adds the receipts and signatures that a response may pass
//! through to the client but that must stay out of logs, traces and error
//! messages. [`Redactor`] extends [`NEVER_LOG`] with deployment-configured
//! names, such as the headers an admission helper attaches.

use crate::rt::{MaybeSend, MaybeSync};

/// Counter: requests handled. Labels: `procedure`, `code`.
pub const METRIC_REQUESTS: &str = "mkit_server_requests_total";
/// Histogram: request latency in milliseconds. Labels: `procedure`.
pub const METRIC_LATENCY: &str = "mkit_server_request_duration_ms";
/// Counter: accepted upload bytes.
pub const METRIC_UPLOAD_BYTES: &str = "mkit_server_upload_bytes_total";

/// Request credentials that are never set on a response, compared ignoring
/// ASCII case. Every entry is also in [`NEVER_LOG`].
pub const NEVER_ECHO: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "payment-authorization",
    "payment-signature",
];

/// Header names whose values never reach a log, trace or error message,
/// compared ignoring ASCII case: [`NEVER_ECHO`] plus payment receipts, the
/// auth v2 signature and `Set-Cookie`. A response may still carry the
/// receipts (SPEC-TRANSPORT-CONNECT §5.1).
pub const NEVER_LOG: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "payment-authorization",
    "payment-signature",
    "payment-receipt",
    "payment-response",
    "x-signature",
    "set-cookie",
];

/// Whether `name` is in [`NEVER_ECHO`], ignoring ASCII case.
#[must_use]
pub fn is_never_echo(name: &str) -> bool {
    NEVER_ECHO.iter().any(|n| n.eq_ignore_ascii_case(name))
}

/// Whether `name` is in [`NEVER_LOG`], ignoring ASCII case.
#[must_use]
pub fn is_never_log(name: &str) -> bool {
    NEVER_LOG.iter().any(|n| n.eq_ignore_ascii_case(name))
}

/// The placeholder logged in place of a redacted header value.
pub const REDACTED_VALUE: &str = "[redacted]";

/// Log redaction policy: [`NEVER_LOG`] plus names the deployment adds, for
/// example its configured `admission_headers`. The default redacts
/// [`NEVER_LOG`] only.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    extra: Vec<String>,
}

impl Redactor {
    /// A redactor for [`NEVER_LOG`] plus `extra` header names.
    #[must_use]
    pub fn new<I, S>(extra: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            extra: extra.into_iter().map(Into::into).collect(),
        }
    }

    /// Whether the value of header `name` must be redacted, ignoring ASCII
    /// case.
    #[must_use]
    pub fn redacts(&self, name: &str) -> bool {
        is_never_log(name) || self.extra.iter().any(|n| n.eq_ignore_ascii_case(name))
    }

    /// The value to log for header `name`: `value` itself, or
    /// [`REDACTED_VALUE`].
    #[must_use]
    pub fn loggable<'a>(&self, name: &str, value: &'a str) -> &'a str {
        if self.redacts(name) {
            REDACTED_VALUE
        } else {
            value
        }
    }
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
        for name in NEVER_ECHO {
            assert!(is_never_echo(name), "{name}");
            assert!(is_never_echo(&name.to_ascii_uppercase()), "{name}");
            assert!(NEVER_LOG.contains(name), "{name} must also be NEVER_LOG");
        }
        for name in NEVER_LOG {
            assert!(is_never_log(name), "{name}");
            assert!(is_never_log(&name.to_ascii_uppercase()), "{name}");
        }
        assert!(is_never_echo("Authorization"));
        assert!(is_never_echo("PAYMENT-SIGNATURE"));
        // Receipts pass through to the client but never reach a log.
        for receipt in ["Payment-Receipt", "PAYMENT-RESPONSE"] {
            assert!(!is_never_echo(receipt), "{receipt}");
            assert!(is_never_log(receipt), "{receipt}");
        }
        assert!(is_never_log("X-Signature") && is_never_log("Set-Cookie"));
        assert!(!is_never_log("WWW-Authenticate"));
        assert!(!is_never_log("authorization-hint"));
        assert!(!is_never_echo(""));
    }

    #[test]
    fn redactor_extends_never_log() {
        let base = Redactor::default();
        assert!(base.redacts("payment-receipt"));
        assert!(!base.redacts("X-Admission-Token"));
        assert_eq!(base.loggable("WWW-Authenticate", "Payment x"), "Payment x");

        let configured = Redactor::new(["x-admission-token"]);
        assert!(configured.redacts("X-Admission-Token"));
        assert!(configured.redacts("Cookie"));
        assert_eq!(
            configured.loggable("X-ADMISSION-TOKEN", "s3cr3t"),
            REDACTED_VALUE
        );
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
