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

/// Optional scalar alarm and verification-slice context for adapters.
#[cfg(feature = "perf-metrics")]
pub mod slice_context;

use crate::rt::{MaybeSend, MaybeSync};

/// Counter: requests handled. Labels: `procedure`, `code`.
pub const METRIC_REQUESTS: &str = "mkit_server_requests_total";
/// Histogram: request latency in milliseconds. Labels: `procedure`.
pub const METRIC_LATENCY: &str = "mkit_server_request_duration_ms";
/// Counter: synchronous inspector calls. Label: `result`.
pub const METRIC_INSPECTION_CALLS: &str = "mkit_server_inspection_calls_total";
/// Counter: accepted upload bytes.
pub const METRIC_UPLOAD_BYTES: &str = "mkit_server_upload_bytes_total";
/// Counter: an expired shard lease remains kept beyond the relay lag bound.
pub const METRIC_RELAY_LEASE_LAG: &str = "mkit_server_relay_lease_lag_total";
/// Counter: an outbox row exceeded the relay lag bound. Label: `source_kind`.
pub const METRIC_RELAY_LAG_EXCEEDED: &str = "mkit_server_relay_lag_exceeded_total";
/// Counter: a relay delivery to a coordinator failed because the repository's
/// stored-bytes counter is missing (a corrupt store; its rows stay queued).
pub const METRIC_RELAY_STORAGE_COUNTER_MISSING: &str =
    "mkit_server_relay_storage_counter_missing_total";
/// Gauge: source outbox rows inspected in the current relay window.
pub const METRIC_RELAY_BACKLOG_ROWS: &str = "mkit_server_relay_backlog_rows";
/// Gauge: subrequests the last scheduled-verification slice spent (WP-4.8).
pub const METRIC_INDEX_SLICE_SUBREQUESTS: &str = "mkit_server_index_slice_subrequests";
/// Counter: verification inventory attempts. Label: `result`.
pub const METRIC_INDEX_INVENTORY_ATTEMPTS: &str = "mkit_server_index_inventory_attempts_total";
/// Gauge: completed staging calls and durable Decode entries per attempt.
/// Labels: `result`, `progress` (`staged` or `checkpointed`).
pub const METRIC_INDEX_INVENTORY_ENTRIES: &str = "mkit_server_index_inventory_entries";
/// Counter: an object index lookup hit a bounded-work cap. Label: `reason`.
pub const METRIC_INDEX_LOOKUP_CAPPED: &str = "mkit_server_index_lookup_capped_total";
/// Counter: a foreground checkpoint committed a new publication limit-reached
/// stop. Label: `reason` (`index_calls` or `retained_items`); input limits excluded.
pub const METRIC_PUBLICATION_LIMIT_REACHED: &str = "mkit_server_publication_limit_reached_total";
/// Counter: a fast-forward check ended unproven (a walk or lookup cap, the
/// decode budget or a corrupt member) and its write was denied. Label: `reason`.
pub const METRIC_REF_POLICY_ANCESTRY_UNCHECKED: &str =
    "mkit_server_ref_policy_ancestry_unchecked_total";
/// Counter: a content rejection could not be persisted in verification state.
pub const METRIC_INDEX_REJECTED_WRITE_FAILED: &str =
    "mkit_server_index_rejected_write_failed_total";
/// Namespace quota writes admitted with no recent coordinator view.
pub const METRIC_NAMESPACE_QUOTA_VIEW_FALLBACK: &str =
    "mkit_server_namespace_quota_view_fallback_total";
/// Counter: a restored shard's cumulative contribution was re-baselined.
pub const METRIC_NAMESPACE_QUOTA_REBASE: &str = "mkit_server_namespace_quota_rebase_total";
/// Counter: a quota rollup failed. Label: `reason`.
pub const METRIC_NAMESPACE_QUOTA_ROLLUP_ERROR: &str =
    "mkit_server_namespace_quota_rollup_error_total";

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
    /// Add deployment-defined credential names to the redaction set.
    pub fn add_names(&mut self, names: &[String]) {
        self.extra.extend(names.iter().cloned());
    }
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
    /// Set a gauge. Sinks without gauge support may discard it.
    fn gauge(&self, _name: &'static str, _labels: &[(&'static str, &str)], _value: f64) {}
}

/// A [`Metrics`] sink that discards everything.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopMetrics;

impl Metrics for NoopMetrics {
    fn incr(&self, _name: &'static str, _labels: &[(&'static str, &str)], _by: u64) {}
    fn observe_ms(&self, _name: &'static str, _labels: &[(&'static str, &str)], _ms: f64) {}
}

/// Counter for commit verification timeline observations. Label: `stage`.
pub const METRIC_VERIFICATION_PROGRESS: &str = "mkit_server_verification_progress_total";

/// Counter for failed or raced verification timer fires. Labels: `outcome`, `class`.
pub const METRIC_VERIFICATION_TIMER_FAILURES: &str =
    "mkit_server_verification_timer_failures_total";

/// IDs belong in logs, never metric labels. Repeated observations are intentional.
pub(crate) fn verification_progress(
    metrics: &dyn Metrics,
    stage: &'static str,
    now_ms: u64,
    ticket: Option<&mkit_core::hash::Hash>,
    pack: Option<&mkit_core::hash::Hash>,
) {
    metrics.incr(METRIC_VERIFICATION_PROGRESS, &[("stage", stage)], 1);
    tracing::info!(
        event = "verification_progress",
        stage,
        now_ms,
        ticket = ticket.map(mkit_core::hash::to_hex).as_deref(),
        pack = pack.map(mkit_core::hash::to_hex).as_deref(),
    );
}

/// Bounded performance observations, enabled explicitly at build time.
#[cfg(feature = "perf-metrics")]
pub(crate) mod performance {
    use super::Metrics;

    const BOUNDS: [u64; 8] = [0, 1, 10, 50, 100, 250, 500, 1_000];

    /// Disjoint duration buckets. Space is constant regardless of object count.
    #[derive(Default)]
    pub(crate) struct Denials {
        buckets: [u64; 9],
    }

    impl Denials {
        pub(crate) fn record(&mut self, ms: u64) {
            let bucket = BOUNDS.iter().position(|bound| ms <= *bound).unwrap_or(8);
            self.buckets[bucket] = self.buckets[bucket].saturating_add(1);
        }

        pub(crate) fn emit(&mut self, metrics: &dyn Metrics, stage: &'static str) {
            let calls = self.buckets.iter().copied().sum();
            if calls == 0 {
                return;
            }
            metrics.incr(
                "mkit_server_verification_denial_calls_total",
                &[("stage", stage)],
                calls,
            );
            tracing::info!(
                event = "verification_denial_histogram",
                stage,
                calls,
                ms_0 = self.buckets[0],
                ms_1 = self.buckets[1],
                ms_10 = self.buckets[2],
                ms_50 = self.buckets[3],
                ms_100 = self.buckets[4],
                ms_250 = self.buckets[5],
                ms_500 = self.buckets[6],
                ms_1000 = self.buckets[7],
                ms_inf = self.buckets[8]
            );
            self.buckets = [0; 9];
        }
    }

    pub(crate) struct DenialAccumulator<'a> {
        pub(crate) counts: Denials,
        target: &'a std::sync::Mutex<Denials>,
    }
    impl<'a> DenialAccumulator<'a> {
        pub(crate) fn new(target: &'a std::sync::Mutex<Denials>) -> Self {
            Self {
                counts: Denials::default(),
                target,
            }
        }
    }
    impl Drop for DenialAccumulator<'_> {
        fn drop(&mut self) {
            if let Ok(mut total) = self.target.lock() {
                for (target, count) in total.buckets.iter_mut().zip(self.counts.buckets) {
                    *target = target.saturating_add(count);
                }
            }
        }
    }

    /// Clock elapsed time includes waits; it is never a CPU measurement.
    pub(crate) fn elapsed(clock: &dyn crate::Clock, started: i64) -> u64 {
        u64::try_from(clock.now_ms().saturating_sub(started)).unwrap_or(0)
    }

    pub(crate) fn duration(
        metrics: &dyn Metrics,
        stage: &'static str,
        component: &'static str,
        ms: u64,
    ) {
        metrics.observe_ms(
            "mkit_server_verification_stage_duration_ms",
            &[("stage", stage), ("component", component)],
            f64::from(u32::try_from(ms).unwrap_or(u32::MAX)),
        );
        if component == "total" {
            tracing::info!(
                event = "verification_stage_duration",
                stage,
                component,
                duration_ms = ms
            );
        }
    }

    /// One fixed-size summary for every `EmitIndex` invocation, including errors.
    pub(crate) struct EmitComponents<'a> {
        clock: &'a dyn crate::Clock,
        metrics: &'a dyn Metrics,
        ms: [u64; 6],
    }
    impl<'a> EmitComponents<'a> {
        pub(crate) fn new(clock: &'a dyn crate::Clock, metrics: &'a dyn Metrics) -> Self {
            Self {
                clock,
                metrics,
                ms: [0; 6],
            }
        }
        pub(crate) fn timer(&mut self, index: usize) -> ComponentTimer<'_> {
            ComponentTimer {
                clock: self.clock,
                started: self.clock.now_ms(),
                total: &mut self.ms[index],
            }
        }
    }
    impl Drop for EmitComponents<'_> {
        fn drop(&mut self) {
            tracing::info!(
                event = "verification_emit_components",
                scan_ms = self.ms[0],
                plan_ms = self.ms[1],
                denial_ms = self.ms[2],
                direct_apply_ms = self.ms[3],
                relay_commit_ms = self.ms[4],
                outbox_read_ms = self.ms[5]
            );
            for (component, ms) in [
                "scan",
                "plan",
                "denial",
                "direct_apply",
                "relay_commit",
                "outbox_read",
            ]
            .into_iter()
            .zip(self.ms)
            {
                duration(self.metrics, "emit_index", component, ms);
            }
        }
    }
    pub(crate) struct ComponentTimer<'a> {
        clock: &'a dyn crate::Clock,
        started: i64,
        total: &'a mut u64,
    }
    impl Drop for ComponentTimer<'_> {
        fn drop(&mut self) {
            *self.total = self.total.saturating_add(elapsed(self.clock, self.started));
        }
    }

    pub(crate) struct Timer<'a> {
        clock: &'a dyn crate::Clock,
        metrics: &'a dyn Metrics,
        stage: &'static str,
        component: &'static str,
        started: i64,
    }
    impl<'a> Timer<'a> {
        pub(crate) fn new(
            clock: &'a dyn crate::Clock,
            metrics: &'a dyn Metrics,
            stage: &'static str,
            component: &'static str,
        ) -> Self {
            Self {
                clock,
                metrics,
                stage,
                component,
                started: clock.now_ms(),
            }
        }
    }
    impl Drop for Timer<'_> {
        fn drop(&mut self) {
            duration(
                self.metrics,
                self.stage,
                self.component,
                elapsed(self.clock, self.started),
            );
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Mutex;

        type CounterRow = (&'static str, Vec<(String, String)>, u64);
        #[derive(Default)]
        struct Capture(Mutex<Vec<CounterRow>>);
        impl Metrics for Capture {
            fn incr(&self, name: &'static str, labels: &[(&'static str, &str)], by: u64) {
                self.0.lock().expect("fixture").push((
                    name,
                    labels
                        .iter()
                        .map(|(k, v)| ((*k).into(), (*v).into()))
                        .collect(),
                    by,
                ));
            }
            fn observe_ms(&self, _: &'static str, _: &[(&'static str, &str)], _: f64) {}
        }

        #[test]
        fn component_totals_include_failed_stage_and_repeated_calls() {
            #[derive(Default)]
            struct Durations(Mutex<Vec<f64>>);
            impl Metrics for Durations {
                fn incr(&self, _: &'static str, _: &[(&'static str, &str)], _: u64) {}
                fn observe_ms(&self, _: &'static str, _: &[(&'static str, &str)], ms: f64) {
                    self.0.lock().expect("fixture").push(ms);
                }
            }
            fn failed_stage(clock: &crate::ManualClock, metrics: &Durations) -> Result<(), ()> {
                let mut summary = EmitComponents::new(clock, metrics);
                {
                    let _timer = summary.timer(2);
                    clock.advance(12);
                }
                {
                    let _timer = summary.timer(2);
                    clock.advance(7);
                }
                Err(())
            }
            let clock = crate::ManualClock::new(0);
            let metrics = Durations::default();
            assert_eq!(failed_stage(&clock, &metrics), Err(()));
            assert_eq!(
                *metrics.0.lock().expect("fixture"),
                vec![0.0, 0.0, 19.0, 0.0, 0.0, 0.0]
            );
        }

        #[test]
        fn duration_buckets_are_disjoint_and_include_overflow() {
            let mut histogram = Denials::default();
            for ms in [0, 1, 10, 50, 100, 250, 500, 1_000, u64::MAX] {
                histogram.record(ms);
            }
            assert_eq!(histogram.buckets, [1; 9]);
        }

        #[test]
        fn denial_histograms_have_constant_volume_and_identifier_free_fields() {
            let metrics = Capture::default();
            let mut counts = Denials::default();
            for _ in 0..10_000 {
                counts.record(55);
            }
            counts.emit(&metrics, "decode");
            counts.emit(&metrics, "decode");
            let rows = metrics.0.lock().expect("fixture");
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].2, 10_000);
            for (_, labels, _) in rows.iter() {
                assert!(
                    labels
                        .iter()
                        .all(|(key, value)| matches!(key.as_str(), "stage")
                            && matches!(value.as_str(), "decode"))
                );
            }
        }
    }
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
