//! One request's outcome: its span, its log line and its request metrics,
//! emitted exactly once. A unary request records when it returns; an upload
//! at `finish` or its first failure; a download when it yields its `last`
//! chunk or first fails. An [`Outcome`] dropped before it
//! recorded (a dropped upload session, a download stream abandoned before
//! its end, a canceled request future) records `canceled`.

use std::sync::Arc;

use crate::error::{Code, ServerError};
use crate::rt::Clock;
use crate::telemetry::{METRIC_LATENCY, METRIC_REQUESTS, Metrics, Redactor};

/// See the module docs.
pub(crate) struct Outcome {
    pub(crate) span: tracing::Span,
    procedure: &'static str,
    start_ms: i64,
    metrics: Arc<dyn Metrics>,
    clock: Arc<dyn Clock>,
    redactor: Redactor,
    done: bool,
}

impl Outcome {
    pub(crate) fn new(
        span: tracing::Span,
        procedure: &'static str,
        metrics: Arc<dyn Metrics>,
        clock: Arc<dyn Clock>,
        redactor: Redactor,
    ) -> Self {
        Self {
            span,
            procedure,
            start_ms: clock.now_ms(),
            metrics,
            clock,
            redactor,
            done: false,
        }
    }

    /// Record `result`, unless this request already recorded.
    pub(crate) fn record(&mut self, result: Result<(), &ServerError>) {
        if core::mem::replace(&mut self.done, true) {
            return;
        }
        let procedure = self.procedure;
        let code = result.err().map_or("ok", |e| e.code().as_str());
        self.span.in_scope(|| match result {
            Ok(()) => tracing::debug!(code, "rpc done"),
            Err(e) => {
                let headers: Vec<_> = e
                    .headers()
                    .iter()
                    .map(|(n, v)| (n.as_str(), self.redactor.loggable(n, v)))
                    .collect();
                tracing::info!(code, message = e.public_message(), ?headers, "rpc failed");
            }
        });
        self.metrics.incr(
            METRIC_REQUESTS,
            &[("procedure", procedure), ("code", code)],
            1,
        );
        let elapsed = self.clock.now_ms().saturating_sub(self.start_ms);
        let elapsed = u32::try_from(elapsed).unwrap_or(u32::MAX);
        self.metrics.observe_ms(
            METRIC_LATENCY,
            &[("procedure", procedure)],
            f64::from(elapsed),
        );
    }
}

impl Drop for Outcome {
    fn drop(&mut self) {
        if !self.done {
            self.record(Err(&ServerError::new(Code::Canceled, "request canceled")));
        }
    }
}
