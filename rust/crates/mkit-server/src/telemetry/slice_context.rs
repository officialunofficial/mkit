//! Optional scalar context for one alarm and one verification slice.
//!
//! Context is installed only while polling a future. It never follows an
//! unrelated task across an await, and contains no request or storage bytes.
use std::cell::RefCell;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

/// Runtime-provided alarm facts. Unknown facts remain absent.
#[derive(Clone, Debug, Default)]
pub struct AlarmMetadata {
    /// Last timestamp armed by the live instance; not necessarily this callback.
    pub alarm_last_armed_ms: Option<u64>,
    /// Physical alarm timestamp confirmed for this non-retry callback.
    pub alarm_scheduled_ms: Option<u64>,
    /// Physical alarm callback entry time.
    pub alarm_fired_ms: Option<u64>,
    /// Retry count reported by the runtime, without interpreting its cause.
    pub runtime_retry_count: Option<u32>,
    /// Whether the runtime reports this callback as a retry.
    pub runtime_is_retry: Option<bool>,
}

/// An adapter-owned alarm scope and its instance's first-slice marker.
#[derive(Clone, Debug)]
pub struct AlarmContext {
    metadata: AlarmMetadata,
    first_slice: Arc<AtomicBool>,
}

impl AlarmContext {
    /// Use a marker initialized to `true` when the adapter instance is constructed.
    #[must_use]
    pub fn new(metadata: AlarmMetadata, first_slice: Arc<AtomicBool>) -> Self {
        Self {
            metadata,
            first_slice,
        }
    }

    /// Poll an alarm with these facts; creating the scope consumes no cold marker.
    pub fn scope<F: Future>(&self, future: F) -> impl Future<Output = F::Output> + use<F> {
        let context = Context {
            alarm: Some(self.clone()),
            ..Context::default()
        };
        scope(context, future)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TimerMetadata {
    pub(crate) scheduled_ms: u64,
    pub(crate) logical_due_ms: u64,
    pub(crate) retry_attempt: u8,
}

#[derive(Clone, Default)]
struct Context {
    alarm: Option<AlarmContext>,
    timer: Option<TimerMetadata>,
    slice: Option<RpcObservation>,
}

thread_local! {
    static ACTIVE: RefCell<Context> = const { RefCell::new(Context { alarm: None, timer: None, slice: None }) };
}

struct PollScope(Context);
impl PollScope {
    fn enter(context: &Context) -> Self {
        Self(ACTIVE.with(|active| active.replace(context.clone())))
    }
}
impl Drop for PollScope {
    fn drop(&mut self) {
        ACTIVE.with(|active| {
            active.replace(std::mem::take(&mut self.0));
        });
    }
}

fn scope<F: Future>(context: Context, future: F) -> impl Future<Output = F::Output> + use<F> {
    // Box immediately: an async forwarding wrapper would retain the entire
    // input future in its unpolled state and enlarge every enclosing future.
    let mut future = Box::pin(future);
    futures::future::poll_fn(move |cx| {
        let _installed = PollScope::enter(&context);
        future.as_mut().poll(cx)
    })
}

pub(crate) fn timer_scope<F: Future>(
    metadata: TimerMetadata,
    future: F,
) -> impl Future<Output = F::Output> + use<F> {
    let mut context = ACTIVE.with(|active| active.borrow().clone());
    context.timer = Some(metadata);
    context.slice = None;
    scope(context, future)
}

#[derive(Clone, Copy, Debug)]
struct SlowestRpc {
    prefix: &'static str,
    ms: f64,
}

#[derive(Default, Debug)]
struct SliceData {
    slowest: Option<SlowestRpc>,
    phase_stop: Option<&'static str>,
    chain_stop: Option<&'static str>,
    chunk_stop: Option<&'static str>,
}

/// A captured slice handle. It remains associated with its originating call
/// when a transport future completes or is cancelled outside an active poll.
#[derive(Clone, Debug)]
pub struct RpcObservation(Arc<Mutex<SliceData>>);

impl RpcObservation {
    /// Capture the slice that owns a newly started transport call, if any.
    #[must_use]
    pub fn current() -> Option<Self> {
        ACTIVE.with(|active| active.borrow().slice.clone())
    }

    /// Record a duration without retaining a target identity, key or payload.
    /// Unknown prefixes become `other`; invalid durations are discarded.
    pub fn record_rpc(&self, prefix: &'static str, duration_ms: f64) {
        if !duration_ms.is_finite() || duration_ms < 0.0 {
            return;
        }
        let prefix = match prefix {
            "ri:" | "x:" | "ci:" | "r:" | "c:" | "n:" => prefix,
            _ => "other",
        };
        let mut data = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if data.slowest.is_none_or(|old| duration_ms > old.ms) {
            data.slowest = Some(SlowestRpc {
                prefix,
                ms: duration_ms,
            });
        }
    }
}

pub(crate) struct SliceScope {
    context: Context,
    started_ms: u64,
    cold: Option<bool>,
    observation: RpcObservation,
}

impl SliceScope {
    pub(crate) fn new(started_ms: u64) -> Self {
        let mut context = ACTIVE.with(|active| active.borrow().clone());
        let cold = context
            .alarm
            .as_ref()
            .map(|alarm| alarm.first_slice.swap(false, Ordering::Relaxed));
        let observation = RpcObservation(Arc::new(Mutex::new(SliceData::default())));
        context.slice = Some(observation.clone());
        Self {
            context,
            started_ms,
            cold,
            observation,
        }
    }

    pub(crate) fn scope<F: Future>(&self, future: F) -> impl Future<Output = F::Output> + use<F> {
        scope(self.context.clone(), future)
    }

    pub(crate) fn snapshot(&self) -> SliceSnapshot {
        let alarm = self
            .context
            .alarm
            .as_ref()
            .map(|context| context.metadata.clone())
            .unwrap_or_default();
        let timer = self.context.timer;
        let data = self
            .observation
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // The outer selection loop's terminal bound wins over an earlier
        // successful chunk boundary. Effect-stage boundaries may hide the
        // inner chunk walk's actual limiting condition.
        let chunk_reason = data.chunk_stop.map(|reason| match reason {
            "steps" | "calls" | "ops" | "elapsed" | "next_error" => reason,
            _ => "chunk_boundary",
        });
        let stop = match data.chain_stop {
            Some("effect_stage") => chunk_reason.or(data.chain_stop),
            Some(reason) => Some(reason),
            None => chunk_reason.or(data.phase_stop),
        }
        .map(|reason| match reason {
            "steps" => "step_cap",
            "calls" => "call_allowance",
            "elapsed" => "elapsed_cutoff",
            "ops" => "operation_allowance",
            other => other,
        });
        SliceSnapshot {
            alarm_delay_ms: alarm
                .alarm_fired_ms
                .zip(alarm.alarm_scheduled_ms)
                .map(|(fired, due)| fired.saturating_sub(due)),
            alarm,
            timer_scheduled_ms: timer.map(|timer| timer.scheduled_ms),
            logical_due_ms: timer.map(|timer| timer.logical_due_ms),
            timer_retry_attempt: timer.map(|timer| timer.retry_attempt),
            slice_started_ms: self.started_ms,
            timer_delay_ms: timer.map(|timer| self.started_ms.saturating_sub(timer.scheduled_ms)),
            cold_first_slice: self.cold,
            slowest_rpc_prefix: data.slowest.map(|call| call.prefix),
            slowest_rpc_ms: data.slowest.map(|call| call.ms),
            slice_stop_reason: stop,
            extract_chain_stop_reason: data.chain_stop,
            extract_chunk_stop_reason: data.chunk_stop,
        }
    }
}

pub(crate) struct SliceSnapshot {
    pub(crate) alarm: AlarmMetadata,
    pub(crate) alarm_delay_ms: Option<u64>,
    pub(crate) timer_scheduled_ms: Option<u64>,
    pub(crate) logical_due_ms: Option<u64>,
    pub(crate) timer_retry_attempt: Option<u8>,
    pub(crate) slice_started_ms: u64,
    pub(crate) timer_delay_ms: Option<u64>,
    pub(crate) cold_first_slice: Option<bool>,
    pub(crate) slowest_rpc_prefix: Option<&'static str>,
    pub(crate) slowest_rpc_ms: Option<f64>,
    pub(crate) slice_stop_reason: Option<&'static str>,
    pub(crate) extract_chain_stop_reason: Option<&'static str>,
    pub(crate) extract_chunk_stop_reason: Option<&'static str>,
}

pub(crate) fn phase_stop(reason: &'static str) {
    if let Some(scope) = RpcObservation::current() {
        scope
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .phase_stop = Some(reason);
    }
}
pub(crate) fn chain_stop(reason: &'static str) {
    if let Some(scope) = RpcObservation::current() {
        scope
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .chain_stop = Some(reason);
    }
}
pub(crate) fn chunk_stop(reason: &'static str) {
    if let Some(scope) = RpcObservation::current() {
        scope
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .chunk_stop = Some(reason);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::task::Poll;

    #[test]
    fn cold_marker_is_consumed_only_by_a_slice_and_metadata_remains_optional() {
        let first = Arc::new(AtomicBool::new(true));
        let alarm = AlarmContext::new(AlarmMetadata::default(), first.clone());
        futures_executor::block_on(alarm.scope(async {}));
        assert!(first.load(Ordering::Relaxed));
        futures_executor::block_on(alarm.scope(async {
            let first_slice = SliceScope::new(10);
            let next_slice = SliceScope::new(11);
            assert_eq!(first_slice.snapshot().cold_first_slice, Some(true));
            assert_eq!(next_slice.snapshot().cold_first_slice, Some(false));
        }));
        assert_eq!(SliceScope::new(12).snapshot().cold_first_slice, None);
        assert!(RpcObservation::current().is_none());
    }

    async fn interleaved(alarm: AlarmContext, prefix: &'static str, ms: f64) -> SliceSnapshot {
        alarm
            .scope(async {
                let slice = SliceScope::new(130);
                slice
                    .scope(async {
                        let owned = RpcObservation::current().unwrap();
                        let mut yielded = false;
                        futures::future::poll_fn(|cx| {
                            let current = RpcObservation::current().unwrap();
                            assert!(Arc::ptr_eq(&owned.0, &current.0));
                            if yielded {
                                owned.record_rpc(prefix, ms);
                                Poll::Ready(())
                            } else {
                                yielded = true;
                                cx.waker().wake_by_ref();
                                Poll::Pending
                            }
                        })
                        .await;
                    })
                    .await;
                slice.snapshot()
            })
            .await
    }

    #[test]
    fn interleaved_slice_polls_cannot_borrow_another_tasks_context() {
        let alarm = |retry| {
            AlarmContext::new(
                AlarmMetadata {
                    runtime_retry_count: Some(retry),
                    ..AlarmMetadata::default()
                },
                Arc::new(AtomicBool::new(true)),
            )
        };
        let (first, second) = futures_executor::block_on(futures::future::join(
            interleaved(alarm(1), "ci:", 80.0),
            interleaved(alarm(2), "r:", 20.0),
        ));
        assert_eq!(first.slowest_rpc_prefix, Some("ci:"));
        assert_eq!(second.slowest_rpc_prefix, Some("r:"));
        assert_eq!(first.alarm.runtime_retry_count, Some(1));
        assert_eq!(second.alarm.runtime_retry_count, Some(2));
        assert!(RpcObservation::current().is_none());
    }

    #[test]
    fn captured_rpc_ownership_survives_scope_exit_and_retains_no_private_prefix() {
        let slice = SliceScope::new(0);
        let handle =
            futures_executor::block_on(slice.scope(async { RpcObservation::current().unwrap() }));
        assert!(RpcObservation::current().is_none());
        handle.record_rpc("private-object-id-secret-credential", 10.0);
        for invalid in [f64::NAN, f64::INFINITY, -1.0] {
            handle.record_rpc("ci:", invalid);
        }
        assert_eq!(slice.snapshot().slowest_rpc_prefix, Some("other"));
        let stored = format!("{handle:?}");
        for secret in ["private-object", "secret", "credential"] {
            assert!(!stored.contains(secret));
        }
    }

    #[test]
    fn known_physical_alarm_schedule_and_fire_report_the_actual_delay() {
        let alarm = AlarmContext::new(
            AlarmMetadata {
                alarm_scheduled_ms: Some(100),
                alarm_fired_ms: Some(125),
                ..AlarmMetadata::default()
            },
            Arc::new(AtomicBool::new(true)),
        );
        let snapshot =
            futures_executor::block_on(alarm.scope(async { SliceScope::new(130).snapshot() }));
        assert_eq!(snapshot.alarm_delay_ms, Some(25));
        assert_eq!(snapshot.slice_started_ms, 130);
        assert_eq!(snapshot.timer_delay_ms, None);
    }

    #[test]
    fn timer_retry_due_and_actual_slice_start_have_distinct_meanings() {
        let snapshot = futures_executor::block_on(timer_scope(
            TimerMetadata {
                scheduled_ms: 100,
                logical_due_ms: 50,
                retry_attempt: 3,
            },
            async { SliceScope::new(130).snapshot() },
        ));
        assert_eq!(snapshot.timer_scheduled_ms, Some(100));
        assert_eq!(snapshot.logical_due_ms, Some(50));
        assert_eq!(snapshot.timer_retry_attempt, Some(3));
        assert_eq!(snapshot.timer_delay_ms, Some(30));
        assert_eq!(snapshot.alarm_delay_ms, None);
    }

    #[test]
    fn final_chain_limit_wins_over_an_earlier_successful_chunk_boundary() {
        let slice = SliceScope::new(0);
        futures_executor::block_on(slice.scope(async {
            chunk_stop("part_complete");
            chain_stop("calls");
        }));
        let snapshot = slice.snapshot();
        assert_eq!(snapshot.slice_stop_reason, Some("call_allowance"));
        assert_eq!(snapshot.extract_chunk_stop_reason, Some("part_complete"));
        futures_executor::block_on(slice.scope(async {
            chunk_stop("elapsed");
            chain_stop("effect_stage");
        }));
        assert_eq!(slice.snapshot().slice_stop_reason, Some("elapsed_cutoff"));
    }
}
