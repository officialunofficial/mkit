//! Production telemetry payloads and persisted retry timing.
use super::*;
use crate::{BoxFuture, ManualClock, MemoryKv};
use std::sync::{Arc, Mutex};

const PRIVATE: &str = "https://backend.invalid/private-repo?token=secret";
type Fire = fn() -> Result<Fired, StoreError>;
type Labels = Vec<(String, String)>;
#[derive(Default)]
struct Metrics(Mutex<Vec<(&'static str, Labels)>>);
impl crate::Metrics for Metrics {
    fn incr(&self, name: &'static str, labels: &[(&'static str, &str)], by: u64) {
        assert_eq!(by, 1);
        self.0.lock().expect("test fixture").push((
            name,
            labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        ));
    }
    fn observe_ms(&self, _: &'static str, _: &[(&'static str, &str)], _: f64) {}
}
struct Verify {
    fire: Fire,
    metrics: Arc<Metrics>,
}
impl TimerHandler<MemoryKv> for Verify {
    fn kind(&self) -> TimerKind {
        registry::kinds::VERIFY
    }
    fn metrics(&self) -> Option<&dyn crate::Metrics> {
        Some(self.metrics.as_ref())
    }
    fn fire<'a>(
        &'a self,
        _: &'a TimerCtx<'a, MemoryKv>,
        _: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move { (self.fire)() })
    }
}

const FAILURES: &[(Fire, &str, &str)] = &[
    (
        || Err(StoreError::unavailable(PRIVATE)),
        "failed",
        "storage_unavailable",
    ),
    (|| Err(StoreError::Full), "failed", "storage_unavailable"),
    (
        || Err(StoreError::Corrupt(PRIVATE.into())),
        "failed",
        "decode_error",
    ),
    (
        || Err(StoreError::Invalid(PRIVATE.into())),
        "failed",
        "other",
    ),
    (
        || Err(StoreError::Unsupported(PRIVATE.into())),
        "failed",
        "other",
    ),
    (|| Err(StoreError::SessionGone), "failed", "other"),
    (|| Err(StoreError::PartSubtreeMismatch), "failed", "other"),
    (
        || Err(StoreError::RangeNotSatisfiable { len: 987_654_321 }),
        "failed",
        "other",
    ),
    (
        || {
            crate::budget::SliceBudget::new(0).charge()?;
            unreachable!()
        },
        "failed",
        "budget_exhausted",
    ),
    (
        || {
            Err(StoreError::unavailable(
                crate::takedown::inventory::StagingFailure::Expired {
                    backend_now: 987_654_321,
                },
            ))
        },
        "failed",
        "deadline",
    ),
    (
        || {
            Err(StoreError::unavailable(
                crate::takedown::inventory::StagingFailure::CasContention { index: 987_654_321 },
            ))
        },
        "failed",
        "guard_conflict",
    ),
    (
        || {
            Ok(Fired::Done(
                Batch::new().require(Precondition::NotAfter(99)),
            ))
        },
        "failed",
        "deadline",
    ),
    (
        || {
            Ok(Fired::Done(Batch::new().require(Precondition::Present(
                Key::new(PRIVATE.as_bytes().to_vec()),
            ))))
        },
        "raced",
        "guard_conflict",
    ),
    (|| Ok(Fired::Retry), "failed", "other"),
    (
        || {
            Ok(Fired::Reschedule {
                due_at_ms: 100,
                value: Value::default(),
                batch: Batch::new(),
            })
        },
        "failed",
        "other",
    ),
    // Backend messages cannot impersonate typed budget exhaustion.
    (
        || Err(StoreError::unavailable("subrequest budget: secret")),
        "failed",
        "storage_unavailable",
    ),
];

#[test]
fn verification_failures_emit_redacted_classes_and_retry_plan() {
    for &(fire, outcome, class) in FAILURES {
        for attempt in [0_u8, 3, 4, keys::MAX_TIMER_RETRY_ATTEMPT] {
            assert_fire(fire, outcome, Some(class), attempt);
        }
    }
    assert_fire(|| Ok(Fired::Done(Batch::new())), "committed", None, 0);
}

fn assert_fire(fire: Fire, outcome: &str, class: Option<&str>, attempt: u8) {
    let events = Events::default();
    let _subscriber = tracing::subscriber::set_default(events.clone());
    let clock = Arc::new(ManualClock::new(100));
    let store = MemoryKv::with_clock(clock.clone());
    let partition = Partition::Namespace(crate::NamespaceKey::deployment_default());
    let metrics = Arc::new(Metrics::default());
    let registry = TimerRegistry::new().register(Verify {
        fire,
        metrics: metrics.clone(),
    });
    let reference = crate::indexed::checkpoint::timer_reference(
        &crate::RepoName::new("private-repo").expect("test fixture"),
        &[7; 32],
    );
    let key = keys::timer_retry(100, registry::kinds::VERIFY.get(), &reference, 100, attempt);
    futures::executor::block_on(async {
        store
            .apply(&partition, Batch::new().put(key.clone(), Value::default()))
            .await
            .expect("test fixture");
        let report = run_due(
            &store,
            &partition,
            &registry,
            clock.as_ref(),
            100,
            &TickBudget::default(),
        )
        .await
        .expect("test fixture");
        assert_eq!(
            (report.fired, report.failed, report.raced),
            match outcome {
                "failed" => (0, 1, 0),
                "raced" => (0, 0, 1),
                _ => (1, 0, 0),
            }
        );
        let event = events
            .0
            .lock()
            .expect("test fixture")
            .iter()
            .find(|e| {
                e.get("event")
                    .is_some_and(|s| s == "verification_timer_result")
            })
            .expect("timer result event")
            .clone();
        assert_eq!(event["outcome"], outcome);
        assert_eq!(event["attempt"], attempt.to_string());
        let mut fields: Vec<_> = event.keys().map(String::as_str).collect();
        let mut expected = vec![
            "event",
            "now_ms",
            "source",
            "attempt",
            "pack",
            "scheduled_ms",
            "outcome",
        ];
        if let Some(class) = class {
            let next = attempt.saturating_add(1).min(keys::MAX_TIMER_RETRY_ATTEMPT);
            let delay = (5_000_u64 * (1 << (next - 1))).min(600_000);
            assert_eq!(event["error_class"], class);
            assert_eq!(event["next_delay_ms"], delay.to_string());
            assert_eq!(event["next_attempt"], next.to_string());
            assert_eq!(report.next_wake_ms, Some(100 + delay));
            let retry = keys::timer_retry(
                100 + delay,
                registry::kinds::VERIFY.get(),
                &reference,
                100,
                next,
            );
            assert_eq!(
                store.get(&partition, &retry).await.expect("test fixture"),
                Some(Value::default())
            );
            expected.extend(["error_class", "next_delay_ms", "next_attempt"]);
        } else {
            assert_eq!(report.next_wake_ms, None);
        }
        fields.sort_unstable();
        expected.sort_unstable();
        assert_eq!(fields, expected, "payload has only approved fields");
        for value in event.values() {
            for secret in [PRIVATE, "private-repo", "secret", "987654321"] {
                assert!(!value.contains(secret), "{event:?}");
            }
        }
        assert_metrics(&metrics, outcome, class);
    });
}

fn assert_metrics(metrics: &Metrics, outcome: &str, class: Option<&str>) {
    let counters = metrics.0.lock().expect("test fixture");
    let failures: Vec<_> = counters
        .iter()
        .filter(|(name, _)| *name == "mkit_server_verification_timer_failures_total")
        .collect();
    if let Some(class) = class {
        assert_eq!(failures.len(), 1);
        assert_eq!(
            failures[0].1,
            vec![
                ("outcome".into(), outcome.into()),
                ("class".into(), class.into())
            ]
        );
    } else {
        assert!(failures.is_empty());
    }
}

type EventFields = std::collections::BTreeMap<String, String>;
#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<EventFields>>>);
impl tracing::Subscriber for Events {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields(EventFields);
        impl tracing::field::Visit for Fields {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.insert(field.name().to_owned(), value.to_owned());
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.insert(field.name().to_owned(), format!("{value:?}"));
            }
        }
        let mut fields = Fields(EventFields::new());
        event.record(&mut fields);
        self.0.lock().expect("test fixture").push(fields.0);
    }
}
