//! Fixed-work verification probe, run identically with observers off and on.
use super::*;
use serde_json::{Map, Value as JsonValue};

#[derive(Clone, Default)]
struct Rows(Arc<Mutex<[usize; 4]>>);

impl tracing::Subscriber for Rows {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() <= tracing::Level::INFO
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields(Map<String, JsonValue>);
        impl tracing::field::Visit for Fields {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.insert(field.name().into(), value.into());
            }
            fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
                self.0.insert(field.name().into(), value.into());
            }
            fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
                self.0.insert(field.name().into(), value.into());
            }
            fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
                self.0.insert(field.name().into(), value.into());
            }
            fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
                self.0.insert(field.name().into(), value.into());
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0
                    .insert(field.name().into(), format!("{value:?}").into());
            }
        }
        let mut fields = Fields(Map::new());
        event.record(&mut fields);
        fields
            .0
            .insert("target".into(), event.metadata().target().into());
        fields.0.insert(
            "level".into(),
            event
                .metadata()
                .level()
                .as_str()
                .to_ascii_lowercase()
                .into(),
        );
        let line = serde_json::to_vec(&fields.0).unwrap();
        {
            let mut totals = self.0.lock().unwrap();
            totals[0] += 1;
            totals[1] += line.len() + 1;
        }
        if !matches!(
            fields.0.get("event").and_then(JsonValue::as_str),
            Some(
                "verification_stage_duration"
                    | "verification_denial_histogram"
                    | "verification_emit_components"
                    | "verification_phase_chain"
                    | "verification_extract_chain"
                    | "verification_extract_chunk_chain"
                    | "verification_await_hint_histogram"
            )
        ) {
            return;
        }
        assert!(public_fields(&fields.0));
        assert!(!String::from_utf8_lossy(&line).contains("private-fixture"));
        let mut counts = self.0.lock().unwrap();
        counts[2] += 1;
        counts[3] += line.len() + 1;
    }
}

fn public_fields(fields: &Map<String, JsonValue>) -> bool {
    fields.keys().all(|key| {
        matches!(
            key.as_str(),
            "event"
                | "level"
                | "target"
                | "stage"
                | "component"
                | "duration_ms"
                | "stop_reason"
                | "calls"
                | "steps"
                | "hint_ms"
                | "ms_0"
                | "ms_1"
                | "ms_10"
                | "ms_50"
                | "ms_100"
                | "ms_250"
                | "ms_500"
                | "ms_1000"
                | "ms_2000"
                | "ms_3000"
                | "ms_inf"
                | "scan_ms"
                | "plan_ms"
                | "denial_ms"
                | "direct_apply_ms"
                | "relay_commit_ms"
                | "outbox_read_ms"
        )
    }) && fields.iter().all(|(key, value)| {
        value.as_str().is_none_or(|label| {
            key == "event"
                || (key == "target" && label.starts_with("mkit_server::"))
                || (key == "level" && label == "info")
                || matches!(
                    label,
                    "decode"
                        | "closure_resolve"
                        | "emit_index"
                        | "await_delivery"
                        | "extract"
                        | "verify"
                        | "recheck"
                        | "watch"
                        | "inline_verifier"
                        | "total"
                        | "scan"
                        | "plan"
                        | "denial"
                        | "direct_apply"
                        | "relay_commit"
                        | "outbox_read"
                        | "complete"
                        | "pending"
                        | "store_error"
                        | "outcome"
                        | "rejected"
                        | "restart"
                        | "pending_or_error"
                        | "decode_boundary"
                        | "phase_incomplete"
                        | "terminal"
                        | "durable_boundary"
                        | "steps"
                        | "calls"
                )
        })
    })
}

#[test]
fn verification_instrumentation_cost_probe() {
    let capture = Rows::default();
    let (pack, _) = tree_pack(16, 32);
    let mut expected: Option<Snapshot> = None;
    let mut slices = 0;
    let mut calls = 0.0;
    let mut digest = String::new();
    tracing::subscriber::with_default(capture.clone(), || {
        for _ in 0..50 {
            let rig = Rig::named("private-fixture", Arc::new(SinglePartition));
            let (ticket, id) = rig.add(&pack);
            rig.create(&ticket, id);
            rig.drive(|rig| rig.finished(&ticket.pack_id));
            let job = rig.job(&ticket.pack_id).unwrap();
            assert!(job.usable());
            assert_eq!(job.entries, 18);
            let actual = snapshot(&rig, &ticket.pack_id);
            if let Some(reference) = &expected {
                assert_eq!(&actual, reference);
            } else {
                digest = mkit_core::hash::to_hex(&hash(format!("{actual:?}").as_bytes()));
                expected = Some(actual);
            }
            let observed = rig.recorder.slices.lock().unwrap();
            slices += observed.len();
            calls += observed.iter().sum::<f64>();
        }
    });
    let [total_rows, total_bytes, rows, bytes] = *capture.0.lock().unwrap();
    // Eighteen entries fit one Decode slice; eight phases and their slice
    // summaries plus two denial histograms and one Emit summary stay bounded.
    assert!(
        rows <= 50 * 24,
        "new structured rows exceeded the fixture bound"
    );
    #[cfg(not(feature = "perf-metrics"))]
    assert_eq!((rows, bytes), (0, 0));
    #[cfg(feature = "perf-metrics")]
    assert!(rows > 0);
    eprintln!(
        "verification_cost iterations=50 slices={slices} calls={calls} total_rows={total_rows} total_bytes={total_bytes} rows={rows} bytes={bytes} digest={digest}"
    );
}
