//! Test-only latency and round tracing; no production behavior.
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};
#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub concurrency: usize,
    pub trace: Arc<Mutex<Vec<Event>>>,
}
#[derive(Clone, Debug)]
pub(crate) struct Event {
    pub phase: &'static str,
    pub start: tokio::time::Instant,
    pub end: tokio::time::Instant,
}
tokio::task_local! { static ACTIVE: Config; }
pub(crate) async fn run<T>(config: Config, future: impl Future<Output = T>) -> T {
    ACTIVE.scope(config, future).await
}
pub(crate) fn latency_ms() -> u64 {
    std::env::var("MKIT_BENCH_LATENCY_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}
pub(crate) fn concurrency(default: usize) -> usize {
    ACTIVE.try_with(|c| c.concurrency).unwrap_or(default)
}
pub(crate) fn phase(key: &[u8]) -> &'static str {
    let tag = key.split(|b| *b == 0).next().unwrap_or_default();
    match tag {
        b"i" => "locate",
        b"m" | b"pm" | b"vs" | b"pp" => "membership",
        b"r" | b"x" | b"pr" | b"py" => "root_capture",
        b"b" if key.get(34..).is_some_and(|v| v.starts_with(b"\0inventory")) => "inventory",
        b"b" | b"tb" => "denial",
        b"h" | b"g" | b"c" => "load_decode",
        _ => "authorization_other",
    }
}
pub(crate) async fn delay(milliseconds: u64, phase: &'static str) {
    if milliseconds == 0 {
        return;
    }
    let start = tokio::time::Instant::now();
    tokio::time::sleep(Duration::from_millis(milliseconds)).await;
    let end = tokio::time::Instant::now();
    let _ = ACTIVE.try_with(|c| c.trace.lock().unwrap().push(Event { phase, start, end }));
}
pub(crate) fn summary(events: &[Event]) -> serde_json::Value {
    let mut spans: BTreeMap<&str, Vec<_>> = BTreeMap::new();
    for event in events {
        spans
            .entry(event.phase)
            .or_default()
            .push((event.start, event.end));
    }
    let mut result = serde_json::Map::new();
    for (phase, mut spans) in spans {
        let rpc_count = spans.len();
        spans.sort();
        let mut union = Duration::ZERO;
        let mut current = spans[0];
        for &(start, end) in &spans[1..] {
            if start <= current.1 {
                current.1 = current.1.max(end);
            } else {
                union += current.1 - current.0;
                current = (start, end);
            }
        }
        union += current.1 - current.0;
        let mut edges: Vec<_> = spans
            .iter()
            .flat_map(|(s, e)| [(*s, 1i32), (*e, -1)])
            .collect();
        edges.sort();
        let (mut inflight, mut peak) = (0, 0);
        for (_, delta) in edges {
            inflight += delta;
            peak = peak.max(inflight);
        }
        result.insert(phase.to_string(),serde_json::json!({"rpcs":rpc_count,"wait_ms":union.as_secs_f64()*1000.0,"rounds":union.as_secs_f64()/0.030,"peak":peak}));
    }
    serde_json::Value::Object(result)
}
