//! Fixed-size RPC summaries. No request or response bytes are retained.
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use std::sync::{Mutex, PoisonError};

use mkit_server::Partition;
use serde::Serialize;

use super::{Channel, ConsoleSink, LineSink};
use crate::wire::{NsCall, NsReply};

pub(crate) const HEADER: &str = "x-mkit-perf";
const WINDOW: u64 = 100;
const TOP: usize = 4;

pub(crate) fn prefix(partition: &Partition) -> &'static str {
    match partition {
        Partition::RepoIndex { .. } => "ri:",
        Partition::RefIndex { .. } => "x:",
        Partition::ContentShard(_) => "ci:",
        Partition::Ref { .. } => "r:",
        Partition::Coordinator(_) => "c:",
        Partition::Namespace(_) => "n:",
        _ => "other",
    }
}

pub(crate) fn count(call: &NsCall) -> usize {
    match call {
        NsCall::GetMany { keys } => keys.len(),
        NsCall::ScanMany { ranges } => ranges.len(),
        NsCall::Apply { batch } => batch.writes.len(),
        NsCall::Get { .. } | NsCall::Scan { .. } | NsCall::Export { .. } => 1,
        _ => 0,
    }
}

pub(crate) fn reply_rows(reply: &NsReply) -> u64 {
    let size = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    match reply {
        NsReply::Value { value } => u64::from(value.is_some()),
        NsReply::Values { values } => size(values.iter().filter(|value| value.is_some()).count()),
        NsReply::Page { entries, .. } => size(entries.len()),
        NsReply::Pages { pages } => pages.iter().fold(0_u64, |total, page| {
            total.saturating_add(size(page.entries.len()))
        }),
        _ => 0,
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Call {
    pub prefix: &'static str,
    pub op: &'static str,
    pub count: usize,
    pub caller_ms: f64,
    pub complete: bool,
    pub inside_ms: Option<f64>,
    pub cold: Option<bool>,
    pub decode_ms: Option<f64>,
    pub encode_ms: Option<f64>,
    pub sql_query_ms: Option<f64>,
    pub sql_statements: Option<u64>,
    pub rows: Option<u64>,
    pub sql_rows: Option<u64>,
}

impl Call {
    pub(crate) fn new(prefix: &'static str, op: &'static str, count: usize) -> Self {
        let prefix = match prefix {
            "ri:" | "x:" | "ci:" | "r:" | "c:" | "n:" => prefix,
            _ => "other",
        };
        let op = match op {
            "ping" | "get" | "get_many" | "scan" | "scan_many" | "apply" | "stats" | "probe"
            | "export" | "test_snapshot" | "test_import" => op,
            _ => "other",
        };
        Self {
            prefix,
            op,
            count,
            caller_ms: 0.0,
            complete: false,
            inside_ms: None,
            cold: None,
            decode_ms: None,
            encode_ms: None,
            sql_query_ms: None,
            sql_statements: None,
            rows: None,
            sql_rows: None,
        }
    }

    // Fixed numeric metadata only. Malformed metadata is absent, never a call failure.
    pub(crate) fn reply_metadata(&mut self, header: &str) {
        let values: Vec<_> = header.split(',').take(10).collect();
        if values.len() != 9 {
            return;
        }
        let ms = |index: usize| {
            values[index]
                .parse::<f64>()
                .ok()
                .filter(|n| n.is_finite() && *n >= 0.0)
        };
        self.inside_ms = ms(0);
        self.cold = match values[1] {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        };
        self.decode_ms = ms(2);
        self.encode_ms = ms(3);
        self.sql_query_ms = ms(4);
        self.sql_statements = values[5].parse().ok();
        self.sql_rows = values[6].parse().ok();
        self.rows = values[7].parse().ok();
        // Version marker prevents interpreting a different header schema.
        if values[8] != "1" {
            self.inside_ms = None;
            self.cold = None;
            self.decode_ms = None;
            self.encode_ms = None;
            self.sql_query_ms = None;
            self.sql_statements = None;
            self.rows = None;
            self.sql_rows = None;
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct Window {
    calls: u64,
    incomplete: u64,
    caller_ms: f64,
    // Disjoint buckets <=1, <=10, <=50, <=100, <=250, <=500, <=1000, >1000 ms.
    caller_ms_buckets: [u64; 8],
    slowest: Vec<Call>,
}

impl Window {
    fn record(&mut self, call: Call) {
        self.calls += 1;
        self.incomplete += u64::from(!call.complete);
        self.caller_ms += call.caller_ms;
        let bucket = [1.0, 10.0, 50.0, 100.0, 250.0, 500.0, 1000.0]
            .iter()
            .position(|bound| call.caller_ms <= *bound)
            .unwrap_or(7);
        self.caller_ms_buckets[bucket] += 1;
        if self.slowest.len() < TOP {
            self.slowest.push(call);
        } else if call.caller_ms > self.slowest[TOP - 1].caller_ms {
            self.slowest[TOP - 1] = call;
        }
        self.slowest
            .sort_by(|a, b| b.caller_ms.total_cmp(&a.caller_ms));
    }

    fn emit(&self, sink: &impl LineSink) {
        if self.calls != 0 {
            sink.write(
                Channel::Log,
                &serde_json::json!({
                    "event": "storage_rpc_summary", "sample_window": WINDOW,
                    "clock": if cfg!(target_arch = "wasm32") { "workers_io" } else { "monotonic" },
                    "summary": self,
                })
                .to_string(),
            );
        }
    }
}

/// One owner per transport factory, shared by its clones. Flush at 100 calls
/// and on final drop, including cancellation. Long-lived alarm clients stay bounded.
#[derive(Debug, Default)]
pub(crate) struct Summary<S: LineSink = ConsoleSink> {
    window: Mutex<Window>,
    sink: S,
}

#[cfg(target_arch = "wasm32")]
pub(crate) struct Observation<'a> {
    summary: &'a Summary,
    started: f64,
    slice: Option<mkit_server::telemetry::slice_context::RpcObservation>,
    pub record: Call,
}

#[cfg(target_arch = "wasm32")]
impl<'a> Observation<'a> {
    pub(crate) fn new(summary: &'a Summary, record: Call) -> Self {
        Self {
            summary,
            started: worker::js_sys::Date::now(),
            slice: mkit_server::telemetry::slice_context::RpcObservation::current(),
            record,
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl Drop for Observation<'_> {
    fn drop(&mut self) {
        self.record.caller_ms = (worker::js_sys::Date::now() - self.started).max(0.0);
        if let Some(slice) = &self.slice {
            slice.record_rpc(self.record.prefix, self.record.caller_ms);
        }
        self.summary.record(self.record.clone());
    }
}

impl<S: LineSink> Summary<S> {
    #[cfg(test)]
    pub(crate) fn with_sink(sink: S) -> Self {
        Self {
            window: Mutex::default(),
            sink,
        }
    }

    pub(crate) fn record(&self, call: Call) {
        let mut window = self.window.lock().unwrap_or_else(PoisonError::into_inner);
        window.record(call);
        if window.calls == WINDOW {
            window.emit(&self.sink);
            *window = Window::default();
        }
    }
}

impl<S: LineSink> Drop for Summary<S> {
    fn drop(&mut self) {
        self.window
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .emit(&self.sink);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_is_bounded_and_never_retains_sensitive_input() {
        let partition =
            Partition::decode(b"rsecret-namespace\0private-repository\0credential-ref\0").unwrap();
        let call = NsCall::GetMany {
            keys: vec![crate::wire::Blob(b"private-object-id-secret-key".to_vec())],
        };
        let mut window = Window::default();
        for n in 0..100 {
            let mut record = Call::new(prefix(&partition), "get_many", count(&call));
            record.caller_ms = f64::from(n);
            record.reply_metadata("1,1,0,0,0,4,16,15,1");
            record.complete = true;
            window.record(record);
        }
        assert_eq!(window.calls, 100);
        assert_eq!(window.caller_ms_buckets.iter().sum::<u64>(), 100);
        assert_eq!(window.slowest.len(), TOP);
        assert_eq!(
            window.slowest[0].caller_ms.total_cmp(&99.0),
            std::cmp::Ordering::Equal
        );
        let json = serde_json::to_string(&window).unwrap();
        for secret in [
            "secret-namespace",
            "private-repository",
            "credential-ref",
            "private-object-id",
            "secret-key",
        ] {
            assert!(!json.contains(secret));
        }
        assert!(json.len() < 2048);
        let direct = Call::new("secret-namespace", "credential-value", 0);
        assert_eq!(direct.prefix, "other");
        assert_eq!(direct.op, "other");
    }

    #[test]
    fn activation_ping_uses_profiled_transport_without_changing_its_wire_body() {
        use crate::naming::DoTarget;
        use crate::ns_client::{DoNamespaceStore, NsTransport};
        use crate::wire::NsRequest;
        use mkit_server::{NamespaceKey, StoreError};

        struct Transport;
        impl NsTransport for Transport {
            async fn call(
                &self,
                _: &DoTarget,
                _: &'static str,
                _: String,
            ) -> Result<String, StoreError> {
                panic!("activation ping must use the profiled path");
            }
            async fn call_profiled(
                &self,
                _: &DoTarget,
                op: &'static str,
                body: String,
                prefix: &'static str,
                count: usize,
            ) -> Result<String, StoreError> {
                let request: NsRequest = serde_json::from_str(&body).unwrap();
                assert!(matches!(request.call, NsCall::Ping));
                assert_eq!(serde_json::to_string(&request).unwrap(), body);
                let record = Call::new(prefix, op, count);
                assert_eq!((record.prefix, record.op, record.count), ("ri:", "ping", 0));
                Ok(serde_json::to_string(&NsReply::Ok).unwrap())
            }
        }
        let partition = Partition::RepoIndex {
            ns: NamespaceKey::deployment_default(),
            repo: mkit_server::RepoName::new("warmup-fixture").unwrap(),
            prefix: 0,
        };
        let store = DoNamespaceStore::new(Transport, partition.clone())
            .with_budget(mkit_server::indexed::budget::SliceBudget::new(0));
        futures::executor::block_on(store.ping(&partition)).unwrap();
    }

    #[derive(Debug, Clone, Default)]
    struct Capture(std::sync::Arc<Mutex<Vec<String>>>);
    impl LineSink for Capture {
        fn write(&self, _: Channel, line: &str) {
            self.0.lock().unwrap().push(line.to_owned());
        }
    }

    #[test]
    fn summaries_flush_at_fixed_volume_and_on_final_drop() {
        let capture = Capture::default();
        let summary = Summary {
            window: Mutex::default(),
            sink: capture.clone(),
        };
        for _ in 0..205 {
            summary.record(Call::new("ci:", "get_many", 2));
        }
        assert_eq!(capture.0.lock().unwrap().len(), 2);
        drop(summary);
        let lines = capture.0.lock().unwrap();
        assert_eq!(lines.len(), 3);
        let calls: Vec<_> = lines
            .iter()
            .map(|line| {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                assert!(line.len() < 2048);
                value["summary"]["calls"].as_u64().unwrap()
            })
            .collect();
        assert_eq!(calls, [100, 100, 5]);
    }

    #[test]
    fn reply_rows_counts_returned_entries_without_sql_lookahead_or_missing_values() {
        use crate::wire::{Blob, WirePage};
        let reply = NsReply::Pages {
            pages: vec![WirePage {
                entries: vec![(
                    Blob(b"private-object-id".to_vec()),
                    Blob(b"credential-value".to_vec()),
                )],
                next: Some(Blob(b"private-cursor".to_vec())),
            }],
        };
        assert_eq!(reply_rows(&reply), 1);
        assert_eq!(
            reply_rows(&NsReply::Values {
                values: vec![None, Some(Blob(vec![42]))]
            }),
            1
        );
        assert_eq!(reply_rows(&NsReply::Ok), 0);
        let mut call = Call::new("ri:", "scan_many", 1);
        call.reply_metadata("1,0,0,0,0,1,2,1,1");
        assert_eq!(call.rows, Some(1));
        assert_eq!(call.sql_rows, Some(2));
        let json = serde_json::to_string(&call).unwrap();
        for secret in ["private-object-id", "credential-value", "private-cursor"] {
            assert!(!json.contains(secret));
        }
    }

    #[test]
    fn malformed_or_absent_reply_metadata_is_not_required() {
        for header in [
            "",
            "secret",
            "1,1,0,0,0,4,16,15,2",
            "NaN,0,-1,inf,0,4,16,15,1",
        ] {
            let mut call = Call::new("ri:", "scan_many", 8);
            call.reply_metadata(header);
            assert_eq!(call.inside_ms, None);
            assert_eq!(call.decode_ms, None);
        }
    }
}
