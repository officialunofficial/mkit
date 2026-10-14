//! Native storage-path cost harness. The timer measures wall time; invoke the
//! test process under a process CPU profiler to measure CPU independently.

use std::time::Instant;

use futures::executor::block_on;
use mkit_server::{Batch, Key, NamespaceKey, NamespaceStore, Partition, Value};
use serde_json::json;

use super::perf_rpc::{Call, Summary};
use super::perf_sql::{SqlTimings, TimedSqlConn};
use super::{Channel, LineSink};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Default)]
struct LogVolume(Arc<Mutex<Vec<usize>>>);
impl LineSink for LogVolume {
    fn write(&self, _: Channel, line: &str) {
        self.0.lock().expect("log volume lock").push(line.len());
    }
}
use crate::classes::ShardClass;
use crate::ns_object::{decode_request, dispatch, encode};
use crate::sql::SqlKvStore;
use crate::test_sqlite::RusqliteConn;
use crate::wire::{Blob, NsCall, NsReply, NsRequest, WireRangeScan};

#[derive(Default)]
struct Cost {
    decode_ms: f64,
    dispatch_ms: f64,
    encode_ms: f64,
    reply_decode_ms: f64,
    total_ms: f64,
    sql_ms: f64,
    statements: u64,
    rows: u64,
    summary_bytes: usize,
}

fn measured<S: NamespaceStore>(store: &S, body: &str) -> (String, Cost) {
    let total = Instant::now();
    let start = Instant::now();
    let (partition, call) = decode_request(body, ShardClass::RefStore).expect("valid scan request");
    let decode_ms = start.elapsed().as_secs_f64() * 1000.0;
    let start = Instant::now();
    let reply = block_on(dispatch(store, &partition, call))
        .expect("scan dispatch")
        .0;
    let dispatch_ms = start.elapsed().as_secs_f64() * 1000.0;
    let start = Instant::now();
    let wire = encode(&reply);
    let encode_ms = start.elapsed().as_secs_f64() * 1000.0;
    let start = Instant::now();
    let _: NsReply = serde_json::from_str(&wire).expect("valid scan reply");
    let reply_decode_ms = start.elapsed().as_secs_f64() * 1000.0;
    (
        wire,
        Cost {
            decode_ms,
            dispatch_ms,
            encode_ms,
            reply_decode_ms,
            total_ms: total.elapsed().as_secs_f64() * 1000.0,
            ..Cost::default()
        },
    )
}

impl Cost {
    fn add(&mut self, cost: &Self, sql: &SqlTimings) {
        self.decode_ms += cost.decode_ms;
        self.dispatch_ms += cost.dispatch_ms;
        self.encode_ms += cost.encode_ms;
        self.reply_decode_ms += cost.reply_decode_ms;
        self.total_ms += cost.total_ms;
        self.sql_ms += sql.sql_query_ms + sql.sql_exec_ms;
        self.statements += sql.query_statements + sql.exec_statements;
        self.rows += sql.query_rows;
    }
}

struct Fixture {
    baseline: SqlKvStore<RusqliteConn>,
    conn: TimedSqlConn<RusqliteConn>,
    instrumented: SqlKvStore<TimedSqlConn<RusqliteConn>>,
    body: String,
}

fn fixture() -> Fixture {
    let partition = Partition::Namespace(NamespaceKey::deployment_default());
    let inner = RusqliteConn::open_in_memory().expect("prepare scan fixture");
    let baseline = SqlKvStore::open(inner.clone()).expect("prepare scan fixture");
    for bucket in 0_u8..8 {
        for start in (0_u8..100).step_by(16) {
            let mut batch = Batch::new();
            for ordinal in start..start.saturating_add(16).min(100) {
                batch = batch.put(Key::new(vec![bucket, ordinal]), Value::new(vec![42; 240]));
            }
            block_on(baseline.apply(&partition, batch)).expect("prepare scan fixture");
        }
    }
    let conn = TimedSqlConn::new(inner);
    let instrumented = SqlKvStore::open(conn.clone()).expect("prepare scan fixture");
    let request = NsRequest::new(
        &partition,
        NsCall::ScanMany {
            ranges: (0_u8..8)
                .map(|bucket| WireRangeScan {
                    start: Blob(vec![bucket]),
                    end: Blob(vec![bucket + 1]),
                    after: None,
                    limit: 100,
                })
                .collect(),
        },
    )
    .expect("prepare scan fixture");
    let body = serde_json::to_string(&request).expect("prepare scan fixture");
    Fixture {
        baseline,
        conn,
        instrumented,
        body,
    }
}

#[test]
fn scan_many_instrumentation_cost_and_wire_identity() {
    let Fixture {
        baseline,
        conn,
        instrumented,
        body,
    } = fixture();
    let reference = measured(&baseline, &body).0;
    let mut costs: [Cost; 3] = std::array::from_fn(|_| Cost::default());
    let selected = std::env::var("MKIT_PERF_COST_MODE").ok();
    let modes = ["baseline", "disabled", "enabled"];
    let iterations = 64;
    let logs = LogVolume::default();
    let summary = Summary::with_sink(logs.clone());
    for round in 0..iterations {
        // Rotate the order so each mode encounters comparable warmed state.
        for offset in 0..3 {
            let mode = (round + offset) % 3;
            if selected
                .as_deref()
                .is_some_and(|selected| selected != modes[mode])
            {
                continue;
            }
            let sampled = mode == 2;
            conn.begin_perf(sampled);
            let (reply, mut cost) = if mode == 0 {
                measured(&baseline, &body)
            } else {
                measured(&instrumented, &body)
            };
            assert_eq!(reply, reference);
            let sql = conn.take_perf();
            if sampled {
                // Each full 16-row step reads one lookahead row.
                assert_eq!(sql.query_rows, 848);
                assert_eq!(sql.query_statements, 56);
                assert_eq!(sql.exec_statements, 0);
                let bytes = serde_json::to_vec(&sql)
                    .expect("serialize SQL summary")
                    .len();
                assert!(bytes < 256, "SQL summary must remain bounded");
                costs[mode].summary_bytes = costs[mode].summary_bytes.max(bytes);
                let overhead = Instant::now();
                let mut call = Call::new("n:", "scan_many", 8);
                call.caller_ms = cost.total_ms;
                call.complete = true;
                call.reply_metadata(&format!(
                    "{},0,{},{},{},{},{},800,1",
                    cost.dispatch_ms + cost.decode_ms + cost.encode_ms,
                    cost.decode_ms,
                    cost.encode_ms,
                    sql.sql_query_ms,
                    sql.query_statements,
                    sql.query_rows,
                ));
                assert_eq!(call.rows, Some(800));
                assert_eq!(call.sql_rows, Some(848));
                summary.record(call);
                cost.total_ms += overhead.elapsed().as_secs_f64() * 1000.0;
            } else {
                assert_eq!(sql, SqlTimings::default());
            }
            costs[mode].add(&cost, &sql);
        }
    }
    drop(summary);
    let lines = logs.0.lock().expect("log volume lock");
    assert!(lines.iter().all(|bytes| *bytes < 2048));
    assert_eq!(
        lines.len(),
        usize::from(selected.as_deref().is_none_or(|mode| mode == "enabled"))
    );
    for (mode, cost) in modes.into_iter().zip(costs) {
        if selected.as_deref().is_some_and(|selected| selected != mode) {
            continue;
        }
        println!(
            "{}",
            json!({
                "harness": "scan_many_cost", "mode": mode, "iterations": iterations,
                "request_bytes": body.len(), "reply_bytes": reference.len(),
                "decode_ms": cost.decode_ms, "dispatch_ms": cost.dispatch_ms,
                "encode_ms": cost.encode_ms, "reply_decode_ms": cost.reply_decode_ms,
                "total_ms": cost.total_ms, "sql_ms": cost.sql_ms,
                "sql_statements": cost.statements, "sql_rows": cost.rows,
                "sql_summary_max_bytes": cost.summary_bytes,
                "sql_statement_log_lines": 0,
                "rpc_summary_lines": if mode == "enabled" { lines.len() } else { 0 },
                "rpc_summary_bytes": if mode == "enabled" { lines.iter().sum::<usize>() } else { 0 },
            })
        );
    }
}
