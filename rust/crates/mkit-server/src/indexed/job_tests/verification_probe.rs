//! Deterministic verification shape: 30 ms per warm storage round and
//! 100 ms per physical alarm re-arm. The injected CPU clock stays frozen.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use tokio::time::Instant;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Row {
    slices: BTreeSet<u64>,
    callbacks: BTreeSet<u64>,
    rearms: u64,
    calls: u64,
    rounds: BTreeSet<Instant>,
    applies: u64,
    stops: BTreeMap<String, u64>,
}

#[derive(Default)]
struct State {
    phase: String,
    substage: Option<String>,
    slice: u64,
    callback: u64,
    rows: BTreeMap<String, Row>,
    decode_scopes: Vec<String>,
}

#[derive(Clone, Default)]
struct Trace(Arc<Mutex<State>>);

impl Trace {
    fn each(&self, mut f: impl FnMut(&mut Row, u64, u64)) {
        let mut state = self.0.lock().unwrap();
        let (slice, callback) = (state.slice, state.callback);
        let mut labels = vec![state.phase.clone()];
        if state.phase == "Decode" {
            labels.push(format!(
                "Decode/{}",
                state
                    .decode_scopes
                    .last()
                    .map_or("checkpoint", String::as_str)
            ));
        }
        if let Some(substage) = &state.substage {
            labels.push(format!("Extract/{substage}"));
        }
        for label in labels {
            f(state.rows.entry(label).or_default(), slice, callback);
        }
    }

    async fn call(&self, transport: bool) {
        let start = Instant::now();
        self.each(|row, _, callback| {
            row.calls += 1;
            if transport {
                row.rounds.insert(start);
            }
            row.callbacks.insert(callback);
        });
        if transport {
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }

    fn committed(&self) {
        self.each(|row, _, _| row.applies += 1);
    }

    fn decode_report(&self) -> String {
        let state = self.0.lock().unwrap();
        let mut calls = 0;
        let mut rounds = 0;
        let rows = [
            "inventory",
            "denial_holder",
            "frames",
            "writes",
            "checkpoint",
        ]
        .map(|category| {
            let row = state
                .rows
                .get(&format!("Decode/{category}"))
                .cloned()
                .unwrap_or_default();
            calls += row.calls;
            rounds += row.rounds.len();
            format!(
                "{category}: calls={} rounds={}",
                row.calls,
                row.rounds.len()
            )
        });
        let decode = &state.rows["Decode"];
        assert_eq!(calls, decode.calls);
        assert_eq!(rounds, decode.rounds.len());
        rows.join("\n")
    }

    fn render(&self) -> String {
        let mut rows = self.0.lock().unwrap().rows.clone();
        for phase in [
            "Decode",
            "ClosureResolve",
            "EmitIndex",
            "AwaitDelivery",
            "Extract",
            "Verify",
        ] {
            rows.entry(phase.into()).or_default();
        }
        for stage in [
            "scan",
            "select",
            "choose",
            "preflight",
            "start",
            "upload",
            "complete",
            "offsets",
            "enqueue",
            "delivery",
            "closure",
            "dependencies",
            "members",
            "head",
        ] {
            rows.entry(format!("Extract/{stage}")).or_default();
        }
        rows
            .iter()
            .filter(|(name, _)| !name.starts_with("Decode/"))
            .map(|(name, row)| {
                format!(
                    "{name}: slices={} callbacks={} rearms={} calls={} rounds={} applies={} modeled_ms={} stops={:?}",
                    row.slices.len(),
                    row.callbacks.len(),
                    row.rearms,
                    row.calls,
                    row.rounds.len(),
                    row.applies,
                    u64::try_from(row.rounds.len()).unwrap() * 30 + row.rearms * 100,
                    row.stops
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[derive(Default)]
struct Fields(BTreeMap<String, String>);
impl tracing::field::Visit for Fields {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().into(), format!("{value:?}"));
    }
}

impl tracing::Subscriber for Trace {
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
        let mut fields = Fields::default();
        event.record(&mut fields);
        match fields.0.get("event").map(String::as_str) {
            Some("verification_probe_decode_scope") => {
                let mut state = self.0.lock().unwrap();
                if fields.0["begin"] == "true" {
                    state.decode_scopes.push(fields.0["category"].clone());
                } else {
                    assert_eq!(
                        state.decode_scopes.pop().as_deref(),
                        Some(fields.0["category"].as_str())
                    );
                }
            }
            Some("verification_probe_slice") => {
                let mut state = self.0.lock().unwrap();
                state.substage = None;
                state.slice += 1;
            }
            Some("verification_slice_start") => {
                let mut state = self.0.lock().unwrap();
                state.phase.clone_from(&fields.0["old_phase"]);
                drop(state);
                self.each(|row, slice, callback| {
                    row.slices.insert(slice);
                    row.callbacks.insert(callback);
                });
            }
            Some("verification_probe_phase") => {
                let mut state = self.0.lock().unwrap();
                if state.phase != fields.0["phase"] {
                    let previous = state.phase.clone();
                    *state
                        .rows
                        .entry(previous)
                        .or_default()
                        .stops
                        .entry("phase_boundary".into())
                        .or_default() += 1;
                }
                state.phase.clone_from(&fields.0["phase"]);
                state.substage = None;
                drop(state);
                self.each(|row, slice, callback| {
                    row.slices.insert(slice);
                    row.callbacks.insert(callback);
                });
            }
            Some("verification_probe_extract") => {
                let stage_index = fields.0["stage"].parse::<usize>().unwrap();
                let name = [
                    "scan",
                    "select",
                    "choose",
                    "preflight",
                    "start",
                    "upload",
                    "complete",
                    "offsets",
                    "enqueue",
                    "delivery",
                    "closure",
                    "dependencies",
                    "members",
                    "head",
                ][stage_index];
                let mut state = self.0.lock().unwrap();
                if let Some(previous) = &state.substage {
                    let label = format!("Extract/{previous}");
                    *state
                        .rows
                        .entry(label)
                        .or_default()
                        .stops
                        .entry("step_boundary".into())
                        .or_default() += 1;
                }
                state.substage = Some(name.into());
                drop(state);
                self.each(|row, slice, callback| {
                    row.slices.insert(slice);
                    row.callbacks.insert(callback);
                });
            }
            Some("verification_extract_chain" | "verification_phase_chain") => {
                let prefix = if fields.0["event"] == "verification_extract_chain" {
                    "chain"
                } else {
                    "slice"
                };
                let reason = format!("{prefix}:{}", fields.0["stop_reason"]);
                self.each(|row, _, _| {
                    *row.stops.entry(reason.clone()).or_default() += 1;
                });
            }
            _ => {}
        }
    }
}

#[derive(Clone)]
struct Store {
    transport: bool,
    inner: Arc<MemoryKv>,
    trace: Trace,
}
impl NamespaceStore for Store {
    fn read_call_allowance(&self) -> Option<u32> {
        self.inner.read_call_allowance()
    }
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        self.trace.call(self.transport).await;
        self.inner.get(p, k).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.trace.call(self.transport).await;
        self.inner.get_many(p, keys).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.trace.call(self.transport).await;
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn scan_many(
        &self,
        p: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        self.trace.call(self.transport).await;
        self.inner.scan_many(p, ranges).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.trace.call(self.transport).await;
        let outcome = self.inner.apply(p, batch).await?;
        if outcome == BatchOutcome::Committed {
            self.trace.committed();
        }
        Ok(outcome)
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.trace.call(self.transport).await;
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.trace.call(self.transport).await;
        self.inner.probe().await
    }
}

#[derive(Clone)]
struct Blobs {
    inner: Arc<MemoryBlobStore>,
    trace: Trace,
}
struct Sink {
    inner: <MemoryBlobStore as BlobStore>::Sink,
    trace: Trace,
}
impl PackSink for Sink {
    async fn write(&mut self, bytes: Bytes) -> Result<(), StoreError> {
        self.trace.call(true).await;
        self.inner.write(bytes).await
    }
    async fn commit(self) -> Result<CommitOutcome, StoreError> {
        self.trace.call(true).await;
        self.inner.commit().await
    }
    async fn commit_with_root(self, root: Hash) -> Result<CommitOutcome, StoreError> {
        self.trace.call(true).await;
        self.inner.commit_with_root(root).await
    }
    async fn abort(self) {
        self.trace.call(true).await;
        self.inner.abort().await;
    }
}
impl BlobStore for Blobs {
    type Sink = Sink;
    async fn begin(&self, key: BlobKey, len: u64) -> Result<Sink, StoreError> {
        self.trace.call(true).await;
        Ok(Sink {
            inner: self.inner.begin(key, len).await?,
            trace: self.trace.clone(),
        })
    }
    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        self.trace.call(true).await;
        self.inner.get(key, range).await
    }
    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.trace.call(true).await;
        self.inner.head(key).await
    }
    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.trace.call(true).await;
        self.inner.delete(key).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.trace.call(true).await;
        self.inner.probe().await
    }
}

struct Measurement {
    table: String,
    durable: Snapshot,
    extracted: Vec<Vec<u8>>,
    index: String,
    decode: String,
    callback_calls: String,
}

#[allow(clippy::too_many_lines)] // Keep the measured fixture and its oracle together.
async fn measure(
    files: u16,
    bytes: usize,
    slices: u32,
    denial: bool,
    pack: &[u8],
    head: Hash,
) -> Measurement {
    let mut rig = Rig::named("probe", Arc::new(D34Shards));
    rig.limits.extract_chain_steps = 16;
    rig.limits.extract_chain_slices = slices;
    rig.limits.closure_chain_slices = slices;
    rig.limits.emit_chain_slices = slices;
    let (ticket, id) = rig.add(pack);
    assert!(rig.check(&[(&ticket, id)], head).is_err());
    let trace = Trace::default();
    let store = Store {
        transport: false,
        inner: rig.store.clone(),
        trace: trace.clone(),
    };
    let remote = Store {
        transport: true,
        ..store.clone()
    };
    let blobs = Blobs {
        inner: rig.blobs.clone(),
        trace: trace.clone(),
    };
    let handler = VerifyTimer {
        takedown_denial: denial,
        remote: remote.clone(),
        windows: BlobWindows(&blobs),
        blobs: blobs.clone(),
        shards: rig.shards.clone(),
        cfg: rig.cfg,
        limits: rig.limits,
        lease: LeaseParams::default(),
        clock: rig.clock.clone(),
        metrics: rig.recorder.clone(),
        extension: TestExtraction::new(&rig),
    };
    let registry = TimerRegistry::new()
        .register(handler)
        .register(crate::relay::RelayHandler {
            target: remote,
            hook: crate::relay::HolderRelayHook {
                clock: rig.clock.clone(),
            },
            budget: crate::relay::RelayBudget::default(),
        });
    let mut callback_calls: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    for callback in 1..=3_000 {
        if rig.job(&ticket.pack_id).unwrap().usable() {
            break;
        }
        {
            let mut state = trace.0.lock().unwrap();
            state.phase = format!("{:?}", rig.job(&ticket.pack_id).unwrap().phase);
            state.substage = None;
            state.callback = callback;
        }
        let phase = format!("{:?}", rig.job(&ticket.pack_id).unwrap().phase);
        let slice_start = rig.recorder.slices.lock().unwrap().len();
        let _subscriber = tracing::subscriber::set_default(trace.clone());
        let now = u64::try_from(rig.clock.now_ms()).unwrap();
        let report = run_due(
            &store,
            &rig.source(),
            &registry,
            rig.clock.as_ref(),
            now,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.failed, 0);
        let calls = rig.recorder.slices.lock().unwrap()[slice_start..]
            .iter()
            .sum::<f64>();
        assert!(
            calls <= f64::from(rig.limits.max_subrequests),
            "one shared callback allowance: {phase} {calls}"
        );
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        callback_calls.entry(phase).or_default().push(calls as u32);
        if !rig.job(&ticket.pack_id).unwrap().usable() {
            trace.each(|row, _, _| row.rearms += 1);
        }
        rig.clock
            .set(i64::try_from(report.next_wake_ms.unwrap_or(now + 1_000).max(now + 1)).unwrap());
    }
    assert!(rig.job(&ticket.pack_id).unwrap().usable());
    let outputs = if bytes > 65_536 {
        (0..files)
            .map(|n| {
                let (id, _) = blob(n, bytes);
                let output = read_blob(&rig.blobs, &BlobKey::object(id)).unwrap();
                assert_eq!(
                    output,
                    [
                        n.to_be_bytes().to_vec(),
                        (0..bytes).map(|i| u8::try_from(i % 251).unwrap()).collect()
                    ]
                    .concat()
                );
                output
            })
            .collect()
    } else {
        Vec::new()
    };
    let range = keys::class_range(keys::TAG_OBJECT_INDEX);
    let mut index = Vec::new();
    for partition in rig.shards.object_index_partitions(&rig.repo) {
        let rows = rig
            .store
            .scan(&partition, &range.0, &range.1, None, 10_000)
            .await
            .unwrap();
        assert!(rows.next.is_none());
        index.push((partition, rows.entries));
    }
    Measurement {
        table: trace.render(),
        durable: snapshot(&rig, &ticket.pack_id),
        extracted: outputs,
        index: format!("{index:?}"),
        decode: trace.decode_report(),
        callback_calls: callback_calls
            .iter()
            .map(|(phase, calls)| format!("{phase}: {calls:?}"))
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

#[tokio::test(start_paused = true)]
async fn verification_pipeline_round_probe() {
    let mut baselines = Vec::new();
    for (files, bytes) in [(500, 25), (3_000, 25), (3, 70_000)] {
        let (pack, head) = tree_pack(files, bytes);
        for denial in [true, false] {
            let before = Box::pin(measure(files, bytes, 1, denial, &pack, head)).await;
            let after = Box::pin(measure(
                files,
                bytes,
                SliceLimits::default().extract_chain_slices,
                denial,
                &pack,
                head,
            ))
            .await;
            println!(
                "PROBE files={files} bytes={bytes} denial={denial} before\n{}\nafter\n{}",
                before.table, after.table
            );
            println!("DECODE files={files} denial={denial}\n{}", before.decode);
            println!(
                "CALLS files={files} denial={denial} before\n{}\nafter\n{}",
                before.callback_calls, after.callback_calls
            );
            assert_eq!(before.decode, after.decode, "Decode attribution unchanged");
            assert_eq!(before.durable, after.durable, "durable verification output");
            assert_eq!(before.extracted, after.extracted, "extracted bytes");
            assert_eq!(
                before.index, after.index,
                "object index bytes across every shard"
            );
            let other_stages = |table: &str| {
                table
                    .lines()
                    .filter(|line| {
                        !["Extract", "ClosureResolve", "EmitIndex", "AwaitDelivery"]
                            .iter()
                            .any(|phase| line.starts_with(phase))
                    })
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                other_stages(&before.table),
                other_stages(&after.table),
                "other verification stages"
            );
            let callbacks = |table: &str, phase: &str| {
                table
                    .lines()
                    .find(|line| line.starts_with(&format!("{phase}:")))
                    .unwrap()
                    .split_whitespace()
                    .find_map(|part| part.strip_prefix("callbacks="))
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
            };
            if files == 3_000 {
                assert!(
                    callbacks(&after.table, "Extract") * 4 <= callbacks(&before.table, "Extract"),
                    "Extract callbacks must fall at least fourfold"
                );
                let combined = |m: &Measurement| {
                    callbacks(&m.table, "ClosureResolve") + callbacks(&m.table, "EmitIndex")
                };
                assert!(
                    combined(&after) * 4 <= combined(&before),
                    "ClosureResolve plus EmitIndex callbacks must fall at least fourfold"
                );
            } else {
                assert!(
                    callbacks(&after.table, "Extract") <= callbacks(&before.table, "Extract"),
                    "control callbacks must not regress"
                );
            }
            baselines.push((files, denial, before.table));
        }
    }
    // Runtime fixtures let probe numbers be refreshed without recompiling
    // this large test binary; every measured case prints before pin checks.
    for (files, denial, baseline) in baselines {
        let name = if files == 3 {
            "control".into()
        } else {
            files.to_string()
        };
        let name = if denial {
            name
        } else {
            format!("{name}-denial-off")
        };
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/indexed/job_tests/verification_probe_data")
            .join(format!("{name}.txt"));
        let expected = std::fs::read_to_string(path).unwrap();
        assert_eq!(baseline, expected.trim_end(), "pinned before table: {name}");
    }
}
