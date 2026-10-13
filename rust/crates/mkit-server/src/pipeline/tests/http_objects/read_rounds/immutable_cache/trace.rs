//! Record authoritative calls below the cache, including exact keys and ranges.
use super::*;
use crate::store::{
    Cursor, PartitionStats, RangeScan, ReadReservation, ScanPage, StoreCapabilities,
};
use std::fmt::Write as _;

type Trace = Arc<Mutex<Vec<serde_json::Value>>>;

#[derive(Clone)]
pub(super) struct TraceKv {
    pub inner: Arc<Spy>,
    pub trace: Trace,
}

#[derive(Clone)]
pub(super) struct TraceBlobs {
    pub inner: SpyBlobs,
    pub trace: Trace,
}

pub(super) fn new() -> Trace {
    Arc::default()
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            write!(out, "{byte:02x}").unwrap();
            out
        })
}

fn describe(key: &Key) -> serde_json::Value {
    let tag = key
        .as_bytes()
        .split(|byte| *byte == 0)
        .next()
        .unwrap_or_default();
    serde_json::json!({
        "family_tag": String::from_utf8_lossy(tag),
        "role_by_key_family": match tag {
            b"rv" | b"rj" => "visibility_authorize_or_final_guard",
            b"e" | b"el" | b"lr" | b"ag" => "authorization_epoch_or_final_guard",
            b"rr" | b"rk" | b"nr" | b"fj" => "repository_authorize_or_final_guard",
            b"pp" | b"pr" | b"py" | b"av" => "publication_proof_or_final_guard",
            b"m" | b"pm" | b"vs" => "membership_proof_or_final_guard",
            b"b" | b"tb" | b"ct" => "denial_or_final_guard",
            b"i" => "locate",
            b"r" | b"x" => "ref_capture_or_final_guard",
            b"h" | b"g" | b"c" => "content_membership_or_denial_proof",
            _ => "other_live_proof",
        },
        "class": format!("{:?}", crate::store::cacheability(key)),
        "step_by_key_family": read_probe::phase(key.as_bytes()),
        "key_hex": hex(key.as_bytes()),
    })
}

impl TraceKv {
    fn record(&self, p: &Partition, method: &str, details: serde_json::Value) {
        self.trace.lock().unwrap().push(serde_json::json!({
            "store": "namespace", "step": read_probe::current_step(), "partition": p.kind(),
            "partition_hex": hex(&p.encode().unwrap()), "method": method, "details": details,
        }));
    }
}

impl NamespaceStore for TraceKv {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    fn read_call_allowance(&self) -> Option<u32> {
        self.inner.read_call_allowance()
    }
    fn reserve_read_calls(&self, calls: u32) -> Result<Option<ReadReservation>, StoreError> {
        self.inner.reserve_read_calls(calls)
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.record(p, "get", describe(key));
        self.inner.get(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.record(
            p,
            "get_many",
            serde_json::json!(keys.iter().map(describe).collect::<Vec<_>>()),
        );
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
        self.record(
            p,
            "scan",
            serde_json::json!({
                "start": describe(start), "end": describe(end),
                "after_hex": after.map(|cursor| hex(cursor.as_bytes())), "limit": limit,
            }),
        );
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn scan_many(
        &self,
        p: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        self.record(
            p,
            "scan_many",
            serde_json::json!(
                ranges
                    .iter()
                    .map(|range| serde_json::json!({
                        "start": describe(&range.start), "end": describe(&range.end),
                        "after_hex": range.after.as_ref().map(|cursor| hex(cursor.as_bytes())),
                        "limit": range.limit,
                    }))
                    .collect::<Vec<_>>()
            ),
        );
        self.inner.scan_many(p, ranges).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.record(
            p,
            "apply",
            serde_json::json!({
                "step": "guarded_batch", "preconditions": format!("{:?}", batch.preconditions),
                "write_count": batch.writes.len(),
            }),
        );
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.record(p, "stats", serde_json::json!({ "class": "Live" }));
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

impl TraceBlobs {
    fn record(&self, key: &BlobKey, method: &str, range: Option<ByteRange>) {
        self.trace.lock().unwrap().push(serde_json::json!({
            "store": "blob", "method": method, "kind": format!("{:?}", key.namespace()),
            "id": hex(key.hash()), "class": format!("{:?}", crate::store::blob_cacheability(key)),
            "read_semantics": if method == "head" { "Live presence" } else { "content bytes" },
            "step": read_probe::current_step(),
            "read_role": if method == "head" { "physical_presence" } else { "load_decode" },
            "range": range.map(|range| serde_json::json!({
                "start": range.start, "end_inclusive": range.end_inclusive,
            })),
        }));
    }
}

impl BlobStore for TraceBlobs {
    type Sink = <SpyBlobs as BlobStore>::Sink;
    fn read_call_allowance(&self) -> Option<u32> {
        self.inner.read_call_allowance()
    }
    fn read_byte_allowance(&self) -> Option<u64> {
        self.inner.read_byte_allowance()
    }
    fn reserve_read_calls(&self, calls: u32) -> Result<Option<ReadReservation>, StoreError> {
        self.inner.reserve_read_calls(calls)
    }
    fn reserve_read_bytes(&self, bytes: u64) -> Result<Option<ReadReservation>, StoreError> {
        self.inner.reserve_read_bytes(bytes)
    }
    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.inner.begin(key, len).await
    }
    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        self.record(key, "get", range);
        self.inner.get(key, range).await
    }
    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.record(key, "head", None);
        self.inner.head(key).await
    }
    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

// The fixture has no multipart backend; preserve the same unsupported defaults.
impl MultipartBlobStore for TraceBlobs {
    type PartSink = UnsupportedPartSink;
    const MAX_PARTS: u32 = u32::MAX;
}

pub(super) fn clear<H: HookSet>(pipe: &CachedPipe<H>) {
    pipe.meta.inner().trace.lock().unwrap().clear();
}

pub(super) fn print<H: HookSet>(
    pipe: &CachedPipe<H>,
    owner: bool,
    denial: bool,
    op: Op,
    variant: &str,
) {
    let trace = pipe.meta.inner().trace.lock().unwrap();
    let mut counts = std::collections::BTreeMap::new();
    for (sequence, call) in trace.iter().enumerate() {
        println!(
            "IMMUTABLE_CACHE_STORE_CALL {}",
            serde_json::json!({
                "owner": owner, "denial": denial, "op": format!("{op:?}"),
                "variant": variant, "sequence": sequence + 1, "call": call,
            })
        );
        let store = call["store"].as_str().unwrap();
        let method = call["method"].as_str().unwrap();
        *counts.entry(format!("{store}.{method}")).or_insert(0_u32) += 1;
    }
    println!(
        "IMMUTABLE_CACHE_STORE_CALL_COUNTS {}",
        serde_json::json!({
            "owner": owner, "denial": denial, "op": format!("{op:?}"),
            "variant": variant, "calls": counts,
        })
    );
}
