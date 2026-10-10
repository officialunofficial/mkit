//! Shared slow-store harness for the full scheduled-verification tests: every
//! storage call advances the business clock by 50 ms and is ledgered.
#![allow(dead_code, unreachable_pub)]
use bytes::Bytes;
use mkit_core::{
    hash::{Hash, hash},
    object::{Blob, Commit, Identity, Object},
    serialize::serialize,
    sign::{KeyPair, sign_commit},
};
use mkit_server::indexed::budget::{BlobWindows, PackWindows, Window, WindowError};
use mkit_server::store::adapter_spi::keys;
use mkit_server::{
    Batch, BatchOutcome, BlobBody, BlobKey, BlobMeta, BlobStore, BoxFuture, ByteRange, Clock,
    Cursor, Key, ManualClock, MemoryBlobStore, MemoryKv, Metrics, NamespaceStore, PackSink,
    Partition, PartitionStats, Precondition, RangeScan, ScanPage, StoreCapabilities, StoreError,
    Value, Write,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU32, Ordering},
};
pub struct Shared<T>(pub Arc<T>, pub Arc<ManualClock>);

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0), Arc::clone(&self.1))
    }
}

impl<T: BlobStore> BlobStore for Shared<T> {
    type Sink = SlowSink<T::Sink>;
    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        self.1.advance(50);
        self.0
            .begin(key, len)
            .await
            .map(|sink| SlowSink(sink, self.1.clone()))
    }
    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        self.1.advance(50);
        self.0.get(key, range).await
    }
    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        self.1.advance(50);
        self.0.head(key).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        self.1.advance(50);
        self.0.probe().await
    }
    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        self.1.advance(50);
        self.0.delete(key).await
    }
}

pub struct SlowSink<T>(pub T, pub Arc<ManualClock>);
pub async fn pause(clock: &ManualClock) {
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    clock.advance(50);
}
impl<T: PackSink> PackSink for SlowSink<T> {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        pause(&self.1).await;
        self.0.write(chunk).await
    }
    async fn commit(self) -> Result<mkit_server::CommitOutcome, StoreError> {
        pause(&self.1).await;
        self.0.commit().await
    }
    async fn abort(self) {
        self.0.abort().await;
    }
}
impl mkit_server::MultipartBlobStore for Shared<MemoryBlobStore> {
    type PartSink = mkit_server::UnsupportedPartSink;
    const MAX_PARTS: u32 = <MemoryBlobStore as mkit_server::MultipartBlobStore>::MAX_PARTS;
}

pub type Pipeline =
    mkit_server::pipeline::Pipeline<Shared<MemoryBlobStore>, Slow, mkit_server::pipeline::Hooks>;
pub fn authenticate(
    pipe: &Pipeline,
    clock: &ManualClock,
    procedure: mkit_server::Procedure,
    nonce: u32,
) -> mkit_server::pipeline::Authenticated {
    use ed25519_dalek::{Signer, SigningKey};
    use mkit_core::{
        hash::{to_hex, to_hex_bytes},
        write_auth::{Context, Operation as SignedOp},
    };
    let owner = SigningKey::from_bytes(&[7; 32]);
    let namespace = mkit_core::repo_identity::Namespace::Ed25519(*owner.verifying_key().as_bytes());
    let identity = format!("{namespace}/slow-verification");
    let digest = to_hex(&hash(b"slow-verification"));
    let commitment = format!("body:{digest}");
    let nonce = format!("{nonce:064x}");
    let now = clock.now_ms();
    let expires = now + 300_000;
    let envelope = SignedOp {
        context: Context {
            audience: "https://verification.example",
            repository: &identity,
        },
        procedure: procedure.connect_path(),
        commitment: &commitment,
        created_at: now,
        expires_at: expires,
        nonce: &nonce,
    };
    let signature = owner.sign(&envelope.digest().unwrap());
    let headers = [
        ("x-envelope-version", "2".to_owned()),
        ("x-audience", "https://verification.example".to_owned()),
        ("x-repository", identity),
        ("x-public-key", to_hex(owner.verifying_key().as_bytes())),
        ("x-signature", to_hex_bytes(&signature.to_bytes())),
        ("x-content-commitment", commitment),
        ("x-digest", digest),
        ("x-created-at", now.to_string()),
        ("x-expires-at", expires.to_string()),
        ("idempotency-key", nonce),
    ];
    pipe.authenticate(&mkit_server::pipeline::RequestMeta {
        procedure,
        header: &|name| {
            headers
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        },
        header_values: None,
        unary_body: Some(b"slow-verification"),
        transport_principal: None,
    })
    .unwrap()
}
pub async fn upload(
    pipe: &Pipeline,
    blobs: &Shared<MemoryBlobStore>,
    clock: &ManualClock,
    bytes: Vec<u8>,
    nonce: u32,
) -> Hash {
    use mkit_server::BeginUploadResult;
    let pack = hash(&bytes);
    let auth = authenticate(pipe, clock, mkit_server::Procedure::BeginUpload, nonce);
    let BeginUploadResult::Ticket { id, .. } = pipe
        .begin_upload(&auth, "refs/heads/main", &pack, bytes.len() as u64)
        .await
        .unwrap()
    else {
        panic!("expected ticket")
    };
    let mut sink = blobs
        .begin(BlobKey::pack(pack), bytes.len() as u64)
        .await
        .unwrap();
    sink.write(Bytes::from(bytes)).await.unwrap();
    sink.commit().await.unwrap();
    // The normal upload adapter writes this content-addressed possession proof.
    let mut marker = b"mkit-upload-marker:v1\0".to_vec();
    marker.extend(id);
    marker.extend(pack);
    let mut sink = blobs
        .begin(BlobKey::upload_marker(hash(&marker)), marker.len() as u64)
        .await
        .unwrap();
    sink.write(Bytes::from(marker)).await.unwrap();
    sink.commit().await.unwrap();
    id
}

pub fn signed_commit(tree: Hash, parents: Vec<Hash>, seed: u8, message: &[u8]) -> (Object, Hash) {
    let key = KeyPair::from_seed([seed; 32]);
    let mut commit = Commit::new_unannotated(
        tree,
        parents,
        Identity::ed25519(key.public.0),
        key.public.0,
        message.to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &key).unwrap().0;
    let commit = Object::Commit(commit);
    let id = commit.id().unwrap();
    (commit, id)
}

pub fn blob(tag: u16, size: usize) -> (Hash, Vec<u8>) {
    let mut data = tag.to_be_bytes().to_vec();
    data.extend((0..size).map(|i| u8::try_from(i % 251).unwrap()));
    let object = Object::Blob(Blob { data });
    (object.id().unwrap(), serialize(&object).unwrap())
}

#[derive(Default)]
pub struct Ledger {
    pub by_class: std::collections::BTreeMap<String, u64>,
    pub calls: u64,
    pub inventory_reads: u64,
    pub inventory_applies: u64,
    pub cas_retries: u64,
    pub max_inventory_ops: usize,
    pub job_writes: u64,
    pub job_batches: u64,
    pub max_batch_ops: usize,
    pub max_batch_bytes: usize,
}
#[derive(Clone)]
pub struct Slow {
    pub inner: Arc<MemoryKv>,
    pub clock: Arc<ManualClock>,
    pub stages: Arc<AtomicU32>,
    pub fault: Option<&'static str>,
    pub barrier: Option<Arc<tokio::sync::Barrier>>,
    pub heads: Arc<AtomicU32>,
    pub ledger: Arc<Mutex<Ledger>>,
}
impl Slow {
    pub async fn pause_p(&self, p: Option<&Partition>) {
        {
            let mut l = self.ledger.lock().unwrap();
            l.calls += 1;
            *l.by_class
                .entry(p.map_or("none", |p| p.kind()).to_owned())
                .or_default() += 1;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        self.clock.advance(50);
    }
}
impl NamespaceStore for Slow {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, partition: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.pause_p(Some(partition)).await;
        if key
            .as_bytes()
            .windows(11)
            .any(|bytes| bytes == b"\0inventory\0")
            || key.as_bytes().ends_with(b"\0inventory-head")
        {
            self.ledger.lock().unwrap().inventory_reads += 1;
        }
        let value = self.inner.get(partition, key).await?;
        if key.as_bytes().ends_with(b"\0inventory-head")
            && let Some(barrier) = &self.barrier
            && self.heads.fetch_add(1, Ordering::SeqCst) < 2
        {
            barrier.wait().await;
        }
        Ok(value)
    }
    async fn get_many(
        &self,
        partition: &Partition,
        key: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.pause_p(Some(partition)).await;
        self.inner.get_many(partition, key).await
    }
    async fn scan_many(
        &self,
        partition: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        self.pause_p(Some(partition)).await;
        self.inner.scan_many(partition, ranges).await
    }
    async fn scan(
        &self,
        partition: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.pause_p(Some(partition)).await;
        self.inner.scan(partition, start, end, after, limit).await
    }
    async fn apply(&self, partition: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.pause_p(Some(partition)).await;
        batch.validate(&self.capabilities())?;
        {
            let mut ledger = self.ledger.lock().unwrap();
            let jobs = batch
                .writes
                .iter()
                .filter(|write| {
                    matches!(write,
                Write::Put(key, _) if matches!(keys::parse(key),
                    Some(keys::ParsedKey::VerifyCursor { sub: keys::VC_JOB, .. })))
                })
                .count();
            let jobs = u64::try_from(jobs).unwrap();
            ledger.job_writes += jobs;
            ledger.job_batches += u64::from(jobs > 0);
            ledger.max_batch_ops = ledger
                .max_batch_ops
                .max(batch.writes.len() + batch.preconditions.len());
            let bytes = batch
                .preconditions
                .iter()
                .map(|guard| match guard {
                    Precondition::Absent(key) | Precondition::Present(key) => key.as_bytes().len(),
                    Precondition::Equals(key, value) => {
                        key.as_bytes().len() + value.as_bytes().len()
                    }
                    Precondition::NotAfter(_) => 0,
                })
                .sum::<usize>()
                + batch
                    .writes
                    .iter()
                    .map(|write| match write {
                        Write::Put(key, value) => key.as_bytes().len() + value.as_bytes().len(),
                        Write::Delete(key) => key.as_bytes().len(),
                    })
                    .sum::<usize>();
            ledger.max_batch_bytes = ledger.max_batch_bytes.max(bytes);
        }
        let staging = batch.writes.iter().any(|write| {
            matches!(write, Write::Put(key, _) if key.as_bytes().windows(11)
                .any(|bytes| bytes == b"\0inventory\0"))
        });
        if staging {
            let mut ledger = self.ledger.lock().unwrap();
            ledger.inventory_applies += 1;
            ledger.max_inventory_ops = ledger
                .max_inventory_ops
                .max(batch.writes.len() + batch.preconditions.len());
        }
        if staging && (self.stages.fetch_add(1, Ordering::SeqCst) + 1).is_multiple_of(7) {
            match self.fault {
                Some("cas_contention") => {
                    return Ok(BatchOutcome::PreconditionFailed {
                        index: 0,
                        observed: None,
                    });
                }
                Some("expired") => self.clock.advance(10_001),
                Some("lost_reply") => {
                    assert_eq!(
                        self.inner.apply(partition, batch).await?,
                        BatchOutcome::Committed
                    );
                    return Err(StoreError::Unavailable("lost inventory apply reply".into()));
                }
                _ => {}
            }
        }
        let outcome = self.inner.apply(partition, batch).await?;
        if matches!(outcome, BatchOutcome::PreconditionFailed { .. }) {
            self.ledger.lock().unwrap().cas_retries += 1;
        }
        Ok(outcome)
    }
    async fn stats(&self, partition: &Partition) -> Result<PartitionStats, StoreError> {
        self.pause_p(Some(partition)).await;
        self.inner.stats(partition).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.pause_p(None).await;
        self.inner.probe().await
    }
}
pub struct Windows {
    pub blobs: Shared<MemoryBlobStore>,
}
impl PackWindows for Windows {
    fn read<'a>(
        &'a self,
        pack: &'a Hash,
        offset: u64,
        length: u64,
        etag: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Window, WindowError>> {
        Box::pin(async move {
            BlobWindows(&self.blobs)
                .read(pack, offset, length, etag)
                .await
        })
    }
}
#[derive(Default)]
pub struct Recorder {
    pub results: Mutex<Vec<(String, String, f64)>>,
    pub attempts: AtomicU32,
}
impl Metrics for Recorder {
    fn incr(&self, name: &'static str, labels: &[(&'static str, &str)], _: u64) {
        if name == mkit_server::telemetry::METRIC_VERIFICATION_PROGRESS
            && labels.contains(&("stage", "verify_fire"))
        {
            self.attempts.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn observe_ms(&self, _: &'static str, _: &[(&'static str, &str)], _: f64) {}
    fn gauge(&self, name: &'static str, labels: &[(&'static str, &str)], value: f64) {
        if name == mkit_server::telemetry::METRIC_INDEX_INVENTORY_ENTRIES {
            let get = |key| labels.iter().find(|(k, _)| *k == key).unwrap().1.to_owned();
            self.results
                .lock()
                .unwrap()
                .push((get("result"), get("progress"), value));
        }
    }
}
