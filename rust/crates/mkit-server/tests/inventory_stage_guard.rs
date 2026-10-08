//! Full scheduled verification with storage I/O advancing the business clock.
#![cfg(feature = "memory")]
#![allow(clippy::unwrap_used)]
use bytes::Bytes;
use mkit_core::{
    hash::{Hash, hash},
    object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry},
    pack::PackWriter,
    serialize::serialize,
    sign::{KeyPair, sign_commit},
};
use mkit_server::{
    Batch, BatchOutcome, BlobBody, BlobKey, BlobMeta, BlobStore, BoxFuture, ByteRange, Clock,
    Cursor, Key, ManualClock, MemoryBlobStore, MemoryKv, Metrics, NamespaceKey, NamespaceStore,
    PackSink, Partition, PartitionStats, Precondition, RangeScan, RepoId, RepoName, ScanPage,
    StoreCapabilities, StoreError, Value, Write,
};
use mkit_server::{
    indexed::{
        self, IndexedConfig,
        budget::{BlobWindows, PackWindows, Window, WindowError},
        checkpoint::{self, Phase},
        job::{FailClosedExtraction, SliceLimits, VerifyTimer},
    },
    pipeline::{D34Shards, LeaseParams, ShardMap},
    store::adapter_spi::keys,
    timers::{TickBudget, TimerRegistry, run_due},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU32, Ordering},
};
struct Shared<T>(Arc<T>, Arc<ManualClock>);

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

struct SlowSink<T>(T, Arc<ManualClock>);
async fn pause(clock: &ManualClock) {
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

type Pipeline =
    mkit_server::pipeline::Pipeline<Shared<MemoryBlobStore>, Slow, mkit_server::pipeline::Hooks>;
fn authenticate(
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
async fn upload(
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

fn signed_commit(tree: Hash, parents: Vec<Hash>, seed: u8, message: &[u8]) -> (Object, Hash) {
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

fn blob(tag: u16, size: usize) -> (Hash, Vec<u8>) {
    let mut data = tag.to_be_bytes().to_vec();
    data.extend((0..size).map(|i| u8::try_from(i % 251).unwrap()));
    let object = Object::Blob(Blob { data });
    (object.id().unwrap(), serialize(&object).unwrap())
}

/// A pack of `count` blobs of `size` bytes, a tree naming them and a signed
/// commit on it. Returns the pack, its head, the tree and the blob ids.
fn tree_pack(count: u16, size: usize) -> (Vec<u8>, Hash) {
    let mut writer = PackWriter::new_raw_only();
    let mut entries = Vec::new();
    for n in 0..count {
        let (id, raw) = blob(n, size);
        writer.push_raw(id, &raw).unwrap();
        entries.push(TreeEntry {
            name: format!("f{n:05}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: id,
        });
    }
    let tree = Object::Tree(Tree { entries });
    writer
        .push_raw(tree.id().unwrap(), &serialize(&tree).unwrap())
        .unwrap();
    let (commit, head) = signed_commit(tree.id().unwrap(), Vec::new(), 7, b"head");
    writer.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    (writer.finish().unwrap(), head)
}

#[derive(Default)]
struct Ledger {
    calls: u64,
    job_writes: u64,
    job_batches: u64,
    max_batch_ops: usize,
    max_batch_bytes: usize,
}
#[derive(Clone)]
struct Slow {
    inner: Arc<MemoryKv>,
    clock: Arc<ManualClock>,
    stages: Arc<AtomicU32>,
    fault: Option<&'static str>,
    barrier: Option<Arc<tokio::sync::Barrier>>,
    heads: Arc<AtomicU32>,
    ledger: Arc<Mutex<Ledger>>,
}
impl Slow {
    async fn pause(&self) {
        self.ledger.lock().unwrap().calls += 1;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        self.clock.advance(50);
    }
}
impl NamespaceStore for Slow {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, partition: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.pause().await;
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
        self.pause().await;
        self.inner.get_many(partition, key).await
    }
    async fn scan_many(
        &self,
        partition: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        self.pause().await;
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
        self.pause().await;
        self.inner.scan(partition, start, end, after, limit).await
    }
    async fn apply(&self, partition: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.pause().await;
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
        if staging && (self.stages.fetch_add(1, Ordering::SeqCst) + 1).is_multiple_of(7) {
            match self.fault {
                Some("cas_contention") => {
                    return Ok(BatchOutcome::PreconditionFailed {
                        index: 0,
                        observed: None,
                    });
                }
                Some("expired") => self.clock.advance(10_001),
                _ => {}
            }
        }
        self.inner.apply(partition, batch).await
    }
    async fn stats(&self, partition: &Partition) -> Result<PartitionStats, StoreError> {
        self.pause().await;
        self.inner.stats(partition).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.pause().await;
        self.inner.probe().await
    }
}
struct Windows {
    blobs: Shared<MemoryBlobStore>,
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
struct Recorder {
    results: Mutex<Vec<(String, String, f64)>>,
    attempts: AtomicU32,
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
#[allow(clippy::too_many_lines)] // Keep the full alarm-driven fixture and progress assertions together.
async fn verifies(objects: u16, fault: Option<&'static str>) {
    let clock = Arc::new(ManualClock::new(1_700_000_000_000));
    let inner = Arc::new(MemoryKv::with_clock(clock.clone()));
    let store = Slow {
        inner: inner.clone(),
        clock: clock.clone(),
        stages: Arc::default(),
        fault,
        barrier: None,
        heads: Arc::default(),
        ledger: Arc::default(),
    };
    let blobs = Shared(Arc::new(MemoryBlobStore::default()), clock.clone());
    let (bytes, head) = tree_pack(objects - 2, 8);
    let pack = hash(&bytes);
    let owner = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let namespace = mkit_core::repo_identity::Namespace::Ed25519(*owner.verifying_key().as_bytes());
    let repo = RepoId {
        namespace: NamespaceKey::from_namespace(&namespace),
        name: RepoName::new("slow-verification").unwrap(),
    };
    let shards: Arc<dyn ShardMap> = Arc::new(D34Shards);
    let source = shards.ref_shard(&repo, "refs/heads/main");
    let cfg = IndexedConfig::scheduled(1 << 30);
    let recorder = Arc::new(Recorder::default());
    let mut pipeline_cfg = mkit_server::pipeline::PipelineConfig::new(
        mkit_server::Addressing::Multi(mkit_server::MultiAddressing::new().with_namespace_policy(
            mkit_server::policy::NamespacePolicy::Allowlist([namespace].into()),
        )),
        mkit_server::pipeline::AuthMode::AuthV2(
            mkit_server::auth_v2::AuthV2Config::new(
                "https://verification.example",
                "slow-verification",
            )
            .unwrap(),
        ),
        mkit_server::upload::UploadLimits::new(1 << 30, 64),
    );
    pipeline_cfg.begin_upload_threshold_bytes = 0;
    pipeline_cfg.write_policy = mkit_server::policy::WritePolicy::Owner;
    pipeline_cfg.sharding = mkit_server::pipeline::Sharding::D34;
    pipeline_cfg.indexed = Some(cfg);
    pipeline_cfg.ticket_keys =
        Some(mkit_server::upload::token::TicketKeys::new(vec![("test".into(), [7; 32])]).unwrap());
    let pipe = Pipeline::new(
        blobs.clone(),
        store.clone(),
        mkit_server::pipeline::Hooks::new(),
        pipeline_cfg,
        clock.clone(),
        recorder.clone(),
    )
    .unwrap();
    let started = clock.now_ms();
    let packmap_bytes = mkit_core::transfer::encode_packlist(None, &[pack]).unwrap();
    let map = hash(&packmap_bytes);
    let tickets = vec![
        upload(&pipe, &blobs, &clock, bytes, 1).await,
        upload(&pipe, &blobs, &clock, packmap_bytes, 2).await,
    ];
    let advance = |name: &str, id| mkit_server::RefUpdate {
        name: name.into(),
        condition: mkit_core::refs::RefWriteCondition::Missing,
        new: Some(id),
    };
    let auth = authenticate(&pipe, &clock, mkit_server::Procedure::AdvanceRefs, 3);
    let error = pipe
        .advance_refs_with_tickets(
            &auth,
            advance("refs/heads/main", head),
            advance("refs/mkit/packmap/main", map),
            tickets.clone(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.public_message(), "pack verification pending");
    let handler = VerifyTimer {
        remote: store.clone(),
        blobs: blobs.clone(),
        windows: Windows {
            blobs: blobs.clone(),
        },
        shards,
        cfg,
        limits: SliceLimits::default(),
        lease: LeaseParams::default(),
        clock: clock.clone(),
        metrics: recorder.clone(),
        extension: FailClosedExtraction,
    };
    let registry =
        TimerRegistry::new()
            .register(handler)
            .register(mkit_server::relay::RelayHandler {
                target: store.clone(),
                hook: mkit_server::relay::NoHook,
                budget: mkit_server::relay::RelayBudget::default(),
            });
    let mut waits = 0;
    let mut failed_waits = 0;
    let mut max_jobs = 0;
    let mut failures = 0;
    let mut previous_entries = 0;
    for attempt in 1_u32..=1024 {
        let now = u64::try_from(clock.now_ms()).unwrap();
        let before_jobs = store.ledger.lock().unwrap().job_writes;
        let report = run_due(
            &store,
            &source,
            &registry,
            clock.as_ref(),
            now,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        max_jobs = max_jobs.max(store.ledger.lock().unwrap().job_writes - before_jobs);
        let (job, state) = checkpoint::read_job(inner.as_ref(), &source, &repo.name, &pack)
            .await
            .unwrap();
        let job = job.unwrap().0;
        if report.failed > 0 {
            assert!(
                fault.is_some(),
                "{objects} objects: attempt {attempt}, phase {:?}, durable entries {}",
                job.phase,
                job.entries
            );
            assert_eq!(job.phase, Phase::Decode);
            assert!(
                job.entries > previous_entries,
                "retry failed without strictly more durable progress"
            );
            failures += report.failed;
        }
        assert!(job.entries >= previous_entries, "durable cursor regressed");
        previous_entries = job.entries;
        let map_ready = checkpoint::read_job(inner.as_ref(), &source, &repo.name, &map)
            .await
            .unwrap()
            .0
            .is_some_and(|(job, _)| job.usable());
        if job.phase == Phase::Watch && map_ready {
            assert!(job.usable(), "verification outcome: {:?}", job.outcome);
            assert!(matches!(
                state,
                Some((indexed::state::VerificationV1::Verified { .. }, _))
            ));
            assert_eq!(job.entries, u64::from(objects));
            if let Some(label) = fault {
                assert!(failures > 1, "fault test must exercise repeated retry");
                assert!(
                    recorder
                        .results
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|(r, p, v)| r == label && p == "checkpointed" && *v > 0.0)
                );
            }
            eprintln!(
                "{objects} objects completed in {} verification timer fires, {attempt} alarm ticks ({failures} failed retries); entries={}",
                recorder.attempts.load(Ordering::SeqCst),
                job.entries
            );
            let auth = authenticate(&pipe, &clock, mkit_server::Procedure::AdvanceRefs, 4);
            assert_eq!(
                pipe.advance_refs_with_tickets(
                    &auth,
                    advance("refs/heads/main", head),
                    advance("refs/mkit/packmap/main", map),
                    tickets.clone()
                )
                .await
                .unwrap(),
                mkit_core::protocol::AdvanceOutcome::Committed
            );
            let mut publication_ticks = 0;
            loop {
                let auth = authenticate(&pipe, &clock, mkit_server::Procedure::ListRefs, 5);
                let refs = pipe.list_refs(&auth, "refs/heads/").await.unwrap();
                if refs
                    .iter()
                    .any(|entry| entry.name == "main" && entry.id == head)
                {
                    break;
                }
                publication_ticks += 1;
                assert!(publication_ticks < 10);
                run_due(
                    &store,
                    &source,
                    &registry,
                    clock.as_ref(),
                    u64::try_from(clock.now_ms()).unwrap(),
                    &TickBudget::default(),
                )
                .await
                .unwrap();
            }
            let results = recorder.results.lock().unwrap();
            let checkpoints: f64 = results
                .iter()
                .filter(|(_, progress, _)| progress == "checkpointed")
                .map(|(_, _, value)| *value)
                .sum();
            let max_checkpoints = results
                .iter()
                .filter(|(_, progress, _)| progress == "checkpointed")
                .map(|(_, _, value)| *value)
                .fold(0.0_f64, f64::max);
            let ledger = store.ledger.lock().unwrap();
            assert!((checkpoints - f64::from(objects)).abs() < f64::EPSILON);
            let elapsed = clock.now_ms() - started;
            if fault.is_none() {
                assert_eq!(failures, 0);
                assert_eq!(failed_waits, 0);
                // Successful slices have no fixed alarm cadence or retry backoff.
                // Allow one delivery wait, plus the driver's immediate wake ticks.
                assert!(waits <= u64::from(attempt) * 2 + 2_000);
                assert!(elapsed <= i64::from(objects) * 700 + 20_000);
            }
            eprintln!(
                "CHECKPOINTS objects={objects} entries={checkpoints} max_per_slice={max_checkpoints}"
            );
            eprintln!(
                "LEDGER objects={objects} publication_ticks={publication_ticks} elapsed_ms={} waits_ms={waits} failed_waits_ms={failed_waits} calls={} job_writes={} max_jobs_tick={max_jobs} max_ops={} max_bytes={}",
                elapsed,
                ledger.calls,
                ledger.job_writes,
                ledger.max_batch_ops,
                ledger.max_batch_bytes
            );
            return;
        }
        let next = report
            .next_wake_ms
            .unwrap_or(now + 1_000)
            .max(u64::try_from(clock.now_ms()).unwrap() + 1);
        let wait = next - u64::try_from(clock.now_ms()).unwrap();
        waits += wait;
        if report.failed > 0 {
            failed_waits += wait;
        }
        clock.set(i64::try_from(next).unwrap());
    }
    panic!("{objects} objects exceeded 1024 alarm ticks");
}
#[tokio::test(start_paused = true)]
async fn decode_inventory_500_objects_at_50ms() {
    Box::pin(verifies(500, None)).await;
}
#[tokio::test(start_paused = true)]
#[ignore = "large scheduled verification; exercised by the ignored-lane CI profile"]
async fn decode_inventory_3000_objects_at_50ms() {
    Box::pin(verifies(3000, None)).await;
}

#[tokio::test(start_paused = true)]
async fn decode_retries_checkpoint_strict_progress_after_cas_contention() {
    Box::pin(verifies(50, Some("cas_contention"))).await;
}
#[tokio::test(start_paused = true)]
async fn decode_retries_checkpoint_strict_progress_after_expiry() {
    Box::pin(verifies(50, Some("expired"))).await;
}

#[tokio::test(start_paused = true)]
async fn concurrent_inventory_stagers_keep_cas_and_distinct_expiry() {
    use mkit_server::takedown::inventory::{self, StagingFailure};
    let clock = Arc::new(ManualClock::new(0));
    let inner = Arc::new(MemoryKv::with_clock(clock.clone()));
    let store = Slow {
        inner: inner.clone(),
        clock: clock.clone(),
        stages: Arc::default(),
        fault: None,
        barrier: Some(Arc::new(tokio::sync::Barrier::new(2))),
        heads: Arc::default(),
        ledger: Arc::default(),
    };
    let pack = [7; 32];
    let a = Object::Blob(Blob { data: vec![1] });
    let b = Object::Blob(Blob { data: vec![2] });
    let aid = a.id().unwrap();
    let bid = b.id().unwrap();
    let (left, right, reads) = tokio::join!(
        inventory::stage(&store, &pack, 100, &aid, &a, None, 0),
        inventory::stage(&store, &pack, 100, &bid, &b, None, 0),
        async {
            for _ in 0..32 {
                inventory::entry(&store, &pack, &aid).await.unwrap();
                inventory::entry(&store, &pack, &bid).await.unwrap();
            }
            64
        }
    );
    assert_eq!(reads, 64);
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let failed = left.as_ref().err().or(right.as_ref().err()).unwrap();
    let StoreError::Unavailable(source) = failed else {
        panic!("expected typed contention")
    };
    assert!(matches!(
        source.downcast_ref::<StagingFailure>(),
        Some(StagingFailure::CasContention { index: 0 })
    ));
    inventory::stage(&store, &pack, 100, &aid, &a, None, 0)
        .await
        .unwrap();
    inventory::stage(&store, &pack, 100, &bid, &b, None, 0)
        .await
        .unwrap();
    inventory::complete(&store, &pack, 100, 0).await.unwrap();
    let mut ids = std::collections::BTreeSet::new();
    inventory::visit(inner.as_ref(), &pack, false, |id, _| {
        ids.insert(id);
        async { Ok(false) }
    })
    .await
    .unwrap();
    assert_eq!(ids, std::collections::BTreeSet::from([aid, bid]));
    clock.advance(10_001);
    let failure = inventory::stage(&store, &[8; 32], 100, &aid, &a, None, 0)
        .await
        .unwrap_err();
    let StoreError::Unavailable(source) = failure else {
        panic!("expected typed expiry")
    };
    assert!(matches!(
        source.downcast_ref::<StagingFailure>(),
        Some(StagingFailure::Expired { .. })
    ));
}
