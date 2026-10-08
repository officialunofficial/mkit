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
    PackSink, Partition, PartitionStats, RangeScan, RepoId, RepoName, ScanPage, StoreCapabilities,
    StoreError, Value, Write,
};
use mkit_server::{
    indexed::{
        self, IndexedConfig, VerificationMode,
        budget::{BlobWindows, PackWindows, Window, WindowError},
        checkpoint::{self, Phase},
        job::{FailClosedExtraction, SliceLimits, VerifyTimer},
    },
    pipeline::{D34Shards, LeaseParams, ShardMap},
    store::adapter_spi::{
        codec::{self, TicketV1},
        keys, tickets,
    },
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
    type Sink = T::Sink;
    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        self.1.advance(50);
        self.0.begin(key, len).await
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

#[derive(Clone)]
struct Slow {
    inner: Arc<MemoryKv>,
    clock: Arc<ManualClock>,
    stages: Arc<AtomicU32>,
    fault: Option<&'static str>,
    barrier: Option<Arc<tokio::sync::Barrier>>,
    heads: Arc<AtomicU32>,
}
impl Slow {
    async fn pause(&self) {
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
    };
    let blobs = Arc::new(MemoryBlobStore::default());
    let (bytes, _) = tree_pack(objects - 2, 8);
    let pack = hash(&bytes);
    let mut sink = blobs
        .begin(BlobKey::pack(pack), bytes.len() as u64)
        .await
        .unwrap();
    sink.write(Bytes::from(bytes.clone())).await.unwrap();
    sink.commit().await.unwrap();
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("slow-verification").unwrap(),
    };
    let shards: Arc<dyn ShardMap> = Arc::new(D34Shards);
    let source = shards.ref_shard(&repo, "refs/heads/main");
    let ticket = TicketV1 {
        authority_generation: None,
        repo: repo.name.clone(),
        ref_name: "refs/heads/main".into(),
        signer: [3; 32],
        pack_id: pack,
        bytes: bytes.len() as u64,
        part_size: 8 << 20,
        expires_at_ms: 1_700_086_400_000,
        created_at_ms: 1_700_000_000_000,
        reservation_id: "slow:1".into(),
        upload_session: None,
    };
    let id = tickets::ticket_id(&ticket.reservation_id);
    inner
        .apply(
            &source,
            Batch::new().put(keys::ticket(&id), codec::encode_ticket(&ticket)),
        )
        .await
        .unwrap();
    indexed::scheduled::create_job(
        inner.as_ref(),
        &source,
        &repo,
        &ticket,
        id,
        clock.as_ref(),
        None,
    )
    .await
    .unwrap();
    let mut cfg = IndexedConfig::default();
    cfg.verification = VerificationMode::Scheduled;
    let recorder = Arc::new(Recorder::default());
    let handler = VerifyTimer {
        remote: store.clone(),
        blobs: Shared(blobs.clone(), clock.clone()),
        windows: Windows {
            blobs: Shared(blobs, clock.clone()),
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
    let mut failures = 0;
    let mut previous_entries = 0;
    for attempt in 1..=1024 {
        let now = u64::try_from(clock.now_ms()).unwrap();
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
        if job.phase == Phase::Watch {
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
                "{objects} objects completed in {} verification attempts, {attempt} alarm ticks ({failures} failures); entries={}",
                recorder.attempts.load(Ordering::SeqCst),
                job.entries
            );
            return;
        }
        let next = report
            .next_wake_ms
            .unwrap_or(now + 1_000)
            .max(u64::try_from(clock.now_ms()).unwrap() + 1);
        clock.set(i64::try_from(next).unwrap());
    }
    panic!("{objects} objects exceeded 1024 alarm ticks");
}
#[tokio::test(start_paused = true)]
async fn decode_inventory_500_objects_at_50ms() {
    verifies(500, None).await;
}
#[tokio::test(start_paused = true)]
#[ignore = "large scheduled verification; exercised by the ignored-lane CI profile"]
async fn decode_inventory_3000_objects_at_50ms() {
    verifies(3000, None).await;
}

#[tokio::test(start_paused = true)]
async fn decode_retries_checkpoint_strict_progress_after_cas_contention() {
    verifies(50, Some("cas_contention")).await;
}
#[tokio::test(start_paused = true)]
async fn decode_retries_checkpoint_strict_progress_after_expiry() {
    verifies(50, Some("expired")).await;
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
    };
    let pack = [7; 32];
    let a = Object::Blob(Blob { data: vec![1] });
    let b = Object::Blob(Blob { data: vec![2] });
    let aid = a.id().unwrap();
    let bid = b.id().unwrap();
    let (left, right) = tokio::join!(
        inventory::stage(&store, &pack, 100, &aid, &a, None, 0),
        inventory::stage(&store, &pack, 100, &bid, &b, None, 0)
    );
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
