//! Actual inline-verification calls at the ordinary index-batch boundary.
//! This probe creates no fork. Run the identical file on both revisions;
//! its output records measured calls rather than a copied batching algorithm.
#![cfg(feature = "memory")]
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
mod fork_support;
use fork_support::{blob, signed_commit, tree_pack};
use mkit_core::hash::{Hash, hash};
use mkit_core::object::{EntryMode, Object, Tree, TreeEntry};
use mkit_core::pack::PackWriter;
use mkit_core::serialize::serialize;
use mkit_server::indexed::{IndexedConfig, verify::verify_ticketed};
use mkit_server::pipeline::{D34Shards, ShardMap, SinglePartition};
use mkit_server::store::adapter_spi::{codec::TicketV1, keys};
use mkit_server::{
    Batch, BatchOutcome, BlobKey, BlobStore, Clock as _, Cursor, Key, ManualClock, MemoryBlobStore,
    MemoryKv, NamespaceKey, NamespaceStore, PackSink, Partition, PartitionStats, RangeScan, RepoId,
    RepoName, ScanPage, StoreCapabilities, StoreError, Value, Write,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

const ROUND_MS: u64 = 5;
const NOW: i64 = 1_700_000_000_000;

struct Measured {
    inner: MemoryKv,
    reserve: usize,
    calls: AtomicU64,
    index_batches: Mutex<Vec<(Partition, usize, usize)>>,
}

impl Measured {
    async fn call(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(ROUND_MS)).await;
    }
}

impl NamespaceStore for Measured {
    fn capabilities(&self) -> StoreCapabilities {
        let mut caps = self.inner.capabilities();
        caps.reserved_batch_ops = self.reserve;
        caps
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.call().await;
        self.inner.get(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.call().await;
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
        self.call().await;
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn scan_many(
        &self,
        p: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        self.call().await;
        self.inner.scan_many(p, ranges).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.call().await;
        batch.validate(&self.capabilities())?;
        let index_rows = batch.writes.iter().filter(|write| matches!(write,
            Write::Put(key, _) if matches!(keys::parse(key), Some(keys::ParsedKey::ObjectIndex { .. })))).count();
        if index_rows > 0 {
            self.index_batches.lock().unwrap().push((
                p.clone(),
                index_rows,
                batch.preconditions.len() + batch.writes.len(),
            ));
        }
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.call().await;
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

/// All requested blob rows land in `RepoIndex` prefix zero. Tree and commit
/// deliberately land elsewhere so they cannot move the measured boundary.
fn one_prefix_pack(rows: u32) -> (Vec<u8>, Hash) {
    let mut writer = PackWriter::new_raw_only();
    let mut entries = Vec::new();
    for tag in 0_u32..100_000 {
        let (id, raw) = blob(tag, 8);
        if id[0] >> 4 != 0 {
            continue;
        }
        writer.push_raw(id, &raw).unwrap();
        entries.push(TreeEntry {
            name: format!("f{:06}", entries.len()).into_bytes(),
            mode: EntryMode::Blob,
            object_hash: id,
        });
        if entries.len() == usize::try_from(rows).unwrap() {
            break;
        }
    }
    assert_eq!(entries.len(), usize::try_from(rows).unwrap());
    let tree = (0..100)
        .find_map(|salt| {
            let mut entries = entries.clone();
            entries[0].name = format!("a{salt:06}").into_bytes();
            let tree = Object::Tree(Tree { entries });
            (tree.id().unwrap()[0] >> 4 != 0).then_some(tree)
        })
        .unwrap();
    let tree_id = tree.id().unwrap();
    writer
        .push_raw(tree_id, &serialize(&tree).unwrap())
        .unwrap();
    let (commit, head) = (0_u32..100)
        .find_map(|salt| {
            let pair = signed_commit(tree_id, vec![], 7, &salt.to_be_bytes());
            (pair.1[0] >> 4 != 0).then_some(pair)
        })
        .unwrap();
    writer.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    (writer.finish().unwrap(), head)
}

#[tokio::test(start_paused = true)]
async fn ordinary_inline_index_boundary_reports_actual_calls() {
    for sharded in [false, true] {
        for reserve in [0, 3] {
            for objects in [95_u32, 96, 97, 192] {
                let clock = Arc::new(ManualClock::new(NOW));
                let store = Measured {
                    inner: MemoryKv::with_clock(clock.clone()),
                    reserve,
                    calls: AtomicU64::new(0),
                    index_batches: Mutex::default(),
                };
                let blobs = MemoryBlobStore::default();
                let repo = RepoId {
                    namespace: NamespaceKey::deployment_default(),
                    name: RepoName::new("ordinary").unwrap(),
                };
                let (bytes, head) = if sharded {
                    one_prefix_pack(objects)
                } else {
                    let (bytes, head, _) =
                        tree_pack(objects - 2, 8, 0, vec![], b"ordinary index cost");
                    (bytes, head)
                };
                let shards: &dyn ShardMap = if sharded {
                    &D34Shards
                } else {
                    &SinglePartition
                };
                let pack = hash(&bytes);
                let ticket = TicketV1 {
                    authority_generation: None,
                    repo: repo.name.clone(),
                    ref_name: "refs/heads/main".into(),
                    signer: [3; 32],
                    pack_id: pack,
                    bytes: bytes.len() as u64,
                    part_size: 1 << 20,
                    expires_at_ms: u64::try_from(NOW).unwrap() + 300_000,
                    created_at_ms: u64::try_from(NOW).unwrap(),
                    reservation_id: "s:ordinary-cost".into(),
                    upload_session: None,
                };
                let mut sink = blobs
                    .begin(BlobKey::pack(pack), bytes.len() as u64)
                    .await
                    .unwrap();
                sink.write(bytes::Bytes::from(bytes)).await.unwrap();
                sink.commit().await.unwrap();
                let source = shards.ref_shard(&repo, "refs/heads/main");
                let target = shards.object_index(&repo, &[0; 32]);
                let started = tokio::time::Instant::now();
                let result = verify_ticketed(
                    &blobs,
                    &store,
                    shards,
                    &repo,
                    &source,
                    &[ticket],
                    &[hash(&pack)],
                    head,
                    IndexedConfig::default(),
                    false,
                    clock.as_ref(),
                    &mkit_server::NoopMetrics,
                )
                .await;
                assert!(
                    result.is_ok(),
                    "reserve={reserve} objects={objects}: {result:?}"
                );
                let elapsed = started.elapsed().as_millis();
                let batches = store.index_batches.lock().unwrap().clone();
                assert_eq!(
                    batches.iter().map(|(_, rows, _)| *rows).sum::<usize>(),
                    usize::try_from(objects + if sharded { 2 } else { 0 }).unwrap()
                );
                assert!(
                    batches
                        .iter()
                        .all(|(_, _, ops)| *ops + reserve <= mkit_server::store::MAX_BATCH_OPS)
                );
                let revision = store
                    .inner
                    .get(&target, &Key::new(b"fv\0".to_vec()))
                    .await
                    .unwrap();
                let target_batches: Vec<_> = batches
                    .iter()
                    .filter(|(partition, _, _)| partition == &target)
                    .map(|(_, rows, ops)| (*rows, *ops))
                    .collect();
                assert_eq!(
                    target_batches.iter().map(|(rows, _)| *rows).sum::<usize>(),
                    usize::try_from(objects).unwrap()
                );
                println!(
                    "NONFORK_INDEX_COST sharded={sharded} reserve={reserve} target_rows={objects} kv_calls={} virtual_ms={elapsed} target_index_applies={} target_rows_and_ops={target_batches:?} all_index_applies={} revision_present={}",
                    store.calls.load(Ordering::SeqCst),
                    target_batches.len(),
                    batches.len(),
                    revision.is_some()
                );
                assert_eq!(
                    clock.now_ms(),
                    NOW,
                    "virtual latency must not consume business-time leases"
                );
            }
        }
    }
}
