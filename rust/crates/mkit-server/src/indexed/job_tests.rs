//! The kind-7 slice machine and the advance's scheduled check, over the
//! memory stores, a `ManualClock` and a fake R2 that counts its calls.
#![allow(clippy::unwrap_used)] // Fixtures and assertions fail the test on invalid setup.

use bytes::Bytes;
use futures_executor::block_on;
use mkit_core::hash::{Hash, hash};
use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::pack::{DecodeLimits, NoExternalBases, PackWriter, decode_entries_with};
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use super::budget::{BlobWindows, PackWindows, Window, WindowError};
use super::checkpoint::{Kind, Phase, VerifyJobV1, decode_job};
use super::entries::{FrameMeta, index_entries};
use super::job::{FailClosedExtraction, SliceLimits, VerifyTimer};
use super::state::VerificationV1;
use super::{IndexedConfig, VerificationMode, scheduled};
use crate::memory::{MemoryBlobStore, MemoryKv};
use crate::pipeline::{D34Shards, LeaseParams, ShardMap, SinglePartition};
use crate::repo::{NamespaceKey, RepoId, RepoName};
use crate::rt::{BoxFuture, Clock, ManualClock};
use crate::store::{
    Batch, BatchOutcome, BlobKey, BlobMeta, BlobStore, ByteRange, Cursor, Key, NamespaceStore,
    PackSink, Partition, PartitionStats, RangeScan, ScanPage, StoreCapabilities, StoreError, Value,
    codec::{self, TicketV1},
    keys, tickets,
};
use crate::telemetry::Metrics;
use crate::timers::{RunReport, TickBudget, TimerRegistry, run_due};

pub(super) const NOW: i64 = 1_700_000_000_000;
const WINDOW: u64 = 64 << 10;

// -- shared handles ---------------------------------------------------------

struct Shared<T>(Arc<T>);

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T: NamespaceStore> NamespaceStore for Shared<T> {
    fn capabilities(&self) -> StoreCapabilities {
        self.0.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.0.get(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.0.get_many(p, keys).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.0.scan(p, start, end, after, limit).await
    }
    async fn scan_many(
        &self,
        p: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        self.0.scan_many(p, ranges).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.0.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.0.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.0.probe().await
    }
}

impl<T: BlobStore> BlobStore for Shared<T> {
    type Sink = T::Sink;
    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.0.begin(key, len).await
    }
    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<crate::BlobBody>, StoreError> {
        self.0.get(key, range).await
    }
    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.0.head(key).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.0.probe().await
    }
    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.0.delete(key).await
    }
}

/// A store whose n-th `apply` fails once, as a killed or contended slice does.
struct Faulty {
    inner: Arc<MemoryKv>,
    applies: AtomicU32,
    fail_at: AtomicU32,
    inventory_guard: Option<(RepoName, Hash, BTreeSet<Hash>)>,
}

impl NamespaceStore for Faulty {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(p, key).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        if let Some((repo, pack, expected)) = &self.inventory_guard {
            let key = keys::verification(repo, pack);
            if batch.writes.iter().any(|write| {
                matches!(write,
                crate::store::Write::Put(k, value) if k == &key
                    && matches!(super::state::decode(value), Ok(VerificationV1::Verified { .. })))
            }) {
                let mut rows = BTreeSet::new();
                assert!(
                    !crate::takedown::inventory::visit(
                        self.inner.as_ref(),
                        pack,
                        false,
                        |id, _| {
                            assert!(rows.insert(id));
                            async { Ok(false) }
                        }
                    )
                    .await?
                );
                assert_eq!(&rows, expected, "Verified preceded the complete inventory");
            }
        }
        let n = self.applies.fetch_add(1, Ordering::SeqCst) + 1;
        if n == self.fail_at.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable("injected fault".into()));
        }
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

/// Window reads with a call counter, a movable etag and injectable damage.
#[derive(Default)]
struct Windows {
    blobs: Arc<MemoryBlobStore>,
    reads: AtomicU32,
    etag: Mutex<u32>,
    flip_after: Mutex<Option<u32>>,
    source: Mutex<Option<Hash>>,
    /// `(offset, reads to let pass first, once)`: flip a byte at `offset`.
    corrupt: Mutex<Option<(u64, u32, bool)>>,
    fail: Mutex<bool>,
}

impl PackWindows for Arc<Windows> {
    fn read<'a>(
        &'a self,
        pack: &'a Hash,
        offset: u64,
        len: u64,
        etag: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Window, WindowError>> {
        Box::pin(async move {
            let n = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
            if *self.fail.lock().unwrap() {
                return Err(WindowError::Unavailable);
            }
            if self
                .flip_after
                .lock()
                .unwrap()
                .is_some_and(|after| n > after)
            {
                *self.etag.lock().unwrap() += 1;
                *self.flip_after.lock().unwrap() = None;
            }
            let current = format!("etag-{}", self.etag.lock().unwrap());
            if etag.is_some_and(|expected| expected != current) {
                return Err(WindowError::EtagChanged);
            }
            let source = self.source.lock().unwrap().unwrap_or(*pack);
            let mut window = BlobWindows(self.blobs.as_ref())
                .read(&source, offset, len, None)
                .await?;
            let mut corrupt = self.corrupt.lock().unwrap();
            if let Some((at, after, once)) = *corrupt
                && n > after
                && (offset..offset + len).contains(&at)
            {
                let i = usize::try_from(at - offset).unwrap();
                window.bytes[i] ^= 0x40;
                if once {
                    *corrupt = None;
                }
            }
            window.etag = current;
            Ok(window)
        })
    }
}

/// Metrics that keep the per-slice subrequest gauge.
#[derive(Default)]
struct Recorder {
    slices: Mutex<Vec<f64>>,
}

impl Metrics for Recorder {
    fn incr(&self, _: &'static str, _: &[(&'static str, &str)], _: u64) {}
    fn observe_ms(&self, _: &'static str, _: &[(&'static str, &str)], _: f64) {}
    fn gauge(&self, name: &'static str, _: &[(&'static str, &str)], value: f64) {
        if name == crate::telemetry::METRIC_INDEX_SLICE_SUBREQUESTS {
            self.slices.lock().unwrap().push(value);
        }
    }
}

// -- fixtures ---------------------------------------------------------------

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

/// One repository over the memory stores.
struct Rig {
    blobs: Arc<MemoryBlobStore>,
    store: Arc<MemoryKv>,
    clock: Arc<ManualClock>,
    windows: Arc<Windows>,
    recorder: Arc<Recorder>,
    shards: Arc<dyn ShardMap>,
    repo: RepoId,
    cfg: IndexedConfig,
    limits: SliceLimits,
    tickets: Mutex<u32>,
}

impl Rig {
    fn new() -> Self {
        Self::named("one", Arc::new(SinglePartition))
    }

    fn named(name: &str, shards: Arc<dyn ShardMap>) -> Self {
        let clock = Arc::new(ManualClock::new(NOW));
        let blobs = Arc::new(MemoryBlobStore::default());
        Self {
            windows: Arc::new(Windows {
                blobs: blobs.clone(),
                ..Windows::default()
            }),
            blobs,
            store: Arc::new(MemoryKv::with_clock(clock.clone())),
            clock,
            recorder: Arc::default(),
            shards,
            repo: RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: RepoName::new(name).unwrap(),
            },
            cfg: IndexedConfig {
                verification: VerificationMode::Scheduled,
                ..IndexedConfig::default()
            },
            limits: SliceLimits {
                window_bytes: WINDOW,
                ..SliceLimits::default()
            },
            tickets: Mutex::new(0),
        }
    }

    fn source(&self) -> Partition {
        self.shards.ref_shard(&self.repo, "refs/heads/main")
    }

    /// Store `pack` and plant its ticket row, as `BeginUpload` and the upload do.
    fn add(&self, pack: &[u8]) -> (TicketV1, Hash) {
        block_on(async {
            let mut sink = self
                .blobs
                .begin(BlobKey::pack(hash(pack)), pack.len() as u64)
                .await
                .unwrap();
            sink.write(Bytes::copy_from_slice(pack)).await.unwrap();
            sink.commit().await.unwrap();
        });
        let n = {
            let mut n = self.tickets.lock().unwrap();
            *n += 1;
            *n
        };
        let ticket = TicketV1 {
            authority_generation: None,
            repo: self.repo.name.clone(),
            ref_name: "refs/heads/main".into(),
            signer: [3; 32],
            pack_id: hash(pack),
            bytes: pack.len() as u64,
            part_size: 8 << 20,
            expires_at_ms: u64::try_from(NOW).unwrap() + 300_000,
            created_at_ms: u64::try_from(self.clock.now_ms()).unwrap(),
            reservation_id: format!("s:{n}"),
            upload_session: None,
        };
        let id = tickets::ticket_id(&ticket.reservation_id);
        block_on(self.store.apply(
            &self.source(),
            Batch::new().put(keys::ticket(&id), codec::encode_ticket(&ticket)),
        ))
        .unwrap();
        (ticket, id)
    }

    fn handler(&self) -> VerifyTimer<Shared<MemoryKv>, Shared<MemoryBlobStore>, Arc<Windows>> {
        VerifyTimer {
            remote: Shared(self.store.clone()),
            blobs: Shared(self.blobs.clone()),
            windows: self.windows.clone(),
            shards: self.shards.clone(),
            cfg: self.cfg,
            limits: self.limits,
            lease: LeaseParams::default(),
            clock: self.clock.clone(),
            metrics: self.recorder.clone(),
            extension: FailClosedExtraction,
        }
    }

    /// One alarm on `store`: due kind-7 and relay timers fire, at most one
    /// verification slice.
    fn tick_on<S: NamespaceStore>(&self, store: &S) -> RunReport {
        let registry =
            TimerRegistry::new()
                .register(self.handler())
                .register(crate::relay::RelayHandler {
                    target: Shared(self.store.clone()),
                    hook: crate::relay::NoHook,
                    budget: crate::relay::RelayBudget::default(),
                });
        let now = u64::try_from(self.clock.now_ms()).unwrap();
        block_on(run_due(
            store,
            &self.source(),
            &registry,
            self.clock.as_ref(),
            now,
            &TickBudget::default(),
        ))
        .unwrap()
    }

    fn tick(&self) -> RunReport {
        self.tick_on(self.store.as_ref())
    }

    /// Follow the driver's wakes, including persisted failure backoff.
    fn drive_on<S: NamespaceStore>(&self, store: &S, mut done: impl FnMut(&Self) -> bool) -> u32 {
        for tick in 0..3_000 {
            if done(self) {
                return tick;
            }
            let now = u64::try_from(self.clock.now_ms()).unwrap();
            let report = self.tick_on(store);
            let next = report.next_wake_ms.unwrap_or(now + 1_000).max(now + 1);
            self.clock.set(i64::try_from(next).unwrap());
        }
        panic!("job did not finish");
    }

    fn drive(&self, done: impl FnMut(&Self) -> bool) -> u32 {
        self.drive_on(self.store.as_ref(), done)
    }

    fn job(&self, pack: &Hash) -> Option<VerifyJobV1> {
        block_on(super::checkpoint::read_job(
            self.store.as_ref(),
            &self.source(),
            &self.repo.name,
            pack,
        ))
        .unwrap()
        .0
        .filter(|(job, _)| !job.gone)
        .map(|(job, _)| job)
    }

    fn state(&self, pack: &Hash) -> Option<VerificationV1> {
        block_on(super::state::read(
            self.store.as_ref(),
            &self.source(),
            &self.repo.name,
            pack,
        ))
        .unwrap()
        .map(|(state, _)| state)
    }

    fn create(&self, ticket: &TicketV1, id: Hash) {
        block_on(scheduled::create_job(
            self.store.as_ref(),
            &self.source(),
            &self.repo,
            ticket,
            id,
            self.clock.as_ref(),
            None,
        ))
        .unwrap();
    }

    /// A repository next door: the same stores and clock, another name.
    fn sibling(&self, name: &str) -> Self {
        Self {
            blobs: self.blobs.clone(),
            store: self.store.clone(),
            clock: self.clock.clone(),
            windows: self.windows.clone(),
            recorder: self.recorder.clone(),
            shards: self.shards.clone(),
            repo: RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: RepoName::new(name).unwrap(),
            },
            cfg: self.cfg,
            limits: self.limits,
            tickets: Mutex::new(*self.tickets.lock().unwrap() + 100),
        }
    }

    /// What an advance consuming `items` answers.
    fn check(
        &self,
        items: &[(&TicketV1, Hash)],
        head: Hash,
    ) -> Result<super::verify::StagedCommits, crate::ServerError> {
        let tickets: Vec<_> = items.iter().map(|(ticket, _)| (*ticket).clone()).collect();
        let ids: Vec<_> = items.iter().map(|(_, id)| *id).collect();
        block_on(scheduled::check(
            self.blobs.as_ref(),
            self.store.as_ref(),
            self.shards.as_ref(),
            &self.repo,
            &self.source(),
            &tickets,
            &ids,
            head,
            self.cfg,
            self.clock.as_ref(),
            self.recorder.as_ref(),
        ))
    }

    fn finished(&self, pack: &Hash) -> bool {
        self.job(pack)
            .is_some_and(|job| job.phase == Phase::Watch || job.outcome.is_some())
    }

    fn rows(&self, pack: &Hash, sub: u8) -> Vec<(Key, Value)> {
        let (start, end) = keys::verify_range(&self.repo.name, pack, Some(sub));
        block_on(self.store.scan(&self.source(), &start, &end, None, 10_000))
            .unwrap()
            .entries
    }

    fn verification_timer(&self, pack: &Hash) -> (Key, Value) {
        let (start, end) = keys::class_range(keys::TAG_TIMER);
        let reference = checkpoint::timer_reference(&self.repo.name, pack);
        let page = block_on(self.store.scan(&self.source(), &start, &end, None, 10_000)).unwrap();
        let mut timers = page.entries.into_iter().filter(|(key, _)| {
            matches!(keys::parse(key), Some(keys::ParsedKey::Timer {
                kind: 7, reference: observed, ..
            }) if observed.as_ref() == reference.as_slice())
        });
        let timer = timers.next().expect("verification work retains its timer");
        assert!(
            timers.next().is_none(),
            "verification timer is never duplicated"
        );
        timer
    }

    fn assert_verification_backoff(&self, pack: &Hash, previous: (Key, Value), now: u64) {
        let (old_key, payload) = previous;
        let (original_due, attempt) = keys::timer_retry_state(&old_key).unwrap();
        let next_attempt = (attempt + 1).min(keys::MAX_TIMER_RETRY_ATTEMPT);
        let delay = (crate::timers::RETRY_BACKOFF_MS * (1_u64 << (next_attempt - 1)))
            .min(crate::timers::MAX_RETRY_BACKOFF_MS);
        let expected = keys::timer_retry(
            now + delay,
            7,
            &checkpoint::timer_reference(&self.repo.name, pack),
            original_due,
            next_attempt,
        );
        assert_eq!(self.verification_timer(pack), (expected, payload));
        assert!(
            block_on(self.store.get(&self.source(), &old_key))
                .unwrap()
                .is_none()
        );
    }
}

// -- tests ------------------------------------------------------------------

#[test]
fn a_multi_window_pack_verifies_in_bounded_slices() {
    let (pack, _head) = tree_pack(40, 4_000);
    assert!(
        pack.len() as u64 > 2 * WINDOW,
        "fixture spans several windows"
    );
    let rig = Rig::new();
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    let ticks = rig.drive(|rig| rig.finished(&ticket.pack_id));
    let job = rig.job(&ticket.pack_id).unwrap();
    assert_eq!(job.outcome, None);
    assert!(matches!(
        rig.state(&ticket.pack_id),
        Some(VerificationV1::Verified { pack_len, .. }) if pack_len == pack.len() as u64
    ));
    assert_eq!(job.entries, 42);
    assert!(
        u64::from(ticks) >= pack.len() as u64 / WINDOW,
        "one window of progress per slice"
    );
    let spent = rig.recorder.slices.lock().unwrap().clone();
    assert!(
        !spent.is_empty() && spent.iter().all(|used| *used <= 256.0),
        "{spent:?}"
    );
    // Every entry has its index row, written only after the decode was done.
    let index = block_on(rig.store.scan(
        &rig.source(),
        &crate::store::keys::class_range(keys::TAG_OBJECT_INDEX).0,
        &crate::store::keys::class_range(keys::TAG_OBJECT_INDEX).1,
        None,
        1_000,
    ))
    .unwrap();
    assert_eq!(index.entries.len(), 42);
    assert!(job.usable());
    assert_eq!(job.kind, Kind::Pack);
}

#[test]
fn the_frame_table_agrees_with_index_entries() {
    // Duplicate objects and an in-pack delta chain, at two window sizes.
    let (b0, raw0) = blob(0, 3_000);
    let (b1, raw1) = blob(1, 3_000);
    let mut writer = PackWriter::new();
    writer.push_raw(b0, &raw0).unwrap();
    writer
        .push_delta(&b0, &mkit_core::delta::encode(&raw0, &raw1).unwrap())
        .unwrap();
    writer.push_raw(b0, &raw0).unwrap();
    let (b2, raw2) = blob(2, 3_000);
    writer
        .push_delta(&b1, &mkit_core::delta::encode(&raw1, &raw2).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    let mut frames = Vec::new();
    decode_entries_with(
        &pack,
        &mut NoExternalBases,
        DecodeLimits::default(),
        |entry| {
            frames.push(FrameMeta {
                id: entry.id,
                frame_offset: entry.frame_offset,
                frame_length: entry.frame_length,
                wire_type: entry.wire_type,
                delta_base: entry.delta_base,
                decoded_size: entry.bytes.len() as u64,
            });
            Ok(())
        },
    )
    .unwrap();
    let expected = index_entries(&frames, 50).unwrap();
    assert_eq!(expected.len(), 3);
    assert!(frames.iter().any(|f| f.id == b2));
    for window in [WINDOW, 1 << 20] {
        let mut rig = Rig::new();
        rig.limits.window_bytes = window;
        let (ticket, id) = rig.add(&pack);
        rig.create(&ticket, id);
        rig.drive(|rig| rig.finished(&ticket.pack_id));
        let mut actual: Vec<_> = rig
            .rows(&ticket.pack_id, keys::VC_FRAME)
            .into_iter()
            .map(|(key, value)| {
                let Some(keys::ParsedKey::VerifyCursor { id: Some(id), .. }) = keys::parse(&key)
                else {
                    panic!("frame key")
                };
                super::checkpoint::index_entry(
                    id,
                    &super::checkpoint::decode_frame(&id, &value).unwrap(),
                )
            })
            .collect();
        let mut expected = expected.clone();
        actual.sort_by_key(|entry| entry.object);
        expected.sort_by_key(|entry| entry.object);
        assert_eq!(actual, expected, "window {window}");
    }
}

type Snapshot = (
    Option<Phase>,
    Option<checkpoint::Outcome>,
    u64,
    u64,
    u64,
    Vec<(Key, Value)>,
    usize,
    Vec<(Key, Value)>,
);

fn snapshot(rig: &Rig, pack: &Hash) -> Snapshot {
    let job = rig.job(pack).unwrap();
    let index = crate::store::keys::class_range(keys::TAG_OBJECT_INDEX);
    let rows = block_on(
        rig.store
            .scan(&rig.source(), &index.0, &index.1, None, 10_000),
    )
    .unwrap()
    .entries
    .len();
    (
        Some(job.phase),
        job.outcome,
        job.entries,
        job.in_pack_bytes,
        job.external_bytes,
        rig.rows(pack, keys::VC_FRAME),
        rows,
        block_on(rig.store.scan(
            &crate::store::content_shard(pack),
            &Key::new(vec![]),
            &Key::new(vec![255]),
            None,
            10_000,
        ))
        .unwrap()
        .entries,
    )
}

use super::checkpoint;

#[test]
fn a_crash_at_every_batch_boundary_resumes_to_the_same_result() {
    let (pack, _) = tree_pack(30, 3_000);
    let reference = {
        let rig = Rig::new();
        let (ticket, id) = rig.add(&pack);
        rig.create(&ticket, id);
        rig.drive(|rig| rig.finished(&ticket.pack_id));
        snapshot(&rig, &ticket.pack_id)
    };
    assert_eq!(reference.0, Some(Phase::Watch));
    let mut boundaries = 0;
    for fail_at in 1..400 {
        let rig = Rig::new();
        let (ticket, id) = rig.add(&pack);
        rig.create(&ticket, id);
        let faulty = Faulty {
            inner: rig.store.clone(),
            applies: AtomicU32::new(0),
            fail_at: AtomicU32::new(fail_at),
            inventory_guard: None,
        };
        rig.drive_on(&faulty, |rig| rig.finished(&ticket.pack_id));
        assert_eq!(
            snapshot(&rig, &ticket.pack_id),
            reference,
            "fault at apply {fail_at}"
        );
        assert!(matches!(
            rig.state(&ticket.pack_id),
            Some(VerificationV1::Verified { .. })
        ));
        if faulty.applies.load(Ordering::SeqCst) < fail_at {
            break;
        }
        boundaries += 1;
    }
    assert!(
        boundaries > 10,
        "faults injected at {boundaries} boundaries"
    );
}

#[test]
fn a_source_restart_cannot_publish_the_old_provisional_history() {
    let tree = Object::Tree(Tree {
        entries: Vec::new(),
    });
    let tree_id = tree.id().unwrap();
    let (old_commit, old_head) = signed_commit(tree_id, Vec::new(), 7, b"fake");
    let (commit, head) = signed_commit(tree_id, Vec::new(), 7, b"head");
    let mut old = PackWriter::new_raw_only();
    let mut fresh = PackWriter::new_raw_only();
    for (writer, objects) in [
        (&mut old, [&old_commit, &tree]),
        (&mut fresh, [&commit, &tree]),
    ] {
        for object in objects {
            writer
                .push_raw(object.id().unwrap(), &serialize(object).unwrap())
                .unwrap();
        }
    }
    let (old, fresh) = (old.finish().unwrap(), fresh.finish().unwrap());
    assert_eq!(old.len(), fresh.len());
    let mut rig = Rig::new();
    rig.limits.max_entries = 1;
    rig.add(&old);
    let (ticket, id) = rig.add(&fresh);
    rig.create(&ticket, id);
    *rig.windows.source.lock().unwrap() = Some(hash(&old));
    rig.tick();
    let old_frame = keys::verify_row(
        &rig.repo.name,
        &ticket.pack_id,
        keys::VC_FRAME,
        Some(&old_head),
    );
    assert!(block_on(rig.store.has(&rig.source(), &old_frame)).unwrap());
    *rig.windows.source.lock().unwrap() = None;
    *rig.windows.etag.lock().unwrap() += 1;
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert!(!block_on(rig.store.has(&rig.source(), &old_frame)).unwrap());
    let old_history = keys::verify_row(
        &rig.repo.name,
        &ticket.pack_id,
        keys::VC_HISTORY,
        Some(&old_head),
    );
    assert!(!block_on(rig.store.has(&rig.source(), &old_history)).unwrap());
    assert!(rig.check(&[(&ticket, id)], head).is_ok());
}

#[test]
fn an_etag_change_restarts_the_job_and_never_rejects_the_pack() {
    let (pack, _) = tree_pack(50, 3_000);
    let rig = Rig::new();
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    *rig.windows.flip_after.lock().unwrap() = Some(3);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    let job = rig.job(&ticket.pack_id).unwrap();
    assert_eq!(job.restarts, 1);
    assert_eq!(job.outcome, None);
    assert!(matches!(
        rig.state(&ticket.pack_id),
        Some(VerificationV1::Verified { .. })
    ));
}

#[test]
fn a_changed_prefix_behind_the_cursor_restarts_once() {
    let (pack, _) = tree_pack(50, 3_000);
    let rig = Rig::new();
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    // The second slice re-reads the window its cursor points into; the
    // verified prefix of that window changed since the first slice.
    *rig.windows.corrupt.lock().unwrap() = Some((WINDOW + 1, 2, true));
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    let job = rig.job(&ticket.pack_id).unwrap();
    assert_eq!(job.restarts, 1);
    assert!(matches!(
        rig.state(&ticket.pack_id),
        Some(VerificationV1::Verified { .. })
    ));
}

#[test]
fn killed_slices_shrink_the_entry_cap_and_end_in_a_terminal_outcome_not_a_rejection() {
    let (pack, head) = tree_pack(10, 1_000);
    let rig = Rig::new();
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    *rig.windows.fail.lock().unwrap() = true;
    let payload = rig.verification_timer(&ticket.pack_id).1;
    let caps = Mutex::new(Vec::new());
    rig.drive(|rig| {
        let job = rig.job(&ticket.pack_id).unwrap();
        assert_eq!(rig.verification_timer(&ticket.pack_id).1, payload);
        caps.lock().unwrap().push((job.entry_cap, job.attempts));
        job.outcome.is_some()
    });
    let job = rig.job(&ticket.pack_id).unwrap();
    assert_eq!(job.outcome, Some(checkpoint::Outcome::DecodeBudget));
    let caps = caps.into_inner().unwrap();
    assert!(
        caps.iter()
            .any(|(cap, attempts)| *cap == 1 && *attempts >= 1),
        "{caps:?}"
    );
    assert!(
        caps.iter()
            .any(|(cap, _)| *cap == checkpoint::DEFAULT_ENTRY_CAP / 2)
    );
    assert!(!matches!(
        rig.state(&ticket.pack_id),
        Some(VerificationV1::Rejected { .. })
    ));
    let error = rig.check(&[(&ticket, id)], head).unwrap_err();
    assert_eq!(error.public_message(), "pack exceeds indexed decode budget");
}

fn rejected(rig: &Rig, pack: &Hash) -> Option<(String, String)> {
    match rig.state(pack) {
        Some(VerificationV1::Rejected { code, message }) => Some((code, message)),
        _ => None,
    }
}

fn repaired(mut pack: Vec<u8>, index: usize) -> Vec<u8> {
    pack[index] ^= 1;
    let trailer = pack.len() - 32;
    let digest = hash(&pack[..trailer]);
    pack[trailer..].copy_from_slice(&digest);
    pack
}

#[test]
fn hash_failure_at_done_precedes_bad_signature() {
    let (pack, head) = tree_pack(12, 3_000);
    // A pack that does not hash to its trailer: identity first.
    let rig = Rig::new();
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    *rig.windows.corrupt.lock().unwrap() = Some((pack.len() as u64 - 1, 0, false));
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert_eq!(
        rejected(&rig, &ticket.pack_id),
        Some(("invalid_argument".into(), "object hash mismatch".into()))
    );
    let error = rig.check(&[(&ticket, id)], head).unwrap_err();
    assert_eq!(error.public_message(), "object hash mismatch");

    // A well-formed pack with a bad commit signature.
    let bad = repaired(pack.clone(), pack.len() - 33);
    let rig = Rig::new();
    let (ticket, id) = rig.add(&bad);
    rig.create(&ticket, id);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert_eq!(
        rejected(&rig, &ticket.pack_id),
        Some(("invalid_argument".into(), "bad signature".into()))
    );
    assert_eq!(
        rig.check(&[(&ticket, id)], head)
            .unwrap_err()
            .public_message(),
        "bad signature"
    );

    // A bad signature and a broken trailer: the pack hash wins.
    let mut both = bad.clone();
    let last = both.len() - 1;
    both[last] ^= 1;
    let rig = Rig::new();
    let (ticket, id) = rig.add(&both);
    rig.create(&ticket, id);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert_eq!(
        rejected(&rig, &ticket.pack_id).unwrap().1,
        "object hash mismatch"
    );
}

fn delta_chain(len: u16) -> Vec<u8> {
    let (first, mut prior) = blob(0, 2_000);
    let mut writer = PackWriter::new();
    writer.push_raw(first, &prior).unwrap();
    let mut base = first;
    for n in 1..len {
        let (id, raw) = blob(n, 2_000);
        writer
            .push_delta(&base, &mkit_core::delta::encode(&prior, &raw).unwrap())
            .unwrap();
        (base, prior) = (id, raw);
    }
    writer.finish().unwrap()
}

#[test]
fn an_in_pack_delta_chain_over_the_cap_is_rejected() {
    let mut rig = Rig::new();
    rig.cfg.max_delta_chain_depth = 2;
    let pack = delta_chain(4);
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert_eq!(
        rejected(&rig, &ticket.pack_id),
        Some(("invalid_argument".into(), "delta chain too deep".into()))
    );
    // Within the cap the same chain verifies and its depths are indexed.
    let mut rig = Rig::new();
    rig.cfg.max_delta_chain_depth = 3;
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert!(matches!(
        rig.state(&ticket.pack_id),
        Some(VerificationV1::Verified { .. })
    ));
    let depths: Vec<_> = rig
        .rows(&ticket.pack_id, keys::VC_FRAME)
        .iter()
        .map(|(key, value)| {
            let Some(keys::ParsedKey::VerifyCursor { id: Some(id), .. }) = keys::parse(key) else {
                panic!()
            };
            super::checkpoint::decode_frame(&id, value)
                .unwrap()
                .value
                .chain_depth
        })
        .collect();
    assert_eq!(depths.iter().copied().max(), Some(3));
}

#[test]
fn a_pack_needing_extraction_never_reaches_verified_here() {
    let (pack, head) = tree_pack(1, 70_000);
    let rig = Rig::new();
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    let job = rig.job(&ticket.pack_id).unwrap();
    assert_eq!(
        job.outcome,
        Some(checkpoint::Outcome::ExtractionUnavailable)
    );
    assert!(!matches!(
        rig.state(&ticket.pack_id),
        Some(VerificationV1::Verified { .. })
    ));
    assert!(rig.check(&[(&ticket, id)], head).is_err());
}

#[test]
fn an_overlapping_advance_does_not_partially_claim_a_new_extraction_group() {
    let rig = Rig::new();
    let (pack_a, head_a) = tree_pack(1, 32);
    let (pack_b, head_b) = tree_pack(1, 33);
    let (pack_c, _) = tree_pack(1, 34);
    let (a, aid) = rig.add(&pack_a);
    let (b, bid) = rig.add(&pack_b);
    let (c, cid) = rig.add(&pack_c);
    assert!(rig.check(&[(&a, aid), (&b, bid)], head_a).is_err());
    assert!(rig.job(&a.pack_id).is_some());
    assert!(rig.job(&b.pack_id).is_some());
    assert!(rig.check(&[(&b, bid), (&c, cid)], head_b).is_err());
    assert!(
        rig.job(&c.pack_id).is_none(),
        "B belongs to unfinished A+B: B+C must claim no new member"
    );
    rig.drive(|rig| rig.finished(&a.pack_id) && rig.finished(&b.pack_id));
    assert!(rig.check(&[(&b, bid), (&c, cid)], head_b).is_err());
    assert!(
        rig.job(&c.pack_id).is_some(),
        "finished A+B must not permanently prevent the later B+C group"
    );
}

#[test]
fn a_single_entry_is_bounded_within_the_slice_resident_budget() {
    let (object, bytes) = blob(7, 2 << 20);
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(object, &bytes).unwrap();
    let pack = writer.finish().unwrap();
    let mut rig = Rig::new();
    rig.limits = SliceLimits::default();
    rig.cfg.extract_min_bytes = 8 << 20;
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert_eq!(
        rig.job(&ticket.pack_id).unwrap().outcome,
        Some(checkpoint::Outcome::DecodeBudget)
    );
    assert!(rejected(&rig, &ticket.pack_id).is_none());
}

#[test]
fn rebuilding_job_rows_cannot_downgrade_an_already_verified_pack() {
    let (pack, _) = tree_pack(1, 3_000);
    let rig = Rig::new();
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    let verified = rig.state(&ticket.pack_id).unwrap();
    let key = keys::verify_job(&rig.repo.name, &ticket.pack_id);
    let raw = block_on(rig.store.get(&rig.source(), &key)).unwrap();
    block_on(scheduled::create_job(
        rig.store.as_ref(),
        &rig.source(),
        &rig.repo,
        &ticket,
        id,
        rig.clock.as_ref(),
        raw,
    ))
    .unwrap();
    *rig.windows.corrupt.lock().unwrap() = Some((pack.len() as u64 - 1, 0, false));
    rig.tick();
    assert_eq!(rig.state(&ticket.pack_id), Some(verified));
}

fn thin(base: Hash, base_raw: &[u8], target_raw: &[u8]) -> Vec<u8> {
    let mut writer = PackWriter::new();
    writer
        .push_delta(
            &base,
            &mkit_core::delta::encode(base_raw, target_raw).unwrap(),
        )
        .unwrap();
    writer.finish().unwrap()
}

fn seed_member(rig: &Rig, object: Hash, raw: &[u8]) {
    super::tests::seed_member_raw(&rig.blobs, &rig.store, &rig.repo, object, raw);
}

#[test]
fn an_external_base_waits_out_the_lag_window_then_ends_terminal_never_rejected() {
    let (base, base_raw) = blob(1, 3_000);
    let (_, target_raw) = blob(2, 3_000);
    let pack = thin(base, &base_raw, &target_raw);
    let rig = Rig::new();
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    for _ in 0..20 {
        rig.tick();
        rig.clock.advance(1_000);
    }
    let job = rig.job(&ticket.pack_id).unwrap();
    assert_eq!(
        (job.phase, job.outcome),
        (Phase::Decode, None),
        "inside the window it waits"
    );
    assert_eq!(job.attempts, 0, "waiting is not a failure");
    let error = rig.check(&[(&ticket, id)], base).unwrap_err();
    assert_eq!(error.public_message(), "pack verification pending");
    assert_eq!(error.details().len(), 1);

    rig.clock
        .advance(i64::try_from(rig.cfg.relay_lag_bound_ms).unwrap());
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    let job = rig.job(&ticket.pack_id).unwrap();
    assert_eq!(job.outcome, Some(checkpoint::Outcome::BaseMissing));
    assert!(
        rejected(&rig, &ticket.pack_id).is_none(),
        "a membership miss is never persisted"
    );
    let error = rig.check(&[(&ticket, id)], base).unwrap_err();
    assert_eq!(error.code(), crate::error::Code::FailedPrecondition);
    assert_eq!(
        error.public_message(),
        "delta base not available in this repository"
    );
}

#[test]
fn a_new_ticket_replaces_a_terminal_job_instead_of_inheriting_its_outcome() {
    let (base, base_raw) = blob(1, 3_000);
    let (_, target) = blob(2, 3_000);
    let pack = thin(base, &base_raw, &target);
    let rig = Rig::new();
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    rig.clock
        .advance(i64::try_from(rig.cfg.relay_lag_bound_ms).unwrap());
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert_eq!(
        rig.job(&ticket.pack_id).unwrap().outcome,
        Some(checkpoint::Outcome::BaseMissing)
    );
    let (fresh, fresh_id) = rig.add(&pack);
    assert_eq!(
        rig.check(&[(&fresh, fresh_id)], [1; 32])
            .unwrap_err()
            .public_message(),
        "pack verification pending"
    );
    let job = rig.job(&ticket.pack_id).unwrap();
    assert_eq!(job.ticket_id, fresh_id);
    assert_eq!(job.created_at_ms, fresh.created_at_ms);
    assert!(job.outcome.is_none());
}

#[test]
fn a_base_only_in_another_repository_answers_like_one_that_exists_nowhere() {
    let (base, base_raw) = blob(1, 3_000);
    let (_, target_raw) = blob(2, 3_000);
    let pack = thin(base, &base_raw, &target_raw);
    let a = Rig::new();
    seed_member(&a, base, &base_raw);
    // In the repository that holds it, the base resolves and is charged.
    let (ticket, id) = a.add(&pack);
    a.create(&ticket, id);
    a.drive(|rig| rig.finished(&ticket.pack_id));
    let job = a.job(&ticket.pack_id).unwrap();
    assert_eq!(job.outcome, None);
    assert_eq!(job.external_bytes, base_raw.len() as u64);
    assert!(matches!(
        a.state(&ticket.pack_id),
        Some(VerificationV1::Verified { .. })
    ));

    let mut answers = Vec::new();
    for name in ["two", "three"] {
        let rig = a.sibling(name);
        let (ticket, id) = rig.add(&pack);
        rig.create(&ticket, id);
        rig.clock
            .advance(i64::try_from(rig.cfg.relay_lag_bound_ms).unwrap());
        rig.drive(|rig| rig.finished(&ticket.pack_id));
        let error = rig.check(&[(&ticket, id)], base).unwrap_err();
        answers.push((
            error.code(),
            error.public_message().to_owned(),
            error.details().len(),
        ));
    }
    // Repository "two" saw the base only in "one"; "three" saw it nowhere.
    assert_eq!(answers[0], answers[1]);
    assert_eq!(answers[0].1, "delta base not available in this repository");
}

#[test]
fn a_capped_base_lookup_is_permanent_at_once() {
    let (base, base_raw) = blob(1, 3_000);
    let (_, target_raw) = blob(2, 3_000);
    let rig = Rig::new();
    super::tests::seed_capped_index(&rig.store, &rig.repo, base);
    let pack = thin(base, &base_raw, &target_raw);
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert_eq!(
        rig.job(&ticket.pack_id).unwrap().outcome,
        Some(checkpoint::Outcome::BaseCapped)
    );
    let error = rig.check(&[(&ticket, id)], base).unwrap_err();
    assert_eq!(error.code(), crate::error::Code::FailedPrecondition);
    assert_eq!(
        error.public_message(),
        "delta base not available in this repository"
    );
}

#[test]
fn external_depth_over_the_cap_is_a_terminal_outcome_not_a_rejection() {
    let mut rig = Rig::new();
    rig.cfg.max_delta_chain_depth = 2;
    // A member pack whose last object is two deltas deep, indexed by its own job.
    let member = delta_chain(3);
    let (member_ticket, member_id) = rig.add(&member);
    rig.create(&member_ticket, member_id);
    rig.drive(|rig| rig.finished(&member_ticket.pack_id));
    block_on(rig.store.apply(
        &rig.source(),
        Batch::new().put(
            keys::membership(&rig.repo.name, &member_ticket.pack_id),
            Value::default(),
        ),
    ))
    .unwrap();
    let (deepest, deepest_raw) = blob(2, 2_000);
    let (_, target_raw) = blob(99, 2_000);
    let pack = thin(deepest, &deepest_raw, &target_raw);
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert_eq!(
        rig.job(&ticket.pack_id).unwrap().outcome,
        Some(checkpoint::Outcome::ExternalTooDeep)
    );
    assert!(rejected(&rig, &ticket.pack_id).is_none());
    let error = rig.check(&[(&ticket, id)], deepest).unwrap_err();
    assert_eq!(error.code(), crate::error::Code::InvalidArgument);
    assert_eq!(error.public_message(), "delta chain too deep");
}

#[test]
fn the_decode_budget_is_the_same_wherever_the_slices_fall() {
    let (base, base_raw) = blob(1, 3_000);
    let mut writer = PackWriter::new();
    let mut in_pack = 0;
    for n in 10..40 {
        let (id, raw) = blob(n, 3_000);
        writer.push_raw(id, &raw).unwrap();
        in_pack += raw.len() as u64;
    }
    let (_, target_raw) = blob(2, 3_000);
    in_pack += target_raw.len() as u64;
    writer
        .push_delta(
            &base,
            &mkit_core::delta::encode(&base_raw, &target_raw).unwrap(),
        )
        .unwrap();
    let pack = writer.finish().unwrap();
    let mut filler_writer = PackWriter::new_raw_only();
    let mut fillers_total = 0;
    for n in 10..40 {
        let (id, raw) = blob(n, 3_000);
        filler_writer.push_raw(id, &raw).unwrap();
        fillers_total += raw.len() as u64;
    }
    let fillers = filler_writer.finish().unwrap();
    let outcomes = |window: u64, max_entries: u32, budget: Option<u64>| {
        let mut rig = Rig::new();
        rig.limits.window_bytes = window;
        rig.limits.max_entries = max_entries;
        if let Some(budget) = budget {
            rig.cfg.decode_budget = budget;
        }
        seed_member(&rig, base, &base_raw);
        let (ticket, id) = rig.add(&pack);
        rig.create(&ticket, id);
        rig.drive(|rig| rig.finished(&ticket.pack_id));
        let job = rig.job(&ticket.pack_id).unwrap();
        (
            job.in_pack_bytes,
            job.external_bytes,
            job.outcome,
            rejected(&rig, &ticket.pack_id),
        )
    };
    let shapes = [(WINDOW, 4096), (1 << 20, 4096), (WINDOW, 1), (WINDOW, 7)];
    let reference = outcomes(WINDOW, 4096, None);
    assert_eq!(reference.0, in_pack);
    assert_eq!(reference.1, base_raw.len() as u64);
    for (window, entries) in shapes {
        assert_eq!(
            outcomes(window, entries, None),
            reference,
            "{window} {entries}"
        );
        // No external base: the in-pack sum alone is over the budget, which
        // is content-intrinsic and persisted.
        let mut rig = Rig::new();
        rig.limits.window_bytes = window;
        rig.limits.max_entries = entries;
        rig.cfg.decode_budget = fillers_total - 1;
        let (ticket, id) = rig.add(&fillers);
        rig.create(&ticket, id);
        rig.drive(|rig| rig.finished(&ticket.pack_id));
        assert_eq!(
            rejected(&rig, &ticket.pack_id),
            Some((
                "invalid_argument".into(),
                "pack exceeds indexed decode budget".into()
            )),
            "{window} {entries}"
        );
        // With the member base on top it is a terminal outcome, never persisted.
        let over = outcomes(window, entries, Some(in_pack + 1_000));
        assert_eq!(
            (over.2, over.3),
            (Some(checkpoint::Outcome::DecodeBudget), None),
            "{window} {entries}"
        );
    }
}

/// A commit pack and a pack with its tree and blobs, and the head.
fn split_packs() -> (Vec<u8>, Vec<u8>, Hash, (Hash, Vec<u8>)) {
    let mut rest = PackWriter::new_raw_only();
    let mut entries = Vec::new();
    for n in 0..3 {
        let (id, raw) = blob(n, 500);
        rest.push_raw(id, &raw).unwrap();
        entries.push(TreeEntry {
            name: format!("f{n}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: id,
        });
    }
    let tree = Object::Tree(Tree { entries });
    let tree_id = tree.id().unwrap();
    let tree_raw = serialize(&tree).unwrap();
    rest.push_raw(tree_id, &tree_raw).unwrap();
    let (commit, head) = signed_commit(tree_id, Vec::new(), 7, b"head");
    let mut first = PackWriter::new_raw_only();
    first.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    (
        first.finish().unwrap(),
        rest.finish().unwrap(),
        head,
        (tree_id, tree_raw),
    )
}

fn phase(rig: &Rig, pack: &Hash) -> Phase {
    rig.job(pack).unwrap().phase
}

#[test]
fn an_advance_answers_pending_until_the_job_verifies_then_commits_clean() {
    let (pack, head) = tree_pack(10, 1_000);
    let rig = Rig::new();
    let (ticket, id) = rig.add(&pack);
    // No job yet: the advance creates it, and answers with one detail.
    let error = rig.check(&[(&ticket, id)], head).unwrap_err();
    assert_eq!(error.public_message(), "pack verification pending");
    assert_eq!(error.details().len(), 1);
    let job = rig
        .job(&ticket.pack_id)
        .expect("the advance created the job");
    assert_eq!((job.phase, job.ticket_id), (Phase::Decode, id));
    assert_eq!(
        rig.check(&[(&ticket, id)], head)
            .unwrap_err()
            .details()
            .len(),
        1
    );
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    rig.check(&[(&ticket, id)], head).unwrap();
    // A different ticket for the same pack waits for the first job's rows.
    let (other, other_id) = rig.add(&pack);
    assert_eq!(
        rig.check(&[(&other, other_id)], head)
            .unwrap_err()
            .public_message(),
        "pack verification pending"
    );
}

#[test]
fn closure_is_checked_over_the_consumed_set_with_the_lag_window_and_final_recheck() {
    let (commit_pack, rest_pack, head, _) = split_packs();
    let rig = Rig::new();
    let (commit_ticket, commit_id) = rig.add(&commit_pack);
    let (rest_ticket, rest_id) = rig.add(&rest_pack);
    for (ticket, id) in [(&commit_ticket, commit_id), (&rest_ticket, rest_id)] {
        rig.create(ticket, id);
    }
    rig.drive(|rig| {
        phase(rig, &commit_ticket.pack_id) == Phase::Recheck && rig.finished(&rest_ticket.pack_id)
    });
    // Together the packs are closed.
    rig.check(
        &[(&commit_ticket, commit_id), (&rest_ticket, rest_id)],
        head,
    )
    .unwrap();
    // The commit alone owes its tree: inside the window, that may still arrive.
    let error = rig.check(&[(&commit_ticket, commit_id)], head).unwrap_err();
    assert_eq!(
        error.public_message(),
        "repository membership not yet visible"
    );
    // Past the window but before the final recheck ran: not yet an answer.
    rig.clock
        .advance(i64::try_from(rig.cfg.relay_lag_bound_ms).unwrap());
    let error = rig.check(&[(&commit_ticket, commit_id)], head).unwrap_err();
    assert_eq!(error.public_message(), "pack verification pending");
    rig.drive(|rig| rig.finished(&commit_ticket.pack_id));
    assert!(
        rig.job(&commit_ticket.pack_id)
            .unwrap()
            .closure_final_at_ms
            .is_some()
    );
    let error = rig.check(&[(&commit_ticket, commit_id)], head).unwrap_err();
    assert_eq!(error.code(), crate::error::Code::InvalidArgument);
    assert_eq!(error.public_message(), "open closure");
    rig.check(
        &[(&commit_ticket, commit_id), (&rest_ticket, rest_id)],
        head,
    )
    .unwrap();
}

#[test]
fn a_satisfying_member_pack_is_rechecked_at_the_advance() {
    let (commit_pack, _, head, (tree, tree_raw)) = split_packs();
    let rig = Rig::new();
    seed_member(&rig, tree, &tree_raw);
    let (commit_ticket, commit_id) = rig.add(&commit_pack);
    rig.create(&commit_ticket, commit_id);
    rig.drive(|rig| rig.finished(&commit_ticket.pack_id));
    let job = rig.job(&commit_ticket.pack_id).unwrap();
    assert_eq!((job.owed, job.satisfying.len()), (0, 1));
    rig.check(&[(&commit_ticket, commit_id)], head).unwrap();
    // The member pack is deleted (GC, or a deleted repository's generation).
    let member = job.satisfying[0];
    block_on(rig.store.apply(
        &rig.source(),
        Batch::new().delete(keys::membership(&rig.repo.name, &member)),
    ))
    .unwrap();
    let error = rig.check(&[(&commit_ticket, commit_id)], head).unwrap_err();
    assert_eq!(
        error.public_message(),
        "repository membership not yet visible"
    );
    rig.clock
        .advance(i64::try_from(rig.cfg.relay_lag_bound_ms).unwrap());
    assert_eq!(
        rig.check(&[(&commit_ticket, commit_id)], head)
            .unwrap_err()
            .public_message(),
        "open closure"
    );
}

#[test]
fn a_crash_cannot_lose_a_satisfying_member_pack() {
    let (pack, _, head, (tree, tree_raw)) = split_packs();
    for fail_at in 1..40 {
        let rig = Rig::new();
        seed_member(&rig, tree, &tree_raw);
        let (ticket, id) = rig.add(&pack);
        rig.create(&ticket, id);
        let faulty = Faulty {
            inner: rig.store.clone(),
            applies: AtomicU32::new(0),
            fail_at: AtomicU32::new(fail_at),
            inventory_guard: None,
        };
        rig.drive_on(&faulty, |rig| rig.finished(&ticket.pack_id));
        let job = rig.job(&ticket.pack_id).unwrap();
        assert_eq!(job.satisfying.len(), 1, "crash at apply {fail_at}");
        block_on(rig.store.apply(
            &rig.source(),
            Batch::new().delete(keys::membership(&rig.repo.name, &job.satisfying[0])),
        ))
        .unwrap();
        assert_eq!(
            rig.check(&[(&ticket, id)], head)
                .unwrap_err()
                .public_message(),
            "repository membership not yet visible",
            "crash at apply {fail_at} must retain the membership dependency"
        );
        if faulty.applies.load(Ordering::SeqCst) < fail_at {
            break;
        }
    }
}

#[test]
fn the_head_must_be_a_commit_remix_or_tag_wherever_it_lives() {
    let (commit_pack, rest_pack, head, (tree, _)) = split_packs();
    let rig = Rig::new();
    let (commit_ticket, commit_id) = rig.add(&commit_pack);
    let (rest_ticket, rest_id) = rig.add(&rest_pack);
    for (ticket, id) in [(&commit_ticket, commit_id), (&rest_ticket, rest_id)] {
        rig.create(ticket, id);
    }
    rig.drive(|rig| rig.finished(&commit_ticket.pack_id) && rig.finished(&rest_ticket.pack_id));
    let both = [(&commit_ticket, commit_id), (&rest_ticket, rest_id)];
    rig.check(&both, head).unwrap();
    // A tree in a consumed pack is not a tip.
    assert_eq!(
        rig.check(&both, tree).unwrap_err().public_message(),
        "open closure"
    );
    // Neither is a blob that is only a member.
    let (member_blob, member_raw) = blob(77, 400);
    seed_member(&rig, member_blob, &member_raw);
    assert_eq!(
        rig.check(&both, member_blob).unwrap_err().public_message(),
        "open closure"
    );
    // An id nobody holds may still be catching up, until the window passes.
    rig.clock
        .set(i64::try_from(commit_ticket.created_at_ms).unwrap() + 1_000);
    assert_eq!(
        rig.check(&both, [5; 32]).unwrap_err().public_message(),
        "repository membership not yet visible"
    );
    rig.clock
        .advance(i64::try_from(rig.cfg.relay_lag_bound_ms).unwrap());
    assert_eq!(
        rig.check(&both, [5; 32]).unwrap_err().public_message(),
        "open closure"
    );
}

#[test]
fn a_packlist_may_name_consumed_or_member_packs_only() {
    let (pack, head) = tree_pack(3, 400);
    let rig = Rig::new();
    let (ticket, id) = rig.add(&pack);
    let member_pack = [8; 32];
    let listing = |packs: &[Hash]| mkit_core::transfer::encode_packlist(None, packs).unwrap();
    let ok = listing(&[ticket.pack_id]);
    let (ok_ticket, ok_id) = rig.add(&ok);
    let foreign = listing(&[ticket.pack_id, member_pack]);
    let (foreign_ticket, foreign_id) = rig.add(&foreign);
    let huge = listing(
        &(0..300_u16)
            .map(|n| hash(&n.to_be_bytes()))
            .collect::<Vec<_>>(),
    );
    let (huge_ticket, huge_id) = rig.add(&huge);
    for (ticket, id) in [
        (&ticket, id),
        (&ok_ticket, ok_id),
        (&foreign_ticket, foreign_id),
        (&huge_ticket, huge_id),
    ] {
        rig.create(ticket, id);
    }
    rig.drive(|rig| {
        [&ticket, &ok_ticket, &foreign_ticket]
            .iter()
            .all(|t| rig.finished(&t.pack_id))
            && rig.job(&huge_ticket.pack_id).unwrap().outcome.is_some()
    });
    assert_eq!(rig.job(&ok_ticket.pack_id).unwrap().kind, Kind::Packlist);
    rig.check(&[(&ticket, id), (&ok_ticket, ok_id)], head)
        .unwrap();
    let both = [(&ticket, id), (&foreign_ticket, foreign_id)];
    assert_eq!(
        rig.check(&both, head).unwrap_err().public_message(),
        "repository membership not yet visible"
    );
    // Once the pack is a member the list is satisfied; past the window an
    // absent one is a distinct permanent answer.
    rig.clock
        .advance(i64::try_from(rig.cfg.relay_lag_bound_ms).unwrap());
    assert_eq!(
        rig.check(&both, head).unwrap_err().public_message(),
        "packlist lists a pack that is not in this repository"
    );
    block_on(rig.store.apply(
        &rig.source(),
        Batch::new().put(
            keys::membership(&rig.repo.name, &member_pack),
            Value::default(),
        ),
    ))
    .unwrap();
    rig.check(&both, head).unwrap();
    // More than a lookup can hold is capped without storing the list.
    let error = rig
        .check(&[(&ticket, id), (&huge_ticket, huge_id)], head)
        .unwrap_err();
    assert_eq!(error.public_message(), "object index limit exceeded");
    assert_eq!(error.code(), crate::error::Code::InvalidArgument);
}

fn rows_left(rig: &Rig, pack: &Hash) -> usize {
    let (start, end) = keys::verify_range(&rig.repo.name, pack, None);
    block_on(rig.store.scan(&rig.source(), &start, &end, None, 100_000))
        .unwrap()
        .entries
        .len()
}

#[test]
fn a_closed_ticket_takes_the_job_rows_and_an_unconsumed_packs_vs_with_it() {
    let (pack, _) = tree_pack(20, 1_000);
    for consumed in [false, true] {
        let rig = Rig::new();
        let (ticket, id) = rig.add(&pack);
        rig.create(&ticket, id);
        rig.drive(|rig| rig.finished(&ticket.pack_id));
        assert!(rows_left(&rig, &ticket.pack_id) >= 22);
        // The ticket closes: consumed by an advance (a member row appears) or expired.
        let mut close = Batch::new().delete(keys::ticket(&id));
        if consumed {
            close = close.put(
                keys::membership(&rig.repo.name, &ticket.pack_id),
                Value::default(),
            );
        }
        block_on(rig.store.apply(&rig.source(), close)).unwrap();
        rig.clock.advance(400_000);
        rig.drive(|rig| rows_left(rig, &ticket.pack_id) == 1);
        let tombstone = block_on(rig.store.get(
            &rig.source(),
            &keys::verify_job(&rig.repo.name, &ticket.pack_id),
        ))
        .unwrap()
        .unwrap();
        assert!(checkpoint::decode_job(&tombstone).unwrap().gone);
        assert_eq!(
            rig.state(&ticket.pack_id).is_some(),
            consumed,
            "vs stays only for a member"
        );
        // The timer is gone too: nothing left to fire.
        let timers = keys::class_range(keys::TAG_TIMER);
        let left = block_on(
            rig.store
                .scan(&rig.source(), &timers.0, &timers.1, None, 10),
        )
        .unwrap();
        assert!(left.entries.is_empty(), "{:?}", left.entries.len());
    }
}

/// Every index row of `pack`'s objects on their index shards.
fn delivered_rows(rig: &Rig, objects: &[Hash]) -> usize {
    objects
        .iter()
        .filter(|object| {
            let partition = rig.shards.object_index(&rig.repo, object);
            let (start, end) = keys::object_index_range(&rig.repo.name, object);
            !block_on(rig.store.scan(&partition, &start, &end, None, 10))
                .unwrap()
                .entries
                .is_empty()
        })
        .count()
}

#[test]
fn index_rows_reach_their_shards_before_verified_under_a_renewed_source_lease() {
    let (pack, _) = tree_pack(20, 1_000);
    let rig = Rig::named("one", Arc::new(D34Shards));
    let (ticket, id) = rig.add(&pack);
    let mut objects = Vec::new();
    decode_entries_with(&pack, &mut NoExternalBases, DecodeLimits::default(), |e| {
        objects.push(e.id);
        Ok(())
    })
    .unwrap();
    // An expired lease: the timer has to renew it through the D-1 seam.
    let stale = codec::EpochLease {
        authority_ready: None,
        authority_generation: None,
        epoch: 0,
        expires_at_ms: u64::try_from(NOW).unwrap() - 1,
        config_version: 1,
    };
    block_on(rig.store.apply(
        &rig.source(),
        Batch::new().put(keys::epoch_lease(), codec::encode_epoch_lease(&stale)),
    ))
    .unwrap();
    rig.create(&ticket, id);
    let mut saw_await = false;
    rig.drive(|rig| {
        let job = rig.job(&ticket.pack_id).unwrap();
        saw_await |= job.phase == Phase::AwaitDelivery;
        if matches!(
            rig.state(&ticket.pack_id),
            Some(VerificationV1::Verified { .. })
        ) {
            // R-130: Verified only once every row is on its shard.
            assert_eq!(delivered_rows(rig, &objects), objects.len());
            assert!(
                block_on(crate::relay::relay_delivered_through(
                    rig.store.as_ref(),
                    &rig.source(),
                    job.last_relay_seq.unwrap()
                ))
                .unwrap()
            );
        }
        rig.finished(&ticket.pack_id)
    });
    assert!(saw_await, "delivery is a phase of its own");
    let lease = block_on(rig.store.get(&rig.source(), &keys::epoch_lease()))
        .unwrap()
        .unwrap();
    let lease = codec::decode_epoch_lease(&lease).unwrap();
    assert!(
        lease.expires_at_ms > u64::try_from(NOW).unwrap(),
        "renewed: {lease:?}"
    );
    let ls = block_on(rig.store.get(
        &rig.shards.coordinator(&rig.repo.namespace),
        &keys::leased_shard(&rig.repo.name, "refs/heads/main"),
    ))
    .unwrap();
    assert!(ls.is_some(), "the coordinator granted the shard");
}

/// Replaces the shard's lease just before the first relay batch commits, as
/// a revocation or a concurrent grant would.
struct Rival {
    inner: Arc<MemoryKv>,
    armed: std::sync::atomic::AtomicBool,
    relay_rows_seen: AtomicU32,
}

impl NamespaceStore for Rival {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(p, key).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        let relay = batch.writes.iter().any(
            |w| matches!(w, crate::store::Write::Put(k, _) if k.as_bytes().starts_with(b"or\0")),
        );
        if relay && self.armed.swap(false, Ordering::SeqCst) {
            let rival = codec::EpochLease {
                authority_ready: None,
                authority_generation: None,
                epoch: 9,
                expires_at_ms: u64::try_from(NOW).unwrap() + 3_600_000,
                config_version: 1,
            };
            self.inner
                .apply(
                    p,
                    Batch::new().put(keys::epoch_lease(), codec::encode_epoch_lease(&rival)),
                )
                .await?;
        }
        let outcome = self.inner.apply(p, batch).await?;
        if relay && matches!(outcome, BatchOutcome::Committed) {
            self.relay_rows_seen.fetch_add(1, Ordering::SeqCst);
        }
        Ok(outcome)
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

#[test]
fn losing_the_source_lease_fails_the_slice_without_committing_relay_rows() {
    let (pack, _) = tree_pack(20, 1_000);
    let rig = Rig::named("one", Arc::new(D34Shards));
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    let rival = Rival {
        inner: rig.store.clone(),
        armed: std::sync::atomic::AtomicBool::new(false),
        relay_rows_seen: AtomicU32::new(0),
    };
    // Run until the decode is done, then arm the rival: the next slice runs
    // the closure and emit phases back to back and fails at the relay commit.
    rig.drive_on(&rival, |rig| {
        rig.job(&ticket.pack_id).unwrap().phase == Phase::ClosureResolve
    });
    rival.armed.store(true, Ordering::SeqCst);
    rig.tick_on(&rival);
    assert_eq!(
        rig.job(&ticket.pack_id).unwrap().phase,
        Phase::ClosureResolve,
        "the slice failed, the job did not move"
    );
    let relay = keys::class_range(keys::TAG_RELAY);
    assert!(
        block_on(rig.store.scan(&rig.source(), &relay.0, &relay.1, None, 10))
            .unwrap()
            .entries
            .is_empty()
    );
    assert_eq!(
        rival.relay_rows_seen.load(Ordering::SeqCst),
        0,
        "nothing committed under a stale lease"
    );
    // The next slice sees the rival's lease and goes on under it.
    rig.drive_on(&rival, |rig| rig.finished(&ticket.pack_id));
    assert!(matches!(
        rig.state(&ticket.pack_id),
        Some(VerificationV1::Verified { .. })
    ));
}

#[test]
fn an_in_pack_base_from_an_earlier_slice_is_reread_from_storage() {
    let (b0, raw0) = blob(0, 3_000);
    let mut writer = PackWriter::new();
    writer.push_raw(b0, &raw0).unwrap();
    for n in 1..60 {
        let (id, raw) = blob(n, 3_000);
        writer.push_raw(id, &raw).unwrap();
    }
    let (_, target) = blob(500, 3_000);
    writer
        .push_delta(&b0, &mkit_core::delta::encode(&raw0, &target).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    let rig = Rig::new();
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    let job = rig.job(&ticket.pack_id).unwrap();
    assert_eq!((job.outcome, job.entries), (None, 61));
    assert!(matches!(
        rig.state(&ticket.pack_id),
        Some(VerificationV1::Verified { .. })
    ));
    let (target_id, _) = blob(500, 3_000);
    let depth = rig
        .rows(&ticket.pack_id, keys::VC_FRAME)
        .into_iter()
        .find_map(|(key, value)| {
            let Some(keys::ParsedKey::VerifyCursor { id: Some(id), .. }) = keys::parse(&key) else {
                return None;
            };
            let row = checkpoint::decode_frame(&id, &value).unwrap();
            (row.value.delta_base == Some(b0)).then_some((row.value.chain_depth, row.external))
        });
    assert_eq!(
        depth,
        Some((1, None)),
        "an in-pack delta, not an external base"
    );
    let _ = target_id;
    assert_eq!(job.external_bytes, 0);
}

#[test]
fn an_unknown_upload_type_is_rejected_like_inline() {
    let rig = Rig::new();
    let junk = b"NOPE-unknown-upload-type".to_vec();
    let (ticket, id) = rig.add(&junk);
    rig.create(&ticket, id);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert_eq!(
        rejected(&rig, &ticket.pack_id),
        Some(("invalid_argument".into(), "unknown upload type".into()))
    );
    assert_eq!(
        rig.check(&[(&ticket, id)], [0; 32])
            .unwrap_err()
            .public_message(),
        "unknown upload type"
    );
}

#[test]
fn the_budgeted_store_charges_one_unit_per_call_however_many_keys() {
    let store = MemoryKv::default();
    let budget = super::budget::SliceBudget::new(3);
    let budgeted = super::budget::Budgeted::new(&store, &budget);
    let p = Partition::Namespace(NamespaceKey::deployment_default());
    let keys: Vec<_> = (0..40_u8).map(|n| Key::new(vec![b'k', n])).collect();
    block_on(async {
        assert_eq!(budgeted.get_many(&p, &keys).await.unwrap().len(), 40);
        assert!(!budgeted.has(&p, &keys[0]).await.unwrap());
        budgeted.get(&p, &keys[1]).await.unwrap();
        // The fourth call is past the limit: the store is not reached.
        let error = budgeted.get(&p, &keys[2]).await.unwrap_err();
        assert!(super::budget::is_exhausted(&error));
        let error = budgeted
            .apply(&p, Batch::new().put(keys[0].clone(), Value::default()))
            .await
            .unwrap_err();
        assert!(super::budget::is_exhausted(&error));
    });
    assert_eq!(budget.used(), 3);
    assert!(
        block_on(store.get(&p, &keys[0])).unwrap().is_none(),
        "the refused write never landed"
    );
}

#[test]
fn ranged_blob_reads_reserve_both_r2_requests_before_reading() {
    let store = MemoryBlobStore::default();
    let budget = super::budget::SliceBudget::new(3);
    let budgeted = super::budget::Budgeted::new(&store, &budget);
    let key = BlobKey::object([87; 32]);
    block_on(async {
        let mut sink = store.begin(key, 2).await.unwrap();
        sink.write(Bytes::from_static(b"ok")).await.unwrap();
        sink.commit_with_root(hash(b"ok")).await.unwrap();
        let range = Some(ByteRange {
            start: 0,
            end_inclusive: 1,
        });
        assert!(budgeted.get(&key, range).await.unwrap().is_some());
        assert_eq!(budget.used(), 2);
        let error = budgeted.get(&key, range).await.unwrap_err();
        assert!(super::budget::is_exhausted(&error));
    });
    assert_eq!(budget.used(), 3);
}

#[test]
fn a_child_that_became_a_member_after_the_job_looked_is_found_by_the_advance() {
    let (commit_pack, _, head, (tree, tree_raw)) = split_packs();
    let rig = Rig::new();
    let (ticket, id) = rig.add(&commit_pack);
    rig.create(&ticket, id);
    // The tree is not a member while the job looks: it stays owed.
    rig.drive(|rig| phase(rig, &ticket.pack_id) == Phase::Recheck);
    assert_eq!(rig.job(&ticket.pack_id).unwrap().owed, 1);
    let error = rig.check(&[(&ticket, id)], head).unwrap_err();
    assert_eq!(
        error.public_message(),
        "repository membership not yet visible"
    );
    // The relay catches up. The advance sees it at once; it does not wait
    // for the job's final recheck after the lag bound.
    seed_member(&rig, tree, &tree_raw);
    rig.check(&[(&ticket, id)], head).unwrap();
}

#[test]
fn the_advance_hands_the_fast_forward_check_the_staged_history_edges_up_to_the_worker_cap() {
    let tree = Object::Tree(Tree {
        entries: Vec::new(),
    });
    let tree_id = tree.id().unwrap();
    let mut writer = PackWriter::new_raw_only();
    writer
        .push_raw(tree_id, &serialize(&tree).unwrap())
        .unwrap();
    let mut prior = Vec::new();
    let mut chain = Vec::new();
    for n in 0..5_u8 {
        let (commit, id) = signed_commit(tree_id, prior.clone(), 7, &[n]);
        writer.push_raw(id, &serialize(&commit).unwrap()).unwrap();
        prior = vec![id];
        chain.push(id);
    }
    let pack = writer.finish().unwrap();
    let head = chain[4];
    let mut rig = Rig::new();
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    let staged = rig.check(&[(&ticket, id)], head).unwrap();
    assert_eq!(staged.objects, 6);
    assert_eq!(
        staged.parents.len(),
        5,
        "every commit on the way down to the root"
    );
    assert_eq!(staged.parents[&head], vec![chain[3]]);
    assert_eq!(staged.parents[&chain[0]], Vec::<Hash>::new());
    assert!(
        !staged.parents.contains_key(&tree_id),
        "a tree has no history edge"
    );
    // A Worker walks at most its cap: past it a commit is simply not staged, and
    // the fast-forward check then finds it in no member and leaves the write denied.
    rig.cfg.max_ancestry_commits = 2;
    let staged = rig.check(&[(&ticket, id)], head).unwrap();
    assert_eq!(
        staged.parents.keys().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([chain[4], chain[3]])
    );
    assert_eq!(
        IndexedConfig::scheduled(1 << 30).max_ancestry_commits,
        super::SCHEDULED_MAX_ANCESTRY_COMMITS
    );
}

#[test]
fn scheduled_history_stages_at_most_sixty_four_commits() {
    let tree = Object::Tree(Tree {
        entries: Vec::new(),
    });
    let tree_id = tree.id().unwrap();
    let mut writer = PackWriter::new_raw_only();
    writer
        .push_raw(tree_id, &serialize(&tree).unwrap())
        .unwrap();
    let mut chain = Vec::new();
    for n in 0..66_u8 {
        let (commit, id) = signed_commit(
            tree_id,
            chain.last().copied().into_iter().collect(),
            7,
            &[n],
        );
        writer.push_raw(id, &serialize(&commit).unwrap()).unwrap();
        chain.push(id);
    }
    let pack = writer.finish().unwrap();
    let rig = Rig::new();
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    let staged = rig.check(&[(&ticket, id)], chain[65]).unwrap();
    assert_eq!(staged.parents.len(), 64);
    assert!(!staged.parents.contains_key(&chain[1]));
    assert!(staged.parents.contains_key(&chain[2]));
}

#[test]
fn distinct_member_locations_of_one_base_are_each_charged() {
    let (base, base_raw) = blob(1, 3_000);
    let (middle, middle_raw) = blob(2, 3_000);
    let mut writer = PackWriter::new();
    writer.push_raw(base, &base_raw).unwrap();
    writer
        .push_delta(
            &base,
            &mkit_core::delta::encode(&base_raw, &middle_raw).unwrap(),
        )
        .unwrap();
    let member_chain = writer.finish().unwrap();
    let member_raw = (0..4_096)
        .find_map(|salt| {
            let (padding, raw) = blob(salt, 10);
            let mut writer = PackWriter::new_raw_only();
            writer.push_raw(base, &base_raw).unwrap();
            writer.push_raw(padding, &raw).unwrap();
            let bytes = writer.finish().unwrap();
            (hash(&bytes) < hash(&member_chain)).then_some(bytes)
        })
        .unwrap();
    let mut writer = PackWriter::new();
    for (id, source, salt) in [(base, &base_raw, 3), (middle, &middle_raw, 4)] {
        let (_, target) = blob(salt, 3_000);
        writer
            .push_delta(&id, &mkit_core::delta::encode(source, &target).unwrap())
            .unwrap();
    }
    let consumed = writer.finish().unwrap();
    for max_entries in [1, 4096] {
        let mut rig = Rig::new();
        rig.limits.max_entries = max_entries;
        for pack in [&member_raw, &member_chain] {
            let (ticket, _) = rig.add(pack);
            let mut frames = Vec::new();
            decode_entries_with(
                pack,
                &mut NoExternalBases,
                DecodeLimits::default(),
                |entry| {
                    frames.push(FrameMeta {
                        id: entry.id,
                        frame_offset: entry.frame_offset,
                        frame_length: entry.frame_length,
                        wire_type: entry.wire_type,
                        delta_base: entry.delta_base,
                        decoded_size: entry.bytes.len() as u64,
                    });
                    Ok(())
                },
            )
            .unwrap();
            let mut batch = Batch::new().put(
                keys::membership(&rig.repo.name, &ticket.pack_id),
                Value::default(),
            );
            for entry in index_entries(&frames, 50).unwrap() {
                batch = batch.put(
                    keys::object_index(&rig.repo.name, &entry.object, &ticket.pack_id),
                    codec::encode_object_index(&entry.object, &entry.value).unwrap(),
                );
            }
            block_on(rig.store.apply(&rig.source(), batch)).unwrap();
        }
        let (ticket, id) = rig.add(&consumed);
        rig.create(&ticket, id);
        rig.drive(|rig| rig.finished(&ticket.pack_id));
        assert_eq!(
            rig.job(&ticket.pack_id).unwrap().external_bytes,
            (2 * base_raw.len() + middle_raw.len()) as u64,
            "entry cap {max_entries}"
        );
    }
}

#[test]
fn external_source_membership_is_rechecked_after_verification() {
    for fail_at in 0..20 {
        let rig = Rig::new();
        let tree = Object::Tree(Tree {
            entries: Vec::new(),
        });
        let tree_id = tree.id().unwrap();
        let (base, base_id) = signed_commit(tree_id, Vec::new(), 8, b"old base");
        let base_raw = serialize(&base).unwrap();
        seed_member(&rig, base_id, &base_raw);
        let mut q = PackWriter::new_raw_only();
        q.push_raw(base_id, &base_raw).unwrap();
        let q_id = hash(&q.finish().unwrap());
        let (middle, middle_id) = signed_commit(tree_id, Vec::new(), 9, b"middle");
        let middle_raw = serialize(&middle).unwrap();
        let mut intermediate = PackWriter::new();
        intermediate
            .push_raw(tree_id, &serialize(&tree).unwrap())
            .unwrap();
        intermediate
            .push_delta(
                &base_id,
                &mkit_core::delta::encode(&base_raw, &middle_raw).unwrap(),
            )
            .unwrap();
        let (member, member_id) = rig.add(&intermediate.finish().unwrap());
        rig.create(&member, member_id);
        rig.drive(|r| r.finished(&member.pack_id));
        block_on(rig.store.apply(
            &rig.source(),
            Batch::new().put(
                keys::membership(&rig.repo.name, &member.pack_id),
                Value::default(),
            ),
        ))
        .unwrap();
        let (target, _) = signed_commit(tree_id, Vec::new(), 7, b"unreachable delta");
        let (visible, head) = signed_commit(tree_id, Vec::new(), 7, b"visible head");
        let mut writer = PackWriter::new();
        writer
            .push_raw(tree_id, &serialize(&tree).unwrap())
            .unwrap();
        writer
            .push_delta(
                &middle_id,
                &mkit_core::delta::encode(&middle_raw, &serialize(&target).unwrap()).unwrap(),
            )
            .unwrap();
        writer
            .push_raw(head, &serialize(&visible).unwrap())
            .unwrap();
        let pack = writer.finish().unwrap();
        let (ticket, id) = rig.add(&pack);
        rig.create(&ticket, id);
        let faulty = Faulty {
            inner: rig.store.clone(),
            applies: AtomicU32::new(0),
            fail_at: AtomicU32::new(fail_at),
            inventory_guard: None,
        };
        rig.drive_on(&faulty, |r| r.finished(&ticket.pack_id));
        let staged = rig.check(&[(&ticket, id)], head).unwrap();
        assert_eq!(
            staged.external_bases,
            BTreeSet::from([q_id, member.pack_id])
        );
        for dependency in [q_id, member.pack_id] {
            assert!(
                block_on(rig.store.has(
                    &rig.source(),
                    &keys::verify_row(
                        &rig.repo.name,
                        &ticket.pack_id,
                        keys::VC_DEPENDENCY,
                        Some(&dependency),
                    )
                ))
                .unwrap()
            );
        }
        block_on(rig.store.apply(
            &rig.source(),
            Batch::new().delete(keys::membership(&rig.repo.name, &q_id)),
        ))
        .unwrap();
        let error = rig.check(&[(&ticket, id)], head).unwrap_err();
        assert_eq!(error.code(), crate::error::Code::Unavailable);
        assert_eq!(
            error.public_message(),
            "repository membership not yet visible"
        );
        rig.clock
            .advance(i64::try_from(rig.cfg.relay_lag_bound_ms).unwrap());
        let error = rig.check(&[(&ticket, id)], head).unwrap_err();
        assert_eq!(error.code(), crate::error::Code::FailedPrecondition);
        assert_eq!(
            error.public_message(),
            "delta base not available in this repository"
        );
        assert!(rejected(&rig, &ticket.pack_id).is_none());
    }
}
#[test]
fn co_consumed_jobs_share_the_decode_budget() {
    for duplicate in [false, true] {
        let mut rig = Rig::new();
        rig.cfg.decode_budget = 3_000;
        rig.cfg.max_pack_bytes = 3_000;
        let (pack, head) = tree_pack(1, 2_000);
        let (other, raw) = blob(if duplicate { 0 } else { 22 }, 2_000);
        let mut writer = PackWriter::new_raw_only();
        writer.push_raw(other, &raw).unwrap();
        let second = writer.finish().unwrap();
        let (first_t, first_id) = rig.add(&pack);
        let (second_t, second_id) = rig.add(&second);
        for (t, id) in [(&first_t, first_id), (&second_t, second_id)] {
            rig.create(t, id);
            rig.drive(|r| r.finished(&t.pack_id));
        }
        let scheduled = rig.check(&[(&first_t, first_id), (&second_t, second_id)], head);
        let mut oracle = Rig::new();
        oracle.cfg = rig.cfg;
        let native_tickets = [oracle.add(&pack), oracle.add(&second)];
        let native = block_on(crate::indexed::verify::verify_ticketed(
            oracle.blobs.as_ref(),
            oracle.store.as_ref(),
            oracle.shards.as_ref(),
            &oracle.repo,
            &oracle.source(),
            &native_tickets
                .iter()
                .map(|(t, _)| t.clone())
                .collect::<Vec<_>>(),
            &native_tickets.iter().map(|(_, id)| *id).collect::<Vec<_>>(),
            head,
            oracle.cfg,
            oracle.clock.as_ref(),
            oracle.recorder.as_ref(),
        ));
        if duplicate {
            assert_eq!(scheduled.unwrap(), native.unwrap());
        } else {
            let error = scheduled.unwrap_err();
            assert_eq!(error.code(), crate::error::Code::InvalidArgument);
            assert_eq!(error.public_message(), native.unwrap_err().public_message());
            assert_eq!(error.public_message(), "pack exceeds indexed decode budget");
        }
        assert!(rejected(&rig, &first_t.pack_id).is_none());
        assert!(rejected(&rig, &second_t.pack_id).is_none());
    }
}

#[test]
fn interrupted_closure_and_recheck_slices_shrink_then_end_terminal() {
    for phase in [Phase::ClosureResolve, Phase::Recheck] {
        let rig = Rig::new();
        let (pack, head) = tree_pack(1, 100);
        let (ticket, id) = rig.add(&pack);
        rig.create(&ticket, id);
        rig.tick();
        let mut job = rig.job(&ticket.pack_id).unwrap();
        job.phase = if phase == Phase::Recheck {
            job.owed = 1;
            Phase::Verify
        } else {
            phase
        };
        job.final_pass = true;
        let raw = block_on(rig.store.get(
            &rig.source(),
            &keys::verify_job(&rig.repo.name, &ticket.pack_id),
        ))
        .unwrap()
        .unwrap();
        let batch = checkpoint::write_job(
            Batch::new(),
            &mut job,
            Some(&raw),
            &rig.repo.name,
            &ticket.pack_id,
        )
        .unwrap();
        block_on(rig.store.apply(&rig.source(), batch)).unwrap();
        if phase == Phase::Recheck {
            rig.clock.advance(1_000);
            rig.tick();
            assert_eq!(rig.job(&ticket.pack_id).unwrap().phase, Phase::Recheck);
        }
        let faulty = Faulty {
            inner: rig.store.clone(),
            applies: AtomicU32::new(0),
            fail_at: AtomicU32::new(0),
            inventory_guard: None,
        };
        let mut caps = BTreeSet::new();
        let (first_key, _) = rig.verification_timer(&ticket.pack_id);
        let Some(keys::ParsedKey::Timer { due_at_ms, .. }) = keys::parse(&first_key) else {
            panic!("verification timer key");
        };
        rig.clock.set(i64::try_from(due_at_ms).unwrap());
        for _ in 0..30 {
            // Commit the attempt marker, then interrupt before progress commits.
            faulty
                .fail_at
                .store(faulty.applies.load(Ordering::SeqCst) + 2, Ordering::SeqCst);
            let now = u64::try_from(rig.clock.now_ms()).unwrap();
            let previous = rig.verification_timer(&ticket.pack_id);
            let report = rig.tick_on(&faulty);
            assert_eq!((report.failed, report.fired), (1, 0));
            rig.assert_verification_backoff(&ticket.pack_id, previous, now);
            let next = report.next_wake_ms.unwrap().max(now + 1);
            rig.clock.set(i64::try_from(next).unwrap());
            let job = rig.job(&ticket.pack_id).unwrap();
            caps.insert(job.closure_cap);
            if job.outcome.is_some() {
                break;
            }
        }
        assert_eq!(caps, BTreeSet::from([1, 2, 5, 11, 22, 45, 90]));
        assert_eq!(
            rig.job(&ticket.pack_id).unwrap().outcome,
            Some(checkpoint::Outcome::ClosureCapped)
        );
        assert!(rejected(&rig, &ticket.pack_id).is_none());
        assert_eq!(
            rig.check(&[(&ticket, id)], head)
                .unwrap_err()
                .public_message(),
            "object index limit exceeded"
        );
    }
}

/// A valid index backend serving smaller pages, so one id exceeds 256 calls.
struct SmallPages(Shared<MemoryKv>);
impl NamespaceStore for SmallPages {
    fn capabilities(&self) -> StoreCapabilities {
        self.0.capabilities()
    }
    async fn get(&self, partition: &Partition, keys: &Key) -> Result<Option<Value>, StoreError> {
        self.0.get(partition, keys).await
    }
    async fn get_many(
        &self,
        partition: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.0.get_many(partition, keys).await
    }
    async fn scan(
        &self,
        partition: &Partition,
        start: &Key,
        end: &Key,
        cursor: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.0
            .scan(partition, start, end, cursor, limit.min(16))
            .await
    }
    async fn scan_many(
        &self,
        partition: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        let ranges: Vec<_> = ranges
            .iter()
            .cloned()
            .map(|mut range| {
                range.limit = range.limit.min(16);
                range
            })
            .collect();
        self.0.scan_many(partition, &ranges).await
    }
    async fn apply(&self, partition: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.0.apply(partition, batch).await
    }
    async fn stats(&self, partition: &Partition) -> Result<PartitionStats, StoreError> {
        self.0.stats(partition).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.0.probe().await
    }
}

#[test]
fn a_single_closure_id_over_one_full_slice_ends_terminal() {
    let rig = Rig::new();
    let (pack, _, _, (tree, _)) = split_packs();
    super::tests::seed_capped_index(&rig.store, &rig.repo, tree);
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    rig.tick();
    let h = rig.handler();
    let registry = TimerRegistry::new().register(VerifyTimer {
        remote: SmallPages(h.remote),
        blobs: h.blobs,
        windows: h.windows,
        shards: h.shards,
        cfg: h.cfg,
        limits: h.limits,
        lease: h.lease,
        clock: h.clock,
        metrics: h.metrics,
        extension: h.extension,
    });
    rig.clock.advance(1_000);
    let report = block_on(run_due(
        rig.store.as_ref(),
        &rig.source(),
        &registry,
        rig.clock.as_ref(),
        u64::try_from(rig.clock.now_ms()).unwrap(),
        &TickBudget::default(),
    ))
    .unwrap();
    assert_eq!(report.failed, 0);
    assert_eq!(
        rig.job(&ticket.pack_id).unwrap().outcome,
        Some(checkpoint::Outcome::ClosureCapped)
    );
    assert!((*rig.recorder.slices.lock().unwrap().last().unwrap() - 256.0).abs() < f64::EPSILON);
    assert!(rejected(&rig, &ticket.pack_id).is_none());
}

#[test]
fn hot_closure_candidates_checkpoint_progress_instead_of_livelock() {
    let rig = Rig::named("one", Arc::new(D34Shards));
    let mut children = Vec::new();
    let value = crate::store::index::IndexValue {
        frame_offset: 12,
        frame_length: 64,
        wire_type: 0,
        decoded_size: 4,
        chain_depth: 0,
        delta_base: None,
    };
    for prefix in 0..9u8 {
        let mut child = [0u8; 32];
        child[0] = prefix;
        children.push(child);
        let partition = rig.shards.object_index(&rig.repo, &child);
        for chunk in (0..4096u32).collect::<Vec<_>>().chunks(90) {
            let mut batch = Batch::new();
            for n in chunk {
                let mut candidate = [0u8; 32];
                candidate[28..].copy_from_slice(&n.to_be_bytes());
                batch = batch.put(
                    keys::object_index(&rig.repo.name, &child, &candidate),
                    codec::encode_object_index(&child, &value).unwrap(),
                );
            }
            assert!(matches!(
                block_on(rig.store.apply(&partition, batch)).unwrap(),
                BatchOutcome::Committed
            ));
        }
    }
    let tree = Object::Tree(Tree {
        entries: children
            .into_iter()
            .enumerate()
            .map(|(n, child)| TreeEntry {
                name: format!("f{n}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: child,
            })
            .collect(),
    });
    let mut writer = PackWriter::new_raw_only();
    writer
        .push_raw(tree.id().unwrap(), &serialize(&tree).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    rig.tick();
    assert_eq!(
        rig.job(&ticket.pack_id).unwrap().phase,
        Phase::ClosureResolve
    );
    // Every slice leaves a durable mark of progress, and the job finishes in a
    // bounded number of slices however the hot ids are batched.
    let mut last = {
        let job = rig.job(&ticket.pack_id).unwrap();
        (job.phase, job.scan, job.owed, job.closure_cap)
    };
    let mut slices = 0;
    while !rig.finished(&ticket.pack_id) {
        slices += 1;
        assert!(slices < 200, "closure of nine hot ids must finish");
        let now = u64::try_from(rig.clock.now_ms()).unwrap();
        let report = rig.tick();
        assert_eq!(report.failed, 0);
        let next = report.next_wake_ms.unwrap_or(now + 1_000).max(now + 1);
        rig.clock.set(i64::try_from(next).unwrap());
        let job = rig.job(&ticket.pack_id).unwrap();
        let now = (job.phase, job.scan, job.owed, job.closure_cap);
        if report.fired > 0 && now.0 == Phase::ClosureResolve {
            assert_ne!(now, last, "a closure slice must change durable state");
            assert!(now.3 <= last.3, "the cap never grows");
        }
        last = now;
    }
    let job = rig.job(&ticket.pack_id).unwrap();
    assert_eq!(job.outcome, None);
    assert_eq!(job.owed, 9);
    assert!(job.closure_final_at_ms.is_some());
    assert!(rejected(&rig, &ticket.pack_id).is_none());
    let error = rig.check(&[(&ticket, id)], [1; 32]).unwrap_err();
    assert_eq!(error.code(), crate::error::Code::InvalidArgument);
    // Per-id slices finish without livelock, while the final aggregate lookup
    // exceeds the retained-candidate budget and asks for a smaller batch.
    assert_eq!(error.public_message(), "object index limit exceeded");
    assert!(
        rig.recorder
            .slices
            .lock()
            .unwrap()
            .iter()
            .all(|calls| *calls <= 256.0)
    );
}

/// Lose a committed reference-page response once. The durable entry cursor
/// must not advance until replay has reconstructed every provisional page.
struct LostPageReply<'a> {
    inner: &'a Faulty,
    enabled: bool,
    lost: std::sync::atomic::AtomicBool,
}

impl NamespaceStore for LostPageReply<'_> {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(p, k).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        let page = batch.writes.iter().any(|write| {
            matches!(write,
            crate::store::Write::Put(key, value)
            if matches!(keys::parse(key), Some(keys::ParsedKey::VerifyCursor {
                sub: keys::VC_CANDIDATE, .. })) && value.as_bytes().first() == Some(&3))
        });
        let result = self.inner.apply(p, batch).await?;
        if self.enabled
            && page
            && matches!(result, BatchOutcome::Committed)
            && !self.lost.swap(true, Ordering::SeqCst)
        {
            return Err(StoreError::Unavailable("lost committed page reply".into()));
        }
        Ok(result)
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

#[test]
fn large_manifest_reference_pages_resume_after_partial_decode_writes() {
    use super::selection::{Projection, REFERENCES_PER_PAGE};
    let references: Vec<Hash> = (0_u32..30_000)
        .map(|n| {
            let mut id = [0; 32];
            id[..4].copy_from_slice(&n.to_be_bytes());
            id
        })
        .collect();
    let object = Object::ChunkedBlob(mkit_core::object::ChunkedBlob {
        total_size: 30_000 * 65_536,
        chunk_size: 65_536,
        chunks: references.clone(),
    });
    let raw = serialize(&object).unwrap();
    assert!(raw.len() < 1024 * 1024);
    let owner = mkit_core::object::id_from_object(&object, &raw);
    let mut writer = PackWriter::new();
    writer.push_raw(owner, &raw).unwrap();
    let pack = writer.finish().unwrap();
    for (fail_at, lost_reply) in [(0, false), (4, false), (5, false), (6, false), (0, true)] {
        let rig = Rig::new();
        let (ticket, id) = rig.add(&pack);
        rig.create(&ticket, id);
        let faulty = Faulty {
            inner: rig.store.clone(),
            applies: AtomicU32::new(0),
            fail_at: AtomicU32::new(fail_at),
            inventory_guard: None,
        };
        let replies = LostPageReply {
            inner: &faulty,
            enabled: lost_reply,
            lost: std::sync::atomic::AtomicBool::new(false),
        };
        rig.drive_on(&replies, |rig| {
            rig.job(&ticket.pack_id)
                .is_some_and(|job| !matches!(job.phase, Phase::Decode))
        });
        let raw = block_on(rig.store.get(&rig.source(),
            &keys::verify_row(&rig.repo.name, &ticket.pack_id, keys::VC_CANDIDATE, Some(&owner))))
            .unwrap().unwrap_or_else(|| panic!("completed decode retains projection (fault {fail_at}, rows {}, frames {:?}): {:?}, {:?}", rig.rows(&ticket.pack_id, keys::VC_CANDIDATE).len(), rig.rows(&ticket.pack_id, keys::VC_FRAME), rig.job(&ticket.pack_id), rig.state(&ticket.pack_id)));
        assert_eq!(replies.lost.load(Ordering::SeqCst), lost_reply);
        let projection = Projection::decode(&owner, &raw).unwrap();
        assert_eq!(projection.references, 30_000);
        let mut restored = Vec::new();
        for index in 0..projection.pages() {
            let value = block_on(rig.store.get(
                &rig.source(),
                &keys::verify_row(
                    &rig.repo.name,
                    &ticket.pack_id,
                    keys::VC_CANDIDATE,
                    Some(&projection.page_id(index)),
                ),
            ))
            .unwrap()
            .unwrap();
            assert!(value.as_bytes().len() <= 89 + REFERENCES_PER_PAGE * 32);
            restored.extend(projection.decode_page(index, &value).unwrap());
        }
        assert_eq!(restored, references);
        assert_eq!(rig.job(&ticket.pack_id).unwrap().entries, 1);
        assert!(!matches!(
            rig.state(&ticket.pack_id),
            Some(VerificationV1::Verified { .. })
        ));
    }
}

#[derive(Clone)]
struct OpaqueEtagWindows {
    inner: Arc<Windows>,
    padding: usize,
}

impl PackWindows for OpaqueEtagWindows {
    fn read<'a>(
        &'a self,
        pack: &'a Hash,
        offset: u64,
        len: u64,
        etag: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Window, WindowError>> {
        Box::pin(async move {
            let padding = "x".repeat(self.padding);
            let prior = etag
                .map(|value| value.strip_prefix(&padding).ok_or(WindowError::EtagChanged))
                .transpose()?;
            let mut window = self.inner.read(pack, offset, len, prior).await?;
            window.etag.insert_str(0, &padding);
            Ok(window)
        })
    }
}

#[test]
fn packlist_inventory_resumes_its_checkpoint_after_a_failed_slice() {
    let rig = Rig::new();
    let ids: Vec<Hash> = (0u32..263)
        .map(|n| {
            let mut id = [17; 32];
            id[..4].copy_from_slice(&n.to_be_bytes());
            id
        })
        .collect();
    let pack = mkit_core::transfer::encode_packlist(None, &ids).unwrap();
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    rig.drive(|r| {
        r.job(&ticket.pack_id)
            .is_some_and(|j| j.phase == Phase::Verify && !j.scan.is_empty())
    });
    let checkpoint = rig.job(&ticket.pack_id).unwrap();
    let offset = codec::decode_u64(&Value::new(checkpoint.scan)).unwrap();
    assert!(offset > 0 && offset < 263);
    assert!(!matches!(
        rig.state(&ticket.pack_id),
        Some(VerificationV1::Verified { .. })
    ));
    assert!(
        block_on(crate::takedown::inventory::seal(
            rig.store.as_ref(),
            &ticket.pack_id
        ))
        .is_err()
    );
    let faulty = Faulty {
        inner: rig.store.clone(),
        applies: AtomicU32::new(0),
        fail_at: AtomicU32::new(1),
        inventory_guard: Some((
            rig.repo.name.clone(),
            ticket.pack_id,
            ids.iter().copied().collect(),
        )),
    };
    assert_eq!(rig.tick_on(&faulty).failed, 1);
    assert_eq!(
        codec::decode_u64(&Value::new(rig.job(&ticket.pack_id).unwrap().scan)).unwrap(),
        offset
    );
    rig.clock.advance(1_000);
    // tick constructs a fresh registry/handler and reloads every cursor.
    rig.drive_on(&faulty, |r| r.finished(&ticket.pack_id));
    let done = rig.job(&ticket.pack_id).unwrap();
    assert!(done.scan.is_empty());
    assert_eq!(done.entries, 0);
    assert_eq!(done.outcome, None);
    assert!(matches!(
        rig.state(&ticket.pack_id),
        Some(VerificationV1::Verified { .. })
    ));
    let mut rows = BTreeSet::new();
    assert!(
        !block_on(crate::takedown::inventory::visit(
            rig.store.as_ref(),
            &ticket.pack_id,
            false,
            |id, _| {
                assert!(
                    rows.insert(id),
                    "dependency replay duplicated an inventory row"
                );
                async { Ok(false) }
            }
        ))
        .unwrap()
    );
    assert_eq!(rows, ids.into_iter().collect());
}

#[test]
#[allow(clippy::too_many_lines)] // The fixture measures both the opaque and bounded guard ledgers.
fn seven_captured_job_guards_have_an_explicit_opaque_etag_byte_ledger() {
    use crate::store::{MAX_BATCH_BYTES, MAX_VALUE_BYTES, Precondition};
    for (padding, packlists) in [(171, false), (150_000, false), (171, true), (150_000, true)] {
        let rig = Rig::new();
        let packs: Vec<_> = (0..7)
            .map(|n| {
                if !packlists {
                    return tree_pack(1, 70_000 + n).0;
                }
                let ids: Vec<Hash> = (0..263_u16)
                    .map(|id| {
                        let mut hash = [255; 32];
                        hash[..2].copy_from_slice(&id.to_be_bytes());
                        hash[31] = u8::try_from(n).unwrap();
                        hash
                    })
                    .collect();
                mkit_core::transfer::encode_packlist(None, &ids).unwrap()
            })
            .collect();
        let tickets: Vec<_> = packs.iter().map(|pack| rig.add(pack)).collect();
        let refs: Vec<_> = tickets.iter().map(|(ticket, id)| (ticket, *id)).collect();
        assert!(rig.check(&refs, [0; 32]).is_err());
        assert!(tickets.iter().all(|(t, _)| {
            rig.job(&t.pack_id)
                .is_some_and(|job| job.extraction_group.len() == 7)
        }));
        let ordinary = rig.handler();
        let handler = VerifyTimer {
            remote: ordinary.remote,
            blobs: ordinary.blobs,
            windows: OpaqueEtagWindows {
                inner: ordinary.windows,
                padding,
            },
            shards: ordinary.shards,
            cfg: ordinary.cfg,
            limits: ordinary.limits,
            lease: ordinary.lease,
            clock: ordinary.clock,
            metrics: ordinary.metrics,
            extension: ordinary.extension,
        };
        let registry =
            TimerRegistry::new()
                .register(handler)
                .register(crate::relay::RelayHandler {
                    target: Shared(rig.store.clone()),
                    hook: crate::relay::NoHook,
                    budget: crate::relay::RelayBudget::default(),
                });
        for _ in 0..300 {
            if tickets.iter().all(|(t, _)| rig.finished(&t.pack_id)) {
                break;
            }
            block_on(run_due(
                rig.store.as_ref(),
                &rig.source(),
                &registry,
                rig.clock.as_ref(),
                u64::try_from(rig.clock.now_ms()).unwrap(),
                &TickBudget::default(),
            ))
            .unwrap();
            rig.clock.advance(1_000);
        }
        assert!(tickets.iter().all(|(t, _)| rig.finished(&t.pack_id)));
        let mut batch = Batch::new().require(Precondition::NotAfter(u64::MAX));
        let mut compact = Batch::new().require(Precondition::NotAfter(u64::MAX));
        let mut values = 0;
        let mut keys_bytes = 0;
        for (ticket, _) in &tickets {
            let key = keys::verify_job(&rig.repo.name, &ticket.pack_id);
            let raw = block_on(rig.store.get(&rig.source(), &key))
                .unwrap()
                .unwrap();
            compact = compact.require(Precondition::Equals(key.clone(), raw.clone()));
            let mut job = decode_job(&raw).unwrap();
            block_on(super::checkpoint::hydrate_job(
                rig.store.as_ref(),
                &rig.source(),
                &rig.repo.name,
                &ticket.pack_id,
                &mut job,
            ))
            .unwrap();
            assert_eq!(job.entries, if packlists { 0 } else { 3 });
            assert_eq!(
                job.outcome,
                if packlists {
                    None
                } else {
                    Some(super::checkpoint::Outcome::ExtractionUnavailable)
                }
            );
            assert!(raw.as_bytes().len() <= MAX_VALUE_BYTES);
            assert!(job.cursor.is_empty());
            assert_eq!(job.packlist.len(), if packlists { 263 } else { 0 });
            assert_eq!(job.extraction_group.len(), 7);
            // Preserve the original opaque-byte ledger as a diagnostic. The
            // current producer guards only its compact content-bound token.
            assert_eq!(job.etag.as_ref().unwrap().len(), 64);
            job.etag = block_on(super::etag::resolve(
                rig.store.as_ref(),
                &rig.source(),
                &rig.repo.name,
                &ticket.pack_id,
                job.etag.as_deref(),
            ))
            .unwrap();
            let raw = super::checkpoint::encode_job(&job);
            values += raw.as_bytes().len();
            keys_bytes += key.as_bytes().len();
            batch = batch.require(Precondition::Equals(key, raw));
        }
        eprintln!(
            "guard ledger: packlists={packlists}, padding={padding}, values={values}, keys={keys_bytes}, total={}, limit={MAX_BATCH_BYTES}",
            values + keys_bytes
        );
        compact.validate(&rig.store.capabilities()).unwrap();
        if padding == 171 {
            batch.validate(&rig.store.capabilities()).unwrap();
        } else {
            assert!(values + keys_bytes > MAX_BATCH_BYTES);
            assert!(matches!(
                batch.validate(&rig.store.capabilities()),
                Err(StoreError::Invalid(_))
            ));
        }
    }
}

#[test]
fn scheduled_distinct_tickets_for_one_verified_pack_match_native_reuse() {
    let rig = Rig::new();
    let (pack, head) = tree_pack(1, 1_000);
    let (first, first_id) = rig.add(&pack);
    rig.create(&first, first_id);
    rig.drive(|rig| rig.finished(&first.pack_id));
    let (second, second_id) = rig.add(&pack);
    assert_ne!(first_id, second_id);
    assert_eq!(first.pack_id, second.pack_id);
    // Both ticket rows are valid and the pack has already completed verification.
    // Native's independent fixture accepts this exact two-ticket shape.
    rig.check(&[(&first, first_id), (&second, second_id)], head)
        .unwrap();
}

#[test]
fn scheduled_fresh_duplicate_pack_tickets_stay_pending_without_claiming_one_identity() {
    let rig = Rig::new();
    let (pack, head) = tree_pack(1, 1_000);
    let (first, first_id) = rig.add(&pack);
    let (second, second_id) = rig.add(&pack);
    let items = [(&first, first_id), (&second, second_id)];
    for _ in 0..2 {
        assert_eq!(
            rig.check(&items, head).unwrap_err().public_message(),
            "pack verification pending"
        );
        assert!(
            rig.job(&first.pack_id).is_none(),
            "fresh duplicate pack tickets must not freeze one last-writer identity"
        );
        assert!(rig.state(&first.pack_id).is_none());
    }
}

#[test]
fn duplicate_tickets_preserve_the_first_stored_rejection() {
    let rig = Rig::new();
    let (pack, head) = tree_pack(1, 1_000);
    let (first, first_id) = rig.add(&pack);
    let (second, second_id) = rig.add(&pack);
    let state = VerificationV1::Rejected {
        code: "invalid_argument".into(),
        message: "bad pack".into(),
    };
    block_on(super::state::write(
        rig.store.as_ref(),
        &rig.source(),
        &rig.repo.name,
        &first.pack_id,
        None,
        &state,
        u64::MAX,
    ))
    .unwrap();
    assert_eq!(
        rig.check(&[(&first, first_id), (&second, second_id)], head)
            .unwrap_err()
            .public_message(),
        "bad pack"
    );
    assert!(rig.job(&first.pack_id).is_none());
}

#[test]
fn verified_duplicate_pack_rebuild_keeps_both_tickets_and_first_decode_owner() {
    let rig = Rig::new();
    let (pack, head) = tree_pack(1, 1_000);
    let (first, first_id) = rig.add(&pack);
    let (second, second_id) = rig.add(&pack);
    block_on(super::state::write(
        rig.store.as_ref(),
        &rig.source(),
        &rig.repo.name,
        &first.pack_id,
        None,
        &VerificationV1::Verified {
            pack_len: first.bytes,
            verified_at_ms: NOW as u64,
            publication: None,
        },
        u64::MAX,
    ))
    .unwrap();
    let items = [(&first, first_id), (&second, second_id)];
    assert_eq!(
        rig.check(&items, head).unwrap_err().public_message(),
        "pack verification pending"
    );
    let job = rig.job(&first.pack_id).unwrap();
    assert_eq!(job.ticket_id, first_id);
    assert_eq!(job.extraction_group.len(), 2);
    assert_eq!(job.extraction_group[0].ticket, first_id);
    assert_eq!(job.extraction_group[1].ticket, second_id);
    assert!(
        job.extraction_group
            .iter()
            .all(|member| member.already_verified)
    );
    rig.drive(|rig| rig.finished(&first.pack_id));
    let facts = rig.check(&items, head).unwrap();
    assert_eq!(facts.objects, 3);
    assert!(
        block_on(rig.store.get(&rig.source(), &keys::ticket(&first_id)))
            .unwrap()
            .is_some()
    );
    assert!(
        block_on(rig.store.get(&rig.source(), &keys::ticket(&second_id)))
            .unwrap()
            .is_some()
    );
}

#[path = "extraction_tests.rs"]
mod extraction_tests;

#[path = "scheduled_reclaim_tests.rs"]
mod scheduled_reclaim_tests;

#[path = "header_tests.rs"]
mod header_tests;

#[cfg(feature = "pack-ruzstd")]
#[test]
fn fifty_in_pack_deltas_keep_cold_slice_progress_and_call_budget() {
    let mut rig = Rig::new();
    rig.limits = SliceLimits::default();
    rig.cfg.max_delta_chain_depth = 50;
    rig.cfg.extract_min_bytes = 8 << 20;
    let mut object = Object::Blob(Blob {
        data: vec![7; (1 << 20) - 64],
    });
    let mut canonical = serialize(&object).unwrap();
    let mut id = hash(&canonical);
    let mut writer = PackWriter::new();
    writer.push_raw(id, &canonical).unwrap();
    for tag in 1..=50 {
        let Object::Blob(blob) = &mut object else {
            unreachable!()
        };
        blob.data[0] = tag;
        let next = serialize(&object).unwrap();
        writer
            .push_delta(&id, &mkit_core::delta::encode(&canonical, &next).unwrap())
            .unwrap();
        canonical = next;
        id = hash(&canonical);
    }
    let pack = writer.finish().unwrap();
    let (ticket, ticket_id) = rig.add(&pack);
    rig.create(&ticket, ticket_id);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    let job = rig.job(&ticket.pack_id).unwrap();
    assert_eq!(job.entries, 51);
    assert_eq!(job.outcome, None);
    assert!(job.usable());
    let spent = rig.recorder.slices.lock().unwrap().clone();
    assert!(spent.iter().all(|used| *used <= 256.0), "{spent:?}");
}

#[cfg(feature = "pack-ruzstd")]
#[test]
fn mixed_member_and_in_pack_deltas_charge_one_external_base_across_cold_slices() {
    let mut rig = Rig::new();
    rig.limits = SliceLimits::default();
    rig.cfg.max_delta_chain_depth = 50;
    rig.cfg.extract_min_bytes = 8 << 20;
    let mut object = Object::Blob(Blob {
        data: vec![7; 64 << 10],
    });
    let mut canonical = serialize(&object).unwrap();
    let external_size = canonical.len() as u64;
    let mut id = hash(&canonical);
    seed_member(&rig, id, &canonical);
    let mut writer = PackWriter::new();
    for tag in 1..=50 {
        let Object::Blob(blob) = &mut object else {
            unreachable!()
        };
        blob.data[0] = tag;
        let next = serialize(&object).unwrap();
        writer
            .push_delta(&id, &mkit_core::delta::encode(&canonical, &next).unwrap())
            .unwrap();
        canonical = next;
        id = hash(&canonical);
    }
    let pack = writer.finish().unwrap();
    let (ticket, ticket_id) = rig.add(&pack);
    rig.create(&ticket, ticket_id);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    let job = rig.job(&ticket.pack_id).unwrap();
    assert_eq!(job.entries, 50);
    assert_eq!(
        job.external_bytes, external_size,
        "cold reacquisition must not double charge"
    );
    assert_eq!(job.outcome, None);
    assert!(job.usable());
    let spent = rig.recorder.slices.lock().unwrap().clone();
    assert!(spent.iter().all(|used| *used <= 256.0), "{spent:?}");
}

// -- batched owed-closure lookups -------------------------------------------

/// A commit on a tree that names `in_pack` blobs held by the pack itself and
/// `external` blobs it does not hold. Returns the pack and its head.
fn external_children_pack(in_pack: u16, external: &[Hash]) -> (Vec<u8>, Hash) {
    let mut writer = PackWriter::new_raw_only();
    let mut entries = Vec::new();
    let mut late = Vec::new();
    for n in 0..in_pack {
        let (id, raw) = blob(n, 64);
        entries.push(id);
        // Some blobs follow the tree, so it owes them when it is decoded.
        if n % 2 == 0 {
            writer.push_raw(id, &raw).unwrap();
        } else {
            late.push((id, raw));
        }
    }
    entries.extend_from_slice(external);
    let tree = Object::Tree(Tree {
        entries: entries
            .into_iter()
            .enumerate()
            .map(|(n, object_hash)| TreeEntry {
                name: format!("f{n:05}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash,
            })
            .collect(),
    });
    writer
        .push_raw(tree.id().unwrap(), &serialize(&tree).unwrap())
        .unwrap();
    for (id, raw) in late {
        writer.push_raw(id, &raw).unwrap();
    }
    let (commit, head) = signed_commit(tree.id().unwrap(), Vec::new(), 7, b"head");
    writer.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    (writer.finish().unwrap(), head)
}

/// `members` seeded as separate member packs, then `missing` ids nobody holds.
fn seeded_children(rig: &Rig, members: u16, missing: u16) -> Vec<Hash> {
    let mut children = Vec::new();
    for n in 0..members {
        let (id, raw) = blob(1_000 + n, 80);
        seed_member(rig, id, &raw);
        children.push(id);
    }
    children.extend((0..missing).map(|n| hash(&n.to_be_bytes())));
    children
}

fn owed_rows(rig: &Rig, pack: &Hash) -> usize {
    rig.rows(pack, keys::VC_CHILD).len()
}

#[test]
fn owed_children_are_looked_up_together_and_each_keeps_its_own_answer() {
    let rig = Rig::new();
    // Present members, ids nobody holds, and blobs the pack holds itself.
    let children = seeded_children(&rig, 6, 5);
    let (pack, head) = external_children_pack(3, &children);
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    let mut closure_slices = 0;
    while phase(&rig, &ticket.pack_id) != Phase::Recheck {
        if phase(&rig, &ticket.pack_id) == Phase::ClosureResolve {
            closure_slices += 1;
        }
        rig.clock.advance(1_000);
        assert_eq!(rig.tick().failed, 0);
        assert!(closure_slices < 4, "eleven owed children share lookups");
    }
    let job = rig.job(&ticket.pack_id).unwrap();
    assert_eq!((job.owed, job.satisfying.len()), (5, 6));
    // Only what no visible pack holds stays owed.
    assert_eq!(owed_rows(&rig, &ticket.pack_id), 5);
    // Inside the lag window those five may still arrive.
    assert_eq!(
        rig.check(&[(&ticket, id)], head)
            .unwrap_err()
            .public_message(),
        "repository membership not yet visible"
    );
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    let job = rig.job(&ticket.pack_id).unwrap();
    assert_eq!((job.owed, job.satisfying.len()), (5, 6));
    assert!(job.outcome.is_none());
    assert_eq!(owed_rows(&rig, &ticket.pack_id), 5);
    rig.clock
        .advance(i64::try_from(rig.cfg.relay_lag_bound_ms).unwrap());
    let error = rig.check(&[(&ticket, id)], head).unwrap_err();
    assert_eq!(error.code(), crate::error::Code::InvalidArgument);
    assert_eq!(error.public_message(), "open closure");
}

#[test]
fn one_capped_child_in_a_batch_ends_the_job_terminal_not_rejected() {
    let rig = Rig::new();
    let mut children = seeded_children(&rig, 4, 3);
    let capped = hash(b"capped child");
    super::tests::seed_capped_index(&rig.store, &rig.repo, capped);
    children.insert(2, capped);
    let (pack, _) = external_children_pack(2, &children);
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    rig.drive(|rig| rig.finished(&ticket.pack_id));
    assert_eq!(
        rig.job(&ticket.pack_id).unwrap().outcome,
        Some(checkpoint::Outcome::ClosureCapped)
    );
    assert!(rejected(&rig, &ticket.pack_id).is_none());
}

#[test]
fn a_crash_inside_a_batch_cannot_lose_a_dependency_or_settle_an_open_child() {
    for fail_at in 1..60 {
        let rig = Rig::new();
        let children = seeded_children(&rig, 6, 4);
        let (pack, _) = external_children_pack(2, &children);
        let (ticket, id) = rig.add(&pack);
        rig.create(&ticket, id);
        let faulty = Faulty {
            inner: rig.store.clone(),
            applies: AtomicU32::new(0),
            fail_at: AtomicU32::new(fail_at),
            inventory_guard: None,
        };
        rig.drive_on(&faulty, |rig| rig.finished(&ticket.pack_id));
        let job = rig.job(&ticket.pack_id).unwrap();
        assert_eq!(job.satisfying.len(), 6, "crash at apply {fail_at}");
        assert_eq!(job.owed, 4, "crash at apply {fail_at}");
        assert_eq!(
            owed_rows(&rig, &ticket.pack_id),
            4,
            "crash at apply {fail_at}"
        );
        if faulty.applies.load(Ordering::SeqCst) < fail_at {
            break;
        }
    }
}

/// Pages of 16 rows, so a batch of hot ids costs more calls than one slice has.
fn small_pages_tick(rig: &Rig) -> RunReport {
    let h = rig.handler();
    let registry = TimerRegistry::new().register(VerifyTimer {
        remote: SmallPages(h.remote),
        blobs: h.blobs,
        windows: h.windows,
        shards: h.shards,
        cfg: h.cfg,
        limits: h.limits,
        lease: h.lease,
        clock: h.clock,
        metrics: h.metrics,
        extension: h.extension,
    });
    block_on(run_due(
        rig.store.as_ref(),
        &rig.source(),
        &registry,
        rig.clock.as_ref(),
        u64::try_from(rig.clock.now_ms()).unwrap(),
        &TickBudget::default(),
    ))
    .unwrap()
}

#[test]
fn a_batch_that_outgrows_one_slice_shrinks_instead_of_ending_terminal() {
    let rig = Rig::named("one", Arc::new(D34Shards));
    let value = crate::store::index::IndexValue {
        frame_offset: 12,
        frame_length: 64,
        wire_type: 0,
        decoded_size: 4,
        chain_depth: 0,
        delta_base: None,
    };
    // Each child has hundreds of candidates in 16-row pages, none a member.
    let children: Vec<Hash> = (0..90u16).map(|n| hash(&n.to_be_bytes())).collect();
    for child in &children {
        let partition = rig.shards.object_index(&rig.repo, child);
        for chunk in (0..300u32).collect::<Vec<_>>().chunks(90) {
            let mut batch = Batch::new();
            for n in chunk {
                let mut candidate = [0u8; 32];
                candidate[28..].copy_from_slice(&n.to_be_bytes());
                batch = batch.put(
                    keys::object_index(&rig.repo.name, child, &candidate),
                    codec::encode_object_index(child, &value).unwrap(),
                );
            }
            block_on(rig.store.apply(&partition, batch)).unwrap();
        }
    }
    let (pack, _) = external_children_pack(0, &children);
    let (ticket, id) = rig.add(&pack);
    rig.create(&ticket, id);
    let mut smallest = u32::MAX;
    let mut previous_cap = u32::MAX;
    let mut slices = 0;
    while !matches!(
        phase(&rig, &ticket.pack_id),
        Phase::AwaitDelivery | Phase::Recheck | Phase::Watch
    ) {
        slices += 1;
        assert!(slices < 400, "a shrinking batch must finish");
        let now = u64::try_from(rig.clock.now_ms()).unwrap();
        let report = small_pages_tick(&rig);
        assert_eq!(report.failed, 0);
        let next = report.next_wake_ms.unwrap_or(now + 1_000).max(now + 1);
        rig.clock.set(i64::try_from(next).unwrap());
        let job = rig.job(&ticket.pack_id).unwrap();
        assert!(job.closure_cap <= previous_cap, "the cap never grows back");
        previous_cap = job.closure_cap;
        smallest = smallest.min(job.closure_cap);
    }
    let job = rig.job(&ticket.pack_id).unwrap();
    assert_eq!(job.outcome, None, "a batch over a slice is retried smaller");
    assert_eq!(job.owed, 90);
    assert!(smallest < 90, "the batch shrank to {smallest}");
    assert!(
        rig.recorder
            .slices
            .lock()
            .unwrap()
            .iter()
            .all(|calls| *calls <= 256.0)
    );
}
