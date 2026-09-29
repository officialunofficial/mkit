//! Extraction into the global object store (WP-4.10): selection, the
//! per-object protocol, verification, crash points, GC ordering and isolation.
#![allow(clippy::unwrap_used)] // Fixtures and assertions fail the test on invalid setup.

use bytes::Bytes;
use futures_executor::block_on;
use mkit_core::hash::{Hash, hash};
use mkit_core::object::{Blob, ChunkedBlob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::pack::PackWriter;
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::extract::{
    self, ExtractError, Extractor, Kind, MALFORMED_MESSAGE, Renew, Staged, encode_offsets, hold_id,
    hold_ttl_ms,
};
use super::tests::{NOW, repo, seed_member_raw, source, ticket, upload};
use super::{IndexedConfig, verify::verify_ticketed};
use crate::memory::{MemoryBlobStore, MemoryKv};
use crate::pipeline::SinglePartition;
use crate::repo::RepoId;
use crate::rt::ManualClock;
use crate::store::BorrowedStore;
use crate::store::{
    Batch, BatchOutcome, BlobBody, BlobKey, BlobMeta, BlobStore, ByteRange, CommitOutcome,
    ContentIndex, Cursor, Holder, Key, MAX_BLOB_PIECE_BYTES, MultipartBlobStore, NamespaceStore,
    PackSink, Partition, PartitionStats, ScanPage, StoreCapabilities, StoreError,
    UnsupportedPartSink, Value, Write, codec::TicketV1, content_shard, keys,
};
use crate::telemetry::NoopMetrics;
use crate::{BoxFuture, ServerError};

/// The size of the large files in these tests, above the 64 KiB threshold.
const BIG: usize = 70_000;

fn content(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (u8::try_from(i % 256).unwrap_or(0)).wrapping_mul(seed) ^ seed)
        .collect()
}

/// An object's id, canonical bytes and decoded form.
type Fixture = (Hash, Vec<u8>, Object);

fn blob_object(data: &[u8]) -> Fixture {
    let object = Object::Blob(Blob {
        data: data.to_vec(),
    });
    (object.id().unwrap(), serialize(&object).unwrap(), object)
}

/// A manifest over `chunks` (their contents), and its chunk objects.
fn manifest(chunks: &[Vec<u8>]) -> (Hash, ChunkedBlob, Vec<Fixture>) {
    let objects: Vec<_> = chunks.iter().map(|data| blob_object(data)).collect();
    let cb = ChunkedBlob {
        total_size: chunks.iter().map(|c| c.len() as u64).sum(),
        chunk_size: 0,
        chunks: objects.iter().map(|(id, _, _)| *id).collect(),
    };
    let id = Object::ChunkedBlob(cb.clone()).id().unwrap();
    (id, cb, objects)
}

/// A tree of one regular file, and a signed commit over it.
fn commit_of(entries: &[(&str, Hash)]) -> (Hash, Vec<u8>, Hash, Vec<u8>) {
    let tree = Object::Tree(Tree {
        entries: entries
            .iter()
            .map(|(name, id)| TreeEntry {
                name: name.as_bytes().to_vec(),
                mode: EntryMode::Blob,
                object_hash: *id,
            })
            .collect(),
    });
    let tree_id = tree.id().unwrap();
    let key = KeyPair::from_seed([7; 32]);
    let mut commit = Commit::new_unannotated(
        tree_id,
        Vec::new(),
        Identity::ed25519(key.public.0),
        key.public.0,
        b"extract".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &key).unwrap().0;
    let commit = Object::Commit(commit);
    (
        tree_id,
        serialize(&tree).unwrap(),
        commit.id().unwrap(),
        serialize(&commit).unwrap(),
    )
}

fn pack_of(objects: &[(Hash, &[u8])]) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for (id, raw) in objects {
        writer.push_raw(*id, raw).unwrap();
    }
    writer.finish().unwrap()
}

/// A consumed-ticket id that is unique per (repository, pack).
fn ticket_id(repo: &RepoId, pack: &[u8]) -> Hash {
    hash(&[repo.name.as_str().as_bytes(), &hash(pack)].concat())
}

fn run<B: MultipartBlobStore, S: NamespaceStore>(
    blobs: &B,
    store: &S,
    repo: &RepoId,
    packs: &[&[u8]],
    head: Hash,
    cfg: IndexedConfig,
    clock: &ManualClock,
) -> Result<Vec<Hash>, ServerError> {
    let tickets: Vec<TicketV1> = packs
        .iter()
        .map(|pack| ticket(repo, pack, NOW as u64))
        .collect();
    let ids: Vec<Hash> = packs.iter().map(|pack| ticket_id(repo, pack)).collect();
    block_on(verify_ticketed(
        blobs,
        store,
        &SinglePartition,
        repo,
        &source(repo),
        &tickets,
        &ids,
        head,
        cfg,
        clock,
        &NoopMetrics,
    ))
}

struct World {
    blobs: MemoryBlobStore,
    clock: Arc<ManualClock>,
    store: MemoryKv,
}

impl World {
    fn new() -> Self {
        let clock = Arc::new(ManualClock::new(NOW));
        Self {
            blobs: MemoryBlobStore::default(),
            store: MemoryKv::with_clock(clock.clone()),
            clock,
        }
    }

    fn content(&self) -> ContentIndex<BorrowedStore<'_, MemoryKv>> {
        ContentIndex::new(BorrowedStore(&self.store))
    }

    fn stored(&self, id: &Hash) -> Option<u64> {
        block_on(self.blobs.head(&BlobKey::object(*id)))
            .unwrap()
            .map(|m| m.len)
    }

    fn read(&self, key: &BlobKey) -> Vec<u8> {
        let body = block_on(self.blobs.get(key, None)).unwrap().unwrap();
        match body {
            BlobBody::Bytes(bytes) => bytes.to_vec(),
            BlobBody::Stream { mut stream, .. } => {
                let mut out = Vec::new();
                while let Some(piece) =
                    block_on(core::future::poll_fn(|cx| stream.as_mut().poll_next(cx)))
                {
                    out.extend_from_slice(&piece.unwrap());
                }
                out
            }
        }
    }

    /// The hold rows currently on `id`.
    fn holds(&self, id: &Hash) -> usize {
        let (start, end) = keys::holds_of(id);
        block_on(self.store.scan(&content_shard(id), &start, &end, None, 100))
            .unwrap()
            .entries
            .len()
    }

    fn holders(&self, id: &Hash) -> Vec<String> {
        block_on(self.content().holders(id, None, 100))
            .unwrap()
            .holders
            .into_iter()
            .map(|h| h.repo.as_str().to_owned())
            .collect()
    }

    /// The crash-matrix invariant: a present object is never unprotected.
    fn assert_protected(&self, id: &Hash) {
        if self.stored(id).is_some() {
            assert!(
                self.holds(id) > 0 || !self.holders(id).is_empty(),
                "object present with neither a hold nor a holder"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Pure pieces.

#[test]
fn selection_threshold_and_chunk_only_blobs() {
    let staged_of = |objects: Vec<(Hash, Vec<u8>, Object)>| -> Staged {
        objects
            .into_iter()
            .map(|(id, raw, object)| (id, (raw, object, 0)))
            .collect()
    };
    let below = blob_object(&content(3, 65_535));
    let at = blob_object(&content(5, 65_536));
    let staged = staged_of(vec![below.clone(), at.clone()]);
    let selected = extract::select(&staged, 65_536);
    assert_eq!(selected.keys().copied().collect::<Vec<_>>(), vec![at.0]);
    assert_eq!(selected[&at.0], Kind::Blob);
    // A lower threshold is honored.
    assert_eq!(extract::select(&staged, 1).len(), 2);

    // A blob that is only a chunk of a staged manifest is not extracted; the
    // manifest is, whatever its size.
    let chunks = vec![content(7, 70_000), content(9, 70_000)];
    let (manifest_id, _, objects) = manifest(&chunks);
    let mut all = objects.clone();
    all.push((
        manifest_id,
        Vec::new(),
        Object::ChunkedBlob(manifest(&chunks).1),
    ));
    let selected = extract::select(&staged_of(all.clone()), 65_536);
    assert_eq!(
        selected.keys().copied().collect::<Vec<_>>(),
        vec![manifest_id]
    );
    assert_eq!(selected[&manifest_id], Kind::Chunked);

    // A blob that is both a file (a staged tree references it) and a chunk
    // is extracted.
    let (tree_id, tree_raw, _, _) = commit_of(&[("file", objects[0].0)]);
    let tree = mkit_core::serialize::deserialize(&tree_raw).unwrap();
    all.push((tree_id, tree_raw, tree));
    let selected = extract::select(&staged_of(all), 65_536);
    let mut want = vec![manifest_id, objects[0].0];
    want.sort_unstable();
    assert_eq!(selected.keys().copied().collect::<Vec<_>>(), want);
}

#[test]
fn offsets_sidecar_layout_golden() {
    assert_eq!(
        encode_offsets(&[0, 3, 10]),
        [
            b"MKOF".as_slice(),
            &2_u32.to_le_bytes(),
            &0_u64.to_le_bytes(),
            &3_u64.to_le_bytes(),
            &10_u64.to_le_bytes(),
        ]
        .concat()
    );
    assert_eq!(
        encode_offsets(&[0]),
        [b"MKOF".as_slice(), &[0; 4], &[0; 8]].concat()
    );
}

#[test]
fn hold_ids_are_deterministic_and_scoped() {
    let (a, b) = (repo("a"), repo("b"));
    let (t1, t2, o1, o2) = ([1; 32], [2; 32], [3; 32], [4; 32]);
    let base = hold_id(&a, &t1, &o1);
    assert_eq!(base, hold_id(&a, &t1, &o1));
    for other in [
        hold_id(&b, &t1, &o1),
        hold_id(&a, &t2, &o1),
        hold_id(&a, &t1, &o2),
    ] {
        assert_ne!(base, other);
    }
    // The documented preimage.
    let mut preimage = b"mkit-extract-hold:v1".to_vec();
    for part in [a.namespace.as_str(), a.name.as_str()] {
        preimage.extend_from_slice(&u32::try_from(part.len()).unwrap().to_le_bytes());
        preimage.extend_from_slice(part.as_bytes());
    }
    preimage.extend_from_slice(&t1);
    preimage.extend_from_slice(&o1);
    assert_eq!(base, hash(&preimage));
}

#[test]
fn hold_ttl_covers_the_relay_and_stays_capped() {
    let hour = 60 * 60 * 1000;
    assert_eq!(hold_ttl_ms(60_000), hour);
    assert_eq!(hold_ttl_ms(2 * hour), 2 * hour + 10_000 + 10 * 60 * 1000);
    assert_eq!(hold_ttl_ms(u64::MAX), crate::store::MAX_HOLD_TTL_MS);
}

// ---------------------------------------------------------------------------
// Whole pushes through `verify_ticketed`.

/// One repository's push of a single large file.
fn file_push(data: &[u8]) -> (Vec<u8>, Hash, Hash) {
    let (blob_id, blob_raw, _) = blob_object(data);
    let (tree_id, tree_raw, head, commit_raw) = commit_of(&[("big", blob_id)]);
    let pack = pack_of(&[
        (blob_id, &blob_raw),
        (tree_id, &tree_raw),
        (head, &commit_raw),
    ]);
    (pack, head, blob_id)
}

#[test]
fn two_repositories_pushing_one_file_share_one_object_with_two_holders() {
    let world = World::new();
    let data = content(11, BIG);
    let (pack, head, id) = file_push(&data);
    upload(&world.blobs, &pack);
    let mut answers = Vec::new();
    let mut bytes = Vec::new();
    for name in ["a", "b"] {
        let repo = repo(name);
        answers.push(
            run(
                &world.blobs,
                &world.store,
                &repo,
                &[&pack],
                head,
                IndexedConfig::default(),
                &world.clock,
            )
            .unwrap(),
        );
        bytes.push(world.read(&BlobKey::object(id)));
    }
    assert_eq!(answers[0], answers[1], "byte-identical responses");
    assert_eq!(bytes[0], bytes[1], "the second push left the stored bytes");
    assert_eq!(bytes[0], data, "stored bytes are the file, not just its id");
    assert_eq!(world.stored(&id), Some(BIG as u64));
    assert_eq!(world.read(&BlobKey::object(id)), data, "raw content");
    assert_eq!(world.holders(&id), ["a", "b"]);
    assert_eq!(world.holds(&id), 0, "both holds were released");
    world.assert_protected(&id);
    assert_eq!(
        block_on(world.content().state(&id))
            .unwrap()
            .unwrap()
            .holders,
        2
    );
    // The extracted copy is not a pack: no pack RPC can serve it.
    assert!(
        block_on(world.blobs.head(&BlobKey::pack(id)))
            .unwrap()
            .is_none()
    );
    // The holder record carries the consuming ticket.
    let a = repo("a");
    let record = block_on(
        world
            .content()
            .holder_record(&id, &Holder::new(a.namespace.clone(), a.name.clone())),
    )
    .unwrap()
    .unwrap();
    assert_eq!(record.op_id, ticket_id(&a, &pack));
    // A blob under the threshold stays in its pack only.
    let (small, small_head, small_id) = file_push(&content(13, 65_535));
    upload(&world.blobs, &small);
    run(
        &world.blobs,
        &world.store,
        &repo("a"),
        &[&small],
        small_head,
        IndexedConfig::default(),
        &world.clock,
    )
    .unwrap();
    assert_eq!(world.stored(&small_id), None);
}

#[test]
fn chunked_blob_round_trip_from_staged_member_and_mixed_chunks() {
    let chunks = vec![
        content(3, 4_000),
        content(5, 9_000),
        content(7, 1_500),
        content(9, 2),
    ];
    let whole: Vec<u8> = chunks.concat();
    for (label, member_chunks) in [
        ("staged", vec![]),
        ("member", vec![0, 1, 2, 3]),
        ("mixed", vec![1, 3]),
    ] {
        let world = World::new();
        let repo = repo(label);
        let (manifest_id, cb, objects) = manifest(&chunks);
        let manifest_raw = serialize(&Object::ChunkedBlob(cb.clone())).unwrap();
        let (tree_id, tree_raw, head, commit_raw) = commit_of(&[("file", manifest_id)]);
        let mut staged: Vec<(Hash, Vec<u8>)> = vec![
            (manifest_id, manifest_raw.clone()),
            (tree_id, tree_raw.clone()),
            (head, commit_raw.clone()),
        ];
        for (i, (id, raw, _)) in objects.iter().enumerate() {
            if member_chunks.contains(&i) {
                seed_member_raw(&world.blobs, &world.store, &repo, *id, raw);
            } else {
                staged.push((*id, raw.clone()));
            }
        }
        let refs: Vec<(Hash, &[u8])> = staged
            .iter()
            .map(|(id, raw)| (*id, raw.as_slice()))
            .collect();
        let pack = pack_of(&refs);
        upload(&world.blobs, &pack);
        run(
            &world.blobs,
            &world.store,
            &repo,
            &[&pack],
            head,
            IndexedConfig::default(),
            &world.clock,
        )
        .unwrap_or_else(|e| panic!("{label}: {}", e.public_message()));
        // Reassembled content, byte for byte, never the manifest.
        assert_eq!(
            world.stored(&manifest_id),
            Some(whole.len() as u64),
            "{label}"
        );
        assert_eq!(world.read(&BlobKey::object(manifest_id)), whole, "{label}");
        // The chunks themselves are chunk-only blobs: not extracted.
        for (id, _, _) in &objects {
            assert_eq!(world.stored(id), None, "{label}: chunk extracted");
        }
        // The sidecar is exactly the boundaries and feeds the range prover.
        let boundaries: Vec<u64> = [0, 4_000, 13_000, 14_500, 14_502].to_vec();
        let sidecar = world.read(&BlobKey::object_offsets(manifest_id));
        assert_eq!(sidecar, encode_offsets(&boundaries), "{label}");
        let mut all: BTreeMap<Hash, Vec<u8>> = objects
            .iter()
            .map(|(id, raw, _)| (*id, raw.clone()))
            .collect();
        all.extend([
            (manifest_id, manifest_raw),
            (tree_id, tree_raw),
            (head, commit_raw),
        ]);
        let proof = mkit_core::verify::span::build_range_proof_from(
            &MapSource(all),
            &head,
            &[b"file"],
            12_990,
            30,
            Some(&boundaries),
        );
        assert!(proof.is_ok(), "{label}: {proof:?}");
        assert_eq!(world.holders(&manifest_id), [label]);
        assert_eq!(world.holds(&manifest_id), 0);
    }
}

struct MapSource(BTreeMap<Hash, Vec<u8>>);

impl mkit_core::store::ObjectSource for MapSource {
    fn read(&self, h: &Hash) -> mkit_core::store::StoreResult<Vec<u8>> {
        self.0
            .get(h)
            .cloned()
            .ok_or_else(|| mkit_core::store::StoreError::ObjectNotFound(mkit_core::hash::to_hex(h)))
    }
}

#[test]
fn a_chunk_known_only_to_another_repository_answers_like_a_missing_chunk() {
    let chunks = vec![content(3, 4_000), content(5, 9_000)];
    let (manifest_id, cb, objects) = manifest(&chunks);
    let manifest_raw = serialize(&Object::ChunkedBlob(cb)).unwrap();
    let (tree_id, tree_raw, head, commit_raw) = commit_of(&[("file", manifest_id)]);
    // The pack carries the manifest but not its second chunk.
    let pack = pack_of(&[
        (objects[0].0, &objects[0].1),
        (manifest_id, &manifest_raw),
        (tree_id, &tree_raw),
        (head, &commit_raw),
    ]);
    let answer = |seed_foreign: bool, extracted_elsewhere: bool| {
        let world = World::new();
        upload(&world.blobs, &pack);
        if seed_foreign {
            seed_member_raw(
                &world.blobs,
                &world.store,
                &repo("other"),
                objects[1].0,
                &objects[1].1,
            );
        }
        if extracted_elsewhere {
            // The chunk sits in the global object store under its id.
            let key = BlobKey::object(objects[1].0);
            block_on(async {
                let mut sink = world.blobs.begin(key, 4).await.unwrap();
                sink.write(Bytes::from_static(b"data")).await.unwrap();
                sink.commit_with_root(hash(b"data")).await.unwrap();
            });
        }
        world.clock.advance(60_000);
        let e = run(
            &world.blobs,
            &world.store,
            &repo("mine"),
            &[&pack],
            head,
            IndexedConfig::default(),
            &world.clock,
        )
        .unwrap_err();
        assert_eq!(world.stored(&manifest_id), None, "nothing was extracted");
        (
            e.code(),
            e.public_message().to_owned(),
            e.details().to_vec(),
        )
    };
    let nowhere = answer(false, false);
    assert_eq!(nowhere.1, "open closure");
    assert_eq!(answer(true, false), nowhere, "foreign-only chunk");
    assert_eq!(
        answer(false, true),
        nowhere,
        "chunk only in the object store"
    );
}

#[test]
fn extraction_budget_and_decode_budget_answer_the_existing_message() {
    let world = World::new();
    let data = content(17, BIG);
    let (pack, head, id) = file_push(&data);
    upload(&world.blobs, &pack);
    let tight = IndexedConfig {
        max_extract_bytes: Some(BIG as u64 - 1),
        ..IndexedConfig::default()
    };
    let e = run(
        &world.blobs,
        &world.store,
        &repo("a"),
        &[&pack],
        head,
        tight,
        &world.clock,
    )
    .unwrap_err();
    assert_eq!(e.public_message(), "pack exceeds indexed decode budget");
    assert_eq!(e.code(), crate::Code::InvalidArgument);
    assert_eq!(world.stored(&id), None);
    let exact = IndexedConfig {
        max_extract_bytes: Some(BIG as u64),
        ..IndexedConfig::default()
    };
    run(
        &world.blobs,
        &world.store,
        &repo("a"),
        &[&pack],
        head,
        exact,
        &world.clock,
    )
    .unwrap();
    assert_eq!(world.stored(&id), Some(BIG as u64));
}

#[test]
fn lost_lease_during_extraction_is_pending_and_the_redo_is_idempotent() {
    let world = World::new();
    let data = content(19, 3 * MAX_BLOB_PIECE_BYTES);
    let (pack, head, id) = file_push(&data);
    upload(&world.blobs, &pack);
    let slow = SlowBlobs {
        inner: world.blobs.clone(),
        clock: world.clock.clone(),
        step_ms: 20_000,
    };
    let e = run(
        &slow,
        &world.store,
        &repo("a"),
        &[&pack],
        head,
        IndexedConfig::default(),
        &world.clock,
    );
    // Each piece takes 20 s of the 30 s lease: the extractor renews between
    // pieces, so the lease is kept and the push succeeds.
    assert!(
        e.is_ok(),
        "{:?}",
        e.map_err(|e| e.public_message().to_owned())
    );
    assert_eq!(world.stored(&id), Some(data.len() as u64));
    // A verifier that loses the lease mid-extraction answers pending, and
    // its redo after the rival is gone succeeds against the stored object.
    let world = World::new();
    upload(&world.blobs, &pack);
    let rival = LoseLease {
        inner: MemoryKv::with_clock(world.clock.clone()),
        clock: world.clock.clone(),
        armed: AtomicBool::new(false),
    };
    let slow = SlowBlobs {
        inner: world.blobs.clone(),
        clock: world.clock.clone(),
        step_ms: 20_000,
    };
    rival.armed.store(true, Ordering::SeqCst);
    let e = run(
        &slow,
        &rival,
        &repo("a"),
        &[&pack],
        head,
        IndexedConfig::default(),
        &world.clock,
    )
    .unwrap_err();
    assert_eq!(e.public_message(), "pack verification pending");
    assert_eq!(world.stored(&id), None, "the object was not committed");
    rival.armed.store(false, Ordering::SeqCst);
    world.clock.advance(120_000);
    run(
        &slow,
        &rival,
        &repo("a"),
        &[&pack],
        head,
        IndexedConfig::default(),
        &world.clock,
    )
    .unwrap();
    assert_eq!(world.stored(&id), Some(data.len() as u64));
}

/// A blob store whose writes each take `step_ms` of the shared clock.
struct SlowBlobs {
    inner: MemoryBlobStore,
    clock: Arc<ManualClock>,
    step_ms: i64,
}

struct SlowSink {
    inner: <MemoryBlobStore as BlobStore>::Sink,
    clock: Arc<ManualClock>,
    step_ms: i64,
}

impl BlobStore for SlowBlobs {
    type Sink = SlowSink;

    async fn begin(&self, key: BlobKey, len: u64) -> Result<SlowSink, StoreError> {
        Ok(SlowSink {
            inner: self.inner.begin(key, len).await?,
            clock: self.clock.clone(),
            step_ms: self.step_ms,
        })
    }

    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        self.inner.get(key, range).await
    }

    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.inner.head(key).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }

    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
}

impl MultipartBlobStore for SlowBlobs {
    type PartSink = UnsupportedPartSink;
    const MAX_PARTS: u32 = 0;
}

impl PackSink for SlowSink {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        // Pack uploads read through `get`; only extraction writes here.
        self.clock.advance(self.step_ms);
        self.inner.write(chunk).await
    }

    async fn commit(self) -> Result<CommitOutcome, StoreError> {
        self.inner.commit().await
    }

    async fn commit_with_root(self, root: Hash) -> Result<CommitOutcome, StoreError> {
        self.inner.commit_with_root(root).await
    }

    async fn abort(self) {
        self.inner.abort().await;
    }
}

/// A store that, while armed, replaces the first verification lease renewal
/// with a rival's newer lease.
struct LoseLease {
    inner: MemoryKv,
    clock: Arc<ManualClock>,
    armed: AtomicBool,
}

impl NamespaceStore for LoseLease {
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
        // A renewal is a guarded rewrite of a pending state: the first one
        // during extraction finds a rival's lease instead.
        let renewal = batch.writes.iter().find_map(|w| match w {
            Write::Put(key, value)
                if matches!(
                    super::state::decode(value),
                    Ok(super::state::VerificationV1::Pending { .. })
                ) && batch
                    .preconditions
                    .iter()
                    .any(|pre| matches!(pre, crate::Precondition::Equals(k, _) if k == key)) =>
            {
                Some(key.clone())
            }
            _ => None,
        });
        if let Some(key) = renewal
            && self.armed.swap(false, Ordering::SeqCst)
        {
            let rival = super::state::VerificationV1::Pending {
                lease_until_ms: u64::try_from(crate::Clock::now_ms(self.clock.as_ref())).unwrap()
                    + super::state::VERIFICATION_LEASE_MS
                    + 1,
            };
            self.inner
                .apply(p, Batch::new().put(key, super::state::encode(&rival)))
                .await?;
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

// ---------------------------------------------------------------------------
// The per-object step, driven directly.

struct NoRenew;

impl Renew for NoRenew {
    fn renew(&mut self) -> BoxFuture<'_, Result<(), ServerError>> {
        Box::pin(async { Ok(()) })
    }
}

fn staged_of(objects: &[(Hash, Vec<u8>, Object)]) -> Staged {
    objects
        .iter()
        .map(|(id, raw, object)| (*id, (raw.clone(), object.clone(), 0)))
        .collect()
}

fn extractor<'a, B: MultipartBlobStore, S: NamespaceStore>(
    blobs: &'a B,
    store: &'a S,
    repo: &'a RepoId,
    clock: &'a ManualClock,
    staged: &'a Staged,
) -> Extractor<'a, B, S> {
    Extractor {
        blobs,
        store,
        shards: &SinglePartition,
        repo,
        cfg: IndexedConfig::default(),
        clock,
        metrics: &NoopMetrics,
        staged,
        staged_bytes: 0,
        resolved: AtomicU64::new(0),
    }
}

const TICKET: Hash = [0x77; 32];

fn extract_one<B: MultipartBlobStore, S: NamespaceStore>(
    ex: &Extractor<'_, B, S>,
    id: Hash,
    kind: Kind,
) -> Result<(), ServerError> {
    match extract_raw(ex, id, kind) {
        Ok(()) => Ok(()),
        Err(ExtractError::Server(error)) => Err(error),
        Err(ExtractError::Content) => panic!("unexpected content rejection"),
    }
}

fn extract_raw<B: MultipartBlobStore, S: NamespaceStore>(
    ex: &Extractor<'_, B, S>,
    id: Hash,
    kind: Kind,
) -> Result<(), ExtractError> {
    block_on(ex.extract(id, kind, &TICKET, &mut NoRenew))
}

#[test]
fn corrupt_chunks_and_sizes_commit_nothing() {
    let chunks = vec![content(3, 4_000), content(5, 9_000)];
    let (manifest_id, cb, objects) = manifest(&chunks);
    let repo = repo("a");
    let clock = ManualClock::new(NOW);
    let manifest_object = Object::ChunkedBlob(cb.clone());
    let good = |extra: Option<(Hash, Vec<u8>, Object)>, cb: ChunkedBlob| {
        let mut all = objects.clone();
        all.extend(extra);
        all.push((manifest_id, Vec::new(), Object::ChunkedBlob(cb)));
        staged_of(&all)
    };
    let attempt = |staged: Staged| {
        let world = World::new();
        let ex = extractor(&world.blobs, &world.store, &repo, &clock, &staged);
        let result = extract_raw(&ex, manifest_id, Kind::Chunked);
        assert_eq!(world.stored(&manifest_id), None, "nothing is visible");
        assert!(
            block_on(world.blobs.head(&BlobKey::object_offsets(manifest_id)))
                .unwrap()
                .is_none()
        );
        assert!(world.holders(&manifest_id).is_empty(), "no holder recorded");
        result
    };
    // The control: the same objects extract fine.
    {
        let staged = good(None, cb.clone());
        let world = World::new();
        let ex = extractor(&world.blobs, &world.store, &repo, &clock, &staged);
        extract_one(&ex, manifest_id, Kind::Chunked).unwrap();
        assert_eq!(world.stored(&manifest_id), Some(13_000));
    }
    let inconsistent = |r: Result<(), ExtractError>| {
        let Err(ExtractError::Server(e)) = r else {
            panic!("expected a storage inconsistency");
        };
        assert_eq!(e.public_message(), "verified pack content inconsistency");
        assert_eq!(e.code(), crate::Code::Unavailable);
    };
    // A client-crafted manifest is a content rejection, not a fault.
    let mut case = 0;
    let mut malformed = |r: Result<(), ExtractError>| {
        case += 1;
        assert!(
            matches!(r, Err(ExtractError::Content)),
            "case {case}: {r:?}"
        );
    };
    // A total_size that disagrees with the chunks, either way.
    for total in [12_999, 13_001] {
        let mut bad = cb.clone();
        bad.total_size = total;
        malformed(attempt(good(None, bad)));
    }
    // A chunk whose canonical bytes do not hash to the manifest's id is a
    // storage fault: the staged bytes were verified when they were staged.
    let mut tampered = objects.clone();
    tampered[1].1 = serialize(&Object::Blob(Blob {
        data: content(6, 9_000),
    }))
    .unwrap();
    let mut all = tampered;
    all.push((manifest_id, Vec::new(), manifest_object.clone()));
    inconsistent(attempt(staged_of(&all)));
    // A wrong-type chunk under a chunk id.
    let (tree_id, tree_raw, _, _) = commit_of(&[("x", [1; 32])]);
    let tree = mkit_core::serialize::deserialize(&tree_raw).unwrap();
    let mut wrong = cb.clone();
    wrong.chunks[1] = tree_id;
    let extra = Some((tree_id, tree_raw, tree));
    malformed(attempt(good(extra, wrong)));
    // A chunk that is neither staged nor a member of this repository.
    let mut missing = cb;
    missing.chunks.push([0xee; 32]);
    inconsistent(attempt(good(None, missing)));
}

type CommitHook = Box<dyn Fn(&BlobKey) + Send>;

/// Fails the `nth` blob write of the object namespace, or its `begin`.
#[derive(Clone, Default)]
struct FaultBlobs {
    inner: MemoryBlobStore,
    fail_begin: Arc<AtomicBool>,
    /// Fail the n-th `begin` (1-based) instead of the next one.
    fail_begin_at: Arc<AtomicU32>,
    begins: Arc<AtomicU32>,
    /// Answer `begin` with a full spool, for every call while set.
    full_spool: Arc<AtomicBool>,
    /// The namespace of every `get`, in order.
    gets: Arc<Mutex<Vec<crate::store::BlobNamespace>>>,
    fail_write: Arc<AtomicU32>,
    writes: Arc<AtomicU32>,
    max_piece: Arc<AtomicU64>,
    /// Called with the key just before a commit is attempted.
    before_commit: Arc<Mutex<Option<CommitHook>>>,
}

struct FaultSink {
    inner: <MemoryBlobStore as BlobStore>::Sink,
    faults: FaultBlobs,
    key: BlobKey,
}

impl BlobStore for FaultBlobs {
    type Sink = FaultSink;

    async fn begin(&self, key: BlobKey, len: u64) -> Result<FaultSink, StoreError> {
        let n = self.begins.fetch_add(1, Ordering::SeqCst) + 1;
        if self.full_spool.load(Ordering::SeqCst) {
            return Err(StoreError::Full);
        }
        if self.fail_begin.swap(false, Ordering::SeqCst)
            || self.fail_begin_at.load(Ordering::SeqCst) == n
        {
            return Err(StoreError::unavailable("injected begin fault"));
        }
        Ok(FaultSink {
            inner: self.inner.begin(key, len).await?,
            faults: self.clone(),
            key,
        })
    }

    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        self.gets.lock().unwrap().push(key.namespace());
        self.inner.get(key, range).await
    }

    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.inner.head(key).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }

    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
}

impl MultipartBlobStore for FaultBlobs {
    type PartSink = UnsupportedPartSink;
    const MAX_PARTS: u32 = 0;
}

impl PackSink for FaultSink {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        let n = self.faults.writes.fetch_add(1, Ordering::SeqCst) + 1;
        self.faults
            .max_piece
            .fetch_max(chunk.len() as u64, Ordering::SeqCst);
        if self.faults.fail_write.load(Ordering::SeqCst) == n {
            return Err(StoreError::unavailable("injected mid-stream fault"));
        }
        self.inner.write(chunk).await
    }

    async fn commit(self) -> Result<CommitOutcome, StoreError> {
        self.inner.commit().await
    }

    async fn commit_with_root(self, root: Hash) -> Result<CommitOutcome, StoreError> {
        if let Some(check) = &*self.faults.before_commit.lock().unwrap() {
            check(&self.key);
        }
        self.inner.commit_with_root(root).await
    }

    async fn abort(self) {
        self.inner.abort().await;
    }
}

/// A store that fails, once, the batch that records a holder.
struct FaultKv {
    inner: MemoryKv,
    fail_holder: AtomicBool,
    fail_verified: AtomicBool,
}

impl NamespaceStore for FaultKv {
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
        let puts = |tag: &[u8]| {
            batch
                .writes
                .iter()
                .any(|w| matches!(w, Write::Put(k, _) if k.as_bytes().starts_with(tag)))
        };
        if puts(b"h\0") && self.fail_holder.swap(false, Ordering::SeqCst) {
            return Err(StoreError::unavailable("injected holder fault"));
        }
        let verified = batch.writes.iter().any(|w| {
            matches!(w, Write::Put(k, v) if k.as_bytes().starts_with(b"vs\0")
                && matches!(super::state::decode(v), Ok(super::state::VerificationV1::Verified { .. })))
        });
        if verified && self.fail_verified.swap(false, Ordering::SeqCst) {
            return Err(StoreError::unavailable("injected verified fault"));
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

fn fault_world() -> (FaultBlobs, FaultKv, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(NOW));
    let kv = FaultKv {
        inner: MemoryKv::with_clock(clock.clone()),
        fail_holder: AtomicBool::new(false),
        fail_verified: AtomicBool::new(false),
    };
    (FaultBlobs::default(), kv, clock)
}

fn protected(blobs: &FaultBlobs, kv: &FaultKv, id: &Hash) {
    let content = ContentIndex::new(BorrowedStore(kv));
    let (start, end) = keys::holds_of(id);
    let holds = block_on(kv.scan(&content_shard(id), &start, &end, None, 10)).unwrap();
    let holders = block_on(content.holders(id, None, 10)).unwrap();
    if block_on(blobs.head(&BlobKey::object(*id)))
        .unwrap()
        .is_some()
    {
        assert!(
            !holds.entries.is_empty() || !holders.holders.is_empty(),
            "object present with neither a hold nor a holder"
        );
    }
}

/// Poll a future that completes without waiting (a memory-store read), for
/// hooks that run inside another executor.
fn now<T>(future: impl core::future::Future<Output = T>) -> T {
    let mut future = core::pin::pin!(future);
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    match future.as_mut().poll(&mut cx) {
        core::task::Poll::Ready(value) => value,
        core::task::Poll::Pending => panic!("a memory read waited"),
    }
}

#[test]
fn crash_matrix_never_leaves_a_present_object_unprotected() {
    let data = content(23, 3 * MAX_BLOB_PIECE_BYTES / 2);
    let (id, raw, object) = blob_object(&data);
    let staged = staged_of(&[(id, raw, object)]);
    let repo = repo("a");
    let holder = Holder::new(repo.namespace.clone(), repo.name.clone());
    let hold_key = keys::hold(&id, &hold_id(&repo, &TICKET, &id));
    let hold_present = |kv: &FaultKv| {
        block_on(kv.get(&content_shard(&id), &hold_key))
            .unwrap()
            .is_some()
    };
    let record = |kv: &FaultKv| {
        block_on(ContentIndex::new(BorrowedStore(kv)).holder_record(&id, &holder)).unwrap()
    };
    let stored = |blobs: &FaultBlobs| {
        block_on(blobs.head(&BlobKey::object(id)))
            .unwrap()
            .map(|m| m.len)
    };

    // After the hold, before the put (`begin` fails): the hold stays, the
    // object is absent, and the retry succeeds and releases it.
    let (blobs, kv, clock) = fault_world();
    blobs.fail_begin.store(true, Ordering::SeqCst);
    let ex = extractor(&blobs, &kv, &repo, &clock, &staged);
    assert!(extract_one(&ex, id, Kind::Blob).is_err());
    assert!(hold_present(&kv));
    assert_eq!(stored(&blobs), None);
    extract_one(&ex, id, Kind::Blob).unwrap();
    assert!(!hold_present(&kv), "released with the holder");
    assert!(record(&kv).is_some());

    // Mid-stream: nothing is visible, the hold stays, the retry completes.
    let (blobs, kv, clock) = fault_world();
    blobs.fail_write.store(2, Ordering::SeqCst);
    let ex = extractor(&blobs, &kv, &repo, &clock, &staged);
    assert!(extract_one(&ex, id, Kind::Blob).is_err());
    assert_eq!(stored(&blobs), None);
    assert!(hold_present(&kv));
    blobs.fail_write.store(0, Ordering::SeqCst);
    extract_one(&ex, id, Kind::Blob).unwrap();
    assert_eq!(stored(&blobs), Some(data.len() as u64));

    // After the put, before the holder: the object is present and held; the
    // retry deduplicates (no second upload) and records the holder.
    let (blobs, kv, clock) = fault_world();
    kv.fail_holder.store(true, Ordering::SeqCst);
    let ex = extractor(&blobs, &kv, &repo, &clock, &staged);
    assert!(extract_one(&ex, id, Kind::Blob).is_err());
    assert_eq!(stored(&blobs), Some(data.len() as u64));
    assert!(hold_present(&kv) && record(&kv).is_none());
    protected(&blobs, &kv, &id);
    let writes = blobs.writes.load(Ordering::SeqCst);
    extract_one(&ex, id, Kind::Blob).unwrap();
    assert_eq!(
        blobs.writes.load(Ordering::SeqCst),
        writes,
        "no second upload"
    );
    assert!(!hold_present(&kv));
    // After the holder, before `Verified`: the retry records it again. The
    // sequence advances and the count stays.
    let first = record(&kv).unwrap();
    extract_one(&ex, id, Kind::Blob).unwrap();
    let second = record(&kv).unwrap();
    assert!(second.seq > first.seq);
    let state = block_on(ContentIndex::new(BorrowedStore(&kv)).state(&id))
        .unwrap()
        .unwrap();
    assert_eq!(state.holders, 1);

    // The hold is durable before the object becomes visible.
    let (blobs, kv, clock) = fault_world();
    let kv = Arc::new(kv);
    let seen = Arc::new(AtomicBool::new(false));
    let probe = {
        let (seen, kv) = (seen.clone(), kv.clone());
        let shard = content_shard(&id);
        move |key: &BlobKey| {
            if key.namespace() == crate::store::BlobNamespace::Object {
                seen.store(
                    now(kv.get(&shard, &hold_key)).unwrap().is_some(),
                    Ordering::SeqCst,
                );
            }
        }
    };
    *blobs.before_commit.lock().unwrap() = Some(Box::new(probe));
    let ex = extractor(&blobs, &*kv, &repo, &clock, &staged);
    extract_one(&ex, id, Kind::Blob).unwrap();
    assert!(
        seen.load(Ordering::SeqCst),
        "the hold preceded the visible object"
    );
}

#[test]
fn crash_after_the_holder_before_verified_redoes_idempotently() {
    let world_clock = Arc::new(ManualClock::new(NOW));
    let blobs = MemoryBlobStore::default();
    let kv = FaultKv {
        inner: MemoryKv::with_clock(world_clock.clone()),
        fail_holder: AtomicBool::new(false),
        fail_verified: AtomicBool::new(true),
    };
    let data = content(29, BIG);
    let (pack, head, id) = file_push(&data);
    upload(&blobs, &pack);
    let repo = repo("a");
    let e = run(
        &blobs,
        &kv,
        &repo,
        &[&pack],
        head,
        IndexedConfig::default(),
        &world_clock,
    );
    assert!(e.is_err());
    let content_index = ContentIndex::new(BorrowedStore(&kv));
    let holder = Holder::new(repo.namespace.clone(), repo.name.clone());
    let first = block_on(content_index.holder_record(&id, &holder))
        .unwrap()
        .unwrap();
    assert_eq!(
        block_on(blobs.head(&BlobKey::object(id)))
            .unwrap()
            .map(|m| m.len),
        Some(BIG as u64)
    );
    // The pack is not Verified yet: no advance could have committed.
    let state = block_on(kv.get(
        &source(&repo),
        &keys::verification(&repo.name, &hash(&pack)),
    ))
    .unwrap();
    assert!(
        !matches!(
            state.map(|raw| super::state::decode(&raw).unwrap()),
            Some(super::state::VerificationV1::Verified { .. })
        ),
        "Verified implies extracted; the reverse need not hold"
    );
    // The retry (after the lease lapses) succeeds and re-records.
    world_clock.advance(120_000);
    run(
        &blobs,
        &kv,
        &repo,
        &[&pack],
        head,
        IndexedConfig::default(),
        &world_clock,
    )
    .unwrap();
    let second = block_on(content_index.holder_record(&id, &holder))
        .unwrap()
        .unwrap();
    assert!(second.seq > first.seq, "a re-record advances the sequence");
    assert_eq!(
        block_on(content_index.state(&id)).unwrap().unwrap().holders,
        1
    );
}

#[test]
fn hold_beats_gc_and_a_deleting_object_is_pending_then_reuploaded() {
    let data = content(31, BIG);
    let (id, raw, object) = blob_object(&data);
    let staged = staged_of(&[(id, raw, object)]);
    let repo = repo("a");
    let world = World::new();
    let ex = extractor(&world.blobs, &world.store, &repo, &world.clock, &staged);
    extract_one(&ex, id, Kind::Blob).unwrap();
    let content_index = world.content();
    let holder = Holder::new(repo.namespace.clone(), repo.name.clone());
    let now = NOW as u64;
    // The holder keeps GC away.
    assert!(
        block_on(content_index.collectable(&id, now + 10_000_000, 0))
            .unwrap()
            .is_none()
    );
    // GC's plan is made, then a new extraction's hold lands first: the plan
    // fails and nothing is deleted.
    let record = block_on(content_index.holder_record(&id, &holder))
        .unwrap()
        .unwrap();
    assert!(block_on(content_index.remove_holder(&id, &holder, record.seq, now)).unwrap());
    let plan = block_on(content_index.collectable(&id, now + 10_000_000, 0))
        .unwrap()
        .unwrap();
    let other = crate::repo::RepoId {
        namespace: repo.namespace.clone(),
        name: crate::repo::RepoName::new("b").unwrap(),
    };
    let ex_b = extractor(&world.blobs, &world.store, &other, &world.clock, &staged);
    extract_one(&ex_b, id, Kind::Blob).unwrap();
    assert!(!block_on(content_index.commit_collect(plan)).unwrap());
    assert!(world.stored(&id).is_some());
    // GC wins the other way: `deleting` is retryable `pending`, and after the
    // bytes are gone and the mark cleared the retry uploads again.
    let record = block_on(content_index.holder_record(
        &id,
        &Holder::new(other.namespace.clone(), other.name.clone()),
    ))
    .unwrap()
    .unwrap();
    assert!(
        block_on(content_index.remove_holder(
            &id,
            &Holder::new(other.namespace.clone(), other.name.clone()),
            record.seq,
            now
        ))
        .unwrap()
    );
    let plan = block_on(content_index.collectable(&id, now + 20_000_000, 0))
        .unwrap()
        .unwrap();
    assert!(block_on(content_index.commit_collect(plan)).unwrap());
    let e = extract_one(&ex, id, Kind::Blob).unwrap_err();
    assert_eq!(e.public_message(), "pack verification pending");
    assert_eq!(
        world.holds(&id),
        0,
        "no hold was taken on a deleting object"
    );
    assert!(block_on(world.blobs.delete(&BlobKey::object(id))).unwrap());
    block_on(content_index.finish_collect(&id, now + 20_000_001)).unwrap();
    extract_one(&ex, id, Kind::Blob).unwrap();
    assert_eq!(world.stored(&id), Some(BIG as u64), "re-uploaded");
    assert_eq!(world.holders(&id), ["a"]);
}

#[test]
fn a_blocked_object_is_refused_at_the_hold_and_at_the_holder() {
    let data = content(37, BIG);
    let (id, raw, object) = blob_object(&data);
    let staged = staged_of(&[(id, raw, object)]);
    let repo = repo("a");
    let world = World::new();
    block_on(
        world
            .content()
            .block(&id, &crate::store::BlockEntry::new("dmca", 1), NOW as u64),
    )
    .unwrap();
    let ex = extractor(&world.blobs, &world.store, &repo, &world.clock, &staged);
    let e = extract_one(&ex, id, Kind::Blob).unwrap_err();
    assert_eq!(e.code(), crate::Code::PermissionDenied);
    assert_eq!(e.public_message(), "object blocked");
    assert!(e.details().is_empty(), "no §14.6 detail before WP-5.6");
    assert_eq!(world.stored(&id), None, "nothing was uploaded");
    assert_eq!(world.holds(&id), 0);
}

#[test]
fn pieces_stay_within_the_blob_piece_bound() {
    let data = content(41, 3 * MAX_BLOB_PIECE_BYTES + 5);
    let (id, raw, object) = blob_object(&data);
    let staged = staged_of(&[(id, raw, object)]);
    let repo = repo("a");
    let (blobs, kv, clock) = fault_world();
    let ex = extractor(&blobs, &kv, &repo, &clock, &staged);
    extract_one(&ex, id, Kind::Blob).unwrap();
    assert_eq!(
        blobs.max_piece.load(Ordering::SeqCst),
        MAX_BLOB_PIECE_BYTES as u64
    );
    assert_eq!(blobs.writes.load(Ordering::SeqCst), 4);
}

#[test]
fn a_member_chunk_beyond_the_remaining_decode_budget_is_refused() {
    let chunks = vec![content(3, 4_000), content(5, 9_000)];
    let (manifest_id, cb, objects) = manifest(&chunks);
    let repo = repo("a");
    let world = World::new();
    seed_member_raw(
        &world.blobs,
        &world.store,
        &repo,
        objects[1].0,
        &objects[1].1,
    );
    let staged = staged_of(&[
        objects[0].clone(),
        (manifest_id, Vec::new(), Object::ChunkedBlob(cb)),
    ]);
    let mut ex = extractor(&world.blobs, &world.store, &repo, &world.clock, &staged);
    ex.cfg.decode_budget = 8_000;
    let e = extract_one(&ex, manifest_id, Kind::Chunked).unwrap_err();
    assert_eq!(e.public_message(), "pack exceeds indexed decode budget");
    assert_eq!(world.stored(&manifest_id), None);
    ex.cfg.decode_budget = 20_000;
    ex.staged_bytes = 0;
    extract_one(&ex, manifest_id, Kind::Chunked).unwrap();
    assert_eq!(world.stored(&manifest_id), Some(13_000));
}

// ---------------------------------------------------------------------------
// Objects beyond the backend's single put go up in parts (D-4).

const PART: usize = 8 * 1024 * 1024;

#[test]
fn objects_beyond_the_single_put_limit_are_extracted_in_verified_parts() {
    let world = World::new();
    let blobs = world.blobs.clone().with_single_put_limit(PART as u64);
    // A plain Blob of 17 MiB: three parts (8 + 8 + 1 MiB).
    let data = content(43, 2 * PART + (1 << 20));
    let (id, raw, object) = blob_object(&data);
    let staged = staged_of(&[(id, raw, object)]);
    let repo = repo("a");
    let ex = extractor(&blobs, &world.store, &repo, &world.clock, &staged);
    extract_one(&ex, id, Kind::Blob).unwrap();
    assert_eq!(world.stored(&id), Some(data.len() as u64));
    assert_eq!(world.read(&BlobKey::object(id)), data, "raw content");
    assert_eq!(world.holders(&id), ["a"]);
    assert_eq!(world.holds(&id), 0);
    assert_eq!(blobs.multipart_session_count(), 0, "the session is closed");

    // A manifest whose reassembly crosses the limit: four 3 MiB chunks, two
    // of them members, with the sidecar written whole.
    let chunks: Vec<Vec<u8>> = (0..4).map(|i| content(47 + i, 3 << 20)).collect();
    let (manifest_id, cb, objects) = manifest(&chunks);
    for (id, raw, _) in &objects[..2] {
        seed_member_raw(&world.blobs, &world.store, &repo, *id, raw);
    }
    let mut staged = objects[2..].to_vec();
    staged.push((manifest_id, Vec::new(), Object::ChunkedBlob(cb)));
    let staged = staged_of(&staged);
    let ex = extractor(&blobs, &world.store, &repo, &world.clock, &staged);
    extract_one(&ex, manifest_id, Kind::Chunked).unwrap();
    assert_eq!(world.read(&BlobKey::object(manifest_id)), chunks.concat());
    let bounds: Vec<u64> = (0..=4).map(|i| i * (3 << 20)).collect();
    assert_eq!(
        world.read(&BlobKey::object_offsets(manifest_id)),
        encode_offsets(&bounds)
    );
    assert_eq!(blobs.multipart_session_count(), 0);
}

#[test]
fn a_failed_multipart_extraction_aborts_its_session_and_publishes_nothing() {
    let world = World::new();
    let blobs = world.blobs.clone().with_single_put_limit(PART as u64);
    // The second chunk is corrupt, after the first part already uploaded.
    let chunks: Vec<Vec<u8>> = (0..4).map(|i| content(53 + i, 3 << 20)).collect();
    let (manifest_id, cb, mut objects) = manifest(&chunks);
    objects[3].1 = serialize(&Object::Blob(Blob {
        data: content(99, 3 << 20),
    }))
    .unwrap();
    let mut all = objects;
    all.push((manifest_id, Vec::new(), Object::ChunkedBlob(cb)));
    let staged = staged_of(&all);
    let repo = repo("a");
    let ex = extractor(&blobs, &world.store, &repo, &world.clock, &staged);
    let e = extract_one(&ex, manifest_id, Kind::Chunked).unwrap_err();
    assert_eq!(e.public_message(), "verified pack content inconsistency");
    assert_eq!(world.stored(&manifest_id), None);
    assert_eq!(
        blobs.multipart_session_count(),
        0,
        "the session was aborted"
    );
    assert!(world.holders(&manifest_id).is_empty());
    // A retry after the content is fixed completes (a fresh session).
    let (_, cb, objects) = manifest(&chunks);
    let mut all = objects;
    all.push((manifest_id, Vec::new(), Object::ChunkedBlob(cb)));
    let staged = staged_of(&all);
    let ex = extractor(&blobs, &world.store, &repo, &world.clock, &staged);
    extract_one(&ex, manifest_id, Kind::Chunked).unwrap();
    assert_eq!(world.read(&BlobKey::object(manifest_id)), chunks.concat());
}

// ---------------------------------------------------------------------------
// Review round: hold renewal, resolution budget, sidecar crash, blocked
// holder, the spool oracle and the resolver's reads.

#[test]
fn a_stream_longer_than_the_hold_ttl_renews_the_hold() {
    let world = World::new();
    // Three pieces, 25 minutes each: 75 minutes against a 60 minute hold.
    let slow = SlowBlobs {
        inner: world.blobs.clone(),
        clock: world.clock.clone(),
        step_ms: 25 * 60 * 1000,
    };
    let data = content(59, 3 * MAX_BLOB_PIECE_BYTES);
    let (id, raw, object) = blob_object(&data);
    let staged = staged_of(&[(id, raw, object)]);
    let repo = repo("a");
    let ex = extractor(&slow, &world.store, &repo, &world.clock, &staged);
    // The holder batch refuses a hold that lapsed, so success proves the
    // stream renewed it.
    extract_one(&ex, id, Kind::Blob).unwrap();
    assert_eq!(world.stored(&id), Some(data.len() as u64));
    assert_eq!(world.holders(&id), ["a"]);
    assert_eq!(world.holds(&id), 0);
}

#[test]
fn repeated_member_chunks_are_charged_against_the_extraction_budget() {
    // One 1,000 byte member chunk listed ten times: each listing resolves it
    // again, so the resolution work is bounded like the output.
    let chunk = content(61, 1_000);
    let (chunk_id, chunk_raw, _) = blob_object(&chunk);
    let cb = ChunkedBlob {
        total_size: 10_000,
        chunk_size: 0,
        chunks: vec![chunk_id; 10],
    };
    let manifest_id = Object::ChunkedBlob(cb.clone()).id().unwrap();
    let repo = repo("a");
    let world = World::new();
    seed_member_raw(&world.blobs, &world.store, &repo, chunk_id, &chunk_raw);
    let staged = staged_of(&[(manifest_id, Vec::new(), Object::ChunkedBlob(cb))]);
    let mut ex = extractor(&world.blobs, &world.store, &repo, &world.clock, &staged);
    ex.cfg.max_extract_bytes = Some(5_000);
    let e = extract_one(&ex, manifest_id, Kind::Chunked).unwrap_err();
    assert_eq!(e.public_message(), "pack exceeds indexed decode budget");
    assert_eq!(world.stored(&manifest_id), None);
    ex.cfg.max_extract_bytes = Some(1 << 20);
    extract_one(&ex, manifest_id, Kind::Chunked).unwrap();
    assert_eq!(world.stored(&manifest_id), Some(10_000));
}

#[test]
fn a_crash_between_the_object_and_its_sidecar_redoes_both() {
    let chunks = vec![content(3, 4_000), content(5, 9_000)];
    let (manifest_id, cb, objects) = manifest(&chunks);
    let mut all = objects;
    all.push((manifest_id, Vec::new(), Object::ChunkedBlob(cb)));
    let staged = staged_of(&all);
    let repo = repo("a");
    let (blobs, kv, clock) = fault_world();
    // The second `begin` is the sidecar's.
    blobs.fail_begin_at.store(2, Ordering::SeqCst);
    let ex = extractor(&blobs, &kv, &repo, &clock, &staged);
    assert!(extract_one(&ex, manifest_id, Kind::Chunked).is_err());
    let sidecar = BlobKey::object_offsets(manifest_id);
    assert!(
        block_on(blobs.head(&BlobKey::object(manifest_id)))
            .unwrap()
            .is_some()
    );
    assert!(block_on(blobs.head(&sidecar)).unwrap().is_none());
    protected(&blobs, &kv, &manifest_id);
    // The retry sees the manifest half-stored, so it is not a dedup: it
    // rewrites the object (already present) and writes the sidecar.
    blobs.fail_begin_at.store(0, Ordering::SeqCst);
    extract_one(&ex, manifest_id, Kind::Chunked).unwrap();
    assert!(block_on(blobs.head(&sidecar)).unwrap().is_some());
    protected(&blobs, &kv, &manifest_id);
    let holder = Holder::new(repo.namespace.clone(), repo.name.clone());
    let content_index = ContentIndex::new(BorrowedStore(&kv));
    assert!(
        block_on(content_index.holder_record(&manifest_id, &holder))
            .unwrap()
            .is_some()
    );
}

#[test]
fn a_block_between_the_hold_and_the_holder_records_no_holder_and_releases_the_hold() {
    let data = content(67, BIG);
    let (id, raw, object) = blob_object(&data);
    let staged = staged_of(&[(id, raw, object)]);
    let repo = repo("a");
    let (blobs, kv, clock) = fault_world();
    let kv = Arc::new(kv);
    // The takedown lands as the bytes become visible.
    let block = {
        let kv = kv.clone();
        move |_: &BlobKey| {
            let index = ContentIndex::new(BorrowedStore(&*kv));
            now(index.block(&id, &crate::store::BlockEntry::new("dmca", 1), NOW as u64)).unwrap();
        }
    };
    *blobs.before_commit.lock().unwrap() = Some(Box::new(block));
    let ex = extractor(&blobs, &*kv, &repo, &clock, &staged);
    let e = extract_one(&ex, id, Kind::Blob).unwrap_err();
    assert_eq!(e.code(), crate::Code::PermissionDenied);
    assert_eq!(e.public_message(), "object blocked");
    // No holder is recorded for a blocked object, and the hold is released
    // in the same batch: the bytes fall to ordinary GC (§14.2).
    let holder = Holder::new(repo.namespace.clone(), repo.name.clone());
    let index = ContentIndex::new(BorrowedStore(&*kv));
    assert!(
        block_on(index.holder_record(&id, &holder))
            .unwrap()
            .is_none()
    );
    let (start, end) = keys::holds_of(&id);
    let holds = block_on(kv.scan(&content_shard(&id), &start, &end, None, 10)).unwrap();
    assert!(holds.entries.is_empty(), "the hold was released");
}

#[test]
fn a_full_spool_answers_alike_whether_or_not_the_object_is_stored() {
    let data = content(71, BIG);
    let (id, raw, object) = blob_object(&data);
    let staged = staged_of(&[(id, raw, object)]);
    let repo = repo("a");
    let answer = |stored: bool| {
        let (blobs, kv, clock) = fault_world();
        let ex = extractor(&blobs, &kv, &repo, &clock, &staged);
        if stored {
            extract_one(&ex, id, Kind::Blob).unwrap();
        }
        blobs.full_spool.store(true, Ordering::SeqCst);
        let e = extract_one(&ex, id, Kind::Blob).unwrap_err();
        (
            e.code(),
            e.public_message().to_owned(),
            e.details().to_vec(),
        )
    };
    assert_eq!(
        answer(true),
        answer(false),
        "no dedup oracle through the spool"
    );
}

#[test]
fn the_resolver_never_reads_object_keys() {
    let chunks = vec![content(3, 4_000), content(5, 9_000)];
    let (manifest_id, cb, objects) = manifest(&chunks);
    let repo = repo("a");
    let world = World::new();
    let blobs = FaultBlobs {
        inner: world.blobs.clone(),
        ..FaultBlobs::default()
    };
    seed_member_raw(
        &world.blobs,
        &world.store,
        &repo,
        objects[1].0,
        &objects[1].1,
    );
    // An object-store decoy under the member chunk's id.
    block_on(async {
        let mut sink = world
            .blobs
            .begin(BlobKey::object(objects[1].0), 3)
            .await
            .unwrap();
        sink.write(Bytes::from_static(b"bad")).await.unwrap();
        sink.commit_with_root(hash(b"bad")).await.unwrap();
    });
    let staged = staged_of(&[
        objects[0].clone(),
        (manifest_id, Vec::new(), Object::ChunkedBlob(cb)),
    ]);
    let ex = extractor(&blobs, &world.store, &repo, &world.clock, &staged);
    extract_one(&ex, manifest_id, Kind::Chunked).unwrap();
    assert_eq!(world.read(&BlobKey::object(manifest_id)), chunks.concat());
    let gets = blobs.gets.lock().unwrap();
    assert!(!gets.is_empty());
    assert!(
        gets.iter()
            .all(|namespace| *namespace == crate::store::BlobNamespace::Pack),
        "extraction and resolution read only pack keys: {gets:?}"
    );
}

// ---------------------------------------------------------------------------
// Fix round: the existence oracle, the per-advance budget, client-crafted
// manifests, the multipart reservation, hold renewal and thresholds (R-163).

fn answer_of(result: Result<(), ServerError>) -> Result<(), (crate::Code, String)> {
    result.map_err(|e| (e.code(), e.public_message().to_owned()))
}

#[test]
fn every_answer_is_independent_of_whether_the_object_is_stored() {
    let chunk = content(61, 1_000);
    let (chunk_id, chunk_raw, _) = blob_object(&chunk);
    let cb = ChunkedBlob {
        total_size: 5_000,
        chunk_size: 0,
        chunks: vec![chunk_id; 5],
    };
    let manifest_id = Object::ChunkedBlob(cb.clone()).id().unwrap();
    let staged = staged_of(&[(manifest_id, Vec::new(), Object::ChunkedBlob(cb))]);
    // Repository "a" extracts the manifest; in the "stored" world another
    // repository already put the same object (and its sidecar) there.
    let answer = |stored: bool, member: bool, max: u64| {
        let world = World::new();
        if stored {
            let other = repo("b");
            seed_member_raw(&world.blobs, &world.store, &other, chunk_id, &chunk_raw);
            let ex = extractor(&world.blobs, &world.store, &other, &world.clock, &staged);
            extract_one(&ex, manifest_id, Kind::Chunked).unwrap();
            assert_eq!(world.stored(&manifest_id), Some(5_000));
        }
        let a = repo("a");
        if member {
            seed_member_raw(&world.blobs, &world.store, &a, chunk_id, &chunk_raw);
        }
        let mut ex = extractor(&world.blobs, &world.store, &a, &world.clock, &staged);
        ex.cfg.max_extract_bytes = Some(max);
        let result = answer_of(extract_one(&ex, manifest_id, Kind::Chunked));
        (
            result,
            world.holders(&manifest_id).contains(&"a".to_owned()),
        )
    };
    // Success, a budget the resolution exceeds, and a chunk this repository
    // does not hold: each answers alike stored or not, and the failures
    // record no holder either way.
    let cases = [(true, 1 << 20), (true, 4_999), (false, 1 << 20)];
    for (member, max) in cases {
        assert_eq!(answer(true, member, max), answer(false, member, max));
    }
    assert_eq!(answer(false, true, 1 << 20), (Ok(()), true));
    let (over, held) = answer(false, true, 4_999);
    assert_eq!(over.unwrap_err().1, "pack exceeds indexed decode budget");
    assert!(!held);
    assert_eq!(
        answer(true, false, 1 << 20).0.unwrap_err().1,
        "verified pack content inconsistency"
    );
}

#[test]
fn resolution_is_charged_cumulatively_across_manifests() {
    // Three manifests over one 1,000 byte member chunk: each resolves it
    // once, well within a per-chunk budget, but the advance-wide counter
    // sums them.
    let chunk = content(63, 1_000);
    let (chunk_id, chunk_raw, _) = blob_object(&chunk);
    let repo = repo("a");
    let world = World::new();
    seed_member_raw(&world.blobs, &world.store, &repo, chunk_id, &chunk_raw);
    let manifests: Vec<(Hash, Object)> = (0..3)
        .map(|i| {
            let object = Object::ChunkedBlob(ChunkedBlob {
                total_size: 1_000,
                chunk_size: i,
                chunks: vec![chunk_id],
            });
            (object.id().unwrap(), object)
        })
        .collect();
    let staged = staged_of(
        &manifests
            .iter()
            .map(|(id, object)| (*id, Vec::new(), object.clone()))
            .collect::<Vec<_>>(),
    );
    let mut ex = extractor(&world.blobs, &world.store, &repo, &world.clock, &staged);
    ex.cfg.max_extract_bytes = Some(2_500);
    let results: Vec<_> = manifests
        .iter()
        .map(|(id, _)| answer_of(extract_one(&ex, *id, Kind::Chunked)))
        .collect();
    assert_eq!(results[0], Ok(()));
    assert_eq!(results[1], Ok(()));
    assert_eq!(
        results[2].clone().unwrap_err().1,
        "pack exceeds indexed decode budget"
    );
    assert_eq!(world.stored(&manifests[2].0), None);
}

#[test]
fn a_client_crafted_manifest_is_rejected_and_the_verdict_persists() {
    let chunks = vec![content(3, 4_000), content(5, 9_000)];
    let world = World::new();
    let repo = repo("a");
    let (_, mut cb, objects) = manifest(&chunks);
    cb.total_size += 1;
    let bad_id = Object::ChunkedBlob(cb.clone()).id().unwrap();
    let (tree_id, tree_raw, head, commit_raw) = commit_of(&[("file", bad_id)]);
    let mut staged: Vec<(Hash, Vec<u8>)> = vec![
        (bad_id, serialize(&Object::ChunkedBlob(cb)).unwrap()),
        (tree_id, tree_raw),
        (head, commit_raw),
    ];
    staged.extend(objects.iter().map(|(id, raw, _)| (*id, raw.clone())));
    let refs: Vec<(Hash, &[u8])> = staged
        .iter()
        .map(|(id, raw)| (*id, raw.as_slice()))
        .collect();
    let pack = pack_of(&refs);
    upload(&world.blobs, &pack);
    let attempt = || {
        run(
            &world.blobs,
            &world.store,
            &repo,
            &[&pack],
            head,
            IndexedConfig::default(),
            &world.clock,
        )
        .unwrap_err()
    };
    let first = attempt();
    assert_eq!(first.code(), crate::Code::InvalidArgument);
    assert_eq!(first.public_message(), MALFORMED_MESSAGE);
    assert_eq!(world.stored(&bad_id), None);
    assert!(world.holders(&bad_id).is_empty());
    // Persisted as Rejected: the retry answers the same, without redoing it.
    let second = attempt();
    assert_eq!(
        (second.code(), second.public_message()),
        (first.code(), first.public_message())
    );
}

/// A store whose multipart sessions cannot be opened: `Full` before anything
/// else, for the reservation test.
struct NoSessions(MemoryBlobStore);

impl BlobStore for NoSessions {
    type Sink = <MemoryBlobStore as BlobStore>::Sink;

    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.0.begin(key, len).await
    }

    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
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

impl MultipartBlobStore for NoSessions {
    type PartSink = <MemoryBlobStore as MultipartBlobStore>::PartSink;
    const MAX_PARTS: u32 = u32::MAX;

    fn supports_multipart(&self) -> bool {
        true
    }

    fn single_put_limit(&self) -> Option<u64> {
        Some(PART as u64)
    }

    async fn begin_multipart_for_ticket(
        &self,
        _key: BlobKey,
        _len: u64,
        _part_size: u64,
        _ticket_id: [u8; 32],
    ) -> Result<Vec<u8>, StoreError> {
        Err(StoreError::Full)
    }
}

#[test]
fn a_full_multipart_reservation_answers_alike_whether_or_not_the_object_is_stored() {
    let data = content(73, PART + 1_000);
    let (id, raw, object) = blob_object(&data);
    let staged = staged_of(&[(id, raw, object)]);
    let repo = repo("a");
    let answer = |stored: bool| {
        let world = World::new();
        if stored {
            let blobs = world.blobs.clone().with_single_put_limit(PART as u64);
            let ex = extractor(&blobs, &world.store, &repo, &world.clock, &staged);
            extract_one(&ex, id, Kind::Blob).unwrap();
            assert_eq!(world.stored(&id), Some(data.len() as u64));
        }
        let blobs = NoSessions(world.blobs.clone());
        let ex = extractor(&blobs, &world.store, &repo, &world.clock, &staged);
        let e = extract_one(&ex, id, Kind::Blob).unwrap_err();
        (e.code(), e.public_message().to_owned())
    };
    assert_eq!(answer(true), answer(false), "no dedup oracle through parts");
}

/// A [`Renew`] that runs `act` on its `n`-th call.
struct OnCall<F: FnMut() -> Result<(), ServerError> + Send> {
    n: u32,
    calls: u32,
    act: F,
}

impl<F: FnMut() -> Result<(), ServerError> + Send> Renew for OnCall<F> {
    fn renew(&mut self) -> BoxFuture<'_, Result<(), ServerError>> {
        self.calls += 1;
        let result = if self.calls == self.n {
            (self.act)()
        } else {
            Ok(())
        };
        Box::pin(async move { result })
    }
}

#[test]
fn a_lapsed_hold_is_not_extended_and_the_extraction_redoes() {
    let data = content(79, BIG);
    let (id, raw, object) = blob_object(&data);
    let staged = staged_of(&[(id, raw, object)]);
    let repo = repo("a");
    for gc_deleted in [false, true] {
        let world = World::new();
        let ex = extractor(&world.blobs, &world.store, &repo, &world.clock, &staged);
        let hold = hold_id(&repo, &TICKET, &id);
        // By the stream's first piece the hold has lapsed (and, in one case,
        // GC has pruned its row).
        let mut lapse = OnCall {
            n: 2,
            calls: 0,
            act: || {
                world.clock.advance(2 * 60 * 60 * 1000);
                if gc_deleted {
                    let at = u64::try_from(crate::Clock::now_ms(world.clock.as_ref())).unwrap();
                    now(world.content().release_hold(&id, &hold, at)).unwrap();
                }
                Ok(())
            },
        };
        let e = block_on(ex.extract(id, Kind::Blob, &TICKET, &mut lapse));
        let Err(ExtractError::Server(e)) = e else {
            panic!("expected a retryable failure");
        };
        assert_eq!(e.public_message(), "pack verification pending");
        assert_eq!(world.stored(&id), None, "nothing was committed");
        assert!(world.holders(&id).is_empty());
        if gc_deleted {
            assert_eq!(world.holds(&id), 0, "a deleted hold is not resurrected");
        }
        // The redo from the head check takes a fresh hold and completes.
        extract_one(&ex, id, Kind::Blob).unwrap();
        assert_eq!(world.stored(&id), Some(BIG as u64));
        assert_eq!(world.holders(&id), ["a"]);
    }
}

#[test]
fn a_lost_lease_leaves_a_shared_multipart_session_alone() {
    let world = World::new();
    let blobs = world.blobs.clone().with_single_put_limit(PART as u64);
    let data = content(83, 2 * PART + 5);
    let (id, raw, object) = blob_object(&data);
    let staged = staged_of(&[(id, raw, object)]);
    let repo = repo("a");
    let ex = extractor(&blobs, &world.store, &repo, &world.clock, &staged);
    // The lease is lost when the second part is being fed.
    let mut lost = OnCall {
        n: 12,
        calls: 0,
        act: || Err(super::pending(1_000)),
    };
    let e = block_on(ex.extract(id, Kind::Blob, &TICKET, &mut lost));
    assert!(matches!(e, Err(ExtractError::Server(_))));
    assert_eq!(world.stored(&id), None);
    assert_eq!(
        blobs.multipart_session_count(),
        1,
        "another verifier may own the session"
    );
    // A failure that is not the lease still aborts its own session.
    let bad = content(84, 2 * PART + 5);
    let (bad_id, _, _) = blob_object(&bad);
    let mut tampered = blob_object(&bad);
    tampered.1 = serialize(&Object::Blob(Blob {
        data: content(85, 9),
    }))
    .unwrap();
    let staged = staged_of(&[(bad_id, tampered.1, tampered.2)]);
    let ex = extractor(&blobs, &world.store, &repo, &world.clock, &staged);
    assert!(extract_one(&ex, bad_id, Kind::Blob).is_err());
    assert_eq!(blobs.multipart_session_count(), 1);
}

#[test]
fn an_object_between_the_backend_limit_and_one_part_uses_a_single_put() {
    let world = World::new();
    // A backend limit below the least part: multipart could not carry it.
    let blobs = world.blobs.clone().with_single_put_limit(1 << 20);
    let data = content(89, 3 << 20);
    let (id, raw, object) = blob_object(&data);
    let staged = staged_of(&[(id, raw, object)]);
    let repo = repo("a");
    let ex = extractor(&blobs, &world.store, &repo, &world.clock, &staged);
    extract_one(&ex, id, Kind::Blob).unwrap();
    assert_eq!(world.read(&BlobKey::object(id)), data);
    assert_eq!(blobs.multipart_session_count(), 0);
}

struct Count(Arc<AtomicU32>);

impl Renew for Count {
    fn renew(&mut self) -> BoxFuture<'_, Result<(), ServerError>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn large_objects_use_parts_from_sixty_four_mebibytes() {
    // The memory store has no single-put limit, yet an object above 64 MiB
    // still goes up in parts, so lease renewal runs between them.
    let world = World::new();
    let data = content(91, (64 << 20) + 1);
    let (id, raw, object) = blob_object(&data);
    let staged = staged_of(&[(id, raw, object)]);
    let repo = repo("a");
    let ex = extractor(&world.blobs, &world.store, &repo, &world.clock, &staged);
    let renewals = Arc::new(AtomicU32::new(0));
    block_on(ex.extract(id, Kind::Blob, &TICKET, &mut Count(renewals.clone()))).unwrap();
    assert_eq!(world.stored(&id), Some(data.len() as u64));
    assert_eq!(world.blobs.multipart_session_count(), 0);
    assert!(renewals.load(Ordering::SeqCst) > 64, "renewed per piece");
}

#[test]
fn the_extraction_cap_defaults_to_four_packs() {
    let cfg = IndexedConfig {
        max_pack_bytes: 1 << 20,
        decode_budget: 1 << 20,
        ..IndexedConfig::default()
    };
    assert_eq!(cfg.max_extract_bytes, None);
    assert_eq!(cfg.effective_max_extract_bytes(), 4 << 20);
    let set = IndexedConfig {
        max_extract_bytes: Some(3 << 20),
        ..cfg
    };
    assert_eq!(set.effective_max_extract_bytes(), 3 << 20);
}

#[test]
fn a_member_chunk_that_is_not_a_blob_is_a_malformed_manifest() {
    let repo = repo("a");
    let world = World::new();
    let (tree_id, tree_raw, _, _) = commit_of(&[("x", [1; 32])]);
    seed_member_raw(&world.blobs, &world.store, &repo, tree_id, &tree_raw);
    let cb = ChunkedBlob {
        total_size: 10,
        chunk_size: 0,
        chunks: vec![tree_id],
    };
    let manifest_id = Object::ChunkedBlob(cb.clone()).id().unwrap();
    let staged = staged_of(&[(manifest_id, Vec::new(), Object::ChunkedBlob(cb))]);
    let ex = extractor(&world.blobs, &world.store, &repo, &world.clock, &staged);
    let r = extract_raw(&ex, manifest_id, Kind::Chunked);
    assert!(matches!(r, Err(ExtractError::Content)), "{r:?}");
    assert_eq!(world.stored(&manifest_id), None);
}

#[test]
fn a_hold_alone_beats_commit_collect() {
    let data = content(97, BIG);
    let (id, raw, object) = blob_object(&data);
    let staged = staged_of(&[(id, raw, object)]);
    let repo = repo("a");
    let (blobs, kv, clock) = fault_world();
    let index = ContentIndex::new(BorrowedStore(&kv));
    let now = NOW as u64;
    // GC plans the object's deletion; then an extraction takes its hold,
    // uploads, and stops before recording a holder: the hold alone protects.
    block_on(index.release_hold(&id, &[0; 32], now)).unwrap();
    let plan = block_on(index.collectable(&id, now + 10_000_000, 0))
        .unwrap()
        .unwrap();
    kv.fail_holder.store(true, Ordering::SeqCst);
    let ex = extractor(&blobs, &kv, &repo, &clock, &staged);
    assert!(extract_one(&ex, id, Kind::Blob).is_err());
    assert!(
        block_on(index.holders(&id, None, 10))
            .unwrap()
            .holders
            .is_empty()
    );
    assert!(!block_on(index.commit_collect(plan)).unwrap());
    assert!(
        block_on(blobs.head(&BlobKey::object(id)))
            .unwrap()
            .is_some()
    );
    protected(&blobs, &kv, &id);
}
