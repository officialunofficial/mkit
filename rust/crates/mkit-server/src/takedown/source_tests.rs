#![allow(clippy::unwrap_used)]
use super::*;
use crate::indexed::budget::{Budgeted, SliceBudget};
use crate::pipeline::{D34Shards, ShardMap};
use crate::store::{
    codec,
    index::{IndexEntry, IndexValue},
    keys,
};
use crate::{
    Batch, BatchOutcome, BlobKey, BlobStore, MemoryBlobStore, MemoryKv, NamespaceKey,
    NamespaceStore, PackSink, RepoId, RepoName, Value,
};
use bytes::Bytes;
use mkit_core::{
    hash::{Hash, hash},
    object::{Blob, Object},
    pack::{self, DecodeLimits, DeltaBaseSource, PackError},
    serialize::serialize,
};

struct Latest(Vec<(Hash, Vec<u8>)>);
impl DeltaBaseSource for Latest {
    const VERIFIED: bool = true;
    fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
        Ok(self
            .0
            .iter()
            .find(|row| row.0 == *id)
            .map(|row| row.1.clone()))
    }
}
fn blob(size: usize, sequence: u32) -> Vec<u8> {
    let mut data = vec![b'A'; size - 10];
    let last = data.len() - 4;
    data[last..].copy_from_slice(&sequence.to_le_bytes());
    serialize(&Object::Blob(Blob { data })).unwrap()
}
fn delta(size: usize, sequence: u32) -> Vec<u8> {
    let mut stream = vec![1];
    stream.extend_from_slice(&(u32::try_from(size).unwrap()).to_le_bytes());
    stream.extend_from_slice(&(u32::try_from(size).unwrap()).to_le_bytes());
    let mut offset = 0;
    while offset < size - 4 {
        let len = (size - 4 - offset).min(u16::MAX as usize);
        stream.push(0x80);
        stream.extend_from_slice(&(u32::try_from(offset).unwrap()).to_le_bytes());
        stream.extend_from_slice(&(u16::try_from(len).unwrap()).to_le_bytes());
        offset += len;
    }
    stream.push(4);
    stream.extend_from_slice(&sequence.to_le_bytes());
    stream
}
fn append(pack: &mut Vec<u8>, kind: u8, payload: &[u8]) -> (u64, u64) {
    let offset = pack.len() as u64;
    pack.push(kind);
    pack.extend_from_slice(&(u32::try_from(payload.len()).unwrap()).to_le_bytes());
    pack.extend_from_slice(payload);
    (offset, payload.len() as u64 + 5)
}
fn finish(mut pack: Vec<u8>, count: u32) -> Vec<u8> {
    pack[8..12].copy_from_slice(&count.to_le_bytes());
    let trailer = hash(&pack);
    pack.extend_from_slice(&trailer);
    pack
}
fn admitted(mut pack: &[u8], expected: usize) {
    let mut latest = Latest(vec![]);
    let mut count = 0;
    let limits =
        DecodeLimits::default().with_max_decoded_bytes(crate::indexed::geometry::CANONICAL_BYTES);
    let length = pack.len() as u64;
    let id = hash(pack);
    pack::window::read_all(&mut pack, length, 16 << 20, limits, Some(id), |entry| {
        let (id, bytes) = pack::decode_entry_with(entry, &mut latest, limits)?;
        latest.0.push((id, bytes));
        if latest.0.len() > 2 {
            latest.0.remove(0);
        }
        count += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(count, expected);
}

// All 4096 candidates fit the existing locator's admitted geometry. Only the
// real source has membership, but all 487 candidate partitions are probed.
async fn dense_candidates(store: &MemoryKv, repo: &RepoId, pack: Hash, entry: IndexEntry) {
    let actual = u16::from_be_bytes([pack[0], pack[1]]) >> 4;
    let mut prefixes: Vec<u16> = (0..487).collect();
    if !prefixes.contains(&actual) {
        prefixes[486] = actual;
    }
    let mut rows = Vec::with_capacity(4096);
    for sequence in 0u32..4095 {
        let prefix = prefixes[usize::try_from(sequence).unwrap() % prefixes.len()];
        let mut candidate = [0; 32];
        candidate[0] = u8::try_from(prefix >> 4).unwrap();
        candidate[1] = u8::try_from((prefix & 15) << 4).unwrap();
        candidate[2..6].copy_from_slice(&sequence.to_be_bytes());
        assert_ne!(candidate, pack);
        rows.push(candidate);
    }
    rows.push(pack);
    assert_eq!(
        rows.iter()
            .map(|id| D34Shards.membership(repo, &BlobKey::pack(*id)))
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        487
    );
    let value = codec::encode_object_index(&entry.object, &entry.value).unwrap();
    for page in rows.chunks(96) {
        let mut batch = Batch::new();
        for candidate in page {
            batch = batch.put(
                keys::object_index(&repo.name, &entry.object, candidate),
                value.clone(),
            );
        }
        store
            .apply(&D34Shards.object_index(repo, &entry.object), batch)
            .await
            .unwrap();
    }
    store
        .apply(
            &D34Shards.membership(repo, &BlobKey::pack(pack)),
            Batch::new().put(keys::membership(&repo.name, &pack), Value::default()),
        )
        .await
        .unwrap();
}

async fn dense_chain(external: bool) -> (MemoryBlobStore, MemoryKv, RepoId, Hash) {
    let size = usize::try_from(crate::indexed::geometry::CANONICAL_BYTES).unwrap();
    let store = MemoryKv::default();
    let blobs = MemoryBlobStore::default();
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("dense").unwrap(),
    };
    let mut pack = b"MKIT\x01\0\0\0\0\0\0\0".to_vec();
    let mut entries = Vec::new();
    let mut previous = [0; 32];
    for sequence in 0..=50 {
        let canonical = blob(size, sequence);
        let id = hash(&canonical);
        let payload = if sequence == 0 {
            canonical
        } else {
            let mut payload = previous.to_vec();
            payload.extend_from_slice(&delta(size, sequence));
            payload
        };
        let (offset, length) = append(&mut pack, if sequence == 0 { 0 } else { 2 }, &payload);
        entries.push(IndexEntry {
            object: id,
            value: IndexValue {
                frame_offset: offset,
                frame_length: length,
                wire_type: if sequence == 0 { 0 } else { 2 },
                decoded_size: size as u64,
                chain_depth: if external && sequence != 0 {
                    1
                } else {
                    sequence
                },
                delta_base: (sequence != 0).then_some(previous),
            },
        });
        previous = id;
        if !external && sequence < 50 {
            continue;
        }
        let bytes = finish(std::mem::take(&mut pack), if external { 1 } else { 51 });
        if external {
            // Each external frame is independently verified with its canonical
            // base, matching admission without assuming in-pack predecessors.
            let mut base = Latest(if sequence == 0 {
                vec![]
            } else {
                vec![(hash(&blob(size, sequence - 1)), blob(size, sequence - 1))]
            });
            let mut reader = bytes.as_slice();
            pack::window::read_all(
                &mut reader,
                bytes.len() as u64,
                16 << 20,
                DecodeLimits::default()
                    .with_max_decoded_bytes(crate::indexed::geometry::CANONICAL_BYTES),
                Some(hash(&bytes)),
                |entry| {
                    pack::decode_entry_with(entry, &mut base, DecodeLimits::default())
                        .map(|decoded| assert_eq!(decoded.0, id))
                },
            )
            .unwrap();
        } else {
            admitted(&bytes, 51);
        }
        let pack_id = hash(&bytes);
        let mut sink = blobs
            .begin(BlobKey::pack(pack_id), bytes.len() as u64)
            .await
            .unwrap();
        for piece in bytes.chunks(crate::store::MAX_BLOB_PIECE_BYTES) {
            sink.write(Bytes::copy_from_slice(piece)).await.unwrap();
        }
        sink.commit().await.unwrap();
        for entry in &entries {
            if external || entry.object == previous {
                dense_candidates(&store, &repo, pack_id, *entry).await;
            } else {
                store
                    .apply(
                        &D34Shards.object_index(&repo, &entry.object),
                        Batch::new().put(
                            keys::object_index(&repo.name, &entry.object, &pack_id),
                            codec::encode_object_index(&entry.object, &entry.value).unwrap(),
                        ),
                    )
                    .await
                    .unwrap();
            }
        }
        entries.clear();
        pack = b"MKIT\x01\0\0\0\0\0\0\0".to_vec();
    }
    (blobs, store, repo, previous)
}

async fn preflight(
    store: &impl NamespaceStore,
    repo: &RepoId,
    target: Hash,
) -> (crate::Partition, crate::Key, usize) {
    let root = D34Shards.coordinator(&NamespaceKey::deployment_default());
    let prefix = crate::Key::new([b"b\0\xffsource-frame\0".as_slice(), &[9; 32], &target].concat());
    let mut checkpoint = Checkpoint::new(target);
    for tick in 1..30_000 {
        // Persisted bytes are the sole continuation; no cache survives a tick.
        let restored = serde_json::from_slice(&serde_json::to_vec(&checkpoint).unwrap()).unwrap();
        let budget = SliceBudget::new(700);
        let bounded = Budgeted::new(store, &budget);
        let result = step(
            &bounded,
            &D34Shards,
            repo,
            &prefix,
            &crate::takedown::acquisition::Profile::scheduled(),
            restored,
        )
        .await
        .unwrap();
        assert_eq!(
            bounded.apply(&root, result.batch).await.unwrap(),
            BatchOutcome::Committed
        );
        assert!(
            budget.used() <= 12,
            "source tick {tick}: {} calls",
            budget.used()
        );
        checkpoint = result.checkpoint;
        if checkpoint.next.is_none() {
            return (root, prefix, tick);
        }
    }
    panic!("admitted finite source did not finish bounded preflight");
}

struct EmptyPages {
    inner: MemoryKv,
    start: crate::Key,
}
impl NamespaceStore for EmptyPages {
    fn capabilities(&self) -> crate::store::StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(
        &self,
        p: &crate::Partition,
        k: &crate::Key,
    ) -> Result<Option<Value>, crate::StoreError> {
        self.inner.get(p, k).await
    }
    async fn get_many(
        &self,
        p: &crate::Partition,
        keys: &[crate::Key],
    ) -> Result<Vec<Option<Value>>, crate::StoreError> {
        self.inner.get_many(p, keys).await
    }
    async fn scan(
        &self,
        p: &crate::Partition,
        start: &crate::Key,
        end: &crate::Key,
        after: Option<&crate::Cursor>,
        limit: u32,
    ) -> Result<crate::ScanPage, crate::StoreError> {
        const MARKER: &[u8] = b"source-empty-page\0";
        if start == &self.start {
            let seen = match after {
                None => Some(0),
                Some(cursor) => cursor
                    .as_bytes()
                    .strip_prefix(MARKER)
                    .map(|raw| u32::from_be_bytes(raw.try_into().unwrap())),
            };
            if let Some(seen) = seen {
                if seen < 511 {
                    return Ok(crate::ScanPage {
                        entries: vec![],
                        next: Some(crate::Cursor::new(
                            [MARKER, &(seen + 1).to_be_bytes()].concat(),
                        )),
                    });
                }
                assert_eq!(seen, 511);
                return self.inner.scan(p, start, end, None, limit).await;
            }
        }
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(
        &self,
        p: &crate::Partition,
        batch: Batch,
    ) -> Result<BatchOutcome, crate::StoreError> {
        self.inner.apply(p, batch).await
    }
    async fn stats(
        &self,
        p: &crate::Partition,
    ) -> Result<crate::PartitionStats, crate::StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), crate::StoreError> {
        self.inner.probe().await
    }
}

#[tokio::test]
async fn virtual_page_cap_allows_511_empty_continuations_and_the_last_128_row_group() {
    let canonical = blob(1024, 0);
    let target = hash(&canonical);
    let mut packed = b"MKIT\x01\0\0\0\0\0\0\0".to_vec();
    let (offset, length) = append(&mut packed, 0, &canonical);
    let packed = finish(packed, 1);
    admitted(&packed, 1);
    let pack_id = hash(&packed);
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("empty").unwrap(),
    };
    let value = IndexValue {
        frame_offset: offset,
        frame_length: length,
        wire_type: 0,
        decoded_size: 1024,
        chain_depth: 0,
        delta_base: None,
    };
    let inner = MemoryKv::default();
    let mut candidates = Vec::new();
    for sequence in 0u32..127 {
        let mut pack = [0; 32];
        pack[28..].copy_from_slice(&sequence.to_be_bytes());
        assert!(pack < pack_id, "the real member is last in pack-id order");
        candidates.push(pack);
    }
    candidates.push(pack_id);
    for page in candidates.chunks(96) {
        let mut batch = Batch::new();
        for pack in page {
            batch = batch.put(
                keys::object_index(&repo.name, &target, pack),
                codec::encode_object_index(&target, &value).unwrap(),
            );
        }
        inner
            .apply(&D34Shards.object_index(&repo, &target), batch)
            .await
            .unwrap();
    }
    inner
        .apply(
            &D34Shards.membership(&repo, &BlobKey::pack(pack_id)),
            Batch::new().put(keys::membership(&repo.name, &pack_id), Value::default()),
        )
        .await
        .unwrap();
    let store = EmptyPages {
        inner,
        start: keys::object_index_range(&repo.name, &target).0,
    };
    let blobs = MemoryBlobStore::default();
    let mut sink = blobs
        .begin(BlobKey::pack(pack_id), packed.len() as u64)
        .await
        .unwrap();
    sink.write(Bytes::from(packed)).await.unwrap();
    sink.commit().await.unwrap();
    // This exact geometry is accepted by the original 128-row locator.
    let old = crate::store::index::locate_many(&store, &D34Shards, &repo, &[target])
        .await
        .unwrap();
    assert!(matches!(old.as_slice(), [Ok(Some(_))]));
    let (root, prefix, ticks) = preflight(&store, &repo, target).await;
    assert_eq!(ticks, 527, "511 empty ticks plus sixteen eight-row pages");
    let budget = SliceBudget::new(700);
    let verified = crate::takedown::acquisition::resolve_selected(
        &Budgeted::new(&blobs, &budget),
        &Budgeted::new(&store, &budget),
        &D34Shards,
        &repo,
        target,
        &crate::takedown::acquisition::Profile::scheduled(),
        &root,
        &prefix,
    )
    .await
    .unwrap();
    assert_eq!(verified.canonical.as_ref(), canonical);
    assert_eq!(budget.used(), 7);
}

#[tokio::test]
async fn corrupt_lookup_counters_and_selected_rows_refuse_completion() {
    let store = MemoryKv::default();
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("corrupt").unwrap(),
    };
    let prefix = crate::Key::new(b"b\0\xffsource-frame\0corrupt".to_vec());
    let mut checkpoint = Checkpoint::new([7; 32]);
    checkpoint.lookup.pages = 512;
    let budget = SliceBudget::new(700);
    assert!(
        step(
            &Budgeted::new(&store, &budget),
            &D34Shards,
            &repo,
            &prefix,
            &crate::takedown::acquisition::Profile::scheduled(),
            checkpoint
        )
        .await
        .is_err()
    );
    assert_eq!(
        budget.used(),
        0,
        "invalid continuation is rejected before source I/O"
    );
    assert!(decode_frame(&Value::new(vec![0; 63])).is_err());
    let mut future = vec![0; 64];
    future.push(2);
    assert!(decode_frame(&Value::new(future)).is_err());
}

#[tokio::test]
async fn all_4096_rows_can_resume_to_a_late_member_in_512_physical_pages() {
    let store = MemoryKv::default();
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("late").unwrap(),
    };
    let target = [7; 32];
    let pack = [255; 32];
    let value = IndexValue {
        frame_offset: 12,
        frame_length: 15,
        wire_type: 0,
        decoded_size: 10,
        chain_depth: 0,
        delta_base: None,
    };
    dense_candidates(
        &store,
        &repo,
        pack,
        IndexEntry {
            object: target,
            value,
        },
    )
    .await;
    let (root, prefix, ticks) = preflight(&store, &repo, target).await;
    assert_eq!(
        ticks, 512,
        "8-row continuation admits all4096 source candidates"
    );
    let raw = store
        .get(
            &root,
            &crate::Key::new([prefix.as_bytes(), &0u32.to_be_bytes()].concat()),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        decode_frame(&raw).unwrap(),
        (target, crate::store::index::LocatedObject { pack, value })
    );
}

#[tokio::test]
async fn dense_same_pack_fifty_hops_complete_across_serialized_ticks() {
    let (blobs, store, repo, target) = dense_chain(false).await;
    let (root, prefix, ticks) = preflight(&store, &repo, target).await;
    assert!(ticks > 50, "dense locator must persist at least one page");
    let budget = SliceBudget::new(700);
    let verified = crate::takedown::acquisition::resolve_selected(
        &Budgeted::new(&blobs, &budget),
        &Budgeted::new(&store, &budget),
        &D34Shards,
        &repo,
        target,
        &crate::takedown::acquisition::Profile::scheduled(),
        &root,
        &prefix,
    )
    .await
    .unwrap();
    assert_eq!(
        verified.canonical.as_ref(),
        blob(
            usize::try_from(crate::indexed::geometry::CANONICAL_BYTES).unwrap(),
            50
        )
    );
    assert_eq!(
        budget.used(),
        357,
        "selected chain performs no dense source lookup"
    );
    let middle = crate::Key::new([prefix.as_bytes(), &25u32.to_be_bytes()].concat());
    for damaged in [Some(Value::new(vec![0; 63])), None] {
        let batch = match damaged {
            Some(raw) => Batch::new().put(middle.clone(), raw),
            None => Batch::new().delete(middle.clone()),
        };
        store.apply(&root, batch).await.unwrap();
        let retry = SliceBudget::new(700);
        assert!(
            crate::takedown::acquisition::resolve_selected(
                &Budgeted::new(&blobs, &retry),
                &Budgeted::new(&store, &retry),
                &D34Shards,
                &repo,
                target,
                &crate::takedown::acquisition::Profile::scheduled(),
                &root,
                &prefix
            )
            .await
            .is_err(),
            "damaged selected middle frame refuses canonical success"
        );
        assert!(retry.used() < 700);
    }
}

#[tokio::test]
async fn dense_external_fifty_hops_complete_and_final_decode_rechecks_membership() {
    let (blobs, store, repo, target) = dense_chain(true).await;
    let (root, prefix, ticks) = preflight(&store, &repo, target).await;
    assert!(
        ticks > 512,
        "external chain traverses multiple dense candidate sets"
    );
    let budget = SliceBudget::new(700);
    let verified = crate::takedown::acquisition::resolve_selected(
        &Budgeted::new(&blobs, &budget),
        &Budgeted::new(&store, &budget),
        &D34Shards,
        &repo,
        target,
        &crate::takedown::acquisition::Profile::scheduled(),
        &root,
        &prefix,
    )
    .await
    .unwrap();
    assert_eq!(
        verified.canonical.as_ref(),
        blob(
            usize::try_from(crate::indexed::geometry::CANONICAL_BYTES).unwrap(),
            50
        )
    );
    assert_eq!(budget.used(), 357);
    let raw = store
        .get(
            &root,
            &crate::Key::new([prefix.as_bytes(), &50u32.to_be_bytes()].concat()),
        )
        .await
        .unwrap()
        .unwrap();
    let (_, terminal) = decode_frame(&raw).unwrap();
    store
        .apply(
            &D34Shards.membership(&repo, &BlobKey::pack(terminal.pack)),
            Batch::new().delete(keys::membership(&repo.name, &terminal.pack)),
        )
        .await
        .unwrap();
    let retry = SliceBudget::new(700);
    assert!(
        crate::takedown::acquisition::resolve_selected(
            &Budgeted::new(&blobs, &retry),
            &Budgeted::new(&store, &retry),
            &D34Shards,
            &repo,
            target,
            &crate::takedown::acquisition::Profile::scheduled(),
            &root,
            &prefix
        )
        .await
        .is_err(),
        "selected source loses authority when membership disappears"
    );
    assert!(retry.used() < 700);
}
