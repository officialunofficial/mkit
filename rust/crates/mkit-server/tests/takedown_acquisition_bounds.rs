#![cfg(feature = "memory")]
// Invalid fixture setup should fail the regression immediately.
#![allow(clippy::unwrap_used)]

use bytes::Bytes;
use mkit_core::{
    hash::{Hash, hash},
    object::{Blob, Object},
    pack::{self, DecodeLimits, DeltaBaseSource, PackError},
    serialize::serialize,
};
use mkit_server::indexed::budget::{Budgeted, SliceBudget};
use mkit_server::pipeline::{D34Shards, ShardMap, SinglePartition};
use mkit_server::store::adapter_spi::{
    codec,
    index::{IndexEntry, IndexValue},
    keys,
};
use mkit_server::takedown::acquisition::*;
use mkit_server::{
    Batch, BlobKey, BlobStore, MemoryBlobStore, MemoryKv, NamespaceKey, NamespaceStore,
    NoopMetrics, PackSink, RepoId, RepoName, Value,
};

/// D34 routing with the earlier twelve-bit repository index (4,096 partitions
/// per repository). D34 now uses sixteen, which cannot reach the worst-case
/// partition spread these bound tests exercise; the lookup caps themselves
/// are unchanged and still apply to any shard map.
struct WideShards;
impl WideShards {
    fn wide(id: &Hash) -> u16 {
        (u16::from(id[0]) << 4) | u16::from(id[1] >> 4)
    }
}
impl ShardMap for WideShards {
    fn ref_shard(&self, repo: &RepoId, ref_name: &str) -> mkit_server::Partition {
        D34Shards.ref_shard(repo, ref_name)
    }
    fn coordinator(&self, ns: &NamespaceKey) -> mkit_server::Partition {
        D34Shards.coordinator(ns)
    }
    fn ref_index(&self, repo: &RepoId, ref_name: &str) -> mkit_server::Partition {
        D34Shards.ref_index(repo, ref_name)
    }
    fn ref_index_partitions(&self, repo: &RepoId) -> Vec<mkit_server::Partition> {
        D34Shards.ref_index_partitions(repo)
    }
    fn membership(&self, repo: &RepoId, pack: &BlobKey) -> mkit_server::Partition {
        mkit_server::Partition::RepoIndex {
            ns: repo.namespace.clone(),
            repo: repo.name.clone(),
            prefix: Self::wide(pack.hash()),
        }
    }
    fn object_index(&self, repo: &RepoId, object: &Hash) -> mkit_server::Partition {
        mkit_server::Partition::RepoIndex {
            ns: repo.namespace.clone(),
            repo: repo.name.clone(),
            prefix: Self::wide(object),
        }
    }
}

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
#[cfg(feature = "pack-ruzstd")]
fn large_delta(size: usize, sequence: u32) -> Vec<u8> {
    let mut stream = vec![1];
    stream.extend_from_slice(&u32::try_from(size).unwrap().to_le_bytes());
    stream.extend_from_slice(&u32::try_from(size).unwrap().to_le_bytes());
    let small_copies = ((1 << 20) - 256) / 7;
    for offset in 0..small_copies {
        stream.push(0x80);
        stream.extend_from_slice(&u32::try_from(offset).unwrap().to_le_bytes());
        stream.extend_from_slice(&1u16.to_le_bytes());
    }
    let mut offset = small_copies;
    while offset < size - 4 {
        let len = (size - 4 - offset).min(u16::MAX as usize);
        stream.push(0x80);
        stream.extend_from_slice(&u32::try_from(offset).unwrap().to_le_bytes());
        stream.extend_from_slice(&u16::try_from(len).unwrap().to_le_bytes());
        offset += len;
    }
    stream.push(4);
    stream.extend_from_slice(&sequence.to_le_bytes());
    assert!(stream.len() <= 1 << 20);
    assert!(stream.len() > (1 << 20) - 256);
    stream
}
#[cfg(feature = "pack-ruzstd")]
fn zstd_raw_blocks(bytes: &[u8]) -> Vec<u8> {
    let mut payload = u32::try_from(bytes.len()).unwrap().to_le_bytes().to_vec();
    // Unknown content size and the largest window Worker admission permits.
    payload.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0, 0x68]);
    let blocks = bytes.chunks(128 << 10);
    let count = blocks.len();
    for (index, block) in blocks.enumerate() {
        let header = (u32::try_from(block.len()).unwrap() << 3) | u32::from(index + 1 == count);
        payload.extend_from_slice(&header.to_le_bytes()[..3]);
        payload.extend_from_slice(block);
    }
    payload
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
async fn fixture(
    pack: &[u8],
    entries: &[IndexEntry],
) -> (MemoryBlobStore, std::sync::Arc<MemoryKv>, RepoId) {
    let blobs = MemoryBlobStore::default();
    let store = std::sync::Arc::new(MemoryKv::with_clock(std::sync::Arc::new(
        mkit_server::ManualClock::new(0),
    )));
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("repo").unwrap(),
    };
    let id = hash(pack);
    let mut sink = blobs
        .begin(BlobKey::pack(id), pack.len() as u64)
        .await
        .unwrap();
    for piece in pack.chunks(mkit_server::store::MAX_BLOB_PIECE_BYTES) {
        sink.write(Bytes::copy_from_slice(piece)).await.unwrap();
    }
    sink.commit().await.unwrap();
    let p = SinglePartition.object_index(&repo, &entries[0].object);
    let mut batch = Batch::new().put(keys::membership(&repo.name, &id), Value::default());
    for entry in entries {
        batch = batch.put(
            keys::object_index(&repo.name, &entry.object, &id),
            codec::encode_object_index(&entry.object, &entry.value).unwrap(),
        );
    }
    store.apply(&p, batch).await.unwrap();
    (blobs, store, repo)
}
fn admitted(pack: &[u8], expected: usize) {
    admitted_with_pinned(pack, expected, None);
}
fn admitted_with_pinned(mut pack: &[u8], expected: usize, pinned: Option<Hash>) {
    let mut latest = Latest(vec![]);
    let mut count = 0;
    let limits = DecodeLimits::default().with_max_decoded_bytes(1 << 20);
    let length = pack.len() as u64;
    let id = hash(pack);
    pack::window::read_all(&mut pack, length, 16 << 20, limits, Some(id), |entry| {
        let (id, bytes) = pack::decode_entry_with(entry, &mut latest, limits)?;
        latest.0.push((id, bytes));
        if latest.0.len() > 2 {
            let evict = usize::from(pinned == Some(latest.0[0].0));
            latest.0.remove(evict);
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
            .map(|id| WideShards.membership(repo, &BlobKey::pack(*id)))
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
            .apply(&WideShards.object_index(repo, &entry.object), batch)
            .await
            .unwrap();
    }
    store
        .apply(
            &WideShards.membership(repo, &BlobKey::pack(pack)),
            Batch::new().put(keys::membership(&repo.name, &pack), Value::default()),
        )
        .await
        .unwrap();
}

async fn dense_chain(external: bool) -> (MemoryBlobStore, MemoryKv, RepoId, Hash) {
    let size = 1 << 20;
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
                DecodeLimits::default().with_max_decoded_bytes(1 << 20),
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
        for piece in bytes.chunks(mkit_server::store::MAX_BLOB_PIECE_BYTES) {
            sink.write(Bytes::copy_from_slice(piece)).await.unwrap();
        }
        sink.commit().await.unwrap();
        for entry in &entries {
            if external || entry.object == previous {
                dense_candidates(&store, &repo, pack_id, *entry).await;
            } else {
                store
                    .apply(
                        &WideShards.object_index(&repo, &entry.object),
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

#[tokio::test]
async fn dense_same_pack_max_chain_exceeds_alarm_budget_without_source_checkpoint() {
    let (blobs, store, repo, id) = dense_chain(false).await;
    for _ in 0..2 {
        let budget = SliceBudget::new(700);
        assert!(
            resolve(
                &Budgeted::new(&blobs, &budget),
                &Budgeted::new(&store, &budget),
                &WideShards,
                &repo,
                id,
                &Profile::scheduled(),
                &NoopMetrics
            )
            .await
            .is_err()
        );
        assert_eq!(
            budget.used(),
            700,
            "fresh retry repeats the same exhausted acquisition"
        );
    }
    for limit in [900, 30_000] {
        let budget = SliceBudget::new(limit);
        let result = resolve(
            &Budgeted::new(&blobs, &budget),
            &Budgeted::new(&store, &budget),
            &WideShards,
            &repo,
            id,
            &Profile::scheduled(),
            &NoopMetrics,
        )
        .await
        .unwrap();
        assert_eq!(result.canonical.as_ref(), blob(1 << 20, 50));
        assert_eq!(
            budget.used(),
            773,
            "32 scans + 487 membership reads + 204 ranges + 50 same-pack probes"
        );
    }
}

#[tokio::test]
async fn dense_external_max_chain_repeats_candidate_lookup_for_every_base() {
    let (blobs, store, repo, id) = dense_chain(true).await;
    for limit in [700, 900] {
        let budget = SliceBudget::new(limit);
        assert!(
            resolve(
                &Budgeted::new(&blobs, &budget),
                &Budgeted::new(&store, &budget),
                &WideShards,
                &repo,
                id,
                &Profile::scheduled(),
                &NoopMetrics
            )
            .await
            .is_err()
        );
        assert_eq!(budget.used(), limit);
    }
    let budget = SliceBudget::new(30_000);
    let result = resolve(
        &Budgeted::new(&blobs, &budget),
        &Budgeted::new(&store, &budget),
        &WideShards,
        &repo,
        id,
        &Profile::scheduled(),
        &NoopMetrics,
    )
    .await
    .unwrap();
    assert_eq!(result.canonical.as_ref(), blob(1 << 20, 50));
    assert_eq!(
        budget.used(),
        26_723,
        "51 dense lookups + 204 ranges + 50 failed same-pack probes"
    );
}

#[tokio::test]
async fn scheduled_acquires_fifty_hop_chain_after_independent_lookup() {
    let size = 1 << 20;
    let mut pack = b"MKIT\x01\0\0\0\0\0\0\0".to_vec();
    let bytes = blob(size, 0);
    let mut previous = hash(&bytes);
    let (offset, length) = append(&mut pack, 0, &bytes);
    let mut entries = vec![IndexEntry {
        object: previous,
        value: IndexValue {
            frame_offset: offset,
            frame_length: length,
            wire_type: 0,
            decoded_size: size as u64,
            chain_depth: 0,
            delta_base: None,
        },
    }];
    for sequence in 1..=50 {
        let id = hash(&blob(size, sequence));
        let mut payload = previous.to_vec();
        payload.extend_from_slice(&delta(size, sequence));
        let (offset, length) = append(&mut pack, 2, &payload);
        entries.push(IndexEntry {
            object: id,
            value: IndexValue {
                frame_offset: offset,
                frame_length: length,
                wire_type: 2,
                decoded_size: size as u64,
                chain_depth: sequence,
                delta_base: Some(previous),
            },
        });
        previous = id;
    }
    let pack = finish(pack, 51);
    admitted(&pack, 51);
    let (blobs, store, repo) = fixture(&pack, &entries).await;
    let budget = SliceBudget::new(700);
    start_allocations();
    let result = resolve(
        &Budgeted::new(&blobs, &budget),
        &Budgeted::new(&store, &budget),
        &SinglePartition,
        &repo,
        previous,
        &Profile::scheduled(),
        &NoopMetrics,
    )
    .await
    .unwrap();
    let peak = finish_allocations();
    assert!(
        peak + mkit_server::store::MAX_BLOB_PIECE_BYTES
            <= usize::try_from(Profile::scheduled().resident_upper_bound()).unwrap(),
        "acquisition peak: {peak}"
    );
    eprintln!(
        "acquisition measured peak={peak}, charged={}",
        budget.used()
    );
    assert_eq!(result.canonical.as_ref(), blob(size, 50));
    assert_eq!(result.kind, 1);
    assert!(
        budget.used() <= 256,
        "actual charged boundaries: {}",
        budget.used()
    );
    let exhausted = SliceBudget::new(1);
    assert!(
        resolve(
            &Budgeted::new(&blobs, &exhausted),
            &Budgeted::new(&store, &exhausted),
            &SinglePartition,
            &repo,
            previous,
            &Profile::scheduled(),
            &NoopMetrics
        )
        .await
        .is_err()
    );
    assert_eq!(exhausted.used(), 1);
}
#[cfg(feature = "pack-ruzstd")]
#[tokio::test]
async fn scheduled_bounds_fifty_compressed_delta_instruction_streams() {
    compressed_chain(false).await;
}

#[cfg(feature = "pack-ruzstd")]
#[tokio::test]
async fn scheduled_bounds_fifty_hops_with_maximum_wire_frame() {
    compressed_chain(true).await;
}

#[cfg(feature = "pack-ruzstd")]
fn widen_delta_frame(pack: &mut Vec<u8>, payload: &mut Vec<u8>, count: &mut u32) {
    let size = 1 << 20;
    // An admitted full-window compressed payload starts just after a
    // header at the preceding window's end. Fill with admitted blobs.
    let boundary = (pack.len() / (16 << 20) + 1) * (16 << 20) - 5;
    while pack.len() < boundary {
        let gap = boundary - pack.len();
        let mut frame_len = gap.min(size + 5);
        if gap > frame_len && gap - frame_len < 19 {
            frame_len -= 19;
        }
        append(pack, 0, &blob(frame_len - 5, 999));
        *count += 1;
    }
    // Extend the single zstd frame with legal empty blocks. Preserve
    // the near-1-MiB instruction stream and the 8-MiB decoder window.
    let mut header = 32 + 4 + 6;
    loop {
        let word =
            u32::from_le_bytes([payload[header], payload[header + 1], payload[header + 2], 0]);
        if word & 1 != 0 {
            payload[header] &= !1;
            break;
        }
        header += 3 + usize::try_from(word >> 3).unwrap();
    }
    let padded = payload.len() + ((16 << 20) - payload.len()) / 3 * 3;
    payload.resize(padded, 0);
    payload[padded - 3] = 1;
    assert!(payload.len() >= (16 << 20) - 2);
}

#[cfg(feature = "pack-ruzstd")]
async fn compressed_chain(wide: bool) {
    let size = 1 << 20;
    let mut pack = b"MKIT\x02\0\0\0\0\0\0\0".to_vec();
    let canonical = blob(size, 0);
    let mut previous = hash(&canonical);
    let mut count = 1;
    let (offset, length) = append(&mut pack, 0, &canonical);
    let mut entries = vec![IndexEntry {
        object: previous,
        value: IndexValue {
            frame_offset: offset,
            frame_length: length,
            wire_type: 0,
            decoded_size: size as u64,
            chain_depth: 0,
            delta_base: None,
        },
    }];
    for sequence in 1..=50 {
        let id = hash(&blob(size, sequence));
        let mut payload = previous.to_vec();
        payload.extend_from_slice(&zstd_raw_blocks(&large_delta(size, sequence)));
        if wide && sequence == 50 {
            widen_delta_frame(&mut pack, &mut payload, &mut count);
        }
        let remaining = (16 << 20) - pack.len() % (16 << 20);
        if !(wide && sequence == 50) && payload.len() + 5 > remaining {
            // Keep this near-1 MiB payload in one admission window: a carried
            // compressed payload and its output together would exceed 1 MiB.
            append(&mut pack, 0, &blob(remaining - 5, 999));
            count += 1;
        }
        let (offset, length) = append(&mut pack, 4, &payload);
        count += 1;
        entries.push(IndexEntry {
            object: id,
            value: IndexValue {
                frame_offset: offset,
                frame_length: length,
                wire_type: 4,
                decoded_size: size as u64,
                chain_depth: sequence,
                delta_base: Some(previous),
            },
        });
        previous = id;
    }
    let pack = finish(pack, count);
    admitted_with_pinned(
        &pack,
        usize::try_from(count).unwrap(),
        wide.then(|| hash(&blob(size, 49))),
    );
    let (blobs, store, repo) = fixture(&pack, &entries).await;
    let budget = SliceBudget::new(700);
    start_allocations();
    let result = resolve(
        &Budgeted::new(&blobs, &budget),
        &Budgeted::new(&store, &budget),
        &SinglePartition,
        &repo,
        previous,
        &Profile::scheduled(),
        &NoopMetrics,
    )
    .await
    .unwrap();
    let peak = finish_allocations();
    eprintln!(
        "compressed acquisition peak={peak}, charged={}",
        budget.used()
    );
    assert!(
        peak + mkit_server::store::MAX_BLOB_PIECE_BYTES <= 48 << 20,
        "acquisition peak: {peak}"
    );
    assert_eq!(result.canonical.as_ref(), blob(size, 50));
    assert!(budget.used() <= 256);
}

#[cfg(feature = "pack-ruzstd")]
#[tokio::test]
async fn scheduled_accepts_admitted_large_wire_small_decoded_frame() {
    let mut pack = b"MKIT\x02\0\0\0\0\0\0\0".to_vec();
    for n in 0..15 {
        append(&mut pack, 0, &blob(1 << 20, n));
    }
    let remaining = (16 << 20) - 5 - pack.len() - 5;
    append(&mut pack, 0, &blob(remaining, 99));
    assert_eq!(pack.len(), (16 << 20) - 5);
    let canonical = serialize(&Object::Blob(Blob {
        data: b"AB".to_vec(),
    }))
    .unwrap();
    let mut payload = (u32::try_from(canonical.len()).unwrap())
        .to_le_bytes()
        .to_vec();
    payload.extend_from_slice(&[
        0x28,
        0xb5,
        0x2f,
        0xfd,
        0x20,
        u8::try_from(canonical.len()).unwrap(),
    ]);
    payload.extend_from_slice(&[u8::try_from(canonical.len() << 3).unwrap(), 0, 0]);
    payload.extend_from_slice(&canonical);
    let blocks = ((16 << 20) - payload.len()) / 3;
    payload.resize(payload.len() + blocks * 3, 0);
    let last = payload.len() - 3;
    payload[last] = 1;
    assert_eq!(payload.len(), 16 << 20);
    let (offset, length) = append(&mut pack, 3, &payload);
    let pack = finish(pack, 17);
    admitted(&pack, 17);
    let id = hash(&canonical);
    let entry = IndexEntry {
        object: id,
        value: IndexValue {
            frame_offset: offset,
            frame_length: length,
            wire_type: 3,
            decoded_size: canonical.len() as u64,
            chain_depth: 0,
            delta_base: None,
        },
    };
    let (blobs, store, repo) = fixture(&pack, &[entry]).await;
    let budget = SliceBudget::new(700);
    start_allocations();
    let result = resolve(
        &Budgeted::new(&blobs, &budget),
        &Budgeted::new(&store, &budget),
        &SinglePartition,
        &repo,
        id,
        &Profile::scheduled(),
        &NoopMetrics,
    )
    .await
    .unwrap();
    let peak = finish_allocations();
    assert!(
        peak + mkit_server::store::MAX_BLOB_PIECE_BYTES
            <= usize::try_from(Profile::scheduled().resident_upper_bound()).unwrap(),
        "acquisition peak: {peak}"
    );
    eprintln!(
        "acquisition measured peak={peak}, charged={}",
        budget.used()
    );
    assert_eq!(result.canonical.as_ref(), canonical);
    assert_eq!(length, (16 << 20) + 5);
    assert!(peak < 20 << 20, "exact frame reservation: {peak}");
    assert!(budget.used() <= 8);
}

// Standalone test-only instrumentation; the server library forbids unsafe code.
// Allocation epochs exclude pre-existing fixture/backend bytes and other threads.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};
#[derive(Clone, Copy, Default)]
struct AllocationStats {
    live: usize,
    peak: usize,
}
thread_local! {
    static EPOCH: Cell<u64> = const { Cell::new(0) };
    static STATS: Cell<AllocationStats> = const { Cell::new(AllocationStats {live:0,peak:0}) };
}
static NEXT_EPOCH: AtomicU64 = AtomicU64::new(1);
struct CountAlloc;
#[global_allocator]
static ALLOCATOR: CountAlloc = CountAlloc;
fn allocation_layout(layout: Layout) -> Option<(Layout, usize)> {
    Layout::new::<u64>()
        .extend(layout)
        .ok()
        .map(|(combined, offset)| (combined.pad_to_align(), offset))
}
fn epoch() -> u64 {
    EPOCH.try_with(Cell::get).unwrap_or(0)
}
fn add(owner: u64, bytes: usize) {
    if owner != 0 {
        let _ = STATS.try_with(|state| {
            let mut stats = state.get();
            stats.live += bytes;
            stats.peak = stats.peak.max(stats.live);
            state.set(stats);
        });
    }
}
// SAFETY: the prefixed allocation satisfies the requested layout. Its header is
// recovered using the identical layout on release; realloc preserves user bytes.
// The combined layout explicitly guarantees u64 alignment for the prefix.
#[allow(clippy::cast_ptr_alignment)]
unsafe impl GlobalAlloc for CountAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let Some((combined, offset)) = allocation_layout(layout) else {
            return std::ptr::null_mut();
        };
        // SAFETY: combined is a valid nonzero layout; null is propagated.
        let base = unsafe { System.alloc(combined) };
        if base.is_null() {
            return base;
        }
        let owner = epoch();
        // SAFETY: the prefix is an aligned u64, disjoint from the user region.
        unsafe { base.cast::<u64>().write(owner) };
        add(owner, layout.size());
        unsafe { base.add(offset) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: alloc honors layout; only the valid user region is zeroed.
        let ptr = unsafe { self.alloc(layout) };
        if !ptr.is_null() {
            unsafe { ptr.write_bytes(0, layout.size()) };
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let Some((combined, offset)) = allocation_layout(layout) else {
            return;
        };
        // SAFETY: ptr came from alloc with this exact layout and prefix offset.
        let base = unsafe { ptr.sub(offset) };
        let owner = unsafe { base.cast::<u64>().read() };
        if owner != 0 && owner == epoch() {
            let _ = STATS.try_with(|state| {
                let mut stats = state.get();
                stats.live -= layout.size();
                state.set(stats);
            });
        }
        // SAFETY: base and combined match the original System allocation.
        unsafe { System.dealloc(base, combined) };
    }
    unsafe fn realloc(&self, ptr: *mut u8, old: Layout, size: usize) -> *mut u8 {
        let Ok(new) = Layout::from_size_align(size, old.align()) else {
            return std::ptr::null_mut();
        };
        // SAFETY: alignment is preserved; failed allocation leaves ptr live.
        // Both buffers count at peak, conservatively covering a moving realloc.
        let next = unsafe { self.alloc(new) };
        if !next.is_null() {
            unsafe { std::ptr::copy_nonoverlapping(ptr, next, old.size().min(size)) };
            unsafe { self.dealloc(ptr, old) };
        }
        next
    }
}
fn start_allocations() {
    STATS.with(|state| state.set(AllocationStats::default()));
    EPOCH.with(|state| state.set(NEXT_EPOCH.fetch_add(1, Ordering::Relaxed)));
}
fn finish_allocations() -> usize {
    EPOCH.with(|state| state.set(0));
    STATS.with(|state| state.get().peak)
}

#[tokio::test]
async fn canonical_manifest_keeps_order_duplicates_and_denied_acquisition_privilege() {
    use mkit_core::object::ChunkedBlob;
    use mkit_server::ContentIndex;
    use mkit_server::store::BlockEntry;
    let a = hash(
        &serialize(&Object::Blob(Blob {
            data: b"A".to_vec(),
        }))
        .unwrap(),
    );
    let b = hash(
        &serialize(&Object::Blob(Blob {
            data: b"B".to_vec(),
        }))
        .unwrap(),
    );
    let ordered = vec![b, a, b, a];
    let manifest = ChunkedBlob {
        total_size: 4,
        chunk_size: 1,
        chunks: ordered.clone(),
    };
    let id = mkit_core::merkle::compute_chunked_id(&manifest);
    let canonical = serialize(&Object::ChunkedBlob(manifest)).unwrap();
    let mut pack = b"MKIT\x01\0\0\0\0\0\0\0".to_vec();
    let (offset, length) = append(&mut pack, 0, &canonical);
    let pack = finish(pack, 1);
    let entry = IndexEntry {
        object: id,
        value: IndexValue {
            frame_offset: offset,
            frame_length: length,
            wire_type: 0,
            decoded_size: canonical.len() as u64,
            chain_depth: 0,
            delta_base: None,
        },
    };
    let (blobs, store, repo) = fixture(&pack, &[entry]).await;
    let content = ContentIndex::new(store.clone());
    content
        .block(&id, &BlockEntry::new("policy", 1), 1)
        .await
        .unwrap();
    let budget = SliceBudget::new(700);
    let verified = resolve(
        &Budgeted::new(&blobs, &budget),
        &Budgeted::new(&store, &budget),
        &SinglePartition,
        &repo,
        id,
        &Profile::scheduled(),
        &NoopMetrics,
    )
    .await
    .unwrap();
    assert_eq!(verified.kind, 5);
    assert_eq!(verified.canonical.as_ref(), canonical);
    let Object::ChunkedBlob(decoded) =
        mkit_core::serialize::deserialize(&verified.canonical).unwrap()
    else {
        panic!("manifest kind lost")
    };
    assert_eq!(decoded.chunks, ordered);
    assert!(content.blocked(&id).await.unwrap().is_some());
    let foreign = RepoId {
        name: RepoName::new("foreign").unwrap(),
        ..repo
    };
    assert!(
        resolve(
            &blobs,
            &store,
            &SinglePartition,
            &foreign,
            id,
            &Profile::scheduled(),
            &NoopMetrics
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn whole_pack_tree_retains_verified_canonical_kind() {
    let tree = mkit_core::object::Tree { entries: vec![] };
    let id = mkit_core::merkle::compute_tree_id(&tree);
    let canonical = serialize(&Object::Tree(tree)).unwrap();
    let mut pack = b"MKIT\x01\0\0\0\0\0\0\0".to_vec();
    let (offset, length) = append(&mut pack, 0, &canonical);
    let pack = finish(pack, 1);
    admitted(&pack, 1);
    let entry = IndexEntry {
        object: id,
        value: IndexValue {
            frame_offset: offset,
            frame_length: length,
            wire_type: 0,
            decoded_size: canonical.len() as u64,
            chain_depth: 0,
            delta_base: None,
        },
    };
    let (blobs, store, repo) = fixture(&pack, &[entry]).await;
    let budget = SliceBudget::new(700);
    let verified = resolve(
        &Budgeted::new(&blobs, &budget),
        &Budgeted::new(&store, &budget),
        &SinglePartition,
        &repo,
        id,
        &Profile::scheduled(),
        &NoopMetrics,
    )
    .await
    .unwrap();
    assert_eq!(verified.id, id);
    assert_eq!(verified.kind, 2);
    assert_eq!(verified.canonical.as_ref(), canonical);
}

#[tokio::test]
async fn recursive_source_limit_rejects_false_size_before_preservation() {
    let source = blob((1 << 20) + 1, 0);
    let source_id = hash(&source);
    let target = serialize(&Object::Blob(Blob {
        data: b"A".to_vec(),
    }))
    .unwrap();
    let target_id = hash(&target);
    let mut stream = vec![1];
    stream.extend_from_slice(&u32::try_from(source.len()).unwrap().to_le_bytes());
    stream.extend_from_slice(&u32::try_from(target.len()).unwrap().to_le_bytes());
    stream.push(u8::try_from(target.len()).unwrap());
    stream.extend_from_slice(&target);
    let mut pack = b"MKIT\x01\0\0\0\0\0\0\0".to_vec();
    let (first, first_len) = append(&mut pack, 0, &source);
    let mut delta_payload = source_id.to_vec();
    delta_payload.extend_from_slice(&stream);
    let (second, second_len) = append(&mut pack, 2, &delta_payload);
    let pack = finish(pack, 2);
    let entries = [
        IndexEntry {
            object: source_id,
            value: IndexValue {
                frame_offset: first,
                frame_length: first_len,
                wire_type: 0,
                decoded_size: 1 << 20,
                chain_depth: 0,
                delta_base: None,
            },
        },
        IndexEntry {
            object: target_id,
            value: IndexValue {
                frame_offset: second,
                frame_length: second_len,
                wire_type: 2,
                decoded_size: target.len() as u64,
                chain_depth: 1,
                delta_base: Some(source_id),
            },
        },
    ];
    let (blobs, store, repo) = fixture(&pack, &entries).await;
    let budget = SliceBudget::new(700);
    start_allocations();
    let result = resolve(
        &Budgeted::new(&blobs, &budget),
        &Budgeted::new(&store, &budget),
        &SinglePartition,
        &repo,
        target_id,
        &Profile::scheduled(),
        &NoopMetrics,
    )
    .await;
    let peak = finish_allocations();
    assert!(result.is_err());
    assert!(peak < 3 << 20, "oversized recursive source: {peak}");
    assert!(budget.used() < 20);
}
