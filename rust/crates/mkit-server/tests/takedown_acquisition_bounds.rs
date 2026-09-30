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
use mkit_server::pipeline::{ShardMap, SinglePartition};
use mkit_server::store::{
    codec,
    index::{IndexEntry, IndexValue},
    keys,
};
use mkit_server::takedown::acquisition::*;
use mkit_server::{
    Batch, BlobKey, BlobStore, MemoryBlobStore, MemoryKv, NamespaceKey, NamespaceStore,
    NoopMetrics, PackSink, RepoId, RepoName, Value,
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
    let store = std::sync::Arc::new(MemoryKv::default());
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
fn admitted(mut pack: &[u8], expected: usize) {
    let mut latest = Latest(vec![]);
    let mut count = 0;
    let limits = DecodeLimits::default().with_max_decoded_bytes(1 << 20);
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
        let remaining = (16 << 20) - pack.len() % (16 << 20);
        if payload.len() + 5 > remaining {
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
    admitted(&pack, usize::try_from(count).unwrap());
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
    assert!(peak + mkit_server::store::MAX_BLOB_PIECE_BYTES < 96 << 20);
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
