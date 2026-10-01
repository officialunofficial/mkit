//! Requested live allocation bound of an actual kind-7 verification slice.
//!
//! Run this binary alone, with the pure-Rust decoder and a single test thread:
//! `cargo test -p mkit-server --no-default-features --features memory,pack-ruzstd
//! --test zstd_slice_heap_bounds -- --ignored --nocapture --test-threads=1`.
//! The selected dependency graph must not enable mkit-core/pack-zstd: dependency
//! features cannot be inspected by this crate's cfg. This is requested heap,
//! including newly acquired input windows, not process RSS or a CPU measurement.
#![cfg(all(
    feature = "memory",
    feature = "pack-ruzstd",
    not(target_arch = "wasm32")
))]
#![allow(clippy::unwrap_used)] // Invalid fixtures and failed assertions fail the test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures_executor::block_on;
use mkit_core::hash::{Hash, hash, to_hex};
use mkit_core::object::{Blob, Object};
use mkit_core::pack::{MAGIC, PackWriter, VERSION, VERSION_V2};
use mkit_core::serialize::serialize;
use mkit_server::indexed::budget::{PackWindows, Window, WindowError};
use mkit_server::indexed::checkpoint::{Phase, read_job};
use mkit_server::indexed::job::{FailClosedExtraction, SliceLimits, VerifyTimer};
use mkit_server::indexed::{IndexedConfig, scheduled, state};
use mkit_server::pipeline::{LeaseParams, ShardMap, SinglePartition};
use mkit_server::store::{Batch, BatchOutcome, NamespaceStore, codec, keys, tickets};
use mkit_server::timers::{TickBudget, TimerRegistry, run_due};
use mkit_server::{
    BoxFuture, ManualClock, MemoryBlobStore, MemoryKv, NamespaceKey, NoopMetrics, RepoId, RepoName,
};

struct CountingAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn account(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::SeqCst) + size;
    PEAK.fetch_max(live, Ordering::SeqCst);
}

// SAFETY: System receives each original pointer and layout. Accounting does
// not allocate. GlobalAlloc's default realloc uses these alloc/dealloc methods,
// retaining the observable overlap of the old and new requested allocations.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            account(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            account(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        unsafe { System.dealloc(pointer, layout) };
    }
}

const MIB: usize = 1 << 20;
const PREFIX_OBJECTS: usize = 8;
const CANONICAL_DATA_BYTES: usize = MIB - 16;
const NOW: u64 = 1_700_000_000_000;

/// An immutable backend fixture. The stored pack is seeded before measurement,
/// but each requested range is acquired into a fresh Vec during the slice.
struct AcquiredWindows {
    pack: Arc<Vec<u8>>,
    id: Hash,
    reads: Arc<AtomicUsize>,
}

impl PackWindows for AcquiredWindows {
    fn read<'a>(
        &'a self,
        pack: &'a Hash,
        offset: u64,
        len: u64,
        etag: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Window, WindowError>> {
        Box::pin(async move {
            if pack != &self.id {
                return Err(WindowError::Missing);
            }
            let tag = to_hex(&self.id);
            if etag.is_some_and(|expected| expected != tag) {
                return Err(WindowError::EtagChanged);
            }
            let start = usize::try_from(offset).map_err(|_| WindowError::Unavailable)?;
            let length = usize::try_from(len).map_err(|_| WindowError::Unavailable)?;
            let end = start.checked_add(length).ok_or(WindowError::Unavailable)?;
            let range = self.pack.get(start..end).ok_or(WindowError::Unavailable)?;
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(Window {
                bytes: range.to_vec(),
                etag: tag,
            })
        })
    }
}

fn raw_entry(pack: &mut Vec<u8>, tag: u8) -> usize {
    let raw = serialize(&Object::Blob(Blob {
        data: vec![tag; CANONICAL_DATA_BYTES],
    }))
    .unwrap();
    assert!(raw.len() < MIB);
    pack.push(0);
    pack.extend_from_slice(&u32::try_from(raw.len()).unwrap().to_le_bytes());
    pack.extend_from_slice(&raw);
    raw.len()
}

/// Every block is a legal 128 KiB RLE block, with an admitted 8 MiB window
/// and no declared frame content size. Total regenerated history exceeds the
/// entry's claim just below 1 MiB. `StreamingDecoder` must retain history before the first
/// output read, so the claim alone does not bound that working allocation.
fn rle_history_entry(pack: &mut Vec<u8>) {
    let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0x68];
    for index in 0..70 {
        let header = ((128_u32 << 10) << 3) | (1 << 1) | u32::from(index == 69);
        frame.extend_from_slice(&header.to_le_bytes()[..3]);
        frame.push(b'A');
    }
    pack.push(3);
    pack.extend_from_slice(&u32::try_from(frame.len() + 4).unwrap().to_le_bytes());
    // WindowReader charges the wire payload plus the claim against the 1 MiB
    // entry allowance. Leave enough room to reach decompression itself.
    let claim = MIB - 1024;
    assert!(claim + frame.len() + 4 <= MIB);
    pack.extend_from_slice(&u32::try_from(claim).unwrap().to_le_bytes());
    pack.extend_from_slice(&frame);
}

fn fixture() -> (Vec<u8>, usize) {
    let mut pack = Vec::new();
    pack.extend_from_slice(MAGIC);
    pack.extend_from_slice(&VERSION_V2.to_le_bytes());
    pack.extend_from_slice(&18_u32.to_le_bytes()); // 8 prefix + malformed + 9 trailing.
    let mut retained_canonical_bytes = 0;
    for tag in 0..PREFIX_OBJECTS {
        retained_canonical_bytes += raw_entry(&mut pack, u8::try_from(tag).unwrap());
    }
    assert!(retained_canonical_bytes <= 8 * MIB);
    assert!(retained_canonical_bytes > 8 * MIB - 1024);
    rle_history_entry(&mut pack);
    // The backend's first real acquisition must cover a full 16 MiB window;
    // trailing entries will never decode because the malformed frame rejects.
    for tag in 16..25 {
        raw_entry(&mut pack, tag);
    }
    let trailer = hash(&pack);
    pack.extend_from_slice(&trailer);
    assert!(pack.len() > 16 * MIB);
    (pack, retained_canonical_bytes)
}

#[test]
#[allow(clippy::too_many_lines)] // One isolated allocator window covers the complete slice.
#[ignore = "run explicitly in an isolated pure-Rust decoder graph; all-features enables C"]
fn scheduled_ruzstd_slice_retains_at_most_48_mib_requested_heap() {
    // A C-enabled writer compresses this highly compressible object. Refuse
    // such a graph instead of accidentally measuring the preferred C decoder.
    let canonical = serialize(&Object::Blob(Blob {
        data: vec![b'A'; 4096],
    }))
    .unwrap();
    let mut writer = PackWriter::new();
    writer.push_raw(hash(&canonical), &canonical).unwrap();
    let writer_probe = writer.finish().unwrap();
    assert_eq!(
        &writer_probe[4..8],
        &VERSION.to_le_bytes(),
        "run in an isolated dependency graph without mkit-core/pack-zstd"
    );
    let (pack, retained_canonical_bytes) = fixture();
    let pack = Arc::new(pack);
    let id = hash(pack.as_slice());
    let clock = Arc::new(ManualClock::new(i64::try_from(NOW).unwrap()));
    let store = Arc::new(MemoryKv::with_clock(clock.clone()));
    let shards: Arc<dyn ShardMap> = Arc::new(SinglePartition);
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("zstd-slice-heap").unwrap(),
    };
    let partition = shards.ref_shard(&repo, "refs/heads/main");
    let ticket = codec::TicketV1 {
        authority_generation: None,
        repo: repo.name.clone(),
        ref_name: "refs/heads/main".into(),
        signer: [3; 32],
        pack_id: id,
        bytes: u64::try_from(pack.len()).unwrap(),
        part_size: 8 << 20,
        expires_at_ms: NOW + 300_000,
        created_at_ms: NOW,
        reservation_id: "s:zstd-slice-heap".into(),
        upload_session: None,
    };
    let ticket_id = tickets::ticket_id(&ticket.reservation_id);
    assert_eq!(
        block_on(store.apply(
            &partition,
            Batch::new().put(keys::ticket(&ticket_id), codec::encode_ticket(&ticket)),
        ))
        .unwrap(),
        BatchOutcome::Committed
    );
    block_on(scheduled::create_job(
        store.as_ref(),
        &partition,
        &repo,
        &ticket,
        ticket_id,
        clock.as_ref(),
        None,
    ))
    .unwrap();
    let reads = Arc::new(AtomicUsize::new(0));
    let limits = SliceLimits::default();
    assert_eq!(limits.window_bytes, 16 << 20);
    assert_eq!(limits.resident_bytes, 48 << 20);
    assert_eq!(limits.max_subrequests, 256);
    let registry = TimerRegistry::new().register(VerifyTimer {
        remote: store.clone(),
        blobs: MemoryBlobStore::default(),
        windows: AcquiredWindows {
            pack: pack.clone(),
            id,
            reads: reads.clone(),
        },
        shards,
        cfg: IndexedConfig::scheduled(1 << 30),
        limits,
        lease: LeaseParams::default(),
        clock: clock.clone(),
        metrics: Arc::new(NoopMetrics),
        extension: FailClosedExtraction,
    });

    // The source pack, ticket, job, registry and fixture inputs already exist.
    // Acquiring/feeding the window, filling the production LRU and decoding
    // the corrupt frame all happen inside this one measured production tick.
    let baseline = LIVE.load(Ordering::SeqCst);
    PEAK.store(baseline, Ordering::SeqCst);
    let result = block_on(run_due(
        store.as_ref(),
        &partition,
        &registry,
        clock.as_ref(),
        NOW,
        &TickBudget::default(),
    ));
    let peak = PEAK.load(Ordering::SeqCst).saturating_sub(baseline);
    let report = result.unwrap();
    let (job, _) = block_on(read_job(store.as_ref(), &partition, &repo.name, &id)).unwrap();
    let (job, _) = job.unwrap();
    let verification = block_on(state::read(store.as_ref(), &partition, &repo.name, &id))
        .unwrap()
        .unwrap()
        .0;
    println!(
        "scheduled legal-RLE history: peak_requested_live_bytes={peak}, allowance_bytes={}, acquired_window_bytes={}, retained_prefix_canonical_bytes={retained_canonical_bytes}, entries={}, reads={}, report={report:?}, verification={verification:?}",
        limits.resident_bytes,
        limits.window_bytes,
        job.entries,
        reads.load(Ordering::SeqCst),
    );
    assert_eq!(report.fired, 1, "the real VerifyTimer slice must commit");
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_eq!(usize::try_from(job.entries).unwrap(), PREFIX_OBJECTS);
    assert_eq!(
        job.phase,
        Phase::Watch,
        "the frame must reject in this slice"
    );
    assert!(matches!(
        verification,
        state::VerificationV1::Rejected { .. }
    ));
    assert!(
        u64::try_from(peak).unwrap() <= limits.resident_bytes,
        "actual scheduled slice requested {peak} live bytes above its seeded baseline; unchanged allowance is {} bytes",
        limits.resident_bytes
    );
}
