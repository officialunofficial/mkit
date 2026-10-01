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
    replacement: Option<(u64, Arc<Vec<u8>>)>,
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
            let original = self.pack.get(start..end).ok_or(WindowError::Unavailable)?;
            let range = self
                .replacement
                .as_ref()
                .filter(|(at, bytes)| offset == *at && bytes.len() == length)
                .map_or(original, |(_, bytes)| bytes.as_slice());
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
#[ignore = "run explicitly in an isolated pure-Rust decoder graph; all-features enables C"]
#[allow(clippy::too_many_lines)] // One isolated allocator run compares all admission/overlap cases.
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
    let (pack, retained) = fixture();
    measure(pack, retained, SliceLimits::default(), PREFIX_OBJECTS, true);

    // Preserve the original custom 64 KiB geometry's near-five-MiB admission.
    let limits = SliceLimits {
        window_bytes: 64 << 10,
        ..SliceLimits::default()
    };
    let admitted = (limits.resident_bytes - 2 * limits.window_bytes - (8 << 20)) / 8;
    let canonical = serialize(&Object::Blob(Blob {
        data: vec![7; usize::try_from(admitted).unwrap() - 128],
    }))
    .unwrap();
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(hash(&canonical), &canonical).unwrap();
    measure(writer.finish().unwrap(), canonical.len(), limits, 1, false);

    // Valid compressed wire bytes can exceed the decoded claim and smaller
    // proposed windows. Empty RFC blocks preserve the canonical output.
    let canonical = serialize(&Object::Blob(Blob {
        data: vec![9; 4096],
    }))
    .unwrap();
    let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0x68];
    frame.resize(frame.len() + 5 * MIB / 3 * 3, 0);
    let header = (u32::try_from(canonical.len()).unwrap() << 3) | 1;
    frame.extend_from_slice(&header.to_le_bytes()[..3]);
    frame.extend_from_slice(&canonical);
    let mut pack = MAGIC.to_vec();
    pack.extend_from_slice(&VERSION_V2.to_le_bytes());
    pack.extend_from_slice(&1_u32.to_le_bytes());
    pack.push(3);
    pack.extend_from_slice(&u32::try_from(frame.len() + 4).unwrap().to_le_bytes());
    pack.extend_from_slice(&u32::try_from(canonical.len()).unwrap().to_le_bytes());
    pack.extend_from_slice(&frame);
    let trailer = hash(&pack);
    pack.extend_from_slice(&trailer);
    measure(pack, canonical.len(), SliceLimits::default(), 1, false);

    // A valid wide-wire base is later corrupted during its separate ranged
    // reacquisition. The outer yielded delta and LRU remain live; the idle
    // WindowReader must release its window before this nested decoder runs.
    let mut valid = vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0x68];
    valid.resize(valid.len() + 15 * MIB / 3 * 3, 0);
    valid.extend_from_slice(&header.to_le_bytes()[..3]);
    valid.extend_from_slice(&canonical);
    let mut source = vec![3];
    source.extend_from_slice(&u32::try_from(valid.len() + 4).unwrap().to_le_bytes());
    source.extend_from_slice(&u32::try_from(canonical.len()).unwrap().to_le_bytes());
    source.extend_from_slice(&valid);
    let mut pack = MAGIC.to_vec();
    pack.extend_from_slice(&VERSION_V2.to_le_bytes());
    pack.extend_from_slice(&20_u32.to_le_bytes());
    pack.extend_from_slice(&source);
    for tag in 0..8 {
        raw_entry(&mut pack, tag);
    }
    let target = serialize(&Object::Blob(Blob {
        data: vec![8; 4096],
    }))
    .unwrap();
    let delta = mkit_core::delta::encode(&canonical, &target).unwrap();
    pack.push(2);
    pack.extend_from_slice(&u32::try_from(32 + delta.len()).unwrap().to_le_bytes());
    pack.extend_from_slice(&hash(&canonical));
    pack.extend_from_slice(&delta);
    for tag in 16..26 {
        raw_entry(&mut pack, tag);
    }
    let trailer = hash(&pack);
    pack.extend_from_slice(&trailer);
    let mut changed = vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0x68];
    for _ in 0..70 {
        let block = ((128_u32 << 10) << 3) | (1 << 1);
        changed.extend_from_slice(&block.to_le_bytes()[..3]);
        changed.push(b'A');
    }
    let remaining = valid.len() - changed.len();
    changed.resize(changed.len() + remaining - remaining % 3, 0);
    changed[valid.len() - remaining % 3 - 3] = 1;
    changed.resize(valid.len(), 0);
    // Preserve the exact ranged frame length and claim: only source payload
    // bytes change, so the verification path must reach bounded decompression.
    source[9..].copy_from_slice(&changed);
    measure_inner(
        pack,
        canonical.len(),
        SliceLimits::default(),
        0,
        false,
        Some((12, source)),
    );
    custom_nested_case();
}

fn measure(
    pack: Vec<u8>,
    retained_canonical_bytes: usize,
    limits: SliceLimits,
    expected_entries: usize,
    rejects: bool,
) {
    measure_inner(
        pack,
        retained_canonical_bytes,
        limits,
        expected_entries,
        rejects,
        None,
    );
}

#[allow(clippy::too_many_lines)] // The metered lifetime includes one complete production timer harness.
fn measure_inner(
    pack: Vec<u8>,
    retained_canonical_bytes: usize,
    limits: SliceLimits,
    expected_entries: usize,
    rejects: bool,
    replacement: Option<(u64, Vec<u8>)>,
) {
    let nested = replacement.is_some();
    let replacement = replacement.map(|(at, bytes)| (at, Arc::new(bytes)));
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
    assert!((64 << 10..=16 << 20).contains(&limits.window_bytes));
    assert_eq!(limits.resident_bytes, 48 << 20);
    assert_eq!(limits.max_subrequests, 256);
    let registry = TimerRegistry::new().register(VerifyTimer {
        remote: store.clone(),
        blobs: MemoryBlobStore::default(),
        windows: AcquiredWindows {
            pack: pack.clone(),
            id,
            reads: reads.clone(),
            replacement,
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
    let mut result = block_on(run_due(
        store.as_ref(),
        &partition,
        &registry,
        clock.as_ref(),
        NOW,
        &TickBudget::default(),
    ));
    if nested {
        for _ in 0..10 {
            let current = block_on(read_job(store.as_ref(), &partition, &repo.name, &id))
                .unwrap()
                .0
                .unwrap()
                .0;
            if current.restarts > 0 {
                break;
            }
            let next = result.as_ref().unwrap().next_wake_ms.unwrap();
            clock.set(i64::try_from(next).unwrap());
            result = block_on(run_due(
                store.as_ref(),
                &partition,
                &registry,
                clock.as_ref(),
                next,
                &TickBudget::default(),
            ));
        }
    }
    let peak = PEAK.load(Ordering::SeqCst).saturating_sub(baseline);
    let report = result.unwrap();
    let (job, _) = block_on(read_job(store.as_ref(), &partition, &repo.name, &id)).unwrap();
    let (job, _) = job.unwrap();
    let verification = block_on(state::read(store.as_ref(), &partition, &repo.name, &id))
        .unwrap()
        .unwrap()
        .0;
    println!(
        "scheduled slice: peak_requested_live_bytes={peak}, allowance_bytes={}, acquired_window_bytes={}, retained_prefix_canonical_bytes={retained_canonical_bytes}, entries={}, reads={}, report={report:?}, verification={verification:?}",
        limits.resident_bytes,
        limits.window_bytes,
        job.entries,
        reads.load(Ordering::SeqCst),
    );
    assert_eq!(report.fired, 1, "the real VerifyTimer slice must commit");
    assert!(reads.load(Ordering::SeqCst) <= 256);
    if nested {
        assert_eq!(
            job.restarts, 1,
            "corrupt reread keeps the existing restart classification: {job:?}"
        );
        assert!(job.outcome.is_none());
    } else if rejects {
        assert_eq!(usize::try_from(job.entries).unwrap(), expected_entries);
        assert_eq!(
            job.phase,
            Phase::Watch,
            "the frame must reject in this slice"
        );
        assert!(matches!(
            verification,
            state::VerificationV1::Rejected { .. }
        ));
    } else {
        assert_eq!(usize::try_from(job.entries).unwrap(), expected_entries);
        assert!(
            job.outcome.is_none(),
            "valid frame must preserve admission: {job:?}"
        );
        assert!(!matches!(
            verification,
            state::VerificationV1::Rejected { .. }
        ));
    }
    assert!(
        u64::try_from(peak).unwrap() <= limits.resident_bytes,
        "actual scheduled slice requested {peak} live bytes above its seeded baseline; unchanged allowance is {} bytes",
        limits.resident_bytes
    );
}

fn custom_nested_case() {
    let limits = SliceLimits {
        window_bytes: 64 << 10,
        ..SliceLimits::default()
    };
    let cap =
        usize::try_from((limits.resident_bytes - 2 * limits.window_bytes - (8 << 20)) / 8).unwrap();
    let base = serialize(&Object::Blob(Blob {
        data: vec![7; cap - 256],
    }))
    .unwrap();
    let small = serialize(&Object::Blob(Blob {
        data: vec![9; 4096],
    }))
    .unwrap();
    let small_delta = mkit_core::delta::encode(&base, &small).unwrap();
    let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0x68];
    let padding = cap - 2 * small_delta.len() - 256;
    frame.resize(frame.len() + padding / 3 * 3, 0);
    let header = (u32::try_from(small_delta.len()).unwrap() << 3) | 1;
    frame.extend_from_slice(&header.to_le_bytes()[..3]);
    frame.extend_from_slice(&small_delta);
    let mut source = vec![4];
    source.extend_from_slice(&u32::try_from(36 + frame.len()).unwrap().to_le_bytes());
    source.extend_from_slice(&hash(&base));
    source.extend_from_slice(&u32::try_from(small_delta.len()).unwrap().to_le_bytes());
    source.extend_from_slice(&frame);
    let mut pack = MAGIC.to_vec();
    pack.extend_from_slice(&VERSION_V2.to_le_bytes());
    pack.extend_from_slice(&20_u32.to_le_bytes());
    pack.push(0);
    pack.extend_from_slice(&u32::try_from(base.len()).unwrap().to_le_bytes());
    pack.extend_from_slice(&base);
    let source_offset = u64::try_from(pack.len()).unwrap();
    pack.extend_from_slice(&source);
    // Tiny preceding entries retain real frame/selection metadata in the
    // same slice as the large yielded delta and nested corrupted source.
    for tag in 0..16 {
        let canonical = serialize(&Object::Blob(Blob { data: vec![tag; 8] })).unwrap();
        pack.push(0);
        pack.extend_from_slice(&u32::try_from(canonical.len()).unwrap().to_le_bytes());
        pack.extend_from_slice(&canonical);
    }
    let target = serialize(&Object::Blob(Blob {
        data: vec![8; cap - (64 << 10)],
    }))
    .unwrap();
    let delta = mkit_core::delta::encode(&small, &target).unwrap();
    pack.push(2);
    pack.extend_from_slice(&u32::try_from(32 + delta.len()).unwrap().to_le_bytes());
    pack.extend_from_slice(&hash(&small));
    pack.extend_from_slice(&delta);
    pack.push(0);
    pack.extend_from_slice(&u32::try_from(small.len()).unwrap().to_le_bytes());
    pack.extend_from_slice(&small);
    let trailer = hash(&pack);
    pack.extend_from_slice(&trailer);
    let mut changed = vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0x68];
    for _ in 0..70 {
        let block = ((128_u32 << 10) << 3) | (1 << 1);
        changed.extend_from_slice(&block.to_le_bytes()[..3]);
        changed.push(b'A');
    }
    changed.resize(frame.len(), 0);
    source[37..41].copy_from_slice(&u32::try_from(cap - 128).unwrap().to_le_bytes());
    source[41..].copy_from_slice(&changed);
    measure_inner(
        pack,
        base.len(),
        limits,
        0,
        false,
        Some((source_offset, source)),
    );
}
