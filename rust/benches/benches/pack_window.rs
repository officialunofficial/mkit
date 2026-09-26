//! Buffered and windowed pack-reader throughput on the same 256 MiB
//! synthetic raw pack. Construction is outside the timed region. Both
//! readers verify the trailer and drop each entry as soon as it is consumed;
//! neither resolves deltas or writes to a store. Windowed measurements include
//! the in-memory source's window allocation and copy, as a fetched range would.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, Xorshift, time_one};
use mkit_core::hash;
use mkit_core::pack::window::read_all;
use mkit_core::pack::{DecodeLimits, PackEntries, PackEntry, PackWriter};

const PACK_SIZE: usize = 256 << 20;
const ENTRY_SIZE: usize = 1 << 20;
const ENTRY_COUNT: usize = 256;
const WINDOWS: &[(u64, &str)] = &[(1 << 20, "1 MiB"), (16 << 20, "16 MiB")];

fn build_pack() -> Vec<u8> {
    let payload = Xorshift::new(0x4_8a).bytes(ENTRY_SIZE);
    let digest = hash::hash(&payload);
    let mut writer = PackWriter::new_raw_only();
    for _ in 0..ENTRY_COUNT - 1 {
        writer.push_raw(digest, &payload).expect("push raw entry");
    }
    // Header (12), trailer (32), and entry frames (5 each) are included
    // in the 256 MiB input size, rather than adding framing to 256 MiB.
    let last_len = PACK_SIZE - 44 - 5 * ENTRY_COUNT - ENTRY_SIZE * (ENTRY_COUNT - 1);
    let last = &payload[..last_len];
    writer
        .push_raw(hash::hash(last), last)
        .expect("push final entry");
    let pack = writer.finish().expect("finish pack");
    assert_eq!(pack.len(), PACK_SIZE);
    pack
}

fn consume(entry: PackEntry<'_>) -> usize {
    match black_box(entry) {
        PackEntry::Raw { bytes } => bytes.len(),
        PackEntry::Delta { .. } => panic!("synthetic pack must contain only raw entries"),
    }
}

fn buffered(pack: &[u8]) -> usize {
    PackEntries::new(black_box(pack))
        .expect("buffered reader")
        .map(|entry| consume(entry.expect("buffered entry")))
        .sum()
}

fn windowed(pack: &[u8], window_size: u64) -> usize {
    let mut source = black_box(pack);
    let mut total = 0;
    read_all(
        &mut source,
        u64::try_from(pack.len()).expect("pack length fits u64"),
        window_size,
        DecodeLimits::default(),
        None,
        |entry| {
            total += consume(entry);
            Ok(())
        },
    )
    .expect("windowed reader");
    total
}

fn bench_pack_window(c: &mut Criterion) {
    let pack = build_pack();
    let payload_bytes = PACK_SIZE - 44 - 5 * ENTRY_COUNT;
    assert_eq!(buffered(&pack), payload_bytes);
    let mut samples = Vec::new();
    let mut group = c.benchmark_group("pack_window");
    group.throughput(Throughput::Bytes(PACK_SIZE as u64));
    group.bench_function("PackEntries", |b| b.iter(|| black_box(buffered(&pack))));
    let seconds = time_one(1, 3, || {
        black_box(buffered(&pack));
    });
    samples.push(Sample {
        category: "pack_window".into(),
        axis: "256 MiB".into(),
        library: "PackEntries".into(),
        value: 256.0 / seconds,
        unit: Unit::MibPerSec,
    });
    for &(window_size, label) in WINDOWS {
        assert_eq!(windowed(&pack, window_size), payload_bytes);
        group.bench_with_input(
            BenchmarkId::new("WindowReader", label),
            &window_size,
            |b, &size| b.iter(|| black_box(windowed(&pack, size))),
        );
        let seconds = time_one(1, 3, || {
            black_box(windowed(&pack, window_size));
        });
        samples.push(Sample {
            category: "pack_window".into(),
            axis: "256 MiB".into(),
            library: format!("WindowReader ({label})"),
            value: 256.0 / seconds,
            unit: Unit::MibPerSec,
        });
    }
    group.finish();
    mkit_benches::write_summary("pack_window", &samples);
}

criterion_group!(name = benches; config = Criterion::default().sample_size(10); targets = bench_pack_window);
criterion_main!(benches);
