//! Checkpoint and verification costs on a deterministic 150 MiB random pack.
//! Compare with `just cargo-cached --config 'profile.dev.package.blake3.opt-level=3'
//! bench -p mkit-benches --bench pack_prefix --profile dev`. Set
//! `MKIT_BENCH_PREFIX_CPU=verify` to measure one verification run with an
//! external CPU timer, or `setup` to measure fixture setup alone.
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use mkit_benches::Xorshift;
use mkit_core::hash;
use mkit_core::pack::window::{Step, WindowReader};
use mkit_core::pack::{DecodeLimits, PackWriter};
use std::hint::black_box;

// Deterministic random, incompressible fixture; every frame has distinct bytes.
fn prefix_pack() -> Vec<u8> {
    let mut random = Xorshift::new(0x50_52_45_46);
    let mut writer = PackWriter::new_raw_only();
    let count = 2400;
    for index in 0..count {
        let len = if index + 1 == count {
            (64 << 10) - 44 - 5 * count
        } else {
            64 << 10
        };
        let payload = random.bytes(len);
        writer.push_raw(hash::hash(&payload), &payload).unwrap();
    }
    let pack = writer.finish().unwrap();
    assert_eq!(pack.len(), 150 << 20);
    pack
}

fn prefix_reader(pack: &[u8], stop: usize) -> WindowReader {
    let mut reader = WindowReader::new(
        pack.len() as u64,
        16 << 20,
        DecodeLimits::default(),
        Some(*blake3::hash(pack).as_bytes()),
    )
    .unwrap();
    let mut entries = 0;
    loop {
        match reader.step().unwrap() {
            Step::NeedWindow(r) => reader
                .feed(
                    r.offset,
                    &pack[r.offset as usize..(r.offset + r.len) as usize],
                )
                .unwrap(),
            Step::Entry(_) => {
                black_box(reader.checkpoint().unwrap());
                entries += 1;
                if entries == stop {
                    return reader;
                }
            }
            Step::Done(_) => return reader,
            _ => unreachable!("unknown reader step"),
        }
    }
}

fn bench_prefix(c: &mut Criterion) {
    let pack = prefix_pack();
    if let Ok(mode) = std::env::var("MKIT_BENCH_PREFIX_CPU") {
        if mode == "verify" {
            black_box(prefix_reader(&pack, usize::MAX));
        } else {
            assert_eq!(mode, "setup");
        }
        return;
    }
    let mut group = c.benchmark_group("pack_window::verify");
    group.throughput(Throughput::Bytes(pack.len() as u64));
    group.bench_function("bytes=157286400/checkpoint=entry", |b| {
        b.iter(|| black_box(prefix_reader(&pack, usize::MAX)));
    });
    group.finish();
    let mut group = c.benchmark_group("pack_window::checkpoint");
    for entries in [1, 64, 240] {
        let reader = prefix_reader(&pack, entries);
        group.bench_function(
            format!("consumed_bytes={}", 12 + entries * ((64 << 10) + 5)),
            |b| {
                b.iter(|| black_box(reader.checkpoint().unwrap()));
            },
        );
    }
    group.finish();
    let mut group = c.benchmark_group("pack_window::resume");
    for entries in [1, 64, 240] {
        let cursor = prefix_reader(&pack, entries).checkpoint().unwrap();
        group.bench_function(
            format!("consumed_bytes={}", 12 + entries * ((64 << 10) + 5)),
            |b| {
                b.iter(|| {
                    let mut reader =
                        WindowReader::resume(&cursor, DecodeLimits::default()).unwrap();
                    let Step::NeedWindow(r) = reader.step().unwrap() else {
                        panic!("expected range")
                    };
                    reader
                        .feed(
                            r.offset,
                            &pack[r.offset as usize..(r.offset + r.len) as usize],
                        )
                        .unwrap();
                    black_box(reader.checkpoint().unwrap());
                })
            },
        );
    }
    group.finish();
}

criterion_group!(name = benches; config = Criterion::default().sample_size(10); targets = bench_prefix);
criterion_main!(benches);
