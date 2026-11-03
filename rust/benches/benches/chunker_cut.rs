//! `FastCdc::cut` scan throughput (pure rolling-hash cost, no I/O).
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use mkit_core::chunker::{ChunkIterator, FastCdc};

fn payload(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    for b in &mut buf {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x & 0xFF) as u8;
    }
    buf
}

fn bench(c: &mut Criterion) {
    let data = payload(64 << 20);
    let mut g = c.benchmark_group("chunker_cut");
    g.throughput(Throughput::Bytes(data.len() as u64));
    g.bench_function("64 MiB", |b| {
        b.iter(|| {
            ChunkIterator::new(FastCdc::v1(), std::hint::black_box(&data))
                .map(|c| c.length)
                .sum::<usize>()
        });
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
