//! Sharded vs monolithic 100 MiB pack transfer under simulated
//! network jitter.
//!
//! The criterion suite measures three numbers per scenario, end-to-end
//! including the jitter sleep:
//!
//!   * `monolithic` — one 100 MiB blob arrives after a single jitter
//!     sleep.
//!   * `sharded-best-case` — 20 shards arrive in parallel after an
//!     individual jitter sleep each; the decoder takes the first 16.
//!   * `sharded-worst-case` — 20 shards arrive sequentially after an
//!     individual jitter sleep each; the decoder takes the first 16.
//!
//! All "network" is in-process; the bench measures the encoder /
//! decoder critical path plus the jitter model. The jitter PRNG is
//! seeded deterministically so reruns produce comparable numbers.
//!
//! Not gated on CI. This file exists so a regression in the
//! pack-shard encode / decode path shows up as a measurable
//! slowdown, and so future tuning of `(N, K)` or `Strategy` has a
//! benchmark to point at.

#![allow(clippy::missing_docs_in_private_items)]

use std::num::NonZeroUsize;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_core::pack_shard::{
    ParallelStrategy, SequentialStrategy, Shard, ShardSet, decode_pack_from_shards,
    decode_pack_from_shards_with_strategy, default_config, encode_pack_to_shards,
    encode_pack_to_shards_with_strategy,
};

const PACK_SIZE: usize = 100 * 1024 * 1024;

/// Deterministic 100 MiB pack-like input. Generated once at the start
/// of the bench so the encode/decode cost dominates the measurement,
/// not synthesis.
fn synthetic_pack(size: usize) -> Vec<u8> {
    let mut x: u64 = 0xC0DE_C0FF_EE15_0A75;
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(size);
    out
}

/// Cheap deterministic xorshift PRNG, used to simulate per-shard
/// network jitter without pulling in `rand`.
struct Xorshift(u64);

impl Xorshift {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// A jitter sleep in the `[low, high]` microsecond range.
    fn jitter(&mut self, low_us: u64, high_us: u64) -> Duration {
        let span = high_us.saturating_sub(low_us).max(1);
        Duration::from_micros(low_us + (self.next_u64() % span))
    }
}

fn bench_monolithic(c: &mut Criterion, pack: &[u8]) {
    let mut rng = Xorshift(0xA110_C8ED);
    c.bench_function("pack-shards/100MiB/monolithic", |b| {
        b.iter(|| {
            // Simulate one network round-trip carrying the whole pack.
            // 10–50 ms is the typical "modem hop + buffer" sleep we
            // use across mkit's transport benches.
            thread::sleep(rng.jitter(10_000, 50_000));
            // Touch the bytes so the compiler can't optimise out the
            // load.
            let mut acc: u64 = 0;
            for chunk in pack.chunks(64) {
                acc = acc.wrapping_add(chunk[0] as u64);
            }
            std::hint::black_box(acc);
        });
    });
}

fn bench_sharded_best_case(
    c: &mut Criterion,
    shards: &[Shard],
    manifest: &mkit_core::pack_shard::ShardSet,
) {
    c.bench_function("pack-shards/100MiB/sharded-parallel", |b| {
        b.iter(|| {
            // Spawn one std thread per shard; each sleeps an
            // independent jitter sample, then sends. The receiver
            // takes the first N and runs the decoder.
            let (tx, rx) = mpsc::channel::<Shard>();
            let n_total = shards.len();
            for shard in shards {
                let tx = tx.clone();
                let s = shard.clone();
                let mut rng = Xorshift(0xC0DE ^ (shard.index as u64));
                thread::spawn(move || {
                    thread::sleep(rng.jitter(10_000, 50_000));
                    let _ = tx.send(s);
                });
            }
            drop(tx);
            let minimum = manifest.config.minimum_shards.get() as usize;
            let mut got: Vec<Shard> = Vec::with_capacity(minimum);
            for s in &rx {
                got.push(s);
                if got.len() >= minimum {
                    break;
                }
            }
            // Drain the rest so worker threads can exit cleanly
            // (otherwise their `tx.send` panics on a closed channel).
            for _ in &rx {}
            let _ = n_total;
            let pack = decode_pack_from_shards(&got, manifest).unwrap();
            std::hint::black_box(pack);
        });
    });
}

fn bench_sharded_worst_case(
    c: &mut Criterion,
    shards: &[Shard],
    manifest: &mkit_core::pack_shard::ShardSet,
) {
    c.bench_function("pack-shards/100MiB/sharded-sequential", |b| {
        b.iter(|| {
            let mut rng = Xorshift(0x000B_00B5_C0DE);
            let minimum = manifest.config.minimum_shards.get() as usize;
            let mut got: Vec<Shard> = Vec::with_capacity(minimum);
            for shard in shards.iter().take(minimum) {
                thread::sleep(rng.jitter(10_000, 50_000));
                got.push(shard.clone());
            }
            let pack = decode_pack_from_shards(&got, manifest).unwrap();
            std::hint::black_box(pack);
        });
    });
}

/// Builds a `Rayon` strategy over all available cores. Falls back to
/// a single-thread pool (still technically the parallel strategy
/// type, just not actually parallel) if the host can't report
/// available parallelism, so the bench never panics on a constrained
/// CI runner.
fn full_parallelism_strategy() -> ParallelStrategy {
    let threads = thread::available_parallelism()
        .map(NonZeroUsize::get)
        .unwrap_or(1)
        .max(1);
    ParallelStrategy::new(NonZeroUsize::new(threads).expect("threads >= 1"))
        .expect("build rayon pool")
}

/// Issue #653 — isolates the `commonware-parallel` execution strategy
/// as the *only* variable (no network jitter, no thread-spawn-per-shard
/// harness) so a regression in the `Sequential` vs. `Rayon` win shows
/// up directly, independent of the transfer-simulation benches above.
fn bench_encode_strategy(c: &mut Criterion, pack: &[u8]) {
    let config = default_config();
    let parallel = full_parallelism_strategy();

    c.bench_function("pack-shards/100MiB/encode-strategy-sequential", |b| {
        b.iter(|| {
            let encoded =
                encode_pack_to_shards_with_strategy(pack, config, &SequentialStrategy).unwrap();
            std::hint::black_box(encoded);
        });
    });

    c.bench_function("pack-shards/100MiB/encode-strategy-parallel", |b| {
        b.iter(|| {
            let encoded = encode_pack_to_shards_with_strategy(pack, config, &parallel).unwrap();
            std::hint::black_box(encoded);
        });
    });
}

/// Decode-side counterpart of [`bench_encode_strategy`]: reconstructs
/// the same 100 MiB pack from the first 16 shards under each strategy.
fn bench_decode_strategy(c: &mut Criterion, shards: &[Shard], manifest: &ShardSet) {
    let subset: Vec<Shard> = shards.iter().take(16).cloned().collect();
    let parallel = full_parallelism_strategy();

    c.bench_function("pack-shards/100MiB/decode-strategy-sequential", |b| {
        b.iter(|| {
            let pack =
                decode_pack_from_shards_with_strategy(&subset, manifest, &SequentialStrategy)
                    .unwrap();
            std::hint::black_box(pack);
        });
    });

    c.bench_function("pack-shards/100MiB/decode-strategy-parallel", |b| {
        b.iter(|| {
            let pack = decode_pack_from_shards_with_strategy(&subset, manifest, &parallel).unwrap();
            std::hint::black_box(pack);
        });
    });
}

fn bench_pack_shard_transfer(c: &mut Criterion) {
    let pack = synthetic_pack(PACK_SIZE);
    let (shards, manifest) =
        encode_pack_to_shards(&pack, default_config()).expect("encode 100 MiB pack");

    bench_monolithic(c, &pack);
    bench_sharded_best_case(c, &shards, &manifest);
    bench_sharded_worst_case(c, &shards, &manifest);
    bench_encode_strategy(c, &pack);
    bench_decode_strategy(c, &shards, &manifest);
}

criterion_group!(name = pack_shard_transfer; config = Criterion::default().sample_size(10); targets = bench_pack_shard_transfer);
criterion_main!(pack_shard_transfer);
