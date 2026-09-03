//! `ObjectStore::bulk_writer` ingest cost — the deferred-fsync bulk
//! write session `mkit-cli`'s `git-import` command uses to land every
//! object of an imported git history (`BulkSink` in
//! `commands/git_import.rs`).
//!
//! Regression guard for the shard-dir `create_dir_all` memoization:
//! `BulkWriter::write` tracks every shard directory it has already
//! created (or observed) in `self.dirs`, so a session ingesting many
//! objects should pay `create_dir_all`'s mkdir+stat cost roughly once
//! per shard (at most 256 exist) rather than once per object. Numbers
//! are wallclock ms; smaller is better, and real fsyncs hit the disk so
//! absolute values are machine/filesystem dependent — the interesting
//! signal is how the per-object cost scales with object count.

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one};
use mkit_core::layout::RepoLayout;
use mkit_core::store::ObjectStore;

const COUNTS: &[usize] = &[100, 1_000, 5_000];

/// Distinct, incompressible-ish small payloads so every write stages a
/// fresh object (no dedup short-circuit) and hashes spread across the
/// full 256-shard space, the same way a real git-import's object ids
/// do.
fn payloads(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| {
            let mut buf = vec![0u8; 256];
            let mut x = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            for b in &mut buf {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = (x & 0xFF) as u8;
            }
            buf
        })
        .collect()
}

fn write_all(store: &ObjectStore, payloads: &[Vec<u8>]) {
    let mut bw = store.bulk_writer();
    for p in payloads {
        bw.write(p).unwrap();
    }
    bw.commit().unwrap();
}

/// Wallclock milliseconds for a single un-warmed invocation of `f` —
/// same rationale as `store_write.rs`: a warmup would let the page
/// cache hide the real flush-to-disk cost this bench cares about.
fn time_ms(f: impl FnMut()) -> f64 {
    time_one(0, 1, f) * 1000.0
}

fn bench_bulk_writer(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &n in COUNTS {
        let data = payloads(n);
        let axis = format!("{n} objects");
        c.bench_function(&format!("bulk_writer/{axis}"), |b| {
            b.iter_with_setup(
                || {
                    let dir = tempfile::tempdir().unwrap();
                    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
                    (dir, store)
                },
                |(_dir, store)| write_all(&store, &data),
            );
        });
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        let ms = time_ms(|| write_all(&store, &data));
        samples.push(Sample {
            category: "bulk_writer".into(),
            axis,
            library: "bulk_writer".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }

    mkit_benches::write_summary("bulk_writer", &samples);
}

criterion_group!(benches, bench_bulk_writer);
criterion_main!(benches);
