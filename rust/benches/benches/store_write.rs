//! Object-store durability schedules — wallclock for writing N objects
//! under each [`SyncPolicy`], plus a chunked-file ingest through a
//! batch. This is the perf regression net for the batched-durability
//! work: `batch` must stay roughly flat in flush cost as N grows while
//! `per_object` grows linearly.
//!
//! Numbers are wallclock ms; smaller is better. Real flushes hit the
//! disk, so absolute values are machine/filesystem dependent — the
//! interesting signal is the per-object/batch ratio on one machine.

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one};
use mkit_core::store::{ObjectStore, SyncPolicy};
use mkit_core::worktree::store_file_object;

const COUNTS: &[(usize, &str)] = &[(10, "10 x 10 KiB"), (100, "100 x 10 KiB")];
// (No "none" series: SyncPolicy::None was removed — ephemeral snapshots
// use store::EphemeralSink and never hit the disk store.)

fn payloads(n: usize) -> Vec<Vec<u8>> {
    // Distinct, incompressible-ish payloads so every write stages a
    // fresh object (no dedup short-circuit).
    (0..n)
        .map(|i| {
            let mut buf = vec![0u8; 10 * 1024];
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

fn write_all(store: &ObjectStore, policy: SyncPolicy, payloads: &[Vec<u8>]) {
    let batch = store.batch_with_policy(policy);
    for p in payloads {
        batch.write(p).unwrap();
    }
    batch.commit().unwrap();
}

/// Wallclock milliseconds for a single un-warmed invocation of `f`.
/// The store-write durability series wants the cost of one real
/// flush-to-disk pass (warmup would let the page cache hide it), so we
/// take exactly one timed iteration and convert seconds → ms.
fn time_ms(f: impl FnMut()) -> f64 {
    time_one(0, 1, f) * 1000.0
}

fn bench_store_write(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &(n, axis) in COUNTS {
        let data = payloads(n);
        for (policy, label) in [
            (SyncPolicy::PerObject, "per_object"),
            (SyncPolicy::Batch, "batch"),
        ] {
            // Fresh repo per measurement; criterion's iter creates a
            // new tempdir each pass so dedup never kicks in.
            c.bench_function(&format!("store_write/{axis}/{label}"), |b| {
                b.iter_with_setup(
                    || {
                        let dir = tempfile::tempdir().unwrap();
                        let store = ObjectStore::init(dir.path()).unwrap();
                        (dir, store)
                    },
                    |(_dir, store)| write_all(&store, policy, &data),
                );
            });
            let dir = tempfile::tempdir().unwrap();
            let store = ObjectStore::init(dir.path()).unwrap();
            let ms = time_ms(|| write_all(&store, policy, &data));
            samples.push(Sample {
                category: "store_write".into(),
                axis: axis.into(),
                library: label.into(),
                value: ms,
                unit: Unit::Millis,
            });
        }
    }

    // Chunked ingest (8 MiB ≫ CHUNK_THRESHOLD) through the default
    // batch — covers the zero-copy put_parts path end to end.
    {
        let mut blob = vec![0u8; 8 * 1024 * 1024];
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        for b in &mut blob {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x & 0xFF) as u8;
        }
        c.bench_function("store_write/8 MiB chunked/batch", |b| {
            b.iter_with_setup(
                || {
                    let dir = tempfile::tempdir().unwrap();
                    let store = ObjectStore::init(dir.path()).unwrap();
                    (dir, store)
                },
                |(_dir, store)| {
                    let batch = store.batch();
                    store_file_object(&batch, &blob).unwrap();
                    batch.commit().unwrap();
                },
            );
        });
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(dir.path()).unwrap();
        let ms = time_ms(|| {
            let batch = store.batch();
            store_file_object(&batch, &blob).unwrap();
            batch.commit().unwrap();
        });
        samples.push(Sample {
            category: "store_write".into(),
            axis: "8 MiB chunked".into(),
            library: "batch".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }

    mkit_benches::write_summary("store_write", &samples);
}

criterion_group!(benches, bench_store_write);
criterion_main!(benches);
