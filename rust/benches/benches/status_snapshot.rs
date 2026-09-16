//! `status`/`diff`'s ephemeral index-tree snapshot
//! (`worktree::build_tree_from_index_with(.., verify = false)`) at
//! increasing tracked-file counts.
//!
//! Isolates the one step `status`/`diff`/`ensure_restore_safe_with_options`
//! all share: turning the staging index into an in-memory tree without
//! publishing anything durable. Before the batched object-type probe
//! (this suite's reason for existing), that step paid one serialized
//! `open`+`read`(+`close`) per tracked file — a `status` on a 20k-file
//! repo spent ~35-40% of its wall time there, all syscall-bound and
//! trivially independent per entry. Numbers are wallclock ms (total) and
//! derived us/entry; smaller is better, and us/entry should stay flat
//! (not grow) as N increases — a regression there is the serialized
//! probe coming back.

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one};
use mkit_core::index::{EntryStatus, Index, IndexEntry};
use mkit_core::layout::RepoLayout;
use mkit_core::store::ObjectStore;
use mkit_core::worktree::build_tree_from_index_with;

const COUNTS: &[(usize, &str)] = &[
    (1_000, "1k files"),
    (10_000, "10k files"),
    (50_000, "50k files"),
];
/// Files per synthetic directory — matches `add_staging`'s fixture shape.
const FANOUT: usize = 200;

/// Deterministic, distinct per-file content — every entry gets its own
/// object, no dedup short-circuit hides the per-object probe cost.
fn file_bytes(i: usize) -> Vec<u8> {
    format!("mkit status-snapshot bench fixture #{i}\n").into_bytes()
}

/// Populate `store` with `n` distinct blobs and a matching staging
/// index spread across `n / FANOUT` synthetic directories.
fn populate(store: &ObjectStore, n: usize) -> Index {
    let mut idx = Index::default();
    let batch = store.batch();
    for i in 0..n {
        let data = file_bytes(i);
        let hash = mkit_core::worktree::store_file_object(&batch, &data).unwrap();
        idx.upsert_entry(IndexEntry {
            path: format!("d{}/f{i}.txt", i / FANOUT),
            status: EntryStatus::Blob,
            object_hash: hash,
            mtime_ns: 0,
            size: data.len() as u64,
            ino: 0,
            ctime_ns: 0,
        });
    }
    batch.commit().unwrap();
    idx
}

/// Wallclock milliseconds for a single un-warmed snapshot build — a
/// real repo's `status` pays this cold (no benefit from criterion's
/// repeated-sampling warmup), matching `add_staging`'s single-pass
/// convention for expensive real-I/O series.
fn time_snapshot_ms(store: &ObjectStore, idx: &Index) -> f64 {
    time_one(0, 1, || {
        build_tree_from_index_with(store, store, idx, false).unwrap();
    }) * 1000.0
}

fn bench_status_snapshot(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &(n, axis) in COUNTS {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        let idx = populate(&store, n);

        let ms = time_snapshot_ms(&store, &idx);
        let per_entry_us = ms * 1000.0 / n as f64;
        eprintln!("status_snapshot/{axis}: {ms:.1} ms total ({per_entry_us:.3} us/entry)");
        samples.push(Sample {
            category: "status_snapshot".into(),
            axis: axis.into(),
            library: "build_tree_from_index".into(),
            value: ms,
            unit: Unit::Millis,
        });

        // Criterion series for the smaller counts only — 50k is too
        // slow to run under repeated sampling (each sample re-walks
        // the whole index), same call as `add_staging`'s 100k series.
        if n <= 10_000 {
            c.bench_function(&format!("status_snapshot/{axis}"), |b| {
                b.iter(|| build_tree_from_index_with(&store, &store, &idx, false).unwrap());
            });
        }
    }

    mkit_benches::write_summary("status_snapshot", &samples);
}

criterion_group!(benches, bench_status_snapshot);
criterion_main!(benches);
