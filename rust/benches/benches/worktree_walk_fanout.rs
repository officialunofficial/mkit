//! Cold-stat-cache timing for `build_tree_inner`'s worktree walk — the
//! `status`/`diff`/`ensure_restore_safe_with_options` snapshot path
//! (checkout/reset/restore/merge/rebase/cherry-pick/revert/stash/pull/
//! sparse-checkout/worktree-add safety), not to be confused with
//! `status_snapshot.rs`'s index-side `build_tree_from_index_with` probe.
//!
//! Before the fan-out this measures, every cache-miss regular file
//! `build_tree_inner` found during its `read_dir` walk was opened,
//! read, and BLAKE3-hashed inline, one at a time — the last remaining
//! serial per-file hashing loop in this crate (`add_hash_fanout.rs`
//! covers the sibling fan-out `commands::add` already got). A cold
//! stat cache is common, not rare: a fresh clone has no prior index,
//! and `index::from_tree`'s HEAD-seeded fallback always emits zeroed
//! stat fields, so the first `status`/checkout-safety snapshot after a
//! clone or a branch switch re-hashes every touched file this way.
//!
//! Numbers are wallclock ms (total) and derived us/file; smaller is
//! better, and us/file should drop once N crosses the fan-out
//! threshold rather than staying flat regardless of available cores —
//! flat would mean the fan-out isn't firing.

use std::path::Path;

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one};
use mkit_core::index::{EntryStatus, Index, IndexEntry};
use mkit_core::layout::RepoLayout;
use mkit_core::store::{EphemeralSink, ObjectStore};
use mkit_core::worktree;

const COUNTS: &[(usize, &str)] = &[
    (1_000, "1k files"),
    (5_000, "5k files"),
    (20_000, "20k files"),
];

/// A small source-file-sized payload, matching `add_hash_fanout`'s
/// convention — well under `worktree::CHUNK_THRESHOLD` so every file
/// takes the single-BLAKE3-pass path (chunked-file ingest is a
/// separate, already-fanned-out cost; see `chunk_hash_fanout.rs`).
const FILE_SIZE: usize = 2048;

fn file_bytes(i: usize) -> Vec<u8> {
    let mut v = format!("mkit worktree-walk bench fixture #{i}\n").into_bytes();
    v.resize(FILE_SIZE, b'x');
    v
}

/// Populate a fresh worktree + store + index with `n` tracked files
/// whose stat cache is COLD (`mtime_ns: 0`) — every one is a cache
/// miss on the next walk, exactly `index::from_tree`'s HEAD-seeded
/// shape right after a fresh clone.
fn populate(dir: &Path, store: &ObjectStore, n: usize) -> Index {
    let mut idx = Index::default();
    let batch = store.batch();
    for i in 0..n {
        let data = file_bytes(i);
        let path = dir.join(format!("f{i}.txt"));
        std::fs::write(&path, &data).expect("write fixture file");
        let hash = worktree::store_file_object(&batch, &data).expect("store fixture object");
        idx.upsert_entry(IndexEntry {
            path: format!("f{i}.txt"),
            status: EntryStatus::Blob,
            object_hash: hash,
            mtime_ns: 0,
            size: data.len() as u64,
            ino: 0,
            ctime_ns: 0,
        });
    }
    batch.commit().expect("commit fixtures");
    idx
}

/// One cold-cache walk: exactly the `EphemeralSink` overlay shape
/// `ops::diff::status_diff_observed` uses (see that function's own
/// doc for why status snapshots go through an ephemeral, non-durable
/// sink).
fn time_walk_ms(store: &ObjectStore, dir: &Path, idx: &Index) -> f64 {
    time_one(0, 1, || {
        let snapshot = EphemeralSink::new(store);
        let mut observations = Vec::new();
        worktree::build_tree_filtered_observed_with_source(
            &snapshot,
            &snapshot,
            dir,
            Some(idx),
            &mut observations,
        )
        .unwrap();
    }) * 1000.0
}

fn bench_worktree_walk(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &(n, axis) in COUNTS {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        let idx = populate(dir.path(), &store, n);

        let ms = time_walk_ms(&store, dir.path(), &idx);
        let per_file_us = ms * 1000.0 / n as f64;
        eprintln!("worktree_walk/{axis}: {ms:.1} ms total ({per_file_us:.3} us/file)");
        samples.push(Sample {
            category: "worktree_walk".into(),
            axis: axis.into(),
            library: "build_tree_filtered_observed_with_source".into(),
            value: ms,
            unit: Unit::Millis,
        });

        // criterion series for the smaller counts only — 20k cold-hashes
        // is too slow to run under repeated sampling, matching
        // `status_snapshot`'s convention for its own largest count.
        if n <= 5_000 {
            c.bench_function(&format!("worktree_walk/{axis}"), |b| {
                b.iter(|| {
                    let snapshot = EphemeralSink::new(&store);
                    let mut observations = Vec::new();
                    worktree::build_tree_filtered_observed_with_source(
                        &snapshot,
                        &snapshot,
                        dir.path(),
                        Some(&idx),
                        &mut observations,
                    )
                    .unwrap();
                });
            });
        }
    }

    mkit_benches::write_summary("worktree_walk", &samples);
}

criterion_group!(benches, bench_worktree_walk);
criterion_main!(benches);
