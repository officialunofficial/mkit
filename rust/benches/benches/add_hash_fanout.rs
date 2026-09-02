//! Sequential-vs-rayon crossover for `mkit add`'s per-file hashing
//! fan-out (`add_whole_worktree` in `mkit-cli`'s `commands/add.rs`).
//!
//! Raised on PR #951 (Slack thread on the parallel-hashing change):
//! does a small worktree pay rayon's thread-dispatch cost for no
//! benefit? This isolates just the hash-fan-out decision — open +
//! read + BLAKE3 via `worktree::hash_file_with_metadata`, the exact
//! function `add.rs` calls — from the surrounding walk/index/commit
//! cost the full `add_staging` bench also measures, so the crossover
//! point isn't drowned out by unrelated overhead.
//!
//! `add.rs`'s hashing helpers are private to `mkit-cli`, so this
//! exercises the same public `mkit-core` entry point directly instead
//! of going through the CLI.

use std::path::{Path, PathBuf};

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one_with_setup};
use mkit_core::layout::RepoLayout;
use mkit_core::store::ObjectStore;
use mkit_core::worktree;
use rayon::prelude::*;
use tempfile::TempDir;

/// File counts spanning the expected crossover: tiny (dispatch
/// overhead should dominate) through the low hundreds (where
/// `add_staging`'s 10k/100k cases already show parallel winning
/// decisively).
const COUNTS: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 256];

/// A small source-file-sized payload — the everyday `mkit add` case
/// this threshold matters for, well under `worktree::CHUNK_THRESHOLD`
/// (1 MiB) so every file takes the single-BLAKE3-pass path.
const FILE_SIZE: usize = 2048;

/// Deterministic, distinct per-file content — every file hashes to a
/// different object, matching `add_staging.rs`'s fixture convention
/// (no dedup short-circuit hiding real per-file cost).
fn file_bytes(i: usize) -> Vec<u8> {
    let mut v = format!("mkit hash-fanout bench fixture #{i}\n").into_bytes();
    v.resize(FILE_SIZE, b'x');
    v
}

/// Write `n` distinct files under `dir` and return their paths.
fn populate(dir: &Path, n: usize) -> Vec<PathBuf> {
    (0..n)
        .map(|i| {
            let p = dir.join(format!("f{i}.txt"));
            std::fs::write(&p, file_bytes(i)).expect("write fixture file");
            p
        })
        .collect()
}

/// Fresh tempdir + store + `n` fixture files — rebuilt every
/// iteration (warmup and timed alike) so no run dedups against a
/// prior iteration's staged content. Returned as one bundle so
/// `time_one_with_setup` can hand it to the timed closure; `_dir`
/// keeps the tempdir alive for the closure's duration without
/// triggering an unused-variable warning.
fn setup(n: usize) -> (TempDir, ObjectStore, Vec<PathBuf>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).expect("init store");
    let files = populate(dir.path(), n);
    (dir, store, files)
}

fn bench_hash_fanout(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &n in COUNTS {
        let axis = format!("{n}_files");

        let seq_ms = time_one_with_setup(
            2,
            20,
            || setup(n),
            |(_dir, store, files)| {
                let batch = store.batch();
                for f in &files {
                    worktree::hash_file_with_metadata(&batch, f).expect("hash");
                }
            },
        ) * 1000.0;

        let par_ms = time_one_with_setup(
            2,
            20,
            || setup(n),
            |(_dir, store, files)| {
                let batch = store.batch();
                files.par_iter().for_each(|f| {
                    worktree::hash_file_with_metadata(&batch, f).expect("hash");
                });
            },
        ) * 1000.0;

        eprintln!("hash_fanout/{axis}: sequential {seq_ms:.4} ms, rayon {par_ms:.4} ms");
        samples.push(Sample {
            category: "hash_fanout".into(),
            axis: axis.clone(),
            library: "sequential".into(),
            value: seq_ms,
            unit: Unit::Millis,
        });
        samples.push(Sample {
            category: "hash_fanout".into(),
            axis,
            library: "rayon".into(),
            value: par_ms,
            unit: Unit::Millis,
        });
    }

    // criterion's own harness is unused here (see the module doc's
    // rationale for `time_one_with_setup` over repeated-sampling
    // benches) — `c` is still threaded through so this stays a normal
    // criterion-managed bench target for `cargo bench`/CI discovery.
    let _ = c;

    mkit_benches::write_summary("hash_fanout", &samples);
}

criterion_group!(benches, bench_hash_fanout);
criterion_main!(benches);
