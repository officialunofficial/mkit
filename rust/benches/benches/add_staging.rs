//! `mkit add -A` staging cost at increasing tracked-file counts.
//!
//! Zero prior coverage before this file (issue #708): `add_one` looked up
//! the target path via `Index::find_entry` — an `O(n)` linear scan,
//! documented as such — up to three times per file, on top of
//! `remove_file_directory_conflicts` running a full `O(n)` `Vec::retain`
//! over the whole index for every file. Neither cost was amortized, so
//! staging N files cost `O(N^2)` index scans total with no benchmark to
//! catch it. This exercises the real `mkit add -A` CLI path
//! (`mkit_cli::dispatch`, in-process — no subprocess spawn) over synthetic
//! 10k- and 100k-file trees.
//!
//! Numbers are wallclock ms (total) and derived us/file; smaller is
//! better, but the interesting signal is that us/file should stay roughly
//! flat from 10k -> 100k files rather than growing ~10x, which is the
//! signature of an `O(N^2)` regression coming back.

use std::path::Path;

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one};
use mkit_core::layout::RepoLayout;
use mkit_core::refs;
use mkit_core::store::ObjectStore;

const COUNTS: &[(usize, &str)] = &[(10_000, "10k files"), (100_000, "100k files")];
/// Files per leaf directory. Spreads the fixture across a realistic
/// directory tree (matching `add_tree`'s recursive-walk shape) instead of
/// one flat N-entry directory, which no real repo looks like.
const FANOUT: usize = 200;

/// Deterministic, distinct per-file content — real bytes, not a
/// pre-existing fixture, so each file hashes to a different object (no
/// dedup short-circuit hides the staging cost).
fn file_bytes(i: usize) -> Vec<u8> {
    format!("mkit add-staging bench fixture #{i}\n").into_bytes()
}

/// Populate `root` with `n` files spread across `n / FANOUT` directories.
fn populate_worktree(root: &Path, n: usize) {
    for i in 0..n {
        let dir = root.join(format!("d{}", i / FANOUT));
        std::fs::create_dir_all(&dir).expect("create fixture dir");
        std::fs::write(dir.join(format!("f{i}.txt")), file_bytes(i)).expect("write fixture file");
    }
}

/// Wallclock milliseconds for a single un-warmed `mkit add -A` over the
/// worktree at `repo_dir` (already `.mkit`-initialised, cwd-independent
/// caller). Staging 100k files is far too slow to run under criterion's
/// repeated-sampling loop (each sample would re-walk the whole tree) —
/// one real pass, like `refs_ops.rs` and `store_write.rs` already do for
/// their expensive real-I/O series.
fn time_add_all_ms(repo_dir: &Path) -> f64 {
    let prev_cwd = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(repo_dir).expect("chdir into fixture repo");
    let ms = time_one(0, 1, || {
        let code = mkit_cli::dispatch(&["mkit".to_string(), "add".to_string(), "-A".to_string()]);
        assert_eq!(code, mkit_cli::exit::OK, "mkit add -A must succeed");
    }) * 1000.0;
    std::env::set_current_dir(prev_cwd).expect("restore cwd");
    ms
}

/// `mkit add -A` staging an entirely-untracked worktree of N files: the
/// first stage of any repo, and the case `add_tree`/`add_one` walk in
/// full (no stat-cache short-circuit can apply — nothing is tracked yet).
fn bench_add_staging(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &(n, axis) in COUNTS {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        ObjectStore::init(&layout).unwrap();
        refs::init(&layout).unwrap();
        populate_worktree(dir.path(), n);

        let ms = time_add_all_ms(dir.path());
        let per_file_us = ms * 1000.0 / n as f64;
        eprintln!("add_staging/{axis}: {ms:.1} ms total ({per_file_us:.2} us/file)");
        samples.push(Sample {
            category: "add_staging".into(),
            axis: axis.into(),
            library: "add -A".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }

    // criterion's own harness is unused here (see `time_add_all_ms`'s
    // doc) — `c` is still threaded through so this stays a normal
    // criterion-managed bench target for `cargo bench`/CI discovery.
    let _ = c;

    mkit_benches::write_summary("add_staging", &samples);
}

criterion_group!(benches, bench_add_staging);
criterion_main!(benches);
