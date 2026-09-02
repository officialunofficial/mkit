//! Pins `add.rs`'s hash-fan-out threshold behavior (PR #951 review):
//! a batch with one unhashable file prints exactly one `error:` line
//! and exits non-zero, whether the batch stays below
//! `hash_fanout_threshold()` (sequential path) or clears it (rayon
//! path). Regression guard for the code-review finding that the
//! parallel path used to print one line per failing file instead of
//! one for the whole command — and for the sequential branch added
//! alongside it, which reimplements the same fail-fast contract by
//! hand and had no coverage of its own.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::Output;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    std::process::Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn mkit")
}

fn init_repo() -> (tempfile::TempDir, tempfile::TempDir) {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    assert!(run_in(root, x, &["init"]).status.success());
    assert!(run_in(root, x, &["keygen"]).status.success());
    (td, xdg)
}

/// A sparse file whose reported length exceeds mkit's per-file cap
/// (`mkit_core::worktree::MAX_FILE_BYTES`) without writing real bytes
/// to disk — `add`'s size check reads only `Metadata::len()`, so this
/// trips the same `FileTooLarge` error a genuinely huge file would,
/// in milliseconds instead of writing a gigabyte.
fn write_oversized_sparse_file(path: &Path) {
    let f = fs::File::create(path).expect("create sparse file");
    f.set_len(mkit_core::worktree::MAX_FILE_BYTES + 1)
        .expect("set sparse length");
}

fn write_small_files(root: &Path, n: usize) {
    for i in 0..n {
        fs::write(root.join(format!("f{i}.txt")), format!("content {i}\n")).unwrap();
    }
}

/// Number of pending files comfortably above `add.rs`'s
/// `hash_fanout_threshold()` (8 files per rayon thread) regardless of
/// this machine's core count, so a batch of this size always takes
/// the rayon path. Rayon's default global pool size mirrors
/// `std::thread::available_parallelism()` absent a `RAYON_NUM_THREADS`
/// override, which this test suite does not set.
fn above_fanout_threshold_file_count() -> usize {
    let threads = std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
    8 * threads + 40
}

/// Count of stderr lines starting with `error:` — should be exactly 1
/// no matter how many files in the batch fail, or how many other
/// files hash successfully before/after the failing one.
fn error_line_count(out: &Output) -> usize {
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter(|l| l.starts_with("error:"))
        .count()
}

#[test]
fn single_error_line_below_hash_fanout_threshold() {
    let (td, xdg) = init_repo();
    let (root, x) = (td.path(), xdg.path());

    // 3 total pending files is safely below `hash_fanout_threshold()`
    // on any realistic core count (>= 1 thread means threshold >= 8).
    write_small_files(root, 2);
    write_oversized_sparse_file(&root.join("oversized.bin"));

    let out = run_in(root, x, &["add", "."]);
    assert!(
        !out.status.success(),
        "add should fail on the oversized file"
    );
    assert_eq!(
        error_line_count(&out),
        1,
        "expected exactly one error line, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn single_error_line_above_hash_fanout_threshold() {
    let (td, xdg) = init_repo();
    let (root, x) = (td.path(), xdg.path());

    write_small_files(root, above_fanout_threshold_file_count());
    write_oversized_sparse_file(&root.join("oversized.bin"));

    let out = run_in(root, x, &["add", "."]);
    assert!(
        !out.status.success(),
        "add should fail on the oversized file"
    );
    assert_eq!(
        error_line_count(&out),
        1,
        "expected exactly one error line, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn happy_path_above_hash_fanout_threshold_stages_and_commits() {
    let (td, xdg) = init_repo();
    let (root, x) = (td.path(), xdg.path());
    let n = above_fanout_threshold_file_count();

    write_small_files(root, n);

    let add_out = run_in(root, x, &["add", "."]);
    assert!(add_out.status.success(), "add failed: {add_out:?}");

    let commit_out = run_in(root, x, &["commit", "-m", "bulk"]);
    assert!(commit_out.status.success(), "commit failed: {commit_out:?}");

    let status_out = run_in(root, x, &["status"]);
    assert!(status_out.status.success());
    // `status`'s human-readable summary goes to stderr, not stdout.
    assert!(
        String::from_utf8_lossy(&status_out.stderr).contains("nothing to commit"),
        "expected clean status after committing all {n} files, got: {}",
        String::from_utf8_lossy(&status_out.stderr)
    );
}
