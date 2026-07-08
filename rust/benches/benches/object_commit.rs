//! Object commit roundtrip — wallclock for hash + write of a small
//! commit blob, mkit vs git2 (libgit2) vs git CLI.
//!
//! All three operate on a fresh empty repo and commit a fixed payload
//! ("hello world\n" × N) at four sizes. Numbers are wallclock ms,
//! NOT throughput, so smaller bars win — the renderer flips bar
//! length to `1000 / value` for the Millis unit.
//!
//! ## What one iteration measures (and the PR #604 bug this fixes)
//!
//! Every backend here is content-addressed (mkit's `ObjectStore`, git2's
//! ODB, and `git hash-object -w` all dedup a write of bytes already on
//! disk into close to a no-op). PR #604's refresh pass found
//! `object_commit` reporting a 100-file commit as *cheaper* than a
//! 10-file commit — physically impossible — because a single
//! store/repo/dir was built once per size and then reused across every
//! criterion iteration AND across the hand-rolled sample used for the
//! chart JSON: only the very first call ever wrote real bytes, every
//! call after that was a dedup hit against warm state.
//!
//! Each iteration now gets its own fresh tempdir + store/repo (via
//! `iter_batched`/a fresh directory per rep), so every iteration pays
//! the full cold cost of N real on-disk writes — the number this bench
//! exists to measure.

use std::path::Path;
use std::process::Command;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, assert_monotonic, time_cold};
use mkit_core::layout::RepoLayout;
use mkit_core::store::ObjectStore;

const SIZES: &[(usize, &str)] = &[
    (1, "1 file"),
    (10, "10 files"),
    (100, "100 files"),
    (1000, "1000 files"),
];

/// Independent cold repetitions for the hand-rolled chart sample. Kept
/// small: each repetition pays for a fresh tempdir + N real on-disk
/// writes, and the largest axis is 1000 files × 3 backends.
const COLD_REPS: u32 = 3;

fn bench_object_commit(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();
    let git_available = Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    for &(n, axis) in SIZES {
        let payloads: Vec<Vec<u8>> = (0..n)
            .map(|i| format!("file {i}\n{}\n", "hello world\n".repeat(8)).into_bytes())
            .collect();

        // --- mkit-core: hash + atomic-write each payload as a blob ------
        // Uses ObjectStore::write so the comparison is apples-to-apples
        // with git2's odb.write and `git hash-object -w` below — all
        // three perform a real on-disk write, not just a hash. Fresh
        // tempdir + store per iteration so dedup never short-circuits.
        {
            c.bench_function(&format!("commit/{axis}/mkit"), |b| {
                b.iter_batched(
                    || {
                        let dir = tempfile::tempdir().unwrap();
                        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
                        (dir, store)
                    },
                    |(_dir, store)| commit_via_mkit(&store, &payloads),
                    BatchSize::PerIteration,
                );
            });
            let t = time_cold(
                COLD_REPS,
                || {
                    let dir = tempfile::tempdir().unwrap();
                    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
                    (dir, store)
                },
                |(_dir, store)| commit_via_mkit(&store, &payloads),
            );
            samples.push(Sample {
                category: "object-commit".into(),
                axis: axis.into(),
                library: "mkit".into(),
                value: t * 1000.0,
                unit: Unit::Millis,
            });
        }

        // --- git2 (libgit2 binding) -------------------------------------
        {
            c.bench_function(&format!("commit/{axis}/git2"), |b| {
                b.iter_batched(
                    || {
                        let dir = tempfile::tempdir().unwrap();
                        let repo = git2::Repository::init(dir.path()).unwrap();
                        (dir, repo)
                    },
                    |(_dir, repo)| commit_via_git2(&repo, &payloads),
                    BatchSize::PerIteration,
                );
            });
            let t = time_cold(
                COLD_REPS,
                || {
                    let dir = tempfile::tempdir().unwrap();
                    let repo = git2::Repository::init(dir.path()).unwrap();
                    (dir, repo)
                },
                |(_dir, repo)| commit_via_git2(&repo, &payloads),
            );
            samples.push(Sample {
                category: "object-commit".into(),
                axis: axis.into(),
                library: "git2 (libgit2)".into(),
                value: t * 1000.0,
                unit: Unit::Millis,
            });
        }

        // --- git CLI ----------------------------------------------------
        if git_available {
            c.bench_function(&format!("commit/{axis}/git-cli"), |b| {
                b.iter_batched(
                    init_git_cli_repo,
                    |dir| commit_via_git_cli(dir.path(), &payloads),
                    BatchSize::PerIteration,
                );
            });
            let t = time_cold(COLD_REPS, init_git_cli_repo, |dir| {
                commit_via_git_cli(dir.path(), &payloads);
            });
            samples.push(Sample {
                category: "object-commit".into(),
                axis: axis.into(),
                library: "git CLI".into(),
                value: t * 1000.0,
                unit: Unit::Millis,
            });
        }
    }

    // Sanity gate: physics demands that committing more files costs at
    // least as much wall-clock as committing fewer, per backend. This
    // is the exact ordering PR #604 found broken (100 files cheaper
    // than 10) — fail loudly here instead of silently publishing
    // impossible numbers again.
    for library in ["mkit", "git2 (libgit2)", "git CLI"] {
        let value_for = |axis: &str| {
            samples
                .iter()
                .find(|s| s.library == library && s.axis == axis)
                .map(|s| s.value)
        };
        let mut prev: Option<(&str, f64)> = None;
        for &(_, axis) in SIZES {
            let Some(v) = value_for(axis) else {
                continue; // e.g. git CLI absent from this run
            };
            if let Some(earlier) = prev {
                assert_monotonic(&format!("object-commit/{library}"), earlier, (axis, v));
            }
            prev = Some((axis, v));
        }
    }

    mkit_benches::write_summary("object_commit", &samples);
}

/// Fresh `git init`ed repo with commit identity configured — shared by
/// both the criterion `iter_batched` setup closure and the hand-rolled
/// `time_cold` sample, so the git-CLI backend gets the same cold,
/// per-iteration fixture as the other two backends.
fn init_git_cli_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let _ = Command::new("git")
        .args(["init", "--quiet", dir.path().to_str().unwrap()])
        .output();
    let _ = Command::new("git")
        .args([
            "-C",
            dir.path().to_str().unwrap(),
            "config",
            "user.email",
            "bench@example.com",
        ])
        .output();
    let _ = Command::new("git")
        .args([
            "-C",
            dir.path().to_str().unwrap(),
            "config",
            "user.name",
            "bench",
        ])
        .output();
    dir
}

fn commit_via_mkit(store: &ObjectStore, payloads: &[Vec<u8>]) {
    // ObjectStore::write hashes the payload (BLAKE3), atomically
    // writes the bytes to <objects>/<2-hex-shard>/<62-hex-suffix> via
    // tmpfile + fsync + rename, and is idempotent on duplicate writes.
    for p in payloads {
        let _h = store.write(p).unwrap();
    }
}

fn commit_via_git2(repo: &git2::Repository, payloads: &[Vec<u8>]) {
    let odb = repo.odb().unwrap();
    for p in payloads {
        let _oid = odb.write(git2::ObjectType::Blob, p).unwrap();
    }
}

fn commit_via_git_cli(repo: &Path, payloads: &[Vec<u8>]) {
    // hash-object writes a blob and prints its SHA-1. No staging, no
    // commit object — apples-to-apples with mkit's hash() above.
    use std::io::Write;
    for p in payloads {
        let mut child = Command::new("git")
            .args(["-C", repo.to_str().unwrap(), "hash-object", "-w", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        child.stdin.as_mut().unwrap().write_all(p).unwrap();
        drop(child.stdin.take());
        let _ = child.wait();
    }
}

// Fresh tempdir + store/repo/dir per iteration (see the module doc)
// means each criterion iteration now pays real setup cost, unlike the
// old shared-fixture version. Cap sample_size so the 1000-file axis
// across three backends stays a few seconds, not minutes — this is a
// tier-3 absolute-timing bench (nightly, tolerant), not a
// statistically load-bearing distribution.
criterion_group!(name = benches; config = Criterion::default().sample_size(10); targets = bench_object_commit);
criterion_main!(benches);
