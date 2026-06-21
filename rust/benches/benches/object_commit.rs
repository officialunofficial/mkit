//! Object commit roundtrip — wallclock for hash + write of a small
//! commit blob, mkit vs git2 (libgit2) vs git CLI.
//!
//! All three operate on a fresh empty repo and commit a fixed payload
//! ("hello world\n" × N) at four sizes. Numbers are wallclock ms,
//! NOT throughput, so smaller bars win — the renderer flips bar
//! length to `1000 / value` for the Millis unit.

use std::path::Path;
use std::process::Command;

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one};
use mkit_core::store::ObjectStore;

const SIZES: &[(usize, &str)] = &[
    (1, "1 file"),
    (10, "10 files"),
    (100, "100 files"),
    (1000, "1000 files"),
];

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
        // three perform a real on-disk write, not just a hash.
        {
            let dir = tempfile::tempdir().unwrap();
            let store = ObjectStore::init(dir.path()).unwrap();
            c.bench_function(&format!("commit/{axis}/mkit"), |b| {
                b.iter(|| commit_via_mkit(&store, &payloads));
            });
            let t = time_one(2, 5, || {
                commit_via_mkit(&store, &payloads);
            });
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
            let dir = tempfile::tempdir().unwrap();
            let repo = git2::Repository::init(dir.path()).unwrap();
            c.bench_function(&format!("commit/{axis}/git2"), |b| {
                b.iter(|| commit_via_git2(&repo, &payloads));
            });
            let t = time_one(2, 5, || {
                commit_via_git2(&repo, &payloads);
            });
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
            let dir = tempfile::tempdir().unwrap();
            let _ = Command::new("git")
                .args(["init", "--quiet", dir.path().to_str().unwrap()])
                .output();
            // Configure user so commits don't prompt.
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

            c.bench_function(&format!("commit/{axis}/git-cli"), |b| {
                b.iter(|| commit_via_git_cli(dir.path(), &payloads));
            });
            let t = time_one(2, 5, || {
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

    mkit_benches::write_summary("object_commit", &samples);
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

criterion_group!(benches, bench_object_commit);
criterion_main!(benches);
