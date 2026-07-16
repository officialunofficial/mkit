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
use mkit_benches::{Sample, Unit, time_one_with_setup};
use mkit_core::layout::RepoLayout;
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
        // Uses ObjectStore::batch(), the write path every multi-object
        // command (add, commit, pack unpack) actually takes — content is
        // still fsynced per object before it becomes visible, but the
        // directory-durability fsync is deferred and amortized to one
        // flush at `commit()`, not paid per object like the raw
        // `ObjectStore::write()` this bench used before. That distinction
        // is the whole story at N>1: the per-object-fsync path is ~8-25x
        // slower here for no correctness benefit, since nothing in this
        // benchmark's multi-file commit needs each object durable before
        // the *next* object is written — only before the batch as a whole
        // is visible. Every measured iteration gets a fresh tempdir +
        // store (like store_write.rs's iter_with_setup) so writes never
        // dedup against a payload already staged by a prior iteration.
        {
            c.bench_function(&format!("commit/{axis}/mkit"), |b| {
                b.iter_with_setup(
                    || {
                        let dir = tempfile::tempdir().unwrap();
                        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
                        (dir, store)
                    },
                    |(_dir, store)| commit_via_mkit(&store, &payloads),
                );
            });
            let t = time_one_with_setup(
                2,
                5,
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
        // Same fresh-repo-per-iteration treatment: libgit2's odb.write
        // is content-addressed too, so a reused repo would dedup from
        // the second iteration onward exactly like mkit's store.
        {
            c.bench_function(&format!("commit/{axis}/git2"), |b| {
                b.iter_with_setup(
                    || {
                        let dir = tempfile::tempdir().unwrap();
                        let repo = git2::Repository::init(dir.path()).unwrap();
                        (dir, repo)
                    },
                    |(_dir, repo)| commit_via_git2(&repo, &payloads),
                );
            });
            let t = time_one_with_setup(
                2,
                5,
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
        // `git hash-object -w` is also content-addressed and skips the
        // write when the object already exists, so this needs a fresh
        // repo per iteration for the same reason as mkit and git2 above.
        if git_available {
            c.bench_function(&format!("commit/{axis}/git-cli"), |b| {
                b.iter_with_setup(
                    || {
                        let dir = tempfile::tempdir().unwrap();
                        init_git_repo(dir.path());
                        dir
                    },
                    |dir| commit_via_git_cli(dir.path(), &payloads),
                );
            });
            let t = time_one_with_setup(
                2,
                5,
                || {
                    let dir = tempfile::tempdir().unwrap();
                    init_git_repo(dir.path());
                    dir
                },
                |dir| commit_via_git_cli(dir.path(), &payloads),
            );
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

/// `git init` a fresh repo and configure a commit identity so runs
/// don't prompt. Shared by the git-CLI setup closure and its
/// `time_one` counterpart.
fn init_git_repo(dir: &Path) {
    let path = dir.to_str().unwrap();
    let _ = Command::new("git").args(["init", "--quiet", path]).output();
    let _ = Command::new("git")
        .args(["-C", path, "config", "user.email", "bench@example.com"])
        .output();
    let _ = Command::new("git")
        .args(["-C", path, "config", "user.name", "bench"])
        .output();
}

fn commit_via_mkit(store: &ObjectStore, payloads: &[Vec<u8>]) {
    // ObjectStore::batch() hashes each payload (BLAKE3) and atomically
    // writes it to <objects>/<2-hex-shard>/<62-hex-suffix> via
    // tmpfile + fsync + rename, same as ObjectStore::write; the
    // difference is `commit()` amortizes the shard-directory fsyncs
    // (rename durability) to once for the whole batch instead of once
    // per object. Idempotent on duplicate writes, same as `write`.
    let batch = store.batch();
    for p in payloads {
        let _h = batch.write(p).unwrap();
    }
    batch.commit().unwrap();
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
