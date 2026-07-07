//! Pack creation — chunk + hash + store a synthetic blob set, mkit
//! (BLAKE3 + content-addressed write per blob) vs git's `pack-objects`
//! over a real git repo.
//!
//! mkit does not have FastCDC chunking exposed at a stable public API
//! yet, so this benchmark anchors on the steady-state "store N blobs
//! in a content-addressed fashion" cost. Wallclock ms, smaller wins.

use std::process::Command;
use std::time::Instant;

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one};
use mkit_core::layout::RepoLayout;
use mkit_core::store::ObjectStore;

const SIZES: &[(usize, usize, &str)] = &[
    // (file_count, file_size, axis_label)
    (10, 64 * 1024, "10 × 64 KiB"),
    (100, 64 * 1024, "100 × 64 KiB"),
    (10, 1024 * 1024, "10 × 1 MiB"),
    (100, 1024 * 1024, "100 × 1 MiB"),
];

fn bench_pack(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();
    let git_available = Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    for &(count, size, axis) in SIZES {
        let blobs = build_blobs(count, size);

        // --- mkit: hash + atomic-write each blob via ObjectStore -------
        // Apples-to-apples with git2's odb.write below: real on-disk
        // writes, not just hashing.
        let mkit_dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(mkit_dir.path())).unwrap();
        c.bench_function(&format!("pack/{axis}/mkit"), |b| {
            b.iter(|| pack_via_mkit(&store, &blobs));
        });
        let t = time_one(1, 5, || pack_via_mkit(&store, &blobs));
        samples.push(Sample {
            category: "pack-create".into(),
            axis: axis.into(),
            library: "mkit (BLAKE3)".into(),
            value: t * 1000.0,
            unit: Unit::Millis,
        });

        // --- git2 odb.write per blob
        {
            let dir = tempfile::tempdir().unwrap();
            let repo = git2::Repository::init(dir.path()).unwrap();
            c.bench_function(&format!("pack/{axis}/git2"), |b| {
                b.iter(|| pack_via_git2(&repo, &blobs));
            });
            let t = time_one(1, 5, || pack_via_git2(&repo, &blobs));
            samples.push(Sample {
                category: "pack-create".into(),
                axis: axis.into(),
                library: "git2 (libgit2)".into(),
                value: t * 1000.0,
                unit: Unit::Millis,
            });
        }

        // --- git pack-objects (CLI). Setup: init a repo, hash-object each
        // blob, then run pack-objects with the resulting OIDs piped on stdin.
        if git_available {
            let t = bench_git_pack_objects(&blobs);
            samples.push(Sample {
                category: "pack-create".into(),
                axis: axis.into(),
                library: "git pack-objects".into(),
                value: t * 1000.0,
                unit: Unit::Millis,
            });
        }
    }

    mkit_benches::write_summary("pack_create", &samples);
}

fn build_blobs(count: usize, size: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(count);
    let mut state: u64 = 0x1234_5678_9abc_def0;
    for i in 0..count {
        let mut buf = Vec::with_capacity(size);
        // Per-blob randomness so the hashing path doesn't dedupe to one entry.
        state ^= (i as u64).rotate_left(13);
        for _ in 0..size {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            buf.push((state >> 56) as u8);
        }
        out.push(buf);
    }
    out
}

fn pack_via_mkit(store: &ObjectStore, blobs: &[Vec<u8>]) {
    for b in blobs {
        let _h = store.write(b).unwrap();
    }
}

fn pack_via_git2(repo: &git2::Repository, blobs: &[Vec<u8>]) {
    let odb = repo.odb().unwrap();
    for b in blobs {
        let _oid = odb.write(git2::ObjectType::Blob, b).unwrap();
    }
}

fn bench_git_pack_objects(blobs: &[Vec<u8>]) -> f64 {
    let dir = tempfile::tempdir().unwrap();
    let dirp = dir.path();
    let _ = Command::new("git")
        .args(["init", "--quiet", dirp.to_str().unwrap()])
        .output();
    // Hash blobs into the repo first.
    use std::io::Write;
    let mut oids = Vec::with_capacity(blobs.len());
    for b in blobs {
        let mut child = Command::new("git")
            .args(["-C", dirp.to_str().unwrap(), "hash-object", "-w", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        child.stdin.as_mut().unwrap().write_all(b).unwrap();
        drop(child.stdin.take());
        let out = child.wait_with_output().unwrap();
        let oid = String::from_utf8_lossy(&out.stdout).trim().to_string();
        oids.push(oid);
    }
    // Now time the pack-objects pass.
    let oid_input = oids.join("\n");
    let mut total = 0.0f64;
    let n = 3;
    for _ in 0..n {
        let t0 = Instant::now();
        let mut child = Command::new("git")
            .args([
                "-C",
                dirp.to_str().unwrap(),
                "pack-objects",
                "--stdout",
                "--quiet",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(oid_input.as_bytes())
            .unwrap();
        drop(child.stdin.take());
        let _ = child.wait();
        total += t0.elapsed().as_secs_f64();
    }
    total / f64::from(n)
}

criterion_group!(benches, bench_pack);
criterion_main!(benches);
