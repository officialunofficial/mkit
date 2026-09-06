//! Sequential-vs-parallel crossover for checkout/restore's per-blob
//! materialisation step (`restore_blob` in `mkit-core`'s
//! `ops/restore.rs`, which backs `mkit checkout`/`clone`/`restore`/
//! `reset`/`sparse-checkout` and the internal `stash pop` path).
//!
//! **Result (measured on this suite's reference container, file counts
//! 1..512, 2 KiB fixtures): parallel is slower than sequential at
//! every single count tested — roughly 1.3x to 2.3x slower, with no
//! crossover.** Restoring a tree was a natural next candidate for the
//! rayon-style fan-out this codebase already applies to `add`'s hash
//! step, `push`'s pack compression, and `fetch`'s signature
//! verification (all CPU-bound, all wins) — and `mkit-core` already
//! has a fitting-looking primitive in `batch::parallel_io`, a scoped-
//! thread work queue written for the commit path's fsync barriers
//! (issue #864). The difference that sinks it here: `parallel_io`'s
//! win comes from overlapping *device* latency — a barrier/fsync
//! genuinely blocks on the disk, so many threads waiting on many
//! barriers concurrently beats one thread waiting on all of them in
//! series. `restore_blob`'s write is deliberately **not** flushed
//! (worktree content isn't part of the store's durability invariant —
//! see that function's doc comment), so there is no device wait to
//! overlap: `fs::write` + `fs::rename` return once the page cache
//! accepts them. Spawning a thread per file (or per `MAX_SYNC_WORKERS`
//! chunk) then pays real OS thread-creation and scheduling cost for a
//! per-file workload that was already fast, and never gets the
//! overlap benefit back. This bench is kept (unlike the reverted
//! restore.rs change it was written to validate) as a permanent
//! regression check: if `restore_blob` ever grows a real per-file
//! device-latency cost (a network filesystem, an fsync added for some
//! new invariant), re-run this and reconsider.
//!
//! `restore_blob` is private to `mkit-core`, so this reimplements the
//! same "read the blob object, write a tmp file, atomically rename it
//! into place" unit directly against the public `ObjectStore` API,
//! then compares running it one file at a time against a
//! `std::thread::scope` work queue with `batch::parallel_io`'s exact
//! shape (same worker cap) — matching this suite's existing convention
//! (`add_hash_fanout.rs`, `verify_fanout.rs`) of isolating just the
//! fan-out decision from the surrounding tree-walk/index cost a full
//! end-to-end bench would also pay.

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one_with_setup};
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Blob, Object};
use mkit_core::serialize::serialize;
use mkit_core::store::ObjectStore;
use tempfile::TempDir;

/// File counts spanning the expected crossover: a handful (typical of
/// `mkit checkout`/`restore` on an everyday edit) through the low
/// hundreds (where a `clone`/large `checkout` would land).
const COUNTS: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 256, 512];

/// Same fixture size convention as `add_hash_fanout.rs`: a small
/// source-file-sized payload, well under the chunking threshold, so
/// every restore takes the plain single-blob path (not `ChunkedBlob`
/// reassembly, which `restore_blob` already streams chunk-by-chunk —
/// issue #828 — and is therefore not this bench's concern).
const FILE_SIZE: usize = 2048;

/// Worker cap mirrored from `batch::MAX_SYNC_WORKERS` — kept as a
/// separate constant here (rather than importing a private item)
/// because it's the number this bench needs to validate for restore's
/// workload, not merely inherit unquestioned.
const MAX_WORKERS: usize = 64;

fn file_bytes(i: usize) -> Vec<u8> {
    let mut v = format!("mkit restore-fanout bench fixture #{i}\n").into_bytes();
    v.resize(FILE_SIZE, b'x');
    v
}

/// Fresh store with `n` distinct blob objects already written (as
/// `add`/`commit` would have left them) plus a fresh empty output
/// directory to restore into — both rebuilt every iteration (warmup
/// and timed alike) so no run dedups against, or writes into, a prior
/// iteration's state.
fn setup(n: usize) -> (TempDir, TempDir, ObjectStore, Vec<Hash>) {
    let store_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tempfile::tempdir().expect("tempdir");
    let layout = RepoLayout::single(store_dir.path());
    let store = ObjectStore::init(&layout).expect("init store");
    let hashes = (0..n)
        .map(|i| {
            let bytes = serialize(&Object::Blob(Blob {
                data: file_bytes(i),
            }))
            .expect("serialize blob");
            store.write(&bytes).expect("write blob")
        })
        .collect();
    (store_dir, out_dir, store, hashes)
}

/// The unit of work `restore_blob_tasks` fans out: read the blob back
/// (BLAKE3-re-verifying, since `ObjectStore::read` does), write it to a
/// tmp sibling, then atomically rename into place — same shape as
/// production `restore_blob`'s plain-`Blob` arm, minus the executable
/// bit and symlink-safety code this bench doesn't exercise.
fn restore_one(store: &ObjectStore, dir: &Path, i: usize, hash: Hash) {
    let Object::Blob(b) = store.read_object(&hash).expect("read object") else {
        panic!("expected blob");
    };
    let name = format!("f{i}.txt");
    let tmp = dir.join(format!(".{name}.tmp"));
    fs::write(&tmp, &b.data).expect("write tmp");
    fs::rename(&tmp, dir.join(name)).expect("rename");
}

/// `batch::parallel_io`'s exact work-queue shape, reimplemented here
/// since the real one is private to `mkit-core`: up to `MAX_WORKERS`
/// scoped threads pulling indices off a shared atomic counter, joined
/// before returning.
fn parallel_restore(store: &ObjectStore, dir: &Path, hashes: &[Hash]) {
    let count = hashes.len();
    if count == 0 {
        return;
    }
    let workers = MAX_WORKERS.min(count);
    if workers == 1 {
        for (i, h) in hashes.iter().enumerate() {
            restore_one(store, dir, i, *h);
        }
        return;
    }
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let next = &next;
            scope.spawn(move || {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= count {
                        return;
                    }
                    restore_one(store, dir, i, hashes[i]);
                }
            });
        }
    });
}

fn bench_restore_fanout(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &n in COUNTS {
        let axis = format!("{n}_files");

        let seq_ms = time_one_with_setup(
            2,
            20,
            || setup(n),
            |(_sd, od, store, hashes)| {
                for (i, h) in hashes.iter().enumerate() {
                    restore_one(&store, od.path(), i, *h);
                }
            },
        ) * 1000.0;

        let par_ms = time_one_with_setup(
            2,
            20,
            || setup(n),
            |(_sd, od, store, hashes)| {
                parallel_restore(&store, od.path(), &hashes);
            },
        ) * 1000.0;

        eprintln!("restore_fanout/{axis}: sequential {seq_ms:.4} ms, parallel {par_ms:.4} ms");
        samples.push(Sample {
            category: "restore_fanout".into(),
            axis: axis.clone(),
            library: "sequential".into(),
            value: seq_ms,
            unit: Unit::Millis,
        });
        samples.push(Sample {
            category: "restore_fanout".into(),
            axis,
            library: "parallel".into(),
            value: par_ms,
            unit: Unit::Millis,
        });
    }

    // criterion's own harness is unused here (see `add_hash_fanout.rs`'s
    // module doc for the rationale) — `c` is still threaded through so
    // this stays a normal criterion-managed bench target for `cargo
    // bench`/CI discovery.
    let _ = c;

    mkit_benches::write_summary("restore_fanout", &samples);
}

criterion_group!(benches, bench_restore_fanout);
criterion_main!(benches);
