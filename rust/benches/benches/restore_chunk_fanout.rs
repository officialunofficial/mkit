//! Sequential-vs-rayon crossover for a `ChunkedBlob`'s *intra-file*
//! chunk-read fan-out during checkout/clone/reset/restore:
//! `ops::restore::restore_tree_to_worktree_with`'s `read_chunks` batch
//! callback.
//!
//! The write side of this exact shape (`worktree::store_large_file_streaming_with`'s
//! `hash_chunks` callback, measured by `chunk_hash_fanout.rs`) already
//! fans a large file's independent per-chunk work out across rayon. The
//! read side — materialising that same file back onto disk during
//! checkout/clone — read every chunk (open + BLAKE3-verify + decode)
//! sequentially on one thread, with no counterpart fan-out, even though
//! each chunk's read is exactly as independent of its neighbours as its
//! write was.
//!
//! Two shapes are measured, mirroring `chunk_hash_fanout.rs`:
//!
//! - `batch/<n>_chunks`: the per-batch crossover in isolation — `n`
//!   already-stored chunks, read back sequentially vs via rayon,
//!   spanning `restore::RESTORE_CHUNK_BATCH` (64).
//! - `file/<n>_mib`: end-to-end restore of one real file (real FastCDC
//!   cuts via `worktree::build_tree`, real tmp-file + rename writes) —
//!   sequential (`restore_tree_to_worktree`) vs fully rayon-fanned
//!   (`restore_tree_to_worktree_with`, every batch fanned out).

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one, time_one_with_setup};
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::object::Object;
use mkit_core::ops::restore::{
    RestoreError, RestoreOptions, restore_tree_to_worktree, restore_tree_to_worktree_with,
};
use mkit_core::store::ObjectStore;
use mkit_core::worktree::{self, store_chunk_blob};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Chunk-batch sizes spanning `restore::RESTORE_CHUNK_BATCH` (64) — tiny
/// (dispatch overhead should dominate) through a full batch.
const BATCH_COUNTS: &[usize] = &[1, 2, 4, 8, 16, 32, 64];

/// Deterministic, distinct per-chunk content — every chunk is a
/// different object, matching `chunk_hash_fanout.rs`'s fixture.
fn chunk_bytes(i: usize) -> Vec<u8> {
    let mut v = format!("mkit restore-chunk-fanout bench fixture #{i}\n").into_bytes();
    v.resize(64 * 1024, b'x');
    v
}

fn fresh_store() -> (TempDir, ObjectStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).expect("init store");
    (dir, store)
}

fn read_chunk(store: &ObjectStore, h: &Hash) -> Vec<u8> {
    match store.read_object(h).expect("read chunk") {
        Object::Blob(b) => b.data,
        _ => panic!("expected a Blob"),
    }
}

fn bench_batch_fanout(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &n in BATCH_COUNTS {
        let axis = format!("{n}_chunks");
        let (_dir, store) = fresh_store();
        let wb = store.batch();
        let hashes: Vec<Hash> = (0..n)
            .map(|i| store_chunk_blob(&wb, &chunk_bytes(i)).expect("store chunk"))
            .collect();
        wb.commit().expect("commit");

        let seq_ms = time_one(2, 20, || {
            let _: Vec<Vec<u8>> = hashes.iter().map(|h| read_chunk(&store, h)).collect();
        }) * 1000.0;

        let par_ms = time_one(2, 20, || {
            let _: Vec<Vec<u8>> = hashes.par_iter().map(|h| read_chunk(&store, h)).collect();
        }) * 1000.0;

        eprintln!(
            "restore_chunk_fanout/batch/{axis}: sequential {seq_ms:.4} ms, rayon {par_ms:.4} ms"
        );
        samples.push(Sample {
            category: "restore_chunk_fanout".into(),
            axis: format!("batch/{axis}"),
            library: "sequential".into(),
            value: seq_ms,
            unit: Unit::Millis,
        });
        samples.push(Sample {
            category: "restore_chunk_fanout".into(),
            axis: format!("batch/{axis}"),
            library: "rayon".into(),
            value: par_ms,
            unit: Unit::Millis,
        });
    }

    let _ = c;
    mkit_benches::write_summary("restore_chunk_fanout_batch", &samples);
}

/// File sizes for the end-to-end restore comparison — large enough to
/// need several `RESTORE_CHUNK_BATCH`-sized batches.
const FILE_MIB: &[u64] = &[8, 32, 128];

fn write_fixture_file(dir: &Path, mib: u64) -> PathBuf {
    // Pseudo-randomized bytes so FastCDC sees real boundary candidates
    // instead of running the whole file as one max-sized chunk — same
    // construction `chunk_hash_fanout.rs` uses.
    let n = (mib * 1024 * 1024) as usize;
    let mut data = Vec::with_capacity(n);
    let mut state: u64 = 0x00C0_FFEE ^ mib;
    for _ in 0..n {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        data.push((z & 0xFF) as u8);
    }
    let path = dir.join(format!("big-{mib}mib.bin"));
    std::fs::write(&path, &data).expect("write fixture");
    path
}

/// Build a real chunked-blob tree for a single `mib`-sized file and
/// durably store it. The returned store's tempdir must outlive the
/// restore calls; the source-file tempdir does not need to (its bytes
/// are already content-addressed into the store by `build_tree`).
fn build_source_tree(mib: u64) -> (TempDir, ObjectStore, Hash) {
    let src_dir = tempfile::tempdir().expect("tempdir");
    write_fixture_file(src_dir.path(), mib);

    let (store_dir, store) = fresh_store();
    let wb = store.batch();
    let tree_hash = worktree::build_tree(&wb, src_dir.path()).expect("build tree");
    wb.commit().expect("commit");
    (store_dir, store, tree_hash)
}

fn bench_file_restore(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &mib in FILE_MIB {
        let axis = format!("{mib}_mib");
        let (_store_dir, store, tree_hash) = build_source_tree(mib);

        let seq_ms = time_one_with_setup(
            1,
            5,
            || tempfile::tempdir().expect("tempdir"),
            |target_dir| {
                restore_tree_to_worktree(
                    &store,
                    &tree_hash,
                    target_dir.path(),
                    &RestoreOptions::default(),
                )
                .expect("restore");
            },
        ) * 1000.0;

        let par_ms = time_one_with_setup(
            1,
            5,
            || tempfile::tempdir().expect("tempdir"),
            |target_dir| {
                restore_tree_to_worktree_with(
                    &store,
                    &tree_hash,
                    target_dir.path(),
                    &RestoreOptions::default(),
                    &|store: &ObjectStore, hashes: &[Hash]| {
                        hashes
                            .par_iter()
                            .map(|h| match store.read_object(h)? {
                                Object::Blob(b) => Ok(b.data),
                                _ => Err(RestoreError::NotABlob),
                            })
                            .collect()
                    },
                )
                .expect("restore");
            },
        ) * 1000.0;

        eprintln!(
            "restore_chunk_fanout/file/{axis}: sequential {seq_ms:.4} ms, rayon {par_ms:.4} ms"
        );
        samples.push(Sample {
            category: "restore_chunk_fanout".into(),
            axis: format!("file/{axis}"),
            library: "sequential".into(),
            value: seq_ms,
            unit: Unit::Millis,
        });
        samples.push(Sample {
            category: "restore_chunk_fanout".into(),
            axis: format!("file/{axis}"),
            library: "rayon".into(),
            value: par_ms,
            unit: Unit::Millis,
        });
    }

    let _ = c;
    mkit_benches::write_summary("restore_chunk_fanout_file", &samples);
}

criterion_group!(benches, bench_batch_fanout, bench_file_restore);
criterion_main!(benches);
