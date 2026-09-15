//! Sequential-vs-rayon crossover for a single large file's *intra-file*
//! chunk-hashing fan-out: `worktree::store_large_file_streaming_with`'s
//! `hash_chunks` batch callback (the path `mkit-cli`'s `commands::add`
//! wires a rayon fan-out into via `hash_pending`).
//!
//! Every other fan-out already benchmarked in this crate
//! (`add_hash_fanout`, `pack_build_fanout`, `verify_fanout`,
//! `delta_plan_fanout`) parallelizes across independent *files/objects*.
//! None of them help a worktree with a single huge file — the exact
//! shape of the "Add + Commit One 1 GiB File" row on the mkit.sh
//! performance page — because there's nothing else to fan out across.
//! This bench isolates the one fan-out that does: once FastCDC has cut
//! a batch of a large file's chunks, hashing (BLAKE3, via
//! `ObjectSink::put_parts`) and staging each chunk's temp file is
//! independent of every other chunk in the batch.
//!
//! Two shapes are measured:
//!
//! - `batch/<n>_chunks`: the per-batch crossover in isolation — `n`
//!   synthetic ~64 KiB chunks (matching `chunker::AVG_SIZE`), sequential
//!   vs rayon, mirroring `add_hash_fanout`'s per-file sweep but for
//!   chunks within `store_large_file_streaming_with`'s
//!   `STREAM_HASH_BATCH` (64-chunk) batches.
//! - `file/<n>_mib`: end-to-end streaming ingest of one real file (real
//!   FastCDC cuts, real temp-file writes via a `WriteBatch`), sequential
//!   (`hash_file_with_metadata`) vs fully rayon-fanned
//!   (`hash_file_with_metadata_with` with every batch fanned out) — the
//!   number comparable to the CLI-level hyperfine rows on the
//!   performance page.

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one_with_setup};
use mkit_core::chunker::AVG_SIZE;
use mkit_core::layout::RepoLayout;
use mkit_core::store::ObjectStore;
use mkit_core::worktree::{self, store_chunk_blob};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Chunk-batch sizes spanning `store_large_file_streaming_with`'s
/// `STREAM_HASH_BATCH` cap (64) — tiny (dispatch overhead should
/// dominate) through a full batch.
const BATCH_COUNTS: &[usize] = &[1, 2, 4, 8, 16, 32, 64];

/// Deterministic, distinct per-chunk content at `chunker::AVG_SIZE` —
/// every chunk hashes to a different object, so no dedup short-circuits
/// the per-chunk hash + temp-file write this bench measures.
fn chunk_bytes(i: usize) -> Vec<u8> {
    let mut v = format!("mkit chunk-hash-fanout bench fixture #{i}\n").into_bytes();
    v.resize(AVG_SIZE, b'x');
    v
}

fn fresh_store() -> (TempDir, ObjectStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).expect("init store");
    (dir, store)
}

fn bench_batch_fanout(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &n in BATCH_COUNTS {
        let axis = format!("{n}_chunks");
        let batch: Vec<Vec<u8>> = (0..n).map(chunk_bytes).collect();

        let seq_ms = time_one_with_setup(2, 20, fresh_store, |(_dir, store)| {
            let wb = store.batch();
            let _: Vec<_> = batch
                .iter()
                .map(|c| store_chunk_blob(&wb, c).expect("store chunk"))
                .collect();
        }) * 1000.0;

        let par_ms = time_one_with_setup(2, 20, fresh_store, |(_dir, store)| {
            let wb = store.batch();
            let _: Vec<_> = batch
                .par_iter()
                .map(|c| store_chunk_blob(&wb, c).expect("store chunk"))
                .collect();
        }) * 1000.0;

        eprintln!(
            "chunk_hash_fanout/batch/{axis}: sequential {seq_ms:.4} ms, rayon {par_ms:.4} ms"
        );
        samples.push(Sample {
            category: "chunk_hash_fanout".into(),
            axis: format!("batch/{axis}"),
            library: "sequential".into(),
            value: seq_ms,
            unit: Unit::Millis,
        });
        samples.push(Sample {
            category: "chunk_hash_fanout".into(),
            axis: format!("batch/{axis}"),
            library: "rayon".into(),
            value: par_ms,
            unit: Unit::Millis,
        });
    }

    let _ = c;
    mkit_benches::write_summary("chunk_hash_fanout_batch", &samples);
}

/// File sizes for the end-to-end streaming-ingest comparison — large
/// enough to need several `STREAM_HASH_BATCH`-sized batches.
const FILE_MIB: &[u64] = &[8, 32, 128];

fn write_fixture_file(dir: &Path, mib: u64) -> PathBuf {
    // Pseudo-randomized bytes so FastCDC sees real boundary candidates
    // instead of running the whole file as one max-sized chunk — same
    // construction `worktree.rs`'s own `large_file_becomes_chunked_blob`
    // test uses.
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

fn setup_file(mib: u64) -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_fixture_file(dir.path(), mib);
    (dir, path)
}

fn bench_file_ingest(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &mib in FILE_MIB {
        let axis = format!("{mib}_mib");

        let seq_ms = time_one_with_setup(
            1,
            5,
            || setup_file(mib),
            |(_dir, path)| {
                let (_sd, store) = fresh_store();
                worktree::hash_file_with_metadata(&store, &path).expect("hash");
            },
        ) * 1000.0;

        let par_ms = time_one_with_setup(
            1,
            5,
            || setup_file(mib),
            |(_dir, path)| {
                let (_sd, store) = fresh_store();
                worktree::hash_file_with_metadata_with(&store, &path, |sink, batch| {
                    batch
                        .par_iter()
                        .map(|c| store_chunk_blob(sink, c))
                        .collect()
                })
                .expect("hash");
            },
        ) * 1000.0;

        eprintln!("chunk_hash_fanout/file/{axis}: sequential {seq_ms:.4} ms, rayon {par_ms:.4} ms");
        samples.push(Sample {
            category: "chunk_hash_fanout".into(),
            axis: format!("file/{axis}"),
            library: "sequential".into(),
            value: seq_ms,
            unit: Unit::Millis,
        });
        samples.push(Sample {
            category: "chunk_hash_fanout".into(),
            axis: format!("file/{axis}"),
            library: "rayon".into(),
            value: par_ms,
            unit: Unit::Millis,
        });
    }

    let _ = c;
    mkit_benches::write_summary("chunk_hash_fanout_file", &samples);
}

criterion_group!(benches, bench_batch_fanout, bench_file_ingest);
criterion_main!(benches);
