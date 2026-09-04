//! Sequential-vs-rayon crossover for pack building's per-entry
//! zstd-compression fan-out (`prepare_raw_batch` in `mkit-cli`'s
//! `remote_dispatch/mod.rs`, backed by `PackWriter::prepare_raw`).
//!
//! `build_and_upload_packs` used to call `store.read` + `PackWriter::
//! push_raw` (disk read + zstd compress + buffer append, all
//! sequential) once per object in the push plan. Splitting the
//! CPU-bound compression step into a pure `PackWriter::prepare_raw`
//! function let it fan out across rayon before the writer's sequential
//! append — this bench isolates just that fan-out decision (mirroring
//! `add_hash_fanout.rs`'s isolation of `add`'s hash fan-out) so the
//! crossover point isn't drowned out by the surrounding plan/seal/
//! upload cost `push_delta.rs`'s end-to-end tests already cover.
//!
//! `mkit-cli`'s `prepare_raw_batch`/`pack_fanout_threshold` are
//! private, so this exercises the same public `mkit-core` entry point
//! (`PackWriter::prepare_raw`) directly, over synthetic in-memory
//! buffers rather than an on-disk store — isolating compression from
//! disk I/O the same way `add_hash_fanout.rs` isolates hashing from
//! the surrounding walk.

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one_with_setup};
use mkit_core::hash;
use mkit_core::pack::PackWriter;
use rayon::prelude::*;

/// Entry counts spanning the expected crossover — same shape as
/// `add_hash_fanout.rs`'s `COUNTS`.
const COUNTS: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 256];

/// A source-file-shaped payload: text-like and comfortably above
/// `pack::MIN_COMPRESS_LEN` (64 bytes, private to `pack.rs`) so every
/// entry actually pays the zstd pass this bench means to measure,
/// rather than short-circuiting on the "too small to bother"
/// pack-compression gate.
const ENTRY_SIZE: usize = 64 * 1024;

/// Deterministic, distinct per-entry content — every entry hashes (and
/// compresses) independently, matching `add_hash_fanout.rs`'s fixture
/// convention (no dedup/identical-buffer shortcut hiding real
/// per-entry cost).
fn entry_bytes(i: usize) -> Vec<u8> {
    let mut v = format!("mkit pack-build fanout bench fixture #{i}\n").into_bytes();
    while v.len() < ENTRY_SIZE {
        v.extend_from_slice(b"mkit pack build fanout bench line of realistic source text\n");
    }
    v.truncate(ENTRY_SIZE);
    v
}

/// `n` distinct `(hash, bytes)` pairs — precomputed hashes so the
/// timed closure spends its time on `prepare_raw`, not BLAKE3.
fn setup(n: usize) -> Vec<(hash::Hash, Vec<u8>)> {
    (0..n)
        .map(|i| {
            let bytes = entry_bytes(i);
            (hash::hash(&bytes), bytes)
        })
        .collect()
}

fn bench_pack_build_fanout(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &n in COUNTS {
        let axis = format!("{n}_entries");

        let seq_ms = time_one_with_setup(
            2,
            20,
            || setup(n),
            |entries| {
                let mut w = PackWriter::new();
                for (h, bytes) in entries {
                    let prepared = PackWriter::prepare_raw(h, bytes);
                    w.push_prepared_raw(prepared).expect("push prepared raw");
                }
            },
        ) * 1000.0;

        let par_ms = time_one_with_setup(
            2,
            20,
            || setup(n),
            |entries| {
                let prepared: Vec<_> = entries
                    .into_par_iter()
                    .map(|(h, bytes)| PackWriter::prepare_raw(h, bytes))
                    .collect();
                let mut w = PackWriter::new();
                for p in prepared {
                    w.push_prepared_raw(p).expect("push prepared raw");
                }
            },
        ) * 1000.0;

        eprintln!("pack_build_fanout/{axis}: sequential {seq_ms:.4} ms, rayon {par_ms:.4} ms");
        samples.push(Sample {
            category: "pack_build_fanout".into(),
            axis: axis.clone(),
            library: "sequential".into(),
            value: seq_ms,
            unit: Unit::Millis,
        });
        samples.push(Sample {
            category: "pack_build_fanout".into(),
            axis,
            library: "rayon".into(),
            value: par_ms,
            unit: Unit::Millis,
        });
    }

    // criterion's own harness is unused here (see `add_hash_fanout.rs`'s
    // module doc for the rationale) — `c` is still threaded through so
    // this stays a normal criterion-managed bench target for `cargo
    // bench`/CI discovery.
    let _ = c;

    mkit_benches::write_summary("pack_build_fanout", &samples);
}

criterion_group!(benches, bench_pack_build_fanout);
criterion_main!(benches);
