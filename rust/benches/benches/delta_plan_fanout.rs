//! Sequential-vs-rayon crossover for push planning's per-candidate delta
//! encoding (`mkit-core`'s `transfer::encode_delta_candidate`, fanned out
//! via `mkit-cli`'s `remote_dispatch::encode_delta_candidates_batch`).
//!
//! `transfer::plan_pack` used to call `store.read` + `delta::encode`
//! (disk read + block-hash-table build + greedy scan, all sequential)
//! once per delta candidate while planning a push. Both steps are
//! CPU/IO-bound and independent across candidates — the same shape as
//! `pack_build_fanout.rs`'s compression fan-out and `verify_fanout.rs`'s
//! signature-verification fan-out — so `plan_pack_with` now takes an
//! `encode_deltas` batch callback the caller can fan out, instead of the
//! built-in sequential loop `plan_pack` still uses by default.
//!
//! This bench isolates just `delta::encode`'s cost (mirroring
//! `pack_build_fanout.rs`'s isolation of `PackWriter::prepare_raw` from
//! disk I/O and pack assembly) over synthetic near-duplicate
//! `(base, target)` pairs shaped like a FastCDC chunk with a small edit —
//! the common case a real push's changed-file diffing hits — rather than
//! exercising the full `plan_pack_with` plumbing (closure walk, base
//! selection) which `transfer.rs`'s own unit tests already cover.

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one_with_setup};
use mkit_core::delta;
use rayon::prelude::*;

/// Candidate counts spanning the expected crossover — same shape as
/// `pack_build_fanout.rs`'s `COUNTS`.
const COUNTS: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 256];

/// FastCDC's average chunk size (`AVG_SIZE` in `chunker.rs`) — delta
/// candidates are blobs, so this is the representative payload size.
const CHUNK_SIZE: usize = 64 * 1024;

/// A source-file-shaped base buffer: text-like, so `delta::encode`'s
/// 16-byte block hashing finds real repeated structure instead of
/// degenerating to all-INSERT on random bytes.
fn base_bytes(i: usize) -> Vec<u8> {
    let mut v = format!("mkit delta fanout bench fixture #{i}\n").into_bytes();
    while v.len() < CHUNK_SIZE {
        v.extend_from_slice(b"mkit delta plan fanout bench line of realistic source text\n");
    }
    v.truncate(CHUNK_SIZE);
    v
}

/// A small, localized edit of `base` — the common "one function changed"
/// shape a real push's chunk-level diffing sees, so most of the chunk
/// still matches and `delta::encode` walks its full hash-table path
/// rather than short-circuiting.
fn target_bytes(base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    let mid = v.len() / 2;
    let patch = b"-- edited line inserted by the delta fanout bench --\n";
    v.splice(mid..mid, patch.iter().copied());
    v
}

/// `n` distinct `(base, target)` pairs — distinct content per pair so no
/// candidate's encode is trivially cached/deduped by the allocator.
fn setup(n: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    (0..n)
        .map(|i| {
            let base = base_bytes(i);
            let target = target_bytes(&base);
            (base, target)
        })
        .collect()
}

fn bench_delta_plan_fanout(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &n in COUNTS {
        let axis = format!("{n}_candidates");

        let seq_ms = time_one_with_setup(
            2,
            20,
            || setup(n),
            |pairs| {
                for (base, target) in &pairs {
                    let _ = delta::encode(base, target).expect("encode");
                }
            },
        ) * 1000.0;

        let par_ms = time_one_with_setup(
            2,
            20,
            || setup(n),
            |pairs| {
                let _: Vec<_> = pairs
                    .par_iter()
                    .map(|(base, target)| delta::encode(base, target).expect("encode"))
                    .collect();
            },
        ) * 1000.0;

        eprintln!("delta_plan_fanout/{axis}: sequential {seq_ms:.4} ms, rayon {par_ms:.4} ms");
        samples.push(Sample {
            category: "delta_plan_fanout".into(),
            axis: axis.clone(),
            library: "sequential".into(),
            value: seq_ms,
            unit: Unit::Millis,
        });
        samples.push(Sample {
            category: "delta_plan_fanout".into(),
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

    mkit_benches::write_summary("delta_plan_fanout", &samples);
}

criterion_group!(benches, bench_delta_plan_fanout);
criterion_main!(benches);
