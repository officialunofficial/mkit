//! `delta::encode`'s byte-by-byte miss scan, isolated from
//! `delta_plan_fanout.rs`'s sequential-vs-rayon question.
//!
//! `delta::encode` (`mkit-core/src/delta.rs`) finds `BLOCK_SIZE`-aligned
//! matches between `base` and `target` via a hash table keyed by
//! `block_hash`. Every position the scan visits *without* a match (the
//! common case once the two inputs diverge) used to call `block_hash`
//! again from scratch — an O(`BLOCK_SIZE`) pass over the next 16-byte
//! window — before advancing by a single byte. That makes the miss-scan
//! O(n * `BLOCK_SIZE`) instead of O(n).
//!
//! This bench isolates that cost across a similarity spectrum: content
//! that resyncs almost immediately (`near_duplicate`, the shape
//! `delta_plan_fanout.rs` already covers) down to content with no
//! matches at all (`random_no_match`, where *every* scanned position is
//! a miss and the per-byte hash cost dominates end to end). That axis is
//! the worst case the O(`BLOCK_SIZE`)-per-byte recompute hits hardest.

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, Xorshift, time_one_with_setup};
use mkit_core::delta;

/// Payload size for every case — FastCDC's average chunk size
/// (`AVG_SIZE` in `chunker.rs`), the representative blob size
/// `delta::encode` runs on in practice.
const SIZE: usize = 64 * 1024;

/// Text-like, highly repetitive base — the shape `delta_plan_fanout.rs`
/// uses, where most of a near-duplicate target resyncs within a few
/// bytes of any edit.
fn text_base() -> Vec<u8> {
    let mut v = Vec::with_capacity(SIZE);
    while v.len() < SIZE {
        v.extend_from_slice(b"mkit delta scan bench line of realistic source text\n");
    }
    v.truncate(SIZE);
    v
}

/// One case in the similarity spectrum: how to derive `(base, target)`,
/// and whether the pair is expected to share any `BLOCK_SIZE`-aligned
/// structure at all. Each `make` is called fresh per bench iteration
/// (see `time_one_with_setup`), so it takes no seed/index — every case's
/// fixture is fixed content by design, not varied across iterations.
struct Case {
    name: &'static str,
    make: fn() -> (Vec<u8>, Vec<u8>),
}

const CASES: &[Case] = &[
    Case {
        name: "near_duplicate",
        make: || {
            let base = text_base();
            let mut target = base.clone();
            let mid = target.len() / 2;
            target.splice(mid..mid, b"-- edited line --\n".iter().copied());
            (base, target)
        },
    },
    Case {
        name: "half_similar",
        // Second half of target is unrelated random bytes: the scan
        // spends its first half mostly matching, its second half
        // entirely missing.
        make: || {
            let base = text_base();
            let mut target = base[..base.len() / 2].to_vec();
            target.extend(Xorshift::new(0xC0FF_EE00).bytes(SIZE / 2));
            (base, target)
        },
    },
    Case {
        name: "random_no_match",
        // Independent random base/target: no `BLOCK_SIZE`-aligned
        // match is ever found, so every position in the scan is a
        // miss — the worst case for a non-incremental block_hash.
        make: || {
            let base = Xorshift::new(0x1234_5678).bytes(SIZE);
            let target = Xorshift::new(0x8765_4321).bytes(SIZE);
            (base, target)
        },
    },
];

fn bench_delta_encode_scan(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for case in CASES {
        let ms = time_one_with_setup(20, 300, case.make, |(base, target)| {
            let _ = delta::encode(&base, &target).expect("encode");
        }) * 1000.0;

        eprintln!("delta_encode_scan/{}: {ms:.4} ms", case.name);
        samples.push(Sample {
            category: "delta_encode_scan".into(),
            axis: case.name.into(),
            library: "mkit".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }

    // criterion's own harness is unused here (see `add_hash_fanout.rs`'s
    // module doc for the rationale) — `c` is still threaded through so
    // this stays a normal criterion-managed bench target for `cargo
    // bench`/CI discovery.
    let _ = c;

    mkit_benches::write_summary("delta_encode_scan", &samples);
}

criterion_group!(benches, bench_delta_encode_scan);
criterion_main!(benches);
