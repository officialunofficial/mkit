//! Hashing throughput: BLAKE3 (mkit's primitive) vs SHA-1 (git's
//! default) vs SHA-256 (git's experimental hash) vs BLAKE2b. All
//! libraries hash the SAME random buffer at four sizes covering the
//! object spectrum mkit sees in practice (small commits → blob).
//!
//! Output: `target/criterion/<bench>/<size>/estimates.json`. The
//! `render-charts` binary reads these and emits SVGs.
//!
//! We also emit a flattened JSON summary at
//! `target/bench-results/hashing.json` so the renderer doesn't need
//! to re-implement criterion's dir layout discovery.

use std::fs;
use std::path::Path;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit};

const SIZES: &[(usize, &str)] = &[
    (1024, "1 KiB"),
    (64 * 1024, "64 KiB"),
    (1024 * 1024, "1 MiB"),
    (16 * 1024 * 1024, "16 MiB"),
];

fn random_buffer(n: usize) -> Vec<u8> {
    // Deterministic, dataset-stable PRNG. Sample bytes from a fixed
    // LCG so reruns produce identical inputs and the throughput
    // numbers are diff-able across commits.
    let mut state: u64 = 0xdead_beef_cafe_d00d;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        out.push((state >> 56) as u8);
    }
    out
}

fn bench_hashing(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &(n, axis) in SIZES {
        let buf = random_buffer(n);
        let mut group = c.benchmark_group(format!("hashing/{axis}"));
        group.throughput(Throughput::Bytes(n as u64));

        // BLAKE3 — mkit's primitive.
        group.bench_with_input(BenchmarkId::new("BLAKE3 (mkit)", n), &buf, |b, buf| {
            b.iter(|| mkit_core::hash::hash(buf));
        });
        samples.push(Sample {
            category: "hashing".into(),
            axis: axis.into(),
            library: "BLAKE3 (mkit)".into(),
            value: throughput_mib(
                n,
                time_one(|| {
                    let _ = mkit_core::hash::hash(&buf);
                }),
            ),
            unit: Unit::MibPerSec,
        });

        // SHA-1 — git's default object hash.
        group.bench_with_input(BenchmarkId::new("SHA-1 (git)", n), &buf, |b, buf| {
            use sha1::{Digest, Sha1};
            b.iter(|| Sha1::digest(buf));
        });
        samples.push(Sample {
            category: "hashing".into(),
            axis: axis.into(),
            library: "SHA-1 (git)".into(),
            value: throughput_mib(
                n,
                time_one(|| {
                    use sha1::{Digest, Sha1};
                    let _ = Sha1::digest(&buf);
                }),
            ),
            unit: Unit::MibPerSec,
        });

        // SHA-256 — git's experimental object hash.
        group.bench_with_input(
            BenchmarkId::new("SHA-256 (git-sha256)", n),
            &buf,
            |b, buf| {
                use sha2::{Digest, Sha256};
                b.iter(|| Sha256::digest(buf));
            },
        );
        samples.push(Sample {
            category: "hashing".into(),
            axis: axis.into(),
            library: "SHA-256 (git-sha256)".into(),
            value: throughput_mib(
                n,
                time_one(|| {
                    use sha2::{Digest, Sha256};
                    let _ = Sha256::digest(&buf);
                }),
            ),
            unit: Unit::MibPerSec,
        });

        // BLAKE2b — comparison anchor.
        group.bench_with_input(BenchmarkId::new("BLAKE2b", n), &buf, |b, buf| {
            use blake2::{Blake2b512, Digest};
            b.iter(|| Blake2b512::digest(buf));
        });
        samples.push(Sample {
            category: "hashing".into(),
            axis: axis.into(),
            library: "BLAKE2b".into(),
            value: throughput_mib(
                n,
                time_one(|| {
                    use blake2::{Blake2b512, Digest};
                    let _ = Blake2b512::digest(&buf);
                }),
            ),
            unit: Unit::MibPerSec,
        });

        group.finish();
    }

    write_summary("hashing", &samples);
}

/// Time a single closure invocation in seconds. Used to populate the
/// summary JSON the renderer reads — criterion writes its own
/// per-iteration estimates, but those are buried in nested dirs and
/// we want a flat shape.
fn time_one<F: FnMut()>(mut f: F) -> f64 {
    // Run a few warm iterations, then a fixed batch of measured ones.
    for _ in 0..50 {
        f();
    }
    let n: u32 = 200;
    let t0 = std::time::Instant::now();
    for _ in 0..n {
        f();
    }
    t0.elapsed().as_secs_f64() / f64::from(n)
}

fn throughput_mib(bytes: usize, seconds_per_iter: f64) -> f64 {
    let mib = bytes as f64 / (1024.0 * 1024.0);
    mib / seconds_per_iter
}

fn write_summary(category: &str, samples: &[Sample]) {
    // Resolve the workspace target dir from CARGO_MANIFEST_DIR so we
    // don't depend on the criterion harness's current working dir.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    let dir = Path::new(&manifest)
        .parent()
        .map(|p| p.join("target/bench-results"))
        .unwrap_or_else(|| Path::new("target/bench-results").to_path_buf());
    let _ = fs::create_dir_all(&dir);
    let path = dir.join(format!("{category}.json"));
    let body = serde_json::to_string_pretty(samples).expect("serialize samples");
    if let Err(e) = fs::write(&path, body) {
        eprintln!("warning: could not write {}: {e}", path.display());
    } else {
        eprintln!("wrote {}", path.display());
    }
}

criterion_group!(benches, bench_hashing);
criterion_main!(benches);
