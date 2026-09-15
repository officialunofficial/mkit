//! `worktree::content_eq` wallclock across the shapes that motivate it:
//! same content re-stored (dedup fast path, `a == b`), a small append, a
//! single-byte in-place edit, and a truncation — each against a large
//! `FastCDC`-chunked base file. This is the regression guard for the
//! id-skip fast path in `chunked_content_eq` (`worktree/blob.rs`): every
//! call site that decides "did this file change?" (`add`, `status`,
//! `diff`, `merge`) goes through `content_eq` once the object ids
//! already differ, and previously re-read and byte-compared every chunk
//! of *both* sides regardless of how much content they actually shared.
//!
//! Numbers are wallclock ms; smaller is better. `append` is the
//! motivating case — mkit.sh/performance's "commit a 1 MiB change to a
//! 100 MiB file" row — where every chunk before the append still lines
//! up by hash, so the optimized path needs zero chunk reads at all.

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one_with_setup};
use mkit_core::layout::RepoLayout;
use mkit_core::store::ObjectStore;
use mkit_core::worktree::{self, content_eq};

/// Base file sizes, all well above `worktree::CHUNK_THRESHOLD` so every
/// case actually exercises `ChunkedBlob` manifests, not inline blobs.
const SIZES_MIB: &[u64] = &[8, 32];

/// Deterministic pseudo-random bytes so FastCDC sees real cut points
/// (matching `chunk_hash_fanout.rs`'s and `worktree.rs`'s own test
/// fixture construction) instead of one run-length-maxed chunk.
fn fixture(mib: u64) -> Vec<u8> {
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
    data
}

fn setup(
    base: &[u8],
    mutate: fn(&[u8]) -> Vec<u8>,
) -> (tempfile::TempDir, ObjectStore, [u8; 32], [u8; 32]) {
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    let a = worktree::store_file_object(&store, base).unwrap();
    let mutated = mutate(base);
    let b = worktree::store_file_object(&store, &mutated).unwrap();
    (dir, store, a, b)
}

/// A mutation scenario: a name and the function producing the mutated
/// bytes from the fixture base. Named so clippy's `type_complexity`
/// lint (`-D warnings` under `--all-features`) doesn't flag the bare
/// slice-of-tuple-of-function-pointer type spelled out inline.
type Scenario = (&'static str, fn(&[u8]) -> Vec<u8>);

fn bench_content_eq(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    let scenarios: &[Scenario] = &[
        ("identical", |base| base.to_vec()),
        ("append_1mib", |base| {
            let mut v = base.to_vec();
            v.extend(std::iter::repeat_n(0xAB_u8, 1024 * 1024));
            v
        }),
        ("edit_middle_byte", |base| {
            let mut v = base.to_vec();
            let mid = v.len() / 2;
            v[mid] ^= 0xFF;
            v
        }),
        ("truncate_1mib", |base| {
            base[..base.len() - 1024 * 1024].to_vec()
        }),
    ];

    for &mib in SIZES_MIB {
        let base = fixture(mib);
        for &(name, mutate) in scenarios {
            let axis = format!("{mib}_mib/{name}");
            let ms = time_one_with_setup(
                1,
                5,
                || setup(&base, mutate),
                |(_dir, store, a, b)| {
                    let _ = content_eq(&store, &a, &b).unwrap();
                },
            ) * 1000.0;

            eprintln!("content_eq/{axis}: {ms:.4} ms");
            samples.push(Sample {
                category: "content_eq".into(),
                axis,
                library: "content_eq".into(),
                value: ms,
                unit: Unit::Millis,
            });
        }
    }

    let _ = c;
    mkit_benches::write_summary("content_eq", &samples);
}

criterion_group!(benches, bench_content_eq);
criterion_main!(benches);
