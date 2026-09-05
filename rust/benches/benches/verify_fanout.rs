//! Sequential-vs-rayon crossover for `clone`/`pull`/`fetch`'s
//! post-download signature-verification pass
//! (`verify_new_object_signatures` in `mkit-cli`'s
//! `remote_dispatch/packmap.rs`, issue #692).
//!
//! That function walks every commit/remix/tag a fetch just introduced,
//! doing `store.read_object` (disk read + BLAKE3 re-hash, since
//! `ObjectStore::read` verifies content-addressing) followed by an
//! Ed25519 `verify_strict` — both CPU-bound and independent per object,
//! same shape as `add_hash_fanout.rs`'s per-file hashing fan-out and
//! `pack_build_fanout.rs`'s per-entry compression fan-out. This bench
//! isolates just that fan-out decision so the crossover point isn't
//! drowned out by the surrounding download/unpack cost.
//!
//! `verify_new_object_signatures` itself is private to `mkit-cli`, so
//! this exercises the same `store.read_object` + `mkit_core::sign::
//! verify_commit` pair directly, over a real on-disk `ObjectStore`
//! (matching `add_hash_fanout.rs`'s choice to keep real disk I/O in
//! scope rather than isolate pure-CPU work only).

use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Commit, Identity, Object};
use mkit_core::serialize::serialize;
use mkit_core::sign::{self, KeyPair};
use mkit_core::store::ObjectStore;

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one_with_setup};
use rayon::prelude::*;
use tempfile::TempDir;

/// Commit counts spanning the expected crossover — same shape as
/// `add_hash_fanout.rs`'s `COUNTS`.
const COUNTS: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 256];

/// A validly-signed commit whose message makes every instance hash
/// (and therefore verify) independently — no dedup shortcut hiding
/// real per-commit cost, matching `add_hash_fanout.rs`'s fixture
/// convention.
fn signed_commit_bytes(kp: &KeyPair, i: usize) -> Vec<u8> {
    let mut c = Commit::new_unannotated(
        mkit_core::hash::hash(format!("tree #{i}").as_bytes()),
        Vec::new(),
        Identity::ed25519(kp.public.0),
        kp.public.0,
        format!("mkit verify-fanout bench fixture #{i}").into_bytes(),
        1_700_000_000 + i as u64,
        [0u8; 64],
    );
    c.signature = sign::sign_commit(&c, kp).expect("sign commit").0;
    serialize(&Object::Commit(c)).expect("serialize commit")
}

/// Fresh tempdir + store populated with `n` distinct signed commits,
/// rebuilt every iteration (warmup and timed alike) so no run dedups
/// against a prior iteration's writes.
fn setup(n: usize) -> (TempDir, ObjectStore, Vec<Hash>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).expect("init store");
    let kp = KeyPair::generate().expect("keypair");
    let hashes = (0..n)
        .map(|i| {
            store
                .write(&signed_commit_bytes(&kp, i))
                .expect("write commit")
        })
        .collect();
    (dir, store, hashes)
}

fn verify_one(store: &ObjectStore, h: &Hash) {
    let Object::Commit(c) = store.read_object(h).expect("read object") else {
        panic!("expected commit");
    };
    sign::verify_commit(&c).expect("verify ok");
}

fn bench_verify_fanout(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &n in COUNTS {
        let axis = format!("{n}_commits");

        let seq_ms = time_one_with_setup(
            2,
            20,
            || setup(n),
            |(_dir, store, hashes)| {
                for h in hashes.iter() {
                    verify_one(&store, h);
                }
            },
        ) * 1000.0;

        let par_ms = time_one_with_setup(
            2,
            20,
            || setup(n),
            |(_dir, store, hashes)| {
                hashes.par_iter().for_each(|h| verify_one(&store, h));
            },
        ) * 1000.0;

        eprintln!("verify_fanout/{axis}: sequential {seq_ms:.4} ms, rayon {par_ms:.4} ms");
        samples.push(Sample {
            category: "verify_fanout".into(),
            axis: axis.clone(),
            library: "sequential".into(),
            value: seq_ms,
            unit: Unit::Millis,
        });
        samples.push(Sample {
            category: "verify_fanout".into(),
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

    mkit_benches::write_summary("verify_fanout", &samples);
}

criterion_group!(benches, bench_verify_fanout);
criterion_main!(benches);
