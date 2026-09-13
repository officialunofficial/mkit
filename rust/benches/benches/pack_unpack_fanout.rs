//! `PackReader::read` (unpack) wallclock across entry counts.
//!
//! Historically `read_inner` decompressed, validated, BLAKE3-hashed,
//! and disk-wrote every raw (`0x00`/`0x03`) entry one at a time on the
//! calling thread — the write side already fans this exact shape of
//! work (per-entry zstd compression, see `pack_build_fanout.rs`) out
//! across worker threads via `PackWriter::prepare_raw`/
//! `push_prepared_raw`, but the read side didn't have a counterpart, so
//! a `clone`/`fetch`'s unpack step ran single-threaded while its own
//! push side (on the far end) was parallel.
//!
//! `PackReader::read` now fans raw-entry preparation (decompress +
//! validate + hash) and staging (`WriteBatch::write_prehashed`, safe to
//! call concurrently by design) out across a `std::thread::scope`
//! worker pool once a pack has enough entries to be worth it — see
//! `stage_raw_entries` in `mkit-core/src/pack.rs`. This bench has no
//! lever to force the old sequential behavior (it was replaced, not
//! made optional), so it just reports wallclock at each entry count;
//! compare against a build of `PackReader::read` from before that
//! change to see the delta directly.

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one_with_setup};
use mkit_core::layout::RepoLayout;
use mkit_core::pack::{PackReader, PackWriter};
use mkit_core::store::ObjectStore;

/// Entry counts spanning the read-side fan-out's threshold (8 entries
/// per available thread — `stage_raw_entries`'s `ENTRIES_PER_THREAD`):
/// small enough to stay sequential on every machine, through large
/// enough to fan out on anything from a 2-core laptop to a 32-core CI
/// box.
const COUNTS: &[usize] = &[16, 64, 256, 1024, 4096];

/// A source-file-shaped payload — same shape as `pack_build_fanout.rs`'s
/// `ENTRY_SIZE` fixture, comfortably above `pack::MIN_COMPRESS_LEN` so
/// every entry pays a real decompress pass, matching a real chunked
/// blob on the wire.
const ENTRY_SIZE: usize = 64 * 1024;

fn entry_bytes(i: usize) -> Vec<u8> {
    let mut v = format!("mkit pack-unpack fanout bench fixture #{i}\n").into_bytes();
    while v.len() < ENTRY_SIZE {
        v.extend_from_slice(b"mkit pack unpack fanout bench line of realistic source text\n");
    }
    v.truncate(ENTRY_SIZE);
    v
}

/// Build a real v2 (zstd) pack of `n` distinct raw blob entries via the
/// public `PackWriter` API — exactly what a push plan builds — so the
/// bench exercises the real wire format `PackReader::read` decodes,
/// not a synthetic shortcut.
fn build_pack(n: usize) -> Vec<u8> {
    let mut w = PackWriter::new();
    for i in 0..n {
        let bytes = mkit_core::object::Object::Blob(mkit_core::object::Blob {
            data: entry_bytes(i),
        });
        let serialized = mkit_core::serialize::serialize(&bytes).expect("serialize blob");
        let h = mkit_core::hash::hash(&serialized);
        w.push_raw(h, &serialized).expect("push raw");
    }
    w.finish().expect("finish pack")
}

fn bench_pack_unpack_fanout(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &n in COUNTS {
        let axis = format!("{n}_entries");
        let pack_bytes = build_pack(n);

        // Fresh tempdir + store per timed iteration (like
        // `pack_create.rs`'s `pack/*/mkit` case) so every iteration
        // pays a real write, never a dedup no-op against a previous
        // iteration's objects.
        let ms = time_one_with_setup(
            1,
            10,
            || {
                let dir = tempfile::tempdir().unwrap();
                let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
                (dir, store)
            },
            |(_dir, store)| {
                PackReader::read(&pack_bytes, &store).expect("unpack");
            },
        ) * 1000.0;

        eprintln!("pack_unpack_fanout/{axis}: {ms:.4} ms");
        samples.push(Sample {
            category: "pack_unpack_fanout".into(),
            axis,
            library: "mkit (PackReader::read)".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }

    // criterion's own harness is unused here (see `add_hash_fanout.rs`'s
    // module doc for the rationale) — `c` is still threaded through so
    // this stays a normal criterion-managed bench target for `cargo
    // bench`/CI discovery.
    let _ = c;

    mkit_benches::write_summary("pack_unpack_fanout", &samples);
}

criterion_group!(benches, bench_pack_unpack_fanout);
criterion_main!(benches);
