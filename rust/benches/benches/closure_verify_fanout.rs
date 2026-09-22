//! Closure (full-disclosure) verification's pre-pass wallclock across
//! object counts, spanning `index_supplied_objects`/
//! `index_pack_entries`'s fan-out threshold.
//!
//! `verify_closure_packs` — the path `mkit closure verify --manifest`
//! and `verify_closure_manifest` (a downloaded closure bundle's
//! verification) actually run — used to deserialize and BLAKE3/BMT
//! re-derive the id of every supplied object twice: once in a serial
//! pre-pass that built the id → payload-range lookup index, then again
//! inside `walk_closure`'s own re-derivation (kept deliberately
//! separate — see that function's doc: the walker is the sole identity
//! authority, so it never trusts a source's own id decision). The
//! pre-pass is a pure, independent map per object, so it now fans out
//! across a `std::thread::scope` worker pool once a closure has enough
//! objects to be worth it (`mkit-core/src/verify/closure.rs`'s
//! `index_pack_entries`), the same shape `verify_fanout.rs` already
//! measures for post-fetch signature verification. `walk_closure`'s own
//! re-derivation pass is untouched (still serial — it is the
//! security-critical half) so the achievable end-to-end win is roughly
//! bounded by halving the double-hash cost, not eliminating it.
//!
//! This bench has no lever to force the old always-sequential
//! behavior (it was replaced, not made optional) — like
//! `pack_unpack_fanout.rs`, it just reports wallclock at each object
//! count; compare against a build of `verify_closure_packs` from
//! before that change to see the delta directly.
//!
//! `CLOSURE_ENTRIES_PER_THREAD` is 1024, not `pack::stage_raw_entries`'s
//! 8: this bench is exactly what that constant's doc comment in
//! `closure.rs` cites measuring. An 8-entries-per-thread threshold (the
//! per-entry decompression cost `pack_unpack_fanout.rs` fans out at)
//! made this pre-pass *slower* than sequential from ~64 through ~1024
//! entries — thread-spawn cost dominates a sub-microsecond per-item
//! deserialize+hash — and only paid off past a few thousand entries.
//! `COUNTS` spans well below and well above the tuned threshold so a
//! regression at the low end (spawning threads too eagerly) or a
//! vanished win at the high end (retuned too conservatively) both show
//! up here.

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one_with_setup};
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::ops::graph::ClosureMode;
use mkit_core::sign::{KeyPair, sign_commit};
use mkit_core::store::ObjectStore;
use mkit_core::verify::{export_closure, verify_closure_packs};
use tempfile::TempDir;

/// Object counts spanning the pre-pass fan-out threshold
/// (`CLOSURE_ENTRIES_PER_THREAD` entries per available thread, tuned to
/// 1024 — see that constant's doc in `mkit-core/src/verify/closure.rs`):
/// well below it on any machine (16-256), around where a 4-core box
/// crosses it (1024-4096), and comfortably past it everywhere (16384).
/// Each count is a tree of that many blob entries plus the tree and its
/// signed commit, so the closure's total object count is `n + 2`.
const COUNTS: &[usize] = &[16, 64, 256, 1024, 4096, 16384];

/// A source-file-shaped blob body, comfortably above `pack::MIN_COMPRESS_LEN`
/// so this matches a real small tracked file rather than a near-empty
/// fixture the id-derivation cost would be trivial for.
const BLOB_SIZE: usize = 512;

fn blob_bytes(i: usize) -> Vec<u8> {
    let mut v = format!("mkit closure-verify fanout bench fixture #{i}\n").into_bytes();
    while v.len() < BLOB_SIZE {
        v.extend_from_slice(b"mkit closure verify fanout bench line of realistic text\n");
    }
    v.truncate(BLOB_SIZE);
    v
}

/// Build a real store with `n` distinct blobs under one tree, commit
/// it, and export a raw-only closure — the exact `export_closure` →
/// `verify_closure_packs` round trip `mkit closure export`/`verify`
/// drive — so the bench exercises the real wire format, not a
/// synthetic shortcut.
fn build_closure(n: usize) -> (Vec<u8>, Vec<Vec<u8>>, mkit_core::hash::Hash) {
    let dir = TempDir::new().expect("tempdir");
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("init store");

    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let bytes = blob_bytes(i);
        let object = Object::Blob(mkit_core::object::Blob { data: bytes });
        let serialized = mkit_core::serialize::serialize(&object).expect("serialize blob");
        let hash = store.write(&serialized).expect("write blob");
        entries.push(TreeEntry {
            name: format!("f{i:06}.txt").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: hash,
        });
    }
    let tree_hash = store
        .write(
            &mkit_core::serialize::serialize(&Object::Tree(Tree { entries }))
                .expect("serialize tree"),
        )
        .expect("write tree");

    let kp = KeyPair::from_seed([0x42; 32]);
    let mut commit = Commit {
        tree_hash,
        parents: vec![],
        author: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"closure verify fanout bench fixture".to_vec(),
        timestamp: 1,
        message_hash: mkit_core::hash::ZERO,
        content_digest: mkit_core::hash::ZERO,
        signature: [0u8; 64],
    };
    commit.signature = sign_commit(&commit, &kp).expect("sign commit").0;
    let commit_id = store
        .write(&mkit_core::serialize::serialize(&Object::Commit(commit)).expect("serialize commit"))
        .expect("write commit");

    let export = export_closure(&store, &commit_id, ClosureMode::Snapshot).expect("export closure");
    (export.manifest, export.packs, commit_id)
}

fn bench_closure_verify_fanout(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &n in COUNTS {
        let axis = format!("{n}_objects");
        let (_manifest, packs, commit_id) = build_closure(n);
        let pack_refs: Vec<&[u8]> = packs.iter().map(Vec::as_slice).collect();

        let ms = time_one_with_setup(
            1,
            10,
            || (),
            |()| {
                let report = verify_closure_packs(&commit_id, ClosureMode::Snapshot, &pack_refs)
                    .expect("verify closure");
                assert!(report.is_complete());
            },
        ) * 1000.0;

        eprintln!("closure_verify_fanout/{axis}: {ms:.4} ms");
        samples.push(Sample {
            category: "closure_verify_fanout".into(),
            axis,
            library: "mkit (verify_closure_packs)".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }

    // criterion's own harness is unused here (see `add_hash_fanout.rs`'s
    // module doc for the rationale) — `c` is still threaded through so
    // this stays a normal criterion-managed bench target for `cargo
    // bench`/CI discovery.
    let _ = c;

    mkit_benches::write_summary("closure_verify_fanout", &samples);
}

criterion_group!(benches, bench_closure_verify_fanout);
criterion_main!(benches);
