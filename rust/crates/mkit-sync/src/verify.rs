//! Post-fetch signature verification of newly introduced objects.
//!
//! A hostile remote can otherwise push an unsigned or forged history that a
//! clone, pull or fetch would silently materialise. Every commit, remix and
//! tag a fetch introduces is checked with the same function `mkit verify`
//! uses, failing closed.

use mkit_core::hash::{self, Hash};
use mkit_core::object::Object;
use mkit_core::sign;
use mkit_core::store::ObjectStore;
use rayon::prelude::*;

use crate::error::SyncError;

/// Entries-per-thread budget below which [`verify_new_object_signatures`]
/// checks signatures sequentially instead of fanning out across rayon's
/// thread pool, for a pool of a given size. Same crossover shape as
/// `remote_dispatch/mod.rs`'s `PACK_FANOUT_ENTRIES_PER_THREAD` (rayon's
/// pool-dispatch overhead loses to a plain loop below a few entries per
/// thread and wins clearly above it) but tuned lower: each entry here is
/// only a `store.read_object` (disk read + BLAKE3 re-hash) plus one
/// Ed25519 `verify_strict` — cheaper per item than the zstd-compression
/// fan-out `PACK_FANOUT_ENTRIES_PER_THREAD` guards, so fewer entries per
/// thread are enough to amortize dispatch. Measured with `cargo bench -p
/// mkit-benches --bench verify_fanout`.
const VERIFY_FANOUT_ENTRIES_PER_THREAD: usize = 2;

/// The total entry count [`verify_new_object_signatures`] fans out across
/// rayon at — see [`VERIFY_FANOUT_ENTRIES_PER_THREAD`].
fn verify_fanout_threshold() -> usize {
    crate::fanout::threshold(VERIFY_FANOUT_ENTRIES_PER_THREAD)
}

/// Chunk size [`verify_new_object_signatures`]'s parallel path processes
/// `stored` in — deliberately decoupled from [`verify_fanout_threshold`]
/// (a small, pool-size-scaled crossover picked to amortize rayon's
/// per-dispatch overhead) rather than reusing it as the chunk size too.
/// The two constants answer different questions: `verify_fanout_threshold`
/// asks "is this worth parallelizing at all?"; this asks "how much wasted
/// verification work should a hostile fetch's first bad signature be
/// allowed to force?" A large legitimate fetch (thousands of newly-signed
/// objects) pays one rayon dispatch per chunk, so reusing the tiny
/// crossover threshold as the chunk size (as few as `2 * num_threads`,
/// e.g. 16 on an 8-core host) meant a 10,000-object fetch paid roughly
/// 625 separate dispatches — thread-pool coordination overhead with no
/// benefit, since the hostile-input bound doesn't need a chunk anywhere
/// near that small. 512 keeps the bound meaningful (a hostile remote can
/// force at most 512 extra reads/Ed25519-verifies past the object that
/// actually fails — a small, fixed amount of wasted CPU regardless of
/// fetch size) while cutting a 10,000-object fetch to ~20 dispatches.
const VERIFY_CHUNK_CAP: usize = 512;

/// The chunk size [`verify_new_object_signatures`]'s parallel path uses —
/// see [`VERIFY_CHUNK_CAP`]. `.max(verify_fanout_threshold())` guards the
/// (currently unreachable on any real host) case of a thread pool large
/// enough that the crossover threshold itself would exceed the cap —
/// a chunk should never be smaller than the count that justified
/// parallelizing it in the first place.
fn verify_chunk_size() -> usize {
    VERIFY_CHUNK_CAP.max(verify_fanout_threshold())
}

/// Verify the Ed25519 signature on every commit/remix/tag in `stored` —
/// the digests [`unpack_downloaded_packs`] just wrote, i.e. the objects
/// this fetch actually introduced (issue #692). Uses the exact same check
/// `mkit verify <rev>` runs manually
/// ([`mkit_core::sign::verify_commit`]/`verify_remix`/`verify_tag`), so
/// clone/pull/fetch cannot publish a remote-tracking ref to a hostile
/// remote's unsigned or forged history (THREAT-MODEL §3.1) without the
/// caller explicitly opting out. Blob/Tree/ChunkedBlob/Delta objects carry
/// no signature and are skipped.
///
/// `require_signed = false` (the explicit opt-out) short-circuits to
/// `Ok(())` without reading any object — a no-op, not a "verify but
/// ignore the result".
///
/// Each entry's read + verify is independent of every other's, so at or
/// above [`verify_fanout_threshold`] entries this fans out across rayon's
/// global thread pool (mirroring `add.rs`'s hash fan-out and
/// `remote_dispatch/mod.rs`'s pack-build fan-out) instead of running one
/// entry at a time — `store.read_object`'s BLAKE3 re-hash and
/// `verify_commit`/`verify_remix`/`verify_tag`'s Ed25519 check are both
/// CPU-bound, so a large fetch's verification pass parallelizes cleanly
/// across cores.
///
/// The parallel path processes `stored` in fixed-size chunks of
/// [`verify_chunk_size`] entries, verifying each chunk in full before
/// starting the next, rather than fanning the whole slice out in one
/// `par_iter` — rayon's `try_for_each` only best-effort short-circuits
/// (already-dispatched work keeps running once an error is found), so a
/// single flat fan-out over a very large hostile fetch could still force
/// reading and Ed25519-verifying a large fraction of the batch past the
/// first invalid signature before the rejection propagates. Chunking
/// bounds that wasted work to at most one chunk: a hostile remote can
/// force at most `verify_chunk_size()` extra reads/verifies beyond the
/// object that actually fails, never the rest of `stored`. Which entry's
/// error surfaces first is not guaranteed to match `stored`'s order
/// *within* a chunk, but the chunk containing the first invalid entry
/// (in `stored`'s order) is always the one whose error is returned,
/// since later chunks are never started.
///
/// Within each chunk (or the whole slice, below the fan-out threshold),
/// [`verify_slice`] tries a single [`mkit_core::sign::verify_batch`] pass
/// over every commit/remix/tag it read before falling back to
/// [`verify_one_object`]'s per-object loop — see [`verify_slice`]'s docs.
pub(crate) fn verify_new_object_signatures(
    store: &ObjectStore,
    stored: &[Hash],
    require_signed: bool,
) -> Result<(), SyncError> {
    if !require_signed {
        return Ok(());
    }
    if stored.len() < verify_fanout_threshold() {
        return verify_slice(store, stored, false);
    }
    stored
        .chunks(verify_chunk_size())
        .try_for_each(|chunk| verify_slice(store, chunk, true))
}

/// Verify the signature on a single already-read object through
/// [`sign::verify_object_signature`] (commit/remix/tag; Blob/Tree/
/// ChunkedBlob/Delta carry no signature and pass). The exact per-object
/// check [`verify_new_object_signatures`] used unconditionally before
/// batch verification was added, now used both as [`verify_slice`]'s
/// fallback and — via that fallback — the sole check whenever the batch
/// fast path doesn't apply or doesn't succeed.
fn verify_one_object(h: Hash, obj: &Object) -> Result<(), SyncError> {
    sign::verify_object_signature(obj).map_err(|e| SyncError::UnsignedOrInvalidObject {
        hash: hash::to_hex(&h),
        reason: e.to_string(),
    })
}

/// Collect `(public_key, digest, signature)` triples for every signed
/// object in `entries`, for a single [`mkit_core::sign::verify_batch`]
/// call — `None` if computing any entry's signing digest itself failed,
/// which [`verify_slice`] treats as "skip the batch attempt", since
/// [`verify_one_object`] will independently hit and correctly attribute
/// that same failure in its fallback loop.
fn collect_batch_entries(
    entries: &[(Hash, Object)],
) -> Option<Vec<(sign::PublicKey, Hash, sign::Signature)>> {
    let mut batch = Vec::new();
    for (_, obj) in entries {
        match obj {
            Object::Commit(c) => batch.push((
                sign::PublicKey(c.signer),
                sign::commit_signing_hash(c).ok()?,
                sign::Signature(c.signature),
            )),
            Object::Remix(r) => batch.push((
                sign::PublicKey(r.signer),
                sign::remix_signing_hash(r).ok()?,
                sign::Signature(r.signature),
            )),
            Object::Tag(t) => batch.push((
                sign::PublicKey(t.signer),
                sign::tag_signing_hash(t).ok()?,
                sign::Signature(t.signature),
            )),
            Object::Blob(_) | Object::Tree(_) | Object::ChunkedBlob(_) | Object::Delta(_) => {}
        }
    }
    Some(batch)
}

/// Splits `batch` into one sub-batch per rayon worker thread and
/// verifies the sub-batches in parallel, instead of one whole-slice
/// [`sign::verify_batch`] call on a single thread.
///
/// `cargo bench -p mkit-benches --bench verify_fanout` on a 4-core host
/// found that a single-threaded batch call, despite doing less total
/// scalar-multiplication work than one `verify_strict` per entry, loses
/// to today's per-object rayon fan-out once the fan-out has enough
/// entries to keep every core busy (256 entries: 9.6ms rayon vs. 11.9ms
/// one whole-slice batch) — batching's ~2x reduction in total work
/// doesn't make up for using only one of four cores. Chunking the batch
/// itself across rayon combines both effects instead of trading one for
/// the other: same bench, same 256 entries, 7.4ms — faster than either
/// alone, and consistently faster than plain rayon fan-out from 8
/// entries up (verified at 8/16/32/64/128/256).
fn verify_batch_parallel(batch: &[(sign::PublicKey, Hash, sign::Signature)]) -> bool {
    let threads = rayon::current_num_threads().max(1);
    let chunk_size = batch.len().div_ceil(threads).max(1);
    batch
        .par_chunks(chunk_size)
        .all(|sub| sign::verify_batch(sub).is_ok())
}

/// Read every object in `hashes` (in parallel iff `parallel`, matching
/// [`verify_new_object_signatures`]'s existing sequential/rayon split),
/// then verify their signatures. Every hash is read (there's no cheaper
/// way to learn an object's type), but only Commit/Remix/Tag entries are
/// retained afterward — see the read step's own comment for why that
/// matters for a chunk dominated by large blobs.
///
/// Tries [`mkit_core::sign::verify_batch`] first over every commit/
/// remix/tag found — via [`verify_batch_parallel`] when `parallel` is
/// set, a single whole-slice call otherwise (see that function's docs
/// for why the two cases need different strategies) — which does
/// strictly less total Ed25519 work than verifying each individually
/// and is the overwhelmingly common case: every object a well-behaved
/// remote sends is validly signed. Batch verification only proves "all
/// valid" or "at least one isn't", never *which* one, so on failure (or
/// if any entry's signing digest itself couldn't be computed) this
/// falls back to [`verify_one_object`]'s per-object loop — identical to
/// [`verify_new_object_signatures`]'s behavior before batch verification
/// was added — to locate and report the exact offending hash. A hostile
/// remote therefore pays for both the batch attempt and the fallback
/// loop on its one bad chunk, same bound [`verify_new_object_signatures`]
/// already documents (at most [`verify_chunk_size`] extra reads/verifies
/// past the object that actually fails); a well-behaved remote pays for
/// the batch attempt only.
fn verify_slice(store: &ObjectStore, hashes: &[Hash], parallel: bool) -> Result<(), SyncError> {
    // Every hash in `hashes` still has to be *read* to learn its type —
    // the pack format doesn't index that separately — but only
    // Commit/Remix/Tag objects are ever inspected below, by both
    // `collect_batch_entries` and `verify_one_object`. Dropping a
    // Blob/Tree/ChunkedBlob/Delta right after the type check, instead of
    // keeping it in `entries` for the rest of this call, matters
    // concretely: a single `Blob` can be up to `worktree::CHUNK_THRESHOLD`
    // (1 MiB — larger files are chunked, per this crate's whole design),
    // so a `verify_chunk_size()`-sized chunk (up to 512 entries)
    // dominated by such blobs previously held up to ~512 MiB of fully
    // decoded, never-inspected object bytes resident at once. This way,
    // at most one blob per rayon worker (or one at all, sequentially) is
    // ever live simultaneously.
    let read_signed_one = |h: &Hash| -> Result<Option<(Hash, Object)>, SyncError> {
        let obj = store.read_object(h)?;
        Ok(match obj {
            Object::Commit(_) | Object::Remix(_) | Object::Tag(_) => Some((*h, obj)),
            Object::Blob(_) | Object::Tree(_) | Object::ChunkedBlob(_) | Object::Delta(_) => None,
        })
    };
    let entries: Vec<(Hash, Object)> = if parallel {
        hashes
            .par_iter()
            .filter_map(|h| read_signed_one(h).transpose())
            .collect::<Result<_, _>>()?
    } else {
        hashes
            .iter()
            .filter_map(|h| read_signed_one(h).transpose())
            .collect::<Result<_, _>>()?
    };

    if let Some(batch) = collect_batch_entries(&entries) {
        let batch_ok = batch.is_empty()
            || if parallel {
                verify_batch_parallel(&batch)
            } else {
                sign::verify_batch(&batch).is_ok()
            };
        if batch_ok {
            return Ok(());
        }
    }

    if parallel {
        entries
            .par_iter()
            .try_for_each(|(h, obj)| verify_one_object(*h, obj))
    } else {
        entries
            .iter()
            .try_for_each(|(h, obj)| verify_one_object(*h, obj))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::object::Object;

    fn h(seed: &str) -> Hash {
        hash::hash(seed.as_bytes())
    }

    // ---- verify_new_object_signatures — sequential/rayon fan-out parity ----

    /// A validly-signed, independently-hashing commit — every `seed`
    /// produces a distinct object, matching the bench fixtures'
    /// no-dedup convention.
    fn signed_commit_bytes(kp: &mkit_core::sign::KeyPair, seed: usize) -> Vec<u8> {
        use mkit_core::object::{Commit, Identity};
        let mut c = Commit::new_unannotated(
            hash::hash(format!("tree #{seed}").as_bytes()),
            Vec::new(),
            Identity::ed25519(kp.public.0),
            kp.public.0,
            format!("packmap fanout test fixture #{seed}").into_bytes(),
            1_700_000_000 + seed as u64,
            [0u8; 64],
        );
        c.signature = mkit_core::sign::sign_commit(&c, kp).unwrap().0;
        mkit_core::serialize::serialize(&Object::Commit(c)).unwrap()
    }

    /// Large enough that `stored.len()` clears
    /// [`verify_fanout_threshold`] on any realistic thread-pool size
    /// (`VERIFY_FANOUT_ENTRIES_PER_THREAD` * rayon's pool size), so
    /// these tests exercise the `par_iter` branch rather than the
    /// sequential one the integration tests in
    /// `tests/verify_signatures_on_fetch.rs` already cover.
    const LARGE_BATCH: usize = 512;

    #[test]
    fn verify_new_object_signatures_accepts_a_large_validly_signed_batch() {
        let dir = tempfile::tempdir().unwrap();
        let layout = mkit_core::layout::RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let kp = mkit_core::sign::KeyPair::generate().unwrap();
        let stored: Vec<Hash> = (0..LARGE_BATCH)
            .map(|i| store.write(&signed_commit_bytes(&kp, i)).unwrap())
            .collect();
        assert!(stored.len() >= verify_fanout_threshold());

        verify_new_object_signatures(&store, &stored, true)
            .expect("every commit in the batch is validly signed");
    }

    /// Regression for `verify_slice`'s read step: a chunk mixing unsigned
    /// object kinds (Blob/Tree — neither carries a signature) with signed
    /// commits must still verify correctly. `verify_slice` reads every
    /// hash to learn its type but only *retains* Commit/Remix/Tag entries
    /// afterward (dropping Blob/Tree/ChunkedBlob/Delta immediately) — this
    /// pins that the filtering doesn't drop a commit it should have kept,
    /// doesn't get confused by interleaving, and both a validly-signed and
    /// a tampered commit are still correctly accepted/rejected when
    /// surrounded by unsigned entries on both sides.
    #[test]
    fn verify_new_object_signatures_mixed_with_unsigned_object_kinds() {
        let dir = tempfile::tempdir().unwrap();
        let layout = mkit_core::layout::RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let kp = mkit_core::sign::KeyPair::generate().unwrap();

        let blob = |seed: usize| -> Hash {
            store
                .write(
                    &mkit_core::serialize::serialize(&Object::Blob(mkit_core::object::Blob {
                        data: format!("unsigned blob fixture #{seed}").into_bytes(),
                    }))
                    .unwrap(),
                )
                .unwrap()
        };

        // Blob, commit, blob, commit, ... — unsigned entries on both
        // sides of every signed one, so a filtering bug that drops or
        // misattributes a neighbor would show up either direction.
        let mut stored: Vec<Hash> = Vec::with_capacity(2 * LARGE_BATCH);
        for i in 0..LARGE_BATCH {
            stored.push(blob(i));
            stored.push(store.write(&signed_commit_bytes(&kp, i)).unwrap());
        }
        assert!(stored.len() >= verify_fanout_threshold());

        verify_new_object_signatures(&store, &stored, true)
            .expect("unsigned entries must not affect verifying the signed ones");

        // Tamper one of the commits — must still be caught even though
        // it's surrounded by unsigned entries the batch/fallback paths
        // both skip.
        let commit_index = 2 * (LARGE_BATCH / 2) + 1;
        let Object::Commit(mut c) = store.read_object(&stored[commit_index]).unwrap() else {
            panic!("expected commit");
        };
        c.signature[0] ^= 0xff;
        let tampered_bytes = mkit_core::serialize::serialize(&Object::Commit(c)).unwrap();
        stored[commit_index] = store.write(&tampered_bytes).unwrap();

        let err = verify_new_object_signatures(&store, &stored, true)
            .expect_err("a tampered commit must still be caught alongside unsigned entries");
        assert!(matches!(err, SyncError::UnsignedOrInvalidObject { .. }));
    }

    #[test]
    fn verify_new_object_signatures_rejects_one_bad_signature_in_a_large_batch() {
        let dir = tempfile::tempdir().unwrap();
        let layout = mkit_core::layout::RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let kp = mkit_core::sign::KeyPair::generate().unwrap();
        let mut stored: Vec<Hash> = (0..LARGE_BATCH)
            .map(|i| store.write(&signed_commit_bytes(&kp, i)).unwrap())
            .collect();
        assert!(stored.len() >= verify_fanout_threshold());

        // Tamper one commit's signature in place — content-addressing stays
        // intact (re-written under a new hash), only the crypto is wrong,
        // same attacker model as `tamper_head_commit_signature` in the
        // integration test.
        let Object::Commit(mut c) = store.read_object(&stored[LARGE_BATCH / 2]).unwrap() else {
            panic!("expected commit");
        };
        c.signature[0] ^= 0xff;
        let tampered_bytes = mkit_core::serialize::serialize(&Object::Commit(c)).unwrap();
        let tampered_hash = store.write(&tampered_bytes).unwrap();
        stored[LARGE_BATCH / 2] = tampered_hash;

        let err = verify_new_object_signatures(&store, &stored, true)
            .expect_err("a batch with one bad signature must be rejected");
        assert!(matches!(err, SyncError::UnsignedOrInvalidObject { .. }));
    }

    #[test]
    fn verify_new_object_signatures_never_reads_past_the_chunk_containing_the_first_bad_signature()
    {
        // Regression for the chunked fan-out: a hostile remote must not be
        // able to force verification work past the chunk containing the
        // first invalid signature. The first `chunk_size` entries are a
        // validly-signed batch with one tampered signature; every entry
        // after that names a digest that was NEVER written to the store.
        // If the implementation ever started a second chunk, reading one
        // of those would surface as a store error (`ObjectNotFound`), not
        // `UnsignedOrInvalidObject` — so this test fails deterministically
        // if chunking regresses back to a single flat fan-out (or any
        // other shape that can read beyond the first failing chunk).
        let dir = tempfile::tempdir().unwrap();
        let layout = mkit_core::layout::RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let kp = mkit_core::sign::KeyPair::generate().unwrap();
        let chunk_size = verify_chunk_size();

        let mut stored: Vec<Hash> = (0..chunk_size)
            .map(|i| store.write(&signed_commit_bytes(&kp, i)).unwrap())
            .collect();
        let Object::Commit(mut c) = store.read_object(&stored[0]).unwrap() else {
            panic!("expected commit");
        };
        c.signature[0] ^= 0xff;
        let tampered_bytes = mkit_core::serialize::serialize(&Object::Commit(c)).unwrap();
        let tampered_hash = store.write(&tampered_bytes).unwrap();
        stored[0] = tampered_hash;
        stored.extend((0..chunk_size * 3).map(|i| h(&format!("never-written-{i}"))));

        let err = verify_new_object_signatures(&store, &stored, true)
            .expect_err("the tampered signature in the first chunk must reject the fetch");
        match err {
            SyncError::UnsignedOrInvalidObject { hash: got, .. } => {
                assert_eq!(got, hash::to_hex(&tampered_hash));
            }
            other => panic!("expected UnsignedOrInvalidObject, got {other:?}"),
        }
    }

    #[test]
    fn verify_new_object_signatures_require_signed_false_skips_a_large_batch() {
        // `require_signed = false` must short-circuit to `Ok(())` without
        // reading the store at all, regardless of batch size — pass a
        // digest list naming objects that were never written, so any
        // attempted read would panic/error and fail the test.
        let dir = tempfile::tempdir().unwrap();
        let layout = mkit_core::layout::RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let stored: Vec<Hash> = (0..LARGE_BATCH)
            .map(|i| h(&format!("never-written-{i}")))
            .collect();

        verify_new_object_signatures(&store, &stored, false)
            .expect("require_signed=false must no-op regardless of batch size");
    }
}
