//! Spike for issue #650 — evaluates `commonware-storage`'s [`Freezer`] and
//! [`prunable::Archive`] as a replacement for mkit's hand-rolled loose-file
//! [`ObjectStore`], using mkit's real object shapes (BLAKE3-domain object
//! ids as keys, variable-size serialized `Blob`/`Tree`/`Commit` bytes as
//! values).
//!
//! This file is compiled only with `--features history-mmr` (the feature
//! that already pulls `commonware-storage`, `commonware-runtime`, and
//! `commonware-utils` into mkit-core).
//!
//! ## What this proves
//!
//! 1. [`freezer_put_get_byte_identical`] — basic put/get round-trip against
//!    real mkit object bytes, byte-identical on read-back.
//! 2. [`freezer_has_no_per_key_delete`] — a compile-time fact, documented
//!    here rather than exercised at runtime: [`Freezer`]'s inherent `impl`
//!    (`commonware-storage` v2026.5.0, `storage/src/freezer/storage.rs`)
//!    exposes exactly `put`, `get`, `sync`, `close`, and `destroy`. `destroy`
//!    consumes `self` and removes the *entire* structure (all three
//!    on-disk components: table blob, key-index journal, value journal) —
//!    there is no method that removes a single key while leaving the
//!    Freezer otherwise intact. If a per-key delete existed, this test
//!    would call it; it does not exist, so there is nothing to call.
//! 3. [`archive_prune_deletes_a_prefix_not_a_single_index`] — the concrete
//!    "delete one object while others remain" scenario the ADR needs. It
//!    demonstrates that `prunable::Archive`'s only removal primitive,
//!    `prune(min_index)`, drops **every** index below `min_index`, not a
//!    chosen single index. Deleting one unreachable object out of an
//!    interior position, while keeping older *and* newer live objects,
//!    is not expressible with this API — it requires collateral deletion
//!    of everything below the target, or a full rebuild.
//!
//! Together these answer the GC-unlink question: mkit's GC deletes
//! individual objects scattered arbitrarily across the BLAKE3 keyspace
//! (unreachability has no relationship to insertion order), and neither
//! `Freezer` nor `Archive` support that operation directly.
#![cfg(feature = "history-mmr")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use bytes::Bytes;
use commonware_codec::RangeCfg;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_runtime::{Runner as _, deterministic};
use commonware_storage::archive::{Archive as _, Identifier as ArchiveIdentifier, prunable};
use commonware_storage::freezer::{
    Config as FreezerConfig, Freezer, Identifier as FreezerIdentifier,
};
use commonware_storage::translator::FourCap;
use commonware_utils::sequence::FixedBytes;
use commonware_utils::{NZU16, NZU64, NZUsize};

use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::serialize;
use mkit_core::store::ObjectStore;

const PAGE_SIZE: std::num::NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: std::num::NonZeroUsize = NZUsize!(10);

/// Freezer/Archive key type for a BLAKE3-domain mkit object id.
type ObjKey = FixedBytes<32>;

fn to_key(h: &Hash) -> ObjKey {
    // `Hash` is `[u8; 32]`; `FixedBytes<32>` is the commonware-utils
    // `Array` impl mkit-core already round-trips through in the vendored
    // BMT cross-check (see `merkle.rs`).
    use commonware_codec::DecodeExt as _;
    FixedBytes::decode(h.as_slice()).unwrap()
}

/// Build a handful of *real* mkit objects (a small blob, a large blob, a
/// tree, and two commits) through the real [`ObjectStore`] so their ids
/// and canonical serialized bytes are exactly what production code would
/// produce — not synthetic stand-ins. Returns `(id, canonical_bytes)`
/// pairs in insertion order.
fn real_mkit_objects() -> (tempfile::TempDir, Vec<(Hash, Vec<u8>)>) {
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();

    let mut out: Vec<(Hash, Vec<u8>)> = Vec::new();
    let put = |obj: &Object| -> (Hash, Vec<u8>) {
        let bytes = serialize::serialize(obj).unwrap();
        let id = store.write(&bytes).unwrap();
        (id, bytes)
    };

    // A small blob.
    out.push(put(&Object::Blob(Blob {
        data: b"hello, freezer".to_vec(),
    })));
    // A large-ish variable-size blob (64 KiB) — stands in for real object
    // sizes closer to a typical mkit chunk than a 15-byte string.
    out.push(put(&Object::Blob(Blob {
        data: vec![0xAB; 64 * 1024],
    })));
    let blob_id = out[0].0;
    // A tree referencing the small blob.
    out.push(put(&Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"hello.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob_id,
        }],
    })));
    let tree_id = out[2].0;
    // Two commits (distinct via message/timestamp so ids don't collide),
    // the second parented on the first.
    out.push(put(&Object::Commit(Commit {
        tree_hash: tree_id,
        parents: vec![],
        author: Identity::opaque(b"spike".to_vec()),
        signer: [0u8; 32],
        message: b"first".to_vec(),
        timestamp: 1,
        message_hash: [0u8; 32],
        content_digest: [0u8; 32],
        signature: [0u8; 64],
    })));
    let first_commit = out[3].0;
    out.push(put(&Object::Commit(Commit {
        tree_hash: tree_id,
        parents: vec![first_commit],
        author: Identity::opaque(b"spike".to_vec()),
        signer: [0u8; 32],
        message: b"second".to_vec(),
        timestamp: 2,
        message_hash: [0u8; 32],
        content_digest: [0u8; 32],
        signature: [0u8; 64],
    })));

    (dir, out)
}

fn freezer_cfg(context: &deterministic::Context, suffix: &str) -> FreezerConfig<RangeCfg<usize>> {
    FreezerConfig {
        key_partition: format!("spike-key-{suffix}"),
        key_write_buffer: NZUsize!(64 * 1024),
        key_page_cache: CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE),
        value_partition: format!("spike-value-{suffix}"),
        // Exercise the built-in zstd compression path (#646 is expected to
        // fold into this once the migration lands): a mid zstd level, same
        // shape as `prunable::Config::compression`.
        value_compression: Some(3),
        value_write_buffer: NZUsize!(64 * 1024),
        value_target_size: 8 * 1024 * 1024,
        table_partition: format!("spike-table-{suffix}"),
        table_initial_size: 16,
        table_resize_frequency: 2,
        table_resize_chunk_size: 16,
        table_replay_buffer: NZUsize!(64 * 1024),
        // `Bytes` codec config: cap a single value at 8 MiB (well above the
        // 64 KiB test blob; mkit's real cap is `MAX_RAW_OBJECT_SIZE` = 1 GiB).
        codec_config: RangeCfg::from(0..=8 * 1024 * 1024),
    }
}

/// 1. Basic put/get: N real mkit objects round-trip byte-identical through
///    [`Freezer`], and a `put` of one key does not disturb any other.
#[test]
fn freezer_put_get_byte_identical() {
    let (_dir, objects) = real_mkit_objects();
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = freezer_cfg(&context, "basic");
        let mut freezer: Freezer<_, ObjKey, Bytes> = Freezer::init(context, cfg).await.unwrap();

        for (id, bytes) in &objects {
            freezer
                .put(to_key(id), Bytes::from(bytes.clone()))
                .await
                .unwrap();
        }
        freezer.sync().await.unwrap();

        for (id, bytes) in &objects {
            let got = freezer
                .get(FreezerIdentifier::Key(&to_key(id)))
                .await
                .unwrap()
                .expect("object must be present");
            assert_eq!(
                got.as_ref(),
                bytes.as_slice(),
                "round-tripped bytes must be byte-identical to the canonical serialization"
            );
        }

        freezer.destroy().await.unwrap();
    });
}

/// 2. Documents (rather than "exercises", since there is no API surface to
///    call) that [`Freezer`] has no per-key delete. See the module doc for
///    the source-level justification. This test still asserts the
///    observable consequence: after writing N objects, `destroy()` is the
///    *only* way to make any of them disappear, and it takes all of them
///    with it (there is no partial/selective variant).
#[test]
fn freezer_has_no_per_key_delete() {
    let (_dir, objects) = real_mkit_objects();
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = freezer_cfg(&context, "nodelete");
        let mut freezer: Freezer<_, ObjKey, Bytes> = Freezer::init(context, cfg).await.unwrap();

        for (id, bytes) in &objects {
            freezer
                .put(to_key(id), Bytes::from(bytes.clone()))
                .await
                .unwrap();
        }
        freezer.sync().await.unwrap();

        // Every object present.
        for (id, _) in &objects {
            assert!(
                freezer
                    .get(FreezerIdentifier::Key(&to_key(id)))
                    .await
                    .unwrap()
                    .is_some()
            );
        }

        // The only removal primitive on `Freezer` is `destroy(self)`,
        // which is total: it consumes the whole structure and deletes the
        // table blob, key-index journal, and value journal together.
        // There is no `Freezer::remove(key)` or equivalent to reach for
        // instead — this call is exhaustive over `Freezer`'s public API
        // (`storage/src/freezer/storage.rs`, v2026.5.0): `init`,
        // `init_with_checkpoint`, `put`, `get`, `sync`, `close`, `destroy`.
        freezer.destroy().await.unwrap();
    });
}

fn archive_cfg(
    context: &deterministic::Context,
    suffix: &str,
) -> prunable::Config<FourCap, RangeCfg<usize>> {
    prunable::Config {
        translator: FourCap,
        key_partition: format!("spike-archive-key-{suffix}"),
        key_page_cache: CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE),
        value_partition: format!("spike-archive-value-{suffix}"),
        compression: Some(3),
        codec_config: RangeCfg::from(0..=8 * 1024 * 1024),
        // One item per section: the finest possible pruning granularity
        // `Archive` supports. Even at this maximally favorable setting,
        // pruning is still a monotonic prefix operation (see the test
        // below) — a coarser `items_per_section` only makes the
        // collateral-deletion problem worse, not better.
        items_per_section: NZU64!(1),
        key_write_buffer: NZUsize!(64 * 1024),
        value_write_buffer: NZUsize!(64 * 1024),
        replay_buffer: NZUsize!(64 * 1024),
    }
}

/// 3. The concrete GC-unlink experiment: put 5 real mkit objects at
///    sequential indices, where index 2 is the one mkit's GC has decided
///    is unreachable and indices 0, 1, 3, 4 are still live. Try to delete
///    *only* index 2. `Archive`'s only removal primitive is
///    `prune(min_index)`, which deletes every index below `min_index` —
///    there is no way to target index 2 alone.
#[test]
fn archive_prune_deletes_a_prefix_not_a_single_index() {
    let (_dir, objects) = real_mkit_objects();
    assert!(objects.len() >= 5, "need 5 distinct objects for this test");
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = archive_cfg(&context, "gc");
        let mut archive: prunable::Archive<FourCap, _, ObjKey, Bytes> =
            prunable::Archive::init(context, cfg).await.unwrap();

        for (i, (id, bytes)) in objects.iter().enumerate() {
            archive
                .put(i as u64, to_key(id), Bytes::from(bytes.clone()))
                .await
                .unwrap();
        }
        archive.sync().await.unwrap();

        // All 5 present before any pruning.
        for (id, _) in &objects {
            assert!(
                archive
                    .get(ArchiveIdentifier::Key(&to_key(id)))
                    .await
                    .unwrap()
                    .is_some()
            );
        }

        // Goal: delete only index 2 (unreachable), keep 0, 1, 3, 4 (live).
        // `Archive::prune` is the only removal primitive on the trait
        // (`archive::Archive::prune` is not even a trait method — it's
        // inherent to `prunable::Archive`, and pruning-by-arbitrary-index
        // does not exist anywhere in `archive::mod.rs`'s `Archive` trait:
        // put/put_sync/get/has/next_gap/missing_items/ranges/ranges_from/
        // first_index/last_index/sync/destroy). The closest lever is
        // pruning everything below index 3, which is the smallest prune
        // point that removes index 2.
        archive.prune(3).await.unwrap();

        // The target is gone, as intended...
        assert!(
            archive
                .get(ArchiveIdentifier::Key(&to_key(&objects[2].0)))
                .await
                .unwrap()
                .is_none(),
            "index 2 (the unreachable object) is gone"
        );
        // ...but so are indices 0 and 1, which were still live. This is
        // the collateral deletion `prune` cannot avoid: it is a monotonic
        // prefix operation, not a per-object unlink.
        assert!(
            archive
                .get(ArchiveIdentifier::Key(&to_key(&objects[0].0)))
                .await
                .unwrap()
                .is_none(),
            "index 0 was live but is collaterally deleted by prune(3)"
        );
        assert!(
            archive
                .get(ArchiveIdentifier::Key(&to_key(&objects[1].0)))
                .await
                .unwrap()
                .is_none(),
            "index 1 was live but is collaterally deleted by prune(3)"
        );
        // The still-live, higher indices survive.
        assert!(
            archive
                .get(ArchiveIdentifier::Key(&to_key(&objects[3].0)))
                .await
                .unwrap()
                .is_some(),
            "index 3 (live, higher than the prune point) survives"
        );
        assert!(
            archive
                .get(ArchiveIdentifier::Key(&to_key(&objects[4].0)))
                .await
                .unwrap()
                .is_some(),
            "index 4 (live, higher than the prune point) survives"
        );

        // Recovering indices 0 and 1 (mkit's GC would never have wanted
        // them deleted) is not possible from here: `put` below a pruned
        // section is rejected outright.
        let reinsert = archive
            .put(0, to_key(&objects[0].0), Bytes::from(objects[0].1.clone()))
            .await;
        assert!(
            reinsert.is_err(),
            "a pruned index cannot be resurrected; the only recovery path is a full rebuild \
             from a separately retained copy of the live objects"
        );

        archive.destroy().await.unwrap();
    });
}
