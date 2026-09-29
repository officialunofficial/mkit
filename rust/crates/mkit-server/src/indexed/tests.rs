//! In-process indexed verification against real pack bytes and metadata rows.
#![allow(clippy::unwrap_used)] // Fixtures and assertions fail the test on invalid setup.

use bytes::Bytes;
use futures_executor::block_on;
use mkit_core::hash::{Hash, hash};
use mkit_core::object::{Commit, Identity, Object, Tree};
use mkit_core::pack::{DecodeLimits, NoExternalBases, PackWriter, decode_entries_with};
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};
use mkit_core::transfer::encode_packlist;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::{IndexedConfig, verify::verify_ticketed};
use crate::memory::{MemoryBlobStore, MemoryKv};
use crate::pipeline::{ShardMap, SinglePartition};
use crate::repo::{NamespaceKey, RepoId, RepoName};
use crate::rt::ManualClock;
use crate::store::{
    Batch, BlobKey, BlobStore, NamespaceStore, PackSink, Partition, codec::TicketV1, keys,
};
use crate::telemetry::NoopMetrics;

const NOW: i64 = 1_700_000_000_000;

fn repo(name: &str) -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new(name).unwrap(),
    }
}

fn ticket(repo: &RepoId, bytes: &[u8], created_at_ms: u64) -> TicketV1 {
    TicketV1 {
        repo: repo.name.clone(),
        ref_name: "refs/heads/main".into(),
        signer: [3; 32],
        pack_id: hash(bytes),
        bytes: bytes.len() as u64,
        part_size: 1 << 20,
        expires_at_ms: NOW as u64 + 300_000,
        created_at_ms,
        reservation_id: "s:test".into(),
        upload_session: None,
    }
}

fn upload(blobs: &MemoryBlobStore, bytes: &[u8]) {
    block_on(async {
        let mut sink = blobs
            .begin(BlobKey::pack(hash(bytes)), bytes.len() as u64)
            .await
            .unwrap();
        sink.write(Bytes::copy_from_slice(bytes)).await.unwrap();
        sink.commit().await.unwrap();
    });
}

fn source(repo: &RepoId) -> Partition {
    SinglePartition.ref_shard(repo, "refs/heads/main")
}

fn verify(
    blobs: &MemoryBlobStore,
    store: &MemoryKv,
    repo: &RepoId,
    tickets: &[TicketV1],
    head: Hash,
    cfg: IndexedConfig,
    clock: &ManualClock,
) -> Result<Vec<Hash>, crate::ServerError> {
    block_on(verify_ticketed(
        blobs,
        store,
        &SinglePartition,
        repo,
        &source(repo),
        tickets,
        head,
        cfg,
        clock,
        &NoopMetrics,
    ))
}

fn good_pack() -> (Vec<u8>, Hash) {
    let tree = Object::Tree(Tree {
        entries: Vec::new(),
    });
    let tree_id = tree.id().unwrap();
    let tree_bytes = serialize(&tree).unwrap();
    let key = KeyPair::from_seed([7; 32]);
    let mut commit = Commit::new_unannotated(
        tree_id,
        Vec::new(),
        Identity::ed25519(key.public.0),
        key.public.0,
        b"good".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &key).unwrap().0;
    let commit = Object::Commit(commit);
    let head = commit.id().unwrap();
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(tree_id, &tree_bytes).unwrap();
    writer.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    (writer.finish().unwrap(), head)
}

#[test]
fn good_push_indexes_before_membership_and_reuses_verified_state() {
    let (pack, head) = good_pack();
    let blobs = MemoryBlobStore::default();
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    upload(&blobs, &pack);
    let ticket = ticket(&repo, &pack, NOW as u64);
    let ids = verify(
        &blobs,
        &store,
        &repo,
        std::slice::from_ref(&ticket),
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap();
    assert_eq!(ids.len(), 2);
    let index = keys::object_index(&repo.name, &head, &ticket.pack_id);
    assert!(
        block_on(store.get(&source(&repo), &index))
            .unwrap()
            .is_some()
    );
    assert!(
        block_on(store.get(
            &source(&repo),
            &keys::membership(&repo.name, &ticket.pack_id)
        ))
        .unwrap()
        .is_none()
    );
    // A previously verified pack contributes no new objects to WP-4.10's
    // per-attempt extraction seam.
    assert!(
        verify(
            &blobs,
            &store,
            &repo,
            &[ticket],
            head,
            IndexedConfig::default(),
            &clock
        )
        .unwrap()
        .is_empty()
    );
}

#[test]
fn bad_signature_and_dangling_object_are_rejected() {
    let (pack, head) = good_pack();
    let mut bad = pack.clone();
    // The commit's signature occupies the last 64 bytes of its payload;
    // mutate it, then repair the pack trailer so identity is checked first.
    let trailer = bad.len() - 32;
    bad[trailer - 1] ^= 1;
    let digest = hash(&bad[..trailer]);
    bad[trailer..].copy_from_slice(&digest);
    let blobs = MemoryBlobStore::default();
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    upload(&blobs, &bad);
    let error = verify(
        &blobs,
        &store,
        &repo,
        &[ticket(&repo, &bad, NOW as u64)],
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.public_message(), "bad signature");

    let (good, head) = good_pack();
    let mut writer = PackWriter::new_raw_only();
    // A tree referring to an absent blob is unreachable from the head, but
    // it is still a consumed object and must pass closure verification.
    let orphan = Object::Tree(Tree {
        entries: vec![mkit_core::object::TreeEntry {
            name: b"missing".to_vec(),
            mode: mkit_core::object::EntryMode::Blob,
            object_hash: [9; 32],
        }],
    });
    writer
        .push_raw(orphan.id().unwrap(), &serialize(&orphan).unwrap())
        .unwrap();
    let orphan_pack = writer.finish().unwrap();
    let blobs = MemoryBlobStore::default();
    let store = MemoryKv::with_clock(clock.clone());
    upload(&blobs, &good);
    upload(&blobs, &orphan_pack);
    let tickets = [
        ticket(&repo, &good, NOW as u64 - 60_000),
        ticket(&repo, &orphan_pack, NOW as u64 - 60_000),
    ];
    let error = verify(
        &blobs,
        &store,
        &repo,
        &tickets,
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.public_message(), "open closure");
}

#[test]
fn corrupt_pack_identity_is_rejected() {
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    let blobs = MemoryBlobStore::default();
    let (mut pack, head) = good_pack();
    let last = pack.len() - 1;
    pack[last] ^= 1; // Valid content-addressed upload, invalid pack trailer.
    upload(&blobs, &pack);
    let error = verify(
        &blobs,
        &store,
        &repo,
        &[ticket(&repo, &pack, NOW as u64)],
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.public_message(), "object hash mismatch");
}

#[test]
fn unknown_type_and_foreign_packlist_follow_exact_errors() {
    let blobs = MemoryBlobStore::default();
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    let unknown = b"NOPE".to_vec();
    upload(&blobs, &unknown);
    let error = verify(
        &blobs,
        &store,
        &repo,
        &[ticket(&repo, &unknown, NOW as u64)],
        [0; 32],
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.public_message(), "unknown upload type");

    let (good, head) = good_pack();
    upload(&blobs, &good);
    let foreign = [8; 32];
    let list = encode_packlist(None, &[foreign]).unwrap();
    upload(&blobs, &list);
    let tickets = [
        ticket(&repo, &good, NOW as u64),
        ticket(&repo, &list, NOW as u64),
    ];
    let retry_store = MemoryKv::with_clock(clock.clone());
    let error = verify(
        &blobs,
        &retry_store,
        &repo,
        &tickets,
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(
        error.public_message(),
        "repository membership not yet visible"
    );
    // The unavailable attempt releases its lease. The same ticket reaches
    // the permanent answer exactly at the lag boundary.
    clock.advance(i64::try_from(IndexedConfig::default().relay_lag_bound_ms).unwrap());
    let error = verify(
        &blobs,
        &retry_store,
        &repo,
        &tickets,
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(
        error.public_message(),
        "packlist lists a pack that is not in this repository"
    );
}

#[test]
fn concurrent_lease_is_pending_without_replay_then_retry_succeeds() {
    let (pack, head) = good_pack();
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    let blobs = MemoryBlobStore::default();
    upload(&blobs, &pack);
    let ticket = ticket(&repo, &pack, NOW as u64);
    let pending = super::state::VerificationV1::Pending {
        lease_until_ms: NOW as u64 + 30_000,
    };
    block_on(store.apply(
        &source(&repo),
        Batch::new().put(
            keys::verification(&repo.name, &ticket.pack_id),
            super::state::encode(&pending),
        ),
    ))
    .unwrap();
    let error = verify(
        &blobs,
        &store,
        &repo,
        std::slice::from_ref(&ticket),
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.code(), crate::Code::Unavailable);
    assert_eq!(error.public_message(), "pack verification pending");
    assert_eq!(error.details().len(), 1);
    assert_eq!(error.http_status(), Some(503));
    assert!(
        block_on(store.get(&source(&repo), &keys::replay(&[0; 32])))
            .unwrap()
            .is_none()
    );
    clock.advance(30_001);
    assert_eq!(
        verify(
            &blobs,
            &store,
            &repo,
            &[ticket],
            head,
            IndexedConfig::default(),
            &clock
        )
        .unwrap()
        .len(),
        2
    );
}

fn blob(data: &[u8]) -> (Hash, Vec<u8>) {
    let object = Object::Blob(mkit_core::object::Blob {
        data: data.to_vec(),
    });
    (object.id().unwrap(), serialize(&object).unwrap())
}

fn thin_pack(base: Hash, base_bytes: &[u8], target_bytes: &[u8]) -> Vec<u8> {
    let mut writer = PackWriter::new();
    writer
        .push_delta(
            &base,
            &mkit_core::delta::encode(base_bytes, target_bytes).unwrap(),
        )
        .unwrap();
    writer.finish().unwrap()
}

fn seed_member_raw(
    blobs: &MemoryBlobStore,
    store: &MemoryKv,
    repo: &RepoId,
    object: Hash,
    raw: &[u8],
) {
    let mut writer = PackWriter::new_raw_only();
    writer.push_raw(object, raw).unwrap();
    let pack = writer.finish().unwrap();
    let pack_id = hash(&pack);
    upload(blobs, &pack);
    let mut frame = None;
    decode_entries_with(
        &pack,
        &mut NoExternalBases,
        DecodeLimits::default(),
        |entry| {
            frame = Some((
                entry.frame_offset,
                entry.frame_length,
                entry.wire_type,
                entry.bytes.len() as u64,
            ));
            Ok(())
        },
    )
    .unwrap();
    let (frame_offset, frame_length, wire_type, decoded_size) = frame.unwrap();
    let value = crate::store::index::IndexValue {
        frame_offset,
        frame_length,
        wire_type,
        decoded_size,
        chain_depth: 0,
        delta_base: None,
    };
    let index = keys::object_index(&repo.name, &object, &pack_id);
    let membership = keys::membership(&repo.name, &pack_id);
    block_on(
        store.apply(
            &source(repo),
            Batch::new()
                .put(
                    index,
                    crate::store::codec::encode_object_index(&object, &value).unwrap(),
                )
                .put(membership, crate::Value::default()),
        ),
    )
    .unwrap();
}

#[test]
fn thin_base_in_another_repository_is_indistinguishable_from_absent() {
    let (base, base_bytes) = blob(b"base");
    let (_, target_bytes) = blob(b"target");
    let thin = thin_pack(base, &base_bytes, &target_bytes);
    let a = repo("a");
    let b = repo("b");
    let blobs = MemoryBlobStore::default();
    upload(&blobs, &thin);
    let clock = Arc::new(ManualClock::new(NOW));
    for age in [0, 60_000] {
        let foreign = MemoryKv::with_clock(clock.clone());
        seed_member_raw(&blobs, &foreign, &a, base, &base_bytes);
        let absent = MemoryKv::with_clock(clock.clone());
        let t = ticket(&b, &thin, NOW as u64 - age);
        let left = verify(
            &blobs,
            &foreign,
            &b,
            std::slice::from_ref(&t),
            [0; 32],
            IndexedConfig::default(),
            &clock,
        )
        .unwrap_err();
        let right = verify(
            &blobs,
            &absent,
            &b,
            &[t],
            [0; 32],
            IndexedConfig::default(),
            &clock,
        )
        .unwrap_err();
        assert_eq!(
            (left.code(), left.public_message(), left.details()),
            (right.code(), right.public_message(), right.details())
        );
        let expected = if age == 0 {
            "repository membership not yet visible"
        } else {
            "delta base not available in this repository"
        };
        assert_eq!(left.public_message(), expected);
    }
}

#[test]
#[allow(clippy::too_many_lines)] // One fixture proves recursion, memoization and the cap.
fn member_frame_resolver_recurses_memoizes_and_caps_total_depth() {
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock);
    let blobs = MemoryBlobStore::default();
    let (a, raw_a) = blob(b"base");
    let (b, raw_b) = blob(b"base2");
    let (c, raw_c) = blob(b"base3");
    let mut writer = PackWriter::new();
    writer.push_raw(a, &raw_a).unwrap();
    writer
        .push_delta(&a, &mkit_core::delta::encode(&raw_a, &raw_b).unwrap())
        .unwrap();
    writer
        .push_delta(&b, &mkit_core::delta::encode(&raw_b, &raw_c).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    let pack_id = hash(&pack);
    upload(&blobs, &pack);
    let mut frames = Vec::new();
    decode_entries_with(
        &pack,
        &mut NoExternalBases,
        DecodeLimits::default(),
        |entry| {
            frames.push(super::entries::FrameMeta {
                id: entry.id,
                frame_offset: entry.frame_offset,
                frame_length: entry.frame_length,
                wire_type: entry.wire_type,
                delta_base: entry.delta_base,
                decoded_size: entry.bytes.len() as u64,
            });
            Ok(())
        },
    )
    .unwrap();
    let entries = super::entries::index_entries(&frames, 50).unwrap();
    let located = crate::store::index::LocatedObject {
        pack: pack_id,
        value: entries[2].value,
    };
    let plan = crate::store::index::plan_index_rows_direct(
        &SinglePartition,
        &repo,
        &source(&repo),
        &pack_id,
        &entries,
        NOW as u64,
    )
    .unwrap();
    for direct in plan.direct {
        let batch = direct
            .puts
            .into_iter()
            .fold(Batch::new(), |batch, (key, value)| batch.put(key, value));
        block_on(store.apply(&direct.target, batch)).unwrap();
    }
    block_on(store.apply(
        &source(&repo),
        Batch::new().put(
            keys::membership(&repo.name, &pack_id),
            crate::Value::default(),
        ),
    ))
    .unwrap();
    let mut memo = BTreeMap::new();
    let mut visiting = BTreeSet::new();
    let (bytes, depth) = block_on(super::resolve::member_object(
        &blobs,
        &store,
        &SinglePartition,
        &repo,
        c,
        located,
        50,
        1 << 20,
        &mut memo,
        &mut visiting,
        &NoopMetrics,
    ))
    .unwrap();
    assert_eq!(bytes, raw_c);
    assert_eq!(depth, 2);
    assert_eq!(memo.len(), 3);
    let before = memo.clone();
    assert_eq!(
        block_on(super::resolve::member_object(
            &blobs,
            &store,
            &SinglePartition,
            &repo,
            c,
            located,
            50,
            1 << 20,
            &mut memo,
            &mut visiting,
            &NoopMetrics
        ))
        .unwrap()
        .1,
        2
    );
    assert_eq!(memo, before);
    let error = block_on(super::resolve::member_object(
        &blobs,
        &store,
        &SinglePartition,
        &repo,
        c,
        located,
        1,
        1 << 20,
        &mut BTreeMap::new(),
        &mut BTreeSet::new(),
        &NoopMetrics,
    ))
    .unwrap_err();
    assert_eq!(
        error
            .public_error(NOW as u64, NOW as u64, 0)
            .public_message(),
        "delta chain too deep"
    );
}

#[test]
fn member_blob_cannot_be_an_advanced_head() {
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    let blobs = MemoryBlobStore::default();
    let (member_id, member_bytes) = blob(b"member blob");
    seed_member_raw(&blobs, &store, &repo, member_id, &member_bytes);
    let (pack, _) = good_pack();
    upload(&blobs, &pack);
    let error = verify(
        &blobs,
        &store,
        &repo,
        &[ticket(&repo, &pack, NOW as u64)],
        member_id,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.public_message(), "open closure");
}

#[test]
fn capped_closure_lookup_has_distinct_permanent_error() {
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    let blobs = MemoryBlobStore::default();
    let (good, head) = good_pack();
    upload(&blobs, &good);
    let missing = [9; 32];
    let orphan = Object::Tree(Tree {
        entries: vec![mkit_core::object::TreeEntry {
            name: b"missing".to_vec(),
            mode: mkit_core::object::EntryMode::Blob,
            object_hash: missing,
        }],
    });
    let mut writer = PackWriter::new_raw_only();
    writer
        .push_raw(orphan.id().unwrap(), &serialize(&orphan).unwrap())
        .unwrap();
    let orphan_pack = writer.finish().unwrap();
    upload(&blobs, &orphan_pack);
    let value = crate::store::codec::encode_object_index(
        &missing,
        &crate::store::index::IndexValue {
            frame_offset: 12,
            frame_length: 20,
            wire_type: 0,
            decoded_size: 5,
            chain_depth: 0,
            delta_base: None,
        },
    )
    .unwrap();
    for chunk in (0..=u32::try_from(crate::store::index::MAX_LOOKUP_ROWS).unwrap())
        .collect::<Vec<_>>()
        .chunks(90)
    {
        let mut batch = Batch::new();
        for n in chunk {
            let mut pack = [0; 32];
            pack[28..].copy_from_slice(&n.to_be_bytes());
            batch = batch.put(
                keys::object_index(&repo.name, &missing, &pack),
                value.clone(),
            );
        }
        block_on(store.apply(&source(&repo), batch)).unwrap();
    }
    let tickets = [
        ticket(&repo, &good, NOW as u64 - 60_000),
        ticket(&repo, &orphan_pack, NOW as u64 - 60_000),
    ];
    let error = verify(
        &blobs,
        &store,
        &repo,
        &tickets,
        head,
        IndexedConfig::default(),
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.public_message(), "object index limit exceeded");
}

#[test]
fn in_pack_delta_chain_above_cap_is_rejected_before_tip() {
    let repo = repo("one");
    let clock = Arc::new(ManualClock::new(NOW));
    let store = MemoryKv::with_clock(clock.clone());
    let blobs = MemoryBlobStore::default();
    let (a, raw_a) = blob(b"base");
    let (b, raw_b) = blob(b"base2");
    let (_, raw_c) = blob(b"base3");
    let mut writer = PackWriter::new();
    writer.push_raw(a, &raw_a).unwrap();
    writer
        .push_delta(&a, &mkit_core::delta::encode(&raw_a, &raw_b).unwrap())
        .unwrap();
    writer
        .push_delta(&b, &mkit_core::delta::encode(&raw_b, &raw_c).unwrap())
        .unwrap();
    let pack = writer.finish().unwrap();
    upload(&blobs, &pack);
    let cfg = IndexedConfig {
        max_delta_chain_depth: 1,
        ..IndexedConfig::default()
    };
    let error = verify(
        &blobs,
        &store,
        &repo,
        &[ticket(&repo, &pack, NOW as u64)],
        [0; 32],
        cfg,
        &clock,
    )
    .unwrap_err();
    assert_eq!(error.public_message(), "delta chain too deep");
}
