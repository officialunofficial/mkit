//! Ticketed advances through the real native pipeline and memory stores.
#![allow(clippy::unwrap_used)] // Invalid fixtures should fail the test immediately.

use super::*;
use crate::repo::MultiAddressing;
use crate::store::{BlobKey, BlobStore, PackSink};
use crate::upload::marker::write_upload_marker;
use bytes::Bytes;
use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::pack::PackWriter;
use mkit_core::repo_identity::Namespace;
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};
use mkit_core::transfer::encode_packlist;

fn environment() -> (Env, SigningKey, String) {
    environment_with_sharding(Sharding::Single)
}

fn environment_with_sharding(sharding: Sharding) -> (Env, SigningKey, String) {
    environment_with(sharding, crate::indexed::IndexedConfig::default())
}

pub(super) fn environment_with(
    sharding: Sharding,
    indexed: crate::indexed::IndexedConfig,
) -> (Env, SigningKey, String) {
    environment_with_policy(sharding, indexed, None)
}

pub(super) fn environment_with_policy(
    sharding: Sharding,
    indexed: crate::indexed::IndexedConfig,
    ref_policy: Option<crate::policy::RefPolicy>,
) -> (Env, SigningKey, String) {
    let owner = key(7);
    let namespace = Namespace::Ed25519(*owner.verifying_key().as_bytes());
    let identity = format!("{namespace}/{REPO}");
    let mut config = cfg(authv2());
    config.addressing = Addressing::Multi(
        MultiAddressing::new()
            .with_namespace_policy(NamespacePolicy::Allowlist([namespace].into())),
    );
    config.write_policy = WritePolicy::Owner;
    config.sharding = sharding;
    config.ticket_keys =
        Some(crate::upload::token::TicketKeys::new(vec![("test".into(), [7; 32])]).unwrap());
    config.indexed = Some(indexed);
    config.ref_policy = ref_policy;
    let clock = clock();
    (
        build(config, Spy::new(store(&clock)), Hooks::new(), clock),
        owner,
        identity,
    )
}

pub(super) fn signed(owner: &SigningKey, identity: &str, procedure: Procedure, number: u32) -> Req {
    let body = b"indexed-pipeline".to_vec();
    let digest = to_hex(&hash(&body));
    let commitment = format!("body:{digest}");
    let nonce = nonce(number);
    let envelope = SignedOp {
        context: AuthContext {
            audience: AUDIENCE,
            repository: identity,
        },
        procedure: procedure.connect_path(),
        commitment: &commitment,
        created_at: T0,
        expires_at: T0 + 300_000,
        nonce: &nonce,
    };
    let signature = owner.sign(&envelope.digest().unwrap());
    let mut request = Req::unsigned(procedure);
    request.body = body;
    for (name, value) in [
        ("x-envelope-version", "2".to_owned()),
        ("x-audience", AUDIENCE.to_owned()),
        ("x-repository", identity.to_owned()),
        ("x-public-key", to_hex(owner.verifying_key().as_bytes())),
        ("x-signature", to_hex_bytes(&signature.to_bytes())),
        ("x-content-commitment", commitment),
        ("x-digest", digest),
        ("x-created-at", T0.to_string()),
        ("x-expires-at", (T0 + 300_000).to_string()),
        ("idempotency-key", nonce),
    ] {
        request = request.header(name, &value);
    }
    request
}

fn signed_objects() -> (Object, Object, Hash) {
    let tree = Object::Tree(Tree {
        entries: Vec::new(),
    });
    let tree_id = tree.id().unwrap();
    let signer = KeyPair::from_seed([9; 32]);
    let mut commit = Commit::new_unannotated(
        tree_id,
        Vec::new(),
        Identity::ed25519(signer.public.0),
        signer.public.0,
        b"indexed".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &signer).unwrap().0;
    let commit = Object::Commit(commit);
    let head = commit.id().unwrap();
    (tree, commit, head)
}

pub(super) fn pack() -> (Vec<u8>, Hash) {
    let (tree, commit, head) = signed_objects();
    let mut writer = PackWriter::new_raw_only();
    writer
        .push_raw(tree.id().unwrap(), &serialize(&tree).unwrap())
        .unwrap();
    writer.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    (writer.finish().unwrap(), head)
}

pub(super) fn split_pack() -> (Vec<u8>, Vec<u8>, Hash) {
    let (tree, commit, head) = signed_objects();
    let mut first = PackWriter::new_raw_only();
    first.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    let mut second = PackWriter::new_raw_only();
    second
        .push_raw(tree.id().unwrap(), &serialize(&tree).unwrap())
        .unwrap();
    (first.finish().unwrap(), second.finish().unwrap(), head)
}

pub(super) fn upload(env: &Env, pack: &[u8], ticket_id: Hash) {
    let pack_id = hash(pack);
    block_on(async {
        let mut sink = env
            .pipe
            .blobs
            .begin(BlobKey::pack(pack_id), pack.len() as u64)
            .await
            .unwrap();
        sink.write(Bytes::copy_from_slice(pack)).await.unwrap();
        sink.commit().await.unwrap();
        write_upload_marker(&env.pipe.blobs, &ticket_id, &pack_id)
            .await
            .unwrap();
    });
}

pub(super) fn begin_and_upload(
    env: &Env,
    owner: &SigningKey,
    identity: &str,
    pack: &[u8],
    number: u32,
) -> Hash {
    let request = signed(owner, identity, Procedure::BeginUpload, number);
    let BeginUploadResult::Ticket { id, .. } = block_on(env.pipe.begin_upload(
        &env.auth(&request).unwrap(),
        HEAD,
        &hash(pack),
        pack.len() as u64,
    ))
    .unwrap() else {
        panic!("expected upload ticket");
    };
    upload(env, pack, id);
    id
}

pub(super) fn assert_advance_unmoved(env: &Env, repo: &RepoId, packs: &[Hash]) {
    let source = env.pipe.shards.ref_shard(repo, HEAD);
    for key in [
        keys::ref_key(&repo.name, HEAD),
        keys::ref_key(&repo.name, PACKMAP),
    ] {
        assert!(
            block_on(env.pipe.meta.get(&source, &key))
                .unwrap()
                .is_none()
        );
    }
    for pack in packs {
        assert!(
            block_on(
                env.pipe
                    .meta
                    .get(&source, &keys::membership(&repo.name, pack))
            )
            .unwrap()
            .is_none()
        );
    }
}

#[test]
fn verified_pack_reuse_rechecks_closure_on_current_consumed_set() {
    let (env, owner, identity) = environment();
    let (commit_pack, tree_pack, head) = split_pack();
    let mut tickets = Vec::new();
    for (number, bytes) in [(100, &commit_pack), (101, &tree_pack)] {
        tickets.push(begin_and_upload(&env, &owner, &identity, bytes, number));
    }

    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 102);
    let auth = env.auth(&request).unwrap();
    let repo = auth.repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    assert_eq!(
        block_on(env.pipe.advance_refs_with_tickets(
            &auth,
            upd(HEAD, Match([0x5a; 32]), head),
            upd(PACKMAP, Missing, hash(&tree_pack)),
            tickets.clone(),
        ))
        .unwrap(),
        AdvanceOutcome::HeadConflict
    );
    for bytes in [&commit_pack, &tree_pack] {
        let raw = block_on(
            env.pipe
                .meta
                .get(&source, &keys::verification(&repo.name, &hash(bytes))),
        )
        .unwrap()
        .unwrap();
        assert!(matches!(
            crate::indexed::state::decode(&raw).unwrap(),
            crate::indexed::state::VerificationV1::Verified { .. }
        ));
    }
    assert!(
        block_on(env.pipe.meta.get(&source, &keys::ref_key(&repo.name, HEAD)))
            .unwrap()
            .is_none()
    );

    env.clock.advance(
        i64::try_from(crate::indexed::IndexedConfig::default().relay_lag_bound_ms).unwrap(),
    );
    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 103);
    let error = block_on(env.pipe.advance_refs_with_tickets(
        &env.auth(&request).unwrap(),
        upd(HEAD, Missing, head),
        upd(PACKMAP, Missing, hash(&commit_pack)),
        vec![tickets[0]],
    ))
    .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(error.public_message(), "open closure");
    for key in [
        keys::ref_key(&repo.name, HEAD),
        keys::ref_key(&repo.name, PACKMAP),
        keys::membership(&repo.name, &hash(&commit_pack)),
        keys::membership(&repo.name, &hash(&tree_pack)),
    ] {
        assert!(
            block_on(env.pipe.meta.get(&source, &key))
                .unwrap()
                .is_none()
        );
    }

    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 104);
    assert_eq!(
        block_on(env.pipe.advance_refs_with_tickets(
            &env.auth(&request).unwrap(),
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, hash(&tree_pack)),
            tickets,
        ))
        .unwrap(),
        AdvanceOutcome::Committed
    );
    assert!(
        block_on(env.pipe.meta.get(&source, &keys::ref_key(&repo.name, HEAD)))
            .unwrap()
            .is_some()
    );
}

#[test]
fn indexed_dangling_and_unknown_upload_leave_refs_unmoved() {
    for (case, expected) in [(0, "open closure"), (1, "unknown upload type")] {
        let (env, owner, identity) = environment();
        let (bytes, head) = if case == 0 {
            let (tree, commit, head) = signed_objects();
            let orphan = Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"missing".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: [0x99; 32],
                }],
            });
            let mut writer = PackWriter::new_raw_only();
            for object in [&tree, &commit, &orphan] {
                writer
                    .push_raw(object.id().unwrap(), &serialize(object).unwrap())
                    .unwrap();
            }
            (writer.finish().unwrap(), head)
        } else {
            (b"NOPE-unknown-upload-type-content".to_vec(), [0x55; 32])
        };
        let pack_id = hash(&bytes);
        let id = begin_and_upload(&env, &owner, &identity, &bytes, 200);
        if case == 0 {
            env.clock.advance(
                i64::try_from(crate::indexed::IndexedConfig::default().relay_lag_bound_ms).unwrap(),
            );
        }
        let request = signed(&owner, &identity, Procedure::AdvanceRefs, 201);
        let auth = env.auth(&request).unwrap();
        let repo = auth.repo().repo.clone();
        let error = block_on(env.pipe.advance_refs_with_tickets(
            &auth,
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, pack_id),
            vec![id],
        ))
        .unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument);
        assert_eq!(error.public_message(), expected);
        assert_advance_unmoved(&env, &repo, &[pack_id]);
    }
}

#[test]
fn indexed_foreign_packlist_miss_leaves_refs_unmoved_inside_and_after_lag() {
    let (env, owner, identity) = environment();
    let (good, head) = pack();
    let foreign = [0x81; 32];
    let list = encode_packlist(None, &[foreign]).unwrap();
    let ids = [
        begin_and_upload(&env, &owner, &identity, &good, 210),
        begin_and_upload(&env, &owner, &identity, &list, 211),
    ];
    let packs = [hash(&good), hash(&list)];
    for (number, expected, code) in [
        (
            212,
            "repository membership not yet visible",
            Code::Unavailable,
        ),
        (
            213,
            "packlist lists a pack that is not in this repository",
            Code::InvalidArgument,
        ),
    ] {
        if number == 213 {
            env.clock.advance(
                i64::try_from(crate::indexed::IndexedConfig::default().relay_lag_bound_ms).unwrap(),
            );
        }
        let request = signed(&owner, &identity, Procedure::AdvanceRefs, number);
        let auth = env.auth(&request).unwrap();
        let repo = auth.repo().repo.clone();
        let error = block_on(env.pipe.advance_refs_with_tickets(
            &auth,
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, packs[1]),
            ids.to_vec(),
        ))
        .unwrap_err();
        assert_eq!(error.code(), code);
        assert_eq!(error.public_message(), expected);
        assert_advance_unmoved(&env, &repo, &packs);
    }
}

#[test]
#[allow(clippy::too_many_lines)] // One fixture compares both repositories at both lag-window times.
fn indexed_foreign_and_absent_thin_bases_match_and_leave_refs_unmoved() {
    let base = Object::Blob(Blob {
        data: b"base".to_vec(),
    });
    let target = Object::Blob(Blob {
        data: b"target".to_vec(),
    });
    let base_id = base.id().unwrap();
    let target_id = target.id().unwrap();
    let base_bytes = serialize(&base).unwrap();
    let target_bytes = serialize(&target).unwrap();
    let mut writer = PackWriter::new();
    writer
        .push_delta(
            &base_id,
            &mkit_core::delta::encode(&base_bytes, &target_bytes).unwrap(),
        )
        .unwrap();
    let thin = writer.finish().unwrap();
    let thin_id = hash(&thin);
    let mut answers = Vec::new();
    for foreign_exists in [false, true] {
        let (env, owner, identity) = environment();
        let ticket = begin_and_upload(&env, &owner, &identity, &thin, 220);
        let request = signed(&owner, &identity, Procedure::AdvanceRefs, 221);
        let repo = env.auth(&request).unwrap().repo().repo.clone();
        if foreign_exists {
            let foreign = RepoId {
                namespace: repo.namespace.clone(),
                name: RepoName::new("foreign").unwrap(),
            };
            let mut writer = PackWriter::new_raw_only();
            writer.push_raw(base_id, &base_bytes).unwrap();
            let member_pack = writer.finish().unwrap();
            let member_id = hash(&member_pack);
            let mut sink = block_on(
                env.pipe
                    .blobs
                    .begin(BlobKey::pack(member_id), member_pack.len() as u64),
            )
            .unwrap();
            block_on(sink.write(Bytes::from(member_pack))).unwrap();
            block_on(sink.commit()).unwrap();
            let value = crate::store::index::IndexValue {
                frame_offset: 12,
                frame_length: 20,
                wire_type: 0,
                decoded_size: base_bytes.len() as u64,
                chain_depth: 0,
                delta_base: None,
            };
            let partition = env.pipe.shards.object_index(&foreign, &base_id);
            block_on(
                env.pipe.meta.apply(
                    &partition,
                    Batch::new()
                        .put(
                            keys::object_index(&foreign.name, &base_id, &member_id),
                            codec::encode_object_index(&base_id, &value).unwrap(),
                        )
                        .put(
                            keys::membership(&foreign.name, &member_id),
                            Value::default(),
                        ),
                ),
            )
            .unwrap();
        }
        let mut repo_answers = Vec::new();
        for (number, expected, code) in [
            (
                221,
                "repository membership not yet visible",
                Code::Unavailable,
            ),
            (
                222,
                "delta base not available in this repository",
                Code::FailedPrecondition,
            ),
        ] {
            if number == 222 {
                env.clock.advance(
                    i64::try_from(crate::indexed::IndexedConfig::default().relay_lag_bound_ms)
                        .unwrap(),
                );
            }
            let request = signed(&owner, &identity, Procedure::AdvanceRefs, number);
            let auth = env.auth(&request).unwrap();
            let error = block_on(env.pipe.advance_refs_with_tickets(
                &auth,
                upd(HEAD, Missing, target_id),
                upd(PACKMAP, Missing, thin_id),
                vec![ticket],
            ))
            .unwrap_err();
            assert_eq!(error.code(), code);
            assert_eq!(error.public_message(), expected);
            assert_advance_unmoved(&env, &repo, &[thin_id]);
            repo_answers.push((
                error.code(),
                error.public_message().to_owned(),
                error.details().to_vec(),
            ));
        }
        answers.push(repo_answers);
    }
    assert_eq!(answers[0], answers[1]);
}

#[test]
fn indexed_concurrent_lease_has_no_replay_row_and_retry_commits() {
    let (env, owner, identity) = environment();
    let (bytes, head) = pack();
    let pack_id = hash(&bytes);
    let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 230);
    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 231);
    let auth = env.auth(&request).unwrap();
    let repo = auth.repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let state = crate::indexed::state::VerificationV1::Pending {
        lease_until_ms: T0 as u64 + crate::indexed::state::VERIFICATION_LEASE_MS,
    };
    block_on(env.pipe.meta.apply(
        &source,
        Batch::new().put(
            keys::verification(&repo.name, &pack_id),
            crate::indexed::state::encode(&state),
        ),
    ))
    .unwrap();
    let replay = keys::replay(&auth.auth.as_ref().unwrap().replay_scope);
    let attempt = || {
        block_on(env.pipe.advance_refs_with_tickets(
            &auth,
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, pack_id),
            vec![ticket],
        ))
    };
    let error = attempt().unwrap_err();
    assert_eq!(error.public_message(), "pack verification pending");
    assert_eq!(error.details().len(), 1);
    assert!(
        block_on(env.pipe.meta.get(&source, &replay))
            .unwrap()
            .is_none()
    );
    env.clock
        .advance(i64::try_from(crate::indexed::state::VERIFICATION_LEASE_MS + 1).unwrap());
    assert_eq!(attempt().unwrap(), AdvanceOutcome::Committed);
}

#[test]
fn indexed_seven_ticket_advance_adds_no_batch_rows() {
    for (sharding, expected) in [(Sharding::D34, 89), (Sharding::Single, 78)] {
        let d34 = sharding == Sharding::D34;
        let batch = planned_ticket_advance_mode(7, d34);
        assert_eq!(batch.preconditions.len() + batch.writes.len(), expected);
        assert!(batch.writes.iter().all(|write| {
            let (Write::Put(key, _) | Write::Delete(key)) = write;
            !matches!(
                keys::parse(key),
                Some(keys::ParsedKey::ObjectIndex { .. } | keys::ParsedKey::Verification { .. })
            )
        }));

        let (env, owner, identity) = environment_with_sharding(sharding);
        let (head_pack, head) = pack();
        let mut packs = vec![head_pack];
        for i in 0..6_u8 {
            let object = Object::Blob(Blob { data: vec![i] });
            let mut writer = PackWriter::new_raw_only();
            writer
                .push_raw(object.id().unwrap(), &serialize(&object).unwrap())
                .unwrap();
            packs.push(writer.finish().unwrap());
        }
        let tickets: Vec<_> = packs
            .iter()
            .enumerate()
            .map(|(i, bytes)| {
                begin_and_upload(
                    &env,
                    &owner,
                    &identity,
                    bytes,
                    1_000 + u32::try_from(i).unwrap(),
                )
            })
            .collect();
        let request = signed(&owner, &identity, Procedure::AdvanceRefs, 1_100);
        let auth = env.auth(&request).unwrap();
        let repo = auth.repo().repo.clone();
        assert_eq!(
            block_on(env.pipe.advance_refs_with_tickets(
                &auth,
                upd(HEAD, Missing, head),
                upd(PACKMAP, Missing, hash(&packs[0])),
                tickets,
            ))
            .unwrap(),
            AdvanceOutcome::Committed
        );
        let ref_key = keys::ref_key(&repo.name, HEAD);
        let batches = env.pipe.meta.batches.lock().unwrap();
        let advances: Vec<_> = batches
            .iter()
            .filter(|batch| {
                batch
                    .writes
                    .iter()
                    .any(|write| matches!(write, Write::Put(key, _) if *key == ref_key))
            })
            .collect();
        assert_eq!(advances.len(), 1);
        let actual = advances[0];
        assert!(actual.preconditions.len() + actual.writes.len() <= expected);
        assert!(actual.writes.iter().all(|write| {
            let (Write::Put(key, _) | Write::Delete(key)) = write;
            !matches!(
                keys::parse(key),
                Some(keys::ParsedKey::ObjectIndex { .. } | keys::ParsedKey::Verification { .. })
            )
        }));
    }
}

#[test]
fn ticketed_good_push_commits_after_index_and_bad_pack_leaves_refs_unmoved() {
    for variant in 0..3 {
        let (env, owner, identity) = environment();
        let (mut pack, head) = pack();
        if variant == 1 {
            // Mutate the content while preserving the transport-level pack
            // commitment. The entry's claimed id then disagrees with bytes.
            let trailer = pack.len() - 32;
            pack[trailer - 1] ^= 1;
            let digest = hash(&pack[..trailer]);
            pack[trailer..].copy_from_slice(&digest);
        } else if variant == 2 {
            let last = pack.len() - 1;
            pack[last] ^= 1;
        }
        let pack_id = hash(&pack);
        let begin = signed(&owner, &identity, Procedure::BeginUpload, 10);
        let result = block_on(env.pipe.begin_upload(
            &env.auth(&begin).unwrap(),
            HEAD,
            &pack_id,
            pack.len() as u64,
        ))
        .unwrap();
        let BeginUploadResult::Ticket { id, .. } = result else {
            panic!("expected upload ticket");
        };
        upload(&env, &pack, id);
        let advance = signed(&owner, &identity, Procedure::AdvanceRefs, 11);
        let result = block_on(env.pipe.advance_refs_with_tickets(
            &env.auth(&advance).unwrap(),
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, pack_id),
            vec![id],
        ));
        let repo = env.auth(&advance).unwrap().repo().repo.clone();
        let source = env.pipe.shards.ref_shard(&repo, HEAD);
        let ref_row =
            block_on(env.pipe.meta.get(&source, &keys::ref_key(&repo.name, HEAD))).unwrap();
        if variant != 0 {
            assert_eq!(
                result.unwrap_err().public_message(),
                if variant == 1 {
                    "bad signature"
                } else {
                    "object hash mismatch"
                }
            );
            assert!(ref_row.is_none());
        } else {
            assert!(matches!(result.unwrap(), AdvanceOutcome::Committed));
            assert!(ref_row.is_some());
            assert!(
                block_on(
                    env.pipe
                        .meta
                        .get(&source, &keys::membership(&repo.name, &pack_id))
                )
                .unwrap()
                .is_some()
            );
        }
    }
}

#[test]
fn begin_already_present_depends_on_membership_not_index_rows() {
    let (pack, _) = pack();
    let pack_id = hash(&pack);
    for member in [false, true] {
        let (env, owner, identity) = environment();
        let request = signed(&owner, &identity, Procedure::BeginUpload, 20);
        let auth = env.auth(&request).unwrap();
        let repo = auth.repo().repo.clone();
        let source = env.pipe.shards.ref_shard(&repo, HEAD);
        let index = keys::object_index(&repo.name, &[0x44; 32], &pack_id);
        let mut batch = Batch::new().put(index, Value::default());
        if member {
            batch = batch.put(keys::membership(&repo.name, &pack_id), Value::default());
        }
        block_on(env.pipe.meta.apply(&source, batch)).unwrap();
        let result = block_on(
            env.pipe
                .begin_upload(&auth, HEAD, &pack_id, pack.len() as u64),
        )
        .unwrap();
        if member {
            assert!(matches!(result, BeginUploadResult::AlreadyPresent));
        } else {
            assert!(matches!(result, BeginUploadResult::Ticket { .. }));
        }
    }
}

/// A pack of one 70,000-byte file, its tree and a signed commit.
fn file_pack() -> (Vec<u8>, Hash, Hash) {
    let blob = Object::Blob(Blob {
        data: vec![0x42; 70_000],
    });
    let blob_id = blob.id().unwrap();
    let tree = Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"file".to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob_id,
        }],
    });
    let signer = KeyPair::from_seed([9; 32]);
    let mut commit = Commit::new_unannotated(
        tree.id().unwrap(),
        Vec::new(),
        Identity::ed25519(signer.public.0),
        signer.public.0,
        b"file".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &signer).unwrap().0;
    let commit = Object::Commit(commit);
    let head = commit.id().unwrap();
    let mut writer = PackWriter::new_raw_only();
    for object in [&blob, &tree, &commit] {
        writer
            .push_raw(object.id().unwrap(), &serialize(object).unwrap())
            .unwrap();
    }
    (writer.finish().unwrap(), head, blob_id)
}

#[test]
fn extraction_stores_the_file_and_no_pack_rpc_serves_it() {
    let (env, owner, identity) = environment();
    let (bytes, head, blob_id) = file_pack();
    let pack_id = hash(&bytes);
    let id = begin_and_upload(&env, &owner, &identity, &bytes, 300);
    let advance = signed(&owner, &identity, Procedure::AdvanceRefs, 301);
    assert_eq!(
        block_on(env.pipe.advance_refs_with_tickets(
            &env.auth(&advance).unwrap(),
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, pack_id),
            vec![id],
        ))
        .unwrap(),
        AdvanceOutcome::Committed
    );
    // The file is in the global object namespace, held by this repository.
    let meta = block_on(env.pipe.blobs.head(&BlobKey::object(blob_id))).unwrap();
    assert_eq!(meta.map(|m| m.len), Some(70_000));
    let content = crate::store::ContentIndex::new(crate::store::BorrowedStore(&env.pipe.meta));
    let state = block_on(content.state(&blob_id)).unwrap().unwrap();
    assert_eq!(state.holders, 1);
    // No pack RPC serves it: the object is not a pack of this repository,
    // and the pack keyspace never holds it.
    let exists = signed(&owner, &identity, Procedure::PackExists, 302);
    assert!(
        !block_on(
            env.pipe
                .pack_exists(&env.auth(&exists).unwrap(), PackKey::new(blob_id))
        )
        .unwrap()
    );
    let exists = signed(&owner, &identity, Procedure::PackExists, 303);
    assert!(
        block_on(
            env.pipe
                .pack_exists(&env.auth(&exists).unwrap(), PackKey::new(pack_id))
        )
        .unwrap()
    );
    let download = signed(&owner, &identity, Procedure::DownloadPack, 304);
    let error = block_on(
        env.pipe
            .download(&env.auth(&download).unwrap(), PackKey::new(blob_id)),
    )
    .err()
    .unwrap();
    assert_eq!(error.code(), Code::NotFound);
    assert!(
        block_on(env.pipe.blobs.head(&BlobKey::pack(blob_id)))
            .unwrap()
            .is_none()
    );
}

#[test]
fn opaque_mode_never_touches_the_object_store_or_the_content_index() {
    // The same push as the extraction test, without `indexed`.
    let owner = key(7);
    let namespace = Namespace::Ed25519(*owner.verifying_key().as_bytes());
    let identity = format!("{namespace}/{REPO}");
    let mut config = cfg(authv2());
    config.addressing = Addressing::Multi(
        MultiAddressing::new()
            .with_namespace_policy(NamespacePolicy::Allowlist([namespace].into())),
    );
    config.write_policy = WritePolicy::Owner;
    config.ticket_keys =
        Some(crate::upload::token::TicketKeys::new(vec![("test".into(), [7; 32])]).unwrap());
    assert!(config.indexed.is_none());
    let clock = clock();
    let env = build(config, Spy::new(store(&clock)), Hooks::new(), clock);
    let (bytes, head, blob_id) = file_pack();
    let pack_id = hash(&bytes);
    let id = begin_and_upload(&env, &owner, &identity, &bytes, 400);
    let advance = signed(&owner, &identity, Procedure::AdvanceRefs, 401);
    assert_eq!(
        block_on(env.pipe.advance_refs_with_tickets(
            &env.auth(&advance).unwrap(),
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, pack_id),
            vec![id],
        ))
        .unwrap(),
        AdvanceOutcome::Committed
    );
    assert!(
        block_on(env.pipe.blobs.head(&BlobKey::object(blob_id)))
            .unwrap()
            .is_none(),
        "no object was extracted"
    );
    assert!(
        block_on(env.pipe.blobs.head(&BlobKey::object_offsets(blob_id)))
            .unwrap()
            .is_none()
    );
    let content = crate::store::ContentIndex::new(crate::store::BorrowedStore(&env.pipe.meta));
    assert!(block_on(content.state(&blob_id)).unwrap().is_none());
}

#[test]
fn indexed_limits_of_zero_are_refused_at_construction() {
    // Zero limits, and an extraction cap below `max_pack_bytes`.
    for (min, max) in [(0, 1), (1, 0), (1, 1)] {
        let owner = key(7);
        let namespace = Namespace::Ed25519(*owner.verifying_key().as_bytes());
        let mut config = cfg(authv2());
        config.addressing = Addressing::Multi(
            MultiAddressing::new()
                .with_namespace_policy(NamespacePolicy::Allowlist([namespace].into())),
        );
        config.write_policy = WritePolicy::Owner;
        config.ticket_keys =
            Some(crate::upload::token::TicketKeys::new(vec![("test".into(), [7; 32])]).unwrap());
        config.indexed = Some(crate::indexed::IndexedConfig {
            extract_min_bytes: min,
            max_extract_bytes: Some(max),
            ..crate::indexed::IndexedConfig::default()
        });
        let clock = clock();
        let built = Pipeline::new(
            crate::memory::MemoryBlobStore::default(),
            store(&clock),
            Hooks::new(),
            config,
            clock,
            std::sync::Arc::new(crate::telemetry::NoopMetrics),
        );
        assert_eq!(
            built.err().unwrap().public_message(),
            "invalid indexed limits"
        );
    }
}
