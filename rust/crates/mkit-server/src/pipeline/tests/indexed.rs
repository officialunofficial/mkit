//! Ticketed advances through the real native pipeline and memory stores.
#![allow(clippy::unwrap_used)] // Invalid fixtures should fail the test immediately.

use super::*;
use crate::repo::MultiAddressing;
use crate::store::{BlobKey, BlobStore, PackSink};
use crate::upload::marker::write_upload_marker;
use bytes::Bytes;
use futures::StreamExt as _;
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
    environment_with_hooks(sharding, indexed, ref_policy, Hooks::new())
}

pub(super) fn environment_with_hooks<H: HookSet>(
    sharding: Sharding,
    indexed: crate::indexed::IndexedConfig,
    ref_policy: Option<crate::policy::RefPolicy>,
    hooks: H,
) -> (Env<H>, SigningKey, String) {
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
        build(config, Spy::new(store(&clock)), hooks, clock),
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

pub(super) fn signed_objects() -> (Object, Object, Hash) {
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

/// The signed commit and its tree plus one blob of `extra`: a distinct pack
/// with the same head, for tests that need several packs of one history.
pub(super) fn pack_with_blob(extra: u8) -> Vec<u8> {
    let (tree, commit, head) = signed_objects();
    let blob = Object::Blob(Blob {
        data: vec![extra; 64],
    });
    let mut writer = PackWriter::new_raw_only();
    writer
        .push_raw(tree.id().unwrap(), &serialize(&tree).unwrap())
        .unwrap();
    writer.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    writer
        .push_raw(blob.id().unwrap(), &serialize(&blob).unwrap())
        .unwrap();
    writer.finish().unwrap()
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

pub(super) fn upload<H: HookSet>(env: &Env<H>, pack: &[u8], ticket_id: Hash) {
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
    // Publication adds four operations to the immediate ticket batches.
    for (sharding, expected) in [(Sharding::D34, 93), (Sharding::Single, 84)] {
        let d34 = sharding == Sharding::D34;
        let batch = planned_ticket_advance_mode(7, d34);
        assert_eq!(batch.preconditions.len() + batch.writes.len(), expected);
        assert!(expected <= crate::store::MAX_BATCH_OPS);
        if !d34 {
            assert_eq!(
                batch
                    .preconditions
                    .iter()
                    .filter(|guard| matches!(guard,
                        Precondition::Absent(key) if *key == keys::authority_generation()
                    ))
                    .count(),
                1
            );
            assert_eq!(
                batch
                    .preconditions
                    .iter()
                    .filter(|guard| matches!(guard,
                        Precondition::Absent(key) if *key == keys::lease_recovery()
                    ))
                    .count(),
                1
            );
        }
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
        // Stored-bytes counting adds one relay row on D34 and, on Single,
        // the seven markers, the counter and one outcome row.
        let counting = if d34 { 1 } else { 12 };
        assert!(actual.preconditions.len() + actual.writes.len() <= expected + counting);
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

pub(super) struct InspectionPolicy(pub(super) crate::store::publication::Clearance);
impl clearance::PublicationPolicy for InspectionPolicy {
    fn prepare<'a>(
        &'a self,
        _: &'a Operation,
        pair: &'a crate::store::publication::Pair,
    ) -> crate::BoxFuture<'a, Result<crate::store::publication::Advance, ServerError>> {
        Box::pin(async move {
            let mut a = clearance::immediate(pair.clone(), [0; 32], vec![]);
            a.state = self.0;
            a.obligations.push(crate::store::publication::Obligation {
                id: [1; 32],
                state: self.0,
            });
            Ok(a)
        })
    }
    fn pack_available(&self, _: &RepoId, _: &Hash) -> bool {
        true
    }
}

#[test]
fn no_inspector_real_advance_reader_and_writer_views_are_identical() {
    let (env, owner, identity) = environment();
    let (bytes, head) = pack();
    let pack_id = hash(&bytes);
    let node = encode_packlist(None, &[pack_id]).unwrap();
    let map = hash(&node);
    let tickets = vec![
        begin_and_upload(&env, &owner, &identity, &bytes, 9000),
        begin_and_upload(&env, &owner, &identity, &node, 9001),
    ];
    let a = env
        .auth(&signed(&owner, &identity, Procedure::AdvanceRefs, 9002))
        .unwrap();
    assert_eq!(
        block_on(env.pipe.advance_refs_with_tickets(
            &a,
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, map),
            tickets
        ))
        .unwrap(),
        AdvanceOutcome::Committed
    );
    let repo = a.repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let state = block_on(crate::store::publication::read(
        &env.pipe.meta,
        &source,
        &repo.name,
        HEAD,
    ))
    .unwrap();
    assert_eq!(state.sequence, state.published);
    assert_eq!(
        state.value,
        crate::store::publication::Pair {
            head: Some(head),
            packmap: Some(map)
        }
    );
    let anonymous = |procedure| {
        env.auth(&Req::unsigned(procedure).header("x-repository", &identity))
            .unwrap()
    };
    let reader = anonymous(Procedure::ListRefs);
    let writer = env
        .auth(&signed(&owner, &identity, Procedure::ListRefs, 9003))
        .unwrap();
    assert_eq!(
        block_on(env.pipe.list_refs(&reader, "")).unwrap(),
        block_on(env.pipe.list_refs(&writer, "")).unwrap()
    );
    for name in [HEAD, PACKMAP] {
        let reader = anonymous(Procedure::ReadRef);
        let writer = env
            .auth(&signed(&owner, &identity, Procedure::ReadRef, 9004))
            .unwrap();
        assert_eq!(
            block_on(env.pipe.read_ref(&reader, name)).unwrap(),
            block_on(env.pipe.read_ref(&writer, name)).unwrap()
        );
    }
    let reader = anonymous(Procedure::PackExists);
    let writer = env
        .auth(&signed(&owner, &identity, Procedure::PackExists, 9005))
        .unwrap();
    assert!(block_on(env.pipe.pack_exists(&reader, PackKey(pack_id))).unwrap());
    assert_eq!(
        block_on(env.pipe.pack_exists(&reader, PackKey(pack_id))).unwrap(),
        block_on(env.pipe.pack_exists(&writer, PackKey(pack_id))).unwrap()
    );
    let read_bytes = |auth: &Authenticated| {
        block_on(async {
            let mut stream = env.pipe.download(auth, PackKey(pack_id)).await.unwrap();
            let mut out = Vec::new();
            while let Some(chunk) = stream.chunks.next().await {
                out.extend_from_slice(&chunk.unwrap().data);
            }
            out
        })
    };
    let reader = anonymous(Procedure::DownloadPack);
    let writer = env
        .auth(&signed(&owner, &identity, Procedure::DownloadPack, 9006))
        .unwrap();
    assert_eq!(read_bytes(&reader), bytes);
    assert_eq!(read_bytes(&reader), read_bytes(&writer));
}

#[test]
#[allow(clippy::too_many_lines)] // One real advance exercises both caller views and both byte RPCs.
fn inspection_pending_is_writer_visible_but_held_bytes_are_absent_for_everyone() {
    let (mut env, owner, identity) = environment();
    env.pipe = env
        .pipe
        .with_publication_policy(Arc::new(InspectionPolicy(
            crate::store::publication::Clearance::Pending,
        )))
        .unwrap();
    let (bytes, head) = pack();
    let pack_id = hash(&bytes);
    let node = encode_packlist(None, &[pack_id]).unwrap();
    let map = hash(&node);
    let tickets = vec![
        begin_and_upload(&env, &owner, &identity, &bytes, 9100),
        begin_and_upload(&env, &owner, &identity, &node, 9101),
    ];
    let a = env
        .auth(&signed(&owner, &identity, Procedure::AdvanceRefs, 9102))
        .unwrap();
    assert_eq!(
        block_on(env.pipe.advance_refs_with_tickets(
            &a,
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, map),
            tickets
        ))
        .unwrap(),
        AdvanceOutcome::Committed
    );
    let reader = env
        .auth(&Req::unsigned(Procedure::ReadRef).header("x-repository", &identity))
        .unwrap();
    let writer = env
        .auth(&signed(&owner, &identity, Procedure::ReadRef, 9103))
        .unwrap();
    assert_eq!(block_on(env.pipe.read_ref(&reader, HEAD)).unwrap(), None);
    assert_eq!(
        block_on(env.pipe.read_ref(&writer, HEAD)).unwrap(),
        Some(head)
    );
    let reader = env
        .auth(&Req::unsigned(Procedure::ListRefs).header("x-repository", &identity))
        .unwrap();
    let writer = env
        .auth(&signed(&owner, &identity, Procedure::ListRefs, 9105))
        .unwrap();
    assert!(
        block_on(env.pipe.list_refs(&reader, ""))
            .unwrap()
            .is_empty()
    );
    assert!(
        !block_on(env.pipe.list_refs(&writer, ""))
            .unwrap()
            .is_empty()
    );
    let r = a.repo().repo.clone();
    let p = env.pipe.shards.ref_shard(&r, HEAD);
    for procedure in [Procedure::PackExists, Procedure::DownloadPack] {
        let reader = env
            .auth(&Req::unsigned(procedure).header("x-repository", &identity))
            .unwrap();
        let writer = env
            .auth(&signed(&owner, &identity, procedure, 9104))
            .unwrap();
        if procedure == Procedure::PackExists {
            assert!(!block_on(env.pipe.pack_exists(&reader, PackKey(pack_id))).unwrap());
            assert!(block_on(env.pipe.pack_exists(&writer, PackKey(pack_id))).unwrap());
        } else {
            assert_eq!(
                block_on(env.pipe.download(&reader, PackKey(pack_id)))
                    .err()
                    .unwrap()
                    .code(),
                Code::NotFound
            );
            assert!(block_on(env.pipe.download(&writer, PackKey(pack_id))).is_ok());
        }
        let key = keys::membership(&r.name, &pack_id);
        let raw = block_on(env.pipe.meta.get(&p, &key)).unwrap().unwrap();
        let mut w = crate::store::publication::Witness::decode(&raw).unwrap();
        w.held = true;
        block_on(
            env.pipe
                .meta
                .inner
                .apply(&p, Batch::new().put(key, w.encode())),
        )
        .unwrap();
        for auth in [&reader, &writer] {
            if procedure == Procedure::PackExists {
                assert!(!block_on(env.pipe.pack_exists(auth, PackKey(pack_id))).unwrap());
            } else {
                assert_eq!(
                    block_on(env.pipe.download(auth, PackKey(pack_id)))
                        .err()
                        .unwrap()
                        .code(),
                    Code::NotFound
                );
            }
        }
        w.held = false;
        block_on(env.pipe.meta.inner.apply(
            &p,
            Batch::new().put(keys::membership(&r.name, &pack_id), w.encode()),
        ))
        .unwrap();
    }
}

#[allow(clippy::too_many_lines)]
fn restart_without_inspector_reuse(sharding: Sharding) {
    let (mut env, owner, identity) = environment_with_sharding(sharding);
    env.pipe = env
        .pipe
        .with_publication_policy(Arc::new(InspectionPolicy(
            crate::store::publication::Clearance::Held,
        )))
        .unwrap();
    let (bytes, head) = pack();
    let pack_id = hash(&bytes);
    let node = encode_packlist(None, &[pack_id]).unwrap();
    let map = hash(&node);
    let tickets = vec![
        begin_and_upload(&env, &owner, &identity, &bytes, 9700),
        begin_and_upload(&env, &owner, &identity, &node, 9701),
    ];
    let other_head = "refs/heads/reuse";
    let other_map = "refs/mkit/packmap/reuse";
    // Legitimate tickets can remain open on another ref when the first hold commits.
    let mut reuse_tickets = Vec::new();
    for (number, data) in [(9703, bytes.as_slice()), (9704, node.as_slice())] {
        let begin = env
            .auth(&signed(&owner, &identity, Procedure::BeginUpload, number))
            .unwrap();
        let BeginUploadResult::Ticket { id, .. } =
            block_on(
                env.pipe
                    .begin_upload(&begin, other_head, &hash(data), data.len() as u64),
            )
            .unwrap()
        else {
            panic!("expected pre-hold reuse ticket")
        };
        upload(&env, data, id);
        reuse_tickets.push(id);
    }
    let auth = env
        .auth(&signed(&owner, &identity, Procedure::AdvanceRefs, 9702))
        .unwrap();
    block_on(env.pipe.advance_refs_with_tickets(
        &auth,
        upd(HEAD, Missing, head),
        upd(PACKMAP, Missing, map),
        tickets,
    ))
    .unwrap();
    let repo = auth.repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let member = keys::membership(&repo.name, &pack_id);
    assert!(
        crate::store::publication::Witness::decode(
            &block_on(env.pipe.meta.get(&source, &member))
                .unwrap()
                .unwrap(),
        )
        .unwrap()
        .held
    );
    // Reconstruct the real pipeline over the same durable stores with default-off policy.
    env.pipe = Pipeline::new(
        env.pipe.blobs,
        env.pipe.meta,
        Hooks::new(),
        env.pipe.cfg,
        env.clock.clone(),
        env.metrics.clone(),
    )
    .unwrap();
    let auth = env
        .auth(&signed(&owner, &identity, Procedure::AdvanceRefs, 9705))
        .unwrap();
    let result = block_on(env.pipe.advance_refs_with_tickets(
        &auth,
        upd(other_head, Missing, head),
        upd(other_map, Missing, map),
        reuse_tickets,
    ));
    let source = env.pipe.shards.ref_shard(&repo, other_head);
    let witness = crate::store::publication::Witness::decode(
        &block_on(env.pipe.meta.get(&source, &member))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let writer = env
        .auth(
            &signed(&owner, &identity, Procedure::PackExists, 9706)
                .header("x-mkit-ref", other_head),
        )
        .unwrap();
    let visible = block_on(env.pipe.pack_exists(&writer, PackKey(pack_id))).unwrap();
    assert!(
        !visible,
        "{sharding:?}: policy removal accepted {result:?}, replaced hold with {witness:?}, and served the pack"
    );
}

#[test]
#[ignore = "WP-5.5c (post-launch): hold authority, see R-198/R-200"]
fn single_restart_without_inspector_must_not_clear_a_reused_held_pack() {
    restart_without_inspector_reuse(Sharding::Single);
}

#[test]
#[ignore = "WP-5.5c (post-launch): hold authority, see R-198/R-200"]
fn d34_restart_without_inspector_must_not_clear_a_reused_held_pack() {
    restart_without_inspector_reuse(Sharding::D34);
}

#[test]
fn head_only_and_packmap_only_updates_verify_the_unchanged_counterpart() {
    let (mut env, owner, identity) = environment();
    let (bytes, head) = pack();
    let map_bytes = encode_packlist(None, &[hash(&bytes)]).unwrap();
    let map = hash(&map_bytes);
    let tickets = vec![
        begin_and_upload(&env, &owner, &identity, &bytes, 9200),
        begin_and_upload(&env, &owner, &identity, &map_bytes, 9201),
    ];
    let a = env
        .auth(&signed(&owner, &identity, Procedure::AdvanceRefs, 9202))
        .unwrap();
    block_on(env.pipe.advance_refs_with_tickets(
        &a,
        upd(HEAD, Missing, head),
        upd(PACKMAP, Missing, map),
        tickets,
    ))
    .unwrap();
    // A second valid history object is a member, but absent from main's packmap.
    let tree = Object::Tree(Tree {
        entries: Vec::new(),
    });
    let signer = KeyPair::from_seed([8; 32]);
    let mut commit = Commit::new_unannotated(
        tree.id().unwrap(),
        Vec::new(),
        Identity::ed25519(signer.public.0),
        signer.public.0,
        b"other".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &signer).unwrap().0;
    let object = Object::Commit(commit);
    let other_head = object.id().unwrap();
    let mut writer = PackWriter::new_raw_only();
    for object in [&tree, &object] {
        writer
            .push_raw(object.id().unwrap(), &serialize(object).unwrap())
            .unwrap();
    }
    let other = writer.finish().unwrap();
    let other_map = encode_packlist(None, &[hash(&other)]).unwrap();
    let tickets = vec![
        begin_and_upload(&env, &owner, &identity, &other, 9203),
        begin_and_upload(&env, &owner, &identity, &other_map, 9204),
    ];
    let a = env
        .auth(&signed(&owner, &identity, Procedure::AdvanceRefs, 9205))
        .unwrap();
    block_on(env.pipe.advance_refs_with_tickets(
        &a,
        upd(HEAD, Match(head), other_head),
        upd(PACKMAP, Match(map), hash(&other_map)),
        tickets,
    ))
    .unwrap();
    env.pipe = env
        .pipe
        .with_publication_policy(Arc::new(InspectionPolicy(
            crate::store::publication::Clearance::Cleared,
        )))
        .unwrap();
    for (name, old, new) in [(HEAD, other_head, head), (PACKMAP, hash(&other_map), map)] {
        let a = env
            .auth(&signed(&owner, &identity, Procedure::UpdateRef, 9206))
            .unwrap();
        let error = block_on(env.pipe.update_ref(&a, upd(name, Match(old), new))).unwrap_err();
        assert_eq!(error.public_message(), "open closure");
        let repo = &a.repo().repo;
        let p = env.pipe.shards.ref_shard(repo, HEAD);
        assert_eq!(
            block_on(crate::store::publication::read(
                &env.pipe.meta,
                &p,
                &repo.name,
                HEAD
            ))
            .unwrap()
            .sequence,
            2
        );
        assert_eq!(
            block_on(read::read_ref(&env.pipe.meta, &p, &repo.name, HEAD)).unwrap(),
            Some(other_head)
        );
        assert_eq!(
            block_on(read::read_ref(&env.pipe.meta, &p, &repo.name, PACKMAP)).unwrap(),
            Some(hash(&other_map))
        );
    }
}

#[test]
fn d34_ref_hint_obeys_pending_and_held_views_before_membership_relay() {
    let (mut env, owner, identity) = environment_with_sharding(Sharding::D34);
    env.pipe = env
        .pipe
        .with_publication_policy(Arc::new(InspectionPolicy(
            crate::store::publication::Clearance::Pending,
        )))
        .unwrap();
    let (bytes, head) = pack();
    let pack_id = hash(&bytes);
    let node = encode_packlist(None, &[pack_id]).unwrap();
    let tickets = vec![
        begin_and_upload(&env, &owner, &identity, &bytes, 9300),
        begin_and_upload(&env, &owner, &identity, &node, 9301),
    ];
    let a = env
        .auth(&signed(&owner, &identity, Procedure::AdvanceRefs, 9302))
        .unwrap();
    block_on(env.pipe.advance_refs_with_tickets(
        &a,
        upd(HEAD, Missing, head),
        upd(PACKMAP, Missing, hash(&node)),
        tickets,
    ))
    .unwrap();
    let repo = &a.repo().repo;
    let p = env.pipe.shards.ref_shard(repo, HEAD);
    assert!(
        block_on(env.pipe.meta.get(
            &env.pipe.shards.membership(repo, &BlobKey::pack(pack_id)),
            &keys::membership(&repo.name, &pack_id)
        ))
        .unwrap()
        .is_none()
    );
    for procedure in [Procedure::PackExists, Procedure::DownloadPack] {
        let reader = env
            .auth(
                &Req::unsigned(procedure)
                    .header("x-repository", &identity)
                    .header("x-mkit-ref", HEAD),
            )
            .unwrap();
        let writer = env
            .auth(&signed(&owner, &identity, procedure, 9303).header("x-mkit-ref", HEAD))
            .unwrap();
        if procedure == Procedure::PackExists {
            assert!(!block_on(env.pipe.pack_exists(&reader, PackKey(pack_id))).unwrap());
            assert!(block_on(env.pipe.pack_exists(&writer, PackKey(pack_id))).unwrap());
        } else {
            assert_eq!(
                block_on(env.pipe.download(&reader, PackKey(pack_id)))
                    .err()
                    .unwrap()
                    .code(),
                Code::NotFound
            );
            assert!(block_on(env.pipe.download(&writer, PackKey(pack_id))).is_ok());
        }
        let key = keys::membership(&repo.name, &pack_id);
        let mut w = crate::store::publication::Witness::decode(
            &block_on(env.pipe.meta.get(&p, &key)).unwrap().unwrap(),
        )
        .unwrap();
        w.held = true;
        block_on(
            env.pipe
                .meta
                .inner
                .apply(&p, Batch::new().put(key, w.encode())),
        )
        .unwrap();
        for auth in [&reader, &writer] {
            if procedure == Procedure::PackExists {
                assert!(!block_on(env.pipe.pack_exists(auth, PackKey(pack_id))).unwrap());
            } else {
                assert_eq!(
                    block_on(env.pipe.download(auth, PackKey(pack_id)))
                        .err()
                        .unwrap()
                        .code(),
                    Code::NotFound
                );
            }
        }
        w.held = false;
        block_on(env.pipe.meta.inner.apply(
            &p,
            Batch::new().put(keys::membership(&repo.name, &pack_id), w.encode()),
        ))
        .unwrap();
    }
}

struct UnavailablePublicationPolicy;
impl clearance::PublicationPolicy for UnavailablePublicationPolicy {
    fn prepare<'a>(
        &'a self,
        _: &'a Operation,
        _: &'a crate::store::publication::Pair,
    ) -> crate::BoxFuture<'a, Result<crate::store::publication::Advance, ServerError>> {
        Box::pin(async { Err(ServerError::unavailable("inspection unavailable")) })
    }
    fn pack_available(&self, _: &RepoId, _: &Hash) -> bool {
        false
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Exercise each deletion surface with retained obligations on both layouts.
fn deletions_publish_without_waiting_for_inspection_or_closure() {
    use crate::store::publication::{Advance, Clearance, Obligation, Pair, Publication};
    for sharding in [Sharding::Single, Sharding::D34] {
        for deleted_ref in [HEAD, PACKMAP, "refs/tags/t", "pair"] {
            let (mut env, owner, identity) = environment_with_sharding(sharding);
            let paired = deleted_ref == "pair";
            let name = if paired { HEAD } else { deleted_ref };
            let procedure = if paired {
                Procedure::AdvanceRefs
            } else {
                Procedure::UpdateRef
            };
            let auth = env
                .auth(&signed(&owner, &identity, procedure, 9800))
                .unwrap();
            let repo = &auth.repo().repo;
            let source = env.pipe.shards.ref_shard(repo, name);
            let sequence_name = crate::store::publication::sequence_ref(name);
            let pair = Pair {
                head: Some(A),
                packmap: (name != "refs/tags/t").then_some(B),
            };
            let retained = Advance {
                sequence: 2,
                generation: 0,
                value: pair.clone(),
                additions: vec![],
                dependencies: vec![],
                external_bases: vec![],
                obligations: vec![Obligation {
                    id: [1; 32],
                    state: Clearance::Held,
                }],
                state: Clearance::Held,
                operation: [2; 32],
            };
            let retained_raw = retained.encode().unwrap();
            let previous = Pair {
                head: Some(C),
                packmap: (name != "refs/tags/t").then_some([0xdd; 32]),
            };
            let state = Publication {
                sequence: 2,
                published: 1,
                value: previous.clone(),
                ..Publication::default()
            };
            let mut batch = Batch::new()
                .put(
                    keys::publication(&repo.name, &sequence_name),
                    state.encode().unwrap(),
                )
                .put(
                    keys::advance(&repo.name, &sequence_name, 2),
                    retained_raw.clone(),
                );
            for (reference, target) in crate::store::publication::value_refs(&sequence_name, &pair)
            {
                batch = batch.put(
                    keys::ref_key(&repo.name, &reference),
                    codec::encode_ref_id(&target.unwrap()),
                );
            }
            for (reference, target) in
                crate::store::publication::value_refs(&sequence_name, &previous)
            {
                batch = batch.put(
                    keys::published_ref(&repo.name, &reference),
                    codec::encode_ref_id(&target.unwrap()),
                );
            }
            block_on(env.pipe.meta.inner.apply(&source, batch)).unwrap();
            env.pipe = env
                .pipe
                .with_publication_policy(Arc::new(UnavailablePublicationPolicy))
                .unwrap();
            let remove = |name: &str, target| RefUpdate {
                name: name.into(),
                new: None,
                condition: Match(target),
            };
            if paired {
                assert_eq!(
                    block_on(
                        env.pipe
                            .advance_refs(&auth, remove(HEAD, A), remove(PACKMAP, B))
                    )
                    .unwrap(),
                    AdvanceOutcome::Committed
                );
            } else {
                let target = if name == PACKMAP { B } else { A };
                assert_eq!(
                    block_on(env.pipe.update_ref(&auth, remove(name, target))).unwrap(),
                    UpdateRefResult::Committed
                );
            }
            let state = block_on(crate::store::publication::read(
                &env.pipe.meta.inner,
                &source,
                &repo.name,
                &sequence_name,
            ))
            .unwrap();
            assert_eq!((state.sequence, state.published, state.boundary), (3, 3, 3));
            let expected = Pair {
                head: (!paired && name == PACKMAP).then_some(C),
                packmap: (!paired && name == HEAD).then_some([0xdd; 32]),
            };
            assert_eq!(state.value, expected);
            for (reference, target) in
                crate::store::publication::value_refs(&sequence_name, &expected)
            {
                assert_eq!(
                    block_on(
                        env.pipe
                            .meta
                            .inner
                            .get(&source, &keys::published_ref(&repo.name, &reference))
                    )
                    .unwrap(),
                    target.map(|id| codec::encode_ref_id(&id))
                );
            }
            if paired {
                assert_eq!(state.value, Pair::default());
                assert_eq!(
                    block_on(
                        env.pipe
                            .meta
                            .inner
                            .get(&source, &keys::published_ref(&repo.name, PACKMAP))
                    )
                    .unwrap(),
                    None
                );
            }
            assert_eq!(
                block_on(
                    env.pipe
                        .meta
                        .inner
                        .get(&source, &keys::published_ref(&repo.name, name))
                )
                .unwrap(),
                None
            );
            assert_eq!(
                block_on(
                    env.pipe
                        .meta
                        .inner
                        .get(&source, &keys::advance(&repo.name, &sequence_name, 2))
                )
                .unwrap(),
                Some(retained_raw)
            );
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Real signed split-pack and relay setup verifies four deployment modes.
fn ticketless_reuse_rechecks_file_in_another_source_pack_with_and_without_policy() {
    for sharding in [Sharding::Single, Sharding::D34] {
        for inspection in [false, true] {
            let (mut env, owner, identity) = environment_with_sharding(sharding);
            env.pipe.cfg.takedown_denial = true;
            if inspection {
                env.pipe = env
                    .pipe
                    .with_publication_policy(Arc::new(InspectionPolicy(
                        crate::store::publication::Clearance::Cleared,
                    )))
                    .unwrap();
            }
            let file = Object::Blob(Blob {
                data: b"blocked reused file".to_vec(),
            });
            let file_id = file.id().unwrap();
            let tree = Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"file.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: file_id,
                }],
            });
            let signer = KeyPair::from_seed([9; 32]);
            let mut commit = Commit::new_unannotated(
                tree.id().unwrap(),
                vec![],
                Identity::ed25519(signer.public.0),
                signer.public.0,
                b"split source reuse".to_vec(),
                42,
                [0; 64],
            );
            commit.signature = sign_commit(&commit, &signer).unwrap().0;
            let commit = Object::Commit(commit);
            let head = commit.id().unwrap();
            let write_pack = |objects: &[&Object]| {
                let mut writer = PackWriter::new_raw_only();
                for object in objects {
                    writer
                        .push_raw(object.id().unwrap(), &serialize(object).unwrap())
                        .unwrap();
                }
                writer.finish().unwrap()
            };
            let file_pack = write_pack(&[&file]);
            let head_pack = write_pack(&[&tree, &commit]);
            let map_bytes = encode_packlist(None, &[hash(&file_pack), hash(&head_pack)]).unwrap();
            let map = hash(&map_bytes);
            let tickets = vec![
                begin_and_upload(&env, &owner, &identity, &file_pack, 9880),
                begin_and_upload(&env, &owner, &identity, &head_pack, 9881),
                begin_and_upload(&env, &owner, &identity, &map_bytes, 9882),
            ];
            let advance = env
                .auth(&signed(&owner, &identity, Procedure::AdvanceRefs, 9883))
                .unwrap();
            assert_eq!(
                block_on(env.pipe.advance_refs_with_tickets(
                    &advance,
                    upd(HEAD, Missing, head),
                    upd(PACKMAP, Missing, map),
                    tickets,
                ))
                .unwrap(),
                AdvanceOutcome::Committed,
            );
            // Ticketed publication had an implicit source view. A ticketless
            // reader must observe the real D34 index/membership relay delivery.
            let repo = advance.repo().repo.clone();
            let source = env.pipe.shards.ref_shard(&repo, HEAD);
            let relay = crate::timers::TimerRegistry::new().register(crate::relay::RelayHandler {
                target: crate::store::BorrowedStore(&env.pipe.meta),
                hook: crate::relay::NoHook,
                budget: crate::relay::RelayBudget::default(),
            });
            for _ in 0..8 {
                block_on(crate::timers::run_due(
                    &env.pipe.meta,
                    &source,
                    &relay,
                    env.clock.as_ref(),
                    T0 as u64,
                    &crate::timers::TickBudget::default(),
                ))
                .unwrap();
            }
            block_on(
                crate::store::ContentIndex::new(crate::store::BorrowedStore(&env.pipe.meta))
                    .install_block_action(
                        &file_id,
                        &crate::takedown::denial::BlockAction {
                            id: [31; 32],
                            takedown_id: [32; 32],
                            reason: "manual".into(),
                            blocked_at_ms: T0 as u64,
                            chunk_ids: vec![],
                        },
                        T0 as u64,
                    ),
            )
            .unwrap();
            let reuse = env
                .auth(&signed(&owner, &identity, Procedure::AdvanceRefs, 9884))
                .unwrap();
            let error = block_on(env.pipe.advance_refs(
                &reuse,
                upd("refs/heads/reuse", Missing, head),
                upd("refs/mkit/packmap/reuse", Missing, map),
            ))
            .expect_err("ticketless reuse published a blocked file from another source pack");
            assert_eq!(
                error.code(),
                Code::PermissionDenied,
                "{sharding:?}, inspection={inspection}"
            );
            assert_eq!(error.public_message(), "object blocked");
            let repo = reuse.repo().repo.clone();
            let source = env.pipe.shards.ref_shard(&repo, "refs/heads/reuse");
            for name in ["refs/heads/reuse", "refs/mkit/packmap/reuse"] {
                assert!(
                    block_on(env.pipe.meta.get(&source, &keys::ref_key(&repo.name, name)))
                        .unwrap()
                        .is_none()
                );
            }
        }
    }
}
#[cfg(feature = "remote-hooks")]
mod inspection;

#[cfg(feature = "remote-hooks")]
mod scanner_retrieval;

#[test]
fn lower_pack_cap_after_restart_preserves_exact_error_for_verified_native_pack() {
    let (env, owner, identity) = environment();
    let (bytes, head) = pack();
    let pack_id = hash(&bytes);
    let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 194_020);
    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 194_021);
    let auth = env.auth(&request).unwrap();
    let repo = auth.repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    assert_eq!(
        block_on(env.pipe.advance_refs_with_tickets(
            &auth,
            upd(HEAD, Match([0x5a; 32]), head),
            upd(PACKMAP, Missing, pack_id),
            vec![ticket]
        ))
        .unwrap(),
        AdvanceOutcome::HeadConflict
    );
    let raw = block_on(
        env.pipe
            .meta
            .get(&source, &keys::verification(&repo.name, &pack_id)),
    )
    .unwrap()
    .unwrap();
    assert!(matches!(
        crate::indexed::state::decode(&raw).unwrap(),
        crate::indexed::state::VerificationV1::Verified { .. }
    ));
    let mut config = env.pipe.cfg.clone();
    config.indexed.as_mut().unwrap().max_pack_bytes = bytes.len() as u64 - 1;
    let restarted = Pipeline::new(
        env.pipe.blobs.clone(),
        env.pipe.meta.inner.clone(),
        Hooks::new(),
        config,
        env.clock.clone(),
        env.metrics.clone(),
    )
    .unwrap();
    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 194_022);
    let error = block_on(restarted.advance_refs_with_tickets(
        &env.auth(&request).unwrap(),
        upd(HEAD, Missing, head),
        upd(PACKMAP, Missing, pack_id),
        vec![ticket],
    ))
    .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(
        error.public_message(),
        "pack exceeds indexed max_pack_bytes"
    );
    assert_advance_unmoved(&env, &repo, &[pack_id]);
}
