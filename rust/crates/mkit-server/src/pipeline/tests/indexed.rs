//! Ticketed advances through the real native pipeline and memory stores.
#![allow(clippy::unwrap_used)] // Invalid fixtures should fail the test immediately.

use super::*;
use crate::repo::MultiAddressing;
use crate::store::{BlobKey, BlobStore, PackSink};
use crate::upload::marker::write_upload_marker;
use bytes::Bytes;
use mkit_core::object::{Commit, Identity, Object, Tree};
use mkit_core::pack::PackWriter;
use mkit_core::repo_identity::Namespace;
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};

fn environment() -> (Env, SigningKey, String) {
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
    config.indexed = Some(crate::indexed::IndexedConfig::default());
    let clock = clock();
    (
        build(config, Spy::new(store(&clock)), Hooks::new(), clock),
        owner,
        identity,
    )
}

fn signed(owner: &SigningKey, identity: &str, procedure: Procedure, number: u32) -> Req {
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

fn pack() -> (Vec<u8>, Hash) {
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
    let mut writer = PackWriter::new_raw_only();
    writer
        .push_raw(tree_id, &serialize(&tree).unwrap())
        .unwrap();
    writer.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    (writer.finish().unwrap(), head)
}

fn upload(env: &Env, pack: &[u8], ticket_id: Hash) {
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
