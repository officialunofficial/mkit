//! Scheduled verification through the real pipeline: an advance never
//! verifies, it answers `PendingVerification` until kind-7 slices finish.
#![allow(clippy::unwrap_used)] // Invalid fixtures should fail the test immediately.

use super::indexed::{
    assert_advance_unmoved, begin_and_upload, environment_with, environment_with_policy, pack,
    signed, split_pack,
};
use super::*;
use crate::indexed::budget::BlobWindows;
use crate::indexed::job::{FailClosedExtraction, SliceLimits, VerifyTimer};
use crate::indexed::{IndexedConfig, VerificationMode};
use crate::relay::{NoHook, RelayBudget, RelayHandler};
use crate::store::{BlobBody, BlobKey, BlobMeta, BlobStore, ByteRange, Cursor, RangeScan};
use crate::timers::{TickBudget, TimerRegistry, run_due};

/// A borrowed store: the handler owns its stores, the pipeline keeps its own.
struct Ref<'a, T>(&'a T);

impl<T: NamespaceStore> NamespaceStore for Ref<'_, T> {
    fn capabilities(&self) -> StoreCapabilities {
        self.0.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, crate::StoreError> {
        self.0.get(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, crate::StoreError> {
        self.0.get_many(p, keys).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, crate::StoreError> {
        self.0.scan(p, start, end, after, limit).await
    }
    async fn scan_many(
        &self,
        p: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, crate::StoreError> {
        self.0.scan_many(p, ranges).await
    }
    async fn apply(
        &self,
        p: &Partition,
        batch: Batch,
    ) -> Result<crate::BatchOutcome, crate::StoreError> {
        self.0.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, crate::StoreError> {
        self.0.stats(p).await
    }
    async fn probe(&self) -> Result<(), crate::StoreError> {
        self.0.probe().await
    }
}

impl<T: BlobStore> BlobStore for Ref<'_, T> {
    type Sink = T::Sink;
    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, crate::StoreError> {
        self.0.begin(key, len).await
    }
    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, crate::StoreError> {
        self.0.get(key, range).await
    }
    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, crate::StoreError> {
        self.0.head(key).await
    }
    async fn probe(&self) -> Result<(), crate::StoreError> {
        self.0.probe().await
    }
    async fn delete(&self, key: &BlobKey) -> Result<bool, crate::StoreError> {
        self.0.delete(key).await
    }
}

fn scheduled() -> IndexedConfig {
    IndexedConfig::scheduled(1 << 30)
}

/// The alarms of `source`'s Durable Object until nothing verification-related is due.
fn alarms(env: &Env, source: &Partition, rounds: u32) {
    let handler = VerifyTimer {
        remote: Ref(&env.pipe.meta),
        blobs: Ref(&env.pipe.blobs),
        windows: BlobWindows(&env.pipe.blobs),
        shards: env.pipe.shards.clone(),
        cfg: env.pipe.cfg.indexed.unwrap(),
        limits: SliceLimits {
            window_bytes: 64 << 10,
            ..SliceLimits::default()
        },
        lease: LeaseParams::from(&env.pipe.cfg),
        clock: env.clock.clone(),
        metrics: env.metrics.clone(),
        extension: FailClosedExtraction,
    };
    let registry = TimerRegistry::new()
        .register(handler)
        .register(RelayHandler {
            target: Ref(&env.pipe.meta),
            hook: NoHook,
            budget: RelayBudget::default(),
        });
    for _ in 0..rounds {
        let now = u64::try_from(env.clock.now_ms()).unwrap();
        block_on(run_due(
            &env.pipe.meta,
            source,
            &registry,
            env.clock.as_ref(),
            now,
            &TickBudget::default(),
        ))
        .unwrap();
        env.clock.advance(1_000);
    }
}

fn ref_batch_ops(env: &Env) -> usize {
    let batches = env.pipe.meta.batches.lock().unwrap();
    let batch = batches
        .iter()
        .rev()
        .find(|batch| {
            batch
                .writes
                .iter()
                .any(|w| matches!(w, Write::Put(key, _) if key.as_bytes().starts_with(b"r\0")))
        })
        .expect("a committed advance batch");
    batch.preconditions.len() + batch.writes.len()
}

fn advance(
    env: &Env,
    owner: &SigningKey,
    identity: &str,
    number: u32,
    head: Hash,
    packmap: Hash,
    tickets: Vec<Hash>,
) -> Result<AdvanceOutcome, crate::ServerError> {
    let request = signed(owner, identity, Procedure::AdvanceRefs, number);
    block_on(env.pipe.advance_refs_with_tickets(
        &env.auth(&request).unwrap(),
        upd(HEAD, Missing, head),
        upd(PACKMAP, Missing, packmap),
        tickets,
    ))
}

#[test]
fn a_pending_advance_leaves_no_trace_and_the_same_nonce_commits_after_the_slices() {
    let (env, owner, identity) = environment_with(Sharding::Single, scheduled());
    let (bytes, head) = pack();
    let id = begin_and_upload(&env, &owner, &identity, &bytes, 300);
    let pack_id = hash(&bytes);
    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 301);
    let auth = env.auth(&request).unwrap();
    let repo = auth.repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let attempt = || {
        block_on(env.pipe.advance_refs_with_tickets(
            &env.auth(&request).unwrap(),
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, pack_id),
            vec![id],
        ))
    };
    let replay = keys::class_range(keys::TAG_REPLAY);
    let replays = || {
        block_on(env.pipe.meta.scan(&source, &replay.0, &replay.1, None, 100))
            .unwrap()
            .entries
            .len()
    };
    let before = replays();
    let error = attempt().unwrap_err();
    assert_eq!(error.public_message(), "pack verification pending");
    assert_eq!(error.details().len(), 1, "one PendingVerification detail");
    assert_advance_unmoved(&env, &repo, &[pack_id]);
    // No replay row: the answer is never stored.
    assert_eq!(replays(), before);
    // The advance created the job, and it is the alarm that verifies.
    assert!(
        block_on(
            env.pipe
                .meta
                .get(&source, &keys::verify_job(&repo.name, &pack_id))
        )
        .unwrap()
        .is_some()
    );
    assert_eq!(
        attempt().unwrap_err().public_message(),
        "pack verification pending"
    );
    alarms(&env, &source, 12);
    assert_eq!(attempt().unwrap(), AdvanceOutcome::Committed);
    // The ticket is consumed; facts clear while a generation tombstone prevents ABA.
    alarms(&env, &source, 3);
    env.clock.advance(3_600_000);
    alarms(&env, &source, 3);
    let (start, end) = keys::verify_range(&repo.name, &pack_id, None);
    let cleaned = block_on(env.pipe.meta.scan(&source, &start, &end, None, 10)).unwrap();
    assert!(cleaned.next.is_none());
    assert_eq!(
        cleaned.entries.len(),
        1,
        "only the generation tombstone survives"
    );
    assert_eq!(cleaned.entries[0].0, keys::verify_job(&repo.name, &pack_id));
    let tombstone = crate::indexed::checkpoint::decode_job(&cleaned.entries[0].1).unwrap();
    assert!(tombstone.gone);
    assert!(tombstone.generation > 0);
    assert!(tombstone.member_body_id.is_none());
    assert!(
        block_on(
            env.pipe
                .meta
                .get(&source, &keys::verification(&repo.name, &pack_id))
        )
        .unwrap()
        .is_some(),
        "a member pack keeps its verified state"
    );
}

#[test]
fn the_advance_batch_is_unchanged_by_scheduling() {
    let mut ops = Vec::new();
    for indexed in [IndexedConfig::default(), scheduled()] {
        let (env, owner, identity) = environment_with(Sharding::Single, indexed);
        let (bytes, head) = pack();
        let id = begin_and_upload(&env, &owner, &identity, &bytes, 310);
        let request = signed(&owner, &identity, Procedure::AdvanceRefs, 311);
        let repo = env.auth(&request).unwrap().repo().repo.clone();
        let source = env.pipe.shards.ref_shard(&repo, HEAD);
        if indexed.verification == VerificationMode::Scheduled {
            assert!(advance(&env, &owner, &identity, 311, head, hash(&bytes), vec![id]).is_err());
            alarms(&env, &source, 12);
        }
        assert_eq!(
            advance(&env, &owner, &identity, 311, head, hash(&bytes), vec![id]).unwrap(),
            AdvanceOutcome::Committed
        );
        ops.push(ref_batch_ops(&env));
    }
    assert_eq!(ops[0], ops[1]);
}

#[test]
fn co_consumed_packs_close_over_each_other_and_a_lone_pack_does_not() {
    let (env, owner, identity) = environment_with(Sharding::Single, scheduled());
    let (commit_pack, tree_pack, head) = split_pack();
    let tickets = [
        begin_and_upload(&env, &owner, &identity, &commit_pack, 320),
        begin_and_upload(&env, &owner, &identity, &tree_pack, 321),
    ];
    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 322);
    let repo = env.auth(&request).unwrap().repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let packs = [hash(&commit_pack), hash(&tree_pack)];
    // Both tickets create their jobs.
    assert!(
        advance(
            &env,
            &owner,
            &identity,
            323,
            head,
            packs[1],
            tickets.to_vec()
        )
        .is_err()
    );
    alarms(&env, &source, 20);
    let lone = advance(
        &env,
        &owner,
        &identity,
        324,
        head,
        packs[0],
        vec![tickets[0]],
    )
    .unwrap_err();
    assert_eq!(
        lone.public_message(),
        "repository membership not yet visible"
    );
    assert_advance_unmoved(&env, &repo, &packs);
    assert_eq!(
        advance(
            &env,
            &owner,
            &identity,
            325,
            head,
            packs[1],
            tickets.to_vec()
        )
        .unwrap(),
        AdvanceOutcome::Committed
    );
}

#[test]
fn d34_slices_relay_index_rows_under_the_shards_lease_before_the_advance_commits() {
    let (env, owner, identity) = environment_with(Sharding::D34, scheduled());
    let (bytes, head) = pack();
    let id = begin_and_upload(&env, &owner, &identity, &bytes, 330);
    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 331);
    let repo = env.auth(&request).unwrap().repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let pack_id = hash(&bytes);
    assert!(advance(&env, &owner, &identity, 331, head, pack_id, vec![id]).is_err());
    alarms(&env, &source, 20);
    // The head's index row is on its own shard by now.
    let shard = env.pipe.shards.object_index(&repo, &head);
    let (start, end) = keys::object_index_range(&repo.name, &head);
    assert_eq!(
        block_on(env.pipe.meta.scan(&shard, &start, &end, None, 10))
            .unwrap()
            .entries
            .len(),
        1
    );
    assert_eq!(
        advance(&env, &owner, &identity, 331, head, pack_id, vec![id]).unwrap(),
        AdvanceOutcome::Committed
    );
}

fn history_commit(parents: &[Hash], salt: u8) -> (mkit_core::object::Object, Hash) {
    use mkit_core::object::{Commit, Identity, Object, Tree};
    use mkit_core::sign::{KeyPair, sign_commit};
    let signer = KeyPair::from_seed([9; 32]);
    let mut commit = Commit::new_unannotated(
        Object::Tree(Tree {
            entries: Vec::new(),
        })
        .id()
        .unwrap(),
        parents.to_vec(),
        Identity::ed25519(signer.public.0),
        signer.public.0,
        vec![salt],
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &signer).unwrap().0;
    let commit = Object::Commit(commit);
    let id = commit.id().unwrap();
    (commit, id)
}

/// A fast-forward-only ref over scheduled verification: the staged history
/// edges come from the job's rows, so a child of the current head passes and a
/// fork is refused, both after the slices ran (WP-4.17 over WP-4.8).
#[test]
fn fast_forward_only_works_over_scheduled_verification() {
    use crate::policy::{RefPolicy, RefRule};
    use mkit_attest::grant::RefPattern;
    use mkit_core::object::{Object, Tree};
    use mkit_core::pack::PackWriter;
    use mkit_core::serialize::serialize;

    let policy = RefPolicy::new(vec![RefRule {
        pattern: RefPattern::parse(HEAD).unwrap(),
        allowed_signers: None,
        fast_forward_only: true,
    }]);
    let (env, owner, identity) =
        environment_with_policy(Sharding::Single, scheduled(), Some(policy));
    let tree = Object::Tree(Tree {
        entries: Vec::new(),
    });
    let pack_of = |objects: &[&Object]| {
        let mut writer = PackWriter::new_raw_only();
        for object in objects {
            writer
                .push_raw(object.id().unwrap(), &serialize(object).unwrap())
                .unwrap();
        }
        writer.finish().unwrap()
    };
    let (c1, id1) = history_commit(&[], 1);
    let (c2, id2) = history_commit(&[id1], 2);
    let (fork, fork_id) = history_commit(&[id1], 3);
    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 340);
    let repo = env.auth(&request).unwrap().repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let mut number = 340;
    let mut push =
        |objects: &[&Object], head: Hash, condition: (RefWriteCondition, RefWriteCondition)| {
            let bytes = pack_of(objects);
            number += 2;
            let ticket = begin_and_upload(&env, &owner, &identity, &bytes, number);
            let request = signed(&owner, &identity, Procedure::AdvanceRefs, number + 1);
            let attempt = || {
                block_on(env.pipe.advance_refs_with_tickets(
                    &env.auth(&request).unwrap(),
                    upd(HEAD, condition.0, head),
                    upd(PACKMAP, condition.1, hash(&bytes)),
                    vec![ticket],
                ))
            };
            assert_eq!(
                attempt().unwrap_err().public_message(),
                "pack verification pending"
            );
            alarms(&env, &source, 12);
            (attempt(), hash(&bytes))
        };
    let (first, pack1) = push(&[&tree, &c1], id1, (Missing, Missing));
    assert_eq!(first.unwrap(), AdvanceOutcome::Committed);
    let (second, pack2) = push(&[&c2], id2, (Match(id1), Match(pack1)));
    assert_eq!(second.unwrap(), AdvanceOutcome::Committed);
    // A fork off c1 is not a descendant of the head c2.
    let (third, _) = push(&[&fork], fork_id, (Match(id2), Match(pack2)));
    let error = third.unwrap_err();
    assert_eq!(
        error.public_message(),
        "non-fast-forward update not allowed on this ref"
    );
    assert_eq!(
        block_on(env.pipe.meta.get(&source, &keys::ref_key(&repo.name, HEAD)))
            .unwrap()
            .map(|raw| codec::decode_ref_id(&raw).unwrap()),
        Some(id2)
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Upload, pending retry and ancestry denial share one fixture.
fn update_only_grants_prove_scheduled_ancestry_after_verification() {
    use mkit_attest::grant::RefScopes;
    use mkit_core::object::{Object, Tree};
    use mkit_core::pack::PackWriter;
    use mkit_core::serialize::serialize;

    let (mut env, owner, identity) = environment_with(Sharding::Single, scheduled());
    env.pipe.cfg.grants = grants::config(&owner, AuthorizerRole::Check).grants;
    let grantee = key(2);
    let header = grants::grant(&owner, &grantee, |grant| {
        grant.ref_scopes = Some(RefScopes::parse("refs/heads/main=u").unwrap());
    });
    let tree = Object::Tree(Tree {
        entries: Vec::new(),
    });
    let (root, root_id) = history_commit(&[], 10);
    let (child, child_id) = history_commit(&[root_id], 11);
    let (fork, fork_id) = history_commit(&[root_id], 12);
    let pack_of = |objects: &[&Object]| {
        let mut writer = PackWriter::new_raw_only();
        for object in objects {
            writer
                .push_raw(object.id().unwrap(), &serialize(object).unwrap())
                .unwrap();
        }
        writer.finish().unwrap()
    };
    let first = pack_of(&[&tree, &root]);
    let ticket = begin_and_upload(&env, &owner, &identity, &first, 400);
    let request = signed(&owner, &identity, Procedure::AdvanceRefs, 401);
    let repo = env.auth(&request).unwrap().repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    assert_eq!(
        advance(
            &env,
            &owner,
            &identity,
            401,
            root_id,
            hash(&first),
            vec![ticket]
        )
        .unwrap_err()
        .public_message(),
        "pack verification pending"
    );
    alarms(&env, &source, 12);
    advance(
        &env,
        &owner,
        &identity,
        401,
        root_id,
        hash(&first),
        vec![ticket],
    )
    .unwrap();
    let mut current = root_id;
    let mut map = hash(&first);
    for (number, object, head, denied) in
        [(410, &child, child_id, false), (420, &fork, fork_id, true)]
    {
        let bytes = pack_of(&[object]);
        let request = signed(&grantee, &identity, Procedure::BeginUpload, number)
            .header("x-write-grant", &header);
        let BeginUploadResult::Ticket { id, .. } = block_on(env.pipe.begin_upload(
            &env.auth(&request).unwrap(),
            HEAD,
            &hash(&bytes),
            bytes.len() as u64,
        ))
        .unwrap() else {
            panic!("expected upload ticket")
        };
        super::indexed::upload(&env, &bytes, id);
        let request = signed(&grantee, &identity, Procedure::AdvanceRefs, number + 1)
            .header("x-write-grant", &header);
        let attempt = || {
            block_on(env.pipe.advance_refs_with_tickets(
                &env.auth(&request).unwrap(),
                upd(HEAD, Match(current), head),
                upd(PACKMAP, Match(map), hash(&bytes)),
                vec![id],
            ))
        };
        assert_eq!(
            attempt().unwrap_err().public_message(),
            "pack verification pending"
        );
        alarms(&env, &source, 12);
        if denied {
            assert_eq!(
                attempt().unwrap_err().public_message(),
                "write grant rejected: ref scope"
            );
        } else {
            assert_eq!(attempt().unwrap(), AdvanceOutcome::Committed);
            current = head;
            map = hash(&bytes);
        }
    }
    assert_eq!(
        block_on(env.pipe.meta.get(&source, &keys::ref_key(&repo.name, HEAD)))
            .unwrap()
            .map(|raw| codec::decode_ref_id(&raw).unwrap()),
        Some(child_id)
    );
}

#[test]
fn lower_pack_cap_after_restart_rejects_fresh_and_usable_jobs() {
    for usable in [false, true] {
        for sharding in [Sharding::Single, Sharding::D34] {
            let (env, owner, identity) = environment_with(sharding, scheduled());
            let (bytes, head) = pack();
            let pack_id = hash(&bytes);
            let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 194_000);
            let request = signed(&owner, &identity, Procedure::AdvanceRefs, 194_001);
            let auth = env.auth(&request).unwrap();
            let repo = auth.repo().repo.clone();
            let source = env.pipe.shards.ref_shard(&repo, HEAD);
            if usable {
                assert_eq!(
                    advance(
                        &env,
                        &owner,
                        &identity,
                        194_002,
                        head,
                        pack_id,
                        vec![ticket]
                    )
                    .unwrap_err()
                    .public_message(),
                    "pack verification pending"
                );
                alarms(&env, &source, 12);
                let raw = block_on(
                    env.pipe
                        .meta
                        .get(&source, &keys::verify_job(&repo.name, &pack_id)),
                )
                .unwrap()
                .unwrap();
                assert!(
                    crate::indexed::checkpoint::decode_job(&raw)
                        .unwrap()
                        .usable()
                );
            }
            let before = block_on(
                env.pipe
                    .meta
                    .get(&source, &keys::verify_job(&repo.name, &pack_id)),
            )
            .unwrap();
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
            let error = block_on(restarted.advance_refs_with_tickets(
                &auth,
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
            assert_eq!(
                block_on(
                    env.pipe
                        .meta
                        .get(&source, &keys::verify_job(&repo.name, &pack_id))
                )
                .unwrap(),
                before,
                "cap rejection must not claim or replace a job"
            );
            assert_advance_unmoved(&env, &repo, &[pack_id]);
        }
    }
}

#[test]
fn lower_pack_cap_stops_scheduled_decode_before_blob_work() {
    let (mut env, owner, identity) = environment_with(Sharding::Single, scheduled());
    let (bytes, head) = pack();
    let pack_id = hash(&bytes);
    let ticket = begin_and_upload(&env, &owner, &identity, &bytes, 194_010);
    let auth = env
        .auth(&signed(&owner, &identity, Procedure::AdvanceRefs, 194_011))
        .unwrap();
    let repo = auth.repo().repo.clone();
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    advance(
        &env,
        &owner,
        &identity,
        194_012,
        head,
        pack_id,
        vec![ticket],
    )
    .unwrap_err();
    env.pipe.cfg.indexed.as_mut().unwrap().max_pack_bytes = bytes.len() as u64 - 1;
    alarms(&env, &source, 12);
    let raw = block_on(
        env.pipe
            .meta
            .get(&source, &keys::verification(&repo.name, &pack_id)),
    )
    .unwrap()
    .unwrap();
    assert!(matches!(crate::indexed::state::decode(&raw).unwrap(),
        crate::indexed::state::VerificationV1::Rejected {code, message}
        if code == "invalid_argument" && message == "pack exceeds indexed max_pack_bytes"));
    assert_advance_unmoved(&env, &repo, &[pack_id]);
}
