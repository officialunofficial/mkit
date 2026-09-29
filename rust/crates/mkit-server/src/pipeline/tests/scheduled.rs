//! Scheduled verification through the real pipeline: an advance never
//! verifies, it answers `PendingVerification` until kind-7 slices finish.
#![allow(clippy::unwrap_used)] // Invalid fixtures should fail the test immediately.

use super::indexed::{
    assert_advance_unmoved, begin_and_upload, environment_with, pack, signed, split_pack,
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
    IndexedConfig {
        verification: VerificationMode::Scheduled,
        ..IndexedConfig::default()
    }
}

/// The alarms of `source`'s Durable Object until nothing verification-related is due.
fn alarms(env: &Env, source: &Partition, rounds: u32) {
    let handler = VerifyTimer {
        remote: Ref(&env.pipe.meta),
        blobs: Ref(&env.pipe.blobs),
        windows: BlobWindows(&env.pipe.blobs),
        shards: env.pipe.shards.clone(),
        cfg: scheduled(),
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
    // The ticket is consumed, and the finished job's rows follow it.
    alarms(&env, &source, 3);
    env.clock.advance(3_600_000);
    alarms(&env, &source, 3);
    let (start, end) = keys::verify_range(&repo.name, &pack_id, None);
    assert!(
        block_on(env.pipe.meta.scan(&source, &start, &end, None, 10))
            .unwrap()
            .entries
            .is_empty()
    );
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
