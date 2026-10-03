//! A prepared publication proof binds to the row it was computed against, and
//! one typed allowance covers every proof phase (SPEC-SERVER §10.2).
#![allow(clippy::unwrap_used)] // Invalid fixtures should fail the test immediately.

use super::indexed::{
    InspectionPolicy, assert_advance_unmoved, begin_and_upload, environment_with, pack, signed,
};
use super::*;
use crate::pipeline::publication_budget::tests::{LAST, OVERRIDE};
use crate::store::publication::{Clearance, Pair, Publication};
use mkit_core::repo_identity::Namespace;
use mkit_core::transfer::encode_packlist;

/// Rewrites the publication row while the proof is being prepared, once.
struct RacePolicy {
    kv: Arc<MemoryKv>,
    source: Partition,
    row_key: Key,
    row: fn(&Pair) -> Publication,
    armed: AtomicBool,
}
impl clearance::PublicationPolicy for RacePolicy {
    fn prepare<'a>(
        &'a self,
        _: &'a Operation,
        pair: &'a Pair,
    ) -> crate::BoxFuture<'a, Result<crate::store::publication::Advance, ServerError>> {
        Box::pin(async move {
            if self.armed.swap(false, Ordering::SeqCst) {
                self.kv
                    .apply(
                        &self.source,
                        Batch::new().put(self.row_key.clone(), (self.row)(pair).encode().unwrap()),
                    )
                    .await
                    .unwrap();
            }
            Ok(clearance::immediate(pair.clone(), [0; 32], vec![]))
        })
    }
    fn pack_available(&self, _: &RepoId, _: &Hash) -> bool {
        true
    }
}

fn repo_of(owner: &SigningKey) -> RepoId {
    RepoId {
        namespace: NamespaceKey::from_namespace(&Namespace::Ed25519(
            *owner.verifying_key().as_bytes(),
        )),
        name: RepoName::new(REPO).unwrap(),
    }
}

fn advance_once(
    env: &Env,
    owner: &SigningKey,
    identity: &str,
    base: u32,
) -> (Result<AdvanceOutcome, ServerError>, Vec<Hash>) {
    let (bytes, head) = pack();
    let pack_id = hash(&bytes);
    let node = encode_packlist(None, &[pack_id]).unwrap();
    let map = hash(&node);
    let tickets = vec![
        begin_and_upload(env, owner, identity, &bytes, base),
        begin_and_upload(env, owner, identity, &node, base + 1),
    ];
    let a = env
        .auth(&signed(owner, identity, Procedure::AdvanceRefs, base + 2))
        .unwrap();
    (
        block_on(env.pipe.advance_refs_with_tickets(
            &a,
            upd(HEAD, Missing, head),
            upd(PACKMAP, Missing, map),
            tickets,
        )),
        vec![pack_id, map],
    )
}

fn raced_environment(
    row: fn(&Pair) -> Publication,
    takedown: bool,
) -> (Env, SigningKey, String, Arc<RacePolicy>) {
    let (mut env, owner, identity) =
        environment_with(Sharding::Single, crate::indexed::IndexedConfig::default());
    // With takedown on, the first apply attempt re-reads every mutable row.
    env.pipe.cfg.takedown_denial = takedown;
    let repo = repo_of(&owner);
    let policy = Arc::new(RacePolicy {
        kv: env.pipe.meta.inner.clone(),
        source: env.pipe.shards.ref_shard(&repo, HEAD),
        row_key: keys::publication(&repo.name, HEAD),
        row,
        armed: AtomicBool::new(true),
    });
    env.pipe = env.pipe.with_publication_policy(policy.clone()).unwrap();
    (env, owner, identity, policy)
}

/// The proof was computed before `row` landed; stale evidence never commits,
/// and the retry prepares against the new row.
fn stale_proof_never_commits(row: fn(&Pair) -> Publication, takedown: bool) {
    let (env, owner, identity, policy) = raced_environment(row, takedown);
    let repo = repo_of(&owner);
    let (first, packs) = advance_once(&env, &owner, &identity, 100);
    let error = first.unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.public_message(), "publication state changed; retry");
    assert_advance_unmoved(&env, &repo, &packs);
    assert!(!policy.armed.load(Ordering::SeqCst));
    let source = env.pipe.shards.ref_shard(&repo, HEAD);
    let after = Publication::decode(
        block_on(
            env.pipe
                .meta
                .get(&source, &keys::publication(&repo.name, HEAD)),
        )
        .unwrap()
        .as_ref(),
    )
    .unwrap();
    assert_eq!(after, row(&Pair::default()).with_pair(&after.value));
    // Nothing from the stale proof was retained.
    assert!(
        block_on(env.pipe.meta.get(
            &source,
            &keys::advance(&repo.name, HEAD, after.sequence + 1)
        ))
        .unwrap()
        .is_none()
    );
    // A fresh attempt re-prepares against the new row and commits.
    let (retry, _) = advance_once(&env, &owner, &identity, 200);
    assert_eq!(retry.unwrap(), AdvanceOutcome::Committed);
    let state = Publication::decode(
        block_on(
            env.pipe
                .meta
                .get(&source, &keys::publication(&repo.name, HEAD)),
        )
        .unwrap()
        .as_ref(),
    )
    .unwrap();
    assert_eq!(state.sequence, after.sequence + 1);
    assert_eq!(state.generation, after.generation);
}

impl Publication {
    fn with_pair(mut self, value: &Pair) -> Self {
        self.value = value.clone();
        self
    }
}

#[test]
fn a_generation_change_between_prepare_and_commit_never_commits_the_proof() {
    for takedown in [false, true] {
        stale_proof_never_commits(
            |_| Publication {
                generation: 1,
                ..Default::default()
            },
            takedown,
        );
    }
}

#[test]
fn a_deletion_boundary_and_recreation_between_prepare_and_commit_never_commits_the_proof() {
    for takedown in [false, true] {
        stale_proof_never_commits(
            |_| Publication {
                sequence: 2,
                published: 2,
                boundary: 2,
                ..Default::default()
            },
            takedown,
        );
    }
}

#[test]
fn a_same_pair_source_publication_between_prepare_and_commit_never_commits_the_proof() {
    for takedown in [false, true] {
        stale_proof_never_commits(
            |pair| Publication {
                sequence: 1,
                published: 1,
                value: pair.clone(),
                ..Default::default()
            },
            takedown,
        );
    }
}

/// Real verdicts are unchanged under an ample allowance: a head that is not a
/// repository member is the permanent open-closure error, not capacity.
#[test]
fn genuine_verdicts_keep_their_codes() {
    let (mut env, owner, identity) =
        environment_with(Sharding::Single, crate::indexed::IndexedConfig::default());
    env.pipe = env
        .pipe
        .with_publication_policy(Arc::new(InspectionPolicy(Clearance::Cleared)))
        .unwrap();
    // Past the membership lag window a missing member is permanent.
    env.clock.advance(
        i64::try_from(crate::indexed::IndexedConfig::default().relay_lag_bound_ms).unwrap(),
    );
    let a = env
        .auth(&signed(&owner, &identity, Procedure::UpdateRef, 300))
        .unwrap();
    let error = block_on(env.pipe.update_ref(&a, upd(HEAD, Missing, [3; 32]))).unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(error.public_message(), "open closure");
}

thread_local! {
    static SETTLED: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Exhaustion injected before, inside and after every proof phase, at the
/// exact boundary, is capacity everywhere and never publishes.
#[test]
fn exhaustion_at_every_call_is_uniform_capacity_and_the_boundary_is_exact() {
    let run = |request_calls: u32| {
        OVERRIDE.set(Some(request_calls));
        let (mut env, owner, identity) =
            environment_with(Sharding::Single, crate::indexed::IndexedConfig::default());
        env.pipe = env
            .pipe
            .with_publication_policy(Arc::new(InspectionPolicy(Clearance::Cleared)))
            .unwrap();
        let repo = repo_of(&owner);
        let (result, packs) = advance_once(&env, &owner, &identity, 400);
        let (used, settled) = LAST.with(|last| {
            let last = last.borrow();
            let ledger = last.as_ref().unwrap();
            (
                ledger.proof().used(),
                ledger.root().used() - ledger.proof().used(),
            )
        });
        SETTLED.with(|cell| cell.set(settled));
        if result.is_err() {
            assert_advance_unmoved(&env, &repo, &packs);
        }
        (result, used)
    };
    let (ample, needed) = run(crate::pipeline::publication_budget::REQUEST_CALLS);
    assert_eq!(ample.unwrap(), AdvanceOutcome::Committed);
    // An uncontended attempt's settlement fits the reserve proof work leaves it.
    assert!(
        SETTLED.get() > 0
            && SETTLED.get() <= crate::pipeline::publication_budget::SETTLEMENT_RESERVE
    );
    assert!(needed > 4, "the proof must make several charged calls");
    let reserve = crate::pipeline::publication_budget::SETTLEMENT_RESERVE;
    for proof_calls in 0..=needed + 1 {
        let (result, _) = run(proof_calls + reserve);
        if proof_calls < needed {
            let error = result.unwrap_err();
            assert_eq!(error.code(), Code::Unavailable, "at {proof_calls}");
            assert_eq!(
                error.public_message(),
                "publication verification capacity exhausted",
                "at {proof_calls}"
            );
        } else {
            assert_eq!(
                result.unwrap(),
                AdvanceOutcome::Committed,
                "at {proof_calls}"
            );
        }
    }
    OVERRIDE.set(None);
}
