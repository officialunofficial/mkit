//! Exact per-repository stored-bytes accounting through the real pipeline.
#![allow(clippy::unwrap_used)] // Invalid fixtures should fail the test immediately.

use std::sync::{Arc, Mutex};

use super::indexed::{
    environment_with, environment_with_hooks, pack, pack_with_blob, signed, upload,
};
use super::scheduled::Ref;
use super::*;
use crate::pipeline::{DeliveryError, Outcome, OutcomeKind, OutcomeSink};
use crate::relay::{NoHook, RelayBudget, RelayHandler};
use crate::rt::ManualSleep;
use crate::store::codec::RepoStorageV1;
use crate::telemetry::NoopMetrics;
use crate::timers::outcome_delivery::OutcomeDelivery;
use crate::timers::{TickBudget, TimerRegistry, run_due};

#[derive(Default)]
struct Capture(Mutex<Vec<Outcome>>);

impl OutcomeSink for Capture {
    async fn deliver(&self, outcome: &Outcome) -> Result<(), DeliveryError> {
        self.0.lock().unwrap().push(outcome.clone());
        Ok(())
    }
}

fn other_identity(identity: &str, name: &str) -> String {
    format!("{}/{name}", identity.split('/').next().unwrap())
}

fn repo_of(env: &Env<impl HookSet>, owner: &SigningKey, identity: &str) -> RepoId {
    let request = signed(
        owner,
        identity,
        Procedure::AdvanceRefs,
        crate::limits::REQUEST_CALLS,
    );
    env.auth(&request).unwrap().repo().repo.clone()
}

fn ticket(
    env: &Env<impl HookSet>,
    owner: &SigningKey,
    identity: &str,
    branch: &str,
    bytes: &[u8],
    number: u32,
) -> Hash {
    let request = signed(owner, identity, Procedure::BeginUpload, number);
    let BeginUploadResult::Ticket { id, .. } = block_on(env.pipe.begin_upload(
        &env.auth(&request).unwrap(),
        &format!("refs/heads/{branch}"),
        &hash(bytes),
        bytes.len() as u64,
    ))
    .unwrap() else {
        panic!("expected upload ticket");
    };
    upload(env, bytes, id);
    id
}

/// Consume `tickets` on `branch`, whose packmap names the first pack.
fn advance(
    env: &Env<impl HookSet>,
    owner: &SigningKey,
    identity: &str,
    number: u32,
    branch: &str,
    packs: &[&[u8]],
    tickets: Vec<Hash>,
) {
    let (_, head) = pack();
    let request = signed(owner, identity, Procedure::AdvanceRefs, number);
    assert_eq!(
        block_on(env.pipe.advance_refs_with_tickets(
            &env.auth(&request).unwrap(),
            upd(&format!("refs/heads/{branch}"), Missing, head),
            upd(
                &format!("refs/mkit/packmap/{branch}"),
                Missing,
                hash(packs[0])
            ),
            tickets,
        ))
        .unwrap(),
        AdvanceOutcome::Committed
    );
}

/// Push `bytes` to `branch` in one ticket and one advance.
fn push(
    env: &Env<impl HookSet>,
    owner: &SigningKey,
    identity: &str,
    branch: &str,
    bytes: &[u8],
    number: u32,
) {
    let id = ticket(env, owner, identity, branch, bytes, number);
    advance(env, owner, identity, number + 1, branch, &[bytes], vec![id]);
}

fn counter(env: &Env<impl HookSet>, repo: &RepoId) -> RepoStorageV1 {
    let raw = block_on(env.pipe.meta.get(
        &env.pipe.shards.coordinator(&repo.namespace),
        &keys::repo_storage(&repo.name),
    ))
    .unwrap()
    .expect("registration creates the counter");
    codec::decode_repo_storage(&raw).unwrap()
}

fn state(bytes: usize, version: u64) -> RepoStorageV1 {
    RepoStorageV1 {
        stored_bytes: bytes as u64,
        version,
    }
}

/// Deliver `source`'s queued relay rows, counting at the coordinator.
fn relay(env: &Env<impl HookSet>, source: &Partition) {
    let registry = TimerRegistry::new().register(RelayHandler {
        target: Ref(&env.pipe.meta),
        hook: NoHook,
        budget: RelayBudget::default(),
    });
    for _ in 0..4 {
        block_on(run_due(
            &env.pipe.meta,
            source,
            &registry,
            env.clock.as_ref(),
            u64::try_from(env.clock.now_ms()).unwrap(),
            &TickBudget::default(),
        ))
        .unwrap();
        env.clock.advance(1_000);
    }
}

fn relay_all(env: &Env<impl HookSet>, repo: &RepoId, branches: &[&str]) {
    for branch in branches {
        relay(
            env,
            &env.pipe
                .shards
                .ref_shard(repo, &format!("refs/heads/{branch}")),
        );
    }
}

/// The `RepoStorageChanged` outcomes the repository's coordinator delivers.
fn storage_outcomes(env: &Env<impl HookSet>, repo: &RepoId, identity: &str) -> Vec<(u64, u64)> {
    let sink = Arc::new(Capture::default());
    let registry = TimerRegistry::new().register(OutcomeDelivery::new(
        sink.clone(),
        "https://example.test".into(),
        Arc::new(NoopMetrics),
        Arc::new(ManualSleep::new()),
    ));
    block_on(run_due(
        &env.pipe.meta,
        &env.pipe.shards.coordinator(&repo.namespace),
        &registry,
        env.clock.as_ref(),
        u64::try_from(env.clock.now_ms()).unwrap(),
        &TickBudget::default(),
    ))
    .unwrap();
    let seen = sink.0.lock().unwrap();
    seen.iter()
        .filter_map(|o| match o.kind {
            OutcomeKind::RepoStorageChanged {
                stored_bytes,
                version,
            } => {
                assert_eq!(o.repository, identity);
                assert_eq!(o.procedure, None);
                Some((stored_bytes, version))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn single_counts_a_pack_once_per_repository_and_reports_each_change() {
    let (env, owner, identity) =
        environment_with(Sharding::Single, crate::indexed::IndexedConfig::default());
    let (first, _) = pack();
    let second = pack_with_blob(1);
    let repo = repo_of(&env, &owner, &identity);

    // Two tickets for one pack, consumed one after the other: it counts once.
    let main = ticket(&env, &owner, &identity, "main", &first, 100);
    let dev = ticket(&env, &owner, &identity, "dev", &first, 102);
    advance(&env, &owner, &identity, 104, "main", &[&first], vec![main]);
    assert_eq!(counter(&env, &repo), state(first.len(), 1));
    advance(&env, &owner, &identity, 106, "dev", &[&first], vec![dev]);
    assert_eq!(counter(&env, &repo), state(first.len(), 1));
    // A re-push of a member pack needs no ticket and adds nothing.
    let request = signed(&owner, &identity, Procedure::BeginUpload, 110);
    assert!(matches!(
        block_on(env.pipe.begin_upload(
            &env.auth(&request).unwrap(),
            "refs/heads/next",
            &hash(&first),
            first.len() as u64,
        ))
        .unwrap(),
        BeginUploadResult::AlreadyPresent
    ));
    assert_eq!(counter(&env, &repo), state(first.len(), 1));
    push(&env, &owner, &identity, "next", &second, 120);
    assert_eq!(
        counter(&env, &repo),
        state(first.len() + second.len(), 2),
        "a new pack adds its bytes and bumps the version"
    );
    // The delivered outcomes carry the absolute value and the version.
    assert_eq!(
        storage_outcomes(&env, &repo, &identity),
        vec![
            (first.len() as u64, 1),
            ((first.len() + second.len()) as u64, 2)
        ]
    );
}

#[test]
fn the_same_pack_counts_in_each_repository() {
    for sharding in [Sharding::Single, Sharding::D34] {
        let (env, owner, identity) =
            environment_with(sharding, crate::indexed::IndexedConfig::default());
        let (bytes, _) = pack();
        let second = other_identity(&identity, "second");
        let (first_repo, second_repo) = (
            repo_of(&env, &owner, &identity),
            repo_of(&env, &owner, &second),
        );
        push(&env, &owner, &identity, "main", &bytes, 200);
        push(&env, &owner, &second, "main", &bytes, 210);
        relay_all(&env, &first_repo, &["main"]);
        relay_all(&env, &second_repo, &["main"]);
        assert_eq!(counter(&env, &first_repo), state(bytes.len(), 1));
        assert_eq!(counter(&env, &second_repo), state(bytes.len(), 1));
    }
}

#[test]
fn d34_counts_a_pack_consumed_on_two_branches_once() {
    let (env, owner, identity) =
        environment_with(Sharding::D34, crate::indexed::IndexedConfig::default());
    let (bytes, _) = pack();
    let repo = repo_of(&env, &owner, &identity);
    // Two tickets for the same pack, one per branch, consumed in different
    // ref shards before either relay row reaches the coordinator.
    let main = ticket(&env, &owner, &identity, "main", &bytes, 300);
    let dev = ticket(&env, &owner, &identity, "dev", &bytes, 310);
    advance(&env, &owner, &identity, 320, "main", &[&bytes], vec![main]);
    advance(&env, &owner, &identity, 330, "dev", &[&bytes], vec![dev]);
    assert_eq!(
        counter(&env, &repo),
        state(0, 0),
        "the counter trails the relay: eventually consistent, never wrong"
    );
    relay_all(&env, &repo, &["main", "dev"]);
    assert_eq!(counter(&env, &repo), state(bytes.len(), 1));
    assert_eq!(
        storage_outcomes(&env, &repo, &identity),
        vec![(bytes.len() as u64, 1)]
    );
    // Idle alarms change nothing.
    relay_all(&env, &repo, &["main", "dev"]);
    assert_eq!(counter(&env, &repo), state(bytes.len(), 1));
}

#[test]
fn a_redelivered_relay_row_does_not_count_again() {
    let (env, owner, identity) =
        environment_with(Sharding::D34, crate::indexed::IndexedConfig::default());
    let (bytes, _) = pack();
    let repo = repo_of(&env, &owner, &identity);
    push(&env, &owner, &identity, "main", &bytes, 400);
    let source = env.pipe.shards.ref_shard(&repo, "refs/heads/main");
    let (start, end) = keys::class_range(keys::TAG_RELAY);
    let queued = block_on(env.pipe.meta.scan(&source, &start, &end, None, 100))
        .unwrap()
        .entries;
    assert!(!queued.is_empty());
    relay(&env, &source);
    assert_eq!(counter(&env, &repo), state(bytes.len(), 1));
    // A crash between the target apply and the source cleanup requeues the
    // already applied rows; the target watermark drops them.
    let mut restore = Batch::new();
    for (key, value) in queued {
        restore = restore.put(key, value);
    }
    assert_eq!(
        block_on(env.pipe.meta.apply(&source, restore)).unwrap(),
        crate::BatchOutcome::Committed
    );
    relay(&env, &source);
    assert_eq!(counter(&env, &repo), state(bytes.len(), 1));
    assert_eq!(storage_outcomes(&env, &repo, &identity).len(), 1);
}

#[test]
fn a_second_source_delivering_a_counted_pack_adds_nothing() {
    // Source watermarks differ per source, so only the marker stops the
    // second branch's relay row from counting the pack again.
    let (env, owner, identity) =
        environment_with(Sharding::D34, crate::indexed::IndexedConfig::default());
    let (bytes, _) = pack();
    let second = pack_with_blob(2);
    let repo = repo_of(&env, &owner, &identity);
    push(&env, &owner, &identity, "main", &bytes, 500);
    relay_all(&env, &repo, &["main"]);
    push(&env, &owner, &identity, "dev", &bytes, 510);
    relay_all(&env, &repo, &["dev"]);
    assert_eq!(counter(&env, &repo), state(bytes.len(), 1));
    push(&env, &owner, &identity, "dev2", &second, 520);
    relay_all(&env, &repo, &["dev2"]);
    assert_eq!(counter(&env, &repo), state(bytes.len() + second.len(), 2));
    let versions: Vec<_> = storage_outcomes(&env, &repo, &identity)
        .into_iter()
        .map(|(_, version)| version)
        .collect();
    assert_eq!(versions, vec![1, 2], "versions are monotonic and gapless");
}

#[cfg(feature = "http-objects")]
#[test]
fn the_bounded_read_matches_the_delivered_outcome() {
    let (env, owner, identity) =
        environment_with(Sharding::Single, crate::indexed::IndexedConfig::default());
    let (bytes, _) = pack();
    let repo = repo_of(&env, &owner, &identity);
    push(&env, &owner, &identity, "main", &bytes, 600);
    let request = signed(&owner, &identity, Procedure::ListRefs, 610);
    let lookup = |name: &str| {
        request
            .headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
    };
    let meta = RequestMeta {
        procedure: request.procedure,
        header: &lookup,
        header_values: None,
        unary_body: Some(&request.body),
        transport_principal: None,
    };
    let read = block_on(env.pipe.repo_storage(&repo, &meta)).unwrap();
    let delivered = storage_outcomes(&env, &repo, &identity);
    assert_eq!(
        (read.stored_bytes, read.version),
        *delivered.last().unwrap(),
        "the read is the latest outcome"
    );
    assert_eq!(read.stored_bytes, bytes.len() as u64);
}

#[test]
fn admission_observes_whether_the_pack_is_already_counted() {
    let hooks = with_admission(Fixed(AdmissionDecision::allow(Vec::new())));
    let (env, owner, identity) = environment_with_hooks(
        Sharding::Single,
        crate::indexed::IndexedConfig::default(),
        None,
        hooks,
    );
    let (bytes, _) = pack();
    let repo = repo_of(&env, &owner, &identity);
    let request = signed(&owner, &identity, Procedure::ListRefs, 700);
    let op = env
        .pipe
        .identify(
            &env.auth(&request).unwrap(),
            OpKind::ListRefs {
                prefix: "refs/".into(),
            },
        )
        .unwrap();
    let key = mkit_core::protocol::PackKey(hash(&bytes));
    let observed = || {
        block_on(env.pipe.new_to_repo_bytes(&op, &key, bytes.len() as u64))
            .unwrap()
            .unwrap()
    };
    assert_eq!(observed(), bytes.len() as u64, "new to the repository");
    push(&env, &owner, &identity, "main", &bytes, 710);
    assert_eq!(counter(&env, &repo), state(bytes.len(), 1));
    assert_eq!(observed(), 0, "already counted");
}

#[test]
fn the_default_admission_skips_the_membership_read() {
    let (env, owner, identity) =
        environment_with(Sharding::Single, crate::indexed::IndexedConfig::default());
    let request = signed(&owner, &identity, Procedure::ListRefs, 720);
    let op = env
        .pipe
        .identify(
            &env.auth(&request).unwrap(),
            OpKind::ListRefs {
                prefix: "refs/".into(),
            },
        )
        .unwrap();
    let key = mkit_core::protocol::PackKey([1; 32]);
    assert_eq!(
        block_on(env.pipe.new_to_repo_bytes(&op, &key, 9)).unwrap(),
        None
    );
}

#[test]
fn the_reserved_storage_prefix_is_not_an_admission_reservation_id() {
    let decision = AdmissionDecision::allow(Vec::new()).with_reservation("rs:abc:1".to_owned());
    assert!(crate::pipeline::admission::validate_decision(&decision).is_err());
}

#[test]
fn a_coordinator_without_a_counter_keeps_the_rows_queued() {
    use crate::store::repo_storage::{relay_extend, relay_read_keys};
    let repo = RepoName::new("lost").unwrap();
    let ns = NamespaceKey::from_namespace(&mkit_core::repo_identity::Namespace::Ed25519([1; 32]));
    let target = Partition::Coordinator(ns);
    let marker = keys::repo_storage_pack(&repo, &[3; 32]);
    let row = crate::store::codec::RelayV1 {
        at_ms: 1,
        target: target.clone(),
        puts: vec![(marker, codec::encode_u64(10))],
        deletes: vec![],
    };
    let rows = [(1, row)];
    let wanted = relay_read_keys(&target, &rows).unwrap();
    let observed: Vec<_> = wanted.into_iter().map(|key| (key, None)).collect();
    let (mut pre, mut writes) = (Vec::new(), Vec::new());
    let error = relay_extend(&target, &rows, &observed, &mut pre, &mut writes).unwrap_err();
    assert!(matches!(error, crate::StoreError::Corrupt(_)));
    // A marker value that is not a byte count refuses delivery too.
    let mut bad = rows[0].1.clone();
    bad.puts[0].1 = Value::default();
    relay_read_keys(&target, &[(1, bad)]).unwrap_err();
    // Other targets are untouched.
    let other = Partition::Namespace(NamespaceKey::deployment_default());
    assert!(relay_read_keys(&other, &rows).unwrap().is_empty());
}

#[test]
fn a_stale_single_counter_snapshot_cannot_commit_a_second_count() {
    // Single drops the markers' own guard because every counting batch
    // guards the counter: a planner holding the pre-count counter fails its
    // `Equals` once another batch counted the pack.
    let repo = RepoId {
        namespace: NamespaceKey::from_namespace(&mkit_core::repo_identity::Namespace::Ed25519(
            [1; 32],
        )),
        name: RepoName::new("room").unwrap(),
    };
    let shards = SinglePartition;
    let source = shards.coordinator(&repo.namespace);
    let stale = crate::store::repo_storage::initial_counter();
    let pack = [5; 32];
    let packs = [(pack, 40_u64)];
    let get = |key: &Key| (*key == keys::repo_storage(&repo.name)).then_some(&stale);
    let mut outbox = crate::store::outbox::OutboxBuilder::new(None, None).unwrap();
    let (mut pre, mut writes) = (Vec::new(), Vec::new());
    crate::store::repo_storage::plan_count(
        &repo,
        &packs,
        &source,
        &shards,
        get,
        |_| false,
        1,
        &mut outbox,
        &mut pre,
        &mut writes,
    )
    .unwrap();
    assert!(pre.contains(&Precondition::Equals(
        keys::repo_storage(&repo.name),
        stale.clone()
    )));
    // After the pack is counted the version moved, so that guard can no longer hold.
    let counted = writes
        .iter()
        .find_map(|w| match w {
            Write::Put(k, v) if *k == keys::repo_storage(&repo.name) => Some(v.clone()),
            _ => None,
        })
        .unwrap();
    assert_ne!(counted, stale);
}

#[cfg(feature = "http-objects")]
#[test]
fn only_an_owner_reads_the_counter() {
    let (env, owner, identity) =
        environment_with(Sharding::Single, crate::indexed::IndexedConfig::default());
    let (bytes, _) = pack();
    let repo = repo_of(&env, &owner, &identity);
    push(&env, &owner, &identity, "main", &bytes, 800);
    let stranger = key(8);
    let request = signed(&stranger, &identity, Procedure::ListRefs, 810);
    let lookup = |name: &str| {
        request
            .headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
    };
    let meta = RequestMeta {
        procedure: request.procedure,
        header: &lookup,
        header_values: None,
        unary_body: Some(&request.body),
        transport_principal: None,
    };
    block_on(env.pipe.repo_storage(&repo, &meta)).unwrap_err();
}
