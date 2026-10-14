use super::*;
use crate::Key;
use crate::repo::{NamespaceKey, RepoName};

fn fixture() -> (RepoId, Partition, Batch) {
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("sample").unwrap(),
    };
    let source = D34Shards.ref_shard(&repo, "refs/heads/main");
    let mut batch = Batch::new()
        .require(Precondition::Absent(keys::publication(
            &repo.name,
            "refs/heads/main",
        )))
        .require(Precondition::Absent(keys::outbox_sequence()))
        .put(keys::outbox_sequence(), codec::encode_u64(2));
    for (sequence, name) in [(1, "refs/heads/main"), (2, "refs/mkit/packmap/main")] {
        let value = codec::encode_ref_id(&[u8::try_from(sequence).unwrap(); 32]);
        batch = batch
            .put(keys::published_ref(&repo.name, name), value.clone())
            .put(
                keys::relay(sequence),
                codec::encode_relay(&codec::RelayV1 {
                    at_ms: 1_000,
                    target: D34Shards.ref_index(&repo, name),
                    puts: vec![(keys::published_index(&repo.name, name), value)],
                    deletes: Vec::new(),
                })
                .unwrap(),
            );
    }
    (repo, source, batch)
}

#[test]
fn branch_pair_retains_every_split_projection_obligation() {
    let (repo, source, batch) = fixture();
    let plan = publication_batch(&source, &batch).unwrap().unwrap();
    for (sequence, name) in [(1, "refs/heads/main"), (2, "refs/mkit/packmap/main")] {
        assert!(plan.targets.iter().any(|(target, last)| {
            target == &D34Shards.ref_index(&repo, name) && *last >= sequence
        }));
    }
    assert_eq!(publication_batch(&source, &batch).unwrap().unwrap(), plan);
}

#[test]
fn missing_rebound_or_misrouted_projection_never_produces_a_fence_plan() {
    let (repo, source, batch) = fixture();
    let mut missing = batch.clone();
    missing.writes.pop();
    assert!(publication_batch(&source, &missing).is_err());
    let mut rebound = batch.clone();
    rebound.writes.push(Write::Put(
        keys::published_ref(&repo.name, "refs/heads/main"),
        codec::encode_ref_id(&[9; 32]),
    ));
    assert!(publication_batch(&source, &rebound).is_err());
    let wrong_source = D34Shards.ref_shard(&repo, "refs/heads/other");
    assert!(publication_batch(&wrong_source, &batch).is_err());
}

#[test]
fn guarded_transaction_digest_changes_for_every_rebound_boundary() {
    let (_, source, batch) = fixture();
    let original = publication_batch(&source, &batch).unwrap().unwrap().digest;
    let mut deadline = batch.clone();
    deadline.preconditions.push(Precondition::NotAfter(99));
    assert_ne!(
        publication_batch(&source, &deadline)
            .unwrap()
            .unwrap()
            .digest,
        original
    );
    let mut effect = batch.clone();
    effect
        .writes
        .push(Write::Put(Key::new(b"aux\0".to_vec()), Value::new(vec![1])));
    assert_ne!(
        publication_batch(&source, &effect).unwrap().unwrap().digest,
        original
    );
    assert!(publication_batch(&source, &Batch::new()).unwrap().is_none());
}

#[test]
fn publication_fence_plan_rejects_unallocated_or_reused_relay_sequences() {
    let (_, source, batch) = fixture();
    let mut unguarded = batch.clone();
    unguarded.preconditions.retain(|precondition| {
        !matches!(precondition, Precondition::Absent(key) if *key == keys::outbox_sequence())
    });
    assert!(publication_batch(&source, &unguarded).is_err());
    let mut reused = batch;
    reused.preconditions[1] = Precondition::Equals(keys::outbox_sequence(), codec::encode_u64(2));
    assert!(publication_batch(&source, &reused).is_err());
}

#[cfg(feature = "memory")]
async fn bootstrap_empty_fixture(
    store: &crate::MemoryKv,
    repo: &RepoId,
) -> crate::store::adapter_spi::publication_fence::PublicationFence {
    use crate::store::adapter_spi::publication_fence::{Generation, PublicationFence};
    use crate::{BatchOutcome, NamespaceStore};

    let fence = PublicationFence::new(repo);
    fence
        .initialize(
            store,
            Generation {
                incarnation: [42; 32],
                number: 1,
            },
        )
        .await
        .expect("initialize empty fixture authority");
    let ready = fence
        .bootstrap_ready_batch(store)
        .await
        .expect("empty fixture is ready");
    assert_eq!(
        store
            .apply(&D34Shards.coordinator(&repo.namespace), ready)
            .await
            .expect("record readiness"),
        BatchOutcome::Committed,
    );
    let receipt = fence
        .verify_bootstrap(store)
        .await
        .expect("verify fixture readiness");
    fence
        .seal(store, &receipt)
        .await
        .expect("seal empty fixture");
    fence
}

#[cfg(feature = "memory")]
#[test]
fn publication_fence_waits_for_real_relay_transactions_and_cleanup() {
    use crate::relay::{NoHook, RelayBudget, RelayHandler};
    use crate::store::adapter_spi::publication_fence::{PublicationFence, Target};
    use crate::timers::{TickBudget, TimerRegistry, registry, run_due};
    use crate::{BatchOutcome, ManualClock, MemoryKv, NamespaceStore};
    use futures_executor::block_on;
    use std::sync::Arc;

    block_on(async {
        let (repo, source, mut batch) = fixture();
        batch = batch.put(
            keys::timer(1000, registry::kinds::RELAY.get(), b""),
            Value::default(),
        );
        let plan = publication_batch(&source, &batch).unwrap().unwrap();
        let clock = Arc::new(ManualClock::new(1000));
        let store = Arc::new(MemoryKv::with_clock(clock.clone()));
        let fence = bootstrap_empty_fixture(store.as_ref(), &repo).await;
        let before = fence.stable(store.as_ref()).await.unwrap().unwrap();
        let intent = fence
            .begin(
                store.as_ref(),
                &source,
                1,
                plan.digest,
                plan.targets
                    .iter()
                    .map(|(target, sequence)| Target::new(target, *sequence).unwrap())
                    .collect(),
            )
            .await
            .unwrap();
        fence.arm(store.as_ref(), &intent).await.unwrap();
        PublicationFence::source_commit_fragment(&intent, &mut batch).unwrap();
        assert_eq!(
            store.apply(&source, batch).await.unwrap(),
            BatchOutcome::Committed
        );
        assert!(
            fence
                .reconcile_delivered(store.as_ref(), &intent)
                .await
                .is_err()
        );
        assert_eq!(fence.stable(store.as_ref()).await.unwrap(), None);
        let registry = TimerRegistry::new().register(RelayHandler {
            target: store.clone(),
            hook: NoHook,
            budget: RelayBudget::default(),
        });
        run_due(
            store.as_ref(),
            &source,
            &registry,
            clock.as_ref(),
            1000,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        for (sequence, name) in [(1, "refs/heads/main"), (2, "refs/mkit/packmap/main")] {
            assert_eq!(
                store
                    .get(
                        &D34Shards.ref_index(&repo, name),
                        &keys::published_index(&repo.name, name)
                    )
                    .await
                    .unwrap(),
                Some(codec::encode_ref_id(&[u8::try_from(sequence).unwrap(); 32])),
            );
            assert!(
                store
                    .get(&source, &keys::relay(sequence))
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        fence
            .reconcile_delivered(store.as_ref(), &intent)
            .await
            .unwrap();
        let after = fence.stable(store.as_ref()).await.unwrap().unwrap();
        assert_eq!(after.generation, before.generation);
        assert!(after.revision > before.revision);
    });
}
