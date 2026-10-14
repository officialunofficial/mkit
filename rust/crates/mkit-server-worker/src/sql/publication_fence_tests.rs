use super::SqlKvStore;
use crate::test_sqlite::RusqliteConn;
use futures::executor::block_on;
use mkit_server::pipeline::{D34Shards, ShardMap};
use mkit_server::store::adapter_spi::publication_fence::{Generation, PublicationFence};
use mkit_server::store::adapter_spi::publication_fence_plan::publication_batch;
use mkit_server::store::adapter_spi::{codec, keys};
use mkit_server::{
    Batch, BatchOutcome, NamespaceKey, NamespaceStore, Partition, Precondition, RepoId, RepoName,
};

fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("fence").expect("valid fixture repository"),
    }
}

fn publication() -> Batch {
    let repo = repo();
    Batch::new()
        .require(Precondition::Absent(keys::outbox_sequence()))
        .put(keys::outbox_sequence(), codec::encode_u64(1))
        .put(
            keys::published_ref(&repo.name, "refs/heads/main"),
            codec::encode_ref_id(&[1; 32]),
        )
        .put(
            keys::relay(1),
            codec::encode_relay(&codec::RelayV1 {
                at_ms: 1_000,
                target: D34Shards.ref_index(&repo, "refs/heads/main"),
                puts: vec![(
                    keys::published_index(&repo.name, "refs/heads/main"),
                    codec::encode_ref_id(&[1; 32]),
                )],
                deletes: Vec::new(),
            })
            .expect("valid fixture relay"),
        )
}

async fn prepared(store: &SqlKvStore<RusqliteConn>) -> (Partition, Batch) {
    let repo = repo();
    let source = D34Shards.ref_shard(&repo, "refs/heads/main");
    let fence = PublicationFence::new(&repo);
    fence
        .initialize(
            store,
            Generation {
                incarnation: [33; 32],
                number: 1,
            },
        )
        .await
        .expect("initialize fixture authority");
    let mut batch = publication();
    let plan = publication_batch(&source, &batch)
        .expect("valid fixture allocation")
        .expect("fixture publishes a ref");
    let intent = fence
        .begin(
            store,
            &source,
            1,
            plan.digest,
            plan.fence_targets()
                .expect("fixture plan binds exact relay rows"),
        )
        .await
        .expect("begin fixture publication");
    fence.arm(store, &intent).await.expect("arm source");
    PublicationFence::source_commit_fragment(&intent, &mut batch).expect("bind source batch");
    (source, batch)
}

#[test]
fn publication_fence_sql_rejects_tampering_after_the_commit_fragment() {
    block_on(async {
        let store = SqlKvStore::open(RusqliteConn::open_in_memory().unwrap()).unwrap();
        let (source, healthy) = prepared(&store).await;
        let mut changed = healthy.clone();
        changed.writes.push(mkit_server::Write::Put(
            keys::published_ref(&repo().name, "refs/heads/main"),
            codec::encode_ref_id(&[9; 32]),
        ));
        assert!(store.apply(&source, changed).await.is_err());
        assert!(
            store
                .get(
                    &source,
                    &keys::published_ref(&repo().name, "refs/heads/main")
                )
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.apply(&source, healthy).await.unwrap(),
            BatchOutcome::Committed
        );
    });
}

#[test]
fn publication_fence_sql_rejects_tampering_by_a_transaction_extension() {
    block_on(async {
        let store = SqlKvStore::open(RusqliteConn::open_in_memory().unwrap()).unwrap();
        let (source, healthy) = prepared(&store).await;
        assert!(
            store
                .apply_extended(&source, healthy.clone(), |_, batch, _| {
                    batch.writes.push(mkit_server::Write::Put(
                        keys::published_ref(&repo().name, "refs/heads/main"),
                        codec::encode_ref_id(&[9; 32]),
                    ));
                    Ok(())
                })
                .is_err()
        );
        assert!(
            store
                .get(&source, &keys::outbox_sequence())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.apply(&source, healthy).await.unwrap(),
            BatchOutcome::Committed
        );
    });
}

#[test]
fn publication_fence_sql_preserves_legacy_but_refuses_enrolled_bypass() {
    block_on(async {
        let store = SqlKvStore::open(RusqliteConn::open_in_memory().unwrap()).unwrap();
        let source = D34Shards.ref_shard(&repo(), "refs/heads/main");
        assert_eq!(
            store.apply(&source, publication()).await.unwrap(),
            BatchOutcome::Committed
        );
        let enrolled = SqlKvStore::open(RusqliteConn::open_in_memory().unwrap()).unwrap();
        let (source, healthy) = prepared(&enrolled).await;
        assert!(enrolled.apply(&source, publication()).await.is_err());
        assert_eq!(
            enrolled.apply(&source, healthy).await.unwrap(),
            BatchOutcome::Committed
        );
    });
}

#[test]
fn publication_fence_sql_checks_guards_added_by_extensions() {
    block_on(async {
        let store = SqlKvStore::open(RusqliteConn::open_in_memory().unwrap()).unwrap();
        let (source, mut forged) = prepared(&store).await;
        assert_eq!(
            store
                .apply(
                    &source,
                    Batch::new().put(keys::outbox_sequence(), codec::encode_u64(2))
                )
                .await
                .unwrap(),
            BatchOutcome::Committed,
        );
        forged.preconditions.retain(
            |pre| !matches!(pre, Precondition::Absent(key) if *key == keys::outbox_sequence()),
        );
        let outcome = store
            .apply_extended(&source, forged, |_, batch, _| {
                batch
                    .preconditions
                    .push(Precondition::Absent(keys::outbox_sequence()));
                Ok(())
            })
            .unwrap();
        assert!(matches!(outcome, BatchOutcome::PreconditionFailed { .. }));
        assert_eq!(
            store.get(&source, &keys::outbox_sequence()).await.unwrap(),
            Some(codec::encode_u64(2))
        );
        assert!(
            store
                .get(
                    &source,
                    &keys::published_ref(&repo().name, "refs/heads/main")
                )
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn publication_fence_sql_refuses_replacing_checked_guards() {
    block_on(async {
        let store = SqlKvStore::open(RusqliteConn::open_in_memory().unwrap()).unwrap();
        let (source, healthy) = prepared(&store).await;
        assert!(
            store
                .apply_extended(&source, healthy, |_, batch, _| {
                    batch.preconditions.clear();
                    Ok(())
                })
                .is_err()
        );
        assert!(
            store
                .get(&source, &keys::outbox_sequence())
                .await
                .unwrap()
                .is_none()
        );
    });
}
