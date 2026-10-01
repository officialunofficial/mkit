use std::sync::Mutex;

use futures_executor::block_on;

use super::*;
use crate::memory::MemoryKv;
use crate::pipeline::{D34Shards, SinglePartition};
use crate::repo::{NamespaceKey, RepoName};
use crate::store::{BatchOutcome, Cursor, Key, PartitionStats, ScanPage, StoreCapabilities};

fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("repo").unwrap(),
    }
}

fn commit<S: NamespaceStore>(holds: &InspectionHolds<'_, S>, batch: Batch) {
    assert_eq!(
        block_on(holds.store.apply(holds.partition(), batch)).unwrap(),
        BatchOutcome::Committed
    );
}

#[test]
fn releasing_one_advance_preserves_another_hold_in_single_and_d34() {
    for shards in [
        &SinglePartition as &dyn ShardMap,
        &D34Shards as &dyn ShardMap,
    ] {
        let store = MemoryKv::default();
        let repo = repo();
        let holds = InspectionHolds::new(&store, shards, &repo, "refs/heads/main");
        let content = [5; 32];
        commit(
            &holds,
            block_on(holds.plan_holds(&[1; 32], &[content])).unwrap(),
        );
        commit(
            &holds,
            block_on(holds.plan_holds(&[2; 32], &[content])).unwrap(),
        );
        commit(&holds, block_on(holds.plan_release(&[1; 32])).unwrap());
        assert_eq!(block_on(holds.is_held(&[content])).unwrap(), vec![content]);
        assert!(
            block_on(store.get(
                holds.partition(),
                &keys::inspection_hold(&repo.name, &content, &[1; 32])
            ))
            .unwrap()
            .is_none()
        );
        assert!(
            block_on(store.get(
                holds.partition(),
                &keys::inspection_hold(&repo.name, &content, &[2; 32])
            ))
            .unwrap()
            .is_some()
        );
        commit(&holds, block_on(holds.plan_release(&[2; 32])).unwrap());
        assert!(block_on(holds.is_held(&[content])).unwrap().is_empty());
        assert!(
            block_on(holds.plan_release(&[2; 32]))
                .unwrap()
                .writes
                .is_empty()
        );
    }
}

#[test]
fn installs_are_deduplicated_idempotent_and_manifest_cas_losses_replan() {
    let store = MemoryKv::default();
    let repo = repo();
    let holds = InspectionHolds::new(&store, &SinglePartition, &repo, "refs/heads/main");
    let advance = [8; 32];
    let first = block_on(holds.plan_holds(&advance, &[[1; 32], [1; 32]])).unwrap();
    assert_eq!(first.preconditions.len() + first.writes.len(), 3);
    let loser = block_on(holds.plan_holds(&advance, &[[2; 32]])).unwrap();
    commit(&holds, first);
    assert!(matches!(
        block_on(store.apply(holds.partition(), loser)).unwrap(),
        BatchOutcome::PreconditionFailed { .. }
    ));
    commit(
        &holds,
        block_on(holds.plan_holds(&advance, &[[2; 32]])).unwrap(),
    );
    assert!(
        block_on(holds.plan_holds(&advance, &[[1; 32], [2; 32]]))
            .unwrap()
            .writes
            .is_empty()
    );
    let stale_release = block_on(holds.plan_release(&advance)).unwrap();
    commit(
        &holds,
        block_on(holds.plan_holds(&advance, &[[3; 32]])).unwrap(),
    );
    assert!(matches!(
        block_on(store.apply(holds.partition(), stale_release)).unwrap(),
        BatchOutcome::PreconditionFailed { .. }
    ));
    commit(&holds, block_on(holds.plan_release(&advance)).unwrap());
    assert!(
        block_on(holds.is_held(&[[1; 32], [2; 32], [3; 32]]))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn release_pages_and_limits_remain_within_the_portable_budget() {
    let store = MemoryKv::default();
    let repo = repo();
    let holds = InspectionHolds::new(&store, &D34Shards, &repo, "refs/heads/main");
    let ids: Vec<Hash> = (0_u32..150)
        .map(|i| {
            let mut id = [0; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id
        })
        .collect();
    assert!(matches!(
        block_on(holds.plan_holds(&[1; 32], &ids)),
        Err(StoreError::Invalid(_))
    ));
    for chunk in ids.chunks(MAX_HOLD_BATCH_IDS) {
        commit(&holds, block_on(holds.plan_holds(&[1; 32], chunk)).unwrap());
    }
    let seven = block_on(holds.plan_holds(&[2; 32], &ids[..7])).unwrap();
    let ops = seven.preconditions.len() + seven.writes.len();
    assert_eq!(ops, HOLD_SHARED_OPS + 7 * HOLD_OPS_PER_ID);
    assert_eq!(ops, 9);
    let seven_ticket_ops = crate::store::outbox::ADVANCE_SHARED_OPS
        + crate::store::outbox::MAX_TICKETS_PER_ADVANCE * 9;
    assert_eq!(seven_ticket_ops, 94);
    assert_eq!(seven_ticket_ops + ops, 103);
    assert!(seven_ticket_ops + ops > MAX_BATCH_OPS);
    let combined = InspectionHolds::new(&store, &D34Shards, &repo, "refs/heads/main")
        .with_reserved_ops(seven_ticket_ops);
    assert!(matches!(
        block_on(combined.plan_holds(&[3; 32], &ids[..7])),
        Err(StoreError::Invalid(_))
    ));
    let bounded = block_on(combined.plan_holds(&[3; 32], &ids[..4])).unwrap();
    assert_eq!(bounded.preconditions.len() + bounded.writes.len(), 6);
    assert_eq!(
        seven_ticket_ops + bounded.preconditions.len() + bounded.writes.len(),
        100
    );
    let page = block_on(holds.plan_release(&[1; 32])).unwrap();
    assert_eq!(page.preconditions.len() + page.writes.len(), MAX_BATCH_OPS);
    commit(&holds, page);
    assert_eq!(block_on(holds.is_held(&ids)).unwrap().len(), 52);
    commit(&holds, block_on(holds.plan_release(&[1; 32])).unwrap());
    assert!(block_on(holds.is_held(&ids)).unwrap().is_empty());
    assert!(matches!(
        block_on(holds.is_held(&vec![[0; 32]; MAX_SCAN_RANGES + 1])),
        Err(StoreError::Invalid(_))
    ));
}

#[derive(Default)]
struct RecordingStore {
    inner: MemoryKv,
    limits: Mutex<Vec<u32>>,
}

impl NamespaceStore for RecordingStore {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(p, key).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.limits.lock().unwrap().push(limit);
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

#[test]
fn prefix_probe_always_requests_one_even_with_many_advances() {
    let store = RecordingStore::default();
    let repo = repo();
    let holds = InspectionHolds::new(&store, &SinglePartition, &repo, "refs/heads/main");
    for i in 0..20 {
        commit(
            &holds,
            block_on(holds.plan_holds(&[i; 32], &[[7; 32]])).unwrap(),
        );
    }
    assert_eq!(
        block_on(holds.is_held(&[[7; 32], [8; 32], [7; 32]])).unwrap(),
        vec![[7; 32]]
    );
    assert_eq!(*store.limits.lock().unwrap(), vec![1, 1]);
}

#[test]
fn corrupt_manifests_and_forward_rows_fail_closed() {
    let store = MemoryKv::default();
    let repo = repo();
    let holds = InspectionHolds::new(&store, &SinglePartition, &repo, "refs/heads/main");
    let key = keys::inspection_hold_index(&repo.name, &[1; 32]);
    let values = [
        Value::default(),
        Value::new(vec![2]),
        Value::new(vec![1]),
        Value::new(vec![1, 0]),
        Value::new([vec![1], vec![0; 64]].concat()),
    ];
    for value in values {
        commit(&holds, Batch::new().put(key.clone(), value));
        assert!(matches!(
            block_on(holds.plan_holds(&[1; 32], &[[1; 32]])),
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(
            block_on(holds.plan_release(&[1; 32])),
            Err(StoreError::Corrupt(_))
        ));
    }
    commit(
        &holds,
        Batch::new().put(
            keys::inspection_hold(&repo.name, &[1; 32], &[1; 32]),
            Value::new(vec![1]),
        ),
    );
    assert!(matches!(
        block_on(holds.is_held(&[[1; 32]])),
        Err(StoreError::Corrupt(_))
    ));
}

#[test]
fn full_manifest_and_reserved_backend_operations_are_accounted_for() {
    let mut caps = StoreCapabilities::full();
    caps.reserved_batch_ops = 2;
    let store = MemoryKv::new(caps);
    let repo = repo();
    let holds = InspectionHolds::new(&store, &SinglePartition, &repo, "refs/heads/main");
    let ids: BTreeSet<Hash> = (0_u32..10_000)
        .map(|i| {
            let mut id = [0; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id
        })
        .collect();
    commit(
        &holds,
        Batch::new().put(
            keys::inspection_hold_index(&repo.name, &[1; 32]),
            encode_manifest(&ids),
        ),
    );
    let duplicate = block_on(holds.plan_holds(&[1; 32], &[ids.first().copied().unwrap()])).unwrap();
    assert!(duplicate.writes.is_empty());
    assert!(matches!(
        block_on(holds.plan_holds(&[1; 32], &[[255; 32]])),
        Err(StoreError::Invalid(_))
    ));
    let page = block_on(holds.plan_release(&[1; 32])).unwrap();
    assert_eq!(
        page.writes.len() + page.preconditions.len(),
        MAX_BATCH_OPS - 2
    );
    page.validate(&caps).unwrap();
}

#[test]
fn no_op_plans_guard_the_observed_manifest() {
    let store = MemoryKv::default();
    let repo = repo();
    let holds = InspectionHolds::new(&store, &SinglePartition, &repo, "refs/heads/main");
    let advance = [1; 32];
    let absent_release = block_on(holds.plan_release(&advance)).unwrap();
    assert!(absent_release.writes.is_empty());
    commit(
        &holds,
        block_on(holds.plan_holds(&advance, &[[2; 32]])).unwrap(),
    );
    assert!(matches!(
        block_on(store.apply(holds.partition(), absent_release)).unwrap(),
        BatchOutcome::PreconditionFailed { .. }
    ));
    let duplicate = block_on(holds.plan_holds(&advance, &[[2; 32]])).unwrap();
    assert!(duplicate.writes.is_empty());
    commit(&holds, block_on(holds.plan_release(&advance)).unwrap());
    assert!(matches!(
        block_on(store.apply(holds.partition(), duplicate)).unwrap(),
        BatchOutcome::PreconditionFailed { .. }
    ));
}

#[test]
fn release_reserves_space_for_the_callers_advance_apply() {
    let store = MemoryKv::default();
    let repo = repo();
    let holds = InspectionHolds::new(&store, &SinglePartition, &repo, "refs/heads/main");
    let ids: Vec<Hash> = (0..98).map(|i| [i; 32]).collect();
    commit(&holds, block_on(holds.plan_holds(&[1; 32], &ids)).unwrap());
    let holds = holds.with_reserved_ops(2);
    let page = block_on(holds.plan_release(&[1; 32])).unwrap();
    assert_eq!(page.writes.len() + page.preconditions.len(), 98);
    commit(&holds, page);
    assert_eq!(block_on(holds.is_held(&ids)).unwrap().len(), 2);
    let holds = holds.with_reserved_ops(usize::MAX);
    assert!(matches!(
        block_on(holds.plan_release(&[1; 32])),
        Err(StoreError::Invalid(_))
    ));
}
