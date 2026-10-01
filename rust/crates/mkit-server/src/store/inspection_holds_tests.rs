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
    let max_ids_alongside_advance =
        (MAX_BATCH_OPS - seven_ticket_ops - HOLD_SHARED_OPS) / HOLD_OPS_PER_ID;
    assert_eq!(max_ids_alongside_advance, 4);

    // A plan pays two shared manifest ops, then one guarded put per new id.
    let one_id = block_on(holds.plan_holds(&[3; 32], &ids[..1])).unwrap();
    let two_ids = block_on(holds.plan_holds(&[3; 32], &ids[..2])).unwrap();
    let one_id_ops = one_id.preconditions.len() + one_id.writes.len();
    let two_id_ops = two_ids.preconditions.len() + two_ids.writes.len();
    assert_eq!(one_id_ops, HOLD_SHARED_OPS + HOLD_OPS_PER_ID);
    assert_eq!(two_id_ops - one_id_ops, HOLD_OPS_PER_ID);

    let advance_hold = block_on(holds.plan_advance_hold(&[3; 32])).unwrap();
    let advance_hold_ops = advance_hold.preconditions.len() + advance_hold.writes.len();
    assert_eq!(advance_hold_ops, ADVANCE_HOLD_MARKER_OPS);
    assert!(seven_ticket_ops + advance_hold_ops <= MAX_BATCH_OPS);
    assert_eq!(seven_ticket_ops + advance_hold_ops, 96);
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

#[test]
fn constant_cost_advance_hold_materializes_and_releases_content_rows() {
    let store = MemoryKv::default();
    let repo = repo();
    let holds = InspectionHolds::new(&store, &D34Shards, &repo, "refs/heads/main");
    let advance = [4; 32];
    let marker = block_on(holds.plan_advance_hold(&advance)).unwrap();
    assert_eq!(marker.preconditions.len() + marker.writes.len(), 2);
    commit(&holds, marker);
    let key = keys::inspection_hold_index(&repo.name, &advance);
    assert_eq!(
        block_on(store.get(holds.partition(), &key)).unwrap(),
        Some(Value::new(vec![PENDING_HOLD_MARKER]))
    );
    assert!(
        block_on(holds.plan_advance_hold(&advance))
            .unwrap()
            .writes
            .is_empty()
    );
    let cancel_advance = [5; 32];
    commit(
        &holds,
        block_on(holds.plan_advance_hold(&cancel_advance)).unwrap(),
    );
    commit(
        &holds,
        block_on(holds.plan_release(&cancel_advance)).unwrap(),
    );
    assert!(
        block_on(store.get(
            holds.partition(),
            &keys::inspection_hold_index(&repo.name, &cancel_advance)
        ))
        .unwrap()
        .is_none()
    );

    let materialized = block_on(holds.plan_holds(&advance, &[[6; 32], [7; 32]])).unwrap();
    assert_eq!(
        materialized.preconditions.len() + materialized.writes.len(),
        4
    );
    commit(&holds, materialized);
    let in_progress = block_on(store.get(holds.partition(), &key))
        .unwrap()
        .unwrap();
    assert_eq!(&in_progress.as_bytes()[..2], &[2, PENDING_HOLD_MARKER]);
    assert_eq!(
        block_on(holds.is_held(&[[6; 32], [7; 32]])).unwrap(),
        vec![[6; 32], [7; 32]]
    );
    commit(&holds, block_on(holds.plan_complete(&advance)).unwrap());
    let complete = block_on(store.get(holds.partition(), &key))
        .unwrap()
        .unwrap();
    assert_eq!(complete.as_bytes()[0], 1);
    commit(&holds, block_on(holds.plan_release(&advance)).unwrap());
    assert!(
        block_on(holds.is_held(&[[6; 32], [7; 32]]))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn completing_an_empty_materialization_clears_pending_fallback() {
    let store = MemoryKv::default();
    let repo = repo();
    let holds = InspectionHolds::new(&store, &D34Shards, &repo, "refs/heads/main");
    let advance = [8; 32];
    commit(&holds, block_on(holds.plan_advance_hold(&advance)).unwrap());
    let complete = block_on(holds.plan_complete(&advance)).unwrap();
    assert_eq!(complete.preconditions.len() + complete.writes.len(), 2);
    commit(&holds, complete);
    let key = keys::inspection_hold_index(&repo.name, &advance);
    assert_eq!(
        block_on(store.get(holds.partition(), &key)).unwrap(),
        Some(Value::new(vec![1]))
    );
    commit(&holds, block_on(holds.plan_release(&advance)).unwrap());
    assert!(
        block_on(store.get(holds.partition(), &key))
            .unwrap()
            .is_none()
    );
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
