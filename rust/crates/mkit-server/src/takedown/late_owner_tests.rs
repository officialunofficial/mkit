use super::*;
use crate::memory::MemoryKv;
use crate::relay::ContentTakedownV1;
use crate::store::{
    BlockEntry, Cursor, Holder, PartitionStats, PendingHolderV1, ScanPage, StoreCapabilities,
};
use crate::{ManualClock, NamespaceKey, RepoName};
use futures_executor::block_on;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, Ordering},
};

fn request() -> ContentTakedownV1 {
    let ns = NamespaceKey::deployment_default();
    ContentTakedownV1 {
        identity: PendingHolderV1::new(
            Holder::new(ns.clone(), RepoName::new("late").unwrap()),
            Partition::Namespace(ns),
            [3; 32],
            [1; 32],
            [2; 32],
            [4; 32],
        )
        .unwrap(),
        blocked: BlockEntry::new("observed private reason", 101),
        queued_at_ms: 102,
        ready_at_ms: Some(103),
    }
}
fn root() -> Partition {
    Partition::Namespace(NamespaceKey::deployment_default())
}
fn memory() -> Arc<MemoryKv> {
    Arc::new(MemoryKv::with_clock(Arc::new(ManualClock::new(104))))
}
fn action(n: u8) -> denial::BlockAction {
    denial::BlockAction {
        id: [n; 32],
        takedown_id: [n + 1; 32],
        reason: "policy".into(),
        blocked_at_ms: 101,
        chunk_ids: vec![[7; 32]],
    }
}

async fn actions(store: &MemoryKv, object: &Hash) -> Vec<denial::StoredAction> {
    denial::decode_actions(
        store
            .get(&content_shard(object), &denial::action_key(object))
            .await
            .unwrap()
            .as_ref(),
    )
    .unwrap()
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "Exercise exact provenance, replay and overlapping actions together."
)]
fn actual_owner_accepts_lagging_membership_and_keeps_exact_provenance_with_overlaps() {
    block_on(async {
        let store = memory();
        let req = request();
        let partition = content_shard(&req.identity.object);
        let index = ContentIndex::new(BorrowedStore(store.as_ref()));
        index
            .block(&req.identity.object, &req.blocked, 104)
            .await
            .unwrap();
        for generation in [10, 20] {
            index
                .install_block_action(&req.identity.object, &action(generation), 104)
                .await
                .unwrap();
        }
        let before = actions(store.as_ref(), &req.identity.object).await;
        let owner = LateOwner::new(store.clone(), root());
        let budget = SliceBudget::new(128);
        owner
            .accept(store.as_ref(), &partition, &req, 104, &budget)
            .await
            .unwrap();
        let id = request_id(&req);
        assert_eq!(
            store.get(&root(), &source_key(&id)).await.unwrap(),
            Some(req.encode().unwrap())
        );
        let raw = store
            .get(&root(), &intent::request_key(&id))
            .await
            .unwrap()
            .unwrap();
        let record: intent::Record = intent::decode(&raw).unwrap();
        assert_eq!(record.created, req.queued_at_ms);
        assert!(record.preservation_pending);
        assert_eq!(record.activation_cursor, 0);
        assert_eq!(record.reason, req.blocked.reason);
        assert!(
            store
                .get(
                    &root(),
                    &keys::timer(
                        104,
                        crate::timers::registry::kinds::TAKEDOWN_WORK.get(),
                        &id
                    )
                )
                .await
                .unwrap()
                .is_some()
        );
        let after = actions(store.as_ref(), &req.identity.object).await;
        for old in before {
            assert!(after.contains(&old));
        }
        assert_eq!(after.len(), 3);
        let staged: denial::StoredAction = intent::decode(
            &store
                .get(&partition, &intent::staged_key(&req.identity.object, &id))
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            record.actions[0].descriptor_hash,
            hash(intent::encode(&staged).unwrap().as_bytes())
        );
        assert_eq!(staged.page_owner, req.identity.object);
        assert_eq!(staged.page_action, [10; 32]);
        assert_eq!(staged.chunk_count, 1);
        assert_eq!(
            denial::page(store.as_ref(), &staged, 0).await.unwrap(),
            vec![[7; 32]]
        );
        assert_eq!(
            index.blocked(&req.identity.object).await.unwrap().unwrap(),
            req.blocked
        );
        let head = store
            .get(&root(), &Key::new(b"ah\0".as_slice()))
            .await
            .unwrap();
        assert!(head.is_some());
        owner
            .accept(store.as_ref(), &partition, &req, 105, &budget)
            .await
            .unwrap();
        assert_eq!(
            store
                .get(&root(), &Key::new(b"ah\0".as_slice()))
                .await
                .unwrap(),
            head
        );
        let mut changed = req.clone();
        changed.blocked.reason = "changed".into();
        assert!(
            owner
                .accept(store.as_ref(), &partition, &changed, 105, &budget)
                .await
                .is_err()
        );
    });
}

#[derive(Clone)]
struct Remote {
    inner: Arc<MemoryKv>,
    fail: bool,
    lose: Arc<AtomicBool>,
    calls: Arc<AtomicU32>,
}
impl NamespaceStore for Remote {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        assert_eq!(*p, root(), "content self calls must use TimerCtx store");
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get(p, k).await
    }
    async fn scan(
        &self,
        partition: &Partition,
        start: &Key,
        end: &Key,
        cursor: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.inner.scan(partition, start, end, cursor, limit).await
    }
    async fn apply(&self, p: &Partition, b: Batch) -> Result<BatchOutcome, StoreError> {
        assert_eq!(*p, root(), "content self calls must use TimerCtx store");
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(unavailable());
        }
        let result = self.inner.apply(p, b).await?;
        if self.lose.swap(false, Ordering::SeqCst) {
            return Err(unavailable());
        }
        Ok(result)
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}
fn remote(inner: Arc<MemoryKv>, fail: bool, lose: bool) -> Remote {
    Remote {
        inner,
        fail,
        lose: Arc::new(AtomicBool::new(lose)),
        calls: Arc::new(AtomicU32::new(0)),
    }
}

#[test]
fn actual_owner_root_failure_lost_reply_and_cold_restart_never_ack_a_marker() {
    block_on(async {
        let local = memory();
        let metadata = memory();
        let req = request();
        let partition = content_shard(&req.identity.object);
        let failed = LateOwner::new(remote(metadata.clone(), true, false), root());
        assert!(
            failed
                .accept(local.as_ref(), &partition, &req, 104, &SliceBudget::new(64))
                .await
                .is_err()
        );
        assert!(
            metadata
                .get(&root(), &intent::request_key(&request_id(&req)))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            local
                .get(&partition, &denial::action_key(&req.identity.object))
                .await
                .unwrap()
                .is_none()
        );
        let lost = LateOwner::new(remote(metadata.clone(), false, true), root());
        assert!(
            lost.accept(local.as_ref(), &partition, &req, 104, &SliceBudget::new(64))
                .await
                .is_err()
        );
        let id = request_id(&req);
        assert_eq!(
            metadata.get(&root(), &source_key(&id)).await.unwrap(),
            Some(req.encode().unwrap())
        );
        assert!(
            metadata
                .get(&root(), &intent::request_key(&id))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            metadata
                .get(
                    &root(),
                    &keys::timer(
                        104,
                        crate::timers::registry::kinds::TAKEDOWN_WORK.get(),
                        &id
                    )
                )
                .await
                .unwrap()
                .is_some()
        );
        let head = metadata
            .get(&root(), &Key::new(b"ah\0".as_slice()))
            .await
            .unwrap();
        assert!(head.is_some());
        let cold = LateOwner::new(remote(metadata.clone(), false, false), root());
        cold.accept(local.as_ref(), &partition, &req, 105, &SliceBudget::new(64))
            .await
            .unwrap();
        assert_eq!(
            metadata
                .get(&root(), &Key::new(b"ah\0".as_slice()))
                .await
                .unwrap(),
            head
        );
        let actions = denial::decode_actions(
            local
                .get(&partition, &denial::action_key(&req.identity.object))
                .await
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action.takedown_id, id);
    });
}

#[test]
fn actual_owner_uses_one_budget_and_rejects_missing_provenance_on_replay() {
    block_on(async {
        let local = memory();
        let metadata = memory();
        let req = request();
        let partition = content_shard(&req.identity.object);
        let backend = remote(metadata.clone(), false, false);
        let calls = backend.calls.clone();
        let owner = LateOwner::new(backend, root());
        let budget = SliceBudget::new(2);
        assert!(
            owner
                .accept(local.as_ref(), &partition, &req, 104, &budget)
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(budget.used(), 2);
        owner
            .accept(local.as_ref(), &partition, &req, 104, &SliceBudget::new(64))
            .await
            .unwrap();
        metadata
            .apply(&root(), Batch::new().delete(source_key(&request_id(&req))))
            .await
            .unwrap();
        assert!(
            owner
                .accept(local.as_ref(), &partition, &req, 105, &SliceBudget::new(64))
                .await
                .is_err()
        );
    });
}
