use super::*;
use crate::memory::MemoryKv;
use crate::relay::{HolderRelayHook, RelayHook};
use crate::store::{BorrowedStore, ContentIndex, Holder, PendingHolderV1, Value, Write, codec};
use crate::takedown::denial::{BlockAction, action_key};
use crate::{BatchOutcome, Key, ManualClock, NamespaceKey, Partition, RepoName};
use futures_executor::block_on;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn identity() -> PendingHolderV1 {
    let ns = NamespaceKey::deployment_default();
    PendingHolderV1::new(
        Holder::new(ns.clone(), RepoName::new("late").unwrap()),
        Partition::Namespace(ns),
        [3; 32],
        [1; 32],
        [2; 32],
        [4; 32],
    )
    .unwrap()
}
fn request(ready: Option<u64>) -> ContentTakedownV1 {
    ContentTakedownV1 {
        identity: identity(),
        blocked: crate::store::BlockEntry::new("late", 101),
        queued_at_ms: 102,
        ready_at_ms: ready,
    }
}
fn action(n: u8) -> BlockAction {
    BlockAction {
        id: [n; 32],
        takedown_id: [n + 1; 32],
        reason: format!("action{n}"),
        blocked_at_ms: 101,
        chunk_ids: vec![],
    }
}
fn timer() -> DueTimer {
    let id = identity();
    DueTimer {
        due_at_ms: 104,
        kind: kinds::CONTENT_TAKEDOWN_REQUEST,
        reference: [id.object.as_slice(), id.intent.as_slice()].concat().into(),
        value: Value::default(),
    }
}
fn store() -> Arc<MemoryKv> {
    Arc::new(MemoryKv::with_clock(Arc::new(ManualClock::new(100))))
}
async fn install_request(store: &MemoryKv, request: &ContentTakedownV1) {
    let id = &request.identity;
    store
        .apply(
            &content_shard(&id.object),
            Batch::new()
                .put(
                    keys::content_takedown(&id.object, &id.intent),
                    request.encode().unwrap(),
                )
                .put(
                    keys::timer(
                        104,
                        kinds::CONTENT_TAKEDOWN_REQUEST.get(),
                        &timer().reference,
                    ),
                    Value::default(),
                ),
        )
        .await
        .unwrap();
}
fn owned_key(request: &ContentTakedownV1) -> Key {
    Key::new(
        [
            keys::block(&request.identity.object).as_bytes(),
            b"\0test-owner\0",
            request.identity.intent.as_slice(),
        ]
        .concat(),
    )
}

/// Contract fixture owns the full unresolved request, audit and timer together;
/// it deliberately loses one committed reply, never acknowledges a bare marker.
struct Owner {
    store: Arc<MemoryKv>,
    fail: bool,
    lose_reply: AtomicBool,
}
impl LateAcceptance for Owner {
    fn accept<'a, S: NamespaceStore>(
        &'a self,
        _local: &'a S,
        _partition: &'a Partition,
        request: &'a ContentTakedownV1,
        now: u64,
        budget: &'a SliceBudget,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            if self.fail {
                return Err(StoreError::unavailable("owner unavailable"));
            }
            let remote = crate::indexed::budget::Budgeted::new(self.store.as_ref(), budget);
            let root = Partition::Namespace(request.identity.holder.ns.clone());
            let key = owned_key(request);
            let full_request = request.encode()?;
            if let Some(old) = remote.get(&root, &key).await? {
                if old != full_request {
                    return Err(StoreError::Corrupt("ownership request changed".into()));
                }
                return Ok(());
            }
            let batch = crate::admin::plan_system(
                &remote,
                &root,
                "system:timer",
                "system:timer/late-takedown",
                &[mkit_core::hash::to_hex(&request.identity.intent)],
                now,
            )
            .await?
            .require(Precondition::Absent(key.clone()))
            .put(key, full_request)
            .put(
                keys::timer(now, kinds::TAKEDOWN_WORK.get(), &timer().reference),
                Value::default(),
            );
            if remote.apply(&root, batch).await? != BatchOutcome::Committed {
                return Err(StoreError::unavailable("owner contended"));
            }
            if self.lose_reply.swap(false, Ordering::SeqCst) {
                return Err(StoreError::unavailable("accepted response lost"));
            }
            Ok(())
        })
    }
}
fn handler(store: Arc<MemoryKv>, fail: bool, lose: bool) -> LateTimer<Owner> {
    LateTimer {
        acceptance: Owner {
            store,
            fail,
            lose_reply: AtomicBool::new(lose),
        },
        max_subrequests: 16,
    }
}

async fn producer_plan(store: &MemoryKv) -> (Vec<Precondition>, Vec<Write>) {
    let identity = identity();
    let target = content_shard(&identity.object);
    let hook = HolderRelayHook {
        clock: Arc::new(ManualClock::new(102)),
    };
    let rows = vec![(
        1,
        codec::RelayV1 {
            at_ms: 100,
            target: target.clone(),
            puts: vec![(
                keys::pending_holder(&identity.object, &identity.hold_id),
                identity.encode().unwrap(),
            )],
            deletes: vec![],
        },
    )];
    let declared = hook.read_keys(&target, &rows).unwrap();
    assert!(declared.contains(&action_key(&identity.object)));
    let mut seen = vec![(keys::relay_high_water(&identity.source).unwrap(), None)];
    for key in declared {
        seen.push((key.clone(), store.get(&target, &key).await.unwrap()));
    }
    let mut pre = vec![];
    let mut writes = vec![];
    hook.before_apply_observed(&target, &rows, &seen, &mut pre, &mut writes)
        .await
        .unwrap();
    assert!(pre.iter().any(|guard| matches!(guard, Precondition::Equals(key, _) if key == &action_key(&identity.object))));
    (pre, writes)
}
async fn pending(store: &MemoryKv) {
    let id = identity();
    let index = ContentIndex::new(BorrowedStore(store));
    let _ = index
        .add_hold(&id.object, &id.hold_id, 10_000, 100)
        .await
        .unwrap();
    let _ = index
        .protect_pending_holder(&id.object, &id.hold_id, &id, 100)
        .await
        .unwrap();
}

#[test]
fn v2_only_holder_delivery_uses_exact_existing_ct_codec_and_guards_overlaps() {
    block_on(async {
        let store = store();
        pending(store.as_ref()).await;
        let id = identity();
        let index = ContentIndex::new(BorrowedStore(store.as_ref()));
        index
            .install_block_action(&id.object, &action(10), 101)
            .await
            .unwrap();
        let (preconditions, writes) = producer_plan(store.as_ref()).await;
        index
            .install_block_action(&id.object, &action(20), 101)
            .await
            .unwrap();
        assert_ne!(
            store
                .apply(
                    &content_shard(&id.object),
                    Batch {
                        preconditions,
                        writes
                    }
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        let (preconditions, writes) = producer_plan(store.as_ref()).await;
        assert_eq!(
            store
                .apply(
                    &content_shard(&id.object),
                    Batch {
                        preconditions,
                        writes
                    }
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        let raw = store
            .get(
                &content_shard(&id.object),
                &keys::content_takedown(&id.object, &id.intent),
            )
            .await
            .unwrap()
            .unwrap();
        let request = ContentTakedownV1::decode(&raw).unwrap();
        assert_eq!(request.identity, id);
        assert_eq!(request.blocked.reason, "action10");
        assert_eq!(request.ready_at_ms, None);
        assert_eq!(request.encode().unwrap(), raw);
        assert_eq!(
            crate::takedown::denial::decode_actions(
                store
                    .get(&content_shard(&id.object), &action_key(&id.object))
                    .await
                    .unwrap()
                    .as_ref()
            )
            .unwrap()
            .len(),
            2
        );
        let (preconditions, writes) = producer_plan(store.as_ref()).await;
        assert_eq!(
            store
                .apply(
                    &content_shard(&id.object),
                    Batch {
                        preconditions,
                        writes
                    }
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        let state = store
            .get(&content_shard(&id.object), &keys::object_state(&id.object))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(codec::decode_object_state(&state).unwrap().holders, 1);
    });
}

#[test]
fn ready_materialization_and_owner_failure_retain_the_original_request() {
    block_on(async {
        let store = store();
        let original = request(None);
        install_request(store.as_ref(), &original).await;
        let partition = content_shard(&original.identity.object);
        let ctx = TimerCtx {
            store: store.as_ref(),
            partition: &partition,
            now_ms: 104,
        };
        let Fired::Reschedule { batch, .. } = handler(store.clone(), true, false)
            .fire(&ctx, &timer())
            .await
            .unwrap()
        else {
            panic!("ready must be durable first")
        };
        assert_eq!(
            store.apply(&partition, batch).await.unwrap(),
            BatchOutcome::Committed
        );
        let key = keys::content_takedown(&original.identity.object, &original.identity.intent);
        let ready = store.get(&partition, &key).await.unwrap().unwrap();
        assert_eq!(
            ContentTakedownV1::decode(&ready).unwrap(),
            request(Some(104))
        );
        assert!(
            handler(store.clone(), true, false)
                .fire(&ctx, &timer())
                .await
                .is_err()
        );
        assert_eq!(store.get(&partition, &key).await.unwrap(), Some(ready));
        assert!(
            store
                .get(
                    &partition,
                    &keys::timer(
                        104,
                        kinds::CONTENT_TAKEDOWN_REQUEST.get(),
                        &timer().reference
                    )
                )
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .get(
                    &Partition::Namespace(identity().holder.ns),
                    &owned_key(&request(Some(104)))
                )
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn lost_acceptance_reply_and_cold_restart_transfer_real_durable_responsibility() {
    block_on(async {
        let store = store();
        let request = request(Some(103));
        install_request(store.as_ref(), &request).await;
        let partition = content_shard(&request.identity.object);
        let ctx = TimerCtx {
            store: store.as_ref(),
            partition: &partition,
            now_ms: 104,
        };
        assert!(
            handler(store.clone(), false, true)
                .fire(&ctx, &timer())
                .await
                .is_err()
        );
        let key = keys::content_takedown(&request.identity.object, &request.identity.intent);
        assert_eq!(
            store.get(&partition, &key).await.unwrap(),
            Some(request.encode().unwrap())
        );
        let root = Partition::Namespace(request.identity.holder.ns.clone());
        assert_eq!(
            store.get(&root, &owned_key(&request)).await.unwrap(),
            Some(request.encode().unwrap())
        );
        assert!(
            store
                .get(
                    &root,
                    &keys::timer(104, kinds::TAKEDOWN_WORK.get(), &timer().reference)
                )
                .await
                .unwrap()
                .is_some()
        );
        let Fired::Done(mut batch) = handler(store.clone(), false, false)
            .fire(&ctx, &timer())
            .await
            .unwrap()
        else {
            panic!("durable owner accepted")
        };
        let mut replaced = request.clone();
        replaced.ready_at_ms = Some(104);
        store
            .apply(
                &partition,
                Batch::new().put(key.clone(), replaced.encode().unwrap()),
            )
            .await
            .unwrap();
        assert_ne!(
            store.apply(&partition, batch.clone()).await.unwrap(),
            BatchOutcome::Committed
        );
        store
            .apply(
                &partition,
                Batch::new().put(key.clone(), request.encode().unwrap()),
            )
            .await
            .unwrap();
        batch = batch.delete(keys::timer(
            104,
            kinds::CONTENT_TAKEDOWN_REQUEST.get(),
            &timer().reference,
        ));
        assert_eq!(
            store.apply(&partition, batch).await.unwrap(),
            BatchOutcome::Committed
        );
        assert!(store.get(&partition, &key).await.unwrap().is_none());
        assert!(
            store
                .get(&root, &owned_key(&request))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .get(
                    &root,
                    &keys::timer(104, kinds::TAKEDOWN_WORK.get(), &timer().reference)
                )
                .await
                .unwrap()
                .is_some()
        );
    });
}

#[test]
fn invalid_identity_readiness_and_shared_budget_fail_before_acknowledgment() {
    block_on(async {
        for ready in [Some(101), Some(105), Some(103)] {
            let store = store();
            let request = request(ready);
            install_request(store.as_ref(), &request).await;
            let partition = content_shard(&request.identity.object);
            let ctx = TimerCtx {
                store: store.as_ref(),
                partition: &partition,
                now_ms: 104,
            };
            let mut handler = handler(store.clone(), false, false);
            handler.max_subrequests = if ready == Some(103) { 5 } else { 16 };
            assert!(handler.fire(&ctx, &timer()).await.is_err());
            let key = keys::content_takedown(&request.identity.object, &request.identity.intent);
            assert_eq!(
                store.get(&partition, &key).await.unwrap(),
                Some(request.encode().unwrap())
            );
        }
        {
            let store = store();
            let mut queued = request(None);
            queued.queued_at_ms = 105;
            install_request(store.as_ref(), &queued).await;
            let partition = content_shard(&queued.identity.object);
            let ctx = TimerCtx {
                store: store.as_ref(),
                partition: &partition,
                now_ms: 104,
            };
            assert!(
                handler(store.clone(), false, false)
                    .fire(&ctx, &timer())
                    .await
                    .is_err()
            );
            let key = keys::content_takedown(&queued.identity.object, &queued.identity.intent);
            assert_eq!(
                store.get(&partition, &key).await.unwrap(),
                Some(queued.encode().unwrap())
            );
        }
        let store = store();
        install_request(store.as_ref(), &request(Some(103))).await;
        let partition = content_shard(&identity().object);
        let ctx = TimerCtx {
            store: store.as_ref(),
            partition: &partition,
            now_ms: 104,
        };
        let mut invalid = timer();
        let mut reference = invalid.reference.to_vec();
        reference[63] ^= 1;
        invalid.reference = reference.into();
        assert!(
            handler(store.clone(), false, false)
                .fire(&ctx, &invalid)
                .await
                .is_err()
        );
    });
}
