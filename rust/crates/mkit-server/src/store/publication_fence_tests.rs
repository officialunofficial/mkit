use super::*;
use crate::pipeline::{D34Shards, ShardMap};
use crate::repo::RepoName;
use crate::{MemoryKv, NamespaceKey};
use futures_executor::block_on;
use std::sync::{Arc, Barrier};

fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("kit").expect("valid fixture repository name"),
    }
}
fn source(name: &str) -> Partition {
    D34Shards.ref_shard(&repo(), &format!("refs/heads/{name}"))
}
fn generation(number: u64) -> Generation {
    Generation {
        incarnation: [7; 32],
        number,
    }
}
fn publication(name: &str, attempt: u64) -> Batch {
    let repo = repo();
    let mut batch = Batch::new()
        .require(if attempt == 1 {
            Precondition::Absent(keys::outbox_sequence())
        } else {
            Precondition::Equals(
                keys::outbox_sequence(),
                codec::encode_u64((attempt - 1) * 2),
            )
        })
        .put(keys::outbox_sequence(), codec::encode_u64(attempt * 2));
    for (offset, name) in [
        (1, format!("refs/heads/{name}")),
        (2, format!("refs/mkit/packmap/{name}")),
    ] {
        let sequence = (attempt - 1) * 2 + offset;
        let value = codec::encode_ref_id(
            &[u8::try_from(sequence).expect("fixture relay sequence fits one byte"); 32],
        );
        batch = batch
            .put(keys::published_ref(&repo.name, &name), value.clone())
            .put(
                keys::relay(sequence),
                codec::encode_relay(&codec::RelayV1 {
                    at_ms: 1000,
                    target: D34Shards.ref_index(&repo, &name),
                    puts: vec![(keys::published_index(&repo.name, &name), value)],
                    deletes: vec![],
                })
                .expect("valid fixture projection relay"),
            );
    }
    batch
}
fn plan(name: &str, attempt: u64) -> super::super::publication_fence_plan::PublicationBatch {
    super::super::publication_fence_plan::publication_batch(
        &source(name),
        &publication(name, attempt),
    )
    .expect("fixture publication has valid projection obligations")
    .expect("fixture batch contains publication effects")
}
fn targets(name: &str, attempt: u64) -> Vec<Target> {
    plan(name, attempt)
        .targets
        .iter()
        .map(|(p, n)| Target::new(p, *n).expect("fixture target has a nonzero watermark"))
        .collect()
}
async fn begin(store: &MemoryKv, fence: &PublicationFence, name: &str, attempt: u64) -> Intent {
    fence
        .begin(
            store,
            &source(name),
            attempt,
            plan(name, attempt).digest,
            targets(name, attempt),
        )
        .await
        .expect("fixture intent invalidation commits")
}
async fn setup(store: &MemoryKv) -> PublicationFence {
    let fence = PublicationFence::new(&repo());
    fence
        .initialize(store, generation(1))
        .await
        .expect("fixture fence initializes");
    assert_eq!(
        fence
            .stable(store)
            .await
            .expect("fresh fence state can be read"),
        None
    );
    ready(store, &fence).await;
    fence
}
async fn ready(store: &MemoryKv, fence: &PublicationFence) {
    let batch = fence
        .bootstrap_ready_batch(store)
        .await
        .expect("quiescent fixture produces readiness batch");
    assert_eq!(
        store
            .apply(&fence.coordinator, batch)
            .await
            .expect("fixture readiness batch commits"),
        BatchOutcome::Committed
    );
    fence
        .seal(
            store,
            &fence
                .verify_bootstrap(store)
                .await
                .expect("fixture readiness marker verifies"),
        )
        .await
        .expect("fixture bootstrap seals");
}
async fn commit(store: &MemoryKv, intent: &Intent, name: &str) {
    let mut batch = publication(name, intent.attempt());
    PublicationFence::source_commit_fragment(intent, &mut batch)
        .expect("fixture commit matches its invalidated plan");
    assert_eq!(
        store
            .apply(&source(name), batch)
            .await
            .expect("fixture source transaction commits"),
        BatchOutcome::Committed
    );
}
async fn abort(store: &MemoryKv, intent: &Intent) {
    let mut batch = Batch::new();
    PublicationFence::source_abort_fragment(intent, &mut batch)
        .expect("fixture abort has no publication effects");
    assert_eq!(
        store
            .apply(
                &intent.source().expect("fixture source partition decodes"),
                batch
            )
            .await
            .expect("fixture irreversible abort commits"),
        BatchOutcome::Committed
    );
}
async fn deliver(store: &MemoryKv, intent: &Intent, index: usize) -> TargetReceipt {
    let target = &intent.targets[index];
    let p = target
        .partition()
        .expect("fixture target partition decodes");
    let source = intent.source().expect("fixture source partition decodes");
    assert_eq!(
        store
            .apply(
                &p,
                Batch::new().put(
                    keys::relay_high_water(&source)
                        .expect("fixture source has a valid relay watermark key"),
                    codec::encode_u64(target.watermark())
                )
            )
            .await
            .expect("fixture target receipt transaction commits"),
        BatchOutcome::Committed
    );
    TargetReceipt::verify(store, intent, index)
        .await
        .expect("fixture target watermark proves delivery")
}

#[test]
fn split_reordered_duplicate_receipts_never_expose_partial_publication() {
    block_on(async {
        let store = MemoryKv::default();
        let fence = setup(&store).await;
        let before = fence.stable(&store).await.unwrap().unwrap();
        let intent = begin(&store, &fence, "main", 1).await;
        assert_eq!(intent.targets.len(), 2);
        assert_eq!(fence.stable(&store).await.unwrap(), None);
        assert_eq!(begin(&store, &fence, "main", 1).await, intent);
        assert!(
            fence
                .begin(&store, &source("main"), 1, [12; 32], intent.targets.clone())
                .await
                .is_err()
        );
        assert!(
            fence
                .begin(&store, &source("main"), 2, [12; 32], vec![])
                .await
                .is_err()
        );
        fence.arm(&store, &intent).await.unwrap();
        assert!(SourceReceipt::verify(&store, &intent).await.is_err());
        assert!(TargetReceipt::verify(&store, &intent, 0).await.is_err());
        commit(&store, &intent, "main").await;
        let second = deliver(&store, &intent, 1).await;
        fence.target_receipt(&store, &second).await.unwrap();
        fence.target_receipt(&store, &second).await.unwrap();
        let receipt = SourceReceipt::verify(&store, &intent).await.unwrap();
        fence.source_receipt(&store, &receipt).await.unwrap();
        assert_eq!(fence.stable(&store).await.unwrap(), None);
        let first = deliver(&store, &intent, 0).await;
        fence.target_receipt(&store, &first).await.unwrap();
        let after = fence.stable(&store).await.unwrap().unwrap();
        assert_ne!(before, after);
        fence.source_receipt(&store, &receipt).await.unwrap();
        fence.target_receipt(&store, &first).await.unwrap();
        assert_eq!(fence.stable(&store).await.unwrap(), Some(after));
        let next = begin(&store, &fence, "main", 2).await;
        assert!(fence.source_receipt(&store, &receipt).await.is_err());
        assert!(fence.target_receipt(&store, &first).await.is_err());
        assert_eq!(next.attempt(), 2);
    });
}

#[test]
fn irreversible_abort_rejects_prepared_late_commit_and_rebound_plans() {
    block_on(async {
        let store = MemoryKv::default();
        let fence = setup(&store).await;
        let intent = begin(&store, &fence, "main", 1).await;
        fence.arm(&store, &intent).await.unwrap();
        let mut rebound = publication("main", 1);
        rebound.writes.push(super::super::Write::Put(
            Key::new(b"aux".to_vec()),
            Value::new(b"late".to_vec()),
        ));
        assert!(PublicationFence::source_commit_fragment(&intent, &mut rebound).is_err());
        assert!(PublicationFence::source_commit_fragment(&intent, &mut Batch::new()).is_err());
        let mut fake = intent.clone();
        fake.targets[0].watermark += 1;
        assert!(
            PublicationFence::source_commit_fragment(&fake, &mut publication("main", 1)).is_err()
        );
        assert!(
            PublicationFence::source_abort_fragment(&intent, &mut publication("main", 1)).is_err()
        );
        let mut stale = publication("main", 1);
        PublicationFence::source_commit_fragment(&intent, &mut stale).unwrap();
        abort(&store, &intent).await;
        let receipt = SourceReceipt::verify(&store, &intent).await.unwrap();
        fence.source_receipt(&store, &receipt).await.unwrap();
        assert!(fence.stable(&store).await.unwrap().is_some());
        assert!(matches!(
            store.apply(&source("main"), stale).await.unwrap(),
            BatchOutcome::PreconditionFailed { .. }
        ));
        assert_eq!(
            store
                .get(
                    &source("main"),
                    &keys::published_ref(&repo().name, "refs/heads/main")
                )
                .await
                .unwrap(),
            None
        );
        assert!(TargetReceipt::verify(&store, &intent, 0).await.is_err());
        // Other source work can allocate/drain relays after an aborted intent.
        // Model that retained sequence so attempt two uses an exact os2 guard.
        assert_eq!(
            store
                .apply(
                    &source("main"),
                    Batch::new()
                        .require(Precondition::Absent(keys::outbox_sequence()))
                        .put(keys::outbox_sequence(), codec::encode_u64(2))
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        let next = begin(&store, &fence, "main", 2).await;
        fence.arm(&store, &next).await.unwrap();
        commit(&store, &next, "main").await;
        fence
            .source_receipt(&store, &SourceReceipt::verify(&store, &next).await.unwrap())
            .await
            .unwrap();
        for index in 0..next.targets.len() {
            fence
                .target_receipt(&store, &deliver(&store, &next, index).await)
                .await
                .unwrap();
        }
        assert!(fence.stable(&store).await.unwrap().is_some());
    });
}

#[test]
fn crash_reopen_preserves_pending_and_rotation_rejects_old_callbacks() {
    block_on(async {
        let store = MemoryKv::default();
        let fence = setup(&store).await;
        let intent = begin(&store, &fence, "main", 1).await;
        fence.arm(&store, &intent).await.unwrap();
        commit(&store, &intent, "main").await;
        let receipt = SourceReceipt::verify(&store, &intent).await.unwrap();
        let reopened = MemoryKv::default();
        for partition in [&fence.coordinator, &source("main")] {
            let (header, stream) = super::super::super::export_partition(&store, partition, 42)
                .await
                .unwrap();
            super::super::super::import_stream(
                &reopened,
                &header,
                super::super::super::ImportMode::Fresh,
                stream,
            )
            .await
            .unwrap();
        }
        drop(store);
        let fresh = PublicationFence::new(&repo());
        assert_eq!(fresh.stable(&reopened).await.unwrap(), None);
        fresh.source_receipt(&reopened, &receipt).await.unwrap();
        assert_eq!(fresh.stable(&reopened).await.unwrap(), None);
        let mut last = None;
        for index in 0..intent.targets.len() {
            let r = deliver(&reopened, &intent, index).await;
            fresh.target_receipt(&reopened, &r).await.unwrap();
            last = Some(r);
        }
        let original = fresh.stable(&reopened).await.unwrap().unwrap();
        fresh.rotate(&reopened, generation(2)).await.unwrap();
        assert_eq!(fresh.stable(&reopened).await.unwrap(), None);
        assert!(fresh.source_receipt(&reopened, &receipt).await.is_err());
        assert!(
            fresh
                .target_receipt(&reopened, &last.unwrap())
                .await
                .is_err()
        );
        assert!(fresh.rotate(&reopened, generation(1)).await.is_err());
        ready(&reopened, &fresh).await;
        assert_ne!(fresh.stable(&reopened).await.unwrap().unwrap(), original);
        fresh
            .rotate(
                &reopened,
                Generation {
                    incarnation: [8; 32],
                    number: 1,
                },
            )
            .await
            .unwrap();
        ready(&reopened, &fresh).await;
        assert_ne!(fresh.stable(&reopened).await.unwrap().unwrap(), original);
        assert_eq!(begin(&reopened, &fresh, "main", 2).await.attempt(), 2);
    });
}

#[test]
fn source_cleanup_proves_delivery_without_time_based_pending_expiry() {
    block_on(async {
        let store = MemoryKv::default();
        let fence = setup(&store).await;
        let intent = begin(&store, &fence, "main", 1).await;
        fence.arm(&store, &intent).await.unwrap();
        commit(&store, &intent, "main").await;
        assert!(fence.reconcile_delivered(&store, &intent).await.is_err());
        assert_eq!(fence.stable(&store).await.unwrap(), None);
        // Simulate SDK delivery and subsequent source cleanup, in that order.
        for index in 0..intent.targets.len() {
            deliver(&store, &intent, index).await;
        }
        store
            .apply(
                &source("main"),
                Batch::new().delete(keys::relay(1)).delete(keys::relay(2)),
            )
            .await
            .unwrap();
        fence.reconcile_delivered(&store, &intent).await.unwrap();
        assert!(fence.stable(&store).await.unwrap().is_some());
    });
}

#[test]
fn stale_cas_never_partially_changes_row_or_pending_count() {
    block_on(async {
        let store = MemoryKv::default();
        let fence = setup(&store).await;
        let (stale, root) = fence.root(&store).await.unwrap();
        let intent = begin(&store, &fence, "a", 1).await;
        let key = fence.row_key(&source("b").encode().unwrap());
        let batch = Batch::new()
            .require(Precondition::Equals(fence.root_key(), stale))
            .require(Precondition::Absent(key.clone()))
            .put(key.clone(), Value::new(b"bad".to_vec()))
            .put(
                fence.root_key(),
                encode(&Root { pending: 0, ..root }).unwrap(),
            );
        assert!(matches!(
            store.apply(&fence.coordinator, batch).await.unwrap(),
            BatchOutcome::PreconditionFailed { .. }
        ));
        assert_eq!(store.get(&fence.coordinator, &key).await.unwrap(), None);
        assert_eq!(fence.root(&store).await.unwrap().1.pending, 1);
        fence.arm(&store, &intent).await.unwrap();
        abort(&store, &intent).await;
        fence
            .source_receipt(
                &store,
                &SourceReceipt::verify(&store, &intent).await.unwrap(),
            )
            .await
            .unwrap();
        assert!(fence.stable(&store).await.unwrap().is_some());
    });
}

#[test]
fn concurrent_sources_preserve_every_invalidation_and_completion() {
    let store = Arc::new(MemoryKv::default());
    block_on(setup(&store));
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|n| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                block_on(async {
                    barrier.wait();
                    let fence = PublicationFence::new(&repo());
                    let name = format!("b{n}");
                    let p = plan(&name, 1);
                    let intent = loop {
                        if let Ok(intent) = fence
                            .begin(
                                store.as_ref(),
                                &source(&name),
                                1,
                                p.digest,
                                targets(&name, 1),
                            )
                            .await
                        {
                            break intent;
                        }
                    };
                    fence.arm(store.as_ref(), &intent).await.unwrap();
                    commit(store.as_ref(), &intent, &name).await;
                    for index in 0..intent.targets.len() {
                        let receipt = deliver(store.as_ref(), &intent, index).await;
                        loop {
                            if fence.target_receipt(store.as_ref(), &receipt).await.is_ok() {
                                break;
                            }
                        }
                    }
                    let receipt = SourceReceipt::verify(store.as_ref(), &intent)
                        .await
                        .unwrap();
                    loop {
                        if fence.source_receipt(store.as_ref(), &receipt).await.is_ok() {
                            break;
                        }
                    }
                });
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    block_on(async {
        let fence = PublicationFence::new(&repo());
        let root = fence.root(store.as_ref()).await.unwrap().1;
        assert_eq!(root.pending, 0);
        assert!(root.revision >= 25);
        assert!(fence.stable(store.as_ref()).await.unwrap().is_some());
    });
}

#[test]
fn bootstrap_receipts_cannot_rebind_across_authorities_or_deleted_readiness() {
    block_on(async {
        let store = MemoryKv::default();
        let a = PublicationFence::new(&repo());
        let mut other_repo = repo();
        other_repo.name = RepoName::new("other").unwrap();
        let b = PublicationFence::new(&other_repo);
        other_repo.namespace = NamespaceKey::from_stored("other".to_owned());
        let c = PublicationFence::new(&other_repo);
        for fence in [&a, &b, &c] {
            fence.initialize(&store, generation(1)).await.unwrap();
        }
        store
            .apply(
                &a.coordinator,
                a.bootstrap_ready_batch(&store).await.unwrap(),
            )
            .await
            .unwrap();
        let receipt = a.verify_bootstrap(&store).await.unwrap();
        assert!(b.seal(&store, &receipt).await.is_err());
        assert!(c.seal(&store, &receipt).await.is_err());
        store
            .apply(&a.coordinator, Batch::new().delete(a.ready_key()))
            .await
            .unwrap();
        assert!(a.seal(&store, &receipt).await.is_err());
        assert_eq!(a.stable(&store).await.unwrap(), None);
        assert_eq!(b.stable(&store).await.unwrap(), None);
        assert_eq!(c.stable(&store).await.unwrap(), None);
    });
}

#[test]
fn bounds_corruption_overflow_and_stale_readiness_fail_closed() {
    block_on(async {
        let store = MemoryKv::default();
        let fence = setup(&store).await;
        let target = targets("main", 1)[0].clone();
        let oversized = vec![target.clone(); 17];
        assert!(
            fence
                .begin(&store, &source("main"), 1, [1; 32], oversized)
                .await
                .is_err()
        );
        assert!(
            fence
                .begin(
                    &store,
                    &source("main"),
                    1,
                    [1; 32],
                    vec![target.clone(), target]
                )
                .await
                .is_err()
        );
        assert!(Target::new(&source("main"), 0).is_err());
        assert!(decode::<Root>(&Value::new(vec![1; MAX_ROW_BYTES + 1])).is_err());
        let mut malformed = Intent {
            generation: generation(1),
            source: source("main").encode().unwrap().to_vec(),
            attempt: 1,
            digest: [1; 32],
            targets: vec![],
        };
        assert!(
            Row {
                intent: malformed.clone(),
                source: None,
                receipts: 1,
                complete: false
            }
            .validate()
            .is_err()
        );
        malformed.attempt = 0;
        assert!(malformed.validate().is_err());
        let (raw, mut root) = fence.root(&store).await.unwrap();
        root.revision = u64::MAX;
        store
            .apply(
                &fence.coordinator,
                Batch::new()
                    .require(Precondition::Equals(fence.root_key(), raw))
                    .put(fence.root_key(), encode(&root).unwrap()),
            )
            .await
            .unwrap();
        assert!(
            fence
                .begin(&store, &source("main"), 1, [1; 32], vec![])
                .await
                .is_err()
        );
        assert_eq!(fence.root(&store).await.unwrap().1.pending, 0);
        fence.rotate(&store, generation(2)).await.unwrap();
        store
            .apply(
                &fence.coordinator,
                fence.bootstrap_ready_batch(&store).await.unwrap(),
            )
            .await
            .unwrap();
        let readiness = fence.verify_bootstrap(&store).await.unwrap();
        begin(&store, &fence, "main", 1).await;
        assert!(fence.seal(&store, &readiness).await.is_err());
        assert_eq!(fence.stable(&store).await.unwrap(), None);
    });
}

async fn validate_final(
    store: &MemoryKv,
    source: &Partition,
    batch: &Batch,
) -> Result<(), StoreError> {
    let observed = store.get(source, &source_key()).await?;
    validate_source_transaction(source, batch, |key| {
        assert_eq!(*key, source_key());
        Ok(observed.clone())
    })
}

#[test]
fn final_storage_boundary_rejects_effects_added_after_fragment_generation() {
    block_on(async {
        let store = MemoryKv::default();
        let fence = setup(&store).await;
        let intent = begin(&store, &fence, "main", 1).await;
        let original = publication("main", 1);
        // Rollout leaves an unenrolled legacy source's behavior unchanged.
        validate_final(&store, &source("main"), &original)
            .await
            .unwrap();
        fence.arm(&store, &intent).await.unwrap();
        assert!(
            validate_final(&store, &source("main"), &original)
                .await
                .is_err()
        );
        let mut bound = original;
        PublicationFence::source_commit_fragment(&intent, &mut bound).unwrap();
        validate_final(&store, &source("main"), &bound)
            .await
            .unwrap();
        let mut changed = bound.clone();
        changed.writes.push(super::super::Write::Put(
            Key::new(b"extra".to_vec()),
            Value::new(b"effect".to_vec()),
        ));
        assert!(
            validate_final(&store, &source("main"), &changed)
                .await
                .is_err()
        );
        let mut changed = bound.clone();
        changed.preconditions.push(Precondition::NotAfter(123));
        assert!(
            validate_final(&store, &source("main"), &changed)
                .await
                .is_err()
        );
        let mut changed = bound.clone();
        changed.writes.retain(
            |write| !matches!(write, super::super::Write::Put(key, _) if *key == keys::relay(1)),
        );
        assert!(
            validate_final(&store, &source("main"), &changed)
                .await
                .is_err()
        );
        let mut changed = bound.clone();
        changed
            .writes
            .push(super::super::Write::Delete(source_key()));
        assert!(
            validate_final(&store, &source("main"), &changed)
                .await
                .is_err()
        );
        assert!(
            validate_final(&store, &source("other"), &bound)
                .await
                .is_err()
        );
        assert_eq!(
            store.apply(&source("main"), bound.clone()).await.unwrap(),
            BatchOutcome::Committed
        );
        assert!(
            validate_final(&store, &source("main"), &bound)
                .await
                .is_err()
        );
        validate_final(
            &store,
            &source("main"),
            &Batch::new().put(
                Key::new(b"ordinary".to_vec()),
                Value::new(b"write".to_vec()),
            ),
        )
        .await
        .unwrap();
    });
}

#[test]
fn final_storage_boundary_rejects_orphan_markers_and_abort_publication() {
    block_on(async {
        let store = MemoryKv::default();
        let fence = setup(&store).await;
        let intent = begin(&store, &fence, "main", 1).await;
        let mut orphan = publication("main", 1);
        PublicationFence::source_commit_fragment(&intent, &mut orphan).unwrap();
        assert!(
            validate_final(&store, &source("main"), &orphan)
                .await
                .is_err()
        );
        let mut arm_with_publication = publication("main", 1);
        arm_with_publication
            .preconditions
            .push(Precondition::Absent(source_key()));
        arm_with_publication.writes.push(super::super::Write::Put(
            source_key(),
            encode(&SourceMarker {
                intent: intent.clone(),
                disposition: Disposition::Armed,
            })
            .unwrap(),
        ));
        assert!(
            validate_final(&store, &source("main"), &arm_with_publication)
                .await
                .is_err()
        );
        fence.arm(&store, &intent).await.unwrap();
        let mut abort = Batch::new();
        PublicationFence::source_abort_fragment(&intent, &mut abort).unwrap();
        validate_final(&store, &source("main"), &abort)
            .await
            .unwrap();
        let mut changed = abort.clone();
        changed.writes.push(super::super::Write::Put(
            keys::published_ref(&repo().name, "refs/heads/main"),
            codec::encode_ref_id(&[4; 32]),
        ));
        assert!(
            validate_final(&store, &source("main"), &changed)
                .await
                .is_err()
        );
        let mut changed = abort.clone();
        changed.writes.extend(publication("main", 1).writes.into_iter().filter(|write| matches!(write, super::super::Write::Put(key, _) if matches!(keys::parse(key), Some(keys::ParsedKey::Relay(_))))));
        assert!(
            validate_final(&store, &source("main"), &changed)
                .await
                .is_err()
        );
        store.apply(&source("main"), abort).await.unwrap();
        assert!(
            validate_final(&store, &source("main"), &orphan)
                .await
                .is_err()
        );
        let deleted = Batch::new()
            .require(Precondition::Present(source_key()))
            .delete(source_key());
        assert!(
            validate_final(&store, &source("main"), &deleted)
                .await
                .is_err()
        );
    });
}

#[test]
fn unrelated_partitions_skip_source_fence_lookup() {
    let batch = Batch::new().put(
        Key::new(b"ordinary".to_vec()),
        Value::new(b"write".to_vec()),
    );
    let coordinator = Partition::Coordinator(repo().namespace);
    validate_source_transaction(&coordinator, &batch, |_| {
        panic!("unrelated partition performed source-marker lookup")
    })
    .unwrap();
    let index = D34Shards.ref_index(&repo(), "refs/heads/main");
    validate_source_transaction(&index, &batch, |_| {
        panic!("index partition performed source-marker lookup")
    })
    .unwrap();
}
