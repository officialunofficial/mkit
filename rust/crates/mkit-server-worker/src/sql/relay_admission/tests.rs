use super::*;
use crate::test_sqlite::RusqliteConn;
use futures::executor::block_on;
use mkit_server::pipeline::{D34Shards, ShardMap};
use mkit_server::store::adapter_spi::publication_fence::PublicationFence;
use mkit_server::store::adapter_spi::publication_fence_plan::publication_batch;
use mkit_server::{NamespaceKey, RepoId, RepoName};
fn generation(number: u64) -> Generation {
    Generation {
        incarnation: [73; 32],
        number,
    }
}
fn repo(name: &str) -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new(name).expect("valid admission fixture"),
    }
}
fn target() -> Partition {
    D34Shards.ref_index(&repo("admission"), "refs/heads/main")
}
fn store() -> SqlKvStore<RusqliteConn> {
    SqlKvStore::open(RusqliteConn::open_in_memory().expect("valid admission fixture"))
        .expect("valid admission fixture")
}
fn activate(store: &SqlKvStore<RusqliteConn>, part: &Partition) {
    store
        .pause_publication(part, None, generation(1))
        .expect("valid admission fixture");
    store
        .activate_relay_admission(part, None, generation(1))
        .expect("valid admission fixture");
}
fn published() -> Key {
    keys::published_index(&repo("admission").name, "refs/heads/main")
}
fn aux() -> Key {
    Key::new(b"aux-fixture\0".to_vec())
}
async fn proof(store: &SqlKvStore<RusqliteConn>, with_aux: bool) -> VerifiedRelay {
    let repository = repo("admission");
    let source = D34Shards.ref_shard(&repository, "refs/heads/main");
    let mut puts = vec![(published(), codec::encode_ref_id(&[1; 32]))];
    if with_aux {
        puts.push((aux(), Value::new(vec![8])));
    }
    let row = codec::encode_relay(&codec::RelayV1 {
        at_ms: 1000,
        target: target(),
        puts,
        deletes: if with_aux {
            vec![Key::new(b"obsolete-fixture\0".to_vec())]
        } else {
            vec![]
        },
    })
    .expect("valid admission fixture");
    let mut batch = Batch::new()
        .require(Precondition::Absent(keys::outbox_sequence()))
        .put(keys::outbox_sequence(), codec::encode_u64(1))
        .put(
            keys::published_ref(&repository.name, "refs/heads/main"),
            codec::encode_ref_id(&[1; 32]),
        )
        .put(keys::relay(1), row);
    let plan = publication_batch(&source, &batch)
        .expect("valid admission fixture")
        .expect("valid admission fixture");
    let fence = PublicationFence::new(&repository);
    fence
        .initialize(store, generation(1))
        .await
        .expect("valid admission fixture");
    let intent = fence
        .begin(
            store,
            &source,
            1,
            plan.digest,
            plan.fence_targets().expect("valid admission fixture"),
        )
        .await
        .expect("valid admission fixture");
    fence
        .arm(store, &intent)
        .await
        .expect("valid admission fixture");
    PublicationFence::source_commit_fragment(&intent, &mut batch).expect("valid admission fixture");
    assert_eq!(
        store
            .apply(&source, batch)
            .await
            .expect("valid admission fixture"),
        BatchOutcome::Committed
    );
    VerifiedRelay::verify(store, &intent, &target(), 1)
        .await
        .expect("valid admission fixture")
}
#[test]
fn resumed_target_rejects_legacy_and_extended_projection_or_watermark_writes() {
    block_on(async {
        let store = store();
        let target = target();
        activate(&store, &target);
        assert!(
            !store
                .publication_paused(&target)
                .expect("valid admission fixture")
        );
        assert!(
            store
                .apply(&target, Batch::new().put(published(), Value::new(vec![9])))
                .await
                .is_err(),
            "resumed target must reject unfenced legacy effects"
        );
        assert!(
            store
                .apply_extended(&target, Batch::new(), |_, batch, _| {
                    batch.writes.push(Write::Delete(published()));
                    Ok(())
                })
                .is_err()
        );
        let source = D34Shards.ref_shard(&repo("admission"), "refs/heads/main");
        assert!(
            store
                .apply(
                    &target,
                    Batch::new().put(
                        keys::relay_high_water(&source).expect("valid admission fixture"),
                        codec::encode_u64(1)
                    )
                )
                .await
                .is_err()
        );
        assert!(
            store
                .get(&target, &published())
                .await
                .expect("valid admission fixture")
                .is_none()
        );
    });
}
#[test]
fn admission_requires_exact_pause_and_survives_reopen_without_default_activation() {
    let conn = RusqliteConn::open_in_memory().expect("valid admission fixture");
    let store = SqlKvStore::open(conn.clone()).expect("valid admission fixture");
    let target = target();
    assert!(
        store
            .activate_relay_admission(&target, None, generation(1))
            .is_err()
    );
    store
        .pause_publication(&target, None, generation(1))
        .expect("valid admission fixture");
    assert!(
        store
            .activate_relay_admission(&target, None, generation(2))
            .is_err()
    );
    store
        .activate_relay_admission(&target, None, generation(1))
        .expect("valid admission fixture");
    let reopened = SqlKvStore::open(conn).expect("valid admission fixture");
    reopened
        .activate_relay_admission(&target, None, generation(1))
        .expect("valid admission fixture");
    let source = D34Shards.ref_shard(&repo("admission"), "refs/heads/main");
    reopened
        .relay_admission_snapshot(&target, &source, generation(1))
        .expect("valid admission fixture");
    assert!(
        reopened
            .relay_admission_snapshot(&target, &source, generation(2))
            .is_err()
    );
    assert!(
        reopened
            .relay_admission_snapshot(
                &D34Shards.ref_index(&repo("other"), "refs/heads/main"),
                &source,
                generation(1)
            )
            .is_err()
    );
}
#[test]
fn actual_messages_preserve_auxiliary_effects_and_watermark_cas() {
    block_on(async {
        let store = store();
        let proof = proof(&store, true).await;
        activate(&store, &target());
        store
            .apply(
                &target(),
                Batch::new().put(
                    Key::new(b"obsolete-fixture\0".to_vec()),
                    Value::new(vec![3]),
                ),
            )
            .await
            .expect("valid admission fixture");
        let snapshot = store
            .relay_admission_snapshot(
                &target(),
                &proof.intent().source().expect("valid admission fixture"),
                generation(1),
            )
            .expect("valid admission fixture");
        assert_eq!(
            store
                .apply_admitted_relay(&snapshot, std::slice::from_ref(&proof), |_, batch, _| {
                    batch.writes.push(Write::Put(
                        Key::new(b"extended-aux\0".to_vec()),
                        Value::new(vec![4]),
                    ));
                    Ok(())
                })
                .expect("valid admission fixture"),
            BatchOutcome::Committed
        );
        assert_eq!(
            store
                .get(&target(), &aux())
                .await
                .expect("valid admission fixture"),
            Some(Value::new(vec![8]))
        );
        assert!(
            store
                .get(&target(), &Key::new(b"obsolete-fixture\0".to_vec()))
                .await
                .expect("valid admission fixture")
                .is_none()
        );
        assert_eq!(
            store
                .get(&target(), &published())
                .await
                .expect("valid admission fixture"),
            Some(codec::encode_ref_id(&[1; 32]))
        );
        assert!(matches!(
            store
                .apply_admitted_relay(&snapshot, &[proof], |_, _, _| Ok(()))
                .expect("valid admission fixture"),
            BatchOutcome::PreconditionFailed { .. }
        ));
    });
}
#[test]
fn extension_cannot_edit_or_shadow_any_message_effect_or_watermark() {
    block_on(async {
        for tamper in 0..5 {
            let store = store();
            let proof = proof(&store, true).await;
            activate(&store, &target());
            let snapshot = store
                .relay_admission_snapshot(
                    &target(),
                    &proof.intent().source().expect("valid admission fixture"),
                    generation(1),
                )
                .expect("valid admission fixture");
            assert!(
                store
                    .apply_admitted_relay(&snapshot, &[proof], move |_, batch, _| {
                        match tamper {
                            0 => {
                                batch.writes.remove(1);
                            }
                            1 => batch.writes.push(Write::Put(aux(), Value::new(vec![99]))),
                            2 => batch.writes.push(Write::Delete(published())),
                            3 => {
                                let key = write_key(
                                    batch.writes.last().expect("valid admission fixture"),
                                )
                                .clone();
                                batch.writes.push(Write::Put(key, codec::encode_u64(99)));
                            }
                            _ => batch.preconditions.clear(),
                        }
                        Ok(())
                    })
                    .is_err(),
                "tamper {tamper}"
            );
            assert!(
                store
                    .get(&target(), &published())
                    .await
                    .expect("valid admission fixture")
                    .is_none()
            );
            assert!(
                store
                    .get(&target(), &aux())
                    .await
                    .expect("valid admission fixture")
                    .is_none()
            );
        }
    });
}
#[test]
fn generation_rotation_refuses_observed_proofs_and_old_duplicates_after_cleanup() {
    block_on(async {
        let store = store();
        let proof = proof(&store, false).await;
        let source = proof.intent().source().expect("valid admission fixture");
        activate(&store, &target());
        let before = store
            .relay_admission_snapshot(&target(), &source, generation(1))
            .expect("valid admission fixture");
        assert_eq!(
            store
                .apply_admitted_relay(&before, std::slice::from_ref(&proof), |_, _, _| Ok(()))
                .expect("valid admission fixture"),
            BatchOutcome::Committed
        );
        store
            .apply(&source, Batch::new().delete(keys::relay(1)))
            .await
            .expect("valid admission fixture");
        assert!(
            VerifiedRelay::verify(&store, proof.intent(), &target(), 1)
                .await
                .is_err()
        );
        assert!(
            store
                .admitted_relay_duplicate(&before, 1)
                .expect("valid admission fixture")
        );
        store
            .pause_publication(&target(), None, generation(2))
            .expect("valid admission fixture");
        store
            .activate_relay_admission(&target(), Some(generation(1)), generation(2))
            .expect("valid admission fixture");
        assert!(store.admitted_relay_duplicate(&before, 1).is_err());
        let current = store
            .relay_admission_snapshot(&target(), &source, generation(2))
            .expect("valid admission fixture");
        assert!(
            store
                .admitted_relay_duplicate(&current, 1)
                .expect("valid admission fixture")
        );
        assert!(
            store
                .apply_admitted_relay(&current, &[proof], |_, _, _| Ok(()))
                .is_err(),
            "old source proof cannot borrow current generation"
        );
    });
}
#[test]
fn logical_repository_isolation_and_portable_import_cannot_clear_admission() {
    block_on(async {
        use mkit_server::store::{ImportMode, Importer, export_header, export_page};
        let store = store();
        let target = target();
        store
            .apply(
                &target,
                Batch::new().put(published(), codec::encode_ref_id(&[1; 32])),
            )
            .await
            .expect("valid admission fixture");
        let header = export_header(&store, &target, 1000)
            .await
            .expect("valid admission fixture");
        let page = export_page(&store, &target, None, 100)
            .await
            .expect("valid admission fixture");
        activate(&store, &target);
        let rows = store
            .conn()
            .query(
                GET,
                &[target_part(&target).expect("valid admission fixture")],
            )
            .expect("valid admission fixture");
        assert_eq!(page.records.len(), 1, "local metadata is not portable KV");
        let mut importer =
            Importer::new(&store, &header, ImportMode::Merge).expect("valid admission fixture");
        importer
            .push(page.records[0].clone())
            .await
            .expect("valid admission fixture");
        assert!(
            importer.finish().await.is_err(),
            "portable merge commit cannot bypass admission"
        );
        assert_eq!(
            store
                .conn()
                .query(
                    GET,
                    &[target_part(&target).expect("valid admission fixture")]
                )
                .expect("valid admission fixture"),
            rows
        );
        let other = D34Shards.ref_index(&repo("other"), "refs/heads/main");
        assert_eq!(
            store
                .apply(
                    &other,
                    Batch::new().put(
                        keys::published_index(&repo("other").name, "refs/heads/main"),
                        Value::new(vec![3])
                    )
                )
                .await
                .expect("valid admission fixture"),
            BatchOutcome::Committed
        );
        assert!(
            store
                .apply(&target, Batch::new().delete(published()))
                .await
                .is_err()
        );
        assert_eq!(
            store
                .apply(&target, Batch::new().delete(aux()))
                .await
                .expect("valid admission fixture"),
            BatchOutcome::Committed,
            "nonprojection pruning still works"
        );
    });
}
#[test]
fn wrong_source_target_generation_and_repeated_proof_do_not_write() {
    block_on(async {
        let store = store();
        let proof = proof(&store, false).await;
        let source = proof.intent().source().expect("valid admission fixture");
        activate(&store, &target());
        let other = D34Shards.ref_index(&repo("other"), "refs/heads/main");
        activate(&store, &other);
        let wrong_target = store
            .relay_admission_snapshot(&other, &source, generation(1))
            .expect("valid admission fixture");
        let wrong_source = store
            .relay_admission_snapshot(
                &target(),
                &D34Shards.ref_shard(&repo("admission"), "refs/heads/dev"),
                generation(1),
            )
            .expect("valid admission fixture");
        for snapshot in [wrong_target, wrong_source] {
            assert!(
                store
                    .apply_admitted_relay(&snapshot, std::slice::from_ref(&proof), |_, _, _| Ok(()))
                    .is_err()
            );
        }
        let snapshot = store
            .relay_admission_snapshot(&target(), &source, generation(1))
            .expect("valid admission fixture");
        assert!(
            store
                .apply_admitted_relay(&snapshot, &[proof.clone(), proof], |_, _, _| Ok(()))
                .is_err()
        );
        assert!(
            store
                .apply_admitted_relay(&snapshot, &[], |_, _, _| Ok(()))
                .is_err()
        );
        assert!(
            store
                .get(&target(), &published())
                .await
                .expect("valid admission fixture")
                .is_none()
        );
    });
}
#[test]
fn final_extension_limits_roll_back_the_complete_message() {
    block_on(async {
        let store = store();
        let proof = proof(&store, true).await;
        activate(&store, &target());
        let snapshot = store
            .relay_admission_snapshot(
                &target(),
                &proof.intent().source().expect("valid admission fixture"),
                generation(1),
            )
            .expect("valid admission fixture");
        assert!(
            store
                .apply_admitted_relay(&snapshot, &[proof], |_, batch, _| {
                    for index in 0..mkit_server::store::MAX_BATCH_OPS {
                        batch.writes.push(Write::Put(
                            Key::new(format!("extension-{index}").into_bytes()),
                            Value::new(vec![1]),
                        ));
                    }
                    Ok(())
                })
                .is_err()
        );
        assert!(
            store
                .get(&target(), &published())
                .await
                .expect("valid admission fixture")
                .is_none()
        );
        assert!(
            store
                .get(&target(), &aux())
                .await
                .expect("valid admission fixture")
                .is_none()
        );
    });
}
#[test]
fn corrupt_admission_fails_closed_and_cannot_be_rebound() {
    block_on(async {
        let store = store();
        activate(&store, &target());
        for raw in [vec![2], vec![1; 513], b"\x01{}".to_vec()] {
            store
                .conn()
                .exec(
                    PUT,
                    &[
                        target_part(&target()).expect("valid admission fixture"),
                        SqlValue::Blob(raw),
                    ],
                )
                .expect("valid admission fixture");
            assert!(
                store
                    .apply(&target(), Batch::new().delete(published()))
                    .await
                    .is_err()
            );
            assert!(
                store
                    .activate_relay_admission(&target(), Some(generation(1)), generation(2))
                    .is_err()
            );
        }
    });
}
#[test]
fn metadata_rotation_preserves_soft_reserve_exact_retries_and_pruning() {
    block_on(async {
        let conn = RusqliteConn::open_in_memory().expect("valid admission fixture");
        let store = SqlKvStore::open_with_capacity(
            conn.clone(),
            super::super::Capacity::new(1 << 20).with_reserve(1 << 19),
        )
        .expect("valid admission fixture");
        activate(&store, &target());
        // Reserve a matching maintenance pause before filling the soft limit.
        let other = D34Shards.ref_index(&repo("other"), "refs/heads/main");
        store
            .pause_publication(&other, None, generation(1))
            .expect("valid admission fixture");
        let writable = Partition::Coordinator(NamespaceKey::deployment_default());
        let mut filled = false;
        for index in 0..128 {
            match store
                .apply(
                    &writable,
                    Batch::new().put(
                        Key::new(format!("fill-{index}").into_bytes()),
                        Value::new(vec![7; 16 * 1024]),
                    ),
                )
                .await
            {
                Ok(BatchOutcome::Committed) => {}
                Err(StoreError::Full) => {
                    filled = true;
                    break;
                }
                other => panic!("unexpected filler result: {other:?}"),
            }
        }
        assert!(filled);
        store
            .activate_relay_admission(&target(), None, generation(1))
            .expect("valid admission fixture");
        assert!(matches!(
            store.activate_relay_admission(&other, None, generation(1)),
            Err(StoreError::Full)
        ));
        assert!(
            store
                .publication_paused(&other)
                .expect("valid admission fixture"),
            "failed activation preserves its pause"
        );
        assert!(
            read(
                store.conn(),
                &target_part(&other).expect("valid admission fixture")
            )
            .expect("valid admission fixture")
            .is_none(),
            "no partial admission survives"
        );
        assert_eq!(
            store
                .apply(&target(), Batch::new().delete(aux()))
                .await
                .expect("valid admission fixture"),
            BatchOutcome::Committed
        );
    });
}

#[test]
fn rotation_after_observation_rejects_a_still_matching_watermark_cas() {
    block_on(async {
        let store = store();
        let proof = proof(&store, true).await;
        activate(&store, &target());
        let snapshot = store
            .relay_admission_snapshot(
                &target(),
                &proof.intent().source().expect("valid admission fixture"),
                generation(1),
            )
            .expect("valid admission fixture");
        store
            .pause_publication(&target(), None, generation(2))
            .expect("valid admission fixture");
        store
            .activate_relay_admission(&target(), Some(generation(1)), generation(2))
            .expect("valid admission fixture");
        assert!(
            store
                .apply_admitted_relay(&snapshot, &[proof], |_, _, _| Ok(()))
                .is_err()
        );
        assert!(
            store
                .get(&target(), &published())
                .await
                .expect("valid admission fixture")
                .is_none()
        );
        assert!(
            store
                .get(&target(), &aux())
                .await
                .expect("valid admission fixture")
                .is_none()
        );
    });
}
#[test]
fn watermark_cannot_skip_a_bound_earlier_message_to_the_same_target() {
    block_on(async {
        let store = store();
        let repository = repo("admission");
        let source = D34Shards.ref_shard(&repository, "refs/heads/main");
        let mut batch = Batch::new()
            .require(Precondition::Absent(keys::outbox_sequence()))
            .put(keys::outbox_sequence(), codec::encode_u64(2));
        for (sequence, name) in [(1, "refs/heads/main"), (2, "refs/heads/main")] {
            let value = codec::encode_ref_id(
                &[u8::try_from(sequence).expect("valid admission fixture"); 32],
            );
            assert_eq!(D34Shards.ref_index(&repository, name), target());
            batch = batch
                .put(keys::published_ref(&repository.name, name), value.clone())
                .put(
                    keys::relay(sequence),
                    codec::encode_relay(&codec::RelayV1 {
                        at_ms: 1000,
                        target: target(),
                        puts: vec![(keys::published_index(&repository.name, name), value)],
                        deletes: vec![],
                    })
                    .expect("valid admission fixture"),
                );
        }
        let plan = publication_batch(&source, &batch)
            .expect("valid admission fixture")
            .expect("valid admission fixture");
        let fence = PublicationFence::new(&repository);
        fence
            .initialize(&store, generation(1))
            .await
            .expect("valid admission fixture");
        let intent = fence
            .begin(
                &store,
                &source,
                1,
                plan.digest,
                plan.fence_targets().expect("valid admission fixture"),
            )
            .await
            .expect("valid admission fixture");
        fence
            .arm(&store, &intent)
            .await
            .expect("valid admission fixture");
        PublicationFence::source_commit_fragment(&intent, &mut batch)
            .expect("valid admission fixture");
        store
            .apply(&source, batch)
            .await
            .expect("valid admission fixture");
        let first = VerifiedRelay::verify(&store, &intent, &target(), 1)
            .await
            .expect("valid admission fixture");
        let second = VerifiedRelay::verify(&store, &intent, &target(), 2)
            .await
            .expect("valid admission fixture");
        activate(&store, &target());
        let snapshot = store
            .relay_admission_snapshot(&target(), &source, generation(1))
            .expect("valid admission fixture");
        assert!(
            store
                .apply_admitted_relay(&snapshot, std::slice::from_ref(&second), |_, _, _| Ok(()))
                .is_err(),
            "rh must not declare an omitted message delivered"
        );
        assert!(
            store
                .get(&target(), &published())
                .await
                .expect("valid admission fixture")
                .is_none()
        );
        assert_eq!(
            store
                .apply_admitted_relay(&snapshot, &[first, second], |_, _, _| Ok(()))
                .expect("valid admission fixture"),
            BatchOutcome::Committed
        );
    });
}
