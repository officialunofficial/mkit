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
    proof_at(store, with_aux, 1, generation(1)).await
}
async fn proof_at(
    store: &SqlKvStore<RusqliteConn>,
    with_aux: bool,
    sequence: u64,
    generation: Generation,
) -> VerifiedRelay {
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
    let guard = if sequence == 1 {
        Precondition::Absent(keys::outbox_sequence())
    } else {
        store
            .apply(
                &source,
                Batch::new().put(keys::outbox_sequence(), codec::encode_u64(sequence - 1)),
            )
            .await
            .expect("prior restored source counter");
        Precondition::Equals(keys::outbox_sequence(), codec::encode_u64(sequence - 1))
    };
    let mut batch = Batch::new()
        .require(guard)
        .put(keys::outbox_sequence(), codec::encode_u64(sequence))
        .put(
            keys::published_ref(&repository.name, "refs/heads/main"),
            codec::encode_ref_id(&[1; 32]),
        )
        .put(keys::relay(sequence), row);
    let plan = publication_batch(&source, &batch)
        .expect("valid admission fixture")
        .expect("valid admission fixture");
    let fence = PublicationFence::new(&repository);
    fence
        .initialize(store, generation)
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
    VerifiedRelay::verify(store, &intent, &target(), sequence)
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
            !store
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
#[test]
fn inherited_compatibility_rh_does_not_acknowledge_restored_source_history() {
    block_on(async {
        let store = store();
        let proof = proof_at(&store, true, 6, generation(1)).await;
        let source = proof.intent().source().expect("fixture source");
        let rh = keys::relay_high_water(&source).expect("fixture rh");
        store
            .apply(
                &target(),
                Batch::new().put(rh.clone(), codec::encode_u64(100)),
            )
            .await
            .expect("legacy target watermark");
        activate(&store, &target());
        let snapshot = store
            .relay_admission_snapshot(&target(), &source, generation(1))
            .expect("admitted snapshot");
        assert_eq!(
            snapshot.watermark(),
            0,
            "raw rh cannot prove new-generation delivery"
        );
        assert!(
            !store
                .admitted_relay_duplicate(&snapshot, 6)
                .expect("duplicate observation")
        );
        assert_eq!(
            store
                .apply_admitted_relay(&snapshot, &[proof], |_, _, _| Ok(()))
                .expect("actual message apply"),
            BatchOutcome::Committed
        );
        assert_eq!(
            store.get(&target(), &rh).await.expect("compatibility rh"),
            Some(codec::encode_u64(100)),
            "compatibility rh must not regress"
        );
        let current = store
            .relay_admission_snapshot(&target(), &source, generation(1))
            .expect("fresh applied progress");
        assert_eq!(current.watermark(), 6);
        assert!(
            store
                .admitted_relay_duplicate(&current, 6)
                .expect("actual duplicate")
        );
        assert_eq!(
            store.get(&target(), &aux()).await.expect("aux effect"),
            Some(Value::new(vec![8]))
        );
    });
}
#[test]
fn snapshots_with_equal_raw_rh_cannot_both_commit_after_private_progress_changes() {
    block_on(async {
        let store = store();
        let proof = proof_at(&store, true, 6, generation(1)).await;
        let source = proof.intent().source().expect("fixture source");
        let rh = keys::relay_high_water(&source).expect("fixture rh");
        store
            .apply(
                &target(),
                Batch::new().put(rh.clone(), codec::encode_u64(100)),
            )
            .await
            .expect("legacy target watermark");
        activate(&store, &target());
        let first = store
            .relay_admission_snapshot(&target(), &source, generation(1))
            .expect("first snapshot");
        let second = store
            .relay_admission_snapshot(&target(), &source, generation(1))
            .expect("second snapshot");
        assert_eq!(
            store
                .apply_admitted_relay(&first, std::slice::from_ref(&proof), |_, _, _| Ok(()))
                .expect("first apply"),
            BatchOutcome::Committed
        );
        assert!(
            store
                .apply_admitted_relay(&second, &[proof], |_, _, _| Ok(()))
                .is_err(),
            "private progress CAS must reject stale snapshot even if compatibility rh stays 100"
        );
        assert_eq!(
            store.get(&target(), &rh).await.expect("unchanged raw rh"),
            Some(codec::encode_u64(100))
        );
    });
}
#[derive(Clone)]
struct LostReplyConn {
    inner: RusqliteConn,
    lose: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl SqlConn for LostReplyConn {
    fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError> {
        self.inner.exec(sql, params)
    }
    fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<super::super::Row>, SqlError> {
        self.inner.query(sql, params)
    }
    fn transaction<T: 'static>(&self, f: super::super::TxFn<Self, T>) -> Result<T, SqlError> {
        let lose = self.lose.clone();
        let result = self
            .inner
            .transaction(Box::new(move |inner| f(Self { inner, lose })))?;
        if self.lose.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(SqlError::Backend(mkit_server::Redacted::new(
                "injected lost commit reply",
            )));
        }
        Ok(result)
    }
    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
    fn size_bytes(&self) -> Result<u64, SqlError> {
        self.inner.size_bytes()
    }
    fn set_size_limit(&self, bytes: u64) -> Result<(), SqlError> {
        self.inner.set_size_limit(bytes)
    }
}
#[test]
fn lost_commit_reply_recovers_private_progress_after_source_cleanup_and_reopen() {
    block_on(async {
        let source_store = store();
        let proof = proof_at(&source_store, true, 6, generation(1)).await;
        let source = proof.intent().source().expect("fixture source");
        let inner = RusqliteConn::open_in_memory().expect("target SQLite");
        let lose = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let target_store = SqlKvStore::open(LostReplyConn {
            inner: inner.clone(),
            lose: lose.clone(),
        })
        .expect("target store");
        target_store
            .pause_publication(&target(), None, generation(1))
            .expect("target pause");
        target_store
            .activate_relay_admission(&target(), None, generation(1))
            .expect("target activation");
        let snapshot = target_store
            .relay_admission_snapshot(&target(), &source, generation(1))
            .expect("snapshot");
        lose.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(
            target_store
                .apply_admitted_relay(&snapshot, std::slice::from_ref(&proof), |_, _, _| Ok(()))
                .is_err()
        );
        source_store
            .apply(&source, Batch::new().delete(keys::relay(6)))
            .await
            .expect("source cleanup");
        assert!(
            VerifiedRelay::verify(&source_store, proof.intent(), &target(), 6)
                .await
                .is_err()
        );
        let reopened = SqlKvStore::open(inner).expect("reopened target");
        let receipt = reopened
            .target_progress_receipt(&target(), &source, generation(1))
            .expect("fresh progress observation")
            .expect("committed progress");
        assert_eq!(receipt.target(), &target());
        assert_eq!(receipt.source(), &source);
        assert_eq!(receipt.generation(), generation(1));
        assert_eq!(receipt.through(), 6);
        assert!(
            reopened
                .admitted_relay_duplicate(&snapshot, 6)
                .expect("recover duplicate")
        );
        assert_eq!(
            reopened
                .get(&target(), &aux())
                .await
                .expect("persisted effect"),
            Some(Value::new(vec![8]))
        );
    });
}
#[test]
fn portable_import_carries_compatibility_rh_but_never_private_applied_progress() {
    block_on(async {
        use mkit_server::store::{ImportMode, Importer, export_header, export_page};
        let original = store();
        let proof = proof_at(&original, false, 6, generation(1)).await;
        let source = proof.intent().source().expect("fixture source");
        activate(&original, &target());
        let snapshot = original
            .relay_admission_snapshot(&target(), &source, generation(1))
            .expect("snapshot");
        original
            .apply_admitted_relay(&snapshot, &[proof], |_, _, _| Ok(()))
            .expect("apply");
        let header = export_header(&original, &target(), 1000)
            .await
            .expect("header");
        let page = export_page(&original, &target(), None, 100)
            .await
            .expect("page");
        assert_eq!(
            page.records.len(),
            2,
            "only py and compatibility rh are portable"
        );
        let restored_store = store();
        let mut importer =
            Importer::new(&restored_store, &header, ImportMode::Fresh).expect("importer");
        for record in page.records {
            importer.push(record).await.expect("queue record");
        }
        importer.finish().await.expect("import actual KV");
        activate(&restored_store, &target());
        let snapshot = restored_store
            .relay_admission_snapshot(&target(), &source, generation(1))
            .expect("restored snapshot");
        assert_eq!(snapshot.watermark(), 0);
        assert!(
            restored_store
                .target_progress_receipt(&target(), &source, generation(1))
                .expect("progress observation")
                .is_none()
        );
        assert!(
            !restored_store
                .admitted_relay_duplicate(&snapshot, 6)
                .expect("restored duplicate")
        );
    });
}
#[test]
fn extension_failure_and_soft_cap_never_leave_partial_progress_or_effects() {
    block_on(async {
        let source_store = store();
        let proof = proof_at(&source_store, true, 6, generation(1)).await;
        let source = proof.intent().source().expect("fixture source");
        let conn = RusqliteConn::open_in_memory().expect("target SQLite");
        let limited = SqlKvStore::open_with_capacity(
            conn,
            super::super::Capacity::new(1 << 20).with_reserve(1 << 19),
        )
        .expect("limited target");
        activate(&limited, &target());
        let snapshot = limited
            .relay_admission_snapshot(&target(), &source, generation(1))
            .expect("snapshot");
        assert!(
            limited
                .apply_admitted_relay(&snapshot, std::slice::from_ref(&proof), |_, _, _| Err(
                    SqlError::Constraint
                ))
                .is_err()
        );
        assert!(
            limited
                .target_progress_receipt(&target(), &source, generation(1))
                .expect("no failed progress")
                .is_none()
        );
        let writable = Partition::Coordinator(NamespaceKey::deployment_default());
        let mut full = false;
        for index in 0..128 {
            match limited
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
                    full = true;
                    break;
                }
                other => panic!("unexpected filler {other:?}"),
            }
        }
        assert!(full);
        assert!(matches!(
            limited.apply_admitted_relay(&snapshot, &[proof], |_, _, _| Ok(())),
            Err(StoreError::Full)
        ));
        assert!(
            limited
                .target_progress_receipt(&target(), &source, generation(1))
                .expect("no full progress")
                .is_none()
        );
        assert!(
            limited
                .get(&target(), &published())
                .await
                .expect("no effects")
                .is_none()
        );
        assert!(
            limited
                .conn()
                .query(
                    "SELECT 1 FROM sqlite_master WHERE name = 'mkit_relay_progress'",
                    &[]
                )
                .expect("metadata table observation")
                .is_empty(),
            "failed applies do not create progress metadata"
        );
    });
}
#[test]
fn private_progress_reserves_operations_and_payload_bytes_in_final_extension() {
    block_on(async {
        for allowance in ["operations", "bytes"] {
            let store = store();
            let proof = proof(&store, true).await;
            let source = proof.intent().source().expect("fixture source");
            activate(&store, &target());
            let snapshot = store
                .relay_admission_snapshot(&target(), &source, generation(1))
                .expect("snapshot");
            assert!(
                store
                    .apply_admitted_relay(&snapshot, &[proof], move |_, batch, _| {
                        if allowance == "operations" {
                            let remaining = mkit_server::store::MAX_BATCH_OPS
                                - batch.preconditions.len()
                                - batch.writes.len();
                            for index in 0..remaining {
                                batch.writes.push(Write::Put(
                                    Key::new(format!("extension-{index}").into_bytes()),
                                    Value::default(),
                                ));
                            }
                        } else {
                            let guard_bytes: usize = batch
                                .preconditions
                                .iter()
                                .map(|guard| match guard {
                                    Precondition::Absent(key) | Precondition::Present(key) => {
                                        key.as_bytes().len()
                                    }
                                    Precondition::Equals(key, value) => {
                                        key.as_bytes().len() + value.as_bytes().len()
                                    }
                                    Precondition::NotAfter(_) => 0,
                                })
                                .sum();
                            let effect_bytes: usize = batch
                                .writes
                                .iter()
                                .map(|write| match write {
                                    Write::Put(key, value) => {
                                        key.as_bytes().len() + value.as_bytes().len()
                                    }
                                    Write::Delete(key) => key.as_bytes().len(),
                                })
                                .sum();
                            let keys = [Key::new(b"size-a".to_vec()), Key::new(b"size-b".to_vec())];
                            let remaining = mkit_server::store::MAX_BATCH_BYTES
                                - guard_bytes
                                - effect_bytes
                                - keys.iter().map(|key| key.as_bytes().len()).sum::<usize>();
                            let first = mkit_server::store::MAX_VALUE_BYTES;
                            batch
                                .writes
                                .push(Write::Put(keys[0].clone(), Value::new(vec![7; first])));
                            batch.writes.push(Write::Put(
                                keys[1].clone(),
                                Value::new(vec![8; remaining - first]),
                            ));
                        }
                        batch
                            .validate(&mkit_server::StoreCapabilities::full())
                            .expect("portable batch alone is within exact allowance");
                        Ok(())
                    })
                    .is_err(),
                "metadata {allowance} must also fit"
            );
            assert!(
                store
                    .target_progress_receipt(&target(), &source, generation(1))
                    .expect("no progress")
                    .is_none()
            );
            assert!(
                store
                    .get(&target(), &published())
                    .await
                    .expect("no effect")
                    .is_none()
            );
        }
    });
}
#[test]
fn failed_private_progress_put_rolls_back_prior_effects_and_compatibility_watermark() {
    block_on(async {
        let store = store();
        let proof = proof(&store, true).await;
        let source = proof.intent().source().expect("fixture source");
        activate(&store, &target());
        store.conn().exec("CREATE TABLE mkit_relay_progress (part BLOB NOT NULL, source BLOB NOT NULL, value BLOB NOT NULL, PRIMARY KEY (part, source)) WITHOUT ROWID", &[]).expect("fixture progress table");
        store.conn().exec("CREATE TRIGGER reject_progress BEFORE INSERT ON mkit_relay_progress BEGIN SELECT RAISE(ABORT, 'fixture'); END", &[]).expect("fixture SQL fault");
        let snapshot = store
            .relay_admission_snapshot(&target(), &source, generation(1))
            .expect("snapshot");
        assert!(
            store
                .apply_admitted_relay(&snapshot, &[proof], |_, _, _| Ok(()))
                .is_err()
        );
        assert!(
            store
                .get(&target(), &published())
                .await
                .expect("rolled back py")
                .is_none()
        );
        assert!(
            store
                .get(&target(), &aux())
                .await
                .expect("rolled back aux")
                .is_none()
        );
        assert!(
            store
                .get(&target(), &keys::relay_high_water(&source).expect("rh key"))
                .await
                .expect("rolled back compatibility rh")
                .is_none()
        );
        assert!(
            store
                .target_progress_receipt(&target(), &source, generation(1))
                .expect("rolled back progress")
                .is_none()
        );
    });
}
#[test]
fn progress_corruption_fails_closed_even_for_old_generation_rows() {
    block_on(async {
        let store = store();
        let proof = proof(&store, false).await;
        let source = proof.intent().source().expect("fixture source");
        activate(&store, &target());
        let snapshot = store
            .relay_admission_snapshot(&target(), &source, generation(1))
            .expect("snapshot");
        store
            .apply_admitted_relay(&snapshot, &[proof], |_, _, _| Ok(()))
            .expect("initial apply");
        let mut raws = vec![vec![b' '; 513], b"{}".to_vec()];
        for field in ["version", "through", "unknown", "old-generation-corrupt"] {
            let mut record: serde_json::Value =
                serde_json::from_slice(&progress::encode(generation(1), 1).expect("valid record"))
                    .expect("JSON fixture");
            match field {
                "version" => record["version"] = serde_json::json!(2),
                "through" => record["through"] = serde_json::json!(0),
                "unknown" => record["extra"] = serde_json::json!(true),
                _ => {
                    record["generation"] =
                        serde_json::to_value(generation(0)).expect("generation JSON");
                    record["extra"] = serde_json::json!(true);
                }
            }
            raws.push(serde_json::to_vec(&record).expect("fixture encoding"));
        }
        for raw in raws {
            store
                .conn()
                .exec(
                    progress::PUT,
                    &[
                        target_part(&target()).expect("part"),
                        SqlValue::Blob(source.encode().expect("source").to_vec()),
                        SqlValue::Blob(raw),
                    ],
                )
                .expect("inject damaged ledger");
            assert!(
                store
                    .relay_admission_snapshot(&target(), &source, generation(1))
                    .is_err()
            );
            assert!(
                store
                    .target_progress_receipt(&target(), &source, generation(1))
                    .is_err()
            );
            assert!(store.admitted_relay_duplicate(&snapshot, 1).is_err());
        }
    });
}
#[test]
fn physical_backup_preserves_progress_but_rotation_reuses_one_bounded_row() {
    block_on(async {
        let original = store();
        let proof = proof(&original, false).await;
        let source = proof.intent().source().expect("fixture source");
        activate(&original, &target());
        let snapshot = original
            .relay_admission_snapshot(&target(), &source, generation(1))
            .expect("snapshot");
        original
            .apply_admitted_relay(&snapshot, &[proof], |_, _, _| Ok(()))
            .expect("apply");
        let dir = tempfile::tempdir().expect("private backup directory");
        let path = dir.path().join("target.sqlite");
        original
            .conn()
            .backup_to(path.to_str().expect("fixture path"))
            .expect("physical backup");
        let restored = SqlKvStore::open_existing(RusqliteConn::open(&path).expect("backup SQLite"))
            .expect("backup store");
        assert_eq!(
            restored
                .target_progress_receipt(&target(), &source, generation(1))
                .expect("backup receipt")
                .expect("backup applied progress")
                .through(),
            1
        );
        restored
            .pause_publication(&target(), None, generation(2))
            .expect("recovery pause");
        restored
            .activate_relay_admission(&target(), Some(generation(1)), generation(2))
            .expect("new admission");
        assert!(
            restored
                .target_progress_receipt(&target(), &source, generation(2))
                .expect("new-generation observation")
                .is_none()
        );
        assert!(
            restored
                .target_progress_receipt(&target(), &source, generation(1))
                .is_err()
        );
        let fresh_source = store();
        let proof = proof_at(&fresh_source, false, 6, generation(2)).await;
        let snapshot = restored
            .relay_admission_snapshot(&target(), &source, generation(2))
            .expect("new snapshot");
        restored
            .apply_admitted_relay(&snapshot, &[proof], |_, _, _| Ok(()))
            .expect("new effects");
        let rows = restored
            .conn()
            .query("SELECT value FROM mkit_relay_progress", &[])
            .expect("bounded ledger");
        assert_eq!(rows.len(), 1);
        assert!(matches!(&rows[0][0], SqlValue::Blob(value) if value.len() <= 512));
        assert_eq!(
            restored
                .target_progress_receipt(&target(), &source, generation(2))
                .expect("new receipt")
                .expect("new applied progress")
                .through(),
            6
        );
    });
}
#[test]
fn private_progress_v1_encoding_matches_durable_golden() {
    block_on(async {
        let store = store();
        let proof = proof_at(&store, false, 6, generation(1)).await;
        let source = proof.intent().source().expect("fixture source");
        activate(&store, &target());
        let snapshot = store
            .relay_admission_snapshot(&target(), &source, generation(1))
            .expect("snapshot");
        store
            .apply_admitted_relay(&snapshot, &[proof], |_, _, _| Ok(()))
            .expect("actual committed progress");
        let expected =
            include_str!("../../../../../tests/golden/publication-fence/target-progress-v1.json")
                .trim_end()
                .as_bytes();
        assert_eq!(
            progress::encode(generation(1), 6).expect("typed encoding"),
            expected
        );
        let rows = store
            .conn()
            .query(
                progress::GET,
                &[
                    target_part(&target()).expect("target"),
                    SqlValue::Blob(source.encode().expect("source").to_vec()),
                ],
            )
            .expect("actual durable row");
        assert_eq!(rows, vec![vec![SqlValue::Blob(expected.to_vec())]]);
    });
}
