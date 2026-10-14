use super::*;
use crate::test_sqlite::RusqliteConn;
use futures::executor::block_on;
use mkit_server::pipeline::{D34Shards, ShardMap};
use mkit_server::{NamespaceKey, Precondition, RepoId, RepoName};
fn generation(number: u64) -> Generation {
    Generation {
        incarnation: [91; 32],
        number,
    }
}
fn source(name: &str) -> Partition {
    D34Shards.ref_shard(
        &RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new(name).expect("valid source repository"),
        },
        "refs/heads/main",
    )
}
fn store() -> SqlKvStore<RusqliteConn> {
    SqlKvStore::open(RusqliteConn::open_in_memory().expect("open source fixture"))
        .expect("open source store")
}
fn activate(store: &SqlKvStore<RusqliteConn>, part: &Partition) {
    store
        .pause_publication(part, None, generation(1))
        .expect("pause source");
    store
        .activate_source_admission(part, None, generation(1))
        .expect("enroll source");
}
fn aux() -> Key {
    Key::new(b"source-aux\0".to_vec())
}
fn apply(
    store: &SqlKvStore<RusqliteConn>,
    part: &Partition,
    batch: Batch,
) -> Result<BatchOutcome, StoreError> {
    store.apply_admitted_source(part, generation(1), batch, |_, _, _| Ok(()))
}
#[test]
fn source_enrollment_rejects_old_writers_imports_and_extended_effects() {
    block_on(async {
        use mkit_server::store::{ImportMode, Importer, export_header, export_page};
        let store = store();
        let part = source("source");
        store
            .apply(&part, Batch::new().put(aux(), Value::new(vec![1])))
            .await
            .unwrap();
        let header = export_header(&store, &part, 1000).await.unwrap();
        let page = export_page(&store, &part, None, 100).await.unwrap();
        activate(&store, &part);
        assert!(
            store
                .apply(&part, Batch::new().put(aux(), Value::new(vec![2])))
                .await
                .is_err()
        );
        assert!(
            store
                .apply(&part, Batch::new().delete(aux()))
                .await
                .is_err()
        );
        assert!(
            store
                .apply_extended(&part, Batch::new(), |_, batch, _| {
                    batch.writes.push(Write::Delete(aux()));
                    Ok(())
                })
                .is_err()
        );
        let mut importer = Importer::new(&store, &header, ImportMode::Merge).unwrap();
        importer.push(page.records[0].clone()).await.unwrap();
        assert!(importer.finish().await.is_err());
        assert_eq!(
            store.get(&part, &aux()).await.unwrap(),
            Some(Value::new(vec![1]))
        );
        assert_eq!(
            store.apply(&part, Batch::new()).await.unwrap(),
            BatchOutcome::Committed
        );
        assert_eq!(
            store
                .apply(
                    &source("other"),
                    Batch::new().put(aux(), Value::new(vec![4]))
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
    });
}

fn append(prior: u64, next: u64, sequences: &[u64]) -> Batch {
    let mut batch = Batch::new()
        .require(if prior == 0 {
            Precondition::Absent(keys::outbox_sequence())
        } else {
            Precondition::Equals(keys::outbox_sequence(), codec::encode_u64(prior))
        })
        .put(keys::outbox_sequence(), codec::encode_u64(next));
    for sequence in sequences {
        batch = batch.put(
            keys::relay(*sequence),
            codec::encode_relay(&codec::RelayV1 {
                at_ms: 1000,
                target: Partition::Coordinator(NamespaceKey::deployment_default()),
                puts: vec![(aux(), Value::new(vec![7]))],
                deletes: vec![],
            })
            .expect("encode auxiliary relay"),
        );
    }
    batch
}
#[test]
fn admitted_auxiliary_allocations_allow_outcome_gaps_but_never_rewrite_or_delete() {
    block_on(async {
        let store = store();
        let part = source("source");
        activate(&store, &part);
        assert_eq!(
            apply(&store, &part, append(0, 5, &[2, 5])).unwrap(),
            BatchOutcome::Committed
        );
        assert_eq!(
            apply(&store, &part, append(5, 7, &[7])).unwrap(),
            BatchOutcome::Committed
        );
        assert!(matches!(
            apply(&store, &part, append(5, 8, &[8])).unwrap(),
            BatchOutcome::PreconditionFailed { .. }
        ));
        let mut rewrite = append(7, 8, &[2]);
        rewrite.writes.push(Write::Put(aux(), Value::new(vec![9])));
        assert!(apply(&store, &part, rewrite).is_err());
        assert!(apply(&store, &part, Batch::new().delete(keys::relay(2))).is_err());
        assert!(
            apply(
                &store,
                &part,
                Batch::new().put(keys::outbox_sequence(), codec::encode_u64(1))
            )
            .is_err()
        );
        let mut unguarded = append(7, 8, &[8]);
        unguarded.preconditions.clear();
        assert!(apply(&store, &part, unguarded).is_err());
        let mut present = append(7, 8, &[8]);
        present.preconditions[0] = Precondition::Present(keys::outbox_sequence());
        assert!(apply(&store, &part, present).is_err());
        assert!(apply(&store, &part, append(7, 8, &[9])).is_err());
        assert!(apply(&store, &part, append(7, 7, &[])).is_err());
        let mut duplicate = append(7, 8, &[8]);
        duplicate
            .preconditions
            .push(duplicate.preconditions[0].clone());
        assert!(apply(&store, &part, duplicate).is_err());
        assert_eq!(
            store.get(&part, &keys::outbox_sequence()).await.unwrap(),
            Some(codec::encode_u64(7))
        );
        assert!(store.get(&part, &aux()).await.unwrap().is_none());
        assert_eq!(
            apply(&store, &part, append(7, 10, &[])).unwrap(),
            BatchOutcome::Committed,
            "outcomes also consume source sequence numbers"
        );
    });
}
#[test]
fn admitted_source_rechecks_generation_pause_and_original_extension_effects() {
    block_on(async {
        let store = store();
        let part = source("source");
        activate(&store, &part);
        let batch = Batch::new().put(aux(), Value::new(vec![1]));
        assert!(
            store
                .apply_admitted_source(&part, generation(2), batch.clone(), |_, _, _| Ok(()))
                .is_err()
        );
        assert!(
            store
                .apply_admitted_source(&part, generation(1), batch.clone(), |_, batch, _| {
                    batch.writes.clear();
                    Ok(())
                })
                .is_err()
        );
        assert!(
            store
                .apply_admitted_source(&part, generation(1), batch.clone(), |_, batch, _| {
                    batch.writes.push(Write::Delete(aux()));
                    Ok(())
                })
                .is_err()
        );
        let guarded = batch.clone().require(Precondition::Absent(aux()));
        assert!(
            store
                .apply_admitted_source(&part, generation(1), guarded, |_, batch, _| {
                    batch.preconditions.clear();
                    Ok(())
                })
                .is_err()
        );
        store.pause_publication(&part, None, generation(2)).unwrap();
        assert!(apply(&store, &part, batch.clone()).is_err());
        assert!(
            store
                .activate_source_admission(&part, None, generation(2))
                .is_err()
        );
        store
            .activate_source_admission(&part, Some(generation(1)), generation(2))
            .unwrap();
        assert!(apply(&store, &part, batch.clone()).is_err());
        assert_eq!(
            store
                .apply_admitted_source(&part, generation(2), batch, |_, batch, _| {
                    batch
                        .writes
                        .push(Write::Put(keys::timer(1000, 1, b""), Value::default()));
                    Ok(())
                })
                .unwrap(),
            BatchOutcome::Committed
        );
        let reopened = SqlKvStore::open_existing(store.conn().clone()).unwrap();
        assert!(
            reopened
                .apply(&part, Batch::new().delete(aux()))
                .await
                .is_err()
        );
        assert_eq!(
            reopened.get(&part, &aux()).await.unwrap(),
            Some(Value::new(vec![1]))
        );
    });
}
#[test]
fn source_admission_private_guard_limits_and_late_extensions_roll_back() {
    block_on(async {
        let store = store();
        let part = source("source");
        activate(&store, &part);
        let mut batch = Batch::new();
        for index in 0..mkit_server::store::MAX_BATCH_OPS {
            batch = batch.put(Key::new(index.to_be_bytes().to_vec()), Value::new(vec![1]));
        }
        assert!(
            apply(&store, &part, batch).is_err(),
            "private generation guard consumes the same operation allowance"
        );
        let batch = Batch::new().put(aux(), Value::new(vec![1]));
        assert!(
            store
                .apply_admitted_source(&part, generation(1), batch, |_, batch, _| {
                    for index in 0..mkit_server::store::MAX_BATCH_OPS {
                        batch.writes.push(Write::Put(
                            Key::new(index.to_be_bytes().to_vec()),
                            Value::new(vec![1]),
                        ));
                    }
                    Ok(())
                })
                .is_err()
        );
        assert!(store.get(&part, &aux()).await.unwrap().is_none());
    });
}

#[test]
fn enrolled_source_accepts_exact_publication_commit_but_keeps_marker_guards() {
    block_on(async {
        use mkit_server::store::adapter_spi::{
            publication_fence::{PublicationFence, VerifiedRelay},
            publication_fence_plan::publication_batch,
        };
        let store = store();
        let repository = RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new("source").unwrap(),
        };
        let source = source("source");
        let name = "refs/heads/main";
        let target = D34Shards.ref_index(&repository, name);
        let value = codec::encode_ref_id(&[1; 32]);
        let row = codec::encode_relay(&codec::RelayV1 {
            at_ms: 1000,
            target: target.clone(),
            puts: vec![(keys::published_index(&repository.name, name), value.clone())],
            deletes: vec![],
        })
        .unwrap();
        let mut batch = Batch::new()
            .require(Precondition::Absent(keys::outbox_sequence()))
            .put(keys::outbox_sequence(), codec::encode_u64(1))
            .put(keys::published_ref(&repository.name, name), value)
            .put(keys::relay(1), row);
        let plan = publication_batch(&source, &batch).unwrap().unwrap();
        let fence = PublicationFence::new(&repository);
        fence.initialize(&store, generation(1)).await.unwrap();
        let intent = fence
            .begin(
                &store,
                &source,
                1,
                plan.digest,
                plan.fence_targets().unwrap(),
            )
            .await
            .unwrap();
        fence.arm(&store, &intent).await.unwrap();
        activate(&store, &source);
        PublicationFence::source_commit_fragment(&intent, &mut batch).unwrap();
        assert_eq!(
            apply(&store, &source, batch).unwrap(),
            BatchOutcome::Committed
        );
        assert!(
            VerifiedRelay::verify(&store, &intent, &target, 1)
                .await
                .is_ok()
        );
        assert!(
            apply(
                &store,
                &source,
                Batch::new().put(
                    keys::published_ref(&repository.name, name),
                    codec::encode_ref_id(&[2; 32])
                )
            )
            .is_err()
        );
    });
}
#[test]
fn source_metadata_capacity_refusal_precedes_create_and_exact_retry_is_no_write() {
    block_on(async {
        use super::super::Capacity;
        for existing_table in [false, true] {
            let conn = RusqliteConn::open_in_memory().unwrap();
            let store = SqlKvStore::open_with_capacity(
                conn.clone(),
                Capacity::new(1 << 20).with_reserve(1 << 19),
            )
            .unwrap();
            let enrolled = source("enrolled");
            if existing_table {
                activate(&store, &enrolled);
            }
            let waiting = source("waiting");
            store
                .pause_publication(&waiting, None, generation(1))
                .unwrap();
            let writable = Partition::Namespace(NamespaceKey::deployment_default());
            let mut full = false;
            for index in 0u32..128 {
                match store
                    .apply(
                        &writable,
                        Batch::new().put(
                            Key::new(index.to_be_bytes().to_vec()),
                            Value::new(vec![1; 16 * 1024]),
                        ),
                    )
                    .await
                {
                    Ok(BatchOutcome::Committed) => {}
                    Err(StoreError::Full) => {
                        full = true;
                        break;
                    }
                    other => panic!("unexpected fill result: {other:?}"),
                }
            }
            assert!(full);
            let before = conn.size_bytes().unwrap();
            assert!(matches!(
                store.activate_source_admission(&waiting, None, generation(1)),
                Err(StoreError::Full)
            ));
            assert_eq!(read(&conn, &source_part(&waiting).unwrap()).unwrap(), None);
            if existing_table {
                store
                    .activate_source_admission(&enrolled, None, generation(1))
                    .unwrap();
            } else {
                assert!(
                    conn.query(PRESENT, &[]).unwrap().is_empty(),
                    "soft-cap refusal must precede lazy table CREATE"
                );
            }
            assert_eq!(conn.size_bytes().unwrap(), before);
            assert!(store.publication_paused(&waiting).unwrap());
        }
    });
}

#[test]
fn source_private_byte_guard_and_preexisting_above_counter_row_fail_closed() {
    block_on(async {
        use mkit_server::store::{MAX_BATCH_BYTES, MAX_VALUE_BYTES};
        let store = store();
        let part = source("source");
        let orphan = append(0, 8, &[8]).writes.pop().unwrap();
        store
            .apply(
                &part,
                Batch {
                    preconditions: vec![],
                    writes: vec![orphan],
                },
            )
            .await
            .unwrap();
        activate(&store, &part);
        assert!(
            apply(&store, &part, append(0, 8, &[8])).is_err(),
            "an existing legacy row above os cannot be rewritten"
        );
        let key_a = Key::new(vec![b'a']);
        let key_b = Key::new(vec![b'b']);
        let exact = Batch::new()
            .put(key_a.clone(), Value::new(vec![1; MAX_VALUE_BYTES]))
            .put(
                key_b.clone(),
                Value::new(vec![2; MAX_BATCH_BYTES - MAX_VALUE_BYTES - 2]),
            );
        assert!(exact.validate(&StoreCapabilities::full()).is_ok());
        assert!(
            apply(&store, &part, exact).is_err(),
            "private generation equality must fit the byte allowance too"
        );
        assert!(store.get(&part, &key_a).await.unwrap().is_none());
        let private = part.encode().unwrap().len()
            + publication_maintenance::encoded_generation(&generation(1))
                .unwrap()
                .len();
        let fitting = Batch::new()
            .put(key_a.clone(), Value::new(vec![1; MAX_VALUE_BYTES]))
            .put(
                key_b,
                Value::new(vec![2; MAX_BATCH_BYTES - MAX_VALUE_BYTES - 2 - private]),
            );
        assert_eq!(
            apply(&store, &part, fitting).unwrap(),
            BatchOutcome::Committed
        );
    });
}
#[test]
fn source_metadata_codec_and_repository_scope_are_fail_closed() {
    block_on(async {
        let store = store();
        let part = source("source");
        activate(&store, &part);
        let row = source_part(&part).unwrap();
        let mut raw = publication_maintenance::encoded_generation(&generation(1)).unwrap();
        raw.push(b' ');
        store
            .conn()
            .exec(PUT, &[row.clone(), SqlValue::Blob(raw)])
            .unwrap();
        assert!(apply(&store, &part, Batch::new().put(aux(), Value::new(vec![1]))).is_err());
        store
            .conn()
            .exec(PUT, &[row, SqlValue::Blob(vec![1; 513])])
            .unwrap();
        assert!(
            store
                .apply(&part, Batch::new().delete(aux()))
                .await
                .is_err()
        );
        assert!(
            store
                .activate_source_admission(
                    &Partition::Coordinator(NamespaceKey::deployment_default()),
                    None,
                    generation(1)
                )
                .is_err()
        );
        assert!(store.get(&part, &aux()).await.unwrap().is_none());
    });
}

async fn foreign_publication(store: &SqlKvStore<RusqliteConn>) -> (Value, Batch) {
    use mkit_server::store::adapter_spi::{
        publication_fence::PublicationFence, publication_fence_plan::publication_batch,
    };
    let repository = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("source").expect("valid foreign fixture repository"),
    };
    let part = source("source");
    let name = "refs/heads/main";
    let value = codec::encode_ref_id(&[1; 32]);
    let row = codec::encode_relay(&codec::RelayV1 {
        at_ms: 1000,
        target: D34Shards.ref_index(&repository, name),
        puts: vec![(keys::published_index(&repository.name, name), value.clone())],
        deletes: vec![],
    })
    .expect("valid foreign fixture relay");
    let mut batch = Batch::new()
        .require(Precondition::Absent(keys::outbox_sequence()))
        .put(keys::outbox_sequence(), codec::encode_u64(1))
        .put(keys::published_ref(&repository.name, name), value)
        .put(keys::relay(1), row);
    let plan = publication_batch(&part, &batch)
        .expect("foreign fixture plan")
        .expect("foreign fixture publication");
    let fence = PublicationFence::new(&repository);
    fence
        .initialize(store, generation(2))
        .await
        .expect("initialize foreign generation");
    let intent = fence
        .begin(
            store,
            &part,
            1,
            plan.digest,
            plan.fence_targets().expect("foreign fixture targets"),
        )
        .await
        .expect("begin foreign intent");
    fence.arm(store, &intent).await.expect("arm foreign intent");
    let armed = store
        .get(&part, &Key::new(b"pc\0".to_vec()))
        .await
        .expect("read foreign marker")
        .expect("foreign marker retained");
    PublicationFence::source_commit_fragment(&intent, &mut batch).expect("bind foreign commit");
    (armed, batch)
}
#[test]
fn source_generation_rejects_new_foreign_armed_marker() {
    block_on(async {
        let donor = store();
        let (armed, _) = foreign_publication(&donor).await;
        let local = store();
        let part = source("source");
        activate(&local, &part);
        let marker = Key::new(b"pc\0".to_vec());
        let batch = Batch::new()
            .require(Precondition::Absent(marker.clone()))
            .put(marker.clone(), armed);
        assert!(
            apply(&local, &part, batch).is_err(),
            "admitted generation1 cannot arm an intent from generation2"
        );
        assert!(local.get(&part, &marker).await.unwrap().is_none());
    });
}
#[test]
fn source_generation_rejects_new_foreign_committed_marker() {
    block_on(async {
        let store = store();
        let (_, batch) = foreign_publication(&store).await;
        let part = source("source");
        activate(&store, &part);
        assert!(
            apply(&store, &part, batch).is_err(),
            "a valid old-generation armed-to-committed transition cannot borrow current admission"
        );
        assert!(
            store
                .get(&part, &keys::outbox_sequence())
                .await
                .unwrap()
                .is_none()
        );
    });
}
#[test]
fn source_generation_rejects_auxiliary_writes_under_stored_foreign_marker() {
    block_on(async {
        for committed in [false, true] {
            let store = store();
            let (_, batch) = foreign_publication(&store).await;
            let part = source("source");
            if committed {
                assert_eq!(
                    store.apply(&part, batch).await.unwrap(),
                    BatchOutcome::Committed
                );
            }
            activate(&store, &part);
            assert!(
                apply(&store, &part, Batch::new().put(aux(), Value::new(vec![8]))).is_err(),
                "stored foreign marker must fence auxiliary writes even without pc effects"
            );
            assert!(store.get(&part, &aux()).await.unwrap().is_none());
        }
    });
}
