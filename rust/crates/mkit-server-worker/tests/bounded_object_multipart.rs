#![allow(clippy::unwrap_used)]
mod common;
use mkit_server_worker::r2::VerifiedObjectPartRef;

// The heap probe is process-wide: exclude unrelated concurrent test payloads.
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

use bytes::Bytes;
use futures::executor::block_on;
use mkit_core::hash::hash;
use mkit_core::upload_parts::{MIN_PART_SIZE, PartPlan, part_subtree_cv};
use mkit_server::{BlobKey, BlobStore, PackSink, PartSink};
use mkit_server_worker::r2::R2BlobStore;

#[test]
#[allow(clippy::too_many_lines)] // Upload lifetime matrix shares one root-pinned fixture.
fn extraction_callbacks_check_cvs_replacement_abort_and_cold_restart() {
    use mkit_server::PartRef;
    use mkit_server::indexed::budget::SliceBudget;
    use mkit_server::indexed::job::{FailClosedExtraction, SliceExtension};
    use mkit_server_worker::verify::R2Extraction;
    let _isolation = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    block_on(async {
        let bucket = common::SimBucket::default();
        let store = R2BlobStore::new(bucket.clone(), "packs");
        let extension = R2Extraction(store.clone());
        let part_size = usize::try_from(MIN_PART_SIZE).unwrap();
        let bytes = vec![17; part_size + 10];
        let plan = PartPlan::new(bytes.len() as u64, MIN_PART_SIZE, 10_000).unwrap();
        let cvs: Vec<_> = (0..plan.count())
            .map(|index| {
                let start = usize::try_from(plan.offset(index).unwrap()).unwrap();
                part_subtree_cv(
                    &plan,
                    index,
                    &bytes[start
                        ..start + usize::try_from(plan.expected_len(index).unwrap()).unwrap()],
                )
                .unwrap()
            })
            .collect();
        let root = hash(&bytes);
        let key = BlobKey::object([81; 32]);
        let budget = SliceBudget::new(256);
        assert!(!FailClosedExtraction.extraction_enabled());
        assert!(
            FailClosedExtraction
                .begin_object(key, &plan, root, &cvs, [82; 32], &budget)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(budget.used(), 0, "default callbacks perform no IO");
        let mut invalid_cvs = cvs.clone();
        invalid_cvs[0][0] ^= 1;
        assert!(
            extension
                .begin_object(key, &plan, root, &invalid_cvs, [82; 32], &budget)
                .await
                .is_err()
        );
        assert!(store.head(&key).await.unwrap().is_none());
        let session = extension
            .begin_object(key, &plan, root, &cvs, [82; 32], &budget)
            .await
            .unwrap()
            .unwrap();
        let first = extension
            .put_object_part(
                key,
                &session,
                &plan,
                0,
                cvs[0],
                bytes[..part_size].to_vec(),
                &budget,
            )
            .await
            .unwrap()
            .unwrap();
        let mut replacement = bytes[..part_size].to_vec();
        replacement[0] ^= 1;
        assert!(
            extension
                .put_object_part(key, &session, &plan, 0, cvs[0], replacement, &budget)
                .await
                .is_err()
        );
        assert!(
            store.head(&key).await.unwrap().is_none(),
            "a mismatching replacement stays private"
        );
        // A fresh adapter resumes the same durable root-bound upload rather
        // than keeping a session or a payload alive across alarm fires.
        let restarted = R2Extraction(R2BlobStore::new(bucket.clone(), "packs"));
        assert_eq!(
            restarted
                .begin_object(key, &plan, root, &cvs, [82; 32], &budget)
                .await
                .unwrap()
                .unwrap(),
            session
        );
        let last = restarted
            .put_object_part(
                key,
                &session,
                &plan,
                1,
                cvs[1],
                bytes[part_size..].to_vec(),
                &budget,
            )
            .await
            .unwrap()
            .unwrap();
        let receipts = vec![
            PartRef {
                index: 0,
                len: MIN_PART_SIZE,
                tag: first,
            },
            PartRef {
                index: 1,
                len: 10,
                tag: last,
            },
        ];
        assert!(
            restarted
                .complete_object(key, &session, &plan, receipts.clone(), [0; 32], &budget)
                .await
                .is_err()
        );
        assert!(store.head(&key).await.unwrap().is_none());
        restarted
            .complete_object(key, &session, &plan, receipts, root, &budget)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            store.head(&key).await.unwrap().unwrap().len,
            bytes.len() as u64
        );
        let abandoned = BlobKey::object([83; 32]);
        let aborted = restarted
            .begin_object(abandoned, &plan, root, &cvs, [84; 32], &budget)
            .await
            .unwrap()
            .unwrap();
        restarted
            .abort_object(abandoned, &aborted, &plan, &budget)
            .await
            .unwrap();
        assert!(
            restarted
                .put_object_part(
                    abandoned,
                    &aborted,
                    &plan,
                    0,
                    cvs[0],
                    bytes[..part_size].to_vec(),
                    &budget
                )
                .await
                .is_err()
        );
        assert!(store.head(&abandoned).await.unwrap().is_none());
        assert!(budget.used() <= 256);
    });
}

#[test]
fn object_backend_completion_uses_pinned_verified_parts_without_rereads() {
    let _isolation = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    block_on(async {
        let bucket = common::SimBucket::default();
        let store = R2BlobStore::new(bucket.clone(), "packs");
        let bytes = vec![7; usize::try_from(MIN_PART_SIZE).unwrap() + 10];
        let plan = PartPlan::new(bytes.len() as u64, MIN_PART_SIZE, 10_000).unwrap();
        let cvs: Vec<_> = (0..plan.count())
            .map(|index| {
                let start = usize::try_from(plan.offset(index).unwrap()).unwrap();
                let end = start + usize::try_from(plan.expected_len(index).unwrap()).unwrap();
                part_subtree_cv(&plan, index, &bytes[start..end]).unwrap()
            })
            .collect();
        let key = BlobKey::object([9; 32]);
        let session = store
            .begin_verified_object(key, &plan, hash(&bytes), &cvs, [3; 32])
            .await
            .unwrap();
        let mut receipts = Vec::new();
        for index in 0..plan.count() {
            let mut sink = store
                .begin_verified_object_part(key, &session, &plan, index, cvs[index as usize])
                .await
                .unwrap();
            let start = usize::try_from(plan.offset(index).unwrap()).unwrap();
            let len = plan.expected_len(index).unwrap();
            for piece in bytes[start..start + usize::try_from(len).unwrap()].chunks(256 * 1024) {
                sink.write(Bytes::copy_from_slice(piece)).await.unwrap();
            }
            receipts.push(VerifiedObjectPartRef {
                index,
                len,
                tag: sink.commit().await.unwrap(),
            });
        }
        assert!(store.head(&key).await.unwrap().is_none());
        let before = bucket
            .metadata_reads
            .load(std::sync::atomic::Ordering::SeqCst);
        store
            .complete_verified_object(key, &session, &plan, &receipts, hash(&bytes))
            .await
            .unwrap();
        assert_eq!(
            bucket
                .metadata_reads
                .load(std::sync::atomic::Ordering::SeqCst)
                - before,
            2
        );
        assert_eq!(
            bucket
                .backend_completions
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            store.head(&key).await.unwrap().unwrap().len,
            bytes.len() as u64
        );
    });
}

#[test]
fn root_binding_covers_legacy_single_put_and_forged_plans() {
    let _isolation = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    block_on(async {
        let store = R2BlobStore::new(common::SimBucket::default(), "tenant/packs");
        let key = BlobKey::object([11; 32]);
        let bytes = vec![5; usize::try_from(MIN_PART_SIZE).unwrap() + 1];
        let plan = PartPlan::new(bytes.len() as u64, MIN_PART_SIZE, 10_000).unwrap();
        let cvs: Vec<_> = (0..plan.count())
            .map(|i| {
                let start = usize::try_from(plan.offset(i).unwrap()).unwrap();
                part_subtree_cv(
                    &plan,
                    i,
                    &bytes[start..start + usize::try_from(plan.expected_len(i).unwrap()).unwrap()],
                )
                .unwrap()
            })
            .collect();
        assert!(
            store
                .begin_verified_object(key, &plan, [0; 32], &cvs, [1; 32])
                .await
                .is_err()
        );
        // A bad plan must not reserve the object root or prevent a valid plan.
        let session = store
            .begin_verified_object(key, &plan, hash(&bytes), &cvs, [1; 32])
            .await
            .unwrap();
        assert!(
            store
                .begin_verified_object_part(key, &session, &plan, 0, [4; 32])
                .await
                .is_err()
        );
        let mut wrong = store.begin(key, 3).await.unwrap();
        wrong.write(Bytes::from_static(b"bad")).await.unwrap();
        assert!(wrong.commit_with_root(hash(b"bad")).await.is_err());
        assert!(store.head(&key).await.unwrap().is_none());
        store
            .abort_verified_object(key, &session, &plan)
            .await
            .unwrap();
        store
            .abort_verified_object(key, &session, &plan)
            .await
            .unwrap();
        let mut stale = store
            .begin_verified_object_part(key, &session, &plan, 1, cvs[1])
            .await
            .unwrap();
        stale.write(Bytes::from_static(&[5])).await.unwrap();
        assert!(stale.commit().await.is_err());
        assert!(store.head(&key).await.unwrap().is_none());
    });
}

async fn prepared() -> (
    R2BlobStore<common::SimBucket>,
    common::SimBucket,
    BlobKey,
    PartPlan,
    Vec<u8>,
    Vec<VerifiedObjectPartRef>,
    Vec<u8>,
    Vec<[u8; 32]>,
) {
    let bucket = common::SimBucket::default();
    let store = R2BlobStore::new(bucket.clone(), "packs");
    let bytes = vec![13; usize::try_from(MIN_PART_SIZE).unwrap() + 10];
    let plan = PartPlan::new(bytes.len() as u64, MIN_PART_SIZE, 10_000).unwrap();
    let cvs: Vec<_> = (0..plan.count())
        .map(|i| {
            let start = usize::try_from(plan.offset(i).unwrap()).unwrap();
            part_subtree_cv(
                &plan,
                i,
                &bytes[start..start + usize::try_from(plan.expected_len(i).unwrap()).unwrap()],
            )
            .unwrap()
        })
        .collect();
    let key = BlobKey::object([6; 32]);
    let session = store
        .begin_verified_object(key, &plan, hash(&bytes), &cvs, [8; 32])
        .await
        .unwrap();
    let mut parts = Vec::new();
    for i in 0..plan.count() {
        let mut sink = store
            .begin_verified_object_part(key, &session, &plan, i, cvs[i as usize])
            .await
            .unwrap();
        let start = usize::try_from(plan.offset(i).unwrap()).unwrap();
        let len = plan.expected_len(i).unwrap();
        for piece in bytes[start..start + usize::try_from(len).unwrap()].chunks(256 * 1024) {
            sink.write(Bytes::copy_from_slice(piece)).await.unwrap();
        }
        parts.push(VerifiedObjectPartRef {
            index: i,
            len,
            tag: sink.commit().await.unwrap(),
        });
    }
    (store, bucket, key, plan, session, parts, bytes, cvs)
}

#[test]
fn forged_receipts_geometry_context_and_root_cannot_publish() {
    let _isolation = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    block_on(async {
        let (store, bucket, key, plan, session, parts, bytes, cvs) = prepared().await;
        let root = hash(&bytes);
        let clone_parts = || {
            parts
                .iter()
                .map(|p| VerifiedObjectPartRef {
                    index: p.index,
                    len: p.len,
                    tag: p.tag.clone(),
                })
                .collect::<Vec<_>>()
        };
        for mutation in 0..9 {
            let mut forged = clone_parts();
            match mutation {
                0 => forged[0].tag[1] ^= 1,
                1 => forged[0].tag[33] ^= 1,
                2 => forged[0].len += 1,
                3 => forged.swap(0, 1),
                4 => forged[1].index = 0,
                5 => {
                    forged.pop();
                }
                6 => forged[0].tag[0] = 2,
                7 => forged[0].tag.resize(1090, b'x'),
                _ => forged[0].tag[65] = 255,
            }
            assert!(
                store
                    .complete_verified_object(key, &session, &plan, &forged, root)
                    .await
                    .is_err()
            );
        }
        assert!(
            store
                .complete_verified_object(key, &session, &plan, &parts, [0; 32])
                .await
                .is_err()
        );
        assert!(
            store
                .complete_verified_object(BlobKey::object([99; 32]), &session, &plan, &parts, root)
                .await
                .is_err()
        );
        assert!(
            store
                .complete_verified_object(key, &[99; 32], &plan, &parts, root)
                .await
                .is_err()
        );
        assert_eq!(
            bucket
                .backend_completions
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert!(store.head(&key).await.unwrap().is_none());
        // Replacing a part changes its receipt, but the only accepted payload
        // still has the pinned CV. The stale selected ETag fails closed.
        let mut replacement = store
            .begin_verified_object_part(key, &session, &plan, 1, cvs[1])
            .await
            .unwrap();
        replacement
            .write(Bytes::copy_from_slice(
                &bytes[usize::try_from(MIN_PART_SIZE).unwrap()..],
            ))
            .await
            .unwrap();
        let new_tag = replacement.commit().await.unwrap();
        assert!(
            store
                .complete_verified_object(key, &session, &plan, &parts, root)
                .await
                .is_err()
        );
        assert!(store.head(&key).await.unwrap().is_none());
        let mut fresh = clone_parts();
        fresh[1].tag = new_tag;
        store
            .complete_verified_object(key, &session, &plan, &fresh, root)
            .await
            .unwrap();
        // Duplicate completion and restart use only immutable metadata/root
        // and the already-completed verified final object.
        store
            .complete_verified_object(key, &session, &plan, &fresh, root)
            .await
            .unwrap();
        assert_eq!(
            store
                .begin_verified_object(key, &plan, root, &cvs, [8; 32])
                .await
                .unwrap(),
            session
        );
    });
}

#[test]
fn wrong_actual_part_bytes_never_create_a_trusted_receipt() {
    let _isolation = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    block_on(async {
        let (store, _, key, plan, session, _, _, cvs) = prepared().await;
        let mut sink = store
            .begin_verified_object_part(key, &session, &plan, 1, cvs[1])
            .await
            .unwrap();
        sink.write(Bytes::from(vec![42; 10])).await.unwrap();
        assert!(sink.commit().await.is_err());
        assert!(store.head(&key).await.unwrap().is_none());
    });
}

#[test]
fn completion_after_a_lost_backend_reply_recovers_only_verified_identity() {
    let _isolation = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    block_on(async {
        let (store, bucket, key, plan, session, parts, bytes, _) = prepared().await;
        bucket
            .lose_completion_reply
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            store
                .complete_verified_object(key, &session, &plan, &parts, hash(&bytes))
                .await
                .unwrap(),
            mkit_server::CommitOutcome::AlreadyPresent
        );
        assert_eq!(
            store.head(&key).await.unwrap().unwrap().len,
            bytes.len() as u64
        );
    });
}

#[test]
fn bounded_object_finalization_calls_and_heap_do_not_scale_with_payload() {
    let _isolation = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    block_on(async {
        for count in [2, 5] {
            let bucket = common::SimBucket::default();
            let store = R2BlobStore::new(bucket.clone(), "packs");
            let bytes = vec![17; usize::try_from(MIN_PART_SIZE).unwrap() * (count - 1) + 1];
            let plan = PartPlan::new(bytes.len() as u64, MIN_PART_SIZE, 10_000).unwrap();
            let cvs: Vec<_> = (0..plan.count())
                .map(|i| {
                    let start = usize::try_from(plan.offset(i).unwrap()).unwrap();
                    part_subtree_cv(
                        &plan,
                        i,
                        &bytes[start
                            ..start + usize::try_from(plan.expected_len(i).unwrap()).unwrap()],
                    )
                    .unwrap()
                })
                .collect();
            let key = BlobKey::object([2; 32]);
            let session = store
                .begin_verified_object(key, &plan, hash(&bytes), &cvs, [9; 32])
                .await
                .unwrap();
            let mut parts = Vec::new();
            for i in 0..plan.count() {
                let mut sink = store
                    .begin_verified_object_part(key, &session, &plan, i, cvs[i as usize])
                    .await
                    .unwrap();
                let start = usize::try_from(plan.offset(i).unwrap()).unwrap();
                let len = plan.expected_len(i).unwrap();
                for chunk in bytes[start..start + usize::try_from(len).unwrap()].chunks(256 * 1024)
                {
                    sink.write(Bytes::copy_from_slice(chunk)).await.unwrap();
                }
                parts.push(VerifiedObjectPartRef {
                    index: i,
                    len,
                    tag: sink.commit().await.unwrap(),
                });
            }
            let before = bucket.operations.load(std::sync::atomic::Ordering::SeqCst);
            let probe = common::multipart_allocator::probe();
            (probe.start)();
            let result = store
                .complete_verified_object(key, &session, &plan, &parts, hash(&bytes))
                .await;
            let peak = (probe.finish)();
            result.unwrap();
            assert_eq!(
                bucket.operations.load(std::sync::atomic::Ordering::SeqCst) - before,
                4
            );
            assert!(peak < 1 << 20, "finalization peak {peak} for {count} parts");
        }
    });
}

#[test]
fn concurrent_session_and_completion_races_preserve_root_binding() {
    let _isolation = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    block_on(async {
        let (store, _, key, plan, session, parts, bytes, cvs) = prepared().await;
        let root = hash(&bytes);
        let (left, right) = futures::join!(
            store.begin_verified_object(key, &plan, root, &cvs, [77; 32]),
            store.begin_verified_object(key, &plan, root, &cvs, [77; 32])
        );
        assert_eq!(left.unwrap(), right.unwrap());
        let wrong = vec![14; bytes.len()];
        let wrong_cvs: Vec<_> = (0..plan.count())
            .map(|i| {
                let start = usize::try_from(plan.offset(i).unwrap()).unwrap();
                part_subtree_cv(
                    &plan,
                    i,
                    &wrong[start..start + usize::try_from(plan.expected_len(i).unwrap()).unwrap()],
                )
                .unwrap()
            })
            .collect();
        assert!(
            store
                .begin_verified_object(key, &plan, hash(&wrong), &wrong_cvs, [78; 32])
                .await
                .is_err()
        );
        assert!(store.head(&key).await.unwrap().is_none());
        let (left, right) = futures::join!(
            store.complete_verified_object(key, &session, &plan, &parts, root),
            store.complete_verified_object(key, &session, &plan, &parts, root)
        );
        left.unwrap();
        right.unwrap();
    });
}

#[test]
fn short_and_cancelled_private_parts_cannot_publish() {
    let _isolation = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    block_on(async {
        let (store, bucket, key, plan, session, _, _, cvs) = prepared().await;
        let mut short = store
            .begin_verified_object_part(key, &session, &plan, 0, cvs[0])
            .await
            .unwrap();
        short.write(Bytes::from_static(b"short")).await.unwrap();
        assert!(short.commit().await.is_err());
        let mut cancelled = store
            .begin_verified_object_part(key, &session, &plan, 0, cvs[0])
            .await
            .unwrap();
        cancelled.write(Bytes::from_static(b"short")).await.unwrap();
        cancelled.abort().await;
        assert!(store.head(&key).await.unwrap().is_none());
        assert_eq!(
            bucket
                .backend_completions
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    });
}

#[test]
fn competing_first_roots_select_one_immutable_identity() {
    let _isolation = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    block_on(async {
        let store = R2BlobStore::new(common::SimBucket::default(), "packs");
        let key = BlobKey::object([90; 32]);
        let a_bytes = vec![1; usize::try_from(MIN_PART_SIZE).unwrap() + 1];
        let b_bytes = vec![2; a_bytes.len()];
        let plan = PartPlan::new(a_bytes.len() as u64, MIN_PART_SIZE, 10_000).unwrap();
        let cvs = |bytes: &[u8]| {
            (0..plan.count())
                .map(|i| {
                    let start = usize::try_from(plan.offset(i).unwrap()).unwrap();
                    part_subtree_cv(
                        &plan,
                        i,
                        &bytes[start
                            ..start + usize::try_from(plan.expected_len(i).unwrap()).unwrap()],
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>()
        };
        let a = cvs(&a_bytes);
        let b = cvs(&b_bytes);
        let (left, right) = futures::join!(
            store.begin_verified_object(key, &plan, hash(&a_bytes), &a, [91; 32]),
            store.begin_verified_object(key, &plan, hash(&b_bytes), &b, [92; 32])
        );
        assert_ne!(left.is_ok(), right.is_ok());
        assert!(store.head(&key).await.unwrap().is_none());
    });
}
