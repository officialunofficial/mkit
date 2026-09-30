#![allow(clippy::unwrap_used)]
mod common;

use bytes::Bytes;
use futures::executor::block_on;
use mkit_core::hash::hash;
use mkit_core::upload_parts::{MIN_PART_SIZE, PartPlan, part_subtree_cv};
use mkit_server::{BlobKey, BlobStore, PartRef, PartSink};
use mkit_server_worker::r2::R2BlobStore;

#[test]
fn object_backend_completion_uses_pinned_verified_parts_without_rereads() {
    block_on(async {
        let bucket = common::SimBucket::default();
        let store = R2BlobStore::new(bucket.clone(), "packs");
        let bytes = vec![7; MIN_PART_SIZE as usize + 10];
        let plan = PartPlan::new(bytes.len() as u64, MIN_PART_SIZE, 10_000).unwrap();
        let cvs: Vec<_> = (0..plan.count())
            .map(|index| {
                let start = plan.offset(index).unwrap() as usize;
                let end = start + plan.expected_len(index).unwrap() as usize;
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
            let start = plan.offset(index).unwrap() as usize;
            let len = plan.expected_len(index).unwrap();
            for piece in bytes[start..start + len as usize].chunks(256 * 1024) {
                sink.write(Bytes::copy_from_slice(piece)).await.unwrap();
            }
            receipts.push(PartRef {
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
    use mkit_server::PackSink;
    block_on(async {
        let store = R2BlobStore::new(common::SimBucket::default(), "tenant/packs");
        let key = BlobKey::object([11; 32]);
        let bytes = vec![5; MIN_PART_SIZE as usize + 1];
        let plan = PartPlan::new(bytes.len() as u64, MIN_PART_SIZE, 10_000).unwrap();
        let cvs: Vec<_> = (0..plan.count())
            .map(|i| {
                let start = plan.offset(i).unwrap() as usize;
                part_subtree_cv(
                    &plan,
                    i,
                    &bytes[start..start + plan.expected_len(i).unwrap() as usize],
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
    Vec<PartRef>,
    Vec<u8>,
    Vec<[u8; 32]>,
) {
    let bucket = common::SimBucket::default();
    let store = R2BlobStore::new(bucket.clone(), "packs");
    let bytes = vec![13; MIN_PART_SIZE as usize + 10];
    let plan = PartPlan::new(bytes.len() as u64, MIN_PART_SIZE, 10_000).unwrap();
    let cvs: Vec<_> = (0..plan.count())
        .map(|i| {
            let start = plan.offset(i).unwrap() as usize;
            part_subtree_cv(
                &plan,
                i,
                &bytes[start..start + plan.expected_len(i).unwrap() as usize],
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
        let start = plan.offset(i).unwrap() as usize;
        let len = plan.expected_len(i).unwrap();
        for piece in bytes[start..start + len as usize].chunks(256 * 1024) {
            sink.write(Bytes::copy_from_slice(piece)).await.unwrap();
        }
        parts.push(PartRef {
            index: i,
            len,
            tag: sink.commit().await.unwrap(),
        });
    }
    (store, bucket, key, plan, session, parts, bytes, cvs)
}

#[test]
fn forged_receipts_geometry_context_and_root_cannot_publish() {
    block_on(async {
        let (store, bucket, key, plan, session, parts, bytes, cvs) = prepared().await;
        let root = hash(&bytes);
        let clone_parts = || {
            parts
                .iter()
                .map(|p| PartRef {
                    index: p.index,
                    len: p.len,
                    tag: p.tag.clone(),
                })
                .collect::<Vec<_>>()
        };
        for mutation in 0..6 {
            let mut forged = clone_parts();
            match mutation {
                0 => forged[0].tag[1] ^= 1,
                1 => forged[0].tag[33] ^= 1,
                2 => forged[0].len += 1,
                3 => forged.swap(0, 1),
                4 => forged[1].index = 0,
                _ => {
                    forged.pop();
                }
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
            .write(Bytes::copy_from_slice(&bytes[MIN_PART_SIZE as usize..]))
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
    block_on(async {
        for count in [2, 5] {
            let bucket = common::SimBucket::default();
            let store = R2BlobStore::new(bucket.clone(), "packs");
            let bytes = vec![17; MIN_PART_SIZE as usize * (count - 1) + 1];
            let plan = PartPlan::new(bytes.len() as u64, MIN_PART_SIZE, 10_000).unwrap();
            let cvs: Vec<_> = (0..plan.count())
                .map(|i| {
                    let start = plan.offset(i).unwrap() as usize;
                    part_subtree_cv(
                        &plan,
                        i,
                        &bytes[start..start + plan.expected_len(i).unwrap() as usize],
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
                let start = plan.offset(i).unwrap() as usize;
                let len = plan.expected_len(i).unwrap();
                for chunk in bytes[start..start + len as usize].chunks(256 * 1024) {
                    sink.write(Bytes::copy_from_slice(chunk)).await.unwrap();
                }
                parts.push(PartRef {
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
                5
            );
            assert!(peak < 1 << 20, "finalization peak {peak} for {count} parts");
        }
    });
}
