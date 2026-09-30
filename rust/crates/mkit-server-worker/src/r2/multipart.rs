//! Verified, CV-keyed R2 multipart staging.

use bytes::Bytes;
use futures::StreamExt as _;
use mkit_core::hash::{Hash, to_hex_bytes};
use mkit_core::upload_parts::{PartPlan, merge_to_root};
use mkit_server::storage_error::StorageOp;
use mkit_server::{
    BlobKey, BlobStore, CommitOutcome, MultipartBlobStore, PackSink, PartRef, PartSink, StoreError,
};

use super::{ObjectBucket, R2BlobStore, R2PackSink, Running, Withheld};
use crate::backend_error;

const META_MAGIC: &[u8; 5] = b"MKUP1";
const META_LEN: usize = 53;

fn session_prefix<B: ObjectBucket>(
    store: &R2BlobStore<B>,
    session: &[u8],
) -> Result<String, StoreError> {
    if session.len() != 32 {
        return Err(StoreError::SessionGone);
    }
    let root = store.keyspace.rsplit_once('/').map_or("", |(root, _)| root);
    let prefix = if root.is_empty() {
        String::new()
    } else {
        format!("{root}/")
    };
    Ok(format!("{prefix}server-uploads/{}/", to_hex_bytes(session)))
}

fn metadata(key: BlobKey, plan: &PartPlan) -> Vec<u8> {
    let mut value = Vec::with_capacity(META_LEN);
    value.extend_from_slice(META_MAGIC);
    value.extend_from_slice(key.hash());
    value.extend_from_slice(&plan.total().to_be_bytes());
    value.extend_from_slice(&plan.part_size().to_be_bytes());
    value
}

fn part_key(prefix: &str, index: u32, cv: &[u8; 32]) -> String {
    format!("{prefix}{index}-{}", to_hex_bytes(cv))
}

impl<B: ObjectBucket> R2BlobStore<B> {
    async fn put_small(&self, object: String, bytes: Bytes) -> Result<(), StoreError> {
        let mut put = Running::spawn(&self.bucket, object, bytes.len() as u64);
        put.send(bytes).await;
        put.finish()
            .await
            .map(|_| ())
            .map_err(|e| backend_error(StorageOp::BlobPut, e))
    }

    async fn read_meta(&self, object: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let Some((size, mut body)) = self
            .bucket
            .get(object, None)
            .await
            .map_err(|e| backend_error(StorageOp::BlobRead, e))?
        else {
            return Ok(None);
        };
        if size != META_LEN as u64 {
            return Err(StoreError::SessionGone);
        }
        let mut value = Vec::with_capacity(META_LEN);
        while let Some(piece) = body.next().await {
            let piece = piece.map_err(|e| backend_error(StorageOp::BlobRead, e))?;
            if piece.len() > META_LEN - value.len() {
                return Err(StoreError::SessionGone);
            }
            value.extend_from_slice(&piece);
        }
        if value.len() != META_LEN {
            return Err(StoreError::SessionGone);
        }
        Ok(Some(value))
    }

    async fn check_meta(&self, object: &str, expected: &[u8]) -> Result<(), StoreError> {
        if self.read_meta(object).await?.as_deref() == Some(expected) {
            Ok(())
        } else {
            Err(StoreError::SessionGone)
        }
    }

    async fn delete_prefix(&self, prefix: &str, except: Option<&str>) -> Result<(), StoreError> {
        // One page keeps cleanup to two R2 calls; the lifecycle reclaims any remainder.
        let page = self
            .bucket
            .list(prefix, None)
            .await
            .map_err(|e| backend_error(StorageOp::BlobRead, e))?;
        let keys: Vec<_> = page
            .keys
            .into_iter()
            .filter(|k| Some(k.as_str()) != except)
            .collect();
        if keys.is_empty() {
            return Ok(());
        }
        self.bucket
            .delete_many(keys)
            .await
            .map_err(|e| backend_error(StorageOp::BlobPut, e))?;
        if page.cursor.is_some() {
            return Err(StoreError::Unavailable(
                "multipart cleanup deferred to bucket lifecycle".into(),
            ));
        }
        Ok(())
    }
}

/// One R2 part whose final byte is released only after the subtree CV matches.
#[derive(Debug)]
pub struct R2PartSink<B: ObjectBucket> {
    store: R2BlobStore<B>,
    sink: R2PackSink<B>,
    meta_key: String,
    expected_meta: Vec<u8>,
    prefix: String,
    object: String,
    index: u32,
    cv: [u8; 32],
    failed: bool,
}

impl<B: ObjectBucket> PartSink for R2PartSink<B> {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        if self.failed {
            return Err(StoreError::Invalid("write after a failed write".into()));
        }
        if chunk.is_empty() {
            self.failed = true;
            return Err(StoreError::Invalid("empty part chunk".into()));
        }
        self.sink.write(chunk).await
    }

    async fn commit(self) -> Result<Vec<u8>, StoreError> {
        if self.failed {
            return Err(StoreError::Invalid("commit after a failed write".into()));
        }
        self.store
            .check_meta(&self.meta_key, &self.expected_meta)
            .await?;
        self.sink.commit().await?;
        // A concurrent same-index writer may race this cleanup. Its loser
        // re-uploads if completion finds no current object.
        let sibling_prefix = format!("{}{}-", self.prefix, self.index);
        self.store
            .delete_prefix(&sibling_prefix, Some(&self.object))
            .await?;
        if self
            .store
            .check_meta(&self.meta_key, &self.expected_meta)
            .await
            .is_err()
        {
            self.store
                .bucket
                .delete(&self.object)
                .await
                .map_err(|e| backend_error(StorageOp::BlobPut, e))?;
            return Err(StoreError::SessionGone);
        }
        Ok(self.cv.to_vec())
    }

    async fn abort(self) {
        self.sink.abort().await;
    }
}

impl<B: ObjectBucket> MultipartBlobStore for R2BlobStore<B> {
    type PartSink = R2PartSink<B>;
    const MAX_PARTS: u32 = 10_000;

    fn supports_multipart(&self) -> bool {
        true
    }

    async fn begin_multipart_for_ticket(
        &self,
        key: BlobKey,
        len: u64,
        part_size: u64,
        ticket_id: [u8; 32],
    ) -> Result<Vec<u8>, StoreError> {
        let plan = PartPlan::new(len, part_size, Self::MAX_PARTS)
            .map_err(|e| StoreError::Invalid(e.to_string().into()))?;
        let prefix = session_prefix(self, &ticket_id)?;
        let meta_key = format!("{prefix}meta");
        let expected = metadata(key, &plan);
        self.put_small(meta_key.clone(), Bytes::from(expected.clone()))
            .await?;
        self.check_meta(&meta_key, &expected).await?;
        Ok(ticket_id.to_vec())
    }

    async fn begin_part(
        &self,
        key: BlobKey,
        session: &[u8],
        plan: &PartPlan,
        index: u32,
        expected_cv: [u8; 32],
    ) -> Result<Self::PartSink, StoreError> {
        let prefix = session_prefix(self, session)?;
        let meta_key = format!("{prefix}meta");
        let expected_meta = metadata(key, plan);
        self.check_meta(&meta_key, &expected_meta).await?;
        let object = part_key(&prefix, index, &expected_cv);
        let core = Withheld::part(expected_cv, plan, index)?;
        let sink = self.sink(object.clone(), core);
        Ok(R2PartSink {
            store: self.clone(),
            sink,
            meta_key,
            expected_meta,
            prefix,
            object,
            index,
            cv: expected_cv,
            failed: false,
        })
    }

    async fn complete(
        &self,
        key: BlobKey,
        session: &[u8],
        plan: &PartPlan,
        parts: &[PartRef],
    ) -> Result<CommitOutcome, StoreError> {
        self.complete_with(key, session, plan, parts, None).await
    }

    async fn complete_with_root(
        &self,
        key: BlobKey,
        session: &[u8],
        plan: &PartPlan,
        parts: &[PartRef],
        content_root: Hash,
    ) -> Result<CommitOutcome, StoreError> {
        self.complete_with(key, session, plan, parts, Some(content_root))
            .await
    }

    fn single_put_limit(&self) -> Option<u64> {
        Some(self.max_bytes)
    }

    async fn abort(&self, _key: BlobKey, session: &[u8]) -> Result<(), StoreError> {
        if self.defer_abort {
            return Err(StoreError::Unavailable(
                "expiry cleanup deferred: Free alarm R2 budget".into(),
            ));
        }
        let prefix = session_prefix(self, session)?;
        self.bucket
            .delete(&format!("{prefix}meta"))
            .await
            .map_err(|e| backend_error(StorageOp::BlobPut, e))?;
        self.delete_prefix(&prefix, None).await
    }
}

impl<B: ObjectBucket> R2BlobStore<B> {
    /// Complete a multipart upload against the key's hash (`None`) or an
    /// object's content root.
    async fn complete_with(
        &self,
        key: BlobKey,
        session: &[u8],
        plan: &PartPlan,
        parts: &[PartRef],
        root: Option<Hash>,
    ) -> Result<CommitOutcome, StoreError> {
        let expected = key.expected_root(root)?;
        // Preserve the public pack protocol's already-completed recovery.
        if root.is_none() && self.head(&key).await?.is_some() {
            return Ok(CommitOutcome::AlreadyPresent);
        }
        let prefix = session_prefix(self, session)?;
        let meta_key = format!("{prefix}meta");
        self.check_meta(&meta_key, &metadata(key, plan)).await?;
        if parts.len() != plan.count() as usize {
            return Err(StoreError::Invalid("wrong number of parts".into()));
        }
        let mut cvs = Vec::with_capacity(parts.len());
        for (position, part) in parts.iter().enumerate() {
            let index = u32::try_from(position)
                .map_err(|_| StoreError::Invalid("part index overflow".into()))?;
            if part.index != index
                || part.len
                    != plan
                        .expected_len(index)
                        .map_err(|e| StoreError::Invalid(e.to_string().into()))?
                || part.tag.len() != 32
            {
                return Err(StoreError::Invalid("part geometry or tag mismatch".into()));
            }
            let cv: [u8; 32] = part
                .tag
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Invalid("invalid part tag".into()))?;
            cvs.push(cv);
        }
        if merge_to_root(plan, &cvs).map_err(|e| StoreError::Invalid(e.to_string().into()))?
            != expected
        {
            return Err(StoreError::Invalid("merged part root mismatch".into()));
        }
        if let Some(root) = root {
            self.pin_object_root(&self.object_key(&key)?, root, plan.total())
                .await?;
        }
        if let Some(meta) = self.head(&key).await? {
            return if meta.len == plan.total() {
                Ok(CommitOutcome::AlreadyPresent)
            } else {
                Err(StoreError::Invalid("stored object length mismatch".into()))
            };
        }
        // Bypass the single-part UploadPack cap; Withheld verifies the whole
        // stream before the conditional final PUT can become visible.
        let mut sink = self.sink(self.object_key(&key)?, Withheld::new(key, plan.total()));
        for (part, cv) in parts.iter().zip(cvs.iter()) {
            let object = part_key(&prefix, part.index, cv);
            let got = self
                .bucket
                .get(&object, None)
                .await
                .map_err(|e| backend_error(StorageOp::BlobRead, e))?;
            let Some((size, mut body)) = got else {
                return if self.read_meta(&meta_key).await?.is_none() {
                    Err(StoreError::SessionGone)
                } else {
                    Err(StoreError::Invalid("part tag has no stored object".into()))
                };
            };
            if size != part.len {
                return Err(StoreError::Invalid("stored part length mismatch".into()));
            }
            let mut seen = 0_u64;
            while let Some(piece) = body.next().await {
                let piece = piece.map_err(|e| backend_error(StorageOp::BlobRead, e))?;
                seen = seen.saturating_add(piece.len() as u64);
                if seen > part.len {
                    return Err(StoreError::Invalid("stored part body overrun".into()));
                }
                sink.write(piece).await?;
            }
            if seen != part.len {
                return Err(StoreError::Invalid("stored part body underrun".into()));
            }
        }
        let outcome = match root {
            Some(root) => sink.commit_with_root(root).await?,
            None => sink.commit().await?,
        };
        self.bucket
            .delete(&meta_key)
            .await
            .map_err(|e| backend_error(StorageOp::BlobPut, e))?;
        if let Err(error) = self.delete_prefix(&prefix, None).await {
            tracing::warn!(%error, "R2 multipart cleanup failed");
        }
        Ok(outcome)
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use crate::r2::{ObjectPage, ObjectStream, PutBody, PutResult};
    use futures::{channel::oneshot, executor::block_on};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone)]
    struct CountBucket {
        remaining: Arc<AtomicUsize>,
        calls: Arc<AtomicUsize>,
    }
    impl CountBucket {
        fn new(parts: usize) -> Self {
            Self {
                remaining: Arc::new(AtomicUsize::new(parts)),
                calls: Arc::default(),
            }
        }
    }
    impl ObjectBucket for CountBucket {
        async fn probe(&self) -> Result<(), String> {
            Ok(())
        }
        fn spawn_put(&self, _: String, _: u64, _: PutBody) -> oneshot::Receiver<PutResult> {
            panic!("unused put")
        }
        async fn head(&self, _: &str) -> Result<Option<u64>, String> {
            panic!("unused head")
        }
        async fn get(
            &self,
            _: &str,
            _: Option<std::ops::Range<u64>>,
        ) -> Result<Option<(u64, ObjectStream)>, String> {
            panic!("unused get")
        }
        async fn delete(&self, _: &str) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn list(&self, prefix: &str, _: Option<&str>) -> Result<ObjectPage, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let count = self.remaining.load(Ordering::SeqCst);
            Ok(ObjectPage {
                keys: (0..count.min(1000))
                    .map(|n| format!("{prefix}{n}"))
                    .collect(),
                cursor: (count > 1000).then(|| "more".into()),
            })
        }
        async fn delete_many(&self, keys: Vec<String>) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.remaining.fetch_sub(keys.len(), Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn session_abort_has_a_fixed_call_cap_and_retains_lifecycle_remainder() {
        let bucket = CountBucket::new(10_000);
        let store = R2BlobStore::new(bucket.clone(), "packs");
        assert!(block_on(store.abort(BlobKey::pack([0; 32]), &[1; 32])).is_err());
        assert_eq!(bucket.calls.load(Ordering::SeqCst), 3);
        assert_eq!(bucket.remaining.load(Ordering::SeqCst), 9_000);
    }

    #[test]
    fn session_abort_drains_a_worker_sized_upload_in_three_calls() {
        let bucket = CountBucket::new(640);
        let store = R2BlobStore::new(bucket.clone(), "packs");
        block_on(store.abort(BlobKey::pack([0; 32]), &[1; 32])).unwrap();
        assert_eq!(bucket.calls.load(Ordering::SeqCst), 3);
        assert_eq!(bucket.remaining.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn free_expiry_session_abort_uses_no_r2_calls() {
        let bucket = CountBucket::new(640);
        let store = R2BlobStore::new(bucket.clone(), "packs").with_deferred_abort(true);
        assert!(block_on(store.abort(BlobKey::pack([0; 32]), &[1; 32])).is_err());
        assert_eq!(bucket.calls.load(Ordering::SeqCst), 0);
        assert_eq!(bucket.remaining.load(Ordering::SeqCst), 640);
    }

    #[test]
    fn free_expiry_closes_tickets_and_records_deferred_abort_failures() {
        use mkit_server::store::{codec, keys, tickets};
        use mkit_server::timers::{TickBudget, TimerRegistry, run_due};
        use mkit_server::{
            Batch, ManualClock, MemoryKv, NamespaceKey, NamespaceStore, Partition, RepoName,
        };
        let clock = Arc::new(ManualClock::new(1000));
        let local = MemoryKv::with_clock(clock.clone());
        let source = Partition::Namespace(NamespaceKey::deployment_default());
        let bucket = CountBucket::new(640);
        let store = R2BlobStore::new(bucket.clone(), "packs").with_deferred_abort(true);
        let registry = TimerRegistry::new()
            .register(mkit_server::timers::ticket_expiry::TicketExpiry { blobs: store });
        let before = mkit_server::timers::ticket_expiry::abort_failures();
        let mut ids = Vec::new();
        for n in 0..8_u8 {
            let ticket = codec::TicketV1 {
                authority_generation: None,
                repo: RepoName::new("room").unwrap(),
                ref_name: "refs/heads/main".into(),
                signer: [3; 32],
                pack_id: [n; 32],
                bytes: 8 << 20,
                part_size: 8 << 20,
                expires_at_ms: 900,
                created_at_ms: 100,
                reservation_id: format!("s:expiry-{n}"),
                upload_session: Some(vec![n; 32]),
            };
            let id = tickets::ticket_id(&ticket.reservation_id);
            block_on(
                local.apply(
                    &source,
                    Batch::new()
                        .put(keys::ticket(&id), codec::encode_ticket(&ticket))
                        .put(
                            keys::reservation(&ticket.reservation_id).unwrap(),
                            codec::encode_reservation(&codec::ReservationV1::Ticketed {
                                ticket_id: id,
                            }),
                        )
                        .put(
                            keys::ticket_index(
                                &ticket.repo,
                                &ticket.ref_name,
                                &ticket.pack_id,
                                &ticket.signer,
                            )
                            .unwrap(),
                            codec::encode_ref_id(&id),
                        )
                        .put(
                            keys::tickets_per_ref(&ticket.repo, &ticket.ref_name).unwrap(),
                            codec::encode_u64(8),
                        )
                        .put(
                            keys::tickets_per_signer(
                                &ticket.repo,
                                &ticket.ref_name,
                                &ticket.signer,
                            )
                            .unwrap(),
                            codec::encode_u64(8),
                        )
                        .put(
                            keys::timer(
                                900,
                                mkit_server::timers::registry::kinds::TICKET_EXPIRY.get(),
                                &id,
                            ),
                            mkit_server::Value::default(),
                        ),
                ),
            )
            .unwrap();
            ids.push((id, ticket.reservation_id));
        }
        let report = block_on(run_due(
            &local,
            &source,
            &registry,
            clock.as_ref(),
            1000,
            &TickBudget::default(),
        ))
        .unwrap();
        assert_eq!(report.fired, 8);
        let calls = bucket.calls.load(Ordering::SeqCst);
        assert!(
            49 + calls <= 50,
            "expiry must fit the existing Free alarm split"
        );
        assert_eq!(calls, 0);
        assert!(mkit_server::timers::ticket_expiry::abort_failures() >= before + 8);
        for (id, reservation) in ids {
            assert!(
                block_on(local.get(&source, &keys::ticket(&id)))
                    .unwrap()
                    .is_none()
            );
            let raw = block_on(local.get(&source, &keys::reservation(&reservation).unwrap()))
                .unwrap()
                .unwrap();
            assert!(matches!(
                codec::decode_reservation(&raw).unwrap(),
                codec::ReservationV1::Expired { .. }
            ));
        }
    }
}
