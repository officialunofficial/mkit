//! Implicit session tickets (WP-1.15, B9/B10): packs an ssh or enc
//! session uploaded and verified earn repository membership when the
//! session's next packmap `UpdateRef` consumes them, without upload
//! tickets, admission or outcome rows.
//!
//! The write itself stays an ordinary [`OpKind::UpdateRef`]: hooks see no
//! new operation kind, and the session's pending set arrives out of band.
//! The B10 check closes the reconnect hole — the node's `prev` is absent
//! or the packmap value the write replaces, and the node and every pack
//! it lists may be only packs pending in this session (and not packlists)
//! or already members; the check can only refuse, never grant membership.

use std::collections::BTreeSet;

use futures::StreamExt as _;
use futures::future::join_all;

use mkit_core::hash::Hash;
#[cfg(feature = "ssh")]
use mkit_core::refs::PACKMAP_REF_PREFIX;
use mkit_core::refs::RefWriteCondition;

use super::plan::Snapshot;
#[cfg(feature = "ssh")]
use super::{Authenticated, StoredResult, UpdateRefResult};
use super::{
    HookSet, OpKind, Operation, Pipeline, RefUpdate, ServerError, StorageOp, internal, meta_error,
    store_error,
};
#[cfg(feature = "ssh")]
use crate::policy::WritePolicy;
use crate::repo::Addressing;
#[cfg(feature = "ssh")]
use crate::repo::NamespaceKey;
#[cfg(feature = "ssh")]
use crate::store::outbox::MAX_TICKETS_PER_ADVANCE;
use crate::store::{BlobBody, BlobKey, MultipartBlobStore, NamespaceStore, codec, keys, read};

/// A pack uploaded and verified during this session, pending membership.
/// The session deduplicates by `pack`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PendingPack {
    /// The pack's id.
    pub(crate) pack: Hash,
    /// Its committed byte count.
    pub(crate) bytes: u64,
    /// The upload began with the MKPL magic: it is a packmap node, never
    /// a listable pack (B10).
    pub(crate) packlist: bool,
}

/// The B10 refusal, pinned on the ssh/enc wire: the packmap's MKPL node,
/// its `prev` node or a pack it lists is neither pending in this session
/// nor already a member.
pub(crate) const IMPLICIT_PACKMAP_UNKNOWN: &str =
    "packmap names packs not uploaded to this repository";

/// The largest MKPL node the consuming check decodes; a session's uploads
/// are each capped far lower on the ssh wire, but a packmap can name packs
/// uploaded over Connect at the deployment's full pack cap.
pub(crate) const MAX_IMPLICIT_PACKLIST_BYTES: u64 = 1024 * 1024;

/// A packmap names at most this many packs; the B10 refusal fires before
/// any membership read.
pub(crate) const MAX_IMPLICIT_LISTED_PACKS: usize = 1024;

/// Bounded membership-read concurrency inside the B10 check.
// Every lookup awaits at most one routed metadata or R2 response at a time.
const IMPLICIT_CHECK_CONCURRENCY: usize = 6;

fn refuse() -> ServerError {
    ServerError::failed_precondition(IMPLICIT_PACKMAP_UNKNOWN)
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Whether transport-identity writes consume session uploads as
    /// implicit tickets: under Multi addressing (an enc listener's bound
    /// repository) or on a namespaced Single repository under the owner
    /// policy (the ssh root mode's). Plain Single and the signed modes
    /// never do.
    #[cfg(feature = "ssh")]
    pub(crate) fn implicit_tickets(&self) -> bool {
        matches!(self.cfg.auth, super::AuthMode::TransportIdentity)
            && match &self.cfg.addressing {
                Addressing::Multi(_) => true,
                Addressing::Single { repo } => {
                    repo.namespace != NamespaceKey::deployment_default()
                        && self.cfg.write_policy == WritePolicy::Owner
                }
            }
    }

    /// One packmap `UpdateRef` that consumes this session's pending packs
    /// (B9). `pending` is the session's deduplicated pending set; on a
    /// committed write the session clears it, on a CAS conflict or an
    /// error it keeps it.
    ///
    /// # Errors
    /// As [`Pipeline::update_ref`]; `internal` for a non-packmap name, a
    /// delete, an over-cap pending set, or a pipeline without implicit
    /// tickets.
    #[cfg(feature = "ssh")]
    pub(crate) async fn update_packmap_consuming(
        &self,
        a: &Authenticated,
        upd: RefUpdate,
        pending: &[PendingPack],
    ) -> Result<UpdateRefResult, ServerError> {
        if !upd.name.starts_with(PACKMAP_REF_PREFIX)
            || upd.new.is_none()
            || pending.len() > MAX_TICKETS_PER_ADVANCE
            || !self.implicit_tickets()
        {
            return Err(internal("not an implicit packmap write"));
        }
        self.observe(a, async {
            super::check_ref_name(&upd.name)?;
            if upd.new.is_none() && !matches!(upd.condition, RefWriteCondition::Match(_)) {
                return Err(ServerError::invalid_argument(
                    "delete requires MATCH and an empty new_id",
                ));
            }
            match self
                .write_with(a, OpKind::UpdateRef(upd), Some(pending))
                .await?
            {
                (StoredResult::UpdateRef(result), _) => Ok(result),
                (other, _) => Err(super::stored_mismatch(&other)),
            }
        })
        .await
    }

    /// The B10 reconnect check, after authorization and before admission
    /// or planning. The new packmap node itself and every pack it lists
    /// may be only packs pending in this session (a pending packlist is
    /// refused — it is a node, not a pack) or already members, at most
    /// [`MAX_IMPLICIT_LISTED_PACKS`] listed. The node's `prev` is absent
    /// or the packmap value this write replaces: under `Match`/`Missing`
    /// that is the condition itself; under `Any` the current value is
    /// read (from `ahead` when the store read it ahead, a direct read
    /// otherwise) and `upd`'s condition rewritten to guard exactly it,
    /// so a concurrent change surfaces as an ordinary CAS conflict.
    /// Every accepted packmap value was checked when written, so by
    /// induction the `prev` chain is exactly the ref's accepted history
    /// and one level suffices. Nothing is written here and the check
    /// never grants membership — it only refuses.
    pub(super) async fn check_implicit_packmap(
        &self,
        op: &Operation,
        pending: &[PendingPack],
        ahead: Option<&Snapshot>,
        upd: &mut RefUpdate,
    ) -> Result<(), ServerError> {
        if !matches!(op.kind, OpKind::UpdateRef(_)) {
            return Err(internal("implicit consumption needs an UpdateRef"));
        }
        let node = upd
            .new
            .ok_or_else(|| internal("implicit packmap write deletes"))?;
        let bytes = self.read_node(&node).await?;
        let listed = mkit_core::transfer::decode_packlist(&bytes).map_err(|_| refuse())?;
        if listed.packs.len() > MAX_IMPLICIT_LISTED_PACKS {
            return Err(refuse());
        }
        if !self.pack_known(op, &upd.name, node, pending).await? {
            return Err(refuse());
        }
        let current = match upd.condition {
            RefWriteCondition::Match(expected) => Some(expected),
            RefWriteCondition::Missing => None,
            RefWriteCondition::Any => self.current_ref(op, &upd.name, ahead).await?,
        };
        if listed.prev.is_some() && listed.prev != current {
            return Err(refuse());
        }
        if matches!(upd.condition, RefWriteCondition::Any) {
            upd.condition = match current {
                Some(id) => RefWriteCondition::Match(id),
                None => RefWriteCondition::Missing,
            };
        }
        let mut packs = listed.packs;
        packs.sort_unstable();
        packs.dedup();
        if packs
            .iter()
            .any(|pack| pending.iter().any(|p| p.pack == *pack && p.packlist))
        {
            return Err(refuse());
        }
        for chunk in packs.chunks(IMPLICIT_CHECK_CONCURRENCY) {
            let results = join_all(
                chunk
                    .iter()
                    .map(|&pack| self.pack_known(op, &upd.name, pack, pending)),
            )
            .await;
            for known in results {
                if !known? {
                    return Err(refuse());
                }
            }
        }
        // On Multi the membership rows the plan writes must name real
        // blobs; on Single the uploads' own `packs/` files are membership,
        // which (a) already established.
        if matches!(self.cfg.addressing, Addressing::Multi(_)) {
            for chunk in pending.chunks(IMPLICIT_CHECK_CONCURRENCY) {
                let heads = join_all(chunk.iter().map(|p| {
                    let key = BlobKey::pack(p.pack);
                    async move { self.blobs.head(&key).await }
                }))
                .await;
                for head in heads {
                    if head
                        .map_err(|e| store_error(StorageOp::BlobHead, e))?
                        .is_none()
                    {
                        return Err(refuse());
                    }
                }
            }
        }
        Ok(())
    }

    /// The packmap ref's current id: the read-ahead snapshot when the
    /// store already read the key, a direct read otherwise.
    pub(super) async fn current_ref(
        &self,
        op: &Operation,
        ref_name: &str,
        ahead: Option<&Snapshot>,
    ) -> Result<Option<Hash>, ServerError> {
        let key = keys::ref_key(&op.repo.name, ref_name);
        if let Some(snap) = ahead.filter(|snap| snap.contains(&key)) {
            return snap
                .get(&key)
                .map(codec::decode_ref_id)
                .transpose()
                .map_err(meta_error);
        }
        let p = self.shards.ref_shard(&op.repo, ref_name);
        read::read_ref(&self.meta, &p, &op.repo.name, ref_name)
            .await
            .map_err(meta_error)
    }

    /// The node's bytes, bounded by [`MAX_IMPLICIT_PACKLIST_BYTES`]: the
    /// reported length is checked before the body is read, and every read
    /// chunk is checked too, so an unbounded body is never buffered.
    async fn read_node(&self, node: &Hash) -> Result<Vec<u8>, ServerError> {
        let body = self
            .blobs
            .get(&BlobKey::pack(*node), None)
            .await
            .map_err(|e| store_error(StorageOp::BlobGet, e))?;
        let Some(body) = body else {
            return Err(refuse());
        };
        match body {
            BlobBody::Bytes(bytes) => {
                if bytes.len() as u64 > MAX_IMPLICIT_PACKLIST_BYTES {
                    return Err(refuse());
                }
                Ok(bytes.to_vec())
            }
            BlobBody::Stream { len, mut stream } => {
                if len > MAX_IMPLICIT_PACKLIST_BYTES {
                    return Err(refuse());
                }
                let mut out = Vec::new();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.map_err(|e| store_error(StorageOp::BlobGet, e))?;
                    if out.len() as u64 + chunk.len() as u64 > MAX_IMPLICIT_PACKLIST_BYTES {
                        return Err(refuse());
                    }
                    out.extend_from_slice(&chunk);
                }
                Ok(out)
            }
        }
    }

    /// Whether `pack` may appear in the consumed packmap: pending in this
    /// session, or already a member (the blob itself under Single, whose
    /// `packs/` directory is membership; the `m` rows under Multi).
    async fn pack_known(
        &self,
        op: &Operation,
        ref_name: &str,
        pack: Hash,
        pending: &[PendingPack],
    ) -> Result<bool, ServerError> {
        if pending.iter().any(|p| p.pack == pack) {
            return Ok(true);
        }
        match &self.cfg.addressing {
            Addressing::Single { .. } => Ok(self
                .blobs
                .head(&BlobKey::pack(pack))
                .await
                .map_err(|e| store_error(StorageOp::BlobHead, e))?
                .is_some()),
            Addressing::Multi(_) => read::is_member(
                &self.meta,
                self.shards.as_ref(),
                &op.repo,
                &pack,
                Some(ref_name),
            )
            .await
            .map_err(meta_error),
        }
    }
}

/// The deduplicated ids of a pending set, for [`ImplicitConsume`].
pub(crate) fn implicit_packs(pending: &[PendingPack]) -> Vec<Hash> {
    pending
        .iter()
        .map(|p| p.pack)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The deduplicated packs and sizes of a pending set, for the stored-bytes counter.
pub(crate) fn implicit_counted(pending: &[PendingPack]) -> Vec<(Hash, u64)> {
    pending
        .iter()
        .map(|p| (p.pack, p.bytes))
        .collect::<std::collections::BTreeMap<_, _>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod concurrency_tests {
    use super::*;
    use crate::{
        BlobMeta, BlobStore, ByteRange, ManualClock, MemoryBlobStore, MemoryKv, NamespaceKey,
        NoopMetrics, Principal, RepoId, RepoName, StoreError,
    };
    use futures::{FutureExt, executor::block_on};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    struct PendingMembership {
        node: Vec<u8>,
        release: AtomicBool,
        active: AtomicUsize,
        peak: AtomicUsize,
        reads: AtomicUsize,
    }
    impl BlobStore for PendingMembership {
        type Sink = <MemoryBlobStore as BlobStore>::Sink;
        async fn begin(&self, _: BlobKey, _: u64) -> Result<Self::Sink, StoreError> {
            unreachable!()
        }
        async fn get(
            &self,
            _: &BlobKey,
            _: Option<ByteRange>,
        ) -> Result<Option<BlobBody>, StoreError> {
            Ok(Some(BlobBody::Bytes(self.node.clone().into())))
        }
        async fn head(&self, _: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            futures::future::poll_fn(|cx| {
                if self.release.load(Ordering::SeqCst) {
                    std::task::Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
            })
            .await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(Some(BlobMeta { len: 32 }))
        }
        async fn probe(&self) -> Result<(), StoreError> {
            unreachable!()
        }
        async fn delete(&self, _: &BlobKey) -> Result<bool, StoreError> {
            unreachable!()
        }
    }
    impl MultipartBlobStore for PendingMembership {
        type PartSink = crate::store::UnsupportedPartSink;
        const MAX_PARTS: u32 = 10_000;
    }

    #[test]
    fn implicit_packmap_checks_keep_at_most_six_backend_requests_active() {
        let packs: Vec<_> = (0..17u8).map(|i| [i; 32]).collect();
        let node = [99; 32];
        let repo = RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new("repo").unwrap(),
        };
        let pipe = Pipeline::new(
            PendingMembership {
                node: mkit_core::transfer::encode_packlist(None, &packs).unwrap(),
                release: AtomicBool::new(false),
                active: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                reads: AtomicUsize::new(0),
            },
            MemoryKv::default(),
            super::super::Hooks::new(),
            super::super::PipelineConfig::new(
                Addressing::Single { repo: repo.clone() },
                super::super::AuthMode::Open,
                crate::upload::UploadLimits::new(1024, 16),
            ),
            Arc::new(ManualClock::new(0)),
            Arc::new(NoopMetrics),
        )
        .unwrap();
        let mut upd = RefUpdate {
            name: "refs/mkit/packmap/main".into(),
            condition: RefWriteCondition::Missing,
            new: Some(node),
        };
        let op = Operation::new(
            repo,
            Principal::Anonymous,
            None,
            OpKind::UpdateRef(upd.clone()),
        );
        let pending = [PendingPack {
            pack: node,
            bytes: 32,
            packlist: true,
        }];
        let mut check = Box::pin(pipe.check_implicit_packmap(&op, &pending, None, &mut upd));
        assert!((&mut check).now_or_never().is_none());
        assert_eq!(pipe.blobs.active.load(Ordering::SeqCst), 6);
        pipe.blobs.release.store(true, Ordering::SeqCst);
        block_on(check).unwrap();
        assert_eq!(pipe.blobs.reads.load(Ordering::SeqCst), packs.len());
        assert_eq!(pipe.blobs.active.load(Ordering::SeqCst), 0);
        assert!(pipe.blobs.peak.load(Ordering::SeqCst) <= 6);
        assert_eq!(upd.new, Some(node));
    }
}
