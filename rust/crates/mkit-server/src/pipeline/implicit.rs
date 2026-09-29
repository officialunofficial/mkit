//! Implicit session tickets (WP-1.15, B9/B10): packs an ssh or enc
//! session uploaded and verified earn repository membership when the
//! session's next packmap `UpdateRef` consumes them, without upload
//! tickets, admission or outcome rows.
//!
//! The write itself stays an ordinary [`OpKind::UpdateRef`]: hooks see no
//! new operation kind, and the session's pending set arrives out of band.
//! The B10 check closes the reconnect hole — a packmap may name only
//! packs pending in this session or already members, and it can only
//! refuse, never grant membership.

use std::collections::BTreeSet;

use futures::StreamExt as _;
use futures::future::join_all;

use mkit_core::hash::Hash;
#[cfg(feature = "ssh")]
use mkit_core::refs::{PACKMAP_REF_PREFIX, RefWriteCondition};

#[cfg(feature = "ssh")]
use super::{Authenticated, RefUpdate, StoredResult, UpdateRefResult};
use super::{
    HookSet, OpKind, Operation, Pipeline, ServerError, StorageOp, internal, meta_error, store_error,
};
use crate::repo::Addressing;
#[cfg(feature = "ssh")]
use crate::repo::NamespaceKey;
#[cfg(feature = "ssh")]
use crate::store::outbox::MAX_TICKETS_PER_ADVANCE;
use crate::store::{BlobBody, BlobKey, MultipartBlobStore, NamespaceStore, read};

/// A pack uploaded and verified during this session, pending membership.
/// The session deduplicates by `pack`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PendingPack {
    /// The pack's id.
    pub(crate) pack: Hash,
    /// Its committed byte count.
    pub(crate) bytes: u64,
}

/// The B10 refusal, pinned on the ssh/enc wire: the packmap's MKPL node or
/// a pack it lists is neither pending in this session nor already a member.
pub(crate) const IMPLICIT_PACKMAP_UNKNOWN: &str =
    "packmap names packs not uploaded to this repository";

/// The largest MKPL node the consuming check decodes; a session's uploads
/// are each capped far lower on the ssh wire, but a packmap can name packs
/// uploaded over Connect at the deployment's full pack cap.
pub(crate) const MAX_IMPLICIT_PACKLIST_BYTES: u64 = 1024 * 1024;

/// Bounded membership-read concurrency inside the B10 check.
const IMPLICIT_CHECK_CONCURRENCY: usize = 16;

fn refuse() -> ServerError {
    ServerError::failed_precondition(IMPLICIT_PACKMAP_UNKNOWN)
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Whether transport-identity writes consume session uploads as
    /// implicit tickets: under Multi addressing (the enc listener's bound
    /// repository) or on a namespaced Single repository (the ssh root
    /// mode's). Plain Single and the signed modes never do.
    #[cfg(feature = "ssh")]
    pub(crate) fn implicit_tickets(&self) -> bool {
        matches!(self.cfg.auth, super::AuthMode::TransportIdentity)
            && match &self.cfg.addressing {
                Addressing::Multi(_) => true,
                Addressing::Single { repo } => repo.namespace != NamespaceKey::deployment_default(),
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
                StoredResult::UpdateRef(result) => Ok(result),
                other => Err(super::stored_mismatch(&other)),
            }
        })
        .await
    }

    /// The B10 reconnect check, after authorization and before admission
    /// or planning: the new packmap node's MKPL may name only packs that
    /// are pending in this session or already members. Nothing is written
    /// here and the check never grants membership — it only refuses.
    pub(super) async fn check_implicit_packmap(
        &self,
        op: &Operation,
        pending: &[PendingPack],
    ) -> Result<(), ServerError> {
        let OpKind::UpdateRef(upd) = &op.kind else {
            return Err(internal("implicit consumption needs an UpdateRef"));
        };
        let node = upd
            .new
            .ok_or_else(|| internal("implicit packmap write deletes"))?;
        if !self.pack_known(op, &upd.name, node, pending).await? {
            return Err(refuse());
        }
        let bytes = self.read_node(&node).await?;
        let listed = mkit_core::transfer::decode_packlist(&bytes).map_err(|_| refuse())?;
        let mut packs = listed.packs;
        packs.sort_unstable();
        packs.dedup();
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
