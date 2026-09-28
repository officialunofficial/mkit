//! Stateless multipart upload operations. The authenticated ticket and part
//! receipts carry everything needed to finish without a metadata read.

use bytes::Bytes;
use mkit_core::protocol::PackKey;
use mkit_core::upload_parts::{PartPlan, merge_to_root};
use mkit_core::write_auth::PartCommitment;

use super::outcome::Outcome;
use super::{AuthMode, Authenticated, HookSet, Pipeline, ServerError, StorageOp, ms, store_error};
use crate::Code;
use crate::op::{Commitment, Procedure};
use crate::store::{BlobKey, MultipartBlobStore, NamespaceStore, PartRef, PartSink, StoreError};
use crate::telemetry::METRIC_UPLOAD_BYTES;
use crate::upload::marker::write_upload_marker;
use crate::upload::receipt;
use crate::upload::ticket_auth::verify_ticket;
use crate::upload::token::TicketClaims;

fn invalid_ticket() -> ServerError {
    ServerError::failed_precondition("invalid or expired upload ticket")
}

#[cfg(test)]
#[path = "parts_tests.rs"]
mod tests;

fn binding_mismatch() -> ServerError {
    ServerError::new(Code::PermissionDenied, "upload ticket binding mismatch")
}

fn part_error(err: mkit_core::upload_parts::PartError) -> ServerError {
    ServerError::invalid_argument(err.to_string())
}

fn multipart_error(op: StorageOp, err: StoreError) -> ServerError {
    match err {
        StoreError::SessionGone => invalid_ticket(),
        StoreError::PartSubtreeMismatch => {
            ServerError::invalid_argument("part subtree hash does not match its commitment")
        }
        StoreError::Invalid(detail) => {
            tracing::warn!(%detail, "multipart storage rejected request");
            ServerError::invalid_argument("invalid multipart upload state")
        }
        other => store_error(op, other),
    }
}

/// One part stream. The store owns its bounded hasher and staged bytes; this
/// handle keeps only the byte count and authenticated commitment.
pub struct PartUploadSession<'p, B: MultipartBlobStore, N, H> {
    pipe: &'p Pipeline<B, N, H>,
    ticket: [u8; 32],
    index: u32,
    subtree: [u8; 32],
    len: u64,
    seen: u64,
    sink: Option<B::PartSink>,
    failed: Option<ServerError>,
    outcome: Outcome,
}

impl<B: MultipartBlobStore, N, H> core::fmt::Debug for PartUploadSession<'_, B, N, H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PartUploadSession")
            .field("index", &self.index)
            .field("len", &self.len)
            .field("seen", &self.seen)
            .finish_non_exhaustive()
    }
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> PartUploadSession<'_, B, N, H> {
    /// Write one nonempty chunk, rejecting an overrun before storing it.
    ///
    /// # Errors
    /// `invalid_argument` for an empty or overlong chunk; storage errors
    /// retain the fixed redacted message.
    pub async fn push(&mut self, chunk: Bytes) -> Result<(), ServerError> {
        if let Some(err) = &self.failed {
            return Err(err.clone());
        }
        let result = self.push_inner(chunk).await;
        if let Err(err) = &result {
            self.outcome.record(Err(err));
            self.failed = Some(err.clone());
        }
        result
    }

    async fn push_inner(&mut self, chunk: Bytes) -> Result<(), ServerError> {
        if chunk.is_empty() {
            return Err(ServerError::invalid_argument("empty upload part chunk"));
        }
        let next = self
            .seen
            .checked_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| ServerError::invalid_argument("part data exceeds the part length"))?;
        if next > self.len {
            return Err(ServerError::invalid_argument(
                "part data exceeds the part length",
            ));
        }
        self.sink
            .as_mut()
            .ok_or_else(|| ServerError::internal("part stream is closed", "missing part sink"))?
            .write(chunk)
            .await
            .map_err(|e| multipart_error(StorageOp::MultipartPart, e))?;
        self.seen = next;
        Ok(())
    }

    /// Verify and commit the part, returning its authenticated receipt.
    ///
    /// # Errors
    /// `invalid_argument` for a short part or mismatched subtree.
    pub async fn finish(mut self) -> Result<Vec<u8>, ServerError> {
        if let Some(err) = self.failed.take() {
            self.abort().await;
            return Err(err);
        }
        if self.seen != self.len {
            let err = ServerError::invalid_argument("part data is shorter than the part length");
            self.outcome.record(Err(&err));
            self.abort().await;
            return Err(err);
        }
        let result = self.finish_inner().await;
        if result.is_ok() {
            self.pipe.metrics.incr(METRIC_UPLOAD_BYTES, &[], self.len);
        }
        self.outcome.record(result.as_ref().map(|_| ()));
        result
    }

    async fn finish_inner(&mut self) -> Result<Vec<u8>, ServerError> {
        let sink = self
            .sink
            .take()
            .ok_or_else(|| ServerError::internal("part stream is closed", "missing part sink"))?;
        let tag = sink.commit().await.map_err(|e| match e {
            StoreError::PartSubtreeMismatch => {
                ServerError::invalid_argument("part subtree hash does not match its commitment")
            }
            other => multipart_error(StorageOp::MultipartPart, other),
        })?;
        let keys = self.pipe.cfg.ticket_keys.as_ref().ok_or_else(|| {
            ServerError::internal("upload tickets are not configured", "ticket keys vanished")
        })?;
        receipt::mint(
            keys,
            &self.ticket,
            self.index,
            &self.subtree,
            self.len,
            &tag,
        )
    }

    /// Discard an incomplete part. An older committed copy of this index is
    /// untouched.
    pub async fn abort(mut self) {
        if let Some(sink) = self.sink.take() {
            sink.abort().await;
        }
    }

    /// Discard an incomplete stream and record the error returned to the client.
    pub async fn abort_with(mut self, err: &ServerError) {
        self.outcome.record(Err(err));
        self.abort().await;
    }
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Records a part-path error the Connect handlers raise outside the pipeline.
    #[cfg(feature = "connect")]
    pub(crate) fn record_part_error(&self, a: &Authenticated, err: &ServerError) {
        self.outcome(a).record(Err(err));
    }

    fn part_ticket(
        &self,
        a: &Authenticated,
        expected: Procedure,
        token: &[u8],
    ) -> Result<TicketClaims, ServerError> {
        if a.procedure() != expected {
            return Err(ServerError::unauthenticated(
                "credentials were checked for another procedure",
            ));
        }
        let keys = self
            .cfg
            .ticket_keys
            .as_ref()
            .ok_or_else(|| ServerError::unimplemented("upload tickets are not configured"))?;
        let AuthMode::AuthV2(cfg) = &self.cfg.auth else {
            let name = if expected == Procedure::UploadPart {
                "UploadPart requires auth v2"
            } else {
                "CompleteUpload requires auth v2"
            };
            return Err(ServerError::unimplemented(name));
        };
        let auth = a
            .auth
            .as_ref()
            .ok_or_else(|| ServerError::unauthenticated("missing auth v2 authorization"))?;
        verify_ticket(
            keys,
            token,
            ms(self.clock.now_ms().saturating_add(a.business_skew_ms)),
            cfg.audience(),
            &a.repo().identity,
            &auth.signer,
        )
    }

    /// Validate a part header and ticket before opening any part sink.
    ///
    /// # Errors
    /// Invalid or mismatched ticket, commitment or part geometry; storage
    /// errors while opening the part.
    pub async fn open_part(
        &self,
        a: &Authenticated,
        token: &[u8],
        index: u32,
    ) -> Result<PartUploadSession<'_, B, N, H>, ServerError> {
        let mut outcome = self.outcome(a);
        let opened = async {
            let claims = self.part_ticket(a, Procedure::UploadPart, token)?;
            let Some(auth) = &a.auth else {
                return Err(ServerError::unauthenticated(
                    "missing auth v2 authorization",
                ));
            };
            let Commitment::Part {
                ticket,
                index: committed_index,
                subtree,
                len,
            } = auth.commitment
            else {
                return Err(binding_mismatch());
            };
            if ticket != claims.ticket_id || committed_index != index {
                return Err(binding_mismatch());
            }
            let plan = PartPlan::new(claims.bytes, claims.part_size, self.cfg.max_parts)
                .map_err(part_error)?;
            plan.check(&PartCommitment {
                ticket,
                index,
                subtree,
                len,
            })
            .map_err(part_error)?;
            if claims.upload_session.is_empty() {
                return Err(invalid_ticket());
            }
            let key: BlobKey = PackKey(claims.pack_id).into();
            let sink = self
                .blobs
                .begin_part(key, &claims.upload_session, &plan, index, subtree)
                .await
                .map_err(|e| multipart_error(StorageOp::MultipartPart, e))?;
            Ok((ticket, subtree, len, sink))
        }
        .await;
        match opened {
            Ok((ticket, subtree, len, sink)) => Ok(PartUploadSession {
                pipe: self,
                ticket,
                index,
                subtree,
                len,
                seen: 0,
                sink: Some(sink),
                failed: None,
                outcome,
            }),
            Err(err) => {
                outcome.record(Err(&err));
                Err(err)
            }
        }
    }

    /// Authenticate all receipts and the merged pack root before any store
    /// call; completion writes no metadata rows.
    ///
    /// # Errors
    /// Invalid ticket, receipt, root, length or storage session.
    pub async fn complete_upload(
        &self,
        a: &Authenticated,
        token: &[u8],
        receipts: &[Vec<u8>],
    ) -> Result<(), ServerError> {
        self.observe(a, async {
            let claims = self.part_ticket(a, Procedure::CompleteUpload, token)?;
            let plan = PartPlan::new(claims.bytes, claims.part_size, self.cfg.max_parts)
                .map_err(part_error)?;
            if u32::try_from(receipts.len()) != Ok(plan.count()) {
                return Err(ServerError::invalid_argument(
                    "wrong number of upload part receipts",
                ));
            }
            let keys = self.cfg.ticket_keys.as_ref().ok_or_else(|| {
                ServerError::internal("upload tickets are not configured", "ticket keys vanished")
            })?;
            let mut cvs = Vec::with_capacity(receipts.len());
            let mut parts = Vec::with_capacity(receipts.len());
            let mut sum = 0_u64;
            for (position, raw) in receipts.iter().enumerate() {
                let receipt = receipt::verify(keys, raw)?;
                if receipt.ticket_id != claims.ticket_id {
                    return Err(binding_mismatch());
                }
                let index = u32::try_from(position).map_err(|_| {
                    ServerError::invalid_argument("wrong number of upload part receipts")
                })?;
                if receipt.index != index
                    || receipt.len != plan.expected_len(index).map_err(part_error)?
                {
                    return Err(ServerError::invalid_argument(
                        "upload part receipt order or length mismatch",
                    ));
                }
                sum = sum.checked_add(receipt.len).ok_or_else(|| {
                    ServerError::invalid_argument("upload part lengths do not match the ticket")
                })?;
                cvs.push(receipt.subtree);
                parts.push(PartRef {
                    index,
                    len: receipt.len,
                    tag: receipt.tag,
                });
            }
            if sum != claims.bytes {
                return Err(ServerError::invalid_argument(
                    "upload part lengths do not match the ticket",
                ));
            }
            if merge_to_root(&plan, &cvs).map_err(part_error)? != claims.pack_id {
                return Err(ServerError::invalid_argument(
                    "merged part root does not match the ticket",
                ));
            }
            self.publish_verified_upload(&claims, &plan, &parts).await
        })
        .await
    }

    /// Called only after every receipt, the total length and the merged root
    /// have been checked without accessing storage.
    async fn publish_verified_upload(
        &self,
        claims: &TicketClaims,
        plan: &PartPlan,
        parts: &[PartRef],
    ) -> Result<(), ServerError> {
        if claims.upload_session.is_empty() {
            return Err(invalid_ticket());
        }
        let key: BlobKey = PackKey(claims.pack_id).into();
        let present = self
            .blobs
            .head(&key)
            .await
            .map_err(|e| multipart_error(StorageOp::BlobHead, e))?;
        if present.is_some_and(|meta| meta.len != claims.bytes) {
            return Err(ServerError::invalid_argument(
                "stored pack length does not match the ticket",
            ));
        }
        if present.is_some() {
            if let Err(err) = self.blobs.abort(key, &claims.upload_session).await {
                tracing::warn!(error = %err, "failed to abort completed multipart session");
            }
        } else {
            match self
                .blobs
                .complete(key, &claims.upload_session, plan, parts)
                .await
            {
                Ok(_) => {}
                Err(StoreError::SessionGone) => {
                    let found = self
                        .blobs
                        .head(&key)
                        .await
                        .map_err(|e| multipart_error(StorageOp::BlobHead, e))?;
                    match found {
                        Some(meta) if meta.len == claims.bytes => {}
                        Some(_) => {
                            return Err(ServerError::invalid_argument(
                                "stored pack length does not match the ticket",
                            ));
                        }
                        None => return Err(invalid_ticket()),
                    }
                }
                Err(e) => return Err(multipart_error(StorageOp::MultipartSession, e)),
            }
        }
        write_upload_marker(&self.blobs, &claims.ticket_id, &claims.pack_id)
            .await
            .map_err(|e| store_error(StorageOp::BlobPut, e))?;
        Ok(())
    }
}
