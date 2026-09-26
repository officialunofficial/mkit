//! `UploadPack` as a session (PRD §5.4 stages 0–6, overview Q5).
//!
//! [`Pipeline::begin_upload`] checks the header and the signed `pack:`
//! commitment, then reserves: one batch puts the replay record
//! `InFlight { resumable: true }` with the quota charge, before any chunk
//! is read (`vcs-worker` `service.rs:432-440`). Each
//! [`UploadSession::push`] validates the chunk's framing and hands it
//! straight to the blob sink, so the session holds at most one chunk.
//! [`UploadSession::finish`] commits the blob (the sink verifies BLAKE3),
//! runs `pre_receive` and commits the record `Committed(UploadPack)` in a
//! second batch, guarded on the in-flight record it read and planned with a
//! fresh deadline: the upload itself may take long, only plan-to-apply is
//! bounded.
//!
//! A retry of the same signed operation resumes: it re-streams and
//! re-commits without a second charge (`auth_v2.mjs --fault
//! after-reserve|after-put`). A retry of a committed one re-streams and
//! validates, and returns OK without writing any metadata.
//!
//! Un-ticketed M0 uploads keep their replay record and quota in the
//! namespace coordinator's partition, so a signer's quota stays exact;
//! ticketed uploads move to their target ref shard in M1 (WP-1.9).

use core::fmt;

use bytes::Bytes;
use tracing::Instrument;

use super::plan::{ReplayGuard, Snapshot, WriteKind, WriteRequest};
use super::{Authenticated, HookSet, Pipeline, internal, meta_error, store_error};
use crate::auth_v2::check_pack_commitment;
use crate::error::{Code, ServerError};
use crate::op::{OpKind, Operation};
use crate::replay::{ReplayDecision, StoredResult, classify};
use crate::storage_error::StorageOp;
use crate::store::{BlobStore, NamespaceStore, PackSink, Partition, StoreError, codec, keys};
use crate::telemetry::METRIC_UPLOAD_BYTES;
use crate::upload::{UploadError, UploadValidator};

use super::hooks::{AdmissionInput, PreReceive};

/// How an upload relates to its replay record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadMode {
    /// A new operation, reserved and charged by `begin_upload` (also every
    /// unsigned upload).
    Fresh,
    /// The same operation is in flight: re-stream and re-commit, with no
    /// second charge.
    Resume,
    /// The operation already committed: re-stream and validate, then
    /// return OK without an apply.
    Replay,
}

/// One `UploadPack` stream in progress. It borrows the pipeline: a
/// binding that owns an `Arc<Pipeline>` keeps the `Arc` alive across the
/// stream. Dropping it without [`Self::finish`] leaves nothing visible;
/// an in-flight record stays resumable until it expires.
pub struct UploadSession<'p, B: BlobStore, N, H> {
    pipe: &'p Pipeline<B, N, H>,
    a: Authenticated,
    op: Operation,
    p: Partition,
    mode: UploadMode,
    validator: UploadValidator,
    sink: Option<B::Sink>,
    failed: Option<ServerError>,
    span: tracing::Span,
    start_ms: i64,
}

impl<B: BlobStore, N, H> fmt::Debug for UploadSession<'_, B, N, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadSession")
            .field("mode", &self.mode)
            .field("validator", &self.validator)
            .finish_non_exhaustive()
    }
}

/// The replay record a signed operation commits.
pub(super) fn replay_guard(op: &Operation) -> Option<ReplayGuard> {
    op.auth.as_ref().map(|auth| ReplayGuard {
        scope: auth.replay_scope,
        fingerprint: auth.fingerprint,
        expires_at_ms: auth.expires_at_ms,
    })
}

/// Stage 0 for an upload: its mode from the replay record.
fn upload_mode(op: &Operation, ahead: Option<&Snapshot>) -> Result<UploadMode, ServerError> {
    let (Some(auth), Some(snap)) = (&op.auth, ahead) else {
        return Ok(UploadMode::Fresh);
    };
    let stored = snap.get(&keys::replay(&auth.replay_scope));
    let record = stored.map(codec::decode_replay_record).transpose();
    match classify(record.map_err(meta_error)?.as_ref(), &auth.fingerprint) {
        ReplayDecision::New => Ok(UploadMode::Fresh),
        ReplayDecision::Resume => Ok(UploadMode::Resume),
        ReplayDecision::Return(StoredResult::UploadPack) => Ok(UploadMode::Replay),
        ReplayDecision::Return(other) => Err(super::stored_mismatch(&other)),
        ReplayDecision::FingerprintMismatch => Err(ServerError::invalid_argument(
            "nonce reused for a different operation",
        )),
        ReplayDecision::RetryLater => Err(ServerError::aborted_retryable(
            "operation already in flight; retry",
        )),
    }
}

impl<'p, B: BlobStore, N: NamespaceStore, H: HookSet> UploadSession<'p, B, N, H> {
    /// See [`Pipeline::begin_upload`].
    pub(super) async fn begin(
        pipe: &'p Pipeline<B, N, H>,
        a: &Authenticated,
        pack_id: Option<&[u8]>,
        total_bytes: Option<u64>,
    ) -> Result<Self, ServerError> {
        let span = pipe.rpc_span(a);
        let start_ms = pipe.clock.now_ms();
        let opened = Self::open(pipe, a, pack_id, total_bytes)
            .instrument(span.clone())
            .await;
        match opened {
            Ok(session) => Ok(Self {
                span,
                start_ms,
                ..session
            }),
            Err(err) => {
                pipe.record(a.procedure(), &span, start_ms, Err(&err));
                Err(err)
            }
        }
    }

    async fn open(
        pipe: &'p Pipeline<B, N, H>,
        a: &Authenticated,
        pack_id: Option<&[u8]>,
        total_bytes: Option<u64>,
    ) -> Result<Self, ServerError> {
        let validator = UploadValidator::new(pack_id, total_bytes, pipe.cfg.upload_limits)?;
        let (key, declared) = (validator.key(), validator.declared());
        let kind = OpKind::UploadPack {
            key,
            declared_len: declared,
        };
        let mut op = pipe.identify(a, kind)?;
        if let Some(auth) = &op.auth {
            check_pack_commitment(auth, &key.0, declared)
                .map_err(|e| ServerError::unauthenticated(e.to_string()))?;
        }
        super::fault!(pipe, AfterAuthenticate, &op, a);
        let p = pipe.shards.coordinator(&op.repo.namespace);
        let ahead = pipe.read_ahead(&op, &p, &[]).await?;
        let mode = upload_mode(&op, ahead.as_ref())?;
        tracing::debug!(stage = "replay_lookup", ?mode);
        if mode != UploadMode::Replay {
            op.authz = pipe.authorize(&op).await?;
            super::fault!(pipe, AfterAuthorize, &op, a);
        }
        if mode == UploadMode::Fresh {
            let mut input = AdmissionInput::new(&op);
            input.declared_bytes = declared;
            input.pack_id = Some(key);
            let charges = pipe.admit(input).await?;
            if op.auth.is_some() || !charges.is_empty() {
                let req = WriteRequest {
                    repo: &op.repo.name,
                    kind: WriteKind::UploadReserve,
                    refs: &[],
                    replay: replay_guard(&op),
                    charges: &charges,
                    grant: op.authz.grant,
                    layout_version: pipe.meta.capabilities().implicit_layout_version.is_none(),
                };
                pipe.apply_atomic(&op, a, &p, &req, ahead).await?;
            }
        }
        super::fault!(pipe, AfterReserve, &op, a);
        let sink = pipe.blobs.begin(key, declared).await;
        let sink = sink.map_err(|e| store_error(StorageOp::BlobPut, e))?;
        Ok(Self {
            pipe,
            a: a.clone(),
            op,
            p,
            mode,
            validator,
            sink: Some(sink),
            failed: None,
            span: tracing::Span::none(),
            start_ms: 0,
        })
    }

    /// How this upload relates to its replay record.
    #[must_use]
    pub fn mode(&self) -> UploadMode {
        self.mode
    }

    /// Validate one chunk's framing and write it to the blob sink; returns
    /// whether the `last` chunk has arrived. After an error the session is
    /// dead: every later call returns that error.
    ///
    /// # Errors
    /// The chunk's [`UploadError`]; `internal` for a failed blob write.
    pub async fn push(
        &mut self,
        chunk_pack_id: Option<&[u8]>,
        offset: Option<u64>,
        data: Bytes,
        last: bool,
    ) -> Result<bool, ServerError> {
        if let Some(err) = &self.failed {
            return Err(err.clone());
        }
        let span = self.span.clone();
        let result = async {
            let progress = self
                .validator
                .push(chunk_pack_id, offset, data.len(), last)?;
            let sink = self
                .sink
                .as_mut()
                .ok_or_else(|| internal("upload sink gone"))?;
            let written = sink.write(data).await;
            written.map_err(|e| store_error(StorageOp::BlobPut, e))?;
            Ok(progress.complete)
        }
        .instrument(span.clone())
        .await;
        if let Err(err) = &result {
            self.fail(err);
        }
        result
    }

    /// End of stream: commit the blob (BLAKE3-verified by the sink), run
    /// `pre_receive`, then commit the replay record. A replayed upload
    /// stops after the blob.
    ///
    /// # Errors
    /// The stream's [`UploadError`] (`DigestMismatch` when the bytes do not
    /// hash to the pack id); a hook's error; the commit batch's error.
    pub async fn finish(mut self) -> Result<(), ServerError> {
        if let Some(err) = self.failed.take() {
            return Err(err);
        }
        let span = self.span.clone();
        let result = self.complete().instrument(span.clone()).await;
        let procedure = self.a.procedure();
        self.pipe
            .record(procedure, &span, self.start_ms, result.as_ref().copied());
        result
    }

    async fn complete(&mut self) -> Result<(), ServerError> {
        let pipe = self.pipe;
        let done = self.validator.clone().finish()?;
        let sink = self
            .sink
            .take()
            .ok_or_else(|| internal("upload sink gone"))?;
        match sink.commit().await {
            Ok(_) => {}
            Err(StoreError::Invalid(detail)) => {
                tracing::info!(%detail, "pack sink rejected the upload");
                return Err(UploadError::DigestMismatch.into());
            }
            Err(e) => return Err(store_error(StorageOp::BlobPut, e)),
        }
        super::fault!(pipe, AfterBlobCommit, &self.op, &self.a);
        pipe.metrics.incr(METRIC_UPLOAD_BYTES, &[], done.total);
        if self.mode == UploadMode::Replay {
            return Ok(());
        }
        tracing::debug!(stage = "pre_receive");
        let hook = pipe.hooks.pre_receive();
        hook.check(&self.op, Some(&done.key)).await?;
        let Some(replay) = replay_guard(&self.op) else {
            return Ok(());
        };
        let req = WriteRequest {
            repo: &self.op.repo.name,
            kind: WriteKind::UploadCommit,
            refs: &[],
            replay: Some(replay),
            charges: &[],
            grant: self.op.authz.grant,
            layout_version: pipe.meta.capabilities().implicit_layout_version.is_none(),
        };
        match pipe
            .apply_atomic(&self.op, &self.a, &self.p, &req, None)
            .await?
        {
            StoredResult::UploadPack => Ok(()),
            other => Err(super::stored_mismatch(&other)),
        }
    }

    /// Discard the upload: nothing becomes visible. An in-flight record
    /// stays resumable.
    pub async fn abort(mut self) {
        if let Some(sink) = self.sink.take() {
            sink.abort().await;
        }
        if self.failed.is_none() {
            self.fail(&ServerError::new(Code::Canceled, "upload aborted"));
        }
    }

    /// Record the session's one failure.
    fn fail(&mut self, err: &ServerError) {
        if self.failed.is_none() {
            let procedure = self.a.procedure();
            self.pipe
                .record(procedure, &self.span, self.start_ms, Err(err));
            self.failed = Some(err.clone());
        }
    }
}
