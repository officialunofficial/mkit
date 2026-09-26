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
//! **Resume is legacy M0 behavior** (00-plan R-85). A retry of the same
//! signed operation finds its record in flight and resumes: it re-streams
//! and re-commits without a second charge (`vcs-worker` parity,
//! `auth_v2.mjs --fault after-reserve|after-put`). SPEC-TRANSPORT-CONNECT
//! §7.1 step 2 answers an in-flight record with `aborted` instead; this
//! exception covers un-ticketed M0 uploads only and goes when WP-1.9 ships
//! replay-exempt ticketed uploads.
//!
//! A retry of a committed operation opens no blob sink: it hashes and
//! length-checks the stream without writing, and returns OK without any
//! metadata write, so a replay never re-creates a pack that GC or a
//! takedown deleted.
//!
//! `pre_receive` runs after the blob is visible, so it cannot prevent
//! visibility: a rejected pack stays until GC reclaims it as unreferenced.
//! A final (storable) rejection is committed as the operation's result, so
//! a retry is answered at `begin_upload` without re-streaming; any other
//! error leaves the record in flight and resumable.
//!
//! An upload that outlives its envelope (past `expires_at +
//! MAX_CLOCK_LEAD_MS`, which caps every signed batch's deadline) cannot
//! commit its record. Once the blob verified and `pre_receive` passed, it
//! returns OK without the record commit and leaves the in-flight record to
//! the pruner: no retry of that nonce can authenticate any more, so replay
//! protection is moot, and the quota stays charged exactly once. The same
//! holds for a commit that fails `unavailable` after `expires_at`.
//!
//! Un-ticketed M0 uploads keep their replay record and quota in the
//! namespace coordinator's partition (`ShardMap::coordinator`), which each
//! upload writes twice (reserve and commit). Under a sharding `ShardMap`
//! the quota is counted per partition, like every quota (PRD §5.4).
//! Ticketed uploads move to their target ref shard in M1 (WP-1.9).

use core::fmt;

use bytes::Bytes;
use mkit_core::hash::Hasher;
use mkit_core::write_auth::MAX_CLOCK_LEAD_MS;
use tracing::Instrument;

use super::hooks::{AdmissionInput, PreReceive};
use super::outcome::Outcome;
use super::plan::{ReplayGuard, Snapshot, WriteKind, WriteRequest};
use super::{Authenticated, HookSet, Pipeline, internal, meta_error, store_error};
use crate::auth_v2::check_pack_commitment;
use crate::error::{Code, ServerError};
use crate::op::{OpKind, Operation};
use crate::replay::{ReplayDecision, StoredRejection, StoredResult, classify};
use crate::storage_error::StorageOp;
use crate::store::{BlobStore, NamespaceStore, PackSink, Partition, StoreError, codec, keys};
use crate::telemetry::METRIC_UPLOAD_BYTES;
use crate::upload::{UploadError, UploadValidator};

/// How an upload relates to its replay record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadMode {
    /// A new operation, reserved and charged by `begin_upload` (also every
    /// unsigned upload).
    Fresh,
    /// The same operation is in flight: re-stream and re-commit, with no
    /// second charge (legacy M0, see the module docs).
    Resume,
    /// The operation already committed: verify the stream without writing
    /// it, then return OK without an apply.
    Replay,
}

/// Where a session's bytes go: the blob sink, or (on a replay) only a
/// hasher.
enum Target<S> {
    Sink(S),
    Verify(Box<Hasher>),
}

/// One `UploadPack` stream in progress. It borrows the pipeline: a
/// binding that owns an `Arc<Pipeline>` keeps the `Arc` alive across the
/// stream. Dropping it without [`Self::finish`] or [`Self::abort`] records
/// the request as `canceled` and leaves nothing visible; an in-flight
/// record stays resumable until it expires.
pub struct UploadSession<'p, B: BlobStore, N, H> {
    pipe: &'p Pipeline<B, N, H>,
    a: Authenticated,
    op: Operation,
    p: Partition,
    mode: UploadMode,
    validator: UploadValidator,
    target: Option<Target<B::Sink>>,
    failed: Option<ServerError>,
    outcome: Outcome,
}

impl<B: BlobStore, N, H> fmt::Debug for UploadSession<'_, B, N, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadSession")
            .field("mode", &self.mode)
            .field("validator", &self.validator)
            .finish_non_exhaustive()
    }
}

/// What [`UploadSession::open`] established.
struct Opened<S> {
    op: Operation,
    p: Partition,
    mode: UploadMode,
    validator: UploadValidator,
    target: Target<S>,
}

/// The replay record a signed operation commits.
pub(super) fn replay_guard(op: &Operation) -> Option<ReplayGuard> {
    op.auth.as_ref().map(|auth| ReplayGuard {
        scope: auth.replay_scope,
        fingerprint: auth.fingerprint,
        expires_at_ms: auth.expires_at_ms,
    })
}

/// Stage 0 for an upload: its mode from the replay record. A stored
/// rejection is answered here, before any chunk.
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

/// A `pre_receive` error a retry may get back forever: a final code and no
/// typed detail (so never an admission challenge).
fn storable(err: &ServerError) -> Option<StoredRejection> {
    if err.details().is_empty() {
        StoredRejection::new(err.code(), err.public_message())
    } else {
        None
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
        let mut outcome = pipe.outcome(a);
        let opened = Self::open(pipe, a, pack_id, total_bytes)
            .instrument(outcome.span.clone())
            .await;
        match opened {
            Ok(o) => Ok(Self {
                pipe,
                a: a.clone(),
                op: o.op,
                p: o.p,
                mode: o.mode,
                validator: o.validator,
                target: Some(o.target),
                failed: None,
                outcome,
            }),
            Err(err) => {
                outcome.record(Err(&err));
                Err(err)
            }
        }
    }

    async fn open(
        pipe: &'p Pipeline<B, N, H>,
        a: &Authenticated,
        pack_id: Option<&[u8]>,
        total_bytes: Option<u64>,
    ) -> Result<Opened<B::Sink>, ServerError> {
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
                    rejection: None,
                };
                pipe.apply_atomic(&op, a, &p, &req, ahead).await?;
            }
        }
        super::fault!(pipe, AfterReserve, &op, a);
        let target = if mode == UploadMode::Replay {
            Target::Verify(Box::default())
        } else {
            let sink = pipe.blobs.begin(key, declared).await;
            Target::Sink(sink.map_err(|e| store_error(StorageOp::BlobPut, e))?)
        };
        Ok(Opened {
            op,
            p,
            mode,
            validator,
            target,
        })
    }

    /// How this upload relates to its replay record.
    #[must_use]
    pub fn mode(&self) -> UploadMode {
        self.mode
    }

    /// Validate one chunk's framing and write it to the blob sink (or, on a
    /// replay, only hash it); returns whether the `last` chunk has arrived.
    /// After an error the session is dead: every later call returns that
    /// error.
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
        let result = async {
            let progress = self
                .validator
                .push(chunk_pack_id, offset, data.len(), last)?;
            match self.target.as_mut() {
                Some(Target::Sink(sink)) => {
                    let written = sink.write(data).await;
                    written.map_err(|e| store_error(StorageOp::BlobPut, e))?;
                }
                Some(Target::Verify(hasher)) => {
                    hasher.update(&data);
                }
                None => return Err(internal("upload sink gone")),
            }
            Ok(progress.complete)
        }
        .instrument(self.outcome.span.clone())
        .await;
        if let Err(err) = &result {
            self.fail(err);
        }
        result
    }

    /// End of stream: commit the blob (BLAKE3-verified by the sink), run
    /// `pre_receive`, then commit the replay record. A replayed upload
    /// stops once the stream verified.
    ///
    /// # Errors
    /// The stream's [`UploadError`] (`DigestMismatch` when the bytes do not
    /// hash to the pack id); a hook's error; the commit batch's error.
    pub async fn finish(mut self) -> Result<(), ServerError> {
        if let Some(err) = self.failed.take() {
            return Err(err);
        }
        let span = self.outcome.span.clone();
        let result = self.complete().instrument(span).await;
        self.outcome.record(result.as_ref().copied());
        result
    }

    async fn complete(&mut self) -> Result<(), ServerError> {
        let pipe = self.pipe;
        let done = self.validator.clone().finish()?;
        match self.target.take() {
            Some(Target::Sink(sink)) => match sink.commit().await {
                Ok(_) => {}
                Err(StoreError::Invalid(detail)) => {
                    tracing::info!(%detail, "pack sink rejected the upload");
                    return Err(UploadError::DigestMismatch.into());
                }
                Err(e) => return Err(store_error(StorageOp::BlobPut, e)),
            },
            Some(Target::Verify(hasher)) if hasher.finalize() == done.key.0 => {}
            Some(Target::Verify(_)) => return Err(UploadError::DigestMismatch.into()),
            None => return Err(internal("upload sink gone")),
        }
        super::fault!(pipe, AfterBlobCommit, &self.op, &self.a);
        if self.mode == UploadMode::Replay {
            return Ok(());
        }
        pipe.metrics.incr(METRIC_UPLOAD_BYTES, &[], done.total);
        tracing::debug!(stage = "pre_receive");
        let checked = pipe
            .hooks
            .pre_receive()
            .check(&self.op, Some(&done.key))
            .await;
        let Some(replay) = replay_guard(&self.op) else {
            return checked;
        };
        let rejection = match &checked {
            Ok(()) => None,
            Err(err) => match storable(err) {
                Some(rejection) => Some(rejection),
                None => return checked,
            },
        };
        if self.now() > replay.expires_at_ms.saturating_add(MAX_CLOCK_LEAD_MS) {
            return Self::lapsed(checked);
        }
        let req = WriteRequest {
            repo: &self.op.repo.name,
            kind: WriteKind::UploadCommit,
            refs: &[],
            replay: Some(replay),
            charges: &[],
            grant: self.op.authz.grant,
            layout_version: pipe.meta.capabilities().implicit_layout_version.is_none(),
            rejection: rejection.as_ref(),
        };
        match pipe
            .apply_atomic(&self.op, &self.a, &self.p, &req, None)
            .await
        {
            Ok(StoredResult::UploadPack) => Ok(()),
            Ok(other) => Err(super::stored_mismatch(&other)),
            // A commit that missed its deadline once the envelope expired:
            // no retry of this nonce can authenticate either.
            Err(e) if e.code() == Code::Unavailable && self.now() > replay.expires_at_ms => {
                Self::lapsed(checked)
            }
            Err(e) => Err(e),
        }
    }

    /// The real clock: the envelope cap bounds deadlines, which never use
    /// the test clock skew.
    fn now(&self) -> i64 {
        self.pipe.clock.now_ms()
    }

    /// The upload outlived its envelope: answer without the record commit
    /// (see the module docs).
    fn lapsed(checked: Result<(), ServerError>) -> Result<(), ServerError> {
        tracing::info!(
            "envelope lapsed during the upload; the in-flight record is left to the pruner"
        );
        checked
    }

    /// Discard the upload: nothing becomes visible. An in-flight record
    /// stays resumable. Recorded as `canceled`.
    pub async fn abort(mut self) {
        if let Some(Target::Sink(sink)) = self.target.take() {
            sink.abort().await;
        }
        self.fail(&ServerError::new(Code::Canceled, "upload aborted"));
    }

    /// Record the session's one failure.
    fn fail(&mut self, err: &ServerError) {
        self.outcome.record(Err(err));
        if self.failed.is_none() {
            self.failed = Some(err.clone());
        }
    }
}
