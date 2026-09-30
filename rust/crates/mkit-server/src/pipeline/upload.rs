//! `UploadPack` streams into a verifying blob sink with bounded memory.
//!
//! [`Pipeline::open_ticketed_upload`] checks framing, the signed `pack:`
//! commitment and the stateless ticket before reading chunks. It skips the
//! replay ledger, authorization, admission, quota and `pre_receive`. After
//! the full pack verifies and commits, it writes a content-addressed upload
//! marker in a non-pack blob namespace. It touches no metadata shard.
//!
//! [`Pipeline::open_upload`] remains for un-ticketed single-repository
//! uploads below the advertised threshold, and for transport identity
//! uploads. A fresh signed operation reserves a replay row and charges
//! quota before streaming. The legacy STC §7.1 MAY (R-85) lets an in-flight
//! retry with the same nonce re-read and commit the stream without charging
//! again. A committed replay verifies the stream without writing a blob.
//! `pre_receive` runs after the pack commit, followed by the replay commit.
//! Rejection leaves an unreferenced pack for GC. If the envelope expires
//! during the stream, the pack may succeed without the final replay write;
//! the in-flight row is left for the pruner.

use core::fmt;

use bytes::Bytes;
use mkit_core::hash::Hasher;
use mkit_core::write_auth::MAX_CLOCK_LEAD_MS;
use tracing::Instrument;

use super::hooks::{AdmissionInput, PreReceive};
use super::outcome::Outcome;
use super::plan::{ReplayGuard, Snapshot, WriteKind, WriteRequest};
use super::{AuthMode, Authenticated, HookSet, Pipeline, internal, meta_error, ms, store_error};
use crate::auth_v2::check_pack_commitment;
use crate::error::{Code, ServerError};
use crate::op::{OpKind, Operation};
use crate::replay::{ReplayDecision, StoredRejection, StoredResult, classify};
use crate::storage_error::StorageOp;
use crate::store::{
    BlobStore, MultipartBlobStore, NamespaceStore, PackSink, Partition, StoreError, codec, keys,
};
use crate::telemetry::METRIC_UPLOAD_BYTES;
use crate::upload::marker::write_upload_marker;
use crate::upload::ticket_auth::verify_ticket;
use crate::upload::{UploadError, UploadValidator};
use mkit_core::hash::Hash;

/// How an upload relates to its replay record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadMode {
    /// A new operation, reserved and charged by `open_upload` (also every
    /// unsigned upload).
    Fresh,
    /// The same operation is in flight: re-stream and re-commit, with no
    /// second charge (legacy M0, see the module docs).
    Resume,
    /// The operation already committed: verify the stream without writing
    /// it, then return OK without an apply.
    Replay,
    /// A stateless ticket authorizes the stream; no metadata is touched.
    Ticketed,
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
    ticket_id: Option<Hash>,
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
    ticket_id: Option<Hash>,
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

impl<'p, B: MultipartBlobStore, N: NamespaceStore, H: HookSet> UploadSession<'p, B, N, H> {
    /// See [`Pipeline::open_upload`].
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
                ticket_id: o.ticket_id,
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
        let mut limits = pipe.cfg.upload_limits;
        if let Some(cap) = pipe.cfg.single_upload_max_bytes {
            limits.max_total_bytes = limits.max_total_bytes.min(cap);
        }
        let validator = UploadValidator::new(pack_id, total_bytes, limits)?;
        if !matches!(pipe.cfg.auth, AuthMode::TransportIdentity)
            && validator.declared() >= pipe.effective_threshold()
        {
            return Err(ServerError::new(
                Code::FailedPrecondition,
                "upload requires a ticket from BeginUpload",
            ));
        }
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
        let ahead = pipe.read_ahead(&op, &p, &[], a.business_skew_ms).await?;
        let mode = upload_mode(&op, ahead.as_ref())?;
        tracing::debug!(stage = "replay_lookup", ?mode);
        if mode != UploadMode::Replay {
            op.authz = pipe.authorize(&op).await?.0;
            super::fault!(pipe, AfterAuthorize, &op, a);
        }
        if mode == UploadMode::Fresh {
            pipe.check_outbox_backpressure(&p, ahead.as_ref()).await?;
            let credentials = super::admission::validate_credentials(&a.credential_capture)?;
            let mut input = AdmissionInput::new(&op);
            input.credential_headers = &credentials;
            input.declared_bytes = declared;
            input.pack_id = Some(key);
            let allowance = pipe.admit_streaming(input).await?;
            if let Some(rid) = &allowance.reservation {
                pipe.abort_unsupported_stream(a, &p, rid).await?;
                let refusal =
                    ServerError::failed_precondition("admission reservations require BeginUpload");
                return Err(if matches!(pipe.cfg.auth, AuthMode::TransportIdentity) {
                    refusal.with_transport_admission_required()
                } else {
                    refusal
                });
            }
            let charges = allowance.charges;
            if op.auth.is_some() || !charges.is_empty() {
                let req = WriteRequest {
                    authority_generation: op.authz.authority_generation,
                    repo: &op.repo.name,
                    kind: WriteKind::UploadReserve,
                    refs: &[],
                    ref_index: None,
                    replay: replay_guard(&op),
                    charges: &charges,
                    namespace_charge: pipe.namespace_charge(
                        &p,
                        &charges,
                        ahead.as_ref().and_then(|s| s.namespace_window),
                    )?,
                    grant: op.authz.grant.clone(),
                    layout_version: pipe.meta.capabilities().implicit_layout_version.is_none(),
                    mark_repo_known: false,
                    lease: None,
                    rejection: None,
                    pending: None,
                    begin: None,
                    advance: None,
                    implicit: None,
                };
                pipe.apply_atomic(&op, a, &p, &req, ahead).await?;
            }
        }
        super::fault!(pipe, AfterReserve, &op, a);
        let target = if mode == UploadMode::Replay {
            Target::Verify(Box::default())
        } else {
            let sink = pipe.blobs.begin(key.into(), declared).await;
            Target::Sink(sink.map_err(|e| store_error(StorageOp::BlobPut, e))?)
        };
        Ok(Opened {
            op,
            p,
            mode,
            validator,
            target,
            ticket_id: None,
        })
    }

    /// Open a replay-exempt ticketed upload without consulting metadata.
    pub(super) async fn begin_ticketed(
        pipe: &'p Pipeline<B, N, H>,
        a: &Authenticated,
        pack_id: Option<&[u8]>,
        total_bytes: Option<u64>,
        token: &[u8],
    ) -> Result<Self, ServerError> {
        let mut outcome = pipe.outcome(a);
        let opened = async {
            let validator = UploadValidator::new(pack_id, total_bytes, pipe.cfg.upload_limits)?;
            let AuthMode::AuthV2(cfg) = &pipe.cfg.auth else {
                return Err(ServerError::new(
                    Code::Unimplemented,
                    "ticketed UploadPack requires auth v2",
                ));
            };
            let keys = pipe.cfg.ticket_keys.as_ref().ok_or_else(|| {
                ServerError::new(Code::Unimplemented, "upload tickets are not configured")
            })?;
            let key = validator.key();
            let declared = validator.declared();
            let mut op = pipe.identify(
                a,
                OpKind::UploadPack {
                    key,
                    declared_len: declared,
                },
            )?;
            let auth = op
                .auth
                .as_ref()
                .ok_or_else(|| internal("ticketed upload lacks auth"))?;
            check_pack_commitment(auth, &key.0, declared)
                .map_err(|e| ServerError::unauthenticated(e.to_string()))?;
            let now_ms = ms(pipe.clock.now_ms().saturating_add(a.business_skew_ms));
            let claims = verify_ticket(
                keys,
                token,
                now_ms,
                cfg.audience(),
                &a.repo().identity,
                &auth.signer,
            )?;
            pipe.check_ticket_generation(&op.repo.namespace, claims.authority_generation)
                .await?;
            op.authz.authority_generation = claims.authority_generation;
            if claims.pack_id != key.0 || claims.bytes != declared {
                return Err(ServerError::new(
                    Code::PermissionDenied,
                    "upload ticket binding mismatch",
                ));
            }
            super::fault!(pipe, AfterAuthenticate, &op, a);
            let sink = pipe
                .blobs
                .begin(key.into(), declared)
                .await
                .map_err(|e| store_error(StorageOp::BlobPut, e))?;
            Ok(Opened {
                op,
                p: pipe.shards.coordinator(&a.repo().repo.namespace),
                mode: UploadMode::Ticketed,
                validator,
                target: Target::Sink(sink),
                ticket_id: Some(claims.ticket_id),
            })
        }
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
                ticket_id: o.ticket_id,
            }),
            Err(err) => {
                outcome.record(Err(&err));
                Err(err)
            }
        }
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
        if let Some(ticket_id) = self.ticket_id {
            pipe.check_ticket_generation(
                &self.op.repo.namespace,
                self.op.authz.authority_generation,
            )
            .await?;
            write_upload_marker(&pipe.blobs, &ticket_id, &done.key.0)
                .await
                .map_err(|e| store_error(StorageOp::BlobPut, e))?;
            pipe.metrics.incr(METRIC_UPLOAD_BYTES, &[], done.total);
            return Ok(());
        }
        if self.mode == UploadMode::Replay {
            return Ok(());
        }
        pipe.metrics.incr(METRIC_UPLOAD_BYTES, &[], done.total);
        tracing::debug!(stage = "pre_receive");
        let checked = pipe
            .hooks
            .pre_receive()
            .check(&self.op, Some(&done.key.into()))
            .await
            .map_err(ServerError::strip_admission_shape);
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
            authority_generation: self.op.authz.authority_generation,
            repo: &self.op.repo.name,
            kind: WriteKind::UploadCommit,
            refs: &[],
            ref_index: None,
            replay: Some(replay),
            charges: &[],
            namespace_charge: None,
            grant: self.op.authz.grant.clone(),
            layout_version: pipe.meta.capabilities().implicit_layout_version.is_none(),
            mark_repo_known: false,
            lease: None,
            rejection: rejection.as_ref(),
            pending: None,
            begin: None,
            advance: None,
            implicit: None,
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
    pub async fn abort(self) {
        self.abort_with(&ServerError::new(Code::Canceled, "upload aborted"))
            .await;
    }

    /// Discard the upload because of `err`, e.g. a malformed message the
    /// binding decoded or a broken request stream: like [`Self::abort`],
    /// but the request is recorded with `err`'s code, the one the client
    /// receives. A session that already failed keeps its first error.
    pub async fn abort_with(mut self, err: &ServerError) {
        if let Some(Target::Sink(sink)) = self.target.take() {
            sink.abort().await;
        }
        self.fail(err);
    }

    /// Record the session's one failure.
    fn fail(&mut self, err: &ServerError) {
        self.outcome.record(Err(err));
        if self.failed.is_none() {
            self.failed = Some(err.clone());
        }
    }
}
