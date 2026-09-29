//! Per-verb dispatch over the pipeline (`mkit serve`'s `dispatch` and
//! `handle_simple_verb`), keeping its responses and error frames.
//!
//! Every pipeline failure maps to the one fixed error frame `mkit serve`
//! sends for that verb, so no pipeline message reaches the ssh wire:
//!
//! | Verb | Failure | Frame |
//! |---|---|---|
//! | `PackExists` | any | `exists = false` |
//! | `ReadRef` | a name over 512 bytes | `INVALID_REQUEST "ref name too long"` |
//! | `ReadRef` | a valid name outside `refs/` | `INVALID_REQUEST`, [`REF_NAME_OUTSIDE_REFS`] |
//! | `ReadRef` | any other | `INTERNAL "read ref failed"` |
//! | `UpdateRef` | a name over 512 bytes | `INVALID_REQUEST "ref name too long"` |
//! | `UpdateRef` | a valid name outside `refs/` | `INVALID_REQUEST`, [`REF_NAME_OUTSIDE_REFS`] |
//! | `UpdateRef` | a CAS conflict | [`cas_conflict_body`] |
//! | `UpdateRef` | admission wants a payment ([`ServerError::is_transport_admission_required`]) | `INVALID_REQUEST`, [`PAYMENT_REQUIRED_FRAME`], empty `details` |
//! | `UpdateRef` | `permission_denied` | `INVALID_REQUEST "write not permitted"` |
//! | `UpdateRef` | a packmap's node, `prev` or a listed pack unknown (B10) | `INVALID_REQUEST`, [`IMPLICIT_PACKMAP_UNKNOWN`] |
//! | `UpdateRef` | any other | `INVALID_REQUEST "update ref failed"` |
//! | `ListRefs` | any | `INTERNAL "list refs failed"` |
//! | `DownloadPack` | any, before the header | `KEY_NOT_FOUND "pack not found"` |
//! | `DownloadPack` | a body read, after the header | `INTERNAL "pack read failed"` |
//! | `UploadPack` | admission wants a payment or a reservation (same marker) | `INVALID_REQUEST`, [`PAYMENT_REQUIRED_FRAME`] |
//! | `UploadPack` | `permission_denied` | `INVALID_REQUEST "write not permitted"` |
//! | `UploadPack` | the eighth distinct pack before a packmap | `INVALID_REQUEST "too many packs uploaded before a packmap update"` |
//! | `UploadPack` | bytes that do not hash to `pack_id` | `INVALID_REQUEST`, [`UploadError::ssh_message`] |
//! | `UploadPack` | any other | `INTERNAL "upload failed"` |
//!
//! Three kinds of row are new. A mid-download read failure cannot happen in
//! `mkit serve`, which reads the whole pack before its header. `mkit serve`
//! had no ref-name length limit; SPEC-REFS §3 now caps names at 512 bytes
//! (`refs::MAX_REF_NAME_BYTES`), and an over-long name is refused by name
//! rather than failing like a storage error. And `mkit serve` stored a name
//! outside `refs/` (`main`) as `<root>/main`; the pipeline serves only
//! `refs/` names (R-86, [`crate::refs::is_served_ref_name`]), and a
//! grammar-valid name outside it is refused by name, so a client of a repo
//! holding such a legacy ref gets an error, never a silent "absent". A name
//! that fails the grammar keeps its old reply.

use core::future::poll_fn;

use bytes::Bytes;
use mkit_core::hash::Hash;
use mkit_core::protocol::PackKey;
use mkit_core::refs::PACKMAP_REF_PREFIX;
use mkit_rpc::mkit::common::v1::RefEntry;
use mkit_rpc::mkit::rpc::v1::ssh::{
    DownloadPack, DownloadPackHeader, ListRefsResponse, PackChunk, PackExistsResponse,
    ReadRefResponse, UpdateRef, UploadPack, UploadPackResponse, ssh_frame,
};
use mkit_rpc::mkit::rpc::v1::{Error as RpcError, ErrorCode};

use super::session::{FrameIoError, FrameSink, FrameSource, Stop, emit_error, send_body};
use crate::error::{Code, ServerError};
use crate::op::{Procedure, RefUpdate};
use crate::pipeline::{
    Authenticated, HookSet, IMPLICIT_PACKMAP_UNKNOWN, PendingPack, Pipeline, RequestMeta,
    UploadSession,
};
use crate::principal::Principal;
use crate::refs::{
    DigestField, MAX_REF_NAME_BYTES, REF_NAME_OUTSIDE_REFS, REF_NAME_TOO_LONG, RefWireError,
    UnusedExpectedId, condition_from_wire, hash_from_slice, is_served_ref_name, validate_ref_name,
};
use crate::store::outbox::MAX_TICKETS_PER_ADVANCE;
use crate::store::{MultipartBlobStore, NamespaceStore};
use crate::upload::{UploadError, UploadLimits, UploadValidator};

/// A verb's fixed rejection: the code and message of its error frame.
pub(super) type VerbError = (ErrorCode, &'static str);

type Body = ssh_frame::Body;

fn wire_error(err: RefWireError) -> VerbError {
    (ErrorCode::InvalidRequest, err.ssh_message())
}

/// A request digest as a pack key, with the ssh message for a bad one:
/// `pack_id missing` or `pack_id must be 32 bytes`.
///
/// # Errors
/// `INVALID_REQUEST` unless `id` is present and 32 bytes long.
pub(super) fn pack_key(id: Option<&[u8]>) -> Result<PackKey, VerbError> {
    hash_from_slice(DigestField::PackId, id)
        .map(PackKey::new)
        .map_err(wire_error)
}

/// An `UpdateRef` request as a [`RefUpdate`] (SPEC-TRANSPORT §4.2.1): a
/// 32-byte `new_id`, then the expectation. `expected_id` is read for
/// `MATCH` only, and must then be 32 bytes; the ssh wire ignores it for
/// `ANY` and `MISSING`.
///
/// # Errors
/// `INVALID_REQUEST` with the ssh message of the first bad field.
pub(super) fn decode_update_ref(req: &UpdateRef) -> Result<RefUpdate, VerbError> {
    let new_id = req.new_id.as_deref().unwrap_or_default();
    let new = hash_from_slice(DigestField::NewId, Some(new_id)).map_err(wire_error)?;
    let expectation = req.expectation.map_or(0, |e| e.to_i32());
    let expected_id = req.expected_id.as_deref().unwrap_or_default();
    let condition = condition_from_wire(expectation, expected_id, UnusedExpectedId::Ignore)
        .map_err(wire_error)?;
    Ok(RefUpdate {
        name: req.name.clone().unwrap_or_default(),
        condition,
        new: Some(new),
    })
}

/// The SPEC-TRANSPORT §4.2.1 reply to a failed CAS:
/// `Error{INVALID_REQUEST}` whose `details` is the ref's current id, or
/// empty when the ref is absent, mirroring `ReadRefResponse`'s
/// empty-means-absent encoding. Strict clients classify a non-empty
/// `details` as `RefConflict` and surface the empty case's message as a
/// remote error, rather than fabricating a current id.
#[must_use]
pub fn cas_conflict_body(current: Option<Hash>) -> ssh_frame::Body {
    let (details, message) = match current {
        Some(h) => (
            h.to_vec(),
            "ref update conflict: expectation does not match current ref value",
        ),
        None => (
            Vec::new(),
            "ref update conflict: expectation not met and ref is currently absent",
        ),
    };
    Body::Error(Box::new(
        RpcError::default()
            .with_code(ErrorCode::InvalidRequest)
            .with_message(message)
            .with_details(details),
    ))
}

/// Refuse by name a ref name over [`MAX_REF_NAME_BYTES`] (SPEC-REFS §3),
/// or a valid one outside `refs/` (R-86). A name that fails the grammar
/// passes, to fail in the pipeline with the verb's old reply.
fn check_name(name: &str) -> Result<(), VerbError> {
    if name.len() > MAX_REF_NAME_BYTES {
        Err((ErrorCode::InvalidRequest, REF_NAME_TOO_LONG))
    } else if validate_ref_name(name) && !is_served_ref_name(name) {
        Err((ErrorCode::InvalidRequest, REF_NAME_OUTSIDE_REFS))
    } else {
        Ok(())
    }
}

/// The upload caps a session enforces: the pipeline's, but never looser
/// than the ssh wire's (SPEC-TRANSPORT §4.4), field by field.
fn session_upload_limits(pipeline: UploadLimits) -> UploadLimits {
    let wire = super::upload_limits();
    UploadLimits {
        max_total_bytes: pipeline.max_total_bytes.min(wire.max_total_bytes),
        max_chunks: pipeline.max_chunks.min(wire.max_chunks),
    }
}

/// Whether `err` is the upload sink's digest check failing.
fn is_digest_mismatch(err: &ServerError) -> bool {
    let want = ServerError::from(UploadError::DigestMismatch);
    err.code() == want.code() && err.public_message() == want.public_message()
}

/// `UpdateRef`'s failure mapping: a denied write and the B10 refusal are
/// pinned, and everything else stays `update ref failed`.
fn update_ref_error(err: &ServerError) -> VerbError {
    if err.is_transport_admission_required() {
        (ErrorCode::InvalidRequest, PAYMENT_REQUIRED_FRAME)
    } else if err.code() == Code::PermissionDenied {
        (ErrorCode::InvalidRequest, "write not permitted")
    } else if err.code() == Code::FailedPrecondition
        && err.public_message() == IMPLICIT_PACKMAP_UNKNOWN
    {
        (ErrorCode::InvalidRequest, IMPLICIT_PACKMAP_UNKNOWN)
    } else {
        (ErrorCode::InvalidRequest, "update ref failed")
    }
}

/// `UploadPack`'s refusal on a denied open; any other open failure keeps
/// `upload failed`.
fn upload_open_error(err: &ServerError) -> Option<VerbError> {
    if err.is_transport_admission_required() {
        Some((ErrorCode::InvalidRequest, PAYMENT_REQUIRED_FRAME))
    } else {
        (err.code() == Code::PermissionDenied)
            .then_some((ErrorCode::InvalidRequest, "write not permitted"))
    }
}

/// The frame message for a write whose admission needs a payment or a
/// reservation: ssh and enc cannot carry either, so the client is told to use
/// HTTPS. Sent as `INVALID_REQUEST` with empty `details`, so a client never
/// reads it as a ref conflict; the frozen `ErrorCode` set is unchanged.
pub const PAYMENT_REQUIRED_FRAME: &str = "payment required: use mkit+https";

/// The verbs of one session: its pipeline, the principal every verb runs
/// as, the repository the transport bound the session to, and the
/// session's implicit pending set.
pub(super) struct Verbs<'p, B, N, H> {
    pipe: &'p Pipeline<B, N, H>,
    principal: Principal,
    /// `x-repository` on each request; `None` on an unbound session.
    repository: Option<String>,
    /// Packs uploaded and verified this session, pending membership
    /// (`Some` iff the pipeline consumes implicit tickets).
    pending: Option<Vec<PendingPack>>,
}

impl<'p, B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Verbs<'p, B, N, H> {
    pub(super) fn new(
        pipe: &'p Pipeline<B, N, H>,
        principal: Principal,
        repository: Option<String>,
    ) -> Self {
        Self {
            pipe,
            principal,
            repository,
            pending: pipe.implicit_tickets().then(Vec::new),
        }
    }

    /// Stage 0 for `procedure`: the transport's principal, and the bound
    /// repository as `x-repository`. Only the enc listener binds a
    /// repository; a client can never name one. No other header is
    /// answered, so a transport-identity write can never carry a grant.
    pub(super) fn auth(&self, procedure: Procedure) -> Result<Authenticated, ServerError> {
        let repository = self.repository.clone();
        let header = move |name: &str| -> Option<String> {
            if name == "x-repository" {
                repository.clone()
            } else {
                None
            }
        };
        self.pipe.authenticate(&RequestMeta {
            procedure,
            header: &header,
            header_values: None,
            unary_body: None,
            transport_principal: Some(self.principal.clone()),
        })
    }

    /// Answer one top-level frame body. The streaming verbs read their
    /// chunk frames from `src`.
    ///
    /// # Errors
    /// [`Stop`] when the sink fails or the source times out mid-upload.
    pub(super) async fn dispatch<S: FrameSource, K: FrameSink>(
        &mut self,
        body: Option<Body>,
        src: &mut S,
        sink: &mut K,
    ) -> Result<(), Stop> {
        let Some(body) = body else {
            return emit_error(sink, ErrorCode::InvalidRequest, "empty frame").await;
        };
        match body {
            Body::DownloadPack(req) => self.download(&req, sink).await,
            Body::UploadPack(header) => self.upload(&header, src, sink).await,
            Body::PackChunk(_) => {
                let message = "PackChunk arrived without UploadPack header";
                emit_error(sink, ErrorCode::InvalidRequest, message).await
            }
            Body::Hello(_) => {
                emit_error(sink, ErrorCode::InvalidRequest, "Hello after handshake").await
            }
            other => match self.simple(&other).await {
                Some(Ok(resp)) => send_body(sink, resp).await,
                Some(Err((code, message))) => emit_error(sink, code, message).await,
                None => {
                    emit_error(sink, ErrorCode::InvalidRequest, "unexpected request frame").await
                }
            },
        }
    }

    /// The one-frame verbs; `None` for any other body.
    pub(super) async fn simple(&mut self, body: &Body) -> Option<Result<Body, VerbError>> {
        Some(match body {
            Body::PackExists(req) => match pack_key(req.pack_id.as_deref()) {
                Ok(key) => {
                    let exists = match self.auth(Procedure::PackExists) {
                        Ok(a) => self.pipe.pack_exists(&a, key).await.unwrap_or(false),
                        Err(_) => false,
                    };
                    Ok(Body::PackExistsResponse(Box::new(PackExistsResponse {
                        exists: Some(exists),
                        ..Default::default()
                    })))
                }
                Err(e) => Err(e),
            },
            Body::ReadRef(req) => {
                let name = req.name.clone().unwrap_or_default();
                if let Err(e) = check_name(&name) {
                    return Some(Err(e));
                }
                let read = match self.auth(Procedure::ReadRef) {
                    Ok(a) => self.pipe.read_ref(&a, &name).await,
                    Err(e) => Err(e),
                };
                match read {
                    Ok(found) => Ok(Body::ReadRefResponse(Box::new(ReadRefResponse {
                        object_id: Some(found.map(|h| h.to_vec()).unwrap_or_default()),
                        ..Default::default()
                    }))),
                    Err(_) => Err((ErrorCode::Internal, "read ref failed")),
                }
            }
            Body::UpdateRef(req) => {
                let update = match decode_update_ref(req) {
                    Ok(update) => update,
                    Err(e) => return Some(Err(e)),
                };
                if let Err(e) = check_name(&update.name) {
                    return Some(Err(e));
                }
                // A packmap write on an implicit session consumes its
                // pending set (B9); any other name is an ordinary write.
                let consuming = self.pending.is_some()
                    && update.name.starts_with(PACKMAP_REF_PREFIX)
                    && update.new.is_some();
                let result = match self.auth(Procedure::UpdateRef) {
                    Ok(a) if consuming => {
                        let pending = self.pending.take().unwrap_or_default();
                        let result = self
                            .pipe
                            .update_packmap_consuming(&a, update, &pending)
                            .await;
                        // A commit consumes the set; a conflict or an
                        // error keeps it for the corrected write.
                        self.pending = Some(match result {
                            Ok(crate::UpdateRefResult::Committed) => Vec::new(),
                            _ => pending,
                        });
                        result
                    }
                    Ok(a) => self.pipe.update_ref(&a, update).await,
                    Err(e) => Err(e),
                };
                match result {
                    Ok(crate::UpdateRefResult::Committed) => {
                        Ok(Body::UpdateRefResponse(Box::default()))
                    }
                    Ok(crate::UpdateRefResult::Conflict { current }) => {
                        Ok(cas_conflict_body(current))
                    }
                    Err(e) => Err(update_ref_error(&e)),
                }
            }
            Body::ListRefs(req) => {
                let prefix = req.prefix.clone().unwrap_or_default();
                let listed = match self.auth(Procedure::ListRefs) {
                    Ok(a) => self.pipe.list_refs(&a, &prefix).await,
                    Err(e) => Err(e),
                };
                match listed {
                    Ok(entries) => Ok(Body::ListRefsResponse(Box::new(ListRefsResponse {
                        refs: entries
                            .into_iter()
                            .map(|e| RefEntry {
                                name: Some(e.name),
                                object_id: Some(e.id.to_vec()),
                                ..Default::default()
                            })
                            .collect(),
                        ..Default::default()
                    }))),
                    Err(_) => Err((ErrorCode::Internal, "list refs failed")),
                }
            }
            _ => return None,
        })
    }

    /// `DownloadPack`: a header with the pack's length, then its chunks,
    /// each repeating the request's `pack_id`; only the final one is
    /// `last`, and an empty pack is one empty `last` chunk.
    async fn download<K: FrameSink>(&self, req: &DownloadPack, sink: &mut K) -> Result<(), Stop> {
        let key = match pack_key(req.pack_id.as_deref()) {
            Ok(key) => key,
            Err((code, message)) => return emit_error(sink, code, message).await,
        };
        let opened = match self.auth(Procedure::DownloadPack) {
            Ok(a) => self.pipe.download(&a, key).await,
            Err(e) => Err(e),
        };
        let Ok(mut stream) = opened else {
            return emit_error(sink, ErrorCode::KeyNotFound, "pack not found").await;
        };
        let header = DownloadPackHeader {
            total_bytes: Some(stream.total_bytes),
            ..Default::default()
        };
        send_body(sink, Body::DownloadPackHeader(Box::new(header))).await?;
        // Polled to its end, past the `last` chunk, so the pipeline
        // records the download as a success.
        while let Some(item) = poll_fn(|cx| stream.chunks.as_mut().poll_next(cx)).await {
            let Ok(chunk) = item else {
                return emit_error(sink, ErrorCode::Internal, "pack read failed").await;
            };
            let chunk = PackChunk {
                pack_id: req.pack_id.clone(),
                offset: Some(chunk.offset),
                data: Some(chunk.data.to_vec()),
                last: Some(chunk.last),
                ..Default::default()
            };
            send_body(sink, Body::PackChunk(Box::new(chunk))).await?;
        }
        Ok(())
    }

    /// `UploadPack`: the header, then `PackChunk` frames read inline from
    /// `src` until `last`. The chunk frames are not charged to the session
    /// budget; `UploadLimits::max_chunks` caps them, at most
    /// [`super::MAX_FRAMES_PER_CONN`] whatever the pipeline allows.
    ///
    /// A framing error is answered at once with its ssh message, like a
    /// read failure or a non-chunk frame (which is consumed); the pack
    /// sink is then discarded, so nothing becomes visible. A storage
    /// failure does not end the stream early: the rest of it is read and
    /// checked, then answered with `upload failed`, as `mkit serve` did.
    async fn upload<S: FrameSource, K: FrameSink>(
        &mut self,
        header: &UploadPack,
        src: &mut S,
        sink: &mut K,
    ) -> Result<(), Stop> {
        let (pack_id, total) = (header.pack_id.as_deref(), header.total_bytes);
        let limits = session_upload_limits(self.pipe.upload_limits());
        let mut framing = match UploadValidator::new(pack_id, total, limits) {
            Ok(framing) => framing,
            Err(e) => return emit_error(sink, ErrorCode::InvalidRequest, e.ssh_message()).await,
        };
        // A session with implicit tickets admits at most
        // MAX_TICKETS_PER_ADVANCE distinct packs before a packmap consumes
        // them; the refusal drains the stream like a failed open.
        let mut failed_open: Option<VerbError> = self
            .pending
            .as_ref()
            .filter(|pending| {
                pending.len() >= MAX_TICKETS_PER_ADVANCE
                    && !pending.iter().any(|p| p.pack == framing.key().0)
            })
            .map(|_| {
                (
                    ErrorCode::InvalidRequest,
                    "too many packs uploaded before a packmap update",
                )
            });
        let mut session = if failed_open.is_some() {
            None
        } else {
            self.open_upload_session(pack_id, total, &mut failed_open)
                .await
        };
        // The pack's first four bytes, accumulated across chunks: they
        // tell B10 whether the pending upload is an MKPL node.
        let mut magic = Vec::with_capacity(4);
        loop {
            let frame = match src.next_frame().await {
                Ok(frame) => frame,
                Err(err) => {
                    abort(session).await;
                    if matches!(err, FrameIoError::Timeout) {
                        return Err(Stop::Timeout);
                    }
                    let message = UploadError::NoLast.ssh_message();
                    return emit_error(sink, ErrorCode::InvalidRequest, message).await;
                }
            };
            let Some(Body::PackChunk(chunk)) = frame.body else {
                abort(session).await;
                let message = "expected PackChunk after UploadPack";
                return emit_error(sink, ErrorCode::InvalidRequest, message).await;
            };
            let mut chunk = *chunk;
            let data = chunk.data.take().unwrap_or_default();
            let last = chunk.last.unwrap_or(false);
            let id = chunk.pack_id.as_deref();
            let progress = match framing.push(id, chunk.offset, data.len(), last) {
                Ok(progress) => progress,
                Err(e) => {
                    abort(session).await;
                    return emit_error(sink, ErrorCode::InvalidRequest, e.ssh_message()).await;
                }
            };
            if magic.len() < 4 && chunk.offset == Some(magic.len() as u64) {
                let take = data.len().min(4 - magic.len());
                magic.extend_from_slice(&data[..take]);
            }
            if let Some(s) = session.as_mut()
                && s.push(id, chunk.offset, Bytes::from(data), last)
                    .await
                    .is_err()
            {
                abort(session.take()).await;
            }
            if progress.complete {
                break;
            }
        }
        let Some(s) = session else {
            let (code, message) = failed_open.unwrap_or((ErrorCode::Internal, "upload failed"));
            return emit_error(sink, code, message).await;
        };
        let finished = s.finish().await;
        match finished {
            Ok(()) => {
                // A verified upload joins the pending set, deduplicated;
                // the session's next packmap consumes it.
                if let Some(pending) = &mut self.pending {
                    let pack = framing.key().0;
                    if !pending.iter().any(|p| p.pack == pack) {
                        pending.push(PendingPack {
                            pack,
                            bytes: framing.declared(),
                            packlist: magic.as_slice()
                                == mkit_core::transfer::PACKLIST_MAGIC.as_slice(),
                        });
                    }
                }
                let resp = Body::UploadPackResponse(Box::<UploadPackResponse>::default());
                send_body(sink, resp).await
            }
            Err(e) if is_digest_mismatch(&e) => {
                let message = UploadError::DigestMismatch.ssh_message();
                emit_error(sink, ErrorCode::InvalidRequest, message).await
            }
            Err(_) => emit_error(sink, ErrorCode::Internal, "upload failed").await,
        }
    }

    /// Open the upload's pack session after authorization; a refusal is
    /// recorded in `failed_open` so the stream still drains.
    async fn open_upload_session(
        &mut self,
        pack_id: Option<&[u8]>,
        total: Option<u64>,
        failed_open: &mut Option<VerbError>,
    ) -> Option<UploadSession<'p, B, N, H>> {
        match self.auth(Procedure::UploadPack) {
            Ok(a) => match self.pipe.open_upload(&a, pack_id, total).await {
                Ok(s) => Some(s),
                Err(e) => {
                    *failed_open = upload_open_error(&e);
                    None
                }
            },
            Err(e) => {
                *failed_open = upload_open_error(&e);
                None
            }
        }
    }
}

/// Discard an upload's pack sink, if one is open.
async fn abort<B: MultipartBlobStore, N: NamespaceStore, H: HookSet>(
    session: Option<UploadSession<'_, B, N, H>>,
) {
    if let Some(session) = session {
        session.abort().await;
    }
}
