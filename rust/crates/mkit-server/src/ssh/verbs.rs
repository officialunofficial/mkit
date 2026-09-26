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
//! | `ReadRef` | any other | `INTERNAL "read ref failed"` |
//! | `UpdateRef` | a name over 512 bytes | `INVALID_REQUEST "ref name too long"` |
//! | `UpdateRef` | a CAS conflict | [`cas_conflict_body`] |
//! | `UpdateRef` | any other | `INVALID_REQUEST "update ref failed"` |
//! | `ListRefs` | any | `INTERNAL "list refs failed"` |
//! | `DownloadPack` | any, before the header | `KEY_NOT_FOUND "pack not found"` |
//! | `DownloadPack` | a body read, after the header | `INTERNAL "pack read failed"` |
//! | `UploadPack` | bytes that do not hash to `pack_id` | `INVALID_REQUEST`, [`UploadError::ssh_message`] |
//! | `UploadPack` | any other | `INTERNAL "upload failed"` |
//!
//! Two rows are new. A mid-download read failure cannot happen in
//! `mkit serve`, which reads the whole pack before its header. And
//! `mkit serve` had no ref-name length limit; SPEC-REFS §3 now caps names at
//! 512 bytes (`refs::MAX_REF_NAME_BYTES`), and an over-long name is refused
//! by name rather than failing like a storage error.

use core::future::poll_fn;

use bytes::Bytes;
use mkit_core::hash::Hash;
use mkit_core::protocol::PackKey;
use mkit_rpc::mkit::common::v1::RefEntry;
use mkit_rpc::mkit::rpc::v1::ssh::{
    DownloadPack, DownloadPackHeader, ListRefsResponse, PackChunk, PackExistsResponse,
    ReadRefResponse, UpdateRef, UploadPack, UploadPackResponse, ssh_frame,
};
use mkit_rpc::mkit::rpc::v1::{Error as RpcError, ErrorCode};

use super::session::{FrameIoError, FrameSink, FrameSource, Stop, emit_error, send_body};
use crate::error::ServerError;
use crate::op::{Procedure, RefUpdate};
use crate::pipeline::{Authenticated, HookSet, Pipeline, RequestMeta, UploadSession};
use crate::principal::Principal;
use crate::refs::{
    DigestField, MAX_REF_NAME_BYTES, REF_NAME_TOO_LONG, RefWireError, UnusedExpectedId,
    condition_from_wire, hash_from_slice,
};
use crate::store::{BlobStore, NamespaceStore};
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
        new,
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

/// Refuse a ref name over [`MAX_REF_NAME_BYTES`] by name (SPEC-REFS §3).
fn check_name_len(name: &str) -> Result<(), VerbError> {
    if name.len() > MAX_REF_NAME_BYTES {
        Err((ErrorCode::InvalidRequest, REF_NAME_TOO_LONG))
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

/// The verbs of one session: its pipeline and the principal every verb
/// runs as.
pub(super) struct Verbs<'p, B, N, H> {
    pipe: &'p Pipeline<B, N, H>,
    principal: Principal,
}

impl<'p, B: BlobStore, N: NamespaceStore, H: HookSet> Verbs<'p, B, N, H> {
    pub(super) fn new(pipe: &'p Pipeline<B, N, H>, principal: Principal) -> Self {
        Self { pipe, principal }
    }

    /// Stage 0 for `procedure`: the transport's principal, no headers.
    fn auth(&self, procedure: Procedure) -> Result<Authenticated, ServerError> {
        let no_headers = |_: &str| -> Option<String> { None };
        self.pipe.authenticate(&RequestMeta {
            procedure,
            header: &no_headers,
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
        &self,
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
    pub(super) async fn simple(&self, body: &Body) -> Option<Result<Body, VerbError>> {
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
                if let Err(e) = check_name_len(&name) {
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
                if let Err(e) = check_name_len(&update.name) {
                    return Some(Err(e));
                }
                let result = match self.auth(Procedure::UpdateRef) {
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
                    Err(_) => Err((ErrorCode::InvalidRequest, "update ref failed")),
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
        &self,
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
        let mut session = match self.auth(Procedure::UploadPack) {
            Ok(a) => self.pipe.begin_upload(&a, pack_id, total).await.ok(),
            Err(_) => None,
        };
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
        let finished = match session {
            Some(s) => s.finish().await,
            None => return emit_error(sink, ErrorCode::Internal, "upload failed").await,
        };
        match finished {
            Ok(()) => {
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
}

/// Discard an upload's pack sink, if one is open.
async fn abort<B: BlobStore, N: NamespaceStore, H: HookSet>(
    session: Option<UploadSession<'_, B, N, H>>,
) {
    if let Some(session) = session {
        session.abort().await;
    }
}
