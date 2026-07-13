// SPDX-License-Identifier: MIT OR Apache-2.0
//
// TransportService implementation.
//
//   PackExists / UploadPack / DownloadPack -> R2 (the STORAGE bucket binding)
//   ListRefs / ReadRef / UpdateRef / AdvanceRefs -> the (single, global)
//   RefStore Durable Object (binding REFSTORE)
//
// SEND on wasm: the generated trait requires handler futures to be `+ Send`,
// but `worker` R2/DO handles wrap JS values and are `!Send`. Workers is
// single-threaded, so each block that touches a worker handle is wrapped in
// `worker::send::SendFuture` (an `unsafe impl Send` shim, sound under
// single-threaded wasm) — same pattern as apps/repo-worker.
//
// Whole-pack buffering, not incremental streaming (deliberate, see README
// "Known limitations" and SPEC-TRANSPORT-CONNECT §6.3): `UploadPack`
// accumulates the full pack in memory before one R2 put; `DownloadPack`
// reads the full pack from R2 before yielding it as a two-item
// (header, chunk) stream. This satisfies the wire contract (SPEC-TRANSPORT-
// CONNECT §6) without attempting the owned-mpsc-channel Workers streaming
// bridge, whose end-to-end delivery is explicitly flagged as an unresolved
// risk in the spec — chunked pack transfer replacing whole-pack buffering is
// out of scope for this issue (see mkit#699 "Out of Scope").

use connectrpc::{
    ConnectError, RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};
use futures::StreamExt;
use serde::Serialize;
use worker::send::SendFuture;
use worker::{Env, Method, Request as WorkerRequest, RequestInit};

use crate::hashing::pack_id_matches;
use crate::proto::mkit::transport::v1::__buffa::oneof::download_pack_response::Body as DownloadBody;
use crate::proto::mkit::transport::v1::__buffa::oneof::upload_pack_request::Body as UploadBody;
use crate::proto::mkit::transport::v1::{
    AdvanceOutcome as ProtoAdvanceOutcome, AdvanceRefsRequest, AdvanceRefsResponse,
    DownloadPackHeader, DownloadPackRequest, DownloadPackResponse, ListRefsRequest,
    ListRefsResponse, PackChunk, PackExistsRequest, PackExistsResponse, ReadRefRequest,
    ReadRefResponse, RefEntry, RefExpectation as ProtoRefExpectation, UpdateRefRequest,
    UpdateRefResponse, UploadPackRequest, UploadPackResponse,
};
use crate::refs::{is_valid_digest, is_valid_ref_name, is_valid_ref_prefix};
use crate::storage_error::StorageOp;

use super::wire::{
    AdvanceOutcome as WireAdvanceOutcome, AdvanceReq, AdvanceResp, GetReq, GetResp, ListReq,
    ListResp, UpdateReq, UpdateResp,
};

const STORAGE_BUCKET: &str = "STORAGE";
const REFSTORE_BINDING: &str = "REFSTORE";
/// The single, global RefStore DO instance name — one Worker deployment
/// serves one mkit repository (SPEC-TRANSPORT-CONNECT §7.1), unlike
/// apps/repo-worker's per-`room` instancing.
const REFSTORE_INSTANCE: &str = "root";

/// Cap on a pack's declared/observed size. This reference server buffers the
/// whole pack in memory (no incremental streaming to/from R2 — see module
/// docs), so this cap bounds worst-case isolate memory, not just wire size.
pub(crate) const MAX_PACK_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

fn ce_invalid(msg: impl Into<String>) -> ConnectError {
    ConnectError::invalid_argument(msg)
}

/// Map a failed storage/DO operation to a client-facing `ConnectError`,
/// logging the real error — which may embed R2/DO SDK detail (bucket keys,
/// JS exception text, etc.) — server-side ONLY via `console_error!`. This is
/// the single seam every R2/DO call in this file goes through instead of the
/// former `ConnectError::internal(format!("R2 put: {e}"))`-style raw leaks
/// (issue #794). See `crate::storage_error` for the exhaustive
/// `StorageOp -> message` mapping (host-testable there) that this just logs
/// through.
fn ce_storage(op: StorageOp, e: impl std::fmt::Display) -> ConnectError {
    let (log_line, client_err) = crate::storage_error::describe_and_map(op, e);
    worker::console_error!("{log_line}");
    client_err
}

/// R2 object key for a pack: `packs/{hex(pack_id)}`.
fn pack_key(pack_id: &[u8]) -> String {
    format!("packs/{}", hex::encode(pack_id))
}

/// Content-addressed, idempotent R2 store. A conditional put with
/// `If-None-Match: *` writes the bytes only when `key` is absent; the key IS
/// the content hash, so a re-put of identical bytes is a harmless no-op.
async fn put_addressed(env: &Env, key: &str, bytes: Vec<u8>) -> Result<(), ConnectError> {
    let bucket = env
        .bucket(STORAGE_BUCKET)
        .map_err(|e| ce_storage(StorageOp::StorageBinding, e))?;
    bucket
        .put(key, bytes)
        .only_if(worker::Conditional {
            etag_does_not_match: Some("*".to_string()),
            ..Default::default()
        })
        .execute()
        .await
        .map_err(|e| ce_storage(StorageOp::R2Put, e))?;
    Ok(())
}

/// Issue a JSON POST to the RefStore DO and decode the response.
async fn do_call<Req: Serialize, Resp: serde::de::DeserializeOwned>(
    env: &Env,
    op: &str,
    body: &Req,
) -> Result<Resp, ConnectError> {
    let payload =
        serde_json::to_string(body).map_err(|e| ce_storage(StorageOp::RequestSerialize, e))?;
    let ns = env
        .durable_object(REFSTORE_BINDING)
        .map_err(|e| ce_storage(StorageOp::RefstoreBinding, e))?;
    let stub = ns
        .id_from_name(REFSTORE_INSTANCE)
        .and_then(|id| id.get_stub())
        .map_err(|e| ce_storage(StorageOp::RefstoreStub, e))?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(payload.into()));
    let req = WorkerRequest::new_with_init(&format!("https://refstore{op}"), &init)
        .map_err(|e| ce_storage(StorageOp::RefstoreRequest, e))?;

    let mut resp = stub
        .fetch_with_request(req)
        .await
        .map_err(|e| ce_storage(StorageOp::RefstoreFetch, e))?;

    if resp.status_code() >= 400 {
        let msg = resp.text().await.unwrap_or_default();
        return Err(ce_invalid(format!("refstore {op}: {msg}")));
    }
    resp.json::<Resp>()
        .await
        .map_err(|e| ce_storage(StorageOp::RefstoreDecode, e))
}

fn hex_to_bytes_opt(s: &Option<String>) -> Option<Vec<u8>> {
    s.as_ref().and_then(|s| hex::decode(s).ok())
}

/// `expected_id` -> the DO wire's `Option<hex>` (empty bytes = None, matching
/// ANY/MISSING's "expected_id MUST be empty" contract).
fn expected_hex(expected_id: &[u8]) -> Option<String> {
    if expected_id.is_empty() {
        None
    } else {
        Some(hex::encode(expected_id))
    }
}

pub struct TransportServer {
    env: Env,
}

impl TransportServer {
    pub fn new(env: Env) -> Self {
        Self { env }
    }
}

#[allow(refining_impl_trait)]
impl crate::proto::mkit::transport::v1::TransportService for TransportServer {
    async fn list_refs(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ListRefsRequest>,
    ) -> ServiceResult<ListRefsResponse> {
        let msg = request.to_owned_message();
        let prefix = msg.prefix.unwrap_or_default();
        if !is_valid_ref_prefix(&prefix) {
            return Err(ce_invalid("prefix is invalid (SPEC-REFS §3)"));
        }

        let env = self.env.clone();
        SendFuture::new(async move {
            // `do_call` needs an owned `prefix` for the wire request; keep a
            // second owned copy to strip off each returned name below (the
            // DO's `/list` returns full paths — see `RefStore::list` — and
            // `mkit_core::protocol::Transport::list_refs`'s contract requires
            // "returned names have `prefix` stripped" (SPEC-REFS §4). Every
            // native `Transport` impl (file/s3/ssh/memory) honors this; the
            // real `mkit-cli` fetch/pull/clone path
            // (`remote_dispatch::fetch_objects_inner`) relies on it to
            // compute each branch's packmap ref name
            // (`refs/mkit/packmap/<bare-branch>`) from the LISTED name —
            // returning the untouched full path there silently breaks that
            // lookup (`packmap_ref("refs/heads/main")` != the real
            // `refs/mkit/packmap/main`), surfacing as "no pack map to
            // reconstruct it" on `mkit clone`/`fetch`/`pull`, not as an
            // auth or wire-shape error.
            let prefix_for_strip = prefix.clone();
            let resp: ListResp = do_call(&env, "/list", &ListReq { prefix }).await?;
            let refs = resp
                .refs
                .into_iter()
                .map(|e| RefEntry {
                    name: Some(
                        e.name
                            .strip_prefix(prefix_for_strip.as_str())
                            .unwrap_or(&e.name)
                            .to_owned(),
                    ),
                    object_id: Some(hex::decode(&e.value).unwrap_or_default()),
                    ..Default::default()
                })
                .collect();
            Ok(Response::new(ListRefsResponse {
                refs,
                ..Default::default()
            }))
        })
        .await
    }

    async fn read_ref(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ReadRefRequest>,
    ) -> ServiceResult<ReadRefResponse> {
        let msg = request.to_owned_message();
        let name = msg.name.unwrap_or_default();
        if !is_valid_ref_name(&name) {
            return Err(ce_invalid("ref name is invalid (SPEC-REFS §3)"));
        }

        let env = self.env.clone();
        SendFuture::new(async move {
            let resp: GetResp = do_call(&env, "/get", &GetReq { name }).await?;
            let object_id = hex_to_bytes_opt(&resp.value).unwrap_or_default();
            Ok(Response::new(ReadRefResponse {
                exists: Some(resp.exists),
                object_id: Some(object_id),
                ..Default::default()
            }))
        })
        .await
    }

    async fn update_ref(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, UpdateRefRequest>,
    ) -> ServiceResult<UpdateRefResponse> {
        let msg = request.to_owned_message();
        let name = msg.name.unwrap_or_default();
        let new_id = msg.new_id.unwrap_or_default();
        let expectation = msg.expectation.map(|e| e.to_i32()).unwrap_or(0);
        let expected_id = msg.expected_id.unwrap_or_default();

        if !is_valid_ref_name(&name) {
            return Err(ce_invalid("ref name is invalid (SPEC-REFS §3)"));
        }
        if expectation == ProtoRefExpectation::REF_EXPECTATION_UNSPECIFIED as i32 {
            return Err(ce_invalid("expectation is UNSPECIFIED (protocol error)"));
        }
        if !is_valid_digest(&new_id) {
            return Err(ce_invalid("new_id must be 32 bytes"));
        }

        let env = self.env.clone();
        SendFuture::new(async move {
            let body = UpdateReq {
                name,
                new: hex::encode(&new_id),
                expectation,
                expected: expected_hex(&expected_id),
            };
            let resp: UpdateResp = do_call(&env, "/update", &body).await?;
            if resp.conflict {
                return Err(ConnectError::failed_precondition(
                    "ref CAS precondition failed — read_ref to disambiguate",
                ));
            }
            Ok(Response::new(UpdateRefResponse::default()))
        })
        .await
    }

    async fn advance_refs(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, AdvanceRefsRequest>,
    ) -> ServiceResult<AdvanceRefsResponse> {
        let msg = request.to_owned_message();
        let head_ref = msg.head_ref.unwrap_or_default();
        let head_expectation = msg.head_expectation.map(|e| e.to_i32()).unwrap_or(0);
        let head_expected_id = msg.head_expected_id.unwrap_or_default();
        let head_new_id = msg.head_new_id.unwrap_or_default();
        let packmap_ref = msg.packmap_ref.unwrap_or_default();
        let packmap_expectation = msg.packmap_expectation.map(|e| e.to_i32()).unwrap_or(0);
        let packmap_expected_id = msg.packmap_expected_id.unwrap_or_default();
        let packmap_new_id = msg.packmap_new_id.unwrap_or_default();

        for name in [&head_ref, &packmap_ref] {
            if !is_valid_ref_name(name) {
                return Err(ce_invalid("ref name is invalid (SPEC-REFS §3)"));
            }
        }
        let unspecified = ProtoRefExpectation::REF_EXPECTATION_UNSPECIFIED as i32;
        if head_expectation == unspecified || packmap_expectation == unspecified {
            return Err(ce_invalid("expectation is UNSPECIFIED (protocol error)"));
        }
        for id in [&head_new_id, &packmap_new_id] {
            if !is_valid_digest(id) {
                return Err(ce_invalid("new_id must be 32 bytes"));
            }
        }

        let env = self.env.clone();
        SendFuture::new(async move {
            let body = AdvanceReq {
                head_ref,
                head_expectation,
                head_expected: expected_hex(&head_expected_id),
                head_new: hex::encode(&head_new_id),
                packmap_ref,
                packmap_expectation,
                packmap_expected: expected_hex(&packmap_expected_id),
                packmap_new: hex::encode(&packmap_new_id),
            };
            let resp: AdvanceResp = do_call(&env, "/advance", &body).await?;
            let outcome = match resp.outcome {
                WireAdvanceOutcome::Committed => ProtoAdvanceOutcome::ADVANCE_OUTCOME_COMMITTED,
                WireAdvanceOutcome::HeadConflict => {
                    ProtoAdvanceOutcome::ADVANCE_OUTCOME_HEAD_CONFLICT
                }
                WireAdvanceOutcome::PackmapConflict => {
                    ProtoAdvanceOutcome::ADVANCE_OUTCOME_PACKMAP_CONFLICT
                }
            };
            Ok(Response::new(AdvanceRefsResponse {
                outcome: Some(outcome.into()),
                ..Default::default()
            }))
        })
        .await
    }

    async fn pack_exists(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, PackExistsRequest>,
    ) -> ServiceResult<PackExistsResponse> {
        let msg = request.to_owned_message();
        let pack_id = msg.pack_id.unwrap_or_default();
        if !is_valid_digest(&pack_id) {
            return Err(ce_invalid("pack_id must be 32 bytes"));
        }

        let env = self.env.clone();
        SendFuture::new(async move {
            let bucket = env
                .bucket(STORAGE_BUCKET)
                .map_err(|e| ce_storage(StorageOp::StorageBinding, e))?;
            let exists = bucket
                .head(pack_key(&pack_id))
                .await
                .map_err(|e| ce_storage(StorageOp::R2Head, e))?
                .is_some();
            Ok(Response::new(PackExistsResponse {
                exists: Some(exists),
                ..Default::default()
            }))
        })
        .await
    }

    async fn upload_pack(
        &self,
        _ctx: RequestContext,
        mut requests: ::connectrpc::InboundStream<UploadPackRequest>,
    ) -> ServiceResult<UploadPackResponse> {
        // 1) First message MUST be `header` (SPEC-TRANSPORT-CONNECT §6.1).
        let first = requests
            .next()
            .await
            .ok_or_else(|| ce_invalid("UploadPack stream ended before a header message"))??;
        let Some(UploadBody::Header(header)) = first.to_owned_message().body else {
            return Err(ce_invalid("first UploadPack message MUST be `header`"));
        };
        let pack_id = header.pack_id.unwrap_or_default();
        let total_bytes = header.total_bytes.unwrap_or(0);
        if !is_valid_digest(&pack_id) {
            return Err(ce_invalid("header.pack_id must be 32 bytes"));
        }
        if total_bytes as usize > MAX_PACK_BYTES {
            return Err(ConnectError::resource_exhausted(format!(
                "declared pack size {total_bytes} exceeds the {MAX_PACK_BYTES}-byte cap"
            )));
        }

        // 2) Chunks, in ascending contiguous offset order, ending with `last`.
        let mut received: Vec<u8> = Vec::with_capacity(total_bytes as usize);
        let mut saw_last = false;
        while let Some(item) = requests.next().await {
            let item = item?;
            let Some(UploadBody::Chunk(chunk)) = item.to_owned_message().body else {
                return Err(ce_invalid(
                    "UploadPack message after `header` MUST be `chunk`",
                ));
            };
            let chunk_pack_id = chunk.pack_id.unwrap_or_default();
            if chunk_pack_id != pack_id {
                return Err(ce_invalid("chunk.pack_id does not match header.pack_id"));
            }
            let offset = chunk.offset.unwrap_or(0);
            if offset != received.len() as u64 {
                return Err(ce_invalid(
                    "chunk.offset is not the next expected byte offset",
                ));
            }
            let data = chunk.data.unwrap_or_default();
            if received.len() + data.len() > MAX_PACK_BYTES {
                return Err(ConnectError::resource_exhausted(format!(
                    "pack exceeds the {MAX_PACK_BYTES}-byte cap"
                )));
            }
            received.extend_from_slice(&data);
            if chunk.last.unwrap_or(false) {
                saw_last = true;
                break;
            }
        }
        if !saw_last {
            return Err(ce_invalid(
                "UploadPack stream ended without a `last = true` chunk",
            ));
        }

        // 3) Verify the declared shape against what was actually received.
        if received.len() as u64 != total_bytes {
            return Err(ce_invalid(
                "received byte count does not equal header.total_bytes",
            ));
        }
        if !pack_id_matches(&received, &pack_id) {
            return Err(ce_invalid(
                "BLAKE3(received bytes) does not equal header.pack_id",
            ));
        }

        let env = self.env.clone();
        SendFuture::new(async move {
            put_addressed(&env, &pack_key(&pack_id), received).await?;
            Ok(Response::new(UploadPackResponse::default()))
        })
        .await
    }

    async fn download_pack(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, DownloadPackRequest>,
    ) -> ServiceResult<ServiceStream<DownloadPackResponse>> {
        let msg = request.to_owned_message();
        let pack_id = msg.pack_id.unwrap_or_default();
        if !is_valid_digest(&pack_id) {
            return Err(ce_invalid("pack_id must be 32 bytes"));
        }

        let env = self.env.clone();
        let key = pack_key(&pack_id);
        let bytes = SendFuture::new(async move {
            let bucket = env
                .bucket(STORAGE_BUCKET)
                .map_err(|e| ce_storage(StorageOp::StorageBinding, e))?;
            match bucket.get(key).execute().await {
                Ok(Some(obj)) => {
                    let bytes = obj
                        .body()
                        .ok_or_else(|| ce_storage(StorageOp::R2Read, "missing body"))?
                        .bytes()
                        .await
                        .map_err(|e| ce_storage(StorageOp::R2Read, e))?;
                    Ok(bytes)
                }
                Ok(None) => Err(ConnectError::not_found("pack not found")),
                Err(e) => Err(ce_storage(StorageOp::R2Get, e)),
            }
        })
        .await?;

        // Whole-pack buffering (see module docs): the data is already fully
        // materialized here (an owned `Vec<u8>`, no borrowed R2/DO handle),
        // so a plain `futures::stream::iter` trivially satisfies the
        // generated trait's `'static + Send` bound — no owned-mpsc-channel
        // bridge needed for this reference server's degenerate two-item
        // stream (one header, one chunk carrying the whole pack).
        let total_bytes = bytes.len() as u64;
        let header = DownloadPackResponse {
            body: Some(DownloadBody::Header(Box::new(DownloadPackHeader {
                total_bytes: Some(total_bytes),
                ..Default::default()
            }))),
            ..Default::default()
        };
        let chunk = DownloadPackResponse {
            body: Some(DownloadBody::Chunk(Box::new(PackChunk {
                pack_id: Some(pack_id),
                offset: Some(0),
                data: Some(bytes),
                last: Some(true),
                ..Default::default()
            }))),
            ..Default::default()
        };
        Response::stream_ok(futures::stream::iter([Ok(header), Ok(chunk)]))
    }
}
