// SPDX-License-Identifier: MIT OR Apache-2.0
//
// RepoService implementation.
//
//   PutObject / GetObject  -> R2 (the STORAGE bucket binding)
//   GetRef / UpdateRef / ListRefs / WatchRefs -> the per-room RefStore DO
//
// SEND on wasm: the generated trait requires handler futures to be `+ Send`,
// but `worker` R2/DO handles wrap JS values and are `!Send`. Workers is
// single-threaded, so we wrap each I/O block in `worker::send::SendFuture`
// (an `unsafe impl Send` shim that's sound under single-threaded wasm) to
// satisfy the bound. `worker::Env` is itself `unsafe impl Send + Sync`, so it
// lives in the service struct.

use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream};
use serde::Serialize;
use worker::send::SendFuture;
use worker::{Env, Method, Request as WorkerRequest, RequestInit};

use super::auth::AuthorPubkey;
use crate::hashing::object_id_matches;
use crate::refs::{is_valid_ref_name, is_valid_ref_prefix, is_valid_room};
use crate::proto::mkit::repo::v1::{
    GetObjectRequest, GetObjectResponse, GetRefRequest, GetRefResponse, ListRefsRequest,
    ListRefsResponse, PutObjectRequest, PutObjectResponse, RefEntry, RefEvent, UpdateRefRequest,
    UpdateRefResponse, WatchRefsRequest,
};
use super::refstore::RefEventJson;

const STORAGE_BUCKET: &str = "STORAGE";
const REFSTORE_BINDING: &str = "REFSTORE";

/// PutObject `bytes` cap (mirrors the worker-level body cap in worker_impl.rs).
const MAX_PUT_BYTES: usize = 8 * 1024 * 1024; // 8 MiB

pub struct RepoServer {
    env: Env,
}

impl RepoServer {
    pub fn new(env: Env) -> Self {
        Self { env }
    }
}

// --- helpers ---------------------------------------------------------------

fn ce_internal(msg: impl Into<String>) -> connectrpc::ConnectError {
    connectrpc::ConnectError::internal(msg)
}
fn ce_invalid(msg: impl Into<String>) -> connectrpc::ConnectError {
    connectrpc::ConnectError::invalid_argument(msg)
}

/// Reject an empty or malformed `room` with `invalid_argument`. Every handler
/// validates the room before touching R2 or the DO (the room is an unescaped
/// key prefix / DO instance name).
fn check_room(room: &str) -> Result<(), connectrpc::ConnectError> {
    if is_valid_room(room) {
        Ok(())
    } else {
        Err(ce_invalid("room is empty or invalid (^[A-Za-z0-9._-]{1,64}$)"))
    }
}

/// R2 object key for a loose object: `{room}/objects/{hex(object_id)}`.
fn object_key(room: &str, object_id: &[u8]) -> String {
    format!("{room}/objects/{}", hex::encode(object_id))
}

/// Issue a JSON POST to the room's RefStore DO and decode the response.
async fn do_call<Req: Serialize, Resp: serde::de::DeserializeOwned>(
    env: &Env,
    room: &str,
    op: &str,
    body: &Req,
) -> Result<Resp, connectrpc::ConnectError> {
    let payload = serde_json::to_string(body).map_err(|e| ce_internal(e.to_string()))?;
    let ns = env
        .durable_object(REFSTORE_BINDING)
        .map_err(|e| ce_internal(format!("REFSTORE binding: {e}")))?;
    let stub = ns
        .id_from_name(room)
        .and_then(|id| id.get_stub())
        .map_err(|e| ce_internal(format!("REFSTORE stub: {e}")))?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_body(Some(payload.into()));
    let req = WorkerRequest::new_with_init(&format!("https://refstore{op}"), &init)
        .map_err(|e| ce_internal(e.to_string()))?;

    let mut resp = stub
        .fetch_with_request(req)
        .await
        .map_err(|e| ce_internal(format!("REFSTORE fetch: {e}")))?;

    if resp.status_code() >= 400 {
        let msg = resp.text().await.unwrap_or_default();
        return Err(ce_invalid(format!("refstore {op}: {msg}")));
    }
    resp.json::<Resp>()
        .await
        .map_err(|e| ce_internal(format!("refstore decode: {e}")))
}

// --- DO wire types (mirror refstore.rs) ------------------------------------

#[derive(Serialize)]
struct GetReq<'a> {
    name: &'a str,
}
#[derive(serde::Deserialize)]
struct GetResp {
    exists: bool,
    value: Option<String>,
}
#[derive(Serialize)]
struct UpdateReq<'a> {
    name: &'a str,
    new: String,
    expectation: i32,
    expected: Option<String>,
    author: Option<String>,
}
#[derive(serde::Deserialize)]
struct UpdateResp {
    committed: bool,
    conflict: bool,
    current: Option<String>,
}
#[derive(Serialize)]
struct ListReq<'a> {
    prefix: &'a str,
}
#[derive(serde::Deserialize)]
struct ListResp {
    refs: Vec<ListEntry>,
}
#[derive(serde::Deserialize)]
struct ListEntry {
    name: String,
    value: String,
}

fn hex_to_bytes_opt(s: &Option<String>) -> Option<Vec<u8>> {
    s.as_ref().and_then(|s| hex::decode(s).ok())
}

// --- the RepoService trait impl --------------------------------------------

impl crate::proto::mkit::repo::v1::RepoService for RepoServer {
    async fn put_object(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, PutObjectRequest>,
    ) -> ServiceResult<PutObjectResponse> {
        let msg = request.to_owned_message();
        let room = msg.room.unwrap_or_default();
        let object_id = msg.object_id.unwrap_or_default();
        let bytes = msg.bytes.unwrap_or_default();

        check_room(&room)?;
        if bytes.len() > MAX_PUT_BYTES {
            return Err(ce_invalid("object bytes exceed the size cap"));
        }
        if object_id.len() != 32 {
            return Err(ce_invalid("object_id must be 32 bytes"));
        }
        // Content-addressing: the server MUST verify BLAKE3(bytes)==object_id.
        if !object_id_matches(&bytes, &object_id) {
            return Err(ce_invalid("object_id does not match BLAKE3(bytes)"));
        }

        let env = self.env.clone();
        SendFuture::new(async move {
            let bucket = env
                .bucket(STORAGE_BUCKET)
                .map_err(|e| ce_internal(format!("STORAGE binding: {e}")))?;
            let key = object_key(&room, &object_id);

            // Idempotent store in ONE round-trip: a conditional put with
            // `If-None-Match: *` (etag_does_not_match = "*") writes only when
            // the key is absent. This drops the prior head()+put() (two R2
            // round-trips) for the common commit-push latency. Safe because
            // the key IS the content hash — a re-put of identical bytes is
            // harmless either way, and we already verified BLAKE3(bytes)==id.
            //
            // execute() returns Ok(Some(_)) when it stored (key was absent)
            // and Ok(None) when the condition failed (key already present),
            // so we still report `duplicate` accurately without the head.
            let stored = bucket
                .put(&key, bytes)
                .only_if(worker::Conditional {
                    etag_does_not_match: Some("*".to_string()),
                    ..Default::default()
                })
                .execute()
                .await
                .map_err(|e| ce_internal(format!("R2 put: {e}")))?
                .is_some();
            Ok(Response::new(PutObjectResponse {
                stored: Some(stored),
                duplicate: Some(!stored),
                ..Default::default()
            }))
        })
        .await
    }

    async fn get_object(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetObjectRequest>,
    ) -> ServiceResult<GetObjectResponse> {
        let msg = request.to_owned_message();
        let room = msg.room.unwrap_or_default();
        let object_id = msg.object_id.unwrap_or_default();

        check_room(&room)?;

        let env = self.env.clone();
        SendFuture::new(async move {
            let bucket = env
                .bucket(STORAGE_BUCKET)
                .map_err(|e| ce_internal(format!("STORAGE binding: {e}")))?;
            let key = object_key(&room, &object_id);
            match bucket.get(&key).execute().await {
                Ok(Some(obj)) => {
                    let bytes = obj
                        .body()
                        .ok_or_else(|| ce_internal("R2 object had no body"))?
                        .bytes()
                        .await
                        .map_err(|e| ce_internal(format!("R2 read: {e}")))?;
                    Ok(Response::new(GetObjectResponse {
                        found: Some(true),
                        bytes: Some(bytes),
                        ..Default::default()
                    }))
                }
                Ok(None) => Ok(Response::new(GetObjectResponse {
                    found: Some(false),
                    bytes: Some(Vec::new()),
                    ..Default::default()
                })),
                Err(e) => Err(ce_internal(format!("R2 get: {e}"))),
            }
        })
        .await
    }

    async fn get_ref(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetRefRequest>,
    ) -> ServiceResult<GetRefResponse> {
        let msg = request.to_owned_message();
        let room = msg.room.unwrap_or_default();
        let name = msg.name.unwrap_or_default();

        check_room(&room)?;
        if !is_valid_ref_name(&name) {
            return Err(ce_invalid("ref name is invalid (SPEC-REFS §3)"));
        }

        let env = self.env.clone();
        SendFuture::new(async move {
            let resp: GetResp = do_call(&env, &room, "/get", &GetReq { name: &name }).await?;
            let object_id = hex_to_bytes_opt(&resp.value).unwrap_or_default();
            Ok(Response::new(GetRefResponse {
                exists: Some(resp.exists),
                object_id: Some(object_id),
                ..Default::default()
            }))
        })
        .await
    }

    async fn update_ref(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateRefRequest>,
    ) -> ServiceResult<UpdateRefResponse> {
        let msg = request.to_owned_message();
        let room = msg.room.unwrap_or_default();
        let name = msg.name.unwrap_or_default();
        let new_id = msg.new_id.unwrap_or_default();
        // EnumValue<RefExpectation> -> its raw proto wire number.
        let expectation = msg.expectation.map(|e| e.to_i32()).unwrap_or(0);
        let expected_id = msg.expected_id.unwrap_or_default();

        check_room(&room)?;
        if !is_valid_ref_name(&name) {
            return Err(ce_invalid("ref name is invalid (SPEC-REFS §3)"));
        }
        if new_id.len() != 32 {
            return Err(ce_invalid("new_id must be 32 bytes"));
        }

        // The verified writer pubkey stashed by the auth interceptor.
        let author = ctx
            .extensions()
            .get::<AuthorPubkey>()
            .map(|a| a.0.clone());

        let env = self.env.clone();
        SendFuture::new(async move {
            let body = UpdateReq {
                name: &name,
                new: hex::encode(&new_id),
                expectation,
                expected: if expected_id.is_empty() {
                    None
                } else {
                    Some(hex::encode(&expected_id))
                },
                author,
            };
            let resp: UpdateResp = do_call(&env, &room, "/update", &body).await?;
            let current = hex_to_bytes_opt(&resp.current).unwrap_or_default();
            Ok(Response::new(UpdateRefResponse {
                committed: Some(resp.committed),
                conflict: Some(resp.conflict),
                current_id: Some(current),
                ..Default::default()
            }))
        })
        .await
    }

    async fn list_refs(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ListRefsRequest>,
    ) -> ServiceResult<ListRefsResponse> {
        let msg = request.to_owned_message();
        let room = msg.room.unwrap_or_default();
        let prefix = msg.prefix.unwrap_or_default();

        check_room(&room)?;
        if !is_valid_ref_prefix(&prefix) {
            return Err(ce_invalid("prefix is invalid (SPEC-REFS §3)"));
        }

        let env = self.env.clone();
        SendFuture::new(async move {
            let resp: ListResp =
                do_call(&env, &room, "/list", &ListReq { prefix: &prefix }).await?;
            let refs = resp
                .refs
                .into_iter()
                .map(|e| RefEntry {
                    name: Some(e.name),
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

    async fn watch_refs(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, WatchRefsRequest>,
    ) -> ServiceResult<ServiceStream<RefEvent>> {
        // FALLBACK (documented): live ref streaming is served over a raw
        // WebSocket at the worker route `GET /watch/<room>`, NOT over Connect
        // server-streaming.
        //
        // Why: the worker `WebSocket::events()` stream is `EventStream<'ws>` —
        // it borrows the WebSocket — so it cannot be boxed into the `'static +
        // Send` `ServiceStream<RefEvent>` the generated trait requires without
        // a self-referential owner. Rather than let this block the unary path
        // (PutObject/GetObject/GetRef/UpdateRef/ListRefs all work), WatchRefs
        // over Connect returns `unimplemented` and points clients at the
        // WebSocket route, which is fully wired: the RefStore DO broadcasts a
        // JSON RefEvent frame to every `/watch` subscriber on each successful
        // UpdateRef. See README "WatchRefs / streaming".
        let _ = (REFSTORE_BINDING, std::marker::PhantomData::<RefEventJson>);
        Err(connectrpc::ConnectError::unimplemented(
            "WatchRefs is served over the WebSocket route GET /watch/<room>, \
             not Connect server-streaming (see README)",
        ))
    }
}
