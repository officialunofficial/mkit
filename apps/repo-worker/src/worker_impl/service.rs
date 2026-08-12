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
use futures_util::StreamExt;
use serde::Serialize;
use worker::send::SendFuture;
use worker::{Env, Method, Request as WorkerRequest, RequestInit, WebSocket, WebsocketEvent};

use super::auth::{AuthorPubkey, IdempotencyKey};
use super::wire::{
    CommitMetaWire, CommitRowWire, GetReq, GetResp, ListCommitsReq, ListCommitsResp, ListReq,
    ListResp, MessagesReq, MessagesResp, PostReq, PostResp, PurgeResp, ReactReq, ReactResp,
    ReactionsResp, RecordCommitsReq, RecordCommitsResp, UpdateReq, UpdateResp,
};
use crate::hashing::object_id_matches;
use crate::proto::mkit::common::v1::RefEntry;
use crate::proto::mkit::repo::v1::{
    ChatMessage, CommitEntry, GetObjectRequest, GetObjectResponse, GetRefRequest, GetRefResponse,
    ListCommitsRequest, ListCommitsResponse, ListMessagesRequest, ListMessagesResponse,
    ListReactionsRequest, ListReactionsResponse, ListRefsRequest, ListRefsResponse,
    PostMessageRequest, PostMessageResponse, PurgeRoomRequest, PurgeRoomResponse, PutObjectRequest,
    PutObjectResponse, ReactRequest, ReactResponse, Reaction, RoomEvent, UpdateRefRequest,
    UpdateRefResponse, WatchRefsRequest,
};
use crate::refs::{
    is_valid_expected_id_len, is_valid_ref_name, is_valid_ref_prefix, is_valid_room,
};
use crate::room_event;
use crate::storage_error::StorageOp;
use std::collections::HashSet;

/// `pub(crate)`: reused by `super::health`'s cheap R2 reachability probe
/// (mkit#796) so the health checker addresses the SAME bucket binding this
/// service does, rather than a second hand-copied literal.
pub(crate) const STORAGE_BUCKET: &str = "STORAGE";
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

fn ce_invalid(msg: impl Into<String>) -> connectrpc::ConnectError {
    connectrpc::ConnectError::invalid_argument(msg)
}

/// Map a failed storage/DO operation to a client-facing `ConnectError`,
/// logging the real error — which may embed R2/DO SDK detail (bucket keys,
/// JS exception text, etc.) — server-side ONLY via `console_error!`. This is
/// the single seam every R2/DO call in this file goes through instead of the
/// former `ConnectError::internal(format!("R2 put: {e}"))`-style raw leaks
/// (issue #794).
/// See `crate::storage_error` for the exhaustive `StorageOp -> message`
/// mapping (host-testable there) that this just logs through.
fn ce_storage(op: StorageOp, e: impl std::fmt::Display) -> connectrpc::ConnectError {
    let (log_line, client_err) = crate::storage_error::describe_and_map(op, e);
    worker::console_error!("{log_line}");
    client_err
}

/// Reject an empty or malformed `room` with `invalid_argument`. Every handler
/// validates the room before touching R2 or the DO (the room is an unescaped
/// key prefix / DO instance name).
fn check_room(room: &str) -> Result<(), connectrpc::ConnectError> {
    if is_valid_room(room) {
        Ok(())
    } else {
        Err(ce_invalid(
            "room is empty or invalid (^[A-Za-z0-9._-]{1,64}$)",
        ))
    }
}

/// R2 object key for a loose object: `{room}/objects/{hex(object_id)}`.
fn object_key(room: &str, object_id: &[u8]) -> String {
    format!("{room}/objects/{}", hex::encode(object_id))
}

/// R2 key for a chat message: `{room}/messages/{hex(message_id)}`. A SEPARATE
/// namespace from `objects/` so a chat id can never collide with — or be decoded
/// as — an mkit object via GetObject (chat bytes are `mkit-chat:v1\n…`, not a
/// decodable commit/tree/blob).
fn message_key(room: &str, id: &[u8]) -> String {
    format!("{room}/messages/{}", hex::encode(id))
}

/// Content-addressed, idempotent R2 store. A conditional put with
/// `If-None-Match: *` writes the bytes only when `key` is absent; the key IS the
/// content hash, so a re-put of identical bytes is a harmless no-op. Returns
/// true when this call wrote (key was absent), false when it already existed.
/// Shared by PutObject and PostMessage so the idempotent-store contract lives in
/// ONE place.
async fn put_addressed(
    env: &Env,
    key: &str,
    bytes: Vec<u8>,
) -> Result<bool, connectrpc::ConnectError> {
    let bucket = env
        .bucket(STORAGE_BUCKET)
        .map_err(|e| ce_storage(StorageOp::StorageBinding, e))?;
    let stored = bucket
        .put(key, bytes)
        .only_if(worker::Conditional {
            etag_does_not_match: Some("*".to_string()),
            ..Default::default()
        })
        .execute()
        .await
        .map_err(|e| ce_storage(StorageOp::R2Put, e))?
        .is_some();
    Ok(stored)
}

/// Read the just-pushed object from R2 and decode its commit metadata into the
/// DO-index wire shape — so a ref update can dual-write the `commits` index.
/// `None` on any miss/read error or a non-commit/remix target; the caller then
/// indexes nothing (the index is backfillable), never failing the update.
async fn read_commit_meta_wire(env: &Env, room: &str, new_id: &[u8]) -> Option<CommitMetaWire> {
    let bucket = env.bucket(STORAGE_BUCKET).ok()?;
    let obj = bucket
        .get(object_key(room, new_id))
        .execute()
        .await
        .ok()??;
    let bytes = obj.body()?.bytes().await.ok()?;
    let m = crate::commit_log::extract_commit_meta(&bytes)?;
    // Compute the borrowing fields before moving the owned `String`s out of `m`.
    let parent = m.parent.map(hex::encode).unwrap_or_default();
    let kind = m.kind.as_str().to_string();
    let sources = m.sources_json();
    Some(CommitMetaWire {
        parent,
        signer: m.signer_hex,
        message: m.message,
        timestamp: m.timestamp as i64,
        kind,
        sources,
    })
}

/// Map a DO commit-index row (hex fields) straight to the proto `CommitEntry`
/// the client renders — no object bytes, no decode. Field-for-field.
fn row_to_entry(row: CommitRowWire) -> CommitEntry {
    CommitEntry {
        hash: Some(row.hash),
        parent: Some(row.parent),
        author_pubkey: Some(row.signer),
        message: Some(row.message),
        created_at_unix: Some(row.timestamp),
        kind: Some(row.kind),
        sources_json: Some(row.sources),
        ..Default::default()
    }
}

/// Issue a JSON POST to the room's RefStore DO and decode the response.
/// `pub(crate)` so `auth.rs`'s write-quota check reuses the SAME DO-call
/// plumbing (retry-free, one round trip) rather than a second copy.
pub(crate) async fn do_call<Req: Serialize, Resp: serde::de::DeserializeOwned>(
    env: &Env,
    room: &str,
    op: &str,
    body: &Req,
) -> Result<Resp, connectrpc::ConnectError> {
    let payload =
        serde_json::to_string(body).map_err(|e| ce_storage(StorageOp::RequestSerialize, e))?;
    let ns = env
        .durable_object(REFSTORE_BINDING)
        .map_err(|e| ce_storage(StorageOp::RefstoreBinding, e))?;
    let stub = ns
        .id_from_name(room)
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

/// Open + accept a WebSocket to the room DO's `/watch` endpoint — the same
/// upgrade `worker_impl.rs::watch_fallback` proxies straight through to a
/// browser client, but here the WORKER itself is the WebSocket client: the
/// returned, owned `WebSocket` is what `bridge_watch_socket` below pumps into
/// the Connect stream. `stub.fetch_with_request` on an `Upgrade: websocket`
/// request resolves once the DO has accepted the pair (see
/// `refstore::RefStore::fetch`'s `/watch` branch), carrying the client
/// half of the pair on the response (`resp.websocket()`).
async fn open_watch_socket(env: Env, room: String) -> Result<WebSocket, connectrpc::ConnectError> {
    let ns = env
        .durable_object(REFSTORE_BINDING)
        .map_err(|e| ce_storage(StorageOp::RefstoreBinding, e))?;
    let stub = ns
        .id_from_name(&room)
        .and_then(|id| id.get_stub())
        .map_err(|e| ce_storage(StorageOp::RefstoreStub, e))?;

    let mut req = WorkerRequest::new("https://refstore/watch", Method::Get)
        .map_err(|e| ce_storage(StorageOp::RefstoreRequest, e))?;
    req.headers_mut()
        .map_err(|e| ce_storage(StorageOp::RefstoreRequest, e))?
        .set("upgrade", "websocket")
        .map_err(|e| ce_storage(StorageOp::RefstoreRequest, e))?;

    let resp = stub
        .fetch_with_request(req)
        .await
        .map_err(|e| ce_storage(StorageOp::RefstoreWatchFetch, e))?;

    let ws = resp.websocket().ok_or_else(|| {
        ce_storage(
            StorageOp::RefstoreWatchAccept,
            "REFSTORE /watch did not upgrade to a websocket",
        )
    })?;
    ws.accept()
        .map_err(|e| ce_storage(StorageOp::RefstoreWatchAccept, e))?;
    Ok(ws)
}

/// Own `ws` end-to-end and drain its (borrowed-from-`ws`, never escaping this
/// function) `EventStream` onto `tx`, forwarding EVERY `RoomEvent` kind the DO
/// broadcasts (commit/chat/reaction/presence — see `crate::room_event`) onto
/// the Connect stream. Runs inside `wasm_bindgen_futures::spawn_local` — see
/// the `watch_refs` doc comment for why that, and not a `Send`-bounded spawn,
/// is what makes this sound. A malformed/unparseable frame is silently
/// skipped (`room_event::decode`'s contract) rather than failing the stream;
/// only a genuine socket error or close ends it.
async fn bridge_watch_socket(
    ws: WebSocket,
    tx: futures_channel::mpsc::UnboundedSender<Result<RoomEvent, connectrpc::ConnectError>>,
) {
    let mut events = match ws.events() {
        Ok(events) => events,
        Err(e) => {
            let _ = tx.unbounded_send(Err(ce_storage(StorageOp::WatchSocket, e)));
            return;
        }
    };
    while let Some(item) = events.next().await {
        match item {
            Ok(WebsocketEvent::Message(msg)) => {
                let Some(text) = msg.text() else { continue };
                if let Some(event) = room_event::decode(&text) {
                    // The receiver end (`rx`, the ServiceStream) is dropped
                    // when the Connect client disconnects and the dispatcher
                    // stops polling the stream; a failed send means exactly
                    // that, so stop pumping rather than looping forever.
                    if tx.unbounded_send(Ok(event)).is_err() {
                        break;
                    }
                }
            }
            Ok(WebsocketEvent::Close(_)) => break,
            Err(e) => {
                let _ = tx.unbounded_send(Err(ce_storage(StorageOp::WatchSocket, e)));
                break;
            }
        }
    }
    // Best-effort: the socket may already be closed (that's often why the
    // loop above exited), so a failure here is not itself an error.
    let _ = ws.close(None, None::<&str>);
}

/// Delete every R2 object under `prefix`, paging through R2's list cursor and
/// batch-deleting each page with `delete_multiple` (capped at 1000 keys per
/// call, which R2 also happens to cap `list()` at by default — one
/// list-then-delete round-trip per page). Returns the total number of
/// objects removed. Used by `PurgeRoom` for both the `{room}/objects/` and
/// `{room}/messages/` prefixes.
async fn purge_prefix(env: &Env, prefix: &str) -> Result<u32, connectrpc::ConnectError> {
    let bucket = env
        .bucket(STORAGE_BUCKET)
        .map_err(|e| ce_storage(StorageOp::StorageBinding, e))?;
    let mut deleted = 0u32;
    let mut cursor: Option<String> = None;
    loop {
        let mut list = bucket.list().prefix(prefix).limit(1000);
        if let Some(c) = cursor.take() {
            list = list.cursor(c);
        }
        let page = list
            .execute()
            .await
            .map_err(|e| ce_storage(StorageOp::R2List, e))?;
        let keys: Vec<String> = page.objects().into_iter().map(|o| o.key()).collect();
        if !keys.is_empty() {
            bucket
                .delete_multiple(keys.clone())
                .await
                .map_err(|e| ce_storage(StorageOp::R2Delete, e))?;
            deleted = deleted.saturating_add(keys.len() as u32);
        }
        if !page.truncated() {
            break;
        }
        // Defensive: `truncated=true` with no cursor should not happen per the
        // R2 contract, but looping forever on a malformed page is worse than
        // stopping one page early.
        match page.cursor() {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    Ok(deleted)
}

// DO wire types are declared once in `super::wire` and shared with refstore.rs.

fn hex_to_bytes_opt(s: &Option<String>) -> Option<Vec<u8>> {
    s.as_ref().and_then(|s| hex::decode(s).ok())
}

// --- the RepoService trait impl --------------------------------------------

// connectrpc 0.8's generated trait methods return
// `impl Encodable<Resp> + Send + use<'a, Self>` so handlers MAY return
// zero-copy views; these handlers return the concrete owned response
// types, which is a (harmless, crate-internal) refinement of that
// signature.
#[allow(refining_impl_trait)]
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
            // Idempotent content-addressed store in ONE round-trip (the key IS
            // the verified hash; a re-put is a no-op). `put_addressed` returns
            // false when the key already existed, so `duplicate` stays accurate
            // without a separate head().
            let stored = put_addressed(&env, &object_key(&room, &object_id), bytes).await?;
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
                .map_err(|e| ce_storage(StorageOp::StorageBinding, e))?;
            let key = object_key(&room, &object_id);
            match bucket.get(&key).execute().await {
                Ok(Some(obj)) => {
                    let bytes = obj
                        .body()
                        .ok_or_else(|| ce_storage(StorageOp::R2Read, "missing body"))?
                        .bytes()
                        .await
                        .map_err(|e| ce_storage(StorageOp::R2Read, e))?;
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
                Err(e) => Err(ce_storage(StorageOp::R2Get, e)),
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
            let resp: GetResp = do_call(&env, &room, "/get", &GetReq { name }).await?;
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
        if !is_valid_expected_id_len(&expected_id) {
            return Err(ce_invalid("expected_id must be 32 bytes"));
        }

        // The verified writer pubkey stashed by the auth interceptor.
        let author = ctx.extensions().get::<AuthorPubkey>().map(|a| a.0.clone());
        // The request's Idempotency-Key (verified in the envelope) — the DO
        // uses it, together with `author` and `name`, to dedupe a replayed
        // signed UpdateRef into its original result instead of re-running the
        // CAS (closes the REF_EXPECTATION_ANY replay-clobber hole).
        let idem = ctx
            .extensions()
            .get::<IdempotencyKey>()
            .map(|k| k.0.clone())
            .unwrap_or_default();

        let env = self.env.clone();
        SendFuture::new(async move {
            // Decode the pushed object once to dual-write the DO commit index.
            let commit = read_commit_meta_wire(&env, &room, &new_id).await;
            let body = UpdateReq {
                name,
                new: hex::encode(&new_id),
                expectation,
                expected: if expected_id.is_empty() {
                    None
                } else {
                    Some(hex::encode(&expected_id))
                },
                author,
                commit,
                idem,
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
        let start_after = msg.start_after.unwrap_or_default();
        let page_size = msg.page_size.unwrap_or(0);

        check_room(&room)?;
        if !is_valid_ref_prefix(&prefix) {
            return Err(ce_invalid("prefix is invalid (SPEC-REFS §3)"));
        }

        let env = self.env.clone();
        SendFuture::new(async move {
            let resp: ListResp = do_call(
                &env,
                &room,
                "/list",
                &ListReq {
                    prefix,
                    start_after,
                    page_size,
                },
            )
            .await?;
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
                next_cursor: Some(resp.next_cursor),
                total: Some(resp.total),
                ..Default::default()
            }))
        })
        .await
    }

    // WatchRefs — Connect server-streaming over an owned-channel DO bridge.
    //
    // The lifetime wall this used to hit: `WebSocket::events()` returns
    // `EventStream<'ws>`, which BORROWS the socket, so a struct holding both
    // the `WebSocket` and its own `EventStream<'_>` is self-referential and
    // can't be built in safe Rust — which blocked returning it as the
    // `'static + Send` `ServiceStream<RoomEvent>` the generated trait requires
    // (see git history / apps/repo-worker/README.md before this change for
    // the previous `unimplemented` stub and its full rationale).
    //
    // The bridge: never let the borrow escape a function at all.
    // `bridge_watch_socket` below OWNS the `WebSocket` and calls `.events()`
    // on it locally — the resulting `EventStream<'_>` borrows a value that
    // lives exactly as long as that async fn's stack frame, and is fully
    // drained (`while let Some(item) = events.next().await`) before the
    // function returns. It never needs to be `Send` either, because it runs
    // inside `wasm_bindgen_futures::spawn_local` — the one Cloudflare-Workers
    // task primitive that does NOT require its future to be `Send` (matching
    // the Router's own internal spawn per the module doc in worker_impl.rs).
    // Each event is translated into a fully-owned `RoomEvent` (or dropped, or
    // turned into an owned `ConnectError`) and pushed onto a
    // `futures_channel::mpsc::unbounded` sender. The receiver end — the
    // "owned channel" — holds no borrow into the spawned task or the
    // WebSocket: it is `Send` because `Result<RoomEvent, ConnectError>` is
    // `Send` (plain owned data, no JsValue), and `'static` because it has no
    // lifetime parameters at all. That receiver, not the WebSocket or its
    // event stream, is what crosses the `ServiceStream<RoomEvent>` boundary.
    //
    // VERIFIED in `wrangler dev` / local Miniflare (2026-07-11/12, issue
    // #705); a real deployed-Worker trial is still pending (#803) — this is
    // NOT yet verified end-to-end against production infrastructure. PR
    // #738 (the #697 spike) proved the bridge itself but reported delivery
    // to a Connect client as an unverified/failing gap ("zero bytes, not
    // even headers") under local `wrangler dev`. Re-running that exact
    // scenario in this pass — repeated trials against a fresh local
    // `wrangler dev` instance (wrangler 4.110.0 / worker-rs 0.8.5 /
    // connectrpc 0.8.0), including incremental multi-event delivery and
    // `Accept-Encoding: gzip` negotiation like a real browser client — did
    // NOT reproduce that gap: headers and body both arrive, and each
    // broadcast event is pushed to the client within tens of milliseconds of
    // the triggering RPC, not buffered until stream end. See the README
    // "WatchRefs / streaming" section for the full writeup and repro script.
    // The one verification this pass could NOT complete — a real `wrangler
    // deploy`/custom-domain edge deployment, blocked by this session's
    // production-deploy guardrail, not by anything in the code — is tracked
    // as issue #803 (do not upgrade this comment back to "verified
    // end-to-end" until that trial actually runs against a deployed Worker).
    async fn watch_refs(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, WatchRefsRequest>,
    ) -> ServiceResult<ServiceStream<RoomEvent>> {
        let msg = request.to_owned_message();
        let room = msg.room.unwrap_or_default();
        check_room(&room)?;

        let env = self.env.clone();
        let room_for_open = room.clone();
        // Opening + accepting the WebSocket touches `!Send` JS handles
        // (Stub, Request, Response), so — like every other DO call in this
        // file — it's wrapped in `SendFuture` (sound under single-threaded
        // wasm; see the module doc at the top of this file).
        let ws = SendFuture::new(open_watch_socket(env, room_for_open)).await?;

        let (tx, rx) =
            futures_channel::mpsc::unbounded::<Result<RoomEvent, connectrpc::ConnectError>>();
        // `spawn_local`, not `SendFuture` + an ordinary `.await`: this task
        // must keep running to feed `rx` for the lifetime of the stream,
        // independent of `watch_refs` having already returned. It has no
        // `Send` bound, which is exactly what lets it own the
        // borrow-of-itself `EventStream` described above.
        wasm_bindgen_futures::spawn_local(bridge_watch_socket(ws, tx));

        Response::stream_ok(rx)
    }

    async fn post_message(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, PostMessageRequest>,
    ) -> ServiceResult<PostMessageResponse> {
        let msg = request.to_owned_message();
        let room = msg.room.unwrap_or_default();
        let raw_text = msg.text.unwrap_or_default();

        check_room(&room)?;
        // Length + non-empty rule (the abuse floor; the passkey-gated, rate-
        // limited write is the rest). Store the trimmed value.
        let text = crate::chat::validate_text(&raw_text)
            .map_err(ce_invalid)?
            .to_string();

        // The verified writer pubkey stashed by the auth interceptor IS the
        // chat author. PostMessage requires write auth, so this is present;
        // treat its absence as an auth failure rather than an anonymous post.
        let author = ctx
            .extensions()
            .get::<AuthorPubkey>()
            .map(|a| a.0.clone())
            .ok_or_else(|| {
                connectrpc::ConnectError::unauthenticated("missing verified author pubkey")
            })?;
        // The request's Idempotency-Key (verified in the envelope) — the DO uses
        // it to dedupe a replayed signature into the original message.
        let idem = ctx
            .extensions()
            .get::<IdempotencyKey>()
            .map(|k| k.0.clone())
            .unwrap_or_default();

        // `message_id` folds the signed per-post idempotency key into the content
        // hash, so each send is a DISTINCT object (identical text posted twice →
        // two ids). That lets reactions key on the plain id. A replay reuses the
        // same `idem`, recomputes the same id, and is deduped on (author, idem) in
        // the DO.
        let id = crate::chat::message_id(&room, &author, &text, &idem);
        let canonical = crate::chat::canonical_message(&room, &author, &text, &idem);

        let env = self.env.clone();
        SendFuture::new(async move {
            // Append to the room's ordered log FIRST — the DO enforces the rate
            // limit, replay dedupe, monotonic seq, and broadcast. Only persist
            // the bytes to R2 once the post is ACCEPTED, so a rate-limited or
            // duplicate post does no wasted R2 write.
            let resp: PostResp = do_call(
                &env,
                &room,
                "/post",
                &PostReq {
                    id: hex::encode(id),
                    author,
                    text,
                    idem,
                },
            )
            .await?;

            if resp.accepted {
                // Durable content-addressed copy in its OWN namespace (the DO
                // SQLite row is the serving source of truth for the feed).
                put_addressed(&env, &message_key(&room, &id), canonical).await?;
            }

            Ok(Response::new(PostMessageResponse {
                // Only surface a content address for a message that was actually
                // stored; a rejected post returns an empty id so a client keying
                // off message_id can't mistake a refusal for a stored message.
                message_id: Some(if resp.accepted {
                    id.to_vec()
                } else {
                    Vec::new()
                }),
                accepted: Some(resp.accepted),
                rate_limited: Some(resp.rate_limited),
                ..Default::default()
            }))
        })
        .await
    }

    async fn list_messages(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ListMessagesRequest>,
    ) -> ServiceResult<ListMessagesResponse> {
        let msg = request.to_owned_message();
        let room = msg.room.unwrap_or_default();
        let limit = msg.limit.unwrap_or(0);

        check_room(&room)?;

        let env = self.env.clone();
        SendFuture::new(async move {
            let resp: MessagesResp =
                do_call(&env, &room, "/messages", &MessagesReq { limit }).await?;
            let messages = resp
                .messages
                .into_iter()
                .map(|m| ChatMessage {
                    message_id: Some(hex::decode(&m.id).unwrap_or_default()),
                    author_pubkey: Some(hex::decode(&m.author).unwrap_or_default()),
                    text: Some(m.text),
                    created_at: Some(m.created_at),
                    seq: Some(m.seq),
                    created_at_unix_ms: Some(m.created_at),
                    ..Default::default()
                })
                .collect();
            Ok(Response::new(ListMessagesResponse {
                messages,
                ..Default::default()
            }))
        })
        .await
    }

    async fn react(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ReactRequest>,
    ) -> ServiceResult<ReactResponse> {
        let msg = request.to_owned_message();
        let room = msg.room.unwrap_or_default();
        let target = msg.target_id.unwrap_or_default();
        let emoji = msg.emoji.unwrap_or_default();

        check_room(&room)?;
        // target_id MUST be a real 64-hex feed-item id (not an arbitrary string),
        // and emoji MUST be one of the allowed set — together these bound the
        // reactions table's cardinality and stop arbitrary content being
        // persisted + broadcast to every viewer.
        if !crate::chat::is_valid_target_id(&target) {
            return Err(ce_invalid(
                "target_id must be a 64-char lowercase-hex feed-item id",
            ));
        }
        if !crate::chat::is_allowed_emoji(&emoji) {
            return Err(ce_invalid("emoji is not in the allowed reaction set"));
        }

        let author = ctx
            .extensions()
            .get::<AuthorPubkey>()
            .map(|a| a.0.clone())
            .ok_or_else(|| {
                connectrpc::ConnectError::unauthenticated("missing verified author pubkey")
            })?;
        // The request's Idempotency-Key — the DO dedupes a replayed signed React
        // (a toggle) into its original result rather than flipping state again.
        let idem = ctx
            .extensions()
            .get::<IdempotencyKey>()
            .map(|k| k.0.clone())
            .unwrap_or_default();

        let env = self.env.clone();
        SendFuture::new(async move {
            let resp: ReactResp = do_call(
                &env,
                &room,
                "/react",
                &ReactReq {
                    target,
                    emoji,
                    author,
                    idem,
                },
            )
            .await?;
            Ok(Response::new(ReactResponse {
                active: Some(resp.active),
                count: Some(resp.count),
                ..Default::default()
            }))
        })
        .await
    }

    async fn list_reactions(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ListReactionsRequest>,
    ) -> ServiceResult<ListReactionsResponse> {
        let msg = request.to_owned_message();
        let room = msg.room.unwrap_or_default();
        check_room(&room)?;

        let env = self.env.clone();
        SendFuture::new(async move {
            // `/reactions` ignores its body; `()` serializes to `null`.
            let resp: ReactionsResp = do_call(&env, &room, "/reactions", &()).await?;
            let reactions = resp
                .reactions
                .into_iter()
                .map(|r| Reaction {
                    target_id: Some(r.target),
                    emoji: Some(r.emoji),
                    author_pubkey: Some(hex::decode(&r.author).unwrap_or_default()),
                    ..Default::default()
                })
                .collect();
            Ok(Response::new(ListReactionsResponse {
                reactions,
                ..Default::default()
            }))
        })
        .await
    }

    async fn list_commits(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ListCommitsRequest>,
    ) -> ServiceResult<ListCommitsResponse> {
        let msg = request.to_owned_message();
        let room = msg.room.unwrap_or_default();
        let mut ref_name = msg.r#ref.unwrap_or_default();
        if ref_name.is_empty() {
            ref_name = "main".to_string();
        }
        let start_id = msg.start_id.unwrap_or_default();
        // Bound the page so one request can't walk unbounded history into memory.
        const DEFAULT_PAGE: usize = 100;
        const MAX_PAGE: usize = 512;
        let cap = match msg.page_size.unwrap_or(0) as usize {
            0 => DEFAULT_PAGE,
            n => n.min(MAX_PAGE),
        };

        check_room(&room)?;
        if !is_valid_ref_name(&ref_name) {
            return Err(ce_invalid("ref name is invalid (SPEC-REFS §3)"));
        }

        let env = self.env.clone();
        SendFuture::new(async move {
            // 1) Serve METADATA straight from the colocated DO index — ONE SQLite
            //    query, NO R2, NO object bytes, NO client decode.
            let idx: ListCommitsResp = do_call(
                &env,
                &room,
                "/list-commits",
                &ListCommitsReq {
                    r#ref: ref_name.clone(),
                    start_id: if start_id.is_empty() {
                        String::new()
                    } else {
                        hex::encode(&start_id)
                    },
                    page_size: cap as u32,
                },
            )
            .await?;

            if idx.complete {
                let commits: Vec<CommitEntry> = idx.commits.into_iter().map(row_to_entry).collect();
                return Ok(Response::new(ListCommitsResponse {
                    commits,
                    next_cursor: Some(idx.next_cursor),
                    ..Default::default()
                }));
            }

            // 2) Pre-index history (index incomplete) → the authoritative sequential
            //    R2 walk to DECODE the metadata, return it, AND backfill the index so
            //    the next read is fully local.
            let bucket = env
                .bucket(STORAGE_BUCKET)
                .map_err(|e| ce_storage(StorageOp::StorageBinding, e))?;
            let head: Vec<u8> = if !start_id.is_empty() {
                start_id
            } else {
                let resp: GetResp = do_call(
                    &env,
                    &room,
                    "/get",
                    &GetReq {
                        name: ref_name.clone(),
                    },
                )
                .await?;
                if !resp.exists {
                    return Ok(Response::new(ListCommitsResponse::default()));
                }
                hex_to_bytes_opt(&resp.value).unwrap_or_default()
            };
            if head.len() != 32 {
                return Ok(Response::new(ListCommitsResponse::default()));
            }

            let mut rows: Vec<CommitRowWire> = Vec::with_capacity(cap);
            let mut seen: HashSet<Vec<u8>> = HashSet::new();
            let mut current = head;
            let mut next_cursor = String::new();
            loop {
                if rows.len() >= cap {
                    next_cursor = hex::encode(&current);
                    break;
                }
                if !seen.insert(current.clone()) {
                    break;
                }
                let bytes = match bucket.get(object_key(&room, &current)).execute().await {
                    Ok(Some(obj)) => obj
                        .body()
                        .ok_or_else(|| ce_storage(StorageOp::R2Read, "missing body"))?
                        .bytes()
                        .await
                        .map_err(|e| ce_storage(StorageOp::R2Read, e))?,
                    Ok(None) => break,
                    Err(e) => return Err(ce_storage(StorageOp::R2Get, e)),
                };
                let Some(m) = crate::commit_log::extract_commit_meta(&bytes) else {
                    break;
                };
                // Compute borrowing fields before moving the owned `String`s out of `m`.
                let parent_hex = m.parent.map(hex::encode).unwrap_or_default();
                let kind = m.kind.as_str().to_string();
                let sources = m.sources_json();
                let timestamp = m.timestamp as i64;
                rows.push(CommitRowWire {
                    hash: hex::encode(&current),
                    parent: parent_hex.clone(),
                    signer: m.signer_hex,
                    message: m.message,
                    timestamp,
                    kind,
                    sources,
                });
                if parent_hex.is_empty() {
                    break;
                }
                current = match hex::decode(&parent_hex) {
                    Ok(b) if b.len() == 32 => b,
                    _ => break,
                };
            }

            // Best-effort backfill (a failure just means a slow next read).
            if !rows.is_empty() {
                let _ = do_call::<_, RecordCommitsResp>(
                    &env,
                    &room,
                    "/record-commits",
                    &RecordCommitsReq {
                        r#ref: ref_name,
                        commits: rows.clone(),
                    },
                )
                .await;
            }

            let commits: Vec<CommitEntry> = rows.into_iter().map(row_to_entry).collect();
            Ok(Response::new(ListCommitsResponse {
                commits,
                next_cursor: Some(next_cursor),
                ..Default::default()
            }))
        })
        .await
    }

    async fn purge_room(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, PurgeRoomRequest>,
    ) -> ServiceResult<PurgeRoomResponse> {
        // `_ctx` is unused: the `AuthInterceptor` already rejected this call
        // before it reached the handler unless `X-Admin-Token` matched the
        // server's `ADMIN_TOKEN` secret (see worker_impl/auth.rs). There is
        // no per-caller identity to extract here, unlike UpdateRef/PostMessage/
        // React's `AuthorPubkey` — a purge has no room-participant author.
        let msg = request.to_owned_message();
        let room = msg.room.unwrap_or_default();
        check_room(&room)?;

        let env = self.env.clone();
        SendFuture::new(async move {
            // R2 first, DO second: if the worker dies between the two, the
            // room is left with objects gone but refs/messages still present
            // rather than the reverse — a re-run of PurgeRoom is idempotent
            // either way (an empty prefix / already-empty tables just yield
            // zero counts on the retried half).
            let objects_deleted = purge_prefix(&env, &format!("{room}/objects/")).await?;
            let message_bodies_deleted = purge_prefix(&env, &format!("{room}/messages/")).await?;
            let resp: PurgeResp = do_call(&env, &room, "/purge", &()).await?;

            // `purged` reflects the proto contract ("true unless the room
            // already had nothing to purge") rather than always `true` — a
            // PurgeRoom against an already-empty/nonexistent room is a
            // harmless no-op, and the response should say so instead of
            // falsely claiming something was removed.
            let purged = objects_deleted > 0
                || message_bodies_deleted > 0
                || resp.refs_deleted > 0
                || resp.messages_deleted > 0
                || resp.reactions_deleted > 0;

            Ok(Response::new(PurgeRoomResponse {
                purged: Some(purged),
                objects_deleted: Some(objects_deleted),
                message_bodies_deleted: Some(message_bodies_deleted),
                refs_deleted: Some(resp.refs_deleted),
                messages_deleted: Some(resp.messages_deleted),
                reactions_deleted: Some(resp.reactions_deleted),
                ..Default::default()
            }))
        })
        .await
    }
}
