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

use super::auth::{AuthorPubkey, IdempotencyKey};
use crate::hashing::object_id_matches;
use crate::refs::{is_valid_ref_name, is_valid_ref_prefix, is_valid_room};
use crate::proto::mkit::repo::v1::{
    ChatMessage, CommitEntry, GetObjectRequest, GetObjectResponse, GetRefRequest, GetRefResponse,
    ListCommitsRequest,
    ListCommitsResponse, ListMessagesRequest, ListMessagesResponse, ListReactionsRequest,
    ListReactionsResponse, ListRefsRequest, ListRefsResponse, PostMessageRequest,
    PostMessageResponse, PutObjectRequest, PutObjectResponse, ReactRequest, ReactResponse, Reaction,
    RefEntry, RefEvent, UpdateRefRequest, UpdateRefResponse, WatchRefsRequest,
};
use std::collections::HashSet;
use super::refstore::WatchFrame;
use super::wire::{
    CommitMetaWire, CommitRowWire, GetReq, GetResp, ListCommitsReq, ListCommitsResp, ListReq,
    ListResp, MessagesReq, MessagesResp, PostReq, PostResp, ReactReq, ReactResp, ReactionsResp,
    RecordCommitsReq, RecordCommitsResp, UpdateReq, UpdateResp,
};

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
async fn put_addressed(env: &Env, key: &str, bytes: Vec<u8>) -> Result<bool, connectrpc::ConnectError> {
    let bucket = env
        .bucket(STORAGE_BUCKET)
        .map_err(|e| ce_internal(format!("STORAGE binding: {e}")))?;
    let stored = bucket
        .put(key, bytes)
        .only_if(worker::Conditional {
            etag_does_not_match: Some("*".to_string()),
            ..Default::default()
        })
        .execute()
        .await
        .map_err(|e| ce_internal(format!("R2 put: {e}")))?
        .is_some();
    Ok(stored)
}

/// Read the just-pushed object from R2 and decode its commit metadata into the
/// DO-index wire shape — so a ref update can dual-write the `commits` index.
/// `None` on any miss/read error or a non-commit/remix target; the caller then
/// indexes nothing (the index is backfillable), never failing the update.
async fn read_commit_meta_wire(env: &Env, room: &str, new_id: &[u8]) -> Option<CommitMetaWire> {
    let bucket = env.bucket(STORAGE_BUCKET).ok()?;
    let obj = bucket.get(&object_key(room, new_id)).execute().await.ok()??;
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

// DO wire types are declared once in `super::wire` and shared with refstore.rs.

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

        // The verified writer pubkey stashed by the auth interceptor.
        let author = ctx
            .extensions()
            .get::<AuthorPubkey>()
            .map(|a| a.0.clone());

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
                do_call(&env, &room, "/list", &ListReq { prefix }).await?;
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
        let _ = (REFSTORE_BINDING, std::marker::PhantomData::<WatchFrame>);
        Err(connectrpc::ConnectError::unimplemented(
            "WatchRefs is served over the WebSocket route GET /watch/<room>, \
             not Connect server-streaming (see README)",
        ))
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

        // `message_id` is a CONTENT hash of the canonical message bytes (like a
        // commit hash: identical content → identical id). It is NOT a unique
        // per-post handle — the monotonic `seq` is the timeline key, and replays
        // are deduped on (author, idempotency-key) in the DO.
        let id = crate::chat::message_id(&room, &author, &text);
        let canonical = crate::chat::canonical_message(&room, &author, &text);

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
                &PostReq { id: hex::encode(id), author, text, idem },
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
                message_id: Some(if resp.accepted { id.to_vec() } else { Vec::new() }),
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
            let resp: MessagesResp = do_call(&env, &room, "/messages", &MessagesReq { limit }).await?;
            let messages = resp
                .messages
                .into_iter()
                .map(|m| ChatMessage {
                    message_id: Some(hex::decode(&m.id).unwrap_or_default()),
                    author_pubkey: Some(hex::decode(&m.author).unwrap_or_default()),
                    text: Some(m.text),
                    created_at: Some(m.created_at),
                    seq: Some(m.seq),
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
            return Err(ce_invalid("target_id must be a 64-char lowercase-hex feed-item id"));
        }
        if !crate::chat::is_allowed_emoji(&emoji) {
            return Err(ce_invalid("emoji is not in the allowed reaction set"));
        }

        let author = ctx
            .extensions()
            .get::<AuthorPubkey>()
            .map(|a| a.0.clone())
            .ok_or_else(|| connectrpc::ConnectError::unauthenticated("missing verified author pubkey"))?;
        // The request's Idempotency-Key — the DO dedupes a replayed signed React
        // (a toggle) into its original result rather than flipping state again.
        let idem = ctx
            .extensions()
            .get::<IdempotencyKey>()
            .map(|k| k.0.clone())
            .unwrap_or_default();

        let env = self.env.clone();
        SendFuture::new(async move {
            let resp: ReactResp =
                do_call(&env, &room, "/react", &ReactReq { target, emoji, author, idem }).await?;
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
                    start_id: if start_id.is_empty() { String::new() } else { hex::encode(&start_id) },
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
                .map_err(|e| ce_internal(format!("STORAGE binding: {e}")))?;
            let head: Vec<u8> = if !start_id.is_empty() {
                start_id
            } else {
                let resp: GetResp =
                    do_call(&env, &room, "/get", &GetReq { name: ref_name.clone() }).await?;
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
                let bytes = match bucket.get(&object_key(&room, &current)).execute().await {
                    Ok(Some(obj)) => obj
                        .body()
                        .ok_or_else(|| ce_internal("R2 object had no body"))?
                        .bytes()
                        .await
                        .map_err(|e| ce_internal(format!("R2 read: {e}")))?,
                    Ok(None) => break,
                    Err(e) => return Err(ce_internal(format!("R2 get: {e}"))),
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
                    &RecordCommitsReq { r#ref: ref_name, commits: rows.clone() },
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
}
