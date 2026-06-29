//! Browser ConnectRPC client for `mkit.repo.v1.RepoService`.
//!
//! Compiles to `wasm32-unknown-unknown` (build with `wasm-pack build --target
//! web`) and is consumed by the web demo behind the `repo-api.ts` facade.
//!
//! ## What JS gets
//!
//! Each exported async fn maps 1:1 to a Connect procedure. Reads
//! (`get_object` / `get_ref` / `list_refs`) take no auth. Writes
//! (`put_object` / `update_ref`) take a JS sign-callback: the transport
//! serializes the request, BLAKE3-hashes the raw body, and calls back into JS to
//! obtain the signed-write envelope headers (see `transport::SigningFetchTransport`
//! and README.md for the exact contract).
//!
//! ## Wire shape
//!
//! All ids cross the wasm boundary as lowercase hex strings; on the wire they
//! are raw 32-byte BLAKE3 digests (`bytes` proto fields). Conversion happens
//! here so JS never touches raw bytes for ids.
//!
//! The proto is `edition = "2023"`, so every generated message field carries
//! explicit presence (`Option<T>`); we wrap on the way in and unwrap (with
//! sensible defaults) on the way out.

mod transport;

mod proto {
    // `::connectrpc` required: the generated file declares `pub mod connectrpc`
    // inside this module, which would shadow the crate name if relative.
    ::connectrpc::include_generated!();
}

use ::connectrpc::client::{CallOptions, ClientConfig};
use proto::mkit::repo::v1::*;
use transport::{FetchTransport, SigningFetchTransport};
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// hex helpers (ids are raw 32-byte digests on the wire, hex across the boundary)
// ---------------------------------------------------------------------------

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, JsError> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if !hex.len().is_multiple_of(2) {
        return Err(JsError::new("odd-length hex string"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| JsError::new(&e.to_string())))
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn config(base_url: &str) -> Result<ClientConfig, JsError> {
    Ok(ClientConfig::new(base_url.parse().map_err(JsError::from)?))
}

fn rpc_err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

/// `js_sys::Reflect::set` returns `Result<_, JsValue>`, which does not implement
/// `std::error::Error` (so `?` can't lift it into `JsError`). Convert eagerly.
fn set(obj: &js_sys::Object, key: &str, val: JsValue) -> Result<(), JsError> {
    js_sys::Reflect::set(obj, &JsValue::from_str(key), &val)
        .map(|_| ())
        .map_err(|e| JsError::new(&e.as_string().unwrap_or_else(|| format!("{e:?}"))))
}

// ---------------------------------------------------------------------------
// Reads (no auth)
// ---------------------------------------------------------------------------

/// `GetRef` — current object id (hex) a ref points at, or `null` if absent.
#[wasm_bindgen]
pub async fn get_ref(base_url: &str, room: String, name: String) -> Result<Option<String>, JsError> {
    let client = RepoServiceClient::new(FetchTransport, config(base_url)?);
    let resp = client
        .get_ref(GetRefRequest {
            room: Some(room),
            name: Some(name),
            ..Default::default()
        })
        .await
        .map_err(rpc_err)?
        .into_owned();
    Ok(resp
        .exists
        .unwrap_or(false)
        .then(|| bytes_to_hex(resp.object_id.as_deref().unwrap_or_default())))
}

/// `GetObject` — raw object bytes, or `null` if absent.
#[wasm_bindgen]
pub async fn get_object(
    base_url: &str,
    room: String,
    object_id_hex: String,
) -> Result<Option<Vec<u8>>, JsError> {
    let client = RepoServiceClient::new(FetchTransport, config(base_url)?);
    let resp = client
        .get_object(GetObjectRequest {
            room: Some(room),
            object_id: Some(hex_to_bytes(&object_id_hex)?),
            ..Default::default()
        })
        .await
        .map_err(rpc_err)?
        .into_owned();
    Ok(resp
        .found
        .unwrap_or(false)
        .then(|| resp.bytes.unwrap_or_default()))
}

/// `ListCommits` — walk the chain from `ref_name` (empty = "main"), or from a
/// `start_id_hex` cursor, returning up to `page_size` RAW commit/remix objects in
/// ONE round-trip (vs O(depth) sequential `GetObject` calls). Returns a JS object
/// `{ commits: [{ idHex, bytes }], nextCursorHex }`; `nextCursorHex` is empty when
/// the chain ended. The caller decodes `bytes` with the mkit wasm decoder.
#[wasm_bindgen]
pub async fn list_commits(
    base_url: &str,
    room: String,
    ref_name: String,
    start_id_hex: String,
    page_size: u32,
) -> Result<JsValue, JsError> {
    let client = RepoServiceClient::new(FetchTransport, config(base_url)?);
    let start_id = if start_id_hex.is_empty() {
        Vec::new()
    } else {
        hex_to_bytes(&start_id_hex)?
    };
    let resp = client
        .list_commits(ListCommitsRequest {
            room: Some(room),
            r#ref: Some(ref_name),
            start_id: Some(start_id),
            page_size: Some(page_size),
            ..Default::default()
        })
        .await
        .map_err(rpc_err)?
        .into_owned();

    let arr = js_sys::Array::new();
    for c in resp.commits {
        let obj = js_sys::Object::new();
        // Metadata straight from the DO index — no object bytes, no decode.
        set(&obj, "hash", c.hash.unwrap_or_default().into())?;
        set(&obj, "parent", c.parent.unwrap_or_default().into())?;
        set(&obj, "authorPubkeyHex", c.author_pubkey.unwrap_or_default().into())?;
        set(&obj, "message", c.message.unwrap_or_default().into())?;
        set(&obj, "createdAtUnix", (c.created_at_unix.unwrap_or(0) as f64).into())?;
        set(&obj, "kind", c.kind.unwrap_or_default().into())?;
        set(&obj, "sourcesJson", c.sources_json.unwrap_or_default().into())?;
        arr.push(&obj);
    }
    let out = js_sys::Object::new();
    set(&out, "commits", arr.into())?;
    set(&out, "nextCursorHex", resp.next_cursor.unwrap_or_default().into())?;
    Ok(out.into())
}

/// `ListRefs` — refs in the room, optionally filtered by name prefix. Returns a
/// JS array of `{ name, objectIdHex }` objects.
#[wasm_bindgen]
pub async fn list_refs(base_url: &str, room: String, prefix: String) -> Result<JsValue, JsError> {
    let client = RepoServiceClient::new(FetchTransport, config(base_url)?);
    let resp = client
        .list_refs(ListRefsRequest {
            room: Some(room),
            prefix: Some(prefix),
            ..Default::default()
        })
        .await
        .map_err(rpc_err)?
        .into_owned();

    let arr = js_sys::Array::new();
    for r in resp.refs {
        let obj = js_sys::Object::new();
        set(&obj, "name", r.name.unwrap_or_default().into())?;
        set(
            &obj,
            "objectIdHex",
            bytes_to_hex(r.object_id.as_deref().unwrap_or_default()).into(),
        )?;
        arr.push(&obj);
    }
    Ok(arr.into())
}

/// `ListMessages` — recent lobby messages (oldest-first), capped by `limit`
/// (0 = server default). No auth. Returns a JS array of
/// `{ messageIdHex, authorPubkeyHex, text, createdAt, seq }`. `createdAt` is
/// server epoch-ms and `seq` the monotonic per-room order — both as JS numbers.
#[wasm_bindgen]
pub async fn list_messages(base_url: &str, room: String, limit: u32) -> Result<JsValue, JsError> {
    let client = RepoServiceClient::new(FetchTransport, config(base_url)?);
    let resp = client
        .list_messages(ListMessagesRequest {
            room: Some(room),
            limit: Some(limit),
            ..Default::default()
        })
        .await
        .map_err(rpc_err)?
        .into_owned();

    let arr = js_sys::Array::new();
    for m in resp.messages {
        let obj = js_sys::Object::new();
        set(
            &obj,
            "messageIdHex",
            bytes_to_hex(m.message_id.as_deref().unwrap_or_default()).into(),
        )?;
        set(
            &obj,
            "authorPubkeyHex",
            bytes_to_hex(m.author_pubkey.as_deref().unwrap_or_default()).into(),
        )?;
        set(&obj, "text", m.text.unwrap_or_default().into())?;
        // i64/u64 -> f64 so JS sees a plain Number (not BigInt); exact for the
        // epoch-ms + sequence magnitudes this demo produces.
        set(&obj, "createdAt", (m.created_at.unwrap_or(0) as f64).into())?;
        set(&obj, "seq", (m.seq.unwrap_or(0) as f64).into())?;
        arr.push(&obj);
    }
    Ok(arr.into())
}

/// `ListReactions` — every reaction in the room. No auth. Returns a JS array of
/// `{ targetIdHex, emoji, authorPubkeyHex }`; the client aggregates counts +
/// "did I react".
#[wasm_bindgen]
pub async fn list_reactions(base_url: &str, room: String) -> Result<JsValue, JsError> {
    let client = RepoServiceClient::new(FetchTransport, config(base_url)?);
    let resp = client
        .list_reactions(ListReactionsRequest {
            room: Some(room),
            ..Default::default()
        })
        .await
        .map_err(rpc_err)?
        .into_owned();

    let arr = js_sys::Array::new();
    for r in resp.reactions {
        let obj = js_sys::Object::new();
        set(&obj, "targetIdHex", r.target_id.unwrap_or_default().into())?;
        set(&obj, "emoji", r.emoji.unwrap_or_default().into())?;
        set(
            &obj,
            "authorPubkeyHex",
            bytes_to_hex(r.author_pubkey.as_deref().unwrap_or_default()).into(),
        )?;
        arr.push(&obj);
    }
    Ok(arr.into())
}

// ---------------------------------------------------------------------------
// Writes (signed via JS callback)
// ---------------------------------------------------------------------------

/// `PutObject` — content-addressed, idempotent. Signed via `sign`. Returns
/// `{ stored, duplicate }`.
#[wasm_bindgen]
pub async fn put_object(
    base_url: &str,
    room: String,
    object_id_hex: String,
    bytes: Vec<u8>,
    sign: js_sys::Function,
) -> Result<JsValue, JsError> {
    let client = RepoServiceClient::new(SigningFetchTransport::new(sign), config(base_url)?);
    let resp = client
        .put_object_with_options(
            PutObjectRequest {
                room: Some(room),
                object_id: Some(hex_to_bytes(&object_id_hex)?),
                bytes: Some(bytes),
                ..Default::default()
            },
            CallOptions::default(),
        )
        .await
        .map_err(rpc_err)?
        .into_owned();

    let obj = js_sys::Object::new();
    set(&obj, "stored", resp.stored.unwrap_or(false).into())?;
    set(&obj, "duplicate", resp.duplicate.unwrap_or(false).into())?;
    Ok(obj.into())
}

/// `UpdateRef` — CAS-advance a ref. `expectation` is `"ANY" | "MISSING" |
/// "MATCH"`. `expected_id_hex` is required (and only valid) for `"MATCH"`.
/// Signed via `sign`. Returns `{ committed, conflict, currentIdHex }`
/// (`currentIdHex` is `null` when the ref is absent).
#[wasm_bindgen]
pub async fn update_ref(
    base_url: &str,
    room: String,
    name: String,
    new_id_hex: String,
    expectation: String,
    expected_id_hex: Option<String>,
    sign: js_sys::Function,
) -> Result<JsValue, JsError> {
    let expectation = match expectation.as_str() {
        "ANY" => RefExpectation::Any,
        "MISSING" => RefExpectation::Missing,
        "MATCH" => RefExpectation::Match,
        other => return Err(JsError::new(&format!("unknown expectation `{other}`"))),
    };
    let expected_id = match &expected_id_hex {
        Some(h) if !h.is_empty() => Some(hex_to_bytes(h)?),
        _ => None,
    };

    let client = RepoServiceClient::new(SigningFetchTransport::new(sign), config(base_url)?);
    let resp = client
        .update_ref_with_options(
            UpdateRefRequest {
                room: Some(room),
                name: Some(name),
                new_id: Some(hex_to_bytes(&new_id_hex)?),
                expectation: Some(expectation.into()),
                expected_id,
                ..Default::default()
            },
            CallOptions::default(),
        )
        .await
        .map_err(rpc_err)?
        .into_owned();

    let obj = js_sys::Object::new();
    set(&obj, "committed", resp.committed.unwrap_or(false).into())?;
    set(&obj, "conflict", resp.conflict.unwrap_or(false).into())?;
    let current = match resp.current_id.as_deref() {
        Some(b) if !b.is_empty() => bytes_to_hex(b).into(),
        _ => JsValue::NULL,
    };
    set(&obj, "currentIdHex", current)?;
    Ok(obj.into())
}

/// `PostMessage` — post a signed chat message. Signed via `sign` (same
/// envelope contract as the other writes: the verified pubkey IS the author).
/// Returns `{ messageIdHex, accepted, rateLimited }` — `rateLimited` is true
/// (with `accepted` false) when the author posted too recently.
#[wasm_bindgen]
pub async fn post_message(
    base_url: &str,
    room: String,
    text: String,
    sign: js_sys::Function,
) -> Result<JsValue, JsError> {
    let client = RepoServiceClient::new(SigningFetchTransport::new(sign), config(base_url)?);
    let resp = client
        .post_message_with_options(
            PostMessageRequest {
                room: Some(room),
                text: Some(text),
                ..Default::default()
            },
            CallOptions::default(),
        )
        .await
        .map_err(rpc_err)?
        .into_owned();

    let obj = js_sys::Object::new();
    set(
        &obj,
        "messageIdHex",
        bytes_to_hex(resp.message_id.as_deref().unwrap_or_default()).into(),
    )?;
    set(&obj, "accepted", resp.accepted.unwrap_or(false).into())?;
    set(&obj, "rateLimited", resp.rate_limited.unwrap_or(false).into())?;
    Ok(obj.into())
}

/// `React` — toggle a signed emoji reaction on a feed item (`target_id_hex`).
/// Signed via `sign`. Returns `{ active, count }` — `active` is the new on/off
/// state for the reactor, `count` the total reactors for (target, emoji).
#[wasm_bindgen]
pub async fn react(
    base_url: &str,
    room: String,
    target_id_hex: String,
    emoji: String,
    sign: js_sys::Function,
) -> Result<JsValue, JsError> {
    let client = RepoServiceClient::new(SigningFetchTransport::new(sign), config(base_url)?);
    let resp = client
        .react_with_options(
            ReactRequest {
                room: Some(room),
                target_id: Some(target_id_hex),
                emoji: Some(emoji),
                ..Default::default()
            },
            CallOptions::default(),
        )
        .await
        .map_err(rpc_err)?
        .into_owned();

    let obj = js_sys::Object::new();
    set(&obj, "active", resp.active.unwrap_or(false).into())?;
    set(&obj, "count", (resp.count.unwrap_or(0) as f64).into())?;
    Ok(obj.into())
}

// ---------------------------------------------------------------------------
// WatchRefs (server-streaming)
// ---------------------------------------------------------------------------

/// `WatchRefs` — live ref advances for a room.
///
/// **STUB (documented):** server-streaming over the Fetch transport in
/// `wasm32-unknown-unknown` requires a streaming `ResponseBody` the buffered
/// Fetch transport here does not provide (it `array_buffer()`s the whole body).
/// The web demo therefore drives liveness another way (mock fan-out today; a
/// WebSocket or SSE bridge later). This stub lets JS feature-detect so the unary
/// surface is unblocked. See README.md §Streaming.
#[wasm_bindgen]
pub fn watch_refs_supported() -> bool {
    false
}
