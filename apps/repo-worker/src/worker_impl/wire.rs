// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The internal worker -> RefStore DO wire protocol, as a single shared set of
// types used by BOTH sides:
//   - service.rs (client): serializes the request, deserializes the response.
//   - refstore.rs (DO):    deserializes the request, serializes the response.
//
// Declaring these once means a field rename can't silently desync the two
// sides — they share the literal struct. Request fields are owned `String`
// (rather than borrowed `&str`) so the DO can `Deserialize` them while the
// worker still serializes them without lifetime gymnastics; the worker-side
// allocation is negligible against the DO round-trip.
//
// JSON over HTTP to a `https://refstore/<op>` URL:
//   POST /get    GetReq    -> GetResp
//   POST /update UpdateReq -> UpdateResp
//   POST /list   ListReq   -> ListResp
//
// `expectation` is the proto wire number (1=ANY, 2=MISSING, 3=MATCH). Hex
// fields are 64-char lowercase hex of a 32-byte object id (or, for `author`,
// the Ed25519 pubkey).

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GetReq {
    pub name: String,
}

#[derive(Serialize, Deserialize)]
pub struct GetResp {
    pub exists: bool,
    pub value: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct UpdateReq {
    pub name: String,
    pub new: String,              // 64-hex target value
    pub expectation: i32,         // proto wire number
    pub expected: Option<String>, // 64-hex (MATCH only)
    pub author: Option<String>,   // 64-hex Ed25519 pubkey of the writer
}

#[derive(Serialize, Deserialize)]
pub struct UpdateResp {
    pub committed: bool,
    pub conflict: bool,
    pub current: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ListReq {
    pub prefix: String,
}

#[derive(Serialize, Deserialize)]
pub struct ListEntry {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize)]
pub struct ListResp {
    pub refs: Vec<ListEntry>,
}

// --- Chat (worker -> DO) ----------------------------------------------------
//
//   POST /post     PostReq     -> PostResp
//   POST /messages MessagesReq -> MessagesResp
//
// The worker has already content-addressed + stored the message in R2 and
// verified the author envelope; the DO owns ORDERING (the monotonic `seq`),
// the server clock (`created_at`), rate-limiting, and the broadcast. `id` and
// `author` are 64-hex; `text` is the raw UTF-8 message.

#[derive(Serialize, Deserialize)]
pub struct PostReq {
    pub id: String,     // 64-hex BLAKE3 message id (content address)
    pub author: String, // 64-hex Ed25519 pubkey of the verified signer
    pub text: String,
    pub idem: String,   // request Idempotency-Key — replay dedupe (empty if none)
}

#[derive(Serialize, Deserialize)]
pub struct PostResp {
    pub accepted: bool,
    pub rate_limited: bool,
    pub seq: u64,
    pub created_at: i64, // server epoch-ms the DO stamped
}

#[derive(Serialize, Deserialize)]
pub struct MessagesReq {
    pub limit: u32,
}

#[derive(Serialize, Deserialize)]
pub struct MsgEntry {
    pub id: String,
    pub author: String,
    pub text: String,
    pub created_at: i64,
    pub seq: u64,
}

#[derive(Serialize, Deserialize)]
pub struct MessagesResp {
    pub messages: Vec<MsgEntry>, // oldest-first
}

// --- Reactions (worker -> DO) ----------------------------------------------
//
//   POST /react     ReactReq  -> ReactResp   (toggle (target, emoji, author))
//   POST /reactions (no body) -> ReactionsResp

#[derive(Serialize, Deserialize)]
pub struct ReactReq {
    pub target: String, // hex id of the feed item
    pub emoji: String,
    pub author: String, // 64-hex Ed25519 pubkey of the verified reactor
    pub idem: String,   // request Idempotency-Key — replay dedupe (empty if none)
}

#[derive(Serialize, Deserialize)]
pub struct ReactResp {
    pub active: bool, // reaction is now ON for this author
    pub count: u32,   // reactors for (target, emoji) after the toggle
}

#[derive(Serialize, Deserialize)]
pub struct ReactionEntry {
    pub target: String,
    pub emoji: String,
    pub author: String,
}

#[derive(Serialize, Deserialize)]
pub struct ReactionsResp {
    pub reactions: Vec<ReactionEntry>,
}
