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

/// Denormalized commit-log metadata recorded into the DO's `commits` index
/// alongside a ref update — so `ListCommits` can later serve from colocated
/// SQLite instead of walking R2. The worker decodes the pushed object once
/// (see `commit_log::extract_commit_meta`) and passes the fields here.
#[derive(Serialize, Deserialize, Default)]
pub struct CommitMetaWire {
    pub parent: String, // 64-hex first parent, empty if root
    pub signer: String, // 64-hex author pubkey
    pub message: String,
    pub timestamp: i64,  // unix seconds
    pub kind: String,    // "commit" | "remix"
    pub sources: String, // JSON [[upstreamHex, commitHex], …]; "[]" for a commit
}

#[derive(Serialize, Deserialize)]
pub struct UpdateReq {
    pub proof: mkit_worker_common::replay::Proof,
    pub name: String,
    pub new: String,              // 64-hex target value
    pub expectation: i32,         // proto wire number
    pub expected: Option<String>, // 64-hex (MATCH only)
    pub author: Option<String>,   // 64-hex Ed25519 pubkey of the writer
    /// Commit metadata to index on a successful CAS (absent for a
    /// non-commit/remix target, or from an older worker — `default` = None).
    #[serde(default)]
    pub commit: Option<CommitMetaWire>,
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
    /// Keyset cursor: return refs with `path > start_after`. Empty = from the
    /// start of the prefix range. Must be empty or start with `prefix` (the
    /// DO validates this).
    #[serde(default)]
    pub start_after: String,
    /// Max refs to return; 0 = ALL (legacy unpaginated behavior — a request
    /// from an older worker/client, or an explicit unbounded listing). A
    /// non-zero value is clamped to `[1, 1000]` by the DO.
    #[serde(default)]
    pub page_size: u32,
}

#[derive(Serialize, Deserialize)]
pub struct ListEntry {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize)]
pub struct ListResp {
    pub refs: Vec<ListEntry>,
    /// Pass as `start_after` for the next page; empty when the listing ended
    /// (fewer than `page_size` rows remained) or `page_size` was 0 (legacy
    /// unbounded scan).
    #[serde(default)]
    pub next_cursor: String,
    /// Total refs matching `prefix` (COUNT(*) on the PK). Computed only on
    /// the first page (`start_after` empty); 0 on later pages — the caller
    /// already has the total from page 1.
    #[serde(default)]
    pub total: u32,
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
    pub proof: mkit_worker_common::replay::Proof,
    pub id: String,     // 64-hex BLAKE3 message id (content address)
    pub author: String, // 64-hex Ed25519 pubkey of the verified signer
    pub text: String,
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
    pub proof: mkit_worker_common::replay::Proof,
    pub target: String, // hex id of the feed item
    pub emoji: String,
    pub author: String, // 64-hex Ed25519 pubkey of the verified reactor
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

// ---- Commit-log index (denormalized) -------------------------------------

/// Ask the DO to walk its `commits` index from a ref head (or a `start_id`
/// cursor) by first-parent, returning a bounded page.
#[derive(Serialize, Deserialize)]
pub struct ListCommitsReq {
    pub r#ref: String,
    pub start_id: String, // empty = walk from the ref head
    pub page_size: u32,
}

/// One indexed commit row — the denormalized metadata plus its hash. Shared by
/// the list response and the backfill request.
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct CommitRowWire {
    pub hash: String,
    pub parent: String,
    pub signer: String,
    pub message: String,
    pub timestamp: i64,
    pub kind: String,
    pub sources: String,
}

#[derive(Serialize, Deserialize)]
pub struct ListCommitsResp {
    pub commits: Vec<CommitRowWire>,
    pub next_cursor: String, // first-parent of the last row; empty when the chain ended
    /// `false` when the walk hit a hash NOT in the index (pre-index history) —
    /// the worker then completes + backfills from R2.
    pub complete: bool,
}

/// Backfill: record rows the worker decoded from R2 (for history pushed before
/// the index existed), so subsequent reads are fully local.
#[derive(Serialize, Deserialize)]
pub struct RecordCommitsReq {
    pub r#ref: String,
    pub commits: Vec<CommitRowWire>,
}

#[derive(Serialize, Deserialize)]
pub struct RecordCommitsResp {
    pub recorded: u32,
}

// --- Room purge (worker -> DO) ----------------------------------------------
//
//   POST /purge (no body) -> PurgeResp
//
// Wipes every table row scoped to this DO instance (one instance per room):
// refs, messages, reactions (with react_rate), and the
// commits index. The worker purges the room's R2 prefixes (objects/,
// messages/) separately — the DO owns none of R2. See service.rs
// `purge_room` and refstore.rs `handle_purge`.

#[derive(Serialize, Deserialize)]
pub struct PurgeResp {
    pub refs_deleted: u32,
    pub messages_deleted: u32,
    pub reactions_deleted: u32,
}

#[derive(Serialize, Deserialize)]
pub struct ObjectWriteReq {
    pub proof: mkit_worker_common::replay::Proof,
    pub bytes: u64,
    pub result: Option<ObjectWriteResult>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ObjectWriteResult {
    pub stored: bool,
}
#[derive(Serialize, Deserialize)]
pub struct ObjectWriteResp {
    pub result: Option<ObjectWriteResult>,
}
