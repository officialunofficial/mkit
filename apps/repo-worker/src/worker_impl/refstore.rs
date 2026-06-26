// SPDX-License-Identifier: MIT OR Apache-2.0
//
// RefStore Durable Object — one instance per room, the single source of truth
// for mutable refs. All ref reads/writes funnel through here so the CAS in
// `UpdateRef` runs inside the DO's serial single-threaded execution (no lost
// updates, no torn reads). WatchRefs subscribers attach over a hibernatable
// WebSocket and receive one event per successful ref advance.
//
// Storage: SQLite (`state.storage().sql()`), table `refs(path PRIMARY KEY,
// value)`. `value` is the 64-char lowercase hex of the 32-byte object id.
//
// Internal wire protocol (the worker -> DO via `stub.fetch_with_request`),
// all JSON over HTTP to a `https://refstore/<op>` URL:
//   POST /get    { "name": "<ref>" }                       -> { "exists", "value"? }
//   POST /update { "name", "new", "expectation", "expected"?, "author"? }
//                                                          -> { "committed", "conflict", "current"? }
//   POST /list   { "prefix": "<prefix>" }                  -> { "refs": [ { "name", "value" } ] }
//   GET  /watch  (Upgrade: websocket)                      -> 101, streams RefEvent JSON frames
//
// `expectation` is the proto wire number (1=ANY, 2=MISSING, 3=MATCH). The
// CAS decision itself is the pure `refs::evaluate_cas` shared with the unit
// tests, so the DO and the conformance vectors agree by construction.

use std::cell::Cell;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
// `wasm_bindgen` must be in scope: the `#[durable_object]` macro emits glue
// that references it by name. `DurableObject` is the trait we implement.
use worker::{
    durable_object, wasm_bindgen, Date, DurableObject, Env, Request, Response, ResponseBuilder,
    Result, State, WebSocket, WebSocketIncomingMessage, WebSocketPair,
};

use crate::chat::is_rate_limited;
use crate::envelope::FRESHNESS_WINDOW_MS;
use crate::refs::{evaluate_cas, CasDecision, ConflictReason, RefExpectation};
// DO wire types are declared once in `super::wire` and shared with service.rs,
// so a field rename can't desync the worker (client) and the DO (server).
use super::wire::{
    GetReq, GetResp, ListEntry, ListReq, ListResp, MessagesReq, MessagesResp, MsgEntry, PostReq,
    PostResp, UpdateReq, UpdateResp,
};

/// Default + max page size for `/messages` (the lobby backlog). A request for
/// `limit=0` gets the default; anything above the max is clamped.
const MESSAGES_DEFAULT_LIMIT: u32 = 50;
const MESSAGES_MAX_LIMIT: u32 = 200;

/// How many recent messages the DO's SQLite index retains. The permanent,
/// content-addressed copy of every message lives in R2 (written by the worker
/// before /post); this index is a bounded serving cache so the DO's storage
/// can't grow without limit (a Cloudflare best practice) — generously larger
/// than MESSAGES_MAX_LIMIT so paging is unaffected.
const MESSAGES_RETAINED: i64 = 1_000;

/// A live ref advance, broadcast to every `/watch` subscriber. `kind` tags the
/// frame as a commit so the SAME socket can also carry chat frames (the lobby
/// merges both into one feed); the hex fields are decoded back to raw bytes by
/// the worker before re-encoding into the proto `RefEvent`.
#[derive(Serialize, Deserialize, Clone)]
pub struct RefEventJson {
    /// Always `"commit"` — distinguishes a ref advance from a `"chat"` frame.
    pub kind: String,
    pub name: String,
    pub object_id: String,           // 64-hex
    pub author_pubkey: Option<String>, // 64-hex
}

/// A live chat message, broadcast to every `/watch` subscriber alongside ref
/// advances. `kind` is `"chat"`; fields mirror the proto `ChatMessage`.
#[derive(Serialize, Deserialize, Clone)]
pub struct ChatEventJson {
    pub kind: String, // always "chat"
    pub message_id: String,   // 64-hex content address
    pub author_pubkey: String, // 64-hex
    pub text: String,
    pub created_at: i64,
    pub seq: u64,
}

/// Per-socket presence, stored as the hibernatable WebSocket attachment so the
/// roster survives DO hibernation (it's rebuilt from `get_websockets()` on
/// demand rather than held in memory).
#[derive(Serialize, Deserialize, Clone)]
struct PresenceAttachment {
    /// Unique per connection — lets `websocket_close` drop exactly this socket
    /// from the roster even when several share a pubkey (or are all viewers).
    id: String,
    /// 64-hex Ed25519 pubkey, or `None` for a signed-out viewer.
    pubkey: Option<String>,
    /// Epoch-ms the socket joined.
    since: i64,
}

/// Live presence roster, broadcast to every `/watch` subscriber on join/leave.
/// `kind: "presence"` distinguishes it from `"commit"` / `"chat"` frames so the
/// one socket can carry all three.
#[derive(Serialize)]
struct PresenceJson {
    kind: &'static str,
    /// Distinct online keys (deduped by pubkey across tabs), earliest `since`.
    members: Vec<PresenceMember>,
    /// Connections with no identity yet — the "N viewers" count.
    viewers: u32,
}

#[derive(Serialize)]
struct PresenceMember {
    pubkey: String,
    since: i64,
}

/// A 64-char lowercase-hex Ed25519 pubkey. Shared with the worker so an invalid
/// `?pubkey=` is treated as a viewer rather than trusted.
pub(crate) fn is_valid_pubkey(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[durable_object]
pub struct RefStore {
    state: State,
    /// Per-isolate connection counter, combined with the wall clock in
    /// `next_conn_id` to mint a unique id per `/watch` socket (single-threaded
    /// wasm, so a `Cell` is enough — no synchronisation needed).
    conn_seq: Cell<u64>,
}

impl DurableObject for RefStore {
    fn new(state: State, _env: Env) -> Self {
        // Defer table creation to the first storage op (`ensure_table`). A DDL
        // failure here would panic the isolate at construction; instead it now
        // surfaces as a clean error on the first fetch.
        Self {
            state,
            conn_seq: Cell::new(0),
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let path = req.path();

        // WatchRefs subscription: accept a hibernatable server WebSocket.
        if path == "/watch" {
            // Optional `?pubkey=<64-hex>` attributes this connection to a key;
            // absent or malformed → a signed-out viewer. Read it before the
            // upgrade (the URL query isn't available afterwards).
            let pubkey = req
                .url()
                .ok()
                .and_then(|u| {
                    u.query_pairs()
                        .find(|(k, _)| k == "pubkey")
                        .map(|(_, v)| v.into_owned())
                })
                .filter(|p| is_valid_pubkey(p));

            let pair = WebSocketPair::new()?;
            self.state.accept_web_socket(&pair.server);
            // Stash the presence info ON the socket so it survives hibernation.
            let _ = pair.server.serialize_attachment(PresenceAttachment {
                id: self.next_conn_id(),
                pubkey,
                since: Date::now().as_millis() as i64,
            });
            // Tell everyone (including the newcomer) the updated roster.
            self.broadcast_presence(None);
            return Ok(ResponseBuilder::new()
                .with_status(101)
                .with_websocket(pair.client)
                .empty());
        }

        // Lazily create the backing tables before any read/write op. On failure
        // return a clean 500 rather than panicking the isolate (H4).
        match path.as_str() {
            "/get" | "/update" | "/list" => {
                if let Err(e) = self.ensure_table() {
                    return Response::error(format!("storage init failed: {e}"), 500);
                }
            }
            "/post" | "/messages" => {
                if let Err(e) = self.ensure_messages_table() {
                    return Response::error(format!("storage init failed: {e}"), 500);
                }
            }
            _ => {}
        }

        match path.as_str() {
            "/get" => {
                let body: GetReq = req.json().await?;
                let value = self.read_ref(&body.name);
                Response::from_json(&GetResp {
                    exists: value.is_some(),
                    value,
                })
            }
            "/update" => {
                let body: UpdateReq = req.json().await?;
                self.handle_update(body)
            }
            "/list" => {
                let body: ListReq = req.json().await?;
                let refs = self.list_refs(&body.prefix);
                Response::from_json(&ListResp { refs })
            }
            "/post" => {
                let body: PostReq = req.json().await?;
                self.handle_post(body)
            }
            "/messages" => {
                let body: MessagesReq = req.json().await?;
                let messages = self.list_messages(body.limit);
                Response::from_json(&MessagesResp { messages })
            }
            _ => Response::error("not found", 404),
        }
    }

    // --- Hibernatable-WebSocket lifecycle handlers --------------------------
    //
    // WatchRefs subscribers attach via `accept_web_socket` (above). The default
    // trait impls `unimplemented!()` (panic → "unreachable"), so they must be
    // provided. Ref/chat fan-out is server→client, so inbound frames are
    // ignored; close/error update the presence roster for everyone else.

    async fn websocket_message(
        &self,
        _ws: WebSocket,
        _message: WebSocketIncomingMessage,
    ) -> Result<()> {
        Ok(())
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        // The closing socket is still in `get_websockets()` here, so drop it by
        // id when recomputing the roster.
        self.broadcast_presence(closing_id(&ws).as_deref());
        Ok(())
    }

    async fn websocket_error(&self, ws: WebSocket, _error: worker::Error) -> Result<()> {
        self.broadcast_presence(closing_id(&ws).as_deref());
        Ok(())
    }
}

/// The presence id stashed on a socket (or `None` if it carried no attachment).
fn closing_id(ws: &WebSocket) -> Option<String> {
    ws.deserialize_attachment::<PresenceAttachment>()
        .ok()
        .flatten()
        .map(|a| a.id)
}

impl RefStore {
    /// Idempotently create the `refs` table. Called at the top of each storage
    /// op so a transient DDL failure surfaces as a clean error instead of
    /// panicking the isolate (H4). `CREATE TABLE IF NOT EXISTS` is cheap to
    /// repeat.
    fn ensure_table(&self) -> Result<()> {
        self.state.storage().sql().exec(
            "CREATE TABLE IF NOT EXISTS refs (path TEXT PRIMARY KEY, value TEXT NOT NULL);",
            None,
        )?;
        Ok(())
    }

    /// Read a ref's current hex value, or None if absent.
    fn read_ref(&self, name: &str) -> Option<String> {
        #[derive(Deserialize)]
        struct Row {
            value: String,
        }
        let rows: Vec<Row> = self
            .state
            .storage()
            .sql()
            .exec("SELECT value FROM refs WHERE path = ? LIMIT 1;", vec![name.into()])
            .ok()?
            .to_array()
            .ok()?;
        rows.into_iter().next().map(|r| r.value)
    }

    /// Apply the CAS update serially. Reads the current value, evaluates the
    /// pure CAS decision, and on commit upserts + broadcasts a RefEvent.
    fn handle_update(&self, req: UpdateReq) -> Result<Response> {
        let current = self.read_ref(&req.name);
        let expectation = RefExpectation::from_wire(req.expectation);
        let expected_bytes = req.expected.as_ref().and_then(|s| hex::decode(s).ok());
        let current_bytes = current.as_ref().and_then(|s| hex::decode(s).ok());

        let decision = evaluate_cas(
            current_bytes.as_deref(),
            expectation,
            expected_bytes.as_deref(),
        );

        match decision {
            CasDecision::Committed => {
                let sql = self.state.storage().sql();
                // Upsert: SQLite ON CONFLICT replaces the value for this path.
                sql.exec(
                    "INSERT INTO refs (path, value) VALUES (?, ?) \
                     ON CONFLICT(path) DO UPDATE SET value = excluded.value;",
                    vec![req.name.clone().into(), req.new.clone().into()],
                )?;
                self.broadcast(&RefEventJson {
                    kind: "commit".to_string(),
                    name: req.name.clone(),
                    object_id: req.new.clone(),
                    author_pubkey: req.author.clone(),
                });
                Response::from_json(&UpdateResp {
                    committed: true,
                    conflict: false,
                    current: Some(req.new),
                })
            }
            CasDecision::Conflict(reason) => {
                // On a precondition failure return the present value (if any)
                // so the client can rebase. `Missing` means the ref is absent.
                let current = match reason {
                    ConflictReason::Missing => None,
                    _ => current,
                };
                Response::from_json(&UpdateResp {
                    committed: false,
                    conflict: true,
                    current,
                })
            }
            CasDecision::Invalid(msg) => Response::error(msg, 400),
        }
    }

    /// List refs whose path starts with `prefix` (empty = all).
    fn list_refs(&self, prefix: &str) -> Vec<ListEntry> {
        #[derive(Deserialize)]
        struct Row {
            path: String,
            value: String,
        }
        let pattern = format!("{}%", prefix.replace('%', "\\%").replace('_', "\\_"));
        let rows: Vec<Row> = self
            .state
            .storage()
            .sql()
            .exec(
                "SELECT path, value FROM refs WHERE path LIKE ? ESCAPE '\\' ORDER BY path;",
                vec![pattern.into()],
            )
            .map(|r| r.to_array().unwrap_or_default())
            .unwrap_or_default();
        rows.into_iter()
            .map(|r| ListEntry { name: r.path, value: r.value })
            .collect()
    }

    /// Idempotently create the `messages` table — the room's chat log. `seq` is
    /// the monotonic per-room order (AUTOINCREMENT) used to page the backlog and
    /// to merge chat against commits in the feed; `created_at` is the DO's own
    /// epoch-ms stamp (server-authoritative ordering, not client clocks). The
    /// author index keeps the per-author rate-limit lookup cheap.
    fn ensure_messages_table(&self) -> Result<()> {
        let sql = self.state.storage().sql();
        sql.exec(
            "CREATE TABLE IF NOT EXISTS messages (\
               seq INTEGER PRIMARY KEY AUTOINCREMENT, \
               id TEXT NOT NULL, \
               author TEXT NOT NULL, \
               text TEXT NOT NULL, \
               created_at INTEGER NOT NULL);",
            None,
        )?;
        sql.exec(
            "CREATE INDEX IF NOT EXISTS messages_author ON messages(author);",
            None,
        )?;
        // Replay-dedupe ledger: the (author, idempotency-key) of each accepted
        // post, with the seq/created_at it produced. A replay of a captured
        // signed request (same author+key) returns the ORIGINAL result instead
        // of inserting a duplicate row. Bounded to the envelope freshness window
        // (older keys can't pass envelope verification anyway).
        sql.exec(
            "CREATE TABLE IF NOT EXISTS idem_keys (\
               author TEXT NOT NULL, \
               idem TEXT NOT NULL, \
               seq INTEGER NOT NULL, \
               created_at INTEGER NOT NULL, \
               PRIMARY KEY (author, idem));",
            None,
        )?;
        Ok(())
    }

    /// Append a chat message under the per-author rate limit, serially (the DO's
    /// single-threaded execution makes the read-then-insert atomic, so two posts
    /// from one author can't both slip past the floor). On accept, stamp the
    /// server clock + the new `seq`, then broadcast a `"chat"` frame to every
    /// `/watch` subscriber. The worker has already content-addressed + stored
    /// the message bytes in R2 and verified the author envelope.
    fn handle_post(&self, req: PostReq) -> Result<Response> {
        let now = Date::now().as_millis() as i64;

        // Replay dedupe FIRST (before the rate limit): a re-submitted signed
        // request (same author + idempotency-key) returns the ORIGINAL result,
        // so a captured signature can't be amplified into duplicate messages and
        // a client retry is idempotent. A genuinely new post carries a fresh key.
        if !req.idem.is_empty() {
            if let Some((seq, created_at)) = self.idem_lookup(&req.author, &req.idem) {
                return Response::from_json(&PostResp {
                    accepted: true,
                    rate_limited: false,
                    seq,
                    created_at,
                });
            }
        }

        let last = self.last_post_ms(&req.author);
        if is_rate_limited(last, now) {
            return Response::from_json(&PostResp {
                accepted: false,
                rate_limited: true,
                seq: 0,
                created_at: 0,
            });
        }

        let sql = self.state.storage().sql();
        sql.exec(
            "INSERT INTO messages (id, author, text, created_at) VALUES (?, ?, ?, ?);",
            vec![
                req.id.clone().into(),
                req.author.clone().into(),
                req.text.clone().into(),
                now.into(),
            ],
        )?;

        // The AUTOINCREMENT rowid of the row we just inserted IS its `seq`.
        #[derive(Deserialize)]
        struct Seq {
            seq: i64,
        }
        let seq_rows: Vec<Seq> = sql
            .exec("SELECT last_insert_rowid() AS seq;", None)
            .and_then(|r| r.to_array())
            .unwrap_or_default();
        let seq: u64 = seq_rows.into_iter().next().map(|r| r.seq as u64).unwrap_or(0);

        // Bound the serving index: drop rows older than the most-recent
        // MESSAGES_RETAINED (R2 still holds every message permanently). seq is
        // monotonic, so this keeps exactly the newest window.
        let _ = sql.exec(
            "DELETE FROM messages WHERE seq <= (SELECT MAX(seq) FROM messages) - ?;",
            vec![MESSAGES_RETAINED.into()],
        );

        // Record this (author, idem) → result for replay dedupe, then drop keys
        // older than the freshness window (a replay that old fails envelope
        // verification, so its key is no longer needed).
        if !req.idem.is_empty() {
            let _ = sql.exec(
                "INSERT OR REPLACE INTO idem_keys (author, idem, seq, created_at) VALUES (?, ?, ?, ?);",
                vec![req.author.clone().into(), req.idem.clone().into(), (seq as i64).into(), now.into()],
            );
            let _ = sql.exec(
                "DELETE FROM idem_keys WHERE created_at < ?;",
                vec![(now - FRESHNESS_WINDOW_MS).into()],
            );
        }

        self.broadcast_str(
            &serde_json::to_string(&ChatEventJson {
                kind: "chat".to_string(),
                message_id: req.id.clone(),
                author_pubkey: req.author.clone(),
                text: req.text.clone(),
                created_at: now,
                seq,
            })
            .unwrap_or_default(),
        );

        Response::from_json(&PostResp {
            accepted: true,
            rate_limited: false,
            seq,
            created_at: now,
        })
    }

    /// If this (author, idempotency-key) already produced a message, return its
    /// (seq, created_at) so a replay can return the original result. None on a
    /// first-seen key.
    fn idem_lookup(&self, author: &str, idem: &str) -> Option<(u64, i64)> {
        #[derive(Deserialize)]
        struct Row {
            seq: i64,
            created_at: i64,
        }
        let rows: Vec<Row> = self
            .state
            .storage()
            .sql()
            .exec(
                "SELECT seq, created_at FROM idem_keys WHERE author = ? AND idem = ? LIMIT 1;",
                vec![author.into(), idem.into()],
            )
            .ok()?
            .to_array()
            .ok()?;
        rows.into_iter().next().map(|r| (r.seq as u64, r.created_at))
    }

    /// The author's most recent post time (epoch-ms), or None if they've never
    /// posted — the input to the rate-limit decision.
    fn last_post_ms(&self, author: &str) -> Option<i64> {
        #[derive(Deserialize)]
        struct Row {
            created_at: i64,
        }
        let rows: Vec<Row> = self
            .state
            .storage()
            .sql()
            .exec(
                "SELECT created_at FROM messages WHERE author = ? ORDER BY seq DESC LIMIT 1;",
                vec![author.into()],
            )
            .ok()?
            .to_array()
            .ok()?;
        rows.into_iter().next().map(|r| r.created_at)
    }

    /// The most recent `limit` messages, returned OLDEST-FIRST (chat reading
    /// order). `limit` is clamped to [1, MESSAGES_MAX_LIMIT]; 0 → default.
    fn list_messages(&self, limit: u32) -> Vec<MsgEntry> {
        let limit = match limit {
            0 => MESSAGES_DEFAULT_LIMIT,
            n => n.min(MESSAGES_MAX_LIMIT),
        };
        #[derive(Deserialize)]
        struct Row {
            seq: i64,
            id: String,
            author: String,
            text: String,
            created_at: i64,
        }
        // Newest `limit` rows, then reverse to oldest-first for the caller.
        let mut rows: Vec<Row> = self
            .state
            .storage()
            .sql()
            .exec(
                "SELECT seq, id, author, text, created_at FROM messages \
                 ORDER BY seq DESC LIMIT ?;",
                vec![(limit as i64).into()],
            )
            .map(|r| r.to_array().unwrap_or_default())
            .unwrap_or_default();
        rows.reverse();
        rows.into_iter()
            .map(|r| MsgEntry {
                id: r.id,
                author: r.author,
                text: r.text,
                created_at: r.created_at,
                seq: r.seq as u64,
            })
            .collect()
    }

    /// Push a ref event to every `/watch` subscriber as a JSON frame.
    fn broadcast(&self, event: &RefEventJson) {
        let Ok(payload) = serde_json::to_string(event) else { return };
        self.broadcast_str(&payload);
    }

    /// Fan a pre-serialized JSON frame out to every attached `/watch` socket.
    /// Shared by ref-advance and chat broadcasts so both ride the one stream.
    fn broadcast_str(&self, payload: &str) {
        for ws in self.state.get_websockets() {
            // Best-effort: a closed/errored socket is simply skipped; the
            // runtime drops it from the set on the next cycle.
            let _ = ws.send_with_str(payload);
        }
    }

    /// Mint a unique id per `/watch` connection: wall clock (unique across
    /// hibernations) + an isolate-local counter (unique within one isolate).
    fn next_conn_id(&self) -> String {
        let n = self.conn_seq.get();
        self.conn_seq.set(n.wrapping_add(1));
        format!("{:x}-{:x}", Date::now().as_millis(), n)
    }

    /// Recompute the live roster from every attached socket's presence
    /// attachment and broadcast a `"presence"` frame to all. `exclude_id` drops
    /// a socket that is mid-close (still present in `get_websockets()` during
    /// `websocket_close`). Keys are deduped across tabs (earliest `since` wins);
    /// identity-less connections are tallied as `viewers`.
    fn broadcast_presence(&self, exclude_id: Option<&str>) {
        let mut by_key: BTreeMap<String, i64> = BTreeMap::new();
        let mut viewers: u32 = 0;
        for ws in self.state.get_websockets() {
            let Some(att) = ws
                .deserialize_attachment::<PresenceAttachment>()
                .ok()
                .flatten()
            else {
                continue;
            };
            if exclude_id == Some(att.id.as_str()) {
                continue;
            }
            match att.pubkey {
                Some(pk) => {
                    by_key
                        .entry(pk)
                        .and_modify(|s| *s = (*s).min(att.since))
                        .or_insert(att.since);
                }
                None => viewers = viewers.saturating_add(1),
            }
        }
        let members = by_key
            .into_iter()
            .map(|(pubkey, since)| PresenceMember { pubkey, since })
            .collect();
        if let Ok(payload) = serde_json::to_string(&PresenceJson {
            kind: "presence",
            members,
            viewers,
        }) {
            self.broadcast_str(&payload);
        }
    }
}
