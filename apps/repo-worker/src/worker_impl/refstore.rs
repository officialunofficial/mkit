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

use serde::{Deserialize, Serialize};
// `wasm_bindgen` must be in scope: the `#[durable_object]` macro emits glue
// that references it by name. `DurableObject` is the trait we implement.
use worker::{
    durable_object, wasm_bindgen, Date, DurableObject, Env, Request, Response, ResponseBuilder,
    Result, State, WebSocket, WebSocketIncomingMessage, WebSocketPair,
};

use crate::chat::{is_rate_limited, REACT_MIN_INTERVAL_MS};
use crate::envelope::FRESHNESS_WINDOW_MS;
use crate::refs::{evaluate_cas, CasDecision, ConflictReason, RefExpectation};
// DO wire types are declared once in `super::wire` and shared with service.rs,
// so a field rename can't desync the worker (client) and the DO (server).
use super::wire::{
    CommitMetaWire, GetReq, GetResp, ListEntry, ListReq, ListResp, MessagesReq, MessagesResp,
    MsgEntry, PostReq, PostResp, ReactReq, ReactResp, ReactionEntry, ReactionsResp, UpdateReq,
    UpdateResp,
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

/// How many reaction rows the DO keeps per room. Like the messages index this
/// bounds the DO's SQLite so a flood of (target, emoji, author) tuples can't
/// grow it without limit; `list_reactions` reads at most this many.
const REACTIONS_RETAINED: i64 = 5_000;

/// A live frame broadcast to every `/watch` subscriber. The SAME socket carries
/// commit / chat / reaction frames so the lobby renders one merged feed; the
/// `kind` discriminator is the serde tag (set by the enum, not by hand), so a
/// variant and its tag can't drift. Hex fields are decoded back to raw bytes by
/// the worker before re-encoding into the proto where needed. Wire shape is
/// `{"kind":"commit"|"chat"|"reaction", …variant fields}` — matched 1:1 by the
/// client's `parseActivityFrame`.
#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WatchFrame {
    Commit {
        name: String,
        object_id: String,                 // 64-hex
        author_pubkey: Option<String>,     // 64-hex
    },
    Chat {
        message_id: String,                // 64-hex content address
        author_pubkey: String,             // 64-hex
        text: String,
        created_at: i64,
        seq: u64,
    },
    Reaction {
        target_id: String,
        emoji: String,
        author_pubkey: String,             // 64-hex
        active: bool,
        count: u32,
    },
}

/// The smallest string strictly greater than every string having `prefix` as a
/// prefix — used as the exclusive upper bound of a prefix range scan. Clone the
/// bytes, drop trailing `0xFF`, and increment the last remaining byte. Returns
/// `None` when the prefix is empty or all-`0xFF` (no finite successor), or when
/// the increment would break UTF-8 — callers then fall back to a lower-bound-only
/// scan (still correct, just not upper-bounded).
fn prefix_successor(prefix: &str) -> Option<String> {
    let mut bytes = prefix.as_bytes().to_vec();
    while let Some(&last) = bytes.last() {
        if last == 0xFF {
            bytes.pop();
        } else {
            let n = bytes.len();
            bytes[n - 1] = last + 1;
            return String::from_utf8(bytes).ok();
        }
    }
    None
}

#[durable_object]
pub struct RefStore {
    state: State,
}

impl DurableObject for RefStore {
    fn new(state: State, _env: Env) -> Self {
        // Defer table creation to the first storage op (`ensure_table`). A DDL
        // failure here would panic the isolate at construction; instead it now
        // surfaces as a clean error on the first fetch.
        Self { state }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let path = req.path();

        // WatchRefs subscription: accept a hibernatable server WebSocket.
        if path == "/watch" {
            let pair = WebSocketPair::new()?;
            self.state.accept_web_socket(&pair.server);
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
                if path == "/update" {
                    if let Err(e) = self.ensure_commits_table() {
                        return Response::error(format!("storage init failed: {e}"), 500);
                    }
                }
            }
            "/post" | "/messages" => {
                if let Err(e) = self.ensure_messages_table() {
                    return Response::error(format!("storage init failed: {e}"), 500);
                }
            }
            "/react" | "/reactions" => {
                if let Err(e) = self.ensure_reactions_table() {
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
            "/react" => {
                let body: ReactReq = req.json().await?;
                self.handle_react(body)
            }
            "/reactions" => {
                let reactions = self.list_reactions();
                Response::from_json(&ReactionsResp { reactions })
            }
            _ => Response::error("not found", 404),
        }
    }

    // --- Hibernatable-WebSocket lifecycle handlers --------------------------
    //
    // WatchRefs subscribers attach via `accept_web_socket` (above). The default
    // trait impls of these handlers `unimplemented!()` (panic → "unreachable"),
    // so a subscriber merely connecting and disconnecting would crash the DO.
    // The fan-out is strictly server→client (broadcast on UpdateRef), so:
    //   - inbound frames are ignored (clients never send),
    //   - close/error are no-ops (the runtime drops the socket from the set).

    async fn websocket_message(
        &self,
        _ws: WebSocket,
        _message: WebSocketIncomingMessage,
    ) -> Result<()> {
        Ok(())
    }

    async fn websocket_close(
        &self,
        _ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, _error: worker::Error) -> Result<()> {
        Ok(())
    }
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

    /// Idempotently create the `commits` index — the denormalized commit-log
    /// (one row per commit/remix, keyed by its hash, with first `parent` for the
    /// chain walk + the fields the lobby renders). Populated on each ref update
    /// (and backfilled from R2 on demand) so `ListCommits` can be served from
    /// this colocated table instead of a per-read R2 walk.
    fn ensure_commits_table(&self) -> Result<()> {
        let sql = self.state.storage().sql();
        sql.exec(
            "CREATE TABLE IF NOT EXISTS commits (\
               hash TEXT PRIMARY KEY, \
               ref TEXT NOT NULL, \
               parent TEXT NOT NULL, \
               signer TEXT NOT NULL, \
               message TEXT NOT NULL, \
               timestamp INTEGER NOT NULL, \
               kind TEXT NOT NULL, \
               sources TEXT NOT NULL);",
            None,
        )?;
        Ok(())
    }

    /// Record one commit into the `commits` index (idempotent — a re-push of the
    /// same hash is a no-op since the object is immutable).
    fn record_commit(&self, hash: &str, ref_name: &str, m: &CommitMetaWire) -> Result<()> {
        self.state.storage().sql().exec(
            "INSERT OR IGNORE INTO commits \
               (hash, ref, parent, signer, message, timestamp, kind, sources) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
            vec![
                hash.into(),
                ref_name.into(),
                m.parent.clone().into(),
                m.signer.clone().into(),
                m.message.clone().into(),
                m.timestamp.into(),
                m.kind.clone().into(),
                m.sources.clone().into(),
            ],
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
                // Dual-write the denormalized commit index. Best-effort: a record
                // failure must NOT fail the (already-committed) ref update — the
                // index is rebuildable by backfill from R2.
                if let Some(m) = &req.commit {
                    if let Err(e) = self.record_commit(&req.new, &req.name, m) {
                        worker::console_error!("record_commit failed for {}: {e}", req.name);
                    }
                }
                self.broadcast(&WatchFrame::Commit {
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
        // Prefix match as a HALF-OPEN RANGE over the `path` PRIMARY KEY so SQLite
        // seeks the index and scans only matching rows. A `LIKE 'p%' ESCAPE` can
        // NOT use the BINARY-collated PK index (the ESCAPE clause and the
        // case-insensitive default both disable the LIKE-prefix optimization), so
        // it full-scans every ref. `hi` is the prefix successor; an empty prefix
        // (or an all-0xFF one with no finite successor) drops the upper bound.
        let sql = self.state.storage().sql();
        let rows: Vec<Row> = if prefix.is_empty() {
            sql.exec("SELECT path, value FROM refs ORDER BY path;", None)
        } else if let Some(hi) = prefix_successor(prefix) {
            sql.exec(
                "SELECT path, value FROM refs WHERE path >= ? AND path < ? ORDER BY path;",
                vec![prefix.into(), hi.into()],
            )
        } else {
            sql.exec(
                "SELECT path, value FROM refs WHERE path >= ? ORDER BY path;",
                vec![prefix.into()],
            )
        }
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
        // Index the time column so the per-post freshness prune
        // (`DELETE … WHERE created_at < ?`) seeks the expired tail instead of
        // full-scanning the whole room-wide ledger on every accepted post.
        sql.exec(
            "CREATE INDEX IF NOT EXISTS idem_keys_created ON idem_keys(created_at);",
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
        let seq: u64 = match seq_rows.into_iter().next() {
            Some(r) => r.seq as u64,
            // The row WAS inserted (the INSERT above used `?`); a missing rowid
            // here means the SELECT itself failed — surface it rather than
            // silently shipping a seq=0 that downstream can't order.
            None => {
                worker::console_error!("post_message: last_insert_rowid() returned no row; persisted message broadcast with seq=0");
                0
            }
        };

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

        // Use the typed `broadcast` helper (like the Commit path) so a serialize
        // failure SKIPS the frame rather than fanning out an empty string "".
        self.broadcast(&WatchFrame::Chat {
            message_id: req.id.clone(),
            author_pubkey: req.author.clone(),
            text: req.text.clone(),
            created_at: now,
            seq,
        });

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

    /// Idempotently create the `reactions` table. One row per
    /// (target, emoji, author); the PK makes a reaction unique per reactor and
    /// makes toggling a single delete/insert.
    fn ensure_reactions_table(&self) -> Result<()> {
        let sql = self.state.storage().sql();
        sql.exec(
            "CREATE TABLE IF NOT EXISTS reactions (\
               target TEXT NOT NULL, \
               emoji TEXT NOT NULL, \
               author TEXT NOT NULL, \
               created_at INTEGER NOT NULL, \
               PRIMARY KEY (target, emoji, author));",
            None,
        )?;
        sql.exec(
            "CREATE INDEX IF NOT EXISTS reactions_created ON reactions(created_at);",
            None,
        )?;
        // Replay-dedupe for React: the (author, idempotency-key) of each accepted
        // toggle and the result it produced. A replay returns the original result
        // (no re-toggle). Bounded to the freshness window. NOTE: this is keyed on
        // a PRESENT idempotency key, so it can't be the rate-limit input — a
        // client may omit the key. The rate floor reads `react_rate` instead.
        sql.exec(
            "CREATE TABLE IF NOT EXISTS react_idem (\
               author TEXT NOT NULL, \
               idem TEXT NOT NULL, \
               active INTEGER NOT NULL, \
               count INTEGER NOT NULL, \
               created_at INTEGER NOT NULL, \
               PRIMARY KEY (author, idem));",
            None,
        )?;
        // Per-author rate ledger: the time of each author's last ACCEPTED toggle,
        // recorded UNCONDITIONALLY (independent of any idempotency key) so the
        // anti-flood floor can't be sidestepped by omitting the key. One row per
        // author; pruned by the freshness window alongside `react_idem`.
        sql.exec(
            "CREATE TABLE IF NOT EXISTS react_rate (\
               author TEXT PRIMARY KEY, \
               last_ms INTEGER NOT NULL);",
            None,
        )?;
        // Index the time columns both per-React prunes filter on, so each
        // `DELETE … WHERE created_at < ?` / `WHERE last_ms < ?` seeks the expired
        // tail instead of full-scanning the whole table on every accepted toggle
        // (a reaction storm was O(reactions × authors) without these).
        sql.exec(
            "CREATE INDEX IF NOT EXISTS react_idem_created ON react_idem(created_at);",
            None,
        )?;
        sql.exec(
            "CREATE INDEX IF NOT EXISTS react_rate_last ON react_rate(last_ms);",
            None,
        )?;
        Ok(())
    }

    /// Toggle a reaction serially, with the same guards the chat write path has:
    /// replay dedupe (a re-submitted signed toggle returns its original result),
    /// a per-author anti-flood rate limit, and a bound on the reactions table.
    fn handle_react(&self, req: ReactReq) -> Result<Response> {
        let sql = self.state.storage().sql();
        let now = Date::now().as_millis() as i64;

        // 1) Replay dedupe: a re-submitted signed React (same author + idem)
        // returns the ORIGINAL result instead of toggling state again.
        if !req.idem.is_empty() {
            if let Some((active, count)) = self.react_idem_lookup(&req.author, &req.idem) {
                return Response::from_json(&ReactResp { active, count });
            }
        }

        let had = self.reaction_exists(&req.target, &req.emoji, &req.author);

        // 2) Per-author anti-flood floor. On refusal, return the CURRENT state
        // unchanged (no toggle, no broadcast); the optimistic client reconciles
        // on its settle refetch.
        let last = self.last_react_ms(&req.author);
        if last.is_some_and(|l| now - l < REACT_MIN_INTERVAL_MS) {
            let count = self.reaction_count(&req.target, &req.emoji);
            return Response::from_json(&ReactResp { active: had, count });
        }

        // 3) Toggle.
        if had {
            sql.exec(
                "DELETE FROM reactions WHERE target = ? AND emoji = ? AND author = ?;",
                vec![req.target.clone().into(), req.emoji.clone().into(), req.author.clone().into()],
            )?;
        } else {
            sql.exec(
                "INSERT INTO reactions (target, emoji, author, created_at) VALUES (?, ?, ?, ?);",
                vec![
                    req.target.clone().into(),
                    req.emoji.clone().into(),
                    req.author.clone().into(),
                    now.into(),
                ],
            )?;
        }
        let active = !had;
        let count = self.reaction_count(&req.target, &req.emoji);

        // 4a) Record the rate-limit timestamp UNCONDITIONALLY — this is the only
        // input to the anti-flood floor, so it must run whether or not the client
        // supplied an idempotency key (otherwise the floor is trivially bypassed).
        let _ = sql.exec(
            "INSERT OR REPLACE INTO react_rate (author, last_ms) VALUES (?, ?);",
            vec![req.author.clone().into(), now.into()],
        );

        // 4b) Record the idem result for replay dedupe (only when a key was sent),
        // then prune both ledgers by freshness and bound the reactions table.
        if !req.idem.is_empty() {
            let _ = sql.exec(
                "INSERT OR REPLACE INTO react_idem (author, idem, active, count, created_at) VALUES (?, ?, ?, ?, ?);",
                vec![
                    req.author.clone().into(),
                    req.idem.clone().into(),
                    i64::from(active).into(),
                    i64::from(count).into(),
                    now.into(),
                ],
            );
        }
        let _ = sql.exec(
            "DELETE FROM react_idem WHERE created_at < ?;",
            vec![(now - FRESHNESS_WINDOW_MS).into()],
        );
        let _ = sql.exec(
            "DELETE FROM react_rate WHERE last_ms < ?;",
            vec![(now - FRESHNESS_WINDOW_MS).into()],
        );
        // Keep only the newest REACTIONS_RETAINED rows by insert time.
        let _ = sql.exec(
            "DELETE FROM reactions WHERE created_at < \
               (SELECT MIN(created_at) FROM \
                  (SELECT created_at FROM reactions ORDER BY created_at DESC LIMIT ?));",
            vec![REACTIONS_RETAINED.into()],
        );

        // 5) Broadcast + respond. Typed `broadcast` (like Commit/Chat) so a
        // serialize failure skips the frame rather than fanning out "".
        self.broadcast(&WatchFrame::Reaction {
            target_id: req.target.clone(),
            emoji: req.emoji.clone(),
            author_pubkey: req.author.clone(),
            active,
            count,
        });

        Response::from_json(&ReactResp { active, count })
    }

    /// Whether (target, emoji, author) currently has a reaction row.
    fn reaction_exists(&self, target: &str, emoji: &str, author: &str) -> bool {
        #[derive(Deserialize)]
        struct Count {
            n: i64,
        }
        self.state
            .storage()
            .sql()
            .exec(
                "SELECT COUNT(*) AS n FROM reactions WHERE target = ? AND emoji = ? AND author = ?;",
                vec![target.into(), emoji.into(), author.into()],
            )
            .and_then(|r| r.to_array::<Count>())
            .ok()
            .and_then(|rows| rows.into_iter().next())
            .map(|c| c.n > 0)
            .unwrap_or(false)
    }

    /// The number of reactors for (target, emoji).
    fn reaction_count(&self, target: &str, emoji: &str) -> u32 {
        #[derive(Deserialize)]
        struct Count {
            n: i64,
        }
        self.state
            .storage()
            .sql()
            .exec(
                "SELECT COUNT(*) AS n FROM reactions WHERE target = ? AND emoji = ?;",
                vec![target.into(), emoji.into()],
            )
            .and_then(|r| r.to_array::<Count>())
            .ok()
            .and_then(|rows| rows.into_iter().next())
            .map(|c| c.n.max(0) as u32)
            .unwrap_or(0)
    }

    /// A prior (author, idem) React result, so a replay returns it unchanged.
    fn react_idem_lookup(&self, author: &str, idem: &str) -> Option<(bool, u32)> {
        #[derive(Deserialize)]
        struct Row {
            active: i64,
            count: i64,
        }
        let rows: Vec<Row> = self
            .state
            .storage()
            .sql()
            .exec(
                "SELECT active, count FROM react_idem WHERE author = ? AND idem = ? LIMIT 1;",
                vec![author.into(), idem.into()],
            )
            .ok()?
            .to_array()
            .ok()?;
        rows.into_iter().next().map(|r| (r.active != 0, r.count.max(0) as u32))
    }

    /// The author's most recent React time (epoch-ms) — the rate-limit input.
    fn last_react_ms(&self, author: &str) -> Option<i64> {
        #[derive(Deserialize)]
        struct Row {
            last_ms: i64,
        }
        let rows: Vec<Row> = self
            .state
            .storage()
            .sql()
            .exec(
                "SELECT last_ms FROM react_rate WHERE author = ? LIMIT 1;",
                vec![author.into()],
            )
            .ok()?
            .to_array()
            .ok()?;
        rows.into_iter().next().map(|r| r.last_ms)
    }

    /// Up to REACTIONS_RETAINED reactions in the room (the client aggregates
    /// counts + "mine"). Capped so a poll can't materialize an unbounded set.
    fn list_reactions(&self) -> Vec<ReactionEntry> {
        #[derive(Deserialize)]
        struct Row {
            target: String,
            emoji: String,
            author: String,
        }
        let rows: Vec<Row> = self
            .state
            .storage()
            .sql()
            .exec(
                "SELECT target, emoji, author FROM reactions ORDER BY created_at DESC LIMIT ?;",
                vec![REACTIONS_RETAINED.into()],
            )
            .map(|r| r.to_array().unwrap_or_default())
            .unwrap_or_default();
        rows.into_iter()
            .map(|r| ReactionEntry { target: r.target, emoji: r.emoji, author: r.author })
            .collect()
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

    /// Serialize a `WatchFrame` and fan it out to every `/watch` subscriber.
    fn broadcast(&self, frame: &WatchFrame) {
        match serde_json::to_string(frame) {
            Ok(payload) => self.broadcast_str(&payload),
            Err(e) => worker::console_error!("broadcast: failed to serialize WatchFrame: {e}"),
        }
    }

    /// Fan a pre-serialized JSON frame out to every attached `/watch` socket.
    /// Shared by ref-advance and chat broadcasts so both ride the one stream.
    /// Best-effort per socket (a closed/errored one is skipped; the runtime drops
    /// it on the next cycle), but failures are COUNTED and logged — a broadcast
    /// that reaches nobody is the signature of "messages persist but never reach
    /// other viewers", so it must be observable, not silent.
    fn broadcast_str(&self, payload: &str) {
        let sockets = self.state.get_websockets();
        let total = sockets.len();
        let mut failed = 0usize;
        for ws in &sockets {
            if ws.send_with_str(payload).is_err() {
                failed += 1;
            }
        }
        if failed > 0 {
            worker::console_error!("broadcast: {failed}/{total} /watch socket sends failed");
        }
    }
}
