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
//   POST /update { "name", "new", "expectation", "expected"?, "author"?, "idem" }
//                                                          -> { "committed", "conflict", "current"? }
//   POST /list   { "prefix", "start_after", "page_size" }  -> { "refs": [ { "name", "value" } ],
//                                                              "next_cursor", "total" }
//   POST /purge  (no body)                                 -> { "refs_deleted", "messages_deleted", "reactions_deleted" }
//   GET  /watch  (Upgrade: websocket)                      -> 101, streams RefEvent JSON frames
//
// `expectation` is the proto wire number (1=ANY, 2=MISSING, 3=MATCH). The
// CAS decision itself is the pure `refs::evaluate_cas` shared with the unit
// tests, so the DO and the conformance vectors agree by construction.

use mkit_worker_common::replay::{Ledger, Proof, Reply};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::{cell::RefCell, rc::Rc};

use serde::{Deserialize, Serialize};
// `wasm_bindgen` must be in scope: the `#[durable_object]` macro emits glue
// that references it by name. `DurableObject` is the trait we implement.
use worker::{
    Date, DurableObject, Env, Request, Response, ResponseBuilder, Result, State, WebSocket,
    WebSocketIncomingMessage, WebSocketPair, durable_object, wasm_bindgen,
};

use crate::chat::{REACT_MIN_INTERVAL_MS, is_rate_limited};
use crate::envelope::FRESHNESS_WINDOW_MS;
use crate::refs::{
    CasDecision, ConflictReason, RefExpectation, evaluate_cas, list_refs_lower_bound,
    prefix_successor, resolve_page_cap,
};
use crate::write_quota::{QuotaDecision, QuotaState, WRITE_QUOTA_WINDOW_MS, evaluate_quota};
// DO wire types are declared once in `super::wire` and shared with service.rs,
// so a field rename can't desync the worker (client) and the DO (server).
use super::commit_index;
use super::wire::{
    GetReq, GetResp, ListCommitsReq, ListCommitsResp, ListEntry, ListReq, ListResp, MessagesReq,
    MessagesResp, MsgEntry, PostReq, PostResp, PurgeResp, ReactReq, ReactResp, ReactionEntry,
    ReactionsResp, RecordCommitsReq, RecordCommitsResp, UpdateReq, UpdateResp,
};
// `/watch` wire encoding: declared once (host+wasm target-independent) in
// `crate::room_event` and shared with the WatchRefs Connect-streaming bridge
// in `service.rs`, so a field rename can't desync producer/consumer.
use crate::room_event;

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

// `prefix_successor` and `list_refs_lower_bound` are pure string logic with
// no `worker`/DO dependency, so — like `room_event.rs` — they live in
// `crate::refs` (host-testable, no wasm32 target needed) rather than here in
// `worker_impl`, which is `#[cfg(target_arch = "wasm32")]`-gated wholesale
// and so can never run its own `#[cfg(test)]`s under plain `cargo test`.
// Imported below via the `use super::wire::...` block's sibling `use
// crate::refs::...`.

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

/// A 64-char lowercase-hex Ed25519 pubkey. Shared with the worker so an invalid
/// `?pubkey=` is treated as a viewer rather than trusted.
pub(crate) fn is_valid_pubkey(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[durable_object]
#[derive(Clone)]
pub struct RefStore {
    state: Rc<State>,
    ledger: Ledger,
    pending_events: Rc<RefCell<Option<Vec<String>>>>,
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
        let ledger = Ledger::new(state);
        Self {
            state: ledger.state.clone(),
            ledger,
            pending_events: Rc::new(RefCell::new(None)),
            conn_seq: Cell::new(0),
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        self.ledger.initialize()?;
        self.ensure_write_quota_table()?;
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
                if path == "/update"
                    && let Err(e) = commit_index::ensure_table(&self.state.storage().sql())
                {
                    return Response::error(format!("storage init failed: {e}"), 500);
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
            "/list-commits" | "/record-commits" => {
                if let Err(e) = commit_index::ensure_table(&self.state.storage().sql()) {
                    return Response::error(format!("storage init failed: {e}"), 500);
                }
            }
            "/purge" => {
                // A purge touches every table this DO owns, including ones a
                // brand-new room may never have created — ensure all four so
                // the DELETEs below are never against a missing table.
                if let Err(e) = self.ensure_table() {
                    return Response::error(format!("storage init failed: {e}"), 500);
                }
                if let Err(e) = self.ensure_messages_table() {
                    return Response::error(format!("storage init failed: {e}"), 500);
                }
                if let Err(e) = self.ensure_reactions_table() {
                    return Response::error(format!("storage init failed: {e}"), 500);
                }
                if let Err(e) = commit_index::ensure_table(&self.state.storage().sql()) {
                    return Response::error(format!("storage init failed: {e}"), 500);
                }
            }
            _ => {}
        }

        match path.as_str() {
            "/get" => {
                let body: GetReq = req.json().await?;
                let value = self.read_ref(&body.name)?;
                Response::from_json(&GetResp {
                    exists: value.is_some(),
                    value,
                })
            }
            "/update" => {
                let body: UpdateReq = req.json().await?;
                let proof = body.proof.clone();
                let owned = self.clone();
                self.mutate(proof, Some(0), true, move || owned.handle_update(body))?
                    .response()
            }
            "/list" => {
                let body: ListReq = req.json().await?;
                match self.list_refs(&body.prefix, &body.start_after, body.page_size) {
                    Ok((refs, next_cursor, total)) => Response::from_json(&ListResp {
                        refs,
                        next_cursor,
                        total,
                    }),
                    Err(msg) => Response::error(msg, 400),
                }
            }
            "/post" => {
                let body: PostReq = req.json().await?;
                let proof = body.proof.clone();
                let owned = self.clone();
                self.mutate(proof, None, true, move || owned.handle_post(body))?
                    .response()
            }
            "/messages" => {
                let body: MessagesReq = req.json().await?;
                let messages = self.list_messages(body.limit);
                Response::from_json(&MessagesResp { messages })
            }
            "/react" => {
                let body: ReactReq = req.json().await?;
                let proof = body.proof.clone();
                let owned = self.clone();
                self.mutate(proof, None, true, move || owned.handle_react(body))?
                    .response()
            }
            "/reactions" => {
                let reactions = self.list_reactions();
                Response::from_json(&ReactionsResp { reactions })
            }
            "/list-commits" => {
                let body: ListCommitsReq = req.json().await?;
                self.handle_list_commits(body)
            }
            "/record-commits" => {
                let body: RecordCommitsReq = req.json().await?;
                self.handle_record_commits(body)
            }
            "/object" => {
                let body: super::wire::ObjectWriteReq = req.json().await?;
                let complete = body.result.is_some();
                self.mutate(body.proof, Some(body.bytes), complete, move || {
                    Reply::json(&super::wire::ObjectWriteResp {
                        result: body.result,
                    })
                })?
                .response()
            }
            "/purge" => self.handle_purge(),
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

    /// Serve `ListCommits` from the colocated `commits` index: resolve the head
    /// (a `start_id` cursor, else the ref) and hand it to the index walk. Refs
    /// are the RefStore's domain; the chain walk lives in `commit_index`.
    fn handle_list_commits(&self, req: ListCommitsReq) -> Result<Response> {
        let cap = req.page_size.clamp(1, 512) as usize;
        let head = if !req.start_id.is_empty() {
            req.start_id.clone()
        } else {
            match self.read_ref(&req.r#ref)? {
                Some(h) => h,
                None => {
                    return Response::from_json(&ListCommitsResp {
                        commits: Vec::new(),
                        next_cursor: String::new(),
                        complete: true,
                    });
                }
            }
        };
        Response::from_json(&commit_index::walk(&self.state.storage().sql(), head, cap))
    }

    /// Backfill rows the worker decoded from R2 (pre-index history).
    fn handle_record_commits(&self, req: RecordCommitsReq) -> Result<Response> {
        let recorded =
            commit_index::record_batch(&self.state.storage().sql(), &req.r#ref, &req.commits);
        Response::from_json(&RecordCommitsResp { recorded })
    }

    /// Wipe every table row this DO instance owns — the mutable-state half of
    /// `PurgeRoom` (the worker purges the room's R2 prefixes separately, since
    /// this DO owns no R2 access). Irreversible: there is no soft-delete or
    /// undo. Counts are taken BEFORE the deletes so the response reports what
    /// was actually removed, not zero.
    fn handle_purge(&self) -> Result<Response> {
        let sql = self.state.storage().sql();
        let refs_deleted = Self::count_rows(&sql, "refs");
        let messages_deleted = Self::count_rows(&sql, "messages");
        let reactions_deleted = Self::count_rows(&sql, "reactions");

        sql.exec("DELETE FROM refs;", None)?;
        sql.exec("DELETE FROM messages;", None)?;
        sql.exec("DELETE FROM reactions;", None)?;
        sql.exec("DELETE FROM react_rate;", None)?;
        sql.exec("DELETE FROM commits;", None)?;

        Response::from_json(&PurgeResp {
            refs_deleted,
            messages_deleted,
            reactions_deleted,
        })
    }

    /// `SELECT COUNT(*)` over one of this DO's own hardcoded table names
    /// (never user input — every call site passes a literal), so
    /// string-formatting the identifier into the query is safe. Returns 0 on
    /// any query failure rather than propagating an error, since this is only
    /// used for a best-effort "how many rows did the purge remove" count.
    fn count_rows(sql: &worker::SqlStorage, table: &str) -> u32 {
        #[derive(Deserialize)]
        struct Count {
            n: i64,
        }
        sql.exec(&format!("SELECT COUNT(*) AS n FROM {table};"), None)
            .and_then(|r| r.to_array::<Count>())
            .ok()
            .and_then(|rows| rows.into_iter().next())
            .map(|c| c.n.max(0) as u32)
            .unwrap_or(0)
    }

    /// Read a ref's current hex value, or None if absent.
    fn read_ref(&self, name: &str) -> Result<Option<String>> {
        #[derive(Deserialize)]
        struct Row {
            value: String,
        }
        let rows: Vec<Row> = self
            .state
            .storage()
            .sql()
            .exec(
                "SELECT value FROM refs WHERE path = ? LIMIT 1;",
                vec![name.into()],
            )?
            .to_array()?;
        let value = rows.into_iter().next().map(|r| r.value);
        if let Some(value) = value.as_deref()
            && !mkit_core::write_auth::is_hex(value, 32)
        {
            return Err(worker::Error::RustError(
                "stored ref is not a canonical object id".into(),
            ));
        }
        Ok(value)
    }

    /// Apply one CAS inside the caller's nonce/quota/effects transaction.
    /// Broadcasts are buffered until that transaction commits.
    fn handle_update(&self, req: UpdateReq) -> Result<Reply> {
        let current = self.read_ref(&req.name)?;
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
                if let Some(m) = &req.commit
                    && let Err(e) = commit_index::record(&sql, &req.new, &req.name, m)
                {
                    worker::console_error!("record_commit failed for {}: {e}", req.name);
                }
                self.broadcast(&room_event::commit_event(
                    req.name.clone(),
                    &req.new,
                    req.author.as_deref(),
                ));
                let resp = UpdateResp {
                    committed: true,
                    conflict: false,
                    current: Some(req.new),
                };
                Reply::json(&resp)
            }
            CasDecision::Conflict(reason) => {
                // On a precondition failure return the present value (if any)
                // so the client can rebase. `Missing` means the ref is absent.
                let current = match reason {
                    ConflictReason::Missing => None,
                    _ => current,
                };
                let resp = UpdateResp {
                    committed: false,
                    conflict: true,
                    current,
                };
                Reply::json(&resp)
            }
            CasDecision::Invalid(msg) => Reply::error(msg, 400),
        }
    }

    /// List refs whose path starts with `prefix` (empty = all), optionally
    /// paged by a keyset cursor (`start_after`) and capped by `page_size`.
    ///
    /// Returns `(refs, next_cursor, total)`, or `Err(msg)` when `start_after`
    /// doesn't extend `prefix` — the `/list` dispatcher (above) maps that to
    /// a 400, which `do_call` in service.rs turns into `invalid_argument`.
    ///
    /// `page_size == 0` is the pre-pagination unbounded scan (legacy
    /// callers): no LIMIT, `next_cursor` always empty — unchanged behavior
    /// for anyone not yet passing the new fields. A non-zero `page_size` is
    /// clamped to `[1, 1000]`; the query fetches one extra row past the cap
    /// so a next page can be detected without a second query.
    fn list_refs(
        &self,
        prefix: &str,
        start_after: &str,
        page_size: u32,
    ) -> std::result::Result<(Vec<ListEntry>, String, u32), &'static str> {
        #[derive(Deserialize)]
        struct Row {
            path: String,
            value: String,
        }

        let (lo, strict) = list_refs_lower_bound(prefix, start_after)?;
        // Prefix match as a HALF-OPEN RANGE over the `path` PRIMARY KEY so SQLite
        // seeks the index and scans only matching rows. A `LIKE 'p%' ESCAPE` can
        // NOT use the BINARY-collated PK index (the ESCAPE clause and the
        // case-insensitive default both disable the LIKE-prefix optimization), so
        // it full-scans every ref. `hi` is the prefix successor; an empty prefix
        // (or an all-0xFF one with no finite successor) drops the upper bound.
        let hi = prefix_successor(prefix);
        let sql = self.state.storage().sql();

        // `total`: COUNT(*) over the same prefix range, computed only on the
        // first page (`start_after` empty) — a later page reuses the total the
        // caller already has from page 1, so paging costs one query per page.
        let total = if start_after.is_empty() {
            Self::count_refs(&sql, prefix, hi.as_deref())
        } else {
            0
        };

        // `cmp` selects `>` for a cursor page vs `>=` for the first page. It's
        // always one of these two hardcoded literals — never derived from
        // request data — so interpolating it into the query text is safe;
        // every actual VALUE still flows through a bound `?` parameter.
        let cmp = if strict { ">" } else { ">=" };

        // `page_size == 0` -> `None`: the legacy unbounded scan (no LIMIT,
        // `next_cursor` always empty). Otherwise the clamped `[1, 1000]` page
        // cap — see `resolve_page_cap`'s doc comment.
        let Some(cap) = resolve_page_cap(page_size) else {
            let rows: Vec<Row> = match hi.as_deref() {
                Some(hi) => sql.exec(
                    &format!(
                        "SELECT path, value FROM refs WHERE path {cmp} ? AND path < ? ORDER BY path;"
                    ),
                    vec![lo.clone().into(), hi.into()],
                ),
                None => sql.exec(
                    &format!("SELECT path, value FROM refs WHERE path {cmp} ? ORDER BY path;"),
                    vec![lo.clone().into()],
                ),
            }
            .map(|r| r.to_array().unwrap_or_default())
            .unwrap_or_default();
            let refs = rows
                .into_iter()
                .map(|r| ListEntry {
                    name: r.path,
                    value: r.value,
                })
                .collect();
            return Ok((refs, String::new(), total));
        };

        let limit = i64::from(cap) + 1; // one extra row: detects whether a next page follows
        let mut rows: Vec<Row> = match hi.as_deref() {
            Some(hi) => sql.exec(
                &format!(
                    "SELECT path, value FROM refs WHERE path {cmp} ? AND path < ? ORDER BY path LIMIT ?;"
                ),
                vec![lo.clone().into(), hi.into(), limit.into()],
            ),
            None => sql.exec(
                &format!(
                    "SELECT path, value FROM refs WHERE path {cmp} ? ORDER BY path LIMIT ?;"
                ),
                vec![lo.clone().into(), limit.into()],
            ),
        }
        .map(|r| r.to_array().unwrap_or_default())
        .unwrap_or_default();

        let next_cursor = if rows.len() as u32 > cap {
            rows.truncate(cap as usize);
            rows.last().map(|r| r.path.clone()).unwrap_or_default()
        } else {
            String::new()
        };
        let refs = rows
            .into_iter()
            .map(|r| ListEntry {
                name: r.path,
                value: r.value,
            })
            .collect();
        Ok((refs, next_cursor, total))
    }

    /// `SELECT COUNT(*)` over the same (prefix, prefix_successor) half-open
    /// range `list_refs` scans — the `total` field on a first-page response.
    /// `hi` is `prefix_successor(prefix)`, precomputed by the caller so this
    /// doesn't redo that (possibly `None`) computation.
    fn count_refs(sql: &worker::SqlStorage, prefix: &str, hi: Option<&str>) -> u32 {
        #[derive(Deserialize)]
        struct Count {
            n: i64,
        }
        let result = match hi {
            Some(hi) => sql.exec(
                "SELECT COUNT(*) AS n FROM refs WHERE path >= ? AND path < ?;",
                vec![prefix.into(), hi.into()],
            ),
            None if prefix.is_empty() => sql.exec("SELECT COUNT(*) AS n FROM refs;", None),
            None => sql.exec(
                "SELECT COUNT(*) AS n FROM refs WHERE path >= ?;",
                vec![prefix.into()],
            ),
        };
        result
            .and_then(|r| r.to_array::<Count>())
            .ok()
            .and_then(|rows| rows.into_iter().next())
            .map(|c| c.n.max(0) as u32)
            .unwrap_or(0)
    }

    /// Idempotently create the `write_quota` table — the per-author
    /// fixed-window write budget ledger for `PutObject`/`UpdateRef` (see
    /// `crate::write_quota::evaluate_quota`). One row per author; the room
    /// itself is implicit (this table lives in THIS room's DO instance).
    fn ensure_write_quota_table(&self) -> Result<()> {
        let sql = self.state.storage().sql();
        sql.exec(
            "CREATE TABLE IF NOT EXISTS write_quota (\
               author TEXT PRIMARY KEY, \
               window_start INTEGER NOT NULL, \
               ops INTEGER NOT NULL, \
               bytes INTEGER NOT NULL);",
            None,
        )?;
        // Seeks the stale tail so the opportunistic prune in
        // `charge_quota` doesn't full-scan the whole per-room author
        // set on every accepted write.
        sql.exec(
            "CREATE INDEX IF NOT EXISTS write_quota_window ON write_quota(window_start);",
            None,
        )?;
        Ok(())
    }

    /// Charge the first reservation inside the nonce/effects transaction.
    /// Replays reuse the saved result without consuming another write budget.
    fn charge_quota(&self, author: &str, bytes: u64) -> Result<Option<Reply>> {
        let now = Date::now().as_millis() as i64;
        match evaluate_quota(self.read_quota_state(author)?, now, bytes) {
            QuotaDecision::Allowed(state) => {
                self.state.storage().sql().exec("INSERT INTO write_quota (author, window_start, ops, bytes) VALUES (?, ?, ?, ?) ON CONFLICT(author) DO UPDATE SET window_start = excluded.window_start, ops = excluded.ops, bytes = excluded.bytes", vec![author.into(), state.window_start.into(), i64::from(state.ops).into(), (state.bytes as i64).into()])?;
                self.state.storage().sql().exec(
                    "DELETE FROM write_quota WHERE window_start < ?;",
                    vec![(now - 2 * WRITE_QUOTA_WINDOW_MS).into()],
                )?;
                Ok(None)
            }
            QuotaDecision::Exhausted { reason } => Ok(Some(Reply::error(reason, 429)?)),
        }
    }

    fn mutate(
        &self,
        proof: Proof,
        bytes: Option<u64>,
        complete: bool,
        action: impl FnOnce() -> Result<Reply> + 'static,
    ) -> Result<Reply> {
        let owned = self.clone();
        *self.pending_events.borrow_mut() = Some(Vec::new());
        let result = self.ledger.transaction(move || {
            let prior = owned
                .ledger
                .reserve(&proof, Date::now().as_millis() as i64)?;
            if let Some(Some(reply)) = prior {
                return Ok(reply);
            }
            if prior.is_none()
                && let Some(bytes) = bytes
                && let Some(reply) = owned.charge_quota(&proof.author, bytes)?
            {
                owned.ledger.finish(&proof, &reply)?;
                return Ok(reply);
            }
            let reply = action()?;
            if complete {
                owned.ledger.finish(&proof, &reply)?;
            }
            Ok(reply)
        });
        let events = self.pending_events.borrow_mut().take().unwrap_or_default();
        if result.is_ok() {
            for event in events {
                self.broadcast_str(&event);
            }
        }
        result
    }

    /// The author's persisted quota state in this room, or `None` if they've
    /// never written here (or their row was pruned as stale) — the input to
    /// `write_quota::evaluate_quota`.
    fn read_quota_state(&self, author: &str) -> Result<Option<QuotaState>> {
        #[derive(Deserialize)]
        struct Row {
            window_start: i64,
            ops: i64,
            bytes: i64,
        }
        let rows: Vec<Row> = self
            .state
            .storage()
            .sql()
            .exec(
                "SELECT window_start, ops, bytes FROM write_quota WHERE author = ? LIMIT 1;",
                vec![author.into()],
            )?
            .to_array()?;
        Ok(rows.into_iter().next().map(|r| QuotaState {
            window_start: r.window_start,
            ops: r.ops.max(0) as u32,
            bytes: r.bytes.max(0) as u64,
        }))
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
        Ok(())
    }

    /// Append a chat message under the per-author rate limit, serially (the DO's
    /// single-threaded execution makes the read-then-insert atomic, so two posts
    /// from one author can't both slip past the floor). On accept, stamp the
    /// server clock + the new `seq`, then broadcast a `"chat"` frame to every
    /// `/watch` subscriber. The worker has already content-addressed + stored
    /// the message bytes in R2 and verified the author envelope.
    fn handle_post(&self, req: PostReq) -> Result<Reply> {
        let now = Date::now().as_millis() as i64;

        let last = self.last_post_ms(&req.author)?;
        if is_rate_limited(last, now) {
            return Reply::json(&PostResp {
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
            .exec("SELECT last_insert_rowid() AS seq;", None)?
            .to_array()?;
        let seq = seq_rows
            .into_iter()
            .next()
            .ok_or_else(|| worker::Error::RustError("missing inserted message sequence".into()))?
            .seq as u64;

        // Bound the serving index: drop rows older than the most-recent
        // MESSAGES_RETAINED (R2 still holds every message permanently). seq is
        // monotonic, so this keeps exactly the newest window.
        let _ = sql.exec(
            "DELETE FROM messages WHERE seq <= (SELECT MAX(seq) FROM messages) - ?;",
            vec![MESSAGES_RETAINED.into()],
        );

        // Use the typed `broadcast` helper (like the Commit path) so a serialize
        // failure SKIPS the frame rather than fanning out an empty string "".
        self.broadcast(&room_event::chat_event(
            &req.id,
            &req.author,
            req.text.clone(),
            now,
            seq,
        ));

        Reply::json(&PostResp {
            accepted: true,
            rate_limited: false,
            seq,
            created_at: now,
        })
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
        // Per-author timestamp of the last accepted toggle. Replay dedupe
        // and rate limiting have independent ledgers; retries never toggle
        // again or advance this timestamp.
        sql.exec(
            "CREATE TABLE IF NOT EXISTS react_rate (\
               author TEXT PRIMARY KEY, \
               last_ms INTEGER NOT NULL);",
            None,
        )?;
        // Seek expired rate entries without scanning all authors.
        sql.exec(
            "CREATE INDEX IF NOT EXISTS react_rate_last ON react_rate(last_ms);",
            None,
        )?;
        Ok(())
    }

    /// Toggle a reaction serially, with the same guards the chat write path has:
    /// replay dedupe (a re-submitted signed toggle returns its original result),
    /// a per-author anti-flood rate limit, and a bound on the reactions table.
    fn handle_react(&self, req: ReactReq) -> Result<Reply> {
        let sql = self.state.storage().sql();
        let now = Date::now().as_millis() as i64;

        let had = self.reaction_exists(&req.target, &req.emoji, &req.author)?;

        // 2) Per-author anti-flood floor. On refusal, return the CURRENT state
        // unchanged (no toggle, no broadcast); the optimistic client reconciles
        // on its settle refetch.
        let last = self.last_react_ms(&req.author)?;
        if last.is_some_and(|l| now - l < REACT_MIN_INTERVAL_MS) {
            let count = self.reaction_count(&req.target, &req.emoji)?;
            return Reply::json(&ReactResp { active: had, count });
        }

        // 3) Toggle.
        if had {
            sql.exec(
                "DELETE FROM reactions WHERE target = ? AND emoji = ? AND author = ?;",
                vec![
                    req.target.clone().into(),
                    req.emoji.clone().into(),
                    req.author.clone().into(),
                ],
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
        let count = self.reaction_count(&req.target, &req.emoji)?;

        // Record the accepted toggle for the per-author anti-flood floor.
        sql.exec(
            "INSERT OR REPLACE INTO react_rate (author, last_ms) VALUES (?, ?);",
            vec![req.author.clone().into(), now.into()],
        )?;

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
        self.broadcast(&room_event::reaction_event(
            req.target.clone(),
            req.emoji.clone(),
            &req.author,
            active,
            count,
        ));

        Reply::json(&ReactResp { active, count })
    }

    /// Whether (target, emoji, author) currently has a reaction row.
    fn reaction_exists(&self, target: &str, emoji: &str, author: &str) -> Result<bool> {
        #[derive(Deserialize)]
        struct Count {
            n: i64,
        }
        Ok(self.state
            .storage()
            .sql()
            .exec(
                "SELECT COUNT(*) AS n FROM reactions WHERE target = ? AND emoji = ? AND author = ?;",
                vec![target.into(), emoji.into(), author.into()],
            )
            .and_then(|r| r.to_array::<Count>())
            ?
            .into_iter().next()
            .map(|c| c.n > 0)
            .unwrap_or(false))
    }

    /// The number of reactors for (target, emoji).
    fn reaction_count(&self, target: &str, emoji: &str) -> Result<u32> {
        #[derive(Deserialize)]
        struct Count {
            n: i64,
        }
        Ok(self
            .state
            .storage()
            .sql()
            .exec(
                "SELECT COUNT(*) AS n FROM reactions WHERE target = ? AND emoji = ?;",
                vec![target.into(), emoji.into()],
            )
            .and_then(|r| r.to_array::<Count>())?
            .into_iter()
            .next()
            .map(|c| c.n.max(0) as u32)
            .unwrap_or(0))
    }

    /// The author's most recent React time (epoch-ms) — the rate-limit input.
    fn last_react_ms(&self, author: &str) -> Result<Option<i64>> {
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
            )?
            .to_array()?;
        Ok(rows.into_iter().next().map(|r| r.last_ms))
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
            .map(|r| ReactionEntry {
                target: r.target,
                emoji: r.emoji,
                author: r.author,
            })
            .collect()
    }

    /// The author's most recent post time (epoch-ms), or None if they've never
    /// posted — the input to the rate-limit decision.
    fn last_post_ms(&self, author: &str) -> Result<Option<i64>> {
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
            )?
            .to_array()?;
        Ok(rows.into_iter().next().map(|r| r.created_at))
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

    /// Serialize a `RoomEvent` and fan it out to every `/watch` subscriber.
    fn broadcast(&self, event: &crate::proto::mkit::repo::v1::RoomEvent) {
        match room_event::to_json(event) {
            Some(payload) => self.broadcast_str(&payload),
            None => worker::console_error!("broadcast: failed to serialize RoomEvent"),
        }
    }

    /// Fan a pre-serialized JSON frame out to every attached `/watch` socket.
    /// Shared by ref-advance and chat broadcasts so both ride the one stream.
    /// Best-effort per socket (a closed/errored one is skipped; the runtime drops
    /// it on the next cycle), but failures are COUNTED and logged — a broadcast
    /// that reaches nobody is the signature of "messages persist but never reach
    /// other viewers", so it must be observable, not silent.
    fn broadcast_str(&self, payload: &str) {
        if let Some(events) = self.pending_events.borrow_mut().as_mut() {
            events.push(payload.to_owned());
            return;
        }
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
        let members = by_key.into_iter().collect();
        self.broadcast(&room_event::presence_event(members, viewers));
    }
}
