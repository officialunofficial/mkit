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
    durable_object, wasm_bindgen, DurableObject, Env, Request, Response, ResponseBuilder, Result,
    State, WebSocket, WebSocketIncomingMessage, WebSocketPair,
};

use crate::refs::{evaluate_cas, CasDecision, ConflictReason, RefExpectation};

#[derive(Deserialize)]
struct GetReq {
    name: String,
}

#[derive(Serialize)]
struct GetResp {
    exists: bool,
    value: Option<String>,
}

#[derive(Deserialize)]
struct UpdateReq {
    name: String,
    new: String,                 // 64-hex target value
    expectation: i32,            // proto wire number
    expected: Option<String>,    // 64-hex (MATCH only)
    author: Option<String>,      // 64-hex Ed25519 pubkey of the writer
}

#[derive(Serialize)]
struct UpdateResp {
    committed: bool,
    conflict: bool,
    current: Option<String>,
}

#[derive(Deserialize)]
struct ListReq {
    prefix: String,
}

#[derive(Serialize)]
struct ListEntry {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct ListResp {
    refs: Vec<ListEntry>,
}

/// A live ref advance, broadcast to every WatchRefs subscriber. The hex
/// fields are decoded back to raw bytes by the worker before re-encoding into
/// the proto `RefEvent`.
#[derive(Serialize, Deserialize, Clone)]
pub struct RefEventJson {
    pub name: String,
    pub object_id: String,           // 64-hex
    pub author_pubkey: Option<String>, // 64-hex
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

        // Lazily create the refs table before any read/write op. On failure
        // return a clean 500 rather than panicking the isolate (H4).
        match path.as_str() {
            "/get" | "/update" | "/list" => {
                if let Err(e) = self.ensure_table() {
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

    /// Push a ref event to every attached WatchRefs subscriber as a JSON frame.
    fn broadcast(&self, event: &RefEventJson) {
        let Ok(payload) = serde_json::to_string(event) else { return };
        for ws in self.state.get_websockets() {
            // Best-effort: a closed/errored socket is simply skipped; the
            // runtime drops it from the set on the next cycle.
            let _ = ws.send_with_str(&payload);
        }
    }
}
