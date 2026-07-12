// SPDX-License-Identifier: MIT OR Apache-2.0
//
// RefStore Durable Object — a SINGLE global instance for the whole
// deployment (one Worker = one mkit repository, per
// SPEC-TRANSPORT-CONNECT §7.1 — unlike apps/repo-worker's per-`room`
// anonymous-multiplayer instancing, this service has no room concept). All
// ref reads/writes funnel through here so CAS runs inside the DO's serial
// single-threaded execution (no lost updates, no torn reads), including the
// two-ref AdvanceRefs transaction.
//
// Storage: SQLite (`state.storage().sql()`), table `refs(path PRIMARY KEY,
// value)`. `value` is the 64-char lowercase hex of the 32-byte object id.
//
// Internal wire protocol (the worker -> DO via `stub.fetch_with_request`),
// JSON over HTTP to a `https://refstore/<op>` URL — see wire.rs for the
// exact request/response shapes.

use serde::Deserialize;
use worker::{DurableObject, Env, Request, Response, Result, State, durable_object, wasm_bindgen};

use super::wire::{
    AdvanceOutcome, AdvanceReq, AdvanceResp, GetReq, GetResp, ListEntry, ListReq, ListResp,
    UpdateReq, UpdateResp,
};
use crate::refs::{CasDecision, ConflictReason, RefExpectation, evaluate_cas};

/// The smallest string strictly greater than every string having `prefix` as
/// a prefix — used as the exclusive upper bound of a prefix range scan.
/// Identical to apps/repo-worker's helper.
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
        // Defer table creation to the first storage op (`ensure_table`) so a
        // transient DDL failure surfaces as a clean error, not a construction
        // panic.
        Self { state }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        if let Err(e) = self.ensure_table() {
            return Response::error(format!("storage init failed: {e}"), 500);
        }

        match req.path().as_str() {
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
            "/advance" => {
                let body: AdvanceReq = req.json().await?;
                self.handle_advance(body)
            }
            _ => Response::error("not found", 404),
        }
    }
}

impl RefStore {
    /// Idempotently create the `refs` table. Called at the top of every fetch
    /// so a transient DDL failure surfaces as a clean error instead of
    /// panicking the isolate.
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
            .exec(
                "SELECT value FROM refs WHERE path = ? LIMIT 1;",
                vec![name.into()],
            )
            .ok()?
            .to_array()
            .ok()?;
        rows.into_iter().next().map(|r| r.value)
    }

    /// Upsert `name` -> `new` unconditionally (the CAS decision has already
    /// been evaluated by the caller). SQLite `ON CONFLICT` replaces the value
    /// for this path.
    fn write_ref(&self, name: &str, new: &str) -> Result<()> {
        self.state.storage().sql().exec(
            "INSERT INTO refs (path, value) VALUES (?, ?) \
             ON CONFLICT(path) DO UPDATE SET value = excluded.value;",
            vec![name.into(), new.into()],
        )?;
        Ok(())
    }

    /// Apply a single-ref CAS update serially: read the current value,
    /// evaluate the pure CAS decision, and on commit upsert.
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
                self.write_ref(&req.name, &req.new)?;
                Response::from_json(&UpdateResp {
                    committed: true,
                    conflict: false,
                    current: Some(req.new),
                })
            }
            CasDecision::Conflict(reason) => {
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

    /// Atomically advance both refs (SPEC-TRANSPORT-CONNECT §4): evaluate
    /// BOTH CAS preconditions before writing EITHER ref. Packmap is checked
    /// first (same precedence as `Transport::advance_refs`'s default
    /// packmap-then-head fallback) — a packmap conflict leaves both refs
    /// untouched; a head conflict (packmap OK) ALSO leaves both untouched,
    /// which is the whole point of running this inside one serial DO fetch
    /// instead of two independent `update_ref` calls: this deployment
    /// advertises atomic advance (no window where the two refs disagree).
    fn handle_advance(&self, req: AdvanceReq) -> Result<Response> {
        let packmap_current = self.read_ref(&req.packmap_ref);
        let packmap_expectation = RefExpectation::from_wire(req.packmap_expectation);
        let packmap_expected = req
            .packmap_expected
            .as_ref()
            .and_then(|s| hex::decode(s).ok());
        let packmap_current_bytes = packmap_current.as_ref().and_then(|s| hex::decode(s).ok());
        let packmap_decision = evaluate_cas(
            packmap_current_bytes.as_deref(),
            packmap_expectation,
            packmap_expected.as_deref(),
        );
        match packmap_decision {
            CasDecision::Invalid(msg) => return Response::error(msg, 400),
            CasDecision::Conflict(_) => {
                return Response::from_json(&AdvanceResp {
                    outcome: AdvanceOutcome::PackmapConflict,
                });
            }
            CasDecision::Committed => {}
        }

        let head_current = self.read_ref(&req.head_ref);
        let head_expectation = RefExpectation::from_wire(req.head_expectation);
        let head_expected = req.head_expected.as_ref().and_then(|s| hex::decode(s).ok());
        let head_current_bytes = head_current.as_ref().and_then(|s| hex::decode(s).ok());
        let head_decision = evaluate_cas(
            head_current_bytes.as_deref(),
            head_expectation,
            head_expected.as_deref(),
        );
        match head_decision {
            CasDecision::Invalid(msg) => return Response::error(msg, 400),
            CasDecision::Conflict(_) => {
                return Response::from_json(&AdvanceResp {
                    outcome: AdvanceOutcome::HeadConflict,
                });
            }
            CasDecision::Committed => {}
        }

        // Both preconditions held — commit both writes now, inside the same
        // serial fetch, so no concurrent request can observe one written and
        // not the other.
        self.write_ref(&req.packmap_ref, &req.packmap_new)?;
        self.write_ref(&req.head_ref, &req.head_new)?;
        Response::from_json(&AdvanceResp {
            outcome: AdvanceOutcome::Committed,
        })
    }

    /// List refs whose path starts with `prefix` (empty = all). Half-open
    /// range scan over the `path` PRIMARY KEY (see apps/repo-worker's
    /// identical helper for the `LIKE` vs range-scan rationale).
    fn list_refs(&self, prefix: &str) -> Vec<ListEntry> {
        #[derive(Deserialize)]
        struct Row {
            path: String,
            value: String,
        }
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
            .map(|r| ListEntry {
                name: r.path,
                value: r.value,
            })
            .collect()
    }
}
