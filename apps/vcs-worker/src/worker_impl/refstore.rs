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
// exact request/response shapes. The replay ledger, write quota, and mutable
// effects share one SQLite transaction; object writes reserve quota once.

use mkit_worker_common::replay::{Ledger, Proof, Reply};
use serde::Deserialize;
use std::rc::Rc;
use worker::{
    Date, DurableObject, Env, Request, Response, Result, State, durable_object, wasm_bindgen,
};

use super::wire::{
    AdvanceOutcome, AdvanceReq, AdvanceResp, GetReq, GetResp, ListEntry, ListReq, ListResp,
    ObjectWriteResp, UpdateReq, UpdateResp,
};
use crate::refs::{CasDecision, ConflictReason, RefExpectation, evaluate_cas};
use crate::write_quota::{QuotaDecision, QuotaState, WRITE_QUOTA_WINDOW_MS, evaluate_quota};

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
#[derive(Clone)]
pub struct RefStore {
    state: Rc<State>,
    ledger: Ledger,
}

impl DurableObject for RefStore {
    fn new(state: State, _env: Env) -> Self {
        // Defer table creation to the first storage op (`ensure_table`) so a
        // transient DDL failure surfaces as a clean error, not a construction
        // panic.
        let ledger = Ledger::new(state);
        Self {
            state: ledger.state.clone(),
            ledger,
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        if let Err(e) = self.ensure_table() {
            return Response::error(format!("storage init failed: {e}"), 500);
        }

        match req.path().as_str() {
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
                self.mutate(proof, 0, true, move || owned.handle_update(body))?
                    .response()
            }
            "/list" => {
                let body: ListReq = req.json().await?;
                let refs = self.list_refs(&body.prefix);
                Response::from_json(&ListResp { refs })
            }
            "/advance" => {
                let body: AdvanceReq = req.json().await?;
                let proof = body.proof.clone();
                let owned = self.clone();
                self.mutate(proof, 0, true, move || owned.handle_advance(body))?
                    .response()
            }
            "/object" => {
                let body: super::wire::ObjectWriteReq = req.json().await?;
                self.mutate(body.proof, body.bytes, body.complete, || {
                    Reply::json(&ObjectWriteResp {
                        allowed: true,
                        reason: None,
                    })
                })?
                .response()
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
        self.ledger.initialize()?;
        self.ensure_write_quota_table()?;
        self.state.storage().sql().exec(
            "CREATE TABLE IF NOT EXISTS refs (path TEXT PRIMARY KEY, value TEXT NOT NULL);",
            None,
        )?;
        Ok(())
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
                self.write_ref(&req.name, &req.new)?;
                Reply::json(&UpdateResp {
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
                Reply::json(&UpdateResp {
                    committed: false,
                    conflict: true,
                    current,
                })
            }
            CasDecision::Invalid(msg) => Reply::error(msg, 400),
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
    fn handle_advance(&self, req: AdvanceReq) -> Result<Reply> {
        let packmap_current = self.read_ref(&req.packmap_ref)?;
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
            CasDecision::Invalid(msg) => return Reply::error(msg, 400),
            CasDecision::Conflict(_) => {
                return Reply::json(&AdvanceResp {
                    outcome: AdvanceOutcome::PackmapConflict,
                });
            }
            CasDecision::Committed => {}
        }

        let head_current = self.read_ref(&req.head_ref)?;
        let head_expectation = RefExpectation::from_wire(req.head_expectation);
        let head_expected = req.head_expected.as_ref().and_then(|s| hex::decode(s).ok());
        let head_current_bytes = head_current.as_ref().and_then(|s| hex::decode(s).ok());
        let head_decision = evaluate_cas(
            head_current_bytes.as_deref(),
            head_expectation,
            head_expected.as_deref(),
        );
        match head_decision {
            CasDecision::Invalid(msg) => return Reply::error(msg, 400),
            CasDecision::Conflict(_) => {
                return Reply::json(&AdvanceResp {
                    outcome: AdvanceOutcome::HeadConflict,
                });
            }
            CasDecision::Committed => {}
        }

        // Both preconditions held — commit both writes now, inside the same
        // serial fetch, so no concurrent request can observe one written and
        // not the other.
        self.write_ref(&req.packmap_ref, &req.packmap_new)?;
        #[cfg(feature = "test-faults")]
        if req.head_ref.starts_with("refs/heads/__test_fail_once-") {
            thread_local! { static FAILED: std::cell::RefCell<std::collections::HashSet<String>> = std::cell::RefCell::default(); }
            if FAILED.with(|failed| failed.borrow_mut().insert(req.head_ref.clone())) {
                return Err(worker::Error::RustError(
                    "injected failure after packmap write".into(),
                ));
            }
        }
        self.write_ref(&req.head_ref, &req.head_new)?;
        Reply::json(&AdvanceResp {
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

    /// Idempotently create the `write_quota` table — the per-author
    /// fixed-window write budget ledger for `UpdateRef`/`AdvanceRefs`/
    /// `UploadPack` (see `crate::write_quota::evaluate_quota`). One row per
    /// author; ported from apps/repo-worker's identical table, minus the
    /// room dimension (this Worker has exactly one RefStore DO instance for
    /// the whole deployment — see module docs).
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
        // `charge_quota` doesn't full-scan the whole author set on
        // every accepted write.
        sql.exec(
            "CREATE INDEX IF NOT EXISTS write_quota_window ON write_quota(window_start);",
            None,
        )?;
        Ok(())
    }

    /// Check-and-consume one author's write budget, serially — the DO's
    /// single-threaded execution makes this read-evaluate-write atomic, so
    /// two writes from the same author can't both slip past the cap. Called
    /// by `AuthInterceptor` for `UpdateRef`/`AdvanceRefs` and by the
    /// `upload_pack` handler for `UploadPack` (see `worker_impl/auth.rs` and
    /// `worker_impl/service.rs`), always BEFORE the corresponding storage
    /// write. A rejected write leaves the persisted state untouched; an
    /// accepted one persists the updated `(window_start, ops, bytes)` and
    /// prunes rows whose window elapsed more than one window ago (bounded
    /// storage, mirrors apps/repo-worker's identical prune).
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
        bytes: u64,
        complete: bool,
        action: impl FnOnce() -> Result<Reply> + 'static,
    ) -> Result<Reply> {
        let owned = self.clone();
        self.ledger.transaction(move || {
            let prior = owned
                .ledger
                .reserve(&proof, Date::now().as_millis() as i64)?;
            if let Some(Some(reply)) = prior {
                return Ok(reply);
            }
            if prior.is_none()
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
        })
    }

    /// The author's persisted quota state, or `None` if they've never
    /// written (or their row was pruned as stale) — the input to
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
}
