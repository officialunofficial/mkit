// SPDX-License-Identifier: MIT OR Apache-2.0
//! Owner-only Snapshot job admission, inspection checkpoints and cleanup.

use super::{
    managed::AdminWire,
    refstore::RefStore,
    snapshot_store::{JOB_IDLE_MS, Job, Meta, TERMINAL_MS},
};
use crate::{
    access_policy::Identity,
    snapshot_wire::{
        self, BeginSnapshot, CancelSnapshot, CleanupReply, CleanupSnapshots, GetSnapshotJob,
    },
};
use mkit_worker_common::replay::Reply;
use serde::Deserialize;
use worker::{Date, Error, Method, Request, Response, Result};

const UNAVAILABLE: &str = "{\"code\":\"unavailable\"}";
const INVALID: &str = "{\"code\":\"invalid_argument\"}";
const CONFLICT: &str = "{\"code\":\"conflict\"}";
const EXHAUSTED: &str = "{\"code\":\"resource_exhausted\"}";
const NOT_FOUND: &str = "{\"code\":\"not_found\"}";

fn err(message: &'static str, code: u16) -> Result<Reply> {
    Reply::error(message, code)
}
fn unavailable() -> Result<Reply> {
    err(UNAVAILABLE, 503)
}
fn invalid() -> Result<Reply> {
    err(INVALID, 400)
}
fn conflict() -> Result<Reply> {
    err(CONFLICT, 409)
}
fn exhausted() -> Result<Reply> {
    err(EXHAUSTED, 429)
}
fn not_found() -> Result<Reply> {
    err(NOT_FOUND, 404)
}

fn replay_error(error: Error) -> Result<Reply> {
    let message = error.to_string();
    if message.contains("nonce reused for a different operation") {
        conflict()
    } else if message.contains("signed operation expired") {
        err("{\"code\":\"unauthenticated\"}", 401)
    } else {
        unavailable()
    }
}

fn now() -> i64 {
    Date::now().as_millis() as i64
}

impl RefStore {
    pub(super) async fn managed_snapshot(&self, req: &mut Request) -> Result<Response> {
        if req.method() != Method::Post {
            return unavailable()?.response();
        }
        let wire: AdminWire = match req.json().await {
            Ok(wire) => wire,
            Err(_) => return invalid()?.response(),
        };
        let configured = match (
            self.env.var("AUTH_AUDIENCE"),
            self.env.var("AUTH_REPOSITORY"),
            self.env.var("MANAGED_OWNER_PUBLIC_KEY"),
        ) {
            (Ok(a), Ok(r), Ok(o)) => {
                Identity::parse(&a.to_string(), &r.to_string(), &o.to_string())
            }
            _ => Err("missing managed configuration"),
        };
        if configured.as_ref().ok() != Some(&wire.identity)
            || wire.proof.author != wire.identity.owner
            || !mkit_core::write_auth::is_hex(&wire.proof.scope, 32)
            || !mkit_core::write_auth::is_hex(&wire.proof.fingerprint, 32)
        {
            return unavailable()?.response();
        }
        if now() > wire.proof.expires_at {
            return err("{\"code\":\"unauthenticated\"}", 401)?.response();
        }
        if self.ensure_table().is_err() {
            return unavailable()?.response();
        }
        // The live persisted identity and policy are checked before even a
        // saved nonce result is looked up. Get is fresh, not ledger replay.
        let policy = match self.read_policy(&wire.identity) {
            Ok(Some(policy)) if policy.validate(&wire.identity).is_ok() => policy,
            _ => return unavailable()?.response(),
        };
        match wire.operation.as_str() {
            "begin_snapshot" => {
                let owned = self.clone();
                let outcome = self
                    .ledger
                    .transaction(move || owned.snapshot_begin(wire, policy.generation));
                match outcome {
                    Ok(reply) => reply.response(),
                    Err(error) => replay_error(error)?.response(),
                }
            }
            "get_snapshot_job" => {
                let owned = self.clone();
                let outcome = self.ledger.transaction(move || owned.snapshot_get(wire));
                match outcome {
                    Ok(reply) => reply.response(),
                    Err(_) => unavailable()?.response(),
                }
            }
            "cancel_snapshot" => {
                let owned = self.clone();
                let outcome = self.ledger.transaction(move || owned.snapshot_cancel(wire));
                match outcome {
                    Ok(reply) => reply.response(),
                    Err(error) => replay_error(error)?.response(),
                }
            }
            "cleanup_snapshots" => {
                let owned = self.clone();
                let outcome = self
                    .ledger
                    .transaction(move || owned.snapshot_cleanup(wire));
                match outcome {
                    Ok(reply) => reply.response(),
                    Err(error) => replay_error(error)?.response(),
                }
            }
            "continue_snapshot" => self.snapshot_continue(wire, policy.generation).await,
            _ => unavailable()?.response(),
        }
    }

    fn snapshot_begin(&self, wire: AdminWire, policy_generation: String) -> Result<Reply> {
        let request: BeginSnapshot =
            match snapshot_wire::decode::<BeginSnapshot>(wire.body.as_bytes()) {
                Ok(request) if request.validate() => request,
                _ => return invalid(),
            };
        let identity = wire.identity.clone();
        let prior = self.ledger.reserve(&wire.proof, now(), || {
            let existing = self.snapshot_meta(&identity)?;
            if existing.is_some() {
                if self.snapshot_job(&request.job_id)?.is_some() { return Ok(Some(conflict()?)); }
                let indexed = self.snapshot_exists("SELECT 1 AS found FROM host_snapshot_indexes WHERE job_id=? LIMIT 1", vec![request.job_id.clone().into()])?;
                if indexed { return Ok(Some(conflict()?)); }
                let live = self.snapshot_count("SELECT COUNT(*) AS n FROM host_snapshot_jobs WHERE state IN ('catalog','walk')", vec![])?;
                let per_ref = self.snapshot_count("SELECT COUNT(*) AS n FROM host_snapshot_jobs WHERE state IN ('catalog','walk') AND exact_ref=?", vec![request.r#ref.clone().into()])?;
                let terminal = self.snapshot_count("SELECT COUNT(*) AS n FROM host_snapshot_jobs WHERE state IN ('ready','cancelled','expired','failed','cleaning')", vec![])?;
                // Every admitted live job may terminalize without a later
                // capacity decision. Reserve its terminal-summary slot now.
                let occupied = live.checked_add(terminal)
                    .ok_or_else(|| Error::RustError("snapshot capacity overflow".into()))?;
                if live >= 2 || per_ref != 0 || occupied >= 128 { return Ok(Some(exhausted()?)); }
            }
            let head = self.read_ref(&request.r#ref)?;
            let packmap = self.read_ref(&request.packmap_ref())?;
            if head.as_deref() != Some(&request.expected_head) || packmap.as_deref() != Some(&request.expected_packmap) {
                return Ok(Some(conflict()?));
            }
            Ok(None)
        });
        let prior = match prior {
            Ok(v) => v,
            Err(error) => return replay_error(error),
        };
        if let Some(Some(reply)) = prior {
            return Ok(reply);
        }
        if let Some(None) = prior {
            return err("{\"code\":\"in_progress\"}", 202);
        }
        let mut meta = match self.snapshot_meta(&identity)? {
            Some(meta) => meta,
            None => self.snapshot_bootstrap(&identity)?,
        };
        let generation = meta.next_generation()?;
        let packmap_ref = request.packmap_ref();
        let selected = request.selected_pack_keys.join("\n");
        let digest = hex::encode(mkit_core::hash::hash(
            [
                b"mkit.host.snapshot.selection.v1\0".as_slice(),
                selected.as_bytes(),
            ]
            .concat()
            .as_slice(),
        ));
        let timestamp = now();
        let job = Job {
            id: request.job_id.clone(),
            generation,
            revision: "0".into(),
            state: "catalog".into(),
            exact_ref: request.r#ref,
            packmap_ref,
            head: request.expected_head,
            packmap: request.expected_packmap,
            selected_digest: digest,
            policy_generation,
            profile_version: 1,
            validator_version: 1,
            tip_checked: false,
            pack_index: 0,
            frame_index: 0,
            frontier_next_seq: 0,
            frontier_rows: 0,
            frontier_bytes: 0,
            catalog_packs: 0,
            catalog_raw_bytes: 0,
            catalog_entries: 0,
            reached_objects: 0,
            reached_bytes: 0,
            max_depth: 0,
            work_units: 0,
            attempts: 0,
            reserved_io_bytes: 0,
            r2_operations: 0,
            attempt_seq: "0".into(),
            attempt_scope: String::new(),
            attempt_fingerprint: String::new(),
            attempt_deadline: 0,
            attempt_bytes: 0,
            attempt_ops: 0,
            idle_deadline: timestamp + JOB_IDLE_MS,
            terminal_deadline: 0,
        };
        self.snapshot_save_meta(&meta)?;
        self.snapshot_save_job(&job)?;
        for (ordinal, key) in request.selected_pack_keys.iter().enumerate() {
            self.state.storage().sql().exec(
                "INSERT INTO host_snapshot_selected(job_id,ordinal,pack_key) VALUES(?,?,?)",
                vec![
                    job.id.clone().into(),
                    (ordinal as i64).into(),
                    key.clone().into(),
                ],
            )?;
        }
        let reply = Reply::json(&job.reply())?;
        self.ledger.finish(&wire.proof, &reply)?;
        Ok(reply)
    }

    fn snapshot_get(&self, wire: AdminWire) -> Result<Reply> {
        let request: GetSnapshotJob =
            match snapshot_wire::decode::<GetSnapshotJob>(wire.body.as_bytes()) {
                Ok(request) if request.validate() => request,
                _ => return invalid(),
            };
        if self.snapshot_meta(&wire.identity)?.is_none() {
            return not_found();
        }
        match self.snapshot_job(&request.job_id)? {
            Some(job) => Reply::json(&job.reply()),
            None => not_found(),
        }
    }

    fn snapshot_cancel(&self, wire: AdminWire) -> Result<Reply> {
        let request: CancelSnapshot =
            match snapshot_wire::decode::<CancelSnapshot>(wire.body.as_bytes()) {
                Ok(request) if request.validate() => request,
                _ => return invalid(),
            };
        let prior = self.ledger.reserve(&wire.proof, now(), || {
            if self.snapshot_meta(&wire.identity)?.is_none() {
                return Ok(Some(not_found()?));
            }
            let Some(job) = self.snapshot_job(&request.job_id)? else {
                return Ok(Some(not_found()?));
            };
            if job.generation != request.job_generation
                || job.revision != request.expected_revision
                || !job.active()
            {
                return Ok(Some(conflict()?));
            }
            Ok(None)
        });
        let prior = match prior {
            Ok(v) => v,
            Err(error) => return replay_error(error),
        };
        if let Some(Some(reply)) = prior {
            return Ok(reply);
        }
        if let Some(None) = prior {
            return err("{\"code\":\"in_progress\"}", 202);
        }
        let mut meta = self
            .snapshot_meta(&wire.identity)?
            .ok_or_else(|| Error::RustError("missing snapshot schema".into()))?;
        let mut job = self
            .snapshot_job(&request.job_id)?
            .ok_or_else(|| Error::RustError("missing job".into()))?;
        job.generation = meta.next_generation()?;
        job.state = "cancelled".into();
        job.terminal_deadline = now() + TERMINAL_MS;
        job.attempt_scope.clear();
        job.attempt_fingerprint.clear();
        self.snapshot_save_meta(&meta)?;
        self.snapshot_save_job(&job)?;
        let reply = Reply::json(&job.reply())?;
        self.ledger.finish(&wire.proof, &reply)?;
        Ok(reply)
    }

    fn snapshot_cleanup(&self, wire: AdminWire) -> Result<Reply> {
        let request: CleanupSnapshots =
            match snapshot_wire::decode::<CleanupSnapshots>(wire.body.as_bytes()) {
                Ok(request) if request.validate() => request,
                _ => return invalid(),
            };
        let prior = self.ledger.reserve(&wire.proof, now(), || {
            let Some(meta) = self.snapshot_meta(&wire.identity)? else {
                return Ok(Some(not_found()?));
            };
            if meta.cleanup_revision != request.expected_cleanup_revision {
                return Ok(Some(conflict()?));
            }
            Ok(None)
        });
        let prior = match prior {
            Ok(v) => v,
            Err(error) => return replay_error(error),
        };
        if let Some(Some(reply)) = prior {
            return Ok(reply);
        }
        if let Some(None) = prior {
            return err("{\"code\":\"in_progress\"}", 202);
        }
        let mut meta = self
            .snapshot_meta(&wire.identity)?
            .ok_or_else(|| Error::RustError("missing snapshot schema".into()))?;
        let affected = self.snapshot_cleanup_rows(&mut meta, request.max_rows)?;
        meta.next_cleanup_revision()?;
        self.snapshot_save_meta(&meta)?;
        let reply = Reply::json(&CleanupReply {
            version: 1,
            cleanup_revision: meta.cleanup_revision,
            affected_rows: affected.to_string(),
            has_more: self.snapshot_has_cleanup(now())?,
        })?;
        self.ledger.finish(&wire.proof, &reply)?;
        Ok(reply)
    }

    fn snapshot_cleanup_rows(&self, meta: &mut Meta, max_rows: u8) -> Result<u64> {
        #[derive(Deserialize)]
        struct Id {
            job_id: String,
        }
        #[derive(Deserialize)]
        struct LeaseId {
            lease_id: String,
        }
        #[derive(Deserialize)]
        struct RawBytes {
            raw_bytes: i64,
        }
        let mut affected = 0u64;
        let current = now();
        while affected < u64::from(max_rows) {
            let rows: Vec<Id> = self.state.storage().sql().exec(
                "SELECT job_id FROM host_snapshot_jobs WHERE state IN ('catalog','walk') AND idle_deadline < ? ORDER BY idle_deadline,job_id LIMIT 1",
                vec![current.into()],
            )?.to_array()?;
            let Some(id) = rows.first() else {
                break;
            };
            let mut job = self
                .snapshot_job(&id.job_id)?
                .ok_or_else(|| Error::RustError("missing job".into()))?;
            job.generation = meta.next_generation()?;
            job.state = "expired".into();
            job.terminal_deadline = current + TERMINAL_MS;
            job.attempt_scope.clear();
            job.attempt_fingerprint.clear();
            self.snapshot_save_job(&job)?;
            affected += 1;
        }
        while affected < u64::from(max_rows) {
            let rows: Vec<LeaseId> = self.state.storage().sql().exec(
                "SELECT lease_id FROM host_snapshot_leases WHERE deadline < ? ORDER BY deadline,lease_id LIMIT 1",
                vec![current.into()],
            )?.to_array()?;
            let Some(id) = rows.first() else {
                break;
            };
            self.state.storage().sql().exec(
                "DELETE FROM host_snapshot_leases WHERE lease_id=?",
                vec![id.lease_id.clone().into()],
            )?;
            affected += 1;
        }
        // A retired index owns its catalog independently of its (possibly
        // already purged) terminal job. An unexpired read lease pins it.
        // None is permitted only when *every* submission table is absent.
        // Partial schema, including a missing pins table, fails closed.
        let submission_pins = self.submission_meta(&meta.identity)?.is_some();
        while affected < u64::from(max_rows) {
            let query = if submission_pins {
                "SELECT job_id FROM host_snapshot_indexes WHERE retired=1 AND NOT EXISTS (SELECT 1 FROM host_snapshot_leases WHERE host_snapshot_leases.job_id=host_snapshot_indexes.job_id AND deadline>=? LIMIT 1) AND NOT EXISTS (SELECT 1 FROM host_submission_pins WHERE host_submission_pins.index_job_id=host_snapshot_indexes.job_id AND expires_at>=? LIMIT 1) ORDER BY job_id LIMIT 1"
            } else {
                "SELECT job_id FROM host_snapshot_indexes WHERE retired=1 AND NOT EXISTS (SELECT 1 FROM host_snapshot_leases WHERE host_snapshot_leases.job_id=host_snapshot_indexes.job_id AND deadline>=? LIMIT 1) ORDER BY job_id LIMIT 1"
            };
            let params = if submission_pins {
                vec![current.into(), current.into()]
            } else {
                vec![current.into()]
            };
            let rows: Vec<Id> = self.state.storage().sql().exec(query, params)?.to_array()?;
            let Some(id) = rows.first() else {
                break;
            };
            let has_catalog = self.snapshot_exists(
                "SELECT 1 AS found FROM host_snapshot_catalog WHERE job_id=? LIMIT 1",
                vec![id.job_id.clone().into()],
            )?;
            if has_catalog {
                self.state.storage().sql().exec(
                    "DELETE FROM host_snapshot_catalog WHERE rowid IN (SELECT rowid FROM host_snapshot_catalog WHERE job_id=? ORDER BY pack_key,ordinal LIMIT 1)",
                    vec![id.job_id.clone().into()],
                )?;
                meta.catalog_rows = meta
                    .catalog_rows
                    .checked_sub(1)
                    .ok_or_else(|| Error::RustError("catalog counter underflow".into()))?;
            } else {
                let rows: Vec<RawBytes> = self
                    .state
                    .storage()
                    .sql()
                    .exec(
                        "SELECT raw_bytes FROM host_snapshot_indexes WHERE job_id=?",
                        vec![id.job_id.clone().into()],
                    )?
                    .to_array()?;
                let raw = u64::try_from(
                    rows.first()
                        .ok_or_else(|| Error::RustError("missing snapshot index".into()))?
                        .raw_bytes,
                )
                .map_err(|_| Error::RustError("invalid raw byte count".into()))?;
                meta.pinned_raw_bytes = meta
                    .pinned_raw_bytes
                    .checked_sub(raw)
                    .ok_or_else(|| Error::RustError("raw byte counter underflow".into()))?;
                self.state.storage().sql().exec(
                    "DELETE FROM host_snapshot_indexes WHERE job_id=?",
                    vec![id.job_id.clone().into()],
                )?;
            }
            affected += 1;
        }
        while affected < u64::from(max_rows) {
            let rows: Vec<Id> = self.state.storage().sql().exec(
                "SELECT job_id FROM host_snapshot_jobs WHERE state IN ('ready','cancelled','expired','failed','cleaning') AND terminal_deadline < ? ORDER BY terminal_deadline,job_id LIMIT 1",
                vec![current.into()],
            )?.to_array()?;
            let Some(id) = rows.first() else {
                break;
            };
            let job = self
                .snapshot_job(&id.job_id)?
                .ok_or_else(|| Error::RustError("missing job".into()))?;
            let indexed = self.snapshot_exists(
                "SELECT 1 AS found FROM host_snapshot_indexes WHERE job_id=? LIMIT 1",
                vec![id.job_id.clone().into()],
            )?;
            let mut deleted_child = false;
            for table in [
                "host_snapshot_selected",
                "host_snapshot_catalog",
                "host_snapshot_seen",
                "host_snapshot_frontier",
            ] {
                // The certificate/index, not the seven-day job summary,
                // owns validated locators after promotion.
                if indexed && table == "host_snapshot_catalog" {
                    continue;
                }
                let query = format!("SELECT 1 AS found FROM {table} WHERE job_id=? LIMIT 1");
                if self.snapshot_exists(&query, vec![id.job_id.clone().into()])? {
                    let query = format!(
                        "DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE job_id=? LIMIT 1)"
                    );
                    self.state
                        .storage()
                        .sql()
                        .exec(&query, vec![id.job_id.clone().into()])?;
                    if table == "host_snapshot_catalog" {
                        meta.catalog_rows = meta
                            .catalog_rows
                            .checked_sub(1)
                            .ok_or_else(|| Error::RustError("catalog counter underflow".into()))?;
                    }
                    affected += 1;
                    deleted_child = true;
                    break;
                }
            }
            if !deleted_child {
                if job.state != "ready" {
                    meta.pinned_raw_bytes = meta
                        .pinned_raw_bytes
                        .checked_sub(job.catalog_raw_bytes)
                        .ok_or_else(|| Error::RustError("raw byte counter underflow".into()))?;
                }
                self.state.storage().sql().exec(
                    "DELETE FROM host_snapshot_jobs WHERE job_id=?",
                    vec![id.job_id.clone().into()],
                )?;
                affected += 1;
            }
        }
        Ok(affected)
    }

    fn snapshot_has_cleanup(&self, current: i64) -> Result<bool> {
        let submission_pins = self
            .submission_meta(&self.submission_identity()?)?
            .is_some();
        let retired = if submission_pins {
            self.snapshot_exists("SELECT 1 AS found FROM host_snapshot_indexes WHERE retired=1 AND NOT EXISTS (SELECT 1 FROM host_snapshot_leases WHERE host_snapshot_leases.job_id=host_snapshot_indexes.job_id AND deadline>=? LIMIT 1) AND NOT EXISTS (SELECT 1 FROM host_submission_pins WHERE host_submission_pins.index_job_id=host_snapshot_indexes.job_id AND expires_at>=? LIMIT 1) LIMIT 1", vec![current.into(),current.into()])?
        } else {
            self.snapshot_exists("SELECT 1 AS found FROM host_snapshot_indexes WHERE retired=1 AND NOT EXISTS (SELECT 1 FROM host_snapshot_leases WHERE host_snapshot_leases.job_id=host_snapshot_indexes.job_id AND deadline>=? LIMIT 1) LIMIT 1", vec![current.into()])?
        };
        Ok(self.snapshot_exists("SELECT 1 AS found FROM host_snapshot_jobs WHERE state IN ('catalog','walk') AND idle_deadline < ? LIMIT 1", vec![current.into()])?
            || self.snapshot_exists("SELECT 1 AS found FROM host_snapshot_leases WHERE deadline < ? LIMIT 1", vec![current.into()])?
            || retired
            || self.snapshot_exists("SELECT 1 AS found FROM host_snapshot_jobs WHERE state IN ('ready','cancelled','expired','failed','cleaning') AND terminal_deadline < ? LIMIT 1", vec![current.into()])?)
    }
}
