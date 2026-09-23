// SPDX-License-Identifier: MIT OR Apache-2.0
//! RefStore-local bounded, versioned Snapshot enrollment state.

use super::refstore::RefStore;
use crate::{
    access_policy::Identity,
    snapshot_wire::{JobProgress, JobReply},
};
use serde::{Deserialize, Serialize};
use worker::{Error, Result};

pub(super) const JOB_IDLE_MS: i64 = 24 * 60 * 60 * 1000;
pub(super) const ATTEMPT_LEASE_MS: i64 = 2 * 60 * 1000;
pub(super) const TERMINAL_MS: i64 = 7 * JOB_IDLE_MS;
pub(super) const MAX_ATTEMPTS: u64 = 8_192;
pub(super) const MAX_JOB_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub(super) const MAX_STEP_BYTES: u64 = 8 * 1024 * 1024;
pub(super) const MAX_STEP_OPS: u64 = 66;
pub(super) const MAX_JOB_OPS: u64 = MAX_ATTEMPTS * MAX_STEP_OPS;

const TABLES: [&str; 9] = [
    "host_snapshot_catalog",
    "host_snapshot_certificates",
    "host_snapshot_frontier",
    "host_snapshot_indexes",
    "host_snapshot_jobs",
    "host_snapshot_leases",
    "host_snapshot_meta",
    "host_snapshot_seen",
    "host_snapshot_selected",
];

fn corrupt() -> Error {
    Error::RustError("corrupt snapshot state".into())
}
fn invalid() -> Error {
    Error::RustError("invalid snapshot operation".into())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Meta {
    pub version: u8,
    pub identity: Identity,
    pub generation: String,
    pub cleanup_revision: String,
    pub catalog_rows: u64,
    pub pinned_raw_bytes: u64,
}

impl Meta {
    pub fn checked(&self, identity: &Identity) -> Result<()> {
        if self.version != 1
            || &self.identity != identity
            || crate::access_policy::generation(&self.generation).is_err()
            || crate::access_policy::generation(&self.cleanup_revision).is_err()
            || self.catalog_rows > 400_000
            || self.pinned_raw_bytes > 1024 * 1024 * 1024
        {
            return Err(corrupt());
        }
        Ok(())
    }

    pub fn next_generation(&mut self) -> Result<String> {
        let next = crate::access_policy::generation(&self.generation)
            .map_err(|_| corrupt())?
            .checked_add(1)
            .ok_or_else(corrupt)?;
        self.generation = next.to_string();
        Ok(self.generation.clone())
    }

    pub fn next_cleanup_revision(&mut self) -> Result<String> {
        let next = crate::access_policy::generation(&self.cleanup_revision)
            .map_err(|_| corrupt())?
            .checked_add(1)
            .ok_or_else(corrupt)?;
        self.cleanup_revision = next.to_string();
        Ok(self.cleanup_revision.clone())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Job {
    pub id: String,
    pub generation: String,
    pub revision: String,
    pub state: String,
    pub exact_ref: String,
    pub packmap_ref: String,
    pub head: String,
    pub packmap: String,
    pub selected_digest: String,
    pub policy_generation: String,
    pub profile_version: u8,
    pub validator_version: u8,
    pub tip_checked: bool,
    pub pack_index: u16,
    pub frame_index: u32,
    pub frontier_next_seq: u64,
    pub frontier_rows: u64,
    pub frontier_bytes: u64,
    pub catalog_packs: u64,
    pub catalog_raw_bytes: u64,
    pub catalog_entries: u64,
    pub reached_objects: u64,
    pub reached_bytes: u64,
    pub max_depth: u64,
    pub work_units: u64,
    pub attempts: u64,
    pub reserved_io_bytes: u64,
    pub r2_operations: u64,
    pub attempt_seq: String,
    pub attempt_scope: String,
    pub attempt_fingerprint: String,
    pub attempt_deadline: i64,
    pub attempt_bytes: u64,
    pub attempt_ops: u64,
    pub idle_deadline: i64,
    pub terminal_deadline: i64,
}

impl Job {
    pub fn checked(&self) -> Result<()> {
        if !crate::snapshot_wire::id(&self.id)
            || !crate::snapshot_wire::id(&self.head)
            || !crate::snapshot_wire::id(&self.packmap)
            || self.profile_version != 1
            || self.validator_version != 1
            || !matches!(
                self.state.as_str(),
                "catalog" | "walk" | "ready" | "cancelled" | "expired" | "failed" | "cleaning"
            )
            || crate::access_policy::generation(&self.generation).is_err()
            || crate::access_policy::generation(&self.revision).is_err()
            || crate::access_policy::generation(&self.attempt_seq).is_err()
            || crate::access_policy::generation(&self.policy_generation).is_err()
            || self.pack_index > 128
            || self.catalog_packs > 128
            || self.catalog_entries > 200_000
            || self.catalog_raw_bytes > 256 * 1024 * 1024
            || self.reached_objects > 100_000
            || self.reached_bytes > 256 * 1024 * 1024
            || self.max_depth > 128
            || self.work_units > 1_000_000
            || self.attempts > MAX_ATTEMPTS
            || self.frontier_rows > 100_000
            || self.frontier_bytes > 32 * 1024 * 1024
            || self.reserved_io_bytes > MAX_JOB_BYTES
            || self.r2_operations > MAX_JOB_OPS
            || self.attempt_bytes > MAX_STEP_BYTES
            || self.attempt_ops > MAX_STEP_OPS
        {
            return Err(corrupt());
        }
        Ok(())
    }

    pub fn active(&self) -> bool {
        matches!(self.state.as_str(), "catalog" | "walk")
    }

    pub fn reply(&self) -> JobReply {
        JobReply {
            version: 1,
            job_id: self.id.clone(),
            job_generation: self.generation.clone(),
            revision: self.revision.clone(),
            state: self.state.clone(),
            progress: JobProgress {
                catalog_packs: self.catalog_packs.to_string(),
                catalog_entries: self.catalog_entries.to_string(),
                reached_objects: self.reached_objects.to_string(),
                reached_bytes: self.reached_bytes.to_string(),
                work_units: self.work_units.to_string(),
                attempts: self.attempts.to_string(),
                reserved_io_bytes: self.reserved_io_bytes.to_string(),
                r2_operations: self.r2_operations.to_string(),
            },
        }
    }

    pub fn next_revision(&mut self, now: i64) -> Result<()> {
        let next = crate::access_policy::generation(&self.revision)
            .map_err(|_| corrupt())?
            .checked_add(1)
            .ok_or_else(corrupt)?;
        self.revision = next.to_string();
        self.idle_deadline = now.checked_add(JOB_IDLE_MS).ok_or_else(corrupt)?;
        Ok(())
    }

    pub fn claim(&mut self, scope: &str, fingerprint: &str, now: i64) -> Result<()> {
        self.attempts = self.attempts.checked_add(1).ok_or_else(corrupt)?;
        if self.attempts > MAX_ATTEMPTS {
            return Err(invalid());
        }
        let next = crate::access_policy::generation(&self.attempt_seq)
            .map_err(|_| corrupt())?
            .checked_add(1)
            .ok_or_else(corrupt)?;
        self.attempt_seq = next.to_string();
        self.attempt_scope = scope.to_owned();
        self.attempt_fingerprint = fingerprint.to_owned();
        self.attempt_deadline = now.checked_add(ATTEMPT_LEASE_MS).ok_or_else(corrupt)?;
        self.attempt_bytes = 0;
        self.attempt_ops = 0;
        Ok(())
    }

    pub fn charge(&mut self, bytes: u64) -> Result<()> {
        self.attempt_bytes = self.attempt_bytes.checked_add(bytes).ok_or_else(corrupt)?;
        self.reserved_io_bytes = self
            .reserved_io_bytes
            .checked_add(bytes)
            .ok_or_else(corrupt)?;
        self.attempt_ops = self.attempt_ops.checked_add(1).ok_or_else(corrupt)?;
        self.r2_operations = self.r2_operations.checked_add(1).ok_or_else(corrupt)?;
        if self.attempt_bytes > MAX_STEP_BYTES
            || self.reserved_io_bytes > MAX_JOB_BYTES
            || self.attempt_ops > MAX_STEP_OPS
            || self.r2_operations > MAX_JOB_OPS
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub fn finish_attempt(&mut self) {
        self.attempt_scope.clear();
        self.attempt_fingerprint.clear();
        self.attempt_deadline = 0;
        self.attempt_bytes = 0;
        self.attempt_ops = 0;
    }
}

#[derive(Deserialize)]
struct Name {
    name: String,
}
#[derive(Deserialize)]
struct Document {
    document: String,
}
#[derive(Deserialize)]
struct StoredJob {
    state: String,
    exact_ref: String,
    idle_deadline: i64,
    terminal_deadline: i64,
    document: String,
    checksum: String,
}

fn job_checksum(document: &str) -> String {
    let mut bytes = b"mkit.host.snapshot.job.v1\0".to_vec();
    bytes.extend_from_slice(document.as_bytes());
    hex::encode(mkit_core::hash::hash(&bytes))
}

impl RefStore {
    pub(super) fn snapshot_meta(&self, identity: &Identity) -> Result<Option<Meta>> {
        let rows: Vec<Name> = self.state.storage().sql().exec(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'host_snapshot_%' ORDER BY name", None
        )?.to_array()?;
        let names: Vec<_> = rows.iter().map(|row| row.name.as_str()).collect();
        if names.is_empty() {
            return Ok(None);
        }
        if names != TABLES {
            return Err(corrupt());
        }
        let rows: Vec<Document> = self
            .state
            .storage()
            .sql()
            .exec("SELECT document FROM host_snapshot_meta WHERE slot=1", None)?
            .to_array()?;
        if rows.len() != 1 {
            return Err(corrupt());
        }
        let meta: Meta = serde_json::from_str(&rows[0].document).map_err(|_| corrupt())?;
        meta.checked(identity)?;
        Ok(Some(meta))
    }

    pub(super) fn snapshot_bootstrap(&self, identity: &Identity) -> Result<Meta> {
        if self.snapshot_meta(identity)?.is_some() {
            return Err(corrupt());
        }
        let sql = self.state.storage().sql();
        sql.exec("CREATE TABLE host_snapshot_meta(slot INTEGER PRIMARY KEY CHECK(slot=1), document TEXT NOT NULL)", None)?;
        sql.exec("CREATE TABLE host_snapshot_jobs(job_id TEXT PRIMARY KEY, state TEXT NOT NULL, exact_ref TEXT NOT NULL, idle_deadline INTEGER NOT NULL, terminal_deadline INTEGER NOT NULL, document TEXT NOT NULL, checksum TEXT NOT NULL)", None)?;
        sql.exec(
            "CREATE INDEX host_snapshot_jobs_active ON host_snapshot_jobs(state, exact_ref)",
            None,
        )?;
        sql.exec(
            "CREATE INDEX host_snapshot_jobs_idle ON host_snapshot_jobs(state, idle_deadline)",
            None,
        )?;
        sql.exec("CREATE INDEX host_snapshot_jobs_terminal ON host_snapshot_jobs(state, terminal_deadline)", None)?;
        sql.exec("CREATE TABLE host_snapshot_selected(job_id TEXT NOT NULL, ordinal INTEGER NOT NULL, pack_key TEXT NOT NULL, PRIMARY KEY(job_id,ordinal), UNIQUE(job_id,pack_key))", None)?;
        sql.exec("CREATE TABLE host_snapshot_catalog(job_id TEXT NOT NULL, pack_key TEXT NOT NULL, ordinal INTEGER NOT NULL, object_id TEXT NOT NULL, kind TEXT NOT NULL, canonical_len INTEGER NOT NULL, payload_offset INTEGER NOT NULL, payload_len INTEGER NOT NULL, pack_size INTEGER NOT NULL, etag TEXT NOT NULL, PRIMARY KEY(job_id,pack_key,ordinal))", None)?;
        sql.exec(
            "CREATE INDEX host_snapshot_catalog_id ON host_snapshot_catalog(job_id,object_id)",
            None,
        )?;
        sql.exec("CREATE TABLE host_snapshot_seen(job_id TEXT NOT NULL, object_id TEXT NOT NULL, canonical_len INTEGER NOT NULL, PRIMARY KEY(job_id,object_id))", None)?;
        sql.exec("CREATE TABLE host_snapshot_frontier(job_id TEXT NOT NULL, seq INTEGER NOT NULL, document TEXT NOT NULL, PRIMARY KEY(job_id,seq))", None)?;
        sql.exec("CREATE TABLE host_snapshot_indexes(job_id TEXT PRIMARY KEY, generation TEXT NOT NULL, exact_ref TEXT NOT NULL, head TEXT NOT NULL, packmap TEXT NOT NULL, catalog_digest TEXT NOT NULL, raw_bytes INTEGER NOT NULL, retired INTEGER NOT NULL)", None)?;
        sql.exec(
            "CREATE INDEX host_snapshot_indexes_retired ON host_snapshot_indexes(retired,job_id)",
            None,
        )?;
        sql.exec("CREATE TABLE host_snapshot_certificates(exact_ref TEXT PRIMARY KEY, job_id TEXT NOT NULL, generation TEXT NOT NULL, head TEXT NOT NULL, packmap TEXT NOT NULL, catalog_digest TEXT NOT NULL, profile_version INTEGER NOT NULL, validator_version INTEGER NOT NULL, retired INTEGER NOT NULL DEFAULT 0)", None)?;
        sql.exec("CREATE TABLE host_snapshot_leases(lease_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, generation TEXT NOT NULL, deadline INTEGER NOT NULL)", None)?;
        sql.exec(
            "CREATE INDEX host_snapshot_leases_deadline ON host_snapshot_leases(deadline)",
            None,
        )?;
        let meta = Meta {
            version: 1,
            identity: identity.clone(),
            generation: "0".into(),
            cleanup_revision: "0".into(),
            catalog_rows: 0,
            pinned_raw_bytes: 0,
        };
        self.snapshot_save_meta(&meta)?;
        Ok(meta)
    }

    pub(super) fn snapshot_save_meta(&self, meta: &Meta) -> Result<()> {
        let document = serde_json::to_string(meta).map_err(|_| corrupt())?;
        self.state.storage().sql().exec(
            "INSERT INTO host_snapshot_meta(slot,document) VALUES(1,?) ON CONFLICT(slot) DO UPDATE SET document=excluded.document",
            vec![document.into()],
        )?;
        Ok(())
    }

    pub(super) fn snapshot_job(&self, id: &str) -> Result<Option<Job>> {
        let rows: Vec<StoredJob> = self.state.storage().sql().exec(
            "SELECT state,exact_ref,idle_deadline,terminal_deadline,document,checksum FROM host_snapshot_jobs WHERE job_id=?", vec![id.into()]
        )?.to_array()?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        if row.checksum != job_checksum(&row.document) {
            return Err(corrupt());
        }
        let job: Job = serde_json::from_str(&row.document).map_err(|_| corrupt())?;
        job.checked()?;
        if job.id != id
            || job.state != row.state
            || job.exact_ref != row.exact_ref
            || job.idle_deadline != row.idle_deadline
            || job.terminal_deadline != row.terminal_deadline
        {
            return Err(corrupt());
        }
        Ok(Some(job))
    }

    pub(super) fn snapshot_save_job(&self, job: &Job) -> Result<()> {
        job.checked()?;
        let document = serde_json::to_string(job).map_err(|_| corrupt())?;
        if document.len() > 4096 {
            return Err(corrupt());
        }
        self.state.storage().sql().exec(
            "INSERT INTO host_snapshot_jobs(job_id,state,exact_ref,idle_deadline,terminal_deadline,document,checksum) VALUES(?,?,?,?,?,?,?) ON CONFLICT(job_id) DO UPDATE SET state=excluded.state,exact_ref=excluded.exact_ref,idle_deadline=excluded.idle_deadline,terminal_deadline=excluded.terminal_deadline,document=excluded.document,checksum=excluded.checksum",
            vec![job.id.clone().into(),job.state.clone().into(),job.exact_ref.clone().into(),job.idle_deadline.into(),job.terminal_deadline.into(),document.clone().into(),job_checksum(&document).into()],
        )?;
        Ok(())
    }

    pub(super) fn snapshot_count(
        &self,
        sql: &str,
        params: Vec<worker::SqlStorageValue>,
    ) -> Result<u64> {
        #[derive(Deserialize)]
        struct Count {
            n: i64,
        }
        let rows: Vec<Count> = self.state.storage().sql().exec(sql, params)?.to_array()?;
        let n = rows.first().ok_or_else(corrupt)?.n;
        u64::try_from(n).map_err(|_| corrupt())
    }

    pub(super) fn snapshot_exists(
        &self,
        sql: &str,
        params: Vec<worker::SqlStorageValue>,
    ) -> Result<bool> {
        #[derive(Deserialize)]
        struct Found {
            found: i64,
        }
        let rows: Vec<Found> = self.state.storage().sql().exec(sql, params)?.to_array()?;
        if rows.len() > 1 || rows.first().is_some_and(|row| row.found != 1) {
            return Err(corrupt());
        }
        Ok(!rows.is_empty())
    }
}
