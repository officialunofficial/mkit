// SPDX-License-Identifier: MIT OR Apache-2.0
//! Private hosted submission bookkeeping. Only immutable identity survives bulky cleanup.
//!
//! All calls that change these rows run inside the RefStore SQL transaction. The
//! typed rows are service checkpoints, never deserializable portable proofs.

use super::refstore::RefStore;
use crate::access_policy::{Identity, generation};
use mkit_core::partial::{SnapshotWalkUsage, StagedUpdateUsageV1};
use serde::{Deserialize, Serialize};
use worker::{Error, Result};

pub(super) const ACTIVE_IDLE_MS: i64 = 24 * 60 * 60 * 1000;
pub(super) const BULKY_MS: i64 = 7 * ACTIVE_IDLE_MS;
pub(super) const CLAIM_MS: i64 = 2 * 60 * 1000;
pub(super) const MAX_CARRIER: u64 = 4 * 1024 * 1024;
pub(super) const MAX_PACK: u64 = 3 * 1024 * 1024;
pub(super) const MAX_ATTEMPTS: u64 = 8192;
pub(super) const MAX_JOB_IO: u64 = 2 * 1024 * 1024 * 1024;
pub(super) const MAX_JOB_OPS: u64 = 540_672;
pub(super) const MAX_STEP_IO: u64 = 8 * 1024 * 1024;
pub(super) const MAX_STEP_OPS: u64 = 66;

const TABLES: [&str; 12] = [
    "host_submission_frontier",
    "host_submission_inventory",
    "host_submission_jobs",
    "host_submission_lifetime",
    "host_submission_matched",
    "host_submission_meta",
    "host_submission_pins",
    "host_submission_required",
    "host_submission_seen",
    "host_submission_selected",
    "host_submission_subjects",
    "host_submission_supplied",
];

pub(super) fn corrupt() -> Error {
    Error::RustError("corrupt hosted submission state".into())
}
pub(super) fn checked_decimal(value: &str) -> Result<u64> {
    generation(value).map_err(|_| corrupt())
}
fn checksum(document: &str) -> String {
    hex::encode(mkit_core::hash::hash(
        [
            b"mkit.host.submission.row.v1\0".as_slice(),
            document.as_bytes(),
        ]
        .concat()
        .as_slice(),
    ))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Meta {
    pub version: u8,
    pub identity: Identity,
    pub next_generation: String,
    pub cleanup_revision: String,
    pub lifetime: u64,
    pub active: u64,
    pub terminal_slots: u64,
    pub carrier_slots: u64,
    pub carrier_bytes: u64,
}

impl Meta {
    fn checked(&self, identity: &Identity) -> Result<()> {
        if self.version != 1
            || &self.identity != identity
            || checked_decimal(&self.next_generation).is_err()
            || checked_decimal(&self.cleanup_revision).is_err()
            || self.lifetime > 100_000
            || self.active > 2
            || self.terminal_slots > 128
            || self.carrier_slots > 8
            || self.carrier_bytes > 32 * 1024 * 1024
        {
            return Err(corrupt());
        }
        Ok(())
    }

    pub fn allocate_generation(&mut self) -> Result<String> {
        self.next_generation = checked_decimal(&self.next_generation)?
            .checked_add(1)
            .ok_or_else(corrupt)?
            .to_string();
        Ok(self.next_generation.clone())
    }
}

/// This row is bounded even when its bulky job and carrier have been reclaimed.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Lifetime {
    pub operation_id: String,
    pub submission_id: String,
    pub generation: String,
    pub subject: String,
    pub binding: String,
    pub workspace_id: String,
    pub grant_id: String,
    pub grant_generation: String,
    pub exact_ref: String,
    pub expected_base: String,
    pub update_digest: String,
    pub update_len: u64,
    pub state: String,
    pub revision: String,
    pub created_at: i64,
    pub terminal_at: i64,
    pub status: String,
    pub terminal_progress: Option<crate::submission_response::Progress>,
}

impl Lifetime {
    pub fn checked(&self) -> Result<()> {
        use crate::snapshot_wire::id;
        if ![
            &self.operation_id,
            &self.submission_id,
            &self.subject,
            &self.binding,
            &self.workspace_id,
            &self.grant_id,
            &self.expected_base,
            &self.update_digest,
        ]
        .into_iter()
        .all(|v| id(v))
            || checked_decimal(&self.generation).is_err()
            || checked_decimal(&self.grant_generation).is_err()
            || checked_decimal(&self.revision).is_err()
            || self.update_len > MAX_CARRIER
            || self.exact_ref.len() > 1024
            || ![
                "awaiting_upload",
                "validating",
                "validated",
                "refused",
                "expired",
            ]
            .contains(&self.state.as_str())
            || self.status.len() > 8192
            || self
                .terminal_progress
                .as_ref()
                .is_some_and(|progress| !progress.checked())
            || (["validated", "refused", "expired"].contains(&self.state.as_str())
                != (self.terminal_at > 0 && self.terminal_progress.is_some()))
        {
            return Err(corrupt());
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Job {
    pub operation_id: String,
    pub submission_id: String,
    pub generation: String,
    pub revision: String,
    pub state: String,
    pub phase: String,
    pub policy_generation: String,
    pub expected_packmap: String,
    #[serde(skip)]
    pub begin_body: String,
    #[serde(skip)]
    pub sealed_header: String,
    pub carrier_key: String,
    pub carrier_etag: String,
    pub pack_key: String,
    pub pack_offset: u64,
    pub pack_len: u64,
    pub inventory_cursor: u64,
    pub inventory_bytes: u64,
    pub inventory_previous_id: String,
    pub usage: Usage,
    pub frontier_next_seq: u64,
    pub frontier_rows: u64,
    pub frontier_bytes: u64,
    pub base_objects: u64,
    pub candidate_objects: u64,
    pub supplied_objects: u64,
    pub required_objects: u64,
    pub matched_changes: u64,
    pub audit_phase: String,
    pub audit_cursor: String,
    pub audit_rows: u64,
    pub audit_bytes: u64,
    pub attempts: u64,
    pub reserved_io_bytes: u64,
    pub r2_operations: u64,
    pub fit_attempts: u64,
    pub fit_io_bytes: u64,
    pub fit_operations: u64,
    pub attempt_seq: String,
    pub attempt_scope: String,
    pub attempt_fingerprint: String,
    pub attempt_deadline: i64,
    pub attempt_bytes: u64,
    pub attempt_ops: u64,
    pub idle_deadline: i64,
    pub bulky_deadline: i64,
    pub cleanup_claim_seq: String,
    pub cleanup_claim_deadline: i64,
    pub cleanup_claim_scope: String,
    pub cleanup_claim_fingerprint: String,
    pub cleanup_ops: u64,
    pub cleanup_bytes: u64,
    pub cleanup_attempts: u64,
    pub marker_confirmed: bool,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WalkUsage {
    pub objects: u64,
    pub canonical_bytes: u64,
    pub max_tree_depth: u64,
    pub work: u64,
}
impl From<SnapshotWalkUsage> for WalkUsage {
    fn from(v: SnapshotWalkUsage) -> Self {
        Self {
            objects: v.objects,
            canonical_bytes: v.canonical_bytes,
            max_tree_depth: v.max_tree_depth,
            work: v.work,
        }
    }
}
impl From<WalkUsage> for SnapshotWalkUsage {
    fn from(v: WalkUsage) -> Self {
        Self {
            objects: v.objects,
            canonical_bytes: v.canonical_bytes,
            max_tree_depth: v.max_tree_depth,
            work: v.work,
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Usage {
    pub header_bytes: u64,
    pub update_bytes: u64,
    pub pack_bytes: u64,
    pub inventory_entries: u64,
    pub inventory_payload_bytes: u64,
    pub inventory_work: u64,
    pub base_walk: WalkUsage,
    pub candidate_walk: WalkUsage,
    pub diff_pair_visits: u64,
    pub diff_compared_entries: u64,
    pub diff_work: u64,
    pub required_unique_ids: u64,
    pub required_canonical_bytes: u64,
    pub origin_work: u64,
    pub max_changed_file_bytes_seen: u64,
    pub changed_total_bytes: u64,
}
impl From<StagedUpdateUsageV1> for Usage {
    fn from(v: StagedUpdateUsageV1) -> Self {
        Self {
            header_bytes: v.header_bytes,
            update_bytes: v.update_bytes,
            pack_bytes: v.pack_bytes,
            inventory_entries: v.inventory_entries,
            inventory_payload_bytes: v.inventory_payload_bytes,
            inventory_work: v.inventory_work,
            base_walk: v.base_walk.into(),
            candidate_walk: v.candidate_walk.into(),
            diff_pair_visits: v.diff_pair_visits,
            diff_compared_entries: v.diff_compared_entries,
            diff_work: v.diff_work,
            required_unique_ids: v.required_unique_ids,
            required_canonical_bytes: v.required_canonical_bytes,
            origin_work: v.origin_work,
            max_changed_file_bytes_seen: v.max_changed_file_bytes_seen,
            changed_total_bytes: v.changed_total_bytes,
        }
    }
}
impl From<Usage> for StagedUpdateUsageV1 {
    fn from(v: Usage) -> Self {
        Self {
            header_bytes: v.header_bytes,
            update_bytes: v.update_bytes,
            pack_bytes: v.pack_bytes,
            inventory_entries: v.inventory_entries,
            inventory_payload_bytes: v.inventory_payload_bytes,
            inventory_work: v.inventory_work,
            base_walk: v.base_walk.into(),
            candidate_walk: v.candidate_walk.into(),
            diff_pair_visits: v.diff_pair_visits,
            diff_compared_entries: v.diff_compared_entries,
            diff_work: v.diff_work,
            required_unique_ids: v.required_unique_ids,
            required_canonical_bytes: v.required_canonical_bytes,
            origin_work: v.origin_work,
            max_changed_file_bytes_seen: v.max_changed_file_bytes_seen,
            changed_total_bytes: v.changed_total_bytes,
        }
    }
}

impl Job {
    pub fn checked(&self) -> Result<()> {
        if !crate::snapshot_wire::id(&self.operation_id)
            || !crate::snapshot_wire::id(&self.submission_id)
            || checked_decimal(&self.generation).is_err()
            || checked_decimal(&self.revision).is_err()
            || checked_decimal(&self.attempt_seq).is_err()
            || checked_decimal(&self.cleanup_claim_seq).is_err()
            || self.begin_body.len() > 256 * 1024
            || self.sealed_header.len() > (128_usize * 1024 * 4).div_ceil(3)
            || self.frontier_rows > 100_000
            || self.frontier_bytes > 32 * 1024 * 1024
            || self.supplied_objects > 2048
            || self.required_objects > 2048
            || self.matched_changes > 256
            || self.audit_cursor.len() > 64
            || ![
                "",
                "base",
                "candidate",
                "required",
                "supplied",
                "matched",
                "done",
            ]
            .contains(&self.audit_phase.as_str())
            || self.attempts > MAX_ATTEMPTS
            || self.reserved_io_bytes > MAX_JOB_IO
            || self.r2_operations > MAX_JOB_OPS
            || self.fit_attempts > 8
            || self.fit_io_bytes > 32 * 1024 * 1024
            || self.fit_operations > 16_384
            || self.attempt_bytes > MAX_STEP_IO
            || self.attempt_ops > MAX_STEP_OPS.max(2048)
            || self.cleanup_ops > 12
            || self.cleanup_bytes > 4096
            || self.cleanup_attempts > MAX_ATTEMPTS
        {
            return Err(corrupt());
        }
        Ok(())
    }

    pub fn claim(
        &mut self,
        scope: &str,
        fingerprint: &str,
        timestamp: i64,
        fit: bool,
    ) -> Result<()> {
        if self.attempt_deadline > timestamp || self.attempts >= MAX_ATTEMPTS {
            return Err(Error::RustError("submission attempt capacity".into()));
        }
        self.attempts = self.attempts.checked_add(1).ok_or_else(corrupt)?;
        self.attempt_seq = checked_decimal(&self.attempt_seq)?
            .checked_add(1)
            .ok_or_else(corrupt)?
            .to_string();
        self.attempt_scope = scope.into();
        self.attempt_fingerprint = fingerprint.into();
        self.attempt_deadline = timestamp.checked_add(CLAIM_MS).ok_or_else(corrupt)?;
        self.attempt_bytes = 0;
        self.attempt_ops = 0;
        if fit {
            self.fit_attempts = self.fit_attempts.checked_add(1).ok_or_else(corrupt)?;
            if self.fit_attempts > 8 {
                return Err(Error::RustError("submission fit capacity".into()));
            }
        }
        Ok(())
    }

    pub fn charge(&mut self, bytes: u64, operations: u64, fit: bool) -> Result<()> {
        if !self.can_charge(bytes, operations, fit)? {
            return Err(Error::RustError("submission I/O capacity".into()));
        }
        self.attempt_bytes += bytes;
        self.attempt_ops += operations;
        self.reserved_io_bytes += bytes;
        self.r2_operations += operations;
        if fit {
            self.fit_io_bytes += bytes;
            self.fit_operations += operations;
        }
        Ok(())
    }

    /// Prospective arithmetic is checked before any reservation is persisted.
    /// A false result is a deterministic hosted-profile refusal, not a SQL or
    /// R2 failure; callers can terminalize without parsing an error string.
    pub fn can_charge(&self, bytes: u64, operations: u64, fit: bool) -> Result<bool> {
        let step_max_bytes = if fit { 4 * 1024 * 1024 } else { MAX_STEP_IO };
        let step_max_ops = if fit { 2048 } else { MAX_STEP_OPS };
        let attempt_bytes = self.attempt_bytes.checked_add(bytes).ok_or_else(corrupt)?;
        let attempt_ops = self
            .attempt_ops
            .checked_add(operations)
            .ok_or_else(corrupt)?;
        let reserved_io_bytes = self
            .reserved_io_bytes
            .checked_add(bytes)
            .ok_or_else(corrupt)?;
        let r2_operations = self
            .r2_operations
            .checked_add(operations)
            .ok_or_else(corrupt)?;
        let fit_io_bytes = self
            .fit_io_bytes
            .checked_add(if fit { bytes } else { 0 })
            .ok_or_else(corrupt)?;
        let fit_operations = self
            .fit_operations
            .checked_add(if fit { operations } else { 0 })
            .ok_or_else(corrupt)?;
        Ok(attempt_bytes <= step_max_bytes
            && attempt_ops <= step_max_ops
            && reserved_io_bytes <= MAX_JOB_IO
            && r2_operations <= MAX_JOB_OPS
            && fit_io_bytes <= 32 * 1024 * 1024
            && fit_operations <= 16_384)
    }

    pub fn finish_attempt(&mut self) {
        self.attempt_scope.clear();
        self.attempt_fingerprint.clear();
        self.attempt_deadline = 0;
        self.attempt_bytes = 0;
        self.attempt_ops = 0;
    }

    pub fn next_revision(&mut self) -> Result<String> {
        self.revision = checked_decimal(&self.revision)?
            .checked_add(1)
            .ok_or_else(corrupt)?
            .to_string();
        Ok(self.revision.clone())
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
struct StoredLifetime {
    document: String,
    checksum: String,
    subject: String,
}
#[derive(Deserialize)]
struct StoredJob {
    document: String,
    checksum: String,
    state: String,
    exact_ref: String,
    idle_deadline: i64,
    bulky_deadline: i64,
    marker_confirmed: i64,
    begin_body: String,
    sealed_header: String,
}

fn job_checksum(document: &str, begin_body: &str, sealed_header: &str) -> String {
    hex::encode(mkit_core::hash::hash(
        [
            b"mkit.host.submission.job.v1\0".as_slice(),
            &(document.len() as u32).to_le_bytes(),
            document.as_bytes(),
            &(begin_body.len() as u32).to_le_bytes(),
            begin_body.as_bytes(),
            &(sealed_header.len() as u32).to_le_bytes(),
            sealed_header.as_bytes(),
        ]
        .concat()
        .as_slice(),
    ))
}

impl RefStore {
    pub(super) fn submission_meta(&self, identity: &Identity) -> Result<Option<Meta>> {
        let names: Vec<Name> = self.state.storage().sql().exec(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'host_submission_%' ORDER BY name", None
        )?.to_array()?;
        let actual: Vec<&str> = names.iter().map(|n| n.name.as_str()).collect();
        if actual.is_empty() {
            return Ok(None);
        }
        if actual != TABLES {
            return Err(corrupt());
        }
        let rows: Vec<Document> = self
            .state
            .storage()
            .sql()
            .exec(
                "SELECT document FROM host_submission_meta WHERE slot=1",
                None,
            )?
            .to_array()?;
        if rows.len() != 1 {
            return Err(corrupt());
        }
        let meta: Meta = serde_json::from_str(&rows[0].document).map_err(|_| corrupt())?;
        meta.checked(identity)?;
        Ok(Some(meta))
    }

    pub(super) fn submission_bootstrap(&self, identity: &Identity) -> Result<Meta> {
        if self.submission_meta(identity)?.is_some() {
            return Err(corrupt());
        }
        let sql = self.state.storage().sql();
        sql.exec("CREATE TABLE host_submission_meta(slot INTEGER PRIMARY KEY CHECK(slot=1), document TEXT NOT NULL)", None)?;
        sql.exec("CREATE TABLE host_submission_lifetime(operation_id TEXT PRIMARY KEY, subject TEXT NOT NULL, document TEXT NOT NULL, checksum TEXT NOT NULL)", None)?;
        sql.exec("CREATE INDEX host_submission_lifetime_subject ON host_submission_lifetime(subject,operation_id)", None)?;
        sql.exec("CREATE TABLE host_submission_subjects(subject TEXT PRIMARY KEY, lifetime INTEGER NOT NULL, carrier_slots INTEGER NOT NULL, carrier_bytes INTEGER NOT NULL)", None)?;
        sql.exec("CREATE TABLE host_submission_jobs(operation_id TEXT PRIMARY KEY, state TEXT NOT NULL, exact_ref TEXT NOT NULL, idle_deadline INTEGER NOT NULL, bulky_deadline INTEGER NOT NULL, marker_confirmed INTEGER NOT NULL CHECK(marker_confirmed IN (0,1)), document TEXT NOT NULL, begin_body TEXT NOT NULL, sealed_header TEXT NOT NULL, checksum TEXT NOT NULL)", None)?;
        sql.exec(
            "CREATE INDEX host_submission_jobs_active ON host_submission_jobs(state,exact_ref)",
            None,
        )?;
        sql.exec(
            "CREATE INDEX host_submission_jobs_idle ON host_submission_jobs(state,idle_deadline)",
            None,
        )?;
        sql.exec(
            "CREATE INDEX host_submission_jobs_bulky ON host_submission_jobs(state,bulky_deadline)",
            None,
        )?;
        sql.exec("CREATE INDEX host_submission_jobs_marker ON host_submission_jobs(marker_confirmed,bulky_deadline)", None)?;
        sql.exec("CREATE TABLE host_submission_selected(operation_id TEXT NOT NULL, ordinal INTEGER NOT NULL, path TEXT NOT NULL, PRIMARY KEY(operation_id,ordinal), UNIQUE(operation_id,path))", None)?;
        sql.exec("CREATE TABLE host_submission_inventory(operation_id TEXT NOT NULL, ordinal INTEGER NOT NULL, object_id TEXT NOT NULL, canonical_len INTEGER NOT NULL, payload_offset INTEGER NOT NULL, payload_len INTEGER NOT NULL, PRIMARY KEY(operation_id,ordinal), UNIQUE(operation_id,object_id))", None)?;
        sql.exec("CREATE TABLE host_submission_supplied(operation_id TEXT NOT NULL, object_id TEXT NOT NULL, canonical_len INTEGER NOT NULL, payload_offset INTEGER NOT NULL, payload_len INTEGER NOT NULL, PRIMARY KEY(operation_id,object_id))", None)?;
        sql.exec("CREATE TABLE host_submission_required(operation_id TEXT NOT NULL, object_id TEXT NOT NULL, canonical_len INTEGER NOT NULL, PRIMARY KEY(operation_id,object_id))", None)?;
        sql.exec("CREATE TABLE host_submission_matched(operation_id TEXT NOT NULL, change_index INTEGER NOT NULL, PRIMARY KEY(operation_id,change_index))", None)?;
        sql.exec("CREATE TABLE host_submission_seen(operation_id TEXT NOT NULL, phase TEXT NOT NULL, object_id TEXT NOT NULL, canonical_len INTEGER NOT NULL, PRIMARY KEY(operation_id,phase,object_id))", None)?;
        sql.exec("CREATE TABLE host_submission_frontier(operation_id TEXT NOT NULL, phase TEXT NOT NULL, seq INTEGER NOT NULL, document TEXT NOT NULL, PRIMARY KEY(operation_id,phase,seq))", None)?;
        sql.exec("CREATE TABLE host_submission_pins(operation_id TEXT NOT NULL, index_job_id TEXT NOT NULL, index_generation TEXT NOT NULL, catalog_digest TEXT NOT NULL, head TEXT NOT NULL, packmap TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(operation_id,index_job_id))", None)?;
        sql.exec("CREATE INDEX host_submission_pins_index ON host_submission_pins(index_job_id,expires_at)", None)?;
        let meta = Meta {
            version: 1,
            identity: identity.clone(),
            next_generation: "0".into(),
            cleanup_revision: "0".into(),
            lifetime: 0,
            active: 0,
            terminal_slots: 0,
            carrier_slots: 0,
            carrier_bytes: 0,
        };
        self.submission_save_meta(&meta)?;
        Ok(meta)
    }

    pub(super) fn submission_save_meta(&self, meta: &Meta) -> Result<()> {
        meta.checked(&meta.identity)?;
        let document = serde_json::to_string(meta).map_err(|_| corrupt())?;
        self.state.storage().sql().exec("INSERT INTO host_submission_meta(slot,document) VALUES(1,?) ON CONFLICT(slot) DO UPDATE SET document=excluded.document", vec![document.into()])?;
        Ok(())
    }

    pub(super) fn submission_lifetime(&self, id: &str) -> Result<Option<Lifetime>> {
        let rows: Vec<StoredLifetime> = self.state.storage().sql().exec(
            "SELECT document,checksum,subject FROM host_submission_lifetime WHERE operation_id=?", vec![id.into()]
        )?.to_array()?;
        if rows.len() > 1 {
            return Err(corrupt());
        }
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        if checksum(&row.document) != row.checksum {
            return Err(corrupt());
        }
        let value: Lifetime = serde_json::from_str(&row.document).map_err(|_| corrupt())?;
        value.checked()?;
        if value.operation_id != id || value.subject != row.subject {
            return Err(corrupt());
        }
        Ok(Some(value))
    }

    pub(super) fn submission_save_lifetime(&self, value: &Lifetime) -> Result<()> {
        value.checked()?;
        let document = serde_json::to_string(value).map_err(|_| corrupt())?;
        if document.len() > 4096 {
            return Err(corrupt());
        }
        self.state.storage().sql().exec(
            "INSERT INTO host_submission_lifetime(operation_id,subject,document,checksum) VALUES(?,?,?,?) ON CONFLICT(operation_id) DO UPDATE SET document=excluded.document,checksum=excluded.checksum",
            vec![value.operation_id.clone().into(),value.subject.clone().into(),document.clone().into(),checksum(&document).into()]
        )?;
        Ok(())
    }

    pub(super) fn submission_job(&self, id: &str) -> Result<Option<Job>> {
        let rows: Vec<StoredJob>=self.state.storage().sql().exec(
            "SELECT document,checksum,state,exact_ref,idle_deadline,bulky_deadline,marker_confirmed,begin_body,sealed_header FROM host_submission_jobs WHERE operation_id=?",vec![id.into()]
        )?.to_array()?;
        if rows.len() > 1 {
            return Err(corrupt());
        }
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        if job_checksum(&row.document, &row.begin_body, &row.sealed_header) != row.checksum {
            return Err(corrupt());
        }
        let mut value: Job = serde_json::from_str(&row.document).map_err(|_| corrupt())?;
        value.begin_body = row.begin_body;
        value.sealed_header = row.sealed_header;
        value.checked()?;
        let lifetime = self.submission_lifetime(id)?.ok_or_else(corrupt)?;
        if value.operation_id != id
            || value.state != row.state
            || value.idle_deadline != row.idle_deadline
            || value.bulky_deadline != row.bulky_deadline
            || i64::from(value.marker_confirmed) != row.marker_confirmed
            || lifetime.exact_ref != row.exact_ref
            || value.generation != lifetime.generation
            || value.revision != lifetime.revision
            || value.submission_id != lifetime.submission_id
            || value.state != lifetime.state
        {
            return Err(corrupt());
        }
        Ok(Some(value))
    }

    pub(super) fn submission_save_job(&self, value: &Job, exact_ref: &str) -> Result<()> {
        value.checked()?;
        let document = serde_json::to_string(value).map_err(|_| corrupt())?;
        if document.len() > 8192 {
            return Err(corrupt());
        }
        self.state.storage().sql().exec(
            "INSERT INTO host_submission_jobs(operation_id,state,exact_ref,idle_deadline,bulky_deadline,marker_confirmed,document,begin_body,sealed_header,checksum) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(operation_id) DO UPDATE SET state=excluded.state,idle_deadline=excluded.idle_deadline,bulky_deadline=excluded.bulky_deadline,marker_confirmed=excluded.marker_confirmed,document=excluded.document,begin_body=excluded.begin_body,sealed_header=excluded.sealed_header,checksum=excluded.checksum",
            vec![value.operation_id.clone().into(),value.state.clone().into(),exact_ref.into(),value.idle_deadline.into(),value.bulky_deadline.into(),i64::from(value.marker_confirmed).into(),document.clone().into(),value.begin_body.clone().into(),value.sealed_header.clone().into(),job_checksum(&document,&value.begin_body,&value.sealed_header).into()]
        )?;
        Ok(())
    }
}
