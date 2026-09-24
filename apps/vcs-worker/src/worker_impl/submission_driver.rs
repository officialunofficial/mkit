// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fenced asynchronous quarantine and staged-validation driver.

use futures::StreamExt;
use mkit_core::{
    hash::{from_hex, hash},
    object::{Identity as ObjectIdentity, Object},
    partial::{
        CheckedMkwu, HeaderPrefix, InspectError, ObjectInspectionLimits, PartialError,
        PartialLimits, PartialObjectRole, PartialSnapshotBuilder, RequiredFileRecord, SnapshotRole,
        SnapshotWalkError, SnapshotWalkRecord, SnapshotWalkUsage, StagedInventoryCursor,
        StagedRequiredObservation, StagedUpdateError, StagedUpdateLimitsV1, StagedUpdateUsageV1,
        StagedValidationContext, WalkObjectObservation, advance_changed_pair,
        advance_required_file, advance_snapshot_walk, advance_staged_inventory,
        apply_changed_accounting, apply_inventory_accounting, apply_required_accounting,
        apply_walk_accounting, default_staged_inspection_limits, inspect_snapshot_object,
        inspect_staged_candidate, inspect_staged_inventory_object, next_manifest_ids,
        next_required_chunk_ids, parse_mkwu_header_prefix, start_changed_pairs,
        start_snapshot_walk, verify_partial_snapshot,
    },
    serialize::deserialize,
};
use mkit_worker_common::replay::{Proof, Reply};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, num::NonZeroUsize};
use worker::{Conditional, Error, Method, Request, Response, Result};

use super::{
    refstore::RefStore,
    service::STORAGE_BUCKET,
    snapshot_driver::Locator,
    snapshot_leases::{SnapshotLeaseAcquire, SnapshotReadLease},
    submission_jobs::{SubmissionWire, error, now, progress, status, unavailable},
    submission_store::{
        ACTIVE_IDLE_MS, BULKY_MS, Job, Lifetime, MAX_ATTEMPTS, MAX_CARRIER, MAX_JOB_IO,
        MAX_JOB_OPS, MAX_PACK, MAX_STEP_IO, corrupt,
    },
};
use crate::{
    access_policy::Identity,
    snapshot_frontier::Frontier,
    submission_errors::{self, ValidationFailure},
    submission_frontier::DiffFrontier,
    submission_wire,
};

const CONFLICT: &str = "{\"code\":\"conflict\"}";
const DENIED: &str = "{\"code\":\"permission_denied\"}";
const EXHAUSTED: &str = "{\"code\":\"resource_exhausted\"}";
const INVALID: &str = "{\"code\":\"invalid_argument\"}";
const UNAVAILABLE: &str = "{\"code\":\"unavailable\"}";

struct ClaimedPermit(std::rc::Rc<std::cell::Cell<bool>>);
impl Drop for ClaimedPermit {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

struct AttemptLease {
    store: RefStore,
    lease: SnapshotReadLease,
}
impl Drop for AttemptLease {
    fn drop(&mut self) {
        let _ = self.store.snapshot_release_read_lease(&self.lease.lease_id);
    }
}
enum AttemptLeaseAcquire {
    Acquired(AttemptLease),
    Capacity,
    Conflict,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UploadContext {
    pub identity: Identity,
    pub proof: Proof,
}

fn portable() -> PartialLimits {
    PartialLimits {
        max_update_bytes: MAX_CARRIER as usize,
        max_raw_pack_bytes: MAX_PACK as usize,
        max_update_objects: 2048,
        max_selected_file_bytes: 256 * 1024,
        max_total_selected_bytes: 1024 * 1024,
        max_base_object_bytes: 2 * 1024 * 1024,
        max_tree_object_bytes: 2 * 1024 * 1024,
        max_tree_entries: 65_536,
        max_object_bytes: 2 * 1024 * 1024,
        ..PartialLimits::V1
    }
}

fn staged() -> StagedUpdateLimitsV1 {
    StagedUpdateLimitsV1 {
        max_update_bytes: MAX_CARRIER,
        max_pack_bytes: MAX_PACK,
        max_inventory_entries: 2048,
        max_inventory_payload_bytes: MAX_PACK,
        max_inventory_work: 4096,
        max_required_unique_ids: 2048,
        max_required_canonical_bytes: MAX_PACK,
        ..StagedUpdateLimitsV1::default()
    }
}

fn deadline_ok(deadline: i64, proof: &Proof) -> Result<()> {
    let timestamp = now();
    if timestamp >= deadline || timestamp > proof.expires_at {
        return Err(Error::RustError("submission deadline".into()));
    }
    Ok(())
}

async fn bounded_body(req: &mut Request, max: usize) -> Result<Option<Vec<u8>>> {
    if req
        .headers()
        .get("content-length")?
        .as_deref()
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|len| len > max)
    {
        return Ok(None);
    }
    let mut stream = req.stream()?;
    let mut bytes = Vec::new();
    while let Some(part) = stream.next().await {
        let part = part?;
        if part.len() > max - bytes.len() {
            return Ok(None);
        }
        bytes.extend_from_slice(&part);
    }
    Ok(Some(bytes))
}

enum Claim {
    Reply(Reply),
    Pending,
    New {
        job: Box<Job>,
        lifetime: Box<Lifetime>,
    },
}

enum ContinueClaim {
    Reply(Reply),
    Pending,
    New(Box<Job>),
}

struct InventoryRecord {
    ordinal: u64,
    id: String,
    canonical_len: u64,
    payload_offset: u64,
    payload_len: u64,
}

#[derive(Deserialize)]
struct Queued {
    seq: i64,
    document: String,
}
#[derive(Deserialize)]
struct SuppliedLocator {
    canonical_len: i64,
    payload_offset: i64,
    payload_len: i64,
}
#[derive(Deserialize)]
struct PinLocator {
    index_job_id: String,
    index_generation: String,
    catalog_digest: String,
    head: String,
    packmap: String,
    expires_at: i64,
}
enum SourceLocator {
    Base(Locator),
    Supplied {
        id: String,
        canonical_len: u64,
        offset: u64,
        len: u64,
    },
}
enum SourceRead {
    Bytes(Vec<u8>),
    Refused(Reply),
}
macro_rules! read_source {
    ($store:expr,$identity:expr,$proof:expr,$job:expr,$locator:expr,$deadline:expr,$fit:expr) => {
        match $store
            .submission_read_source($identity, $proof, $job, $locator, $deadline, $fit)
            .await?
        {
            SourceRead::Bytes(bytes) => bytes,
            SourceRead::Refused(reply) => return Ok(reply),
        }
    };
}
impl SourceLocator {
    fn len(&self) -> u64 {
        match self {
            Self::Base(v) => v.payload_len as u64,
            Self::Supplied { len, .. } => *len,
        }
    }
}

impl RefStore {
    fn refuse_staged_error(
        &self,
        identity: &Identity,
        proof: &Proof,
        job: &Job,
        error: StagedUpdateError,
        bad: &str,
    ) -> Result<Reply> {
        match submission_errors::staged(&error) {
            ValidationFailure::Resource => {
                self.submission_refuse(identity, proof, job, "resource_exhausted")
            }
            ValidationFailure::Invalid => self.submission_refuse(identity, proof, job, bad),
            ValidationFailure::Unavailable => Err(corrupt()),
        }
    }

    fn refuse_walk_error(
        &self,
        identity: &Identity,
        proof: &Proof,
        job: &Job,
        error: SnapshotWalkError,
        candidate: bool,
    ) -> Result<Reply> {
        match submission_errors::walk(error, candidate) {
            ValidationFailure::Resource => {
                self.submission_refuse(identity, proof, job, "resource_exhausted")
            }
            ValidationFailure::Invalid => {
                self.submission_refuse(identity, proof, job, "invalid_candidate")
            }
            ValidationFailure::Unavailable => Err(corrupt()),
        }
    }

    fn refuse_inspect_error(
        &self,
        identity: &Identity,
        proof: &Proof,
        job: &Job,
        error: InspectError,
        candidate: bool,
    ) -> Result<Reply> {
        match submission_errors::inspect(&error, candidate) {
            ValidationFailure::Resource => {
                self.submission_refuse(identity, proof, job, "resource_exhausted")
            }
            ValidationFailure::Invalid => {
                self.submission_refuse(identity, proof, job, "invalid_candidate")
            }
            ValidationFailure::Unavailable => Err(corrupt()),
        }
    }

    fn refuse_partial_error(
        &self,
        identity: &Identity,
        proof: &Proof,
        job: &Job,
        error: PartialError,
    ) -> Result<Reply> {
        match submission_errors::partial(&error) {
            ValidationFailure::Resource => {
                self.submission_refuse(identity, proof, job, "resource_exhausted")
            }
            ValidationFailure::Invalid => {
                self.submission_refuse(identity, proof, job, "unsupported_profile")
            }
            ValidationFailure::Unavailable => Err(corrupt()),
        }
    }

    /// Count the business row returned by SQLite, not rows_written: the latter
    /// includes index maintenance on the pin expiry index in Durable Objects.
    fn submission_set_pin_expiry(
        &self,
        id: &str,
        deadline: i64,
        minimum: Option<i64>,
    ) -> Result<()> {
        #[derive(Deserialize)]
        struct Updated {
            operation_id: String,
        }
        let (sql, args) = if let Some(minimum) = minimum {
            (
                "UPDATE host_submission_pins SET expires_at=? WHERE operation_id=? AND expires_at>=? RETURNING operation_id",
                vec![deadline.into(), id.to_owned().into(), minimum.into()],
            )
        } else {
            (
                "UPDATE host_submission_pins SET expires_at=? WHERE operation_id=? RETURNING operation_id",
                vec![deadline.into(), id.to_owned().into()],
            )
        };
        let rows: Vec<Updated> = self.state.storage().sql().exec(sql, args)?.to_array()?;
        if rows.len() != 1 || rows[0].operation_id != id {
            return Err(corrupt());
        }
        Ok(())
    }

    fn submission_new_seen(
        &self,
        job: &Job,
        phase: &str,
        observations: &[WalkObjectObservation],
    ) -> Result<Vec<[u8; 32]>> {
        #[derive(Deserialize)]
        struct Seen {
            canonical_len: i64,
        }
        let mut newly = Vec::new();
        let mut local = BTreeSet::new();
        for observed in observations {
            if !local.insert(observed.id()) {
                continue;
            }
            let old:Vec<Seen>=self.state.storage().sql().exec(
                "SELECT canonical_len FROM host_submission_seen WHERE operation_id=? AND phase=? AND object_id=?",
                vec![job.operation_id.clone().into(),phase.into(),hex::encode(observed.id()).into()],
            )?.to_array()?;
            if old.len() > 1 {
                return Err(corrupt());
            }
            if let Some(old) = old.first() {
                if old.canonical_len
                    != i64::try_from(observed.canonical_len()).map_err(|_| corrupt())?
                {
                    return Err(corrupt());
                }
            } else {
                newly.push(observed.id());
            }
        }
        Ok(newly)
    }

    fn submission_acquire_attempt_lease(
        &self,
        identity: &Identity,
        job: &Job,
    ) -> Result<AttemptLeaseAcquire> {
        let lifetime = self
            .submission_lifetime(&job.operation_id)?
            .ok_or_else(corrupt)?;
        let mut id = [0u8; 32];
        getrandom::fill(&mut id).map_err(|_| corrupt())?;
        let acquired = self.snapshot_acquire_read_lease(
            identity,
            &lifetime.exact_ref,
            &lifetime.expected_base,
            &job.expected_packmap,
            &hex::encode(id),
            5 * 60 * 1000,
        )?;
        let lease = match acquired {
            SnapshotLeaseAcquire::Acquired(lease) => AttemptLease {
                store: self.clone(),
                lease,
            },
            SnapshotLeaseAcquire::Capacity => return Ok(AttemptLeaseAcquire::Capacity),
            SnapshotLeaseAcquire::Conflict => return Ok(AttemptLeaseAcquire::Conflict),
        };
        let pins:Vec<PinLocator>=self.state.storage().sql().exec(
            "SELECT index_job_id,index_generation,catalog_digest,head,packmap,expires_at FROM host_submission_pins WHERE operation_id=?",
            vec![job.operation_id.clone().into()],
        )?.to_array()?;
        if pins.len() != 1
            || pins[0].index_job_id != lease.lease.job_id
            || pins[0].index_generation != lease.lease.generation
            || pins[0].catalog_digest != lease.lease.catalog_digest
            || !self.snapshot_lease_current(
                identity,
                &lifetime.exact_ref,
                &lifetime.expected_base,
                &job.expected_packmap,
                &lease.lease,
            )?
        {
            return Ok(AttemptLeaseAcquire::Conflict);
        }
        Ok(AttemptLeaseAcquire::Acquired(lease))
    }

    fn submission_context(&self, job: &Job) -> Result<StagedValidationContext> {
        let prefix = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &job.sealed_header,
        )
        .map_err(|_| corrupt())?;
        if prefix.len() > 128 * 1024 || prefix.len() as u64 != job.pack_offset {
            return Err(corrupt());
        }
        let HeaderPrefix::Parsed(header) =
            parse_mkwu_header_prefix(&prefix, &portable(), &staged()).map_err(|_| corrupt())?
        else {
            return Err(corrupt());
        };
        if hex::encode(header.pack_hash()) != job.pack_key
            || header.pack_offset() as u64 != job.pack_offset
            || header.pack_len() as u64 != job.pack_len
        {
            return Err(corrupt());
        }
        let mut inspection = default_staged_inspection_limits();
        inspection.max_object_bytes = inspection.max_object_bytes.min(portable().max_object_bytes);
        inspection.max_tree_bytes = inspection
            .max_tree_bytes
            .min(portable().max_tree_object_bytes);
        inspection.max_tree_entries = inspection.max_tree_entries.min(portable().max_tree_entries);
        inspection.max_manifest_chunks = inspection.max_manifest_chunks.min(32_768);
        StagedValidationContext::new(header, portable(), staged(), inspection)
            .map_err(|_| corrupt())
    }

    fn submission_new_required(
        &self,
        job: &Job,
        observations: &[StagedRequiredObservation],
    ) -> Result<Option<Vec<[u8; 32]>>> {
        #[derive(Deserialize)]
        struct Length {
            canonical_len: i64,
        }
        let mut local = std::collections::BTreeMap::new();
        let mut new = Vec::new();
        for observed in observations {
            let id = hex::encode(observed.id());
            let len = i64::try_from(observed.canonical_len()).map_err(|_| corrupt())?;
            if local
                .insert(id.clone(), len)
                .is_some_and(|prior| prior != len)
            {
                return Err(corrupt());
            }
            let supplied:Vec<Length>=self.state.storage().sql().exec(
                "SELECT canonical_len FROM host_submission_supplied WHERE operation_id=? AND object_id=?",
                vec![job.operation_id.clone().into(),id.clone().into()],
            )?.to_array()?;
            if supplied.len() != 1 || supplied[0].canonical_len != len {
                return Ok(None);
            }
            let prior:Vec<Length>=self.state.storage().sql().exec(
                "SELECT canonical_len FROM host_submission_required WHERE operation_id=? AND object_id=?",
                vec![job.operation_id.clone().into(),id.into()],
            )?.to_array()?;
            if prior.len() > 1 || prior.first().is_some_and(|v| v.canonical_len != len) {
                return Err(corrupt());
            }
            if prior.is_empty() && !new.contains(&observed.id()) {
                new.push(observed.id());
            }
        }
        Ok(Some(new))
    }

    fn submission_insert_required(
        &self,
        job: &Job,
        observations: &[StagedRequiredObservation],
        new: &[[u8; 32]],
    ) -> Result<()> {
        for id in new {
            let len = observations
                .iter()
                .find(|v| v.id() == *id)
                .ok_or_else(corrupt)?
                .canonical_len();
            self.state.storage().sql().exec(
                "INSERT INTO host_submission_required(operation_id,object_id,canonical_len) VALUES(?,?,?)",
                vec![job.operation_id.clone().into(),hex::encode(id).into(),i64::try_from(len).map_err(|_|corrupt())?.into()],
            )?;
        }
        Ok(())
    }

    /// None means an authenticated candidate edge has no supplied or certified
    /// base origin. Base-side absence remains a storage-integrity error.
    fn submission_source(
        &self,
        lifetime: &Lifetime,
        job: &Job,
        id: &str,
        candidate: bool,
    ) -> Result<Option<SourceLocator>> {
        if candidate {
            let rows:Vec<SuppliedLocator>=self.state.storage().sql().exec(
                "SELECT canonical_len,payload_offset,payload_len FROM host_submission_supplied WHERE operation_id=? AND object_id=?",
                vec![job.operation_id.clone().into(),id.into()],
            )?.to_array()?;
            if rows.len() > 1 {
                return Err(corrupt());
            }
            if let Some(v) = rows.first() {
                let (canonical_len, offset, len) = (
                    u64::try_from(v.canonical_len).map_err(|_| corrupt())?,
                    u64::try_from(v.payload_offset).map_err(|_| corrupt())?,
                    u64::try_from(v.payload_len).map_err(|_| corrupt())?,
                );
                if canonical_len == 0
                    || canonical_len != len
                    || len > 2 * 1024 * 1024
                    || offset
                        .checked_add(len)
                        .is_none_or(|end| end > lifetime.update_len)
                    || job.carrier_etag.is_empty()
                    || !crate::snapshot_wire::id(id)
                {
                    return Err(corrupt());
                }
                return Ok(Some(SourceLocator::Supplied {
                    id: id.into(),
                    canonical_len,
                    offset,
                    len,
                }));
            }
        }
        let rows:Vec<PinLocator>=self.state.storage().sql().exec(
            "SELECT index_job_id,index_generation,catalog_digest,head,packmap,expires_at FROM host_submission_pins WHERE operation_id=?",
            vec![job.operation_id.clone().into()],
        )?.to_array()?;
        if rows.len() != 1 {
            return Err(corrupt());
        }
        let pin = &rows[0];
        if pin.expires_at<job.idle_deadline || pin.head!=lifetime.expected_base || pin.packmap!=job.expected_packmap
            || self.snapshot_exists(
                "SELECT 1 AS found FROM host_snapshot_indexes WHERE job_id=? AND generation=? AND catalog_digest=? AND exact_ref=? AND head=? AND packmap=? LIMIT 1",
                vec![pin.index_job_id.clone().into(),pin.index_generation.clone().into(),pin.catalog_digest.clone().into(),lifetime.exact_ref.clone().into(),pin.head.clone().into(),pin.packmap.clone().into()],
            )? == false
        { return Err(corrupt()); }
        if candidate && !self.snapshot_exists(
            "SELECT 1 AS found FROM host_snapshot_catalog WHERE job_id=? AND object_id=? LIMIT 1",
            vec![pin.index_job_id.clone().into(),id.into()],
        )? {return Ok(None);}
        Ok(Some(SourceLocator::Base(
            self.snapshot_index_locator(&pin.index_job_id, id)?,
        )))
    }

    async fn submission_read_source(
        &self,
        identity: &Identity,
        proof: &Proof,
        original: &Job,
        locator: &SourceLocator,
        deadline: i64,
        fit: bool,
    ) -> Result<SourceRead> {
        if !self.submission_charge(identity, proof, original, locator.len(), 1, fit)? {
            return Ok(SourceRead::Refused(self.submission_refuse(
                identity,
                proof,
                original,
                "resource_exhausted",
            )?));
        }
        deadline_ok(deadline, proof)?;
        match locator {
            SourceLocator::Base(v) => Ok(SourceRead::Bytes(
                self.snapshot_read_range(v, deadline).await?,
            )),
            SourceLocator::Supplied {
                id,
                canonical_len,
                offset,
                len,
            } => {
                let bucket = self.env.bucket(STORAGE_BUCKET)?;
                let object = bucket
                    .get(format!("quarantine/submissions/{}", original.carrier_key))
                    .only_if(Conditional {
                        etag_matches: Some(original.carrier_etag.clone()),
                        ..Default::default()
                    })
                    .range(worker::Range::OffsetWithLength {
                        offset: *offset,
                        length: *len,
                    })
                    .execute()
                    .await?
                    .ok_or_else(corrupt)?;
                deadline_ok(deadline, proof)?;
                let lifetime = self
                    .submission_lifetime(&original.operation_id)?
                    .ok_or_else(corrupt)?;
                if object.size() != lifetime.update_len || object.etag() != original.carrier_etag {
                    return Err(corrupt());
                }
                let mut stream = object.body().ok_or_else(corrupt)?.stream()?;
                let mut bytes = Vec::new();
                let cap = usize::try_from(*len).map_err(|_| corrupt())?;
                while let Some(part) = stream.next().await {
                    deadline_ok(deadline, proof)?;
                    let part = part?;
                    if part.len() > cap - bytes.len() {
                        return Err(corrupt());
                    }
                    bytes.extend_from_slice(&part);
                }
                if bytes.len() != cap || *canonical_len != *len || !crate::snapshot_wire::id(id) {
                    return Err(corrupt());
                }
                Ok(SourceRead::Bytes(bytes))
            }
        }
    }

    /// Current effects fence. The historical Get path deliberately does not
    /// call this: an expired grant cannot act, but its subject can recover the
    /// saved opaque result under a new valid request signature.
    pub(super) fn submission_live_authority(
        &self,
        identity: &Identity,
        proof: &Proof,
        lifetime: &Lifetime,
        job: &Job,
    ) -> Result<bool> {
        if now() > proof.expires_at
            || lifetime.subject != proof.author
            || lifetime.operation_id != job.operation_id
            || lifetime.submission_id != job.submission_id
            || lifetime.generation != job.generation
            || lifetime.revision != job.revision
        {
            return Ok(false);
        }
        let request =
            submission_wire::decode_begin(job.begin_body.as_bytes()).map_err(|_| corrupt())?;
        let grant = match self.submission_grant(identity, proof, &request)? {
            super::grant_store::SubmissionGrant::Allowed {
                policy_generation, ..
            } => policy_generation,
            _ => return Ok(false),
        };
        if grant != job.policy_generation
            || self.read_ref(&lifetime.exact_ref)?.as_deref() != Some(&lifetime.expected_base)
        {
            return Ok(false);
        }
        let Some(branch) = lifetime.exact_ref.strip_prefix("refs/heads/") else {
            return Ok(false);
        };
        if self
            .read_ref(&format!("refs/mkit/packmap/{branch}"))?
            .as_deref()
            != Some(&job.expected_packmap)
        {
            return Ok(false);
        }
        #[derive(Deserialize)]
        struct Pin {
            index_job_id: String,
            index_generation: String,
            catalog_digest: String,
            head: String,
            packmap: String,
        }
        let rows:Vec<Pin>=self.state.storage().sql().exec(
            "SELECT index_job_id,index_generation,catalog_digest,head,packmap FROM host_submission_pins WHERE operation_id=?",
            vec![lifetime.operation_id.clone().into()],
        )?.to_array()?;
        if rows.len() != 1 {
            return Err(corrupt());
        }
        let pin = &rows[0];
        if pin.head != lifetime.expected_base || pin.packmap != job.expected_packmap {
            return Ok(false);
        }
        let current=self.snapshot_exists(
            "SELECT 1 AS found FROM host_snapshot_certificates WHERE exact_ref=? AND job_id=? AND generation=? AND catalog_digest=? AND head=? AND packmap=? AND profile_version=1 AND validator_version=1 AND retired=0 LIMIT 1",
            vec![lifetime.exact_ref.clone().into(),pin.index_job_id.clone().into(),pin.index_generation.clone().into(),pin.catalog_digest.clone().into(),pin.head.clone().into(),pin.packmap.clone().into()],
        )?;
        Ok(current)
    }

    pub(super) fn submission_fence(
        &self,
        identity: &Identity,
        proof: &Proof,
        lifetime: &Lifetime,
        job: &Job,
    ) -> Result<bool> {
        if !["awaiting_upload", "validating"].contains(&job.state.as_str())
            || job.idle_deadline <= now()
            || !self.submission_live_authority(identity, proof, lifetime, job)?
        {
            return Ok(false);
        }
        #[derive(Deserialize)]
        struct Deadline {
            expires_at: i64,
        }
        let rows: Vec<Deadline> = self
            .state
            .storage()
            .sql()
            .exec(
                "SELECT expires_at FROM host_submission_pins WHERE operation_id=?",
                vec![job.operation_id.clone().into()],
            )?
            .to_array()?;
        Ok(rows.len() == 1 && rows[0].expires_at >= job.idle_deadline)
    }

    fn submission_attempt_current(
        &self,
        identity: &Identity,
        proof: &Proof,
        original: &Job,
    ) -> Result<(Lifetime, Job)> {
        let lifetime = self
            .submission_lifetime(&original.operation_id)?
            .ok_or_else(corrupt)?;
        let job = self
            .submission_job(&original.operation_id)?
            .ok_or_else(corrupt)?;
        if job.attempt_seq != original.attempt_seq
            || job.attempt_scope != proof.scope
            || job.attempt_fingerprint != proof.fingerprint
            || job.attempt_deadline <= now()
            || !self.submission_fence(identity, proof, &lifetime, &job)?
        {
            return Err(Error::RustError("stale submission attempt".into()));
        }
        Ok((lifetime, job))
    }

    /// Classify a post-await refusal from persisted fences, not from an
    /// error string. Corrupt/unreadable storage remains unavailable.
    fn submission_known_stale(
        &self,
        identity: &Identity,
        proof: &Proof,
        original: &Job,
    ) -> Result<bool> {
        let Some(lifetime) = self.submission_lifetime(&original.operation_id)? else {
            return Ok(true);
        };
        let Some(job) = self.submission_job(&original.operation_id)? else {
            return Ok(true);
        };
        Ok(job.attempt_seq != original.attempt_seq
            || job.attempt_scope != proof.scope
            || job.attempt_fingerprint != proof.fingerprint
            || !self.submission_fence(identity, proof, &lifetime, &job)?)
    }

    fn submission_charge(
        &self,
        identity: &Identity,
        proof: &Proof,
        original: &Job,
        bytes: u64,
        operations: u64,
        fit: bool,
    ) -> Result<bool> {
        let owned = self.clone();
        let identity = identity.clone();
        let proof = proof.clone();
        let original = original.clone();
        self.ledger.transaction(move || {
            let (_lifetime, mut current) =
                owned.submission_attempt_current(&identity, &proof, &original)?;
            if !current.can_charge(bytes, operations, fit)? {
                return Ok(false);
            }
            current.charge(bytes, operations, fit)?;
            owned.submission_save_job(&current, &_lifetime.exact_ref)?;
            Ok(true)
        })
    }

    /// Private Worker-to-DO handoff: u32-LE context JSON length, exactly that
    /// many bounded bytes, then the original signed MKSU body. No base64 copy.
    pub(super) async fn managed_submission_upload(&self, req: &mut Request) -> Result<Response> {
        if req.method() != Method::Post {
            return error(INVALID, 405)?.response();
        }
        let Some(body) = bounded_body(req, 4 + 4096 + submission_wire::MAX_UPLOAD_BODY).await?
        else {
            return error(EXHAUSTED, 413)?.response();
        };
        if body.len() < 4 {
            return error(INVALID, 400)?.response();
        }
        let context_len = u32::from_le_bytes(body[..4].try_into().map_err(|_| corrupt())?) as usize;
        if context_len > 4096 || body.len() < 4 + context_len {
            return error(INVALID, 400)?.response();
        }
        let context: UploadContext = match serde_json::from_slice(&body[4..4 + context_len]) {
            Ok(v) => v,
            Err(_) => return error(INVALID, 400)?.response(),
        };
        if self.submission_identity().as_ref().ok() != Some(&context.identity)
            || now() > context.proof.expires_at
        {
            return unavailable()?.response();
        }
        let upload = match submission_wire::decode_mksu(&body[4 + context_len..]) {
            Ok(v) => v,
            Err(submission_wire::SubmissionWireError::ResourceExhausted) => {
                return error(EXHAUSTED, 413)?.response();
            }
            Err(_) => return error(INVALID, 400)?.response(),
        };
        let operation_id = hex::encode(upload.operation_id);
        let submission_id = hex::encode(upload.submission_id);
        let carrier = upload.carrier.to_vec();
        let digest = hex::encode(hash(&carrier));
        let declared_len = upload.declared_len;
        let generation = upload.generation.to_string();
        drop(body);
        let proof = context.proof.clone();
        let identity = context.identity.clone();
        let busy = self.snapshot_busy.clone();
        let acquired = std::rc::Rc::new(std::cell::Cell::new(false));
        let acquired_in_tx = acquired.clone();
        let owned = self.clone();
        let claim = self.ledger.transaction(move || {
            // Authenticated malformed/unbound data never enters the replay
            // ledger, alters an operation, or claims the heavy permit.
            if owned.submission_meta(&context.identity)?.is_none() {
                return Ok(Claim::Reply(error(DENIED, 403)?));
            }
            let Some(lifetime) = owned.submission_lifetime(&operation_id)? else {
                return Ok(Claim::Reply(error(DENIED, 403)?));
            };
            if lifetime.subject != context.proof.author {
                return Ok(Claim::Reply(error(DENIED, 403)?));
            }
            let Some(job) = owned.submission_job(&operation_id)? else {
                return Err(corrupt());
            };
            if lifetime.submission_id != submission_id
                || lifetime.generation != generation
                || lifetime.update_len != declared_len
                || lifetime.update_digest != digest
            {
                return Ok(Claim::Reply(error(CONFLICT, 409)?));
            }
            if !owned.submission_live_authority(
                &context.identity,
                &context.proof,
                &lifetime,
                &job,
            )? {
                return Ok(Claim::Reply(error(CONFLICT, 409)?));
            }
            let prior = owned.ledger.reserve(&context.proof, now(), || {
                if job.state == "awaiting_upload"
                    && !owned.submission_fence(
                        &context.identity,
                        &context.proof,
                        &lifetime,
                        &job,
                    )?
                {
                    return Ok(Some(error(CONFLICT, 409)?));
                }
                if job.state == "awaiting_upload" && busy.get() {
                    return Ok(Some(error(EXHAUSTED, 429)?));
                }
                if job.state != "awaiting_upload" && job.state != "validating" {
                    return Ok(Some(error(CONFLICT, 409)?));
                }
                Ok(None)
            })?;
            if let Some(Some(reply)) = prior {
                return Ok(Claim::Reply(reply));
            }
            if let Some(None) = prior {
                return Ok(Claim::Pending);
            }
            if job.state == "validating" {
                let reply = Reply::json(&status(&lifetime, Some(&job)))?;
                owned.ledger.finish(&context.proof, &reply)?;
                return Ok(Claim::Reply(reply));
            }
            let timestamp = now();
            if job.attempt_deadline > timestamp {
                let reply = error(EXHAUSTED, 429)?;
                owned.ledger.finish(&context.proof, &reply)?;
                return Ok(Claim::Reply(reply));
            }
            if job.attempts >= MAX_ATTEMPTS
                || job.reserved_io_bytes >= MAX_JOB_IO
                || job.r2_operations >= MAX_JOB_OPS
            {
                let reply = owned.submission_terminalize(
                    &context.identity,
                    &context.proof,
                    lifetime,
                    job,
                    "resource_exhausted",
                )?;
                return Ok(Claim::Reply(reply));
            }
            let mut preview = job.clone();
            preview.claim(
                &context.proof.scope,
                &context.proof.fingerprint,
                timestamp,
                false,
            )?;
            if !preview.can_charge(declared_len, 1, false)? {
                let reply = owned.submission_terminalize(
                    &context.identity,
                    &context.proof,
                    lifetime,
                    job,
                    "resource_exhausted",
                )?;
                return Ok(Claim::Reply(reply));
            }
            busy.set(true);
            acquired_in_tx.set(true);
            preview.charge(declared_len, 1, false)?;
            owned.submission_save_job(&preview, &lifetime.exact_ref)?;
            Ok(Claim::New {
                job: Box::new(preview),
                lifetime: Box::new(lifetime),
            })
        });
        let claim = match claim {
            Ok(v) => v,
            Err(e) => {
                if acquired.get() {
                    self.snapshot_busy.set(false);
                }
                return if e.to_string().contains("nonce reused") {
                    error(CONFLICT, 409)?.response()
                } else {
                    unavailable()?.response()
                };
            }
        };
        let Claim::New { job, lifetime } = claim else {
            return match claim {
                Claim::Reply(reply) => reply.response(),
                Claim::Pending => error("{\"code\":\"in_progress\"}", 202)?.response(),
                Claim::New { .. } => unreachable!(),
            };
        };
        let _permit = ClaimedPermit(self.snapshot_busy.clone());
        // The long-lived submission pin retains storage across attempts, but
        // cannot act as a current structural capability. Acquire a fresh C1
        // read lease for this effects attempt, including fit and source-only
        // graph work. The lease is released even on a failed/timeout step.
        let lease = self.submission_acquire_attempt_lease(&identity, &job);
        let _lease = match lease {
            Ok(AttemptLeaseAcquire::Acquired(v)) => v,
            other => {
                let (body, code) = match other {
                    Ok(AttemptLeaseAcquire::Capacity) => (EXHAUSTED, 429),
                    Ok(AttemptLeaseAcquire::Conflict) => (CONFLICT, 409),
                    Err(_) => (UNAVAILABLE, 503),
                    _ => unreachable!(),
                };
                let owned = self.clone();
                let identity = identity.clone();
                let proof = proof.clone();
                let failed = (*job).clone();
                let _ = self.ledger.transaction(move || {
                    let Ok((lifetime, mut current)) =
                        owned.submission_attempt_current(&identity, &proof, &failed)
                    else {
                        return Ok(());
                    };
                    current.finish_attempt();
                    owned.submission_save_job(&current, &lifetime.exact_ref)?;
                    owned.ledger.finish(&proof, &error(body, code)?)?;
                    Ok(())
                });
                return error(body, code)?.response();
            }
        };
        let deadline = now().checked_add(20_000).ok_or_else(corrupt)?;
        let result = self
            .upload_attempt(&identity, &proof, &job, &lifetime, &carrier, deadline)
            .await;
        match result {
            Ok(reply) => reply.response(),
            Err(error_value) => {
                #[cfg(feature = "test-faults")]
                worker::console_log!("submission upload attempt failure: {}", error_value);
                #[cfg(not(feature = "test-faults"))]
                let _ = &error_value;
                if self
                    .submission_known_stale(&identity, &proof, &job)
                    .unwrap_or(false)
                {
                    return error(CONFLICT, 409)?.response();
                }
                let owned = self.clone();
                let identity = identity.clone();
                let proof = proof.clone();
                let job = (*job).clone();
                let _ = self.ledger.transaction(move || {
                    let Ok((lifetime, mut current)) =
                        owned.submission_attempt_current(&identity, &proof, &job)
                    else {
                        return Ok(());
                    };
                    current.finish_attempt();
                    owned.submission_save_job(&current, &lifetime.exact_ref)?;
                    owned.ledger.finish(&proof, &error(UNAVAILABLE, 503)?)?;
                    Ok(())
                });
                unavailable()?.response()
            }
        }
    }

    async fn upload_attempt(
        &self,
        identity: &Identity,
        proof: &Proof,
        original: &Job,
        lifetime: &Lifetime,
        carrier: &[u8],
        deadline: i64,
    ) -> Result<Reply> {
        deadline_ok(deadline, proof)?;
        let expected_digest = from_hex(&lifetime.update_digest).map_err(|_| corrupt())?;
        let expected_base = from_hex(&lifetime.expected_base).map_err(|_| corrupt())?;
        let checked = CheckedMkwu::open(
            carrier,
            lifetime.update_len,
            expected_digest,
            expected_base,
            portable(),
            staged(),
        );
        let checked = match checked {
            Ok(v) => v,
            Err(e) => {
                return self.refuse_staged_error(
                    identity,
                    proof,
                    original,
                    e,
                    "unsupported_profile",
                );
            }
        };
        // This caller-buffer check is preflight only. Seal facts come from
        // a separately charged exact quarantine readback in Continue.
        drop(checked);
        #[cfg(feature = "test-faults")]
        if let Ok(delay) = self.env.var("SUBMISSION_TEST_UPLOAD_PRE_PUT_MS") {
            let millis = delay.to_string().parse::<u64>().unwrap_or(0).min(5_000);
            if millis > 0 {
                worker::Delay::from(std::time::Duration::from_millis(millis)).await;
            }
        }
        #[cfg(feature = "test-faults")]
        if self
            .env
            .var("SUBMISSION_TEST_UPLOAD_TRANSIENT")
            .ok()
            .is_some_and(|v| v.to_string() == "1")
        {
            return Err(Error::RustError(
                "test-only transient upload storage fault".into(),
            ));
        }
        deadline_ok(deadline, proof)?;
        let key = format!("quarantine/submissions/{}", original.carrier_key);
        let bucket = self.env.bucket(STORAGE_BUCKET)?;
        let put = bucket
            .put(key.clone(), carrier.to_vec())
            .only_if(Conditional {
                etag_does_not_match: Some("*".into()),
                ..Default::default()
            })
            .execute()
            .await?;
        #[cfg(feature = "test-faults")]
        if put.is_some() {
            self.state.storage().sql().exec(
                "CREATE TABLE IF NOT EXISTS submission_test_puts(operation_id TEXT PRIMARY KEY)",
                None,
            )?;
            self.state.storage().sql().exec(
                "INSERT OR IGNORE INTO submission_test_puts(operation_id) VALUES(?)",
                vec![original.operation_id.clone().into()],
            )?;
        }
        #[cfg(feature = "test-faults")]
        if let Ok(delay) = self.env.var("SUBMISSION_TEST_UPLOAD_POST_PUT_MS") {
            let millis = delay.to_string().parse::<u64>().unwrap_or(0).min(5_000);
            if millis > 0 {
                worker::Delay::from(std::time::Duration::from_millis(millis)).await;
            }
        }
        deadline_ok(deadline, proof)?;
        let etag = if let Some(object) = put {
            if object.size() != lifetime.update_len {
                return Err(corrupt());
            }
            object.etag()
        } else {
            if !self.submission_charge(identity, proof, original, 0, 1, false)? {
                return self.submission_refuse(identity, proof, original, "resource_exhausted");
            }
            let object = bucket.head(key.clone()).await?.ok_or_else(corrupt)?;
            deadline_ok(deadline, proof)?;
            if object.size() != lifetime.update_len {
                return Err(corrupt());
            }
            let etag = object.etag();
            if !self.submission_charge(identity, proof, original, lifetime.update_len, 1, false)? {
                return self.submission_refuse(identity, proof, original, "resource_exhausted");
            }
            let returned = bucket
                .get(key)
                .only_if(Conditional {
                    etag_matches: Some(etag.clone()),
                    ..Default::default()
                })
                .execute()
                .await?
                .ok_or_else(corrupt)?;
            deadline_ok(deadline, proof)?;
            if returned.etag() != etag || returned.size() != lifetime.update_len {
                return Err(corrupt());
            }
            let mut stream = returned.body().ok_or_else(corrupt)?.stream()?;
            let mut bytes = Vec::new();
            let cap = usize::try_from(lifetime.update_len).map_err(|_| corrupt())?;
            while let Some(part) = stream.next().await {
                deadline_ok(deadline, proof)?;
                let part = part?;
                if part.len() > cap - bytes.len() {
                    return Err(corrupt());
                }
                bytes.extend_from_slice(&part);
            }
            deadline_ok(deadline, proof)?;
            if bytes.len() != cap || hash(&bytes) != expected_digest {
                return Err(corrupt());
            }
            etag
        };
        let owned = self.clone();
        let identity = identity.clone();
        let proof = proof.clone();
        let original = original.clone();
        self.ledger.transaction(move || {
            let (mut lifetime, mut job) =
                owned.submission_attempt_current(&identity, &proof, &original)?;
            if lifetime.update_digest != hex::encode(expected_digest) {
                return Err(corrupt());
            }
            job.carrier_etag = etag;
            job.state = "validating".into();
            job.phase = "seal".into();
            job.next_revision()?;
            job.idle_deadline = now().checked_add(ACTIVE_IDLE_MS).ok_or_else(corrupt)?;
            owned.submission_set_pin_expiry(
                &lifetime.operation_id,
                job.idle_deadline,
                Some(now()),
            )?;
            job.finish_attempt();
            lifetime.state = job.state.clone();
            lifetime.revision = job.revision.clone();
            owned.submission_save_job(&job, &lifetime.exact_ref)?;
            owned.submission_save_lifetime(&lifetime)?;
            let reply = Reply::json(&status(&lifetime, Some(&job)))?;
            owned.ledger.finish(&proof, &reply)?;
            Ok(reply)
        })
    }

    fn submission_refuse(
        &self,
        identity: &Identity,
        proof: &Proof,
        original: &Job,
        code: &str,
    ) -> Result<Reply> {
        let owned = self.clone();
        let identity = identity.clone();
        let proof = proof.clone();
        let original = original.clone();
        let code = code.to_owned();
        self.ledger.transaction(move || {
            let (lifetime, job) = owned.submission_attempt_current(&identity, &proof, &original)?;
            owned.submission_terminalize(&identity, &proof, lifetime, job, &code)
        })
    }

    /// Call only inside an existing short SQL transaction after live authority
    /// and replay checks. This also handles an exhausted job with no new claim.
    fn submission_terminalize(
        &self,
        identity: &Identity,
        proof: &Proof,
        mut lifetime: Lifetime,
        mut job: Job,
        code: &str,
    ) -> Result<Reply> {
        if ![
            "unsupported_profile",
            "invalid_candidate",
            "resource_exhausted",
        ]
        .contains(&code)
            || !["awaiting_upload", "validating"].contains(&job.state.as_str())
        {
            return Err(corrupt());
        }
        let mut meta = self.submission_meta(identity)?.ok_or_else(corrupt)?;
        meta.active = meta.active.checked_sub(1).ok_or_else(corrupt)?;
        job.state = "refused".into();
        job.phase = "terminal".into();
        job.bulky_deadline = now().checked_add(BULKY_MS).ok_or_else(corrupt)?;
        job.next_revision()?;
        job.finish_attempt();
        lifetime.state = job.state.clone();
        lifetime.revision = job.revision.clone();
        lifetime.terminal_at = now();
        lifetime.terminal_progress = Some(progress(&job));
        lifetime.status = code.into();
        self.submission_set_pin_expiry(&lifetime.operation_id, now(), None)?;
        self.submission_save_meta(&meta)?;
        self.submission_save_job(&job, &lifetime.exact_ref)?;
        self.submission_save_lifetime(&lifetime)?;
        let http = if code == "resource_exhausted" {
            429
        } else {
            422
        };
        let reply = Reply::error(format!("{{\"code\":\"{code}\"}}"), http)?;
        self.ledger.finish(proof, &reply)?;
        Ok(reply)
    }

    async fn submission_read_carrier(
        &self,
        job: &Job,
        proof: &Proof,
        deadline: i64,
    ) -> Result<Vec<u8>> {
        deadline_ok(deadline, proof)?;
        let lifetime = self
            .submission_lifetime(&job.operation_id)?
            .ok_or_else(corrupt)?;
        let expected = from_hex(&lifetime.update_digest).map_err(|_| corrupt())?;
        let bucket = self.env.bucket(STORAGE_BUCKET)?;
        let object = bucket
            .get(format!("quarantine/submissions/{}", job.carrier_key))
            .only_if(Conditional {
                etag_matches: Some(job.carrier_etag.clone()),
                ..Default::default()
            })
            .execute()
            .await?
            .ok_or_else(corrupt)?;
        deadline_ok(deadline, proof)?;
        if object.size() != lifetime.update_len || object.etag() != job.carrier_etag {
            return Err(corrupt());
        }
        let mut stream = object.body().ok_or_else(corrupt)?.stream()?;
        let mut bytes = Vec::new();
        let cap = usize::try_from(lifetime.update_len).map_err(|_| corrupt())?;
        while let Some(part) = stream.next().await {
            deadline_ok(deadline, proof)?;
            let part = part?;
            if part.len() > cap - bytes.len() {
                return Err(corrupt());
            }
            bytes.extend_from_slice(&part);
        }
        deadline_ok(deadline, proof)?;
        if bytes.len() != cap || hash(&bytes) != expected {
            return Err(corrupt());
        }
        Ok(bytes)
    }

    pub(super) async fn submission_continue(
        &self,
        wire: SubmissionWire,
        _policy_generation: String,
    ) -> Result<Response> {
        let request = match submission_wire::decode_continue(wire.body.as_bytes()) {
            Ok(v) => v,
            Err(submission_wire::SubmissionWireError::ResourceExhausted) => {
                return error(EXHAUSTED, 429)?.response();
            }
            Err(_) => return error(INVALID, 400)?.response(),
        };
        let proof = wire.proof.clone();
        let identity = wire.identity.clone();
        let busy = self.snapshot_busy.clone();
        let acquired = std::rc::Rc::new(std::cell::Cell::new(false));
        let acquired_in_tx = acquired.clone();
        let owned = self.clone();
        let claim = self.ledger.transaction(move || {
            let Some(_meta) = owned.submission_meta(&wire.identity)? else {
                return Ok(ContinueClaim::Reply(error(DENIED, 403)?));
            };
            let Some(lifetime) = owned.submission_lifetime(&request.operation_id)? else {
                return Ok(ContinueClaim::Reply(error(DENIED, 403)?));
            };
            if lifetime.subject != wire.proof.author {
                return Ok(ContinueClaim::Reply(error(DENIED, 403)?));
            }
            let Some(job) = owned.submission_job(&request.operation_id)? else {
                return Ok(ContinueClaim::Reply(error(CONFLICT, 409)?));
            };
            if !owned.submission_live_authority(&wire.identity, &wire.proof, &lifetime, &job)? {
                return Ok(ContinueClaim::Reply(error(CONFLICT, 409)?));
            }
            let prior = owned.ledger.reserve(&wire.proof, now(), || {
                if lifetime.submission_id != request.submission_id
                    || lifetime.generation != request.submission_generation
                    || lifetime.revision != request.expected_revision
                    || !owned.submission_fence(&wire.identity, &wire.proof, &lifetime, &job)?
                {
                    return Ok(Some(error(CONFLICT, 409)?));
                }
                if busy.get() {
                    return Ok(Some(error(EXHAUSTED, 429)?));
                }
                Ok(None)
            })?;
            if let Some(Some(reply)) = prior {
                return Ok(ContinueClaim::Reply(reply));
            }
            if let Some(None) = prior {
                return Ok(ContinueClaim::Pending);
            }
            let timestamp = now();
            if job.attempt_deadline > timestamp {
                let reply = error(EXHAUSTED, 429)?;
                owned.ledger.finish(&wire.proof, &reply)?;
                return Ok(ContinueClaim::Reply(reply));
            }
            if job.attempts >= MAX_ATTEMPTS
                || job.reserved_io_bytes >= MAX_JOB_IO
                || job.r2_operations >= MAX_JOB_OPS
                || (job.phase == "fit" && job.fit_attempts >= 8)
            {
                let reply = owned.submission_terminalize(
                    &wire.identity,
                    &wire.proof,
                    lifetime,
                    job,
                    "resource_exhausted",
                )?;
                return Ok(ContinueClaim::Reply(reply));
            }
            let mut preview = job.clone();
            let fit = preview.phase == "fit";
            preview.claim(&wire.proof.scope, &wire.proof.fingerprint, timestamp, fit)?;
            if (preview.phase == "inventory" || preview.phase == "seal")
                && !preview.can_charge(lifetime.update_len, 1, false)?
            {
                let reply = owned.submission_terminalize(
                    &wire.identity,
                    &wire.proof,
                    lifetime,
                    job,
                    "resource_exhausted",
                )?;
                return Ok(ContinueClaim::Reply(reply));
            }
            busy.set(true);
            acquired_in_tx.set(true);
            if preview.phase == "inventory" || preview.phase == "seal" {
                preview.charge(lifetime.update_len, 1, false)?;
            }
            owned.submission_save_job(&preview, &lifetime.exact_ref)?;
            Ok(ContinueClaim::New(Box::new(preview)))
        });
        let claim = match claim {
            Ok(v) => v,
            Err(e) => {
                if acquired.get() {
                    self.snapshot_busy.set(false);
                }
                return if e.to_string().contains("nonce reused") {
                    error(CONFLICT, 409)?.response()
                } else {
                    unavailable()?.response()
                };
            }
        };
        let ContinueClaim::New(job) = claim else {
            return match claim {
                ContinueClaim::Reply(reply) => reply.response(),
                ContinueClaim::Pending => error("{\"code\":\"in_progress\"}", 202)?.response(),
                ContinueClaim::New(_) => unreachable!(),
            };
        };
        let _permit = ClaimedPermit(self.snapshot_busy.clone());
        let deadline = now().checked_add(20_000).ok_or_else(corrupt)?;
        let _lease = match self.submission_acquire_attempt_lease(&identity, &job) {
            Ok(AttemptLeaseAcquire::Acquired(lease)) => lease,
            other => {
                let (body, code) = match other {
                    Ok(AttemptLeaseAcquire::Capacity) => (EXHAUSTED, 429),
                    Ok(AttemptLeaseAcquire::Conflict) => (CONFLICT, 409),
                    Err(_) => (UNAVAILABLE, 503),
                    _ => unreachable!(),
                };
                let owned = self.clone();
                let identity = identity.clone();
                let proof = proof.clone();
                let failed = (*job).clone();
                let _ = self.ledger.transaction(move || {
                    let Ok((lifetime, mut current)) =
                        owned.submission_attempt_current(&identity, &proof, &failed)
                    else {
                        return Ok(());
                    };
                    current.finish_attempt();
                    owned.submission_save_job(&current, &lifetime.exact_ref)?;
                    owned.ledger.finish(&proof, &error(body, code)?)?;
                    Ok(())
                });
                return error(body, code)?.response();
            }
        };
        let result = match job.phase.as_str() {
            "seal" => {
                self.submission_seal_step(&identity, &proof, &job, deadline)
                    .await
            }
            "inventory" => {
                self.submission_inventory_step(&identity, &proof, &job, deadline)
                    .await
            }
            "base_walk" => {
                self.submission_walk_step(&identity, &proof, &job, deadline, false)
                    .await
            }
            "diff_init" => {
                self.submission_diff_init(&identity, &proof, &job, deadline)
                    .await
            }
            "diff_pairs" => {
                self.submission_diff_pair_step(&identity, &proof, &job, deadline)
                    .await
            }
            "diff_files" => {
                self.submission_diff_file_step(&identity, &proof, &job, deadline)
                    .await
            }
            "candidate_walk" => {
                self.submission_walk_step(&identity, &proof, &job, deadline, true)
                    .await
            }
            "audit" => self.submission_audit_step(&identity, &proof, &job, deadline),
            "fit" => {
                self.submission_fit_step(&identity, &proof, &job, deadline)
                    .await
            }
            _ => unavailable(),
        };
        match result {
            Ok(reply) => reply.response(),
            Err(e) => {
                #[cfg(feature = "test-faults")]
                worker::console_log!("submission continue attempt failure: {}", e);
                #[cfg(not(feature = "test-faults"))]
                let _ = &e;
                if self
                    .submission_known_stale(&identity, &proof, &job)
                    .unwrap_or(false)
                {
                    return error(CONFLICT, 409)?.response();
                }
                let (body, code) = (UNAVAILABLE, 503);
                let owned = self.clone();
                let identity = identity.clone();
                let proof = proof.clone();
                let job = (*job).clone();
                let _ = self.ledger.transaction(move || {
                    let Ok((lifetime, mut current)) =
                        owned.submission_attempt_current(&identity, &proof, &job)
                    else {
                        return Ok(());
                    };
                    current.finish_attempt();
                    owned.submission_save_job(&current, &lifetime.exact_ref)?;
                    owned.ledger.finish(&proof, &error(body, code)?)?;
                    Ok(())
                });
                error(body, code)?.response()
            }
        }
    }
}

mod graph;
