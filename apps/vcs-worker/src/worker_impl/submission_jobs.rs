// SPDX-License-Identifier: MIT OR Apache-2.0
//! Subject admission and bounded historical status for hosted submissions.

use super::{
    grant_store::SubmissionGrant,
    refstore::RefStore,
    submission_store::{ACTIVE_IDLE_MS, Job, Lifetime, Usage, corrupt},
};
use crate::submission_response::{Progress, SubmissionReply};
use crate::{access_policy::Identity, submission_wire};
use mkit_worker_common::replay::{Proof, Reply};
use serde::{Deserialize, Serialize};
use worker::{Date, Method, Request, Response, Result};

const INVALID: &str = "{\"code\":\"invalid_argument\"}";
const DENIED: &str = "{\"code\":\"permission_denied\"}";
const CONFLICT: &str = "{\"code\":\"conflict\"}";
const EXHAUSTED: &str = "{\"code\":\"resource_exhausted\"}";
const UNAVAILABLE: &str = "{\"code\":\"unavailable\"}";

pub(super) fn now() -> i64 {
    Date::now().as_millis() as i64
}
pub(super) fn error(body: &'static str, status: u16) -> Result<Reply> {
    Reply::error(body, status)
}
pub(super) fn unavailable() -> Result<Reply> {
    error(UNAVAILABLE, 503)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SubmissionWire {
    pub identity: Identity,
    pub proof: Proof,
    pub operation: String,
    pub body: String,
}

pub(super) fn progress(job: &Job) -> Progress {
    Progress {
        inventory_entries: job.inventory_cursor.to_string(),
        base_objects: job.base_objects.to_string(),
        changed_pairs: job.matched_changes.to_string(),
        required_objects: job.required_objects.to_string(),
        candidate_objects: job.candidate_objects.to_string(),
        attempts: job.attempts.to_string(),
        reserved_io_bytes: job.reserved_io_bytes.to_string(),
        r2_operations: job.r2_operations.to_string(),
    }
}
pub(super) fn status(lifetime: &Lifetime, job: Option<&Job>) -> SubmissionReply {
    let progress = job
        .map(progress)
        .or_else(|| lifetime.terminal_progress.clone())
        .unwrap_or_else(Progress::zero);
    SubmissionReply {
        version: 1,
        operation_id: lifetime.operation_id.clone(),
        submission_id: lifetime.submission_id.clone(),
        submission_generation: lifetime.generation.clone(),
        revision: lifetime.revision.clone(),
        state: lifetime.state.clone(),
        progress,
        code: if lifetime.status.is_empty() {
            None
        } else {
            Some(lifetime.status.clone())
        },
    }
}

#[derive(Deserialize)]
struct Subject {
    lifetime: i64,
    carrier_slots: i64,
    carrier_bytes: i64,
}
#[derive(Deserialize)]
struct Certificate {
    job_id: String,
    generation: String,
    head: String,
    packmap: String,
    catalog_digest: String,
    profile_version: i64,
    validator_version: i64,
}

impl RefStore {
    pub(super) async fn managed_submission(&self, req: &mut Request) -> Result<Response> {
        if req.method() != Method::Post {
            return error(INVALID, 405)?.response();
        }
        let wire: SubmissionWire = match req.json().await {
            Ok(v) => v,
            Err(_) => return error(INVALID, 400)?.response(),
        };
        let configured = self.submission_identity();
        if configured.as_ref().ok() != Some(&wire.identity)
            || !mkit_core::write_auth::is_hex(&wire.proof.scope, 32)
            || !mkit_core::write_auth::is_hex(&wire.proof.fingerprint, 32)
        {
            return unavailable()?.response();
        }
        if now() > wire.proof.expires_at {
            return error("{\"code\":\"unauthenticated\"}", 401)?.response();
        }
        let policy = match self.read_policy(&wire.identity) {
            Ok(Some(p)) if p.validate(&wire.identity).is_ok() => p,
            _ => return unavailable()?.response(),
        };
        if self.ensure_table().is_err() {
            return unavailable()?.response();
        }
        if (wire.operation == "cleanup_submissions"
            || wire.operation == "test_submission_marker_create")
            && wire.proof.author != wire.identity.owner
        {
            return error(DENIED, 403)?.response();
        }
        match wire.operation.as_str() {
            "begin_submission" => {
                let owned = self.clone();
                match self
                    .ledger
                    .transaction(move || owned.submission_begin(wire))
                {
                    Ok(reply) => reply.response(),
                    Err(_) => unavailable()?.response(),
                }
            }
            "get_staged_submission" => {
                let owned = self.clone();
                match self.ledger.transaction(move || owned.submission_get(wire)) {
                    Ok(reply) => reply.response(),
                    Err(_) => unavailable()?.response(),
                }
            }
            "continue_submission" => self.submission_continue(wire, policy.generation).await,
            "cleanup_submissions" => self.submission_cleanup(wire).await,
            #[cfg(feature = "test-faults")]
            "test_submission_marker_create" => self.submission_test_marker_create(wire).await,
            _ => unavailable()?.response(),
        }
    }

    pub(super) fn submission_identity(&self) -> Result<Identity> {
        match (
            self.env.var("AUTH_AUDIENCE"),
            self.env.var("AUTH_REPOSITORY"),
            self.env.var("MANAGED_OWNER_PUBLIC_KEY"),
        ) {
            (Ok(a), Ok(r), Ok(o)) => {
                Identity::parse(&a.to_string(), &r.to_string(), &o.to_string())
                    .map_err(|_| corrupt())
            }
            _ => Err(corrupt()),
        }
    }

    fn submission_subject(&self, subject: &str) -> Result<Option<Subject>> {
        let rows:Vec<Subject>=self.state.storage().sql().exec(
            "SELECT lifetime,carrier_slots,carrier_bytes FROM host_submission_subjects WHERE subject=?",
            vec![subject.into()],
        )?.to_array()?;
        if rows.len() > 1 {
            return Err(corrupt());
        }
        Ok(rows.into_iter().next())
    }

    fn submission_certificate(
        &self,
        identity: &Identity,
        exact_ref: &str,
        base: &str,
    ) -> Result<Option<Certificate>> {
        if self.snapshot_meta(identity)?.is_none() {
            return Ok(None);
        }
        let Some(branch) = exact_ref.strip_prefix("refs/heads/") else {
            return Ok(None);
        };
        let Some(packmap) = self.read_ref(&format!("refs/mkit/packmap/{branch}"))? else {
            return Ok(None);
        };
        if self.read_ref(exact_ref)?.as_deref() != Some(base) {
            return Ok(None);
        }
        let rows:Vec<Certificate>=self.state.storage().sql().exec(
            "SELECT job_id,generation,head,packmap,catalog_digest,profile_version,validator_version FROM host_snapshot_certificates WHERE exact_ref=? AND retired=0",
            vec![exact_ref.into()],
        )?.to_array()?;
        if rows.len() > 1 {
            return Err(corrupt());
        }
        let Some(cert) = rows.into_iter().next() else {
            return Ok(None);
        };
        if cert.head != base
            || cert.packmap != packmap
            || cert.profile_version != 1
            || cert.validator_version != 1
        {
            return Ok(None);
        }
        let indexed=self.snapshot_exists(
            "SELECT 1 AS found FROM host_snapshot_indexes WHERE job_id=? AND generation=? AND exact_ref=? AND head=? AND packmap=? AND catalog_digest=? AND retired=0 LIMIT 1",
            vec![cert.job_id.clone().into(),cert.generation.clone().into(),exact_ref.into(),cert.head.clone().into(),cert.packmap.clone().into(),cert.catalog_digest.clone().into()],
        )?;
        Ok(indexed.then_some(cert))
    }

    fn submission_begin(&self, wire: SubmissionWire) -> Result<Reply> {
        let request = match submission_wire::decode_begin(wire.body.as_bytes()) {
            Ok(v) => v,
            Err(submission_wire::SubmissionWireError::ResourceExhausted) => {
                return error(EXHAUSTED, 429);
            }
            Err(_) => return error(INVALID, 400),
        };
        let subject_bytes: [u8; 32] = hex::decode(&wire.proof.author)
            .map_err(|_| corrupt())?
            .try_into()
            .map_err(|_| corrupt())?;
        let binding = hex::encode(
            submission_wire::binding_fingerprint(
                &wire.identity.audience,
                &wire.identity.repository,
                &subject_bytes,
                wire.body.as_bytes(),
            )
            .map_err(|_| corrupt())?,
        );
        let grant = match self.submission_grant(&wire.identity, &wire.proof, &request)? {
            SubmissionGrant::Allowed {
                consumed,
                maximum,
                policy_generation,
            } => (consumed, maximum, policy_generation),
            SubmissionGrant::Denied => return error(DENIED, 403),
            SubmissionGrant::Conflict => return error(CONFLICT, 409),
        };
        // Unlike historical Get, *every* Begin attempt (including exact
        // nonce or operation replay) must still see current structural state.
        if self
            .submission_certificate(
                &wire.identity,
                &request.expected_ref,
                &request.expected_base,
            )?
            .is_none()
        {
            return error(CONFLICT, 409);
        }
        let prior=self.ledger.reserve(&wire.proof,now(),|| {
            let meta=self.submission_meta(&wire.identity)?;
            if let Some(existing)=if meta.is_some(){self.submission_lifetime(&request.operation_id)?}else{None} {
                if existing.binding!=binding || existing.subject!=wire.proof.author {
                    return Ok(Some(error(CONFLICT,409)?));
                }
                return Ok(None);
            }
            let (lifetime,active,terminal,slots,bytes)=meta.as_ref().map_or((0,0,0,0,0),|m|(
                m.lifetime,m.active,m.terminal_slots,m.carrier_slots,m.carrier_bytes,
            ));
            let subject=if meta.is_some(){self.submission_subject(&wire.proof.author)?}else{None};
            let (subject_lifetime,subject_slots,subject_bytes)=subject.as_ref().map_or((0,0,0),|s|(
                s.lifetime,s.carrier_slots,s.carrier_bytes,
            ));
            let declared=crate::access_policy::generation(&request.update_len).map_err(|_|corrupt())?;
            let new_bytes=bytes.checked_add(declared).ok_or_else(corrupt)?;
            let new_subject_bytes=u64::try_from(subject_bytes).ok().and_then(|v|v.checked_add(declared));
            if lifetime>=100_000 || active>=2 || terminal>=128 || slots>=8
                || subject_lifetime>=1024 || subject_slots>=4
                || new_bytes>32*1024*1024 || new_subject_bytes.is_none_or(|n|n>16*1024*1024)
                || grant.0>=grant.1
            { return Ok(Some(error(EXHAUSTED,429)?)); }
            let on_ref=if meta.is_some(){self.snapshot_count(
                "SELECT COUNT(*) AS n FROM host_submission_jobs WHERE state IN ('awaiting_upload','validating') AND exact_ref=?",
                vec![request.expected_ref.clone().into()],
            )?}else{0};
            if on_ref!=0 { return Ok(Some(error(EXHAUSTED,429)?)); }
            if self.submission_certificate(&wire.identity,&request.expected_ref,&request.expected_base)?.is_none() {
                return Ok(Some(error(CONFLICT,409)?));
            }
            Ok(None)
        });
        let prior = match prior {
            Ok(v) => v,
            Err(e) if e.to_string().contains("nonce reused") => return error(CONFLICT, 409),
            Err(e) if e.to_string().contains("expired") => {
                return error("{\"code\":\"unauthenticated\"}", 401);
            }
            Err(_) => return unavailable(),
        };
        if let Some(Some(reply)) = prior {
            return Ok(reply);
        }
        if let Some(None) = prior {
            return error("{\"code\":\"in_progress\"}", 202);
        }
        let existing = if self.submission_meta(&wire.identity)?.is_some() {
            self.submission_lifetime(&request.operation_id)?
        } else {
            None
        };
        if let Some(existing) = existing {
            let job = self.submission_job(&request.operation_id)?;
            let reply = Reply::json(&status(&existing, job.as_ref()))?;
            self.ledger.finish(&wire.proof, &reply)?;
            return Ok(reply);
        }
        let mut meta = match self.submission_meta(&wire.identity)? {
            Some(m) => m,
            None => self.submission_bootstrap(&wire.identity)?,
        };
        let cert = self
            .submission_certificate(
                &wire.identity,
                &request.expected_ref,
                &request.expected_base,
            )?
            .ok_or_else(corrupt)?;
        let generation = meta.allocate_generation()?;
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|_| corrupt())?;
        let submission_id = hex::encode(random);
        let timestamp = now();
        let declared =
            crate::access_policy::generation(&request.update_len).map_err(|_| corrupt())?;
        let carrier_key = hex::encode(mkit_core::hash::hash(
            format!(
                "mkit.host.submission.quarantine.v1\0{}\0{}\0{}",
                generation, request.operation_id, request.update_digest
            )
            .as_bytes(),
        ));
        let lifetime = Lifetime {
            operation_id: request.operation_id.clone(),
            submission_id: submission_id.clone(),
            generation: generation.clone(),
            subject: wire.proof.author.clone(),
            binding,
            workspace_id: request.workspace_id.clone(),
            grant_id: request.grant_id.clone(),
            grant_generation: request.grant_generation.clone(),
            exact_ref: request.expected_ref.clone(),
            expected_base: request.expected_base.clone(),
            update_digest: request.update_digest.clone(),
            update_len: declared,
            state: "awaiting_upload".into(),
            revision: "0".into(),
            created_at: timestamp,
            terminal_at: 0,
            status: String::new(),
            terminal_progress: None,
        };
        let job = Job {
            operation_id: request.operation_id.clone(),
            submission_id,
            generation,
            revision: "0".into(),
            state: "awaiting_upload".into(),
            phase: "upload".into(),
            policy_generation: grant.2,
            expected_packmap: cert.packmap.clone(),
            begin_body: wire.body.clone(),
            sealed_header: String::new(),
            carrier_key,
            carrier_etag: String::new(),
            pack_key: String::new(),
            pack_offset: 0,
            pack_len: 0,
            inventory_cursor: 0,
            inventory_bytes: 0,
            inventory_previous_id: String::new(),
            usage: Usage::default(),
            frontier_next_seq: 0,
            frontier_rows: 0,
            frontier_bytes: 0,
            base_objects: 0,
            candidate_objects: 0,
            supplied_objects: 0,
            required_objects: 0,
            matched_changes: 0,
            audit_phase: String::new(),
            audit_cursor: String::new(),
            audit_rows: 0,
            audit_bytes: 0,
            attempts: 0,
            reserved_io_bytes: 0,
            r2_operations: 0,
            fit_attempts: 0,
            fit_io_bytes: 0,
            fit_operations: 0,
            attempt_seq: "0".into(),
            attempt_scope: String::new(),
            attempt_fingerprint: String::new(),
            attempt_deadline: 0,
            attempt_bytes: 0,
            attempt_ops: 0,
            idle_deadline: timestamp.checked_add(ACTIVE_IDLE_MS).ok_or_else(corrupt)?,
            bulky_deadline: 0,
            cleanup_claim_seq: "0".into(),
            cleanup_claim_deadline: 0,
            cleanup_claim_scope: String::new(),
            cleanup_claim_fingerprint: String::new(),
            cleanup_ops: 0,
            cleanup_bytes: 0,
            cleanup_attempts: 0,
            marker_confirmed: false,
        };
        if !self.submission_charge_grant(&wire.identity, &request, grant.0, grant.1)? {
            return Err(corrupt());
        }
        self.submission_save_lifetime(&lifetime)?;
        self.submission_save_job(&job, &request.expected_ref)?;
        for (ordinal, path) in request.selected_paths.iter().enumerate() {
            let encoded = serde_json::to_string(path).map_err(|_| corrupt())?;
            self.state.storage().sql().exec(
                "INSERT INTO host_submission_selected(operation_id,ordinal,path) VALUES(?,?,?)",
                vec![
                    request.operation_id.clone().into(),
                    (ordinal as i64).into(),
                    encoded.into(),
                ],
            )?;
        }
        self.state.storage().sql().exec(
            "INSERT INTO host_submission_pins(operation_id,index_job_id,index_generation,catalog_digest,head,packmap,expires_at) VALUES(?,?,?,?,?,?,?)",
            vec![request.operation_id.clone().into(),cert.job_id.into(),cert.generation.into(),cert.catalog_digest.into(),cert.head.into(),cert.packmap.into(),
                timestamp.checked_add(ACTIVE_IDLE_MS).ok_or_else(corrupt)?.into()],
        )?;
        meta.lifetime = meta.lifetime.checked_add(1).ok_or_else(corrupt)?;
        meta.active = meta.active.checked_add(1).ok_or_else(corrupt)?;
        meta.terminal_slots = meta.terminal_slots.checked_add(1).ok_or_else(corrupt)?;
        meta.carrier_slots = meta.carrier_slots.checked_add(1).ok_or_else(corrupt)?;
        meta.carrier_bytes = meta
            .carrier_bytes
            .checked_add(declared)
            .ok_or_else(corrupt)?;
        self.submission_save_meta(&meta)?;
        let subject = self.submission_subject(&wire.proof.author)?;
        let (lifetime_count, slots, bytes) = subject.map_or((0, 0, 0), |s| {
            (s.lifetime, s.carrier_slots, s.carrier_bytes)
        });
        let (lifetime_count, slots, bytes) = (
            u64::try_from(lifetime_count).map_err(|_| corrupt())?,
            u64::try_from(slots).map_err(|_| corrupt())?,
            u64::try_from(bytes).map_err(|_| corrupt())?,
        );
        self.state.storage().sql().exec(
            "INSERT INTO host_submission_subjects(subject,lifetime,carrier_slots,carrier_bytes) VALUES(?,?,?,?) ON CONFLICT(subject) DO UPDATE SET lifetime=excluded.lifetime,carrier_slots=excluded.carrier_slots,carrier_bytes=excluded.carrier_bytes",
            vec![wire.proof.author.clone().into(),i64::try_from(lifetime_count+1).map_err(|_|corrupt())?.into(),i64::try_from(slots+1).map_err(|_|corrupt())?.into(),i64::try_from(bytes+declared).map_err(|_|corrupt())?.into()],
        )?;
        let reply = Reply::json(&status(&lifetime, Some(&job)))?;
        self.ledger.finish(&wire.proof, &reply)?;
        Ok(reply)
    }

    fn submission_get(&self, wire: SubmissionWire) -> Result<Reply> {
        let request = match submission_wire::decode_get(wire.body.as_bytes()) {
            Ok(v) => v,
            Err(_) => return error(INVALID, 400),
        };
        if self.submission_meta(&wire.identity)?.is_none() {
            return error(DENIED, 403);
        }
        let Some(lifetime) = self.submission_lifetime(&request.operation_id)? else {
            return error(DENIED, 403);
        };
        if lifetime.subject != wire.proof.author {
            return error(DENIED, 403);
        }
        let job = self.submission_job(&request.operation_id)?;
        Reply::json(&status(&lifetime, job.as_ref()))
    }
}
