// SPDX-License-Identifier: MIT OR Apache-2.0
//! Owner-only, bounded quarantine retirement. The immutable lifetime row and
//! one-key marker survive bulky reclamation; no carrier DELETE is issued.

use futures::StreamExt;
use mkit_core::hash::hash;
use mkit_worker_common::replay::{Proof, Reply};
use serde::Deserialize;
use worker::{Conditional, Error, Response, Result};

use super::{
    refstore::RefStore,
    service::STORAGE_BUCKET,
    submission_jobs::{SubmissionWire, error, now, progress},
    submission_store::{Job, Meta, checked_decimal, corrupt},
};
use crate::{access_policy::Identity, submission_response::CleanupReply, submission_wire};

const DENIED: &str = "{\"code\":\"permission_denied\"}";
const CONFLICT: &str = "{\"code\":\"conflict\"}";
const EXHAUSTED: &str = "{\"code\":\"resource_exhausted\"}";
const INVALID: &str = "{\"code\":\"invalid_argument\"}";
const UNAVAILABLE: &str = "{\"code\":\"unavailable\"}";
const MARKER_DOMAIN: &[u8] = b"mkit.host.submission.retired.v1\0";
const CLEANUP_CLAIM_MS: i64 = 2 * 60 * 1000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Id {
    operation_id: String,
}

enum Claim {
    Reply(Reply),
    Pending,
    Work {
        id: Option<String>,
        seq: String,
        affected: u64,
    },
}
struct Busy(std::rc::Rc<std::cell::Cell<bool>>);
impl Drop for Busy {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

fn marker(job: &Job) -> Vec<u8> {
    let mut bytes = b"MKST\x01".to_vec();
    let binding = [
        MARKER_DOMAIN,
        job.operation_id.as_bytes(),
        job.generation.as_bytes(),
        job.carrier_key.as_bytes(),
    ]
    .concat();
    bytes.extend_from_slice(&hash(&binding));
    bytes
}

impl RefStore {
    /// Test-faults-only storage oracle: an authenticated owner attempts the
    /// same create-only PUT that a delayed Upload would issue after cleanup.
    /// It names only an existing confirmed operation, derives the private key
    /// and fixed marker bytes from that row, and never alters SQL/quota state.
    #[cfg(feature = "test-faults")]
    pub(super) async fn submission_test_marker_create(
        &self,
        wire: SubmissionWire,
    ) -> Result<Response> {
        if !self.cleanup_owner(&wire.identity, &wire.proof)? {
            return error(DENIED, 403)?.response();
        }
        let request: Id = match serde_json::from_str(&wire.body) {
            Ok(value) => value,
            Err(_) => return error(INVALID, 400)?.response(),
        };
        if !crate::snapshot_wire::id(&request.operation_id) {
            return error(INVALID, 400)?.response();
        }
        let job = self.submission_job(&request.operation_id)?;
        let Some(job) = job.filter(|v| v.marker_confirmed && v.state == "expired") else {
            return error(CONFLICT, 409)?.response();
        };
        let key = format!("quarantine/submissions/{}", job.carrier_key);
        let bytes = marker(&job);
        if bytes.len() > 128 {
            return error(UNAVAILABLE, 503)?.response();
        }
        let bucket = self.env.bucket(STORAGE_BUCKET)?;
        let put = bucket
            .put(key.clone(), bytes.clone())
            .only_if(Conditional {
                etag_does_not_match: Some("*".into()),
                ..Default::default()
            })
            .execute()
            .await?;
        if !self.cleanup_owner(&wire.identity, &wire.proof)? {
            return error(CONFLICT, 409)?.response();
        }
        let current = self.submission_job(&request.operation_id)?;
        if current.as_ref().is_none_or(|v| {
            !v.marker_confirmed
                || v.generation != job.generation
                || v.carrier_key != job.carrier_key
        }) {
            return error(CONFLICT, 409)?.response();
        }
        // A successful create would disprove the marker's conditional-write
        // protection. Never report a safe failed-precondition in that case.
        if put.is_some() {
            return error(UNAVAILABLE, 503)?.response();
        }
        let Some(object) = bucket.get(key).execute().await? else {
            return error(UNAVAILABLE, 503)?.response();
        };
        if object.size() != bytes.len() as u64 || object.size() > 128 {
            return error(UNAVAILABLE, 503)?.response();
        }
        let mut stream = object.body().ok_or_else(corrupt)?.stream()?;
        let mut observed = Vec::with_capacity(bytes.len());
        while let Some(part) = stream.next().await {
            let part = part?;
            if part.len() > bytes.len() - observed.len() {
                return error(UNAVAILABLE, 503)?.response();
            }
            observed.extend_from_slice(&part);
        }
        if observed != bytes {
            return error(UNAVAILABLE, 503)?.response();
        }
        Reply::json(&serde_json::json!({
            "version":1,"put_rejected":true,
            "marker_digest":hex::encode(hash(&bytes)),"marker_bytes":bytes.len(),
        }))?
        .response()
    }

    fn cleanup_owner(&self, identity: &Identity, proof: &Proof) -> Result<bool> {
        if proof.author != identity.owner || now() > proof.expires_at {
            return Ok(false);
        }
        Ok(self
            .read_policy(identity)?
            .is_some_and(|p| p.validate(identity).is_ok()))
    }

    fn cleanup_current(
        &self,
        identity: &Identity,
        proof: &Proof,
        id: &str,
        seq: &str,
    ) -> Result<Job> {
        if !self.cleanup_owner(identity, proof)? {
            return Err(corrupt());
        }
        let job = self.submission_job(id)?.ok_or_else(corrupt)?;
        if job.cleanup_claim_seq != seq
            || job.cleanup_claim_scope != proof.scope
            || job.cleanup_claim_fingerprint != proof.fingerprint
            || job.cleanup_claim_deadline <= now()
            || job.marker_confirmed
            || !["validated", "refused", "expired"].contains(&job.state.as_str())
        {
            return Err(corrupt());
        }
        Ok(job)
    }

    fn cleanup_charge(
        &self,
        identity: &Identity,
        proof: &Proof,
        id: &str,
        seq: &str,
        bytes: u64,
    ) -> Result<()> {
        let owned = self.clone();
        let identity = identity.clone();
        let proof = proof.clone();
        let id = id.to_owned();
        let seq = seq.to_owned();
        self.ledger.transaction(move || {
            let mut job = owned.cleanup_current(&identity, &proof, &id, &seq)?;
            job.cleanup_ops = job.cleanup_ops.checked_add(1).ok_or_else(corrupt)?;
            job.cleanup_bytes = job.cleanup_bytes.checked_add(bytes).ok_or_else(corrupt)?;
            if job.cleanup_ops > 12 || job.cleanup_bytes > 4096 {
                return Err(Error::RustError("cleanup capacity".into()));
            }
            let lifetime = owned.submission_lifetime(&id)?.ok_or_else(corrupt)?;
            owned.submission_save_job(&job, &lifetime.exact_ref)
        })
    }

    fn cleanup_has_more(&self, current: i64) -> Result<bool> {
        Ok(self.snapshot_exists("SELECT 1 AS found FROM host_submission_jobs WHERE state IN ('awaiting_upload','validating') AND idle_deadline<=? LIMIT 1",vec![current.into()])?
            || self.snapshot_exists("SELECT 1 AS found FROM host_submission_jobs WHERE state IN ('validated','refused','expired') AND bulky_deadline<=? LIMIT 1",vec![current.into()])?
            || self.snapshot_exists("SELECT 1 AS found FROM host_submission_jobs WHERE marker_confirmed=1 LIMIT 1",vec![])? )
    }

    fn cleanup_paged_rows(&self, meta: &mut Meta, limit: u64) -> Result<u64> {
        let mut affected = 0;
        while affected < limit {
            let rows:Vec<Id>=self.state.storage().sql().exec(
                "SELECT operation_id FROM host_submission_jobs WHERE marker_confirmed=1 AND state IN ('validated','refused','expired') AND bulky_deadline<=? ORDER BY bulky_deadline,operation_id LIMIT 1",
                vec![now().into()],
            )?.to_array()?;
            let Some(id) = rows.first() else { break };
            let job = self.submission_job(&id.operation_id)?.ok_or_else(corrupt)?;
            if !job.marker_confirmed {
                return Err(corrupt());
            }
            let mut deleted = false;
            for table in [
                "host_submission_selected",
                "host_submission_inventory",
                "host_submission_supplied",
                "host_submission_required",
                "host_submission_matched",
                "host_submission_seen",
                "host_submission_frontier",
                "host_submission_pins",
            ] {
                let query = format!(
                    "DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE operation_id=? LIMIT 1)"
                );
                let result = self
                    .state
                    .storage()
                    .sql()
                    .exec(&query, vec![id.operation_id.clone().into()])?;
                if result.rows_written() > 0 {
                    affected += 1;
                    deleted = true;
                    break;
                }
            }
            if deleted {
                continue;
            }
            self.state.storage().sql().exec(
                "DELETE FROM host_submission_jobs WHERE operation_id=?",
                vec![id.operation_id.clone().into()],
            )?;
            meta.terminal_slots = meta.terminal_slots.checked_sub(1).ok_or_else(corrupt)?;
            affected += 1;
        }
        Ok(affected)
    }

    fn cleanup_claim(
        &self,
        wire: SubmissionWire,
        request: submission_wire::CleanupSubmissions,
    ) -> Result<Claim> {
        if !self.cleanup_owner(&wire.identity, &wire.proof)? {
            return Ok(Claim::Reply(error(DENIED, 403)?));
        }
        let prior = self.ledger.reserve(&wire.proof, now(), || {
            let Some(meta) = self.submission_meta(&wire.identity)? else {
                return Ok(Some(error(CONFLICT, 409)?));
            };
            if meta.cleanup_revision != request.expected_cleanup_revision {
                return Ok(Some(error(CONFLICT, 409)?));
            }
            Ok(None)
        });
        let prior = match prior {
            Ok(v) => v,
            Err(e) if e.to_string().contains("nonce reused") => {
                return Ok(Claim::Reply(error(CONFLICT, 409)?));
            }
            Err(_) => return Ok(Claim::Reply(error(UNAVAILABLE, 503)?)),
        };
        if let Some(Some(reply)) = prior {
            return Ok(Claim::Reply(reply));
        }
        if let Some(None) = prior {
            return Ok(Claim::Pending);
        }
        let mut meta = self.submission_meta(&wire.identity)?.ok_or_else(corrupt)?;
        let oldest:Vec<Id>=self.state.storage().sql().exec(
            "SELECT operation_id FROM host_submission_jobs WHERE marker_confirmed=0 AND state IN ('refused','expired') AND bulky_deadline<=? ORDER BY bulky_deadline,operation_id LIMIT 1",
            vec![now().into()],
        )?.to_array()?;
        let exhausted_due = if let Some(id) = oldest.first() {
            let job = self.submission_job(&id.operation_id)?.ok_or_else(corrupt)?;
            job.cleanup_attempts >= 8192
        } else {
            false
        };
        let mut affected = 0;
        // First fence at most one idle active job. The physical reservation is
        // deliberately retained until the marker is confirmed.
        let rows:Vec<Id>=self.state.storage().sql().exec(
            "SELECT operation_id FROM host_submission_jobs WHERE state IN ('awaiting_upload','validating') AND idle_deadline<=? ORDER BY idle_deadline,operation_id LIMIT 1",vec![now().into()]
        )?.to_array()?;
        if let Some(id) = rows.first() {
            let mut job = self.submission_job(&id.operation_id)?.ok_or_else(corrupt)?;
            let mut lifetime = self
                .submission_lifetime(&id.operation_id)?
                .ok_or_else(corrupt)?;
            meta.active = meta.active.checked_sub(1).ok_or_else(corrupt)?;
            job.state = "expired".into();
            job.phase = "terminal".into();
            job.bulky_deadline = now();
            job.idle_deadline = now();
            job.next_revision()?;
            job.finish_attempt();
            lifetime.state = "expired".into();
            lifetime.revision = job.revision.clone();
            lifetime.terminal_at = now();
            lifetime.terminal_progress = Some(progress(&job));
            self.submission_save_job(&job, &lifetime.exact_ref)?;
            self.submission_save_lifetime(&lifetime)?;
            affected += 1;
        }
        // A once-validated result must become permanently unpublishable
        // before its pinned candidate source is physically reclaimed.
        if affected < u64::from(request.max_rows) {
            let due:Vec<Id>=self.state.storage().sql().exec(
                "SELECT operation_id FROM host_submission_jobs WHERE state='validated' AND bulky_deadline<=? ORDER BY bulky_deadline,operation_id LIMIT 1",
                vec![now().into()],
            )?.to_array()?;
            if let Some(id) = due.first() {
                let mut job = self.submission_job(&id.operation_id)?.ok_or_else(corrupt)?;
                let mut lifetime = self
                    .submission_lifetime(&id.operation_id)?
                    .ok_or_else(corrupt)?;
                job.state = "expired".into();
                job.phase = "terminal".into();
                job.next_revision()?;
                lifetime.state = "expired".into();
                lifetime.revision = job.revision.clone();
                lifetime.terminal_at = now();
                lifetime.terminal_progress = Some(progress(&job));
                self.submission_save_job(&job, &lifetime.exact_ref)?;
                self.submission_save_lifetime(&lifetime)?;
                affected += 1;
            }
        }
        let mut selected = None;
        if affected < u64::from(request.max_rows) && !self.snapshot_busy.get() {
            let rows:Vec<Id>=self.state.storage().sql().exec(
                "SELECT operation_id FROM host_submission_jobs WHERE state IN ('refused','expired') AND bulky_deadline<=? ORDER BY bulky_deadline,operation_id LIMIT 1",vec![now().into()]
            )?.to_array()?;
            if let Some(id) = rows.first() {
                let mut job = self.submission_job(&id.operation_id)?.ok_or_else(corrupt)?;
                if !job.marker_confirmed
                    && job.cleanup_claim_deadline <= now()
                    && job.cleanup_attempts < 8192
                {
                    job.cleanup_claim_seq = checked_decimal(&job.cleanup_claim_seq)?
                        .checked_add(1)
                        .ok_or_else(corrupt)?
                        .to_string();
                    job.cleanup_claim_scope = wire.proof.scope.clone();
                    job.cleanup_claim_fingerprint = wire.proof.fingerprint.clone();
                    job.cleanup_claim_deadline =
                        now().checked_add(CLEANUP_CLAIM_MS).ok_or_else(corrupt)?;
                    job.cleanup_ops = 0;
                    job.cleanup_bytes = 0;
                    job.cleanup_attempts =
                        job.cleanup_attempts.checked_add(1).ok_or_else(corrupt)?;
                    if job.cleanup_attempts > 8192 {
                        return Err(corrupt());
                    }
                    let lifetime = self
                        .submission_lifetime(&id.operation_id)?
                        .ok_or_else(corrupt)?;
                    self.submission_save_job(&job, &lifetime.exact_ref)?;
                    selected = Some((id.operation_id.clone(), job.cleanup_claim_seq));
                }
            }
        }
        if selected.is_none() && affected < u64::from(request.max_rows) {
            affected +=
                self.cleanup_paged_rows(&mut meta, u64::from(request.max_rows) - affected)?;
        }
        if selected.is_none() && affected == 0 && exhausted_due {
            let reply = error(EXHAUSTED, 429)?;
            self.ledger.finish(&wire.proof, &reply)?;
            return Ok(Claim::Reply(reply));
        }
        self.submission_save_meta(&meta)?;
        Ok(Claim::Work {
            id: selected.as_ref().map(|v| v.0.clone()),
            seq: selected.map_or(String::new(), |v| v.1),
            affected,
        })
    }

    async fn cleanup_marker(
        &self,
        identity: &Identity,
        proof: &Proof,
        id: &str,
        seq: &str,
    ) -> Result<()> {
        let job = self.cleanup_current(identity, proof, id, seq)?;
        let bytes = marker(&job);
        let key = format!("quarantine/submissions/{}", job.carrier_key);
        let bucket = self.env.bucket(STORAGE_BUCKET)?;
        let deadline = now().checked_add(20_000).ok_or_else(corrupt)?;
        for _ in 0..3 {
            if now() >= deadline {
                return Err(corrupt());
            }
            self.cleanup_charge(identity, proof, id, seq, 0)?;
            let head = bucket.head(key.clone()).await?;
            self.cleanup_current(identity, proof, id, seq)?;
            let conditional = match head {
                Some(ref object) => Conditional {
                    etag_matches: Some(object.etag()),
                    ..Default::default()
                },
                None => Conditional {
                    etag_does_not_match: Some("*".into()),
                    ..Default::default()
                },
            };
            self.cleanup_charge(identity, proof, id, seq, bytes.len() as u64)?;
            #[cfg(feature = "test-faults")]
            if let Ok(delay) = self.env.var("SUBMISSION_TEST_MARKER_PRE_PUT_MS") {
                let millis = delay.to_string().parse::<u64>().unwrap_or(0).min(5_000);
                if millis > 0 {
                    worker::Delay::from(std::time::Duration::from_millis(millis)).await;
                }
            }
            self.cleanup_current(identity, proof, id, seq)?;
            let put = bucket
                .put(key.clone(), bytes.clone())
                .only_if(conditional)
                .execute()
                .await?;
            self.cleanup_current(identity, proof, id, seq)?;
            if put.is_none() {
                continue;
            }
            self.cleanup_charge(identity, proof, id, seq, bytes.len() as u64)?;
            let response = bucket
                .get(key.clone())
                .only_if(Conditional {
                    etag_matches: Some(put.unwrap().etag()),
                    ..Default::default()
                })
                .execute()
                .await?;
            let Some(response) = response else { continue };
            if response.size() != bytes.len() as u64 {
                continue;
            }
            let mut stream = response.body().ok_or_else(corrupt)?.stream()?;
            let mut observed = Vec::new();
            while let Some(part) = stream.next().await {
                if now() >= deadline {
                    return Err(corrupt());
                }
                let part = part?;
                if part.len() > 128 - observed.len() {
                    return Err(corrupt());
                }
                observed.extend_from_slice(&part);
            }
            self.cleanup_current(identity, proof, id, seq)?;
            if observed == bytes {
                return Ok(());
            }
        }
        Err(corrupt())
    }

    pub(super) async fn submission_cleanup(&self, wire: SubmissionWire) -> Result<Response> {
        let request = match submission_wire::decode_cleanup(wire.body.as_bytes()) {
            Ok(v) => v,
            Err(_) => return error(INVALID, 400)?.response(),
        };
        let identity = wire.identity.clone();
        let proof = wire.proof.clone();
        let owned = self.clone();
        let claim = self
            .ledger
            .transaction(move || owned.cleanup_claim(wire, request));
        let claim = match claim {
            Ok(v) => v,
            Err(_) => return error(UNAVAILABLE, 503)?.response(),
        };
        let Claim::Work { id, seq, affected } = claim else {
            return match claim {
                Claim::Reply(v) => v.response(),
                Claim::Pending => error("{\"code\":\"in_progress\"}", 202)?.response(),
                _ => unreachable!(),
            };
        };
        if id.is_some() {
            self.snapshot_busy.set(true);
        }
        let _busy = id.as_ref().map(|_| Busy(self.snapshot_busy.clone()));
        let physical = if let Some(ref id) = id {
            self.cleanup_marker(&identity, &proof, id, &seq).await
        } else {
            Ok(())
        };
        let owned = self.clone();
        let reply=self.ledger.transaction(move ||{
            if !owned.cleanup_owner(&identity,&proof)? {return error(CONFLICT,409);}
            let mut meta=owned.submission_meta(&identity)?.ok_or_else(corrupt)?;
            let mut affected=affected;
            if let Some(id)=id {
                let mut job=owned.cleanup_current(&identity,&proof,&id,&seq)?;
                job.cleanup_claim_deadline=0;job.cleanup_claim_scope.clear();job.cleanup_claim_fingerprint.clear();
                if physical.is_ok() {
                    let lifetime=owned.submission_lifetime(&id)?.ok_or_else(corrupt)?;
                    let subject=lifetime.subject.clone();
                    meta.carrier_slots=meta.carrier_slots.checked_sub(1).ok_or_else(corrupt)?;
                    meta.carrier_bytes=meta.carrier_bytes.checked_sub(lifetime.update_len).ok_or_else(corrupt)?;
                    #[derive(Deserialize)] struct Quota {carrier_slots:i64,carrier_bytes:i64}
                    let rows:Vec<Quota>=owned.state.storage().sql().exec("SELECT carrier_slots,carrier_bytes FROM host_submission_subjects WHERE subject=?",vec![subject.clone().into()])?.to_array()?;
                    if rows.len()!=1 || rows[0].carrier_slots<=0 || rows[0].carrier_bytes<i64::try_from(lifetime.update_len).map_err(|_|corrupt())? {return Err(corrupt());}
                    owned.state.storage().sql().exec("UPDATE host_submission_subjects SET carrier_slots=?,carrier_bytes=? WHERE subject=?",
                        vec![(rows[0].carrier_slots-1).into(),(rows[0].carrier_bytes-i64::try_from(lifetime.update_len).map_err(|_|corrupt())?).into(),subject.into()])?;
                    job.marker_confirmed=true;affected+=1;
                }
                let lifetime=owned.submission_lifetime(&id)?.ok_or_else(corrupt)?;
                owned.submission_save_job(&job,&lifetime.exact_ref)?;
            }
            meta.cleanup_revision=checked_decimal(&meta.cleanup_revision)?.checked_add(1).ok_or_else(corrupt)?.to_string();
            owned.submission_save_meta(&meta)?;
            let reply=if physical.is_ok() {Reply::json(&CleanupReply{version:1,cleanup_revision:meta.cleanup_revision,affected_rows:affected.to_string(),has_more:owned.cleanup_has_more(now())?})?}
                else {error(UNAVAILABLE,503)?};
            owned.ledger.finish(&proof,&reply)?;
            Ok(reply)
        });
        match reply {
            Ok(v) => v.response(),
            Err(_) => error(UNAVAILABLE, 503)?.response(),
        }
    }
}
