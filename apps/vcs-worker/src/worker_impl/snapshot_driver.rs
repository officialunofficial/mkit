// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded asynchronous R2 driver for one durable Snapshot job transition.

use std::{cell::Cell, num::NonZeroUsize, rc::Rc};

use futures::StreamExt;
use mkit_core::{
    hash::Hash,
    pack::{CheckedRawPack, RawPackError, RawPackLimits},
    partial::{
        ObjectInspectionLimits, SnapshotRole, SnapshotWalkLimits, SnapshotWalkRecord,
        SnapshotWalkUsage, advance_snapshot_walk, apply_walk_accounting, identify_snapshot_object,
        inspect_snapshot_object, next_manifest_ids,
    },
    transfer::decode_packlist_bounded,
};
use mkit_worker_common::replay::{Proof, Reply};
use serde::Deserialize;
use worker::{Conditional, Date, Error, Range, Response, Result};

use super::{
    managed::AdminWire,
    refstore::RefStore,
    service::STORAGE_BUCKET,
    snapshot_store::{Job, MAX_ATTEMPTS, MAX_JOB_OPS, MAX_STEP_BYTES},
};
use crate::{
    snapshot_frontier::Frontier,
    snapshot_wire::{self, ContinueSnapshot, PendingReply},
};

const UNAVAILABLE: &str = "{\"code\":\"unavailable\"}";
const CONFLICT: &str = "{\"code\":\"conflict\"}";
const EXHAUSTED: &str = "{\"code\":\"resource_exhausted\"}";
const PROFILE: &str = "{\"code\":\"unsupported_profile\"}";

fn now() -> i64 {
    Date::now().as_millis() as i64
}
fn storage_error() -> Error {
    Error::RustError("snapshot storage unavailable".into())
}
fn within_deadline(deadline: i64) -> Result<()> {
    if now() >= deadline {
        Err(storage_error())
    } else {
        Ok(())
    }
}

pub(super) struct HeavyPermit(Rc<Cell<bool>>);
impl HeavyPermit {
    pub(super) fn acquire(busy: &Rc<Cell<bool>>) -> Option<Self> {
        if busy.replace(true) {
            None
        } else {
            Some(Self(busy.clone()))
        }
    }
}
impl Drop for HeavyPermit {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

#[derive(Clone)]
enum Plan {
    Tip,
    Pack(String),
    Walk {
        seq: i64,
        document: String,
        record: SnapshotWalkRecord,
        parent: Locator,
    },
    Promote,
}
enum Claim {
    Reply(Reply),
    Pending(String),
    New { job: Box<Job>, plan: Plan },
}

#[derive(Deserialize)]
struct Selected {
    pack_key: String,
}
#[derive(Clone, Deserialize)]
pub(super) struct Locator {
    pub pack_key: String,
    pub object_id: String,
    pub canonical_len: i64,
    pub payload_offset: i64,
    pub payload_len: i64,
    pub pack_size: i64,
    pub etag: String,
}
#[derive(Deserialize)]
struct Queued {
    seq: i64,
    document: String,
}
#[derive(Deserialize)]
struct CatalogIdentity {
    kind: String,
    canonical_len: i64,
}

impl RefStore {
    pub(super) async fn snapshot_continue(
        &self,
        wire: AdminWire,
        policy_generation: String,
    ) -> Result<Response> {
        let request: ContinueSnapshot =
            match snapshot_wire::decode::<ContinueSnapshot>(wire.body.as_bytes()) {
                Ok(request) if request.validate() => request,
                _ => return Reply::error("{\"code\":\"invalid_argument\"}", 400)?.response(),
            };
        let proof = wire.proof.clone();
        let busy = self.snapshot_busy.clone();
        let acquired = Rc::new(Cell::new(false));
        let acquired_in_tx = acquired.clone();
        let owned = self.clone();
        let claim = self.ledger.transaction(move || {
            let prior = owned.ledger.reserve(&wire.proof, now(), || {
                let Some(_meta) = owned.snapshot_meta(&wire.identity)? else {
                    return Ok(Some(Reply::error(UNAVAILABLE, 503)?));
                };
                let Some(job) = owned.snapshot_job(&request.job_id)? else {
                    return Ok(Some(Reply::error("{\"code\":\"not_found\"}", 404)?));
                };
                if job.generation != request.job_generation
                    || job.revision != request.expected_revision
                    || !job.active()
                    || job.policy_generation != policy_generation
                    || job.idle_deadline < now()
                    || job.attempt_deadline > now()
                    || owned.read_ref(&job.exact_ref)?.as_deref() != Some(&job.head)
                    || owned.read_ref(&job.packmap_ref)?.as_deref() != Some(&job.packmap)
                {
                    return Ok(Some(Reply::error(CONFLICT, 409)?));
                }
                if job.attempts >= MAX_ATTEMPTS || job.r2_operations >= MAX_JOB_OPS {
                    return Ok(Some(Reply::error(EXHAUSTED, 429)?));
                }
                if busy.get() {
                    return Ok(Some(Reply::error(EXHAUSTED, 429)?));
                }
                Ok(None)
            })?;
            if let Some(Some(reply)) = prior {
                return Ok(Claim::Reply(reply));
            }
            if let Some(None) = prior {
                return Ok(Claim::Pending(request.job_id));
            }
            // Only a genuinely new admitted nonce takes the process permit.
            // The caller releases it if any part of this transaction fails.
            busy.set(true);
            acquired_in_tx.set(true);
            let mut job = owned
                .snapshot_job(&request.job_id)?
                .ok_or_else(storage_error)?;
            let plan = owned.snapshot_plan(&job)?;
            job.claim(&wire.proof.scope, &wire.proof.fingerprint, now())?;
            match &plan {
                Plan::Tip | Plan::Pack(_) => job.charge(0)?, // HEAD before first await.
                Plan::Walk { parent, .. } => job.charge(parent.payload_len as u64)?,
                Plan::Promote => {}
            }
            owned.snapshot_save_job(&job)?;
            Ok(Claim::New {
                job: Box::new(job),
                plan,
            })
        });
        let claim = match claim {
            Ok(claim) => claim,
            Err(error) => {
                if acquired.get() {
                    self.snapshot_busy.set(false);
                }
                return if error.to_string().contains("nonce reused") {
                    Reply::error(CONFLICT, 409)?.response()
                } else if error.to_string().contains("invalid snapshot operation") {
                    Reply::error(EXHAUSTED, 429)?.response()
                } else {
                    Reply::error(UNAVAILABLE, 503)?.response()
                };
            }
        };
        let Claim::New { job, plan } = claim else {
            return match claim {
                Claim::Reply(reply) => reply.response(),
                Claim::Pending(job_id) => Reply::error(
                    serde_json::to_string(&PendingReply {
                        version: 1,
                        code: "in_progress",
                        job_id,
                    })
                    .map_err(|_| storage_error())?,
                    202,
                )?
                .response(),
                Claim::New { .. } => unreachable!(),
            };
        };
        let _permit = HeavyPermit(self.snapshot_busy.clone());
        let deadline = now().checked_add(20_000).ok_or_else(storage_error)?;
        let result = match plan {
            Plan::Tip => self.snapshot_step_tip(&job, &proof, deadline).await,
            Plan::Pack(key) => self.snapshot_step_pack(&job, &proof, &key, deadline).await,
            Plan::Walk {
                seq,
                document,
                record,
                parent,
            } => {
                self.snapshot_step_walk(&job, &proof, seq, document, record, parent, deadline)
                    .await
            }
            Plan::Promote => self.snapshot_promote(&job, &proof, deadline),
        };
        match result {
            Ok(reply) => reply.response(),
            Err(error) => {
                let capacity = error.to_string().contains("invalid snapshot operation");
                let (body, status) = if capacity {
                    (EXHAUSTED, 429)
                } else {
                    (UNAVAILABLE, 503)
                };
                let owned = self.clone();
                let seq = job.attempt_seq.clone();
                let proof_copy = proof.clone();
                let original = job.clone();
                let _ = self.ledger.transaction(move || {
                    let Ok(mut current) = owned.snapshot_check_fence(&original, &proof_copy) else {
                        return Ok(());
                    };
                    if current.attempt_seq == seq && current.attempt_scope == proof_copy.scope {
                        current.finish_attempt();
                        owned.snapshot_save_job(&current)?;
                        owned
                            .ledger
                            .finish(&proof_copy, &Reply::error(body, status)?)?;
                    }
                    Ok(())
                });
                Reply::error(body, status)?.response()
            }
        }
    }

    fn snapshot_plan(&self, job: &Job) -> Result<Plan> {
        if job.state == "catalog" {
            if !job.tip_checked {
                return Ok(Plan::Tip);
            }
            let rows: Vec<Selected> = self
                .state
                .storage()
                .sql()
                .exec(
                    "SELECT pack_key FROM host_snapshot_selected WHERE job_id=? AND ordinal=?",
                    vec![job.id.clone().into(), i64::from(job.pack_index).into()],
                )?
                .to_array()?;
            if let Some(row) = rows.first() {
                return Ok(Plan::Pack(row.pack_key.clone()));
            }
            return Err(storage_error());
        }
        let rows: Vec<Queued> = self.state.storage().sql().exec(
            "SELECT seq,document FROM host_snapshot_frontier WHERE job_id=? ORDER BY seq LIMIT 1",
            vec![job.id.clone().into()],
        )?.to_array()?;
        if let Some(row) = rows.first() {
            let frontier: Frontier =
                serde_json::from_str(&row.document).map_err(|_| storage_error())?;
            let record = frontier.record().map_err(|_| storage_error())?;
            let parent = self.snapshot_locator(job, &frontier.id)?;
            return Ok(Plan::Walk {
                seq: row.seq,
                document: row.document.clone(),
                record,
                parent,
            });
        }
        if job.frontier_rows != 0 {
            return Err(storage_error());
        }
        Ok(Plan::Promote)
    }

    fn snapshot_check_fence(&self, original: &Job, proof: &Proof) -> Result<Job> {
        let current = self.snapshot_job(&original.id)?.ok_or_else(storage_error)?;
        let identity = self.snapshot_identity()?;
        self.snapshot_meta(&identity)?.ok_or_else(storage_error)?;
        let policy = self.read_policy(&identity)?.ok_or_else(storage_error)?;
        if current.generation != original.generation
            || current.revision != original.revision
            || current.attempt_seq != original.attempt_seq
            || current.attempt_scope != proof.scope
            || current.attempt_fingerprint != proof.fingerprint
            || current.attempt_deadline < now()
            || proof.expires_at < now()
            || current.policy_generation != policy.generation
            || !current.active()
            || current.exact_ref != original.exact_ref
            || current.packmap_ref != original.packmap_ref
            || current.head != original.head
            || current.packmap != original.packmap
            || current.selected_digest != original.selected_digest
            || self.read_ref(&current.exact_ref)?.as_deref() != Some(&current.head)
            || self.read_ref(&current.packmap_ref)?.as_deref() != Some(&current.packmap)
        {
            return Err(storage_error());
        }
        let selection = self.snapshot_selected(&current)?.join("\n");
        let digest = hex::encode(mkit_core::hash::hash(
            [
                b"mkit.host.snapshot.selection.v1\0".as_slice(),
                selection.as_bytes(),
            ]
            .concat()
            .as_slice(),
        ));
        if digest != current.selected_digest {
            return Err(storage_error());
        }
        Ok(current)
    }

    fn snapshot_identity(&self) -> Result<crate::access_policy::Identity> {
        use crate::access_policy::Identity;
        let (a, r, o) = (
            self.env.var("AUTH_AUDIENCE")?,
            self.env.var("AUTH_REPOSITORY")?,
            self.env.var("MANAGED_OWNER_PUBLIC_KEY")?,
        );
        Identity::parse(&a.to_string(), &r.to_string(), &o.to_string()).map_err(|_| storage_error())
    }

    fn snapshot_charge(&self, original: &Job, proof: &Proof, bytes: u64) -> Result<()> {
        let owned = self.clone();
        let original = original.clone();
        let proof = proof.clone();
        self.ledger.transaction(move || {
            let mut current = owned.snapshot_check_fence(&original, &proof)?;
            current.charge(bytes)?;
            owned.snapshot_save_job(&current)
        })
    }

    async fn snapshot_read_complete(
        &self,
        original: &Job,
        proof: &Proof,
        key: &str,
        max_bytes: u64,
        deadline: i64,
    ) -> Result<(Vec<u8>, String)> {
        within_deadline(deadline)?;
        let bucket = self.env.bucket(STORAGE_BUCKET)?;
        let object = bucket
            .head(format!("packs/{key}"))
            .await?
            .ok_or_else(storage_error)?;
        within_deadline(deadline)?;
        if object.size() == 0 || object.size() > max_bytes {
            return Err(storage_error());
        }
        let bytes_reserved = object.size();
        let etag = object.etag();
        self.snapshot_charge(original, proof, bytes_reserved)?;
        // Local fault profile only: create a deterministic R2-await window to
        // verify administration and replay stay responsive without a SQL hold.
        #[cfg(feature = "test-faults")]
        if let Ok(value) = self.env.var("SNAPSHOT_TEST_R2_PAUSE_MS") {
            if let Ok(millis) = value.to_string().parse::<u64>() {
                if (1..=10_000).contains(&millis) {
                    worker::Delay::from(std::time::Duration::from_millis(millis)).await;
                }
            }
        }
        within_deadline(deadline)?;
        let object = bucket
            .get(format!("packs/{key}"))
            .only_if(Conditional {
                etag_matches: Some(etag.clone()),
                ..Default::default()
            })
            .execute()
            .await?
            .ok_or_else(storage_error)?;
        within_deadline(deadline)?;
        if object.size() != bytes_reserved || object.etag() != etag {
            return Err(storage_error());
        }
        let body = object.body().ok_or_else(storage_error)?;
        let mut stream = body.stream()?;
        let mut bytes = Vec::new();
        let reserved_len = usize::try_from(bytes_reserved).map_err(|_| storage_error())?;
        while let Some(part) = stream.next().await {
            within_deadline(deadline)?;
            let part = part?;
            snapshot_wire::append_reserved(&mut bytes, &part, reserved_len)
                .map_err(|_| storage_error())?;
        }
        if bytes.len() as u64 != bytes_reserved {
            return Err(storage_error());
        }
        Ok((bytes, etag))
    }

    fn snapshot_locator(&self, job: &Job, id: &str) -> Result<Locator> {
        self.snapshot_index_locator(&job.id, id)
    }

    /// Lookup only a builder-requested ID under a certified, leased index.
    /// The caller must authenticate the subject and check the live lease.
    pub(super) fn snapshot_index_locator(&self, job_id: &str, id: &str) -> Result<Locator> {
        let rows: Vec<Locator> = self.state.storage().sql().exec(
            "SELECT pack_key,object_id,canonical_len,payload_offset,payload_len,pack_size,etag FROM host_snapshot_catalog WHERE job_id=? AND object_id=? ORDER BY pack_key,ordinal LIMIT 1",
            vec![job_id.into(), id.into()],
        )?.to_array()?;
        let locator = rows.into_iter().next().ok_or_else(storage_error)?;
        let end = locator
            .payload_offset
            .checked_add(locator.payload_len)
            .ok_or_else(storage_error)?;
        if locator.object_id != id
            || locator.canonical_len <= 0
            || locator.canonical_len != locator.payload_len
            || locator.payload_offset < 0
            || locator.payload_len > 2 * 1024 * 1024
            || end > locator.pack_size
            || locator.pack_size > 4 * 1024 * 1024
            || locator.etag.is_empty()
            || !snapshot_wire::id(&locator.pack_key)
        {
            return Err(storage_error());
        }
        Ok(locator)
    }

    pub(super) async fn snapshot_read_range(
        &self,
        locator: &Locator,
        deadline: i64,
    ) -> Result<Vec<u8>> {
        within_deadline(deadline)?;
        let bucket = self.env.bucket(STORAGE_BUCKET)?;
        let object = bucket
            .get(format!("packs/{}", locator.pack_key))
            .only_if(Conditional {
                etag_matches: Some(locator.etag.clone()),
                ..Default::default()
            })
            .range(Range::OffsetWithLength {
                offset: locator.payload_offset as u64,
                length: locator.payload_len as u64,
            })
            .execute()
            .await?
            .ok_or_else(storage_error)?;
        within_deadline(deadline)?;
        // workers-rs 0.8.6 `R2Object::range()` panics in actual local
        // workerd for ranged GETs. The requested exact range is fixed above;
        // ETag, full-object size, exact body length and object inspection
        // authenticate the bytes without invoking that SDK accessor.
        if object.etag() != locator.etag || object.size() != locator.pack_size as u64 {
            return Err(storage_error());
        }
        let body = object.body().ok_or_else(storage_error)?;
        let mut stream = body.stream()?;
        let mut bytes = Vec::new();
        while let Some(part) = stream.next().await {
            within_deadline(deadline)?;
            let part = part?;
            if part.len() > locator.payload_len as usize - bytes.len() {
                return Err(storage_error());
            }
            bytes.extend_from_slice(&part);
        }
        if bytes.len() != locator.payload_len as usize {
            return Err(storage_error());
        }
        Ok(bytes)
    }

    async fn snapshot_step_tip(&self, job: &Job, proof: &Proof, deadline: i64) -> Result<Reply> {
        let (bytes, _) = self
            .snapshot_read_complete(job, proof, &job.packmap, 64 * 1024, deadline)
            .await?;
        if hex::encode(mkit_core::hash::hash(&bytes)) != job.packmap {
            return Err(storage_error());
        }
        let node = decode_packlist_bounded(&bytes, 64 * 1024, 1024).map_err(|_| storage_error())?;
        let selected = self.snapshot_selected(job)?;
        if selected
            .iter()
            .any(|key| !node.packs.iter().any(|pack| hex::encode(pack) == *key))
        {
            return self.snapshot_fail_profile(job, proof, deadline);
        }
        let owned = self.clone();
        let original = job.clone();
        let proof = proof.clone();
        self.ledger.transaction(move || {
            within_deadline(deadline)?;
            let mut current = owned.snapshot_check_fence(&original, &proof)?;
            current.tip_checked = true;
            current.next_revision(now())?;
            current.finish_attempt();
            owned.snapshot_save_job(&current)?;
            let reply = Reply::json(&current.reply())?;
            owned.ledger.finish(&proof, &reply)?;
            Ok(reply)
        })
    }

    fn snapshot_selected(&self, job: &Job) -> Result<Vec<String>> {
        let rows: Vec<Selected> = self
            .state
            .storage()
            .sql()
            .exec(
                "SELECT pack_key FROM host_snapshot_selected WHERE job_id=? ORDER BY ordinal",
                vec![job.id.clone().into()],
            )?
            .to_array()?;
        if rows.is_empty() || rows.len() > 128 {
            return Err(storage_error());
        }
        Ok(rows.into_iter().map(|row| row.pack_key).collect())
    }

    fn snapshot_fail_profile(&self, job: &Job, proof: &Proof, deadline: i64) -> Result<Reply> {
        let owned = self.clone();
        let original = job.clone();
        let proof = proof.clone();
        self.ledger.transaction(move || {
            within_deadline(deadline)?;
            let mut current = owned.snapshot_check_fence(&original, &proof)?;
            current.state = "failed".into();
            current.terminal_deadline = now() + super::snapshot_store::TERMINAL_MS;
            current.finish_attempt();
            owned.snapshot_save_job(&current)?;
            let reply = Reply::error(PROFILE, 422)?;
            owned.ledger.finish(&proof, &reply)?;
            Ok(reply)
        })
    }

    async fn snapshot_step_pack(
        &self,
        job: &Job,
        proof: &Proof,
        key: &str,
        deadline: i64,
    ) -> Result<Reply> {
        let (bytes, etag) = self
            .snapshot_read_complete(job, proof, key, 4 * 1024 * 1024, deadline)
            .await?;
        let key_hash: Hash = hex::decode(key)
            .map_err(|_| storage_error())?
            .try_into()
            .map_err(|_| storage_error())?;
        let checked = match CheckedRawPack::open(
            &bytes,
            key_hash,
            RawPackLimits {
                max_pack_bytes: 4 * 1024 * 1024,
                max_entries: 200_000,
                max_entry_bytes: 2 * 1024 * 1024,
                max_payload_bytes: 4 * 1024 * 1024,
            },
        ) {
            Ok(checked) => checked,
            Err(RawPackError::WrongProfile) => {
                return self.snapshot_fail_profile(job, proof, deadline);
            }
            Err(_) => return Err(storage_error()),
        };
        let mut facts = Vec::new();
        let limits = ObjectInspectionLimits {
            max_object_bytes: 2 * 1024 * 1024,
            max_tree_bytes: 2 * 1024 * 1024,
            max_tree_entries: 65_536,
            max_manifest_chunks: 32_768,
        };
        for entry in checked.entries().skip(job.frame_index as usize).take(64) {
            let fact =
                identify_snapshot_object(entry.payload(), limits).map_err(|_| storage_error())?;
            facts.push((
                hex::encode(fact.id()),
                format!("{:?}", fact.kind()),
                fact.canonical_len(),
                entry.ordinal(),
                entry.payload_range().start,
                entry.payload_range().len(),
            ));
        }
        if facts.is_empty() {
            return Err(storage_error());
        }
        let finished = job.frame_index as usize + facts.len() == checked.entry_count() as usize;
        let key = key.to_owned();
        let owned = self.clone();
        let original = job.clone();
        let proof = proof.clone();
        self.ledger.transaction(move || {
            within_deadline(deadline)?;
            let mut current = owned.snapshot_check_fence(&original, &proof)?;
            let mut meta = owned.snapshot_meta(&owned.snapshot_identity()?)?.ok_or_else(storage_error)?;
            let new_entries = current.catalog_entries.checked_add(facts.len() as u64).ok_or_else(storage_error)?;
            let new_rows = meta.catalog_rows.checked_add(facts.len() as u64).ok_or_else(storage_error)?;
            let new_raw = if finished { current.catalog_raw_bytes.checked_add(bytes.len() as u64).ok_or_else(storage_error)? } else { current.catalog_raw_bytes };
            let new_pinned = if finished { meta.pinned_raw_bytes.checked_add(bytes.len() as u64).ok_or_else(storage_error)? } else { meta.pinned_raw_bytes };
            if new_entries > 200_000 || new_rows > 400_000 || new_raw > 256 * 1024 * 1024 || new_pinned > 1024 * 1024 * 1024 {
                let reply = Reply::error(EXHAUSTED, 429)?;
                current.finish_attempt();
                owned.snapshot_save_job(&current)?;
                owned.ledger.finish(&proof, &reply)?;
                return Ok(reply);
            }
            for (id, kind, len, ordinal, offset, payload_len) in &facts {
                let prior: Vec<CatalogIdentity> = owned.state.storage().sql().exec(
                    "SELECT kind,canonical_len FROM host_snapshot_catalog WHERE job_id=? AND object_id=? LIMIT 1",
                    vec![current.id.clone().into(), id.clone().into()],
                )?.to_array()?;
                if prior.first().is_some_and(|row| row.kind != *kind || row.canonical_len != *len as i64) {
                    return Err(storage_error());
                }
                owned.state.storage().sql().exec(
                    "INSERT INTO host_snapshot_catalog(job_id,pack_key,ordinal,object_id,kind,canonical_len,payload_offset,payload_len,pack_size,etag) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    vec![current.id.clone().into(),key.clone().into(),i64::from(*ordinal).into(),id.clone().into(),kind.clone().into(),(*len as i64).into(),(*offset as i64).into(),(*payload_len as i64).into(),(bytes.len() as i64).into(),etag.clone().into()],
                )?;
                meta.catalog_rows += 1;
            }
            current.catalog_entries += facts.len() as u64;
            current.frame_index += facts.len() as u32;
            if finished {
                current.catalog_raw_bytes = new_raw;
                meta.pinned_raw_bytes = new_pinned;
                current.pack_index += 1;
                current.catalog_packs += 1;
                current.frame_index = 0;
                if current.pack_index as usize == owned.snapshot_selected(&current)?.len() {
                    current.state = "walk".into();
                    let root: Hash = hex::decode(&current.head).map_err(|_| storage_error())?.try_into().map_err(|_| storage_error())?;
                    let record = mkit_core::partial::start_snapshot_walk(root, SnapshotRole::BaseRoot).map_err(|_| storage_error())?;
                    let document = serde_json::to_string(&Frontier::from_record(&record)).map_err(|_| storage_error())?;
                    current.frontier_rows = 1;
                    current.frontier_bytes = document.len() as u64;
                    current.frontier_next_seq = 1;
                    owned.state.storage().sql().exec(
                        "INSERT INTO host_snapshot_frontier(job_id,seq,document) VALUES(?,?,?)",
                        vec![current.id.clone().into(),0i64.into(),document.into()],
                    )?;
                }
            }
            current.next_revision(now())?;
            current.finish_attempt();
            owned.snapshot_save_meta(&meta)?;
            owned.snapshot_save_job(&current)?;
            let reply = Reply::json(&current.reply())?;
            owned.ledger.finish(&proof, &reply)?;
            Ok(reply)
        })
    }

    async fn snapshot_step_walk(
        &self,
        job: &Job,
        proof: &Proof,
        seq: i64,
        document: String,
        record: SnapshotWalkRecord,
        parent_locator: Locator,
        deadline: i64,
    ) -> Result<Reply> {
        let limits = ObjectInspectionLimits {
            max_object_bytes: 2 * 1024 * 1024,
            max_tree_bytes: 2 * 1024 * 1024,
            max_tree_entries: 65_536,
            max_manifest_chunks: 32_768,
        };
        let walk_limits = SnapshotWalkLimits {
            max_objects: 100_000,
            max_canonical_bytes: 256 * 1024 * 1024,
            max_tree_depth: 128,
            max_work: 1_000_000,
        };
        within_deadline(deadline)?;
        let bytes = self.snapshot_read_range(&parent_locator, deadline).await?; // charged by the claim.
        within_deadline(deadline)?;
        let parent = inspect_snapshot_object(record.id(), &bytes, record.role(), limits)
            .map_err(|_| storage_error())?;
        drop(bytes);
        let mut chunks = Vec::new();
        let mut width = 64usize;
        if let SnapshotWalkRecord::ManifestPage { next_index, .. } = record {
            let (_, _, total) = parent.manifest().ok_or_else(storage_error)?;
            let start = next_index as usize;
            if start >= total {
                return Err(storage_error());
            }
            let ids = next_manifest_ids(
                &record,
                &parent,
                NonZeroUsize::new((total - start).min(64)).ok_or_else(storage_error)?,
            )
            .map_err(|_| storage_error())?;
            let mut planned = parent_locator.payload_len as u64;
            width = 0;
            for id in ids {
                let locator = self.snapshot_locator(job, &hex::encode(id))?;
                let Some(next) = planned.checked_add(locator.payload_len as u64) else {
                    break;
                };
                if next > MAX_STEP_BYTES {
                    break;
                }
                within_deadline(deadline)?;
                self.snapshot_charge(job, proof, locator.payload_len as u64)?;
                let chunk_bytes = self.snapshot_read_range(&locator, deadline).await?;
                within_deadline(deadline)?;
                chunks.push(
                    inspect_snapshot_object(*id, &chunk_bytes, SnapshotRole::Chunk, limits)
                        .map_err(|_| storage_error())?,
                );
                drop(chunk_bytes);
                planned = next;
                width += 1;
            }
            if width == 0 {
                return Err(storage_error());
            }
        }
        let step = advance_snapshot_walk(
            &record,
            &parent,
            &chunks,
            NonZeroUsize::new(width).ok_or_else(storage_error)?,
            &walk_limits,
        )
        .map_err(|_| storage_error())?;
        within_deadline(deadline)?;
        let owned = self.clone();
        let original = job.clone();
        let proof = proof.clone();
        self.ledger.transaction(move || {
            within_deadline(deadline)?;
            let mut current = owned.snapshot_check_fence(&original, &proof)?;
            let rows: Vec<Queued> = owned
                .state
                .storage()
                .sql()
                .exec(
                    "SELECT seq,document FROM host_snapshot_frontier WHERE job_id=? AND seq=?",
                    vec![current.id.clone().into(), seq.into()],
                )?
                .to_array()?;
            if rows.len() != 1 || rows[0].document != document {
                return Err(storage_error());
            }
            if current.frontier_rows == 0 {
                return Err(storage_error());
            }
            let mut newly_seen = Vec::new();
            let mut local_seen = std::collections::BTreeSet::new();
            for observed in step.observations() {
                let id = observed.id();
                if !local_seen.insert(id) {
                    continue;
                }
                #[derive(Deserialize)]
                struct Seen {
                    canonical_len: i64,
                }
                let old: Vec<Seen> = owned.state.storage().sql().exec(
                    "SELECT canonical_len FROM host_snapshot_seen WHERE job_id=? AND object_id=?",
                    vec![current.id.clone().into(),hex::encode(id).into()],
                )?.to_array()?;
                if let Some(old) = old.first() {
                    if old.canonical_len != observed.canonical_len() as i64 {
                        return Err(storage_error());
                    }
                } else {
                    newly_seen.push(id);
                }
            }
            let previous = SnapshotWalkUsage {
                objects: current.reached_objects,
                canonical_bytes: current.reached_bytes,
                max_tree_depth: current.max_depth,
                work: current.work_units,
            };
            let next = apply_walk_accounting(previous, &step, &newly_seen, walk_limits)
                .map_err(|_| storage_error())?;
            let mut documents = Vec::with_capacity(step.successors().len());
            let mut successor_bytes = 0u64;
            for successor in step.successors() {
                let serialized = serde_json::to_string(&Frontier::from_record(successor))
                    .map_err(|_| storage_error())?;
                if serialized.len() > 4096 {
                    return Err(storage_error());
                }
                successor_bytes = successor_bytes
                    .checked_add(serialized.len() as u64)
                    .ok_or_else(storage_error)?;
                documents.push(serialized);
            }
            let new_frontier_rows = current
                .frontier_rows
                .checked_sub(1)
                .and_then(|n| n.checked_add(documents.len() as u64))
                .ok_or_else(storage_error)?;
            let new_frontier_bytes = current
                .frontier_bytes
                .checked_sub(document.len() as u64)
                .and_then(|n| n.checked_add(successor_bytes))
                .ok_or_else(storage_error)?;
            if new_frontier_rows > 100_000 || new_frontier_bytes > 32 * 1024 * 1024 {
                let reply = Reply::error(EXHAUSTED, 429)?;
                current.finish_attempt();
                owned.snapshot_save_job(&current)?;
                owned.ledger.finish(&proof, &reply)?;
                return Ok(reply);
            }
            for id in &newly_seen {
                let len = step
                    .observations()
                    .iter()
                    .find(|fact| fact.id() == *id)
                    .ok_or_else(storage_error)?
                    .canonical_len();
                owned.state.storage().sql().exec(
                    "INSERT INTO host_snapshot_seen(job_id,object_id,canonical_len) VALUES(?,?,?)",
                    vec![
                        current.id.clone().into(),
                        hex::encode(id).into(),
                        (len as i64).into(),
                    ],
                )?;
            }
            for serialized in documents {
                let next_seq =
                    i64::try_from(current.frontier_next_seq).map_err(|_| storage_error())?;
                owned.state.storage().sql().exec(
                    "INSERT INTO host_snapshot_frontier(job_id,seq,document) VALUES(?,?,?)",
                    vec![
                        current.id.clone().into(),
                        next_seq.into(),
                        serialized.into(),
                    ],
                )?;
                current.frontier_next_seq = current
                    .frontier_next_seq
                    .checked_add(1)
                    .ok_or_else(storage_error)?;
            }
            owned.state.storage().sql().exec(
                "DELETE FROM host_snapshot_frontier WHERE job_id=? AND seq=?",
                vec![current.id.clone().into(), seq.into()],
            )?;
            current.frontier_rows = new_frontier_rows;
            current.frontier_bytes = new_frontier_bytes;
            current.reached_objects = next.objects;
            current.reached_bytes = next.canonical_bytes;
            current.max_depth = next.max_tree_depth;
            current.work_units = next.work;
            current.next_revision(now())?;
            current.finish_attempt();
            owned.snapshot_save_job(&current)?;
            let reply = Reply::json(&current.reply())?;
            owned.ledger.finish(&proof, &reply)?;
            Ok(reply)
        })
    }

    fn snapshot_promote(&self, job: &Job, proof: &Proof, deadline: i64) -> Result<Reply> {
        let owned = self.clone();
        let original = job.clone();
        let proof = proof.clone();
        self.ledger.transaction(move || {
            within_deadline(deadline)?;
            let mut current = owned.snapshot_check_fence(&original, &proof)?;
            if current.state != "walk" || current.frontier_rows != 0
                || owned.snapshot_exists("SELECT 1 AS found FROM host_snapshot_frontier WHERE job_id=? LIMIT 1", vec![current.id.clone().into()])?
            { return Err(storage_error()); }
            // One bounded-index aggregate at promotion (not every page)
            // reconciles persisted counters with the actual durable rows.
            // It also catches a low injected counter before certification.
            let catalog_rows = owned.snapshot_count(
                "SELECT COUNT(*) AS n FROM host_snapshot_catalog WHERE job_id=?",
                vec![current.id.clone().into()],
            )?;
            let seen_rows = owned.snapshot_count(
                "SELECT COUNT(*) AS n FROM host_snapshot_seen WHERE job_id=?",
                vec![current.id.clone().into()],
            )?;
            let seen_bytes = owned.snapshot_count(
                "SELECT COALESCE(SUM(canonical_len),0) AS n FROM host_snapshot_seen WHERE job_id=?",
                vec![current.id.clone().into()],
            )?;
            if catalog_rows != current.catalog_entries || seen_rows != current.reached_objects
                || seen_bytes != current.reached_bytes
                || current.catalog_packs as usize != owned.snapshot_selected(&current)?.len()
            { return Err(storage_error()); }
            let missing_reached = owned.snapshot_exists(
                "SELECT 1 AS found FROM host_snapshot_seen s WHERE s.job_id=? AND NOT EXISTS(SELECT 1 FROM host_snapshot_catalog c WHERE c.job_id=s.job_id AND c.object_id=s.object_id) LIMIT 1",
                vec![current.id.clone().into()],
            )?;
            let extra_catalog = owned.snapshot_exists(
                "SELECT 1 AS found FROM host_snapshot_catalog c WHERE c.job_id=? AND NOT EXISTS(SELECT 1 FROM host_snapshot_seen s WHERE s.job_id=c.job_id AND s.object_id=c.object_id) LIMIT 1",
                vec![current.id.clone().into()],
            )?;
            if missing_reached || extra_catalog { return Err(storage_error()); }
            let existing = owned.snapshot_count("SELECT COUNT(*) AS n FROM host_snapshot_certificates WHERE exact_ref=?", vec![current.exact_ref.clone().into()])?;
            let ready = owned.snapshot_count("SELECT COUNT(*) AS n FROM host_snapshot_certificates", vec![])?;
            if existing == 0 && ready >= 8 {
                let reply = Reply::error(EXHAUSTED, 429)?;
                current.finish_attempt();
                owned.snapshot_save_job(&current)?;
                owned.ledger.finish(&proof, &reply)?;
                return Ok(reply);
            }
            owned.state.storage().sql().exec(
                "UPDATE host_snapshot_indexes SET retired=1 WHERE job_id=(SELECT job_id FROM host_snapshot_certificates WHERE exact_ref=?)",
                vec![current.exact_ref.clone().into()],
            )?;
            owned.state.storage().sql().exec(
                "INSERT INTO host_snapshot_indexes(job_id,generation,exact_ref,head,packmap,catalog_digest,raw_bytes,retired) VALUES(?,?,?,?,?,?,?,0)",
                vec![current.id.clone().into(),current.generation.clone().into(),current.exact_ref.clone().into(),current.head.clone().into(),current.packmap.clone().into(),current.selected_digest.clone().into(),(current.catalog_raw_bytes as i64).into()],
            )?;
            owned.state.storage().sql().exec(
                "INSERT INTO host_snapshot_certificates(exact_ref,job_id,generation,head,packmap,catalog_digest,profile_version,validator_version,retired) VALUES(?,?,?,?,?,?,1,1,0) ON CONFLICT(exact_ref) DO UPDATE SET job_id=excluded.job_id,generation=excluded.generation,head=excluded.head,packmap=excluded.packmap,catalog_digest=excluded.catalog_digest,profile_version=1,validator_version=1,retired=0",
                vec![current.exact_ref.clone().into(),current.id.clone().into(),current.generation.clone().into(),current.head.clone().into(),current.packmap.clone().into(),current.selected_digest.clone().into()],
            )?;
            current.state = "ready".into();
            current.terminal_deadline = now() + super::snapshot_store::TERMINAL_MS;
            current.next_revision(now())?;
            current.finish_attempt();
            owned.snapshot_save_job(&current)?;
            let reply = Reply::json(&current.reply())?;
            owned.ledger.finish(&proof, &reply)?;
            Ok(reply)
        })
    }
}
