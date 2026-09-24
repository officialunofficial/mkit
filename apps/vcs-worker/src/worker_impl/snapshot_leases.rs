// SPDX-License-Identifier: MIT OR Apache-2.0
//! Structural index read leases for the later private disclosure route.
//! A lease never grants a subject access to bytes.

use super::refstore::RefStore;
use crate::{access_policy::Identity, snapshot_wire};
use serde::Deserialize;
use worker::{Date, Error, Result};

const MAX_LEASE_MS: i64 = 5 * 60 * 1000;

fn unavailable() -> Error {
    Error::RustError("snapshot index unavailable".into())
}

#[allow(dead_code)] // Internal c2 seam; c1 does not expose private disclosure.
#[derive(Clone, Debug)]
pub(super) struct SnapshotReadLease {
    pub lease_id: String,
    pub job_id: String,
    pub generation: String,
    pub catalog_digest: String,
    pub deadline: i64,
}

pub(super) enum SnapshotLeaseAcquire {
    Acquired(SnapshotReadLease),
    Capacity,
    Conflict,
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
    /// A lease pins storage only. Recheck the current certificate/ref tuple
    /// separately from the caller's live grant decision on every disclosure.
    pub(super) fn snapshot_lease_current(
        &self,
        identity: &Identity,
        exact_ref: &str,
        head: &str,
        packmap: &str,
        lease: &SnapshotReadLease,
    ) -> Result<bool> {
        if Date::now().as_millis() as i64 >= lease.deadline
            || self.snapshot_meta(identity)?.is_none()
            || self.read_policy(identity)?.is_none()
            || self.read_ref(exact_ref)?.as_deref() != Some(head)
        {
            return Ok(false);
        }
        let Some(branch) = exact_ref.strip_prefix("refs/heads/") else {
            return Ok(false);
        };
        if self
            .read_ref(&format!("refs/mkit/packmap/{branch}"))?
            .as_deref()
            != Some(packmap)
        {
            return Ok(false);
        }
        let rows: Vec<Certificate> = self.state.storage().sql().exec(
            "SELECT job_id,generation,head,packmap,catalog_digest,profile_version,validator_version FROM host_snapshot_certificates WHERE exact_ref=?",
            vec![exact_ref.into()],
        )?.to_array()?;
        let Some(cert) = rows.first() else {
            return Ok(false);
        };
        if cert.job_id != lease.job_id
            || cert.generation != lease.generation
            || cert.catalog_digest != lease.catalog_digest
            || cert.head != head
            || cert.packmap != packmap
            || cert.profile_version != 1
            || cert.validator_version != 1
        {
            return Ok(false);
        }
        let live = self.snapshot_exists(
            "SELECT 1 AS found FROM host_snapshot_leases WHERE lease_id=? AND job_id=? AND generation=? AND deadline>? LIMIT 1",
            vec![lease.lease_id.clone().into(), lease.job_id.clone().into(), lease.generation.clone().into(), (Date::now().as_millis() as i64).into()],
        )?;
        let index = self.snapshot_exists(
            "SELECT 1 AS found FROM host_snapshot_indexes WHERE job_id=? AND generation=? AND exact_ref=? AND head=? AND packmap=? AND catalog_digest=? AND retired=0 LIMIT 1",
            vec![lease.job_id.clone().into(), lease.generation.clone().into(), exact_ref.into(), head.into(), packmap.into(), lease.catalog_digest.clone().into()],
        )?;
        Ok(live && index)
    }
    /// Pins an exact currently live structural index. A caller must separately
    /// authorize every private read against the current grant and policy.
    #[allow(dead_code)]
    pub(super) fn snapshot_acquire_read_lease(
        &self,
        identity: &Identity,
        exact_ref: &str,
        head: &str,
        packmap: &str,
        lease_id: &str,
        duration_ms: i64,
    ) -> Result<SnapshotLeaseAcquire> {
        if !snapshot_wire::id(lease_id)
            || lease_id.bytes().all(|b| b == b'0')
            || duration_ms <= 0
            || duration_ms > MAX_LEASE_MS
        {
            return Err(unavailable());
        }
        let owned = self.clone();
        let identity = identity.clone();
        let exact_ref = exact_ref.to_owned();
        let head = head.to_owned();
        let packmap = packmap.to_owned();
        let lease_id = lease_id.to_owned();
        self.ledger.transaction(move || {
            let timestamp = Date::now().as_millis() as i64;
            if owned.snapshot_meta(&identity)?.is_none() || owned.read_policy(&identity)?.is_none() {
                return Ok(SnapshotLeaseAcquire::Conflict);
            }
            if owned.read_ref(&exact_ref)?.as_deref() != Some(&head) { return Ok(SnapshotLeaseAcquire::Conflict); }
            let packmap_ref = exact_ref.strip_prefix("refs/heads/").map(|branch| format!("refs/mkit/packmap/{branch}"))
                .ok_or_else(unavailable)?;
            if owned.read_ref(&packmap_ref)?.as_deref() != Some(&packmap) { return Ok(SnapshotLeaseAcquire::Conflict); }
            let rows: Vec<Certificate> = owned.state.storage().sql().exec(
                "SELECT job_id,generation,head,packmap,catalog_digest,profile_version,validator_version FROM host_snapshot_certificates WHERE exact_ref=?",
                vec![exact_ref.clone().into()],
            )?.to_array()?;
            let Some(cert) = rows.first() else { return Ok(SnapshotLeaseAcquire::Conflict); };
            if cert.head != head || cert.packmap != packmap || cert.profile_version != 1 || cert.validator_version != 1 {
                return Ok(SnapshotLeaseAcquire::Conflict);
            }
            let index = owned.snapshot_exists(
                "SELECT 1 AS found FROM host_snapshot_indexes WHERE job_id=? AND generation=? AND exact_ref=? AND head=? AND packmap=? AND catalog_digest=? AND retired=0 LIMIT 1",
                vec![cert.job_id.clone().into(),cert.generation.clone().into(),exact_ref.clone().into(),head.clone().into(),packmap.clone().into(),cert.catalog_digest.clone().into()],
            )?;
            if !index { return Ok(SnapshotLeaseAcquire::Conflict); }
            // Bound physical rows as well as live pins; expired rows are
            // reclaimed by owner Cleanup, never silently accumulated here.
            let total = owned.snapshot_count("SELECT COUNT(*) AS n FROM host_snapshot_leases", vec![])?;
            let per_cert = owned.snapshot_count("SELECT COUNT(*) AS n FROM host_snapshot_leases WHERE job_id=?", vec![cert.job_id.clone().into()])?;
            if total >= 64 || per_cert >= 16 {
                return Ok(SnapshotLeaseAcquire::Capacity);
            }
            let deadline = timestamp.checked_add(duration_ms).ok_or_else(unavailable)?;
            owned.state.storage().sql().exec(
                "INSERT INTO host_snapshot_leases(lease_id,job_id,generation,deadline) VALUES(?,?,?,?)",
                vec![lease_id.clone().into(),cert.job_id.clone().into(),cert.generation.clone().into(),deadline.into()],
            )?;
            Ok(SnapshotLeaseAcquire::Acquired(SnapshotReadLease { lease_id, job_id: cert.job_id.clone(), generation: cert.generation.clone(),
                catalog_digest: cert.catalog_digest.clone(), deadline }))
        })
    }

    /// Releases a structural pin; repeated release is harmless.
    #[allow(dead_code)]
    pub(super) fn snapshot_release_read_lease(&self, lease_id: &str) -> Result<()> {
        if !snapshot_wire::id(lease_id) {
            return Err(unavailable());
        }
        self.state.storage().sql().exec(
            "DELETE FROM host_snapshot_leases WHERE lease_id=?",
            vec![lease_id.into()],
        )?;
        Ok(())
    }
}
