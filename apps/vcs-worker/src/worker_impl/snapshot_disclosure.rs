// SPDX-License-Identifier: MIT OR Apache-2.0
//! Private, selected-only MKWB disclosure. Structural readiness is never
//! treated as grant authority; both are checked again after every R2 await.

use mkit_core::{
    hash::{from_hex, to_hex},
    partial::{PartialError, PartialLimits, PartialSnapshotBuilder, verify_partial_snapshot},
};
use mkit_worker_common::replay::Proof;
use serde::{Deserialize, Serialize};
use worker::{Date, Request, Response, Result};

use super::{
    grant_store::DisclosureGrant, refstore::RefStore, snapshot_driver::HeavyPermit,
    snapshot_leases::SnapshotReadLease,
};
use crate::{
    access_policy::Identity,
    snapshot_wire::{self, GetWorkspace},
};

pub(super) const PATH: &str = "/mkit/partial/v1/GetWorkspace";
const MAX_RESPONSE: usize = 4 * 1024 * 1024;
const MAX_IO_BYTES: usize = 4 * 1024 * 1024;
const MAX_IO_READS: usize = 2_048;
const DEADLINE_MS: i64 = 20_000;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DisclosureWire {
    pub identity: Identity,
    pub proof: Proof,
    pub body: String,
}

fn limits() -> PartialLimits {
    PartialLimits {
        max_bundle_bytes: MAX_RESPONSE,
        max_witness_bytes: 1024 * 1024,
        max_total_selected_bytes: 1024 * 1024,
        max_selected_file_bytes: 256 * 1024,
        max_objects: 2_048,
        max_tree_visits: 2_048,
        max_base_object_bytes: 2 * 1024 * 1024,
        max_tree_object_bytes: 2 * 1024 * 1024,
        max_object_bytes: 2 * 1024 * 1024,
        ..PartialLimits::V1
    }
}

fn now() -> i64 {
    Date::now().as_millis() as i64
}

fn error(status: u16, code: &str) -> Result<Response> {
    let mut response = Response::ok(format!("{{\"code\":\"{code}\"}}"))?.with_status(status);
    response
        .headers_mut()
        .set("Content-Type", "application/json")?;
    response
        .headers_mut()
        .set("Cache-Control", "private, no-store")?;
    Ok(response)
}

fn deadline_ok(deadline: i64) -> bool {
    now() < deadline
}

fn builder_error(error_value: PartialError) -> Result<Response> {
    let (status, code) = snapshot_wire::disclosure_builder_failure(&error_value);
    error(status, code)
}

struct LeaseGuard<'a> {
    store: &'a RefStore,
    id: String,
}
impl Drop for LeaseGuard<'_> {
    fn drop(&mut self) {
        let _ = self.store.snapshot_release_read_lease(&self.id);
    }
}

impl RefStore {
    pub(super) async fn managed_disclosure(&self, req: &mut Request) -> Result<Response> {
        if req.method() != worker::Method::Post {
            return error(405, "method_not_allowed");
        }
        let wire: DisclosureWire = match req.json().await {
            Ok(wire) => wire,
            Err(_) => return error(400, "invalid_argument"),
        };
        let configured = match (
            self.env.var("AUTH_AUDIENCE"),
            self.env.var("AUTH_REPOSITORY"),
            self.env.var("MANAGED_OWNER_PUBLIC_KEY"),
        ) {
            (Ok(a), Ok(r), Ok(o)) => {
                Identity::parse(&a.to_string(), &r.to_string(), &o.to_string())
            }
            _ => Err("missing configuration"),
        };
        if configured.as_ref().ok() != Some(&wire.identity) {
            return error(503, "unavailable");
        }
        if now() > wire.proof.expires_at {
            return error(401, "unauthenticated");
        }
        let request = match snapshot_wire::decode_disclosure(wire.body.as_bytes()) {
            Ok(request) => request,
            Err(_) => return error(400, "invalid_argument"),
        };
        let Some(paths) = request.checked_paths() else {
            return error(400, "invalid_argument");
        };
        let Ok(base) = from_hex(&request.expected_base) else {
            return error(400, "invalid_argument");
        };
        let profile = limits();
        let mut builder = match PartialSnapshotBuilder::new(base, &paths, &profile) {
            Ok(builder) => builder,
            Err(e) => return builder_error(e),
        };
        let (exact_ref, head) =
            match self.disclosure_grant(&wire.identity, &wire.proof, &request)? {
                DisclosureGrant::Allowed(exact_ref, head) => (exact_ref, head),
                DisclosureGrant::Denied => return error(403, "permission_denied"),
                DisclosureGrant::Conflict => return error(409, "conflict"),
            };
        let Some(branch) = exact_ref.strip_prefix("refs/heads/") else {
            return error(409, "conflict");
        };
        let Some(packmap) = self.read_ref(&format!("refs/mkit/packmap/{branch}"))? else {
            return error(409, "conflict");
        };
        let Some(_permit) = HeavyPermit::acquire(&self.snapshot_busy) else {
            return error(429, "resource_exhausted");
        };
        let mut random = [0u8; 32];
        getrandom::fill(&mut random)
            .map_err(|_| worker::Error::RustError("entropy unavailable".into()))?;
        let lease_id = hex::encode(random);
        let lease = match self.snapshot_acquire_read_lease(
            &wire.identity,
            &exact_ref,
            &head,
            &packmap,
            &lease_id,
            5 * 60 * 1000,
        ) {
            Ok(lease) => lease,
            Err(e) if e.to_string().contains("snapshot lease capacity") => {
                return error(429, "resource_exhausted");
            }
            Err(_) => return error(409, "conflict"),
        };
        let _lease = LeaseGuard {
            store: self,
            id: lease_id,
        };
        let deadline = now().saturating_add(DEADLINE_MS);
        let mut io_bytes = 0usize;
        let mut reads = 0usize;
        while let Some(next) = builder.next_request() {
            let current = if deadline_ok(deadline) {
                self.disclosure_current(
                    &wire.identity,
                    &wire.proof,
                    &request,
                    &exact_ref,
                    &head,
                    &packmap,
                    &lease,
                )?
            } else {
                false
            };
            if let Some((status, code)) =
                snapshot_wire::disclosure_fence_failure(!deadline_ok(deadline), current)
            {
                return error(status, code);
            }
            let id = to_hex(&next.id());
            let locator = match self.snapshot_index_locator(&lease.job_id, &id) {
                Ok(locator) => locator,
                Err(_) => return error(503, "unavailable"),
            };
            #[cfg(feature = "test-faults")]
            {
                self.state.storage().sql().exec(
                    "CREATE TABLE IF NOT EXISTS c2_test_reads (seq INTEGER PRIMARY KEY, object_id TEXT NOT NULL, pack_key TEXT NOT NULL)",
                    None,
                )?;
                self.state.storage().sql().exec(
                    "INSERT INTO c2_test_reads(object_id,pack_key) VALUES(?,?)",
                    vec![id.clone().into(), locator.pack_key.clone().into()],
                )?;
            }
            let Some(length) = usize::try_from(locator.payload_len).ok() else {
                return error(503, "unavailable");
            };
            if length > next.max_bytes()
                || length > MAX_IO_BYTES.saturating_sub(io_bytes)
                || reads >= MAX_IO_READS
            {
                return error(429, "resource_exhausted");
            }
            io_bytes += length;
            reads += 1;
            let bytes = match self.snapshot_read_range(&locator, deadline).await {
                Ok(bytes) => bytes,
                Err(_) => return error(503, "unavailable"),
            };
            #[cfg(feature = "test-faults")]
            if let Ok(delay) = self.env.var("C2_TEST_PAUSE_MS") {
                let pause = delay.to_string().parse::<u64>().unwrap_or(0).min(5_000);
                if pause > 0 {
                    worker::Delay::from(std::time::Duration::from_millis(pause)).await;
                }
            }
            let current = if deadline_ok(deadline) {
                self.disclosure_current(
                    &wire.identity,
                    &wire.proof,
                    &request,
                    &exact_ref,
                    &head,
                    &packmap,
                    &lease,
                )?
            } else {
                false
            };
            if let Some((status, code)) =
                snapshot_wire::disclosure_fence_failure(!deadline_ok(deadline), current)
            {
                return error(status, code);
            }
            builder = match builder.supply(bytes) {
                Ok(builder) => builder,
                Err(e) => return builder_error(e),
            };
        }
        let bytes = match builder.finish().and_then(|bundle| bundle.encode(&profile)) {
            Ok(bytes) if bytes.len() <= MAX_RESPONSE => bytes,
            Ok(_) => return error(429, "resource_exhausted"),
            Err(e) => return builder_error(e),
        };
        if verify_partial_snapshot(base, &paths, &bytes, &profile).is_err() {
            return error(503, "unavailable");
        }
        let current = if deadline_ok(deadline) {
            self.disclosure_current(
                &wire.identity,
                &wire.proof,
                &request,
                &exact_ref,
                &head,
                &packmap,
                &lease,
            )?
        } else {
            false
        };
        if let Some((status, code)) =
            snapshot_wire::disclosure_fence_failure(!deadline_ok(deadline), current)
        {
            return error(status, code);
        }
        let size = bytes.len();
        let mut response = Response::from_bytes(bytes)?;
        response
            .headers_mut()
            .set("Content-Type", "application/octet-stream")?;
        response
            .headers_mut()
            .set("Cache-Control", "private, no-store")?;
        response
            .headers_mut()
            .set("Content-Length", &size.to_string())?;
        Ok(response)
    }

    fn disclosure_current(
        &self,
        identity: &Identity,
        proof: &Proof,
        request: &GetWorkspace,
        exact_ref: &str,
        head: &str,
        packmap: &str,
        lease: &SnapshotReadLease,
    ) -> Result<bool> {
        if !self.disclosure_grant_current(identity, proof, request)? {
            return Ok(false);
        }
        self.snapshot_lease_current(identity, exact_ref, head, packmap, lease)
    }
}
