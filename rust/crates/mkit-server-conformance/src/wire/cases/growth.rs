//! Bounded growth (R-31): replay records and quota windows are pruned once
//! they can no longer matter, so a partition shrinks back after load.
//! Needs the stats endpoint ([`crate::wire::STATS_PATH`], `test-faults`)
//! and a declared quota whose window is short enough to wait out.
//!
//! Pruning runs on the server's real clock, not the business clock the
//! clock-skew directive shifts (WP-M0-05a), so the case waits in real
//! time. It keeps the wait short by signing envelopes valid for a few
//! seconds only: a record is prunable once its envelope has expired plus
//! the server's grace.

use std::time::{Duration, Instant};

use buffa::Message as _;
use mkit_core::hash::{hash, to_hex};
use mkit_transport_connect::generated::UpdateRefResponse;

use super::{A, CaseResult, Ctx, Exp, Failure, ensure, update_req, want_ok};
use crate::wire::STATS_PATH;
use crate::wire::client::{Rpc, RpcError};
use crate::wire::sign::{Signer, body_commitment};

/// Load writes, each by its own signer: one replay record and one quota
/// window each.
const LOAD: u32 = 64;
/// Envelope lifetime of every write here.
const VALIDITY_MS: i64 = 5_000;
/// Longest quota window the case will wait out.
const MAX_WINDOW_MS: i64 = 60_000;
/// Give up after this long without shrinking back.
const MAX_WAIT: Duration = Duration::from_mins(5);
/// Pause between probe writes.
const PROBE_EVERY: Duration = Duration::from_millis(500);

/// `bytes` from the stats endpoint.
async fn stats_bytes(ctx: &Ctx) -> Result<u64, Failure> {
    let reply = ctx.client().get(STATS_PATH).await?;
    ensure!(
        reply.status == 200,
        "GET {STATS_PATH}: HTTP {}",
        reply.status
    );
    let json: serde_json::Value = serde_json::from_slice(&reply.body)
        .map_err(|e| format!("GET {STATS_PATH}: not JSON: {e}"))?;
    json.get("bytes")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| Failure::Fail(format!("GET {STATS_PATH}: no `bytes` in {json}")))
}

/// A signed `UpdateRef(<ns>/main, ANY, A)` by `signer`, valid for
/// [`VALIDITY_MS`].
async fn write(ctx: &Ctx, signer: &Signer) -> Result<Result<UpdateRefResponse, RpcError>, String> {
    let body = update_req(&ctx.head("main"), Exp::Any, &A).encode_to_vec();
    let mut env = signer.envelope(Rpc::UpdateRef.procedure(), body_commitment(&body));
    env.digest = Some(to_hex(&hash(&body)));
    env.expires_at = env.created_at + VALIDITY_MS;
    ctx.client()
        .unary(Rpc::UpdateRef, body, &signer.sign(&env).headers)
        .await
}

#[allow(clippy::cast_precision_loss)] // byte counts far below 2^52
pub(super) async fn replay_and_quota_pruned(ctx: Ctx) -> CaseResult {
    let window_ms = ctx.profile().quota.map_or(i64::MAX, |q| q.window_ms);
    if window_ms > MAX_WINDOW_MS {
        return Err(Failure::Skip(format!(
            "needs a declared quota window of at most {MAX_WINDOW_MS} ms"
        )));
    }
    let before = stats_bytes(&ctx).await?;
    for i in 0..LOAD {
        let signer = ctx.v2_signer(&format!("load{i}"))?;
        want_ok(write(&ctx, &signer).await?, &format!("load write {i}"))?;
    }
    let loaded = stats_bytes(&ctx).await?;
    ensure!(
        loaded > before,
        "no growth under load: {before} -> {loaded} bytes"
    );
    let per_write = (loaded - before) as f64 / f64::from(LOAD);
    let started = Instant::now();
    let mut k = 0u32;
    while started.elapsed() < MAX_WAIT {
        tokio::time::sleep(PROBE_EVERY).await;
        k += 1;
        let signer = ctx.v2_signer(&format!("probe{k}"))?;
        want_ok(write(&ctx, &signer).await?, &format!("probe write {k}"))?;
        // Discount the probes' own rows; the load's must be ≥ 90% gone.
        let now = stats_bytes(&ctx).await? as f64;
        let residue = now - f64::from(k) * per_write - before as f64;
        if residue <= 0.1 * (loaded - before) as f64 {
            ctx.set_note(format!(
                "{before} -> {loaded} bytes under load; shrank back after {:.0?} and {k} probe writes",
                started.elapsed()
            ));
            return Ok(());
        }
    }
    Err(Failure::Fail(format!(
        "the partition did not shrink back within {MAX_WAIT:?} ({before} -> {loaded} bytes, now {}, {k} probes)",
        stats_bytes(&ctx).await?
    )))
}
