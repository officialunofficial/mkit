//! Bounded growth (R-31): replay records and quota windows are pruned once
//! they can no longer matter, so a partition shrinks back after load, and
//! never before (§7.1: a replay record MUST outlive its signed expiry).
//! Needs the stats endpoint ([`crate::wire::STATS_PATH`], `test-faults`)
//! and a declared quota whose window is short enough to wait out.
//!
//! Pruning runs on the server's real clock, not the business clock the
//! clock-skew directive shifts (WP-M0-05a), so the case waits in real
//! time: it signs the load with short envelopes, waits out validity +
//! [`Profile::replay_prune_grace_ms`](crate::wire::Profile) + the quota
//! window + a 5 s allowance for the skew between the suite's clock and the
//! server's, then sends trigger writes (a server may prune a sample of
//! writes only) from one fixed probe signer.
//!
//! The bound is absolute. The probe's per-write growth is measured before
//! the load, and the partition must come back to at most its pre-load size
//! plus that growth per trigger plus 10% of the load. A server that never
//! prunes keeps the whole load and fails, however many triggers it sees.

use std::time::Duration;

use mkit_transport_connect::generated::UpdateRefResponse;

use super::{A, CaseResult, Ctx, Exp, Failure, Signed, ensure, sign_unary, update_req, want_ok};
use crate::wire::STATS_PATH;
use crate::wire::client::{Rpc, RpcError};
use crate::wire::sign::{Signer, now_ms};

/// Load writes, each by its own signer: one replay record and one quota
/// window each.
const LOAD: u32 = 64;
/// Envelope lifetime of every write here.
const VALIDITY_MS: i64 = 10_000;
/// Longest quota window the case will wait out.
const MAX_WINDOW_MS: i64 = 60_000;
/// Allowance for the skew between the suite's clock and the server's.
const SKEW_ALLOWANCE_MS: i64 = 5_000;
/// Probe writes measured before the load.
const CALIBRATE: u32 = 8;
/// Trigger writes allowed after the wait.
const MAX_TRIGGERS: u32 = 256;
/// Probe writes per quota window the case needs.
const PROBE_WRITES: u32 = 1 + CALIBRATE + MAX_TRIGGERS;

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

/// A signed `UpdateRef(<ns>/<leaf>, exp, A)` by `signer`, valid for
/// [`VALIDITY_MS`].
fn write(ctx: &Ctx, signer: &Signer, leaf: &str, exp: Exp<'_>) -> Signed {
    let req = update_req(&ctx.head(leaf), exp, &A);
    sign_unary(signer, Rpc::UpdateRef, &req, |env| {
        env.expires_at = env.created_at + VALIDITY_MS;
    })
}

async fn send(ctx: &Ctx, s: &Signed) -> Result<Result<UpdateRefResponse, RpcError>, String> {
    ctx.send(s).await
}

#[allow(clippy::cast_precision_loss)] // byte counts far below 2^52
pub(super) async fn replay_and_quota_pruned(ctx: Ctx) -> CaseResult {
    let profile = ctx.profile();
    let Some(quota) = profile.quota.filter(|q| q.window_ms <= MAX_WINDOW_MS) else {
        return Err(Failure::Skip(format!(
            "needs a declared quota window of at most {MAX_WINDOW_MS} ms"
        )));
    };
    if quota.max_ops < PROBE_WRITES {
        return Err(Failure::Skip(format!(
            "needs a quota of at least {PROBE_WRITES} writes per window"
        )));
    }
    let probe = ctx.v2_signer("probe")?;
    // Calibrate: one probe write opens its quota window, the next ones add
    // one replay record each.
    want_ok(
        send(&ctx, &write(&ctx, &probe, "probe", Exp::Any)).await?,
        "probe write",
    )?;
    let calibrating = stats_bytes(&ctx).await?;
    for i in 0..CALIBRATE {
        let s = write(&ctx, &probe, "probe", Exp::Any);
        want_ok(send(&ctx, &s).await?, &format!("calibration write {i}"))?;
    }
    let before = stats_bytes(&ctx).await?;
    // A server holding other expired records may prune some of them here,
    // which would understate this: run the case on a disposable server.
    ensure!(
        before > calibrating,
        "calibration saw no growth ({calibrating} -> {before} bytes): other records were pruned \
         meanwhile; run on a fresh server"
    );
    let per_probe = (before - calibrating) as f64 / f64::from(CALIBRATE);

    // Load: all but the last write go to one ref, so the load's lasting
    // growth is replay records and quota windows, not new refs. The last
    // is create-only, so a replay answered by re-execution would fail.
    for i in 0..LOAD - 1 {
        let signer = ctx.v2_signer(&format!("load{i}"))?;
        let s = write(&ctx, &signer, "load", Exp::Any);
        want_ok(send(&ctx, &s).await?, &format!("load write {i}"))?;
    }
    let last = write(&ctx, &ctx.v2_signer("load-last")?, "last", Exp::Missing);
    want_ok(send(&ctx, &last).await?, "the last load write")?;
    let loaded = stats_bytes(&ctx).await?;
    ensure!(
        loaded > before,
        "no growth under load: {before} -> {loaded} bytes"
    );
    // Lower bound: before its expiry the record still answers its replay.
    want_ok(
        send(&ctx, &last).await?,
        "a load write replayed before its expiry",
    )?;

    let signed_at = now_ms();
    let wait_ms = VALIDITY_MS + profile.replay_prune_grace_ms + quota.window_ms + SKEW_ALLOWANCE_MS;
    tokio::time::sleep(Duration::from_millis(u64::try_from(wait_ms).unwrap_or(0))).await;
    ensure!(now_ms() >= signed_at + wait_ms, "suite bug: short sleep");

    let slack = 0.1 * (loaded - before) as f64;
    let mut now = loaded;
    for t in 1..=MAX_TRIGGERS {
        let s = write(&ctx, &probe, "probe", Exp::Any);
        want_ok(send(&ctx, &s).await?, &format!("trigger write {t}"))?;
        now = stats_bytes(&ctx).await?;
        let bound = before as f64 + f64::from(t) * per_probe + slack;
        if now as f64 <= bound {
            ctx.set_note(format!(
                "{before} -> {loaded} bytes under load; {now} after {t} trigger writes \
                 (bound {bound:.0})"
            ));
            return Ok(());
        }
    }
    let bound = before as f64 + f64::from(MAX_TRIGGERS) * per_probe + slack;
    Err(Failure::Fail(format!(
        "not pruned: {before} -> {loaded} bytes under load, {now} after {MAX_TRIGGERS} \
         trigger writes {wait_ms} ms later, bound {bound:.0} ({per_probe:.0} bytes per probe write)"
    )))
}
