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
//! plus that growth per trigger plus the load's lasting rows. When the
//! stats hook reports `keys`, the bound is on the exact key count: the load
//! may leave only its two refs, so even one leaked index row per record
//! fails. Otherwise it falls back to bytes, with 10% of the load as slack.
//! A server that never prunes keeps the whole load and fails, however many
//! triggers it sees.
//!
//! The case needs a disposable server: other records expiring on the same
//! partition would be pruned during calibration and skew the measurement.
//!
//! Under D34 every write of these cases goes to one ref, whose shard is the
//! partition the stats hook reads (`?ref=<name>`); Single sharding keeps the
//! one deployment-wide partition. [`tickets_and_outbox_pruned`] runs the same
//! measurement over upload tickets: the load opens tickets, they expire on
//! the server's own clock (it needs a short ticket lifetime: the Worker's
//! `TEST_TICKET_TTL_MS`), and the shard must shrink once their expiry
//! timers run and the outcome and relay outboxes drain. The clock-skew
//! directive cannot stand in: the timers it fires schedule their outcome
//! delivery on the skewed clock, an hour ahead of the real one.

use std::time::Duration;

use mkit_transport_connect::generated::{BeginUploadResponse, UpdateRefResponse};

use super::{
    A, CaseResult, Ctx, Exp, Failure, Signed, ensure, sign_unary, tickets, update_req, want_ok,
};
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

/// Keys the load leaves for good: its two refs (`load`, `last`).
const LASTING_KEYS: u64 = 2;

/// Writes that flush an earlier case's expired records before calibration.
const FLUSH_WRITES: u32 = 64;

/// Tickets the ticket load opens at most.
const TICKETS: u64 = 32;
/// The longest ticket lifetime the case waits out.
const MAX_TICKET_WAIT_MS: i64 = 120_000;
/// After the last ticket expires: its timer, then outcome and relay delivery.
const DRAIN_ALLOWANCE_MS: i64 = 30_000;

/// One stats reading.
#[derive(Debug, Clone, Copy)]
struct Stats {
    bytes: u64,
    keys: Option<u64>,
}

/// What the bound counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unit {
    Keys,
    Bytes,
}

impl Stats {
    fn get(self, unit: Unit) -> Result<u64, Failure> {
        match unit {
            Unit::Bytes => Ok(self.bytes),
            Unit::Keys => self
                .keys
                .ok_or_else(|| Failure::Fail(format!("GET {STATS_PATH}: `keys` went missing"))),
        }
    }
}

/// The stats endpoint's reading: of the partition holding `scope`'s replay
/// records when the server shards by ref (D34), else of the one partition.
async fn stats(ctx: &Ctx, scope: &str) -> Result<Stats, Failure> {
    let path = if ctx.profile().sharding_d34 {
        let scope: String = url::form_urlencoded::byte_serialize(scope.as_bytes()).collect();
        format!("{STATS_PATH}?ref={scope}")
    } else {
        STATS_PATH.to_owned()
    };
    let reply = ctx.client().get(&path).await?;
    ensure!(
        reply.status == 200,
        "GET {STATS_PATH}: HTTP {}",
        reply.status
    );
    let json: serde_json::Value = serde_json::from_slice(&reply.body)
        .map_err(|e| format!("GET {STATS_PATH}: not JSON: {e}"))?;
    let bytes = json
        .get("bytes")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| Failure::Fail(format!("GET {STATS_PATH}: no `bytes` in {json}")))?;
    let keys = json.get("keys").and_then(serde_json::Value::as_u64);
    Ok(Stats { bytes, keys })
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

/// What the case loads onto the partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Load {
    /// [`LOAD`] writes by their own signers: replay records and quota windows.
    Replay,
    /// Open tickets, which expire on the server's clock.
    Tickets,
}

pub(super) async fn replay_and_quota_pruned(ctx: Ctx) -> CaseResult {
    pruned(ctx, Load::Replay).await
}

pub(super) async fn tickets_and_outbox_pruned(ctx: Ctx) -> CaseResult {
    pruned(ctx, Load::Tickets).await
}

#[allow(clippy::cast_precision_loss, clippy::too_many_lines)] // Byte counts far below 2^52; one measurement.
async fn pruned(ctx: Ctx, load: Load) -> CaseResult {
    let profile = ctx.profile();
    let quota = profile.quota.filter(|q| q.window_ms <= MAX_WINDOW_MS);
    if load == Load::Replay && quota.is_none() {
        return Err(Failure::Skip(format!(
            "needs a declared quota window of at most {MAX_WINDOW_MS} ms"
        )));
    }
    if quota.is_some_and(|q| q.max_ops < PROBE_WRITES) {
        return Err(Failure::Skip(format!(
            "needs a quota of at least {PROBE_WRITES} writes per window"
        )));
    }
    let window_ms = quota.map_or(0, |q| q.window_ms);
    let probe = ctx.v2_signer("probe")?;
    if load == Load::Tickets && !profile.sharding_d34 {
        // One partition holds every case's records: let the replay case's
        // last records expire, then flush them with writes of another signer
        // (pruning runs on writes), or they are pruned mid-calibration.
        let settle = VALIDITY_MS + profile.replay_prune_grace_ms + window_ms + SKEW_ALLOWANCE_MS;
        tokio::time::sleep(Duration::from_millis(u64::try_from(settle).unwrap_or(0))).await;
        let warm = ctx.v2_signer("warm")?;
        for i in 0..FLUSH_WRITES {
            let s = write(&ctx, &warm, "probe", Exp::Any);
            want_ok(send(&ctx, &s).await?, &format!("flush write {i}"))?;
        }
    }
    // Under D34 the probe, the load and the triggers share one ref, and so
    // one shard: the partition the stats hook reads.
    let home = "probe";
    let scope = ctx.head(home);
    // Calibrate: one probe write opens its quota window, the next ones add
    // one replay record each.
    want_ok(
        send(&ctx, &write(&ctx, &probe, "probe", Exp::Any)).await?,
        "probe write",
    )?;
    let first = stats(&ctx, &scope).await?;
    let unit = if first.keys.is_some() {
        Unit::Keys
    } else {
        Unit::Bytes
    };
    let calibrating = first.get(unit)?;
    for i in 0..CALIBRATE {
        let s = write(&ctx, &probe, "probe", Exp::Any);
        want_ok(send(&ctx, &s).await?, &format!("calibration write {i}"))?;
    }
    let before = stats(&ctx, &scope).await?.get(unit)?;
    // A server holding other expired records may prune some of them here,
    // which would understate this: run the case on a disposable server.
    ensure!(
        before > calibrating,
        "calibration saw no growth ({calibrating} -> {before} {unit:?}): other records were \
         pruned meanwhile; run on a fresh server"
    );
    let per_probe = (before - calibrating) as f64 / f64::from(CALIBRATE);

    let loaded_by = match load {
        Load::Replay => replay_load(&ctx, home).await?,
        Load::Tickets => ticket_load(&ctx, &scope).await?,
    };
    let loaded = stats(&ctx, &scope).await?.get(unit)?;
    ensure!(
        loaded > before,
        "no growth under load: {before} -> {loaded} {unit:?}"
    );
    let signed_at = now_ms();
    let mut wait_ms = VALIDITY_MS + profile.replay_prune_grace_ms + window_ms + SKEW_ALLOWANCE_MS;
    if let Some(last_expiry) = loaded_by {
        // The tickets close at their expiry; their outcome and relay rows
        // then drain within the allowance.
        wait_ms = wait_ms.max(last_expiry - signed_at + DRAIN_ALLOWANCE_MS);
    }
    tokio::time::sleep(Duration::from_millis(u64::try_from(wait_ms).unwrap_or(0))).await;
    ensure!(now_ms() >= signed_at + wait_ms, "suite bug: short sleep");

    let slack = match unit {
        Unit::Keys => LASTING_KEYS as f64,
        Unit::Bytes => 0.1 * (loaded - before) as f64,
    };
    let bound = |t: u32| before as f64 + f64::from(t) * per_probe + slack;
    let mut now = loaded;
    for t in 1..=MAX_TRIGGERS {
        let s = write(&ctx, &probe, "probe", Exp::Any);
        want_ok(send(&ctx, &s).await?, &format!("trigger write {t}"))?;
        now = stats(&ctx, &scope).await?.get(unit)?;
        if now as f64 <= bound(t) {
            ctx.set_note(format!(
                "{unit:?}: {before} -> {loaded} under load; {now} after {t} trigger writes \
                 (bound {:.0})",
                bound(t)
            ));
            return Ok(());
        }
    }
    Err(Failure::Fail(format!(
        "not pruned ({unit:?}): {before} -> {loaded} under load, {now} after {MAX_TRIGGERS} \
         trigger writes {wait_ms} ms later, bound {:.0} ({per_probe:.1} per probe write)",
        bound(MAX_TRIGGERS)
    )))
}

/// The replay load. Nearly every write goes to one ref, so the load's
/// lasting growth is replay records and quota windows, not new refs. The
/// last is create-only, so a replay answered by re-execution would fail.
async fn replay_load(ctx: &Ctx, home: &str) -> Result<Option<i64>, Failure> {
    let shared = if ctx.profile().sharding_d34 {
        home
    } else {
        "load"
    };
    for i in 0..LOAD - 1 {
        let signer = ctx.v2_signer(&format!("load{i}"))?;
        let s = write(ctx, &signer, shared, Exp::Any);
        want_ok(send(ctx, &s).await?, &format!("load write {i}"))?;
    }
    let last = write(ctx, &ctx.v2_signer("load-last")?, "last", Exp::Missing);
    want_ok(send(ctx, &last).await?, "the last load write")?;
    // Lower bound: before its expiry the record still answers its replay.
    want_ok(
        send(ctx, &last).await?,
        "a load write replayed before its expiry",
    )?;
    Ok(None)
}

/// The ticket load: as many open tickets as one signer may hold on `scope`,
/// at most [`TICKETS`]. Returns when the last expires, in Unix milliseconds.
async fn ticket_load(ctx: &Ctx, scope: &str) -> Result<Option<i64>, Failure> {
    let signer = ctx.v2_signer("load-tickets")?;
    let mut last_expiry = 0;
    for salt in 0..ctx.profile().ticket_per_signer.min(TICKETS) {
        let req = tickets::request(scope.to_owned(), salt);
        let begin = sign_unary(&signer, Rpc::BeginUpload, &req, |env| {
            env.expires_at = env.created_at + VALIDITY_MS;
        });
        let opened: BeginUploadResponse = want_ok(ctx.send(&begin).await?, "load BeginUpload")?;
        let expires = tickets::ticket(opened)?.expires_unix_ms.unwrap_or_default();
        if expires - now_ms() > MAX_TICKET_WAIT_MS {
            return Err(Failure::Skip(format!(
                "tickets live longer than {MAX_TICKET_WAIT_MS} ms: needs a short ticket lifetime"
            )));
        }
        last_expiry = last_expiry.max(expires);
    }
    Ok(Some(last_expiry))
}
