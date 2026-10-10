//! Admission and replay settlement, carried as data in the job row so that
//! the kind-16 timer can finish a fork the starting request has left.
//!
//! The reservation's deadline is the job's expiry, not the apply window:
//! an unfinished fork holds its reservation (and the quota it was admitted
//! against) for at most [`super::JOB_TTL_MS`], after which the job aborts it
//! with the normal `Aborted` outcome.

use super::{ForkEnv, ForkError, ForkJobV1};
use crate::pipeline::{PlanSnapshot as Snapshot, plan_charge};
use crate::quota::{
    NamespaceCharge, QuotaCharge, QuotaLimits, QuotaScope, counter_key, namespace_window,
    plan_namespace_charge,
};
use crate::replay::{ReplayRecord, ReplayState, StoredResult};
use crate::store::codec::{self, AbortReason, ReservationV1, StoredProcedure};
use crate::store::outbox::{OutboxBuilder, Terminal};
use crate::store::{Batch, Key, NamespaceStore, Precondition, Value, Write, keys};
use mkit_core::hash::Hash;
use serde::{Deserialize, Serialize};

/// One quota charge, as data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChargeV1 {
    /// The charged scope.
    pub scope: String,
    /// Bytes charged.
    pub bytes: u64,
    /// Window length.
    pub window_ms: i64,
    /// Operation cap.
    pub max_ops: u32,
    /// Byte cap.
    pub max_bytes: u64,
}

impl ChargeV1 {
    /// Capture an admitted charge.
    #[must_use]
    pub fn of(charge: &QuotaCharge) -> Self {
        Self {
            scope: charge.scope.as_str().to_owned(),
            bytes: charge.bytes,
            window_ms: charge.limits.window_ms,
            max_ops: charge.limits.max_ops,
            max_bytes: charge.limits.max_bytes,
        }
    }
    fn charge(&self) -> QuotaCharge {
        QuotaCharge {
            scope: QuotaScope::from_stored(self.scope.clone()),
            bytes: self.bytes,
            limits: QuotaLimits::new(self.window_ms, self.max_ops, self.max_bytes),
        }
    }
}

/// The signed request's replay binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayV1 {
    /// Replay scope.
    pub scope: Hash,
    /// Request fingerprint.
    pub fingerprint: Hash,
    /// Envelope expiry, Unix ms.
    pub expires_at_ms: i64,
}

/// What admission granted the request, to settle once, atomically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettleV1 {
    /// Reservation id; empty when admission granted no reservation (the
    /// default admission), in which case there is no outcome to settle.
    pub rid: String,
    /// The exact pending reservation value, the arbiter every contender
    /// guards.
    pub pending: Vec<u8>,
    /// Repository identity for the outcome.
    pub repository: String,
    /// The replay record to commit with the outcome.
    pub replay: Option<ReplayV1>,
    /// The admission charges. [`super::start_with`] applies them in the batch
    /// that creates the job (so quota is a hard bound: an exhausted window
    /// refuses the fork before any work) and stores the job with this list
    /// emptied.
    pub charges: Vec<ChargeV1>,
    /// Under the default admission, the per-namespace aggregate cap the
    /// charges are also counted against (the first charge's limits and bytes,
    /// as for an upload); applied and cleared with `charges`.
    pub namespace_cap: Option<ChargeV1>,
    /// The inherited bytes admission charged for, an upper bound the plan
    /// must stay within: the fork fails if the pack set it resolves is larger.
    pub declared_bytes: u64,
}

async fn read_counters<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &ForkJobV1,
    extra: &[Key],
) -> Result<(Option<Value>, Option<Value>, Snapshot), ForkError> {
    let p = env.shards.coordinator(&job.dest()?.namespace);
    let mut wanted = vec![keys::outbox_sequence(), keys::outcome_backlog()];
    wanted.extend(extra.iter().cloned());
    let rows = env.store.get_many(&p, &wanted).await?;
    let mut snapshot = Snapshot::default();
    for (key, row) in wanted.iter().zip(&rows).skip(2) {
        snapshot.insert(key.clone(), row.clone());
    }
    Ok((
        rows.first().cloned().flatten(),
        rows.get(1).cloned().flatten(),
        snapshot,
    ))
}

fn builder(os: Option<&Value>, oc: Option<&Value>) -> Result<OutboxBuilder, ForkError> {
    Ok(OutboxBuilder::new(os, oc)?)
}

fn append(batch: &mut Batch, pre: Vec<Precondition>, writes: Vec<Write>) {
    batch.preconditions.extend(pre);
    batch.writes.extend(writes);
}

fn quota_reason(message: &str) -> &'static str {
    if message.starts_with("namespace") {
        "namespace write op/byte quota exceeded for this window; try again later"
    } else if message.contains("op quota") {
        "write op quota exceeded for this window; try again later"
    } else {
        "write byte quota exceeded for this window; try again later"
    }
}

/// The charges of a new job, planned against the destination coordinator's
/// quota rows. An exhausted window refuses the fork: this is where quota
/// binds, once, before any work (the commit of the outcome charges nothing).
pub(crate) async fn charge<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    coordinator: &crate::store::Partition,
    settle: &SettleV1,
    now: u64,
) -> Result<(Vec<Precondition>, Vec<Write>), ForkError> {
    let now_ms = i64::try_from(now).unwrap_or(i64::MAX);
    // The namespace's exact counter lives in the coordinator, where the fork's
    // job is created, so it is charged in the same batch.
    let namespace = settle.namespace_cap.as_ref().map(|cap| {
        let limits = QuotaLimits::new(cap.window_ms, cap.max_ops, cap.max_bytes);
        NamespaceCharge {
            limits,
            window: namespace_window(now_ms, cap.window_ms),
            bytes: cap.bytes,
            rollup: false,
        }
    });
    let mut wanted: Vec<Key> = settle
        .charges
        .iter()
        .map(|c| keys::quota(&c.charge().scope))
        .collect();
    let counter = namespace.map(|n| counter_key(n, n.window));
    wanted.extend(counter.clone());
    let mut snapshot = Snapshot::default();
    if !wanted.is_empty() {
        let rows = env.store.get_many(coordinator, &wanted).await?;
        for (key, row) in wanted.iter().zip(rows) {
            snapshot.insert(key.clone(), row);
        }
    }
    let (mut pre, mut writes) = (Vec::new(), Vec::new());
    let refused = |error: crate::ServerError| match error.code() {
        crate::Code::ResourceExhausted => ForkError::Quota(quota_reason(error.public_message())),
        _ => ForkError::from(error),
    };
    for charge in &settle.charges {
        plan_charge(&charge.charge(), &snapshot, now_ms, &mut pre, &mut writes).map_err(refused)?;
    }
    if let (Some(charge), Some(key)) = (namespace, counter) {
        plan_namespace_charge(
            charge,
            snapshot.get(&key),
            None,
            now_ms,
            now,
            &mut pre,
            &mut writes,
        )
        .map_err(refused)?;
    }
    Ok((pre, writes))
}

/// The effects that commit the fork's outcome: `Committed` and the replay
/// record, in the caller's single batch.
pub(crate) async fn commit<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &ForkJobV1,
    now: u64,
) -> Result<Batch, ForkError> {
    let mut batch = Batch::new();
    let Some(settle) = &job.settle else {
        return Ok(batch);
    };
    if !settle.rid.is_empty() {
        let (os, oc, _) = read_counters(env, job, &[]).await?;
        let mut outbox = builder(os.as_ref(), oc.as_ref())?;
        let pending = Value::new(settle.pending.clone());
        outbox.outcome(
            &settle.rid,
            &pending,
            Terminal::new(ReservationV1::Committed {
                repository: settle.repository.clone(),
                occurred_at_ms: now,
                bytes_stored: job.pack_bytes(),
                new_to_repo: job.pack_bytes(),
                new_to_store: 0,
                refs: Vec::new(),
                procedure: StoredProcedure::Fork,
            })?,
        );
        outbox.relay_at(now);
        let (mut pre, mut writes) = (Vec::new(), Vec::new());
        outbox.try_finish(&mut pre, &mut writes)?;
        append(&mut batch, pre, writes);
    }
    if let Some(replay) = &settle.replay {
        let key = keys::replay(&replay.scope);
        batch = batch
            .require(Precondition::Absent(key.clone()))
            .put(
                key,
                codec::encode_replay_record(&ReplayRecord {
                    fingerprint: replay.fingerprint,
                    expires_at_ms: replay.expires_at_ms,
                    state: ReplayState::Committed(StoredResult::Fork),
                }),
            )
            .put(
                keys::replay_expiry(
                    u64::try_from(replay.expires_at_ms).unwrap_or(0),
                    &replay.scope,
                ),
                Value::default(),
            );
    }
    Ok(batch)
}

/// The effects that abort the reservation with the normal `Aborted` outcome.
/// A reservation another contender already settled is left alone.
pub(crate) async fn abort<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &ForkJobV1,
    now: u64,
    detail: &str,
    reason: AbortReason,
) -> Result<Batch, ForkError> {
    let mut batch = Batch::new();
    let Some(settle) = job.settle.as_ref().filter(|s| !s.rid.is_empty()) else {
        return Ok(batch);
    };
    let p = env.shards.coordinator(&job.dest()?.namespace);
    let row = keys::reservation(&settle.rid).map_err(ForkError::from)?;
    let rows = env
        .store
        .get_many(&p, &[keys::outbox_sequence(), keys::outcome_backlog(), row])
        .await?;
    let pending = Value::new(settle.pending.clone());
    if rows.get(2).and_then(Option::as_ref) != Some(&pending) {
        return Ok(batch);
    }
    let mut outbox = builder(
        rows.first().and_then(Option::as_ref),
        rows.get(1).and_then(Option::as_ref),
    )?;
    outbox.outcome(
        &settle.rid,
        &pending,
        Terminal::new(ReservationV1::Aborted {
            repository: settle.repository.clone(),
            occurred_at_ms: now,
            reason,
            detail: detail.to_owned(),
            procedure: StoredProcedure::Fork,
        })?,
    );
    outbox.relay_at(now);
    let (mut pre, mut writes) = (Vec::new(), Vec::new());
    outbox.try_finish(&mut pre, &mut writes)?;
    append(&mut batch, pre, writes);
    Ok(batch)
}

/// Whether the pending reservation is still the one the job admitted.
pub(crate) async fn current<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &ForkJobV1,
) -> Result<bool, ForkError> {
    let Some(settle) = job.settle.as_ref().filter(|s| !s.rid.is_empty()) else {
        return Ok(true);
    };
    let p = env.shards.coordinator(&job.dest()?.namespace);
    let row = env
        .store
        .get(
            &p,
            &keys::reservation(&settle.rid).map_err(ForkError::from)?,
        )
        .await?;
    Ok(row.as_ref().map(Value::as_bytes) == Some(settle.pending.as_slice()))
}
