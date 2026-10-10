//! Admission and replay settlement, carried as data in the job row so that
//! the kind-16 timer can finish a fork the starting request has left.
//!
//! The reservation's deadline is the job's expiry, not the apply window:
//! an unfinished fork holds its reservation (and the quota it was admitted
//! against) for at most [`super::JOB_TTL_MS`], after which the job aborts it
//! with the normal `Aborted` outcome.

use super::{ForkEnv, ForkError, ForkJobV1};
use crate::pipeline::{PlanSnapshot as Snapshot, plan_charge};
use crate::quota::{QuotaCharge, QuotaLimits, QuotaScope};
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
    /// Reservation id.
    pub rid: String,
    /// The exact pending reservation value, the arbiter every contender
    /// guards.
    pub pending: Vec<u8>,
    /// Repository identity for the outcome.
    pub repository: String,
    /// The replay record to commit with the outcome.
    pub replay: Option<ReplayV1>,
    /// The admission charges.
    pub charges: Vec<ChargeV1>,
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

/// The effects that commit the fork's outcome: `Committed`, the replay
/// record and the admission charges, all in the caller's single batch.
pub(crate) async fn commit<S: NamespaceStore>(
    env: &ForkEnv<'_, S>,
    job: &ForkJobV1,
    now: u64,
) -> Result<Batch, ForkError> {
    let mut batch = Batch::new();
    let Some(settle) = &job.settle else {
        return Ok(batch);
    };
    let charge_keys: Vec<Key> = settle
        .charges
        .iter()
        .map(|c| keys::quota(&c.charge().scope))
        .collect();
    let (os, oc, snapshot) = read_counters(env, job, &charge_keys).await?;
    for charge in &settle.charges {
        let (mut pre, mut writes) = (Vec::new(), Vec::new());
        // Admission decided this charge when it granted the request. A window
        // that has filled up since then does not undo a fork that is already
        // published, so an exhausted charge is not applied; a corrupt row
        // still stops the commit.
        match plan_charge(
            &charge.charge(),
            &snapshot,
            i64::try_from(now).unwrap_or(i64::MAX),
            &mut pre,
            &mut writes,
        ) {
            Ok(()) => append(&mut batch, pre, writes),
            Err(error) if error.code() == crate::Code::ResourceExhausted => {}
            Err(error) => return Err(ForkError::from(error)),
        }
    }
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
    let Some(settle) = &job.settle else {
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
    let Some(settle) = &job.settle else {
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
