//! Pure write planners (reconciliation R-18) and the commit deadline
//! (R-61/R-62, 00-plan P-21).
//!
//! The store only checks preconditions and applies writes, so every write
//! is planned here as **read → decide → batch**: [`plan_write`] is a pure
//! function of the request, a read [`Snapshot`] and a [`PlanClock`], and
//! every value it decided on is guarded by a precondition. The pipeline
//! applies the batch and re-plans when a guard fails.

use std::collections::BTreeMap;

use mkit_core::hash::Hash;
use mkit_core::protocol::AdvanceOutcome;
use mkit_core::refs::RefWriteCondition;

use crate::error::ServerError;
use crate::op::{GrantRef, RefUpdate};
use crate::quota::{QuotaCharge, QuotaDecision, evaluate_quota};
use crate::refs::{CasDecision, evaluate_condition};
use crate::replay::{
    ReplayDecision, ReplayRecord, ReplayState, StoredRejection, StoredResult, UpdateRefResult,
    classify,
};
use crate::repo::RepoName;
use crate::storage_error::{StorageOp, describe_and_map};
use crate::store::keys::{self, LAYOUT_VERSION, ParsedKey};
use crate::store::{Batch, Key, MAX_BATCH_OPS, Precondition, Value, Write, codec};

/// Most re-plans after a guard failed because another writer changed a
/// value the plan read; then the write is a retryable `aborted`.
pub(crate) const MAX_REPLAN: u32 = 8;

/// Most expired replay records, and separately most stale quota windows,
/// one sampled write prunes (each an index key plus its row). One write in
/// [`PRUNE_SAMPLE`] prunes, so this must be at least `PRUNE_SAMPLE` for
/// growth to stay bounded; the batch op cap trims it further
/// ([`MAX_BATCH_OPS`]). WP-1.24's alarm sweep replaces this.
pub(crate) const PRUNE_LIMIT: u32 = 16;

/// One write in this many runs the prune scans.
pub(crate) const PRUNE_SAMPLE: u8 = 8;

const _: () = assert!(PRUNE_LIMIT >= PRUNE_SAMPLE as u32);

/// Whether this write runs the prune scans: deterministically one in
/// [`PRUNE_SAMPLE`], by replay scope for a signed write, keeping the scans
/// off the hot path.
#[must_use]
pub(crate) fn prune_sampled(req: &WriteRequest<'_>, plan_time_ms: u64) -> bool {
    match req.replay {
        Some(replay) => replay.scope[0].is_multiple_of(PRUNE_SAMPLE),
        None => !req.charges.is_empty() && plan_time_ms.is_multiple_of(u64::from(PRUNE_SAMPLE)),
    }
}

/// The clocks one planning attempt uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PlanClock {
    /// Unix ms from the injected clock, never shifted by a test clock-skew
    /// directive. Only the commit deadline uses it.
    pub(crate) plan_time_ms: u64,
    /// Business time, Unix ms: quota windows and replay pruning.
    pub(crate) business_now_ms: i64,
    /// `PipelineConfig::max_apply_window`, in ms.
    pub(crate) max_apply_window_ms: u64,
    /// An extra bound on the deadline: WP-1.25 passes
    /// `lease_expires - margin` here without touching the planners.
    pub(crate) deadline_cap: Option<u64>,
}

impl PlanClock {
    /// `min(plan_time + max_apply_window, deadline_cap)`: the batch's
    /// `NotAfter`, which the backend checks on its own clock.
    #[must_use]
    pub(crate) fn deadline(&self) -> u64 {
        let window = self.plan_time_ms.saturating_add(self.max_apply_window_ms);
        self.deadline_cap.map_or(window, |cap| cap.min(window))
    }
}

/// The ref write being planned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum WriteKind {
    /// One conditional ref write.
    UpdateRef,
    /// Packmap and head, in one batch.
    AdvanceRefs,
    /// An `UploadPack` reservation: the replay record `InFlight { resumable:
    /// true }` and the quota charge, before any chunk is read.
    UploadReserve,
    /// An `UploadPack` commit: the in-flight record becomes
    /// `Committed(UploadPack)`, guarded by `Equals` on the record read.
    UploadCommit,
}

/// The replay record a signed write commits with its effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplayGuard {
    /// The auth v2 replay scope.
    pub(crate) scope: Hash,
    /// The operation fingerprint.
    pub(crate) fingerprint: Hash,
    /// Envelope expiry, Unix ms.
    pub(crate) expires_at_ms: i64,
}

/// A write to plan.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) struct WriteRequest<'a> {
    /// The repository whose refs are written.
    pub(crate) repo: &'a RepoName,
    /// What the refs are.
    pub(crate) kind: WriteKind,
    /// Ref writes in decision order: `[update]`, or `[packmap, head]`, so a
    /// packmap conflict takes precedence (`refstore.rs` parity).
    pub(crate) refs: &'a [RefUpdate],
    /// The replay record to commit, for signed writes.
    pub(crate) replay: Option<ReplayGuard>,
    /// Quota charges from admission.
    pub(crate) charges: &'a [QuotaCharge],
    /// The grant the write was authorized under (M2).
    pub(crate) grant: Option<GrantRef>,
    /// Whether to guard the layout version key: false on stores that
    /// report an implicit layout version.
    pub(crate) layout_version: bool,
    /// `UploadCommit` only: a final `pre_receive` rejection to store in
    /// place of `UploadPack`, so a retry is answered before re-streaming.
    pub(crate) rejection: Option<&'a StoredRejection>,
}

impl WriteRequest<'_> {
    /// Every key the planner reads, besides prune candidates.
    #[must_use]
    pub(crate) fn read_keys(&self) -> Vec<Key> {
        let mut out = Vec::new();
        if self.layout_version {
            out.push(keys::layout_version());
        }
        if self.grant.is_some() {
            out.push(keys::grant_epoch());
        }
        out.extend(self.charges.iter().map(|c| keys::quota(&c.scope)));
        out.extend(self.refs.iter().map(|r| keys::ref_key(self.repo, &r.name)));
        if let (WriteKind::UploadCommit, Some(replay)) = (self.kind, self.replay) {
            out.push(keys::replay(&replay.scope));
        }
        out
    }
}

/// What a planning attempt read: key values plus the prune candidates of
/// `store::read::{expired_replay_keys, stale_quota_keys}`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Snapshot {
    values: BTreeMap<Key, Option<Value>>,
    /// `(index, record)` pairs of expired replay records.
    pub(crate) expired_replays: Vec<(Key, Key)>,
    /// `(index, quota)` pairs of ended quota windows; their quota keys are
    /// read too.
    pub(crate) stale_quotas: Vec<(Key, Key)>,
}

impl Snapshot {
    /// Record that `key` held `value`.
    pub(crate) fn insert(&mut self, key: Key, value: Option<Value>) {
        self.values.insert(key, value);
    }

    /// Whether `key` was read.
    #[must_use]
    pub(crate) fn contains(&self, key: &Key) -> bool {
        self.values.contains_key(key)
    }

    /// What `key` held; a key never read counts as absent.
    #[must_use]
    pub(crate) fn get(&self, key: &Key) -> Option<&Value> {
        debug_assert!(self.values.contains_key(key), "planner read an unread key");
        self.values.get(key).and_then(Option::as_ref)
    }
}

/// A planned batch and what it means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    /// The batch; its first precondition is always the `NotAfter`.
    pub(crate) batch: Batch,
    /// The result once the batch commits.
    pub(crate) on_commit: StoredResult,
    /// Index of the replay record's `Absent` guard.
    pub(crate) replay_index: Option<usize>,
    /// Index of the grant epoch guard.
    pub(crate) epoch_index: Option<usize>,
    /// The prune deletes alone, retried when a full partition rejects the
    /// batch (delete-only batches never fail with `Full`).
    pub(crate) prune: Option<Batch>,
    /// Index of the first prune guard: a failure at or after it is only
    /// the opportunistic prune losing a race, so the pipeline retries
    /// without the prune.
    pub(crate) prune_from: usize,
}

/// What [`plan_write`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum Planned {
    /// Apply this batch.
    Apply(Plan),
    /// Nothing to write: an unsigned write that conflicts on the snapshot.
    Done(StoredResult),
}

/// Plan `req` on `snap` at `clock`.
///
/// # Errors
/// `resource_exhausted` when a quota charge is over budget (nothing is
/// written), `permission_denied` when the grant epoch moved, and `internal`
/// for an undecodable stored value or a newer layout version.
pub(crate) fn plan_write(
    req: &WriteRequest<'_>,
    snap: &Snapshot,
    clock: &PlanClock,
) -> Result<Planned, ServerError> {
    let deadline = Precondition::NotAfter(clock.deadline());
    let mut pre = vec![deadline.clone()];
    let mut puts = Vec::new();

    let epoch_index = match req.grant {
        Some(grant) => {
            let key = keys::grant_epoch();
            let stored = snap.get(&key).map(codec::decode_u64).transpose();
            if stored.map_err(corrupt)?.unwrap_or(0) != grant.epoch {
                return Err(epoch_moved());
            }
            pre.push(guard(key, snap));
            Some(pre.len() - 1)
        }
        None => None,
    };
    if req.layout_version {
        let key = keys::layout_version();
        match snap.get(&key).map(codec::decode_u32).transpose() {
            Ok(None) => puts.push(Write::Put(key.clone(), codec::encode_u32(LAYOUT_VERSION))),
            Ok(Some(LAYOUT_VERSION)) => {}
            Ok(Some(newer)) => return Err(corrupt(format!("layout version {newer}"))),
            Err(e) => return Err(corrupt(e)),
        }
        pre.push(guard(key, snap));
    }
    for charge in req.charges {
        plan_charge(charge, snap, clock.business_now_ms, &mut pre, &mut puts)?;
    }

    // Quota IS charged on a CAS conflict, as in vcs-worker, where the
    // charge commits in the same transaction as the replay row: a conflict
    // still costs an operation and a ledger row, so the charge bounds
    // ledger growth per signer. PRD §5.4's separate `Aborted` transaction
    // is for M3 payment reservations, not this abuse quota.
    let (outcome, ref_puts) = decide_refs(req, snap, &mut pre)?;
    let conflict = outcome.is_some();
    let on_commit = outcome.unwrap_or(match req.kind {
        WriteKind::UpdateRef => StoredResult::UpdateRef(UpdateRefResult::Committed),
        WriteKind::AdvanceRefs => StoredResult::AdvanceRefs(AdvanceOutcome::Committed),
        WriteKind::UploadReserve | WriteKind::UploadCommit => {
            req.rejection.map_or(StoredResult::UploadPack, |r| {
                StoredResult::Rejected(r.clone())
            })
        }
    });
    if conflict && req.replay.is_none() && req.charges.is_empty() {
        return Ok(Planned::Done(on_commit));
    }
    if !conflict {
        puts.extend(ref_puts);
    }

    let replay_index = match req.replay {
        Some(replay) => {
            let index = pre.len();
            if let Some(done) =
                plan_replay(req.kind, replay, snap, &on_commit, &mut pre, &mut puts)?
            {
                return Ok(Planned::Done(done));
            }
            Some(index)
        }
        None => None,
    };

    let budget = MAX_BATCH_OPS.saturating_sub(pre.len() + puts.len());
    let prune = plan_prune(req, snap, &deadline, budget)?;
    // Prune deletes go first: a later write to the same key wins.
    let mut writes = prune.as_ref().map(|b| b.writes.clone()).unwrap_or_default();
    writes.extend(puts);
    let prune_from = pre.len();
    if let Some(prune) = &prune {
        pre.extend(prune.preconditions.iter().skip(1).cloned());
    }
    Ok(Planned::Apply(Plan {
        batch: Batch {
            preconditions: pre,
            writes,
        },
        on_commit,
        replay_index,
        epoch_index,
        prune,
        prune_from,
    }))
}

/// The replay record's guard and writes. A new record is guarded
/// `Absent`, written with its expiry index; an upload's commit guards the
/// in-flight record it read with `Equals`. `Some(result)` when an upload
/// being committed already committed: nothing to write.
fn plan_replay(
    kind: WriteKind,
    replay: ReplayGuard,
    snap: &Snapshot,
    on_commit: &StoredResult,
    pre: &mut Vec<Precondition>,
    puts: &mut Vec<Write>,
) -> Result<Option<StoredResult>, ServerError> {
    let key = keys::replay(&replay.scope);
    let state = match kind {
        WriteKind::UploadReserve => ReplayState::InFlight { resumable: true },
        _ => ReplayState::Committed(on_commit.clone()),
    };
    let record = ReplayRecord {
        fingerprint: replay.fingerprint,
        expires_at_ms: replay.expires_at_ms,
        state,
    };
    if kind == WriteKind::UploadCommit {
        let stored = snap.get(&key);
        let decoded = stored.map(codec::decode_replay_record).transpose();
        match (
            classify(decoded.map_err(corrupt)?.as_ref(), &replay.fingerprint),
            stored,
        ) {
            (ReplayDecision::Resume, Some(value)) => {
                pre.push(Precondition::Equals(key.clone(), value.clone()));
            }
            (ReplayDecision::Return(result), _) => return Ok(Some(result)),
            (ReplayDecision::FingerprintMismatch, _) => {
                return Err(ServerError::invalid_argument(
                    "nonce reused for a different operation",
                ));
            }
            _ => {
                return Err(ServerError::aborted_retryable(
                    "upload reservation lost; retry",
                ));
            }
        }
        puts.push(Write::Put(key, codec::encode_replay_record(&record)));
        return Ok(None);
    }
    pre.push(Precondition::Absent(key.clone()));
    puts.push(Write::Put(key, codec::encode_replay_record(&record)));
    let expires = u64::try_from(replay.expires_at_ms).unwrap_or(0);
    puts.push(Write::Put(
        keys::replay_expiry(expires, &replay.scope),
        Value::default(),
    ));
    Ok(None)
}

/// `Equals` on the value `key` held, or `Absent`.
fn guard(key: Key, snap: &Snapshot) -> Precondition {
    match snap.get(&key) {
        Some(value) => Precondition::Equals(key, value.clone()),
        None => Precondition::Absent(key),
    }
}

fn corrupt(detail: impl core::fmt::Display) -> ServerError {
    let (line, err) = describe_and_map(StorageOp::MetaDecode, detail);
    tracing::warn!(detail = %line, "undecodable stored value");
    err
}

/// The grant's epoch no longer holds (M2; unreachable in M0).
pub(crate) fn epoch_moved() -> ServerError {
    ServerError::permission_denied("write grant epoch changed; re-authorize")
}

/// Evaluate one charge and add its guard and writes, keeping the window
/// index (`qx`) one-to-one with live quota rows.
fn plan_charge(
    charge: &QuotaCharge,
    snap: &Snapshot,
    now: i64,
    pre: &mut Vec<Precondition>,
    puts: &mut Vec<Write>,
) -> Result<(), ServerError> {
    let key = keys::quota(&charge.scope);
    let current = snap.get(&key).map(codec::decode_quota_state).transpose();
    let current = current.map_err(corrupt)?;
    let state = match evaluate_quota(current, now, charge.bytes, &charge.limits) {
        QuotaDecision::Allowed(state) => state,
        QuotaDecision::Exhausted { reason } => return Err(ServerError::resource_exhausted(reason)),
    };
    let start = |s: i64| u64::try_from(s).unwrap_or(0);
    let old_start = current.map(|c| c.window_start);
    if old_start != Some(state.window_start) {
        if let Some(old) = old_start {
            puts.push(Write::Delete(keys::quota_window(start(old), &charge.scope)));
        }
        let index = keys::quota_window(start(state.window_start), &charge.scope);
        puts.push(Write::Put(index, Value::default()));
    }
    pre.push(guard(key.clone(), snap));
    puts.push(Write::Put(key, codec::encode_quota_state(&state)));
    Ok(())
}

/// Decide the ref writes in order. On the first conflict, return its
/// result: only the refs decided so far are guarded.
fn decide_refs(
    req: &WriteRequest<'_>,
    snap: &Snapshot,
    pre: &mut Vec<Precondition>,
) -> Result<(Option<StoredResult>, Vec<Write>), ServerError> {
    let mut puts = Vec::new();
    for (i, update) in req.refs.iter().enumerate() {
        let key = keys::ref_key(req.repo, &update.name);
        let current = snap.get(&key).map(codec::decode_ref_id).transpose();
        let current = current.map_err(corrupt)?;
        match evaluate_condition(current.as_ref(), &update.condition) {
            CasDecision::Committed => {
                // `Any` commits whatever the ref holds: nothing to guard.
                if update.condition != RefWriteCondition::Any {
                    pre.push(guard(key.clone(), snap));
                }
                puts.push(Write::Put(key, codec::encode_ref_id(&update.new)));
            }
            CasDecision::Conflict(_) => {
                pre.push(guard(key, snap));
                let result = match (req.kind, i) {
                    (WriteKind::UpdateRef, _) => {
                        StoredResult::UpdateRef(UpdateRefResult::Conflict { current })
                    }
                    (WriteKind::AdvanceRefs, 0) => {
                        StoredResult::AdvanceRefs(AdvanceOutcome::PackmapConflict)
                    }
                    // Uploads write no refs.
                    _ => StoredResult::AdvanceRefs(AdvanceOutcome::HeadConflict),
                };
                return Ok((Some(result), Vec::new()));
            }
            CasDecision::Invalid(msg) => return Err(ServerError::invalid_argument(msg)),
        }
    }
    Ok((None, puts))
}

/// The opportunistic prune: every expired replay record, and every stale
/// quota window not charged by this write (the charge rolls it over
/// itself). A quota row is deleted only while it still holds the window
/// its index names, guarded by `Equals`. At most `budget` operations, so
/// the combined batch stays within [`MAX_BATCH_OPS`].
fn plan_prune(
    req: &WriteRequest<'_>,
    snap: &Snapshot,
    deadline: &Precondition,
    budget: usize,
) -> Result<Option<Batch>, ServerError> {
    let mut batch = Batch::new().require(deadline.clone());
    let used = |b: &Batch| b.preconditions.len() - 1 + b.writes.len();
    for (index, record) in &snap.expired_replays {
        if used(&batch) + 2 > budget {
            break;
        }
        batch = batch.delete(index.clone()).delete(record.clone());
    }
    let charged: Vec<Key> = req.charges.iter().map(|c| keys::quota(&c.scope)).collect();
    for (index, quota) in &snap.stale_quotas {
        if used(&batch) + 3 > budget {
            break;
        }
        if charged.contains(quota) {
            continue;
        }
        batch = batch.delete(index.clone());
        let Some(value) = snap.get(quota) else {
            continue;
        };
        let state = codec::decode_quota_state(value).map_err(corrupt)?;
        let Some(ParsedKey::QuotaWindow {
            window_start_ms: indexed,
            ..
        }) = keys::parse(index)
        else {
            return Err(corrupt("malformed quota window key"));
        };
        if u64::try_from(state.window_start).ok() == Some(indexed) {
            batch = batch
                .require(Precondition::Equals(quota.clone(), value.clone()))
                .delete(quota.clone());
        }
    }
    Ok((!batch.writes.is_empty()).then_some(batch))
}
